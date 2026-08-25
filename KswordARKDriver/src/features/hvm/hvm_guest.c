/*++

Module Name:

    hvm_guest.c

Abstract:

    Executes a bounded one-shot long-mode guest that immediately issues
    VMCALL, records the resulting VM exit, leaves VMX operation, and restores
    the saved assembly-wrapper continuation on the same logical processor.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_guest.h"
#include "../../platform/pool_compat.h"

#if defined(_M_AMD64)
#include <intrin.h>

#define KSW_HVM_GUEST_STACK_BYTES 0x4000U
#define KSW_HVM_HOST_STACK_BYTES  0x4000U
#define KSW_HVM_GUEST_POOL_TAG    'gHvK'
#define KSW_HVM_CR4_VMXE          (1ULL << 13)
#define KSW_HVM_VMCS_INSTRUCTION_ERROR 0x4400U
#define KSW_HVM_BUGCHECK_CODE     0x00020001UL
#define KSW_HVM_VMCS_EXIT_CONTROLS 0x400CUL
#define KSW_HVM_VMCS_GUEST_DEBUGCTL 0x2802UL
#define KSW_HVM_VMCS_GUEST_PKRS 0x2818UL
#define KSW_HVM_VMCS_GUEST_DR7 0x681AUL
#define KSW_HVM_VMCS_GUEST_S_CET 0x6828UL
#define KSW_HVM_VMCS_GUEST_SSP 0x682AUL
#define KSW_HVM_VMCS_GUEST_INTERRUPT_SSP_TABLE 0x682CUL
#define KSW_HVM_VMCS_GUEST_UINV 0x0814UL
#define KSW_HVM_EXIT_SAVE_DEBUG_CONTROLS (1UL << 2)
#define KSW_HVM_EXIT_CLEAR_UINV (1UL << 27)
#define KSW_HVM_EXIT_LOAD_CET (1UL << 28)
#define KSW_HVM_EXIT_LOAD_PKRS (1UL << 29)
#define KSW_HVM_IA32_PKRS 0x6E1UL
#define KSW_HVM_IA32_UINTR_MISC 0x988UL

typedef struct _KSW_HVM_ACTIVE_GUEST
{
    ULONGLONG LaunchStackPointer;
    volatile LONG VmxActive;
    volatile LONG Cr4Restored;
    NTSTATUS ExitStatus;
    ULONGLONG OriginalCr4;
    unsigned __int64 VmcsPhysical;
    KSW_HVM_GUEST_LAUNCH_RESULT Result;
    ULONGLONG GuestSCet;
    ULONGLONG GuestSsp;
    ULONGLONG GuestInterruptSspTable;
    ULONGLONG GuestPkrs;
    ULONGLONG GuestUinv;
    ULONGLONG GuestDebugControl;
    ULONGLONG GuestDr7;
    UCHAR CetStateManaged;
    UCHAR PkrsStateManaged;
    UCHAR UinvStateManaged;
    UCHAR DebugStateManaged;
    ULONG Reserved;
    ULONGLONG OriginalRflags;
} KSW_HVM_ACTIVE_GUEST;

/* Keep the assembly continuation pointer at the documented field-zero offset. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, LaunchStackPointer) == 0);
/* 保持一次性退出汇编使用的扩展状态偏移稳定。 */
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, GuestSCet) == 96);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, GuestSsp) == 104);
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_ACTIVE_GUEST,
    GuestInterruptSspTable) == 112);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, GuestPkrs) == 120);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, GuestDebugControl) == 136);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, GuestDr7) == 144);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, CetStateManaged) == 152);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, PkrsStateManaged) == 153);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, UinvStateManaged) == 154);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, DebugStateManaged) == 155);
C_ASSERT(FIELD_OFFSET(KSW_HVM_ACTIVE_GUEST, OriginalRflags) == 160);

static KSW_HVM_ACTIVE_GUEST* volatile g_KswordHvmActiveGuest = NULL;

static KSW_HVM_ACTIVE_GUEST*
KswordARKHvmReadActiveGuest(
    VOID
    )
{
    /* Read the single active launch pointer with full interlocked ordering. */
    return (KSW_HVM_ACTIVE_GUEST*)InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_KswordHvmActiveGuest,
        NULL,
        NULL);
}

static VOID
KswordARKHvmClearActiveGuest(
    _In_ KSW_HVM_ACTIVE_GUEST* Context
    )
{
    /* Clear only the exact launch context that currently owns VMX root. */
    (void)InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_KswordHvmActiveGuest,
        NULL,
        Context);
}

PVOID
KswordARKHvmVmExitDispatch(
    VOID
    )
{
    KSW_HVM_ACTIVE_GUEST* context = NULL;
    NTSTATUS telemetryStatus = STATUS_UNSUCCESSFUL;
    ULONG basicReason = KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    UCHAR vmclearResult = 0xFFU;
    SIZE_T exitControls = 0U;
    SIZE_T value = 0U;

    /* Resolve the launch context before reading the current VMCS. */
    context = KswordARKHvmReadActiveGuest();
    /* A VM exit without an owning launch cannot be resumed safely. */
    if (context == NULL) {
        KeBugCheckEx(
            KSW_HVM_BUGCHECK_CODE,
            (ULONG_PTR)0x48564D01UL,
            0U,
            0U,
            0U);
    }

    /* Capture all protocol-visible exit fields while the VMCS remains current. */
    telemetryStatus = KswordARKHvmReadVmExitTelemetry(
        &context->Result.Exit);
    /* Derive the Intel basic reason without discarding the raw protocol field. */
    basicReason =
        context->Result.Exit.Reason &
        KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    /* Mark the guest launched because control reached a valid host exit entry. */
    context->Result.GuestLaunched = 1U;
    /* Mark the exit handled before restoring the launch continuation. */
    context->Result.VmExitHandled = 1U;
    /* Select success only for a readable, non-entry-failure VMCALL exit. */
    if (NT_SUCCESS(telemetryStatus) &&
        (context->Result.Exit.Reason &
            KSW_HVM_VMEXIT_REASON_ENTRY_FAILURE) == 0UL &&
        basicReason == KSW_HVM_VMEXIT_REASON_VMCALL) {
        context->ExitStatus = STATUS_SUCCESS;
    } else if (!NT_SUCCESS(telemetryStatus)) {
        context->ExitStatus = telemetryStatus;
    } else {
        context->ExitStatus = STATUS_UNEXPECTED_IO_ERROR;
    }

    /* 在 VMCLEAR 前保存硬件已写回 VMCS 的可选客户机状态。 */
    if (__vmx_vmread(
            KSW_HVM_VMCS_EXIT_CONTROLS,
            &exitControls) != 0U) {
        context->ExitStatus = STATUS_HV_OPERATION_FAILED;
    } else {
        if ((exitControls & KSW_HVM_EXIT_LOAD_CET) != 0U) {
            if (__vmx_vmread(
                    KSW_HVM_VMCS_GUEST_S_CET,
                    &value) == 0U) {
                context->GuestSCet = (ULONGLONG)value;
                if (__vmx_vmread(
                        KSW_HVM_VMCS_GUEST_SSP,
                        &value) == 0U) {
                    context->GuestSsp = (ULONGLONG)value;
                    if (__vmx_vmread(
                            KSW_HVM_VMCS_GUEST_INTERRUPT_SSP_TABLE,
                            &value) == 0U) {
                        context->GuestInterruptSspTable =
                            (ULONGLONG)value;
                        context->CetStateManaged = 1U;
                    }
                }
            }
            if (context->CetStateManaged == 0U) {
                context->ExitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
        if ((exitControls & KSW_HVM_EXIT_LOAD_PKRS) != 0U) {
            if (__vmx_vmread(KSW_HVM_VMCS_GUEST_PKRS, &value) == 0U) {
                context->GuestPkrs = (ULONGLONG)value;
                context->PkrsStateManaged = 1U;
            } else {
                context->ExitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
        if ((exitControls & KSW_HVM_EXIT_CLEAR_UINV) != 0U) {
            if (__vmx_vmread(KSW_HVM_VMCS_GUEST_UINV, &value) == 0U) {
                context->GuestUinv = (ULONGLONG)value & 0xFFULL;
                context->UinvStateManaged = 1U;
            } else {
                context->ExitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
        if ((exitControls & KSW_HVM_EXIT_SAVE_DEBUG_CONTROLS) != 0U) {
            if (__vmx_vmread(
                    KSW_HVM_VMCS_GUEST_DEBUGCTL,
                    &value) == 0U) {
                context->GuestDebugControl = (ULONGLONG)value;
                if (__vmx_vmread(
                        KSW_HVM_VMCS_GUEST_DR7,
                        &value) == 0U) {
                    context->GuestDr7 = (ULONGLONG)value;
                    context->DebugStateManaged = 1U;
                }
            }
            if (context->DebugStateManaged == 0U) {
                context->ExitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
    }

    /* Return the current VMCS to clear state before leaving VMX operation. */
    vmclearResult = __vmx_vmclear(&context->VmcsPhysical);
    /* Preserve VMCLEAR failure as a launch failure without hiding exit evidence. */
    if (vmclearResult != 0U &&
        NT_SUCCESS(context->ExitStatus)) {
        context->ExitStatus = STATUS_HV_OPERATION_FAILED;
        context->Result.VmxInstructionResult = vmclearResult;
    }
    /* Leave VMX operation before restoring the original CR4 value. */
    __vmx_off();
    /* 恢复 VM-exit 为根模式加载或清除的非 CET 状态。 */
    if (context->PkrsStateManaged != 0U) {
        __writemsr(KSW_HVM_IA32_PKRS, context->GuestPkrs);
    }
    if (context->UinvStateManaged != 0U) {
        ULONGLONG uintrMisc = __readmsr(KSW_HVM_IA32_UINTR_MISC);

        uintrMisc &= ~(0xFFULL << 32);
        uintrMisc |= (context->GuestUinv & 0xFFULL) << 32;
        __writemsr(KSW_HVM_IA32_UINTR_MISC, uintrMisc);
    }
    /* Publish that cleanup no longer owns an active VMX root. */
    InterlockedExchange(&context->VmxActive, 0L);
    /* Restore the launcher's exact pre-VMX control-register state. */
    __writecr4(context->OriginalCr4);
    /* Publish the completed CR4 restoration to the C cleanup path. */
    InterlockedExchange(&context->Cr4Restored, 1L);
    /* Remove the global owner before execution resumes on its original stack. */
    KswordARKHvmClearActiveGuest(context);
    /* Return the context whose field zero contains the wrapper stack pointer. */
    return context;
}

NTSTATUS
KswordARKHvmLaunchControlledGuest(
    _In_ const KSW_HVM_GUEST_LAUNCH_INPUT* Input,
    _Out_ KSW_HVM_GUEST_LAUNCH_RESULT* Result
    )
{
    KSW_HVM_ACTIVE_GUEST context = { 0 };
    KSW_HVM_VMCS_INPUT vmcsInput = { 0 };
    GROUP_AFFINITY targetAffinity = { 0 };
    GROUP_AFFINITY oldAffinity = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    PVOID guestStack = NULL;
    PVOID hostStack = NULL;
    ULONGLONG originalCr0 = 0ULL;
    ULONGLONG requiredCr0 = 0ULL;
    ULONGLONG requiredCr4 = 0ULL;
    unsigned __int64 vmxonPhysical = 0ULL;
    UCHAR vmxResult = 0xFFU;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN affinitySet = FALSE;
    BOOLEAN transitionLockHeld = FALSE;
    BOOLEAN cr4Changed = FALSE;

    /* Validate the fixed launch contract before allocating nonpaged stacks. */
    if (Input == NULL ||
        Result == NULL ||
        Input->TransitionLock == NULL ||
        Input->PowerTransitionPending == NULL ||
        Input->PowerTransitionGeneration == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Start with deterministic diagnostics even when allocation fails. */
    RtlZeroMemory(Result, sizeof(*Result));
    /* Use 0xFF to distinguish an instruction that was never attempted. */
    Result->VmxInstructionResult = 0xFFU;
    /* Allocate a private non-executable stack for the controlled guest. */
    guestStack = KswordARKAllocateNonPagedPool(
        KSW_HVM_GUEST_STACK_BYTES,
        KSW_HVM_GUEST_POOL_TAG);
    /* Allocate a separate stack used only by the VM-exit entry path. */
    hostStack = KswordARKAllocateNonPagedPool(
        KSW_HVM_HOST_STACK_BYTES,
        KSW_HVM_GUEST_POOL_TAG);
    /* Fail before affinity changes when either bounded stack is unavailable. */
    if (guestStack == NULL || hostStack == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Complete;
    }
    /* Remove stale data from both stacks before VM-entry state references them. */
    RtlZeroMemory(guestStack, KSW_HVM_GUEST_STACK_BYTES);
    /* Remove stale data from the dedicated host-exit stack. */
    RtlZeroMemory(hostStack, KSW_HVM_HOST_STACK_BYTES);

    /* Bind the launch thread to the exact VMX resource-owning processor. */
    targetAffinity.Group = Input->ProcessorGroup;
    /* Build the single-processor affinity mask without narrowing. */
    targetAffinity.Mask =
        ((KAFFINITY)1) << Input->ProcessorNumber;
    /* Apply the group affinity and retain the caller's original affinity. */
    KeSetSystemGroupAffinityThread(
        &targetAffinity,
        &oldAffinity);
    /* Record the affinity transition for symmetric cleanup. */
    affinitySet = TRUE;
    /* Serialize the nonallocating VMX window against system power transition. */
    KeAcquireSpinLock(Input->TransitionLock, &oldIrql);
    transitionLockHeld = TRUE;

    /* Protect privileged state transitions from virtual-CPU exceptions. */
    __try {
        /* A leaving-S0 callback always wins before any new VMXON. */
        if (InterlockedCompareExchange(
                Input->PowerTransitionPending,
                0L,
                0L) != 0L ||
            InterlockedCompareExchange(
                Input->PowerTransitionGeneration,
                0L,
                0L) != Input->ExpectedPowerTransitionGeneration) {
            status = STATUS_POWER_STATE_INVALID;
            __leave;
        }
        /* Capture CR0 before checking fixed-bit compatibility. */
        originalCr0 = __readcr0();
        /* Capture CR4 for both conflict detection and exact restoration. */
        context.OriginalCr4 = __readcr4();
        /* Calculate the architecturally required CR0 without changing it. */
        requiredCr0 =
            (originalCr0 | Input->Cr0Fixed0) &
            Input->Cr0Fixed1;
        /* Calculate VMX-root CR4 while preserving every active host feature. */
        requiredCr4 =
            ((context.OriginalCr4 | Input->Cr4Fixed0) &
                Input->Cr4Fixed1) |
            KSW_HVM_CR4_VMXE;
        /*
         * Refuse to steal an existing VMX root, alter CR0, or clear an active
         * CR4 feature merely to make the controlled launch pass.
         */
        if ((context.OriginalCr4 & KSW_HVM_CR4_VMXE) != 0ULL ||
            requiredCr0 != originalCr0 ||
            (requiredCr4 & context.OriginalCr4) != context.OriginalCr4) {
            status = STATUS_CONFLICTING_ADDRESSES;
            __leave;
        }

        /* Enable VMX instructions on the selected logical processor. */
        __writecr4(requiredCr4);
        /* Record the CR4 transition for symmetric cleanup. */
        cr4Changed = TRUE;
        /* Copy the VMXON region physical address into intrinsic storage. */
        vmxonPhysical =
            (unsigned __int64)Input->VmxonPhysical.QuadPart;
        /* Enter VMX root using the processor-specific VMXON region. */
        vmxResult = __vmx_on(&vmxonPhysical);
        /* Preserve the exact VMX instruction result for UI diagnostics. */
        context.Result.VmxInstructionResult = vmxResult;
        /* Stop when VMXON fails validly or invalidly. */
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }
        /* Record active VMX ownership before any later fallible instruction. */
        InterlockedExchange(&context.VmxActive, 1L);
        /* Copy the VMCS physical address for launch and exit cleanup. */
        context.VmcsPhysical =
            (unsigned __int64)Input->VmcsPhysical.QuadPart;
        /* Clear the VMCS launch state before making it current. */
        vmxResult = __vmx_vmclear(&context.VmcsPhysical);
        /* Preserve a failed VMCLEAR result. */
        context.Result.VmxInstructionResult = vmxResult;
        /* Stop when the VMCS cannot be cleared. */
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }
        /* Load the processor-specific VMCS as current. */
        vmxResult = __vmx_vmptrld(&context.VmcsPhysical);
        /* Preserve a failed VMPTRLD result. */
        context.Result.VmxInstructionResult = vmxResult;
        /* Stop when the VMCS cannot be made current. */
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }
        /* Publish current-VMCS evidence to the runtime result. */
        context.Result.VmcsLoaded = 1U;

        /* Copy immutable capability and EPT inputs into the VMCS builder. */
        vmcsInput.VmxBasic = Input->VmxBasic;
        /* Copy CR0 fixed-zero requirements into the VMCS builder. */
        vmcsInput.Cr0Fixed0 = Input->Cr0Fixed0;
        /* Copy CR0 fixed-one permissions into the VMCS builder. */
        vmcsInput.Cr0Fixed1 = Input->Cr0Fixed1;
        /* Copy CR4 fixed-zero requirements into the VMCS builder. */
        vmcsInput.Cr4Fixed0 = Input->Cr4Fixed0;
        /* Copy CR4 fixed-one permissions into the VMCS builder. */
        vmcsInput.Cr4Fixed1 = Input->Cr4Fixed1;
        /* Reference the prebuilt identity-mapped EPT hierarchy. */
        vmcsInput.EptPointer = Input->EptPointer;
        /* Align the guest stack top to the x64 ABI boundary. */
        vmcsInput.GuestStackPointer =
            ((ULONGLONG)(ULONG_PTR)guestStack +
                KSW_HVM_GUEST_STACK_BYTES) &
            ~0xFULL;
        /* Align the VM-exit stack top before its assembly entry reserves home space. */
        vmcsInput.HostStackPointer =
            ((ULONGLONG)(ULONG_PTR)hostStack +
                KSW_HVM_HOST_STACK_BYTES) &
            ~0xFULL;
        /* Enter the fixed assembly stub that immediately executes VMCALL. */
        vmcsInput.GuestInstructionPointer =
            (ULONGLONG)(ULONG_PTR)KswordARKHvmControlledGuestEntry;
        /* Route every VM exit through the non-returning assembly entry. */
        vmcsInput.HostInstructionPointer =
            (ULONGLONG)(ULONG_PTR)KswordARKHvmVmExitEntry;
        /* Program the complete VMCS before publishing the active context. */
        status = KswordARKHvmConfigureVmcs(
            &vmcsInput,
            &context.Result.VmInstructionError);
        /* Stop when any control or state field is rejected. */
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        /* Claim the single active launch slot before entering the assembly wrapper. */
        if (InterlockedCompareExchangePointer(
                (PVOID volatile*)&g_KswordHvmActiveGuest,
                &context,
                NULL) != NULL) {
            status = STATUS_DEVICE_BUSY;
            __leave;
        }
        /* Attempt VM entry while preserving an assembly-level return stack. */
        vmxResult = KswordARKHvmAsmLaunch(&context);
        /* Preserve the wrapper's VM-entry result for protocol diagnostics. */
        context.Result.VmxInstructionResult = vmxResult;
        /* A handled VM exit returns through the saved wrapper stack with zero. */
        if (context.Result.VmExitHandled != 0U) {
            status = context.ExitStatus;
            __leave;
        }

        /* Read VMfailValid detail while the failed VMCS remains current. */
        if (vmxResult == 1U) {
            SIZE_T instructionError = 0U;

            /* Preserve the VM-instruction error when VMREAD succeeds. */
            if (__vmx_vmread(
                    KSW_HVM_VMCS_INSTRUCTION_ERROR,
                    &instructionError) == 0U) {
                context.Result.VmInstructionError =
                    (ULONG)instructionError;
            }
        }
        /* Any direct return from VMLAUNCH is a failed controlled launch. */
        status = STATUS_HV_OPERATION_FAILED;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve the privileged exception as the authoritative failure. */
        status = GetExceptionCode();
    }

    /* Remove a launch slot that failed before the exit dispatcher cleared it. */
    KswordARKHvmClearActiveGuest(&context);
    /* Leave VMX root on every failure path that still owns it. */
    if (InterlockedCompareExchange(
            &context.VmxActive,
            0L,
            0L) != 0L) {
        /* Reset the VMCS launch state before VMXOFF when possible. */
        (void)__vmx_vmclear(&context.VmcsPhysical);
        /* Leave VMX operation before restoring CR4. */
        __vmx_off();
        /* Publish completed VMX cleanup. */
        InterlockedExchange(&context.VmxActive, 0L);
    }
    /* Restore CR4 only after VMX operation has ended. */
    if (cr4Changed &&
        InterlockedCompareExchange(
            &context.Cr4Restored,
            0L,
            0L) == 0L) {
        __try {
            /* Restore the exact control-register value captured before VMXON. */
            __writecr4(context.OriginalCr4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Preserve restoration failure over an earlier result. */
            status = GetExceptionCode();
        }
    }

Complete:
    /* Reopen the power callback only after privileged cleanup is complete. */
    if (transitionLockHeld) {
        KeReleaseSpinLock(Input->TransitionLock, oldIrql);
    }
    /* Restore the caller's group affinity after returning to passive migration. */
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }
    /* Release the private guest stack after no VMCS references it. */
    if (guestStack != NULL) {
        ExFreePool(guestStack);
    }
    /* Release the private VM-exit stack after the continuation is restored. */
    if (hostStack != NULL) {
        ExFreePool(hostStack);
    }
    /* Publish the authoritative operation status in both channels. */
    context.Result.Status = status;
    /* Copy the complete result only after all cleanup is finished. */
    *Result = context.Result;
    return status;
}

#else

NTSTATUS
KswordARKHvmLaunchControlledGuest(
    _In_ const KSW_HVM_GUEST_LAUNCH_INPUT* Input,
    _Out_ KSW_HVM_GUEST_LAUNCH_RESULT* Result
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Input);
    /* Clear a supplied result before returning the architecture boundary. */
    if (Result != NULL) {
        RtlZeroMemory(Result, sizeof(*Result));
        Result->Status = STATUS_NOT_SUPPORTED;
        Result->VmxInstructionResult = 0xFFU;
    }
    return STATUS_NOT_SUPPORTED;
}

PVOID
KswordARKHvmVmExitDispatch(
    VOID
    )
{
    /* The non-x64 project excludes the assembly entry, so this is unreachable. */
    KeBugCheckEx(
        0x00020001UL,
        (ULONG_PTR)0x48564D03UL,
        0U,
        0U,
        0U);
}

#endif
