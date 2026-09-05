/*++

Module Name:

    hvm_exit.c

Abstract:

    Dispatches resident VM exits without allocation or waiting, records bounded
    evidence, restores allow-once EPT rules, and devirtualizes on unknown exits.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_exit.h"
#include "hvm_exit_emulate.h"
#include "hvm_cr_policy.h"
#include "hvm_ept_view.h"
#include "hvm_msr_policy.h"
#include "hvm_resident.h"
#include "hvm_ept.h"
#include "hvm_event.h"
#include "hvm_nested.h"
#include "hvm_vmcs.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the VMCS primary processor-based controls field. */
#define KSW_VMCS_PRIMARY_CONTROLS 0x4002UL
/* Name the VMCS VM-exit reason field through shared telemetry. */
#define KSW_VMCS_GUEST_PHYSICAL_ADDRESS 0x2400UL
/* Name the VMCS guest linear address field. */
#define KSW_VMCS_GUEST_LINEAR_ADDRESS 0x640AUL
/* Name the VMCS guest instruction pointer field. */
#define KSW_VMCS_GUEST_RIP 0x681EUL

/* Identify the monitor-trap flag execution control. */
#define KSW_VMX_PRIMARY_MONITOR_TRAP_FLAG (1UL << 27)

/* Name architecturally common VM-exit reasons. */
#define KSW_VMX_EXIT_EXCEPTION_OR_NMI 0UL
/* Name the external-interrupt VM-exit reason. */
#define KSW_VMX_EXIT_EXTERNAL_INTERRUPT 1UL
/* Name the CPUID VM-exit reason. */
#define KSW_VMX_EXIT_CPUID 10UL
/* Name the HLT VM-exit reason. */
#define KSW_VMX_EXIT_HLT 12UL
/* Name the VMCALL VM-exit reason. */
#define KSW_VMX_EXIT_VMCALL 18UL
/* Name the VMFUNC VM-exit reason, taken only when the function fails. */
#define KSW_VMX_EXIT_VMFUNC 59UL
/* Name the INVD VM-exit reason, which no execution control can suppress. */
#define KSW_VMX_EXIT_INVD 13UL
/* Name the RDMSR VM-exit reason. */
#define KSW_VMX_EXIT_RDMSR 31UL
/* Name the WRMSR VM-exit reason. */
#define KSW_VMX_EXIT_WRMSR 32UL
/* Name the XSETBV VM-exit reason, which no execution control can suppress. */
#define KSW_VMX_EXIT_XSETBV 55UL
/* Name the MOV-CR VM-exit reason, reached only for masked bits. */
#define KSW_VMX_EXIT_MOV_CR 28UL
/* Name the MOV-DR VM-exit reason, reached only when interception is on. */
#define KSW_VMX_EXIT_MOV_DR 29UL
/* Name the monitor-trap VM-exit reason. */
#define KSW_VMX_EXIT_MONITOR_TRAP 37UL
/* Name the EPT-violation VM-exit reason. */
#define KSW_VMX_EXIT_EPT_VIOLATION 48UL
/* Name the EPT-misconfiguration VM-exit reason. */
#define KSW_VMX_EXIT_EPT_MISCONFIGURATION 49UL

/* Identify the first and last VMX instruction exit reasons in the base block. */
#define KSW_VMX_EXIT_VMCLEAR 19UL
/* Identify the last base VMX instruction exit reason. */
#define KSW_VMX_EXIT_VMXON 27UL
/* Identify INVEPT as a nested VMX instruction exit. */
#define KSW_VMX_EXIT_INVEPT 50UL
/* Identify INVVPID as a nested VMX instruction exit. */
#define KSW_VMX_EXIT_INVVPID 53UL

/* Advance guest RIP after one completely decoded exit instruction. */
static BOOLEAN
KswordARKHvmExitAdvanceRip(
    _In_ ULONG InstructionLength
    )
{
    SIZE_T guestRip = 0U;

    /* Require one architecturally valid instruction length. */
    if (InstructionLength == 0UL ||
        InstructionLength > 15UL) {
        /* Report that no safe guest continuation was written. */
        return FALSE;
    }
    /* Read the current guest instruction pointer. */
    if (__vmx_vmread(
            KSW_VMCS_GUEST_RIP,
            &guestRip) != 0U) {
        /* Report VMREAD failure to the dispatcher. */
        return FALSE;
    }
    /* Reject pointer addition overflow before advancing. */
    if (guestRip > MAXULONG_PTR - InstructionLength) {
        /* Report an unsafe guest continuation. */
        return FALSE;
    }
    /* Advance to the instruction following the intercepted operation. */
    guestRip += InstructionLength;
    /* Write the complete guest instruction continuation. */
    return __vmx_vmwrite(
        KSW_VMCS_GUEST_RIP,
        guestRip) == 0U;
}

/* Enable or disable monitor-trap exit in the current VMCS. */
static BOOLEAN
KswordARKHvmExitSetMonitorTrap(
    _In_ BOOLEAN Enabled
    )
{
    SIZE_T controls = 0U;

    /* Read the current primary processor-based controls. */
    if (__vmx_vmread(
            KSW_VMCS_PRIMARY_CONTROLS,
            &controls) != 0U) {
        /* Report VMREAD failure to the dispatcher. */
        return FALSE;
    }
    /* Set the monitor-trap flag for one allow-once instruction. */
    if (Enabled) {
        /* Enable the monitor-trap execution control. */
        controls |=
            (SIZE_T)KSW_VMX_PRIMARY_MONITOR_TRAP_FLAG;
    } else {
        /* Disable monitor-trap after restoring EPT permissions. */
        controls &=
            ~(SIZE_T)KSW_VMX_PRIMARY_MONITOR_TRAP_FLAG;
    }
    /* Write the complete updated primary controls. */
    return __vmx_vmwrite(
        KSW_VMCS_PRIMARY_CONTROLS,
        controls) == 0U;
}

/* Convert EPT qualification bits to the public access mask. */
static ULONG
KswordARKHvmExitDecodeEptAccess(
    _In_ ULONGLONG Qualification
    )
{
    ULONG access = 0UL;

    /* Decode an attempted data read. */
    if ((Qualification & (1ULL << 0)) != 0ULL) {
        /* Publish protocol-visible read access. */
        access |= KSWORD_ARK_HVM_EPT_ACCESS_READ;
    }
    /* Decode an attempted data write. */
    if ((Qualification & (1ULL << 1)) != 0ULL) {
        /* Publish protocol-visible write access. */
        access |= KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
    }
    /* Decode an attempted instruction fetch. */
    if ((Qualification & (1ULL << 2)) != 0ULL) {
        /* Publish protocol-visible execute access. */
        access |= KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
    }
    /* Return the complete attempted-access mask. */
    return access;
}

/* Capture optional guest physical and linear addresses for exit evidence. */
static VOID
KswordARKHvmExitReadAddresses(
    _Out_ ULONGLONG* GuestPhysicalAddress,
    _Out_ ULONGLONG* GuestLinearAddress
    )
{
    SIZE_T guestPhysical = 0U;
    SIZE_T guestLinear = 0U;

    /* Reject either missing fixed output pointer. */
    if (GuestPhysicalAddress == NULL ||
        GuestLinearAddress == NULL) {
        /* Return without publishing a partial address pair. */
        return;
    }
    /* Publish zero defaults before optional VMREAD operations. */
    *GuestPhysicalAddress = 0ULL;
    /* Publish the zero guest-linear default. */
    *GuestLinearAddress = 0ULL;
    /* Preserve guest physical address only when VMREAD succeeds. */
    if (__vmx_vmread(
            KSW_VMCS_GUEST_PHYSICAL_ADDRESS,
            &guestPhysical) == 0U) {
        /* Publish the complete guest physical address. */
        *GuestPhysicalAddress =
            (ULONGLONG)guestPhysical;
    }
    /* Preserve guest linear address only when VMREAD succeeds. */
    if (__vmx_vmread(
            KSW_VMCS_GUEST_LINEAR_ADDRESS,
            &guestLinear) == 0U) {
        /* Publish the complete guest linear address. */
        *GuestLinearAddress =
            (ULONGLONG)guestLinear;
    }
}

/* Publish one fixed VM-exit event and runtime snapshot. */
static VOID
KswordARKHvmExitPublishTelemetry(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _In_ const KSW_HVM_VMEXIT_TELEMETRY* Telemetry,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONGLONG GuestLinearAddress,
    _In_ ULONG EventType,
    _In_ ULONG Access,
    _In_ ULONG RuleId,
    _In_ NTSTATUS Status
    )
{
    KSWORD_ARK_HVM_EVENT_ROW eventRow = { 0 };
    ULONG basicReason = 0UL;

    /* Reject incomplete fixed telemetry state. */
    if (Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL ||
        Telemetry == NULL) {
        /* Return without publishing partial evidence. */
        return;
    }
    /* Decode the Intel basic reason for protocol state. */
    basicReason =
        Telemetry->Reason &
        KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    /* Increment the process-wide VM-exit count atomically. */
    InterlockedIncrement64(
        &Context->Runtime->VmExitCount);
    /* Publish the last exit qualification atomically. */
    InterlockedExchange64(
        &Context->Runtime->LastExitQualification,
        (LONG64)Telemetry->Qualification);
    /* Publish the last guest instruction pointer atomically. */
    InterlockedExchange64(
        &Context->Runtime->LastGuestRip,
        (LONG64)Telemetry->GuestRip);
    /* Publish the last guest stack pointer atomically. */
    InterlockedExchange64(
        &Context->Runtime->LastGuestRsp,
        (LONG64)Telemetry->GuestRsp);
    /* Publish the last basic exit reason atomically. */
    InterlockedExchange(
        &Context->Runtime->LastExitReason,
        (LONG)basicReason);
    /* Publish the last exit instruction length atomically. */
    InterlockedExchange(
        &Context->Runtime->LastExitInstructionLength,
        (LONG)Telemetry->InstructionLength);
    /* Publish the last VM-instruction error atomically. */
    InterlockedExchange(
        &Context->Runtime->LastVmInstructionError,
        (LONG)Telemetry->VmInstructionError);
    /* Increment the processor-local VM-exit count atomically. */
    InterlockedIncrement64(
        (volatile LONG64*)&Context->Resource->
            Row.vmExitCount);
    /* Publish the processor-local last exit reason. */
    Context->Resource->Row.lastExitReason =
        basicReason;
    /* Publish the processor-local nested state. */
    Context->Resource->Row.nestedState =
        Context->Nested.State;
    /* Publish the processor-local eVMCS version evidence. */
    Context->Resource->Row.evmcsVersion =
        Context->Runtime->EvmcsVersion;
    /* Preserve the exact group identity in the event row. */
    eventRow.processorGroup =
        Context->Resource->Row.processorGroup;
    /* Preserve the exact group-relative processor number. */
    eventRow.processorNumber =
        Context->Resource->Row.processorNumber;
    /* Preserve the selected event classification. */
    eventRow.type = EventType;
    /* Preserve the Intel basic exit reason. */
    eventRow.exitReason = basicReason;
    /* Preserve the attempted EPT access mask. */
    eventRow.access = Access;
    /* Preserve the matching EPT rule identifier. */
    eventRow.ruleId = RuleId;
    /* Preserve the guest physical address when available. */
    eventRow.guestPhysicalAddress =
        GuestPhysicalAddress;
    /* Preserve the guest linear address when available. */
    eventRow.guestLinearAddress =
        GuestLinearAddress;
    /* Preserve the guest instruction pointer. */
    eventRow.guestRip = Telemetry->GuestRip;
    /* Preserve the complete exit qualification. */
    eventRow.qualification =
        Telemetry->Qualification;
    /* Preserve the authoritative dispatch status. */
    eventRow.status = Status;
    /* Publish the complete nonblocking event row. */
    KswordARKHvmEventPublish(&eventRow);
    /* Publish protocol-visible event availability. */
    InterlockedOr(
        (volatile LONG*)&Context->Runtime->StateFlags,
        (LONG)KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE);
}

/* Emulate one CPUID exit and preserve nested-exposure policy. */
static BOOLEAN
KswordARKHvmExitHandleCpuid(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG InstructionLength
    )
{
    int registers[4] = { 0 };
    ULONG leaf = (ULONG)Frame->Rax;
    ULONG subleaf = (ULONG)Frame->Rcx;

    /* Execute the exact host CPUID leaf and subleaf. */
    __cpuidex(
        registers,
        (int)leaf,
        (int)subleaf);
    /* Hide guest VMX exposure unless nested dispatch was explicitly enabled. */
    if (leaf == 1UL &&
        !Context->Nested.Enabled) {
        /* Clear the VMX capability bit in guest CPUID.1:ECX. */
        registers[2] &= ~(1L << 5);
    }
    /* Publish zero-extended guest RAX. */
    Frame->Rax = (ULONG)registers[0];
    /* Publish zero-extended guest RBX. */
    Frame->Rbx = (ULONG)registers[1];
    /* Publish zero-extended guest RCX. */
    Frame->Rcx = (ULONG)registers[2];
    /* Publish zero-extended guest RDX. */
    Frame->Rdx = (ULONG)registers[3];
    /* Advance past the fully decoded CPUID instruction. */
    return KswordARKHvmExitAdvanceRip(
        InstructionLength);
}

/* Return whether one exit reason belongs to nested VMX instruction dispatch. */
static BOOLEAN
KswordARKHvmExitIsNestedInstruction(
    _In_ ULONG ExitReason
    )
{
    /* Accept the contiguous VMCLEAR through VMXON reason block. */
    if (ExitReason >= KSW_VMX_EXIT_VMCLEAR &&
        ExitReason <= KSW_VMX_EXIT_VMXON) {
        /* Report a base nested VMX instruction exit. */
        return TRUE;
    }
    /* Accept invalidation instructions that live outside the base block. */
    return ExitReason == KSW_VMX_EXIT_INVEPT ||
        ExitReason == KSW_VMX_EXIT_INVVPID;
}

ULONG
KswordARKHvmResidentVmExitDispatch(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context
    )
{
    KSW_HVM_VMEXIT_TELEMETRY telemetry = { 0 };
    ULONGLONG guestPhysicalAddress = 0ULL;
    ULONGLONG guestLinearAddress = 0ULL;
    ULONG basicReason = KSWORD_ARK_HVM_EXIT_REASON_NONE;
    ULONG access = 0UL;
    ULONG ruleId = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG eptDisposition = KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE;
    BOOLEAN handled = FALSE;
    BOOLEAN injectFault = FALSE;
    BOOLEAN guestLinearValid = FALSE;

    /* Reject a VM exit without an exact active processor context. */
    if (Frame == NULL ||
        Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL ||
        InterlockedCompareExchange(
            &Context->Active,
            0L,
            0L) == 0L) {
        /* Request a bounded fatal trap with no unsafe continuation. */
        return KSW_HVM_EXIT_ACTION_FATAL;
    }
    /* Capture protocol-visible VMCS exit telemetry. */
    status = KswordARKHvmReadVmExitTelemetry(
        &telemetry);
    /* Stop when the current VMCS cannot be inspected safely. */
    if (!NT_SUCCESS(status)) {
        /* Attempt devirtualization without advancing an unknown instruction. */
        handled = KswordARKHvmResidentDeactivateCurrent(
            Context,
            0UL,
            TRUE);
        /* Return only a verified guest continuation. */
        return handled
            ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
            : KSW_HVM_EXIT_ACTION_FATAL;
    }
    /* Decode the Intel basic VM-exit reason. */
    basicReason =
        telemetry.Reason &
        KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    /* Read address fields only for exits where Intel defines their content. */
    if (basicReason == KSW_VMX_EXIT_EPT_VIOLATION ||
        basicReason == KSW_VMX_EXIT_EPT_MISCONFIGURATION) {
        /* Capture EPT guest-physical and optional guest-linear evidence. */
        KswordARKHvmExitReadAddresses(
            &guestPhysicalAddress,
            &guestLinearAddress);
        /* Retain GLA only when EPT-violation qualification marks it valid. */
        if (basicReason != KSW_VMX_EXIT_EPT_VIOLATION ||
            (telemetry.Qualification & (1ULL << 7)) == 0ULL) {
            /* Clear architecturally unavailable guest-linear evidence. */
            guestLinearAddress = 0ULL;
        } else {
            /*
             * Record validity separately: a reported guest-linear address of
             * zero is legitimate, so the value alone cannot stand in for the
             * qualification bit that says the CPU supplied one.
             */
            guestLinearValid = TRUE;
        }
    }
    /* Emulate ordinary CPUID and continue the resident guest. */
    if (basicReason == KSW_VMX_EXIT_CPUID) {
        /* Execute CPUID under explicit nested-exposure policy. */
        handled = KswordARKHvmExitHandleCpuid(
            Context,
            Frame,
            telemetry.InstructionLength);
    /* Dispatch KSword-private lifecycle VMCALLs. */
    } else if (basicReason == KSW_VMX_EXIT_VMCALL &&
               Frame->Rax ==
                    KSW_HVM_HYPERCALL_SIGNATURE) {
        /* Complete a private stop by leaving VMX operation. */
        if (Frame->Rcx == KSW_HVM_HYPERCALL_STOP) {
            /* Publish successful private hypercall return value. */
            Frame->Rax = 0ULL;
            /* Devirtualize and continue after the exact VMCALL. */
            handled = KswordARKHvmResidentDeactivateCurrent(
                Context,
                telemetry.InstructionLength,
                FALSE);
            /* Publish the final VM-exit event before changing stacks. */
            KswordARKHvmExitPublishTelemetry(
                Context,
                &telemetry,
                guestPhysicalAddress,
                guestLinearAddress,
                KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE,
                0UL,
                0UL,
                handled
                    ? STATUS_SUCCESS
                    : STATUS_HV_OPERATION_FAILED);
            /* Return only a verified guest continuation. */
            return handled
                ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
                : KSW_HVM_EXIT_ACTION_FATAL;
        /* Execute one current-context INVEPT in VMX root. */
        } else if (Frame->Rcx ==
            KSW_HVM_HYPERCALL_INVEPT) {
            /* Require the exact active EPT pointer identity. */
            if (Frame->Rdx !=
                    Context->Runtime->EptPointer) {
                /* Publish a failed private hypercall result. */
                Frame->Rax = 1ULL;
            } else {
                /* Execute single-context INVEPT in VMX root. */
                Frame->Rax =
                    KswordARKHvmAsmInveptSingle(
                        Frame->Rdx);
            }
            /* Advance past the fully decoded private VMCALL. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        /* Return current resident state without mutation. */
        } else if (Frame->Rcx ==
            KSW_HVM_HYPERCALL_QUERY) {
            /* Return one for active resident state. */
            Frame->Rax = 1ULL;
            /* Advance past the fully decoded private VMCALL. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        } else {
            /*
             * Report an unknown private command through the return register
             * instead of tearing down residency, so a future protocol version
             * can probe this dispatcher without disabling the hypervisor.
             */
            Frame->Rax = MAXULONGLONG;
            /* Advance past the fully decoded private VMCALL. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Refuse every VMCALL that does not carry the private signature. */
    } else if (basicReason == KSW_VMX_EXIT_VMCALL) {
        /*
         * Without a hypervisor VMCALL raises #UD, so unrelated software that
         * probes for one must see the same result.  Devirtualizing here would
         * let any user-mode instruction dismantle the resident hypervisor.
         */
        handled = KswordARKHvmExitInjectUndefinedOpcode();
    /*
     * A VMFUNC exit means the function failed - a successful EPTP switch does
     * not exit at all.  Guest code reached here by naming an entry outside the
     * list or one holding an invalid pointer, so the architectural answer is
     * the same one it would get on a processor without VM functions.
     *
     * Not advancing RIP is deliberate: #UD is a fault, and a fault restarts
     * the instruction it reports rather than skipping it.
     */
    } else if (basicReason == KSW_VMX_EXIT_VMFUNC) {
        /* Deliver the architectural undefined-opcode fault to the guest. */
        handled = KswordARKHvmExitInjectUndefinedOpcode();
    /* Complete the unconditional INVD exit without dropping modified lines. */
    } else if (basicReason == KSW_VMX_EXIT_INVD) {
        /* Write back and invalidate instead of discarding host cache lines. */
        handled = KswordARKHvmExitEmulateInvd();
        /* Advance only after the substituted instruction fully completed. */
        if (handled) {
            /* Continue at the instruction following INVD. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Apply one validated XSETBV or deliver its architectural fault. */
    } else if (basicReason == KSW_VMX_EXIT_XSETBV) {
        /* Validate every operand before touching XCR0 in VMX root. */
        handled = KswordARKHvmExitEmulateXsetbv(
            Frame,
            &injectFault);
        /* Advance only after the extended-state mask was actually applied. */
        if (handled) {
            /* Continue at the instruction following XSETBV. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        } else if (injectFault) {
            /* Restart the instruction after the guest takes #GP. */
            handled = KswordARKHvmExitInjectGeneralProtection();
        }
    /* Resolve MSR access the bitmap deliberately let exit. */
    } else if (basicReason == KSW_VMX_EXIT_RDMSR ||
               basicReason == KSW_VMX_EXIT_WRMSR) {
        const BOOLEAN isWrite =
            (BOOLEAN)(basicReason == KSW_VMX_EXIT_WRMSR);
        /*
         * An index inside the bitmap only exits because a policy opened a hole
         * for it, so the policy engine gets first refusal.  Anything it does
         * not claim fell outside the bitmap entirely.
         */
        const ULONG policyResult = KswordARKHvmMsrPolicyApply(
            Context->Runtime,
            Frame,
            isWrite);

        if (policyResult == KSW_HVM_MSR_POLICY_RESULT_HANDLED) {
            /* Continue at the instruction following the MSR access. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        } else if (policyResult ==
            KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT) {
            /* Restart the instruction after the guest takes #GP. */
            handled = KswordARKHvmExitInjectGeneralProtection();
        } else {
            /* Classify the index against the architectural bitmap coverage. */
            handled = KswordARKHvmExitEmulateMsr(
                Frame,
                isWrite,
                &injectFault);
            /* Advance only after a complete emulation wrote every result. */
            if (handled) {
                /* Continue at the instruction following the MSR access. */
                handled = KswordARKHvmExitAdvanceRip(
                    telemetry.InstructionLength);
            } else if (injectFault) {
                /* Restart the instruction after the guest takes #GP. */
                handled = KswordARKHvmExitInjectGeneralProtection();
            }
        }
    /* Apply control-register policy to a masked bit or a tracked CR3 load. */
    } else if (basicReason == KSW_VMX_EXIT_MOV_CR) {
        /* Merge the write against the pinned bits, or replay a CR3 access. */
        handled = KswordARKHvmCrPolicyHandleControlRegister(
            Context->Runtime,
            Frame,
            telemetry.Qualification);
        /* Advance only after the register state was completely written. */
        if (handled) {
            /* Continue at the instruction following the MOV. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Record and replay one intercepted debug-register access. */
    } else if (basicReason == KSW_VMX_EXIT_MOV_DR) {
        /* Observation only: the access is replayed unchanged. */
        handled = KswordARKHvmCrPolicyHandleDebugRegister(
            Context->Runtime,
            Frame,
            telemetry.Qualification);
        /* Advance only after the register state was completely written. */
        if (handled) {
            /* Continue at the instruction following the MOV. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Restore allow-once EPT permissions after one guest instruction. */
    } else if (basicReason ==
        KSW_VMX_EXIT_MONITOR_TRAP) {
        /* Restore and invalidate the exact restricted EPT entry. */
        handled = KswordARKHvmEptHandleMonitorTrap(
            Context->Runtime,
            &Context->EptTransient);
        /* Disable monitor-trap only after restoration is proven complete. */
        if (handled) {
            /* Return to ordinary execution controls after the one-shot step. */
            handled = KswordARKHvmExitSetMonitorTrap(
                FALSE);
        }
    /* Apply one bounded EPT violation rule. */
    } else if (basicReason ==
        KSW_VMX_EXIT_EPT_VIOLATION) {
        /* Decode attempted read, write, and execute access. */
        access = KswordARKHvmExitDecodeEptAccess(
            telemetry.Qualification);
        /*
         * Views own their leaf exclusively, so a page covered by one never
         * reaches the rule backend.  A view match that could not be completed
         * returns its identity with a false result, which must fail closed
         * rather than fall through to a rule scan of the same page.
         */
        handled = KswordARKHvmEptViewHandleViolation(
            Context->Runtime,
            guestPhysicalAddress,
            access,
            &Context->EptTransient,
            &ruleId);
        if (handled) {
            /* Restore the primary view value after one instruction. */
            handled = KswordARKHvmExitSetMonitorTrap(TRUE);
            /* Publish the complete exit evidence before resuming. */
            KswordARKHvmExitPublishTelemetry(
                Context,
                &telemetry,
                guestPhysicalAddress,
                guestLinearAddress,
                KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION,
                access,
                ruleId,
                handled
                    ? STATUS_SUCCESS
                    : STATUS_NOT_SUPPORTED);
            /* Resume only after the restoration step is actually armed. */
            if (handled) {
                /* Request VMRESUME with the flipped leaf in place. */
                return KSW_HVM_EXIT_ACTION_RESUME;
            }
            /* Fall through to the shared fail-closed rollback below. */
            handled = KswordARKHvmResidentDeactivateCurrent(
                Context,
                0UL,
                TRUE);
            /* Return only a verified guest continuation. */
            return handled
                ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
                : KSW_HVM_EXIT_ACTION_FATAL;
        }
        /* Resolve the violation against every rule covering this page. */
        handled = ruleId != 0UL
            ? FALSE
            : KswordARKHvmEptHandleViolation(
                Context->Runtime,
                guestPhysicalAddress,
                access,
                guestLinearValid,
                &Context->EptTransient,
                &ruleId,
                &eptDisposition);
        /* Complete the disposition the rule aggregation selected. */
        if (handled) {
            if (eptDisposition ==
                KSW_HVM_EPT_DISPOSITION_INJECT_FAULT) {
                /*
                 * Durable denial: the guest takes a page fault at the address
                 * it touched and residency continues.  Nothing was granted,
                 * so no monitor-trap step is needed.
                 */
                handled = KswordARKHvmExitInjectPageFault(
                    guestLinearAddress,
                    access);
            } else {
                /* Arm one-instruction permission restoration. */
                handled = KswordARKHvmExitSetMonitorTrap(
                    TRUE);
            }
        }
    /* Dispatch bounded VMX instruction semantics without claiming L2 active. */
    } else if (KswordARKHvmExitIsNestedInstruction(
        basicReason)) {
        /* Execute the explicit partial vmcs12 state machine. */
        handled = KswordARKHvmNestedHandleExit(
            Context->Runtime,
            &Context->Nested,
            Frame,
            basicReason,
            telemetry.InstructionLength);
        /* Publish the latest nested state to the processor row. */
        Context->Resource->Row.nestedState =
            Context->Nested.State;
        /*
         * A refused VMX instruction must not cost us the hypervisor.  Falling
         * through to the fail-closed path would mean any guest that sets
         * CR4.VMXE and issues one VMX instruction tears the VMM down - and a
         * guest running WSL2 or a virtual machine does exactly that.
         *
         * #UD is also what the guest should architecturally receive: outside
         * nested dispatch its CPUID reports no VMX and its CR4.VMXE is clear,
         * so a VMX instruction is undefined by definition.
         */
        if (!handled) {
            /* Refuse the instruction without leaving VMX operation. */
            handled = KswordARKHvmExitInjectUndefinedOpcode();
        }
    /* HLT should not exit in resident mode unless hardware forced the control. */
    } else if (basicReason == KSW_VMX_EXIT_HLT ||
               basicReason ==
                    KSW_VMX_EXIT_EXCEPTION_OR_NMI ||
               basicReason ==
                    KSW_VMX_EXIT_EXTERNAL_INTERRUPT ||
               basicReason ==
                    KSW_VMX_EXIT_EPT_MISCONFIGURATION) {
        /* Fail closed into devirtualization for unimplemented mandatory exits. */
        handled = FALSE;
    } else {
        /* Unknown exits retain evidence and fail closed into devirtualization. */
        handled = FALSE;
    }
    /* Publish the complete exit evidence before resume or devirtualization. */
    KswordARKHvmExitPublishTelemetry(
        Context,
        &telemetry,
        guestPhysicalAddress,
        guestLinearAddress,
        basicReason == KSW_VMX_EXIT_EPT_VIOLATION
            ? KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION
            : (KswordARKHvmExitIsNestedInstruction(
                    basicReason)
                ? KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX
                : KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT),
        access,
        ruleId,
        handled
            ? STATUS_SUCCESS
            : STATUS_NOT_SUPPORTED);
    /* Resume only exits whose complete semantics succeeded. */
    if (handled) {
        /* Request VMRESUME with the updated register frame and VMCS. */
        return KSW_HVM_EXIT_ACTION_RESUME;
    }
    /* Devirtualize unexpected or incomplete exits without advancing RIP. */
    handled = KswordARKHvmResidentDeactivateCurrent(
        Context,
        0UL,
        TRUE);
    /* Publish one explicit fatal-exit event after rollback preparation. */
    KswordARKHvmExitPublishTelemetry(
        Context,
        &telemetry,
        guestPhysicalAddress,
        guestLinearAddress,
        KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT,
        access,
        ruleId,
        handled
            ? STATUS_NOT_SUPPORTED
            : STATUS_HV_OPERATION_FAILED);
    /* Return only a verified guest continuation. */
    return handled
        ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
        : KSW_HVM_EXIT_ACTION_FATAL;
}

ULONG
KswordARKHvmResidentVmResumeFailure(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ UCHAR InstructionResult
    )
{
    BOOLEAN devirtualized = FALSE;

    /* Reject a missing processor context after VMRESUME failure. */
    if (Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL) {
        /* Request a bounded fatal trap with no unsafe continuation. */
        return KSW_HVM_EXIT_ACTION_FATAL;
    }
    /* Preserve the exact VMRESUME instruction result. */
    Context->Resource->Row.vmxInstructionResult =
        InstructionResult;
    /* Preserve the authoritative VMX operation failure. */
    Context->LastStatus =
        STATUS_HV_OPERATION_FAILED;
    /* Attempt devirtualization at the already advanced guest continuation. */
    devirtualized =
        KswordARKHvmResidentDeactivateCurrent(
            Context,
            0UL,
            TRUE);
    /* Return only a verified guest continuation. */
    return devirtualized
        ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
        : KSW_HVM_EXIT_ACTION_FATAL;
}

#else

ULONG
KswordARKHvmResidentVmExitDispatch(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Frame);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Context);
    /* Request a bounded fatal path on unsupported architectures. */
    return KSW_HVM_EXIT_ACTION_FATAL;
}

ULONG
KswordARKHvmResidentVmResumeFailure(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ UCHAR InstructionResult
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Context);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(InstructionResult);
    /* Request a bounded fatal path on unsupported architectures. */
    return KSW_HVM_EXIT_ACTION_FATAL;
}

#endif
