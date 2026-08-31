/*++

Module Name:

    hvm_resident.c

Abstract:

    Implements all-processor VMX entry, resident rollback, EPT invalidation,
    and exact guest continuations for the HVM protocol v3 lifecycle.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_resident.h"
#include "hvm_exit.h"
#include "hvm_event.h"
#include "hvm_vmcs.h"
#include "../../platform/pool_compat.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Tag resident VM-exit stacks in nonpaged pool diagnostics. */
#define KSW_HVM_RESIDENT_POOL_TAG 'rHvK'

/* Name the VMCS guest stack-pointer field. */
#define KSW_VMCS_GUEST_RSP 0x681CUL
/* Name the VMCS guest instruction-pointer field. */
#define KSW_VMCS_GUEST_RIP 0x681EUL
/* Name the VMCS guest RFLAGS field. */
#define KSW_VMCS_GUEST_RFLAGS 0x6820UL
/* Name the VMCS primary VM-exit controls field. */
#define KSW_VMCS_EXIT_CONTROLS 0x400CUL
/* Name the VMCS guest IA32_DEBUGCTL field. */
#define KSW_VMCS_GUEST_DEBUGCTL 0x2802UL
/* Name the VMCS guest PKRS field. */
#define KSW_VMCS_GUEST_PKRS 0x2818UL
/* Name the VMCS guest DR7 field. */
#define KSW_VMCS_GUEST_DR7 0x681AUL
/* Name the VMCS guest supervisor CET field. */
#define KSW_VMCS_GUEST_S_CET 0x6828UL
/* Name the VMCS guest shadow-stack pointer field. */
#define KSW_VMCS_GUEST_SSP 0x682AUL
/* Name the VMCS guest interrupt shadow-stack table field. */
#define KSW_VMCS_GUEST_INTERRUPT_SSP_TABLE 0x682CUL
/* Name the VMCS guest user-interrupt notification vector field. */
#define KSW_VMCS_GUEST_UINV 0x0814UL
/* Name the VMCS VM-instruction error field. */
#define KSW_VMCS_INSTRUCTION_ERROR 0x4400UL
/* FXSAVE64 in the VM-exit entry requires host CR0.TS to remain clear. */
#define KSW_HVM_CR0_TASK_SWITCHED (1ULL << 3)
/* Request VM-exit guest debug-state saving. */
#define KSW_HVM_EXIT_SAVE_DEBUG_CONTROLS (1UL << 2)
/* Request VM-exit UINV clearing. */
#define KSW_HVM_EXIT_CLEAR_UINV (1UL << 27)
/* Request VM-exit host CET-state loading. */
#define KSW_HVM_EXIT_LOAD_CET (1UL << 28)
/* Request VM-exit host PKRS loading. */
#define KSW_HVM_EXIT_LOAD_PKRS (1UL << 29)
/* Name the protection-key rights model-specific register. */
#define KSW_HVM_IA32_PKRS 0x6E1UL
/* Name the user-interrupt miscellaneous model-specific register. */
#define KSW_HVM_IA32_UINTR_MISC 0x988UL

/* Identify one all-processor resident start rendezvous. */
#define KSW_HVM_RENDEZVOUS_START 1UL
/* Identify one all-processor resident stop rendezvous. */
#define KSW_HVM_RENDEZVOUS_STOP 2UL
/* Identify one all-processor EPT invalidation rendezvous. */
#define KSW_HVM_RENDEZVOUS_INVEPT 3UL

/* Own fixed per-processor resident contexts and their lifetime. */
typedef struct _KSW_HVM_RESIDENT_STATE
{
    /* Publish whether host-stack contexts have been prepared. */
    BOOLEAN Prepared;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Preserve the number of prepared per-processor contexts. */
    ULONG ProcessorCount;
    /* Preserve the start flags used to configure nested dispatch. */
    ULONG Flags;
    /* Reference the runtime whose pages remain resident. */
    KSW_HVM_RUNTIME* Runtime;
    /* Own every bounded per-processor resident context. */
    KSW_HVM_RESIDENT_VCPU Processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
} KSW_HVM_RESIDENT_STATE;

/* Share one fixed operation across an IPI rendezvous. */
typedef struct _KSW_HVM_RENDEZVOUS
{
    /* Select the start, stop, or invalidation operation. */
    ULONG Operation;
    /* Preserve the number of successful target processors. */
    volatile LONG SuccessCount;
    /* Preserve the number of failed or unrepresented processors. */
    volatile LONG FailureCount;
    /* Preserve the first authoritative failure. */
    volatile LONG FirstStatus;
    /* Preserve the EPT pointer used by invalidation hypercalls. */
    ULONGLONG EptPointer;
} KSW_HVM_RENDEZVOUS;

/* Own the process-wide resident contexts under the runtime lifecycle lock. */
static KSW_HVM_RESIDENT_STATE g_KswordHvmResident;

/* Keep assembly offsets synchronized with the resident context contract. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    LaunchStackPointer) == 0);
/* Keep the launch RFLAGS assembly offset synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    LaunchRflags) == 8);
/* Keep the devirtualization RSP assembly offset synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    DevirtualizeRsp) == 56);
/* Keep the devirtualization RIP assembly offset synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    DevirtualizeRip) == 64);
/* Keep the devirtualization RFLAGS assembly offset synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    DevirtualizeRflags) == 72);
/* Keep every assembly-restored extended-state offset synchronized. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_RESIDENT_VCPU, GuestSCet) == 80);
C_ASSERT(FIELD_OFFSET(KSW_HVM_RESIDENT_VCPU, GuestSsp) == 88);
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    GuestInterruptSspTable) == 96);
C_ASSERT(FIELD_OFFSET(KSW_HVM_RESIDENT_VCPU, GuestPkrs) == 104);
C_ASSERT(FIELD_OFFSET(KSW_HVM_RESIDENT_VCPU, GuestUinv) == 112);
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    GuestDebugControl) == 120);
C_ASSERT(FIELD_OFFSET(KSW_HVM_RESIDENT_VCPU, GuestDr7) == 128);
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    CetStateManaged) == 136);
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    DebugStateManaged) == 139);
/* Keep the FXSAVE64 assembly offset and alignment synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    FxState) == 144);
C_ASSERT((FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    FxState) & 0xFUL) == 0);
C_ASSERT(__alignof(KSW_HVM_RESIDENT_VCPU) >= 16);
C_ASSERT((FIELD_OFFSET(
    KSW_HVM_RESIDENT_STATE,
    Processors) & 0xFUL) == 0);
C_ASSERT(__alignof(KSW_HVM_RESIDENT_STATE) >= 16);
/* Keep the post-stack-switch active commit offset synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    Active) == 656);
/* Keep assembly-owned context pointers synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    Runtime) == 16);
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RESIDENT_VCPU,
    Resource) == 24);
/* Keep the final resident-count commit offset synchronized. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_RUNTIME,
    ResidentProcessorCount) == 40);
/* Keep the protocol row state offset synchronized with assembly. */
C_ASSERT(FIELD_OFFSET(
    KSW_HVM_CPU_RESOURCE,
    Row.stateFlags) == 4);

/* Record one rendezvous result without waiting or allocation. */
static VOID
KswordARKHvmResidentRecordResult(
    _Inout_ KSW_HVM_RENDEZVOUS* Rendezvous,
    _In_ NTSTATUS Status
    )
{
    /* Count one successful processor result. */
    if (NT_SUCCESS(Status)) {
        /* Publish one additional successful target. */
        InterlockedIncrement(&Rendezvous->SuccessCount);
    } else {
        /* Publish one additional failed target. */
        InterlockedIncrement(&Rendezvous->FailureCount);
        /* Preserve only the first authoritative failure. */
        (void)InterlockedCompareExchange(
            &Rendezvous->FirstStatus,
            Status,
            STATUS_SUCCESS);
    }
}

/* Return the resident context for one processor identity. */
static KSW_HVM_RESIDENT_VCPU*
KswordARKHvmResidentFindProcessor(
    _In_ USHORT ProcessorGroup,
    _In_ UCHAR ProcessorNumber
    )
{
    ULONG index = 0UL;

    /* Search only prepared bounded processor contexts. */
    for (index = 0UL;
         index < g_KswordHvmResident.ProcessorCount;
         ++index) {
        KSW_HVM_RESIDENT_VCPU* context =
            &g_KswordHvmResident.Processors[index];

        /* Match the exact group and group-relative processor number. */
        if (context->Resource != NULL &&
            context->Resource->Row.processorGroup ==
                ProcessorGroup &&
            context->Resource->Row.processorNumber ==
                ProcessorNumber) {
            /* Return the exact processor-owned resident context. */
            return context;
        }
    }
    /* Report a processor that exceeds the prepared protocol capacity. */
    return NULL;
}

KSW_HVM_RESIDENT_VCPU*
KswordARKHvmResidentFindCurrent(
    VOID
    )
{
    PROCESSOR_NUMBER processor = { 0 };

    /* Read the current group-aware processor identity. */
    KeGetCurrentProcessorNumberEx(&processor);
    /* Resolve the exact prepared resident context. */
    return KswordARKHvmResidentFindProcessor(
        processor.Group,
        processor.Number);
}

/* Release host stacks only after every processor has left VMX operation. */
static VOID
KswordARKHvmResidentReleaseContexts(
    VOID
    )
{
    ULONG index = 0UL;

    /* Preserve contexts while any processor remains resident. */
    if (g_KswordHvmResident.Runtime != NULL &&
        InterlockedCompareExchange(
            &g_KswordHvmResident.Runtime->
                ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /* Return without releasing a live VMCS host stack. */
        return;
    }
    /* Free every processor-owned host stack symmetrically. */
    for (index = 0UL;
         index < g_KswordHvmResident.ProcessorCount;
         ++index) {
        /* Release one nonpaged host stack when allocated. */
        if (g_KswordHvmResident.Processors[index].
                HostStack != NULL) {
            /* Free the exact processor-owned host stack. */
            ExFreePool(
                g_KswordHvmResident.Processors[index].
                    HostStack);
        }
    }
    /* Clear every stale pointer after all host stacks are released. */
    RtlZeroMemory(
        &g_KswordHvmResident,
        sizeof(g_KswordHvmResident));
}

/* Allocate and anchor every processor-owned VM-exit host stack. */
static NTSTATUS
KswordARKHvmResidentPrepareContexts(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Flags
    )
{
    ULONG index = 0UL;

    /* Reject a missing or empty prepared runtime. */
    if (Runtime == NULL ||
        Runtime->ProcessorCount == 0UL ||
        Runtime->ProcessorCount >
            KSWORD_ARK_HVM_MAX_PROCESSORS) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Release reusable stopped contexts before replacing their runtime. */
    KswordARKHvmResidentReleaseContexts();
    /* Initialize the complete process-wide resident state. */
    RtlZeroMemory(
        &g_KswordHvmResident,
        sizeof(g_KswordHvmResident));
    /* Preserve the runtime for nonblocking VM-exit lookups. */
    g_KswordHvmResident.Runtime = Runtime;
    /* Preserve the complete bounded processor count. */
    g_KswordHvmResident.ProcessorCount =
        Runtime->ProcessorCount;
    /* Preserve the exact resident start flags. */
    g_KswordHvmResident.Flags = Flags;
    /* Allocate and initialize one host stack per prepared processor. */
    for (index = 0UL;
         index < Runtime->ProcessorCount;
         ++index) {
        KSW_HVM_RESIDENT_VCPU* context =
            &g_KswordHvmResident.Processors[index];
        ULONG_PTR stackTop = 0U;
        PVOID* contextAnchor = NULL;

        /* Reference the process-wide runtime from the processor context. */
        context->Runtime = Runtime;
        /* Reference the exact processor-owned VMX resources. */
        context->Resource = &Runtime->Processors[index];
        /* Preserve the stable processor array index. */
        context->ProcessorIndex = index;
        /* Allocate a bounded nonpaged VM-exit stack. */
        context->HostStack = KswordARKAllocateNonPagedPool(
            KSW_HVM_RESIDENT_HOST_STACK_BYTES,
            KSW_HVM_RESIDENT_POOL_TAG);
        /* Roll back every prior host stack on allocation failure. */
        if (context->HostStack == NULL) {
            /* Release the fully stopped partial context set. */
            KswordARKHvmResidentReleaseContexts();
            /* Return the exact resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* Remove stale data before VMCS host state references the stack. */
        RtlZeroMemory(
            context->HostStack,
            KSW_HVM_RESIDENT_HOST_STACK_BYTES);
        /* Align the exclusive stack top to the x64 ABI boundary. */
        stackTop =
            ((ULONG_PTR)context->HostStack +
                KSW_HVM_RESIDENT_HOST_STACK_BYTES) &
            ~(ULONG_PTR)0xFULL;
        /* Reserve one pointer-sized context anchor below the stack top. */
        contextAnchor =
            (PVOID*)(stackTop - sizeof(PVOID));
        /* Publish the exact context consumed by the VM-exit assembly entry. */
        *contextAnchor = context;
        /* Preserve the anchored host stack pointer for the VMCS. */
        context->HostStackPointer =
            (ULONGLONG)(ULONG_PTR)contextAnchor;
        /* Initialize bounded nested state from explicit start flags. */
        KswordARKHvmNestedInitializeVcpu(
            &context->Nested,
            (Flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX) !=
                0UL,
            Runtime->EptPointer);
    }
    /* Publish that every processor has a complete host-stack context. */
    g_KswordHvmResident.Prepared = TRUE;
    /* Complete context preparation successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmConfigureResidentVmcsFromAsm(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    )
{
    KSW_HVM_VMCS_INPUT input = { 0 };
    SIZE_T exitControls = 0U;
    SIZE_T value = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete processor context in VMX root. */
    if (Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL ||
        Context->HostStackPointer == 0ULL ||
        Context->LaunchStackPointer == 0ULL) {
        /* Return the exact assembly-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Copy the VMX control revision and mode evidence. */
    input.VmxBasic = Context->Runtime->VmxBasic;
    /* Copy the CR0 required-one mask. */
    input.Cr0Fixed0 = Context->Runtime->Cr0Fixed0;
    /* Copy the CR0 allowed-one mask. */
    input.Cr0Fixed1 = Context->Runtime->Cr0Fixed1;
    /* Copy the CR4 required-one mask. */
    input.Cr4Fixed0 = Context->Runtime->Cr4Fixed0;
    /* Copy the CR4 allowed-one mask. */
    input.Cr4Fixed1 = Context->Runtime->Cr4Fixed1;
    /* Reference the prepared MTRR-aware identity EPT. */
    input.EptPointer = Context->Runtime->EptPointer;
    /* Resume on the exact assembly wrapper stack. */
    input.GuestStackPointer =
        Context->LaunchStackPointer;
    /* Receive VM exits on the processor-owned anchored host stack. */
    input.HostStackPointer =
        Context->HostStackPointer;
    /* Resume as the guest at the assembly wrapper continuation. */
    input.GuestInstructionPointer =
        (ULONGLONG)(ULONG_PTR)
            KswordARKHvmResidentGuestResume;
    /* Route every resident exit through the register-preserving entry. */
    input.HostInstructionPointer =
        (ULONGLONG)(ULONG_PTR)
            KswordARKHvmResidentVmExitEntry;
    /* Preserve the exact guest flags captured by the wrapper. */
    input.GuestRflags = Context->LaunchRflags;
    /* Select resident controls rather than one-shot HLT interception. */
    input.ResidentMode = 1U;
    /* Select nested instruction exposure only when explicitly requested. */
    input.EnableNestedVmx =
        Context->Nested.Enabled ? 1U : 0U;
    /* Discard every prior launch's optional-state ownership evidence. */
    Context->GuestSCet = 0ULL;
    Context->GuestSsp = 0ULL;
    Context->GuestInterruptSspTable = 0ULL;
    Context->GuestPkrs = 0ULL;
    Context->GuestUinv = 0ULL;
    Context->GuestDebugControl = 0ULL;
    Context->GuestDr7 = 0ULL;
    Context->CetStateManaged = 0U;
    Context->PkrsStateManaged = 0U;
    Context->UinvStateManaged = 0U;
    Context->DebugStateManaged = 0U;
    /* Program the complete current VMCS. */
    status = KswordARKHvmConfigureVmcs(
        &input,
        &Context->LastVmInstructionError);
    if (!NT_SUCCESS(status)) {
        Context->LastStatus = status;
        return status;
    }
    /* Recover the exact optional-state controls selected by the builder. */
    if (__vmx_vmread(KSW_VMCS_EXIT_CONTROLS, &exitControls) != 0U) {
        status = STATUS_HV_OPERATION_FAILED;
    } else {
        Context->CetStateManaged =
            (exitControls & KSW_HVM_EXIT_LOAD_CET) != 0U ? 1U : 0U;
        Context->PkrsStateManaged =
            (exitControls & KSW_HVM_EXIT_LOAD_PKRS) != 0U ? 1U : 0U;
        Context->UinvStateManaged =
            (exitControls & KSW_HVM_EXIT_CLEAR_UINV) != 0U ? 1U : 0U;
        Context->DebugStateManaged =
            (exitControls & KSW_HVM_EXIT_SAVE_DEBUG_CONTROLS) != 0U
                ? 1U
                : 0U;
        /* Assembly needs the CET enable bit before the final resident entry. */
        if (Context->CetStateManaged != 0U) {
            if (__vmx_vmread(KSW_VMCS_GUEST_S_CET, &value) != 0U) {
                status = STATUS_HV_OPERATION_FAILED;
            } else {
                Context->GuestSCet = (ULONGLONG)value;
            }
        }
    }
    /* Preserve the authoritative per-processor VMCS status. */
    Context->LastStatus = status;
    /* Return the complete VMCS programming result to assembly. */
    return status;
}

NTSTATUS
KswordARKHvmWriteResidentGuestSspFromAsm(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    )
{
    /* Reject a missing context before touching the current VMCS. */
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* No SSP transfer is required when supervisor shadow stacks are inactive. */
    if (Context->CetStateManaged == 0U ||
        (Context->GuestSCet & 1ULL) == 0ULL) {
        return STATUS_SUCCESS;
    }
    /* A zero shadow-stack continuation can never back the resident RET. */
    if (Context->GuestSsp == 0ULL) {
        return STATUS_INVALID_ADDRESS;
    }
    /* Commit the SSP captured after every nested configuration call returned. */
    if (__vmx_vmwrite(
            KSW_VMCS_GUEST_SSP,
            (SIZE_T)Context->GuestSsp) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
KswordARKHvmCaptureResidentExtendedState(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    )
{
    SIZE_T value = 0U;

    /* Capture every component before VMCLEAR destroys the VMCS image. */
    if (Context->CetStateManaged != 0U) {
        if (__vmx_vmread(KSW_VMCS_GUEST_S_CET, &value) != 0U) {
            return FALSE;
        }
        Context->GuestSCet = (ULONGLONG)value;
        if (__vmx_vmread(KSW_VMCS_GUEST_SSP, &value) != 0U) {
            return FALSE;
        }
        Context->GuestSsp = (ULONGLONG)value;
        if (__vmx_vmread(
                KSW_VMCS_GUEST_INTERRUPT_SSP_TABLE,
                &value) != 0U) {
            return FALSE;
        }
        Context->GuestInterruptSspTable = (ULONGLONG)value;
    }
    if (Context->PkrsStateManaged != 0U) {
        if (__vmx_vmread(KSW_VMCS_GUEST_PKRS, &value) != 0U) {
            return FALSE;
        }
        Context->GuestPkrs = (ULONGLONG)value;
    }
    if (Context->UinvStateManaged != 0U) {
        if (__vmx_vmread(KSW_VMCS_GUEST_UINV, &value) != 0U) {
            return FALSE;
        }
        Context->GuestUinv = (ULONGLONG)value & 0xFFULL;
    }
    if (Context->DebugStateManaged != 0U) {
        if (__vmx_vmread(KSW_VMCS_GUEST_DEBUGCTL, &value) != 0U) {
            return FALSE;
        }
        Context->GuestDebugControl = (ULONGLONG)value;
        if (__vmx_vmread(KSW_VMCS_GUEST_DR7, &value) != 0U) {
            return FALSE;
        }
        Context->GuestDr7 = (ULONGLONG)value;
    }
    return TRUE;
}

/* Enter resident VMX non-root operation on the current IPI target. */
static NTSTATUS
KswordARKHvmResidentStartCurrent(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    )
{
    ULONGLONG originalCr0 = 0ULL;
    ULONGLONG requiredCr0 = 0ULL;
    ULONGLONG requiredCr4 = 0ULL;
    unsigned __int64 vmxonPhysical = 0ULL;
    unsigned __int64 vmcsPhysical = 0ULL;
    UCHAR vmxResult = 0xFFU;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN cr4Changed = FALSE;

    /* Reject incomplete processor resources at IPI_LEVEL. */
    if (Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL) {
        /* Return the exact current-processor contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Refuse a duplicate start on an already resident processor. */
    if (InterlockedCompareExchange(
            &Context->Active,
            0L,
            0L) != 0L) {
        /* Return the exact duplicate lifecycle result. */
        return STATUS_ALREADY_REGISTERED;
    }
    /* Protect every privileged transition from virtual-CPU exceptions. */
    __try {
        /* Capture current CR0 before fixed-bit validation. */
        originalCr0 = __readcr0();
        /* Capture exact CR4 for later devirtualization. */
        Context->OriginalCr4 = __readcr4();
        /* Compute the required CR0 without changing host state. */
        requiredCr0 =
            (originalCr0 |
                Context->Runtime->Cr0Fixed0) &
            Context->Runtime->Cr0Fixed1;
        /* Compute VMX-root CR4 while preserving every active host feature. */
        requiredCr4 =
            ((Context->OriginalCr4 |
                Context->Runtime->Cr4Fixed0) &
                Context->Runtime->Cr4Fixed1) |
            KSW_CR4_VMXE;
        /*
         * Refuse to steal VMX root, alter incompatible control state, or
         * program a host CR0 that would make the entry FXSAVE64 raise #NM.
         */
        if ((Context->OriginalCr4 &
                KSW_CR4_VMXE) != 0ULL ||
            (originalCr0 &
                KSW_HVM_CR0_TASK_SWITCHED) != 0ULL ||
            requiredCr0 != originalCr0 ||
            (requiredCr4 &
                Context->OriginalCr4) !=
                Context->OriginalCr4) {
            /* Preserve protocol-visible conflict evidence. */
            Context->Resource->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_CONFLICT;
            /* Return the exact ownership conflict. */
            status = STATUS_CONFLICTING_ADDRESSES;
            /* Leave the guarded transition block. */
            __leave;
        }
        /* Enable VMX instructions on this exact logical processor. */
        __writecr4(requiredCr4);
        /* Record the CR4 transition for symmetric cleanup. */
        cr4Changed = TRUE;
        /* Copy the processor-owned VMXON physical address. */
        vmxonPhysical =
            (unsigned __int64)
                Context->Resource->
                    VmxonPhysical.QuadPart;
        /* Enter VMX root using the processor-owned VMXON region. */
        vmxResult = __vmx_on(&vmxonPhysical);
        /* Preserve the exact VMX instruction result. */
        Context->Resource->Row.vmxInstructionResult =
            vmxResult;
        /* Stop when VMXON fails validly or invalidly. */
        if (vmxResult != 0U) {
            /* Preserve the authoritative VMX operation failure. */
            status = STATUS_HV_OPERATION_FAILED;
            /* Leave the guarded transition block. */
            __leave;
        }
        /* Publish current ownership of VMX root state. */
        InterlockedExchange(&Context->VmxRoot, 1L);
        /* Copy the processor-owned VMCS physical address. */
        vmcsPhysical =
            (unsigned __int64)
                Context->Resource->
                    VmcsPhysical.QuadPart;
        /* Clear the VMCS launch state before making it current. */
        vmxResult = __vmx_vmclear(&vmcsPhysical);
        /* Preserve the exact VMCLEAR result. */
        Context->Resource->Row.vmxInstructionResult =
            vmxResult;
        /* Stop when VMCLEAR fails. */
        if (vmxResult != 0U) {
            /* Preserve the authoritative VMX operation failure. */
            status = STATUS_HV_OPERATION_FAILED;
            /* Leave the guarded transition block. */
            __leave;
        }
        /* Load the processor-owned VMCS as current. */
        vmxResult = __vmx_vmptrld(&vmcsPhysical);
        /* Preserve the exact VMPTRLD result. */
        Context->Resource->Row.vmxInstructionResult =
            vmxResult;
        /* Stop when VMPTRLD fails. */
        if (vmxResult != 0U) {
            /* Preserve the authoritative VMX operation failure. */
            status = STATUS_HV_OPERATION_FAILED;
            /* Leave the guarded transition block. */
            __leave;
        }
        /* Publish current-VMCS evidence. */
        Context->Resource->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED;
        /* Publish active ownership before any valid VM exit can occur. */
        InterlockedExchange(&Context->Active, 1L);
        /* Attempt resident VM entry through the exact assembly continuation. */
        vmxResult = KswordARKHvmAsmLaunchResident(Context);
        /* Preserve the wrapper VM-entry result. */
        Context->Resource->Row.vmxInstructionResult =
            vmxResult;
        /* Successful VMLAUNCH resumes here in VMX non-root with result zero. */
        if (vmxResult == 0U &&
            InterlockedCompareExchange(
                &Context->Active,
                0L,
                0L) != 0L) {
            /* Publish resident active state on this processor. */
            Context->Resource->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED |
                KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE;
            /* Publish one additional resident processor. */
            InterlockedIncrement(
                &Context->Runtime->
                    ResidentProcessorCount);
            /* Preserve successful current-processor status. */
            status = STATUS_SUCCESS;
            /* Leave the guarded transition block in guest context. */
            __leave;
        }
        /* Read VMfailValid detail while the failed VMCS remains current. */
        if (vmxResult == 1U) {
            SIZE_T instructionError = 0U;

            /* Preserve VM-instruction error when VMREAD succeeds. */
            if (__vmx_vmread(
                    KSW_VMCS_INSTRUCTION_ERROR,
                    &instructionError) == 0U) {
                /* Publish the exact VM-instruction error. */
                Context->LastVmInstructionError =
                    (ULONG)instructionError;
            }
        }
        /* Publish failed resident entry. */
        status = STATUS_HV_OPERATION_FAILED;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve privileged exception evidence. */
        status = GetExceptionCode();
        /* Publish processor-local exception state. */
        Context->Resource->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
    }
    /* Clean up only a failed start that remains in VMX root. */
    if (!NT_SUCCESS(status)) {
        /* Remove a premature active marker. */
        InterlockedExchange(&Context->Active, 0L);
        /* Leave VMX operation when this context still owns root state. */
        if (InterlockedCompareExchange(
                &Context->VmxRoot,
                0L,
                0L) != 0L) {
            /* Clear current VMCS state before VMXOFF when possible. */
            (void)__vmx_vmclear(&vmcsPhysical);
            /* Leave VMX operation on this exact processor. */
            __vmx_off();
            /* Publish completed VMX root cleanup. */
            InterlockedExchange(&Context->VmxRoot, 0L);
        }
        /* Restore the exact pre-VMX CR4 after VMXOFF. */
        if (cr4Changed) {
            /* Protect CR4 restoration from virtual-CPU exceptions. */
            __try {
                /* Restore the exact captured CR4 value. */
                __writecr4(Context->OriginalCr4);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                /* Preserve restoration failure over an earlier result. */
                status = GetExceptionCode();
                /* Publish processor-local exception state. */
                Context->Resource->Row.stateFlags |=
                    KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
            }
        }
    }
    /* Preserve the authoritative per-processor status. */
    Context->LastStatus = status;
    /* Publish the authoritative protocol row status. */
    Context->Resource->Row.lastStatus = status;
    /* Publish the last VM-instruction error to the runtime. */
    InterlockedExchange(
        &Context->Runtime->LastVmInstructionError,
        (LONG)Context->LastVmInstructionError);
    /* Return the complete current-processor lifecycle result. */
    return status;
}

BOOLEAN
KswordARKHvmResidentDeactivateCurrent(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG InstructionLength,
    _In_ BOOLEAN Faulted
    )
{
    SIZE_T guestRsp = 0U;
    SIZE_T guestRip = 0U;
    SIZE_T guestRflags = 0U;
    unsigned __int64 vmcsPhysical = 0ULL;
    UCHAR vmxResult = 0xFFU;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN transientRestored = TRUE;
    BOOLEAN safeToResumeNative = TRUE;

    /* Reject a missing or inactive current processor context. */
    if (Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL ||
        InterlockedCompareExchange(
            &Context->Active,
            0L,
            0L) == 0L) {
        /* Report that no safe devirtualization occurred. */
        return FALSE;
    }
    /*
     * Restore any outstanding allow-once permission before reading the guest
     * continuation.  An INVEPT failure is resolved by the VMXOFF below, but it
     * remains fault evidence and must never be silently discarded.
     */
    transientRestored = KswordARKHvmEptRestoreTransient(
        Context->Runtime,
        &Context->EptTransient);
    /* Preserve the invalidation failure while continuing to fail-closed exit. */
    if (!transientRestored) {
        /* Retain the authoritative current-context invalidation failure. */
        status = STATUS_HV_OPERATION_FAILED;
    }
    /* Read the exact guest stack used for the post-VMX continuation. */
    if (__vmx_vmread(
            KSW_VMCS_GUEST_RSP,
            &guestRsp) != 0U ||
        __vmx_vmread(
            KSW_VMCS_GUEST_RIP,
            &guestRip) != 0U ||
        __vmx_vmread(
            KSW_VMCS_GUEST_RFLAGS,
            &guestRflags) != 0U) {
        /* Preserve an unsafe VMREAD failure. */
        Context->LastStatus = STATUS_HV_OPERATION_FAILED;
        /* Report that no safe devirtualization occurred. */
        return FALSE;
    }
    /* Preserve every optional guest component before VMCLEAR. */
    if (!KswordARKHvmCaptureResidentExtendedState(Context)) {
        Context->LastStatus = STATUS_HV_OPERATION_FAILED;
        return FALSE;
    }
    /* Advance only a fully decoded stop or private hypercall. */
    if (InstructionLength != 0UL) {
        /* Reject an architecturally invalid instruction length. */
        if (InstructionLength > 15UL ||
            guestRip > MAXULONG_PTR - InstructionLength) {
            /* Preserve the exact continuation validation failure. */
            Context->LastStatus = STATUS_INTEGER_OVERFLOW;
            /* Report that no safe devirtualization occurred. */
            return FALSE;
        }
        /* Continue after the intercepted instruction. */
        guestRip += InstructionLength;
    }
    /* Publish every continuation field before leaving VMX root. */
    Context->DevirtualizeRsp = (ULONGLONG)guestRsp;
    /* Publish the exact guest instruction continuation. */
    Context->DevirtualizeRip = (ULONGLONG)guestRip;
    /* Publish the exact guest RFLAGS continuation. */
    Context->DevirtualizeRflags =
        (ULONGLONG)guestRflags;
    /* Copy the processor-owned VMCS physical address. */
    vmcsPhysical =
        (unsigned __int64)
            Context->Resource->VmcsPhysical.QuadPart;
    /* Clear VMCS launch state before VMXOFF. */
    vmxResult = __vmx_vmclear(&vmcsPhysical);
    /* Preserve VMCLEAR failure without hiding guest continuation evidence. */
    if (vmxResult != 0U) {
        /* Preserve the exact VMX instruction result. */
        Context->Resource->Row.vmxInstructionResult =
            vmxResult;
        /* Preserve the authoritative VMX operation failure. */
        status = STATUS_HV_OPERATION_FAILED;
        /* A failed VMCLEAR cannot commit resource release. */
        safeToResumeNative = FALSE;
    }
    /* Leave VMX operation on the current logical processor. */
    __vmx_off();
    /* Publish completed VMX root cleanup. */
    InterlockedExchange(&Context->VmxRoot, 0L);
    /* Restore non-CET state before entering the final assembly continuation. */
    __try {
        if (Context->PkrsStateManaged != 0U) {
            __writemsr(KSW_HVM_IA32_PKRS, Context->GuestPkrs);
        }
        if (Context->UinvStateManaged != 0U) {
            ULONGLONG uintrMisc =
                __readmsr(KSW_HVM_IA32_UINTR_MISC);

            uintrMisc &= ~(0xFFULL << 32);
            uintrMisc |=
                (Context->GuestUinv & 0xFFULL) << 32;
            __writemsr(KSW_HVM_IA32_UINTR_MISC, uintrMisc);
        }
        /* Restore CR4 after VMXOFF and before returning to guest state. */
        __writecr4(Context->OriginalCr4);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve the exact privileged restoration exception. */
        status = GetExceptionCode();
        /* CR4 restoration failure cannot commit resource release. */
        safeToResumeNative = FALSE;
    }
    /*
     * VMXOFF invalidates this processor's EPT context.  Only now may a failed
     * transient INVEPT discard its retained recovery record.
     */
    if (!transientRestored) {
        /* Clear the recovery record after the EPT context ceased to exist. */
        RtlZeroMemory(
            &Context->EptTransient,
            sizeof(Context->EptTransient));
    }
    /* Preserve the authoritative per-processor status. */
    Context->LastStatus = status;
    /* Preserve the authoritative protocol row status. */
    Context->Resource->Row.lastStatus = status;
    /* Publish fault and rollback evidence for unexpected exits. */
    if (Faulted ||
        !safeToResumeNative ||
        !transientRestored) {
        /* Publish process-wide fault and rollback-required state atomically. */
        InterlockedOr(
            (volatile LONG*)&Context->Runtime->StateFlags,
            (LONG)(
                KSWORD_ARK_HVM_STATE_FAULTED |
                KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED));
        /* Publish explicit partial maturity after an unexpected per-CPU exit. */
        Context->Runtime->ResidentImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
    }
    /*
     * Active, resident count, and DEVIRTUALIZED are intentionally not changed
     * here.  Assembly commits them only after it has copied all continuation
     * state to the guest stack and no longer references the host stack.
     */
    return safeToResumeNative;
}

/* Execute one resident operation on every processor at IPI_LEVEL. */
static ULONG_PTR
KswordARKHvmResidentIpiWorker(
    _In_ ULONG_PTR ContextValue
    )
{
    KSW_HVM_RENDEZVOUS* rendezvous =
        (KSW_HVM_RENDEZVOUS*)ContextValue;
    KSW_HVM_RESIDENT_VCPU* context =
        KswordARKHvmResidentFindCurrent();
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an invalid rendezvous or an unrepresented processor. */
    if (rendezvous == NULL ||
        context == NULL) {
        /* Select the explicit processor-capacity failure. */
        status = STATUS_NOT_FOUND;
    /* Start resident VMX on the exact current processor. */
    } else if (rendezvous->Operation ==
        KSW_HVM_RENDEZVOUS_START) {
        /* Execute the complete current-processor start lifecycle. */
        status = KswordARKHvmResidentStartCurrent(context);
    /* Stop only a processor that remains resident. */
    } else if (rendezvous->Operation ==
        KSW_HVM_RENDEZVOUS_STOP) {
        /* Skip processors that already devirtualized after a fatal exit. */
        if (InterlockedCompareExchange(
                &context->Active,
                0L,
                0L) != 0L) {
            ULONGLONG hypercallResult = 0ULL;

            /* Publish the explicit stop request before entering VMX root. */
            InterlockedExchange(
                &context->StopRequested,
                1L);
            /* Request devirtualization through the private VMCALL contract. */
            hypercallResult = KswordARKHvmAsmResidentHypercall(
                KSW_HVM_HYPERCALL_STOP,
                0ULL);
            /* Require the exit path to clear active state before returning. */
            status =
                hypercallResult == 0ULL &&
                InterlockedCompareExchange(
                    &context->Active,
                    0L,
                    0L) == 0L
                ? STATUS_SUCCESS
                : STATUS_HV_OPERATION_FAILED;
        }
    /* Invalidate EPT from VMX root through a private VMCALL. */
    } else if (rendezvous->Operation ==
        KSW_HVM_RENDEZVOUS_INVEPT) {
        /* Skip processors that are no longer resident. */
        if (InterlockedCompareExchange(
                &context->Active,
                0L,
                0L) != 0L) {
            ULONGLONG hypercallResult = 0ULL;

            /* Execute single-context INVEPT in this processor's VMX root. */
            hypercallResult = KswordARKHvmAsmResidentHypercall(
                KSW_HVM_HYPERCALL_INVEPT,
                rendezvous->EptPointer);
            /* Convert the private hypercall result to NTSTATUS. */
            status = hypercallResult == 0ULL
                ? STATUS_SUCCESS
                : STATUS_HV_OPERATION_FAILED;
        }
    } else {
        /* Reject an unknown all-processor operation. */
        status = STATUS_INVALID_PARAMETER;
    }
    /* Publish this exact processor's operation result. */
    KswordARKHvmResidentRecordResult(
        rendezvous,
        status);
    /* Return a conventional nonzero IPI worker result on success. */
    return NT_SUCCESS(status) ? 1U : 0U;
}

/* Broadcast one fixed resident operation to every active processor. */
static NTSTATUS
KswordARKHvmResidentRendezvous(
    _In_ ULONG Operation,
    _In_ ULONGLONG EptPointer,
    _Out_opt_ LONG* SuccessCount
    )
{
    KSW_HVM_RENDEZVOUS rendezvous = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    /* Initialize the complete fixed rendezvous contract. */
    rendezvous.Operation = Operation;
    /* Preserve the optional EPT pointer for invalidation. */
    rendezvous.EptPointer = EptPointer;
    /* Publish success as the initial compare-exchange sentinel. */
    rendezvous.FirstStatus = STATUS_SUCCESS;
    /* Interrupt every active processor and execute the nonpaged worker. */
    (void)KeIpiGenericCall(
        KswordARKHvmResidentIpiWorker,
        (ULONG_PTR)&rendezvous);
    /* Return the successful target count when requested. */
    if (SuccessCount != NULL) {
        /* Publish the complete interlocked success count. */
        *SuccessCount = rendezvous.SuccessCount;
    }
    /* Select the first authoritative worker failure. */
    if (rendezvous.FailureCount != 0L) {
        /* Preserve a missing explicit status as generic failure. */
        status = NT_SUCCESS(rendezvous.FirstStatus)
            ? STATUS_UNSUCCESSFUL
            : (NTSTATUS)rendezvous.FirstStatus;
    }
    /* Return the complete all-processor rendezvous result. */
    return status;
}

NTSTATUS
KswordARKHvmResidentStart(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Flags
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS rollbackStatus = STATUS_SUCCESS;
    NTSTATUS guardStatus = STATUS_SUCCESS;
    LONG successCount = 0L;
    ULONG activeProcessorCount = 0UL;
    ULONG processorIndex = 0UL;
    ULONG ruleIndex = 0UL;
    LONG powerGeneration = 0L;
    KSWORD_ARK_HVM_EVENT_ROW eventRow = { 0 };

    /* Reject a missing runtime before evaluating lifecycle policy. */
    if (Runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Resident entry requires the complete driver-side lifecycle guard set. */
    if (!Runtime->ResidentStartAllowed ||
        (Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_INTEL |
             KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED)) !=
            (KSWORD_ARK_HVM_FEATURE_INTEL |
             KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED)) {
        /* Preserve every nonresident HVM capability while refusing residency. */
        Runtime->ResidentImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
        return STATUS_NOT_SUPPORTED;
    }
    /* Refuse VMX entry while the power manager is leaving the S0 working state. */
    if (InterlockedCompareExchange(
            &Runtime->PowerTransitionPending,
            0L,
            0L) != 0L) {
        return STATUS_POWER_STATE_INVALID;
    }
    powerGeneration = InterlockedCompareExchange(
        &Runtime->PowerTransitionGeneration,
        0L,
        0L);
    /* Refuse a resident mapping whose architectural address space was clipped. */
    if ((Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_EPT_TRUNCATED) != 0UL) {
        /* Do not enter VMX with an incomplete architectural identity map. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Never reuse a lifecycle whose prior devirtualization is uncertain. */
    if ((Runtime->StateFlags &
            (KSWORD_ARK_HVM_STATE_FAULTED |
             KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED |
             KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED)) != 0UL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Validate prepared, tested, and EPT-ready state before allocation. */
    if (
        (Runtime->StateFlags &
            (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
             KSWORD_ARK_HVM_STATE_EPT_READY |
             KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED)) !=
            (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
             KSWORD_ARK_HVM_STATE_EPT_READY |
             KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED)) {
        /* Return the exact lifecycle prerequisite failure. */
        return STATUS_DEVICE_NOT_READY;
    }
    /* Revalidate the complete topology immediately before host allocation. */
    activeProcessorCount =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (activeProcessorCount == 0UL ||
        activeProcessorCount != Runtime->ProcessorCount ||
        Runtime->PreparedProcessorCount != Runtime->ProcessorCount ||
        Runtime->SelfTestPassedProcessorCount != Runtime->ProcessorCount) {
        return STATUS_REVISION_MISMATCH;
    }
    /* Require affirmative per-CPU VMXON/VMXOFF evidence for every target. */
    for (processorIndex = 0UL;
         processorIndex < Runtime->ProcessorCount;
         ++processorIndex) {
        const ULONG cpuState =
            Runtime->Processors[processorIndex].Row.stateFlags;

        if ((cpuState &
                (KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY |
                 KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED |
                 KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED)) !=
            (KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY |
             KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED |
             KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED)) {
            return STATUS_REVISION_MISMATCH;
        }
    }
    /* Refuse duplicate resident start while any processor remains active. */
    if (InterlockedCompareExchange(
            &Runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /* Return the exact duplicate lifecycle result. */
        return STATUS_ALREADY_REGISTERED;
    }
    /*
     * An existing hypervisor requires complete outer-hypercall forwarding and
     * active eVMCS ownership.  Capability-only eVMCS must never be launched.
     */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL) {
        /* Return the explicit hypervisor ownership conflict. */
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
    /*
     * ALLOW_ONCE temporarily edits the shared EPT leaf.  Refuse start unless
     * the complete target topology is one VCPU and both restoration controls
     * are available.  Ordinary tripwire rules remain valid on any topology.
     */
    for (ruleIndex = 0UL;
         ruleIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++ruleIndex) {
        const KSW_HVM_EPT_RULE_SLOT* rule =
            &Runtime->EptRules[ruleIndex];

        /* Skip inactive rules and strict devirtualization tripwires. */
        if (!rule->Active ||
            (rule->Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE) == 0UL) {
            /* Continue to the next immutable pre-start rule. */
            continue;
        }
        /* Reject every shared-leaf temporary grant on a multicore target. */
        if (Runtime->ProcessorCount != 1UL ||
            (Runtime->FeatureFlags &
                (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
                 KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) !=
                (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
                 KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) {
            /* Return before host-stack allocation or any VMX transition. */
            return STATUS_NOT_SUPPORTED;
        }
    }
    /* Serialize passive-level context construction against power teardown. */
    if (InterlockedCompareExchange(
            &Runtime->ResidentContextPreparing,
            1L,
            0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }
    /* Allocate every nonpaged host-stack context before raising IRQL. */
    status = KswordARKHvmResidentPrepareContexts(
        Runtime,
        Flags);
    /* Stop before VMX entry when context preparation fails. */
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &Runtime->ResidentContextPreparing,
            0L);
        /* Return the exact context preparation failure. */
        return status;
    }
    /* Own the transition phase without holding its state lock over the IPI. */
    status = KswordARKHvmAcquireResidentTransition(Runtime);
    if (!NT_SUCCESS(status)) {
        KswordARKHvmResidentReleaseContexts();
        InterlockedExchange(
            &Runtime->ResidentContextPreparing,
            0L);
        return status;
    }
    /* A power callback may have arrived while host stacks were allocated. */
    if (InterlockedCompareExchange(
            &Runtime->PowerTransitionPending,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &Runtime->PowerTransitionGeneration,
            0L,
            0L) != powerGeneration) {
        /* Release the fully stopped contexts without attempting VMX entry. */
        KswordARKHvmResidentReleaseContexts();
        InterlockedExchange(
            &Runtime->ResidentContextPreparing,
            0L);
        KswordARKHvmReleaseResidentTransition(Runtime);
        return STATUS_POWER_STATE_INVALID;
    }
    /* Prevent image unload before the first processor can enter VMX. */
    guardStatus = KswordARKHvmArmUnloadGuard(Runtime);
    if (!NT_SUCCESS(guardStatus)) {
        /* No processor entered VMX, so every prepared host stack is releasable. */
        KswordARKHvmResidentReleaseContexts();
        InterlockedExchange(
            &Runtime->ResidentContextPreparing,
            0L);
        KswordARKHvmReleaseResidentTransition(Runtime);
        return guardStatus;
    }
    /* Publish starting state before any processor enters VMX non-root. */
    Runtime->StateFlags |=
        KSWORD_ARK_HVM_STATE_RESIDENT_STARTING;
    /* Enter VMX non-root on every active processor. */
    status = KswordARKHvmResidentRendezvous(
        KSW_HVM_RENDEZVOUS_START,
        Runtime->EptPointer,
        &successCount);
    /* Require every prepared processor to report resident success. */
    if (!NT_SUCCESS(status) ||
        successCount != (LONG)Runtime->ProcessorCount ||
        InterlockedCompareExchange(
            &Runtime->ResidentProcessorCount,
            0L,
            0L) != (LONG)Runtime->ProcessorCount ||
        InterlockedCompareExchange(
            &Runtime->PowerTransitionPending,
            0L,
            0L) != 0L) {
        /* Convert a count mismatch or a concurrent power event to a failure. */
        if (NT_SUCCESS(status)) {
            status = InterlockedCompareExchange(
                    &Runtime->PowerTransitionPending,
                    0L,
                    0L) != 0L
                ? STATUS_POWER_STATE_INVALID
                : STATUS_HV_OPERATION_FAILED;
        }

        /* Publish rollback-required state before stopping partial residency. */
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
        /* Stop every processor that entered VMX non-root successfully. */
        rollbackStatus = KswordARKHvmResidentRendezvous(
            KSW_HVM_RENDEZVOUS_STOP,
            Runtime->EptPointer,
            NULL);
        /* Preserve every live or uncertain resident context after rollback. */
        if (!NT_SUCCESS(rollbackStatus) ||
            InterlockedCompareExchange(
                &Runtime->ResidentProcessorCount,
                0L,
                0L) != 0L) {
            /* Publish explicit partial implementation after failed rollback. */
            Runtime->ResidentImplementation =
                KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
            /* Preserve the authoritative rollback failure. */
            if (NT_SUCCESS(rollbackStatus)) {
                status = STATUS_HV_OPERATION_FAILED;
            } else {
                status = rollbackStatus;
            }
            /* Keep the unload guard and host stacks while safety is uncertain. */
            Runtime->StateFlags &=
                ~KSWORD_ARK_HVM_STATE_RESIDENT_STARTING;
            InterlockedExchange(
                &Runtime->ResidentContextPreparing,
                0L);
            KswordARKHvmReleaseResidentTransition(Runtime);
            return status;
        }
        /* Release host stacks only after rollback reached zero active CPUs. */
        KswordARKHvmResidentReleaseContexts();
        /* Restore unload only outside a power transition. */
        if (InterlockedCompareExchange(
                &Runtime->PowerTransitionPending,
                0L,
                0L) == 0L) {
            guardStatus = KswordARKHvmDisarmUnloadGuard(Runtime);
        }
        /* Clear transient state after a complete, verified rollback. */
        Runtime->StateFlags &=
            ~(KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
              KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
              KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
              KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        Runtime->ResidentImplementation =
            Runtime->ResidentStartAllowed
                ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
                : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
        if (!NT_SUCCESS(guardStatus)) {
            /* A stuck unload slot is fail-closed and requires intervention. */
            Runtime->StateFlags |=
                KSWORD_ARK_HVM_STATE_FAULTED |
                KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
            Runtime->ResidentImplementation =
                KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
            status = guardStatus;
        }
        InterlockedExchange(
            &Runtime->ResidentContextPreparing,
            0L);
        KswordARKHvmReleaseResidentTransition(Runtime);
        /* Return the authoritative all-processor start failure. */
        return status;
    }
    /* Clear transient starting state after full all-processor success. */
    Runtime->StateFlags &=
        ~KSWORD_ARK_HVM_STATE_RESIDENT_STARTING;
    /* Publish resident active only after every target processor succeeds. */
    Runtime->StateFlags |=
        KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE;
    /* Clear stale rollback evidence after complete startup. */
    Runtime->StateFlags &=
        ~KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
    /* Publish active resident implementation maturity. */
    Runtime->ResidentImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE;
    /* Publish implemented resident and multicore features. */
    Runtime->FeatureFlags |=
        KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
        KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS;
    /* Context construction is complete before exposing active residency. */
    InterlockedExchange(
        &Runtime->ResidentContextPreparing,
        0L);
    KswordARKHvmReleaseResidentTransition(Runtime);
    /* Describe one lifecycle event after full residency succeeds. */
    eventRow.type = KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE;
    /* Publish successful resident start status. */
    eventRow.status = STATUS_SUCCESS;
    /* Publish the complete lifecycle event. */
    KswordARKHvmEventPublish(&eventRow);
    /* Complete the full resident start successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmResidentStop(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS guardStatus = STATUS_SUCCESS;
    KSWORD_ARK_HVM_EVENT_ROW eventRow = { 0 };

    /* Reject a missing runtime before lifecycle mutation. */
    if (Runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Serialize devirtualization through the wait-aware transition phase. */
    status = KswordARKHvmAcquireResidentTransition(Runtime);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Treat a fully stopped lifecycle as idempotent success. */
    if (InterlockedCompareExchange(
            &Runtime->ResidentProcessorCount,
            0L,
            0L) == 0L) {
        /* A power callback must not free contexts still being constructed. */
        if (InterlockedCompareExchange(
                &Runtime->ResidentContextPreparing,
                0L,
                0L) == 0L) {
            /* Release stopped contexts retained after a prior fault. */
            KswordARKHvmResidentReleaseContexts();
        }
        /* Clear protocol-visible resident active state. */
        Runtime->StateFlags &=
            ~(KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
              KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
              KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        /* Preserve the fail-closed public maturity after an idempotent stop. */
        Runtime->ResidentImplementation =
            Runtime->ResidentStartAllowed
                ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
                : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
        /* Keep unload disabled throughout an active non-S0 transition. */
        if (InterlockedCompareExchange(
                &Runtime->PowerTransitionPending,
                0L,
                0L) == 0L) {
            guardStatus = KswordARKHvmDisarmUnloadGuard(Runtime);
        }
        if (!NT_SUCCESS(guardStatus)) {
            Runtime->StateFlags |=
                KSWORD_ARK_HVM_STATE_FAULTED |
                KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
            Runtime->ResidentImplementation =
                KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
            KswordARKHvmReleaseResidentTransition(Runtime);
            return guardStatus;
        }
        KswordARKHvmReleaseResidentTransition(Runtime);
        /* Complete the idempotent stop successfully. */
        return STATUS_SUCCESS;
    }
    /* Publish stopping state before issuing private stop VMCALLs. */
    Runtime->StateFlags |=
        KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING;
    /* Request devirtualization on every active processor. */
    status = KswordARKHvmResidentRendezvous(
        KSW_HVM_RENDEZVOUS_STOP,
        Runtime->EptPointer,
        NULL);
    /* Preserve host stacks and rollback state while any processor remains live. */
    if (!NT_SUCCESS(status) ||
        InterlockedCompareExchange(
            &Runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /* Publish explicit rollback-required state. */
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
        /* Publish explicit partial maturity rather than active success. */
        Runtime->ResidentImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
        /* Clear transient stopping state after the failed rendezvous. */
        Runtime->StateFlags &=
            ~KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING;
        KswordARKHvmReleaseResidentTransition(Runtime);
        /* Return the authoritative stop or incomplete rollback failure. */
        return NT_SUCCESS(status)
            ? STATUS_HV_OPERATION_FAILED
            : status;
    }
    /* Release host stacks after every CPU completes VMXOFF. */
    KswordARKHvmResidentReleaseContexts();
    /* Clear all resident lifecycle state after complete rollback. */
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
          KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
          KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
    /* Preserve the configured lifecycle maturity without claiming active. */
    Runtime->ResidentImplementation =
        Runtime->ResidentStartAllowed
            ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
            : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    /* Keep unload disabled until S0 resume clears the transition gate. */
    if (InterlockedCompareExchange(
            &Runtime->PowerTransitionPending,
            0L,
            0L) == 0L) {
        guardStatus = KswordARKHvmDisarmUnloadGuard(Runtime);
    }
    if (!NT_SUCCESS(guardStatus)) {
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_FAULTED |
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
        Runtime->ResidentImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
        KswordARKHvmReleaseResidentTransition(Runtime);
        return guardStatus;
    }
    KswordARKHvmReleaseResidentTransition(Runtime);
    /* Describe one successful resident stop lifecycle event. */
    eventRow.type = KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE;
    /* Publish successful resident stop status. */
    eventRow.status = STATUS_SUCCESS;
    /* Publish the complete lifecycle event. */
    KswordARKHvmEventPublish(&eventRow);
    /* Complete the full resident stop successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmResidentInvalidateEpt(
    _In_ ULONGLONG EptPointer
    )
{
    KSW_HVM_RUNTIME* runtime =
        g_KswordHvmResident.Runtime;

    /* Treat a stopped resident lifecycle as requiring no invalidation. */
    if (runtime == NULL ||
        InterlockedCompareExchange(
            &runtime->ResidentProcessorCount,
            0L,
            0L) == 0L) {
        /* Complete the no-op invalidation successfully. */
        return STATUS_SUCCESS;
    }
    /* Require the exact active EPT context identity. */
    if (EptPointer == 0ULL ||
        EptPointer != runtime->EptPointer) {
        /* Return the explicit EPT identity mismatch. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Execute one private INVEPT hypercall on every active processor. */
    return KswordARKHvmResidentRendezvous(
        KSW_HVM_RENDEZVOUS_INVEPT,
        EptPointer,
        NULL);
}

#else

NTSTATUS
KswordARKHvmResidentStart(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Flags
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Flags);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmResidentStop(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmResidentInvalidateEpt(
    _In_ ULONGLONG EptPointer
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(EptPointer);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmConfigureResidentVmcsFromAsm(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Context);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmWriteResidentGuestSspFromAsm(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Context);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

BOOLEAN
KswordARKHvmResidentDeactivateCurrent(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG InstructionLength,
    _In_ BOOLEAN Faulted
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Context);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(InstructionLength);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Faulted);
    /* Report that no processor was devirtualized. */
    return FALSE;
}

KSW_HVM_RESIDENT_VCPU*
KswordARKHvmResidentFindCurrent(
    VOID
    )
{
    /* Report that resident VMX is unavailable on this architecture. */
    return NULL;
}

#endif
