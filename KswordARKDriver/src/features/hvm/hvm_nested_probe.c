/*++

Module Name:

    hvm_nested_probe.c

Abstract:

    Executes VMX instructions from guest context so the nested dispatch that
    services them can be observed end to end.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_probe.h"
#include "hvm_resident.h"
#include "hvm_runtime.h"
#include "driver/KswordArkHvmIoctl.h"

#if defined(_M_AMD64)
#include <intrin.h>
#include "../../platform/pool_compat.h"

/* Name the CR4 bit that must be set before any VMX instruction is legal. */
#define KSW_PROBE_CR4_VMXE (1ULL << 13)
/* Name the MSR carrying the VMCS revision identifier. */
#define KSW_PROBE_IA32_VMX_BASIC 0x480UL
/* Name the guest RIP field, used as a harmless VMREAD/VMWRITE target. */
#define KSW_PROBE_VMCS_GUEST_RIP 0x681EUL
/* Name a value with no architectural meaning, chosen to be recognizable. */
#define KSW_PROBE_PATTERN 0x00005357444E3142ULL

/* Carry one probe's working state across the pinned execution. */
typedef struct _KSW_HVM_NESTED_PROBE_CONTEXT
{
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE* Response;
    PVOID VmxonVirtual;
    ULONGLONG VmxonPhysical;
    PVOID Vmcs12Virtual;
    ULONGLONG Vmcs12Physical;
} KSW_HVM_NESTED_PROBE_CONTEXT;

/*
 * Run the instruction sequence on the processor this thread is pinned to.
 *
 * Every step records the architectural result rather than stopping at the
 * first failure: a VMPTRLD that fails after a VMXON that succeeded is a
 * different and more interesting report than "the probe failed".
 */
static VOID
KswordARKHvmNestedProbeExecute(
    _Inout_ KSW_HVM_NESTED_PROBE_CONTEXT* Probe
    )
{
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE* response = Probe->Response;
    KSW_HVM_RESIDENT_VCPU* vcpu = KswordARKHvmResidentFindCurrent();
    ULONGLONG originalCr4 = __readcr4();
    ULONGLONG vmxonPhysical = Probe->VmxonPhysical;
    ULONGLONG vmcs12Physical = Probe->Vmcs12Physical;
    ULONGLONG readBack = 0ULL;
    ULONGLONG storedPointer = 0ULL;
    ULONGLONG startingCount = 0ULL;

    response->processorIndex =
        (ULONG)KeGetCurrentProcessorNumberEx(NULL);
    /*
     * Refuse without an armed nested dispatch on *this* processor.
     *
     * Not caution - necessity.  With dispatch disabled the exit handler
     * injects #UD for a VMX instruction, and that #UD lands on the kernel code
     * three lines below.  There is no recovering from it, so the only place to
     * stop is before the first instruction.
     */
    if (vcpu == NULL ||
        !vcpu->Nested.Enabled ||
        InterlockedCompareExchange(&vcpu->Active, 0L, 0L) == 0L) {
        response->status = KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NOT_ARMED;
        /* Return without executing anything. */
        return;
    }
    startingCount = vcpu->Nested.InstructionCount;
    /*
     * Set CR4.VMXE and read it back.
     *
     * A write that our own CR policy declines leaves the bit clear, and VMXON
     * with it clear is #UD - again on our own kernel code.  The read-back is
     * the gate, not the write.
     */
    __writecr4(originalCr4 | KSW_PROBE_CR4_VMXE);
    if ((__readcr4() & KSW_PROBE_CR4_VMXE) == 0ULL) {
        response->status =
            KSWORD_ARK_HVM_NESTED_PROBE_STATUS_VMXE_REFUSED;
        /* Return without executing anything. */
        return;
    }
    response->vmwriteValue = KSW_PROBE_PATTERN;
    /* Enter emulated L1 VMX operation. */
    response->vmxonResult = (ULONG)__vmx_on(&vmxonPhysical);
    if (response->vmxonResult == 0UL) {
        /* Make our probe vmcs12 current. */
        response->vmptrldResult =
            (ULONG)__vmx_vmptrld(&vmcs12Physical);
        if (response->vmptrldResult == 0UL) {
            /* Write a recognizable value into a field and read it back. */
            response->vmwriteResult = (ULONG)__vmx_vmwrite(
                (SIZE_T)KSW_PROBE_VMCS_GUEST_RIP,
                (SIZE_T)KSW_PROBE_PATTERN);
            response->vmreadResult = (ULONG)__vmx_vmread(
                (SIZE_T)KSW_PROBE_VMCS_GUEST_RIP,
                (SIZE_T*)&readBack);
            response->vmreadValue = readBack;
            response->vmreadMatched =
                (response->vmwriteResult == 0UL &&
                 response->vmreadResult == 0UL &&
                 readBack == KSW_PROBE_PATTERN) ? 1UL : 0UL;
            /*
             * Ask which VMCS is current and compare with what we loaded.
             *
             * VMPTRST has no failure encoding - it always stores - so the
             * result slot records that it ran, and the comparison below is
             * the actual judgement.
             */
            __vmx_vmptrst(&storedPointer);
            response->vmptrstResult = 0UL;
            response->vmptrstMatched =
                (storedPointer == Probe->Vmcs12Physical) ? 1UL : 0UL;
        }
        /* Leave VMX operation however far the sequence got. */
        __vmx_off();
        response->vmxoffResult = 0UL;
    }
    /* Put CR4 back exactly as it was found. */
    __writecr4(originalCr4);
    response->dispatchedInstructions =
        vcpu->Nested.InstructionCount - startingCount;
    response->nestedStateAfter = vcpu->Nested.State;
    response->lastInstructionError = vcpu->Nested.LastInstructionError;
    response->status = KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK;
}

NTSTATUS
KswordARKHvmNestedProbeRun(
    _In_ const KSWORD_ARK_HVM_NESTED_PROBE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE* Response
    )
{
    KSW_HVM_NESTED_PROBE_CONTEXT probe = { 0 };
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    PHYSICAL_ADDRESS physical = { 0 };
    ULONG revision = 0UL;
    KAFFINITY affinity = 0;
    GROUP_AFFINITY target = { 0 };
    GROUP_AFFINITY previous = { 0 };
    PROCESSOR_NUMBER processorNumber = { 0 };

    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    /* Start every step at "did not execute" so silence is never success. */
    Response->vmxonResult = KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED;
    Response->vmptrldResult = KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED;
    Response->vmwriteResult = KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED;
    Response->vmreadResult = KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED;
    Response->vmptrstResult = KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED;
    Response->vmxoffResult = KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED;
    /* Reject a request that does not match the compiled contract. */
    if (Request->version !=
            KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request)) {
        Response->status =
            KSWORD_ARK_HVM_NESTED_PROBE_STATUS_INVALID_REQUEST;
        /* Return the exact contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require the explicit confirmation this control class shares. */
    if ((Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
        Request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN) {
        Response->status =
            KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIRMATION_REQUIRED;
        /* Return the exact confirmation failure. */
        return STATUS_SUCCESS;
    }
    revision = (ULONG)(__readmsr(KSW_PROBE_IA32_VMX_BASIC) & 0x7FFFFFFFULL);
    highest.QuadPart = MAXLONGLONG;
    probe.VmxonVirtual = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, lowest, highest, boundary, MmCached);
    probe.Vmcs12Virtual = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, lowest, highest, boundary, MmCached);
    if (probe.VmxonVirtual == NULL || probe.Vmcs12Virtual == NULL) {
        if (probe.VmxonVirtual != NULL) {
            MmFreeContiguousMemory(probe.VmxonVirtual);
        }
        if (probe.Vmcs12Virtual != NULL) {
            MmFreeContiguousMemory(probe.Vmcs12Virtual);
        }
        Response->status =
            KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NO_RESOURCES;
        /* Return the exact allocation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(probe.VmxonVirtual, PAGE_SIZE);
    RtlZeroMemory(probe.Vmcs12Virtual, PAGE_SIZE);
    /*
     * Both regions start with the revision identifier.
     *
     * Our own dispatch does not read them - it cannot, because they are named
     * by physical addresses - but writing them keeps the probe honest: if the
     * check is ever added, this probe must still pass.
     */
    *(volatile ULONG*)probe.VmxonVirtual = revision;
    *(volatile ULONG*)probe.Vmcs12Virtual = revision;
    physical = MmGetPhysicalAddress(probe.VmxonVirtual);
    probe.VmxonPhysical = (ULONGLONG)physical.QuadPart;
    physical = MmGetPhysicalAddress(probe.Vmcs12Virtual);
    probe.Vmcs12Physical = (ULONGLONG)physical.QuadPart;
    probe.Response = Response;
    /*
     * Pin to one processor for the whole sequence.
     *
     * VMX operation is per-processor state.  Migrating between the VMXON and
     * the VMXOFF would leave one processor in emulated VMX operation with
     * nothing to take it out, and execute the rest against a nested record
     * that never saw the VMXON.
     */
    KeGetCurrentProcessorNumberEx(&processorNumber);
    affinity = (KAFFINITY)1 << processorNumber.Number;
    target.Group = processorNumber.Group;
    target.Mask = affinity;
    KeSetSystemGroupAffinityThread(&target, &previous);
    KswordARKHvmNestedProbeExecute(&probe);
    KeRevertToUserGroupAffinityThread(&previous);
    MmFreeContiguousMemory(probe.VmxonVirtual);
    MmFreeContiguousMemory(probe.Vmcs12Virtual);
    /* Return a completed probe whatever the individual steps reported. */
    return STATUS_SUCCESS;
}

#else

NTSTATUS
KswordARKHvmNestedProbeRun(
    _In_ const KSWORD_ARK_HVM_NESTED_PROBE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE* Response
    )
{
    UNREFERENCED_PARAMETER(Request);
    /* Zero the output so no caller reads uninitialized probe state. */
    if (Response != NULL) {
        RtlZeroMemory(Response, sizeof(*Response));
        Response->status =
            KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NOT_ARMED;
    }
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

#endif
