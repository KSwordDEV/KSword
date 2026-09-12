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
#include "hvm_vmcs.h"
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

/* Name the VMCS fields the L2 construction writes by hand. */
#define KSW_PROBE_VMCS_LINK_POINTER 0x2800UL
#define KSW_PROBE_GUEST_EFER 0x2806UL
#define KSW_PROBE_PIN_CONTROLS 0x4000UL
#define KSW_PROBE_PRIMARY_CONTROLS 0x4002UL
#define KSW_PROBE_EXCEPTION_BITMAP 0x4004UL
#define KSW_PROBE_EXIT_CONTROLS 0x400CUL
#define KSW_PROBE_ENTRY_CONTROLS 0x4012UL
#define KSW_PROBE_EXIT_REASON 0x4402UL
#define KSW_PROBE_GUEST_ACTIVITY 0x4826UL
#define KSW_PROBE_GUEST_INTERRUPTIBILITY 0x4824UL
#define KSW_PROBE_GUEST_CR0 0x6800UL
#define KSW_PROBE_GUEST_CR3 0x6802UL
#define KSW_PROBE_GUEST_CR4 0x6804UL
#define KSW_PROBE_GUEST_DR7 0x681AUL
#define KSW_PROBE_GUEST_RSP 0x681CUL
#define KSW_PROBE_GUEST_RFLAGS 0x6820UL
#define KSW_PROBE_HOST_RSP 0x6C14UL
#define KSW_PROBE_HOST_RIP 0x6C16UL
#define KSW_PROBE_EXIT_QUALIFICATION 0x6400UL

/* Name the entry control that runs L2 in 64-bit mode. */
#define KSW_PROBE_ENTRY_IA32E_MODE 0x00000200UL
/* Name the exit control that returns to a 64-bit host. */
#define KSW_PROBE_EXIT_HOST_ADDRESS_SPACE 0x00000200UL
/* Name the MSR holding IA32_EFER. */
#define KSW_PROBE_IA32_EFER 0xC0000080UL
/* Name the unusable marker for a segment with no descriptor. */
#define KSW_PROBE_SEGMENT_UNUSABLE 0x10000UL

/* Bound the stack the probe's own L1 exit handler runs on. */
#define KSW_PROBE_L1_STACK_BYTES 8192UL

/*
 * Declared here because the WDK headers this driver includes do not.
 *
 * Both are exported by ntoskrnl and are the only way to get control back from
 * a VM-exit handler that lands on a stack of our choosing with nothing to
 * unwind to.  Declaring them locally is preferable to reaching for a private
 * header: the prototypes are stable and documented, and the alternative is
 * hand-written assembly doing the same thing less clearly.
 */
NTSYSAPI VOID NTAPI RtlCaptureContext(_Out_ PCONTEXT ContextRecord);
NTSYSAPI VOID NTAPI RtlRestoreContext(
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _EXCEPTION_RECORD* ExceptionRecord);

/* Carry one probe's working state across the pinned execution. */
typedef struct _KSW_HVM_NESTED_PROBE_CONTEXT
{
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE* Response;
    PVOID VmxonVirtual;
    ULONGLONG VmxonPhysical;
    PVOID Vmcs12Virtual;
    ULONGLONG Vmcs12Physical;
    /* One page of L2 code, plus the stack L2 runs on. */
    PVOID L2CodeVirtual;
    /* The stack this probe's own L1 VM-exit handler runs on. */
    PVOID L1StackVirtual;
} KSW_HVM_NESTED_PROBE_CONTEXT;

/*
 * The probe's L2 result, reached from a different stack.
 *
 * Module scope rather than on the stack because the L1 exit handler below runs
 * on its own stack with no argument: the only channel between it and the code
 * that launched L2 is memory that both can name.  Safe here because the probe
 * is pinned, single-shot, and serialized by the IOCTL path - none of which
 * would hold for a production path, and none of which is assumed elsewhere.
 */
static volatile LONG g_KswordProbeL2Exited;
static volatile ULONGLONG g_KswordProbeL2ExitReason;
static volatile ULONGLONG g_KswordProbeL2Qualification;
static volatile ULONGLONG g_KswordProbeL2GuestRip;
static CONTEXT g_KswordProbeResumeContext;

/*
 * The probe's own L1 VM-exit handler - where vmcs12's host RIP points.
 *
 * Reached only if the whole chain worked: vmcs02 merged, L2 entered, L2 took
 * an exit, and our reflection loaded vmcs01 and set L1's guest state to this
 * function.  So arriving here at all is the positive result; the exit reason
 * read below says what L2 did.
 *
 * The VMREADs here are executed by L1 and go through nested dispatch against
 * vmcs12 - which is the second thing being tested: L1 has to be able to read
 * the exit information our reflection wrote.
 */
DECLSPEC_NOINLINE
static VOID
KswordARKHvmNestedProbeL1Host(
    VOID
    )
{
    SIZE_T value = 0U;

    if (__vmx_vmread((SIZE_T)KSW_PROBE_EXIT_REASON, &value) == 0) {
        g_KswordProbeL2ExitReason = (ULONGLONG)value;
    }
    if (__vmx_vmread((SIZE_T)KSW_PROBE_EXIT_QUALIFICATION, &value) == 0) {
        g_KswordProbeL2Qualification = (ULONGLONG)value;
    }
    if (__vmx_vmread((SIZE_T)KSW_PROBE_VMCS_GUEST_RIP, &value) == 0) {
        g_KswordProbeL2GuestRip = (ULONGLONG)value;
    }
    InterlockedExchange(&g_KswordProbeL2Exited, 1L);
    /* Leave emulated VMX operation before abandoning this stack. */
    __vmx_off();
    /*
     * Return to the launcher by restoring the context it captured.
     *
     * A VM exit does not return to its caller - it lands here on a stack this
     * function was given, with nothing to unwind to.  Restoring the captured
     * context is the only way back, and it is exactly a longjmp: the launcher
     * resumes just after its capture, with the flag above already set.
     */
    RtlRestoreContext(&g_KswordProbeResumeContext, NULL);
}

/* Write one field into vmcs12 through nested dispatch, ignoring refusal. */
static VOID
KswordARKHvmNestedProbeVmcs12Write(
    _In_ ULONG Field,
    _In_ ULONGLONG Value
    )
{
    (void)__vmx_vmwrite((SIZE_T)Field, (SIZE_T)Value);
}

/* Program one segment's four guest-state fields from a resolved descriptor. */
static VOID
KswordARKHvmNestedProbeWriteSegment(
    _In_ ULONG SelectorField,
    _In_ const KSW_HVM_SEGMENT_STATE* Segment
    )
{
    KswordARKHvmNestedProbeVmcs12Write(
        SelectorField,
        Segment->Selector);
    /* Limit, access rights and base sit at fixed strides from the selector. */
    KswordARKHvmNestedProbeVmcs12Write(
        0x4800UL + (SelectorField - 0x0800UL),
        Segment->Limit);
    KswordARKHvmNestedProbeVmcs12Write(
        0x4814UL + (SelectorField - 0x0800UL),
        Segment->AccessRights);
    KswordARKHvmNestedProbeVmcs12Write(
        0x6806UL + (SelectorField - 0x0800UL),
        Segment->Base);
}

/*
 * Fill vmcs12 with a complete description of one minimal L2.
 *
 * L2 runs in 64-bit mode on the *current* address space: same CR0/CR3/CR4 and
 * EFER, same descriptor tables.  That is deliberate - building an independent
 * address space for L2 would mean building page tables, and none of what is
 * under test here depends on L2 having its own.  What it does depend on is
 * guest state that VM entry accepts, and the surest source of state that a
 * processor accepts is the state that processor is running right now.
 */
static VOID
KswordARKHvmNestedProbeBuildVmcs12(
    _In_ const KSW_HVM_NESTED_PROBE_CONTEXT* Probe
    )
{
    KSW_HVM_SEGMENT_SNAPSHOT snapshot = { 0 };
    KSW_HVM_SEGMENT_STATE segment = { 0 };
    ULONGLONG efer = __readmsr(KSW_PROBE_IA32_EFER);

    KswordARKHvmCaptureSegments(&snapshot);
    /* Controls: ask for nothing beyond 64-bit entry and exit. */
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_PIN_CONTROLS, 0ULL);
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_PRIMARY_CONTROLS, 0ULL);
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_EXCEPTION_BITMAP, 0ULL);
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_EXIT_CONTROLS,
        KSW_PROBE_EXIT_HOST_ADDRESS_SPACE);
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_ENTRY_CONTROLS,
        KSW_PROBE_ENTRY_IA32E_MODE);
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_VMCS_LINK_POINTER,
        ~0ULL);
    /* Guest control registers and mode. */
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_GUEST_CR0, __readcr0());
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_GUEST_CR3, __readcr3());
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_GUEST_CR4, __readcr4());
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_GUEST_EFER, efer);
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_GUEST_DR7, 0x400ULL);
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_GUEST_ACTIVITY, 0ULL);
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_GUEST_INTERRUPTIBILITY,
        0ULL);
    /* Guest segments, resolved from the descriptor tables we are using. */
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Es, &segment);
    KswordARKHvmNestedProbeWriteSegment(0x0800UL, &segment);
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Cs, &segment);
    KswordARKHvmNestedProbeWriteSegment(0x0802UL, &segment);
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Ss, &segment);
    KswordARKHvmNestedProbeWriteSegment(0x0804UL, &segment);
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Ds, &segment);
    KswordARKHvmNestedProbeWriteSegment(0x0806UL, &segment);
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Fs, &segment);
    KswordARKHvmNestedProbeWriteSegment(0x0808UL, &segment);
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Gs, &segment);
    /* GS base lives in an MSR, not in the descriptor the selector names. */
    segment.Base = __readmsr(0xC0000101UL);
    KswordARKHvmNestedProbeWriteSegment(0x080AUL, &segment);
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Ldtr, &segment);
    KswordARKHvmNestedProbeWriteSegment(0x080CUL, &segment);
    (void)KswordARKHvmReadSegment(&snapshot, snapshot.Tr, &segment);
    KswordARKHvmNestedProbeWriteSegment(0x080EUL, &segment);
    /* Descriptor tables. */
    KswordARKHvmNestedProbeVmcs12Write(0x4810UL, snapshot.Gdtr.Limit);
    KswordARKHvmNestedProbeVmcs12Write(0x6816UL, snapshot.Gdtr.Base);
    KswordARKHvmNestedProbeVmcs12Write(0x4812UL, snapshot.Idtr.Limit);
    KswordARKHvmNestedProbeVmcs12Write(0x6818UL, snapshot.Idtr.Base);
    /* Where L2 starts, and the stack it starts on. */
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_VMCS_GUEST_RIP,
        (ULONGLONG)(ULONG_PTR)Probe->L2CodeVirtual);
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_GUEST_RSP,
        (ULONGLONG)(ULONG_PTR)Probe->L2CodeVirtual + (PAGE_SIZE - 256ULL));
    KswordARKHvmNestedProbeVmcs12Write(KSW_PROBE_GUEST_RFLAGS, 0x2ULL);
    /* Host state: where L1 wants control back, and on which stack. */
    KswordARKHvmNestedProbeVmcs12Write(0x0C00UL, snapshot.Es);
    KswordARKHvmNestedProbeVmcs12Write(0x0C02UL, snapshot.Cs);
    KswordARKHvmNestedProbeVmcs12Write(0x0C04UL, snapshot.Ss);
    KswordARKHvmNestedProbeVmcs12Write(0x0C06UL, snapshot.Ds);
    KswordARKHvmNestedProbeVmcs12Write(0x0C08UL, snapshot.Fs);
    KswordARKHvmNestedProbeVmcs12Write(0x0C0AUL, snapshot.Gs);
    KswordARKHvmNestedProbeVmcs12Write(0x0C0CUL, snapshot.Tr);
    KswordARKHvmNestedProbeVmcs12Write(0x6C00UL, __readcr0());
    KswordARKHvmNestedProbeVmcs12Write(0x6C02UL, __readcr3());
    KswordARKHvmNestedProbeVmcs12Write(0x6C04UL, __readcr4());
    KswordARKHvmNestedProbeVmcs12Write(0x6C0CUL, snapshot.Gdtr.Base);
    KswordARKHvmNestedProbeVmcs12Write(0x6C0EUL, snapshot.Idtr.Base);
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_HOST_RIP,
        (ULONGLONG)(ULONG_PTR)&KswordARKHvmNestedProbeL1Host);
    KswordARKHvmNestedProbeVmcs12Write(
        KSW_PROBE_HOST_RSP,
        ((ULONGLONG)(ULONG_PTR)Probe->L1StackVirtual +
            KSW_PROBE_L1_STACK_BYTES - 256ULL) & ~0xFULL);
}

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
            /*
             * Only attempt L2 once the field plumbing demonstrably works.
             *
             * A VMLAUNCH built on a vmcs12 whose writes are not landing would
             * fail on guest state and report a field problem, which is a true
             * statement about the wrong layer.
             */
            if (response->vmreadMatched == 1UL) {
                KswordARKHvmNestedProbeBuildVmcs12(Probe);
                g_KswordProbeL2ExitReason = 0ULL;
                g_KswordProbeL2Qualification = 0ULL;
                g_KswordProbeL2GuestRip = 0ULL;
                InterlockedExchange(&g_KswordProbeL2Exited, 0L);
                RtlCaptureContext(&g_KswordProbeResumeContext);
                /*
                 * Two paths arrive here.
                 *
                 * The first is the ordinary one, immediately after the
                 * capture, with the flag clear - that path launches.  The
                 * second is the L1 exit handler restoring this context, with
                 * the flag set - that path must not launch again.  The flag
                 * is read through an interlocked access so it comes from
                 * memory rather than a register the restore just rewrote.
                 */
                if (InterlockedCompareExchange(
                        &g_KswordProbeL2Exited, 0L, 0L) == 0L) {
                    response->vmlaunchResult =
                        (ULONG)__vmx_vmlaunch();
                } else {
                    /* Reached only by the restore: L2 ran and came back. */
                    response->vmlaunchResult = 0UL;
                    response->l2Reached = 1UL;
                }
                response->l2ExitReason = g_KswordProbeL2ExitReason;
                response->l2Qualification = g_KswordProbeL2Qualification;
                response->l2GuestRip = g_KswordProbeL2GuestRip;
                /*
                 * The handler already executed VMXOFF on its own stack, so
                 * the sequence below must not do it twice.
                 */
                if (response->l2Reached != 0UL) {
                    response->vmxoffResult = 0UL;
                    __writecr4(originalCr4);
                    response->dispatchedInstructions =
                        vcpu->Nested.InstructionCount - startingCount;
                    response->nestedStateAfter = vcpu->Nested.State;
                    response->lastInstructionError =
                        vcpu->Nested.LastInstructionError;
                    response->status =
                        KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK;
                    /* Return without a second VMXOFF. */
                    return;
                }
            }
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
    Response->vmlaunchResult = KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED;
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
    probe.L2CodeVirtual = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, lowest, highest, boundary, MmCached);
    probe.L1StackVirtual = KswordARKAllocateNonPagedPool(
        KSW_PROBE_L1_STACK_BYTES,
        'pnHK');
    if (probe.VmxonVirtual == NULL || probe.Vmcs12Virtual == NULL ||
        probe.L2CodeVirtual == NULL || probe.L1StackVirtual == NULL) {
        if (probe.VmxonVirtual != NULL) {
            MmFreeContiguousMemory(probe.VmxonVirtual);
        }
        if (probe.Vmcs12Virtual != NULL) {
            MmFreeContiguousMemory(probe.Vmcs12Virtual);
        }
        if (probe.L2CodeVirtual != NULL) {
            MmFreeContiguousMemory(probe.L2CodeVirtual);
        }
        if (probe.L1StackVirtual != NULL) {
            ExFreePool(probe.L1StackVirtual);
        }
        Response->status =
            KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NO_RESOURCES;
        /* Return the exact allocation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(probe.VmxonVirtual, PAGE_SIZE);
    RtlZeroMemory(probe.Vmcs12Virtual, PAGE_SIZE);
    RtlZeroMemory(probe.L1StackVirtual, KSW_PROBE_L1_STACK_BYTES);
    /*
     * L2's entire program: CPUID, then an unreachable self-loop.
     *
     * CPUID exits unconditionally under VMX, so L2 executes exactly one
     * instruction before control returns - the shortest program that proves it
     * ran.  The loop after it exists so that a reflection which fails to stop
     * L2 parks it instead of running off the page into whatever follows.
     */
    RtlZeroMemory(probe.L2CodeVirtual, PAGE_SIZE);
    ((volatile UCHAR*)probe.L2CodeVirtual)[0] = 0x0FU;
    ((volatile UCHAR*)probe.L2CodeVirtual)[1] = 0xA2U;
    ((volatile UCHAR*)probe.L2CodeVirtual)[2] = 0xEBU;
    ((volatile UCHAR*)probe.L2CodeVirtual)[3] = 0xFEU;
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
    MmFreeContiguousMemory(probe.L2CodeVirtual);
    ExFreePool(probe.L1StackVirtual);
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
