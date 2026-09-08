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

/* Tag the per-processor private-hierarchy descriptor array. */
#define KSW_HVM_EPT_LOCAL_ARRAY_POOL_TAG 'AvHK'
#include "hvm_exit.h"
#include "hvm_event.h"
/* The multicore start gate asks the view records whether any would flip a leaf. */
#include "hvm_ept_view.h"
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
/* Guest page-directory base, reloaded by hand after VMXOFF. */
#define KSW_VMCS_GUEST_CR3 0x6802UL
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
    /*
     * Own every private EPT hierarchy, appended after Processors so no
     * existing offset moves.  NULL whenever the feature was not armed for
     * this residency.
     */
    KSW_HVM_EPT_LOCAL* EptLocalArray;
    /* Retain how many hierarchies the array holds, for the release path. */
    ULONG EptLocalCount;
    /* Keep the tail deterministic for crash-dump inspection. */
    ULONG Reserved1;
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

#pragma pack(push, 1)
/* The ten-byte operand SIDT stores. */
typedef struct _KSW_HVM_IDT_REGISTER
{
    USHORT Limit;
    ULONG_PTR Base;
} KSW_HVM_IDT_REGISTER;

/* One 64-bit interrupt gate. */
typedef struct _KSW_HVM_IDT_ENTRY
{
    USHORT OffsetLow;
    USHORT Selector;
    /* Bits 2:0 select the interrupt stack table entry; the rest is type/DPL/P. */
    USHORT IstAndType;
    USHORT OffsetMiddle;
    ULONG OffsetHigh;
    ULONG Reserved;
} KSW_HVM_IDT_ENTRY;
#pragma pack(pop)

/* A full 64-bit IDT is 256 sixteen-byte gates. */
#define KSW_HVM_IDT_VECTOR_COUNT 256UL
#define KSW_HVM_IDT_BYTES \
    (KSW_HVM_IDT_VECTOR_COUNT * sizeof(KSW_HVM_IDT_ENTRY))
/* Vector 2 is NMI. */
#define KSW_HVM_IDT_VECTOR_NMI 2UL
/*
 * CPUID.1:EBX[31:24] is eight bits wide, so it addresses at most this many
 * processors.  A machine with more logical processors than that reports its
 * ids through CPUID leaf 0x0B instead and would alias here; the send path
 * refuses to fire in that case rather than signalling the wrong processor.
 */
#define KSW_HVM_APIC_ID_CAPACITY 256UL

/*
 * Where the guest's vector 2 pointed, so the stub can forward there.
 *
 * Not static: hvm_entry.asm jumps through it by name.
 */
ULONGLONG g_KswordHvmOriginalNmiHandler = 0ULL;

/* The private VMX-root IDT, or NULL while none has been built. */
static KSW_HVM_IDT_ENTRY* g_KswordHvmHostIdt = NULL;

/*
 * How many NMIs each processor still owes to a flush this driver requested,
 * indexed by initial APIC id.
 *
 * Indexed by APIC id rather than held per VCPU because both consumers have to
 * agree and only one of them can reach a VCPU: the assembly stub runs on an
 * interrupt frame in VMX root with the host GS base loaded and no per-processor
 * pointer available, so CPUID.1:EBX[31:24] is the only identity it can get
 * cheaply.  The C dispatcher indexes the same array with the id its own
 * processor recorded at launch, so the two halves consume one ledger.
 *
 * Both halves are needed because an NMI cannot be told to wait: one that
 * arrives in VMX non-root becomes a VM exit and is claimed in C, one that
 * arrives in VMX root is delivered through the private IDT and is claimed by
 * the stub.
 *
 * Not static: hvm_entry.asm addresses it by name.
 */
volatile LONG g_KswordHvmPendingTlbNmi[KSW_HVM_APIC_ID_CAPACITY] = { 0 };

/* Read this processor's initial APIC id, the way the stub reads it. */
static ULONG
KswordARKHvmReadInitialApicId(
    VOID
    )
{
    int registers[4] = { 0 };

    __cpuid(registers, 1);
    return ((ULONG)registers[1] >> 24) & 0xFFUL;
}

/*
 * Build one IDT for VMX root, copied from the running one with vector 2
 * redirected.
 *
 * Why VMX root needs its own IDT at all: an NMI that arrives while this
 * processor is in VMX root is **not** converted into a VM exit, whatever the
 * pin controls say - it is delivered through HOST_IDTR_BASE.  That has been
 * the guest's own table, whose vector 2 belongs to Windows, and Windows
 * bugchecks 0x80 on an NMI it cannot attribute to a source it knows.  So a
 * private table is a precondition for this driver ever *sending* an NMI, not
 * an optimization.  Measured 2026-09-07: the first cross-processor flush
 * attempt failed exactly this way.
 *
 * Copied rather than authored: VMX root should raise no exception at all, but
 * "should" is not a guarantee, and a table holding only vector 2 would turn any
 * mistake in the exit path into a triple fault - a reset with no bugcheck and
 * no dump, the least debuggable failure this driver can produce.  Copying keeps
 * every other vector behaving exactly as it does today, so the private table
 * changes the behavior of NMIs and nothing else.
 *
 * Selector, IST index and type/DPL/present bits are preserved from the guest's
 * own descriptor; only the 64-bit offset is rewritten.  The IST index matters
 * most: Windows runs its NMI handler on a dedicated stack, and the stub
 * forwards there, so the stack the processor switches to has to be the one
 * that handler expects.
 *
 * One table for the whole machine.  Windows keeps the same gate layout on
 * every processor - the per-processor half of a stack switch lives in that
 * processor's TSS, which the IST index selects and this table does not carry.
 *
 * Idempotent: the first processor to reach it builds the table and the rest
 * reuse it.  Callers hold the runtime lock.
 */
static NTSTATUS
KswordARKHvmBuildHostIdtLocked(
    VOID
    )
{
    KSW_HVM_IDT_REGISTER idtr = { 0 };
    const KSW_HVM_IDT_ENTRY* source = NULL;
    KSW_HVM_IDT_ENTRY* target = NULL;
    ULONGLONG stub = (ULONGLONG)(ULONG_PTR)KswordARKHvmAsmHostNmiStub;
    ULONG copyBytes = 0UL;

    /* Reuse the table the first processor built. */
    if (g_KswordHvmHostIdt != NULL) {
        return STATUS_SUCCESS;
    }
    __sidt(&idtr);
    /* Refuse a table that cannot even hold the vector being replaced. */
    if (idtr.Base == 0 ||
        idtr.Limit <
            (((KSW_HVM_IDT_VECTOR_NMI + 1UL) *
                sizeof(KSW_HVM_IDT_ENTRY)) - 1UL)) {
        return STATUS_NOT_SUPPORTED;
    }
    source = (const KSW_HVM_IDT_ENTRY*)idtr.Base;
    /* Copy what the running table actually holds, never past its limit. */
    copyBytes = (ULONG)idtr.Limit + 1UL;
    if (copyBytes > (ULONG)KSW_HVM_IDT_BYTES) {
        copyBytes = (ULONG)KSW_HVM_IDT_BYTES;
    }
    target = (KSW_HVM_IDT_ENTRY*)KswordARKAllocateNonPagedPool(
        KSW_HVM_IDT_BYTES,
        KSW_HVM_RESIDENT_POOL_TAG);
    if (target == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Vectors past the guest's limit stay zero: not present, same as absent. */
    RtlZeroMemory(target, KSW_HVM_IDT_BYTES);
    RtlCopyMemory(target, source, copyBytes);
    /* Preserve the forwarding target before overwriting the descriptor. */
    g_KswordHvmOriginalNmiHandler =
        ((ULONGLONG)target[KSW_HVM_IDT_VECTOR_NMI].OffsetLow) |
        (((ULONGLONG)target[KSW_HVM_IDT_VECTOR_NMI].OffsetMiddle) << 16) |
        (((ULONGLONG)target[KSW_HVM_IDT_VECTOR_NMI].OffsetHigh) << 32);
    /* Refuse to install a table whose forwarding target is unusable. */
    if (g_KswordHvmOriginalNmiHandler == 0ULL) {
        ExFreePool(target);
        return STATUS_NOT_SUPPORTED;
    }
    /* Rewrite only the offset; selector, IST and type stay as they were. */
    target[KSW_HVM_IDT_VECTOR_NMI].OffsetLow =
        (USHORT)(stub & 0xFFFFULL);
    target[KSW_HVM_IDT_VECTOR_NMI].OffsetMiddle =
        (USHORT)((stub >> 16) & 0xFFFFULL);
    target[KSW_HVM_IDT_VECTOR_NMI].OffsetHigh =
        (ULONG)((stub >> 32) & 0xFFFFFFFFULL);
    /* Order every descriptor byte before any processor can load the table. */
    KeMemoryBarrier();
    g_KswordHvmHostIdt = target;
    return STATUS_SUCCESS;
}

/* IA32_APIC_BASE. */
#define KSW_IA32_APIC_BASE 0x1BUL
/* IA32_APIC_BASE bit 10: the local APIC is in x2APIC mode. */
#define KSW_APIC_BASE_X2APIC_ENABLED (1ULL << 10)
/* x2APIC interrupt command register, writable with a single WRMSR. */
#define KSW_X2APIC_ICR 0x830UL
/*
 * Delivery mode NMI (100b at bits 10:8) plus destination shorthand
 * "all excluding self" (11b at bits 19:18).
 *
 * The shorthand is what makes this affordable from a VM-exit handler: without
 * it the sender would need a destination field per target and a loop of writes.
 * With it there is one write and no destination to get wrong.
 */
#define KSW_APIC_ICR_NMI_ALL_BUT_SELF 0x000C0400ULL

BOOLEAN
KswordARKHvmResidentClaimTlbNmi(
    _In_ ULONG ApicId
    )
{
    /* Reject an identity that cannot index the ledger. */
    if (ApicId >= KSW_HVM_APIC_ID_CAPACITY) {
        return FALSE;
    }
    /*
     * Claim speculatively and restore on underflow, matching the stub exactly.
     * Testing first and decrementing after would let two deliveries claim one
     * credit; this way the only NMI swallowed is one whose slot really was
     * positive.
     */
    if (InterlockedDecrement(
            &g_KswordHvmPendingTlbNmi[ApicId]) >= 0L) {
        return TRUE;
    }
    InterlockedIncrement(&g_KswordHvmPendingTlbNmi[ApicId]);
    return FALSE;
}

VOID
KswordARKHvmResidentRequestTlbNmi(
    _In_ KSW_HVM_RESIDENT_VCPU* Self
    )
{
    ULONG index = 0UL;
    BOOLEAN anyTarget = FALSE;

    /* Reject a missing caller context before touching the ledger. */
    if (Self == NULL) {
        return;
    }
    /*
     * Without the private IDT an NMI that lands on a target in VMX root goes
     * to the guest's vector 2, and Windows bugchecks 0x80 on an NMI it cannot
     * attribute.  Refusing to send is the only safe answer.
     */
    if (g_KswordHvmHostIdt == NULL) {
        return;
    }
    /*
     * x2APIC only.  In xAPIC mode the ICR is MMIO and would need a page mapped
     * at prepare time; rather than half-implement that, send nothing and let
     * the probe's violation count say whether this machine needed it.
     */
    if ((__readmsr(KSW_IA32_APIC_BASE) &
            KSW_APIC_BASE_X2APIC_ENABLED) == 0ULL) {
        return;
    }
    /*
     * Publish intent before sending.  A broadcast that outran its own ledger
     * entries would be handed to the guest as a spurious NMI - harmless, but it
     * would also flush nothing.
     */
    for (index = 0UL;
         index < g_KswordHvmResident.ProcessorCount;
         ++index) {
        KSW_HVM_RESIDENT_VCPU* context =
            &g_KswordHvmResident.Processors[index];

        /* Skip the processor that is asking; it flushes on its own re-entry. */
        if (context == Self) {
            continue;
        }
        /* Skip processors not in VMX non-root; they hold nothing stale. */
        if (InterlockedCompareExchange(
                &context->Active,
                0L,
                0L) == 0L) {
            continue;
        }
        /* Refuse to signal a processor whose identity cannot index the ledger. */
        if (context->ApicId >= KSW_HVM_APIC_ID_CAPACITY) {
            continue;
        }
        InterlockedIncrement(
            &g_KswordHvmPendingTlbNmi[context->ApicId]);
        anyTarget = TRUE;
    }
    /* Send nothing when this processor is the only resident one. */
    if (!anyTarget) {
        return;
    }
    /* One broadcast reaches every target; there is no per-target send. */
    __writemsr(KSW_X2APIC_ICR, KSW_APIC_ICR_NMI_ALL_BUT_SELF);
}

VOID
KswordARKHvmSetVmreadBenchIterations(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Requested
    )
{
    ULONG depth = Requested;

    /* Reject a missing runtime before publishing measurement state. */
    if (Runtime == NULL) {
        return;
    }
    /* Zero asks for the default rather than for a benchmark that does nothing. */
    if (depth == 0UL) {
        depth = KSWORD_ARK_HVM_VMREAD_BENCH_DEFAULT;
    }
    /*
     * Clamp rather than refuse.  This runs on every exit with interrupts off
     * on the exit stack; a mistyped depth should cost a pinned measurement,
     * not a machine nobody can get back.
     */
    if (depth > KSWORD_ARK_HVM_VMREAD_BENCH_MAX) {
        depth = KSWORD_ARK_HVM_VMREAD_BENCH_MAX;
    }
    InterlockedExchange(
        &Runtime->VmreadBenchIterations,
        (LONG)depth);
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

/*
 * Release host stacks only after every processor has left VMX operation.
 *
 * Returns FALSE when it declined because somebody is still resident, and TRUE
 * when the context set is now released and cleared.  The result matters to
 * callers that go on to overwrite this state: the pointers this function
 * declines to free are the only record of those allocations.
 */
static BOOLEAN
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
        /* Report that a live VMCS host stack was left allocated. */
        return FALSE;
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
    /*
     * Release every private EPT hierarchy alongside the host stacks.  Their
     * lifetimes coincide exactly: the private root is live in VMCS
     * EPT_POINTER for precisely as long as the host stack is live in
     * HOST_RSP, and the early return above guards both.
     *
     * ExFreePool rather than MmFreeContiguousMemory: this runs on a teardown
     * path a power callback can reach, where PASSIVE_LEVEL is not guaranteed.
     * That constraint is why the module allocates one nonpaged block per
     * processor instead of one contiguous page per table.
     */
    if (g_KswordHvmResident.EptLocalArray != NULL) {
        for (index = 0UL;
             index < g_KswordHvmResident.EptLocalCount;
             ++index) {
            /* Idempotent on a record whose build never completed. */
            KswordARKHvmEptLocalRelease(
                &g_KswordHvmResident.EptLocalArray[index]);
        }
        ExFreePool(g_KswordHvmResident.EptLocalArray);
        g_KswordHvmResident.EptLocalArray = NULL;
        g_KswordHvmResident.EptLocalCount = 0UL;
    }
    /* Clear every stale pointer after all host stacks are released. */
    RtlZeroMemory(
        &g_KswordHvmResident,
        sizeof(g_KswordHvmResident));
    /* Report a complete release. */
    return TRUE;
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
    /*
     * Build the VMX-root IDT here, at PASSIVE_LEVEL, because it allocates.
     * The processors that will load it enter VMX from an IPI worker where
     * allocation is not available.
     *
     * A failure is not fatal to preparing: HostIdtBase stays zero, VMX root
     * keeps running on the guest's table exactly as it did before, and the
     * only capability lost is sending NMIs - which nothing does unless this
     * succeeded.
     */
    (void)KswordARKHvmBuildHostIdtLocked();
    /*
     * Release reusable stopped contexts before replacing their runtime, and
     * refuse to continue if that release did not happen.
     *
     * The zeroing below is what makes this mandatory rather than tidy: the
     * host stack pointers live only in the structure it clears, so preparing
     * over a set the release declined to free leaks them outright - 32 KiB per
     * processor plus that processor's private EPT block, with nothing left
     * pointing at either.  The release declines for one reason, somebody is
     * still resident, and preparing on top of live contexts would be wrong
     * even if it leaked nothing.
     */
    if (!KswordARKHvmResidentReleaseContexts()) {
        /* Return the exact lifecycle-ordering failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
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
    /*
     * Publish the VMREAD measurement request where the exit path can see it.
     *
     * The depth was written by the caller before this point, so arming last
     * means the exit path never observes an armed benchmark whose iteration
     * count has not been decided yet.
     */
    InterlockedExchange(
        &Runtime->VmreadBenchArmed,
        ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_VMREAD_BENCH) != 0UL)
            ? 1L
            : 0L);
    /*
     * Publish whether routine exits go into the ring, before the first exit.
     *
     * Set per resident start rather than sticky, so a run that did not ask for
     * a trace never inherits one from an earlier run - a trace silently left on
     * would fill the ring and evict exactly the evidence the next run is
     * looking for, which is the failure this default exists to prevent.
     */
    InterlockedExchange(
        &Runtime->TraceRoutineExits,
        ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS) != 0UL)
            ? 1L
            : 0L);
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
            (void)KswordARKHvmResidentReleaseContexts();
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
    /*
     * The one and only place a per-processor EPT pointer is selected.  When
     * the feature is off EptLocal is NULL and this is the assignment it has
     * always been.
     */
    input.EptPointer = Context->EptLocal != NULL
        ? Context->EptLocal->EptPointer
        : Context->Runtime->EptPointer;
    /*
     * Whatever pointer was just selected is the base for this processor, so
     * its hierarchy state starts at "on the base, never switched".
     *
     * Reset here rather than once at start because this is where the field is
     * (re)written - a power transition or any other reconfiguration puts the
     * processor back on the base pointer, and a ledger that still claimed a
     * secondary index would make every later decision from a premise the VMCS
     * no longer supports.  The forward-progress record has to go with it: a
     * stale (RIP, page, target) from before the reconfiguration would make the
     * first legitimate switch afterwards look like a cycle, and the machine
     * would fail closed immediately after installing a view.
     */
    Context->ActiveEptpIndex = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    KswordArkHvmEptSwProgressReset(&Context->EptpSwitchProgress);
    /* Keep resident guest MSR access native through the shared bitmap. */
    input.MsrBitmapPhysical =
        (ULONGLONG)Context->Runtime->MsrBitmapPhysical.QuadPart;
    /*
     * Control-register policy is consumed here rather than applied later: the
     * guest/host masks and the CR3/DR exiting controls are VMCS fields, so a
     * policy installed after launch would not take effect until the next one.
     */
    input.Cr0PinnedMask = Context->Runtime->CrPolicyCr0PinnedMask;
    /* Pin the same way for CR4. */
    input.Cr4PinnedMask = Context->Runtime->CrPolicyCr4PinnedMask;
    /* Request address-space switch observation only when asked. */
    input.TrackCr3 = (Context->Runtime->CrPolicyFlags &
        KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) != 0UL ? 1U : 0U;
    /* Request debug-register interception only when asked. */
    input.InterceptDr = (Context->Runtime->CrPolicyFlags &
        KSWORD_ARK_HVM_CR_POLICY_FLAG_INTERCEPT_DR) != 0UL ? 1U : 0U;
    /* Resume on the exact assembly wrapper stack. */
    input.GuestStackPointer =
        Context->LaunchStackPointer;
    /* Receive VM exits on the processor-owned anchored host stack. */
    input.HostStackPointer =
        Context->HostStackPointer;
    /*
     * Run the exit handler on the System address space, captured at prepare
     * time.  Residency outlives the process that requested it, so anything
     * derived from the current CR3 here would be freed underneath a live VMCS.
     */
    input.HostCr3 = Context->Runtime->HostCr3;
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
    /*
     * Record what ends up enforced, so the protocol can report which control
     * bits this machine made mandatory rather than which ones we asked for.
     */
    input.ActiveControls = &Context->Runtime->ActiveControls;
    /*
     * Run VMX root on the private IDT when one was built; zero keeps the
     * guest's table, which is what every build before this one used.
     */
    input.HostIdtBase = (ULONGLONG)(ULONG_PTR)g_KswordHvmHostIdt;
    /* Select nested instruction exposure only when explicitly requested. */
    input.EnableNestedVmx =
        Context->Nested.Enabled ? 1U : 0U;
    /*
     * #VE is opt-in per start and stays inert on its own.  The information
     * area is this processor's alone; it was latched busy at allocation, so
     * the processor keeps choosing the ordinary EPT-violation exit.
     */
    input.EnableVe = ((g_KswordHvmResident.Flags &
        KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE) != 0UL) ? 1U : 0U;
    /* Point at this processor's area so a conversion has somewhere to land. */
    input.VeInfoPhysical =
        (ULONGLONG)Context->Resource->VeInfoPhysical.QuadPart;
    /*
     * VM functions are opt-in per start, like #VE.  Unlike #VE they have no
     * second safety net: once armed, any ring-3 instruction can switch views.
     * The protection is structural instead - a domain can only ever hold
     * fewer permissions than the default view.
     */
    input.EnableVmFunctions = ((g_KswordHvmResident.Flags &
        KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC) != 0UL) ? 1U : 0U;
    /* Share the one list; domains are global, not per-processor. */
    input.EptpListPhysical =
        (ULONGLONG)Context->Runtime->EptpListPhysical.QuadPart;
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
    if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_EXIT_CONTROLS, &exitControls) != 0U) {
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
            if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_S_CET, &value) != 0U) {
                status = STATUS_HV_OPERATION_FAILED;
            } else {
                Context->GuestSCet = (ULONGLONG)value;
            }
        }
    }
    /*
     * Flush any translations cached under this EPT root before the first
     * entry uses it.
     *
     * A private hierarchy is built out of recycled nonpaged memory, so its
     * root address may have tagged cached guest-physical translations from an
     * earlier residency - the architecture does not require VMXON to discard
     * them.  Entering with a stale tag would let the processor use mappings
     * that describe pages this hierarchy never mapped.
     *
     * This used to run only for private roots, on the stated assumption that
     * "the shared hierarchy is invalidated on every path that changes it".
     * **That assumption is false, and it was measured false.**
     *
     * The paths that change the shared hierarchy - installing an EPT rule or
     * a split view - do call KswordARKHvmResidentInvalidateEpt, but that
     * wrapper is a no-op while no processor is resident.  And a rule or a view
     * can *only* be installed while residency is stopped, because the exit
     * path reads those tables without taking the lock.  So the entire sequence
     * is: change the shared leaf, invalidate nothing, start residency, enter
     * without invalidating - and the processor keeps using translations it
     * cached under this same root during an earlier residency.
     *
     * The symptom is the worst kind this project has: a restriction that is
     * correctly written into the leaf and simply never takes effect.  Measured
     * on 2026-09-06 - the base leaf read back as execute-only
     * (0x8000000175692034, R=0 W=0 X=1) while a kernel read of that very page
     * completed and returned the real contents, with no EPT violation and no
     * exit.  It reproduced for both EPT rules and split views, and it passed
     * on an earlier run only because that run's freshly allocated page
     * happened to carry no stale tag.
     *
     * Invalidate whichever root this entry will actually load.  The cost is
     * one INVEPT per entry on a path that already does far more than that.
     */
    if (NT_SUCCESS(status) && input.EptPointer != 0ULL) {
        if (KswordARKHvmAsmInveptSingle(input.EptPointer) != 0U) {
            /* Refuse the entry rather than launch on an unproven context. */
            status = STATUS_HV_OPERATION_FAILED;
        }
    }
    /*
     * Do the same for every secondary hierarchy this entry could switch to.
     *
     * The invalidation above covers only the root that gets loaded, and for a
     * long time that was every root there was.  The EPTP-switching backend
     * added more: a violation can VMWRITE EPT_POINTER to any built
     * EptSwitch.Eptp[k] without ever passing through here again.  Those roots
     * carry exactly the same stale-tag exposure, and worse, they are **more**
     * likely to be stale than the base:
     *
     *   - a slot's pages are a fixed slice computed from its index
     *     (hvm_ept_switch.c:127), and the pool outlives residency, so
     *     removing a view and adding another hands the new one the same slot,
     *     the same four pages, and therefore **the same EPTP bit pattern**
     *     while the tables underneath now describe a different page;
     *   - KswordARKHvmResidentInvalidateEpt cannot help: it refuses any
     *     pointer that is not the shared root (see its parameter check), so
     *     nothing on the view install or release path ever invalidates these.
     *
     * That is the 2026-09-06 defect - a restriction correctly written into a
     * leaf that simply never takes effect - with the fault moved from the base
     * root to a secondary one. It is also the stated prerequisite for opening
     * the multicore gate to this backend: do that first and the same failure
     * comes back, only now with a second processor able to observe it.
     *
     * Slot 0 duplicates the base and is invalidated twice; INVEPT is
     * idempotent and this runs once per processor at residency start, not per
     * exit, so the cost is not worth a special case.
     */
    if (NT_SUCCESS(status) &&
        Context->Runtime->EptSwitch.Active) {
        ULONG hierarchy = 0UL;
        ULONG ledgerLength = Context->Runtime->EptSwitch.HierarchyCount;

        /* Never index past the fixed ledger, whatever the recorded length. */
        if (ledgerLength >
            (KSWORD_ARK_HVM_MAX_VIEWS + 1UL)) {
            ledgerLength = KSWORD_ARK_HVM_MAX_VIEWS + 1UL;
        }
        for (hierarchy = 0UL;
             hierarchy < ledgerLength;
             ++hierarchy) {
            ULONGLONG secondary =
                Context->Runtime->EptSwitch.Eptp[hierarchy];

            /* Skip the slots this runtime never built. */
            if (secondary == 0ULL) {
                continue;
            }
            if (KswordARKHvmAsmInveptSingle(secondary) != 0U) {
                /* Refuse the entry rather than launch on an unproven context. */
                status = STATUS_HV_OPERATION_FAILED;
                break;
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
    if (KswordARKHvmVmcsFieldStore(
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
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_S_CET, &value) != 0U) {
            return FALSE;
        }
        Context->GuestSCet = (ULONGLONG)value;
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_SSP, &value) != 0U) {
            return FALSE;
        }
        Context->GuestSsp = (ULONGLONG)value;
        if (KswordARKHvmVmcsFieldLoad(
                KSW_VMCS_GUEST_INTERRUPT_SSP_TABLE,
                &value) != 0U) {
            return FALSE;
        }
        Context->GuestInterruptSspTable = (ULONGLONG)value;
    }
    if (Context->PkrsStateManaged != 0U) {
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_PKRS, &value) != 0U) {
            return FALSE;
        }
        Context->GuestPkrs = (ULONGLONG)value;
    }
    if (Context->UinvStateManaged != 0U) {
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_UINV, &value) != 0U) {
            return FALSE;
        }
        Context->GuestUinv = (ULONGLONG)value & 0xFFULL;
    }
    if (Context->DebugStateManaged != 0U) {
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_DEBUGCTL, &value) != 0U) {
            return FALSE;
        }
        Context->GuestDebugControl = (ULONGLONG)value;
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_DR7, &value) != 0U) {
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
        /*
         * Record the identity the flush ledger is indexed by, before this
         * processor can be a target.  Written here rather than at prepare
         * because CPUID only answers for the processor executing it, and this
         * is the point where that is guaranteed to be this context's own.
         */
        Context->ApicId = KswordARKHvmReadInitialApicId();
        /* Publish active ownership before any valid VM exit can occur. */
        InterlockedExchange(&Context->Active, 1L);
        /*
         * Count this processor **before** the entry that can make it exit,
         * paired with the marker above and not with the success path below.
         *
         * The two used to be split across VMLAUNCH: marker before, count
         * after.  That leaves a window a few instructions wide where the
         * processor is already in VMX non-root but uncounted, and an exit
         * taken there that fails closed decrements a count this processor
         * never added.  The window is real - VM entry resumes the guest at
         * KswordARKHvmResidentGuestResume, which returns into the C code just
         * below, so those instructions genuinely execute in non-root - and the
         * devirtualization path decrements unconditionally in assembly.
         *
         * The damage is not a bad free: every release site tests `!= 0` rather
         * than `<= 0`, so an undercount fails those guards instead of passing
         * them.  It is worse in a quieter way - the count never returns to
         * zero, so contexts are never released and hvm_resident.c refuses to
         * start residency again.  A machine that needs a reboot, with nothing
         * logged to say why.
         *
         * Nothing can exit between these two writes: VM entry has not happened
         * yet, so there is no window on this side.  The failure path below
         * settles the symmetry by testing the marker it clears.
         */
        InterlockedIncrement(
            &Context->Runtime->ResidentProcessorCount);
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
            /* The count was already published alongside the active marker. */
            /* Preserve successful current-processor status. */
            status = STATUS_SUCCESS;
            /* Leave the guarded transition block in guest context. */
            __leave;
        }
        /* Read VMfailValid detail while the failed VMCS remains current. */
        if (vmxResult == 1U) {
            SIZE_T instructionError = 0U;

            /* Preserve VM-instruction error when VMREAD succeeds. */
            if (KswordARKHvmVmcsFieldLoad(
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
        /*
         * Remove a premature active marker, and give back the count only if
         * this is the one removing it.
         *
         * The marker is the discriminator, and it is exact.  Devirtualization
         * clears it and decrements in assembly, so a nonzero old value here
         * means no exit path ran and the count raised before VMLAUNCH is still
         * outstanding; a zero old value means one already did both.  Testing
         * the exchange's old value rather than reading the marker separately
         * is what keeps that from being two decisions that can disagree.
         *
         * This also covers the failures that never reached VMLAUNCH at all -
         * including an exception before the marker was ever set, where the old
         * value is zero and nothing was counted to give back.
         */
        if (InterlockedExchange(&Context->Active, 0L) != 0L) {
            /* Give back the count this processor raised and never used. */
            InterlockedDecrement(
                &Context->Runtime->ResidentProcessorCount);
        }
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
     * A fail-closed exit is a whole-machine event, so publish it before this
     * processor does anything else.
     *
     * This call only devirtualizes the current processor, and the IPI
     * rendezvous that could reach the others is unusable from here (VMX root,
     * indeterminate IRQL).  The remaining processors therefore have to notice
     * on their own, and the earliest they can is their next VM exit - so the
     * request has to be visible before this one leaves VMX rather than after.
     *
     * Only on Faulted.  The planned per-processor stop also lands here with
     * Faulted == FALSE (the KSW_HVM_HYPERCALL_STOP branch of the dispatcher)
     * and must not drag the other processors out with it; the rendezvous is
     * already stopping them one by one, in order, with the correct instruction
     * length.
     */
    if (Faulted) {
        /* Publish the whole-machine stop request before leaving VMX. */
        InterlockedExchange(
            &Context->Runtime->ResidentFaultStopRequested,
            1L);
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
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_RSP,
            &guestRsp) != 0U ||
        KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_RIP,
            &guestRip) != 0U ||
        KswordARKHvmVmcsFieldLoad(
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
    /*
     * Capture the guest address space while the VMCS is still current.  VMXOFF
     * leaves HOST_CR3 loaded, and HOST_CR3 is the System address space, so
     * without this the guest would resume on somebody else's page tables.
     */
    {
        SIZE_T guestCr3 = 0;

        /* Read the exact space the guest was executing on. */
        if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_CR3, &guestCr3) == 0U &&
            guestCr3 != 0) {
            /* Publish it for the post-VMXOFF restoration below. */
            Context->GuestCr3 = (ULONGLONG)guestCr3;
        } else {
            /* Refuse to resume the guest on an unverified address space. */
            Context->LastStatus = STATUS_HV_OPERATION_FAILED;
            /* Report that no safe devirtualization occurred. */
            return FALSE;
        }
    }
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
    /*
     * Return to the guest's own address space immediately.  VMXOFF leaves
     * HOST_CR3 loaded, and that is the System space, not the space this thread
     * belongs to.  Everything below runs on kernel addresses, which both spaces
     * map identically, so the only visible symptom of getting this wrong is the
     * requesting process quietly losing its user half after it resumes.
     */
    __writecr3((ULONG_PTR)Context->GuestCr3);
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
    /*
     * Whether this residency actually gets per-processor hierarchies.  Both
     * halves matter: the caller has to ask, and the runtime has to have armed
     * the capability at prepare time.  Everything downstream keys off this
     * single value so the two conditions cannot drift apart.
     */
    BOOLEAN localEptRequested = FALSE;
    KSWORD_ARK_HVM_EVENT_ROW eventRow = { 0 };

    /* Reject a missing runtime before evaluating lifecycle policy. */
    if (Runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Resolve the per-processor EPT decision once, before any gate reads it. */
    localEptRequested =
        ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT) != 0UL &&
         Runtime->LocalEptArmed)
        ? TRUE
        : FALSE;
    /*
     * Resident entry requires the complete driver-side lifecycle guard set,
     * plus the MSR bitmap.  Without the bitmap every RDMSR and WRMSR exits
     * unconditionally, so residency would collapse on the first MSR access
     * the running system performs.
     */
    if (!Runtime->ResidentStartAllowed ||
        Runtime->MsrBitmapPhysical.QuadPart == 0LL ||
        (Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_INTEL |
             KSWORD_ARK_HVM_FEATURE_MSR_BITMAP |
             KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED)) !=
            (KSWORD_ARK_HVM_FEATURE_INTEL |
             KSWORD_ARK_HVM_FEATURE_MSR_BITMAP |
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
     * Running underneath another hypervisor means we become L1: every VMX
     * operation is emulated by the outer hypervisor rather than executed
     * directly.  That is slower and the capability set is whatever the outer
     * one chose to expose, but it is not incorrect - and it is the only
     * environment where this code can be exercised without risking the
     * development machine on every mistake.
     *
     * The previous unconditional refusal cited "complete outer-hypercall
     * forwarding and active eVMCS ownership" as prerequisites.  That over-
     * states the requirement: plain VMREAD/VMWRITE work under nested VMX
     * because the outer hypervisor emulates them; enlightened VMCS is a
     * performance optimization, not a correctness one.
     *
     * So the gate becomes an explicit opt-in plus evidence that the outer
     * hypervisor actually exposes nested VMX.  Without the opt-in the refusal
     * stands, because bare-metal residency remains the intended mode.
     */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL ||
         (Runtime->FeatureFlags &
             KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED) == 0ULL)) {
        /* Return the explicit hypervisor ownership conflict. */
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
    /*
     * #VE is refused rather than silently downgraded.  A caller that asked
     * for it and got a run without it would draw exactly the wrong conclusion
     * about what the guest is exposed to, and this is not a feature to be
     * wrong about in that direction.
     */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE) != 0UL &&
        (Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_EPT_VIOLATION_VE) == 0ULL) {
        /* Return the exact unsupported-control failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * The EPTP-switching backend is incompatible with per-processor
     * hierarchies and with VM functions, and this is the **only** place that
     * check can actually fire.
     *
     * The protocol layer already refuses a single request carrying
     * ENABLE_EPTP_SWITCH together with either of them - but the three flags
     * never ride the same request: the first is read by PREPARE, the other two
     * by START_RESIDENT.  So that refusal has nothing to refuse, and without
     * this one a runtime prepared with the switching backend could then be
     * started with VMFUNC or per-processor EPT armed.
     *
     * Why the composite has no meaning: per-processor hierarchies exist to
     * bound a leaf *write* to one processor, and this backend never writes a
     * leaf at run time; VM functions publish one shared EPTP list that guest
     * code selects from by index, while this backend's indices are private to
     * each processor and mean different things on each.  Guessing a behaviour
     * for either combination would produce a machine that hangs with no
     * bugcheck rather than an error.
     */
    if (Runtime->EptpSwitchArmed &&
        (Flags &
            (KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT |
             KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC)) != 0UL) {
        /* Return the exact unsupported-control failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * VM functions are refused the same way, and additionally require the
     * list to exist.  Arming the control without a list would leave guest
     * VMFUNC reading entries the driver never wrote.
     */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC) != 0UL &&
        (Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING |
             KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY)) !=
            (KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING |
             KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY)) {
        /* Return the exact unsupported-control failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * Per-processor EPT is refused rather than downgraded, for the same
     * reason as #VE and VMFUNC: a caller that asked for per-processor
     * isolation and silently got a shared hierarchy would install views on a
     * multicore box believing each flip is local, which is exactly the
     * corruption the flag exists to prevent.
     */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT) != 0UL &&
        !Runtime->LocalEptArmed) {
        /* Return the exact unsupported-control failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * VMFUNC publishes ONE EPTP list that every processor shares, and the
     * guest selects entries from it by index.  Per-processor hierarchies mean
     * the same index would name a different hierarchy on each processor, so
     * the two mechanisms cannot describe the same machine.
     */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT) != 0UL &&
        (Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC) != 0UL) {
        /* Return the exact conflicting-request failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Nested VMX composes its own EPT pointer from the guest hypervisor's
     * hierarchy and ours.  Handing it a per-processor root would make that
     * composition processor-dependent, which nothing downstream expects.
     */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT) != 0UL &&
        (Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX) != 0UL) {
        /* Return the exact conflicting-request failure. */
        return STATUS_INVALID_PARAMETER;
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
        /*
         * Reject every SHARED-leaf temporary grant on a multicore target.
         * With per-processor hierarchies the leaf is no longer shared, so the
         * topology clause - and only that clause - stops applying.  The
         * capability clause is unchanged: single-context INVEPT and the
         * Monitor Trap Flag are required either way.
         */
        if ((Runtime->ProcessorCount != 1UL && !localEptRequested) ||
            (Runtime->FeatureFlags &
                (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
                 KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) !=
                (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
                 KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) {
            /* Return before host-stack allocation or any VMX transition. */
            return STATUS_NOT_SUPPORTED;
        }
    }
    /*
     * Views installed on a multicore box are only safe while this residency
     * actually gives each processor its own hierarchy.  The predicate is
     * deliberately a property of installed state alone - it does not consult
     * the arm latch, because a start that simply omits the flag must still be
     * refused.  Making the latch part of the condition would turn the single
     * thing standing between an installed view and a shared-leaf flip into
     * something a caller can switch off.
     */
    if (Runtime->EptViewCount != 0UL &&
        Runtime->ProcessorCount != 1UL &&
        !localEptRequested &&
        !KswordARKHvmEptViewAllSwitchBackedLocked(Runtime)) {
        /* Return before host-stack allocation or any VMX transition. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * A view backed by the EPTP-switching hierarchy needs no extra refusal
     * here: the exit path services it by writing this processor's own
     * EPT_POINTER, and every case that cannot be served that way - an access
     * no single hierarchy can represent, or a switch that would not advance
     * RIP - is refused by the planner and fails closed exactly like a failed
     * leaf flip.
     *
     * The temporary refusal that used to sit here was removed together with
     * that wiring; it existed only while the hierarchies were built but never
     * loaded.
     *
     * This paragraph was true and the gate directly above it still refused
     * anyway, for months, because it was written before that backend existed
     * and nobody rechecked it when this comment was added. The gate now asks
     * KswordARKHvmEptViewAllSwitchBackedLocked - which reads the installed
     * records rather than any latch, so the two can never drift apart again.
     *
     * The records, not the latch, on purpose. The predicate that matters is
     * "can any installed view flip a shared leaf", and only the records answer
     * it directly. Asking whether the switching backend is armed happens to
     * give the same answer today, but it is an inference across three separate
     * facts, and if any of them ever stops holding the gate opens onto a
     * shared-leaf flip on a multicore box - silent data corruption with no
     * exit, no event and no bugcheck.
     */
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
    /*
     * Build the private hierarchies here: after the contexts exist, before
     * any processor can enter VMX.  All-or-nothing on purpose - a processor
     * bound to a half-built hierarchy would walk into whatever the unfinished
     * tables happened to contain.
     *
     * The caller holds the runtime push lock exclusive across this whole
     * routine, so nothing here may acquire it.
     */
    if (localEptRequested) {
        ULONGLONG leafBases[KSW_HVM_MAX_LOCAL_LEAVES] = { 0 };
        ULONG leafCount = 0UL;

        status = KswordARKHvmEptLocalCollectLeaves(
            Runtime,
            leafBases,
            KSW_HVM_MAX_LOCAL_LEAVES,
            &leafCount);
        if (!NT_SUCCESS(status)) {
            (void)KswordARKHvmResidentReleaseContexts();
            InterlockedExchange(
                &Runtime->ResidentContextPreparing,
                0L);
            /* Return the exact leaf-collection failure. */
            return status;
        }
        /*
         * No flippable leaf means nothing would ever be written privately,
         * so building hierarchies would cost pages and change no behavior.
         * Every Context->EptLocal stays NULL and the run is byte-for-byte
         * the shared-hierarchy run.
         */
        if (leafCount != 0UL) {
            KSW_HVM_EPT_LOCAL* localArray = NULL;
            ULONG built = 0UL;
            ULONG index = 0UL;

            localArray = (KSW_HVM_EPT_LOCAL*)
                KswordARKAllocateNonPagedPool(
                    (SIZE_T)g_KswordHvmResident.ProcessorCount *
                        sizeof(KSW_HVM_EPT_LOCAL),
                    KSW_HVM_EPT_LOCAL_ARRAY_POOL_TAG);
            if (localArray == NULL) {
                (void)KswordARKHvmResidentReleaseContexts();
                InterlockedExchange(
                    &Runtime->ResidentContextPreparing,
                    0L);
                /* Return the exact nonpaged-resource failure. */
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(
                localArray,
                (SIZE_T)g_KswordHvmResident.ProcessorCount *
                    sizeof(KSW_HVM_EPT_LOCAL));
            for (index = 0UL;
                 index < g_KswordHvmResident.ProcessorCount;
                 ++index) {
                status = KswordARKHvmEptLocalBuild(
                    Runtime,
                    leafBases,
                    leafCount,
                    &localArray[index]);
                if (!NT_SUCCESS(status)) {
                    /* Stop at the first failure; the tail stays zeroed. */
                    break;
                }
                built += 1UL;
            }
            /*
             * Prove the result independently of how it was built.  A mistake
             * shared between the build and a replay of the build would
             * survive both, so this walks each private root from the top.
             */
            if (NT_SUCCESS(status)) {
                status = KswordARKHvmEptLocalVerify(
                    Runtime,
                    localArray,
                    g_KswordHvmResident.ProcessorCount,
                    leafBases,
                    leafCount);
            }
            if (!NT_SUCCESS(status)) {
                for (index = 0UL; index < built; ++index) {
                    KswordARKHvmEptLocalRelease(&localArray[index]);
                }
                ExFreePool(localArray);
                (void)KswordARKHvmResidentReleaseContexts();
                InterlockedExchange(
                    &Runtime->ResidentContextPreparing,
                    0L);
                /* Return the exact build or verification failure. */
                return status;
            }
            /* Publish only after every hierarchy is built AND verified. */
            for (index = 0UL;
                 index < g_KswordHvmResident.ProcessorCount;
                 ++index) {
                g_KswordHvmResident.Processors[index].EptLocal =
                    &localArray[index];
            }
            g_KswordHvmResident.EptLocalArray = localArray;
            g_KswordHvmResident.EptLocalCount =
                g_KswordHvmResident.ProcessorCount;
        }
    }
    /* Own the transition phase without holding its state lock over the IPI. */
    status = KswordARKHvmAcquireResidentTransition(Runtime);
    if (!NT_SUCCESS(status)) {
        (void)KswordARKHvmResidentReleaseContexts();
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
        (void)KswordARKHvmResidentReleaseContexts();
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
        (void)KswordARKHvmResidentReleaseContexts();
        InterlockedExchange(
            &Runtime->ResidentContextPreparing,
            0L);
        KswordARKHvmReleaseResidentTransition(Runtime);
        return guardStatus;
    }
    /* Publish starting state before any processor enters VMX non-root. */
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STARTING);
    /*
     * Clear any stop request left over from a previous fail-closed exit.
     *
     * It is per-runtime and set from a VM-exit handler, so nothing else can
     * clear it: the processor that set it is on its way out, and the ones that
     * consume it are leaving too.  Clearing here - after the starting state is
     * published and before the first processor enters VMX non-root - is the one
     * point where no processor is resident and no exit can be in flight.
     * Miss it and the next START devirtualizes every processor on its first
     * exit, which would look exactly like "residency refuses to hold".
     */
    InterlockedExchange(&Runtime->ResidentFaultStopRequested, 0L);
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
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
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
            KswordARKHvmStateClear(
                Runtime,
                KSWORD_ARK_HVM_STATE_RESIDENT_STARTING);
            InterlockedExchange(
                &Runtime->ResidentContextPreparing,
                0L);
            KswordARKHvmReleaseResidentTransition(Runtime);
            return status;
        }
        /* Release host stacks only after rollback reached zero active CPUs. */
        (void)KswordARKHvmResidentReleaseContexts();
        /* Restore unload only outside a power transition. */
        if (InterlockedCompareExchange(
                &Runtime->PowerTransitionPending,
                0L,
                0L) == 0L) {
            guardStatus = KswordARKHvmDisarmUnloadGuard(Runtime);
        }
        /* Clear transient state after a complete, verified rollback. */
        KswordARKHvmStateClear(
            Runtime,
            KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
                KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
                KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
                KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        Runtime->ResidentImplementation =
            Runtime->ResidentStartAllowed
                ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
                : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
        if (!NT_SUCCESS(guardStatus)) {
            /* A stuck unload slot is fail-closed and requires intervention. */
            KswordARKHvmStateSet(
                Runtime,
                KSWORD_ARK_HVM_STATE_FAULTED |
                    KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
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
    KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STARTING);
    /* Publish resident active only after every target processor succeeds. */
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE);
    /*
     * Publish whether the #VE control is armed on this residency.  It says
     * the control is on, not that any #VE can be delivered: suppress-#VE on
     * every leaf and the latched-busy information area both still stand
     * between the control and an actual guest exception.
     */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE) != 0UL) {
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_VE_ACTIVE);
    }
    /* Publish whether guest code can switch views with a single VMFUNC. */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC) != 0UL) {
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE);
    }
    /*
     * Record whether this residency is nested.  Callers must be able to tell
     * the two apart: under an outer hypervisor every VMX operation is emulated,
     * so timings, available capabilities and failure modes all differ from
     * bare metal.  Presenting them as the same result would make any
     * measurement taken here misleading.
     */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL) {
        /* Publish the degraded nested-residency marker. */
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_NESTED);
    } else {
        /* Clear any marker left by an earlier nested run. */
        KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_NESTED);
    }
    /* Clear stale rollback evidence after complete startup. */
    KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
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
            (void)KswordARKHvmResidentReleaseContexts();
        }
        /* Clear protocol-visible resident active state. */
        KswordARKHvmStateClear(
            Runtime,
            KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
                KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
                KSWORD_ARK_HVM_STATE_VE_ACTIVE |
                KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE |
                KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE |
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
            KswordARKHvmStateSet(
                Runtime,
                KSWORD_ARK_HVM_STATE_FAULTED |
                    KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
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
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
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
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        /* Publish explicit partial maturity rather than active success. */
        Runtime->ResidentImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
        /* Clear transient stopping state after the failed rendezvous. */
        KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
        KswordARKHvmReleaseResidentTransition(Runtime);
        /* Return the authoritative stop or incomplete rollback failure. */
        return NT_SUCCESS(status)
            ? STATUS_HV_OPERATION_FAILED
            : status;
    }
    /* Release host stacks after every CPU completes VMXOFF. */
    (void)KswordARKHvmResidentReleaseContexts();
    /* Clear all resident lifecycle state after complete rollback. */
    KswordARKHvmStateClear(
        Runtime,
        KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
            KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
            KSWORD_ARK_HVM_STATE_VE_ACTIVE |
            KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE |
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
        KswordARKHvmStateSet(
            Runtime,
            KSWORD_ARK_HVM_STATE_FAULTED |
                KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
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
