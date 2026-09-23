/* Transactional control of a single composed-EPT page override. */
#include "hvm_nested_ept.h"
#include "hvm_resident.h"
#include "hvm_metrics.h"
#include "hvm_event.h"
#include "../../platform/pool_compat.h"

#if defined(_M_AMD64)
/* Use one tag for the allocation and every rejection/reclamation path. */
#define KSW_HVM_PAGE_POOL_TAG 'PvHK'
/* Permit only page-aligned architectural physical addresses. */
#define KSW_HVM_PAGE_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Operation ids survive resource teardown and reset only at driver load. */
static volatile LONG g_PageOperationSequence;
/* Serialize process-object publication against the process-exit callback. */
static KSPIN_LOCK g_PageOwnerLock;
/* Unregistration drains callbacks before driver resources are released. */
static BOOLEAN g_PageOwnerNotifyRegistered;
/* This documented process identity is independent of private EPROCESS offsets. */
NTSYSAPI LONGLONG NTAPI PsGetProcessCreateTimeQuadPart(_In_ PEPROCESS Process);
/* ntddk does not declare the documented ntifs process lookup export. */
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

static VOID KswordARKHvmPageRevoke(KSW_HVM_RUNTIME* Runtime, ULONG Reason)
{
    /* Only the first observer changes this lease's policy generation. */
    if (InterlockedCompareExchange(&Runtime->NestedPageRevocationReason,
            (LONG)Reason, (LONG)KSWORD_ARK_HVM_PAGE_LEASE_VALID) == 0L) {
        /* Future entries must discard translations composed under the old policy. */
        InterlockedIncrement((volatile LONG*)&Runtime->NestedPageGeneration);
    }
}

static int KswordARKHvmPageReadSource(void* Context, KSW_LEASE_U64 Address,
    KSW_LEASE_U64* Value)
{
    MM_COPY_ADDRESS source;
    SIZE_T copied = 0U;
    NTSTATUS status;
    /* Admission runs below APC_LEVEL; no mapping-manager call occurs in VMX root. */
    UNREFERENCED_PARAMETER(Context);
    /* Only ordinary physical RAM is accepted by this checked kernel copy. */
    source.PhysicalAddress.QuadPart = (LONGLONG)Address;
    /* Reject a partial read rather than interpreting uninitialized entry bits. */
    status = MmCopyMemory(Value, source, sizeof(*Value), MM_COPY_MEMORY_PHYSICAL, &copied);
    /* Both status and copied length must establish a complete source word. */
    return NT_SUCCESS(status) && copied == sizeof(*Value);
}

static int KswordARKHvmPageReadSourceRoot(void* Context, KSW_LEASE_U64 Address,
    KSW_LEASE_U64* Value)
{
    /* The per-CPU window performs no allocation or operating-system memory call. */
    return NT_SUCCESS(KswordARKHvmPhysWindowReadQword(
        (KSW_HVM_PHYS_WINDOW*)Context, Address, Value));
}

BOOLEAN KswordARKHvmNestedPageValidateTranslation(KSW_HVM_RUNTIME* Runtime,
    KSW_HVM_PHYS_WINDOW* Window, ULONGLONG EptPointer)
{
    KSW_HVM_NESTED_PAGE* page;
    int result;
    /* The all-CPU retirement barrier pins any pointer a root reader observes. */
    page = (KSW_HVM_NESTED_PAGE*)ReadPointerAcquire((PVOID volatile*)&Runtime->NestedPage);
    /* Unrelated roots need no page-policy work. */
    if (page == NULL || page->Ept12Pointer != EptPointer) { return TRUE; }
    /* Revocation is sticky until an explicit drain and a new map operation. */
    if (ReadAcquire(&Runtime->NestedPageRevocationReason) != 0L) { return FALSE; }
    /* Refuse any legacy/inconsistent rule that relies on sampled fine leaves. */
    if (page->ScanAdmitted || !KswordHvmLeafPolicySourceCovers(
            page->Plan.LeafShift, page->Translation.EntryCount)) {
        KswordARKHvmPageRevoke(Runtime, KSWORD_ARK_HVM_PAGE_LEASE_REGION_DRIFTED);
        return FALSE;
    }
    /* Compare all captured path entries, never just a recycled root pointer. */
    result = KswordHvmLeaseValidate(&page->Translation, KswordARKHvmPageReadSourceRoot, Window);
    /* A mismatch and an inaccessible source are separately observable rejections. */
    if (result != 1) {
        /* Retain backing; this callback is not a global invalidation acknowledgement. */
        KswordARKHvmPageRevoke(Runtime, result == 0 ?
            KSWORD_ARK_HVM_PAGE_LEASE_TRANSLATION_CHANGED : KSWORD_ARK_HVM_PAGE_LEASE_SOURCE_UNREADABLE);
    }
    /* Re-read after validation to notice another CPU's simultaneous revocation. */
    return ReadAcquire(&Runtime->NestedPageRevocationReason) == 0L;
}

/* Legacy diagnostic sampler. New admission rejects fine-source coarse rules.
   Fill-driven sampling has no wall-clock completion guarantee and must never
   authorize a mapping or substitute for source validation/invalidation. */
VOID KswordARKHvmNestedPageSampleRegion(KSW_HVM_RUNTIME* Runtime,
    KSW_HVM_PHYS_WINDOW* Window)
{
    KSW_HVM_NESTED_PAGE* page;
    LONG cursor;

    page = (KSW_HVM_NESTED_PAGE*)ReadPointerAcquire(
        (PVOID volatile*)&Runtime->NestedPage);
    /* Nothing to recheck for an absent, ordinary, or already revoked lease. */
    if (page == NULL || !page->ScanAdmitted ||
        ReadAcquire(&Runtime->NestedPageRevocationReason) != 0L) {
        return;
    }
    /* One page per sample, from a cursor the planner folds into the region. */
    cursor = InterlockedIncrement(&page->ScanCursor) - 1L;
    /*
     * The decision lives in the planner, beside the scan whose conclusion it
     * rechecks, so the two cannot disagree about which bits matter and so it
     * can be tested without a machine. An unreadable entry is not a proven
     * change: UNKNOWN leaves the lease alone and lets the ordinary path report
     * an unreadable source if it sees one.
     */
    if (KswordHvmLeafPlanRecheckPage(page->Ept12Pointer, &page->Plan,
            (KSW_PLAN_U64)(ULONG)cursor, page->ScanSharedBits,
            KswordARKHvmPageReadSourceRoot, Window) ==
        KSW_PLAN_RECHECK_DRIFTED) {
        KswordARKHvmPageRevoke(Runtime,
            KSWORD_ARK_HVM_PAGE_LEASE_REGION_DRIFTED);
    }
}

static VOID KswordARKHvmPageOwnerNotify(PEPROCESS Process, HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    KIRQL oldIrql;
    /* Only object identity is needed; PID reuse cannot revive an expired lease. */
    UNREFERENCED_PARAMETER(ProcessId);
    /* Process creation cannot invalidate an existing owner's mapping. */
    if (CreateInfo != NULL) { return; }
    /* Match and revoke in one bounded critical section; never wait for VM exits here. */
    KeAcquireSpinLock(&g_PageOwnerLock, &oldIrql);
    /* A rule remains referenced until explicit all-CPU reclamation completes. */
    if (runtime->NestedPageOwner == Process && runtime->NestedPageOwnerExited == 0L) {
        /* Stop new compositions from using the replacement. */
        InterlockedExchange(&runtime->NestedPageOwnerExited, 1L);
        /* Expire both process and translation policy without freeing backing. */
        KswordARKHvmPageRevoke(runtime, KSWORD_ARK_HVM_PAGE_LEASE_OWNER_EXITED);
    }
    /* Release before returning to process teardown. */
    KeReleaseSpinLock(&g_PageOwnerLock, oldIrql);
}

NTSTATUS KswordARKHvmNestedPageGuardInitialize(VOID)
{
    NTSTATUS status;
    /* Initialize once before any page rule can be published. */
    KeInitializeSpinLock(&g_PageOwnerLock);
    /* Use a documented notification, without patching or injecting into the VMM. */
    status = PsSetCreateProcessNotifyRoutineEx(KswordARKHvmPageOwnerNotify, FALSE);
    /* Record only a registration the OS actually accepted. */
    g_PageOwnerNotifyRegistered = NT_SUCCESS(status);
    /* Resident admission is denied if its owner-lifetime guard is unavailable. */
    return status;
}

VOID KswordARKHvmNestedPageGuardShutdown(VOID)
{
    /* Failed initialization has no callback to remove. */
    if (g_PageOwnerNotifyRegistered) {
        /* The OS waits for in-flight callbacks before this routine returns. */
        (void)PsSetCreateProcessNotifyRoutineEx(KswordARKHvmPageOwnerNotify, TRUE);
        /* Prevent a second unregistration on a partial-start cleanup path. */
        g_PageOwnerNotifyRegistered = FALSE;
    }
}

static NTSTATUS KswordARKHvmPageBindOwner(KSW_HVM_RUNTIME* Runtime,
    KSW_HVM_NESTED_PAGE* Page, const KSWORD_ARK_HVM_NESTED_PAGE_REQUEST* Request)
{
    PEPROCESS process = NULL;
    KIRQL oldIrql;
    NTSTATUS status;
    /* A caller must identify a live owner; an EPT address is not a lifetime. */
    if (Request->ownerProcessId <= 4UL || Request->ownerCreationTime == 0ULL) { return STATUS_INVALID_PARAMETER; }
    /* Take the reference before exposing its pointer to the exit callback. */
    status = PsLookupProcessByProcessId(ULongToHandle(Request->ownerProcessId), &process);
    /* Failed lookup owns no reference. */
    if (!NT_SUCCESS(status)) { return status; }
    /* A reused PID must never be mistaken for the selected VMM. */
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(process) != Request->ownerCreationTime) {
        /* Release the unadmitted process reference. */
        ObDereferenceObject(process);
        /* Distinguish identity drift from a resource failure. */
        return STATUS_REVISION_MISMATCH;
    }
    /* The page record owns this reference even if subsequent admission fails. */
    Page->OwnerProcess = process;
    /* Retain exactly the identity validated above. */
    Page->OwnerCreationTime = Request->ownerCreationTime;
    /* Close the callback/publication race before checking termination status. */
    KeAcquireSpinLock(&g_PageOwnerLock, &oldIrql);
    /* A previous retired rule must already have been drained before mapping again. */
    Runtime->NestedPageOwnerExited = 0L;
    /* A prior lease must have been drained before a new owner can be published. */
    Runtime->NestedPageRevocationReason = 0L;
    /* Publish the referenced object, not only its recyclable numeric PID. */
    Runtime->NestedPageOwner = process;
    /* Process exit after publication now marks the rule expired. */
    KeReleaseSpinLock(&g_PageOwnerLock, oldIrql);
    /* Exit before publication is caught here; exit after this check hits the callback. */
    return PsGetProcessExitStatus(process) == STATUS_PENDING ? STATUS_SUCCESS : STATUS_PROCESS_IS_TERMINATING;
}

/* Fixed local metadata remains valid after its backing allocation is freed. */
typedef struct _KSW_HVM_PAGE_TRACE {
    ULONG Id, Operation, Flags;
    ULONGLONG EptPointer, GuestPage, BackingPage;
} KSW_HVM_PAGE_TRACE;

static VOID KswordARKHvmPageTrace(const KSW_HVM_PAGE_TRACE* Trace, ULONG Stage, NTSTATUS Status)
{
    /* Retain the existing event ABI and give its new type explicit semantics. */
    KSWORD_ARK_HVM_EVENT_ROW row = { 0 };
    PROCESSOR_NUMBER processor;
    /* Queries do not advance the transaction trace or generate events. */
    if (Trace->Id == 0UL) { return; }
    /* Record the control caller, not a claim of per-CPU invalidation timing. */
    (void)KeGetCurrentProcessorNumberEx(&processor);
    /* Select the separately decoded page transaction event type. */
    row.type = KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE;
    /* Distinguish this transaction from older events in the same ring. */
    row.ruleId = Trace->Id;
    /* Stage and operation occupy fields otherwise used for VM-exit metadata. */
    row.exitReason = Stage;
    /* Preserve map/remove identity, including fault-injection requests. */
    row.access = Trace->Operation;
    /* Keep the exact explicit fault mode in the trace. */
    row.qualification = Trace->Flags;
    /* Record the target descendant GPA. */
    row.guestPhysicalAddress = Trace->GuestPage;
    /* For this event type, this field is the EPT12 root, not a linear address. */
    row.guestLinearAddress = Trace->EptPointer;
    /* For this event type, this field is backing PA, not an instruction pointer. */
    row.guestRip = Trace->BackingPage;
    /* Record the complete operation result at this boundary. */
    row.status = Status;
    /* Preserve the observing processor group. */
    row.processorGroup = processor.Group;
    /* Preserve the observing processor number. */
    row.processorNumber = processor.Number;
    /* The event publisher stamps QPC and reports ring overwrite/drop counts. */
    KswordARKHvmEventPublish(&row);
}

/*
 * FNV-1a over a region, read one page at a time.
 *
 * Page at a time because the source is physical memory we do not own: a single
 * unreadable page then names itself instead of failing a 2 MiB copy with no
 * indication of where. A page that cannot be read makes the whole digest
 * unavailable rather than silently contributing zeroes, since a digest that
 * quietly skips part of the region would compare equal to one that did not.
 */
static BOOLEAN KswordARKHvmPageDigestPhysical(ULONGLONG Base, ULONGLONG Bytes,
    ULONGLONG* Digest)
{
    ULONGLONG hash = 0xCBF29CE484222325ULL;
    ULONGLONG offset;
    /* A page-sized staging buffer, from the pool rather than the kernel stack:
       4 KiB is a large fraction of one, and this runs under the runtime lock
       where an overflow would be a bugcheck rather than a failed request. */
    UCHAR* page = (UCHAR*)KswordARKAllocateNonPagedPool(PAGE_SIZE,
        KSW_HVM_PAGE_POOL_TAG);

    *Digest = 0ULL;
    if (page == NULL) { return FALSE; }
    for (offset = 0ULL; offset < Bytes; offset += PAGE_SIZE) {
        MM_COPY_ADDRESS source;
        SIZE_T copied = 0U;
        ULONG index;

        source.PhysicalAddress.QuadPart = (LONGLONG)(Base + offset);
        if (!NT_SUCCESS(MmCopyMemory(page, source, PAGE_SIZE,
                MM_COPY_MEMORY_PHYSICAL, &copied)) || copied != PAGE_SIZE) {
            ExFreePoolWithTag(page, KSW_HVM_PAGE_POOL_TAG);
            return FALSE;
        }
        for (index = 0UL; index < PAGE_SIZE; ++index) {
            hash = (hash ^ (ULONGLONG)page[index]) * 0x100000001B3ULL;
        }
    }
    ExFreePoolWithTag(page, KSW_HVM_PAGE_POOL_TAG);
    *Digest = hash;
    return TRUE;
}

static VOID KswordARKHvmNestedPageFree(KSW_HVM_NESTED_PAGE* Page)
{
    /* Failed allocation and empty removal both permit an empty record. */
    if (Page == NULL) { return; }
    /* Owner references remain pinned for the same lifetime as replacement backing. */
    if (Page->OwnerProcess != NULL) {
        KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
        KIRQL oldIrql;
        /* Unpublish the object before releasing its final rule reference. */
        KeAcquireSpinLock(&g_PageOwnerLock, &oldIrql);
        /* A single slot cannot replace another live lease. */
        if (runtime->NestedPageOwner == Page->OwnerProcess) { runtime->NestedPageOwner = NULL; }
        /* Finish the callback barrier before invoking the object manager. */
        KeReleaseSpinLock(&g_PageOwnerLock, oldIrql);
        /* No owner identity is dereferenced from VMX root. */
        ObDereferenceObject(Page->OwnerProcess);
    }
    /* Backing may be absent after an allocation failure. */
    if (Page->ShadowVirtual != NULL) {
        /* Caller has either never published it or drained all possible readers. */
        MmFreeContiguousMemory(Page->ShadowVirtual);
        /* Count actual frees independently of mapping-slot occupancy. */
        KswordARKHvmMetricsAllocation(TRUE, TRUE);
    }
    /* Pair the rule's exact tagged allocation. */
    ExFreePoolWithTag(Page, KSW_HVM_PAGE_POOL_TAG);
    /* Keep failed preparations visible in the object ledger. */
    KswordARKHvmMetricsAllocation(FALSE, TRUE);
}

VOID KswordARKHvmNestedPageResetLocked(KSW_HVM_RUNTIME* Runtime)
{
    /* VMXOFF on every CPU is required for teardown without another rendezvous. */
    if (Runtime->ResidentProcessorCount != 0L) { return; }
    /* Resource teardown owns the runtime lock and cannot race a publication. */
    KswordARKHvmNestedPageFree((KSW_HVM_NESTED_PAGE*)InterlockedExchangePointer(
        (PVOID volatile*)&Runtime->NestedPage, NULL));
    /* Reclaim a retained page only after the stopped lifecycle is proven. */
    KswordARKHvmNestedPageFree(Runtime->NestedPageRetired);
    /* Publish the empty retention slot. */
    Runtime->NestedPageRetired = NULL;
    /* Invalidate stale generation-bound user requests. */
    InterlockedIncrement((volatile LONG*)&Runtime->NestedPageGeneration);
}

static NTSTATUS KswordARKHvmPageRetire(KSW_HVM_RUNTIME* Runtime,
    KSW_HVM_PAGE_TRACE* Trace, BOOLEAN FailFlush)
{
    NTSTATUS status;
    KSW_HVM_NESTED_PAGE* page;
    BOOLEAN unpublished = FALSE;
    /* A failed earlier attempt is retried without losing its pinned backing. */
    if (Runtime->NestedPageRetired == NULL) {
        /* Stop new root readers from discovering the override. */
        Runtime->NestedPageRetired = (KSW_HVM_NESTED_PAGE*)InterlockedExchangePointer(
            (PVOID volatile*)&Runtime->NestedPage, NULL);
        /* The logical mapping changes even if subsequent invalidation fails. */
        InterlockedIncrement((volatile LONG*)&Runtime->NestedPageGeneration);
        /* Delay the event until its retained allocation identity is available. */
        unpublished = TRUE;
    }
    /* Copy identities before any possible free. */
    page = Runtime->NestedPageRetired;
    /* Empty removes still validate the invalidation path. */
    if (page != NULL) {
        /* Preserve the actual retained allocation's EPT identity on retries. */
        Trace->EptPointer = page->Ept12Pointer;
        /* Preserve its target GPA for removal requests without an address. */
        Trace->GuestPage = page->GuestPhysicalPage;
        /* Preserve its backing PA beyond reclamation. */
        Trace->BackingPage = page->ShadowPhysicalPage;
    }
    /* Unpublication is distinct from successful hardware invalidation. */
    if (unpublished) { KswordARKHvmPageTrace(Trace, KSW_HVM_PAGE_UNPUBLISHED, STATUS_SUCCESS); }
    /* Bound the all-CPU drain independently of the user-mode command. */
    KswordARKHvmPageTrace(Trace, KSW_HVM_PAGE_ROLLBACK_BEGIN, STATUS_SUCCESS);
    /* Fault injection omits this drain; it never reports an unexecuted INVEPT. */
    status = FailFlush ? STATUS_HV_OPERATION_FAILED : KswordARKHvmResidentInvalidateEpt(Runtime->EptPointer);
    /* A failed drain leaves all possibly referenced allocations pinned. */
    KswordARKHvmPageTrace(Trace, KSW_HVM_PAGE_ROLLBACK_END, status);
    /* Reclamation is permitted only after every participant acknowledged. */
    if (NT_SUCCESS(status) && page != NULL) {
        /* Both the object and backing are now unreachable by resident readers. */
        KswordARKHvmNestedPageFree(page);
        /* Publish successful retirement after actual reclamation. */
        Runtime->NestedPageRetired = NULL;
        /* Timestamp after free, retaining identities in the local trace. */
        KswordARKHvmPageTrace(Trace, KSW_HVM_PAGE_RECLAIMED, STATUS_SUCCESS);
    }
    /* Return actual drain status; slot occupancy alone is not success. */
    return status;
}

NTSTATUS KswordARKHvmNestedPageControl(const KSWORD_ARK_HVM_NESTED_PAGE_REQUEST* Request,
    KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE* Response)
{
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    KSW_HVM_NESTED_PAGE* page;
    KSW_HVM_PAGE_TRACE trace = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    ULONG index, fault;
    /* Set only when the caller asked for the scan and it proved uniformity. */
    int sourceUniform = 0;
    /* Validate fixed input/output pointers before any state access. */
    if (Request == NULL || Response == NULL || runtime == NULL) { return STATUS_INVALID_PARAMETER; }
    /* Clear every response field, including inactive-page identities. */
    RtlZeroMemory(Response, sizeof(*Response));
    /* Preserve the existing wire layout and version. */
    Response->version = KSWORD_ARK_HVM_NESTED_PAGE_VERSION;
    /* Report the exact compatible fixed buffer length. */
    Response->size = sizeof(*Response);
    /* Prevent asynchronous kernel APCs while owning the push lock. */
    KeEnterCriticalRegion();
    /* Serialize publication, retirement, lifecycle changes, and retries. */
    ExAcquirePushLockExclusive(&runtime->Lock);
    /* Enumerate roots under the same control serialization. */
    KswordARKHvmResidentNestedRoots(Response);
    /* Decode a request-local fault; no global fault switch remains armed. */
    fault = (Request->flags & KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK) >> KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT;
    /* Reject unknown versions, reserved bits and unsupported fault combinations. */
    if (Request->version != KSWORD_ARK_HVM_NESTED_PAGE_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->operation > KSWORD_ARK_HVM_NESTED_PAGE_STAGE ||
        /* Validate before scanning or constructing a shifted synthetic backing. */
        (Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_MAP &&
         Request->leafShift != 0UL &&
         !KswordHvmLeafPolicyValidShift(Request->leafShift)) ||
        /* Granularity is meaningful only when creating the region. */
        (Request->operation != KSWORD_ARK_HVM_NESTED_PAGE_MAP &&
         Request->leafShift != 0UL) ||
        /* A page index is meaningful only when staging one page of it. */
        (Request->operation != KSWORD_ARK_HVM_NESTED_PAGE_STAGE &&
         Request->stagePageIndex != 0UL) ||
        /* Staging edits published backing; it takes no lab fault injection. */
        (Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_STAGE && fault != 0UL) ||
        (Request->flags & ~(KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED |
                            KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE |
                            KSWORD_ARK_HVM_NESTED_PAGE_DIGEST |
                            KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK)) != 0UL ||
        /* Scanning the source only means anything while creating a region. */
        ((Request->flags & KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE) != 0UL &&
         Request->operation != KSWORD_ARK_HVM_NESTED_PAGE_MAP) ||
        fault > KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH ||
        (fault != 0UL && ((Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_QUERY) ||
         (Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_MAP && fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH) ||
         (Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_REMOVE && fault != KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH)))) {
        /* Return a semantic rejection without changing mappings or generations. */
        status = STATUS_INVALID_PARAMETER;
        /* Fill the complete query-compatible response below. */
        goto complete;
    }
    /* A query never emits operation events or mutates the page policy. */
    if (Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_QUERY) { goto complete; }
    /* Preserve explicit confirmation on every mutation, including lab faults. */
    if (Request->confirmationToken != KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (Request->flags & KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED) == 0UL) {
        /* Deny a request that lacks the existing write contract. */
        status = STATUS_ACCESS_DENIED;
        /* No allocation or publication has occurred. */
        goto complete;
    }
    /* Allocate a durable correlation id for an authorized operation. */
    trace.Id = (ULONG)InterlockedIncrement(&g_PageOperationSequence);
    /* Preserve the requested operation. */
    trace.Operation = Request->operation;
    /* Preserve confirmation and fault flags for attribution. */
    trace.Flags = Request->flags;
    /* Preserve the requested root. */
    trace.EptPointer = Request->ept12Pointer;
    /* Preserve the requested descendant physical page. */
    trace.GuestPage = Request->guestPhysicalPage;
    /* Timestamp the start before lifecycle and generation validation. */
    KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_BEGIN, STATUS_SUCCESS);
    /* Reject overlap with an incomplete lifecycle operation. */
    if (!runtime->Initialized || runtime->Busy) { status = STATUS_DEVICE_BUSY; goto complete; }
    /* Do not mutate a runtime whose CPU ownership is already uncertain. */
    if ((runtime->StateFlags & (KSWORD_ARK_HVM_STATE_FAULTED | KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED)) != 0UL) {
        /* Keep any outstanding backing pinned for stopped resource teardown. */
        status = STATUS_INVALID_DEVICE_STATE;
        /* Report the fault without starting another rendezvous. */
        goto complete;
    }
    /* Stale requests cannot remove or replace another transaction's mapping. */
    if (Request->expectedGeneration != runtime->NestedPageGeneration) { status = STATUS_REVISION_MISMATCH; goto complete; }
    /* Removal and retry share the same drain-before-free implementation. */
    if (Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_REMOVE) {
        /* Only the explicit removal test is permitted to omit this drain. */
        status = KswordARKHvmPageRetire(runtime, &trace, fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH);
        /* Return active/retired occupancy as observed after the attempt. */
        goto complete;
    }
    /*
     * Overwrite one 4-KiB page of the live region's replacement backing.
     *
     * This edits memory the descendant may be reading right now. It is not an
     * atomic page update and is not presented as one: a reader concurrent with
     * the copy can observe a mix of old and new bytes, exactly as the manuscript
     * states for the override path generally. What it does guarantee is that no
     * write lands outside the published region, because the index is resolved
     * through the same plan the composition path uses.
     */
    if (Request->operation == KSWORD_ARK_HVM_NESTED_PAGE_STAGE) {
        KSW_HVM_NESTED_PAGE* const live = runtime->NestedPage;

        /* Staging has nothing to edit before a region is published. */
        if (live == NULL) { status = STATUS_NOT_FOUND; goto complete; }
        /* A revoked lease must not accept further edits to retained backing. */
        if (ReadAcquire(&runtime->NestedPageRevocationReason) != 0L) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto complete;
        }
        /* Refuse an index the plan does not own rather than clamping it. */
        if (KswordHvmLeafPlanPageFrame(&live->Plan,
                (KSW_PLAN_U64)Request->stagePageIndex) == 0ULL) {
            status = STATUS_INVALID_PARAMETER;
            goto complete;
        }
        /* Backing is one contiguous block, so the index is a direct offset. */
        RtlCopyMemory((PUCHAR)live->ShadowVirtual +
                ((SIZE_T)Request->stagePageIndex * (SIZE_T)PAGE_SIZE),
            Request->shadow, PAGE_SIZE);
        /* Count applied edits for evidence; the region itself is unchanged. */
        (void)InterlockedIncrement64(&live->StagedPageCount);
        /* No mapping, generation or CPU state changed, so no drain is owed. */
        goto complete;
    }
    /* A map needs a running nested monitor and exclusive ownership of the slot. */
    if (runtime->ResidentProcessorCount == 0L || runtime->NestedPage != NULL || runtime->NestedPageRetired != NULL) {
        /* Never overwrite an allocation that may remain visible in a CPU cache. */
        status = STATUS_DEVICE_BUSY;
        /* Keep the existing mapping intact. */
        goto complete;
    }
    /* Reject alignment errors and addresses wider than the architectural field. */
    if ((Request->guestPhysicalPage & ~KSW_HVM_PAGE_FRAME_MASK) != 0ULL) { status = STATUS_INVALID_PARAMETER; goto complete; }
    /* Require a root actually observed by the resident nested runtime. */
    for (index = 0UL; index < Response->rootCount; ++index) {
        /* Exact EPTP matching preserves its translation configuration bits. */
        if (Response->ept12Roots[index] == Request->ept12Pointer) { break; }
    }
    /* Unknown roots never allocate replacement memory. */
    if (index == Response->rootCount) { status = STATUS_NOT_FOUND; goto complete; }
    /* Timestamp before either allocation. */
    KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_BEGIN, STATUS_SUCCESS);
    /* Allocate the rule independently of its contiguous backing. */
    page = (KSW_HVM_NESTED_PAGE*)KswordARKAllocateNonPagedPool(sizeof(*page), KSW_HVM_PAGE_POOL_TAG);
    /* An object allocation failure never publishes a partial record. */
    if (page == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto complete; }
    /* Count actual object allocation. */
    KswordARKHvmMetricsAllocation(FALSE, FALSE);
    /* Initialize the optional backing before any cleanup can inspect it. */
    RtlZeroMemory(page, sizeof(*page));
    /* Capture a specific ordinary-RAM translation before allocating its replacement. */
    if (!KswordHvmLeaseCapture(Request->ept12Pointer, Request->guestPhysicalPage,
            KswordARKHvmPageReadSource, NULL, &page->Translation) ||
        KswordHvmLeaseValidate(&page->Translation, KswordARKHvmPageReadSource, NULL) != 1) {
        /* Failed or already changed captures cannot create a live mapping. */
        KswordARKHvmNestedPageFree(page);
        /* Preserve a precise admission failure independent of allocation injection. */
        status = STATUS_INVALID_ADDRESS;
        /* Return without changing the published page policy. */
        goto complete;
    }
    /*
     * Decide the region before allocating it, using the planner's own rules.
     *
     * The probe passes a synthetic backing address chosen to satisfy every
     * backing test, so this call answers exactly one question: is the requested
     * granularity admissible for this guest address and this source path?
     * Duplicating those rules here to avoid the synthetic argument would give
     * two places that must agree about what a legal region is.
     */
    {
        const ULONG requestedShift = (Request->leafShift != 0UL)
            ? Request->leafShift : KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_4K;
        KSW_HVM_LEAF_PLAN probe;

        /* Preserve explicitly requested scan diagnostics. Uniform attributes
           no longer override the single-source-leaf admission requirement. */
        if ((Request->flags & KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE) != 0UL) {
            KSW_HVM_LEAF_SOURCE_SCAN scan;

            if (KswordHvmLeafPlanScanSource(Request->ept12Pointer,
                    Request->guestPhysicalPage, requestedShift,
                    KswordARKHvmPageReadSource, NULL, &scan)) {
                sourceUniform = (scan.Uniform != 0 && scan.Complete != 0) ? 1 : 0;
                Response->scannedLeafCount = scan.LeafCount;
                Response->scannedSharedBits = scan.SharedBits;
            }
        }
        if (!KswordHvmLeafPlanCreate(requestedShift, Request->guestPhysicalPage,
                page->Translation.EntryCount, sourceUniform,
                (KSW_PLAN_U64)1ULL << requestedShift,
                (KSW_PLAN_U64)1ULL << requestedShift, &probe)) {
            const ULONG sourceLeafShift =
                KswordHvmLeafSourceShift(page->Translation.EntryCount);
            /* Save diagnostics before reclaiming the never-published rule. */
            KswordARKHvmNestedPageFree(page);
            /*
             * Name the refusal rather than reporting one generic error.
             *
             * A caller that asked for 2 MiB over 512 separately mapped source
             * pages and one that mis-aligned its address have to be told apart:
             * the first is a property of the descendant's own tables and will
             * not change by retrying, the second is the caller's bug.
             */
            status = (probe.Refusal == KSW_PLAN_REFUSE_SOURCE_GRANULARITY ||
                      probe.Refusal == KSW_PLAN_REFUSE_SOURCE_UNKNOWN)
                ? STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER;
            /* Publish the refused geometry so the caller can read why. */
            Response->leafShift = requestedShift;
            Response->sourceLeafShift = sourceLeafShift;
            goto complete;
        }
        page->BackingBytes = probe.RegionBytes;
    }
    /* Allocation injection deliberately exercises cleanup of the allocated object. */
    if (fault != KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ALLOCATE) {
        PHYSICAL_ADDRESS low = { 0 }, high, boundary = { 0 };
        /* Accept any allocatable backing PA supported by the current system. */
        high.QuadPart = MAXLONGLONG;
        /*
         * Force the block onto its own granularity by forbidding it to cross one.
         *
         * A leaf carries a single frame and hardware ignores the address bits
         * below its granularity, so an unaligned 2-MiB block would be read as
         * its own aligned base and serve the wrong bytes with no error anywhere.
         * A request of exactly N bytes that may not cross an N-aligned boundary
         * can only start on one. Left at zero for an ordinary page, which is
         * inherently aligned, so the single-page path is unchanged.
         */
        if (page->BackingBytes > PAGE_SIZE) {
            boundary.QuadPart = (LONGLONG)page->BackingBytes;
        }
        /* Allocate ordinary WB RAM for the whole replacement region. */
        page->ShadowVirtual = MmAllocateContiguousMemorySpecifyCache(
            (SIZE_T)page->BackingBytes, low, high, boundary, MmCached);
    }
    /* An absent backing takes the same cleanup branch as a real allocation failure. */
    if (page->ShadowVirtual == NULL) {
        /* Reclaim the never-published rule. */
        KswordARKHvmNestedPageFree(page);
        /* Preserve an allocation-specific error. */
        status = STATUS_INSUFFICIENT_RESOURCES;
        /* Record the failure boundary without inventing an allocated page. */
        KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, status);
        /* Return with generations and active mappings unchanged. */
        goto complete;
    }
    /* Account for backing as soon as allocation succeeds. */
    KswordARKHvmMetricsAllocation(TRUE, FALSE);
    /*
     * Initialize all content before root readers can discover it.
     *
     * The two granularities mean different things and are initialized
     * differently. A 4-KiB override replaces one page outright, so it takes the
     * caller's inline page and that path is byte-for-byte what it was. A region
     * is a clone: every page including the first is copied from the source, so
     * publishing it changes nothing the descendant can observe, and STAGE then
     * changes the parts that should differ. The inline page is ignored there,
     * because a region that started as one repeated page, or as zeroes, would
     * be an immediate whole-region corruption - the opposite of a control
     * primitive you can arm first and fire later.
     */
    {
        /* The capture folds the guest offset in, and the request is aligned to
           the region, so this is already the region's source base. */
        const ULONGLONG sourceBase = page->Translation.SourcePage;
        const ULONGLONG firstCopied =
            (page->BackingBytes > PAGE_SIZE) ? 0ULL : PAGE_SIZE;
        ULONGLONG offset;

        if (firstCopied != 0ULL) {
            RtlCopyMemory(page->ShadowVirtual, Request->shadow, PAGE_SIZE);
        }
        for (offset = firstCopied; offset < page->BackingBytes; offset += PAGE_SIZE) {
            MM_COPY_ADDRESS source;
            SIZE_T copied = 0U;

            source.PhysicalAddress.QuadPart = (LONGLONG)(sourceBase + offset);
            /* Copy one page at a time so an unreadable page names itself. */
            if (!NT_SUCCESS(MmCopyMemory((PUCHAR)page->ShadowVirtual + offset,
                    source, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &copied)) ||
                copied != PAGE_SIZE) {
                /* Never publish a region holding uninitialized bytes. */
                KswordARKHvmNestedPageFree(page);
                status = STATUS_INVALID_ADDRESS;
                KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, status);
                goto complete;
            }
        }
    }
    /* Allocation/copy may outlive the captured source mapping. */
    if (KswordHvmLeaseValidate(&page->Translation,
            KswordARKHvmPageReadSource, NULL) != 1) {
        KswordARKHvmNestedPageFree(page);
        status = STATUS_REVISION_MISMATCH;
        KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, status);
        goto complete;
    }
    /* Bind lifetime before publication; cleanup also releases failed admission. */
    status = KswordARKHvmPageBindOwner(runtime, page, Request);
    /* A dead or reused owner must not leave any allocated replacement behind. */
    if (!NT_SUCCESS(status)) { KswordARKHvmNestedPageFree(page); goto complete; }
    /* Resolve the actual backing PA for EPT and evidence. */
    page->ShadowPhysicalPage = (ULONGLONG)MmGetPhysicalAddress(page->ShadowVirtual).QuadPart;
    /*
     * Build the published plan from the address actually allocated.
     *
     * The probe above proved the geometry was admissible; this proves the
     * allocator honoured it. The boundary argument is a request, not a
     * guarantee, and an unaligned block would otherwise be published as a leaf
     * that serves the wrong bytes without failing anywhere. A refusal here is a
     * clean rejection, not a downgrade to a smaller leaf.
     */
    if (!KswordHvmLeafPlanCreate(
            (Request->leafShift != 0UL) ? Request->leafShift
                                        : KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_4K,
            Request->guestPhysicalPage, page->Translation.EntryCount,
            sourceUniform, page->ShadowPhysicalPage, page->BackingBytes,
            &page->Plan)) {
        /* Reclaim backing whose address the plan cannot accept. */
        KswordARKHvmNestedPageFree(page);
        status = STATUS_INSUFFICIENT_RESOURCES;
        KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, status);
        goto complete;
    }
    /*
     * Keep the scan's conclusion so the sampler can recheck it.
     *
     * Only for regions the scan admitted: one whose source leaf already covered
     * the region cannot disagree with itself, and its single captured path is
     * already revalidated at every composition.
     */
    page->ScanAdmitted = (page->Plan.LeafShift > KSW_PLAN_SHIFT_4K &&
        KswordHvmLeafSourceShift(page->Translation.EntryCount) <
            page->Plan.LeafShift) ? TRUE : FALSE;
    page->ScanSharedBits = Response->scannedSharedBits;
    page->ScanCursor = 0L;
    /* Store the root identity used by the composition path. */
    page->Ept12Pointer = Request->ept12Pointer;
    /* Store the target page used by the composition path. */
    page->GuestPhysicalPage = Request->guestPhysicalPage;
    /* Retain backing identity independently of object lifetime. */
    trace.BackingPage = page->ShadowPhysicalPage;
    /* Close allocation and initialization timing. */
    KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_ALLOCATE_END, STATUS_SUCCESS);
    /* Cancellation before publication requires no remote invalidation. */
    if (fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_CANCEL) {
        /* Reclaim both allocations while no CPU can reference the rule. */
        KswordARKHvmNestedPageFree(page);
        /* Record completed reclamation with the retained backing identity. */
        KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_RECLAIMED, STATUS_SUCCESS);
        /* Distinguish a requested cancellation from normal mapping success. */
        status = STATUS_CANCELLED;
        /* Preserve the original generation. */
        goto complete;
    }
    /* Publish only a fully initialized rule with one release-ordered pointer swap. */
    (void)InterlockedExchangePointer((PVOID volatile*)&runtime->NestedPage, page);
    /* Invalidate stale control requests once publication occurs. */
    InterlockedIncrement((volatile LONG*)&runtime->NestedPageGeneration);
    /* Record publication separately from eventual cache coherence. */
    KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_PUBLISHED, STATUS_SUCCESS);
    /* Bound the commit invalidation operation. */
    KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_FLUSH_BEGIN, STATUS_SUCCESS);
    /* Simulate a failed call boundary without reporting an actual INVEPT failure. */
    status = fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_COMMIT_FLUSH ?
        STATUS_HV_OPERATION_FAILED : KswordARKHvmResidentInvalidateEpt(runtime->EptPointer);
    /* Record real or explicitly injected commit status. */
    KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_FLUSH_END, status);
    /* Post-commit cancellation follows successful publication and invalidation. */
    if (NT_SUCCESS(status) && fault == KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ROLLBACK) { status = STATUS_CANCELLED; }
    /* Owner exit during commit is a failed transaction, not a successful mapping. */
    if (NT_SUCCESS(status) && ReadAcquire(&runtime->NestedPageOwnerExited) != 0L) { status = STATUS_PROCESS_IS_TERMINATING; }
    /* Source drift observed during commit is not a successful page transaction. */
    if (NT_SUCCESS(status) && ReadAcquire(&runtime->NestedPageRevocationReason) != 0L) { status = STATUS_REVISION_MISMATCH; }
    /* A failed commit must withdraw the override instead of silently leaving it active. */
    if (!NT_SUCCESS(status)) {
        /* Keep the original error; failed rollback remains visible as retired backing. */
        (void)KswordARKHvmPageRetire(runtime, &trace, FALSE);
    }
complete:
    /* A query reports the newest id; an operation reports its own correlation id. */
    Response->operationId = trace.Id != 0UL ? trace.Id : (ULONG)InterlockedCompareExchange(&g_PageOperationSequence, 0L, 0L);
    /* Retained memory is reported even when logical publication has ended. */
    page = runtime->NestedPage != NULL ? runtime->NestedPage : runtime->NestedPageRetired;
    /* Keep semantic operation failures independent from IOCTL transport success. */
    Response->status = NT_SUCCESS(status) ? 0UL : 1UL;
    /* Preserve the precise original operation status. */
    Response->lastStatus = (ULONG)status;
    /* Return the current control generation. */
    Response->generation = runtime->NestedPageGeneration;
    /* Report logical mapping occupancy. */
    Response->active = runtime->NestedPage != NULL && ReadAcquire(&runtime->NestedPageRevocationReason) == 0L;
    /* Report potentially referenced, unreclaimed backing. */
    Response->retired = runtime->NestedPageRetired != NULL || (runtime->NestedPage != NULL && ReadAcquire(&runtime->NestedPageRevocationReason) != 0L);
    /* Preserve resident participant count for the caller's preconditions. */
    Response->residentProcessors = (ULONG)runtime->ResidentProcessorCount;
    /* Only dereference an allocation still owned by the runtime. */
    if (page != NULL) {
        /* Report the stable owner and the reason backing may still be retained. */
        Response->ownerProcessId = HandleToULong(PsGetProcessId(page->OwnerProcess));
        /* Preserve the process creation identity for both live and expired leases. */
        Response->ownerCreationTime = page->OwnerCreationTime;
        /* This flag does not claim that retained backing has already been freed. */
        Response->ownerExited = ReadAcquire(&runtime->NestedPageOwnerExited) != 0L;
        /* Report the first reason this translation lease ceased to authorize remapping. */
        Response->leaseRevocationReason = (ULONG)ReadAcquire(&runtime->NestedPageRevocationReason);
        /* Preserve admission-time source identity after automatic revocation. */
        Response->sourcePhysicalPage = page->Translation.SourcePage;
        /* Expose only the bounded captured path for machine-readable evidence. */
        Response->sourceEntryCount = page->Translation.EntryCount;
        /* The arrays are immutable from publication until reclamation. */
        RtlCopyMemory(Response->sourceEntryAddress, page->Translation.EntryAddress, sizeof(Response->sourceEntryAddress));
        /* Keep normalized values alongside their exact physical entry addresses. */
        RtlCopyMemory(Response->sourceEntryValue, page->Translation.EntryValue, sizeof(Response->sourceEntryValue));
        /* Return its exact translation identity. */
        Response->ept12Pointer = page->Ept12Pointer;
        /* Return its exact descendant page. */
        Response->guestPhysicalPage = page->GuestPhysicalPage;
        /* Return its replacement backing. */
        Response->shadowPhysicalPage = page->ShadowPhysicalPage;
        /* Sample the original backing discovered during composition. */
        Response->originalPhysicalPage = (ULONGLONG)InterlockedCompareExchange64(&page->OriginalPhysicalPage, 0LL, 0LL);
        /* Sample actual composition hits independently. */
        Response->composedCount = (ULONGLONG)InterlockedCompareExchange64(&page->ComposedCount, 0LL, 0LL);
        /* Report the granularity actually published and the region it owns. */
        Response->leafShift = page->Plan.LeafShift;
        Response->regionBytes = page->Plan.RegionBytes;
        Response->regionPageCount = page->Plan.PageCount;
        /* Report what limited that granularity, so a refusal reads without a walk. */
        Response->sourceLeafShift =
            KswordHvmLeafSourceShift(page->Translation.EntryCount);
        /* A published region whose source is finer was admitted by scanning. */
        Response->admittedByScan =
            (page->Plan.LeafShift > KSW_PLAN_SHIFT_4K &&
             KswordHvmLeafSourceShift(page->Translation.EntryCount) <
                 page->Plan.LeafShift) ? 1UL : 0UL;
        /*
         * Digests are computed only on request: each one reads the whole region.
         * Both sides or neither, so that "equal" is never an artefact of one
         * side having been skipped.
         */
        if ((Request->flags & KSWORD_ARK_HVM_NESTED_PAGE_DIGEST) != 0UL &&
            page->Plan.Refusal == KSW_PLAN_OK && page->ShadowVirtual != NULL) {
            ULONGLONG sourceDigest = 0ULL, backingDigest = 0ULL;

            if (KswordHvmLeafPolicySourceCovers(page->Plan.LeafShift,
                    page->Translation.EntryCount) &&
                KswordHvmLeaseValidate(&page->Translation,
                    KswordARKHvmPageReadSource, NULL) == 1 &&
                KswordARKHvmPageDigestPhysical(page->Translation.SourcePage,
                    page->BackingBytes, &sourceDigest) &&
                KswordARKHvmPageDigestPhysical(page->ShadowPhysicalPage,
                    page->BackingBytes, &backingDigest) &&
                KswordHvmLeaseValidate(&page->Translation,
                    KswordARKHvmPageReadSource, NULL) == 1) {
                Response->sourceDigest = sourceDigest;
                Response->backingDigest = backingDigest;
                Response->digestBytes = page->BackingBytes;
            }
        }
        /* Report applied staged edits; publication alone leaves this zero. */
        Response->stagedPageCount =
            (ULONGLONG)InterlockedCompareExchange64(&page->StagedPageCount, 0LL, 0LL);
    }
    /* Finish the correlated trace before releasing the control lock. */
    KswordARKHvmPageTrace(&trace, KSW_HVM_PAGE_END, status);
    /* Release mutation serialization. */
    ExReleasePushLockExclusive(&runtime->Lock);
    /* Restore normal kernel APC delivery. */
    KeLeaveCriticalRegion();
    /* A complete semantic response was produced even when the request failed. */
    return STATUS_SUCCESS;
}
#else
/* HVM has no resident implementation on other architectures. */
NTSTATUS KswordARKHvmNestedPageGuardInitialize(VOID) { return STATUS_NOT_SUPPORTED; }
/* No notification was registered on an unsupported architecture. */
VOID KswordARKHvmNestedPageGuardShutdown(VOID) { }
#endif
