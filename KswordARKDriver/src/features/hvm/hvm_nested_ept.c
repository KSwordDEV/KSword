/*++

Module Name:

    hvm_nested_ept.c

Abstract:

    Implements shadow-EPT composition for L2 execution.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_ept.h"
#include "hvm_ept.h"
#include "hvm_ept_switch.h"
#include "hvm_resident.h"

#if defined(_M_AMD64)

#include "../../platform/pool_compat.h"

/* Tag the single per-processor block backing every shadow table. */
#define KSW_HVM_NEPT_POOL_TAG 'NvHK'

/* Name the read, write and execute permission bits of an EPT entry. */
#define KSW_HVM_NEPT_READ 0x1ULL
#define KSW_HVM_NEPT_WRITE 0x2ULL
#define KSW_HVM_NEPT_EXECUTE 0x4ULL
#define KSW_HVM_NEPT_PERMISSIONS \
    (KSW_HVM_NEPT_READ | KSW_HVM_NEPT_WRITE | KSW_HVM_NEPT_EXECUTE)
/* Name the bit that makes an interior entry a leaf. */
#define KSW_HVM_NEPT_LARGE 0x80ULL
/* Name the frame field of an EPT entry. */
#define KSW_HVM_NEPT_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Name write-back in the memory-type field of a leaf. */
#define KSW_HVM_NEPT_MEMORY_TYPE_WB 0x30ULL
/* Name the four-level page-walk length an EPT pointer encodes. */
#define KSW_HVM_NEPT_EPTP_WALK_4 0x18ULL
/* Name the EPT-pointer bit that asks the processor to maintain A/D flags. */
#define KSW_HVM_NEPT_EPTP_ENABLE_AD (1ULL << 6)
/* Name the two leaf bits the processor maintains: accessed (8), dirty (9). */
#define KSW_HVM_NEPT_AD_BITS ((1ULL << 8) | (1ULL << 9))

/* Find the override that owns this guest-physical address, or NULL. */
static KSW_HVM_NESTED_PAGE* KswordARKHvmNestedPageForAddress(
    KSW_HVM_RUNTIME* Runtime, KSW_HVM_SHADOW_EPT_STATE* Shadow,
    ULONGLONG GuestPhysical)
{
    KSW_HVM_NESTED_PAGE* page = (KSW_HVM_NESTED_PAGE*)InterlockedCompareExchangePointer(
        (PVOID volatile*)&Runtime->NestedPage, NULL, NULL);
    /* A revoked lease composes nothing, whatever it still owns. */
    if (page == NULL || ReadAcquire(&Runtime->NestedPageRevocationReason) != 0L ||
        page->Ept12Pointer != Shadow->L1EptPointer) {
        return NULL;
    }
    /*
     * Ask the plan, not the base address.
     *
     * A 4-KiB plan answers exactly what the previous equality test answered, so
     * the single-page path is unchanged; a larger plan owns every page of its
     * region. Comparing against GuestPhysicalPage here instead would silently
     * restrict a published 2-MiB region to its first page, leaving 511 pages
     * composed from the source while every counter reported a live override.
     */
    return KswordHvmLeafPlanContains(&page->Plan, GuestPhysical) ? page : NULL;
}

static ULONGLONG KswordARKHvmNestedPageLeaf(
    KSW_HVM_RUNTIME* Runtime, KSW_HVM_SHADOW_EPT_STATE* Shadow,
    ULONGLONG GuestPhysical, ULONGLONG OriginalLeaf, BOOLEAN Count)
{
    KSW_HVM_NESTED_PAGE* page =
        KswordARKHvmNestedPageForAddress(Runtime, Shadow, GuestPhysical);
    ULONGLONG index;

    if (page == NULL) { return OriginalLeaf; }
    /* The replacement is ordinary RAM. Preserve both levels' permissions. */
    if ((OriginalLeaf & 0x38ULL) != KSW_HVM_NEPT_MEMORY_TYPE_WB) { return OriginalLeaf; }
    if (Count) {
        (void)InterlockedCompareExchange64(&page->OriginalPhysicalPage,
            (LONG64)(OriginalLeaf & KSW_HVM_NEPT_FRAME_MASK), 0LL);
        (void)InterlockedIncrement64(&page->ComposedCount);
    }
    /* Backing is contiguous, so the page's offset in the region is its offset
       in the backing. For a 4-KiB plan the index is always zero. */
    index = (GuestPhysical - page->Plan.GuestBase) >> KSW_PLAN_SHIFT_4K;
    return (OriginalLeaf & ~KSW_HVM_NEPT_FRAME_MASK) |
        KswordHvmLeafPlanPageFrame(&page->Plan, index);
}

/*
 * Answer whether this address should be published as a leaf above the PT level,
 * and with which frame.
 *
 * Returning the granularity rather than a boolean keeps one decision in one
 * place: the fill path stops its descent at whatever level this names, and a
 * plan that names 4 KiB produces the ordinary path with no special case.
 */
static ULONG KswordARKHvmNestedPageLargeLeaf(
    KSW_HVM_RUNTIME* Runtime, KSW_HVM_SHADOW_EPT_STATE* Shadow,
    ULONGLONG GuestPhysical, ULONGLONG ComposedLeaf, ULONG OuterLeafShift,
    ULONGLONG* LargeLeaf)
{
    KSW_HVM_NESTED_PAGE* page =
        KswordARKHvmNestedPageForAddress(Runtime, Shadow, GuestPhysical);

    *LargeLeaf = 0ULL;
    /* Both translation levels must cover the whole region. A selected view
       can narrow a different page even if this address uses a coarse base leaf. */
    if (page == NULL || !KswordHvmLeafPolicyUseLarge(page->Plan.LeafShift,
            page->Translation.EntryCount, page->ScanAdmitted, OuterLeafShift,
            Runtime->EptSwitch.Active || Shadow->OuterViewIndex != 0UL)) {
        return KSW_PLAN_SHIFT_4K;
    }
    /* Only write-back RAM is replaced, exactly as at 4 KiB. */
    if ((ComposedLeaf & 0x38ULL) != KSW_HVM_NEPT_MEMORY_TYPE_WB) {
        return KSW_PLAN_SHIFT_4K;
    }
    /*
     * Carry the region base and set the leaf bit.
     *
     * The frame is the region base and not the faulting page's frame: hardware
     * supplies the offset from the address it is translating, so a leaf naming
     * an offset frame would serve the whole region shifted by that offset.
     * Permissions and memory type come from the composed 4-KiB leaf. The
     * publication policy requires both source leaves to cover the full region
     * and excludes selected views; neither level may narrow another page.
     */
    *LargeLeaf = (ComposedLeaf & ~KSW_HVM_NEPT_FRAME_MASK) |
        KswordHvmLeafPlanLeafFrame(&page->Plan) | KSW_HVM_NEPT_LARGE;
    return page->Plan.LeafShift;
}

/*
 * Answer whether this processor can maintain EPT accessed/dirty flags.
 *
 * Asked of the capability MSR rather than assumed from the fact that L1 asked:
 * L1 reads the same MSR, but it reads it through us, and nothing guarantees
 * the two views agree on a machine where an outer hypervisor filters it.
 * Setting EPTP bit 6 on a processor that cannot honour it fails VM entry with
 * an error L1 has no way to act on.
 */
static BOOLEAN
KswordARKHvmNestedEptProcessorSupportsAccessedDirty(
    VOID
    )
{
    /* IA32_VMX_EPT_VPID_CAP bit 21 reports EPT A/D support. */
    const ULONGLONG capability = __readmsr(0x48CUL);

    /* Report exactly what the processor claims. */
    return ((capability & (1ULL << 21)) != 0ULL) ? TRUE : FALSE;
}
/* Name write-back in the memory-type field of an EPT pointer. */
#define KSW_HVM_NEPT_EPTP_MEMORY_TYPE_WB 0x6ULL

/* Hand out one zero-initialized page from the processor's block. */
static PVOID
KswordARKHvmNestedEptTakePage(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Out_ ULONGLONG* PhysicalAddress
    )
{
    PVOID page = NULL;
    PHYSICAL_ADDRESS physical = { 0 };

    *PhysicalAddress = 0ULL;
    /* Report exhaustion rather than running past the block. */
    if (Shadow->PageBlock == NULL ||
        Shadow->PageUsed >= Shadow->PageTotal) {
        /* Return no page for an exhausted block. */
        return NULL;
    }
    page = (PVOID)((PUCHAR)Shadow->PageBlock +
        ((SIZE_T)Shadow->PageUsed * (SIZE_T)PAGE_SIZE));
    RtlZeroMemory(page, PAGE_SIZE);
    physical = MmGetPhysicalAddress(page);
    *PhysicalAddress = (ULONGLONG)physical.QuadPart;
    Shadow->PagePhysical[Shadow->PageUsed] =
        (ULONGLONG)physical.QuadPart & KSW_HVM_NEPT_FRAME_MASK;
    Shadow->PageUsed += 1UL;
    /* Return one page whose physical identity is already resolved. */
    return page;
}

/*
 * Navigate one interior entry back to the table it names.
 *
 * Only pages this record handed out are accepted.  A frame we never issued
 * means the entry was not written by us - either an invariant is broken or
 * something outside edited the hierarchy - and the honest response is to stop
 * rather than follow a pointer into memory of unknown ownership.
 */
static volatile ULONGLONG*
KswordARKHvmNestedEptPageVirtual(
    _In_ const KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG Entry
    )
{
    const ULONGLONG frame = Entry & KSW_HVM_NEPT_FRAME_MASK;
    ULONG index = 0UL;

    for (index = 0UL; index < Shadow->PageUsed; ++index) {
        if (Shadow->PagePhysical[index] == frame) {
            /* Return the table this record issued for that frame. */
            return (volatile ULONGLONG*)((PUCHAR)Shadow->PageBlock +
                ((SIZE_T)index * (SIZE_T)PAGE_SIZE));
        }
    }
    /* Return nothing for a frame this record never issued. */
    return NULL;
}

VOID
KswordARKHvmNestedEptInitialize(
    _Out_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L0EptPointer
    )
{
    /* Ignore a missing record rather than fault on initialization. */
    if (Shadow == NULL) {
        /* Return without touching absent state. */
        return;
    }
    RtlZeroMemory(Shadow, sizeof(*Shadow));
    Shadow->L0EptPointer = L0EptPointer;
    Shadow->LastStatus = STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmNestedEptPrepare(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    ULONGLONG rootPhysical = 0ULL;
    /* Preserve the ledger allocation result for a complete rollback. */
    NTSTATUS adStatus = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before reserving anything. */
    if (Shadow == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Keep an existing reservation rather than leaking a second one. */
    if (Shadow->PageBlock != NULL) {
        /* Return the already-complete reservation. */
        return STATUS_SUCCESS;
    }
    /*
     * One allocation for the whole processor, from the pool rather than
     * contiguous memory.  Releasing happens on the residency teardown path,
     * which a power callback can reach and where PASSIVE_LEVEL is not
     * guaranteed - the same constraint that already shapes the private EPT
     * hierarchies and the host stacks.
     */
    Shadow->PageBlock = KswordARKAllocateNonPagedPool(
        (SIZE_T)KSW_HVM_NEPT_TABLE_PAGES * (SIZE_T)PAGE_SIZE,
        KSW_HVM_NEPT_POOL_TAG);
    /* Leave composition unavailable when the reservation fails. */
    if (Shadow->PageBlock == NULL) {
        Shadow->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        Shadow->PageBlock,
        (SIZE_T)KSW_HVM_NEPT_TABLE_PAGES * (SIZE_T)PAGE_SIZE);
    Shadow->PageTotal = KSW_HVM_NEPT_TABLE_PAGES;
    Shadow->PageUsed = 0UL;
    /*
     * Room for a copy of every EPT12 table page the hierarchy depends on.
     *
     * A second allocation rather than a bigger first one: this block is read
     * and compared, never handed out as a table, and keeping the two apart
     * means a bug in one cannot hand the processor a page from the other.
     * Failure is not fatal - it costs the right to keep the shadow across an
     * invalidation, which is exactly what the code did before this existed.
     */
    Shadow->TrackedCopyBlock = KswordARKAllocateNonPagedPool(
        (SIZE_T)KSW_HVM_NEPT_TRACKED_PAGES * (SIZE_T)PAGE_SIZE,
        KSW_HVM_NEPT_POOL_TAG);
    if (Shadow->TrackedCopyBlock != NULL) {
        RtlZeroMemory(
            Shadow->TrackedCopyBlock,
            (SIZE_T)KSW_HVM_NEPT_TRACKED_PAGES * (SIZE_T)PAGE_SIZE);
    }
    Shadow->TrackedCount = 0UL;
    Shadow->TrackedOverflowCount = 0UL;
    /* Every composed leaf must have a lossless A/D ledger reservation. */
    adStatus = KswordARKHvmNestedAdPrepare(Shadow);
    /* Unwind all partial reservations on a ledger allocation failure. */
    if (!NT_SUCCESS(adStatus)) {
        /* Release the table and snapshot blocks as well. */
        KswordARKHvmNestedEptRelease(Shadow);
        /* Preserve the original error after cleanup. */
        Shadow->LastStatus = adStatus;
        /* Refuse incomplete preparation. */
        return adStatus;
    }
    /* Take the root first so every fill below has somewhere to publish. */
    Shadow->RootVirtual = KswordARKHvmNestedEptTakePage(
        Shadow,
        &rootPhysical);
    if (Shadow->RootVirtual == NULL) {
        /* Release snapshots and the ledger too if root reservation failed. */
        KswordARKHvmNestedEptRelease(Shadow);
        Shadow->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Shadow->RootPhysical = rootPhysical;
    /*
     * The composed pointer names our root, never L1's.
     *
     * Walk length and memory type come from what the processor supports, not
     * from what L1 asked for: L1's EPT12 is data we interpret, and copying its
     * pointer format would let a malformed one reach the hardware EPTP.
     */
    Shadow->ComposedEptPointer =
        (rootPhysical & KSW_HVM_NEPT_FRAME_MASK) |
        KSW_HVM_NEPT_EPTP_WALK_4 |
        KSW_HVM_NEPT_EPTP_MEMORY_TYPE_WB;
    Shadow->LastStatus = STATUS_SUCCESS;
    /* Return a complete reservation. */
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmNestedEptRelease(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    /* Ignore a record whose reservation never completed. */
    if (Shadow == NULL) {
        /* Return without touching an absent reservation. */
        return;
    }
    /* Release even a partially prepared hierarchy. */
    if (Shadow->PageBlock != NULL) {
        /* No CPU can still execute this block on the release path. */
        ExFreePool(Shadow->PageBlock);
        /* Make repeated cleanup harmless. */
        Shadow->PageBlock = NULL;
    }
    /* The ledger is owned by this active CPU reservation. */
    KswordARKHvmNestedAdRelease(Shadow);
    if (Shadow->TrackedCopyBlock != NULL) {
        ExFreePool(Shadow->TrackedCopyBlock);
        Shadow->TrackedCopyBlock = NULL;
    }
    Shadow->TrackedCount = 0UL;
    Shadow->TrackedOverflowCount = 0UL;
    Shadow->PageTotal = 0UL;
    Shadow->PageUsed = 0UL;
    Shadow->RootVirtual = NULL;
    Shadow->RootPhysical = 0ULL;
    Shadow->ComposedEptPointer = 0ULL;
    Shadow->Active = FALSE;
}

VOID
KswordARKHvmNestedEptInvalidate(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    /* Ignore a record with nothing composed. */
    if (Shadow == NULL || Shadow->RootVirtual == NULL) {
        /* Return without dropping absent mappings. */
        return;
    }
    /*
     * Drop everything rather than the one entry L1 named.
     *
     * Precise invalidation needs a reverse map from L1 physical back to every
     * L2 page that composed through it, and nothing here maintains one.
     * Dropping the whole hierarchy costs refills; dropping the wrong subset
     * costs an L2 running on a translation L1 already retired, with no symptom
     * until the memory underneath it is reused.  Coarse and certain beats
     * precise and unproven.
     */
    RtlZeroMemory(Shadow->RootVirtual, PAGE_SIZE);
    Shadow->PageUsed = 1UL;
    /*
     * The copies describe a hierarchy that no longer exists.
     *
     * What gets composed next may walk a different set of EPT12 pages, and
     * comparing the next invalidation against copies taken for the old one
     * would vouch for pages the new mappings never read.  Forgetting them
     * costs one snapshot per table page on the way back up.
     */
    Shadow->TrackedCount = 0UL;
    Shadow->TrackedOverflowCount = 0UL;
    /*
     * The A/D records describe leaves that no longer exist.
     *
     * Keeping them would have the next propagation read bits out of table
     * pages that have since been handed to a different guest-physical address,
     * and write them into EPT12 entries for pages L2 never touched.  The
     * caller is expected to have propagated before invalidating; anything not
     * folded by then is lost, which is the same thing INVEPT means for the
     * translations themselves.
     */
    Shadow->AdRecordCount = 0UL;
    /*
     * Zeroing the tables is not the whole job.
     *
     * The processor caches translations derived from them, and those survive
     * an edit to the memory they came from - that is what INVEPT exists for.
     * Dropping the tables without invalidating leaves L2 running on exactly
     * the mappings this call was made to retire, and the tables now say
     * nothing, so nothing later will contradict the stale entry either.
     */
    if (Shadow->ComposedEptPointer != 0ULL) {
        if (KswordARKHvmAsmInveptSingle(Shadow->ComposedEptPointer) != 0U) {
            Shadow->Faulted = TRUE;
            Shadow->LastStatus = STATUS_UNSUCCESSFUL;
        }
    }
    Shadow->InvalidationGeneration = Shadow->Generation;
    Shadow->Generation += 1UL;
    /* A wrapped epoch must not alias an entry from the first generation. */
    if (Shadow->Generation == 0UL && Shadow->AdEntries != NULL) {
        /* No leaf survives the invalidation that precedes this reset. */
        RtlZeroMemory(Shadow->AdEntries,
            (SIZE_T)KSW_HVM_NEPT_AD_RECORDS * sizeof(*Shadow->AdEntries));
    }
}

NTSTATUS
KswordARKHvmNestedEptSetL1Pointer(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L1EptPointer
    )
{
    /* Reject an incomplete caller contract before recording anything. */
    if (Shadow == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    if (Shadow->Faulted) { return Shadow->LastStatus; }
    /* Refuse to arm composition without a reserved hierarchy. */
    if (Shadow->RootVirtual == NULL) {
        Shadow->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Return the exact unavailable-reservation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Reject an EPT pointer whose frame the architecture cannot encode. */
    if ((L1EptPointer & KSW_HVM_NEPT_FRAME_MASK) == 0ULL) {
        Shadow->LastStatus = STATUS_INVALID_PARAMETER;
        /* Return the exact encoding failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Accessed/dirty is maintained and folded back, not refused.
     *
     * L1 asking for A/D is L1 saying it intends to read those bits back out of
     * its own EPT12 - that is the only thing they are for, and every use of
     * them (live migration, snapshots, copy-on-write) decides which pages to
     * copy from exactly that readback.
     *
     * L2 runs on the composed hierarchy, so the processor sets A/D in *our*
     * shadow leaves.  Leaving it there means L1 reads its own tables back,
     * finds every bit clear, and skips exactly the pages its guest modified -
     * silently, with nothing anywhere reporting it.  So the bits are folded
     * into EPT12 when L2 stops, using the leaf addresses recorded during
     * composition.
     *
     * Two things still have to be true, and both are checked rather than
     * assumed: the processor must be able to maintain the bits at all, and the
     * record table must not overflow.  Either failing turns the feature off
     * and refuses the entry, because half-propagated A/D is worse than none.
     */
    if ((L1EptPointer & KSW_HVM_NEPT_EPTP_ENABLE_AD) != 0ULL) {
        Shadow->L1RequestedAccessedDirty = TRUE;
        if (!KswordARKHvmNestedEptProcessorSupportsAccessedDirty()) {
            Shadow->AccessedDirtyActive = FALSE;
            Shadow->LastStatus = STATUS_NOT_SUPPORTED;
            /* Return the exact unsupported-control failure. */
            return STATUS_NOT_SUPPORTED;
        }
        Shadow->AccessedDirtyActive = TRUE;
    } else {
        Shadow->L1RequestedAccessedDirty = FALSE;
        Shadow->AccessedDirtyActive = FALSE;
    }
    /* Drop every mapping composed against a different EPT12. */
    if (Shadow->L1EptPointer != L1EptPointer) {
        KswordARKHvmNestedEptInvalidate(Shadow);
        if (Shadow->Faulted) { return Shadow->LastStatus; }
        Shadow->OuterViewIndex = 0UL;
        KswordArkHvmEptSwProgressReset(&Shadow->OuterViewProgress);
        Shadow->L1EptPointer = L1EptPointer;
    }
    /*
     * Put A/D into the pointer the processor actually loads.
     *
     * The composed pointer is built once at reservation time, before anything
     * knows what L1 will ask for, so this bit can only be decided here.  It is
     * assigned in both directions: a stale set bit from a previous L1 would
     * have the processor maintaining bits nobody is folding back.
     */
    if (Shadow->AccessedDirtyActive) {
        Shadow->ComposedEptPointer |= KSW_HVM_NEPT_EPTP_ENABLE_AD;
    } else {
        Shadow->ComposedEptPointer &= ~KSW_HVM_NEPT_EPTP_ENABLE_AD;
    }
    Shadow->L1PointerValid = TRUE;
    Shadow->Active = TRUE;
    Shadow->LastStatus = STATUS_SUCCESS;
    /* Return the armed composition. */
    return STATUS_SUCCESS;
}

/*
 * Take a private copy of one EPT12 table page, once.
 *
 * Called from the walk, so it runs in VMX root and must map through the
 * per-processor window like everything else here.  A frame already tracked is
 * left alone: the copy has to be of what the hierarchy was *composed from*,
 * and re-snapshotting on a later walk would quietly absorb an edit L1 made in
 * between - which is exactly the edit this exists to catch.
 */
static VOID
KswordARKHvmNestedEptTrackTablePage(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG TableFrame,
    _In_ ULONG Level
    )
{
    volatile VOID* mapped = NULL;
    ULONG index = 0UL;

    if (Shadow->TrackedCopyBlock == NULL || TableFrame == 0ULL) {
        /* Report nothing; the invalidation path treats absent as unknown. */
        return;
    }
    for (index = 0UL; index < Shadow->TrackedCount; ++index) {
        if (Shadow->TrackedFrame[index] == TableFrame) {
            /* Aliased table levels cannot share a safe A/D interpretation. */
            if (Shadow->TrackedLevel[index] != (UCHAR)Level) {
                /* Force the conservative invalidation path for this hierarchy. */
                Shadow->TrackedOverflowCount += 1UL;
            }
            /* Return; the copy that matters is the first one. */
            return;
        }
    }
    if (Shadow->TrackedCount >= KSW_HVM_NEPT_TRACKED_PAGES) {
        Shadow->TrackedOverflowCount += 1UL;
        /* Return; the count is what forfeits the right to keep the shadow. */
        return;
    }
    if (KswordARKHvmPhysWindowMap(
            Window,
            TableFrame,
            PAGE_SIZE,
            &mapped) != KSW_HVM_PHYS_WINDOW_OK ||
        mapped == NULL) {
        Shadow->TrackedOverflowCount += 1UL;
        /* Return; an untaken copy is counted the same as no room for one. */
        return;
    }
    RtlCopyMemory(
        (UCHAR*)Shadow->TrackedCopyBlock +
            ((SIZE_T)Shadow->TrackedCount * (SIZE_T)PAGE_SIZE),
        (const VOID*)mapped,
        PAGE_SIZE);
    KswordARKHvmPhysWindowUnmap(Window);
    Shadow->TrackedFrame[Shadow->TrackedCount] = TableFrame;
    /* Keep the architectural level with the exact table snapshot. */
    Shadow->TrackedLevel[Shadow->TrackedCount] = (UCHAR)Level;
    Shadow->TrackedCount += 1UL;
}

BOOLEAN
KswordARKHvmNestedEptInvalidateChecked(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    ULONG index = 0UL;

    if (Shadow == NULL || Window == NULL ||
        Shadow->RootVirtual == NULL) {
        /* Report that nothing was kept, because nothing was composed. */
        return FALSE;
    }
    /*
     * A hierarchy we could not fully snapshot has to be dropped.
     *
     * Overflow means at least one table page the mappings depend on has no
     * copy, so "unchanged" cannot be established for it.  Keeping the shadow
     * on the strength of the pages we did copy would be asserting something
     * about the ones we did not.
     */
    if (Shadow->TrackedCopyBlock == NULL ||
        Shadow->TrackedCount == 0UL ||
        Shadow->TrackedOverflowCount != 0UL) {
        KswordARKHvmNestedEptInvalidate(Shadow);
        Shadow->InvalidateDroppedCount += 1UL;
        /* Report the drop. */
        return FALSE;
    }
    for (index = 0UL; index < Shadow->TrackedCount; ++index) {
        volatile VOID* mapped = NULL;
        BOOLEAN same = FALSE;

        if (KswordARKHvmPhysWindowMap(
                Window,
                Shadow->TrackedFrame[index],
                PAGE_SIZE,
                &mapped) != KSW_HVM_PHYS_WINDOW_OK ||
            mapped == NULL) {
            /* A page we cannot re-read is a page we cannot vouch for. */
            KswordARKHvmNestedEptInvalidate(Shadow);
            Shadow->InvalidateDroppedCount += 1UL;
            /* Report the drop. */
            return FALSE;
        }
        /* Hardware A/D sets alone do not change a translation or its rights. */
        same = KswordARKHvmNestedAdCompare(Shadow, index,
            (const volatile ULONGLONG*)mapped);
        KswordARKHvmPhysWindowUnmap(Window);
        if (!same) {
            KswordARKHvmNestedEptInvalidate(Shadow);
            Shadow->InvalidateDroppedCount += 1UL;
            /* Report the drop; L1 really did edit its tables. */
            return FALSE;
        }
    }
    /*
     * Every mapping field is unchanged, so the composed mappings still say
     * exactly what EPT12 says.  What remains is the processor's own caches,
     * which is the part INVEPT genuinely always means.
     */
    if (Shadow->ComposedEptPointer != 0ULL) {
        if (KswordARKHvmAsmInveptSingle(Shadow->ComposedEptPointer) != 0U) {
            Shadow->Faulted = TRUE;
            Shadow->LastStatus = STATUS_UNSUCCESSFUL;
        }
    }
    Shadow->InvalidationGeneration = Shadow->Generation;
    Shadow->InvalidateKeptCount += 1UL;
    /* Report that the hierarchy was kept. */
    return TRUE;
}

/*
 * Walk EPT12 for one L2 guest physical address.
 *
 * Every level is read through the window because EPT12's tables live at L1
 * physical addresses, which under our identity EPT01 are host physical
 * addresses - readable only through a mapping we create.
 */
static BOOLEAN
KswordARKHvmNestedEptWalkL1(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG GuestPhysicalAddress,
    _Out_ ULONGLONG* L1Physical,
    _Out_ ULONGLONG* Permissions,
    _Out_opt_ ULONGLONG* L1EntryAddress
    )
{
    /* Index shifts for PML4, PDPT, PD and PT in walk order. */
    static const ULONG shifts[4] = { 39UL, 30UL, 21UL, 12UL };
    ULONGLONG table = Shadow->L1EptPointer & KSW_HVM_NEPT_FRAME_MASK;
    ULONGLONG permissions = KSW_HVM_NEPT_PERMISSIONS;
    ULONG level = 0UL;

    *L1Physical = 0ULL;
    *Permissions = 0ULL;
    if (L1EntryAddress != NULL) { *L1EntryAddress = 0ULL; }
    for (level = 0UL; level < 4UL; ++level) {
        const ULONGLONG index =
            (GuestPhysicalAddress >> shifts[level]) & 0x1FFULL;
        const ULONGLONG entryAddress = table + (index << 3);
        ULONGLONG entry = 0ULL;

        /*
         * Copy this table page before reading anything out of it.
         *
         * Before, not after: the copy has to be of the bytes the mapping is
         * about to be composed from, so that a later comparison answers "is
         * the hierarchy still what L1's tables say" rather than "did anything
         * change since some arbitrary moment".
         */
        KswordARKHvmNestedEptTrackTablePage(Shadow, Window, table, level);
        if (!NT_SUCCESS(KswordARKHvmPhysWindowReadQword(
                Window,
                entryAddress,
                &entry))) {
            Shadow->LastDenySite = 6UL;
            Shadow->LastStatus = STATUS_INVALID_ADDRESS;
            /* This is our read failure, not a missing EPT12 mapping. */
            return FALSE;
        }
        /*
         * Remember where the entry that decides this page lives.
         *
         * Only meaningful at the last level, and only known here - after the
         * walk returns, `table` is gone and recovering this address would mean
         * walking EPT12 again, from a VM exit, for every page.
         */
        if (L1EntryAddress != NULL) { *L1EntryAddress = entryAddress; }
        /*
         * Accumulate permissions down the walk, never widen them.
         *
         * An interior entry that denies write denies it for everything
         * beneath, so the effective permission is the intersection - taking
         * only the leaf's bits would grant access L1 revoked one level up.
         */
        permissions &= entry;
        /* A wholly unreadable entry terminates the walk with no mapping. */
        if ((entry & KSW_HVM_NEPT_PERMISSIONS) == 0ULL) {
            /*
             * Keep which level stopped and what it read.
             *
             * "The walk found nothing" is not actionable on its own: stopping
             * at the PML4 means L1 has not built this half of the address
             * space at all, stopping at the PT means one page is absent, and
             * an entry that is nonzero but permissionless means L1 deliberately
             * revoked it.  Those are three different defects and one count.
             */
            Shadow->LastDenySite = 1UL;
            Shadow->LastDenyLevel = level;
            Shadow->LastDenyEntry = entry;
            Shadow->LastDenyGuestPhysical = GuestPhysicalAddress;
            /* Report that EPT12 maps nothing here. */
            return FALSE;
        }
        /* Resolve large leaves at the levels that may terminate a walk. */
        if ((level >= 1UL && level <= 2UL &&
                (entry & KSW_HVM_NEPT_LARGE) != 0ULL) ||
            level == 3UL) {
            const ULONGLONG offsetMask =
                (level == 3UL)
                    ? (PAGE_SIZE - 1ULL)
                    : ((1ULL << shifts[level]) - 1ULL);

            *L1Physical =
                ((entry & KSW_HVM_NEPT_FRAME_MASK) & ~offsetMask) |
                (GuestPhysicalAddress & offsetMask);
            /* Retain EPT12's cache type and ignore-PAT policy as well as RWX. */
            *Permissions = (permissions & KSW_HVM_NEPT_PERMISSIONS) |
                (entry & 0x78ULL);
            /* Report a complete EPT12 translation. */
            return TRUE;
        }
        table = entry & KSW_HVM_NEPT_FRAME_MASK;
    }
    /* Report that the walk ran out of levels without a leaf. */
    return FALSE;
}


/* Resolve the selected KSword backing page without assuming identity. */
static BOOLEAN
KswordARKHvmNestedEptReadOuter(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L1Physical,
    _Out_ ULONGLONG* Leaf,
    _Out_ ULONG* Shift
    )
{
    const KSW_HVM_EPTSW_HIERARCHY* selected = NULL;

    if (!KswordARKHvmEptReadLeaf(Runtime, L1Physical, Leaf, Shift)) {
        return FALSE;
    }
    if (Shadow->OuterViewIndex == 0UL) { return TRUE; }
    if (!Runtime->EptSwitch.Active ||
        Shadow->OuterViewIndex > Runtime->EptSwitch.LeafCapacity ||
        Shadow->OuterViewIndex > KSWORD_ARK_HVM_MAX_VIEWS) {
        return FALSE;
    }
    selected = &Runtime->EptSwitch.Hierarchies[Shadow->OuterViewIndex - 1UL];
    if (!selected->Active) { return FALSE; }
    if (selected->LeafPhysical == (L1Physical & KSW_HVM_NEPT_FRAME_MASK)) {
        *Leaf = selected->SecondaryEntry;
        *Shift = 12UL;
    }
    return TRUE;
}

/* Reuse the existing view planner; only this processor's shadow is rebuilt. */
static NTSTATUS
KswordARKHvmNestedEptSwitchOuter(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG L1Physical,
    _In_ ULONGLONG GuestPhysical,
    _In_ ULONGLONG GuestRip,
    _In_ ULONG Access
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        KSW_HVM_EPT_VIEW_SLOT* view = &Runtime->EptViews[index];
        ULONG next = 0UL;
        ULONGLONG outerEptp = 0ULL;
        NTSTATUS status;

        if (!view->Active ||
            view->PhysicalAddress != (L1Physical & KSW_HVM_NEPT_FRAME_MASK)) {
            continue;
        }
        /* A nested view requires the backend that does not depend on MTF. */
        if (view->EptSwitchIndex == 0UL) { return STATUS_NOT_SUPPORTED; }
        status = KswordARKHvmEptSwitchPlanViolation(
            Runtime, &Shadow->OuterViewProgress, Shadow->OuterViewIndex,
            view->EptSwitchIndex - 1UL, Access, view->Kind,
            GuestRip, GuestPhysical, &next, &outerEptp);
        if (!NT_SUCCESS(status)) { return status; }
        /* Fold before retiring the mappings. Aliases all change together. */
        (void)KswordARKHvmNestedEptPropagateAccessedDirty(Shadow, Window);
        KswordARKHvmNestedEptInvalidate(Shadow);
        if (Shadow->Faulted) { return Shadow->LastStatus; }
        Shadow->OuterViewIndex = next;
        InterlockedIncrement64(&view->FlipCount);
        /* outerEptp is a planner identity, never a vmcs02 EPT pointer. */
        return STATUS_SUCCESS;
    }
    return STATUS_ACCESS_DENIED;
}

ULONG
KswordARKHvmNestedEptFill(
    _Inout_ struct _KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_ ULONGLONG GuestRip
    )
{
    /* Index shifts for PML4, PDPT, PD and PT in walk order. */
    static const ULONG shifts[4] = { 39UL, 30UL, 21UL, 12UL };
    ULONGLONG l1Physical = 0ULL;
    ULONGLONG permissions = 0ULL;
    /* Where EPT12's own leaf for this page lives, for folding A/D back. */
    ULONGLONG l1EntryAddress = 0ULL;
    volatile ULONGLONG* publishedLeaf = NULL;
    volatile ULONGLONG* table = NULL;
    ULONGLONG hostLeaf = 0ULL;
    ULONGLONG composedLeaf = 0ULL;
    ULONG hostShift = 0UL;
    ULONG composition = 0UL;
    BOOLEAN switched = FALSE;
    ULONG level = 0UL;
    /* Level whose entry holds the leaf: 3 for an ordinary page, higher for a
       large one. Set once the override's granularity is known. */
    ULONG leafTerminationLevel = 3UL;

    /* Refuse composition without an armed hierarchy or a usable window. */
    if (Runtime == NULL || Shadow == NULL || Window == NULL ||
        Shadow->Faulted ||
        !Shadow->Active || Shadow->RootVirtual == NULL) {
        /* Report that this violation is not ours to satisfy. */
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    Shadow->LastStatus = STATUS_SUCCESS;
    Shadow->LastDenySite = 0UL;
    if (Access == 0UL || (Access & ~7UL) != 0UL) {
        Shadow->LastStatus = STATUS_INVALID_PARAMETER;
        return KSW_HVM_NEPT_FILL_FAILED;
    }
retryTranslation:
    /* Recheck before filling as a local L2 exit need not revisit its entry builder. */
    if (!KswordARKHvmNestedPageValidateTranslation(Runtime, Window, Shadow->L1EptPointer)) {
        /* A revoked lease must not preserve this CPU's already composed override. */
        KswordARKHvmNestedEptInvalidate(Shadow);
        /* Retain backing and propagate an actual local invalidation failure. */
        if (Shadow->Faulted) { return KSW_HVM_NEPT_FILL_FAILED; }
    }
    /* Translate through L1's own hierarchy first. */
    if (!KswordARKHvmNestedEptWalkL1(
            Shadow,
            Window,
            GuestPhysicalAddress,
            &l1Physical,
            &permissions,
            &l1EntryAddress)) {
        Shadow->DenyCount += 1UL;
        return Shadow->LastDenySite == 1UL
            ? KSW_HVM_NEPT_FILL_L1_DENIED : KSW_HVM_NEPT_FILL_FAILED;
    }
    /*
     * Refuse when EPT12 grants less than the access needs.
     *
     * This is the violation L1 installed its EPT to receive, so it must reach
     * L1 rather than be satisfied here.  Composing a leaf that permits it
     * would silently defeat whatever L1 was protecting.
     */
    if ((Access & KSW_HVM_NEPT_PERMISSIONS) != 0UL &&
        ((ULONGLONG)Access & permissions) !=
            ((ULONGLONG)Access & KSW_HVM_NEPT_PERMISSIONS)) {
        Shadow->DenyCount += 1UL;
        Shadow->LastDenySite = 2UL;
        Shadow->LastDenyAccess = Access;
        Shadow->LastDenyPermissions = permissions;
        Shadow->LastDenyGuestPhysical = GuestPhysicalAddress;
        /* Report the violation as L1's to handle. */
        return KSW_HVM_NEPT_FILL_L1_DENIED;
    }
    if (!KswordARKHvmNestedEptReadOuter(
            Runtime, Shadow, l1Physical, &hostLeaf, &hostShift)) {
        Shadow->LastDenySite = 3UL;
        Shadow->LastStatus = STATUS_INVALID_ADDRESS;
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    composition = KswordArkHvmNestedEptComposeLeaf(
        l1Physical, permissions, hostLeaf, hostShift, Access, &composedLeaf);
    if (composition == KSWORD_ARK_HVM_NEPT_COMPOSE_OUTER_DENIED && !switched) {
        Shadow->LastStatus = KswordARKHvmNestedEptSwitchOuter(
            Runtime, Shadow, Window, l1Physical, GuestPhysicalAddress,
            GuestRip, Access);
        if (NT_SUCCESS(Shadow->LastStatus)) {
            switched = TRUE;
            /* Invalidation retired EPT12 snapshots too; take them again. */
            goto retryTranslation;
        }
    }
    if (composition != KSWORD_ARK_HVM_NEPT_COMPOSE_OK) {
        Shadow->DenyCount += 1UL;
        Shadow->LastDenySite = 3UL;
        Shadow->LastDenyAccess = Access;
        Shadow->LastDenyPermissions = permissions & hostLeaf & 7ULL;
        Shadow->LastDenyGuestPhysical = GuestPhysicalAddress;
        Shadow->LastDenyEntry = hostLeaf;
        if (NT_SUCCESS(Shadow->LastStatus)) {
            Shadow->LastStatus = STATUS_NOT_SUPPORTED;
        }
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    composedLeaf = KswordARKHvmNestedPageLeaf(
        Runtime, Shadow, GuestPhysicalAddress, composedLeaf, TRUE);
    /*
     * Decide the granularity before descending, because it decides how far.
     *
     * A 2-MiB leaf lives in the PD and a 1-GiB leaf in the PDPT, so the walk
     * that builds interior tables has to stop one or two levels earlier. The
     * shifts array is indexed by level, so the level that terminates the walk is
     * the index whose shift equals the plan's granularity.
     */
    {
        ULONGLONG largeLeaf = 0ULL;
        const ULONG leafShift = KswordARKHvmNestedPageLargeLeaf(
            Runtime, Shadow, GuestPhysicalAddress, composedLeaf, hostShift, &largeLeaf);

        if (leafShift > KSW_PLAN_SHIFT_4K) {
            /* PDPT for 1 GiB, PD for 2 MiB; both are inside the interior walk. */
            const ULONG leafLevel = (leafShift == KSW_PLAN_SHIFT_1G) ? 1UL : 2UL;

            composedLeaf = largeLeaf;
            leafTerminationLevel = leafLevel;
        }
    }
    /* Build the shadow path down to the leaf's own level. */
    table = (volatile ULONGLONG*)Shadow->RootVirtual;
    for (level = 0UL; level < leafTerminationLevel; ++level) {
        const ULONGLONG index =
            (GuestPhysicalAddress >> shifts[level]) & 0x1FFULL;
        ULONGLONG entry = table[index];

        if ((entry & KSW_HVM_NEPT_PERMISSIONS) == 0ULL) {
            ULONGLONG childPhysical = 0ULL;
            PVOID child = KswordARKHvmNestedEptTakePage(
                Shadow,
                &childPhysical);

            /* Report exhaustion as a refusal, never as a crash. */
            if (child == NULL) {
                Shadow->ExhaustionCount += 1UL;
                Shadow->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
                Shadow->LastDenySite = 4UL;
                Shadow->LastDenyLevel = level;
                Shadow->LastDenyGuestPhysical = GuestPhysicalAddress;
                /* Report that no mapping could be composed. */
                return KSW_HVM_NEPT_FILL_FAILED;
            }
            /*
             * Interior entries carry full permissions.
             *
             * The leaf is where the intersection is expressed; narrowing an
             * interior entry would apply it to every page under that entry,
             * including ones composed later from different EPT12 leaves.
             */
            entry = (childPhysical & KSW_HVM_NEPT_FRAME_MASK) |
                KSW_HVM_NEPT_PERMISSIONS;
            table[index] = entry;
        }
        table = KswordARKHvmNestedEptPageVirtual(Shadow, entry);
        /* Refuse when an interior entry names a page we did not hand out. */
        if (table == NULL) {
            Shadow->LastStatus = STATUS_DATA_ERROR;
            Shadow->LastDenySite = 5UL;
            Shadow->LastDenyLevel = level;
            Shadow->LastDenyEntry = entry;
            Shadow->LastDenyGuestPhysical = GuestPhysicalAddress;
            /* Report that the hierarchy could not be navigated. */
            return KSW_HVM_NEPT_FILL_FAILED;
        }
    }
    {
        const ULONGLONG leaf = composedLeaf;
        /* Index at the level the walk stopped on, not always the PT. */
        const ULONGLONG leafIndex =
            (GuestPhysicalAddress >> shifts[leafTerminationLevel]) & 0x1FFULL;

        /*
         * Writing a leaf here may replace an interior entry that still names a
         * table page filled by earlier 4-KiB faults in the same region. Those
         * pages are not returned to the block: the block is reclaimed whole on
         * release, and returning one would require proving no processor still
         * holds a cached translation through it. Leaking a table page until
         * release is bounded; freeing one early is not.
         */
        publishedLeaf = &table[leafIndex];
        *publishedLeaf = leaf;
        /*
         * Read the assignment back.  One load, and it separates "we composed
         * the wrong mapping" from "we composed the right one somewhere else" -
         * two failures that look identical from every counter downstream.
         */
        if (table[leafIndex] != leaf) {
            Shadow->LeafWriteMismatchCount += 1UL;
        }
    }
    /*
     * Every so often, re-ask EPT12 about a mapping composed earlier.
     *
     * The address verified is the one held back from the previous sample, not
     * this one: a leaf checked against the walk that just produced it proves
     * only that the assignment worked, which the read-back above already says.
     * What matters is whether a mapping that has been in use still agrees with
     * L1's tables.  See the field comment for why this is the one failure that
     * leaves no exit behind.
     */
    /*
     * Ride the same sampling tick for the region recheck.
     *
     * One EPT12 walk per 4096 fills, against a lease that is otherwise rechecked
     * only where it was captured. Sharing the tick keeps the exit path's cost
     * unchanged in shape: it was already doing a walk here every 4096 fills.
     */
    if ((Shadow->FillCount & 0xFFFUL) == 0UL) {
        KswordARKHvmNestedPageSampleRegion(Runtime, Window);
    }
    if ((Shadow->FillCount & 0xFFFUL) == 0UL) {
        const ULONGLONG pending = Shadow->VerifyPendingGuestPhysical;

        if (pending != 0ULL &&
            Shadow->VerifyPendingGeneration != Shadow->Generation) {
            /*
             * The hierarchy was dropped and rebuilt since this address was
             * held back, so the leaf now present was composed from a different
             * EPT12.  Comparing it proves nothing either way.
             */
            Shadow->VerifySkippedGenerationCount += 1UL;
        } else if (pending != 0ULL) {
            volatile ULONGLONG* verifyTable =
                (volatile ULONGLONG*)Shadow->RootVirtual;
            ULONG verifyLevel = 0UL;
            /* Set when the walk ends on a large leaf above the PT level. */
            BOOLEAN verifyLarge = FALSE;

            Shadow->VerifySampleCount += 1UL;
            for (verifyLevel = 0UL; verifyLevel < 3UL; ++verifyLevel) {
                const ULONGLONG entry =
                    verifyTable[(pending >> shifts[verifyLevel]) & 0x1FFULL];

                if ((entry & KSW_HVM_NEPT_PERMISSIONS) == 0ULL) {
                    verifyTable = NULL;
                    break;
                }
                /*
                 * A large leaf terminates this walk; it is not an interior
                 * entry and its frame is replacement backing, not a table page
                 * we handed out. Resolving it as a table returns NULL and would
                 * be charged as "the hierarchy could not be navigated" - a
                 * correct mapping counted as an unexplained failure, on every
                 * sample, for as long as the region stays published.
                 */
                if (verifyLevel >= 1UL &&
                    (entry & KSW_HVM_NEPT_LARGE) != 0ULL) {
                    verifyLarge = TRUE;
                    break;
                }
                verifyTable =
                    KswordARKHvmNestedEptPageVirtual(Shadow, entry);
                if (verifyTable == NULL) { break; }
            }
            if (verifyTable == NULL) {
                /* Dropped by an invalidation: correct, not a mismatch. */
                Shadow->VerifyUnresolvedCount += 1UL;
            } else {
                ULONGLONG freshPhysical = 0ULL;
                ULONGLONG freshPermissions = 0ULL;
                /* The leaf lives at whichever level terminated the walk. */
                const ULONGLONG shadowLeaf = verifyTable[
                    (pending >> shifts[verifyLarge ? verifyLevel : 3UL]) & 0x1FFULL];

                if (!KswordARKHvmNestedEptWalkL1(
                        Shadow,
                        Window,
                        pending,
                        &freshPhysical,
                        &freshPermissions,
                        NULL)) {
                    Shadow->VerifyUnresolvedCount += 1UL;
                } else if (!KswordARKHvmNestedEptReadOuter(
                               Runtime, Shadow, freshPhysical, &hostLeaf, &hostShift)) {
                    Shadow->VerifyUnresolvedCount += 1UL;
                } else {
                    const ULONGLONG composed = hostLeaf |
                        (freshPhysical & ((1ULL << hostShift) - 1ULL) &
                         KSW_HVM_NEPT_FRAME_MASK);
                    ULONGLONG expectedLarge = 0ULL;
                    /*
                     * Expect what the fill path would install today, at the same
                     * granularity. A large leaf carries the region base while the
                     * per-page frame carries an offset, so comparing a published
                     * 2-MiB leaf against the 4-KiB answer would report a mismatch
                     * on every sample of a region that is in fact correct.
                     */
                    const ULONG expectedShift = KswordARKHvmNestedPageLargeLeaf(
                        Runtime, Shadow, pending, composed, hostShift, &expectedLarge);
                    const ULONGLONG expectedFrame =
                        (expectedShift > KSW_PLAN_SHIFT_4K)
                            ? (expectedLarge & KSW_HVM_NEPT_FRAME_MASK)
                            : (KswordARKHvmNestedPageLeaf(Runtime, Shadow, pending,
                                   composed, FALSE) & KSW_HVM_NEPT_FRAME_MASK);

                    if ((shadowLeaf & KSW_HVM_NEPT_FRAME_MASK) != expectedFrame) {
                        /*
                         * Recorded only on a mismatch.  Recording every sample
                         * overwrites the one case worth looking at with the
                         * ordinary one that follows it - measured: the counter
                         * said three mismatches while the retained scene showed a
                         * matching pair.
                         */
                        Shadow->VerifyLastGuestPhysical = pending;
                        Shadow->VerifyLastShadowFrame =
                            shadowLeaf & KSW_HVM_NEPT_FRAME_MASK;
                        Shadow->VerifyLastL1Frame =
                            (hostLeaf & KSW_HVM_NEPT_FRAME_MASK) |
                            (freshPhysical & ((1ULL << hostShift) - 1ULL) &
                             KSW_HVM_NEPT_FRAME_MASK);
                        Shadow->VerifyMismatchCount += 1UL;
                    }
                }
            }
        }
        Shadow->VerifyPendingGuestPhysical =
            GuestPhysicalAddress & KSW_HVM_NEPT_FRAME_MASK;
        Shadow->VerifyPendingGeneration = Shadow->Generation;
    }
    /* Retain every source until its writable A/D state has been published. */
    if (Shadow->AccessedDirtyActive && !KswordARKHvmNestedAdRecord(Shadow,
            publishedLeaf, l1EntryAddress)) {
        /* An untracked translation must never run with advertised A/D support. */
        Shadow->Faulted = TRUE;
        /* Return a local resource failure rather than a fictitious L1 fault. */
        Shadow->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Stop L2 before using the untracked leaf. */
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    Shadow->FillCount += 1UL;
    Shadow->LastStatus = STATUS_SUCCESS;
    /* Report that the faulting access may now be retried. */
    return KSW_HVM_NEPT_FILL_RESOLVED;
}

#else

VOID KswordARKHvmNestedPageResetLocked(KSW_HVM_RUNTIME* Runtime)
{
    UNREFERENCED_PARAMETER(Runtime);
}

NTSTATUS KswordARKHvmNestedPageControl(
    const KSWORD_ARK_HVM_NESTED_PAGE_REQUEST* Request,
    KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE* Response)
{
    UNREFERENCED_PARAMETER(Request);
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_NESTED_PAGE_VERSION;
    Response->size = sizeof(*Response);
    Response->status = 1UL;
    Response->lastStatus = (ULONG)STATUS_NOT_SUPPORTED;
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmNestedEptInitialize(
    _Out_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L0EptPointer
    )
{
    UNREFERENCED_PARAMETER(L0EptPointer);
    /* Zero the record so no caller reads uninitialized shadow state. */
    if (Shadow != NULL) {
        RtlZeroMemory(Shadow, sizeof(*Shadow));
    }
}

NTSTATUS
KswordARKHvmNestedEptPrepare(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    UNREFERENCED_PARAMETER(Shadow);
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

VOID
KswordARKHvmNestedEptRelease(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    UNREFERENCED_PARAMETER(Shadow);
}

NTSTATUS
KswordARKHvmNestedEptSetL1Pointer(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L1EptPointer
    )
{
    UNREFERENCED_PARAMETER(Shadow);
    UNREFERENCED_PARAMETER(L1EptPointer);
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

VOID
KswordARKHvmNestedEptInvalidate(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    UNREFERENCED_PARAMETER(Shadow);
}

BOOLEAN
KswordARKHvmNestedEptInvalidateChecked(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    UNREFERENCED_PARAMETER(Shadow);
    UNREFERENCED_PARAMETER(Window);
    /* Report the explicit unsupported-architecture boundary as "not kept". */
    return FALSE;
}

ULONG
KswordARKHvmNestedEptFill(
    _Inout_ struct _KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_ ULONGLONG GuestRip
    )
{
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Shadow);
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(GuestPhysicalAddress);
    UNREFERENCED_PARAMETER(Access);
    UNREFERENCED_PARAMETER(GuestRip);
    /* Report that no mapping could be composed. */
    return KSW_HVM_NEPT_FILL_FAILED;
}

#endif
