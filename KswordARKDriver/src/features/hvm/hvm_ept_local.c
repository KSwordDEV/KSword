/*++

Module Name:

    hvm_ept_local.c

Abstract:

    Implements per-processor private EPT hierarchies.

    Both flip mechanisms in this driver write one EPT leaf and let the guest
    retire a single instruction.  With one shared hierarchy that write is
    visible to every other processor for the whole window, which is why both
    features refuse any topology but a single processor.

    A private hierarchy removes that window by construction rather than by
    timing: each processor walks its own copy of the tables on the path to a
    flippable leaf, and everything else stays shared.  A private path is its
    shared counterpart with only the addresses replaced, so the two are
    provably identical in every other bit.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL except for Translate.

--*/

#include "hvm_ept_local.h"

#include "driver/KswordArkHvmControls.h"

#if defined(_M_AMD64)

#include "../../platform/pool_compat.h"

/* Tag the single per-processor block backing every private table. */
#define KSW_HVM_EPT_LOCAL_POOL_TAG 'LvHK'

/* Carve one per-processor block into pages without a second allocator. */
typedef struct _KSW_HVM_LOCAL_PAGE_CURSOR
{
    /* Retain the block start so pages can be handed out in order. */
    PUCHAR Block;
    /* Retain how many pages the block holds. */
    ULONG Total;
    /* Retain how many pages have been handed out. */
    ULONG Used;
} KSW_HVM_LOCAL_PAGE_CURSOR;

/*
 * Hand out one zero-initialized page from the block.
 *
 * A nonpaged allocation of a whole number of pages is page aligned, so each
 * page handed out here is exactly one physical page and its address can be
 * published into a parent entry on its own.  The pages need not be
 * physically contiguous with each other - nothing in the hierarchy assumes
 * that - which is what lets one allocation replace one per table.
 */
static PVOID
KswordARKHvmEptLocalTakePage(
    _Inout_ KSW_HVM_LOCAL_PAGE_CURSOR* Cursor,
    _Out_ PHYSICAL_ADDRESS* PhysicalAddress
    )
{
    PVOID page = NULL;

    /* Report exhaustion rather than running past the block. */
    PhysicalAddress->QuadPart = 0LL;
    if (Cursor->Used >= Cursor->Total) {
        /* Return no page for an exhausted block. */
        return NULL;
    }
    page = Cursor->Block + ((SIZE_T)Cursor->Used * (SIZE_T)PAGE_SIZE);
    Cursor->Used += 1UL;
    *PhysicalAddress = MmGetPhysicalAddress(page);
    /* Refuse a page whose physical address could not be resolved. */
    if (PhysicalAddress->QuadPart == 0LL) {
        /* Return no page rather than publishing address zero. */
        return NULL;
    }
    /* Return the page for the caller to fill. */
    return page;
}

/* Find the forked table that mirrors one shared table, or NULL. */
static KSW_HVM_EPT_LOCAL_TABLE*
KswordARKHvmEptLocalFindTable(
    _In_ const KSW_HVM_EPT_LOCAL* Local,
    _In_ const VOID* SharedVirtual,
    _In_ ULONG Level
    )
{
    ULONG index = 0UL;

    /* Scan the bounded fork ledger for an exact match. */
    for (index = 0UL; index < Local->TableCount; ++index) {
        /* Compare both the source table and its level. */
        if (Local->Tables[index].SharedVirtual == SharedVirtual &&
            Local->Tables[index].Level == Level) {
            /* Return the existing fork, cast away const for the caller. */
            return (KSW_HVM_EPT_LOCAL_TABLE*)&Local->Tables[index];
        }
    }
    /* Report that this table is still shared. */
    return NULL;
}

/* Copy one shared table into a fresh private page and record the fork. */
static NTSTATUS
KswordARKHvmEptLocalForkTable(
    _Inout_ KSW_HVM_EPT_LOCAL* Local,
    _Inout_ KSW_HVM_LOCAL_PAGE_CURSOR* Cursor,
    _In_ PVOID SharedVirtual,
    _In_ ULONG Level,
    _Outptr_ KSW_HVM_EPT_LOCAL_TABLE** Table
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    KSW_HVM_EPT_LOCAL_TABLE* record = NULL;
    PVOID page = NULL;

    /* Refuse a fork the bounded ledger cannot record. */
    if (Local->TableCount >= KSW_HVM_MAX_LOCAL_TABLES) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    page = KswordARKHvmEptLocalTakePage(Cursor, &physicalAddress);
    /* Refuse when the pre-computed page budget turned out to be short. */
    if (page == NULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Copy the shared table wholesale.  Everything below this table stays
     * shared until something forks it too, so the private path starts out
     * indistinguishable from the shared one.
     */
    RtlCopyMemory(page, SharedVirtual, (SIZE_T)PAGE_SIZE);
    record = &Local->Tables[Local->TableCount];
    record->SharedVirtual = SharedVirtual;
    record->PrivateVirtual = page;
    record->PrivatePhysical = physicalAddress;
    record->Level = Level;
    record->Reserved0 = 0UL;
    Local->TableCount += 1UL;
    *Table = record;
    /* Complete the fork successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptLocalCollectLeaves(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _Out_writes_to_(Capacity, *Count) ULONGLONG* Bases,
    _In_ ULONG Capacity,
    _Out_ ULONG* Count
    )
{
    ULONG index = 0UL;
    ULONG scan = 0UL;
    ULONG total = 0UL;

    /* Reject an incomplete caller contract before reading any table. */
    if (Runtime == NULL || Bases == NULL || Count == NULL || Capacity == 0UL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0UL;
    /*
     * Views own their leaf exclusively and flip it on every access-type
     * mismatch, so every installed view contributes a base.
     */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        ULONGLONG base = 0ULL;
        BOOLEAN duplicate = FALSE;

        /* Skip slots that hold no view. */
        if (!Runtime->EptViews[index].Active) {
            /* Continue to the next bounded record. */
            continue;
        }
        base = KswordArkHvmEptLeafBase(
            Runtime->EptViews[index].PhysicalAddress);
        /* Skip a base another view already contributed. */
        for (scan = 0UL; scan < total; ++scan) {
            if (Bases[scan] == base) {
                /* Record the duplicate and stop scanning. */
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate) {
            /* Continue to the next bounded record. */
            continue;
        }
        /* Refuse a set larger than one private hierarchy may mirror. */
        if (total >= Capacity) {
            /* Return the exact bounded-resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Bases[total] = base;
        total += 1UL;
    }
    /*
     * Allow-once rules temporarily widen a leaf, so every page they cover
     * contributes its containing leaf.  Rules that only deny access never
     * flip anything and are deliberately not collected.
     */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_EPT_RULES; ++index) {
        ULONGLONG cursor = 0ULL;
        ULONGLONG end = 0ULL;

        /* Skip inactive rules and rules that never grant. */
        if (!Runtime->EptRules[index].Active ||
            (Runtime->EptRules[index].Flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE) == 0UL) {
            /* Continue to the next bounded record. */
            continue;
        }
        cursor = KswordArkHvmEptLeafBase(
            Runtime->EptRules[index].PhysicalAddress);
        end = Runtime->EptRules[index].PhysicalAddress +
            ((ULONGLONG)Runtime->EptRules[index].PageCount *
                KSW_HVM_PAGE_BYTES);
        while (cursor < end) {
            BOOLEAN duplicate = FALSE;

            /* Skip a base already contributed by a view or another rule. */
            for (scan = 0UL; scan < total; ++scan) {
                if (Bases[scan] == cursor) {
                    /* Record the duplicate and stop scanning. */
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                /* Refuse a set larger than one hierarchy may mirror. */
                if (total >= Capacity) {
                    /* Return the exact bounded-resource failure. */
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                Bases[total] = cursor;
                total += 1UL;
            }
            /* Advance to the next whole two-MiB leaf. */
            cursor += KSW_HVM_LARGE_PAGE_BYTES;
        }
    }
    *Count = total;
    /* Complete the collection successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptLocalCheckAdmission(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG ByteCount
    )
{
    ULONGLONG bases[KSW_HVM_MAX_LOCAL_LEAVES] = { 0 };
    ULONGLONG cursor = 0ULL;
    ULONGLONG end = 0ULL;
    ULONG count = 0UL;
    ULONG scan = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before reading any table. */
    if (Runtime == NULL || ByteCount == 0ULL ||
        PhysicalAddress > (MAXULONGLONG - ByteCount)) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* No mirroring means no limit; this is the feature-off answer. */
    if (!Runtime->LocalEptArmed) {
        /* Complete without consulting any bound. */
        return STATUS_SUCCESS;
    }
    /* Start from what the currently installed rules and views already cost. */
    status = KswordARKHvmEptLocalCollectLeaves(
        Runtime,
        bases,
        KSW_HVM_MAX_LOCAL_LEAVES,
        &count);
    if (!NT_SUCCESS(status)) {
        /* Return the exact collection failure. */
        return status;
    }
    /* Add every leaf the prospective range would contribute. */
    cursor = KswordArkHvmEptLeafBase(PhysicalAddress);
    end = PhysicalAddress + ByteCount;
    while (cursor < end) {
        BOOLEAN duplicate = FALSE;

        for (scan = 0UL; scan < count; ++scan) {
            if (bases[scan] == cursor) {
                /* An already-counted leaf costs nothing more. */
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            /* Refuse here, where the caller still knows what it asked for. */
            if (count >= KSW_HVM_MAX_LOCAL_LEAVES) {
                /* Return the exact bounded-resource failure. */
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            bases[count] = cursor;
            count += 1UL;
        }
        /* Advance to the next whole two-MiB leaf. */
        cursor += KSW_HVM_LARGE_PAGE_BYTES;
    }
    /*
     * Also check the aggregate page budget, using the worst-case shape where
     * every leaf needs its own parents.  Refusing a set the exact build would
     * have accepted is the safe direction to be wrong in.
     */
    if (!KswordArkHvmEptLocalFitsBudget(
            KswordArkHvmEptLocalPageCost(
                Runtime->ProcessorCount,
                count,
                count,
                count),
            KSW_HVM_MAX_LOCAL_EPT_PAGES)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Complete the admission check successfully. */
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmEptLocalRelease(
    _Inout_ KSW_HVM_EPT_LOCAL* Local
    )
{
    /* Tolerate a zeroed record so every failure path can call this. */
    if (Local == NULL) {
        /* Return without touching an absent record. */
        return;
    }
    /*
     * One allocation backs the root and every forked table, so one free
     * releases all of them.  ExFreePool is legal at DISPATCH_LEVEL, which
     * matters because this runs from the resident teardown path that a power
     * callback can reach.
     */
    if (Local->PageBlock != NULL) {
        ExFreePool(Local->PageBlock);
    }
    RtlZeroMemory(Local, sizeof(*Local));
}

NTSTATUS
KswordARKHvmEptLocalBuild(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_reads_(Count) const ULONGLONG* Bases,
    _In_ ULONG Count,
    _Out_ KSW_HVM_EPT_LOCAL* Local
    )
{
    KSW_HVM_LOCAL_PAGE_CURSOR cursor = { 0 };
    PHYSICAL_ADDRESS rootPhysical = { 0 };
    ULONGLONG pageCost = 0ULL;
    ULONG distinctPml4 = 0UL;
    ULONG distinctGib = 0UL;
    ULONG index = 0UL;
    ULONG scan = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before allocating anything. */
    if (Runtime == NULL || Bases == NULL || Local == NULL ||
        Count == 0UL || Count > KSW_HVM_MAX_LOCAL_LEAVES ||
        Runtime->EptPml4 == NULL || Runtime->EptPointer == 0ULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Local, sizeof(*Local));
    /*
     * Count the distinct parents before allocating, so the page budget is
     * exact rather than worst-case.  Two leaves in the same GiB window share
     * both a PDPT and a page directory.
     */
    for (index = 0UL; index < Count; ++index) {
        BOOLEAN seenPml4 = FALSE;
        BOOLEAN seenGib = FALSE;

        for (scan = 0UL; scan < index; ++scan) {
            if (KswordArkHvmEptPml4Index(Bases[scan]) ==
                KswordArkHvmEptPml4Index(Bases[index])) {
                /* Record that this PML4 slot already has a fork. */
                seenPml4 = TRUE;
                if (KswordArkHvmEptPdptIndex(Bases[scan]) ==
                    KswordArkHvmEptPdptIndex(Bases[index])) {
                    /* Record that this GiB window already has a fork. */
                    seenGib = TRUE;
                }
            }
        }
        if (!seenPml4) {
            distinctPml4 += 1UL;
        }
        if (!seenGib) {
            distinctGib += 1UL;
        }
    }
    /* Refuse before allocating when the whole set cannot fit the budget. */
    pageCost = KswordArkHvmEptLocalPageCost(
        Runtime->ProcessorCount,
        distinctPml4,
        distinctGib,
        Count);
    if (!KswordArkHvmEptLocalFitsBudget(
            pageCost,
            KSW_HVM_MAX_LOCAL_EPT_PAGES)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* This record needs only its own share of that budget. */
    cursor.Total = 1UL + distinctPml4 + distinctGib + Count;
    if (cursor.Total > (KSW_HVM_MAX_LOCAL_TABLES + 1UL)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * One allocation for the whole processor.  A per-table allocator would
     * make a fragmented machine fail a start half-way through, and would put
     * MmFreeContiguousMemory - which requires PASSIVE_LEVEL - on a teardown
     * path a power callback can reach.
     */
    cursor.Block = (PUCHAR)KswordARKAllocateNonPagedPool(
        (SIZE_T)cursor.Total * (SIZE_T)PAGE_SIZE,
        KSW_HVM_EPT_LOCAL_POOL_TAG);
    if (cursor.Block == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(cursor.Block, (SIZE_T)cursor.Total * (SIZE_T)PAGE_SIZE);
    Local->PageBlock = cursor.Block;
    Local->PageCount = cursor.Total;
    /* Take the root first so every rebase below has somewhere to publish. */
    Local->Pml4Virtual = KswordARKHvmEptLocalTakePage(
        &cursor,
        &rootPhysical);
    if (Local->Pml4Virtual == NULL) {
        /* Release everything this record took before returning. */
        KswordARKHvmEptLocalRelease(Local);
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(
        Local->Pml4Virtual,
        Runtime->EptPml4,
        (SIZE_T)PAGE_SIZE);
    Local->Pml4Physical = rootPhysical;
    /*
     * Derive the private pointer from the shared one rather than composing it
     * from constants.  Composing would give the memory type, the walk length
     * and the accessed/dirty bit a second source of truth; derived this way
     * the private pointer is accepted by VM entry exactly when the shared one
     * is, and an INVEPT descriptor built from it matches the VMCS field.
     */
    Local->EptPointer = KswordArkHvmEptRebaseEntry(
        Runtime->EptPointer,
        (ULONGLONG)rootPhysical.QuadPart);
    /* Fork parent before child so no private entry ever points at nothing. */
    for (index = 0UL; index < Count; ++index) {
        const ULONG pml4Index = KswordArkHvmEptPml4Index(Bases[index]);
        const ULONG pdptIndex = KswordArkHvmEptPdptIndex(Bases[index]);
        const ULONG pdIndex = KswordArkHvmEptPdIndex(Bases[index]);
        KSW_HVM_EPT_LOCAL_TABLE* pdptRecord = NULL;
        KSW_HVM_EPT_LOCAL_TABLE* pdRecord = NULL;
        KSW_HVM_EPT_LOCAL_TABLE* ptRecord = NULL;
        KSW_HVM_EPT_SPLIT* split = NULL;
        ULONGLONG* privateTable = NULL;
        ULONG splitScan = 0UL;

        /* Refuse a base whose shared hierarchy was never populated. */
        if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
            pdptIndex >= 512UL ||
            Runtime->EptPdpt[pml4Index] == NULL ||
            Runtime->EptPd[pml4Index][pdptIndex] == NULL) {
            /* Release everything and refuse the whole set. */
            KswordARKHvmEptLocalRelease(Local);
            /* Return the exact hierarchy-contract failure. */
            return STATUS_INVALID_PARAMETER;
        }
        /*
         * Require a live split.  Splitting here would allocate from the
         * shared ledger while this routine owns a private block, and both
         * producers already split eagerly when the rule or view was added -
         * so a missing split means the caller changed the tables underneath
         * us, which must fail rather than be repaired.
         */
        for (splitScan = 0UL;
             splitScan < KSW_HVM_MAX_EPT_SPLITS;
             ++splitScan) {
            if (Runtime->EptSplits[splitScan].Active &&
                Runtime->EptSplits[splitScan].PhysicalBase == Bases[index]) {
                /* Bind the split whose page table will be mirrored. */
                split = &Runtime->EptSplits[splitScan];
                break;
            }
        }
        if (split == NULL || split->PageTable == NULL) {
            /* Release everything and refuse the whole set. */
            KswordARKHvmEptLocalRelease(Local);
            /* Return the exact missing-split failure. */
            return STATUS_NOT_FOUND;
        }
        /* Ensure this PML4 slot has a private page-directory-pointer table. */
        pdptRecord = KswordARKHvmEptLocalFindTable(
            Local,
            Runtime->EptPdpt[pml4Index],
            KSW_HVM_LOCAL_LEVEL_PDPT);
        if (pdptRecord == NULL) {
            status = KswordARKHvmEptLocalForkTable(
                Local,
                &cursor,
                Runtime->EptPdpt[pml4Index],
                KSW_HVM_LOCAL_LEVEL_PDPT,
                &pdptRecord);
            if (!NT_SUCCESS(status)) {
                /* Release everything and refuse the whole set. */
                KswordARKHvmEptLocalRelease(Local);
                /* Return the exact fork failure. */
                return status;
            }
            /* Point the private root at the private PDPT. */
            ((ULONGLONG*)Local->Pml4Virtual)[pml4Index] =
                KswordArkHvmEptRebaseEntry(
                    ((const ULONGLONG*)Runtime->EptPml4)[pml4Index],
                    (ULONGLONG)pdptRecord->PrivatePhysical.QuadPart);
        }
        /* Ensure this GiB window has a private page directory. */
        pdRecord = KswordARKHvmEptLocalFindTable(
            Local,
            Runtime->EptPd[pml4Index][pdptIndex],
            KSW_HVM_LOCAL_LEVEL_PD);
        if (pdRecord == NULL) {
            status = KswordARKHvmEptLocalForkTable(
                Local,
                &cursor,
                Runtime->EptPd[pml4Index][pdptIndex],
                KSW_HVM_LOCAL_LEVEL_PD,
                &pdRecord);
            if (!NT_SUCCESS(status)) {
                /* Release everything and refuse the whole set. */
                KswordARKHvmEptLocalRelease(Local);
                /* Return the exact fork failure. */
                return status;
            }
            /* Point the private PDPT at the private page directory. */
            privateTable = (ULONGLONG*)pdptRecord->PrivateVirtual;
            privateTable[pdptIndex] = KswordArkHvmEptRebaseEntry(
                ((const ULONGLONG*)Runtime->EptPdpt[pml4Index])[pdptIndex],
                (ULONGLONG)pdRecord->PrivatePhysical.QuadPart);
        }
        /* Mirror the split page table that actually gets flipped. */
        ptRecord = KswordARKHvmEptLocalFindTable(
            Local,
            split->PageTable,
            KSW_HVM_LOCAL_LEVEL_PT);
        if (ptRecord == NULL) {
            status = KswordARKHvmEptLocalForkTable(
                Local,
                &cursor,
                split->PageTable,
                KSW_HVM_LOCAL_LEVEL_PT,
                &ptRecord);
            if (!NT_SUCCESS(status)) {
                /* Release everything and refuse the whole set. */
                KswordARKHvmEptLocalRelease(Local);
                /* Return the exact fork failure. */
                return status;
            }
            /* Point the private page directory at the private leaf table. */
            privateTable = (ULONGLONG*)pdRecord->PrivateVirtual;
            privateTable[pdIndex] = KswordArkHvmEptRebaseEntry(
                ((const ULONGLONG*)
                    Runtime->EptPd[pml4Index][pdptIndex])[pdIndex],
                (ULONGLONG)ptRecord->PrivatePhysical.QuadPart);
        }
    }
    /* Publish the record only after every table is in place. */
    KeMemoryBarrier();
    Local->Active = TRUE;
    /* Complete the build successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptLocalVerify(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_reads_(ProcessorCount) const KSW_HVM_EPT_LOCAL* LocalArray,
    _In_ ULONG ProcessorCount,
    _In_reads_(Count) const ULONGLONG* Bases,
    _In_ ULONG Count
    )
{
    ULONG processor = 0UL;
    ULONG peer = 0UL;
    ULONG index = 0UL;

    /* Reject an incomplete caller contract before any walk. */
    if (Runtime == NULL || LocalArray == NULL || Bases == NULL ||
        ProcessorCount == 0UL || Count == 0UL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    for (processor = 0UL; processor < ProcessorCount; ++processor) {
        const KSW_HVM_EPT_LOCAL* local = &LocalArray[processor];

        /* Every processor must actually own a built hierarchy. */
        if (!local->Active ||
            local->Pml4Virtual == NULL ||
            local->EptPointer == 0ULL) {
            /* Return the exact verification failure. */
            return STATUS_UNSUCCESSFUL;
        }
        /*
         * Compare the root address, not the whole pointer.
         *
         * What makes single-context INVEPT on one processor leave the others
         * alone is that their cached translations are tagged by the root
         * address.  Two pointers differing only in a control bit would tag
         * identically, so comparing whole pointers would accept exactly the
         * arrangement this check exists to reject.
         */
        if ((local->EptPointer & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) ==
            (Runtime->EptPointer & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK)) {
            /* Return the exact verification failure. */
            return STATUS_UNSUCCESSFUL;
        }
        for (peer = 0UL; peer < processor; ++peer) {
            if ((local->EptPointer & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) ==
                (LocalArray[peer].EptPointer &
                    KSWORD_ARK_HVM_EPT_PHYSICAL_MASK)) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
        }
        /*
         * Walk each base from this private root downward and check the
         * postcondition, rather than replaying how the build got there.  A
         * mistake shared by build and check would survive a replay.
         */
        for (index = 0UL; index < Count; ++index) {
            const ULONG pml4Index = KswordArkHvmEptPml4Index(Bases[index]);
            const ULONG pdptIndex = KswordArkHvmEptPdptIndex(Bases[index]);
            const ULONG pdIndex = KswordArkHvmEptPdIndex(Bases[index]);
            const KSW_HVM_EPT_LOCAL_TABLE* record = NULL;
            const ULONGLONG* table = NULL;
            ULONGLONG entry = 0ULL;
            ULONG scan = 0UL;
            ULONG slot = 0UL;

            /* Resolve the private PDPT the private root names. */
            entry = ((const ULONGLONG*)local->Pml4Virtual)[pml4Index];
            record = NULL;
            for (scan = 0UL; scan < local->TableCount; ++scan) {
                if ((ULONGLONG)local->Tables[scan].PrivatePhysical.QuadPart ==
                        (entry & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) &&
                    local->Tables[scan].Level == KSW_HVM_LOCAL_LEVEL_PDPT) {
                    /* Bind the private table this entry actually names. */
                    record = &local->Tables[scan];
                    break;
                }
            }
            if (record == NULL) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
            /* Resolve the private page directory that PDPT names. */
            table = (const ULONGLONG*)record->PrivateVirtual;
            entry = table[pdptIndex];
            record = NULL;
            for (scan = 0UL; scan < local->TableCount; ++scan) {
                if ((ULONGLONG)local->Tables[scan].PrivatePhysical.QuadPart ==
                        (entry & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) &&
                    local->Tables[scan].Level == KSW_HVM_LOCAL_LEVEL_PD) {
                    /* Bind the private table this entry actually names. */
                    record = &local->Tables[scan];
                    break;
                }
            }
            if (record == NULL) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
            /* Resolve the private leaf table that page directory names. */
            table = (const ULONGLONG*)record->PrivateVirtual;
            entry = table[pdIndex];
            record = NULL;
            for (scan = 0UL; scan < local->TableCount; ++scan) {
                if ((ULONGLONG)local->Tables[scan].PrivatePhysical.QuadPart ==
                        (entry & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) &&
                    local->Tables[scan].Level == KSW_HVM_LOCAL_LEVEL_PT) {
                    /* Bind the private table this entry actually names. */
                    record = &local->Tables[scan];
                    break;
                }
            }
            if (record == NULL) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
            /*
             * The private leaf table must still agree with the shared one,
             * entry for entry.  Any divergence at arm time means the copy
             * raced a mutation, and the whole arm has to fail.
             */
            for (slot = 0UL;
                 slot < (PAGE_SIZE / sizeof(ULONGLONG));
                 ++slot) {
                if (((const ULONGLONG*)record->PrivateVirtual)[slot] !=
                    ((const ULONGLONG*)record->SharedVirtual)[slot]) {
                    /* Return the exact verification failure. */
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }
    }
    /* Complete verification successfully. */
    return STATUS_SUCCESS;
}

volatile ULONGLONG*
KswordARKHvmEptLocalTranslate(
    _In_opt_ const KSW_HVM_EPT_LOCAL* Local,
    _In_opt_ volatile ULONGLONG* SharedEntry
    )
{
    ULONGLONG tableBase = 0ULL;
    ULONGLONG offset = 0ULL;
    ULONG index = 0UL;

    /*
     * The feature-off case.  Returning NULL here is what makes the two arm
     * sites collapse to exactly the code they run today: they keep the
     * shared pointer they already hold.
     */
    if (Local == NULL || SharedEntry == NULL || !Local->Active) {
        /* Report that no translation applies. */
        return NULL;
    }
    tableBase = KswordArkHvmEptEntryTableBase((ULONGLONG)(ULONG_PTR)SharedEntry);
    offset = KswordArkHvmEptEntryByteOffset((ULONGLONG)(ULONG_PTR)SharedEntry);
    /* Find the private mirror of the table this entry lives in. */
    for (index = 0UL; index < Local->TableCount; ++index) {
        /* Only leaf tables are ever flipped, so only they are translated. */
        if (Local->Tables[index].Level == KSW_HVM_LOCAL_LEVEL_PT &&
            (ULONGLONG)(ULONG_PTR)Local->Tables[index].SharedVirtual ==
                tableBase) {
            /* Return the same slot inside this processor's own copy. */
            return (volatile ULONGLONG*)(
                (PUCHAR)Local->Tables[index].PrivateVirtual +
                (SIZE_T)offset);
        }
    }
    /*
     * A flippable leaf that has no mirror is a build error, and the caller
     * must fail closed rather than write the shared table it was trying to
     * avoid.
     */
    return NULL;
}

#endif /* defined(_M_AMD64) */
