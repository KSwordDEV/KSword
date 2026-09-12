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
    /* Take the root first so every fill below has somewhere to publish. */
    Shadow->RootVirtual = KswordARKHvmNestedEptTakePage(
        Shadow,
        &rootPhysical);
    if (Shadow->RootVirtual == NULL) {
        ExFreePool(Shadow->PageBlock);
        Shadow->PageBlock = NULL;
        Shadow->PageTotal = 0UL;
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
    if (Shadow == NULL || Shadow->PageBlock == NULL) {
        /* Return without touching an absent reservation. */
        return;
    }
    ExFreePool(Shadow->PageBlock);
    Shadow->PageBlock = NULL;
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
    Shadow->InvalidationGeneration = Shadow->Generation;
    Shadow->Generation += 1UL;
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
    /* Drop every mapping composed against a different EPT12. */
    if (Shadow->L1EptPointer != L1EptPointer) {
        KswordARKHvmNestedEptInvalidate(Shadow);
        Shadow->L1EptPointer = L1EptPointer;
    }
    Shadow->L1PointerValid = TRUE;
    Shadow->Active = TRUE;
    Shadow->LastStatus = STATUS_SUCCESS;
    /* Return the armed composition. */
    return STATUS_SUCCESS;
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
    _Out_ ULONGLONG* Permissions
    )
{
    /* Index shifts for PML4, PDPT, PD and PT in walk order. */
    static const ULONG shifts[4] = { 39UL, 30UL, 21UL, 12UL };
    ULONGLONG table = Shadow->L1EptPointer & KSW_HVM_NEPT_FRAME_MASK;
    ULONGLONG permissions = KSW_HVM_NEPT_PERMISSIONS;
    ULONG level = 0UL;

    *L1Physical = 0ULL;
    *Permissions = 0ULL;
    for (level = 0UL; level < 4UL; ++level) {
        const ULONGLONG index =
            (GuestPhysicalAddress >> shifts[level]) & 0x1FFULL;
        ULONGLONG entry = 0ULL;

        if (!NT_SUCCESS(KswordARKHvmPhysWindowReadQword(
                Window,
                table + (index << 3),
                &entry))) {
            /* Report that EPT12 could not be walked at all. */
            return FALSE;
        }
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
            *Permissions = permissions & KSW_HVM_NEPT_PERMISSIONS;
            /* Report a complete EPT12 translation. */
            return TRUE;
        }
        table = entry & KSW_HVM_NEPT_FRAME_MASK;
    }
    /* Report that the walk ran out of levels without a leaf. */
    return FALSE;
}

BOOLEAN
KswordARKHvmNestedEptFill(
    _Inout_ struct _KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access
    )
{
    /* Index shifts for PML4, PDPT, PD and PT in walk order. */
    static const ULONG shifts[4] = { 39UL, 30UL, 21UL, 12UL };
    ULONGLONG l1Physical = 0ULL;
    ULONGLONG permissions = 0ULL;
    volatile ULONGLONG* table = NULL;
    const volatile ULONGLONG* hostLeaf = NULL;
    ULONG level = 0UL;

    /* Refuse composition without an armed hierarchy or a usable window. */
    if (Shadow == NULL || Window == NULL ||
        !Shadow->Active || Shadow->RootVirtual == NULL) {
        /* Report that this violation is not ours to satisfy. */
        return FALSE;
    }
    /* Translate through L1's own hierarchy first. */
    if (!KswordARKHvmNestedEptWalkL1(
            Shadow,
            Window,
            GuestPhysicalAddress,
            &l1Physical,
            &permissions)) {
        Shadow->DenyCount += 1UL;
        /* Report that EPT12 itself refuses this access. */
        return FALSE;
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
        /* Report the violation as L1's to handle. */
        return FALSE;
    }
    /*
     * Intersect with our own leaf for the same page.
     *
     * EPT01 is an identity map, so the frame is unchanged - but a view or a
     * rule may have narrowed the permissions of that exact page, and L2 must
     * not be handed more than L1-as-a-guest already has.  A page we never
     * split has no four-KiB leaf and keeps the identity default.
     */
    hostLeaf = KswordARKHvmEptFindLeafEntry(Runtime, l1Physical);
    if (hostLeaf != NULL) {
        permissions &= (*hostLeaf & KSW_HVM_NEPT_PERMISSIONS);
        if (((ULONGLONG)Access & permissions) !=
                ((ULONGLONG)Access & KSW_HVM_NEPT_PERMISSIONS)) {
            Shadow->DenyCount += 1UL;
            /* Report a violation our own hierarchy refuses. */
            return FALSE;
        }
    }
    /* Build the shadow path down to the four-KiB leaf. */
    table = (volatile ULONGLONG*)Shadow->RootVirtual;
    for (level = 0UL; level < 3UL; ++level) {
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
                /* Report that no mapping could be composed. */
                return FALSE;
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
            /* Report that the hierarchy could not be navigated. */
            return FALSE;
        }
    }
    table[(GuestPhysicalAddress >> shifts[3]) & 0x1FFULL] =
        (l1Physical & KSW_HVM_NEPT_FRAME_MASK) |
        (permissions & KSW_HVM_NEPT_PERMISSIONS) |
        KSW_HVM_NEPT_MEMORY_TYPE_WB;
    Shadow->FillCount += 1UL;
    Shadow->LastStatus = STATUS_SUCCESS;
    /* Report that the faulting access may now be retried. */
    return TRUE;
}

#else

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
KswordARKHvmNestedEptFill(
    _Inout_ struct _KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access
    )
{
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Shadow);
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(GuestPhysicalAddress);
    UNREFERENCED_PARAMETER(Access);
    /* Report that no mapping could be composed. */
    return FALSE;
}

#endif
