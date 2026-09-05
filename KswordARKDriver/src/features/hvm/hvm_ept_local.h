/*++

Module Name:

    hvm_ept_local.h

Abstract:

    Declares per-processor private EPT hierarchies.  A private hierarchy is
    the shared one with the few tables on the path to a flippable leaf
    replaced by private copies, so that writing that leaf reaches only the
    processor walking it.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

#if defined(_M_AMD64)

/*
 * Bound the flippable leaves one private hierarchy mirrors.
 *
 * Every leaf costs one private page table per processor, so this bound is
 * what keeps a 128-way machine affordable.  It is deliberately small: the
 * mechanism exists for a handful of hooked or cloaked pages, not for a
 * general-purpose second address space.
 */
#define KSW_HVM_MAX_LOCAL_LEAVES 8UL
/*
 * Bound the paging structures one processor may fork.
 *
 * Worst case per processor is one PDPT and one page directory per leaf plus
 * the leaf tables themselves, which for eight leaves that share no parent is
 * 8 + 8 + 8 = 24.  A set that needs more is refused rather than truncated.
 */
#define KSW_HVM_MAX_LOCAL_TABLES 24UL
/*
 * Bound the total pages every processor together may consume.
 *
 * This is checked against KswordArkHvmEptLocalPageCost before the first
 * allocation, so an inadmissible topology is refused while nothing has been
 * allocated rather than half-way through.
 */
#define KSW_HVM_MAX_LOCAL_EPT_PAGES 2048ULL

/* Tag which level of the hierarchy a forked table sits at. */
#define KSW_HVM_LOCAL_LEVEL_PDPT 1UL
#define KSW_HVM_LOCAL_LEVEL_PD   2UL
#define KSW_HVM_LOCAL_LEVEL_PT   3UL

/* Track one paging structure this processor forked from the shared tree. */
typedef struct _KSW_HVM_EPT_LOCAL_TABLE
{
    /* Retain the shared table this one was copied from. */
    PVOID SharedVirtual;
    /* Retain the private copy this processor walks instead. */
    PVOID PrivateVirtual;
    /* Retain the private physical address published into the parent entry. */
    PHYSICAL_ADDRESS PrivatePhysical;
    /* Record the level, which decides how the entry is rebased. */
    ULONG Level;
    /* Keep the structure explicitly initialized across architectures. */
    ULONG Reserved0;
} KSW_HVM_EPT_LOCAL_TABLE;

/* Own one processor's private view of the EPT hierarchy. */
typedef struct _KSW_HVM_EPT_LOCAL
{
    /* Record whether this record describes a built hierarchy. */
    BOOLEAN Active;
    /* Keep the 64-bit members naturally aligned. */
    UCHAR Reserved0[7];
    /*
     * Retain the EPT pointer this processor loads.  It is the shared pointer
     * with only the root address replaced, so it is accepted by VM entry
     * exactly when the shared one is.
     */
    ULONGLONG EptPointer;
    /* Retain this processor's own root table. */
    PVOID Pml4Virtual;
    /* Retain the root physical address encoded into EptPointer. */
    PHYSICAL_ADDRESS Pml4Physical;
    /*
     * Retain the single allocation backing every private table.
     *
     * One nonpaged allocation per processor rather than one per table: the
     * teardown path runs from a power callback where MmFreeContiguousMemory
     * would be illegal, and a fragmented machine should not be able to fail
     * a start half-way through.
     */
    PVOID PageBlock;
    /* Retain how many pages the block holds, for the release path. */
    ULONG PageCount;
    /* Retain how many forked tables are recorded. */
    ULONG TableCount;
    /* Own every forked paging structure on this processor. */
    KSW_HVM_EPT_LOCAL_TABLE Tables[KSW_HVM_MAX_LOCAL_TABLES];
} KSW_HVM_EPT_LOCAL;

EXTERN_C_START

/*
 * Collect the two-MiB bases whose leaves any mechanism may flip.
 *
 * Reads the rule and view tables, which the caller must already have frozen.
 * Pure read: allocates nothing and publishes nothing.
 */
NTSTATUS
KswordARKHvmEptLocalCollectLeaves(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _Out_writes_to_(Capacity, *Count) ULONGLONG* Bases,
    _In_ ULONG Capacity,
    _Out_ ULONG* Count
    );

/*
 * Build one processor's private hierarchy over the collected bases.
 *
 * PASSIVE_LEVEL, caller holds the runtime lock exclusive.  On failure the
 * record is released before returning, so a caller never sees a half-built
 * hierarchy.
 */
NTSTATUS
KswordARKHvmEptLocalBuild(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_reads_(Count) const ULONGLONG* Bases,
    _In_ ULONG Count,
    _Out_ KSW_HVM_EPT_LOCAL* Local
    );

/*
 * Prove the built hierarchies independently of how they were built.
 *
 * Deliberately not a replay: it walks each private root from the top and
 * checks the postcondition, so a bug shared between build and check cannot
 * hide.  Returns STATUS_SUCCESS only when every processor passes.
 */
NTSTATUS
KswordARKHvmEptLocalVerify(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_reads_(ProcessorCount) const KSW_HVM_EPT_LOCAL* LocalArray,
    _In_ ULONG ProcessorCount,
    _In_reads_(Count) const ULONGLONG* Bases,
    _In_ ULONG Count
    );

/*
 * Decide whether one more protected range would still fit.
 *
 * Called from the add paths rather than only from start, so an inadmissible
 * rule or view is refused where the caller can still do something about it -
 * with the numbers in hand - instead of at the end of a lifecycle preamble.
 * Returns STATUS_SUCCESS when the feature is not armed, because then nothing
 * is mirrored and no limit applies.
 */
NTSTATUS
KswordARKHvmEptLocalCheckAdmission(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG ByteCount
    );

/* Release one private hierarchy.  Idempotent on a zeroed record. */
VOID
KswordARKHvmEptLocalRelease(
    _Inout_ KSW_HVM_EPT_LOCAL* Local
    );

/*
 * Translate a shared leaf pointer into this processor's private one.
 *
 * The only entry point reachable from VMX root.  Returns NULL when Local is
 * NULL - the feature-off case, where the caller keeps using the shared
 * pointer it already has - and also when the address belongs to no mirrored
 * table, which is a build error and must fail closed.
 */
volatile ULONGLONG*
KswordARKHvmEptLocalTranslate(
    _In_opt_ const KSW_HVM_EPT_LOCAL* Local,
    _In_opt_ volatile ULONGLONG* SharedEntry
    );

EXTERN_C_END

#endif /* defined(_M_AMD64) */
