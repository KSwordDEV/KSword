/* Preallocated AMD NPT02 construction; all paths are bounded and nonblocking. */
#include "hvm_svm_nested_shadow.h"

/* Clear one owned hardware page without calling an allocator or memory manager. */
static void KswNshadowClear(KSW_SVM_U64* Words)
{
    /* Every page contains exactly 512 architectural entries. */
    unsigned int slot;
    /* The owning CPU is outside its nested guest during every update. */
    for (slot = 0; slot < 512U; ++slot) { Words[slot] = 0; }
}

/* Locate child pages through the allocation ledger, never by mapping guest pointers. */
static unsigned int KswNshadowFind(const KSW_NSHADOW* Shadow, KSW_SVM_U64 Physical)
{
    /* Search has an explicit maximum of 256 prepared pages. */
    unsigned int page;
    /* Root is never a valid child of another table. */
    for (page = 1; page < Shadow->Used; ++page) {
        /* Hardware addresses were validated at prepare time. */
        if (Shadow->Pages[page].Physical == Physical) { return page; }
    }
    /* An entry outside the owned ledger indicates corruption. */
    return Shadow->Capacity;
}

/* Try an aligned large NPT leaf before falling back to the 4-KiB path. */
static int KswNshadowTryLarge(KSW_NSHADOW* Shadow,
    const unsigned int* Indices, unsigned int TargetLevel, KSW_SVM_U64 Leaf)
{
    unsigned int page = 0, level, missing = TargetLevel;
    KSW_SVM_U64 entry;

    /* Only ancestors before the selected large leaf may need allocation. */
    for (level = 0; level < TargetLevel; ++level) {
        entry = Shadow->Pages[page].Words[Indices[level]];
        if (!entry) { missing = level; break; }
        if ((entry & ~Shadow->AddressMask & ~0x20ULL) != 7ULL) { return -2; }
        page = KswNshadowFind(Shadow, entry & Shadow->AddressMask);
        if (page == Shadow->Capacity) { return -2; }
    }

    /* A table already occupying this PD slot may contain 4-KiB leaves. */
    entry = Shadow->Pages[page].Words[Indices[TargetLevel]];
    if (entry && !(entry & 0x80ULL)) { return -1; }
    if (TargetLevel - missing > Shadow->Capacity - Shadow->Used) { return -3; }

    for (level = missing; level < TargetLevel; ++level) {
        unsigned int child = Shadow->Used++;
        KswNshadowClear(Shadow->Pages[child].Words);
        Shadow->Pages[page].Words[Indices[level]] = Shadow->Pages[child].Physical | 7ULL;
        page = child;
    }
    entry = Shadow->Pages[page].Words[Indices[TargetLevel]];
    if (!entry || entry != Leaf) {
        Shadow->Pages[page].Words[Indices[TargetLevel]] = Leaf;
        Shadow->FlushPending = 1;
    }
    return 0;
}

/* Validate the entire pool before clearing or publishing any page. */
unsigned int KswSvmNestedShadowInitialize(KSW_NSHADOW* Shadow,
    KSW_NSHADOW_PAGE* Pages, unsigned int Count, unsigned int PhysicalBits)
{
    /* Bound physical addresses before any shifts or parent publication. */
    KSW_SVM_U64 mask = KswNptAddressMask(PhysicalBits);
    /* Duplicate mappings would make per-level ownership ambiguous. */
    unsigned int page, previous;
    /* Only an empty software owner may acquire a pool. */
    if (!Shadow || Shadow->Pages || !Pages || !mask || !Count || Count > KSW_NSHADOW_MAX_PAGES) {
        /* Reject without altering caller-owned state. */
        return KSW_NSHADOW_INVALID;
    }
    /* Verify all resource descriptors before the first page write. */
    for (page = 0; page < Count; ++page) {
        /* Zero physical frame is refused for the host-owned table pool. */
        if (!Pages[page].Words || ((size_t)Pages[page].Words & 4095U) ||
            !Pages[page].Physical || (Pages[page].Physical & ~mask)) { return KSW_NSHADOW_INVALID; }
        /* Distinct virtual mappings of one physical page are not distinct resources. */
        for (previous = 0; previous < page; ++previous) {
            /* Check both identities to avoid accidentally aliasing live tables. */
            if (Pages[page].Physical == Pages[previous].Physical ||
                Pages[page].Words == Pages[previous].Words) { return KSW_NSHADOW_INVALID; }
        }
    }
    /* Publish the verified ledger while no CPU can execute this root. */
    Shadow->Pages = Pages;
    /* Preserve the hard preparation budget. */
    Shadow->Capacity = Count;
    /* Initially only the empty root belongs to the hardware tree. */
    Shadow->Used = 1;
    /* Bind the first translation resolution to epoch one. */
    Shadow->Epoch = 1;
    /* Preserve the exact PA mask used for every later entry. */
    Shadow->AddressMask = mask;
    /* First use must not inherit translations from an earlier ASID owner. */
    Shadow->FlushPending = 1;
    /* No guest entry may observe allocator residue. */
    KswNshadowClear(Pages[0].Words);
    /* Unused child pages are cleared just before they are linked. */
    return KSW_NSHADOW_OK;
}

/* Reset is a software invalidation only; it is not a substitute for TLB_CONTROL. */
unsigned int KswSvmNestedShadowReset(KSW_NSHADOW* Shadow)
{
    /* Epoch wrap cannot make an ancient candidate look current. */
    if (!Shadow || !Shadow->Pages || !Shadow->Used || Shadow->Epoch == ~0ULL) { return KSW_NSHADOW_INVALID; }
    /* Clearing the root disconnects every old child before the pool is reused. */
    KswNshadowClear(Shadow->Pages[0].Words);
    /* Future child allocations clear their pages again before publication. */
    Shadow->Used = 1;
    /* Invalidate all previously resolved candidates. */
    ++Shadow->Epoch;
    /* The owner must issue a real hardware flush before using this root again. */
    Shadow->FlushPending = 1;
    /* Resource ownership remains unchanged. */
    return KSW_NSHADOW_OK;
}

/* Install one 4-KiB leaf, splitting large source mappings in the resolver. */
unsigned int KswSvmNestedShadowInstall(KSW_NSHADOW* Shadow, const KSW_NMMU_RESULT* Result)
{
    /* Retain at most the four indices needed by this bounded walk. */
    unsigned int indices[4];
    /* Track existing parent pages before making any edits. */
    unsigned int page = 0, level, missing = 3;
    /* Allowed leaf bits: frame, P/RW/US, cache, A/D and NX; no Intel EPT attributes. */
    KSW_SVM_U64 allowed;
    /* Refuse malformed owners before indexing their resource ledger. */
    if (!Shadow || !Result || !Shadow->Pages || !Shadow->Used ||
        Shadow->Used > Shadow->Capacity || Shadow->Capacity > KSW_NSHADOW_MAX_PAGES) { return KSW_NSHADOW_INVALID; }
    /* Zero/default result buffers are never valid mappings. */
    if (Result->Status != KSW_NNPT_OK || !Result->Leaf || !Result->Inner.Complete || !Result->Outer.Complete) {
        /* The caller must resolve and commit both source paths first. */
        return KSW_NSHADOW_INVALID;
    }
    /* Reject stale translations even if their physical frames happen to match. */
    if (Result->Epoch != Shadow->Epoch) { return KSW_NSHADOW_STALE; }
    /* Keep the candidate bound to both committed source translations. */
    if (Result->Gpa != Result->Inner.InputAddress || Result->Inner.Address != Result->Outer.InputAddress ||
        (Result->Leaf & Shadow->AddressMask) != (Result->Outer.Address & Shadow->AddressMask) ||
        (Result->Leaf & 7ULL & ~(Result->Inner.Permissions & Result->Outer.Permissions)) ||
        ((Result->Inner.Permissions | Result->Outer.Permissions) & KSW_NNPT_NX & ~Result->Leaf)) {
        /* Refuse mixed evidence even when its epoch is numerically current. */
        return KSW_NSHADOW_INVALID;
    }
    /* Allow bit 7 as 4-KiB PAT, not as a large-page flag. */
    allowed = Shadow->AddressMask | 0xffULL | KSW_NNPT_NX;
    /* Physical/GPA width, user permission and committed A bit are required. */
    if ((Result->Leaf & ~allowed) || (Result->Gpa & ~(Shadow->AddressMask | 4095ULL)) ||
        (Result->Leaf & 0x25ULL) != 0x25ULL ||
        ((Result->Leaf & 2ULL) && !(Result->Leaf & 0x40ULL))) { return KSW_NSHADOW_INVALID; }
    /* Compute each index from the original L2 GPA, never from the final host PA. */
    for (level = 0; level < 4; ++level) { indices[level] = (unsigned int)((Result->Gpa >> (39U - 9U * level)) & 511ULL); }
    /* A pair of aligned 1-GiB source leaves covers the complete large span. */
    if ((Result->Inner.LeafShift >= 30U && Result->Outer.LeafShift >= 30U) &&
        ((Result->Gpa ^ Result->Inner.Address) & 0x3fffffffULL) == 0ULL &&
        ((Result->Gpa ^ Result->Outer.Address) & 0x3fffffffULL) == 0ULL) {
        unsigned int pat = (unsigned int)(((Result->Leaf >> 3) & 3ULL) |
            (((Result->Leaf >> 7) & 1ULL) << 2));
        KSW_SVM_U64 large = (Result->Outer.Address & Shadow->AddressMask & ~0x3fffffffULL) |
            (Result->Leaf & (0x7ULL | 0x18ULL | 0x60ULL | KSW_NNPT_NX)) |
            (KswNptLeafFlags(3U, pat) & ~7ULL);
        int largeStatus = KswNshadowTryLarge(Shadow, indices, 1U, large);
        if (largeStatus >= 0) { return (unsigned int)largeStatus; }
        if (largeStatus == -3) { return KSW_NSHADOW_FULL; }
        if (largeStatus == -2) { return KSW_NSHADOW_INVALID; }
    }
    /* A pair of aligned 2-MiB source leaves covers the complete smaller span. */
    if ((Result->Inner.LeafShift >= 21U && Result->Outer.LeafShift >= 21U) &&
        ((Result->Gpa ^ Result->Inner.Address) & 0x1fffffULL) == 0ULL &&
        ((Result->Gpa ^ Result->Outer.Address) & 0x1fffffULL) == 0ULL) {
        unsigned int pat = (unsigned int)(((Result->Leaf >> 3) & 3ULL) |
            (((Result->Leaf >> 7) & 1ULL) << 2));
        KSW_SVM_U64 large = (Result->Outer.Address & Shadow->AddressMask & ~0x1fffffULL) |
            (Result->Leaf & (0x7ULL | 0x18ULL | 0x60ULL | KSW_NNPT_NX)) |
            (KswNptLeafFlags(2U, pat) & ~7ULL);
        int largeStatus = KswNshadowTryLarge(Shadow, indices, 2U, large);
        if (largeStatus >= 0) { return (unsigned int)largeStatus; }
        if (largeStatus == -3) { return KSW_NSHADOW_FULL; }
        if (largeStatus == -2) { return KSW_NSHADOW_INVALID; }
    }
    /* Inspect existing tables without mutating on budget/corruption failure. */
    for (level = 0; level < 3; ++level) {
        /* Read a host-owned parent entry, not a guest-controlled table. */
        KSW_SVM_U64 entry = Shadow->Pages[page].Words[indices[level]];
        /* A zero slot needs a new suffix of intermediate tables. */
        if (!entry) { missing = level; break; }
        /* Only exact permissive nonleaf entries, plus hardware A, are owned here. */
        if ((entry & ~Shadow->AddressMask & ~0x20ULL) != 7ULL) { return KSW_NSHADOW_INVALID; }
        /* A hardware pointer must resolve through our prepared ownership ledger. */
        {
            /* Parents are allocated before children, so a backward edge is corruption. */
            unsigned int child = KswNshadowFind(Shadow, entry & Shadow->AddressMask);
            /* This also rejects cycles and a table pointing at itself. */
            if (child <= page || child == Shadow->Capacity) { return KSW_NSHADOW_INVALID; }
            /* Follow only a forward edge in the allocation ledger. */
            page = child;
        }
        /* Never follow a forged pointer outside the pool. */
        if (page == Shadow->Capacity) { return KSW_NSHADOW_INVALID; }
    }
    /* Refuse before clearing/linking anything when the entire suffix cannot fit. */
    if (3U - missing > Shadow->Capacity - Shadow->Used) { return KSW_NSHADOW_FULL; }
    /* Add at most three pages, all of which were preallocated and validated. */
    for (level = missing; level < 3; ++level) {
        /* Acquire the next unused page from the local ledger. */
        unsigned int child = Shadow->Used++;
        /* Eliminate stale leaf entries before making this page reachable. */
        KswNshadowClear(Shadow->Pages[child].Words);
        /* The owner is outside VMRUN; publication completes before the next entry. */
        Shadow->Pages[page].Words[indices[level]] = Shadow->Pages[child].Physical | 7ULL;
        /* Continue down the newly constructed suffix. */
        page = child;
    }
    /* Commit a fully resolved leaf only after all parents are present. */
    {
        KSW_SVM_U64 previous = Shadow->Pages[page].Words[indices[3]];
        Shadow->Pages[page].Words[indices[3]] = Result->Leaf;
        /* AMD may retain a negative NPT walk after an NPF. Flush after both
           first publication and replacement before retrying the same GPA. */
        if (!previous || previous != Result->Leaf) { Shadow->FlushPending = 1; }
    }
    /* Two large source leaves prove uniform translation/permissions/cache over this aligned 2-MiB span. */
    if ((Result->Inner.LeafShift == 21U || Result->Inner.LeafShift == 30U) &&
        (Result->Outer.LeafShift == 21U || Result->Outer.LeafShift == 30U) &&
        ((Result->Gpa ^ Result->Inner.Address) & 0x1fffffULL) == 0 &&
        ((Result->Gpa ^ Result->Outer.Address) & 0x1fffffULL) == 0) {
        /* Preserve the composed 4-KiB PAT encoding and all existing permission restrictions. */
        KSW_SVM_U64 flags = Result->Leaf & ~Shadow->AddressMask;
        /* The validated source leaves cover every frame without walking neighboring source entries. */
        KSW_SVM_U64 base = Result->Outer.Address & Shadow->AddressMask & ~0x1fffffULL;
        /* Populate only empty siblings; do not downgrade previously resolved writable pages. */
        unsigned int slot;
        /* Bound prefilling to the already allocated PT page; no extra allocation or source access. */
        for (slot = 0; slot < 512U; ++slot) {
            /* A/D accounting belongs to the same two large source leaves for every sibling. */
            if (!Shadow->Pages[page].Words[slot]) {
                /* Clean sources stay read-only until their real first write commits D. */
                Shadow->Pages[page].Words[slot] = (base + (KSW_SVM_U64)slot * 4096ULL) | flags;
            }
        }
    }
    /* New leaves are visible on the next walk; reset/replacement paths already request a flush. */
    /* No source A/D work or memory allocation remains in this installation. */
    return KSW_NSHADOW_OK;
}
