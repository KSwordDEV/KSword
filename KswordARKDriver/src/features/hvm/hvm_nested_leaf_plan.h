/* Decide whether one override may be published as a leaf larger than 4 KiB. */
#pragma once

/* The source scan reads EPT entries through the same callback the lease walker
   uses, so a caller never has to supply two different readers for one region. */
#include "hvm_nested_lease_walk.h"
#include "hvm_nested_leaf_policy.h"

/* Keep the planner independent of Windows so adversarial cases can be tested. */
typedef unsigned long long KSW_PLAN_U64;

/* Architectural EPT frame bits, independent of the host's pointer size. */
#define KSW_PLAN_FRAME 0x000FFFFFFFFFF000ULL
/* Guest-physical addresses are bounded by the architectural EPT width. */
#define KSW_PLAN_GPA_LIMIT (1ULL << 48)
/* The three leaf granularities a four-level EPT can terminate on. */
#define KSW_PLAN_SHIFT_4K 12U
#define KSW_PLAN_SHIFT_2M 21U
#define KSW_PLAN_SHIFT_1G 30U

/* Name why a request was refused; never downgrade silently to a smaller leaf. */
#define KSW_PLAN_OK 0U
#define KSW_PLAN_REFUSE_SHIFT 1U
#define KSW_PLAN_REFUSE_GUEST_ALIGNMENT 2U
#define KSW_PLAN_REFUSE_GUEST_RANGE 3U
#define KSW_PLAN_REFUSE_SOURCE_UNKNOWN 4U
#define KSW_PLAN_REFUSE_SOURCE_GRANULARITY 5U
#define KSW_PLAN_REFUSE_BACKING_ADDRESS 6U
#define KSW_PLAN_REFUSE_BACKING_ALIGNMENT 7U
#define KSW_PLAN_REFUSE_BACKING_SIZE 8U

/* A published plan: the region it owns and the backing that replaces it. */
typedef struct _KSW_HVM_LEAF_PLAN {
    /* Granularity of the shadow leaf this plan installs: 12, 21 or 30. */
    unsigned int LeafShift;
    /* Why the plan was refused, or KSW_PLAN_OK. */
    unsigned int Refusal;
    /* First guest-physical address the plan owns, aligned to its granularity. */
    KSW_PLAN_U64 GuestBase;
    /* Size of the owned region, in bytes. */
    KSW_PLAN_U64 RegionBytes;
    /* Number of 4-KiB pages in the region; the staging index space. */
    KSW_PLAN_U64 PageCount;
    /* Physical base of the contiguous replacement backing. */
    KSW_PLAN_U64 BackingBase;
} KSW_HVM_LEAF_PLAN;

/* Translate a captured source path length into the granularity it terminated on.
   A four-level walk that stopped after two entries ended on a 1-GiB leaf, after
   three on a 2-MiB leaf, and after four on an ordinary page.  Returns 0 for a
   count no walk can produce, so callers cannot read a granularity out of a
   capture that never happened. */
static __inline unsigned int KswordHvmLeafSourceShift(unsigned int EntryCount)
{
    /* Only these three lengths correspond to a terminated four-level walk. */
    return EntryCount == 4U ? KSW_PLAN_SHIFT_4K :
           EntryCount == 3U ? KSW_PLAN_SHIFT_2M :
           EntryCount == 2U ? KSW_PLAN_SHIFT_1G : 0U;
}

/*
 * Plan one override region.
 *
 * The rule that matters is the source-granularity test.  A shadow leaf larger
 * than 4 KiB applies one permission set to every page it covers, so it may only
 * be installed where the source already treats the whole region uniformly - that
 * is, where EPT12's own leaf is at least as coarse as the leaf being installed.
 * Composing a 2-MiB leaf over 512 separately mapped source pages would hand the
 * descendant whatever the sampled page happened to allow, including access the
 * intermediate VMM revoked on one of the other 511.  That is not a performance
 * trade-off; it is a hole, and it is why this is refused rather than narrowed.
 *
 * Every other test is arithmetic: the region must be aligned and inside the
 * architectural address space, and the backing must be a real, aligned, large
 * enough contiguous block.  Alignment of the backing is required because the
 * installed leaf carries a single frame, and hardware ignores the bits below
 * the granularity - an unaligned backing would silently be read as its own
 * aligned base, serving the wrong bytes with no error anywhere.
 */
static __inline int KswordHvmLeafPlanCreate(unsigned int LeafShift,
    KSW_PLAN_U64 GuestPage, unsigned int SourceEntryCount, int SourceUniform,
    KSW_PLAN_U64 BackingPhysical, KSW_PLAN_U64 BackingBytes,
    KSW_HVM_LEAF_PLAN* Plan)
{
    /* Use a constant initializer supported by both WDK C and the host tests. */
    const KSW_HVM_LEAF_PLAN empty = {0};
    /* Granularity the source path actually terminated on. */
    const unsigned int sourceShift = KswordHvmLeafSourceShift(SourceEntryCount);
    /* Size of the region the requested leaf would own. */
    KSW_PLAN_U64 regionBytes;

    /* Reject a missing destination before reporting anything. */
    if (Plan == 0) { return 0; }
    /* Initialize before any test so a refusal never returns stale fields. */
    *Plan = empty;
    /* Only the three architectural granularities may be requested. */
    if (!KswordHvmLeafPolicyValidShift(LeafShift)) {
        Plan->Refusal = KSW_PLAN_REFUSE_SHIFT;
        return 0;
    }
    regionBytes = 1ULL << LeafShift;
    /* Record the request even on refusal, so a rejection names its own region. */
    Plan->LeafShift = LeafShift;
    Plan->RegionBytes = regionBytes;
    Plan->PageCount = regionBytes >> KSW_PLAN_SHIFT_4K;
    /* The region must start on its own granularity. */
    if ((GuestPage & (regionBytes - 1ULL)) != 0ULL) {
        Plan->Refusal = KSW_PLAN_REFUSE_GUEST_ALIGNMENT;
        return 0;
    }
    /*
     * The base must lie inside the architectural address space.
     *
     * Checking the region's end as well would be unreachable, not defensive:
     * every granularity is a power of two dividing the 48-bit limit, so a base
     * already known to be aligned and below the limit is at most limit minus one
     * region, and the region cannot overrun.  A branch no input can take is not
     * protection - it is an untested path that reads like protection.  The test
     * suite asserts the derived property instead.
     */
    if (GuestPage >= KSW_PLAN_GPA_LIMIT) {
        Plan->Refusal = KSW_PLAN_REFUSE_GUEST_RANGE;
        return 0;
    }
    Plan->GuestBase = GuestPage;
    /* A capture that never terminated cannot say what granularity it found. */
    if (sourceShift == 0U) {
        Plan->Refusal = KSW_PLAN_REFUSE_SOURCE_UNKNOWN;
        return 0;
    }
    /* Uniform attributes do not prove contiguous frames, stable leases or
       one-to-one A/D ownership. Keep the parameter for source compatibility,
       but admit a region only when one captured source leaf covers it. */
    (void)SourceUniform;
    if (!KswordHvmLeafPolicySourceCovers(LeafShift, SourceEntryCount)) {
        Plan->Refusal = KSW_PLAN_REFUSE_SOURCE_GRANULARITY;
        return 0;
    }
    /* Physical zero is never handed out as backing. */
    if ((BackingPhysical & KSW_PLAN_FRAME) == 0ULL ||
        (BackingPhysical & ~KSW_PLAN_FRAME) != 0ULL) {
        Plan->Refusal = KSW_PLAN_REFUSE_BACKING_ADDRESS;
        return 0;
    }
    /* Hardware ignores address bits below the granularity of the leaf. */
    if ((BackingPhysical & (regionBytes - 1ULL)) != 0ULL) {
        Plan->Refusal = KSW_PLAN_REFUSE_BACKING_ALIGNMENT;
        return 0;
    }
    /* A short allocation would publish a leaf over memory we do not own. */
    if (BackingBytes < regionBytes) {
        Plan->Refusal = KSW_PLAN_REFUSE_BACKING_SIZE;
        return 0;
    }
    Plan->BackingBase = BackingPhysical;
    /* Report a complete, publishable plan. */
    Plan->Refusal = KSW_PLAN_OK;
    return 1;
}

/* How many 4-KiB source entries a scan will examine before giving up.
   A 2-MiB region is 512 of them, which is one table page and one pass. A 1-GiB
   region is 262,144, and every one would have to be re-read on each drift check;
   that is refused rather than attempted, so the bound is a policy and not a
   truncation. */
#define KSW_PLAN_MAX_SCAN_ENTRIES 512U

/* What examining every source entry under a region concluded. */
typedef struct _KSW_HVM_LEAF_SOURCE_SCAN {
    /* Granularity the walk terminated on for the region's first address. */
    unsigned int Shift;
    /* Number of distinct leaf entries the region is covered by. */
    KSW_PLAN_U64 LeafCount;
    /* Access and memory-type bits shared by every leaf, when Uniform. */
    KSW_PLAN_U64 SharedBits;
    /* 1 when every leaf grants identical access and memory type. */
    int Uniform;
    /* 1 when the whole region is covered; 0 when a leaf was unreadable. */
    int Complete;
} KSW_HVM_LEAF_SOURCE_SCAN;

/* Diagnostic attribute scan only. Its result never authorizes coarse mapping.
   A/D bits are excluded because hardware changes them independently. */
static __inline int KswordHvmLeafPlanScanSource(KSW_PLAN_U64 EptPointer,
    KSW_PLAN_U64 GuestBase, unsigned int LeafShift, KSW_LEASE_READ Read,
    void* Context, KSW_HVM_LEAF_SOURCE_SCAN* Scan)
{
    /* Hardware walk order, including 1-GiB and 2-MiB leaf offsets. */
    static const unsigned int shifts[4] = {39U, 30U, 21U, 12U};
    const KSW_HVM_LEAF_SOURCE_SCAN empty = {0};
    KSW_PLAN_U64 regionBytes;
    KSW_PLAN_U64 offset;
    KSW_PLAN_U64 shared = 0ULL;
    int first = 1;

    if (Scan == 0) { return 0; }
    *Scan = empty;
    if (Read == 0 || !KswordHvmLeafPolicyValidShift(LeafShift) ||
        GuestBase >= KSW_PLAN_GPA_LIMIT ||
        (GuestBase & ((1ULL << LeafShift) - 1ULL)) != 0ULL) {
        return 0;
    }
    regionBytes = 1ULL << LeafShift;
    /* Walk one address per 4-KiB page and stop at whatever leaf covers it. */
    for (offset = 0ULL; offset < regionBytes; offset += (1ULL << KSW_PLAN_SHIFT_4K)) {
        const KSW_PLAN_U64 guest = GuestBase + offset;
        KSW_PLAN_U64 table = EptPointer & KSW_PLAN_FRAME;
        KSW_PLAN_U64 leafBits = 0ULL;
        KSW_PLAN_U64 covered = 1ULL << KSW_PLAN_SHIFT_4K;
        unsigned int level;

        if (table == 0ULL) { return 0; }
        for (level = 0U; level < 4U; ++level) {
            const KSW_PLAN_U64 address =
                table + (((guest >> shifts[level]) & 0x1FFULL) << 3);
            KSW_PLAN_U64 entry = 0ULL;

            /* An unreadable or absent entry means the region is not covered. */
            if (!Read(Context, address, &entry) || (entry & 7ULL) == 0ULL) {
                return 1; /* Scan is valid; Complete stays zero. */
            }
            if (level == 3U || ((level == 1U || level == 2U) &&
                                (entry & 0x80ULL) != 0ULL)) {
                /* Access, memory type and ignore-PAT; never accessed/dirty. */
                leafBits = entry & 0x7FULL;
                covered = 1ULL << shifts[level];
                break;
            }
            table = entry & KSW_PLAN_FRAME;
            if (table == 0ULL) { return 1; }
        }
        /*
         * No "did the walk terminate" check here, because it always does: the
         * level-3 arm of the test above is unconditional, so the only ways out
         * of that loop are a leaf or one of the two returns inside it. A guard
         * here would be a branch no input can reach - the third one this header
         * grew and the third one a surviving mutation found.
         */
        if (first) {
            Scan->Shift = (unsigned int)(covered == (1ULL << KSW_PLAN_SHIFT_4K)
                ? KSW_PLAN_SHIFT_4K
                : (covered == (1ULL << KSW_PLAN_SHIFT_2M) ? KSW_PLAN_SHIFT_2M
                                                          : KSW_PLAN_SHIFT_1G));
            /*
             * Refuse an oversized region before reading any of it.
             *
             * The first leaf's granularity fixes how many leaves the region has,
             * so the cost is known now rather than after several hundred reads.
             * It also has to be known now for a different reason: every one of
             * these entries has to be re-read on each drift check, so a bound
             * that only stopped the initial scan would be measuring the wrong
             * thing. A 1-GiB region over ordinary pages is 262,144 of them.
             */
            if ((regionBytes >> Scan->Shift) >
                    (KSW_PLAN_U64)KSW_PLAN_MAX_SCAN_ENTRIES) {
                Scan->Uniform = 0;
                Scan->Complete = 0;
                return 1;
            }
            shared = leafBits;
            first = 0;
        } else if (leafBits != shared) {
            /* One disagreeing page is enough; the region cannot be one leaf. */
            Scan->LeafCount += 1ULL;
            Scan->SharedBits = shared;
            Scan->Uniform = 0;
            Scan->Complete = 1;
            return 1;
        }
        Scan->LeafCount += 1ULL;
        /* A leaf that already spans the rest of the region ends the walk. */
        if (covered >= regionBytes) { break; }
        /* Skip to the next leaf rather than re-walking every page under it. */
        offset += covered - (1ULL << KSW_PLAN_SHIFT_4K);
        /* Refuse rather than truncate when a region needs too many reads. */
        if (Scan->LeafCount > (KSW_PLAN_U64)KSW_PLAN_MAX_SCAN_ENTRIES) {
            Scan->SharedBits = shared;
            Scan->Uniform = 0;
            Scan->Complete = 0;
            return 1;
        }
    }
    /*
     * Reaching here means the region was covered and nothing disagreed.
     *
     * Not a conditional: the region is at least one page, so the loop runs at
     * least once, and that first iteration either returns early or clears
     * `first`. Writing `first ? 0 : 1` here would look like a guard while being
     * a branch no input can take -- and a mutation that replaced it with a bare
     * 1 survived the suite, which is how this was found.
     */
    Scan->SharedBits = shared;
    Scan->Uniform = 1;
    Scan->Complete = 1;
    return 1;
}

/* Answer whether one guest-physical address falls inside a published plan. */
static __inline int KswordHvmLeafPlanContains(const KSW_HVM_LEAF_PLAN* Plan,
    KSW_PLAN_U64 GuestPhysical)
{
    /* An unpublished or refused plan owns nothing at all. */
    if (Plan == 0 || Plan->Refusal != KSW_PLAN_OK || Plan->RegionBytes == 0ULL) {
        return 0;
    }
    /* Compare on the region, not on a page: the leaf owns every page in it. */
    return (GuestPhysical >= Plan->GuestBase &&
            GuestPhysical - Plan->GuestBase < Plan->RegionBytes) ? 1 : 0;
}

/* Frame that replaces one 4-KiB page of the region, for staging its contents. */
static __inline KSW_PLAN_U64 KswordHvmLeafPlanPageFrame(
    const KSW_HVM_LEAF_PLAN* Plan, KSW_PLAN_U64 PageIndex)
{
    /* Refuse an index outside the region rather than running past the backing. */
    if (Plan == 0 || Plan->Refusal != KSW_PLAN_OK || PageIndex >= Plan->PageCount) {
        return 0ULL;
    }
    /* Backing is contiguous, so the region offset is the backing offset. */
    return Plan->BackingBase + (PageIndex << KSW_PLAN_SHIFT_4K);
}

/* Frame the installed leaf carries. Always the region base: hardware supplies
   the offset from the guest-physical address it is translating, so a leaf that
   named an offset frame would serve the region shifted by that offset. */
static __inline KSW_PLAN_U64 KswordHvmLeafPlanLeafFrame(
    const KSW_HVM_LEAF_PLAN* Plan)
{
    /* Report nothing for a plan that was never published. */
    return (Plan == 0 || Plan->Refusal != KSW_PLAN_OK) ? 0ULL : Plan->BackingBase;
}

/* What re-reading one page of a scan-admitted region concluded. */
#define KSW_PLAN_RECHECK_AGREES 0U
#define KSW_PLAN_RECHECK_DRIFTED 1U
/* Nothing was proven: the read failed, or the table itself is malformed. The
   caller must leave the lease alone, because a failed read is not a change. */
#define KSW_PLAN_RECHECK_UNKNOWN 2U

/*
 * Re-read one page of a region the scanning rule admitted.
 *
 * Admission by scanning proves that every source leaf under the region agreed,
 * at one instant. The intermediate VMM keeps editing its own tables, so that
 * proof has to be revisited or the region serves on a condition nobody looks at
 * again. This answers the revisit for a single page, so the caller can spread
 * the cost of a region over many samples instead of re-reading every entry.
 *
 * It lives here, beside the scan whose conclusion it is rechecking, for two
 * reasons. The bits compared must be exactly the bits the scan compared --
 * access, memory type and ignore-PAT, never accessed or dirty -- and splitting
 * that across two files is how the two drift apart. And a decision that revokes
 * a published lease has to be testable without a machine.
 *
 * PageIndex wraps, so a caller can hold one ever-increasing cursor and let this
 * fold it into the region.
 */
static __inline unsigned int KswordHvmLeafPlanRecheckPage(
    KSW_PLAN_U64 EptPointer, const KSW_HVM_LEAF_PLAN* Plan,
    KSW_PLAN_U64 PageIndex, KSW_PLAN_U64 SharedBits,
    KSW_LEASE_READ Read, void* Context)
{
    /* Hardware walk order, including the two large-leaf levels. */
    static const unsigned int shifts[4] = {39U, 30U, 21U, 12U};
    KSW_PLAN_U64 guest;
    KSW_PLAN_U64 table;
    unsigned int level;

    /* An unpublished plan, an empty region or a missing reader proves nothing. */
    if (Read == 0 || Plan == 0 || Plan->Refusal != KSW_PLAN_OK ||
        Plan->PageCount == 0ULL) {
        return KSW_PLAN_RECHECK_UNKNOWN;
    }
    guest = Plan->GuestBase + ((PageIndex % Plan->PageCount) << KSW_PLAN_SHIFT_4K);
    table = EptPointer & KSW_PLAN_FRAME;
    if (table == 0ULL) { return KSW_PLAN_RECHECK_UNKNOWN; }
    for (level = 0U; level < 4U; ++level) {
        const KSW_PLAN_U64 address =
            table + (((guest >> shifts[level]) & 0x1FFULL) << 3);
        KSW_PLAN_U64 entry = 0ULL;

        /* A read that failed is not evidence of a change. */
        if (!Read(Context, address, &entry)) { return KSW_PLAN_RECHECK_UNKNOWN; }
        /* The region is no longer mapped here, which is a change. */
        if ((entry & 7ULL) == 0ULL) { return KSW_PLAN_RECHECK_DRIFTED; }
        if (level == 3U || ((level == 1U || level == 2U) &&
                            (entry & 0x80ULL) != 0ULL)) {
            /* Exactly the bits the admitting scan compared. */
            return (entry & 0x7FULL) == SharedBits
                ? KSW_PLAN_RECHECK_AGREES : KSW_PLAN_RECHECK_DRIFTED;
        }
        table = entry & KSW_PLAN_FRAME;
        /* A present entry naming frame zero is malformed, not a proven change. */
        if (table == 0ULL) { return KSW_PLAN_RECHECK_UNKNOWN; }
    }
    /*
     * Unreachable for the same reason the scan's equivalent is: the level-3 arm
     * above returns unconditionally, so the loop cannot run out. Returning
     * UNKNOWN rather than AGREES keeps the unreachable case on the side that
     * changes nothing.
     */
    return KSW_PLAN_RECHECK_UNKNOWN;
}
