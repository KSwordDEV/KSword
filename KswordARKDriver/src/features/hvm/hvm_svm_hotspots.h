/* Single-CPU raw exit accounting: no allocation, locks, guest writes or instruction execution. */
#pragma once
#include "../../../../shared/driver/KswordArkHvmHotspots.h"

/* Saturation must not turn a large counter into misleading low activity. */
static __inline void KswSvmHotIncrement(KSWORD_HVM_HOTSPOTS* Hot, unsigned long long* Value)
{
    /* Published saturation makes future deltas explicitly unusable. */
    if (*Value == ~0ULL) { Hot->saturated = 1; }
    /* Only the owning CPU writes the storage under the platform sequence. */
    else { ++*Value; }
}

/* Level and RCX must be captured before instruction emulation or L2 reflection. */
static __inline void KswSvmHotObserve(KSWORD_HVM_HOTSPOTS* Hot, unsigned int Level,
    unsigned long long Code, unsigned long long Rip, unsigned long long Info1,
    unsigned long long Info2, unsigned long Msr)
{
    /* A missing monitor allocation has nothing to publish. */
    KSWORD_HVM_HOT_LEVEL* row;
    /* Searching never exceeds the fixed set of first-seen MSR identities. */
    unsigned int slot;
    /* Invalid session phases must not be silently charged to L1. */
    if (Level > 1U) { KswSvmHotIncrement(Hot, &Hot->invalidLevel); return; }
    /* Phase is stable because the owning CPU is in its VMEXIT handler. */
    row = &Hot->levels[Level];
    /* Every observed exit contributes to exactly one level and reason bucket. */
    KswSvmHotIncrement(Hot, &row->total);
    /* Preserve sparse AMD values without using them as unbounded array indices. */
    if (Code < 256ULL) { KswSvmHotIncrement(Hot, &row->codes[(unsigned int)Code]); }
    /* NPF is outside the dense architectural legacy exit range. */
    else if (Code == 0x400ULL) { KswSvmHotIncrement(Hot, &row->npf); }
    /* INVALID is an all-ones unsigned 64-bit value. */
    else if (Code == ~0ULL) { KswSvmHotIncrement(Hot, &row->invalid); }
    /* Future sparse extensions remain visible without misclassification. */
    else { KswSvmHotIncrement(Hot, &row->other); }
    /* Last operands retain their raw hardware meaning. */
    row->lastCode = Code; row->lastRip = Rip; row->lastInfo1 = Info1; row->lastInfo2 = Info2;
    /* Only an actual MSR exit supplies a meaningful MSR number in RCX. */
    if (Code != 0x7cULL) { return; }
    /* The architecture selects the MSR using ECX, not its upper half. */
    row->lastMsr = Msr;
    /* Preserve malformed direction evidence separately from reads and writes. */
    if (Info1 > 1ULL) { KswSvmHotIncrement(Hot, &row->invalidMsrDirection); }
    /* Never evict counters: an observed identity retains exact accounting. */
    for (slot = 0; slot < row->msrUsed; ++slot) {
        /* Both RDMSR and WRMSR use this same identity slot. */
        if (row->msrs[slot].number == Msr) { break; }
    }
    /* A full table retains its first identities and counts all omitted exits. */
    if (slot == KSW_HVM_HOT_MSR_SLOTS) { KswSvmHotIncrement(Hot, &row->msrOverflow); return; }
    /* Only a previously unused zero-initialized slot acquires a new identity. */
    if (slot == row->msrUsed) { row->msrs[slot].number = Msr; ++row->msrUsed; }
    /* Invalid direction never increments either architectural direction bucket. */
    if (Info1 > 1ULL) { KswSvmHotIncrement(Hot, &row->msrs[slot].invalidDirection); }
    /* Writes have EXITINFO1 equal to one. */
    else if (Info1) { KswSvmHotIncrement(Hot, &row->msrs[slot].writes); }
    /* Reads have EXITINFO1 equal to zero. */
    else { KswSvmHotIncrement(Hot, &row->msrs[slot].reads); }
}
