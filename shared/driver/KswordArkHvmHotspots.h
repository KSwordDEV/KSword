/* Metrics v7: exact bounded exit accounting, independent from L2 flight history. */
#pragma once
#define KSW_HVM_HOT_MSR_SLOTS 16U
/* Each slot tracks one MSR identity without eviction or approximate replacement. */
typedef struct _KSWORD_HVM_HOT_MSR {
    unsigned long number, reserved;
    unsigned long long reads, writes, invalidDirection;
} KSWORD_HVM_HOT_MSR;
/* Index zero means L1 and index one means L2 at raw hardware VMEXIT. */
typedef struct _KSWORD_HVM_HOT_LEVEL {
    unsigned long long total, codes[256], npf, invalid, other;
    unsigned long long lastCode, lastRip, lastInfo1, lastInfo2;
    unsigned long long msrOverflow, invalidMsrDirection;
    unsigned long msrUsed, lastMsr;
    KSWORD_HVM_HOT_MSR msrs[KSW_HVM_HOT_MSR_SLOTS];
} KSWORD_HVM_HOT_LEVEL;
/* Valid applies only to this short writer transaction, never the general snapshot. */
typedef struct _KSWORD_HVM_HOTSPOTS {
    unsigned long valid, saturated;
    unsigned long long sequence, invalidLevel;
    KSWORD_HVM_HOT_LEVEL levels[2];
} KSWORD_HVM_HOTSPOTS;
