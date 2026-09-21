/* Fixed-width, pointer-free diagnostic ABI; this header has no OS dependencies. */
#pragma once
#define KSW_HVM_FLIGHT_ROWS 32U
#define KSW_HVM_FLIGHT_PAGE_BYTES 4096U
#define KSW_HVM_FLIGHT_ENTRY 1U
#define KSW_HVM_FLIGHT_EXIT 2U
#define KSW_HVM_FLIGHT_SHUTDOWN 1U
#define KSW_HVM_FLIGHT_INVALID 2U
#define KSW_HVM_FLIGHT_INTERNAL 3U
typedef struct _KSWORD_HVM_FLIGHT_ROW {
    /* Chronological identity belongs to this prepared CPU resource lifetime. */
    unsigned long long ordinal, tsc, operandPa, leaseToken;
    /* Phase identifies L1 versus L2; action on EXIT is the pre-dispatch action. */
    unsigned int kind, phase, action, generation;
    /* Raw observed values; an ENTRY record's exit fields describe the previous exit. */
    unsigned long long exitCode, info1, info2, rip, rsp, cr2, cr3, event, exitIntInfo, nrip;
} KSWORD_HVM_FLIGHT_ROW;
typedef struct _KSWORD_HVM_FLIGHT_RECORDER {
    /* coherent is set only by the reader after verifying publication. */
    unsigned int coherent, latched, reason, captureTiming;
    /* Timing: 1=before exit dispatch, 2=after failed dispatch/entry; vmcb12Valid is independent. */
    unsigned int vmcb12Valid, count, next, reserved;
    /* Monotonic within one prepared allocation; records stop changing once latched. */
    unsigned long long total;
    /* Circular storage; export starts at (next + capacity - count) % capacity. */
    KSWORD_HVM_FLIGHT_ROW rows[KSW_HVM_FLIGHT_ROWS];
    /* Complete byte images include descriptor tables, CRs and all event/control fields. */
    unsigned char vmcb12[KSW_HVM_FLIGHT_PAGE_BYTES];
    unsigned char currentVmcb[KSW_HVM_FLIGHT_PAGE_BYTES];
} KSWORD_HVM_FLIGHT_RECORDER;
