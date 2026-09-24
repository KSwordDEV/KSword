#pragma once

#include "KswordArkHvmIoctl.h"
#include "KswordArkHvmFlightRecorder.h"
#include "KswordArkHvmHotspots.h"
#include "KswordArkHvmNptCacheStats.h"

/* Independent versioning keeps existing HVM query clients ABI-compatible. */
#define KSWORD_ARK_HVM_METRICS_VERSION 9UL

/* General execution observations are independent of bounded-probe completion evidence. */
typedef struct _KSWORD_ARK_HVM_SVM_GENERAL_METRICS {
    /* Stable/even sequence validates this entire record; zero never means an executed entry. */
    unsigned long valid, initialized, enabled, phase, action, gif;
    /* These are retained software owners, not proof that a processor returned natively. */
    unsigned long pending, nmiCaptured, instructionStatus, instructionLength, operandAddressBits, shadowPages;
    /* Keep all counters, tokens and physical identities at their architectural width. */
    unsigned long long sequence, preparedEntries, hardwareExits, exitCode;
    unsigned long long leaseToken, operandHostPa, armedToken, retryToken;
    unsigned long long delivered, retried, cacheRecycles, virtualEfer, virtualHsave, guestXcr0, guestXss;
    KSWORD_HVM_NPT_CACHE_STATS nptCache;
    unsigned long long invlpgaCount, shadowEpoch;
} KSWORD_ARK_HVM_SVM_GENERAL_METRICS;

/* AMD diagnostics have their own full-width exit namespace and validity flag. */
typedef struct _KSWORD_ARK_HVM_SVM_METRICS {
    /* Stable processor identity, independent of APIC numbering. */
    unsigned short group;
    unsigned char number, reserved;
    /* A concurrently overwritten record has valid=0, never fabricated zeros. */
    unsigned long valid, sequence, stage, asid, generation;
    /* Raw architecture evidence; represent as strings in JSON. */
    unsigned long long exitCode, exitInfo1, exitInfo2, rip, rsp, cr3, nrip, event, tsc;
    /* Hardware resource identities and observed completed VMRUN/flush count. */
    unsigned long long vmcbPa, hsavePa, nptRootPa, tlbRequests;
    /* Ring wrapping is independent from coherent snapshot validity. */
    unsigned long ringPosition, ringOverwritten;
    /* Independently valid MSR evidence captured while preparing this CPU. */
    unsigned long msrValidMask, svmFeatures, asidCount, physicalBits;
    /* Originating per-CPU failure survives a successful rollback. */
    unsigned long failureStatus, failureStage;
    /* Valid only when the sequence is stable/even after complete native return. */
    unsigned long nestedProbeValid, nestedProbeSequence, nestedProbeStatus;
    /* These counters describe the bounded hardware probe, not general nested-VMM support. */
    unsigned long nestedProbeEntries, nestedProbeReflections, nestedProbeFaults;
    /* Preserve raw AMD exit and executed inner marker at full width. */
    unsigned long long nestedProbeExit, nestedProbeMarker;
    /* Values must not be interpreted when the corresponding valid bit is clear. */
    unsigned long long observedVmCr, observedEfer, observedHsave;
    /* Version five adds a separate seqlock snapshot; it never reuses the probe valid bit. */
    KSWORD_ARK_HVM_SVM_GENERAL_METRICS general;
    /* Version six retains the first terminal incident independently from recent exits. */
    KSWORD_HVM_FLIGHT_RECORDER flight;
    /* Version seven provides independently coherent L1/L2 exit and MSR counts. */
    KSWORD_HVM_HOTSPOTS hotspots;
} KSWORD_ARK_HVM_SVM_METRICS;
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_METRICS 0x916UL
#define IOCTL_KSWORD_ARK_HVM_METRICS \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_METRICS, METHOD_BUFFERED, FILE_READ_ACCESS)

/* CPU stamps are QPC readings, not TSC cycles or cross-machine UTC values. */
#define KSW_HVM_TIME_IPI_ENTER 0UL
#define KSW_HVM_TIME_IPI_LEAVE 1UL
#define KSW_HVM_TIME_VMCS_BEGIN 2UL
#define KSW_HVM_TIME_STATE_CAPTURED 3UL
#define KSW_HVM_TIME_VMCS_WRITTEN 4UL
#define KSW_HVM_TIME_ENTRY_BEFORE 5UL
#define KSW_HVM_TIME_ENTRY_AFTER 6UL
#define KSW_HVM_TIME_CPU_STAGES 7UL

/* Global intervals distinguish preparation from the disruptive rendezvous. */
#define KSW_HVM_TIME_RESOURCES_BEGIN 0UL
#define KSW_HVM_TIME_RESOURCES_END 1UL
#define KSW_HVM_TIME_EPT_BEGIN 2UL
#define KSW_HVM_TIME_EPT_END 3UL
#define KSW_HVM_TIME_RENDEZVOUS_BEGIN 4UL
#define KSW_HVM_TIME_RENDEZVOUS_END 5UL
#define KSW_HVM_TIME_GLOBAL_STAGES 6UL

typedef struct _KSWORD_ARK_HVM_METRICS_CPU {
    unsigned short group;
    unsigned char number;
    unsigned char reserved;
    unsigned long validMask;
    unsigned long long qpc[KSW_HVM_TIME_CPU_STAGES];
} KSWORD_ARK_HVM_METRICS_CPU;

/* Per-CPU observational counters reset when resident resources are recreated. */
typedef struct _KSWORD_ARK_HVM_SHADOW_METRICS {
    unsigned long index, pagesUsed, trackedPages, trackedOverflow;
    unsigned long fills, denied, exhausted, kept, dropped;
    unsigned long adPending, adPropagated, adOverflow, verifyMismatch;
} KSWORD_ARK_HVM_SHADOW_METRICS;

typedef struct _KSWORD_ARK_HVM_METRICS_REQUEST {
    unsigned long version, size, flags, reserved;
} KSWORD_ARK_HVM_METRICS_REQUEST;

typedef struct _KSWORD_ARK_HVM_METRICS_RESPONSE {
    unsigned long version, size;
    /* A zero value forbids treating the transition snapshot as complete. */
    unsigned long transitionCoherent, transitionSequence;
    unsigned long command, lastStatus, processorCount, globalValidMask;
    unsigned long long qpcFrequency, snapshotBeginQpc, snapshotEndQpc;
    unsigned long long commandBeginQpc, commandEndQpc;
    unsigned long long globalQpc[KSW_HVM_TIME_GLOBAL_STAGES];
    /* Attempt/result counters include every call through the INVEPT wrapper. */
    unsigned long long inveptAttempts, inveptSucceeded, inveptFailed;
    /* These ledgers cover nested-page rule objects and replacement pages only. */
    unsigned long long ruleAllocations, ruleFrees, replacementAllocations, replacementFrees;
    /* Endpoints bracket concurrent counters; they are not one atomic snapshot. */
    KSWORD_ARK_HVM_METRICS_CPU processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* Version 2 samples current shadow caches separately from transition stamps. */
    unsigned long shadowProcessorCount, reserved;
    KSWORD_ARK_HVM_SHADOW_METRICS shadowProcessors[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* V3 leaves every Intel metric in its original namespace. */
    unsigned long backend, svmProcessorCount;
    /* Latest coherent raw exit from each CPU; full history remains in its ring. */
    KSWORD_ARK_HVM_SVM_METRICS svmProcessors[KSWORD_ARK_HVM_MAX_PROCESSORS];
} KSWORD_ARK_HVM_METRICS_RESPONSE;
