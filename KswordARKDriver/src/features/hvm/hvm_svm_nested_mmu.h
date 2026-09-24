/* Bounded software composition of NPT12 and NPT01; no Windows or hardware calls. */
#pragma once
#include "hvm_svm_nested_npt.h"

/* Fault ownership is separate from the architectural NPF error bits. */
#define KSW_NMMU_INNER 1U
/* NPT01 rejected an access to an NPT12 table, not to the final data page. */
#define KSW_NMMU_OUTER_TABLE 2U
/* NPT01 rejected the translated final data page. */
#define KSW_NMMU_OUTER_DATA 3U
/* Physical window / RAM admission failure must not be reflected as a guest NPF. */
#define KSW_NMMU_PHYSICAL 4U
/* Preserve the original hardware NPF context when reflecting an NPT12 fault. */
#define KSW_NMMU_FINAL (1ULL << 32)
/* A guest page-table access is always a nested-level user write. */
#define KSW_NMMU_TABLE (1ULL << 33)

/* Captured by the future entry owner; immutable throughout one resolution. */
typedef struct _KSW_NMMU_CONFIG {
    /* Inner addresses refer to L1 physical memory; outer addresses are host physical. */
    KSW_SVM_U64 InnerRoot, OuterRoot;
    /* These PATs belong to the two page-table owners, not to the final L2 guest. */
    KSW_SVM_U64 InnerPat, OuterPat, HardwarePat;
    /* Stamp each result; hardware publication must hold the same invalidation epoch. */
    KSW_SVM_U64 Epoch;
    /* The current backend admits only four-level, at most 48-bit paging. */
    unsigned int InnerBits, OuterBits, InnerPage1Gb, OuterPage1Gb;
    /* NX reserved-bit checks follow the corresponding page-table owner's EFER. */
    unsigned int InnerNx, OuterNx;
    /* Mapping/permissions of NPT01 must remain fixed throughout this resolve; A/D may change. */
    unsigned int OuterImmutable;
} KSW_NMMU_CONFIG;

/* Callbacks operate on host physical RAM, validate ownership, and never allocate. */
typedef struct _KSW_NMMU_IO {
    /* Every successful read returns one aligned, complete source word. */
    KSW_NNPT_READ Read;
    /* The update must be an atomic compare-exchange, not a read followed by a write. */
    KSW_NNPT_COMPARE_OR CompareOr;
    /* Per-CPU physical window and immutable RAM inventory are supplied by the owner. */
    void* Context;
} KSW_NMMU_IO;

/* Preserve both walks for diagnostics; no pointer to a temporary mapping escapes. */
typedef struct _KSW_NMMU_RESULT {
    /* Zero unless all translations, cache checks and A/D commits succeeded. */
    KSW_SVM_U64 Leaf;
    /* Original input and epoch allow a caller to reject unrelated/stale results. */
    KSW_SVM_U64 Gpa, Epoch;
    /* Only Inner faults are candidates for reflection into the inner VMM. */
    KSW_SVM_U64 FaultAddress, FaultInfo;
    /* Raw software outcome, ownership, and successful physical read count. */
    unsigned int Status, FaultOwner, Reads;
    /* Inner slots are guest physical; outer slots are host physical. */
    KSW_NNPT_WALK Inner, Outer;
} KSW_NMMU_RESULT;

/* Produces one 4-KiB leaf; does not install it or claim a hardware TLB flush. */
unsigned int KswSvmNestedMmuResolve(const KSW_NMMU_CONFIG* Config,
    const KSW_NMMU_IO* Io, KSW_SVM_U64 Gpa, unsigned int Access,
    KSW_SVM_U64 FaultContext, KSW_NMMU_RESULT* Result);
