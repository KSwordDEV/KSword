/* Driver-owned, explicitly requested nested-SVM hardware probe resources. */
#pragma once
#if defined(KSW_SVM_NESTED_HOST_TEST)
/* Test builds execute the same dispatcher with explicit host-only platform substitutes. */
#include "svm_nested_probe_fixture.h"
#else
#include "hvm_svm.h"
#include "hvm_phys_window.h"
#endif
#include "hvm_svm_nested_shadow.h"
#include "hvm_svm_nested_state.h"
#include "hvm_svm_nested_msr.h"
#include "hvm_svm_nested_permissions.h"
#include "hvm_svm_nested_operand.h"
#include "hvm_svm_nested_entry.h"
#include "hvm_svm_nested_writeback.h"
#include "hvm_svm_nested_session.h"
#include "hvm_svm_nested_route.h"
#include "hvm_svm_nested_register.h"
#include "hvm_svm_xstate.h"
/* Enough sparse tables for the bounded probe; exhaustion returns a failed test. */
#define KSW_NSVM_PROBE_PAGES 64U
/* Private markers distinguish the inner exit from the final outer continuation. */
#define KSW_NSVM_INNER_MARKER 0x4b534e31U
/* The final CPUID may succeed only after virtual ownership was relinquished. */
#define KSW_NSVM_DONE_MARKER 0x4b534e32U
/* Private VMMCALL opens the known probe before any nonvolatile register changes. */
#define KSW_NSVM_BEGIN 3ULL
/* Per-CPU state is retained until native return and common release. */
typedef struct _KSW_SVM_NESTED {
    /* Saved initial Windows image supports bounded-test abort, never arbitrary VM abort. */
    KSW_SVM_VMCB Original;
    /* General VMRUN transaction is independent of the bounded test's original snapshot. */
    KSW_NSVM_SESSION Session;
    /* Borrowed shared lifetime ledger; never freed independently of the backend. */
    KSW_NSVM_OWNER_TABLE* Owners;
    /* Frozen Windows group:number identity for this CPU's acquisition evidence. */
    ULONG CpuIdentity;
    /* Last permission/VMCB capture outcome, retained independently of inner NPFs. */
    KSW_NSVM_OPERAND_RESULT LastOperand;
    /* Admission errors retain architecture-vs-implementation classification. */
    KSW_NSVM_ENTRY_RESULT LastEntry;
    /* Routing precedes emulation so shared intercept ownership is never lost. */
    KSW_NSVM_EXIT_ROUTE LastRoute;
    /* One contiguous allocation: merged MSRPM followed by merged IOPM. */
    PUCHAR MergedMaps;
    /* Derived at PASSIVE_LEVEL and checked against MAXPHYADDR before use. */
    ULONGLONG MergedMapsPa;
    /* Preserve nonvolatile caller state even if the controlled probe aborts. */
    ULONGLONG OriginalGpr[16];
    /* Two contiguous pages: VMCB12 operand followed by virtual HSAVE. */
    KSW_SVM_VMCB* Operand;
    /* Operand identity is resolved before any SVM instruction executes. */
    ULONGLONG OperandPa;
    /* Private nonpaged stack for the bounded inner guest. */
    PVOID Stack;
    /* Preallocated translation cache and ownership descriptors. */
    KSW_NSHADOW Shadow;
    /* All pool pages are tracked even when preparation fails partway. */
    KSW_NSHADOW_PAGE Pages[KSW_NSVM_PROBE_PAGES];
    /* Prepared physical window, never shared across CPUs. */
    KSW_HVM_PHYS_WINDOW* Window;
    /* Runtime identity map/RAM inventory lifetime is held by the SVM backend. */
    KSW_NPT* Outer;
    /* Translation policy remains fixed throughout one probe. */
    KSW_NMMU_CONFIG Config;
    /* Last resolution is retained for KD diagnostics, including failed NPF ownership. */
    KSW_NMMU_RESULT LastTranslation;
    /* Virtual registers do not grant access to the real host's SVM ownership. */
    KSW_NSVM_MSRS Msrs;
    /* Probe entry/reflection counters are evidence, not general nested support flags. */
    ULONG Begun, RunningL2, Entries, Reflections, Faults, VirtualGif;
    /* A bounded probe must reduce and restore XCR0 across real exits before claiming success. */
    ULONG Xcr0Writes;
    /* Odd during a probe; even only after verified native EFER/HSAVE restoration. */
    volatile LONG Sequence;
    /* Published together with the completed sequence, including failed probes. */
    NTSTATUS CompletionStatus;
    /* Precise raw inner exit and marker before reflection changes the current image. */
    ULONGLONG LastExit, LastMarker;
} KSW_SVM_NESTED;
/* Resource acquisition is PASSIVE_LEVEL only and uses the backend release ledger. */
NTSTATUS KswordSvmNestedPrepare(KSW_SVM_CPU* Cpu, ULONG Index);
/* Never call until common ownership checks prove the processor is native. */
VOID KswordSvmNestedRelease(KSW_SVM_CPU* Cpu);
/* Set up the driver-owned operand after the regular VMCB builder completed. */
NTSTATUS KswordSvmNestedBuildProbe(KSW_SVM_CPU* Cpu);
/* Probe-only dispatcher: zero resumes a VMCB; one restores the original Windows caller. */
ULONG KswordSvmNestedProbeExit(KSW_SVM_CPU* Cpu);
/* Physical RAM callbacks for production MMU resolution, not the host-test adapter. */
int KswordSvmNestedRead(void* Context, KSW_SVM_U64 Address, KSW_SVM_U64* Value);
/* Atomic source A/D commit through the same per-processor physical window. */
int KswordSvmNestedCompareOr(void* Context, KSW_SVM_U64 Address, KSW_SVM_U64 Expected, KSW_SVM_U64 Bits);
/* Validate the complete word/page against the retained outer RAM inventory. */
BOOLEAN KswordSvmNestedRamRange(const KSW_SVM_NESTED* Nested, ULONGLONG Address, ULONG Bytes);
/* Architectural output fields only; partial progress is never reported as success. */
int KswordSvmNestedCommitVmcb(void* Context, KSW_SVM_U64 HostPa,
    const KSW_SVM_VMCB* Image, unsigned int Operation, unsigned int NestedPaging,
    unsigned int* WordsWritten);
/* Assembly markers are also used to validate the exact probe continuation. */
VOID KswordSvmAsmNestedProbe(VOID);
/* Inner code performs a unique intercepted CPUID; it never runs an OS. */
VOID KswordSvmAsmNestedPayload(VOID);
