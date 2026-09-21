/* Virtual CPU capabilities are an implementation contract, not raw hardware advertisements. */
#pragma once
#include "hvm_svm_xstate.h"
/* Only implemented baseline nested features may be exposed by this revision. */
#define KSW_NSVM_CPUID_SVM_FEATURES 0xc9U
/* Callers choose exposure only after the full execution/interrupt path is available. */
typedef struct _KSW_NSVM_CPUID_POLICY {
    /* Prepared per-CPU XSTATE capacity and hardware component geometry. */
    const KSW_SVM_XSTATE_LAYOUT* Xstate;
    /* ExposeSvm is false in L2; the implementation does not offer a further nesting level. */
    unsigned ExposeSvm, AsidCount, SvmFeatures, PhysicalBits;
    /* The outer-state builder must support each advertised writable control feature. */
    KSW_SVM_U64 Cr4Supported;
    /* Raw topology/vendor leaves remain those of this virtual CPU's physical execution context. */
    KSW_SVM_CPUID_READ Read;
    void* Context;
} KSW_NSVM_CPUID_POLICY;
/* Return false for missing policy/evidence instead of fabricating a supported CPU. */
int KswSvmNestedCpuid(const KSW_NSVM_CPUID_POLICY* Policy, KSW_SVM_U64 GuestCr4,
    KSW_SVM_U64 GuestXcr0, KSW_SVM_U64 GuestXss, unsigned Leaf, unsigned Subleaf,
    unsigned Words[4]);
