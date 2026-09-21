/* Allocation-bounded XCR0 policy; independent of Windows and privileged instructions. */
#pragma once
#include "hvm_svm_arch.h"
/* This implementation handles x87/SSE/AVX and the complete AVX-512 component group. */
#define KSW_SVM_XCR0_IMPLEMENTED 0xe7ULL
/* Success and architectural exception vectors are distinct from unsupported policy. */
#define KSW_SVM_XCR_OK 0U
#define KSW_SVM_XCR_UD 6U
#define KSW_SVM_XCR_GP 13U
#define KSW_SVM_XCR_UNSUPPORTED 256U
/* A prepared mask must satisfy dependencies and must not require unknown state components. */
int KswSvmXcr0MaskValid(KSW_SVM_U64 Mask);
/* Commit software state only after checking the guest instruction and allocation contract. */
unsigned KswSvmXcr0Write(KSW_SVM_U64 Prepared, KSW_SVM_U64 Cr4, unsigned Cpl,
    unsigned Index, KSW_SVM_U64 Value, KSW_SVM_U64* Current);
/* Supervisor save enablement is separate from whether the CET feature itself is enabled. */
unsigned KswSvmXssWrite(KSW_SVM_U64 Prepared, unsigned Features, unsigned Cpl,
    KSW_SVM_U64 Value, KSW_SVM_U64* Current);
/* Capture CPUID geometry once while pinned; root CPUID.D sizes otherwise reflect root masks. */
typedef void (*KSW_SVM_CPUID_READ)(void* Context, unsigned Leaf, unsigned Subleaf, unsigned Words[4]);
/* Preserve the hardware component ABI while restricting which components the VMM exposes. */
typedef struct _KSW_SVM_XSTATE_LAYOUT {
    /* Virtual support never exceeds the already allocated host component set. */
    KSW_SVM_U64 User, Supervisor;
    /* Physical XSAVE family capabilities; no synthetic instruction support. */
    unsigned Features;
    /* Cached CPUID.D component records; 0/1 are synthesized from current guest masks. */
    unsigned Component[64][4];
    /* Publication occurs only after sizes, dependencies and ownership were checked. */
    unsigned Ready;
} KSW_SVM_XSTATE_LAYOUT;
/* Fail closed on malformed geometry or insufficient preallocated area. */
int KswSvmXstateLayoutCapture(KSW_SVM_XSTATE_LAYOUT* Layout, KSW_SVM_U64 User,
    KSW_SVM_U64 Supervisor, unsigned Capacity, unsigned Compacted,
    KSW_SVM_CPUID_READ Read, void* Context);
/* Produce CPUID.D using guest enablement without modifying root XCR0 or XSS. */
int KswSvmXstateCpuid(const KSW_SVM_XSTATE_LAYOUT* Layout, KSW_SVM_U64 Xcr0,
    KSW_SVM_U64 Xss, unsigned Subleaf, unsigned Words[4]);
