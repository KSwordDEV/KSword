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
