/* XSETBV admission never expands the nonpaged save area after prepare. */
#include "hvm_svm_xstate.h"

/* Reject combinations which hardware would fault on before assembly executes XSETBV. */
int KswSvmXcr0MaskValid(KSW_SVM_U64 Mask)
{
    /* x87 must stay enabled; unknown components need their own dependencies and storage. */
    if (!(Mask & 1ULL) || (Mask & ~KSW_SVM_XCR0_IMPLEMENTED)) { return 0; }
    /* AVX state requires SSE state. */
    if ((Mask & 4ULL) && !(Mask & 2ULL)) { return 0; }
    /* Opmask, ZMM_Hi256 and Hi16_ZMM form one group and require AVX/SSE. */
    if ((Mask & 0xe0ULL) && ((Mask & 0xe0ULL) != 0xe0ULL || (Mask & 6ULL) != 6ULL)) { return 0; }
    /* The supported subset is now safe to use with a preallocated fixed save mask. */
    return 1;
}

/* Caller preserves the faulting RIP for any nonzero result. */
unsigned KswSvmXcr0Write(KSW_SVM_U64 Prepared, KSW_SVM_U64 Cr4, unsigned Cpl,
    unsigned Index, KSW_SVM_U64 Value, KSW_SVM_U64* Current)
{
    /* Invalid monitor policy is not an architectural guest fault. */
    if (!Current || !KswSvmXcr0MaskValid(Prepared)) { return KSW_SVM_XCR_UNSUPPORTED; }
    /* Without CR4.OSXSAVE the instruction is unavailable even at CPL0. */
    if (!(Cr4 & (1ULL << 18))) { return KSW_SVM_XCR_UD; }
    /* Only ring zero may write the only implemented extended control register. */
    if (Cpl || Index) { return KSW_SVM_XCR_GP; }
    /* Prepared components are the storage ceiling, not all host CPUID-supported components. */
    if ((Value & ~Prepared) || !KswSvmXcr0MaskValid(Value)) { return KSW_SVM_XCR_GP; }
    /* Hardware switching occurs in assembly only after root C has finished. */
    *Current = Value;
    /* No allocation, CPUID, MSR write or SIMD state mutation occurs here. */
    return KSW_SVM_XCR_OK;
}
