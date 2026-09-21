/* Virtual state MSRs never access root MSRs from C. */
#pragma once
#include "hvm_svm_nested_msr.h"
#include "hvm_svm_xstate.h"
/* An implementation restriction is distinct from an architectural #GP. */
#define KSW_NSVM_MSR_UNSUPPORTED 3U
/* Bind the visible context and immutable root save/cache contract for one exit. */
typedef struct _KSW_NSVM_REGISTER_IO {
    /* The currently executing L1 or L2 image supplies mode and privilege state. */
    KSW_SVM_VMCB* Current;
    /* SVM software ownership belongs to L1 even while L2 executes. */
    KSW_NSVM_MSRS* Svm;
    /* Guest XSS is shared across virtual VMRUN/VMEXIT, just like the real register. */
    KSW_SVM_U64* GuestXss;
    /* Fixed resource/feature contract captured on the owning CPU. */
    KSW_SVM_U64 PreparedXss, RootPat, EferAllowed;
    /* XSAVES availability, CET MSR availability and whether this is the L1 virtual VMM. */
    unsigned XsaveFeatures, CetPresent, ExposeSvm, Inner;
} KSW_NSVM_REGISTER_IO;
/* A successful access changes only owned software state; caller advances the checked NRIP. */
unsigned KswSvmNestedRegisterAccess(KSW_NSVM_REGISTER_IO* Io, unsigned Msr,
    unsigned Write, KSW_SVM_U64* Value);
