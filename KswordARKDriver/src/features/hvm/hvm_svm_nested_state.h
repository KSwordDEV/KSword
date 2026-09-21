/* Architectural state subsets for software SVM nesting, APM 15.5.1/15.5.2/15.6. */
#pragma once
#include "hvm_svm_arch.h"

/* VMLOAD/VMSAVE state is separate from the state switched by VMRUN/VMEXIT. */
void KswSvmNestedCopyVmload(KSW_SVM_VMCB* Destination, const KSW_SVM_VMCB* Source);
/* Baseline VMRUN state only; the entry owner separately validates all controls. */
void KswSvmNestedCopyVmrun(KSW_SVM_VMCB* Destination, const KSW_SVM_VMCB* Source,
    unsigned int NestedPaging);
/* Save a hardware exit to VMCB12 without leaking host addresses or changing controls. */
void KswSvmNestedReflectExit(KSW_SVM_VMCB* Vmcb12, const KSW_SVM_VMCB* Vmcb02,
    unsigned int NestedPaging);
/* Raw intercept classification precedes MSRPM/IOPM fine-grained checks by the caller. */
unsigned int KswSvmNestedInterceptRequested(const KSW_SVM_VMCB* Vmcb12,
    KSW_SVM_U64 ExitCode);
/* Unknown exit ranges must not silently become handled/reenter decisions. */
#define KSW_NSVM_INTERCEPT_UNKNOWN 2U

/* Resume an L0-handled exit with exactly the interrupted event, if any.
   This is event reinjection only, not aggregation of a newly raised exception. */
#define KSW_NSVM_EVENT_OK 0U
#define KSW_NSVM_EVENT_INVALID 1U
#define KSW_NSVM_EVENT_NRIP_REQUIRED 2U
unsigned int KswSvmNestedResumeEvent(KSW_SVM_VMCB* Current);
