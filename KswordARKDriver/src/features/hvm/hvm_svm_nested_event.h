/* Pure exception arbitration; physical interrupt acknowledgement is never inferred here. */
#pragma once
#include "hvm_svm_nested_state.h"
/* Actions are consumed before changing the current VMCB or clearing pending events. */
#define KSW_NSVM_EVENT_FAULT 0U
#define KSW_NSVM_EVENT_INJECT 1U
#define KSW_NSVM_EVENT_REFLECT 2U
#define KSW_NSVM_EVENT_SHUTDOWN 3U
/* A planned result contains all information needed to commit or retain an event. */
typedef struct _KSW_NSVM_EVENT_PLAN {
    /* Failure is the zero-initialized default; no guessed reentry is permitted. */
    unsigned Action, WriteCr2;
    /* Event to inject and an acknowledged asynchronous event that must not be discarded. */
    KSW_SVM_U64 Event, Deferred;
    /* Reflection metadata is synthesized without mutating the captured hardware record. */
    KSW_SVM_U64 ExitCode, Info1, Info2, Cr2;
} KSW_NSVM_EVENT_PLAN;
/* Classify a fault caused by L0 emulation or an L0-owned exception intercept.
   Inner is the original VMCB12 intercept policy; NULL means ordinary L1 delivery. */
unsigned KswSvmNestedExceptionPlan(const KSW_SVM_VMCB* Current,
    const KSW_SVM_VMCB* Inner, unsigned Vector, unsigned Error,
    KSW_SVM_U64 Address, KSW_NSVM_EVENT_PLAN* Plan);
/* Apply only the injection portion after a caller has retained Deferred, if nonzero. */
int KswSvmNestedExceptionInject(KSW_SVM_VMCB* Current, const KSW_NSVM_EVENT_PLAN* Plan,
    unsigned DeferredRetained);
