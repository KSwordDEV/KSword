/* APM 8.2.9 and 15.7.2: intercept ownership precedes exception aggregation. */
#include "hvm_svm_nested_event.h"

/* Error-code exceptions use their architecturally defined pushed error field. */
static unsigned KswNsvmErrorVector(unsigned Vector)
{
    /* Include CET, virtualization communication and security exception vectors. */
    return Vector == 8 || (Vector >= 10 && Vector <= 14) || Vector == 17 ||
        Vector == 21 || Vector == 29 || Vector == 30;
}

/* Contributory exceptions combine with prior contributory or page-fault delivery. */
static unsigned KswNsvmContributory(unsigned Vector)
{
    /* Page fault has its own asymmetric rule and is deliberately excluded here. */
    return Vector == 0 || (Vector >= 10 && Vector <= 13) || Vector == 21 || Vector == 29 || Vector == 30;
}

/* Preserve the raw guest RIP; fault/trap advance decisions belong to the instruction owner. */
unsigned KswSvmNestedExceptionPlan(const KSW_SVM_VMCB* Current,
    const KSW_SVM_VMCB* Inner, unsigned Vector, unsigned Error,
    KSW_SVM_U64 Address, KSW_NSVM_EVENT_PLAN* Plan)
{
    /* A complete result replaces stale state from a prior event. */
    const KSW_NSVM_EVENT_PLAN empty = {0};
    /* EXITINTINFO describes the interrupted delivery, not a queued EVENTINJ request. */
    KSW_SVM_U64 prior;
    /* Event type and vector are decoded only after checking validity. */
    unsigned oldVector, oldType;
    /* No output buffer means no action can be committed. */
    if (!Plan) { return KSW_NSVM_EVENT_FAULT; }
    /* Initialize a retained-fault default before reading any input. */
    *Plan = empty;
    /* Reserved/nonexception vectors cannot be synthesized as architectural exceptions. */
    if (!Current || Vector > 31 || Vector == 2 || Vector == 9 || Vector == 15 ||
        (Vector >= 22 && Vector <= 28)) { return Plan->Action; }
    /* Hardware checks the original exception intercept before combining prior delivery. */
    Plan->ExitCode = 0x40ULL + Vector;
    /* Non-error-code exception metadata must not leak arbitrary caller values. */
    Plan->Info1 = KswNsvmErrorVector(Vector) ? Error : 0;
    /* Only page-fault reflection has a faulting address operand. */
    Plan->Info2 = Vector == 14 ? Address : 0;
    /* An inner request receives the original exception, not a prematurely synthesized #DF. */
    if (Inner && KswSvmNestedInterceptRequested(Inner, Plan->ExitCode) == 1) {
        /* Caller performs architectural VMEXIT reflection while retaining EXITINTINFO. */
        Plan->Action = KSW_NSVM_EVENT_REFLECT; return Plan->Action;
    }
    /* Preserve the interrupted event before selecting a replacement injection. */
    prior = KswSvmRead64(Current, KSW_VMCB_EXITINTINFO);
    /* The valid bit is authoritative even if hardware left other bits stale. */
    if (prior & (1ULL << 31)) {
        /* Decode only the documented event format. */
        oldVector = (unsigned)(prior & 255ULL); oldType = (unsigned)((prior >> 8) & 7ULL);
        /* Invalid metadata must never be normalized into a different architectural event. */
        if ((prior & 0x7ffff000ULL) || (oldType != 0 && oldType != 2 && oldType != 3 && oldType != 4) ||
            (oldType == 3 && (oldVector == 2 || oldVector > 31))) { return Plan->Action; }
        /* Failure while delivering #DF shuts down only this virtual CPU. */
        if (oldType == 3 && oldVector == 8) {
            /* A virtual host may intercept shutdown rather than accepting a dead guest. */
            Plan->ExitCode = 0x7f; Plan->Info1 = Plan->Info2 = 0;
            /* Never execute physical HLT/reset/bugcheck as the emulation of a guest shutdown. */
            Plan->Action = Inner && KswSvmNestedInterceptRequested(Inner, 0x7f) == 1 ?
                KSW_NSVM_EVENT_REFLECT : KSW_NSVM_EVENT_SHUTDOWN;
            /* Current hardware image stays intact until its owner commits the chosen action. */
            return Plan->Action;
        }
        /* #PF followed by #PF/contributory, or contributory followed by contributory, produces #DF. */
        if (oldType == 3 && ((KswNsvmContributory(oldVector) && KswNsvmContributory(Vector)) ||
            (oldVector == 14 && (Vector == 14 || KswNsvmContributory(Vector))))) {
            /* The aggregate #DF always pushes error code zero. */
            Vector = 8; Error = 0; Plan->ExitCode = 0x48; Plan->Info1 = Plan->Info2 = 0;
            /* AMD separately checks the #DF intercept after combining the exceptions. */
            if (Inner && KswSvmNestedInterceptRequested(Inner, 0x48) == 1) {
                /* A new #DF intercept takes precedence over injecting the aggregate. */
                Plan->Action = KSW_NSVM_EVENT_REFLECT; return Plan->Action;
            }
        }
        /* Hardware already acknowledged an interrupted external interrupt/NMI delivery. */
        if (oldType == 0 || oldType == 2) { Plan->Deferred = prior & 0xffffffffULL; }
        /* Software INT/faults restart through guest architectural fault handling, not a second queued IRQ. */
    }
    /* CR2 is changed only when actually injecting the page fault, never for another exception. */
    Plan->WriteCr2 = Vector == 14; Plan->Cr2 = Address;
    /* Construct the event from checked vector/type/valid bits rather than caller-supplied flags. */
    Plan->Event = (1ULL << 31) | (3ULL << 8) | Vector;
    /* Error-valid and its payload travel together; #DF's payload is forced to zero above. */
    if (KswNsvmErrorVector(Vector)) { Plan->Event |= (1ULL << 11) | ((KSW_SVM_U64)Error << 32); }
    /* The plan does not modify guest state or consume the deferred interrupt. */
    Plan->Action = KSW_NSVM_EVENT_INJECT;
    /* Caller may commit only after preserving any already-acknowledged prior event. */
    return Plan->Action;
}

/* No RIP advance is performed for a fault, including a synthesized #DF. */
int KswSvmNestedExceptionInject(KSW_SVM_VMCB* Current, const KSW_NSVM_EVENT_PLAN* Plan,
    unsigned DeferredRetained)
{
    /* Queue overflow must retain the original image and fail, never lose an acknowledged IRQ. */
    if (!Current || !Plan || Plan->Action != KSW_NSVM_EVENT_INJECT ||
        (Plan->Deferred && !DeferredRetained)) { return 0; }
    /* CR2 belongs to the fault being delivered, not to the host/root address space. */
    if (Plan->WriteCr2) { KswSvmWrite64(Current, KSW_VMCB_CR2, Plan->Cr2); }
    /* Replace a stale EVENTINJ only after the full aggregation/ownership decision. */
    KswSvmWrite64(Current, KSW_VMCB_EVENT, Plan->Event);
    /* Physical acknowledgement and asynchronous scheduling remain separate operations. */
    return 1;
}
