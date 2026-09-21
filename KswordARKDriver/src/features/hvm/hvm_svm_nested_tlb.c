/* Processor-local virtual TLB invalidation; physical TLB_CONTROL=1 remains mandatory. */
#include "hvm_svm_nested_session.h"

/* Caller checks virtual SVME/CPL and validates NRIP before this completed instruction action. */
unsigned int KswSvmNestedSessionInvalidate(KSW_NSVM_SESSION* Session,
    KSW_NSVM_SESSION_IO* Io, KSW_SVM_U64 Linear, unsigned Asid)
{
    /* An active inner guest or retained VMCB writeback cannot be reset as an L1 instruction. */
    if (!Session || !Io || !Io->Shadow || !Io->Mmu || Session->Lease.Token ||
        Session->Phase != KSW_NSVM_SESSION_IDLE) { return KSW_NSVM_ACTION_UNSUPPORTED; }
    /* Invalidation counters cannot wrap into a prior diagnostic generation. */
    if (Session->Invalidations == ~0ULL) { return KSW_NSVM_ACTION_FAULT; }
    /* Discard the entire NPT02 cache instead of attempting an incomplete linear-address walk. */
    if (KswSvmNestedShadowReset(Io->Shadow) != KSW_NSHADOW_OK) {
        /* The current virtual CPU must not enter a root with uncertain cache ownership. */
        Session->Phase = KSW_NSVM_SESSION_FAULTED; return KSW_NSVM_ACTION_FAULT;
    }
    /* A future installation must carry the new epoch; old walk results become inadmissible. */
    Io->Mmu->Epoch = Io->Shadow->Epoch;
    /* Record exact virtual operands without using the guest ASID as a hardware ASID. */
    Session->LastInvalidationLinear = Linear; Session->LastInvalidationAsid = Asid;
    /* Both the cache and its public-to-root metadata now refer to one generation. */
    Session->LastInvalidationEpoch = Io->Shadow->Epoch; ++Session->Invalidations;
    /* Full hardware flush on the next VMRUN removes translations of discarded NPT02 leaves. */
    return KSW_NSVM_ACTION_RETURN;
}
