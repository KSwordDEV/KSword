/* General translated VMLOAD/VMSAVE transaction; no fixed probe operand or raw guest mapping. */
#include "hvm_svm_nested_session.h"

/* An unsupported address form is kept separate from an architectural virtual instruction fault. */
static unsigned KswNsvmTransferFault(KSW_NSVM_SESSION* Session)
{
    /* Preserve any acquired lease and partial writeback diagnostics. */
    Session->Phase = KSW_NSVM_SESSION_FAULTED;
    /* The caller must not retry a partially completed VMSAVE as a new instruction. */
    return KSW_NSVM_ACTION_FAULT;
}

/* Guest operands are snapshots; holding a lease never permits raw physical pointer dereferences. */
unsigned int KswSvmNestedSessionTransfer(KSW_NSVM_SESSION* Session,
    const KSW_NSVM_SESSION_IO* Io, KSW_SVM_VMCB* Current, KSW_SVM_U64 OperandPa,
    unsigned Save)
{
    /* The same physical identity must survive both capture passes and writeback. */
    unsigned status;
    KSW_SVM_U64 cacheToken = 0;
    /* This storage cannot be borrowed from a running or fault-retained VMRUN transaction. */
    if (!Session || !Io || !Io->Owners || !Io->Commit || !Current || Save > 1 ||
        Session->Phase != KSW_NSVM_SESSION_IDLE || Session->Lease.Token) { return KSW_NSVM_ACTION_UNSUPPORTED; }
    /* Never mutate state and then discover that the virtual instruction has no valid continuation. */
    if (!KswSvmNextRipValid(KswSvmRead64(Current, KSW_VMCB_RIP), KswSvmRead64(Current, KSW_VMCB_NRIP))) {
        /* The original image remains intact for diagnosis. */
        return KswNsvmTransferFault(Session);
    }
    /* Resolve identity before leasing; defer the expensive snapshot until ownership is held. */
    status = KswSvmNestedResolveOperand(&Io->Operand, OperandPa, &Session->OperandResult);
    /* A physical access failure is not the fabricated success of a zero-filled operand. */
    if (status != KSW_NNPT_OK) { return KswNsvmTransferFault(Session); }
    /* Retain identities before a writeback callback repurposes its diagnostic output. */
    Session->OperandPa = OperandPa; Session->OperandHostPa = Session->OperandResult.HostPa;
    /* VMSAVE must not overwrite a VMCB currently executing on another processor. */
    Session->OwnerStatus = KswSvmNestedOwnerAcquire(Io->Owners, Session->OperandHostPa,
        Io->CpuIdentity, &Session->Lease);
    /* Busy/exhaustion is an implementation admission result, not an invented #GP. */
    if (Session->OwnerStatus != KSW_NSVM_LEASE_OK) { return KSW_NSVM_ACTION_UNSUPPORTED; }
    if (Session->Lease.PreviousToken) {
        KswHvmNptCacheCount(&Session->CacheStats, &Session->CacheStats.ownerTransitions);
        if (Session->Lease.PreviousCpuIdentity != Io->CpuIdentity) {
            KswHvmNptCacheCount(&Session->CacheStats, &Session->CacheStats.ownerCpuTransitions);
        }
    }
    /* VMLOAD needs a post-lease snapshot; VMSAVE's writeback re-walks NPT01 with write access. */
    if (!Save) {
        status = KswSvmNestedReadOperandPage(&Io->Operand, OperandPa,
            (unsigned char*)&Session->Vmcb12, &Session->OperandResult);
        /* A remap cannot change the ownership identity after acquisition. */
        if (status != KSW_NNPT_OK || Session->OperandResult.HostPa != Session->Lease.HostPa) {
            /* The lease is released only by a later, independently proven native abort. */
            return KswNsvmTransferFault(Session);
        }
    } else {
        /* Merge just VMLOAD-managed state into a private snapshot for whitelist writeback. */
        KswSvmNestedCopyVmload(&Session->Vmcb12, Current);
        /* The generic writer keeps controls, other state and reserved bits untouched. */
        status = KswSvmNestedWriteback(&Io->Operand, OperandPa, Session->OperandHostPa,
            &Session->Vmcb12, KSW_NSVM_SAVE_VMSAVE, 1, Io->Commit, &Session->OperandResult);
        /* A partial output retains the same lease and its written-word progress. */
        if (status != KSW_NNPT_OK) { return KswNsvmTransferFault(Session); }
    }
    if (Session->CacheValid && Session->CacheKey[0] == Session->Lease.HostPa &&
        Session->CacheOwnerToken == Session->Lease.PreviousToken) {
        cacheToken = Session->Lease.Token;
    }
    /* End physical operand ownership only after the read/output transaction completed. */
    if (!KswSvmNestedOwnerRelease(Io->Owners, &Session->Lease)) { return KswNsvmTransferFault(Session); }
    if (cacheToken) { Session->CacheOwnerToken = cacheToken; }
    /* The owned snapshot remains stable even when L1 changes the original page afterward. */
    if (!Save) { KswSvmNestedCopyVmload(Current, &Session->Vmcb12); }
    /* Caller completes this virtual instruction with its already validated hardware NRIP. */
    return KSW_NSVM_ACTION_RETURN;
}
