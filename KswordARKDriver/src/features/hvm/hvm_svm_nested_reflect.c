/* Instruction and physical exits use one event-aware architectural return transaction. */
#include "hvm_svm_nested_execute.h"

/* No event acknowledgement changes owners before all VMCB outputs were committed. */
unsigned KswSvmNestedReturnL1(KSW_NSVM_EXECUTION* Execution)
{
    /* Retain exact values before the session replaces Current with the saved L1 continuation. */
    KSW_SVM_U64 transferToken = 0, transferEvent, owner;
    /* Reject an absent/already completed transaction before deriving a VMCB owner. */
    if (!Execution || !Execution->Current || !Execution->Session || !Execution->Io ||
        Execution->Session->Phase != KSW_NSVM_SESSION_L2 || !Execution->Session->Lease.Token ||
        Execution->Session->OperandHostPa == ~0ULL) { return KSW_NSVM_EXEC_FAULT; }
    /* This namespace is based on translated VMCB identity, not its ASID or virtual address. */
    owner = Execution->Session->OperandHostPa + 1ULL;
    /* Raw interrupted-delivery state was captured by real hardware before dispatch. */
    transferEvent = KswSvmRead64(Execution->Current, KSW_VMCB_EXITINTINFO);
    /* A queued but never injected event cannot be smuggled into architectural EXITINTINFO. */
    if (!KswSvmNestedPendingPrepareTransfer(&Execution->Pending, owner,
        Execution->RetryEventToken, transferEvent, &transferToken)) { return KSW_NSVM_EXEC_EVENT_BLOCKED; }
    /* Partial output retains the live lease and acknowledgement; it is never a native return. */
    if (KswSvmNestedSessionReflect(Execution->Session, Execution->Io, Execution->Current) != KSW_NSVM_ACTION_RETURN) {
        /* The caller retains the entire resource graph for diagnosis. */
        return KSW_NSVM_EXEC_FAULT;
    }
    /* Only the complete writeback authorizes the exact hardware-observed event's transfer. */
    if (transferToken && !KswSvmNestedPendingTransfer(&Execution->Pending, transferToken, transferEvent)) {
        /* A violated single-writer invariant after writeback still cannot authorize reentry. */
        return KSW_NSVM_EXEC_FAULT;
    }
    /* No stale retry identity may refer to an acknowledgement now owned by L1. */
    Execution->RetryEventToken = 0;
    /* Virtual VMEXIT closes GIF before the physical coordinator prepares L1 execution. */
    Execution->Gif = Execution->GifRequested = 0;
    /* This returns to the real L1 VMRUN continuation, not the original Windows startup snapshot. */
    return KSW_NSVM_EXEC_RESUME;
}
