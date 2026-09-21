/* APM 8.1.4, 13.1.4 and 15.8: interception precedes IRET exceptions; completion releases NMI. */
#include "hvm_svm_nested_iret.h"
/* VMCB exception bitmap precedes the first miscellaneous intercept dword. */
#define KSW_NSVM_IRET_EXCEPTIONS 0x008U
#define KSW_NSVM_IRET_TF (1ULL << 8)
#define KSW_NSVM_IRET_BS (1ULL << 14)

/* The caller has already restored original intercept ownership and retained all event tokens. */
int KswSvmNestedIretRequest(KSW_NSVM_IRET* Step)
{
    /* An unfinished observation cannot be overwritten by another intercepted instruction. */
    if (!Step || Step->Requested || Step->Applied) { return 0; }
    /* The retry budget belongs to this IRET, not the lifetime of the CPU. */
    Step->Requested = 1; Step->Attempts = Step->Completed = 0; return 1;
}

/* Hardware executes the original instruction with its original stack and descriptor semantics. */
int KswSvmNestedIretArm(KSW_SVM_VMCB* Current, KSW_NSVM_IRET* Step)
{
    /* No speculative injection may change RIP before the observed instruction runs. */
    if (!Current || !Step || !Step->Requested || Step->Applied || Step->Attempts >= 64 ||
        Step->Entries == ~0ULL || (KswSvmRead64(Current, KSW_VMCB_EVENT) & (1ULL << 31))) { return 0; }
    /* Save the exact current retry image rather than the state of an earlier attempt. */
    Step->Rip = KswSvmRead64(Current, KSW_VMCB_RIP); Step->Flags = KswSvmRead64(Current, KSW_VMCB_RFLAGS);
    /* DR6.BS is sticky; a previous one must not be mistaken for proof of this attempt. */
    Step->Dr6 = KswSvmRead64(Current, KSW_VMCB_DR6);
    /* These dwords are restored in reverse overlay order before original L1 routing. */
    Step->Misc1 = (unsigned)KswSvmRead64(Current, KSW_VMCB_MISC1);
    /* Adjacent intercept dwords are not changed by the width-specific writes. */
    Step->Exceptions = (unsigned)KswSvmRead64(Current, KSW_NSVM_IRET_EXCEPTIONS);
    /* Catch every exception before its IDT delivery can manufacture apparent RIP progress. */
    KswSvmWrite32(Current, KSW_NSVM_IRET_EXCEPTIONS, ~0U);
    /* Catch physical and virtual asynchronous delivery, but allow this one IRET to execute. */
    KswSvmWrite32(Current, KSW_VMCB_MISC1, (Step->Misc1 | 0x1fU) & ~(1U << 20));
    /* Only TF is temporary; RF, IF and the original return stack remain untouched. */
    KswSvmWrite64(Current, KSW_VMCB_RFLAGS, Step->Flags | KSW_NSVM_IRET_TF);
    /* Preserve every debug status bit except the stale single-step indication. */
    KswSvmWrite64(Current, KSW_VMCB_DR6, Step->Dr6 & ~KSW_NSVM_IRET_BS);
    /* Publishing Applied last makes an INVALID retain the full observation contract. */
    ++Step->Attempts; ++Step->Entries; Step->Applied = 1; return 1;
}

/* A faulting IRET does not release the software NMI block or advance its instruction pointer. */
unsigned KswSvmNestedIretObserve(KSW_SVM_VMCB* Current, KSW_NSVM_IRET* Step)
{
    /* Raw outputs must be captured before any exception planner or reflection changes them. */
    KSW_SVM_U64 code, flags, debug;
    /* Synthetic BS is separable from simultaneous guest breakpoint causes. */
    unsigned retired, monitorDb;
    /* No missing/duplicate observation may restore stale control or debugging state. */
    if (!Current || !Step || !Step->Requested || !Step->Applied) { return KSW_NSVM_IRET_FAULT; }
    /* Preserve raw code on both successful and retained-fault paths. */
    code = Step->LastCode = KswSvmRead64(Current, KSW_VMCB_EXITCODE);
    /* INVALID did not execute; an interrupted IDT delivery violates this window's entry contract. */
    if (code == KSW_SVM_EXIT_INVALID || (KswSvmRead64(Current, KSW_VMCB_EXITINTINFO) & (1ULL << 31))) { return KSW_NSVM_IRET_FAULT; }
    /* TF in this output may have been legitimately loaded from the IRET frame. */
    flags = KswSvmRead64(Current, KSW_VMCB_RFLAGS); debug = KswSvmRead64(Current, KSW_VMCB_DR6);
    /* With all event dispatch intercepted, changed RIP proves execution reached the IRET target.
       A same-RIP return needs this attempt's newly set #DB.BS instead. */
    retired = KswSvmRead64(Current, KSW_VMCB_RIP) != Step->Rip || (code == 0x41 && (debug & KSW_NSVM_IRET_BS));
    /* Suppress only our own trace trap; original TF and simultaneous B0..B3/BD/BT remain guest-owned. */
    monitorDb = retired && code == 0x41 && (debug & KSW_NSVM_IRET_BS) &&
        !(Step->Flags & KSW_NSVM_IRET_TF) && !(debug & 0xa00fULL);
    /* Before completion, restore the TF we temporarily set. After completion, keep the popped guest TF. */
    if (!retired) { flags = (flags & ~KSW_NSVM_IRET_TF) | (Step->Flags & KSW_NSVM_IRET_TF); }
    /* Reestablish sticky pre-entry BS; retain new BS only when the guest itself requested tracing. */
    debug = (debug & ~KSW_NSVM_IRET_BS) | (Step->Dr6 & KSW_NSVM_IRET_BS) |
        ((Step->Flags & KSW_NSVM_IRET_TF) ? (debug & KSW_NSVM_IRET_BS) : 0);
    /* Debug state is restored before dispatch can reflect it to L1 or inject a real #DB. */
    KswSvmWrite64(Current, KSW_VMCB_RFLAGS, flags); KswSvmWrite64(Current, KSW_VMCB_DR6, debug);
    /* Original exception ownership, not the all-exception observation bitmap, controls reflection. */
    KswSvmWrite32(Current, KSW_NSVM_IRET_EXCEPTIONS, Step->Exceptions);
    /* The caller then removes any underlying IRQ and GIF overlays. */
    KswSvmWrite32(Current, KSW_VMCB_MISC1, Step->Misc1); Step->Applied = 0;
    /* Completion remains explicit even when a real target-instruction exit must still be dispatched. */
    Step->Completed = retired;
    /* Only a recoverable NPF before completion continues this same IRET watch.
       Exceptions and asynchronous exits yield to their ordinary owners before any later IRET. */
    Step->Requested = !retired && code == KSW_SVM_EXIT_NPF;
    /* A pure monitor trap has no architectural guest event to reflect or inject. */
    if (monitorDb) { return KSW_NSVM_IRET_MONITOR_DB; }
    /* The coordinator clears its NMI masks only for the explicit completed result. */
    return retired ? KSW_NSVM_IRET_RETIRED : KSW_NSVM_IRET_CONTINUE;
}
