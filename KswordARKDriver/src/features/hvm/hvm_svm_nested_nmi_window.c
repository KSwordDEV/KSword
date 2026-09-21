/* Observe the instruction window blocking NMI; do not change GIF, guest IF or interrupt shadow. */
#include "hvm_svm_nested_nmi_window.h"
#define KSW_NMI_TRACE_FLAGS ((1ULL << 8) | (1ULL << 16))
#define KSW_NMI_TRACE_BS (1ULL << 14)

/* Trace the current continuation while retaining the original event's higher delivery priority. */
int KswSvmNestedNmiWindowArm(KSW_SVM_VMCB* Current, KSW_SVM_U64 Token,
    KSW_NSVM_NMI_WINDOW* Window)
{
    /* Only a real queue identity may cause an observation entry. */
    if (!Current || !Window || !Token || Window->Applied || Window->Entries == ~0ULL) { return 0; }
    /* A new acknowledgement receives its own bounded observation budget. */
    if (Window->Token != Token) { Window->Token = Token; Window->Attempts = 0; }
    /* Repeated nonprogress is retained instead of creating an unbounded root/guest loop. */
    if (Window->Attempts >= 64) { return 0; }
    /* Save only the state changed by this overlay; other guest arithmetic flags remain live. */
    Window->Flags = KswSvmRead64(Current, KSW_VMCB_RFLAGS); Window->Dr6 = KswSvmRead64(Current, KSW_VMCB_DR6);
    /* Entry evidence distinguishes a shadow wait from an existing injection collision. */
    Window->Rip = KswSvmRead64(Current, KSW_VMCB_RIP); Window->Event = KswSvmRead64(Current, KSW_VMCB_EVENT);
    /* Catch secondary exceptions before aggregation and asynchronous events before IDT delivery. */
    Window->Exceptions = (unsigned)KswSvmRead64(Current, 0x008U);
    /* Leave instruction intercepts, including any lower IRET mask guard, unchanged. */
    Window->Misc1 = (unsigned)KswSvmRead64(Current, KSW_VMCB_MISC1);
    /* Debug and fault ownership is recovered from these original controls on exit. */
    KswSvmWrite32(Current, 0x008U, ~0U); KswSvmWrite32(Current, KSW_VMCB_MISC1, Window->Misc1 | 0x1fU);
    /* RF prevents a pre-instruction execution breakpoint from repeatedly starving the NMI window. */
    KswSvmWrite64(Current, KSW_VMCB_RFLAGS, Window->Flags | KSW_NMI_TRACE_FLAGS);
    /* Sticky BS from an earlier guest trap is not proof of a newly observed step. */
    KswSvmWrite64(Current, KSW_VMCB_DR6, Window->Dr6 & ~KSW_NMI_TRACE_BS);
    /* Preserve EVENTINJ byte-for-byte, and publish the complete overlay last. */
    ++Window->Attempts; ++Window->Entries; Window->Applied = 1; return 1;
}

/* Caller supplies the raw hardware output before any exception planner changes EVENTINJ. */
unsigned KswSvmNestedNmiWindowRestore(KSW_SVM_VMCB* Current, KSW_NSVM_NMI_WINDOW* Window)
{
    /* Preserve guest flags outside the two temporary tracing bits. */
    KSW_SVM_U64 flags, debug, code;
    /* A guest-requested trace or simultaneous breakpoint must remain guest-visible. */
    unsigned privateDb;
    /* A stale restore cannot remove controls from a different hardware attempt. */
    if (!Current || !Window || !Window->Applied) { return KSW_NSVM_NMI_WINDOW_FAULT; }
    /* INVALID retains the entire executable overlay for the fault path. */
    code = Window->LastCode = KswSvmRead64(Current, KSW_VMCB_EXITCODE);
    /* Missing exception interception invalidates the evidence used by this observer. */
    if (code == KSW_SVM_EXIT_INVALID || (unsigned)KswSvmRead64(Current, 0x008U) != ~0U) { return KSW_NSVM_NMI_WINDOW_FAULT; }
    /* Inspect raw BS before restoring sticky debug status. */
    flags = KswSvmRead64(Current, KSW_VMCB_RFLAGS); debug = KswSvmRead64(Current, KSW_VMCB_DR6);
    /* A pure tracing trap has no interrupted delivery; preserve all other exit ownership. */
    privateDb = code == 0x41 && (debug & KSW_NMI_TRACE_BS) && !(debug & 0xa00fULL) &&
        !(Window->Flags & (1ULL << 8)) && !(KswSvmRead64(Current, KSW_VMCB_EXITINTINFO) & (1ULL << 31));
    /* Remove monitor TF/RF before the caller reflects or injects an architectural event. */
    flags = (flags & ~KSW_NMI_TRACE_FLAGS) | (Window->Flags & KSW_NMI_TRACE_FLAGS);
    /* Retain original sticky BS and new BS when the guest had already enabled tracing. */
    debug = (debug & ~KSW_NMI_TRACE_BS) | (Window->Dr6 & KSW_NMI_TRACE_BS) |
        ((Window->Flags & (1ULL << 8)) ? (debug & KSW_NMI_TRACE_BS) : 0);
    /* Never restore guest arithmetic flags, RIP or a launch-time register snapshot. */
    KswSvmWrite64(Current, KSW_VMCB_RFLAGS, flags); KswSvmWrite64(Current, KSW_VMCB_DR6, debug);
    /* Underlying IRET/IRQ/GIF controls are restored later in reverse order by the coordinator. */
    KswSvmWrite32(Current, 0x008U, Window->Exceptions); KswSvmWrite32(Current, KSW_VMCB_MISC1, Window->Misc1);
    /* Even a real fault/NPF completes this observation attempt, not the queued NMI itself. */
    Window->Applied = 0;
    /* The waiting NMI is selected only by a later fresh GIF/shadow/blocking eligibility check. */
    return privateDb ? KSW_NSVM_NMI_WINDOW_DB : KSW_NSVM_NMI_WINDOW_EXIT;
}
