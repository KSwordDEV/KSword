/* V_IRQ is used only to request a hardware eligibility exit; EVENTINJ delivers the real event later. */
#include "hvm_svm_nested_window.h"

/* APM 15.21.4 gives physical interrupts precedence over virtual IRQs, independently of vector class. */
int KswSvmNestedPreferVirq(const KSW_SVM_VMCB* Current, KSW_SVM_U64 QueuedEvent)
{
    /* V_INTR_PRIO controls eligibility against TPR, not ordering ahead of a ready physical event. */
    KSW_SVM_U64 control;
    /* Preserve an eligible/retrying acknowledged event before starting another virtual delivery. */
    if (QueuedEvent & (1ULL << 31)) { return 0; }
    /* A synchronous injection keeps its own delivery contract ahead of this arbiter. */
    if (!Current || (KswSvmRead64(Current, KSW_VMCB_EVENT) & (1ULL << 31)) ||
        !(KswSvmRead64(Current, KSW_VMCB_RFLAGS) & (1ULL << 9)) ||
        (KswSvmRead64(Current, 0x068U) & 1ULL)) { return 0; }
    /* These are original controls before any temporary scheduling overlay. */
    control = KswSvmRead64(Current, KSW_VMCB_INTCTL);
    /* IGN_TPR applies only to the original virtual request, never to the acknowledged queue item. */
    return (control & (1ULL << 8)) && ((control & (1ULL << 20)) || ((control >> 16) & 15ULL) > (control & 15ULL));
}

/* Temporarily multiplex eligibility; the original virtual request is restored before ownership decisions. */
int KswSvmNestedIrqWindowArm(KSW_SVM_VMCB* Current, KSW_SVM_U64 Event,
    KSW_SVM_U64 Token, KSW_NSVM_IRQ_WINDOW* Window)
{
    /* Interrupt class and vector are copied from the already acknowledged event. */
    unsigned vector = (unsigned)(Event & 255ULL), priority = vector >> 4;
    /* Save all source controls before publishing an executable window. */
    KSW_SVM_U64 control;
    /* NMI has no IF/TPR eligibility window and must not use this mechanism. */
    if (!Current || !Window || Window->Applied || !Token ||
        (Event & ~255ULL) != 0x80000000ULL || vector < 16) { return 0; }
    /* Existing EVENTINJ retains priority and its exact payload; VINTR waits until that delivery
       and the resulting handler state make the queued IRQ eligible. Never overwrite EVENTINJ. */
    /* Preserve real V_IRQ requests rather than changing interrupt priority/order. */
    control = KswSvmRead64(Current, KSW_VMCB_INTCTL);
    /* Wake when either request may be deliverable. The exit still does not consume either source. */
    if ((control & (1ULL << 8)) && ((control >> 16) & 15ULL) > priority) {
        /* An original higher-priority request must not wait behind a blocked lower-priority queue item. */
        priority = (unsigned)((control >> 16) & 15ULL);
    }
    /* Snapshot the exact executable overlay, which may include monitor-owned NMI controls. */
    Window->IntCtl = control; Window->Misc1 = (unsigned)KswSvmRead64(Current, KSW_VMCB_MISC1);
    /* Bind eligibility to a stable queue token, not to the current slot index. */
    Window->Token = Token;
    /* Clear old vector/priority/IGN_TPR, preserving the current TPR and masking mode. */
    control &= ~((255ULL << 32) | (31ULL << 16));
    /* This vector never reaches an IDT; priority represents the union of both requests' eligibility. */
    control |= ((KSW_SVM_U64)vector << 32) | ((KSW_SVM_U64)priority << 16) | (1ULL << 8);
    /* An original IGN_TPR request must still wake the arbiter even while TPR blocks our queued IRQ. */
    if (Window->IntCtl & (1ULL << 8)) { control |= Window->IntCtl & (1ULL << 20); }
    /* Set the intercept before the V_IRQ request can be passed to hardware. */
    KswSvmWrite32(Current, KSW_VMCB_MISC1, Window->Misc1 | (1U << 4));
    /* VINTR interception precedes V_IRQ consumption and IDT access. */
    KswSvmWrite64(Current, KSW_VMCB_INTCTL, control);
    /* Only after both controls are present may the platform issue VMRUN. */
    Window->Applied = 1; return 1;
}

/* Remove the synthetic request before route/reflect sees any hardware result. */
int KswSvmNestedIrqWindowRestore(KSW_SVM_VMCB* Current, KSW_NSVM_IRQ_WINDOW* Window,
    unsigned* WindowExit)
{
    /* Hardware may update V_TPR while waiting for IF or an interrupt shadow to clear. */
    KSW_SVM_U64 output;
    /* No stale completion can remove another pending event's window. */
    if (!Current || !Window || !Window->Applied || !WindowExit) { return 0; }
    /* A rejected real VMCB must retain the entire executable window for diagnosis. */
    if (KswSvmRead64(Current, KSW_VMCB_EXITCODE) == KSW_SVM_EXIT_INVALID) { return 0; }
    /* The sentinel cannot have reached the guest IDT because its VINTR intercept was mandatory. */
    output = KswSvmRead64(Current, KSW_VMCB_INTCTL);
    /* A missing V_IRQ would indicate an impossible consumption or corrupted controls. */
    if (!(output & (1ULL << 8))) { return 0; }
    /* Detect this internal eligibility exit before restoring the original VINTR ownership bit. */
    *WindowExit = KswSvmRead64(Current, KSW_VMCB_EXITCODE) == 0x64ULL;
    /* Keep guest CR8 changes, while discarding every temporary vector/priority/request bit. */
    KswSvmWrite64(Current, KSW_VMCB_INTCTL, (Window->IntCtl & ~15ULL) | (output & 15ULL));
    /* The original VMM never observes a synthetic VINTR request as its own event. */
    KswSvmWrite32(Current, KSW_VMCB_MISC1, Window->Misc1);
    /* The queue still owns its acknowledgement; the following entry decides actual injection. */
    Window->Applied = 0; return 1;
}
