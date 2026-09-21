/* An event disappears only after observed hardware delivery or explicit architectural transfer. */
#include "hvm_svm_nested_pending.h"

/* A token is never resolved by slot index alone. */
const KSW_NSVM_PENDING_ITEM* KswSvmNestedPendingLookup(const KSW_NSVM_PENDING* Pending,
    KSW_SVM_U64 Token)
{
    /* Search only the fixed per-CPU storage. */
    unsigned index;
    /* Zero denotes no owned event. */
    if (!Pending || !Token) { return NULL; }
    /* Recycled slots have different serials even when the event/vector is identical. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        /* A free slot's historical token cannot authorize a retry. */
        if (Pending->Items[index].State && Pending->Items[index].Token == Token) { return &Pending->Items[index]; }
    }
    /* The caller must preserve the raw hardware evidence when the identity is missing. */
    return NULL;
}

/* Reject invalid/reserved encodings instead of silently changing an acknowledged event. */
static int KswNsvmPendingValid(KSW_SVM_U64 Event)
{
    /* Only the valid/type/vector fields exist on an acknowledged asynchronous event. */
    unsigned type = (unsigned)((Event >> 8) & 7ULL);
    /* Error payloads and reserved bits cannot belong to INTR/NMI. */
    return (Event & (1ULL << 31)) && !(Event & ~0x800007ffULL) &&
        (type == 0 || type == 2);
}

/* The current root CPU owns every slot and its entire injection transaction. */
static KSW_NSVM_PENDING_ITEM* KswNsvmPendingFind(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token)
{
    /* Search cost is fixed and independent of interrupt rate. */
    unsigned index;
    /* Zero is never an acknowledgement identity. */
    if (!Pending || !Token) { return NULL; }
    /* A recycled slot has a new serial and cannot match a stale token. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        /* Only a live slot can complete an event. */
        if (Pending->Items[index].State && Pending->Items[index].Token == Token) { return &Pending->Items[index]; }
    }
    /* A missing token must not be counted as idempotent successful delivery. */
    return NULL;
}

/* A failed enqueue does not modify the source caller's ownership. */
int KswSvmNestedPendingPush(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Event,
    KSW_SVM_U64 Owner, KSW_SVM_U64* Token)
{
    /* The first free slot is independent of delivery ordering. */
    unsigned index;
    /* Preflight all failure conditions before writing an entry. */
    if (!Pending || !Token || !KswNsvmPendingValid(Event) || Pending->Serial == ~0ULL ||
        Pending->Count >= KSW_NSVM_PENDING_CAPACITY) { return 0; }
    /* The sequence token supplies stable FIFO ordering even after slot reuse. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        /* Occupied entries are never overwritten on overflow. */
        if (Pending->Items[index].State) { continue; }
        /* Preserve exact acknowledged vector/type rather than normalizing NMI vector bits. */
        Pending->Items[index].Event = Event; Pending->Items[index].Owner = Owner;
        /* Allocate a new identity without ever wrapping through zero. */
        Pending->Items[index].Token = ++Pending->Serial;
        /* Slot reuse never inherits a previous event's hardware-delivery proof. */
        Pending->Items[index].Interrupted = 0;
        /* Publish queued state only after every payload field is complete. */
        Pending->Items[index].State = KSW_NSVM_PENDING_QUEUED; Pending->Items[index].Physical = 0; ++Pending->Count;
        /* The caller may relinquish its source record only on success. */
        *Token = Pending->Items[index].Token; return 1;
    }
    /* Count/slot inconsistency remains a fault rather than destructive repair. */
    return 0;
}

/* The caller must retain actual physical acknowledgement evidence until this succeeds. */
int KswSvmNestedPendingPhysicalNmi(KSW_NSVM_PENDING* Pending, KSW_SVM_U64* Token)
{
    /* This operation cannot turn a guest-requested injection into a physical event. */
    KSW_NSVM_PENDING_ITEM* item;
    /* A confirmed NMI initially belongs to the virtual host's hardware context. */
    if (!KswSvmNestedPendingPush(Pending, 0x80000202ULL, 0, Token)) { return 0; }
    /* The same single-writer call still owns the exact freshly allocated slot. */
    item = KswNsvmPendingFind(Pending, *Token);
    /* Missing identity is a ledger fault, never permission to clear physical evidence. */
    if (!item) { return 0; }
    /* No IDT delivery has begun; a later VMRUN may change where this physical event is taken. */
    item->Physical = 1; return 1;
}

/* Never migrate an interrupted delivery or a guest-injected event to a different IDT. */
int KswSvmNestedPendingMovePhysical(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token,
    KSW_SVM_U64 Owner)
{
    /* Lookup verifies a unique acknowledgement identity rather than an event/vector match. */
    KSW_NSVM_PENDING_ITEM* item = KswNsvmPendingFind(Pending, Token);
    /* Once armed, the original guest context owns all delivery faults and retries. */
    if (!item || !item->Physical || item->State != KSW_NSVM_PENDING_QUEUED) { return 0; }
    /* Rebinding is allowed only before the first injection ever began. */
    item->Owner = Owner; return 1;
}

/* Eligibility is supplied by a separate GIF/IF/NMI-blocking owner. */
const KSW_NSVM_PENDING_ITEM* KswSvmNestedPendingSelect(const KSW_NSVM_PENDING* Pending,
    KSW_SVM_U64 Owner, unsigned AllowIrq, unsigned AllowNmi, unsigned Tpr)
{
    /* No entry is removed until the next actual hardware result. */
    const KSW_NSVM_PENDING_ITEM* selected = NULL;
    /* Priorities use NMI above every IRQ and vector class for maskable interrupts. */
    unsigned index, best = 0;
    /* Invalid control inputs cannot open an interrupt window. */
    if (!Pending || AllowIrq > 1 || AllowNmi > 1 || Tpr > 15) { return NULL; }
    /* One fixed pass preserves FIFO among equally prioritized candidates. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        /* Borrow the slot without changing its ownership. */
        const KSW_NSVM_PENDING_ITEM* item = &Pending->Items[index];
        /* A pending event follows its exact virtual context. */
        unsigned nmi = ((item->Event >> 8) & 7ULL) == 2;
        /* APIC class comparisons use the upper four vector bits. */
        unsigned priority = nmi ? 16U : (unsigned)((item->Event & 255ULL) >> 4);
        /* An armed entry cannot be scheduled a second time. */
        if (item->State != KSW_NSVM_PENDING_QUEUED || item->Owner != Owner ||
            (nmi ? !AllowNmi : (!AllowIrq || priority <= Tpr))) { continue; }
        /* Prefer highest priority, then the earliest acknowledgement at that priority. */
        if (!selected || priority > best || (priority == best && item->Token < selected->Token)) {
            /* Selection is read-only, including its ordering token. */
            selected = item; best = priority;
        }
    }
    /* NULL means no eligible event, not an empty queue. */
    return selected;
}

/* Arming is an ownership change, not evidence that VMRUN succeeded. */
int KswSvmNestedPendingArm(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token)
{
    /* A stale token cannot alter a new event in a recycled slot. */
    KSW_NSVM_PENDING_ITEM* item = KswNsvmPendingFind(Pending, Token);
    /* Duplicate arming could otherwise inject one acknowledgement twice. */
    if (!item || item->State != KSW_NSVM_PENDING_QUEUED) { return 0; }
    /* Hardware entry/result is handled by the platform after this call. */
    item->State = KSW_NSVM_PENDING_ARMED; item->Physical = 0; item->Interrupted = 0; return 1;
}

/* Observe before emulation replaces EVENTINJ/EXITINTINFO or switches virtual context. */
int KswSvmNestedPendingObserve(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token,
    unsigned Entered, KSW_SVM_U64 ExitIntInfo)
{
    /* The exact token ties one hardware attempt to one source event. */
    KSW_NSVM_PENDING_ITEM* item = KswNsvmPendingFind(Pending, Token);
    /* INVALID does not consume or reclassify an acknowledged event. */
    if (!item || item->State != KSW_NSVM_PENDING_ARMED || Entered != 1) { return 0; }
    /* Interrupted delivery keeps the same acknowledgement identity for retry. */
    if (ExitIntInfo & (1ULL << 31)) {
        /* A different valid event may be a later, separate delivery after ours completed.
           Without that ordering proof this API deliberately retains both raw records. */
        if (ExitIntInfo != item->Event || Pending->Retried == ~0ULL) { return 0; }
        /* Caller owns reinjection timing; the event is not rearmed automatically. */
        item->State = KSW_NSVM_PENDING_QUEUED; item->Interrupted = 1; ++Pending->Retried; return 1;
    }
    /* Counter exhaustion cannot turn into false fresh evidence. */
    if (!Pending->Count || Pending->Delivered == ~0ULL) { return 0; }
    /* No interrupted event remains after a successful entry, so this injection completed. */
    item->State = KSW_NSVM_PENDING_FREE; --Pending->Count; ++Pending->Delivered; return 1;
}

/* Read-only preflight keeps a failed/partial VMCB writeback from consuming source ownership. */
int KswSvmNestedPendingPrepareTransfer(const KSW_NSVM_PENDING* Pending,
    KSW_SVM_U64 Owner, KSW_SVM_U64 RetryToken, KSW_SVM_U64 ReflectedEvent,
    KSW_SVM_U64* TransferToken, KSW_SVM_U64* PhysicalToken)
{
    /* One interrupted delivery and one not-yet-delivered physical NMI have different handoffs. */
    KSW_SVM_U64 transfer = 0, physical = 0;
    /* Validate every owned entry before publishing either handoff token. */
    unsigned index;
    /* Owner zero is the physical virtual host, never the departing L2 VMCB. */
    if (!Pending || !TransferToken || !PhysicalToken || TransferToken == PhysicalToken || !Owner) { return 0; }
    /* Unrelated owners retain their own state; they never populate this departing VMCB's EXITINTINFO. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        /* The private root writer owns this immutable preflight view. */
        const KSW_NSVM_PENDING_ITEM* item = &Pending->Items[index];
        /* A free or unrelated entry has no handoff in this transaction. */
        if (!item->State || item->Owner != Owner) { continue; }
        /* No in-flight hardware attempt may be reflected before its real output was observed. */
        if (item->State != KSW_NSVM_PENDING_QUEUED || !item->Token) { return 0; }
        /* An undelivered physical NMI follows VMEXIT's current CPU context without fabricating EXITINTINFO. */
        if (item->Physical) {
            /* Hardware has one pending NMI latch; interrupted delivery is no longer movable. */
            if (physical || item->Interrupted || ((item->Event >> 8) & 7ULL) != 2) { return 0; }
            /* Rebinding happens only after successful architectural VMCB writeback. */
            physical = item->Token;
        } else {
            /* All other acknowledged events need the exact hardware-interrupted record, not a same-vector guess. */
            if (transfer || !item->Interrupted || item->Token != RetryToken || item->Event != ReflectedEvent) { return 0; }
            /* Exactly one event can be represented by EXITINTINFO. */
            transfer = item->Token;
        }
    }
    /* Neither output changes on failure, so partial preflight cannot authorize either mutation. */
    *TransferToken = transfer; *PhysicalToken = physical; return 1;
}

/* Only committed VMEXIT writeback may hand an interrupted event to the inner VMM. */
int KswSvmNestedPendingTransfer(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token,
    KSW_SVM_U64 ReflectedEvent)
{
    /* The caller supplies the exact EVENTINFO written back to the same owner. */
    KSW_NSVM_PENDING_ITEM* item = KswNsvmPendingFind(Pending, Token);
    /* Refuse a transfer that could silently drop or substitute an acknowledgement. */
    if (!item || item->Event != ReflectedEvent || !Pending->Count || item->Physical ||
        !item->Interrupted || item->State != KSW_NSVM_PENDING_QUEUED) { return 0; }
    /* Transfer is not hardware delivery and does not increment Delivered. */
    item->State = KSW_NSVM_PENDING_FREE; --Pending->Count; return 1;
}

/* A zero return is the prerequisite for releasing a virtual context's asynchronous state. */
unsigned KswSvmNestedPendingOwned(const KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Owner)
{
    /* Fixed bound works even in a retained-fault root path. */
    unsigned count = 0, index;
    /* Missing evidence is conservatively nonempty. */
    if (!Pending) { return KSW_NSVM_PENDING_CAPACITY; }
    /* Armed entries count exactly like queued entries until proof of completion. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        /* Different guest owners must never receive each other's pending event. */
        if (Pending->Items[index].State && Pending->Items[index].Owner == Owner) { ++count; }
    }
    /* The caller still needs the session/lease/native checks before release. */
    return count;
}
