/* Shared VMCB event persistence uses the existing nonblocking execution lease, never a root lock. */
#include "hvm_svm_nested_owner.h"
#include <intrin.h>

/* No untrusted/stale lease may read or alter another virtual CPU's deferred interrupts. */
static KSW_NSVM_OWNER_SLOT* KswNsvmMailbox(KSW_NSVM_OWNER_TABLE* Table, const KSW_NSVM_LEASE* Lease)
{
    /* Validate the bounded index before looking at its permanent physical identity. */
    if (!Table || !Lease || !Lease->Token || Lease->Slot >= KSW_NSVM_OWNER_SLOTS) { return NULL; }
    /* Both key and acquisition ticket must match; GPA aliases use this same key. */
    if ((KSW_SVM_U64)_InterlockedCompareExchange64(&Table->Slots[Lease->Slot].Key, 0, 0) != (Lease->HostPa >> 12) + 1 ||
        (KSW_SVM_U64)_InterlockedCompareExchange64(&Table->Slots[Lease->Slot].Token, 0, 0) != Lease->Token) { return NULL; }
    /* The exclusive lease protects the payload until release publishes the complete transaction. */
    return &Table->Slots[Lease->Slot];
}

/* Only valid, unarmed asynchronous records can be parked for a later VMRUN. */
int KswSvmNestedOwnerCanPark(KSW_NSVM_OWNER_TABLE* Table, const KSW_NSVM_LEASE* Lease,
    const KSW_NSVM_PENDING* Pending)
{
    /* A mailbox is consumed on entry and must be empty before this guest exits again. */
    KSW_NSVM_OWNER_SLOT* slot = KswNsvmMailbox(Table, Lease);
    /* Count actual slots so a corrupt Count cannot cause underflow during export. */
    unsigned index, total = 0;
    /* A no-event probe may omit the local ledger but cannot discard existing saved events. */
    if (!slot || slot->DeferredCount) { return 0; }
    /* No local ledger means no events to park. */
    if (!Pending) { return 1; }
    /* Preflight the full ledger before writeback or any ownership mutation. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        /* Only the current physical CPU mutates its live queue. */
        const KSW_NSVM_PENDING_ITEM* item = &Pending->Items[index];
        /* Free slots retain historical payload and do not participate. */
        if (!item->State) { continue; }
        /* The local count includes records for L1 and other retained contexts. */
        ++total;
        /* Other contexts stay with their owner; physical NMI has its separate handoff. */
        if (item->Owner != Lease->HostPa + 1 || item->Physical) { continue; }
        /* Interrupted delivery is transferred through EXITINTINFO, not this mailbox. */
        if (item->State != KSW_NSVM_PENDING_QUEUED || !item->Token ||
            !(item->Event & (1ULL << 31)) || (item->Event & ~0x800007ffULL) ||
            (((item->Event >> 8) & 7ULL) != 0 && ((item->Event >> 8) & 7ULL) != 2)) { return 0; }
    }
    /* No best-effort correction of a damaged ledger is allowed at this boundary. */
    return total == Pending->Count;
}

/* Called only after full architectural VMCB writeback and before releasing its execution lease. */
int KswSvmNestedOwnerPark(KSW_NSVM_OWNER_TABLE* Table, const KSW_NSVM_LEASE* Lease,
    KSW_NSVM_PENDING* Pending)
{
    /* Resolve source ownership before writing any shared payload. */
    KSW_NSVM_OWNER_SLOT* slot = KswNsvmMailbox(Table, Lease);
    /* At most sixteen records are sorted by their original FIFO identity. */
    unsigned count = 0, index;
    /* A failed preflight leaves both shared and private ledgers untouched. */
    if (!slot || !KswSvmNestedOwnerCanPark(Table, Lease, Pending)) { return 0; }
    /* Probe sessions without an event ledger need no mutation. */
    if (!Pending) { return 1; }
    /* Each pass consumes the oldest eligible record, independently of recycled slot positions. */
    for (;;) {
        /* This pointer is private and remains valid until this same writer frees its slot. */
        KSW_NSVM_PENDING_ITEM* first = NULL;
        /* The bounded queue fixes the maximum work at sixteen squared comparisons. */
        for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
            /* Ignore physical and still-interrupted records: they have other architectural owners. */
            KSW_NSVM_PENDING_ITEM* item = &Pending->Items[index];
            /* No armed state can survive the successful preflight above. */
            if (item->State && item->Owner == Lease->HostPa + 1 && !item->Physical && !item->Interrupted &&
                (!first || item->Token < first->Token)) { first = item; }
        }
        /* All eligible events now have one shared owner. */
        if (!first) { break; }
        /* Retain the exact event word; source serials are local and are not copied across CPUs. */
        slot->Deferred[count++] = first->Event;
        /* Free only after payload storage, with the VMCB lease still preventing readers. */
        first->State = KSW_NSVM_PENDING_FREE; --Pending->Count;
    }
    /* Publish the complete mailbox before OwnerRelease permits another CPU to acquire it. */
    _InterlockedExchange(&slot->DeferredCount, (long)count); return 1;
}

/* Import happens under the new VMRUN lease, after admission but before publishing L2 execution. */
int KswSvmNestedOwnerRestore(KSW_NSVM_OWNER_TABLE* Table, const KSW_NSVM_LEASE* Lease,
    KSW_NSVM_PENDING* Pending)
{
    /* Lease validation supplies cross-CPU acquire ordering for the payload. */
    KSW_NSVM_OWNER_SLOT* slot = KswNsvmMailbox(Table, Lease);
    /* Source count is stable until this exclusive owner releases the slot. */
    unsigned count, index, freeSlots = 0;
    /* Each imported record receives a fresh destination-CPU identity. */
    KSW_SVM_U64 token;
    /* Corrupt or stale metadata cannot be interpreted as an empty mailbox. */
    if (!slot || slot->DeferredCount < 0 || slot->DeferredCount > KSW_NSVM_PENDING_CAPACITY) { return 0; }
    /* Zero saved events need no destination queue. */
    count = (unsigned)slot->DeferredCount; if (!count) { return 1; }
    /* Preflight capacity, serial exhaustion and duplicate ownership before copying any record. */
    if (!Pending || Pending->Count > KSW_NSVM_PENDING_CAPACITY - count ||
        Pending->Serial > ~0ULL - count || KswSvmNestedPendingOwned(Pending, Lease->HostPa + 1)) { return 0; }
    /* Validate free-slot/count consistency independently of the aggregate field. */
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) { if (!Pending->Items[index].State) { ++freeSlots; } }
    /* Exact count agreement prevents a later enqueue from partially filling a corrupt queue. */
    if (freeSlots != KSW_NSVM_PENDING_CAPACITY - Pending->Count || freeSlots < count) { return 0; }
    /* Shared bytes are untrusted if a prior fault corrupted them; validate all before mutation. */
    for (index = 0; index < count; ++index) {
        /* Match the asynchronous event encoding accepted by PendingPush. */
        KSW_SVM_U64 event = slot->Deferred[index];
        /* Reserved bits/error payload must never be imported as a new interrupt. */
        if (!(event & (1ULL << 31)) || (event & ~0x800007ffULL) ||
            (((event >> 8) & 7ULL) != 0 && ((event >> 8) & 7ULL) != 2)) { return 0; }
    }
    /* Input preflight and the single writer make these bounded enqueues deterministic. */
    for (index = 0; index < count; ++index) {
        /* Unexpected failure keeps the shared count and execution lease retained; never reenter. */
        if (!KswSvmNestedPendingPush(Pending, slot->Deferred[index], Lease->HostPa + 1, &token)) { return 0; }
    }
    /* Only the complete import relinquishes shared ownership; Delivered is deliberately unchanged. */
    _InterlockedExchange(&slot->DeferredCount, 0); return 1;
}
