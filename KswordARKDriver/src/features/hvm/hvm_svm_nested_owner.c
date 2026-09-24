/* MSVC interlocked intrinsics emit bounded CPU operations and call no OS services. */
#include "hvm_svm_nested_owner.h"
#include <intrin.h>

/* Insert/find a permanent key, then atomically claim that key's execution token. */
unsigned KswSvmNestedOwnerAcquire(KSW_NSVM_OWNER_TABLE* Table, KSW_SVM_U64 HostPa,
    unsigned CpuIdentity, KSW_NSVM_LEASE* Lease)
{
    /* Physical width is further restricted by the caller's translated operand contract. */
    KSW_SVM_U64 key;
    /* A bounded scan is not a spin waiting for another CPU to leave a critical section. */
    unsigned first, step;
    /* Signed intrinsics preserve exact positive ticket/key representations. */
    long long observed, token;
    /* Replacing a still-held lease would orphan its old hardware owner. */
    if (!Table || !Lease || Lease->Token || (HostPa & 4095ULL) || HostPa >= (1ULL << 52)) { return KSW_NSVM_LEASE_INVALID; }
    /* Publish identity without an ABA-prone delete/reinsert operation. */
    key = (HostPa >> 12) + 1;
    /* Mix distant page numbers while retaining a fixed power-of-two table bound. */
    first = (unsigned)((key ^ (key >> 12) ^ (key >> 24)) & (KSW_NSVM_OWNER_SLOTS - 1));
    /* Collision keys remain permanent even after their execution token is released. */
    for (step = 0; step < KSW_NSVM_OWNER_SLOTS; ++step) {
        /* Probe all slots at most once, with no yielding or blocking call. */
        unsigned slot = (first + step) & (KSW_NSVM_OWNER_SLOTS - 1);
        /* The winning CAS publishes the key before any owner may claim its token. */
        observed = _InterlockedCompareExchange64(&Table->Slots[slot].Key, (long long)key, 0);
        /* Other keys never move, so equal GPAs/HPA aliases cannot acquire duplicate slots. */
        if (observed && (KSW_SVM_U64)observed != key) { continue; }
        /* Refuse ticket exhaustion rather than wrap to a stale authority value. */
        observed = _InterlockedCompareExchange64(&Table->Serial, 0, 0);
        /* Leave a large terminal range so increment saturation cannot become ordinary reuse. */
        if (observed < 0 || (KSW_SVM_U64)observed >= 0x3fffffffffffffffULL) { return KSW_NSVM_LEASE_FULL; }
        /* Each invocation obtains a distinct token, including unsuccessful busy claims. */
        token = _InterlockedIncrement64(&Table->Serial);
        /* Cross-CPU increments at the bound cannot turn an exhausted ticket into admission. */
        if (token <= 0 || (KSW_SVM_U64)token >= 0x3fffffffffffffffULL) { return KSW_NSVM_LEASE_FULL; }
        /* Exactly one owner can transition this permanent key from idle to executing. */
        if (_InterlockedCompareExchange64(&Table->Slots[slot].Token, token, 0) != 0) { return KSW_NSVM_LEASE_BUSY; }
        /* This CPU now owns both the operand snapshot and subsequent architectural output. */
        Lease->HostPa = HostPa; Lease->Token = (KSW_SVM_U64)token;
        Lease->PreviousToken = Table->Slots[slot].LastToken;
        Table->Slots[slot].LastToken = Lease->Token;
        /* Retain frozen topology identity for failure evidence and release bookkeeping. */
        Lease->Slot = slot; Lease->CpuIdentity = CpuIdentity;
        /* There was no allocation or wait at root execution level. */
        return KSW_NSVM_LEASE_OK;
    }
    /* A new distinct operand needs a new prepared lifetime if the immutable-key budget is exhausted. */
    return KSW_NSVM_LEASE_FULL;
}

/* May be called after committed VMEXIT or after separately proven native abort. */
int KswSvmNestedOwnerRelease(KSW_NSVM_OWNER_TABLE* Table, KSW_NSVM_LEASE* Lease)
{
    /* An absent authority cannot release another CPU's slot. */
    if (!Table || !Lease || !Lease->Token || Lease->Slot >= KSW_NSVM_OWNER_SLOTS) { return 0; }
    /* Check the immutable identity in addition to the unique token. */
    if ((KSW_SVM_U64)_InterlockedCompareExchange64(&Table->Slots[Lease->Slot].Key, 0, 0) != (Lease->HostPa >> 12) + 1) { return 0; }
    /* A duplicated/stale release leaves the newer owner entirely unchanged. */
    if ((KSW_SVM_U64)_InterlockedCompareExchange64(&Table->Slots[Lease->Slot].Token, 0,
        (long long)Lease->Token) != Lease->Token) { return 0; }
    /* Erase only local authority; the permanent key prevents collision-chain holes and ABA. */
    Lease->Token = 0;
    /* No cross-CPU lock must be held when returning to L1 or native Windows. */
    return 1;
}

/* This observation is meaningful for teardown only after the common all-native barrier. */
int KswSvmNestedOwnersIdle(KSW_NSVM_OWNER_TABLE* Table)
{
    /* Missing storage is not proof that a prepared owner has exited. */
    unsigned slot;
    /* Callers with no nested preparation need not invoke this helper. */
    if (!Table) { return 0; }
    /* Tokens are read atomically even in diagnostic queries. */
    for (slot = 0; slot < KSW_NSVM_OWNER_SLOTS; ++slot) {
        /* One live or fault-retained owner forbids teardown of the shared lifetime. */
        if (_InterlockedCompareExchange64(&Table->Slots[slot].Token, 0, 0)) { return 0; }
        /* An idle VMCB can still own an acknowledged event awaiting its next execution. */
        if (_InterlockedCompareExchange(&Table->Slots[slot].DeferredCount, 0, 0)) { return 0; }
    }
    /* This is a quiescent ledger check, not authorization to stop an executing CPU. */
    return 1;
}
