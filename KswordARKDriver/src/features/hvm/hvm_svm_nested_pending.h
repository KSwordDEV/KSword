/* CPU-private acknowledged-event ownership; never an APIC acknowledgement mechanism. */
#pragma once
#include "hvm_svm_arch.h"
/* Bounded storage is allocated before residency. Overflow retains the source event. */
#define KSW_NSVM_PENDING_CAPACITY 16U
/* States separate queued ownership from an attempted hardware injection. */
#define KSW_NSVM_PENDING_FREE 0U
#define KSW_NSVM_PENDING_QUEUED 1U
#define KSW_NSVM_PENDING_ARMED 2U
typedef struct _KSW_NSVM_PENDING_ITEM {
    /* Unique identity survives retries; zero is never a live token. */
    KSW_SVM_U64 Token, Event, Owner;
    /* Owner zero is L1; nonzero is the translated VMCB12 page plus one. */
    unsigned State, Physical;
    /* Set only by hardware's interrupted-delivery observation, never by enqueue alone. */
    unsigned Interrupted;
} KSW_NSVM_PENDING_ITEM;
typedef struct _KSW_NSVM_PENDING {
    /* Entries never move while a caller holds a token. */
    KSW_NSVM_PENDING_ITEM Items[KSW_NSVM_PENDING_CAPACITY];
    /* Saturating at exhaustion is preferable to token reuse. */
    KSW_SVM_U64 Serial, Delivered, Retried;
    /* No atomics are needed: only this physical CPU's root loop writes this ledger. */
    unsigned Count;
} KSW_NSVM_PENDING;
/* Accept only already acknowledged external interrupts/NMIs, not arbitrary injection words. */
int KswSvmNestedPendingPush(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Event,
    KSW_SVM_U64 Owner, KSW_SVM_U64* Token);
/* Only a confirmed physical NMI may follow VMRUN's change of the current execution context. */
int KswSvmNestedPendingPhysicalNmi(KSW_NSVM_PENDING* Pending, KSW_SVM_U64* Token);
/* A not-yet-injected physical NMI may enter L2 when L1 explicitly did not intercept it. */
int KswSvmNestedPendingMovePhysical(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token,
    KSW_SVM_U64 Owner);
/* Select without consuming; NMI priority and FIFO order within priority are preserved. */
const KSW_NSVM_PENDING_ITEM* KswSvmNestedPendingSelect(const KSW_NSVM_PENDING* Pending,
    KSW_SVM_U64 Owner, unsigned AllowIrq, unsigned AllowNmi, unsigned Tpr);
/* Arm after the caller has prepared an executable image. No entry means no delivery. */
int KswSvmNestedPendingArm(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token);
/* Hardware INVALID leaves ownership armed. Interrupted delivery requeues the same identity. */
int KswSvmNestedPendingObserve(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token,
    unsigned Entered, KSW_SVM_U64 ExitIntInfo);
/* Validate the complete owner backlog before any architectural VMEXIT writeback. */
int KswSvmNestedPendingPrepareTransfer(const KSW_NSVM_PENDING* Pending,
    KSW_SVM_U64 Owner, KSW_SVM_U64 RetryToken, KSW_SVM_U64 ReflectedEvent,
    KSW_SVM_U64* TransferToken, KSW_SVM_U64* PhysicalToken);
/* Architectural VMEXIT transfers only a hardware-observed interrupted delivery. */
int KswSvmNestedPendingTransfer(KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Token,
    KSW_SVM_U64 ReflectedEvent);
/* Refuse context destruction/migration while an acknowledged event still belongs to it. */
unsigned KswSvmNestedPendingOwned(const KSW_NSVM_PENDING* Pending, KSW_SVM_U64 Owner);
/* Borrow one exact identity for retry/architectural handoff; do not keep it across a mutation. */
const KSW_NSVM_PENDING_ITEM* KswSvmNestedPendingLookup(const KSW_NSVM_PENDING* Pending,
    KSW_SVM_U64 Token);
