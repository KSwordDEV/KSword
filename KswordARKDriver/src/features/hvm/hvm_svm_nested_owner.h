/* Lifetime-bounded, nonblocking ownership of translated VMCB physical pages. */
#pragma once
#include "hvm_svm_arch.h"
#include "hvm_svm_nested_pending.h"
/* Keys never move during one prepared lifetime; exhaustion is explicit rather than unsafe eviction. */
#define KSW_NSVM_OWNER_SLOTS 4096U
#define KSW_NSVM_LEASE_OK 0U
#define KSW_NSVM_LEASE_BUSY 1U
#define KSW_NSVM_LEASE_FULL 2U
#define KSW_NSVM_LEASE_INVALID 3U
/* Permanent page identity and independently reusable execution token. */
typedef struct _KSW_NSVM_OWNER_SLOT {
    /* Physical page number plus one distinguishes physical address zero from an unused key. */
    volatile long long Key;
    /* Zero means idle; a nonzero token is unique throughout this prepared lifetime. */
    volatile long long Token;
    /* Deferred guest events follow this VMCB across physical CPUs while its lease is idle. */
    KSW_SVM_U64 Deferred[KSW_NSVM_PENDING_CAPACITY];
    /* Published atomically for teardown; payload access requires this slot's exclusive lease. */
    volatile long DeferredCount;
} KSW_NSVM_OWNER_SLOT;
/* Allocate/zero once at PASSIVE_LEVEL; do not reset while any processor can enter. */
typedef struct _KSW_NSVM_OWNER_TABLE {
    /* Atomic ticket generation; saturation permanently closes admission for this lifetime. */
    volatile long long Serial;
    /* Fixed storage means root entry cannot allocate or wait for another CPU's lock. */
    KSW_NSVM_OWNER_SLOT Slots[KSW_NSVM_OWNER_SLOTS];
} KSW_NSVM_OWNER_TABLE;
/* Only the acquiring CPU/session retains this release authority. */
typedef struct _KSW_NSVM_LEASE {
    /* The pair binds writeback and release to the exact translated page and acquisition. */
    KSW_SVM_U64 HostPa, Token;
    /* CPU identity is Windows group:number packed as two 16-bit values, never APIC ID. */
    unsigned Slot, CpuIdentity;
} KSW_NSVM_LEASE;
/* Different L1 GPAs mapping the same HPA contend on the same permanent key. */
unsigned KswSvmNestedOwnerAcquire(KSW_NSVM_OWNER_TABLE* Table, KSW_SVM_U64 HostPa,
    unsigned CpuIdentity, KSW_NSVM_LEASE* Lease);
/* One atomic compare/exchange releases only the exact holder; stale releases cannot clear a new owner. */
int KswSvmNestedOwnerRelease(KSW_NSVM_OWNER_TABLE* Table, KSW_NSVM_LEASE* Lease);
/* Read-only quiescence check used after all native acknowledgements, never as a live rendezvous. */
int KswSvmNestedOwnersIdle(KSW_NSVM_OWNER_TABLE* Table);
/* These bounded transactions require a current lease; physical NMIs never enter the mailbox. */
int KswSvmNestedOwnerCanPark(KSW_NSVM_OWNER_TABLE* Table, const KSW_NSVM_LEASE* Lease,
    const KSW_NSVM_PENDING* Pending);
int KswSvmNestedOwnerPark(KSW_NSVM_OWNER_TABLE* Table, const KSW_NSVM_LEASE* Lease,
    KSW_NSVM_PENDING* Pending);
int KswSvmNestedOwnerRestore(KSW_NSVM_OWNER_TABLE* Table, const KSW_NSVM_LEASE* Lease,
    KSW_NSVM_PENDING* Pending);
