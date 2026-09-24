/* CPU-private VMRUN transaction. Scheduling, virtual GIF and event delivery remain external. */
#pragma once
#include "hvm_svm_nested_entry.h"
#include "hvm_svm_nested_writeback.h"
#include "hvm_svm_nested_shadow.h"
#include "hvm_svm_nested_owner.h"
#include "../../../../shared/driver/KswordArkHvmNptCacheStats.h"

/* Phases describe retained ownership, not public resident capability. */
#define KSW_NSVM_SESSION_IDLE 0U
#define KSW_NSVM_SESSION_L2 1U
#define KSW_NSVM_SESSION_FAULTED 2U
/* Actions distinguish architectural return from failure of the monitor's implementation. */
#define KSW_NSVM_ACTION_ENTER 0U
#define KSW_NSVM_ACTION_RETURN 1U
#define KSW_NSVM_ACTION_INVALID 2U
#define KSW_NSVM_ACTION_UNSUPPORTED 3U
#define KSW_NSVM_ACTION_FAULT 4U

typedef struct _KSW_NSVM_SESSION {
    /* All images are owned nonpaged storage, never a mapped guest pointer. */
    KSW_SVM_VMCB Vmcb12, L1;
    /* Original inner permission maps are retained for exit ownership decisions. */
    KSW_NSVM_PERMISSION_IMAGE Permissions;
    /* Both identities bind reflection to exactly the operand captured at entry. */
    KSW_SVM_U64 OperandPa, OperandHostPa;
    /* A live lease persists across hardware execution and partial architectural writeback. */
    KSW_NSVM_LEASE Lease;
    /* Busy, exhausted and invalid ownership are retained separately from VMCB admission. */
    unsigned OwnerStatus;
    /* Virtual invalidations are distinct from assembly's physical flush-on-every-entry counter. */
    KSW_SVM_U64 Invalidations, LastInvalidationLinear, LastInvalidationEpoch;
    /* Guest ASIDs are diagnostic inputs; physical ASIDs are always owned separately by L0. */
    unsigned LastInvalidationAsid;
    /* Completion counters include only committed transitions. */
    KSW_SVM_U64 Entries, Returns, InvalidEntries;
    /* Entry failure and physical IO failure must remain distinguishable. */
    KSW_NSVM_ENTRY_RESULT Admission;
    KSW_NSVM_OPERAND_RESULT OperandResult;
    /* Caller must hold resources if a physical commit failed or L2 still owns the CPU. */
    unsigned int Phase, VirtualGif;
    KSW_SVM_U64 CacheKey[13], CacheEpoch, CacheOwnerToken;
    unsigned CacheValid;
    KSWORD_HVM_NPT_CACHE_STATS CacheStats;
} KSW_NSVM_SESSION;

typedef struct _KSW_NSVM_SESSION_IO {
    /* Trusted outer capability and translation evidence, frozen before root entry. */
    KSW_NSVM_ENTRY_POLICY Policy;
    KSW_NSVM_OPERAND_IO Operand;
    KSW_NSVM_COMMIT_VMCB Commit;
    /* One shared identity domain for all CPUs using this immutable NPT01 lifetime. */
    KSW_NSVM_OWNER_TABLE* Owners;
    /* Windows processor group:number identity frozen by prepare. */
    unsigned CpuIdentity;
    /* Optional for fixed probes; general execution persists deferred events under the VMCB lease. */
    KSW_NSVM_PENDING* Pending;
    /* Per-CPU preallocated output maps and their already validated host identities. */
    unsigned char* MergedMsr;
    unsigned char* MergedIo;
    KSW_SVM_U64 MsrPa, IoPa;
    unsigned int Asid;
    /* L0 maps are immutable; L1 cannot weaken any bit while requesting its own exits. */
    KSW_NSVM_PERMISSION_VIEW OuterPermissions;
    /* No allocation or shared-cache lock is taken by a nested transition. */
    KSW_NSHADOW* Shadow;
    KSW_NMMU_CONFIG* Mmu;
    unsigned ReuseNpt;
} KSW_NSVM_SESSION_IO;

/* Virtual instruction legality/EFER/HSAVE/GIF are checked by the dispatcher first.
   Session must start zeroed. On FAULT, preserve current image and all resources. */
unsigned int KswSvmNestedSessionEnter(KSW_NSVM_SESSION* Session,
    KSW_NSVM_SESSION_IO* Io, KSW_SVM_VMCB* Current, KSW_SVM_U64 OperandPa);
/* Reflect a real or synthesized inner-owned exit before resuming the saved L1 continuation. */
unsigned int KswSvmNestedSessionReflect(KSW_NSVM_SESSION* Session,
    const KSW_NSVM_SESSION_IO* Io, KSW_SVM_VMCB* Current);
/* VMLOAD/VMSAVE use the same translated ownership domain but never start an inner VMRUN.
   Caller checks virtual SVME/CPL/instruction legality and advances RIP only on RETURN. */
unsigned int KswSvmNestedSessionTransfer(KSW_NSVM_SESSION* Session,
    const KSW_NSVM_SESSION_IO* Io, KSW_SVM_VMCB* Current, KSW_SVM_U64 OperandPa,
    unsigned Save);
/* INVLPGA may invalidate more translations than requested. This first implementation
   discards every cached composition on this virtual CPU, independently of guest ASID. */
unsigned int KswSvmNestedSessionInvalidate(KSW_NSVM_SESSION* Session,
    KSW_NSVM_SESSION_IO* Io, KSW_SVM_U64 Linear, unsigned Asid);
