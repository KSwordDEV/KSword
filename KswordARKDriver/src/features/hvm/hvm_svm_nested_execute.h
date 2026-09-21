/* General nested exit engine. Platform event delivery/physical acknowledgement is a separate layer. */
#pragma once
#include "hvm_svm_nested_session.h"
#include "hvm_svm_nested_route.h"
#include "hvm_svm_nested_register.h"
#include "hvm_svm_nested_cpuid.h"
#include "hvm_svm_nested_event.h"
/* Callers may issue VMRUN only for an explicit RESUME action after event preparation. */
#define KSW_NSVM_EXEC_RESUME 0U
#define KSW_NSVM_EXEC_FAULT 1U
#define KSW_NSVM_EXEC_UNSUPPORTED 2U
#define KSW_NSVM_EXEC_PHYSICAL_EVENT 3U
#define KSW_NSVM_EXEC_SHUTDOWN 4U
#define KSW_NSVM_EXEC_GIF_CHANGED 5U
/* Root-private state; every pointer refers to preallocated storage owned by this CPU/lifetime. */
typedef struct _KSW_NSVM_EXECUTION {
    /* Current image and nonautomatic general registers change together. */
    KSW_SVM_VMCB* Current;
    KSW_SVM_U64* Gpr;
    /* Existing general transactions retain operand ownership and current L1 continuation. */
    KSW_NSVM_SESSION* Session;
    KSW_NSVM_SESSION_IO* Io;
    /* Shared-mode state follows hardware's nonautomatic XCR0/XSS behavior. */
    KSW_SVM_U64* GuestXcr0;
    KSW_SVM_U64 PreparedXcr0;
    /* The register policy includes virtual EFER/HSAVE, guest XSS and root cache limits. */
    KSW_NSVM_REGISTER_IO Registers;
    /* Raw leaf access is processor-pinned and does not allocate. */
    KSW_NSVM_CPUID_POLICY Cpuid;
    /* Composed translations use a CPU-private physical window. */
    KSW_NMMU_IO MmuIo;
    /* Software GIF is committed by the event layer before the next VMRUN. */
    unsigned Gif, GifRequested;
    /* Consecutive unresolved NPFs are bounded; successful cache installs reset this counter. */
    unsigned NpfRetries;
    /* Physical-event action leaves raw evidence intact for its platform owner. */
    KSW_NSVM_EXIT_ROUTE Route;
    KSW_NMMU_RESULT Translation;
    KSW_NSVM_EVENT_PLAN Exception;
    /* Acknowledged interrupted events cannot be lost when raising a replacement exception. */
    KSW_SVM_U64 Deferred[16];
    unsigned DeferredCount;
    /* Cache recycling is deliberate, bounded by preallocated capacity and always followed by flush. */
    KSW_SVM_U64 CacheRecycles;
} KSW_NSVM_EXECUTION;
/* Do not call on a fixed probe merely to skip its evidence/marker checks.
   Physical-event/GIF_CHANGED are requests to the platform arbiter, never permission to reenter. */
unsigned KswSvmNestedExecute(KSW_NSVM_EXECUTION* Execution);
/* Commit a GIF instruction only after the platform can enforce its physical and virtual masking. */
unsigned KswSvmNestedCommitGif(KSW_NSVM_EXECUTION* Execution);
