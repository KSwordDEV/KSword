/* Observe IRET completion without emulating its stack, privilege or CET state transitions. */
#pragma once
#include "hvm_svm_arch.h"
#define KSW_NSVM_IRET_FAULT 0U
#define KSW_NSVM_IRET_CONTINUE 1U
#define KSW_NSVM_IRET_RETIRED 2U
#define KSW_NSVM_IRET_MONITOR_DB 3U
typedef struct _KSW_NSVM_IRET {
    /* Requested survives only an uncompleted, nonfaulting hardware retry. */
    unsigned Requested, Applied, Attempts;
    /* Capture controls before adding the observation intercepts. */
    unsigned Misc1, Exceptions;
    /* A different RIP is progress only because every intervening IDT delivery is intercepted. */
    KSW_SVM_U64 Rip, Flags, Dr6;
    /* Entry counters and exact last output remain diagnostic after restoring the overlay. */
    KSW_SVM_U64 Entries, LastCode;
    unsigned Completed;
} KSW_NSVM_IRET;
/* Called only after a real IRET intercept has been classified as L0-owned. */
int KswSvmNestedIretRequest(KSW_NSVM_IRET* Step);
/* Apply last, after the ordinary GIF/IRQ controls. No EVENTINJ may accompany this attempt. */
int KswSvmNestedIretArm(KSW_SVM_VMCB* Current, KSW_NSVM_IRET* Step);
/* Restore before dispatch; RETIRED does not mean the current raw exit may be discarded. */
unsigned KswSvmNestedIretObserve(KSW_SVM_VMCB* Current, KSW_NSVM_IRET* Step);
