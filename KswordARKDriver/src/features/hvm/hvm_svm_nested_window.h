/* A VINTR scheduling window must never escape as a fabricated guest interrupt. */
#pragma once
#include "hvm_svm_arch.h"
typedef struct _KSW_NSVM_IRQ_WINDOW {
    /* Save executable controls after the ordinary GIF/masking overlay was applied. */
    KSW_SVM_U64 IntCtl, Token;
    unsigned Misc1, Applied;
} KSW_NSVM_IRQ_WINDOW;
/* Original virtual IRQ may run only when no acknowledged queued event is currently eligible. */
int KswSvmNestedPreferVirq(const KSW_SVM_VMCB* Current, KSW_SVM_U64 QueuedEvent);
/* Supports a queued maskable event while preserving original V_IRQ and EVENTINJ ownership. */
int KswSvmNestedIrqWindowArm(KSW_SVM_VMCB* Current, KSW_SVM_U64 Event,
    KSW_SVM_U64 Token, KSW_NSVM_IRQ_WINDOW* Window);
/* Restore before the ordinary masking overlay, whether or not VINTR caused the exit. */
int KswSvmNestedIrqWindowRestore(KSW_SVM_VMCB* Current, KSW_NSVM_IRQ_WINDOW* Window,
    unsigned* WindowExit);
