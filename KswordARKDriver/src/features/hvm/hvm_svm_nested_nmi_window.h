/* CPU-private NMI eligibility observation, separate from the IRET service-mask observer. */
#pragma once
#include "hvm_svm_arch.h"
#define KSW_NSVM_NMI_WINDOW_FAULT 0U
#define KSW_NSVM_NMI_WINDOW_EXIT 1U
#define KSW_NSVM_NMI_WINDOW_DB 2U
typedef struct _KSW_NSVM_NMI_WINDOW {
    /* An unchanged acknowledgement identity bounds repeated observation attempts. */
    KSW_SVM_U64 Token, Flags, Dr6, Rip, Event, Entries, LastCode;
    /* Original ownership controls are restored before normal exception/interrupt dispatch. */
    unsigned Exceptions, Misc1, Applied, Attempts;
} KSW_NSVM_NMI_WINDOW;
/* Preserve any existing EVENTINJ; never inject the waiting NMI over another event. */
int KswSvmNestedNmiWindowArm(KSW_SVM_VMCB* Current, KSW_SVM_U64 Token,
    KSW_NSVM_NMI_WINDOW* Window);
/* Only a monitor-created BS trap may be consumed; real exits continue ordinary dispatch. */
unsigned KswSvmNestedNmiWindowRestore(KSW_SVM_VMCB* Current, KSW_NSVM_NMI_WINDOW* Window);
