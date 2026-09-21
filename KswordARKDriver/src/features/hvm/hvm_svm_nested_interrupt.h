/* Translate virtual interrupt masking into a reversible, processor-private hardware overlay. */
#pragma once
#include "hvm_svm_nested_session.h"
#define KSW_NSVM_INTERRUPT_FAULT 0U
#define KSW_NSVM_INTERRUPT_RESUME 1U
#define KSW_NSVM_INTERRUPT_REFLECT 2U
#define KSW_NSVM_INTERRUPT_ACK_NMI 3U
#define KSW_NSVM_INTERRUPT_UNSUPPORTED 4U
typedef struct _KSW_NSVM_INTERRUPT_OVERLAY {
    /* Only control fields are restored; hardware guest state must never be rolled back. */
    KSW_SVM_U64 OriginalIntCtl;
    unsigned OriginalMisc1;
    /* This identity prevents applying an overlay twice without processing a hardware result. */
    unsigned Applied, ForcedMask, SuppressedVirq, Inner;
    /* Assembly consumes HostIf while physical GIF is still zero. */
    unsigned HostIf;
} KSW_NSVM_INTERRUPT_OVERLAY;
/* Caller has synchronized the physical TPR with any L1 CR8 changes made under forced masking. */
int KswSvmNestedInterruptPrepare(KSW_SVM_VMCB* Current, const KSW_NSVM_SESSION* Session,
    unsigned Gif, KSW_NSVM_INTERRUPT_OVERLAY* Overlay);
/* Call before ownership routing/VMEXIT reflection, including failed real VMRUN attempts. */
int KswSvmNestedInterruptRestore(KSW_SVM_VMCB* Current, unsigned PhysicalTpr,
    unsigned Entered, KSW_NSVM_INTERRUPT_OVERLAY* Overlay);
/* Physical INTR is never acknowledged in root. NMI acknowledgement has a separate caller. */
unsigned KswSvmNestedPhysicalEvent(const KSW_NSVM_SESSION* Session,
    unsigned Gif, KSW_SVM_U64 ExitCode, unsigned* ReflectAfterAck);
