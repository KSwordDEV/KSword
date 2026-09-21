/* APM 15.21: V_INTR_MASKING selects saved host IF and changes CR8 virtualization. */
#include "hvm_svm_nested_interrupt.h"

/* The executable VMCB is overlaid only after all ordinary exit mutations finish. */
int KswSvmNestedInterruptPrepare(KSW_SVM_VMCB* Current, const KSW_NSVM_SESSION* Session,
    unsigned Gif, KSW_NSVM_INTERRUPT_OVERLAY* Overlay)
{
    /* Preserve the original control vector for subsequent ownership decisions. */
    KSW_SVM_U64 control;
    /* Intercept bits must not be reinterpreted through an already merged/modified snapshot. */
    unsigned misc, inner;
    /* A failed transaction never authorizes interrupt reentry. */
    if (!Current || !Session || !Overlay || Overlay->Applied || Gif > 1 ||
        Session->Phase == KSW_NSVM_SESSION_FAULTED) { return 0; }
    /* VMRUN sets the inner GIF; no unimplemented deeper CLGI is admitted. */
    inner = Session->Phase == KSW_NSVM_SESSION_L2;
    /* An L2 image with software GIF cleared has no supported hardware representation here. */
    if (inner && !Gif) { return 0; }
    /* The original word includes L1's V_IRQ/vector/priority and masking request. */
    control = KswSvmRead64(Current, KSW_VMCB_INTCTL);
    /* Read the dword without touching adjacent miscellaneous intercepts. */
    misc = (unsigned)KswSvmRead64(Current, KSW_VMCB_MISC1);
    /* L1 is the existing Windows execution context, without a separately virtualized APIC. */
    if (!inner && (control & (1ULL << 24))) { return 0; }
    /* Capture exact ownership before changing executable controls. */
    Overlay->OriginalIntCtl = control; Overlay->OriginalMisc1 = misc;
    /* No bits are suppressed on an ordinary, open-GIF entry. */
    Overlay->ForcedMask = Overlay->SuppressedVirq = 0; Overlay->Inner = inner;
    /* With the inner masking bit set, saved L1 IF controls physical interrupts. */
    Overlay->HostIf = inner && (control & (1ULL << 24)) &&
        (KswSvmRead64(&Session->L1, KSW_VMCB_RFLAGS) & (1ULL << 9));
    /* Closed L1 GIF must mask physical interrupts even if L1 executes STI. */
    if (!Gif) {
        /* V_INTR_MASKING with host IF=0 supplies physical INTR masking independently of guest IF. */
        control |= 1ULL << 24; Overlay->ForcedMask = 1; Overlay->HostIf = 0;
        /* Virtual IRQs also wait for virtual STGI, regardless of the guest's IF. */
        Overlay->SuppressedVirq = (unsigned)((control >> 8) & 1ULL); control &= ~(1ULL << 8);
        /* NMI is intercepted for acknowledgement/retention instead of entering the closed-GIF guest. */
        misc |= 1U << 1;
    }
    /* Do not alter V_TPR: the platform prepared it from real or virtual CR8 as appropriate. */
    KswSvmWrite64(Current, KSW_VMCB_INTCTL, control);
    /* Original intercept ownership remains in Overlay until the real VMEXIT is processed. */
    KswSvmWrite32(Current, KSW_VMCB_MISC1, misc);
    /* Publish last; double prepare is rejected until Restore consumes this attempt. */
    Overlay->Applied = 1; return 1;
}

/* Only hardware-updated V_TPR/V_IRQ survive into the original virtual control contract. */
int KswSvmNestedInterruptRestore(KSW_SVM_VMCB* Current, unsigned PhysicalTpr,
    unsigned Entered, KSW_NSVM_INTERRUPT_OVERLAY* Overlay)
{
    /* Original control bits never come from a guest-controlled raw pointer. */
    KSW_SVM_U64 output, restored;
    /* No missing/duplicate completion may remove someone else's active overlay. */
    if (!Current || !Overlay || !Overlay->Applied || PhysicalTpr > 15 || Entered > 1) { return 0; }
    /* A physical INVALID did not execute any guest CR8 or dispatch any virtual IRQ. */
    restored = Overlay->OriginalIntCtl;
    /* Actual hardware entry may have changed the two architecturally saved output fields. */
    if (Entered) {
        /* Preserve the dynamic fields before replacing the executable mask. */
        output = KswSvmRead64(Current, KSW_VMCB_INTCTL);
        /* Without masking, real APIC.TPR is authoritative even if no guest CR8 write occurred. */
        if (!(Overlay->OriginalIntCtl & (1ULL << 24)) && !Overlay->ForcedMask) {
            /* This repairs the initially loaded V_TPR value when physical CR8 was already nonzero. */
            output = (output & ~15ULL) | PhysicalTpr;
        }
        /* A suppressed request could not have been dispatched by this hardware entry. */
        if (Overlay->SuppressedVirq) { output |= 1ULL << 8; }
        /* Reconstruct only architectural output bits; keep vector, priority and mask from the owner. */
        restored = (restored & ~0x10fULL) | (output & 0x10fULL);
    }
    /* Original MISC1 is restored before routing physical or virtual exits. */
    KswSvmWrite32(Current, KSW_VMCB_MISC1, Overlay->OriginalMisc1);
    /* L1 never observes the monitor's temporary masking control in its reflected VMCB. */
    KswSvmWrite64(Current, KSW_VMCB_INTCTL, restored);
    /* The metadata remains diagnostic, but no executable overlay remains outstanding. */
    Overlay->Applied = 0; return 1;
}

/* Classify pending physical events without consuming them or advancing guest RIP. */
unsigned KswSvmNestedPhysicalEvent(const KSW_NSVM_SESSION* Session,
    unsigned Gif, KSW_SVM_U64 ExitCode, unsigned* ReflectAfterAck)
{
    /* The route must use the source VMCB12 and not the temporary overlay. */
    unsigned inner, requested;
    /* Outputs are explicit even for rejected physical events. */
    if (!Session || !ReflectAfterAck || Gif > 1) { return KSW_NSVM_INTERRUPT_FAULT; }
    /* A previous NMI reflection decision cannot leak into this event. */
    *ReflectAfterAck = 0;
    /* Faulted sessions cannot receive additional architectural transitions. */
    if (Session->Phase == KSW_NSVM_SESSION_FAULTED) { return KSW_NSVM_INTERRUPT_FAULT; }
    /* Physical INIT/SMI need platform-specific semantics; never issue blind STGI or fake completion. */
    if (ExitCode == 0x62 || ExitCode == 0x63) { return KSW_NSVM_INTERRUPT_UNSUPPORTED; }
    /* This helper is not an instruction/exception/virtual-interrupt dispatcher. */
    if (ExitCode != 0x60 && ExitCode != 0x61) { return KSW_NSVM_INTERRUPT_FAULT; }
    /* No deeper nesting is admitted by the current execution contract. */
    inner = Session->Phase == KSW_NSVM_SESSION_L2;
    /* An L1-owned event must be reflected before any handler executes at the wrong level. */
    requested = inner ? KswSvmNestedInterceptRequested(&Session->Vmcb12, ExitCode) : 0;
    /* A physical INTR intercept is left pending in APIC; virtual VMEXIT closes L1 GIF. */
    if (ExitCode == 0x60) {
        /* No root INTACK/EOI occurs; STGI in the resumed L1 will permit normal Windows delivery. */
        return requested == 1 ? KSW_NSVM_INTERRUPT_REFLECT : KSW_NSVM_INTERRUPT_FAULT;
    }
    /* NMI interception does not acknowledge it, so simply returning would immediately exit again. */
    if (requested == 1 || (!inner && !Gif)) {
        /* The caller must first capture the physical NMI and retain its acknowledgement. */
        *ReflectAfterAck = requested == 1; return KSW_NSVM_INTERRUPT_ACK_NMI;
    }
    /* An unexpected NMI exit must not invent an event owner or consume a pending hardware NMI. */
    return KSW_NSVM_INTERRUPT_FAULT;
}
