/* Privilege, mode and storage checks for the mandatory intercepted state MSRs. */
#include "hvm_svm_nested_register.h"

/* Preserve the architecture's PAT type and reserved-bit checks independently of NPT policy. */
static unsigned KswNsvmPatValid(KSW_SVM_U64 Value)
{
    /* All eight entries are complete bytes; do not mask away reserved bits. */
    unsigned index;
    /* UC/WC/WT/WP/WB/UC-minus are the only legal encodings. */
    for (index = 0; index < 8; ++index) {
        /* Invalid memory types cause #GP even if the current mode has paging disabled. */
        unsigned type = (unsigned)((Value >> (index * 8)) & 255ULL);
        /* Types two/three and high bits are reserved. */
        if (type > 7 || type == 2 || type == 3) { return 0; }
    }
    /* This validates the register, not whether a particular NPT mapping supports the requested cache type. */
    return 1;
}

/* Root EFER.SVME stays set in executable VMCBs while the virtual bit is kept separately. */
static unsigned KswNsvmEfer(KSW_NSVM_REGISTER_IO* Io, unsigned Write, KSW_SVM_U64* Value)
{
    /* Hardware/current mode owns LMA; software SVM ownership supplies only visible SVME. */
    KSW_SVM_U64 hardware = KswSvmRead64(Io->Current, KSW_VMCB_EFER);
    /* L2 cannot accidentally inherit L1's virtual SVM availability or ownership bit. */
    KSW_SVM_U64 visible = (hardware & ~KSW_SVM_EFER_SVME) |
        ((Io->ExposeSvm && !Io->Inner) ? (Io->Svm->Efer & KSW_SVM_EFER_SVME) : 0);
    /* Reads are side-effect free and must not expose the backend's real ownership. */
    if (!Write) { *Value = visible; return KSW_NSVM_MSR_OK; }
    /* Reject genuinely reserved feature bits before evaluating mode transitions. */
    if (*Value & ~(Io->EferAllowed | (1ULL << 10))) { return KSW_NSVM_MSR_GP; }
    /* A hidden/unimplemented nested level cannot acquire real or virtual SVM. */
    if ((*Value & KSW_SVM_EFER_SVME) && (!Io->ExposeSvm || Io->Inner || (Io->Svm->VmCr & 0x10ULL))) { return KSW_NSVM_MSR_GP; }
    /* LME may change only while paging is disabled; this is not an implementation-only refusal. */
    if (((*Value ^ visible) & (1ULL << 8)) && (KswSvmRead64(Io->Current, KSW_VMCB_CR0) & (1ULL << 31))) { return KSW_NSVM_MSR_GP; }
    /* Ignore writes to the read-only long-mode-active bit and preserve the actual current mode. */
    visible = (*Value & ~(1ULL << 10)) | (hardware & (1ULL << 10));
    /* Only L1 owns this software SVM register image. */
    if (!Io->Inner) { Io->Svm->Efer = visible; }
    /* The next physical VMRUN still requires SVME in its guest save area. */
    KswSvmWrite64(Io->Current, KSW_VMCB_EFER, visible | KSW_SVM_EFER_SVME);
    /* Neither physical EFER nor HSAVE was written by the emulator. */
    return KSW_NSVM_MSR_OK;
}

/* Return OTHER only for an MSR not owned by this mandatory state-interception layer. */
unsigned KswSvmNestedRegisterAccess(KSW_NSVM_REGISTER_IO* Io, unsigned Msr,
    unsigned Write, KSW_SVM_U64* Value)
{
    /* Privilege comes from the executing image, not the root code's CPL. */
    if (!Io || !Io->Current || !Io->Svm || !Io->GuestXss || !Value || Write > 1) { return KSW_NSVM_MSR_UNSUPPORTED; }
    /* RDMSR/WRMSR do not become user-callable simply because the VMM intercepts them. */
    if (((const unsigned char*)Io->Current)[KSW_VMCB_CPL]) { return KSW_NSVM_MSR_GP; }
    /* EFER mode changes are validated and committed into the current virtual image. */
    if (Msr == KSW_SVM_MSR_EFER) { return KswNsvmEfer(Io, Write, Value); }
    /* Virtual ownership registers are unavailable to an unexposed third nesting level. */
    if (Msr == KSW_SVM_MSR_HSAVE || Msr == KSW_SVM_MSR_VM_CR) {
        /* Do not let L2 mutate the virtual host's save-area declaration. */
        if (!Io->ExposeSvm || Io->Inner) { return KSW_NSVM_MSR_GP; }
        /* Existing firmware lock/address-width policy remains authoritative. */
        return KswSvmNestedMsrAccess(Io->Svm, Msr, Write, Value);
    }
    /* XSS is switched in assembly only after leaving root C. */
    if (Msr == 0xda0U) {
        /* An absent XSAVES/XSS feature must not appear as a readable zero-valued MSR. */
        if (!(Io->XsaveFeatures & 8U)) { return KSW_NSVM_MSR_GP; }
        /* Reads report the guest's last accepted value. */
        if (!Write) { *Value = *Io->GuestXss; return KSW_NSVM_MSR_OK; }
        /* Current save-area capacity is an immutable upper bound on accepted components. */
        return KswSvmXssWrite(Io->PreparedXss, Io->XsaveFeatures, 0, *Value, Io->GuestXss) == KSW_SVM_XCR_OK ?
            KSW_NSVM_MSR_OK : KSW_NSVM_MSR_GP;
    }
    /* With NPT enabled, the currently executing guest PAT is VMCB state. */
    if (Msr == 0x277U) {
        /* Reads never use root PAT while it is temporarily restored for the exit handler. */
        if (!Write) { *Value = KswSvmRead64(Io->Current, KSW_VMCB_PAT); return KSW_NSVM_MSR_OK; }
        /* Architecture rejects reserved cache encodings. */
        if (!KswNsvmPatValid(*Value)) { return KSW_NSVM_MSR_GP; }
        /* Current NPT01 cache policy is immutable; changing its owner's PAT needs a rebuild. */
        if (!Io->Inner && *Value != Io->RootPat) { return KSW_NSVM_MSR_UNSUPPORTED; }
        /* L2 G_PAT is separate from the L1 PAT used to interpret NPT12. */
        KswSvmWrite64(Io->Current, KSW_VMCB_PAT, *Value);
        /* The hardware guest PAT load occurs on the following real VMRUN. */
        return KSW_NSVM_MSR_OK;
    }
    /* Supervisor CET continuations are not supported by the current root stack/return path. */
    if (Msr == KSW_SVM_MSR_S_CET) {
        /* Do not emulate a CET register on a CPU that did not enumerate it. */
        if (!Io->CetPresent) { return KSW_NSVM_MSR_GP; }
        /* Refuse an implementation extension explicitly instead of silently dropping its control bits. */
        if (Write && *Value) { return KSW_NSVM_MSR_UNSUPPORTED; }
        /* Admission guarantees that supervisor CET is disabled. */
        *Value = KswSvmRead64(Io->Current, KSW_VMCB_S_CET);
        /* Zero writes are idempotent under the same admission invariant. */
        return *Value ? KSW_NSVM_MSR_UNSUPPORTED : KSW_NSVM_MSR_OK;
    }
    /* The caller owns unrelated MSRs and must not guess a hardware passthrough here. */
    return KSW_NSVM_MSR_OTHER;
}
