/* AMD APM 15.5/15.6/15.20/15.25.4; admission is independent of execution policy. */
#include "hvm_svm_nested_entry.h"

/* Small byte copy keeps this portable core free of kernel or runtime dependencies. */
static void KswNsvmEntryCopy(void* Destination, const void* Source, unsigned int Size)
{
    /* Callers supply distinct images, or exactly the same address. */
    unsigned int index;
    /* All copied bytes belong to preallocated nonpageable snapshots. */
    for (index = 0; index < Size; ++index) { ((unsigned char*)Destination)[index] = ((const unsigned char*)Source)[index]; }
}

/* Preserve the reason for a refusal separately from whether it was architectural. */
static unsigned int KswNsvmEntryFail(KSW_NSVM_ENTRY_RESULT* Result,
    unsigned int Status, unsigned int Offset, KSW_SVM_U64 Value)
{
    /* Diagnostics are optional; status is always returned directly. */
    if (Result) { Result->Status = Status; Result->Offset = Offset; Result->Value = Value; }
    /* No VMCB or guest state is modified during validation. */
    return Status;
}

/* Read control dwords without assuming compiler bitfield encoding. */
static unsigned int KswNsvmEntryRead32(const KSW_SVM_VMCB* Vmcb, unsigned int Offset)
{
    /* Byte decoding also works for unaligned private snapshots. */
    const unsigned char* bytes = (const unsigned char*)Vmcb + Offset;
    /* The AMD control image is little endian. */
    return (unsigned int)bytes[0] | ((unsigned int)bytes[1] << 8) |
        ((unsigned int)bytes[2] << 16) | ((unsigned int)bytes[3] << 24);
}

/* EVENTINJ invalid cases are not interchangeable with unsupported software features. */
static unsigned int KswNsvmEntryEvent(KSW_SVM_U64 Event, unsigned int LongCode)
{
    /* Vector is ignored for NMI; do not require a particular vector value. */
    unsigned int type = (unsigned int)((Event >> 8) & 7ULL);
    /* The valid bit gates the entire event record, including otherwise stale fields. */
    unsigned int vector = (unsigned int)(Event & 255ULL);
    /* Hardware ignores a disabled event. */
    if (!(Event & (1ULL << 31))) { return KSW_NSVM_ENTRY_OK; }
    /* Only external interrupt, NMI, exception and software interrupt are defined. */
    if (type != 0U && type != 2U && type != 3U && type != 4U) { return KSW_NSVM_ENTRY_INVALID; }
    /* Exception vector two is NMI, and values beyond 31 are not exceptions. */
    if (type == 3U && (vector == 2U || vector > 31U)) { return KSW_NSVM_ENTRY_INVALID; }
    /* BOUND has no 64-bit-mode exception to inject. */
    if (type == 3U && vector == 5U && LongCode) { return KSW_NSVM_ENTRY_INVALID; }
    /* Reserved event bits are unsupported input, not discarded silently. */
    if (Event & 0x7ffff000ULL) { return KSW_NSVM_ENTRY_UNSUPPORTED; }
    /* Error-code semantics and normal delivery are left to the hardware event engine. */
    return KSW_NSVM_ENTRY_OK;
}

/* Validate an immutable snapshot before replacing any live L1 execution state. */
unsigned int KswSvmNestedValidateEntry(const KSW_SVM_VMCB* Inner,
    const KSW_NSVM_ENTRY_POLICY* Policy, KSW_NSVM_ENTRY_RESULT* Result)
{
    /* Keep raw register values for exact field diagnostics. */
    KSW_SVM_U64 cr0, cr4, efer, value, mask, base;
    /* PAT has eight entries; control bytes are inspected only within fixed ranges. */
    unsigned int index, asid, eventStatus, longCode;
    /* A null image or absent capability contract is a software admission failure. */
    if (!Inner || !Policy || !(mask = KswNptAddressMask(Policy->PhysicalBits)) || Policy->AsidCount < 2U) {
        /* No register from an invalid source was read. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, 0, 0);
    }
    /* Automatic state fields are owned byte images, not raw physical operands. */
    cr0 = KswSvmRead64(Inner, KSW_VMCB_CR0); cr4 = KswSvmRead64(Inner, KSW_VMCB_CR4);
    /* EFER.SVME is required even when the L2 CPUID hides further nesting. */
    efer = KswSvmRead64(Inner, KSW_VMCB_EFER);
    /* Architecture disallows NW without CD and any CR0 high dword. */
    if ((cr0 >> 32) || ((cr0 & 0x20000000ULL) && !(cr0 & 0x40000000ULL))) {
        /* Return the field that failed rather than a generic failed-VMRUN code. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_CR0, cr0);
    }
    /* Disabling SVM in the inner save area makes hardware entry invalid. */
    if (!(efer & KSW_SVM_EFER_SVME)) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_EFER, efer); }
    /* Long-mode paging requires protected mode and PAE. Paged real mode itself is legal. */
    if ((efer & 0x100ULL) && (cr0 & 0x80000000ULL) && (!(cr0 & 1ULL) || !(cr4 & 0x20ULL))) {
        /* This is a documented mode consistency failure. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_CR4, cr4);
    }
    /* A 64-bit code segment cannot simultaneously select the legacy default operand size. */
    longCode = (efer & 0x100ULL) && (cr0 & 0x80000000ULL) && (cr4 & 0x20ULL) &&
        (((const unsigned char*)Inner)[KSW_VMCB_CS + 3U] & 2U);
    /* Attribute bits L and D are bits 9 and 10 in AMD's segment encoding. */
    if (longCode && (((const unsigned char*)Inner)[KSW_VMCB_CS + 3U] & 4U)) {
        /* RIP canonicality is deliberately NOT an entry consistency check. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_CS,
            KswNsvmEntryRead32(Inner, KSW_VMCB_CS));
    }
    /* CET requires supervisor write protection when enabled through CR4. */
    if ((cr4 & (1ULL << 23)) && !(cr0 & (1ULL << 16))) {
        /* Preserve the actual guest CR0; never repair it by turning WP on. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_CR0, cr0);
    }
    /* Both debug registers have an architecturally reserved high dword. */
    for (index = KSW_VMCB_DR7; index <= KSW_VMCB_DR6; index += 8U) {
        /* VMCB DR7 precedes DR6 in the automatic state area. */
        value = KswSvmRead64(Inner, index);
        /* Do not silently truncate rejected debug state. */
        if (value >> 32) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, index, value); }
    }
    /* An inner VMM must intercept VMRUN instead of delegating a third level to hardware. */
    if (!(KswNsvmEntryRead32(Inner, KSW_VMCB_MISC2) & 1U)) {
        /* Without this bit AMD defines VMEXIT_INVALID. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_MISC2, KswNsvmEntryRead32(Inner, KSW_VMCB_MISC2));
    }
    /* ASID namespaces are per virtual CPU; zero is reserved for its virtual host. */
    asid = KswNsvmEntryRead32(Inner, KSW_VMCB_ASID);
    /* Out-of-range ASIDs cannot be translated into a valid hardware context. */
    if (!KswSvmAsidValid(Policy->AsidCount, asid)) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_ASID, asid); }
    /* Validate whole map allocations while honoring ignored low base bits. */
    if (!KswSvmNestedMapAddress(KswSvmRead64(Inner, KSW_VMCB_MSRPM), KSW_NSVM_MSRPM_BYTES, Policy->PhysicalBits, &base)) {
        /* A valid merged host pointer must not conceal an invalid virtual map range. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_MSRPM, KswSvmRead64(Inner, KSW_VMCB_MSRPM));
    }
    /* Apply the same range contract to IOPM's third hardware page. */
    if (!KswSvmNestedMapAddress(KswSvmRead64(Inner, KSW_VMCB_IOPM), KSW_NSVM_IOPM_BYTES, Policy->PhysicalBits, &base)) {
        /* Memory readability is checked separately by operand capture. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_IOPM, KswSvmRead64(Inner, KSW_VMCB_IOPM));
    }
    /* The first general builder uses composed NPT, not shadow guest CR3 paging. */
    value = KswSvmRead64(Inner, KSW_VMCB_NP);
    /* SEV and other extended nested-control modes require separate state contracts. */
    if (value != 1ULL) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_NP, value); }
    /* NCR3's frame must fit the advertised virtual physical width. */
    value = KswSvmRead64(Inner, KSW_VMCB_NCR3);
    /* The current software walker does not implement NCR3 cache-control bits. */
    if (value & ~mask) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_NCR3, value); }
    /* Nested paging loads guest PAT, including validation of all eight entries. */
    value = KswSvmRead64(Inner, KSW_VMCB_PAT);
    /* Types 2 and 3, or nonzero reserved bits, are architecturally invalid. */
    for (index = 0; index < 8U; ++index) {
        /* Extract one complete byte so reserved bits are not hidden by masking. */
        unsigned int type = (unsigned int)((value >> (8U * index)) & 255ULL);
        /* Legal PAT types are UC, WC, WT, WP, WB and UC-minus. */
        if (type > 7U || type == 2U || type == 3U) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_INVALID, KSW_VMCB_PAT, value); }
    }
    /* Validate only events marked valid; failed injection must not enter L2. */
    value = KswSvmRead64(Inner, KSW_VMCB_EVENT);
    /* Keep unsupported software bits separate from the documented invalid-event cases. */
    eventStatus = KswNsvmEntryEvent(value, longCode);
    /* Do not replace a requested exception with an unrelated synthetic event. */
    if (eventStatus) { return KswNsvmEntryFail(Result, eventStatus, KSW_VMCB_EVENT, value); }
    /* Supported subsets remain explicit until the complete state-switch contract exists. */
    if (efer & ~Policy->EferSupported) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_EFER, efer); }
    /* Do not turn an implementation restriction into an apparent firmware refusal. */
    if (cr4 & ~Policy->Cr4Supported) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_CR4, cr4); }
    /* Supervisor CET still requires a separate host shadow-stack continuation. */
    value = KswSvmRead64(Inner, KSW_VMCB_S_CET);
    /* User CET can remain handled by the existing XSTATE save/restore path. */
    if (value) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_S_CET, value); }
    /* LBR/virtual-VMLOAD controls are outside this initial composed-state builder. */
    value = KswSvmRead64(Inner, 0x0b8U);
    /* Reject rather than ignoring extension semantics requested by the inner VMM. */
    if (value) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, 0x0b8U, value); }
    /* New intercept words are not automatically part of our advertised capabilities. */
    value = KswNsvmEntryRead32(Inner, 0x014U);
    /* The two baseline miscellaneous words are implemented by the exit classifier. */
    if (value) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, 0x014U, value); }
    /* Debug-control virtualization is separate from ordinary DR6/DR7 state. */
    value = KswSvmRead64(Inner, KSW_VMCB_DEBUGCTL);
    /* Do not inherit L0 debug controls in place of a requested inner debug mode. */
    if (value) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_DEBUGCTL, value); }
    /* The baseline handles only AMD's documented flush request values. */
    value = ((const unsigned char*)Inner)[KSW_VMCB_TLB];
    /* Reserved encodings cannot silently become full flush requests. */
    if (value != 0 && value != 1 && value != 3 && value != 7) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_TLB, value); }
    /* Only the ordinary interrupt-shadow state is supported by this builder. */
    value = KswSvmRead64(Inner, 0x068U);
    /* Extended blocking state requires a matching interrupt implementation. */
    if (value & ~1ULL) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, 0x068U, value); }
    /* Virtual interrupt/APIC extensions need a dedicated pending-event state machine. */
    value = KswSvmRead64(Inner, KSW_VMCB_INTCTL);
    /* Baseline V_TPR/V_IRQ/priority/masking/vector bits are representable here. */
    if (value & ~0x000000ff011f010fULL) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_INTCTL, value); }
    /* Success resets any diagnostics from a previous rejected operand. */
    return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_OK, 0, 0);
}

/* Build from two owned snapshots; the destination may alias Outer, but not Inner. */
unsigned int KswSvmNestedBuildEntry(KSW_SVM_VMCB* Destination,
    const KSW_SVM_VMCB* Outer, const KSW_SVM_VMCB* Inner,
    const KSW_NSVM_ENTRY_POLICY* Policy, KSW_SVM_U64 RootPa,
    KSW_SVM_U64 MsrPa, KSW_SVM_U64 IoPa, unsigned int Asid,
    KSW_NSVM_ENTRY_RESULT* Result)
{
    /* Keep host-pointer failures separate from invalid virtual guest controls. */
    KSW_SVM_U64 base;
    /* Intercept words cover CR/DR/exception and the two baseline misc vectors. */
    unsigned int offset, status;
    /* Reject incomplete inputs without modifying the executable destination. */
    if (!Destination || !Outer || Destination == Inner) { return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, 0, 0); }
    /* The VMCB12 must pass before any source field is copied into VMCB02. */
    status = KswSvmNestedValidateEntry(Inner, Policy, Result);
    /* Both invalid state and unsupported features leave L1 runnable. */
    if (status) { return status; }
    /* Hardware frame addresses are owned and strictly aligned, not normalized guest inputs. */
    if (!RootPa || (RootPa & ~KswNptAddressMask(Policy->PhysicalBits)) ||
        (MsrPa & 4095ULL) || (IoPa & 4095ULL) || !KswSvmAsidValid(Policy->AsidCount, Asid) ||
        !KswSvmNestedMapAddress(MsrPa, KSW_NSVM_MSRPM_BYTES, Policy->PhysicalBits, &base) ||
        !KswSvmNestedMapAddress(IoPa, KSW_NSVM_IOPM_BYTES, Policy->PhysicalBits, &base)) {
        /* No attacker-provided physical control pointer is passed through. */
        return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_UNSUPPORTED, KSW_VMCB_NCR3, RootPa);
    }
    /* Preserve VMLOAD-owned state and outer-only controls from the current L1 image. */
    KswNsvmEntryCopy(Destination, Outer, sizeof(*Destination));
    /* VMRUN switches only the documented automatic subset. */
    KswSvmNestedCopyVmrun(Destination, Inner, 1);
    /* Every L0 intercept remains active regardless of the inner permission request. */
    for (offset = 0; offset < 0x014U; offset += 4U) {
        /* Source controls have not been altered by the automatic-state copy. */
        KswSvmWrite32(Destination, offset, KswNsvmEntryRead32(Outer, offset) | KswNsvmEntryRead32(Inner, offset));
    }
    /* TSC offsets compose modulo 2^64, matching architectural offset addition. */
    KswSvmWrite64(Destination, 0x050U, KswSvmRead64(Outer, 0x050U) + KswSvmRead64(Inner, 0x050U));
    /* A separate interrupt arbiter must account for these inner virtual controls. */
    KswSvmWrite64(Destination, KSW_VMCB_INTCTL, KswSvmRead64(Inner, KSW_VMCB_INTCTL));
    /* Interrupt shadow belongs to the resumed inner guest, not the outer host. */
    KswSvmWrite64(Destination, 0x068U, KswSvmRead64(Inner, 0x068U) & 1ULL);
    /* Inject exactly the validated inner event, including its error code if present. */
    KswSvmWrite64(Destination, KSW_VMCB_EVENT, KswSvmRead64(Inner, KSW_VMCB_EVENT));
    /* Software-interrupt injection uses the requested inner next RIP. */
    KswSvmWrite64(Destination, KSW_VMCB_NRIP, KswSvmRead64(Inner, KSW_VMCB_NRIP));
    /* NPT02, never the inner VMM's raw NCR3, is given to hardware. */
    KswSvmWrite64(Destination, KSW_VMCB_NCR3, RootPa);
    /* Permission-map composition completed before this builder is called. */
    KswSvmWrite64(Destination, KSW_VMCB_MSRPM, MsrPa); KswSvmWrite64(Destination, KSW_VMCB_IOPM, IoPa);
    /* Virtual ASIDs are never directly used as hardware allocation identities. */
    KswSvmWrite32(Destination, KSW_VMCB_ASID, Asid);
    /* A full flush handles both source changes and virtual ASID reuse conservatively. */
    ((unsigned char*)Destination)[KSW_VMCB_TLB] = 1;
    /* No hardware clean-cache state is inherited from the untrusted source image. */
    KswSvmWrite32(Destination, KSW_VMCB_CLEAN, 0);
    /* Caller still owns entry publication, GIF handling and the actual VMRUN. */
    return KswNsvmEntryFail(Result, KSW_NSVM_ENTRY_OK, 0, 0);
}

/* Invalid-entry reflection preserves unexecuted save state but consumes EVENTINJ on VMEXIT. */
void KswSvmNestedInvalidExit(KSW_SVM_VMCB* Inner)
{
    /* VMEXIT_INVALID is a full-width architectural value, not an Intel exit index. */
    KswSvmWrite64(Inner, KSW_VMCB_EXITCODE, KSW_SVM_EXIT_INVALID);
    /* Invalid VMRUN also returns with no pending injection request or stale error-code payload. */
    KswSvmWrite64(Inner, KSW_VMCB_EVENT, 0);
    /* These undefined exit operands are deterministically zeroed without leaking host state. */
    KswSvmWrite64(Inner, KSW_VMCB_EXITINFO1, 0); KswSvmWrite64(Inner, KSW_VMCB_EXITINFO2, 0);
    /* No guest event started delivery during this software-rejected entry. */
    KswSvmWrite64(Inner, KSW_VMCB_EXITINTINFO, 0);
}

/* Resume the actual L1 VMRUN continuation, never the monitor's launch-time snapshot. */
void KswSvmNestedRestoreL1(KSW_SVM_VMCB* Destination, KSW_SVM_VMCB* SavedL1,
    const KSW_SVM_VMCB* CurrentL2)
{
    /* VMLOAD-managed registers remain at their current guest values after VMEXIT. */
    KswSvmNestedCopyVmload(SavedL1, CurrentL2);
    /* CR2 and DR6 are not restored by the architectural virtual-host return. */
    KswSvmWrite64(SavedL1, KSW_VMCB_CR2, KswSvmRead64(CurrentL2, KSW_VMCB_CR2));
    /* Keep the inner execution's latest debug status rather than an old L1 snapshot. */
    KswSvmWrite64(SavedL1, KSW_VMCB_DR6, KswSvmRead64(CurrentL2, KSW_VMCB_DR6));
    /* Restore L1 core state and L0-owned execution controls, including its original RAX. */
    KswNsvmEntryCopy(Destination, SavedL1, sizeof(*Destination));
    /* Hardware VMEXIT forces protected mode and privilege level zero. */
    KswSvmWrite64(Destination, KSW_VMCB_CR0, KswSvmRead64(Destination, KSW_VMCB_CR0) | 1ULL);
    /* Virtual-x86 mode is cleared, and completion of VMRUN consumes RF. */
    KswSvmWrite64(Destination, KSW_VMCB_RFLAGS, KswSvmRead64(Destination, KSW_VMCB_RFLAGS) & ~0x30000ULL);
    /* Debug breakpoint enables are reset as required for the virtual host. */
    KswSvmWrite64(Destination, KSW_VMCB_DR7, 0x400ULL);
    /* The caller tracks virtual GIF=0 separately from the real host's GIF. */
    ((unsigned char*)Destination)[KSW_VMCB_CPL] = 0;
}
