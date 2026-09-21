/* General operand/continuation transaction; no probe address, marker or original snapshot. */
#include "hvm_svm_nested_session.h"

/* Retain map-read diagnostics without changing the separately bound VMCB identity. */
typedef struct _KSW_NSVM_CAPTURE_CONTEXT {
    /* Both pointers remain valid for the bounded capture call on this root stack. */
    const KSW_NSVM_SESSION_IO* Io;
    KSW_NSVM_SESSION* Session;
} KSW_NSVM_CAPTURE_CONTEXT;

/* Copy owned pages without depending on a kernel runtime library in portable tests. */
static void KswNsvmSessionCopy(KSW_SVM_VMCB* To, const KSW_SVM_VMCB* From)
{
    /* Byte access supports compiler-independent VMCB packing. */
    unsigned int index;
    /* No input here is a transient physical-window pointer. */
    for (index = 0; index < sizeof(*To); ++index) { ((unsigned char*)To)[index] = ((const unsigned char*)From)[index]; }
}

/* Permission capture uses the same NPT01 translator as the VMCB capture. */
static int KswNsvmSessionReadMap(void* Context, KSW_SVM_U64 Pa, unsigned char* Page)
{
    /* The descriptor lives on the current root stack while the callback executes. */
    const KSW_NSVM_CAPTURE_CONTEXT* capture = Context;
    /* Map capture treats unreadable pages as failures, never empty bitmaps. */
    return KswSvmNestedReadOperandPage(&capture->Io->Operand, Pa, Page,
        &capture->Session->OperandResult) == KSW_NNPT_OK;
}

/* Retain guest state and ownership after a transition can no longer complete. */
static unsigned int KswNsvmSessionFault(KSW_NSVM_SESSION* Session)
{
    /* Recovery is owned by the resident lifecycle, not a launch-time Windows snapshot. */
    Session->Phase = KSW_NSVM_SESSION_FAULTED;
    /* The caller must not infer native execution or release resources. */
    return KSW_NSVM_ACTION_FAULT;
}

/* Capture the actual virtual host continuation, including special VMRUN RAX/RSP state. */
static void KswNsvmSessionSaveL1(KSW_NSVM_SESSION* Session, const KSW_SVM_VMCB* Current)
{
    /* This snapshot is made per VMRUN, not once at monitor startup. */
    KswNsvmSessionCopy(&Session->L1, Current);
    /* VMRUN resumes at the next instruction after a later virtual VMEXIT. */
    KswSvmWrite64(&Session->L1, KSW_VMCB_RIP, KswSvmRead64(Current, KSW_VMCB_NRIP));
    /* An event preceding the intercepted VMRUN already completed; do not inject it twice. */
    KswSvmWrite64(&Session->L1, KSW_VMCB_EVENT, 0);
}

/* Bind each transaction to one arbitrary translated operand and one processor-private cache. */
unsigned int KswSvmNestedSessionEnter(KSW_NSVM_SESSION* Session,
    KSW_NSVM_SESSION_IO* Io, KSW_SVM_VMCB* Current, KSW_SVM_U64 OperandPa)
{
    /* A valid permission view is derived only from a completed private capture. */
    KSW_NSVM_PERMISSION_VIEW inner;
    /* Keep the exact failed permission-page identity in transaction diagnostics. */
    KSW_NSVM_CAPTURE_CONTEXT capture;
    /* Keep software validation status distinct from an eventual hardware exit. */
    unsigned int status;
    /* No partial context is allowed to reach entry preparation. */
    if (!Session || !Io || !Current || !Io->Commit || !Io->MergedMsr || !Io->MergedIo ||
        !Io->Shadow || !Io->Mmu || !Io->Shadow->Pages || !Io->Shadow->Capacity) { return KSW_NSVM_ACTION_UNSUPPORTED; }
    /* Neither reentrant entry nor a previous failed writeback can replace an owner. */
    if (Session->Phase != KSW_NSVM_SESSION_IDLE) { return KSW_NSVM_ACTION_FAULT; }
    /* A stale/missing hardware NRIP cannot be turned into an invented L1 continuation. */
    if (!KswSvmNextRipValid(KswSvmRead64(Current, KSW_VMCB_RIP), KswSvmRead64(Current, KSW_VMCB_NRIP))) {
        /* State is retained for diagnosis; the instruction has not completed. */
        return KswNsvmSessionFault(Session);
    }
    /* Old permission evidence is invalid even if the next operand capture fails. */
    Session->Permissions.Ready = 0;
    /* Capture a complete VMCB using the trusted outer physical/cache contract. */
    status = KswSvmNestedReadOperandPage(&Io->Operand, OperandPa,
        (unsigned char*)&Session->Vmcb12, &Session->OperandResult);
    /* This is a monitor memory failure, not an invented architectural INVALID. */
    if (status != KSW_NNPT_OK) { return KswNsvmSessionFault(Session); }
    /* Save identities independently from later map reads or writeback diagnostics. */
    Session->OperandPa = OperandPa; Session->OperandHostPa = Session->OperandResult.HostPa;
    /* Replacing untrusted controls with valid host pointers must not hide invalid guest input. */
    status = KswSvmNestedValidateEntry(&Session->Vmcb12, &Io->Policy, &Session->Admission);
    /* Implementation restrictions preserve the original runnable L1 image. */
    if (status == KSW_NSVM_ENTRY_UNSUPPORTED) { return KSW_NSVM_ACTION_UNSUPPORTED; }
    /* Architecturally invalid VMRUN returns to L1 with INVALID, not to the initial Windows caller. */
    if (status == KSW_NSVM_ENTRY_INVALID) {
        /* Save the real per-instruction continuation before returning the virtual exit. */
        KswNsvmSessionSaveL1(Session, Current);
        /* Leave the unexecuted guest state and all source controls untouched. */
        KswSvmNestedInvalidExit(&Session->Vmcb12);
        /* A failed physical write cannot publish a completed virtual VMEXIT. */
        status = KswSvmNestedWriteback(&Io->Operand, Session->OperandPa, Session->OperandHostPa,
            &Session->Vmcb12, KSW_NSVM_SAVE_INVALID, 1, Io->Commit, &Session->OperandResult);
        /* Do not automatically retry a possibly partial write. */
        if (status != KSW_NNPT_OK) { return KswNsvmSessionFault(Session); }
        /* Apply the architectural host-return effects using the current context. */
        KswSvmNestedRestoreL1(Current, &Session->L1, Current);
        /* Virtual VMEXIT clears GIF even when the inner guest never executed. */
        Session->VirtualGif = 0;
        /* Count only successfully committed invalid-entry returns. */
        ++Session->InvalidEntries;
        /* The next dispatcher action resumes L1 rather than admitting L2. */
        return KSW_NSVM_ACTION_INVALID;
    }
    /* Capture callbacks borrow this descriptor only during the current entry attempt. */
    capture.Io = Io; capture.Session = Session;
    /* Capture only enabled maps; low base bits follow AMD's ignored-bit semantics. */
    if (!KswSvmNestedCapturePermissions(&Session->Permissions,
        (unsigned int)KswSvmRead64(&Session->Vmcb12, KSW_VMCB_MISC1),
        KswSvmRead64(&Session->Vmcb12, KSW_VMCB_MSRPM),
        KswSvmRead64(&Session->Vmcb12, KSW_VMCB_IOPM), Io->Policy.PhysicalBits,
        KswNsvmSessionReadMap, &capture) || !KswSvmNestedPermissionView(&Session->Permissions, &inner)) {
        /* No merged permission output is executable after a partial capture. */
        return KswNsvmSessionFault(Session);
    }
    /* Both owners may request exits; neither can remove the other's restrictions. */
    if (!KswSvmNestedMergePermissions(&Io->OuterPermissions, &inner, Io->MergedMsr, Io->MergedIo)) {
        /* An incoherent outer permission descriptor is an implementation failure. */
        return KswNsvmSessionFault(Session);
    }
    /* Every new virtual VMRUN invalidates cached source mappings regardless of virtual ASID. */
    if (KswSvmNestedShadowReset(Io->Shadow) != KSW_NSHADOW_OK) { return KswNsvmSessionFault(Session); }
    /* Preserve the host continuation before replacing its automatic execution state. */
    KswNsvmSessionSaveL1(Session, Current);
    /* Build with real processor-local ASID and L0-owned map/NPT pointers only. */
    status = KswSvmNestedBuildEntry(Current, &Session->L1, &Session->Vmcb12, &Io->Policy,
        Io->Shadow->Pages[0].Physical, Io->MsrPa, Io->IoPa, Io->Asid, &Session->Admission);
    /* Builder rejection leaves Current intact and cannot imply successful entry. */
    if (status != KSW_NSVM_ENTRY_OK) { return KswNsvmSessionFault(Session); }
    /* NPT12's cache interpretation belongs to L1 PAT, not L2's guest PAT. */
    Io->Mmu->InnerPat = KswSvmRead64(&Session->L1, KSW_VMCB_PAT);
    /* The composed walker never installs NCR3 directly into hardware. */
    Io->Mmu->InnerRoot = KswSvmRead64(&Session->Vmcb12, KSW_VMCB_NCR3);
    /* Virtual L1 capabilities bound every nested page-table walk. */
    Io->Mmu->InnerBits = Io->Policy.PhysicalBits;
    /* This implementation advertises no page size beyond the trusted outer CPU. */
    Io->Mmu->InnerPage1Gb = Io->Operand.Page1Gb;
    /* NPT12 NX interpretation uses the virtual host EFER. */
    Io->Mmu->InnerNx = (KswSvmRead64(&Session->L1, KSW_VMCB_EFER) & (1ULL << 11)) != 0;
    /* Cache publication is tied to this exact reset generation. */
    Io->Mmu->Epoch = Io->Shadow->Epoch;
    /* VMRUN sets guest GIF; the interrupt arbiter translates this logical state. */
    Session->VirtualGif = 1;
    /* Only now can the caller publish the inner owner before executing hardware. */
    Session->Phase = KSW_NSVM_SESSION_L2; ++Session->Entries;
    /* This requests VMRUN; it is not evidence that hardware has executed the guest. */
    return KSW_NSVM_ACTION_ENTER;
}

/* Complete an inner-owned exit without rewinding any Windows launch-time state. */
unsigned int KswSvmNestedSessionReflect(KSW_NSVM_SESSION* Session,
    const KSW_NSVM_SESSION_IO* Io, KSW_SVM_VMCB* Current)
{
    /* An L1 instruction exit cannot be mistaken for an active L2 reflection. */
    if (!Session || !Io || !Current || Session->Phase != KSW_NSVM_SESSION_L2) { return KSW_NSVM_ACTION_FAULT; }
    /* An invalid physical VMCB02 is our builder/hardware-contract fault, not automatically L1's fault. */
    if (KswSvmRead64(Current, KSW_VMCB_EXITCODE) == KSW_SVM_EXIT_INVALID) { return KswNsvmSessionFault(Session); }
    /* Merge hardware outputs into the captured source, preserving all L1 control fields. */
    KswSvmNestedReflectExit(&Session->Vmcb12, Current, 1);
    /* Bind output to the same physical page even if a future outer owner supports remapping. */
    if (KswSvmNestedWriteback(&Io->Operand, Session->OperandPa, Session->OperandHostPa,
        &Session->Vmcb12, KSW_NSVM_SAVE_VMEXIT, 1, Io->Commit, &Session->OperandResult) != KSW_NNPT_OK) {
        /* A partial or rejected output keeps L2 resources owned for diagnosis. */
        return KswNsvmSessionFault(Session);
    }
    /* Current VMLOAD state/CR2/DR6 survive while L1's current VMRUN core state returns. */
    KswSvmNestedRestoreL1(Current, &Session->L1, Current);
    /* The virtual host resumes with GIF clear; the arbiter controls actual event delivery. */
    Session->VirtualGif = 0;
    /* Publish idle only after output and the current continuation are both complete. */
    Session->Phase = KSW_NSVM_SESSION_IDLE; ++Session->Returns;
    /* The caller must now run the saved L1 continuation, never an original probe context. */
    return KSW_NSVM_ACTION_RETURN;
}
