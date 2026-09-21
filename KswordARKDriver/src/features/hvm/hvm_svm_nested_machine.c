/* Keep physical acknowledgement, instruction completion and virtual exit ownership separate. */
#include "hvm_svm_nested_machine.h"

/* Save a result on every path without changing its architectural meaning. */
static unsigned KswNsvmMachineResult(KSW_NSVM_MACHINE* Machine, unsigned Action)
{
    /* Retained diagnostics are processor-private, with no root-mode allocation or lock. */
    if (Machine) { Machine->LastAction = Action; }
    /* READY is the only action permitting a later hardware VMRUN. */
    return Action;
}

/* Coordinator reflection uses the same exact VMCB transaction as ordinary L1-owned exits. */
static unsigned KswNsvmMachineReflect(KSW_NSVM_MACHINE* Machine)
{
    /* One implementation owns both writeback ordering and interrupted-event transfer. */
    unsigned action = KswSvmNestedReturnL1(Machine->Execution);
    /* An unstarted backlog still requires scheduling; it is never fabricated as EXITINTINFO. */
    if (action == KSW_NSVM_EXEC_EVENT_BLOCKED) { return KSW_NSVM_MACHINE_WINDOW; }
    /* Only complete architectural return permits the next L1 entry preparation. */
    return action == KSW_NSVM_EXEC_RESUME ? KSW_NSVM_MACHINE_READY : KSW_NSVM_MACHINE_FAULT;
}

/* Complete a physical event without ever calling a Windows ISR on the root stack. */
static unsigned KswNsvmMachinePhysical(KSW_NSVM_MACHINE* Machine, unsigned Forced)
{
    /* Callbacks and event slots were allocated/bound before entering root. */
    KSW_NSVM_EXECUTION* execution = Machine->Execution;
    /* Reflection after NMI acknowledgement is independent of whether queuing succeeds. */
    unsigned reflect = 0, action;
    /* Retain the token even though its next injection may happen much later. */
    KSW_SVM_U64 token;
    /* Physical NMIs held before first injection have a single hardware-style pending latch. */
    const KSW_NSVM_PENDING_ITEM* previous = KswSvmNestedPendingLookup(&execution->Pending, Machine->PhysicalNmiToken);
    /* Classify against the original L1 intercepts, not our executable overlay. */
    action = KswSvmNestedPhysicalEvent(execution->Session, execution->Gif, Machine->LastExit, &reflect);
    /* A software NMI mask or IRET observation intercept can own an otherwise un-intercepted NMI. */
    if (Machine->LastExit == 0x61 && (Forced || Machine->NmiBlocked)) {
        /* While servicing a virtual NMI, another physical NMI remains pending instead of reflecting early. */
        reflect = !Machine->NmiBlocked && execution->Session->Phase == KSW_NSVM_SESSION_L2 &&
            KswSvmNestedInterceptRequested(&execution->Session->Vmcb12, 0x61) == 1;
        /* Capture it without running a Windows ISR on the private root stack. */
        action = KSW_NSVM_INTERRUPT_ACK_NMI;
    }
    /* Keep the exact platform action for failure diagnostics. */
    Machine->LastPhysicalAction = action;
    /* INTR remains pending in the APIC and is delivered normally after virtual STGI. */
    if (action == KSW_NSVM_INTERRUPT_REFLECT) { return KswNsvmMachineReflect(Machine); }
    /* SMI/INIT must not be acknowledged by the NMI-only helper. */
    if (action == KSW_NSVM_INTERRUPT_UNSUPPORTED) { return KSW_NSVM_MACHINE_UNSUPPORTED; }
    /* An unowned event cannot be silently discarded/reentered. */
    if (action != KSW_NSVM_INTERRUPT_ACK_NMI) { return KSW_NSVM_MACHINE_FAULT; }
    /* Reserve capacity before consuming anything from physical hardware. */
    if ((!previous || !previous->Physical) &&
        (execution->Pending.Count >= KSW_NSVM_PENDING_CAPACITY || execution->Pending.Serial == ~0ULL)) {
        /* The intercepted NMI is still in hardware; no Count was consumed. */
        return KSW_NSVM_MACHINE_FAULT;
    }
    /* No callback means the platform has no implemented acknowledgement mechanism. */
    if (!Machine->Io.AcknowledgeNmi || !Machine->Io.CommitNmi || Machine->NmiCount || Machine->NmiHardwareMask ||
        (previous && previous->Physical && Machine->NmiCoalesced == ~0ULL)) { return KSW_NSVM_MACHINE_FAULT; }
    /* A real acknowledgement is retained before any architectural reflection. */
    Machine->NmiCount = Machine->Io.AcknowledgeNmi(Machine->Io.Context);
    /* Zero/multiple/saturated observations are never turned into one fabricated event. */
    if (Machine->NmiCount != 1) { return KSW_NSVM_MACHINE_FAULT; }
    /* The near-return acknowledgement leaf owns a real NMI mask until an observed completed IRET. */
    Machine->NmiHardwareMask = 1;
    /* Physical NMI is for the virtual host once the inner intercept returns control to it. */
    if (previous && previous->Physical) {
        /* Hardware likewise coalesces NMIs while one is pending before dispatch; preserve the first identity. */
        token = previous->Token; ++Machine->NmiCoalesced;
    } else if (!KswSvmNestedPendingPhysicalNmi(&execution->Pending, &token)) { return KSW_NSVM_MACHINE_FAULT; }
    /* Distinguish a hardware-pending NMI from an event whose delivery already started in an IDT. */
    Machine->PhysicalNmiToken = token;
    /* Clear the capture counter only after the software ledger accepted its ownership. */
    if (!Machine->Io.CommitNmi(Machine->Io.Context, 1)) { return KSW_NSVM_MACHINE_FAULT; }
    /* The event now belongs to Pending; no duplicate physical acknowledgement can be consumed. */
    Machine->NmiCount = 0;
    /* A requested inner intercept receives VMEXIT(NMI), with hardware-style L1 GIF=0. */
    if (reflect) { return KswNsvmMachineReflect(Machine); }
    /* L1 was already running with GIF=0, so preserve its exact interrupted continuation. */
    return KswSvmNestedResumeEvent(execution->Current) == KSW_NSVM_EVENT_OK ?
        KSW_NSVM_MACHINE_READY : KSW_NSVM_MACHINE_FAULT;
}

/* The first physical TPR observation is not inferred from a zeroed VMCB.V_TPR field. */
unsigned KswSvmNestedMachineInitialize(KSW_NSVM_MACHINE* Machine)
{
    /* CPU identity/affinity is supplied by the common frozen-topology lifecycle. */
    KSW_NSVM_EXECUTION* execution;
    /* Read the actual TPR exactly on this target CPU. */
    unsigned tpr;
    /* No partial callback set may claim runnable entry preparation. */
    if (!Machine || !(execution = Machine->Execution) || !execution->Current || !execution->Session ||
        !execution->Io || !Machine->Io.ReadTpr || !Machine->Io.WriteTpr ||
        !Machine->Io.AcknowledgeNmi || !Machine->Io.CommitNmi || Machine->Initialized ||
        Machine->Overlay.Applied || Machine->HeldNmiGuard || Machine->Iret.Requested || Machine->Iret.Applied ||
        Machine->NmiHardwareMask || Machine->NmiBlocked || Machine->ArmedToken || Machine->ArmedObservation || execution->Pending.Count ||
        execution->Session->Phase != KSW_NSVM_SESSION_IDLE || execution->Session->Lease.Token) {
        /* Initialization never performs a best-effort partial entry. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* Callback failure is represented outside the four-bit architectural range. */
    tpr = Machine->Io.ReadTpr(Machine->Io.Context);
    /* An invalid TPR cannot be truncated into an apparently valid priority. */
    if (tpr > 15) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
    /* Set only the virtual TPR bits; retain every other initial interrupt-control field. */
    KswSvmWrite64(execution->Current, KSW_VMCB_INTCTL,
        (KswSvmRead64(execution->Current, KSW_VMCB_INTCTL) & ~15ULL) | tpr);
    /* Windows started with native GIF enabled; this is initial state, not a forced later recovery. */
    execution->Gif = execution->GifRequested = 1; Machine->Initialized = 1;
    /* Caller must still execute Entry before issuing VMRUN. */
    return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_READY);
}

/* Process real hardware outputs before any architectural emulation can overwrite them. */
unsigned KswSvmNestedMachineExit(KSW_NSVM_MACHINE* Machine)
{
    /* Preserve the running virtual context before a reflection changes it. */
    KSW_NSVM_EXECUTION* execution;
    /* Raw hardware values are read once before restoring the control overlay. */
    KSW_SVM_U64 event;
    /* TPR is actual physical state, not a count or an APIC ID. */
    unsigned tpr, action, inner, wasMasked, windowExit = 0, heldIret = 0, stepExit, stepResult = KSW_NSVM_IRET_CONTINUE;
    /* No exit may be processed twice for one hardware entry. */
    if (!Machine || !Machine->Initialized || !(execution = Machine->Execution) || !Machine->Overlay.Applied) {
        /* Preserve outstanding ownership if the caller violated ordering. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* Retain original raw code even if reflection later installs the L1 image. */
    Machine->LastExit = KswSvmRead64(execution->Current, KSW_VMCB_EXITCODE);
    /* Capture interrupted-delivery metadata before exception planning. */
    event = KswSvmRead64(execution->Current, KSW_VMCB_EXITINTINFO);
    /* An invalid real VMCB is an L0 construction failure; never fabricate a virtual INVALID here. */
    if (Machine->LastExit == KSW_SVM_EXIT_INVALID) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
    /* Injection observation is outermost and must be restored before original exception routing. */
    if (Machine->ArmedObservation) {
        /* Hardware must have executed with every secondary exception intercepted. */
        if (!Machine->ArmedToken || (unsigned)KswSvmRead64(execution->Current, 0x008U) != ~0U) {
            /* Retain both raw event records after an invalid observation contract. */
            return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
        }
        /* Restore only this dword; adjacent CR/DR intercepts retain their original contents. */
        KswSvmWrite32(execution->Current, 0x008U, Machine->ArmedExceptions);
    }
    /* The IRET observer is below injection observation; the two never arm together. */
    stepExit = Machine->Iret.Applied;
    /* The original raw exit remains available even after observer-only TF/intercepts are removed. */
    if (stepExit) {
        /* No completion is inferred from a faulting or invalid attempt. */
        stepResult = KswSvmNestedIretObserve(execution->Current, &Machine->Iret);
        /* Invalid observation retains all lower overlays and masks. */
        if (stepResult == KSW_NSVM_IRET_FAULT) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
    }
    /* This outermost overlay prevents an unrelated IRET from releasing a not-yet-delivered NMI. */
    if (Machine->HeldNmiGuard) {
        /* No guest instruction can change the private acknowledgement identity while running. */
        const KSW_NSVM_PENDING_ITEM* held = KswSvmNestedPendingLookup(&execution->Pending, Machine->HeldNmiToken);
        /* Retain the raw controls if the source record disappeared or was improperly armed. */
        if ((!Machine->NmiHardwareMask && !Machine->NmiBlocked && (!held || !held->Physical)) ||
            !(KswSvmRead64(execution->Current, KSW_VMCB_MISC1) & (1ULL << 20))) {
            /* A missing acknowledgement is never repaired by opening NMI delivery. */
            return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
        }
        /* IRET interception precedes exceptions and instruction completion, hence does not release NMI. */
        heldIret = Machine->LastExit == 0x74 && !stepExit;
        /* Restore in reverse order: held-NMI guard, IRQ window, then ordinary interrupt masking. */
        KswSvmWrite32(execution->Current, KSW_VMCB_MISC1, Machine->HeldNmiMisc1);
        /* The source acknowledgement remains queued; only the temporary intercept has been consumed. */
        Machine->HeldNmiGuard = 0;
    }
    /* The hardware has now completed an IRET, releasing the same processor's physical NMI block. */
    if (stepExit && Machine->Iret.Completed) { Machine->NmiHardwareMask = Machine->NmiBlocked = 0; }
    /* A queued injection must have an explicit hardware completion before dropping its token. */
    if (Machine->ArmedToken) {
        /* All secondary exceptions were intercepted before aggregation, proving distinct-event ordering. */
        if (!Machine->ArmedObservation || !KswSvmNestedPendingObserveProtected(&execution->Pending, Machine->ArmedToken, event)) {
            /* Stale/duplicate token completion is not a successful delivery. */
            return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
        }
        /* An interrupted attempt retains the same token for NPF retry or VMEXIT handoff. */
        execution->RetryEventToken = (event & (1ULL << 31)) &&
            (event & 0xffffffffULL) == Machine->ArmedEvent ? Machine->ArmedToken : 0;
        /* Only the ledger's successful completion permits reusing the injection slot. */
        Machine->ArmedToken = Machine->ArmedEvent = Machine->ArmedOwner = 0;
        /* The completed observation no longer blocks another entry or native stop. */
        Machine->ArmedObservation = 0;
    }
    /* Observe physical priority while all interrupts remain closed in root. */
    tpr = Machine->Io.ReadTpr(Machine->Io.Context);
    /* Synthetic scheduling controls sit on top of the ordinary GIF/masking overlay. */
    if (Machine->IrqWindow.Applied && !KswSvmNestedIrqWindowRestore(execution->Current, &Machine->IrqWindow, &windowExit)) {
        /* Never route an internal sentinel as a real L1-owned interrupt. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* Preserve whether L2 had direct physical CR8 access before removing the overlay. */
    inner = execution->Session->Phase == KSW_NSVM_SESSION_L2;
    /* Forced L1 masking and L1-requested L2 masking have different output owners. */
    wasMasked = (Machine->Overlay.OriginalIntCtl & (1ULL << 24)) != 0;
    /* Original intercepts must be visible to route/reflect, never our temporary NMI bit. */
    if (!KswSvmNestedInterruptRestore(execution->Current, tpr, 1, &Machine->Overlay)) {
        /* An unknown TPR or missing overlay keeps the CPU in a retained-fault state. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* A direct L2 CR8 write affects the physical APIC and survives virtual VMEXIT. */
    if (inner && !wasMasked) {
        /* L1 host restoration must not rewind that shared physical APIC priority. */
        KswSvmWrite64(&execution->Session->L1, KSW_VMCB_INTCTL,
            (KswSvmRead64(&execution->Session->L1, KSW_VMCB_INTCTL) & ~15ULL) | tpr);
    }
    /* Honor an original inner IRET intercept before allowing hardware to execute the instruction. */
    if (heldIret) {
        /* L1's requested intercept takes precedence over this monitor's observation need. */
        if (inner && KswSvmNestedInterceptRequested(&execution->Session->Vmcb12, 0x74) == 1) {
            /* Reflection retains hardware masking until L1 or a subsequent L2 completes its own IRET. */
            return KswNsvmMachineResult(Machine, KswNsvmMachineReflect(Machine));
        }
        /* Reenter at the unchanged IRET with a bounded completion watch, never emulate its stack. */
        return KswNsvmMachineResult(Machine, KswSvmNestedIretRequest(&Machine->Iret) ?
            KSW_NSVM_MACHINE_READY : KSW_NSVM_MACHINE_FAULT);
    }
    /* Only a monitor-created, otherwise unowned #DB is consumed by the observer. */
    if (stepResult == KSW_NSVM_IRET_MONITOR_DB) {
        /* No interrupted delivery existed in this window; preserve the actual completed IRET target. */
        KswSvmWrite64(execution->Current, KSW_VMCB_EVENT, 0); return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_READY);
    }
    /* An observation-only INTR/VINTR must yield to ordinary hardware delivery without consuming its source. */
    if (stepExit && (Machine->LastExit == 0x60 || Machine->LastExit == 0x64) &&
        (!inner || KswSvmNestedInterceptRequested(&execution->Session->Vmcb12, Machine->LastExit) != 1)) {
        /* Original controls are restored, so a subsequent entry can dispatch the original request. */
        return KswNsvmMachineResult(Machine, KswSvmNestedResumeEvent(execution->Current) == KSW_NSVM_EVENT_OK ?
            KSW_NSVM_MACHINE_READY : KSW_NSVM_MACHINE_FAULT);
    }
    /* VINTR already proved IF/TPR/shadow eligibility; no guest instruction needs emulation. */
    if (windowExit) {
        /* Any interrupted event still belongs to hardware's original delivery transaction. */
        if (KswSvmNestedResumeEvent(execution->Current) != KSW_NSVM_EVENT_OK) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
        /* The next Entry selects and injects the original queued vector once. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_READY);
    }
    /* Physical events have an acknowledgement contract unlike ordinary instructions. */
    if (Machine->LastExit >= 0x60 && Machine->LastExit <= 0x63) {
        /* INTR/NMI raw state stays intact until this explicit platform path accepts it. */
        return KswNsvmMachineResult(Machine, KswNsvmMachinePhysical(Machine, stepExit));
    }
    /* Private lifecycle controls are recognized only after raw event/overlay ownership is resolved. */
    if (Machine->Io.PrivateControl) {
        /* The callback cannot impersonate an ordinary L1/L2 instruction handler. */
        action = Machine->Io.PrivateControl(Machine->Io.Context, Machine);
        /* Query/rejected stop may resume; only a fully quiescent stop may return natively. */
        if (action != KSW_NSVM_MACHINE_NOT_CONTROL) {
            /* Reject arbitrary callback values rather than interpreting them as successful entry. */
            return KswNsvmMachineResult(Machine, action == KSW_NSVM_MACHINE_READY || action == KSW_NSVM_MACHINE_NATIVE ?
                action : KSW_NSVM_MACHINE_FAULT);
        }
    }
    /* Dispatch current execution after restoring original ownership controls. */
    action = KswSvmNestedExecute(execution);
    /* The overlay implements L1 GIF changes; actual entry applies it only after this commit. */
    if (action == KSW_NSVM_EXEC_GIF_CHANGED) { action = KswSvmNestedCommitGif(execution); }
    /* Virtual CPU shutdown is distinct from either host failure or successful native return. */
    if (action == KSW_NSVM_EXEC_SHUTDOWN) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_SHUTDOWN); }
    /* Unimplemented instruction/extension handling remains an explicit software restriction. */
    if (action == KSW_NSVM_EXEC_UNSUPPORTED) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_UNSUPPORTED); }
    /* Instruction reflection uses the same backlog restriction as physical-event reflection. */
    if (action == KSW_NSVM_EXEC_EVENT_BLOCKED) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_WINDOW); }
    /* No unrecognized action permits a blind hardware retry. */
    return KswNsvmMachineResult(Machine, action == KSW_NSVM_EXEC_RESUME ? KSW_NSVM_MACHINE_READY : KSW_NSVM_MACHINE_FAULT);
}

/* Build executable event controls only after the previous instruction/exit transaction completed. */
unsigned KswSvmNestedMachineEntry(KSW_NSVM_MACHINE* Machine)
{
    /* Current may refer to either the L1 or L2 architectural image. */
    KSW_NSVM_EXECUTION* execution;
    /* Borrow an event without consuming its acknowledgement. */
    const KSW_NSVM_PENDING_ITEM* pending;
    /* A blocked maskable request may arm a hardware eligibility window without consuming its token. */
    const KSW_NSVM_PENDING_ITEM* window = NULL;
    /* Event owner and physical TPR are independent of virtual ASID. */
    KSW_SVM_U64 owner, control, event, flags;
    /* Virtual shadow and guest IF must be checked before unconditional EVENTINJ. */
    unsigned inner, shadow, tpr;
    /* Every hardware entry has exactly one fresh overlay and at most one armed queue token. */
    if (!Machine || !Machine->Initialized || !(execution = Machine->Execution) || Machine->Overlay.Applied ||
        Machine->HeldNmiGuard || Machine->Iret.Applied || Machine->ArmedToken || Machine->ArmedObservation || Machine->NmiCount || execution->Session->Phase == KSW_NSVM_SESSION_FAULTED) {
        /* No best-effort entry after a partial physical or architectural transaction. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* The frozen session identity determines which IDT may receive each queued event. */
    inner = execution->Session->Phase == KSW_NSVM_SESSION_L2;
    /* L1's event namespace has a distinguished zero identity. */
    owner = inner ? execution->Session->OperandHostPa + 1ULL : 0;
    /* A virtual VMRUN cannot silently move an already acknowledged L1 event to another IDT. */
    if (inner && KswSvmNestedPendingOwned(&execution->Pending, 0)) {
        /* A VMRUN with a still-pending physical NMI follows L1's original NMI-intercept policy. */
        const KSW_NSVM_PENDING_ITEM* nmi = KswSvmNestedPendingLookup(&execution->Pending, Machine->PhysicalNmiToken);
        /* Deferred L1 injections stay on this CPU until L1 resumes; only a physical NMI follows VMRUN. */
        if (nmi && nmi->Physical && !nmi->Owner) {
        /* An intercepted pending NMI produces virtual VMEXIT before the first L2 instruction. */
        if (!Machine->NmiBlocked && KswSvmNestedInterceptRequested(&execution->Session->Vmcb12, 0x61) == 1) {
            /* No IDT delivery began, so EXITINTINFO must remain invalid. */
            KswSvmWrite64(execution->Current, KSW_VMCB_EXITCODE, 0x61);
            /* These event-specific exit operands are undefined and deterministic zero here. */
            KswSvmWrite64(execution->Current, KSW_VMCB_EXITINFO1, 0); KswSvmWrite64(execution->Current, KSW_VMCB_EXITINFO2, 0);
            /* Never claim that an acknowledgement has already been injected into L2. */
            KswSvmWrite64(execution->Current, KSW_VMCB_EXITINTINFO, 0); KswSvmWrite64(execution->Current, KSW_VMCB_NRIP, 0);
            /* The pending source remains in L0's queue while L1 receives its NMI-intercept return. */
            if (KswNsvmMachineReflect(Machine) != KSW_NSVM_MACHINE_READY) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
            /* Continue this same preparation with L1's now-closed GIF and original event owner. */
            inner = 0; owner = 0;
        } else if (!Machine->NmiBlocked && !KswSvmNestedPendingMovePhysical(&execution->Pending, nmi->Token, owner)) {
            /* L1 allowed direct delivery, but a stale ledger token cannot authorize it. */
            return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
        }
        }
    }
SelectCurrent:
    /* Read all scheduling inputs from the same current image, including a just-reflected L1 continuation. */
    control = KswSvmRead64(execution->Current, KSW_VMCB_INTCTL);
    /* Existing injections cannot be overwritten by a new asynchronous event. */
    event = KswSvmRead64(execution->Current, KSW_VMCB_EVENT);
    /* The guest's IF, never root's temporary IF, governs a queued maskable event. */
    flags = KswSvmRead64(execution->Current, KSW_VMCB_RFLAGS);
    /* MOV SS/STI shadow delays external event delivery through the next executed instruction. */
    shadow = (unsigned)(KswSvmRead64(execution->Current, 0x068U) & 1ULL);
    /* Select using the current virtual CPU's priority. */
    pending = KswSvmNestedPendingLookup(&execution->Pending, execution->RetryEventToken);
    /* Interrupted delivery was already accepted; retry does not retest new interrupt eligibility. */
    if (pending && (pending->Owner != owner || pending->Event != event)) { pending = NULL; }
    /* New delivery, unlike retry, must respect the current virtual masking state. */
    if (!pending) {
        /* Existing unrelated EVENTINJ is handled by the separate collision/window path below. */
        pending = KswSvmNestedPendingSelect(&execution->Pending, owner,
            execution->Gif && !shadow && (flags & (1ULL << 9)), execution->Gif && !shadow && !Machine->NmiBlocked, (unsigned)(control & 15ULL));
    }
    /* A virtual IRQ may run while the acknowledged queue is masked; physical events otherwise take precedence. */
    if (!Machine->Iret.Requested && execution->Gif && KswSvmNestedPendingOwned(&execution->Pending, owner) &&
        KswSvmNestedPreferVirq(execution->Current, pending ? pending->Event : 0)) {
        /* A requested VINTR is L1-owned; reflecting it with retained L2 acknowledgements needs explicit handoff. */
        if (inner && KswSvmNestedInterceptRequested(&execution->Session->Vmcb12, 0x64) == 1) {
            /* VINTR precedes V_IRQ consumption and IDT delivery, so it carries no EXITINTINFO. */
            KswSvmWrite64(execution->Current, KSW_VMCB_EXITCODE, 0x64); KswSvmWrite64(execution->Current, KSW_VMCB_EXITINTINFO, 0);
            /* These undefined operands are deterministic, without fabricating an instruction advance. */
            KswSvmWrite64(execution->Current, KSW_VMCB_EXITINFO1, 0); KswSvmWrite64(execution->Current, KSW_VMCB_EXITINFO2, 0);
            /* VINTR has no intercepted instruction whose length could be reused by the inner VMM. */
            KswSvmWrite64(execution->Current, KSW_VMCB_NRIP, 0);
            /* A not-yet-injected physical NMI can follow VMEXIT; other unrepresentable backlog remains blocked. */
            tpr = KswNsvmMachineReflect(Machine);
            /* Partial writeback and unrepresentable event state never authorize another hardware attempt. */
            if (tpr != KSW_NSVM_MACHINE_READY) { return KswNsvmMachineResult(Machine, tpr); }
            /* Re-select once in L1's closed-GIF context using its actual restored controls. */
            inner = 0; owner = 0; goto SelectCurrent;
        }
        /* Only a nonintercepted eligible virtual IRQ is converted to the equivalent unconditional injection. */
        event = (1ULL << 31) | ((control >> 32) & 255ULL);
        /* Clear the source request at the same architectural point, before beginning its IDT delivery. */
        control &= ~(1ULL << 8); KswSvmWrite64(execution->Current, KSW_VMCB_INTCTL, control);
        /* The original virtual interrupt remains separately represented from the queued physical acknowledgement. */
        KswSvmWrite64(execution->Current, KSW_VMCB_EVENT, event); pending = NULL;
    }
    /* An enabled GIF with pending but blocked delivery needs an explicit window implementation. */
    if (!Machine->Iret.Requested && execution->Gif && KswSvmNestedPendingOwned(&execution->Pending, owner) &&
        (!pending || ((event & (1ULL << 31)) && (pending->Token != execution->RetryEventToken || pending->Event != event)))) {
        /* A pending NMI has higher priority and cannot be represented by a maskable sentinel. */
        if (!Machine->NmiBlocked && KswSvmNestedPendingSelect(&execution->Pending, owner, 0, 1, 0)) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_WINDOW); }
        /* Find the highest-priority IRQ independently of IF/TPR and an existing synchronous injection. */
        window = KswSvmNestedPendingSelect(&execution->Pending, owner, 1, 0, 0);
        /* Preserve all ownership when the ledger cannot supply an eligible scheduling identity. */
        if (!window && !Machine->NmiBlocked) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_WINDOW); }
        /* Existing EVENTINJ is delivered first. The IRQ token remains queued until hardware VINTR eligibility. */
        pending = NULL;
    }
    /* IRET completion must be observed without an intervening injection changing its instruction pointer. */
    if (Machine->Iret.Requested) { pending = NULL; window = NULL; }
    /* An injected physical NMI needs software blocking if an earlier unrelated IRET released the hardware mask. */
    if (pending && pending->Physical && ((pending->Event >> 8) & 7ULL) == 2) { Machine->NmiBlocked = 1; }
    /* CR8 writes while L1 GIF was closed affected V_TPR; synchronize them before reentry. */
    tpr = (unsigned)(KswSvmRead64(inner ? &execution->Session->L1 : execution->Current, KSW_VMCB_INTCTL) & 15ULL);
    /* Never truncate a failed callback or issue host APIs to update interrupt priority. */
    if (!Machine->Io.WriteTpr(Machine->Io.Context, tpr)) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
    /* Apply masks only after all previous failure paths have retained their original state. */
    if (!KswSvmNestedInterruptPrepare(execution->Current, execution->Session, execution->Gif, &Machine->Overlay)) {
        /* No executable control overlay means no hardware entry is authorized. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* The sentinel causes a VINTR exit before any IDT access; it is not a second acknowledgement. */
    if (window && !KswSvmNestedIrqWindowArm(execution->Current, window->Event, window->Token, &Machine->IrqWindow)) {
        /* Keep both the queue and ordinary overlay retained on a window-construction failure. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* The acknowledgement leaf intentionally returned without IRET to keep physical NMI blocked. */
    if (Machine->PhysicalNmiToken || Machine->NmiHardwareMask || Machine->NmiBlocked) {
        /* Tokens survive slot reuse; a completed historical acknowledgement creates no new guard. */
        const KSW_NSVM_PENDING_ITEM* held = KswSvmNestedPendingLookup(&execution->Pending, Machine->PhysicalNmiToken);
        /* Only a source not yet injected has physical masking that an unrelated guest IRET could release. */
        if ((held && held->Physical) || Machine->NmiHardwareMask || Machine->NmiBlocked) {
            /* A physical acknowledgement may not be simultaneously armed by another injection path. */
            if (held && held->Physical && held->State != KSW_NSVM_PENDING_QUEUED) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
            /* Snapshot after all other overlays so reverse restoration preserves their own controls. */
            Machine->HeldNmiMisc1 = (unsigned)KswSvmRead64(execution->Current, KSW_VMCB_MISC1);
            /* Stable token identifies the exact physical acknowledgement protected by this entry. */
            Machine->HeldNmiToken = held ? held->Token : 0;
            /* AMD IRET intercept is MISC1 bit 20, VMEXIT 0x74, before exception checking. */
            KswSvmWrite32(execution->Current, KSW_VMCB_MISC1, Machine->HeldNmiMisc1 | (1U << 20) |
                (Machine->NmiBlocked ? 2U : 0));
            /* The guard is executable only after its original controls and token are retained. */
            Machine->HeldNmiGuard = 1;
        }
    }
    /* Execute only the original IRET, with all event delivery intercepted until completion is known. */
    if (Machine->Iret.Requested && !KswSvmNestedIretArm(execution->Current, &Machine->Iret)) {
        /* Retain lower overlays and all acknowledgements when the observer cannot build an entry. */
        return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT);
    }
    /* Reserve the queue identity before committing its injection control. */
    if (pending) {
        /* Observe every secondary exception before it can replace an unfinished asynchronous delivery. */
        Machine->ArmedExceptions = (unsigned)KswSvmRead64(execution->Current, 0x008U);
        /* Original exception ownership is restored before dispatch/VMEXIT reflection. */
        KswSvmWrite32(execution->Current, 0x008U, ~0U); Machine->ArmedObservation = 1;
        /* The fixed queue is single-writer, so the borrowed token cannot change concurrently. */
        if (!KswSvmNestedPendingArm(&execution->Pending, pending->Token)) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
        /* Preserve the exact attempt identity until MachineExit sees a real hardware result. */
        Machine->ArmedToken = pending->Token; Machine->ArmedEvent = pending->Event; Machine->ArmedOwner = pending->Owner;
        /* Injection is unconditional only after software GIF/IF/TPR/shadow checks above. */
        KswSvmWrite64(execution->Current, KSW_VMCB_EVENT, pending->Event);
    }
    /* Counter wrap is retained as a fault rather than reusing transition evidence. */
    if (Machine->Transitions == ~0ULL) { return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_FAULT); }
    /* This counts prepared attempts; only real exits count as hardware execution. */
    ++Machine->Transitions;
    /* Assembly still must install Overlay.HostIf with GIF=0 and request a full TLB flush. */
    return KswNsvmMachineResult(Machine, KSW_NSVM_MACHINE_READY);
}

/* This is a per-CPU prerequisite, never a replacement for the common all-CPU rendezvous. */
unsigned KswSvmNestedMachineCanStop(const KSW_NSVM_MACHINE* Machine)
{
    /* All pointers describe the live current virtual CPU. */
    const KSW_NSVM_EXECUTION* execution;
    /* Unknown state cannot authorize freeing a stack, page table or hardware save area. */
    if (!Machine || !Machine->Initialized || !(execution = Machine->Execution) || !execution->Session ||
        !execution->Registers.Svm || execution->Session->Phase == KSW_NSVM_SESSION_FAULTED ||
        Machine->Overlay.Applied || Machine->IrqWindow.Applied || Machine->HeldNmiGuard ||
        Machine->Iret.Applied || Machine->Iret.Requested || Machine->ArmedObservation) { return KSW_NSVM_STOP_FAULT; }
    /* A live inner VMRUN cannot be returned directly to the original Windows caller. */
    if (execution->Session->Phase == KSW_NSVM_SESSION_L2 || execution->Session->Lease.Token) { return KSW_NSVM_STOP_L2; }
    /* Virtual SVM ownership must have been explicitly relinquished by the inner VMM. */
    if ((execution->Registers.Svm->Efer & KSW_SVM_EFER_SVME) || execution->Registers.Svm->Hsave) { return KSW_NSVM_STOP_OWNER; }
    /* Acknowledged but undelivered events survive CLI termination or a stop request. */
    if (execution->Pending.Count || Machine->ArmedToken || Machine->NmiCount || Machine->NmiHardwareMask || Machine->NmiBlocked) { return KSW_NSVM_STOP_EVENTS; }
    /* Native Windows must not inherit a monitor-created closed global interrupt window. */
    if (!execution->Gif) { return KSW_NSVM_STOP_GIF; }
    /* The common lifecycle still has to execute and independently acknowledge actual native return. */
    return KSW_NSVM_STOP_READY;
}
