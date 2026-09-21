/* Ordinary nested VMM instructions share the same transactions as the bounded hardware probe. */
#include "hvm_svm_nested_execute.h"

/* Completed intercepted instructions require known NRIP and no unfinished delivery transaction. */
static int KswNsvmCanComplete(const KSW_SVM_VMCB* Current)
{
    /* MSR/CPUID/SVM instructions cannot be executed as part of hardware IDT descriptor delivery. */
    return !(KswSvmRead64(Current, KSW_VMCB_EXITINTINFO) & (1ULL << 31)) &&
        KswSvmNextRipValid(KswSvmRead64(Current, KSW_VMCB_RIP), KswSvmRead64(Current, KSW_VMCB_NRIP));
}

/* This helper is used only after all mutations have passed their admission checks. */
static unsigned KswNsvmComplete(KSW_NSVM_EXECUTION* Execution)
{
    /* Never invent a fixed instruction length in the general engine. */
    if (!KswNsvmCanComplete(Execution->Current)) { return KSW_NSVM_EXEC_FAULT; }
    /* Faults do not use this helper and retain their original RIP. */
    KswSvmWrite64(Execution->Current, KSW_VMCB_RIP, KswSvmRead64(Execution->Current, KSW_VMCB_NRIP));
    /* Clear any completed, stale injection request before executing the next instruction. */
    KswSvmWrite64(Execution->Current, KSW_VMCB_EVENT, 0);
    /* Async event preparation remains mandatory before the platform issues VMRUN. */
    return KSW_NSVM_EXEC_RESUME;
}

/* Reflection does not emulate the intercepted instruction before returning to L1. */
static unsigned KswNsvmReturnL1(KSW_NSVM_EXECUTION* Execution)
{
    /* Partial output keeps the session/lease retained; no original Windows snapshot is used. */
    if (KswSvmNestedSessionReflect(Execution->Session, Execution->Io, Execution->Current) != KSW_NSVM_ACTION_RETURN) {
        /* Caller preserves all buffers and the exact failed commit for diagnosis. */
        return KSW_NSVM_EXEC_FAULT;
    }
    /* Virtual VMEXIT always clears L1 GIF; event controls must enforce it before reentry. */
    Execution->Gif = Execution->GifRequested = 0;
    /* The current image is now the actual L1 continuation after its VMRUN. */
    return KSW_NSVM_EXEC_RESUME;
}

/* Apply architectural exception ordering before deciding whether L1 or guest delivery owns it. */
static unsigned KswNsvmRaise(KSW_NSVM_EXECUTION* Execution, unsigned Vector, unsigned Error,
    KSW_SVM_U64 Address)
{
    /* An active L2 uses the captured, unmerged L1 intercept policy. */
    const KSW_SVM_VMCB* inner = Execution->Session->Phase == KSW_NSVM_SESSION_L2 ? &Execution->Session->Vmcb12 : NULL;
    /* The complete plan remains in preallocated diagnostic state. */
    unsigned action = KswSvmNestedExceptionPlan(Execution->Current, inner, Vector, Error, Address, &Execution->Exception);
    /* A virtual shutdown is handled by lifecycle policy, never host HLT/reset. */
    if (action == KSW_NSVM_EVENT_SHUTDOWN) { return KSW_NSVM_EXEC_SHUTDOWN; }
    /* Reflect the original or newly aggregated exception using the ordinary writeback transaction. */
    if (action == KSW_NSVM_EVENT_REFLECT) {
        /* Hardware-style return metadata preserves the existing EXITINTINFO aggregation history. */
        KswSvmWrite64(Execution->Current, KSW_VMCB_EXITCODE, Execution->Exception.ExitCode);
        /* Error and address fields are supplied only for the appropriate exception. */
        KswSvmWrite64(Execution->Current, KSW_VMCB_EXITINFO1, Execution->Exception.Info1);
        /* No instruction pointer advance precedes the virtual exit. */
        KswSvmWrite64(Execution->Current, KSW_VMCB_EXITINFO2, Execution->Exception.Info2);
        /* Complete L1's current VMRUN, not a stale probe launch. */
        return KswNsvmReturnL1(Execution);
    }
    /* Unknown/invalid event encodings remain a retained fault. */
    if (action != KSW_NSVM_EVENT_INJECT) { return KSW_NSVM_EXEC_FAULT; }
    /* Preserve acknowledged interrupted IRQ/NMI before installing a replacement exception. */
    if (Execution->Exception.Deferred) {
        /* Queue exhaustion is explicit; overwriting/dropping events is forbidden. */
        if (Execution->DeferredCount >= 16) { return KSW_NSVM_EXEC_FAULT; }
        /* This queue belongs solely to this CPU; event delivery consumes it separately. */
        Execution->Deferred[Execution->DeferredCount++] = Execution->Exception.Deferred;
    }
    /* CR2 and EVENTINJ commit together only after deferred ownership was retained. */
    return KswSvmNestedExceptionInject(Execution->Current, &Execution->Exception, 1) ?
        KSW_NSVM_EXEC_RESUME : KSW_NSVM_EXEC_FAULT;
}

/* Handle demand composition or return a genuine NPT12 fault to L1. */
static unsigned KswNsvmResolve(KSW_NSVM_EXECUTION* Execution)
{
    /* The raw hardware context distinguishes guest table access from final data access. */
    KSW_SVM_U64 info = KswSvmRead64(Execution->Current, KSW_VMCB_EXITINFO1);
    /* Preserve the original L2 physical address throughout the composed walk. */
    KSW_SVM_U64 gpa = KswSvmRead64(Execution->Current, KSW_VMCB_EXITINFO2);
    /* Real failures and cache-capacity recycling are separate outcomes. */
    unsigned status;
    /* A malicious or unstable guest table must not create an unbounded root-only retry loop. */
    if (++Execution->NpfRetries > 64) { return KSW_NSVM_EXEC_FAULT; }
    /* All physical memory access goes through the prepared RAM/window callbacks. */
    status = KswSvmNestedMmuResolve(Execution->Io->Mmu, &Execution->MmuIo, gpa,
        (unsigned)(info & (KSW_NNPT_WRITE | KSW_NNPT_EXECUTE)), info & (KSW_NMMU_FINAL | KSW_NMMU_TABLE), &Execution->Translation);
    /* Concurrent A/D changes may be retried without advancing the faulting guest instruction. */
    if (status == KSW_NNPT_RETRY) {
        /* Keep interrupted event delivery intact through a recoverable page-table race. */
        return KswSvmNestedResumeEvent(Execution->Current) == KSW_NSVM_EVENT_OK ? KSW_NSVM_EXEC_RESUME : KSW_NSVM_EXEC_FAULT;
    }
    /* Only a fault owned by the inner page-table translation can be reflected as guest NPF. */
    if (status == KSW_NNPT_FAULT && Execution->Translation.FaultOwner == KSW_NMMU_INNER) {
        /* Fault address and context come from the validated walker, never a host PA. */
        KswSvmWrite64(Execution->Current, KSW_VMCB_EXITINFO1, Execution->Translation.FaultInfo);
        /* EXITCODE remains the original NPF from the combined hardware guest. */
        KswSvmWrite64(Execution->Current, KSW_VMCB_EXITINFO2, Execution->Translation.FaultAddress);
        /* L1 may repair its own mapping and execute VMRUN again. */
        return KswNsvmReturnL1(Execution);
    }
    /* Outer access/cache/RAM failures must not be disguised as a virtual guest's page fault. */
    if (status != KSW_NNPT_OK) { return KSW_NSVM_EXEC_FAULT; }
    /* Install only a completed walk from the current invalidation epoch. */
    status = KswSvmNestedShadowInstall(Execution->Io->Shadow, &Execution->Translation);
    /* Preallocated cache exhaustion is recoverable by evicting all composition entries. */
    if (status == KSW_NSHADOW_FULL) {
        /* Epoch/counter wrap is never accepted as fresh invalidation evidence. */
        if (Execution->CacheRecycles == ~0ULL || KswSvmNestedShadowReset(Execution->Io->Shadow) != KSW_NSHADOW_OK) { return KSW_NSVM_EXEC_FAULT; }
        /* Do not install the now-stale candidate; the next NPF performs a fresh source walk. */
        Execution->Io->Mmu->Epoch = Execution->Io->Shadow->Epoch; ++Execution->CacheRecycles;
        /* Assembly must issue TLB_CONTROL=1 before reentry into the emptied root. */
        return KswSvmNestedResumeEvent(Execution->Current) == KSW_NSVM_EVENT_OK ? KSW_NSVM_EXEC_RESUME : KSW_NSVM_EXEC_FAULT;
    }
    /* Wrong epoch or corrupt storage is not a reason to widen guest permissions. */
    if (status != KSW_NSHADOW_OK) { return KSW_NSVM_EXEC_FAULT; }
    /* An installed page is progress; future faults receive their own bounded retry budget. */
    Execution->NpfRetries = 0;
    /* NPF during an injected event needs that same interrupted event on retry. */
    return KswSvmNestedResumeEvent(Execution->Current) == KSW_NSVM_EVENT_OK ? KSW_NSVM_EXEC_RESUME : KSW_NSVM_EXEC_FAULT;
}

/* Called by a platform event bridge only after it can enforce the requested physical masks. */
unsigned KswSvmNestedCommitGif(KSW_NSVM_EXECUTION* Execution)
{
    /* A missing/stale instruction cannot modify interrupt state. */
    if (!Execution || !Execution->Current || !KswNsvmCanComplete(Execution->Current) || Execution->GifRequested > 1) { return KSW_NSVM_EXEC_FAULT; }
    /* The platform consumes GIF_CHANGED before this call; the opcode must still match. */
    if (KswSvmRead64(Execution->Current, KSW_VMCB_EXITCODE) != (Execution->GifRequested ? 0x84ULL : 0x85ULL)) { return KSW_NSVM_EXEC_FAULT; }
    /* Commit software GIF only after platform acceptance, not merely after decoding CLGI/STGI. */
    Execution->Gif = Execution->GifRequested;
    /* Only a completed virtual instruction advances its guest continuation. */
    return KswNsvmComplete(Execution);
}

/* Unknown exits and incomplete platform operations are never treated as successful emulation. */
unsigned KswSvmNestedExecute(KSW_NSVM_EXECUTION* Execution)
{
    /* Raw operands remain intact until route/admission permits a side effect. */
    KSW_SVM_U64 code, operand, value;
    /* Current nested level comes from owned transaction state, not a user-supplied flag. */
    unsigned inner, action, result;
    /* No partial execution descriptor may access hardware or guest memory. */
    if (!Execution || !Execution->Current || !Execution->Gpr || !Execution->Session ||
        !Execution->Io || !Execution->Io->Mmu || !Execution->Io->Shadow || !Execution->Registers.Svm ||
        !Execution->GuestXcr0 || !Execution->Registers.GuestXss) { return KSW_NSVM_EXEC_FAULT; }
    /* Failed transactions retain ownership until an explicit, independently proven recovery. */
    if (Execution->Session->Phase == KSW_NSVM_SESSION_FAULTED) { return KSW_NSVM_EXEC_FAULT; }
    /* An INVALID physical VMCB is a monitor failure, not fabricated L1 responsibility. */
    code = KswSvmRead64(Execution->Current, KSW_VMCB_EXITCODE);
    /* Hardware saves guest RAX in VMCB rather than in the host's scratch accumulator. */
    operand = KswSvmRead64(Execution->Current, KSW_VMCB_RAX);
    /* No instruction is emulated following a rejected real VMRUN. */
    if (code == KSW_SVM_EXIT_INVALID) { return KSW_NSVM_EXEC_FAULT; }
    /* Bind current mode for shared register policy and any resulting virtual exceptions. */
    inner = Execution->Session->Phase == KSW_NSVM_SESSION_L2;
    /* Register policy always refers to the current executing image. */
    Execution->Registers.Current = Execution->Current; Execution->Registers.Inner = inner;
    /* L2 routing must preserve L1-requested intercepts before L0 emulates anything. */
    if (inner) {
        /* Original permission maps, not the OR-merged hardware maps, determine ownership. */
        KSW_NSVM_PERMISSION_VIEW maps;
        /* A stale/incomplete capture cannot authorize a route. */
        if (!KswSvmNestedPermissionView(&Execution->Session->Permissions, &maps)) { return KSW_NSVM_EXEC_FAULT; }
        /* Preserve the exact route and operands for later platform event decisions. */
        action = KswSvmNestedRouteExit(&Execution->Session->L1, &Execution->Session->Vmcb12,
            &Execution->Io->OuterPermissions, &maps, code, KswSvmRead64(Execution->Current, KSW_VMCB_EXITINFO1),
            (unsigned)Execution->Gpr[1], &Execution->Route);
        /* A requested inner exit is reflected before RIP/register/injection changes. */
        if (action == KSW_NSVM_ROUTE_REFLECT) { return KswNsvmReturnL1(Execution); }
        /* Physical events still need acknowledgement and GIF/masking arbitration. */
        if (action == KSW_NSVM_ROUTE_ASYNC) { return KSW_NSVM_EXEC_PHYSICAL_EVENT; }
        /* NPT faults require explicit ownership from the composed walk. */
        if (action == KSW_NSVM_ROUTE_NPF) { return KswNsvmResolve(Execution); }
        /* NONE/invalid ownership cannot silently become a guest operation. */
        if (action != KSW_NSVM_ROUTE_EMULATE) { return KSW_NSVM_EXEC_FAULT; }
    }
    /* L1 physical interrupts also stay pending until the platform bridge processes them. */
    if (code >= 0x60 && code <= 0x63) { return KSW_NSVM_EXEC_PHYSICAL_EVENT; }
    /* Handle L0-owned synchronous exceptions through the same aggregate/reflect policy. */
    if (code >= 0x40 && code <= 0x5f) {
        /* EXITINFO1 holds the exception error and EXITINFO2 the page-fault address. */
        return KswNsvmRaise(Execution, (unsigned)(code - 0x40),
            (unsigned)KswSvmRead64(Execution->Current, KSW_VMCB_EXITINFO1), KswSvmRead64(Execution->Current, KSW_VMCB_EXITINFO2));
    }
    /* A guest shutdown is never implemented by shutting down the physical machine. */
    if (code == 0x7f) { return KSW_NSVM_EXEC_SHUTDOWN; }
    /* Successful instruction emulation needs a real, complete continuation before any mutation. */
    if (!KswNsvmCanComplete(Execution->Current)) { return KSW_NSVM_EXEC_FAULT; }
    /* CPUID preserves raw topology while applying only the implemented virtual feature contract. */
    if (code == KSW_SVM_EXIT_CPUID) {
        /* Make a small borrowed policy copy so L2 cannot mutate L1 exposure settings. */
        KSW_NSVM_CPUID_POLICY policy = Execution->Cpuid;
        /* All output registers are architectural zero-extended dwords. */
        unsigned words[4];
        /* No third SVM level is implemented. */
        if (inner) { policy.ExposeSvm = 0; }
        /* XSTATE sizes use current guest state, not root's temporary save mask. */
        if (!KswSvmNestedCpuid(&policy, KswSvmRead64(Execution->Current, KSW_VMCB_CR4),
            *Execution->GuestXcr0, *Execution->Registers.GuestXss, (unsigned)operand, (unsigned)Execution->Gpr[1], words)) { return KSW_NSVM_EXEC_FAULT; }
        /* Commit after the complete virtual response is available. */
        KswSvmWrite64(Execution->Current, KSW_VMCB_RAX, words[0]); Execution->Gpr[3] = words[1];
        /* RCX/RDX are not automatic VMCB registers. */
        Execution->Gpr[1] = words[2]; Execution->Gpr[2] = words[3];
        /* CPUID completed without any memory or ownership side effect. */
        return KswNsvmComplete(Execution);
    }
    /* Mandatory state MSRs never execute privileged root accesses with guest operands. */
    if (code == KSW_SVM_EXIT_MSR) {
        /* EXITINFO1 must encode exactly read or write, not an unknown operation. */
        KSW_SVM_U64 direction = KswSvmRead64(Execution->Current, KSW_VMCB_EXITINFO1);
        /* Reserved direction bits are a monitor/hardware-contract failure. */
        if (direction > 1) { return KSW_NSVM_EXEC_FAULT; }
        /* WRMSR ignores high halves of RAX/RDX. */
        value = ((Execution->Gpr[2] & 0xffffffffULL) << 32) | (operand & 0xffffffffULL);
        /* The shared register layer validates privilege and mode before writing software state. */
        result = KswSvmNestedRegisterAccess(&Execution->Registers, (unsigned)Execution->Gpr[1], (unsigned)direction, &value);
        /* Only an architectural refusal becomes #GP(0). */
        if (result == KSW_NSVM_MSR_GP) { return KswNsvmRaise(Execution, 13, 0, 0); }
        /* Unknown/unsupported register state remains explicitly unimplemented; never a root passthrough. */
        if (result != KSW_NSVM_MSR_OK) { return KSW_NSVM_EXEC_UNSUPPORTED; }
        /* Successful reads return zero-extended architectural halves. */
        if (!direction) { KswSvmWrite64(Execution->Current, KSW_VMCB_RAX, (unsigned)value); Execution->Gpr[2] = (unsigned)(value >> 32); }
        /* Accepted writes become hardware guest state on the following prepared VMRUN. */
        return KswNsvmComplete(Execution);
    }
    /* XSETBV changes are installed by the assembly state bridge after leaving C. */
    if (code == 0x8d) {
        /* Build the exact 64-bit guest operand. */
        value = ((Execution->Gpr[2] & 0xffffffffULL) << 32) | (operand & 0xffffffffULL);
        /* Prepared allocation bounds and architectural dependency checks are both mandatory. */
        result = KswSvmXcr0Write(Execution->PreparedXcr0, KswSvmRead64(Execution->Current, KSW_VMCB_CR4),
            ((const unsigned char*)Execution->Current)[KSW_VMCB_CPL], (unsigned)Execution->Gpr[1], value, Execution->GuestXcr0);
        /* Guest exceptions retain RIP and still honor L1 exception intercepts. */
        if (result == KSW_SVM_XCR_GP || result == KSW_SVM_XCR_UD) { return KswNsvmRaise(Execution, result, 0, 0); }
        /* Invalid monitor policy cannot be repaired by attempting a root XSETBV. */
        return result == KSW_SVM_XCR_OK ? KswNsvmComplete(Execution) : KSW_NSVM_EXEC_UNSUPPORTED;
    }
    /* SVM virtual instructions exist only in the admitted L1 virtual VMM. */
    if (code == KSW_SVM_EXIT_INVLPGA || (code >= 0x80 && code <= 0x86)) {
        /* Private KSword control calls must be consumed by the outer dispatcher before this engine. */
        if (inner || !Execution->Registers.ExposeSvm || !(Execution->Registers.Svm->Efer & KSW_SVM_EFER_SVME) ||
            !(KswSvmRead64(Execution->Current, KSW_VMCB_CR0) & 1ULL) ||
            (KswSvmRead64(Execution->Current, KSW_VMCB_RFLAGS) & (1ULL << 17))) { return KswNsvmRaise(Execution, 6, 0, 0); }
        /* SVM instructions other than the hypercall are privileged to the virtual host. */
        if (((const unsigned char*)Execution->Current)[KSW_VMCB_CPL]) { return KswNsvmRaise(Execution, 13, 0, 0); }
        /* No nested hypercall ABI is implemented here. */
        if (code == 0x81 || code == KSW_SVM_EXIT_SKINIT) { return KswNsvmRaise(Execution, 6, 0, 0); }
        /* General virtual VMRUN owns its actual L1 continuation and translated operand. */
        if (code == 0x80) {
            /* A virtual save area must be declared before acquiring a guest execution context. */
            if (!Execution->Registers.Svm->Hsave) { return KSW_NSVM_EXEC_UNSUPPORTED; }
            /* All controls/permission maps are captured and validated by the shared transaction. */
            result = KswSvmNestedSessionEnter(Execution->Session, Execution->Io, Execution->Current, operand);
            /* Entry and INVALID return each have their own architecture-defined GIF result. */
            if (result == KSW_NSVM_ACTION_ENTER || result == KSW_NSVM_ACTION_INVALID) {
                /* VMRUN sets L2 GIF; VMEXIT_INVALID clears the resumed virtual host's GIF. */
                Execution->Gif = Execution->GifRequested = result == KSW_NSVM_ACTION_ENTER;
                /* The transaction has already installed the appropriate RIP; do not advance again. */
                return KSW_NSVM_EXEC_RESUME;
            }
            /* Retained writeback/memory faults are distinct from software support restrictions. */
            return result == KSW_NSVM_ACTION_UNSUPPORTED ? KSW_NSVM_EXEC_UNSUPPORTED : KSW_NSVM_EXEC_FAULT;
        }
        /* VMLOAD/VMSAVE need the same per-HPA owner as VMRUN. */
        if (code == 0x82 || code == 0x83) {
            /* General operands are not restricted to a driver-owned fixed marker page. */
            result = KswSvmNestedSessionTransfer(Execution->Session, Execution->Io, Execution->Current, operand, code == 0x83);
            /* Successful transfer completes this instruction, not an entire virtual guest session. */
            if (result == KSW_NSVM_ACTION_RETURN) { return KswNsvmComplete(Execution); }
            /* A partial VMSAVE remains retained for diagnosis/recovery. */
            return result == KSW_NSVM_ACTION_UNSUPPORTED ? KSW_NSVM_EXEC_UNSUPPORTED : KSW_NSVM_EXEC_FAULT;
        }
        /* INVLPGA discards this CPU's entire virtual cache rather than using untrusted physical ASIDs. */
        if (code == KSW_SVM_EXIT_INVLPGA) {
            /* The following physical VMRUN still carries a full TLB flush request. */
            result = KswSvmNestedSessionInvalidate(Execution->Session, Execution->Io, operand, (unsigned)Execution->Gpr[1]);
            /* No progress is reported if cache reset did not complete. */
            return result == KSW_NSVM_ACTION_RETURN ? KswNsvmComplete(Execution) : KSW_NSVM_EXEC_FAULT;
        }
        /* CLGI/STGI are not complete until the platform can enforce the new physical masks. */
        Execution->GifRequested = code == 0x84;
        /* The caller must invoke the event bridge and CommitGif before any reentry. */
        return KSW_NSVM_EXEC_GIF_CHANGED;
    }
    /* A reflected L1 IOIO/HLT/etc. exit was already handled above; no arbitrary root I/O occurs here. */
    return KSW_NSVM_EXEC_UNSUPPORTED;
}
