/* Windows platform binding for the portable nested execution/event transactions. */
#include "hvm_svm_nested_runtime.h"
#include <intrin.h>

/* The coordinator never calls an OS interrupt handler to discover the current priority. */
static unsigned KswNsvmReadTpr(void* Context)
{
    /* The current CPU is pinned by the common entry/rendezvous lifecycle. */
    UNREFERENCED_PARAMETER(Context);
    /* CR8 contains only the architectural four-bit task-priority class. */
    return (unsigned)__readcr8();
}

/* This callback is used only in complete root state with physical GIF and IF closed. */
static int KswNsvmWriteTpr(void* Context, unsigned Value)
{
    /* No guest pointer or APIC MMIO address is accepted as an operand. */
    UNREFERENCED_PARAMETER(Context);
    /* A failed read must not be silently truncated to a valid interrupt priority. */
    if (Value > 15) { return 0; }
    /* Preserve native/virtual CR8 semantics without calling pageable Windows services. */
    __writecr8(Value);
    /* The control register is read back on the same processor. */
    return __readcr8() == Value;
}

/* The acknowledgement leaf retains its count until the queue explicitly accepts it. */
static unsigned KswNsvmAcknowledgeNmi(void* Context)
{
    /* This descriptor belongs to the current CPU's prepared nonpageable allocation. */
    KSW_SVM_CPU* cpu = Context;
    /* Missing/already active captures are not one successfully acknowledged NMI. */
    if (!cpu || !cpu->Nested || !cpu->Nested->Nmi.Ready || cpu->Nested->Nmi.Armed || cpu->Nested->Nmi.Count) { return ~0U; }
    /* Execute only after VMEXIT has restored host state and closed IF; no C callback is made by the leaf. */
    (VOID)KswordSvmAsmAcknowledgeNmi(&cpu->Nested->Nmi);
    /* Return the exact retained hardware observation, including zero/multiple/saturation. */
    return cpu->Nested->Nmi.Count;
}

/* This operation is not a physical acknowledgement; it transfers an already captured record. */
static int KswNsvmCommitNmi(void* Context, unsigned Count)
{
    /* Queue acceptance and this transfer both execute in the same root CPU window. */
    KSW_SVM_CPU* cpu = Context;
    /* Never clear evidence after a count mismatch or while the private IDT is still installed. */
    if (!cpu || !cpu->Nested || cpu->Nested->Nmi.Armed || Count != 1 || cpu->Nested->Nmi.Count != Count) { return 0; }
    /* The coordinator retains the event token before reaching this statement. */
    cpu->Nested->Nmi.Count = 0; return 1;
}

/* CPUID executes on the same prepared processor as VMRUN, never a worker with different affinity. */
static void KswNsvmGeneralCpuid(void* Context, unsigned Leaf, unsigned Subleaf, unsigned Words[4])
{
    /* MSVC intrinsics use signed integers; result bit patterns are converted explicitly. */
    int values[4];
    /* No callback state is needed for raw processor enumeration. */
    UNREFERENCED_PARAMETER(Context);
    /* The portable filter applies guest XSTATE/control/SVM policy afterwards. */
    __cpuidex(values, (int)Leaf, (int)Subleaf);
    /* CPUID always returns four zero-extended architectural dwords. */
    Words[0] = (unsigned)values[0]; Words[1] = (unsigned)values[1];
    /* No host-side sign extension can enter the guest's GPRs. */
    Words[2] = (unsigned)values[2]; Words[3] = (unsigned)values[3];
}

/* Stop remains a private L0 lifecycle operation, never an L2 VMMCALL escape. */
static unsigned KswNsvmGeneralControl(void* Context, KSW_NSVM_MACHINE* Machine)
{
    /* The common lifecycle supplies this exact processor's context. */
    KSW_SVM_CPU* cpu = Context;
    /* Return data is not a native-return decision until every prerequisite succeeds. */
    ULONGLONG value, next;
    /* Ordinary VMMCALLs follow the nested ownership/exception dispatcher. */
    unsigned native = 0;
    /* Do not consume a virtual inner VMM's own hypercall or an unprivileged request. */
    if (!cpu || !cpu->Nested || Machine->Execution->Session->Phase != KSW_NSVM_SESSION_IDLE ||
        Machine->LastExit != KSW_SVM_EXIT_VMMCALL || cpu->Gpr[1] != KSW_SVM_CALL_SIGNATURE ||
        ((PUCHAR)cpu->Guest)[KSW_VMCB_CPL]) { return KSW_NSVM_MACHINE_NOT_CONTROL; }
    /* A private control must have a complete architectural continuation before changing anything. */
    next = KswSvmRead64(cpu->Guest, KSW_VMCB_NRIP);
    /* Interrupted IDT delivery cannot masquerade as a completed hypercall. */
    if ((KswSvmRead64(cpu->Guest, KSW_VMCB_EXITINTINFO) & (1ULL << 31)) ||
        !KswSvmNextRipValid(KswSvmRead64(cpu->Guest, KSW_VMCB_RIP), next)) { return KSW_NSVM_MACHINE_FAULT; }
    /* Queries retain their established private response signature. */
    if (cpu->Gpr[2] == KSW_SVM_CALL_QUERY) { value = KSW_SVM_CALL_SIGNATURE; }
    /* Vote inspects the live session without changing residency or clearing virtual SVM ownership. */
    else if (cpu->Gpr[2] == KSW_SVM_CALL_QUIESCE && cpu->StopRequested == 2 && cpu->Active) {
        /* The caller waits for all votes in Windows IPI execution, never on this root stack. */
        value = KswSvmNestedMachineCanStop(Machine) == KSW_NSVM_STOP_READY ? 0 : (ULONG)STATUS_DEVICE_BUSY;
    }
    /* Only the IPI stop owner may request native execution on an active CPU. */
    else if (cpu->Gpr[2] == KSW_SVM_CALL_STOP && cpu->StopRequested == 1 && cpu->Active) {
        /* Busy retains resident ownership; a nonzero result prevents the caller's native readback path. */
        native = KswSvmNestedMachineCanStop(Machine) == KSW_NSVM_STOP_READY;
        /* Never clear virtual SVM ownership or discard pending events to make stop appear successful. */
        value = native ? 0 : (ULONG)STATUS_DEVICE_BUSY;
    } else { return KSW_NSVM_MACHINE_NOT_CONTROL; }
    /* Only a completed control writes its return value and advances RIP. */
    KswSvmWrite64(cpu->Guest, KSW_VMCB_RAX, value); KswSvmWrite64(cpu->Guest, KSW_VMCB_RIP, next);
    /* A completed instruction consumes a preceding single-instruction shadow. */
    KswSvmWrite64(cpu->Guest, 0x068U, 0); KswSvmWrite64(cpu->Guest, KSW_VMCB_EVENT, 0);
    /* Native assembly still has to restore the current guest state and acknowledge it separately. */
    return native ? KSW_NSVM_MACHINE_NATIVE : KSW_NSVM_MACHINE_READY;
}

/* Bind the prepared resource graph without allocating inside an entry/exit transition. */
NTSTATUS KswordSvmNestedInitializeGeneral(KSW_SVM_CPU* Cpu)
{
    /* All subordinate descriptors are embedded in the existing per-CPU allocation. */
    KSW_SVM_NESTED* nested;
    /* A packed IDTR operand is built from the trusted, current-CPU capture. */
    UCHAR idtr[16] = {0};
    /* Current Windows segment records were validated by the ordinary VMCB builder. */
    const KSW_SVM_SEGMENT* table;
    /* Every field gets an explicit owner rather than borrowing the bounded test's original snapshot. */
    KSW_NSVM_SESSION_IO* io;
    /* No partial or previously live state may be reinitialized. */
    if (!Cpu || !(nested = Cpu->Nested) || Cpu->SelfTest || Cpu->Active || nested->GeneralInitialized ||
        nested->Session.Lease.Token || nested->Session.Phase != KSW_NSVM_SESSION_IDLE ||
        !nested->Outer || !nested->Window || !Cpu->XstateLayout.Ready) { return STATUS_INVALID_DEVICE_STATE; }
    /* The software register owner starts from native SVM-free Windows state. */
    nested->Msrs.Efer = Cpu->Caps.Efer & ~KSW_SVM_EFER_SVME; nested->Msrs.Hsave = 0;
    /* Firmware disable/lock and the physical-width mask remain read-only virtual capabilities. */
    nested->Msrs.VmCr = Cpu->Caps.VmCr; nested->Msrs.AddressMask = nested->Outer->AddressMask;
    /* NPT01 is immutable for the complete prepared lifetime. */
    nested->Config.OuterRoot = nested->Outer->RootPa; nested->Config.OuterPat = Cpu->Caps.Pat;
    /* Both translations use the unchanged hardware PAT encoding. */
    nested->Config.HardwarePat = Cpu->Caps.Pat; nested->Config.OuterBits = Cpu->Caps.PhysicalBits;
    /* NPT address/large-page/NX policy comes from this same processor's admitted capabilities. */
    nested->Config.OuterPage1Gb = Cpu->Caps.Page1Gb; nested->Config.OuterNx = (Cpu->Caps.Efer & (1ULL << 11)) != 0;
    /* Session operands and page-table words all use the same validated RAM window. */
    io = &nested->GeneralIo; RtlZeroMemory(io, sizeof(*io));
    /* The operand snapshot must use L0 translation, never an inner NCR3 directly. */
    io->Operand.Root = nested->Config.OuterRoot; io->Operand.Pat = Cpu->Caps.Pat;
    /* These features match the outer NPT builder and the CPUID contract below. */
    io->Operand.PhysicalBits = Cpu->Caps.PhysicalBits; io->Operand.Page1Gb = Cpu->Caps.Page1Gb;
    /* No physical callback allocates or retains a mapped pointer across calls. */
    io->Operand.Nx = nested->Config.OuterNx; io->Operand.Read = KswordSvmNestedRead; io->Operand.Context = nested;
    /* Virtual capabilities cannot exceed what this prepared CPU can restore natively. */
    io->Policy.PhysicalBits = Cpu->Caps.PhysicalBits; io->Policy.AsidCount = Cpu->Caps.AsidCount;
    /* This first general contract still explicitly rejects unsupported CR4/EFER extensions. */
    io->Policy.EferSupported = Cpu->Caps.Efer | KSW_SVM_EFER_SVME; io->Policy.Cr4Supported = Cpu->Caps.Cr4;
    /* Exact writeback and cross-CPU VMCB authority are shared with the bounded probe. */
    io->Commit = KswordSvmNestedCommitVmcb; io->Owners = nested->Owners; io->CpuIdentity = nested->CpuIdentity;
    /* Both merged maps are hardware-contiguous prepared buffers. */
    io->MergedMsr = nested->MergedMaps; io->MergedIo = nested->MergedMaps + KSW_NSVM_MSRPM_BYTES;
    /* Guest-provided addresses are never substituted for these physical map identities. */
    io->MsrPa = nested->MergedMapsPa; io->IoPa = nested->MergedMapsPa + KSW_NSVM_MSRPM_BYTES; io->Asid = 1;
    /* The initial L0 intercept set is immutable even when per-entry masking overlays change MISC1. */
    io->OuterPermissions.Flags = (unsigned)KswSvmRead64(Cpu->Guest, KSW_VMCB_MISC1);
    /* L1 cannot weaken a bit in either immutable outer bitmap. */
    io->OuterPermissions.Msr = Cpu->Msrpm; io->OuterPermissions.Io = Cpu->Iopm;
    /* Every virtual CPU uses its own cache epoch and composition pages. */
    io->Shadow = &nested->Shadow; io->Mmu = &nested->Config;
    /* Bind the ordinary register image instead of a driver-owned fixed probe marker. */
    RtlZeroMemory(&nested->GeneralExecution, sizeof(nested->GeneralExecution));
    /* Hardware RAX/RSP remain in VMCB, while other GPRs use the established assembly prefix. */
    nested->GeneralExecution.Current = Cpu->Guest; nested->GeneralExecution.Gpr = Cpu->Gpr;
    /* The same live transaction handles every arbitrary admitted VMCB12 operand. */
    nested->GeneralExecution.Session = &nested->Session; nested->GeneralExecution.Io = io;
    /* XCR0/XSS write policies are bounded by the original allocation geometry. */
    nested->GeneralExecution.GuestXcr0 = &Cpu->GuestXcr0; nested->GeneralExecution.PreparedXcr0 = Cpu->HostXcr0;
    /* Register state is virtual except for the fixed root cache/state restore contract. */
    nested->GeneralExecution.Registers.Current = Cpu->Guest; nested->GeneralExecution.Registers.Svm = &nested->Msrs;
    /* XSAVE format and capacity never shrink when the guest chooses fewer enabled components. */
    nested->GeneralExecution.Registers.GuestXss = &Cpu->GuestXss; nested->GeneralExecution.Registers.PreparedXss = Cpu->HostXss;
    /* Cache/MSR support matches admission and CPUID enumeration. */
    nested->GeneralExecution.Registers.RootPat = Cpu->Caps.Pat; nested->GeneralExecution.Registers.EferAllowed = io->Policy.EferSupported;
    /* Supervisor CET remains excluded by the underlying entry/restore contract. */
    nested->GeneralExecution.Registers.XsaveFeatures = Cpu->Caps.XsaveFeatures; nested->GeneralExecution.Registers.CetPresent = Cpu->Caps.CetPresent;
    /* Exposure here is internal policy only; this function does not activate the public resident path. */
    nested->GeneralExecution.Registers.ExposeSvm = 1;
    /* CPUID capabilities refer to preallocated state and this virtual ASID namespace. */
    nested->GeneralExecution.Cpuid.Xstate = &Cpu->XstateLayout; nested->GeneralExecution.Cpuid.ExposeSvm = 1;
    /* Only implemented feature bits are published by the portable CPUID filter. */
    nested->GeneralExecution.Cpuid.AsidCount = Cpu->Caps.AsidCount; nested->GeneralExecution.Cpuid.SvmFeatures = Cpu->Caps.Features;
    /* Physical and CR4 widths agree with VMCB/operand validation. */
    nested->GeneralExecution.Cpuid.PhysicalBits = Cpu->Caps.PhysicalBits; nested->GeneralExecution.Cpuid.Cr4Supported = io->Policy.Cr4Supported;
    /* Raw topology/vendor data remains tied to this CPU rather than a cached different core. */
    nested->GeneralExecution.Cpuid.Read = KswNsvmGeneralCpuid; nested->GeneralExecution.Cpuid.Context = Cpu;
    /* Source table A/D changes use compare-exchange under the same physical RAM admission. */
    nested->GeneralExecution.MmuIo.Read = KswordSvmNestedRead; nested->GeneralExecution.MmuIo.CompareOr = KswordSvmNestedCompareOr;
    /* No global root lock or guest pointer is passed to the walker. */
    nested->GeneralExecution.MmuIo.Context = nested;
    /* NMI table preparation uses the trusted original host IDTR, never an inner guest image. */
    table = (const KSW_SVM_SEGMENT*)((const UCHAR*)Cpu->Guest + KSW_VMCB_IDTR);
    /* Keep the hardware's packed descriptor format explicit. */
    RtlCopyMemory(idtr, &table->limit, sizeof(USHORT)); RtlCopyMemory(idtr + 2, &table->base, sizeof(ULONGLONG));
    /* A stale/unreadable trusted table refuses admission before any real SVM ownership changes. */
    __try {
        /* The private NMI gate uses this same CPU's captured kernel code selector. */
        if (!KswordSvmNmiInitialize(&nested->Nmi, idtr, ((KSW_SVM_SEGMENT*)((PUCHAR)Cpu->Guest + KSW_VMCB_CS))->selector)) { return STATUS_NOT_SUPPORTED; }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    /* Binding callbacks is separate from issuing any physical entry or NMI acknowledgement. */
    RtlZeroMemory(&nested->GeneralMachine, sizeof(nested->GeneralMachine));
    /* Every state object remains embedded in the retained per-CPU resource allocation. */
    nested->GeneralMachine.Execution = &nested->GeneralExecution; nested->GeneralMachine.Io.Context = Cpu;
    /* Physical acknowledgement is exactly the bounded root leaf, followed by explicit queue handoff. */
    nested->GeneralMachine.Io.AcknowledgeNmi = KswNsvmAcknowledgeNmi; nested->GeneralMachine.Io.CommitNmi = KswNsvmCommitNmi;
    /* CR8 synchronization and private lifecycle controls have their own narrow callbacks. */
    nested->GeneralMachine.Io.ReadTpr = KswNsvmReadTpr; nested->GeneralMachine.Io.WriteTpr = KswNsvmWriteTpr;
    /* Private control cannot run until raw overlay/event state has been processed. */
    nested->GeneralMachine.Io.PrivateControl = KswNsvmGeneralControl;
    /* Capture actual initial TPR, but do not create an executable overlay before assembly sets final RIP/RFLAGS. */
    if (KswSvmNestedMachineInitialize(&nested->GeneralMachine) != KSW_NSVM_MACHINE_READY) { return STATUS_NOT_SUPPORTED; }
    /* This is bound-resource readiness; public activation and hardware success are separate evidence. */
    nested->GeneralInitialized = 1; return STATUS_SUCCESS;
}

/* The assembly-facing caller is responsible for refusing every non-READY action. */
ULONG KswordSvmNestedGeneralEntry(KSW_SVM_CPU* Cpu)
{
    /* No dormant/unbound descriptor may be used as a hardware entry request. */
    ULONG action;
    /* Do not turn a missing optional resource into baseline residency silently. */
    if (!Cpu || !Cpu->Nested || !Cpu->Nested->GeneralInitialized) { return KSW_NSVM_MACHINE_FAULT; }
    /* This writes only processor-owned state and invokes the closed-root callbacks above. */
    action = KswSvmNestedMachineEntry(&Cpu->Nested->GeneralMachine);
    /* Host IF is installed by assembly while physical GIF remains closed. */
    if (action == KSW_NSVM_MACHINE_READY) { Cpu->HostInterruptsAllowed = Cpu->Nested->GeneralMachine.Overlay.HostIf; }
    /* WINDOW/FAULT/UNSUPPORTED never authorize a blind VMRUN. */
    return action;
}

/* Raw hardware exit accounting remains owned by the common SVM dispatcher. */
ULONG KswordSvmNestedGeneralExit(KSW_SVM_CPU* Cpu)
{
    /* Initialization and activation are deliberately separate contracts. */
    if (!Cpu || !Cpu->Nested || !Cpu->Nested->GeneralInitialized) { return KSW_NSVM_MACHINE_FAULT; }
    /* Native return is requested only by the private, quiescent stop callback. */
    return KswSvmNestedMachineExit(&Cpu->Nested->GeneralMachine);
}

/* Do not release the host stack/HSAVE simply because a nested sub-release refused to free itself. */
BOOLEAN KswordSvmNestedBusy(const KSW_SVM_CPU* Cpu)
{
    /* Partial preparation is releasable when no owner exists. */
    const KSW_SVM_NESTED* nested;
    /* The common CPU active bit remains authoritative for ordinary residency as well. */
    if (!Cpu || Cpu->Active) { return TRUE; }
    /* No optional allocation means there is no nested owner to retain. */
    if (!(nested = Cpu->Nested)) { return FALSE; }
    /* Both general and bounded-probe VMCB ownership must be gone before release. */
    if (nested->RunningL2 || nested->Session.Lease.Token || nested->Session.Phase == KSW_NSVM_SESSION_L2 ||
        nested->Nmi.Armed || nested->Nmi.Count) { return TRUE; }
    /* Acknowledged events or executable overlay windows retain their containing CPU resources. */
    return nested->GeneralExecution.Pending.Count || nested->GeneralMachine.ArmedToken ||
        nested->GeneralMachine.NmiCount || nested->GeneralMachine.Overlay.Applied || nested->GeneralMachine.IrqWindow.Applied;
}
