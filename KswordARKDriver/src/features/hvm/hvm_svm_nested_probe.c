/* Bounded executable nesting probe. This is not admission for an arbitrary inner VMM. */
#include "hvm_svm_nested_runtime.h"

/* Capture permission pages through the prepared outer translation and RAM guard. */
static int KswNsvmProbeReadMap(void* Context, KSW_SVM_U64 Address, unsigned char* Page)
{
    /* Only trusted outer translation metadata is borrowed from the current CPU. */
    KSW_SVM_CPU* cpu = Context;
    /* Configuration remains fixed for the entire prepared backend lifetime. */
    KSW_SVM_NESTED* nested = cpu->Nested;
    /* Source access never uses VMCB12's NCR3 or guest PAT as the outer authority. */
    KSW_NSVM_OPERAND_IO io;
    /* Bind both source translation and cache interpretation to L0. */
    io.Root = nested->Config.OuterRoot; io.Pat = nested->Config.OuterPat;
    /* Match the actual outer CPU's physical-address and paging features. */
    io.PhysicalBits = nested->Config.OuterBits; io.Page1Gb = nested->Config.OuterPage1Gb;
    /* The same platform callback protects page-table and final data RAM reads. */
    io.Nx = nested->Config.OuterNx; io.Read = KswordSvmNestedRead; io.Context = nested;
    /* Failure remains distinct from an all-zero permission map. */
    return KswSvmNestedReadOperandPage(&io, Address, Page, &nested->LastOperand) == KSW_NNPT_OK;
}

/* Complete the controlled probe using its original, fully captured Windows context. */
static ULONG KswNsvmFinish(KSW_SVM_CPU* Cpu, NTSTATUS Status)
{
    /* The begin marker is observed before the probe changes any nonvolatile GPR. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Preserve the actual exit before replacing the executable image. */
    if (!NT_SUCCESS(Status)) { KswordSvmTrace(Cpu, KSWORD_ARK_HVM_STAGE_FAILED); }
    /* Only the bounded probe may return to this initial snapshot. */
    if (nested->Begun) {
        /* Restore the Windows state captured immediately after real first entry. */
        RtlCopyMemory(Cpu->Guest, &nested->Original, sizeof(*Cpu->Guest));
        /* Restore the caller's nonvolatile registers even on an early probe abort. */
        RtlCopyMemory(Cpu->Gpr, nested->OriginalGpr, sizeof(Cpu->Gpr));
    }
    /* No later VMRUN can reference the inner image after this native return request. */
    nested->RunningL2 = 0;
    /* The assembly path owns real SVME/HSAVE release; clear only virtual ownership here. */
    nested->Msrs.Efer &= ~KSW_SVM_EFER_SVME;
    /* A failed test must not leave virtual ownership in the next test's context. */
    nested->Msrs.Hsave = 0;
    /* Self-test return status remains separate from the assembly continuation's EAX. */
    Cpu->Result = Status;
    /* Restore the known entry CALL chain rather than an arbitrary rejected operand. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmGuestResume);
    /* The original caller stack includes its untouched return address. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RSP, Cpu->LaunchRsp);
    /* CLI inside the test must not leak IF=0 back into Windows. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RFLAGS, Cpu->LaunchFlags);
    /* Request complete native assembly restoration, not another VMRUN. */
    return 1;
}

/* Validate and consume hardware NRIP for a completed virtual instruction. */
static BOOLEAN KswNsvmAdvance(KSW_SVM_CPU* Cpu)
{
    /* Never guess the size of an intercepted instruction. */
    ULONGLONG next = KswSvmRead64(Cpu->Guest, KSW_VMCB_NRIP);
    /* Invalid NRIP aborts this bounded test with complete native restoration. */
    if (!KswSvmNextRipValid(KswSvmRead64(Cpu->Guest, KSW_VMCB_RIP), next)) { return FALSE; }
    /* The operation completed; exceptions do not use this helper. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RIP, next);
    /* The dispatcher may now reenter its current VMCB. */
    return TRUE;
}

/* Construct the only admitted VMCB12 from the validated current Windows image. */
NTSTATUS KswordSvmNestedBuildProbe(KSW_SVM_CPU* Cpu)
{
    /* Resources can only have been acquired by explicit prepare-svm-probe. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* A missing pool is a preparation failure, never a reason to allocate at high IRQL. */
    if (!nested || !nested->Operand || !nested->Stack || !nested->MergedMaps ||
        !nested->Shadow.Pages || nested->RunningL2) { return STATUS_DEVICE_NOT_READY; }
    /* Previous permission snapshots cannot authorize a later probe invocation. */
    nested->Permissions.Ready = 0;
    /* Reusing this CPU must invalidate previous shadow translations/evidence. */
    if (KswSvmNestedShadowReset(&nested->Shadow) != KSW_NSHADOW_OK) { return STATUS_INTEGER_OVERFLOW; }
    /* Invalidate previous published completion before changing any probe evidence. */
    InterlockedIncrement(&nested->Sequence);
    /* Each test begins with no successful inner hardware entry or reflection. */
    nested->Begun = nested->Entries = nested->Reflections = nested->Faults = 0;
    /* Reset raw evidence separately from the public baseline exit counter. */
    nested->LastExit = nested->LastMarker = 0;
    /* Software GIF is diagnostic in this IF=0 bounded probe, not full NMI virtualization. */
    nested->VirtualGif = 1;
    /* Start with the Windows-visible EFER, which has no virtual SVM owner. */
    nested->Msrs.Efer = Cpu->OriginalEfer;
    /* Never inherit a previous test's virtual save-area declaration. */
    nested->Msrs.Hsave = 0;
    /* Preserve firmware's observed lock/disable state. */
    nested->Msrs.VmCr = Cpu->Caps.VmCr;
    /* MSR operands use the exact CPU address-width contract. */
    nested->Msrs.AddressMask = nested->Outer->AddressMask;
    /* No old operand/control residue is allowed to survive into the next test. */
    RtlZeroMemory(nested->Operand, 8192);
    /* Copy only from the VMCB just validated by the regular current-CPU builder. */
    RtlCopyMemory(nested->Operand, Cpu->Guest, sizeof(*Cpu->Guest));
    /* Inner execution starts at a fixed nonpageable CPUID marker. */
    KswSvmWrite64(nested->Operand, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmNestedPayload);
    /* The test never borrows an interruptible user-mode stack. */
    KswSvmWrite64(nested->Operand, KSW_VMCB_RSP,
        ((ULONGLONG)(ULONG_PTR)nested->Stack + KSW_SVM_STACK_BYTES - 64ULL) & ~15ULL);
    /* No maskable interrupt is expected in the bounded inner instruction sequence. */
    KswSvmWrite64(nested->Operand, KSW_VMCB_RFLAGS, 2);
    /* The first inner instruction supplies the marker, not this initialization. */
    KswSvmWrite64(nested->Operand, KSW_VMCB_RAX, 0);
    /* A known baseline DR7 prevents an inherited instruction breakpoint from changing the probe. */
    KswSvmWrite64(nested->Operand, KSW_VMCB_DR7, 0x400);
    /* The driver-owned identity NPT serves as the initial NPT12 operand. */
    nested->Config.InnerRoot = nested->Outer->RootPa;
    /* The outer root stays immutable apart from hardware/software A/D. */
    nested->Config.OuterRoot = nested->Outer->RootPa;
    /* This bounded test uses the already validated, unchanged hardware PAT at all levels. */
    nested->Config.InnerPat = nested->Config.OuterPat = nested->Config.HardwarePat = Cpu->Caps.Pat;
    /* Match candidate translations to the newly reset software cache. */
    nested->Config.Epoch = nested->Shadow.Epoch;
    /* Both stages run under the same verified virtual CPU address-width capability. */
    nested->Config.InnerBits = nested->Config.OuterBits = Cpu->Caps.PhysicalBits;
    /* The outer VMM's advertised large-page limit is authoritative. */
    nested->Config.InnerPage1Gb = nested->Config.OuterPage1Gb = Cpu->Caps.Page1Gb;
    /* Preserve the current paging owner's NX enablement independently from leaf bits. */
    nested->Config.InnerNx = nested->Config.OuterNx = (Cpu->OriginalEfer & (1ULL << 11)) != 0;
    /* Preserve the operand for the first bounded guest instruction sequence. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RAX, nested->OperandPa);
    /* Only construction completed here; the self-test still needs actual hardware execution. */
    return STATUS_SUCCESS;
}

/* Reflection restores virtual host core state while retaining VMLOAD-managed state. */
static VOID KswNsvmReflect(KSW_SVM_CPU* Cpu)
{
    /* Current image is VMCB02 until the final copy below. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Preserve full-width raw evidence before switching images. */
    nested->LastExit = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITCODE);
    /* CPUID marker is still in hardware-saved guest RAX at this point. */
    nested->LastMarker = KswSvmRead64(Cpu->Guest, KSW_VMCB_RAX);
    /* Hardware VMRUN/VMEXIT do not implicitly execute VMLOAD/VMSAVE for L1. */
    KswSvmNestedCopyVmload(&nested->L1, Cpu->Guest);
    /* CR2 and DR6 are not part of the automatically restored host-state subset. */
    KswSvmWrite64(&nested->L1, KSW_VMCB_CR2, KswSvmRead64(Cpu->Guest, KSW_VMCB_CR2));
    /* Preserve current debug status rather than reverting it to a launch snapshot. */
    KswSvmWrite64(&nested->L1, KSW_VMCB_DR6, KswSvmRead64(Cpu->Guest, KSW_VMCB_DR6));
    /* Reflect the inner exit only into the pre-owned operand page. */
    KswSvmNestedReflectExit(nested->Operand, Cpu->Guest, 1);
    /* Restore the virtual host image captured after advancing its VMRUN continuation. */
    RtlCopyMemory(Cpu->Guest, &nested->L1, sizeof(*Cpu->Guest));
    /* VMEXIT forces host CPL zero and CR0.PE, and disables its debug breakpoints. */
    ((PUCHAR)Cpu->Guest)[KSW_VMCB_CPL] = 0;
    /* Preserve all other host CR0 bits. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_CR0, KswSvmRead64(Cpu->Guest, KSW_VMCB_CR0) | 1ULL);
    /* RF clears on completed VMRUN and VM is forced clear by VMEXIT. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RFLAGS, KswSvmRead64(Cpu->Guest, KSW_VMCB_RFLAGS) & ~0x30000ULL);
    /* Architectural fixed DR7 bit remains one. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_DR7, 0x400);
    /* No inner execution may be mistaken for the final outer CPUID. */
    nested->RunningL2 = 0;
    /* Track virtual GIF separately from the real root GIF held by assembly. */
    nested->VirtualGif = 0;
    /* Count a reflection only after the complete outer continuation has been restored. */
    ++nested->Reflections;
}

/* Resolve a real hardware NPF into the preallocated NPT02. */
static ULONG KswNsvmNpf(KSW_SVM_CPU* Cpu)
{
    /* The prepared state survives until the native continuation completes. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Raw NPF context must be preserved through software composition. */
    ULONGLONG info = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITINFO1);
    /* Fault GPA is relative to the inner guest, not a host physical address. */
    ULONGLONG gpa = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITINFO2);
    /* Install the production physical-window adapter. */
    KSW_NMMU_IO io = { KswordSvmNestedRead, KswordSvmNestedCompareOr, nested };
    /* Preserve the resolver outcome separately from the hardware exit code. */
    ULONG status;
    /* The probe must make bounded progress even with a repeatedly changing source table. */
    if (++nested->Faults > 128U) { return KswNsvmFinish(Cpu, STATUS_IO_TIMEOUT); }
    /* No allocation, wait, pageable access or OS memory mapping occurs here. */
    status = KswSvmNestedMmuResolve(&nested->Config, &io, gpa,
        (ULONG)(info & (KSW_NNPT_WRITE | KSW_NNPT_EXECUTE)), info & (KSW_NMMU_FINAL | KSW_NMMU_TABLE),
        &nested->LastTranslation);
    /* A competing A/D update is retried by the same bounded hardware NPF loop. */
    if (status == KSW_NNPT_RETRY) { return 0; }
    /* Failed translation never falls back to the outer identity root. */
    if (status != KSW_NNPT_OK) { return KswNsvmFinish(Cpu, STATUS_HV_OPERATION_FAILED); }
    /* Publish only a candidate from the current shadow epoch. */
    if (KswSvmNestedShadowInstall(&nested->Shadow, &nested->LastTranslation) != KSW_NSHADOW_OK) {
        /* Retain raw fault/resolution evidence for KD before returning natively. */
        return KswNsvmFinish(Cpu, STATUS_INSUFFICIENT_RESOURCES);
    }
    /* The existing assembly loop issues TLB_CONTROL=1 on every actual VMRUN. */
    return 0;
}

/* Execute virtual SVM only for the exact, driver-owned bounded probe. */
ULONG KswordSvmNestedProbeExit(KSW_SVM_CPU* Cpu)
{
    /* No user-provided VM or arbitrary guest physical operand is admitted here. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Retain the exact architecture code, including 64-bit INVALID. */
    ULONGLONG code = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITCODE);
    /* Guest accumulator is stored in VMCB, not the host RAX register. */
    ULONGLONG operand = KswSvmRead64(Cpu->Guest, KSW_VMCB_RAX);
    /* An entry may be rejected before the initial begin hypercall executed. */
    if (code == KSW_SVM_EXIT_INVALID) { return KswNsvmFinish(Cpu, STATUS_HV_OPERATION_FAILED); }
    /* First capture occurs before assembly touches any nonvolatile caller register. */
    if (!nested->Begun) {
        /* A different first exit cannot count as an executable probe. */
        if (code != KSW_SVM_EXIT_VMMCALL || Cpu->Gpr[1] != KSW_SVM_CALL_SIGNATURE ||
            Cpu->Gpr[2] != KSW_NSVM_BEGIN || operand != nested->OperandPa) { return KswNsvmFinish(Cpu, STATUS_DATA_ERROR); }
        /* Snapshot the actual first guest context, not the pre-VMRUN builder's incomplete RIP/RSP. */
        RtlCopyMemory(&nested->Original, Cpu->Guest, sizeof(*Cpu->Guest));
        /* Preserve all non-VMCB registers before the probe starts modifying them. */
        RtlCopyMemory(nested->OriginalGpr, Cpu->Gpr, sizeof(Cpu->Gpr));
        /* Publish that controlled native abort is now fully restorable. */
        nested->Begun = 1;
        /* Resume immediately after the begin marker. */
        return KswNsvmAdvance(Cpu) ? 0 : KswNsvmFinish(Cpu, STATUS_DATA_ERROR);
    }
    /* A current inner image needs inner exit routing before ordinary SVM handling. */
    if (nested->RunningL2) {
        /* Sparse NPT02 creates demand faults even for guest page-table walks. */
        if (code == KSW_SVM_EXIT_NPF) { return KswNsvmNpf(Cpu); }
        /* Only execution of the known inner marker proves this probe's hardware entry. */
        if (code != KSW_SVM_EXIT_CPUID || (ULONG)operand != KSW_NSVM_INNER_MARKER ||
            KswSvmNestedInterceptRequested(&nested->Vmcb12, code) != 1U) {
            /* Unknown exits are evidence of failure, never a guessed successful reflection. */
            return KswNsvmFinish(Cpu, STATUS_HV_OPERATION_FAILED);
        }
        /* Return to the actual L1 continuation after its intercepted VMRUN. */
        KswNsvmReflect(Cpu);
        /* Reenter the restored outer VMCB, not the inner one. */
        return 0;
    }
    /* Every admitted SVM/MSR operation belongs to the kernel-only test sequence. */
    if (((PUCHAR)Cpu->Guest)[KSW_VMCB_CPL] != 0) { return KswNsvmFinish(Cpu, STATUS_ACCESS_DENIED); }
    /* Virtual MSRs are exercised before and after the actual inner execution. */
    if (code == KSW_SVM_EXIT_MSR) {
        /* Reconstruct WRMSR's EDX:EAX operand with architectural truncation. */
        ULONGLONG value = ((Cpu->Gpr[2] & 0xffffffffULL) << 32) | (operand & 0xffffffffULL);
        /* Intercept info distinguishes reads from writes. */
        ULONG write = (ULONG)(KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITINFO1) & 1ULL);
        /* No real RDMSR/WRMSR is performed by this virtual ownership handler. */
        if (KswSvmNestedMsrAccess(&nested->Msrs, (ULONG)Cpu->Gpr[1], write, &value) != KSW_NSVM_MSR_OK) {
            /* A rejected test operation terminates the bounded test; it is not a general exception emulator. */
            return KswNsvmFinish(Cpu, STATUS_HV_OPERATION_FAILED);
        }
        /* RDMSR writes both guest halves with zero extension. */
        if (!write) { KswSvmWrite64(Cpu->Guest, KSW_VMCB_RAX, (ULONG)value); Cpu->Gpr[2] = (ULONG)(value >> 32); }
    } else if (code == 0x82ULL || code == 0x83ULL) {
        /* Software VMLOAD/VMSAVE may access only the dedicated operand in this phase. */
        if (!(nested->Msrs.Efer & KSW_SVM_EFER_SVME) || operand != nested->OperandPa) { return KswNsvmFinish(Cpu, STATUS_ACCESS_DENIED); }
        /* VMLOAD changes only its own architectural subset in the current executable image. */
        if (code == 0x82ULL) { KswSvmNestedCopyVmload(Cpu->Guest, nested->Operand); }
        /* VMSAVE leaves all VMRUN controls and automatic state untouched. */
        else { KswSvmNestedCopyVmload(nested->Operand, Cpu->Guest); }
    } else if (code == KSW_SVM_EXIT_VMRUN) {
        /* Keep source ownership separate from the executable combined permission maps. */
        KSW_NSVM_PERMISSION_VIEW outer, inner;
        /* Entry is restricted to the fixed probe operand and its declared virtual HSAVE. */
        if (!(nested->Msrs.Efer & KSW_SVM_EFER_SVME) || operand != nested->OperandPa ||
            nested->Msrs.Hsave != nested->OperandPa + 4096ULL || nested->Entries ||
            (KswSvmRead64(Cpu->Guest, KSW_VMCB_RFLAGS) & 0x200ULL)) { return KswNsvmFinish(Cpu, STATUS_INVALID_DEVICE_STATE); }
        /* The operand belongs to this CPU and cannot be changed by another test participant. */
        RtlCopyMemory(&nested->Vmcb12, nested->Operand, sizeof(nested->Vmcb12));
        /* Capture a private L1 map image before changing any executable controls. */
        if (!KswSvmNestedCapturePermissions(&nested->Permissions,
            *(ULONG*)(nested->Vmcb12.control + KSW_VMCB_MISC1),
            KswSvmRead64(&nested->Vmcb12, KSW_VMCB_MSRPM),
            KswSvmRead64(&nested->Vmcb12, KSW_VMCB_IOPM), Cpu->Caps.PhysicalBits,
            KswNsvmProbeReadMap, Cpu) || !KswSvmNestedPermissionView(&nested->Permissions, &inner)) {
            /* A partial or foreign map never reaches VMRUN. */
            return KswNsvmFinish(Cpu, STATUS_ACCESS_DENIED);
        }
        /* Outer maps are frozen per CPU for the lifetime of this backend prepare. */
        outer.Flags = *(ULONG*)(Cpu->Guest->control + KSW_VMCB_MISC1);
        /* Read the original owned maps, not the inner operand's physical pointers. */
        outer.Msr = Cpu->Msrpm; outer.Io = Cpu->Iopm;
        /* L0 restrictions survive every attempted inner permission relaxation. */
        if (!KswSvmNestedMergePermissions(&outer, &inner, nested->MergedMaps,
            nested->MergedMaps + KSW_NSVM_MSRPM_BYTES)) { return KswNsvmFinish(Cpu, STATUS_DATA_ERROR); }
        /* Preserve the correct host continuation; VMRUN completes only after reflection. */
        if (!KswNsvmAdvance(Cpu)) { return KswNsvmFinish(Cpu, STATUS_DATA_ERROR); }
        /* Capture complete L1 state privately rather than interpreting hardware HSAVE bytes. */
        RtlCopyMemory(&nested->L1, Cpu->Guest, sizeof(*Cpu->Guest));
        /* Copy only the automatic guest-state subset; retain L1's current VMLOAD state. */
        KswSvmNestedCopyVmrun(Cpu->Guest, &nested->Vmcb12, 1);
        /* Hardware receives only our owned shadow root, never NPT12 directly. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_NCR3, nested->Pages[0].Physical);
        /* Hardware sees only the independently owned, complete merged permission maps. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_MSRPM, nested->MergedMapsPa);
        /* IOPM starts after the two contiguous MSRPM pages. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_IOPM, nested->MergedMapsPa + KSW_NSVM_MSRPM_BYTES);
        /* Preserve raw non-map L0 intercepts as well as every fixed inner request. */
        KswSvmWrite32(Cpu->Guest, KSW_VMCB_MISC1,
            outer.Flags | *(ULONG*)(nested->Vmcb12.control + KSW_VMCB_MISC1));
        /* Miscellaneous SVM instruction interception remains owned by L0. */
        KswSvmWrite32(Cpu->Guest, KSW_VMCB_MISC2,
            *(ULONG*)(nested->L1.control + KSW_VMCB_MISC2) | *(ULONG*)(nested->Vmcb12.control + KSW_VMCB_MISC2));
        /* The bounded payload injects no event into its inner context. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_EVENT, 0);
        /* Every shadow mapping initially faults and must pass both source translations. */
        nested->RunningL2 = 1;
        /* VMRUN sets virtual GIF for its guest, independently from outer host GIF. */
        nested->VirtualGif = 1;
        /* Actual success still requires the executed marker and reflected continuation. */
        ++nested->Entries;
        /* The assembly host loop performs the real VMRUN with this VMCB02 image. */
        return 0;
    } else if (code == 0x84ULL) {
        /* The probe restores virtual GIF before returning to the Windows continuation. */
        if (!(nested->Msrs.Efer & KSW_SVM_EFER_SVME)) { return KswNsvmFinish(Cpu, STATUS_INVALID_DEVICE_STATE); }
        /* This bounded IF=0 path does not advertise general IRQ/NMI virtualization. */
        nested->VirtualGif = 1;
    } else if (code == KSW_SVM_EXIT_CPUID && (ULONG)operand == KSW_NSVM_DONE_MARKER) {
        /* Final success requires both hardware entry/reflection and virtual ownership cleanup. */
        BOOLEAN passed = nested->Entries == 1 && nested->Reflections == 1 && nested->Faults != 0 &&
            nested->LastExit == KSW_SVM_EXIT_CPUID && nested->LastMarker == KSW_NSVM_INNER_MARKER &&
            !(nested->Msrs.Efer & KSW_SVM_EFER_SVME) && !nested->Msrs.Hsave && nested->VirtualGif;
        /* Complete native restoration before the public per-CPU self-test result is counted. */
        return KswNsvmFinish(Cpu, passed ? STATUS_SUCCESS : STATUS_HV_OPERATION_FAILED);
    } else {
        /* The bounded probe has no legitimate unknown instruction/exception exit. */
        return KswNsvmFinish(Cpu, STATUS_NOT_SUPPORTED);
    }
    /* Resume only a successfully completed virtual instruction with valid hardware NRIP. */
    return KswNsvmAdvance(Cpu) ? 0 : KswNsvmFinish(Cpu, STATUS_DATA_ERROR);
}
