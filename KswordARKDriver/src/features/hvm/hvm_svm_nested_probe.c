/* Bounded executable nesting probe. This is not admission for an arbitrary inner VMM. */
#include "hvm_svm_nested_runtime.h"

/* Bind operand IO only to the immutable outer translation and the CPU's RAM window. */
static VOID KswNsvmProbeIo(KSW_SVM_CPU* Cpu, KSW_NSVM_OPERAND_IO* Io)
{
    /* Configuration remains fixed for the entire prepared backend lifetime. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Bind both source translation and cache interpretation to L0. */
    Io->Root = nested->Config.OuterRoot; Io->Pat = nested->Config.OuterPat;
    /* Match the actual outer CPU's physical-address and paging features. */
    Io->PhysicalBits = nested->Config.OuterBits; Io->Page1Gb = nested->Config.OuterPage1Gb;
    /* The same platform callback protects page-table and final data RAM reads. */
    Io->Nx = nested->Config.OuterNx; Io->Read = KswordSvmNestedRead; Io->Context = nested;
}

/* Capture permission/VMCB pages through the prepared outer translation and RAM guard. */
static int KswNsvmProbeReadMap(void* Context, KSW_SVM_U64 Address, unsigned char* Page)
{
    /* Source access never uses VMCB12's NCR3 or PAT as the outer authority. */
    KSW_SVM_CPU* cpu = Context;
    /* A small stack descriptor borrows only immutable outer mapping metadata. */
    KSW_NSVM_OPERAND_IO io;
    /* Use the same outer translation contract for reads and architectural writeback. */
    KswNsvmProbeIo(cpu, &io);
    /* Failure remains distinct from an all-zero permission map. */
    return KswSvmNestedReadOperandPage(&io, Address, Page, &cpu->Nested->LastOperand) == KSW_NNPT_OK;
}

/* Exercise the general architectural writeback path on the probe's owned operand. */
static BOOLEAN KswNsvmProbeWrite(KSW_SVM_CPU* Cpu, ULONG Operation)
{
    /* The probe's physical operand is identity mapped; general callers retain captured HPA. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Do not carry a mapped pointer across a root callback. */
    KSW_NSVM_OPERAND_IO io;
    /* The source page is a CPU-owned snapshot, never the mutable guest mapping. */
    KswNsvmProbeIo(Cpu, &io);
    /* A rejected or partial commit must stop this test instead of resuming with stale data. */
    return KswSvmNestedWriteback(&io, nested->OperandPa, nested->OperandPa,
        &nested->Session.Vmcb12, Operation, 1, KswordSvmNestedCommitVmcb, &nested->LastOperand) == KSW_NNPT_OK;
}

/* Select the probe's prepared storage for the same transaction used by general VMRUN. */
static VOID KswNsvmProbeSessionIo(KSW_SVM_CPU* Cpu, KSW_NSVM_SESSION_IO* Io)
{
    /* Ownership remains processor-local throughout the transaction. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* Bind physical access to the trusted outer map. */
    KswNsvmProbeIo(Cpu, &Io->Operand);
    /* The probe does not introduce control features absent from its current Windows state. */
    Io->Policy.PhysicalBits = Cpu->Caps.PhysicalBits; Io->Policy.AsidCount = Cpu->Caps.AsidCount;
    /* General capability exposure must separately provide its implemented virtual feature mask. */
    Io->Policy.EferSupported = Cpu->Caps.Efer | KSW_SVM_EFER_SVME; Io->Policy.Cr4Supported = Cpu->Caps.Cr4;
    /* Output uses the verified per-CPU physical window, with architectural field masks. */
    Io->Commit = KswordSvmNestedCommitVmcb;
    /* Host-owned combined maps are contiguous but retain their two architectural sizes. */
    Io->MergedMsr = nested->MergedMaps; Io->MergedIo = nested->MergedMaps + KSW_NSVM_MSRPM_BYTES;
    /* These hardware addresses were resolved and verified at PASSIVE_LEVEL. */
    Io->MsrPa = nested->MergedMapsPa; Io->IoPa = nested->MergedMapsPa + KSW_NSVM_MSRPM_BYTES;
    /* Full hardware flush on every entry permits the existing CPU-local ASID reuse. */
    Io->Asid = 1;
    /* Select L0 controls from the actual L1 image, never from a current combined image. */
    Io->OuterPermissions.Flags = *(ULONG*)((nested->Session.Phase == KSW_NSVM_SESSION_L2 ?
        nested->Session.L1.control : Cpu->Guest->control) + KSW_VMCB_MISC1);
    /* Only immutable L0 maps participate as the outer permission owner. */
    Io->OuterPermissions.Msr = Cpu->Msrpm; Io->OuterPermissions.Io = Cpu->Iopm;
    /* Share the prepared sparse-cache ledger and its translation diagnostics. */
    Io->Shadow = &nested->Shadow; Io->Mmu = &nested->Config;
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
    /* Only the known bounded native-return path can discard its failed transaction. */
    nested->Session.Phase = KSW_NSVM_SESSION_IDLE;
    /* The assembly path owns real SVME/HSAVE release; clear only virtual ownership here. */
    nested->Msrs.Efer &= ~KSW_SVM_EFER_SVME;
    /* A failed test must not leave virtual ownership in the next test's context. */
    nested->Msrs.Hsave = 0;
    /* Only this bounded instruction stream may abort to the original Windows XCR0. */
    Cpu->GuestXcr0 = Cpu->HostXcr0;
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
    /* Mask transitions require an implemented dependency set and SSE-enabled native caller. */
    if (!KswSvmXcr0MaskValid(Cpu->HostXcr0) || !(Cpu->HostXcr0 & 2ULL)) { return STATUS_NOT_SUPPORTED; }
    /* Previous permission snapshots cannot authorize a later probe invocation. */
    nested->Session.Permissions.Ready = 0;
    /* Each test starts a fresh transaction with independently counted virtual returns. */
    RtlZeroMemory(&nested->Session, sizeof(nested->Session));
    /* Reusing this CPU must invalidate previous shadow translations/evidence. */
    if (KswSvmNestedShadowReset(&nested->Shadow) != KSW_NSHADOW_OK) { return STATUS_INTEGER_OVERFLOW; }
    /* Invalidate previous published completion before changing any probe evidence. */
    InterlockedIncrement(&nested->Sequence);
    /* Each test begins with no successful inner hardware entry or reflection. */
    nested->Begun = nested->Entries = nested->Reflections = nested->Faults = 0;
    /* Completion must account for both independently intercepted XSETBV instructions. */
    nested->Xcr0Writes = 0;
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
static BOOLEAN KswNsvmReflect(KSW_SVM_CPU* Cpu)
{
    /* Current image is VMCB02 until the final copy below. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* General reflection owns the operand commit and actual L1 continuation restoration. */
    KSW_NSVM_SESSION_IO io;
    /* Preserve full-width raw evidence before switching images. */
    nested->LastExit = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITCODE);
    /* CPUID marker is still in hardware-saved guest RAX at this point. */
    nested->LastMarker = KswSvmRead64(Cpu->Guest, KSW_VMCB_RAX);
    /* This uses the same path as an arbitrary admitted VMCB12, with no marker assumptions. */
    KswNsvmProbeSessionIo(Cpu, &io);
    /* A failed output cannot let the virtual VMM consume stale exit state. */
    if (KswSvmNestedSessionReflect(&nested->Session, &io, Cpu->Guest) != KSW_NSVM_ACTION_RETURN) {
        /* Retain physical progress for the bounded failure record. */
        nested->LastOperand = nested->Session.OperandResult; return FALSE;
    }
    /* No inner execution may be mistaken for the final outer CPUID. */
    nested->RunningL2 = 0;
    /* Track virtual GIF separately from the real root GIF held by assembly. */
    nested->VirtualGif = 0;
    /* Count a reflection only after the complete outer continuation has been restored. */
    ++nested->Reflections;
    /* L1 continuation and guest-visible exit fields are now consistent. */
    return TRUE;
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
    if (status == KSW_NNPT_RETRY) {
        /* Preserve delivery if the translation fault interrupted an injected event. */
        return KswSvmNestedResumeEvent(Cpu->Guest) == KSW_NSVM_EVENT_OK ? 0 : KswNsvmFinish(Cpu, STATUS_DATA_ERROR);
    }
    /* Failed translation never falls back to the outer identity root. */
    if (status != KSW_NNPT_OK) { return KswNsvmFinish(Cpu, STATUS_HV_OPERATION_FAILED); }
    /* Publish only a candidate from the current shadow epoch. */
    if (KswSvmNestedShadowInstall(&nested->Shadow, &nested->LastTranslation) != KSW_NSHADOW_OK) {
        /* Retain raw fault/resolution evidence for KD before returning natively. */
        return KswNsvmFinish(Cpu, STATUS_INSUFFICIENT_RESOURCES);
    }
    /* Restore interrupted event delivery before the next full-flush VMRUN. */
    return KswSvmNestedResumeEvent(Cpu->Guest) == KSW_NSVM_EVENT_OK ? 0 : KswNsvmFinish(Cpu, STATUS_DATA_ERROR);
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
        /* Return only this bounded test's owned mapping; physical operands remain in RAX. */
        Cpu->Gpr[2] = (ULONGLONG)(ULONG_PTR)nested->Operand;
        /* Resume immediately after the begin marker. */
        return KswNsvmAdvance(Cpu) ? 0 : KswNsvmFinish(Cpu, STATUS_DATA_ERROR);
    }
    /* A current inner image needs inner exit routing before ordinary SVM handling. */
    if (nested->RunningL2) {
        /* Classify against the captured sources, not the OR-combined executable image. */
        KSW_NSVM_SESSION_IO io;
        /* The same immutable inner permission image governed this VMRUN. */
        KSW_NSVM_PERMISSION_VIEW inner;
        /* L0 permission identity remains separate from the captured L1 bitmap. */
        KswNsvmProbeSessionIo(Cpu, &io);
        /* A missing snapshot cannot authorize any reflected exit. */
        if (!KswSvmNestedPermissionView(&nested->Session.Permissions, &inner)) { return KswNsvmFinish(Cpu, STATUS_DATA_ERROR); }
        /* Route before changing registers, advancing RIP or synthesizing an event. */
        KswSvmNestedRouteExit(&nested->Session.L1, &nested->Session.Vmcb12,
            &io.OuterPermissions, &inner, code, KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITINFO1),
            (ULONG)Cpu->Gpr[1], &nested->LastRoute);
        /* Sparse NPT02 creates demand faults even for guest page-table walks. */
        if (nested->LastRoute.Action == KSW_NSVM_ROUTE_NPF) { return KswNsvmNpf(Cpu); }
        /* Only execution of the known inner marker proves this probe's hardware entry. */
        if (code != KSW_SVM_EXIT_CPUID || (ULONG)operand != KSW_NSVM_INNER_MARKER ||
            nested->LastRoute.Action != KSW_NSVM_ROUTE_REFLECT) {
            /* Unknown exits are evidence of failure, never a guessed successful reflection. */
            return KswNsvmFinish(Cpu, STATUS_HV_OPERATION_FAILED);
        }
        /* Return to the actual L1 continuation after its intercepted VMRUN. */
        if (!KswNsvmReflect(Cpu)) { return KswNsvmFinish(Cpu, STATUS_DATA_ERROR); }
        /* Reenter the restored outer VMCB, not the inner one. */
        return 0;
    }
    /* Every admitted SVM/MSR operation belongs to the kernel-only test sequence. */
    if (((PUCHAR)Cpu->Guest)[KSW_VMCB_CPL] != 0) { return KswNsvmFinish(Cpu, STATUS_ACCESS_DENIED); }
    /* Virtual MSRs are exercised before and after the actual inner execution. */
    if (code == 0x8dULL) {
        /* The private probe must reduce to x87-only, then restore the prepared native mask. */
        ULONGLONG value = ((Cpu->Gpr[2] & 0xffffffffULL) << 32) | (operand & 0xffffffffULL);
        /* Validate NRIP before mutating software state; this test aborts instead of injecting faults. */
        if (nested->Xcr0Writes >= 2 || (nested->Xcr0Writes && !nested->Reflections) ||
            value != (nested->Xcr0Writes ? Cpu->HostXcr0 : 1ULL) ||
            !KswSvmNextRipValid(KswSvmRead64(Cpu->Guest, KSW_VMCB_RIP), KswSvmRead64(Cpu->Guest, KSW_VMCB_NRIP))) {
            /* Missing, duplicate or reordered transitions cannot pass the fixed probe. */
            return KswNsvmFinish(Cpu, STATUS_DATA_ERROR);
        }
        /* Use the same allocation-bounded policy intended for the future general XSETBV handler. */
        if (KswSvmXcr0Write(Cpu->HostXcr0, KswSvmRead64(Cpu->Guest, KSW_VMCB_CR4),
            ((PUCHAR)Cpu->Guest)[KSW_VMCB_CPL], (ULONG)Cpu->Gpr[1], value, &Cpu->GuestXcr0) != KSW_SVM_XCR_OK) {
            /* The probe may only execute known-valid instructions. */
            return KswNsvmFinish(Cpu, STATUS_HV_OPERATION_FAILED);
        }
        /* Do not write real XCR0 from C, which may still emit SSE instructions. */
        ++nested->Xcr0Writes;
    } else if (code == KSW_SVM_EXIT_MSR) {
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
        if (code == 0x82ULL) {
            /* VMLOAD consumes a translated owned snapshot, not a raw physical pointer. */
            if (!KswNsvmProbeReadMap(Cpu, operand, (PUCHAR)&nested->Session.Vmcb12)) { return KswNsvmFinish(Cpu, STATUS_ACCESS_DENIED); }
            /* Automatic state and permission controls are not part of VMLOAD. */
            KswSvmNestedCopyVmload(Cpu->Guest, &nested->Session.Vmcb12);
        }
        /* VMSAVE leaves all VMRUN controls and automatic state untouched. */
        else {
            /* Only the VMSAVE whitelist will be written; all other scratch bytes are ignored. */
            KswSvmNestedCopyVmload(&nested->Session.Vmcb12, Cpu->Guest);
            /* Preserve the input page's controls and automatic state during output. */
            if (!KswNsvmProbeWrite(Cpu, KSW_NSVM_SAVE_VMSAVE)) { return KswNsvmFinish(Cpu, STATUS_DATA_ERROR); }
        }
    } else if (code == KSW_SVM_EXIT_VMRUN) {
        /* General transaction is shared with arbitrary VMCB entry/return handling. */
        KSW_NSVM_SESSION_IO io;
        /* Probe policy still requires exactly one known, noninterruptible inner entry. */
        ULONG action;
        /* Entry is restricted only by this test harness, not by the general transaction. */
        if (!(nested->Msrs.Efer & KSW_SVM_EFER_SVME) || operand != nested->OperandPa ||
            nested->Msrs.Hsave != nested->OperandPa + 4096ULL || nested->Entries ||
            nested->Xcr0Writes != 1 || Cpu->GuestXcr0 != 1 ||
            (KswSvmRead64(Cpu->Guest, KSW_VMCB_RFLAGS) & 0x200ULL)) { return KswNsvmFinish(Cpu, STATUS_INVALID_DEVICE_STATE); }
        /* Reuse the current CPU's fixed resources and trusted outer capability contract. */
        KswNsvmProbeSessionIo(Cpu, &io);
        /* Capture/admit/merge/build as one transaction before publishing inner execution. */
        action = KswSvmNestedSessionEnter(&nested->Session, &io, Cpu->Guest, operand);
        /* Keep physical and architectural failures independently visible to KD. */
        nested->LastOperand = nested->Session.OperandResult; nested->LastEntry = nested->Session.Admission;
        /* First entry deliberately uses ASID zero and must return through the actual L1 code. */
        if (action == KSW_NSVM_ACTION_INVALID && nested->Session.InvalidEntries == 1) {
            /* The generic transaction already installed NRIP and the virtual host context. */
            nested->VirtualGif = 0; return 0;
        }
        /* The probe requires a real inner entry; general INVALID itself resumes L1 normally. */
        if (action != KSW_NSVM_ACTION_ENTER) { return KswNsvmFinish(Cpu,
            nested->LastOperand.Status != KSW_NNPT_OK ? STATUS_ACCESS_DENIED : STATUS_HV_OPERATION_FAILED); }
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
            nested->Session.InvalidEntries == 1 && nested->Session.Returns == 1 &&
            nested->Xcr0Writes == 2 && Cpu->GuestXcr0 == Cpu->HostXcr0 &&
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
