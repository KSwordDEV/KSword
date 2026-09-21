/* AMD capability discovery and PASSIVE_LEVEL resource ownership. */
#include "hvm_svm.h"
#include "hvm_svm_nested_runtime.h"
#include "../../platform/pool_compat.h"
#include <intrin.h>

/* Capture component layout while the prepare caller is pinned to the owning CPU. */
static VOID KswSvmReadXstateCpuid(void* Context, unsigned Leaf, unsigned Subleaf, unsigned Words[4])
{
    /* CPUID itself requires no pageable state or borrowed OS service. */
    int r[4];
    /* This callback reads only the already selected processor. */
    UNREFERENCED_PARAMETER(Context);
    /* Signed intrinsic operands/results preserve their exact 32-bit architectural patterns. */
    __cpuidex(r, (int)Leaf, (int)Subleaf);
    /* Copy explicitly instead of relying on differently signed pointer aliasing. */
    Words[0] = (unsigned)r[0]; Words[1] = (unsigned)r[1]; Words[2] = (unsigned)r[2]; Words[3] = (unsigned)r[3];
}

/* Read each MSR independently; absent evidence must not look like zero. */
static VOID KswSvmReadEvidence(KSW_SVM_CAPS* Caps, ULONG Msr, ULONG Bit, ULONGLONG* Value)
{
    /* A VMM may advertise SVM while filtering individual MSRs. */
    __try { *Value = __readmsr(Msr); Caps->Valid |= Bit; }
    /* Preserve a missing field and its precise exception. */
    __except (EXCEPTION_EXECUTE_HANDLER) { Caps->Exception = GetExceptionCode(); }
}

/* Preserve the exact admission check independently from its shared NTSTATUS. */
static NTSTATUS KswSvmReject(KSW_SVM_CAPS* Caps, ULONG Reason, NTSTATUS Status)
{
    /* Every refusal publishes a stable protocol reason before returning. */
    Caps->RejectReason = Reason;
    /* Keep the existing status contract for control callers. */
    return Status;
}

/* Must execute on the processor whose evidence it returns. */
NTSTATUS KswordSvmProbeCpu(KSW_SVM_CAPS* Caps)
{
    /* CPUID outputs are signed intrinsics, decoded explicitly below. */
    int r[4];
    /* Start with no valid privileged evidence. */
    RtlZeroMemory(Caps, sizeof(*Caps));
    /* Never query an unavailable extended leaf. */
    __cpuid(r, (int)0x80000000U);
    /* Preserve the bound for diagnostics. */
    Caps->MaxLeaf = (ULONG)r[0];
    /* The backend needs both MAXPHYADDR and SVM enumeration. */
    if (Caps->MaxLeaf < 0x8000000aU) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_CPUID_RANGE, STATUS_NOT_SUPPORTED); }
    /* Discover SVM and one-GiB pages separately. */
    __cpuid(r, (int)0x80000001U);
    /* ECX.SVM is the instruction capability gate. */
    Caps->Svm = ((ULONG)r[2] & 4U) != 0;
    /* EDX.Page1GB controls large NPT leaf construction. */
    Caps->Page1Gb = ((ULONG)r[3] & (1U << 26)) != 0;
    /* SVM ASID count and optional features. */
    __cpuid(r, (int)0x8000000aU);
    /* ASID zero is reserved. */
    Caps->AsidCount = (ULONG)r[1];
    /* Do not infer optional features from the CPU model. */
    Caps->Features = (ULONG)r[3];
    /* Read the actual address width exposed by the outer VMM. */
    __cpuid(r, (int)0x80000008U);
    /* The four-level NPT implementation validates this width. */
    Caps->PhysicalBits = (ULONG)r[0] & 0xffU;
    /* Stop before touching SVM-only MSRs if SVM is filtered. */
    if (!Caps->Svm || !(Caps->Features & 1U) || !KswSvmAsidValid(Caps->AsidCount, 1)) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_SVM_NPT_ASID, STATUS_NOT_SUPPORTED); }
    /* General user-mode intercepts need NRIP; no unsafe root instruction fetch fallback. */
    if (!(Caps->Features & 8U)) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_NRIP, STATUS_NOT_SUPPORTED); }
    /* Capture all ownership/cache evidence independently. */
    KswSvmReadEvidence(Caps, KSW_SVM_MSR_VM_CR, 1, &Caps->VmCr);
    /* EFER.SVME belongs to an existing VMM when already set. */
    KswSvmReadEvidence(Caps, KSW_SVM_MSR_EFER, 2, &Caps->Efer);
    /* A nonzero save address is treated conservatively as ownership conflict. */
    KswSvmReadEvidence(Caps, KSW_SVM_MSR_HSAVE, 4, &Caps->Hsave);
    /* Read the existing PAT rather than writing a preferred layout. */
    KswSvmReadEvidence(Caps, 0x277U, 8, &Caps->Pat);
    /* A filtered MSR makes hardware readiness unproven. */
    if (Caps->Valid != 15) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_MSR_READ, NT_SUCCESS(Caps->Exception) ? STATUS_NOT_SUPPORTED : Caps->Exception); }
    /* Respect firmware SVMDIS and existing virtualization ownership. */
    if (Caps->VmCr & 0x10ULL) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_FIRMWARE, STATUS_DEVICE_BUSY); }
    /* An enabled SVM owner remains an unconditional refusal. */
    if (Caps->Efer & KSW_SVM_EFER_SVME) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_SVME, STATUS_DEVICE_BUSY); }
    /* Preserve the conservative nonzero-HSAVE gate while diagnosing other blockers. */
    if (Caps->Hsave) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_HSAVE, STATUS_DEVICE_BUSY); }
    /* Capture the CR4 observation before testing individual unsupported state bits. */
    Caps->Cr4 = __readcr4();
    /* Zero CR4 is only meaningful when this explicit observation bit is set. */
    Caps->StateValid |= KSWORD_ARK_SVM_VALID_CR4;
    /* Require an OS-enabled XSAVE path for complete user XSTATE preservation. */
    __cpuid(r, 1);
    /* Preserve the OSXSAVE gate as well as the hardware XSAVE support bit. */
    Caps->Cpuid1Ecx = (ULONG)r[2];
    /* Publish which leaf was actually executed. */
    Caps->StateValid |= KSWORD_ARK_SVM_VALID_CPUID1;
    /* Both XSAVE and OSXSAVE must be present before reading XCR0. */
    if ((Caps->Cpuid1Ecx & (3U << 26)) != (3U << 26)) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_XSAVE, STATUS_NOT_SUPPORTED); }
    /* Discover the save family before admitting XSS-managed user CET. */
    __cpuidex(r, 0xd, 1);
    /* Preserve the actual XSAVE instruction-family enumeration. */
    Caps->XsaveFeatures = (ULONG)r[0];
    /* Raw feature zero is distinguishable from a skipped CPUID leaf. */
    Caps->StateValid |= KSWORD_ARK_SVM_VALID_CPUID_D1;
    /* Read-only extended-state inspection never enables unsupported state. */
    __try {
        /* XGETBV is legal only after the verified OSXSAVE gate above. */
        Caps->Xcr0 = _xgetbv(0);
        /* Publish XCR0 independently from a possibly filtered XSS read. */
        Caps->StateValid |= KSWORD_ARK_SVM_VALID_XCR0;
        /* XSS is not assumed to exist on processors without XSAVES. */
        if (Caps->XsaveFeatures & 8U) {
            /* Retain the real supervisor-state mask even when a CR4 gate also fails. */
            Caps->Xss = __readmsr(0xda0U);
            /* An observed zero is now distinguishable from a skipped/failed read. */
            Caps->StateValid |= KSWORD_ARK_SVM_VALID_XSS;
        }
        /* Query CET enumeration only when basic leaf seven exists. */
        __cpuid(r, 0);
        /* CPUs without CET retain zero state and never execute a CET MSR read. */
        if ((ULONG)r[0] >= 7U) {
            /* AMD CET_SS enumerates the architectural shadow-stack MSRs. */
            __cpuidex(r, 7, 0);
            /* Record support independently from the current CR4 enable bit. */
            Caps->CetPresent = ((ULONG)r[2] >> 7) & 1U;
        }
        /* Even CR4.CET=0 must not hide nonzero supervisor controls. */
        if (Caps->CetPresent) {
            /* Supervisor CET cannot run on the current private root stack. */
            Caps->Scet = __readmsr(KSW_SVM_MSR_S_CET);
            /* Retain the interrupt shadow-stack table for the initial VMCB. */
            Caps->Isst = __readmsr(KSW_SVM_MSR_ISST);
            /* Bounded self-tests must prove that both user CET MSRs survived the round trip. */
            Caps->Ucet = __readmsr(0x6a0U);
            /* PL3_SSP is live per-thread state, not a processor preparation constant. */
            Caps->Pl3Ssp = __readmsr(0x6a7U);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve the exact exception instead of fabricating absent supervisor state. */
        Caps->Exception = GetExceptionCode();
        /* No virtualization ownership was acquired by these reads. */
        return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_XSTATE_READ, Caps->Exception);
    }
    /* LA57, PKS and user-interrupt state transfers remain unsupported. */
    if (Caps->Cr4 & KSW_SVM_UNSUPPORTED_CR4) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_CR4, STATUS_NOT_SUPPORTED); }
    /* Only CET_U has a supported supervisor XSTATE save/restore contract. */
    if (Caps->Xss & ~KSW_SVM_XSS_CET_U) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_XSS, STATUS_NOT_SUPPORTED); }
    /* Never admit supervisor CET or a missing XSAVES path merely by clearing a gate. */
    if (!KswSvmUserCetValid(Caps->Cr4, Caps->Xcr0, Caps->Xss, Caps->XsaveFeatures, Caps->CetPresent, Caps->Scet)) {
        /* Keep this distinguishable from unrelated CR4 and XSS refusals. */
        return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_CET_STATE, STATUS_NOT_SUPPORTED);
    }
    /* Validate the advertised compacted supervisor component before executing XSAVES. */
    if (Caps->Xss) {
        /* D.1 enumerates XSS bits in EDX:ECX. */
        __cpuidex(r, 0xd, 1);
        /* This implementation requires exactly the architecturally defined CET_U component. */
        if (!((ULONG)r[2] & (1U << 11))) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_CET_STATE, STATUS_NOT_SUPPORTED); }
        /* Component eleven contains two eight-byte MSRs and is supervisor-managed. */
        __cpuidex(r, 0xd, 11);
        /* Reject inconsistent outer-VMM enumeration before allocating or entering. */
        if ((ULONG)r[0] != 16U || !((ULONG)r[2] & 1U)) { return KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_CET_STATE, STATUS_NOT_SUPPORTED); }
    }
    /* Capability success does not itself prove that VMRUN works. */
    return KswNptAddressMask(Caps->PhysicalBits) ? STATUS_SUCCESS : KswSvmReject(Caps, KSWORD_ARK_SVM_REJECT_PHYSICAL_WIDTH, STATUS_NOT_SUPPORTED);
}

/* Publish hardware evidence separately from runtime implementation state. */
NTSTATUS KswordSvmProbe(KSW_HVM_RUNTIME* Runtime)
{
    /* Probe the current processor; prepare repeats on every target processor. */
    KSW_SVM_CAPS caps;
    /* Preserve precise failure while still publishing capability evidence. */
    NTSTATUS status = KswordSvmProbeCpu(&caps);
    /* Preserve each independent source and validity flag for pre-prepare diagnosis. */
    Runtime->SvmCapabilities.maxLeaf = caps.MaxLeaf; Runtime->SvmCapabilities.features = caps.Features;
    /* CPUID enumeration is separate from privileged MSR validity. */
    Runtime->SvmCapabilities.asidCount = caps.AsidCount; Runtime->SvmCapabilities.physicalBits = caps.PhysicalBits;
    /* A failed MSR read must remain distinguishable from a returned zero. */
    Runtime->SvmCapabilities.msrValidMask = caps.Valid; Runtime->SvmCapabilities.exceptionStatus = (ULONG)caps.Exception;
    /* Preserve raw ownership and PAT observations without interpreting invalid fields. */
    Runtime->SvmCapabilities.vmCr = caps.VmCr; Runtime->SvmCapabilities.efer = caps.Efer;
    /* Preserve the remaining independently sampled registers. */
    Runtime->SvmCapabilities.hsave = caps.Hsave; Runtime->SvmCapabilities.pat = caps.Pat;
    /* Admission failure must identify the precise check, not only STATUS_NOT_SUPPORTED. */
    Runtime->SvmCapabilities.rejectReason = caps.RejectReason; Runtime->SvmCapabilities.stateValidMask = caps.StateValid;
    /* Record both CPUID leaves used to decide which state reads were legal. */
    Runtime->SvmCapabilities.cpuid1Ecx = caps.Cpuid1Ecx; Runtime->SvmCapabilities.xsaveFeatures = caps.XsaveFeatures;
    /* Preserve raw extended-state evidence even when preparation is refused. */
    Runtime->SvmCapabilities.cr4 = caps.Cr4; Runtime->SvmCapabilities.xcr0 = caps.Xcr0; Runtime->SvmCapabilities.xss = caps.Xss;
    /* Select SVM independently from generic x64 compiler architecture. */
    Runtime->BackendId = KSWORD_ARK_HVM_BACKEND_SVM;
    /* Mark the CPU vendor without claiming implementation readiness. */
    Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_AMD;
    /* Publish enumerated instruction and paging capabilities. */
    if (caps.Svm) { Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_SVM; }
    /* NPT is not EPT. */
    if (caps.Features & 1U) { Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_NPT; }
    /* Record optional next-RIP capability. */
    if (caps.Features & 8U) { Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_NRIP; }
    /* Record optional invalidation optimization capability. */
    if (caps.Features & 64U) { Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_FLUSH_BY_ASID; }
    /* Record optional decode assists without relying on them. */
    if (caps.Features & 128U) { Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_DECODE_ASSISTS; }
    /* Only a valid VM_CR read can establish firmware-disabled status. */
    if ((caps.Valid & 1U) && (caps.VmCr & 0x10ULL)) { Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_FIRMWARE_DISABLED; }
    /* Distinguish a usable backend from a missing firmware capability. */
    Runtime->QueryStatus = NT_SUCCESS(status) ? KSWORD_ARK_HVM_QUERY_STATUS_OK : KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
    /* Refine the firmware diagnosis only when directly observed. */
    if (caps.VmCr & 0x10ULL) { Runtime->QueryStatus = KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED; }
    /* Retain precise ownership/filtering failures. */
    Runtime->LastStatus = status;
    /* Return capability readiness only. */
    return status;
}

/* Reject every optional Intel feature before allocating AMD resources. */
NTSTATUS KswordSvmValidateFlags(KSW_HVM_RUNTIME* Runtime, ULONG Flags)
{
    /* Only baseline lifecycle flags have AMD implementations. */
    const ULONG allowed = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED | KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
        KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED | KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE;
    /* Unknown/Intel-specific features must not silently degrade to baseline. */
    if (Flags & ~allowed) { return STATUS_NOT_SUPPORTED; }
    /* Running under a VMM requires opt-in and a specifically supported outer host. */
    if (Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) {
        /* Do not spoof CPUID or accept an unknown host to make entry pass. */
        if (!(Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) ||
            RtlCompareMemory(Runtime->HypervisorVendor, "VMwareVMware", 12) != 12) { return STATUS_NOT_SUPPORTED; }
    }
    /* All required SVM state is validated separately. */
    return STATUS_SUCCESS;
}

/* Allocate a zeroed hardware buffer under the guest physical-address ceiling. */
static PVOID KswSvmAllocateHardware(SIZE_T Bytes, ULONG Bits)
{
    /* NPT width is checked before this helper is reached. */
    PHYSICAL_ADDRESS highest;
    /* Capture the owned allocation. */
    PVOID result;
    /* Avoid allocating an unrepresentable hardware operand. */
    highest.QuadPart = (LONGLONG)((1ULL << Bits) - 1);
    /* VMCB, HSAVE and permission maps require physical contiguity. */
    result = MmAllocateContiguousMemory(Bytes, highest);
    /* Reserved fields begin as architectural zero. */
    if (result != NULL) { RtlZeroMemory(result, Bytes); }
    /* Caller records the returned pointer immediately. */
    return result;
}

/* All resources are retained if any CPU could still use them. */
VOID KswordSvmRelease(KSW_HVM_RUNTIME* Runtime)
{
    /* A failed prepare may own only a prefix of this allocation set. */
    KSW_SVM_STATE* state = Runtime->BackendContext;
    /* Reverse-order release does not dereference a missing state. */
    ULONG index;
    /* Never free even apparently inactive per-CPU pages before a complete stop. */
    if (state == NULL || Runtime->ResidentProcessorCount != 0) { return; }
    /* Partial nested output/ownership faults also retain the shared lifetime. */
    if (!KswSvmNestedOwnersIdle(&state->NestedOwners)) { return; }
    /* Check individual owners as well as the summary count. */
    for (index = 0; state->Cpus != NULL && index < state->Count; ++index) {
        /* A stale summary cannot authorize freeing an active CPU's stack. */
        if (state->Cpus[index].Active || (state->Cpus[index].Nested &&
            (state->Cpus[index].Nested->RunningL2 || state->Cpus[index].Nested->Session.Lease.Token ||
             state->Cpus[index].Nested->Nmi.Armed || state->Cpus[index].Nested->Nmi.Count))) { return; }
    }
    /* Release per-CPU allocations in exact reverse ownership order. */
    for (index = state->Count; state->Cpus != NULL && index != 0;) {
        /* Select the next owned context. */
        KSW_SVM_CPU* cpu = &state->Cpus[--index];
        /* Nested operands/cache pages share the same all-native release boundary. */
        KswordSvmNestedRelease(cpu);
        /* NX XSTATE and host-stack allocations use the same pool tag. */
        if (cpu->XstateAllocation) { ExFreePoolWithTag(cpu->XstateAllocation, 'cSvK'); }
        /* The host stack remains alive until native return acknowledgement. */
        if (cpu->Stack) { ExFreePoolWithTag(cpu->Stack, 'cSvK'); }
        /* Permission maps and hardware pages are physically contiguous. */
        if (cpu->Iopm) { MmFreeContiguousMemory(cpu->Iopm); }
        /* Release the MSR bitmap after all exits stopped. */
        if (cpu->Msrpm) { MmFreeContiguousMemory(cpu->Msrpm); }
        /* Release hardware's opaque host-save area. */
        if (cpu->Hsave) { MmFreeContiguousMemory(cpu->Hsave); }
        /* Release our explicit host state image. */
        if (cpu->Host) { MmFreeContiguousMemory(cpu->Host); }
        /* Release the guest control/save image last. */
        if (cpu->Guest) { MmFreeContiguousMemory(cpu->Guest); }
        /* Remove the runtime's dangling private-context link. */
        Runtime->Processors[index].BackendContext = NULL;
    }
    /* Shared NPT is freed only after all per-CPU owners are gone. */
    KswordNptRelease(&state->Npt);
    /* Free the context array when prepare reached its allocation. */
    if (state->Cpus) { ExFreePoolWithTag(state->Cpus, 'cSvK'); }
    /* Drop runtime state and public preparation evidence together. */
    ExFreePoolWithTag(state, 'sSvK');
    /* Prevent reuse of the released lifetime. */
    Runtime->BackendContext = NULL;
    /* Clear every stale processor row and count. */
    RtlZeroMemory(Runtime->Processors, sizeof(Runtime->Processors));
    /* No prepared CPU survives teardown. */
    Runtime->ProcessorCount = Runtime->PreparedProcessorCount = Runtime->SelfTestPassedProcessorCount = 0;
    /* NPT never sets an EPT-ready bit. */
    KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_RESOURCES_READY | KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED);
}

/* Allocate and validate each processor before any CPU executes VMRUN. */
NTSTATUS KswordSvmPrepare(KSW_HVM_RUNTIME* Runtime, ULONG Flags)
{
    /* Keep precise failure for the command response. */
    NTSTATUS status = KswordSvmValidateFlags(Runtime, Flags);
    /* Snapshot all processor groups, never just group zero. */
    ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    /* Loop index is a Windows global processor index, not APIC ID. */
    ULONG index;
    /* The prepare allocation is owned by Runtime immediately. */
    KSW_SVM_STATE* state;
    /* Reject unsupported options before changing ownership. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Repeated preparation must not replace a live or partially owned context. */
    if (Runtime->BackendContext) { return STATUS_ALREADY_REGISTERED; }
    /* Enforce protocol capacity without silently dropping processors. */
    if (count == 0 || count > KSWORD_ARK_HVM_MAX_PROCESSORS) { return STATUS_NOT_SUPPORTED; }
    /* Allocate runtime state from nonpaged NX pool. */
    state = KswordARKAllocateNonPagedPool(sizeof(*state), 'sSvK');
    /* Allocation failure leaves all public readiness clear. */
    if (state == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Initialize every ownership pointer before publishing the context. */
    RtlZeroMemory(state, sizeof(*state));
    /* Publish cleanup ownership, not readiness. */
    Runtime->BackendContext = state;
    /* Freeze the target count for subsequent allocations. */
    state->Count = count;
    /* Bind capability/allocation evidence to the current power epoch. */
    state->PreparedPowerGeneration = Runtime->PowerTransitionGeneration;
    /* Allocate all contexts before pinning individual processors. */
    state->Cpus = KswordARKAllocateNonPagedPool(sizeof(KSW_SVM_CPU) * count, 'cSvK');
    /* Release the owned state if the array allocation fails. */
    if (state->Cpus == NULL) { KswordSvmRelease(Runtime); return STATUS_INSUFFICIENT_RESOURCES; }
    /* Every individual pointer must start null for partial cleanup. */
    RtlZeroMemory(state->Cpus, sizeof(KSW_SVM_CPU) * count);
    /* Record target size before preparing rows. */
    Runtime->ProcessorCount = count;
    /* Validate capabilities on every actual target processor. */
    for (index = 0; index < count; ++index) {
        /* Private context associated with this Windows processor identity. */
        KSW_SVM_CPU* cpu = &state->Cpus[index];
        /* Group-aware target and saved calling affinity. */
        PROCESSOR_NUMBER number;
        /* Group affinity is restored on every path after binding. */
        GROUP_AFFINITY affinity = {0}, previous;
        /* Enumerated XSAVE capacity. */
        int r[4];
        /* Resolve the frozen global index to its actual group and number. */
        status = KeGetProcessorNumberFromIndex(index, &number);
        /* Topology failures cannot be ignored. */
        if (!NT_SUCCESS(status)) { break; }
        /* Set a single-bit mask within the target group. */
        affinity.Group = number.Group; affinity.Mask = (KAFFINITY)1 << number.Number;
        /* Bind only while reading CPU-specific evidence. */
        KeSetSystemGroupAffinityThread(&affinity, &previous);
        /* Require valid SVM ownership evidence on this CPU. */
        status = KswordSvmProbeCpu(&cpu->Caps);
        /* Record the currently enabled user XSTATE mask and storage requirement. */
        if (NT_SUCCESS(status)) {
            /* XSS selects a compacted XSAVES area; standard XSAVE cannot save CET_U. */
            cpu->XstateCompacted = cpu->Caps.Xss != 0;
            /* D.1 EBX includes current XCR0 and XSS; D.0 EBX is standard user state. */
            __cpuidex(r, 0xd, (int)cpu->XstateCompacted); cpu->XstateBytes = (ULONG)r[1];
            /* Save exactly the enabled components using the matching instruction family. */
            cpu->XstateMask = cpu->Caps.Xcr0 | cpu->Caps.Xss;
            /* Guest changes are bounded by this immutable root mask and existing allocation. */
            cpu->HostXcr0 = cpu->GuestXcr0 = cpu->Caps.Xcr0;
            /* No guest XSS change can enable a component absent from this fixed root save mask. */
            cpu->HostXss = cpu->GuestXss = cpu->Caps.Xss;
            /* A failed layout stays unpublished; the nested builder refuses it before entry. */
            (void)KswSvmXstateLayoutCapture(&cpu->XstateLayout, cpu->Caps.Xcr0, cpu->Caps.Xss,
                cpu->XstateBytes, cpu->XstateCompacted, KswSvmReadXstateCpuid, NULL);
            /* Assembly must never touch CET MSRs on the old non-CET VMware baseline. */
            cpu->CetPresent = cpu->Caps.CetPresent;
        }
        /* Never leave the control thread pinned after probing. */
        KeRevertToUserGroupAffinityThread(&previous);
        /* Refuse failed evidence before allocating processor-owned pages. */
        if (!NT_SUCCESS(status)) { break; }
        /* Cross-CPU paging/cache contracts must match exactly. */
        if (index && (cpu->Caps.PhysicalBits != state->Cpus[0].Caps.PhysicalBits ||
            cpu->Caps.Page1Gb != state->Cpus[0].Caps.Page1Gb || cpu->Caps.Pat != state->Cpus[0].Caps.Pat)) {
            /* Preserve a heterogeneous-machine refusal rather than guessing. */
            status = STATUS_NOT_SUPPORTED; break;
        }
        /* Bound the saved state size before allocation arithmetic. */
        if (cpu->XstateBytes < 576 || cpu->XstateBytes > 65536) { status = STATUS_NOT_SUPPORTED; break; }
        /* Associate common and private state without reusing VMX fields. */
        cpu->Runtime = Runtime; cpu->Resource = &Runtime->Processors[index];
        /* Retain the System CR3 captured by the common prepare path. */
        cpu->HostCr3 = Runtime->HostCr3;
        /* Preserve processor identity in the common row. */
        cpu->Resource->Row.processorGroup = number.Group; cpu->Resource->Row.processorNumber = number.Number;
        /* Select the correct protocol decoder. */
        cpu->Resource->Row.backend = KSWORD_ARK_HVM_BACKEND_SVM;
        /* No VMX instruction result exists on this backend. */
        cpu->Resource->Row.vmxInstructionResult = 0xffU;
        /* Publish ownership for diagnosis and teardown. */
        cpu->Resource->BackendContext = cpu;
        /* Allocate all hardware operands before publishing readiness. */
        cpu->Guest = KswSvmAllocateHardware(4096, cpu->Caps.PhysicalBits);
        /* Host VMLOAD/VMSAVE image is not the opaque HSAVE page. */
        cpu->Host = KswSvmAllocateHardware(4096, cpu->Caps.PhysicalBits);
        /* Hardware-owned host save page. */
        cpu->Hsave = KswSvmAllocateHardware(4096, cpu->Caps.PhysicalBits);
        /* Two-page MSR bitmap. */
        cpu->Msrpm = KswSvmAllocateHardware(8192, cpu->Caps.PhysicalBits);
        /* Three-page I/O bitmap, even though baseline I/O interception is off. */
        cpu->Iopm = KswSvmAllocateHardware(12288, cpu->Caps.PhysicalBits);
        /* Stack and XSAVE storage are NX and need not be physically contiguous. */
        cpu->Stack = KswordARKAllocateNonPagedPool(KSW_SVM_STACK_BYTES, 'cSvK');
        /* Include slack for 64-byte alignment. */
        cpu->XstateAllocation = KswordARKAllocateNonPagedPool(cpu->XstateBytes + 63, 'cSvK');
        /* A partial per-CPU allocation set is not ready. */
        if (!cpu->Guest || !cpu->Host || !cpu->Hsave || !cpu->Msrpm || !cpu->Iopm || !cpu->Stack || !cpu->XstateAllocation) {
            /* Release all allocations through the shared ledger below. */
            status = STATUS_INSUFFICIENT_RESOURCES; break;
        }
        /* Clear XSAVE's reserved header bytes before its first use. */
        RtlZeroMemory(cpu->XstateAllocation, cpu->XstateBytes + 63);
        /* XSAVE/XRSTOR require 64-byte alignment. */
        cpu->Xstate = (PVOID)(((ULONG_PTR)cpu->XstateAllocation + 63) & ~(ULONG_PTR)63);
        /* Keep the Windows x64 shadow space and the context anchor within the stack. */
        cpu->StackTop = ((ULONGLONG)(ULONG_PTR)cpu->Stack + KSW_SVM_STACK_BYTES - 64) & ~15ULL;
        /* Cache hardware addresses outside VMEXIT. */
        cpu->GuestPa = (ULONGLONG)MmGetPhysicalAddress(cpu->Guest).QuadPart;
        /* Explicit host VMLOAD image. */
        cpu->HostPa = (ULONGLONG)MmGetPhysicalAddress(cpu->Host).QuadPart;
        /* Record prepared state only after all allocations succeeded. */
        cpu->Stage = KSWORD_ARK_HVM_STAGE_PREPARED;
        /* Publish generic resource evidence, never VMXON success. */
        cpu->Resource->Row.stateFlags = KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY;
        /* Count only complete per-CPU resource sets. */
        Runtime->PreparedProcessorCount++;
        /* Exercise reverse cleanup after a complete owned CPU allocation set. */
        if (KswordSvmFault(1, index)) { status = STATUS_CANCELLED; break; }
    }
    /* NPT uses the common cache/address-width contract established above. */
    if (NT_SUCCESS(status)) { status = KswordNptBuild(&state->Npt, &state->Cpus[0].Caps); }
    /* Probe resources are opt-in and never allocated by ordinary prepare. */
    if (NT_SUCCESS(status) && (Flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE)) {
        /* Prepare every CPU before publishing any enhanced self-test readiness. */
        for (index = 0; index < count; ++index) {
            /* No mapping/stack allocation occurs in the later VMEXIT path. */
            status = KswordSvmNestedPrepare(&state->Cpus[index], index);
            /* The common reverse ledger unwinds the full partially allocated set. */
            if (!NT_SUCCESS(status)) { break; }
        }
    }
    /* No preparation evidence may span a sleep/resume or topology change. */
    if (NT_SUCCESS(status) && (Runtime->PowerTransitionPending || Runtime->PowerTransitionGeneration != state->PreparedPowerGeneration ||
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != count)) { status = STATUS_POWER_STATE_INVALID; }
    /* Nothing may remain marked ready after partial prepare. */
    if (!NT_SUCCESS(status)) { KswordSvmRelease(Runtime); return status; }
    /* Publish resources only; actual SVM execution is a separate self-test. */
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESOURCES_READY);
    /* No CPU has yet entered SVM. */
    return STATUS_SUCCESS;
}
