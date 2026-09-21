/* All-processor SVM lifecycle using the existing power/unload transition guard. */
#include "hvm_svm.h"
#include <intrin.h>

/* Debugger-only deterministic fault controls default to inert. */
volatile LONG g_KswSvmFaultStage;
/* Exact global processor index selected by the test operator. */
volatile LONG g_KswSvmFaultCpu;
/* Only a debugger can arm this internal fault point. */
volatile LONG g_KswSvmFaultArmed;

/* Consume a fault only at its requested stage and CPU. */
BOOLEAN KswordSvmFault(ULONG Stage, ULONG Cpu)
{
    /* A nonmatching stage never consumes the one-shot arm. */
    if ((ULONG)g_KswSvmFaultStage != Stage || (ULONG)g_KswSvmFaultCpu != Cpu) { return FALSE; }
    /* Exactly one matching caller may inject a controlled failure. */
    return InterlockedCompareExchange(&g_KswSvmFaultArmed, 0, 1) == 1;
}

/* One stack-owned rendezvous survives until every IPI callback returned. */
typedef struct _KSW_SVM_RENDEZVOUS {
    /* Runtime-private processor identity map. */
    KSW_SVM_STATE* State;
    /* Start=1, stop=0. */
    BOOLEAN Start;
    /* Each target must acknowledge exactly once. */
    volatile LONG Seen[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* First authoritative worker failure. */
    volatile LONG Failure;
} KSW_SVM_RENDEZVOUS;

/* Publish only the first failing NTSTATUS. */
static VOID KswSvmFail(KSW_SVM_RENDEZVOUS* Call, NTSTATUS Status)
{
    /* Do not let later successful CPUs overwrite failure evidence. */
    if (!NT_SUCCESS(Status)) { InterlockedCompareExchange(&Call->Failure, Status, STATUS_SUCCESS); }
}

/* Execute on the exact target CPU; no waiting, allocating, or pageable access. */
static ULONG_PTR KswSvmIpi(ULONG_PTR Parameter)
{
    /* The broadcast owner retains this object until KeIpiGenericCall returns. */
    KSW_SVM_RENDEZVOUS* call = (KSW_SVM_RENDEZVOUS*)Parameter;
    /* Global index alone is not trusted without group/number comparison. */
    ULONG index = KeGetCurrentProcessorIndex();
    /* Preserve the exact current identity for verification. */
    PROCESSOR_NUMBER number;
    /* This worker's status is independent of other CPU return values. */
    NTSTATUS status = STATUS_SUCCESS;
    /* The context is resolved only after checking array bounds. */
    KSW_SVM_CPU* cpu;
    /* An unrepresented processor invalidates the complete target set. */
    if (index >= call->State->Count) { KswSvmFail(call, STATUS_NOT_FOUND); return 0; }
    /* Select only the CPU-owned context. */
    cpu = &call->State->Cpus[index];
    /* Partial preparation never supplies an executable CPU context. */
    if (cpu->Resource == NULL) { KswSvmFail(call, STATUS_DEVICE_NOT_READY); return 0; }
    /* Obtain the actual Windows group/number pair. */
    KeGetCurrentProcessorNumberEx(&number);
    /* Both duplicate and mismatched participants invalidate the rendezvous. */
    if (number.Group != cpu->Resource->Row.processorGroup || number.Number != cpu->Resource->Row.processorNumber ||
        InterlockedIncrement(&call->Seen[index]) != 1) { KswSvmFail(call, STATUS_DATA_ERROR); return 0; }
    /* Starting must occur only after this CPU's real VMRUN self-test. */
    if (call->Start) {
        /* Check pending power immediately before the architecture transition. */
        if (!cpu->TestPassed || cpu->Runtime->PowerTransitionPending ||
            cpu->Runtime->PowerTransitionGeneration != call->State->TestedPowerGeneration) { status = STATUS_POWER_STATE_INVALID; }
        /* Current processor entry uses only preallocated resources. */
        else if (KswordSvmFault(2, index)) { status = STATUS_CANCELLED; }
        /* A post-continuation fault keeps Active set so rollback must really stop this CPU. */
        else {
            /* Begin a normal resident continuation. */
            cpu->SelfTest = 0; cpu->StopRequested = 0; status = KswordSvmEnterCurrent(cpu);
            /* Failure after entry is not allowed to erase its hardware ownership. */
            if (NT_SUCCESS(status) && KswordSvmFault(3, index)) { status = STATUS_CANCELLED; }
        }
    } else if (cpu->Active) {
        /* Publish ownership of the private stop operation before VMMCALL. */
        InterlockedExchange(&cpu->StopRequested, 1);
        /* Request complete native restoration, not just exit from VMRUN. */
        if (cpu->NativeReturnSeen || KswordSvmAsmCall(KSW_SVM_CALL_STOP) != 0) { status = STATUS_HV_OPERATION_FAILED; }
        /* The hypercall returned only after EFER/HSAVE/stack restoration. */
        else if ((__readmsr(KSW_SVM_MSR_EFER) & KSW_SVM_EFER_SVME) || __readmsr(KSW_SVM_MSR_HSAVE) != cpu->OriginalHsave ||
            !KswordSvmVerifyNativeState(cpu)) {
            /* Do not free resources when native ownership readback failed. */
            status = STATUS_HV_OPERATION_FAILED;
            /* The CPU did return natively; never execute a second native VMMCALL on retry. */
            cpu->NativeReturnSeen = 1;
        } else {
            /* Current CPU acknowledges complete native continuation. */
            InterlockedExchange(&cpu->Active, 0);
            /* Summary count follows the per-CPU acknowledgement. */
            InterlockedDecrement(&cpu->Runtime->ResidentProcessorCount);
            /* Publish architecture-neutral stopped evidence. */
            cpu->Stage = KSWORD_ARK_HVM_STAGE_STOPPED;
            /* Clear the generic resident bit and mark complete devirtualization. */
            cpu->Resource->Row.stateFlags &= ~KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE;
            /* This bit describes complete native return, not VMXOFF specifically. */
            cpu->Resource->Row.stateFlags |= KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED;
        }
    }
    /* Preserve per-CPU status even if a different CPU failed first. */
    if (!NT_SUCCESS(status) && NT_SUCCESS(cpu->FailureStatus)) {
        /* Preserve the first fault while rollback may later complete successfully. */
        cpu->FailureStatus = status; cpu->FailureStage = (ULONG)cpu->Stage;
    }
    /* A successful rollback must not erase which CPU originally failed. */
    cpu->Resource->Row.lastStatus = NT_SUCCESS(cpu->FailureStatus) ? status : cpu->FailureStatus;
    /* Keep the first broadcast failure. */
    KswSvmFail(call, status);
    /* The caller validates all Seen slots, not this single return value. */
    return NT_SUCCESS(status) ? 1 : 0;
}

/* Verify the exact participant set and final ownership, not merely counts. */
static NTSTATUS KswSvmBroadcast(KSW_SVM_STATE* State, BOOLEAN Start)
{
    /* Zero-init guarantees every target begins unacknowledged. */
    KSW_SVM_RENDEZVOUS call = {0};
    /* Verification iterates the frozen topology. */
    ULONG index;
    /* A general nested context requires quiescence across the complete frozen CPU set. */
    if (!Start && KswordSvmHasGeneral(State)) { return KswordSvmNestedStopBroadcast(State); }
    /* Give each callback the same immutable target set. */
    call.State = State; call.Start = Start;
    /* Synchronous completion establishes lifetime of call and Seen array. */
    (void)KeIpiGenericCall(KswSvmIpi, (ULONG_PTR)&call);
    /* Verify every expected target and its final architecture state. */
    for (index = 0; index < State->Count; ++index) {
        /* A missing callback cannot be hidden by a duplicate success elsewhere. */
        if (!KswSvmParticipantValid((ULONG)call.Seen[index], (ULONG)State->Cpus[index].Active, Start)) {
            /* Retain the more specific worker error if one already exists. */
            KswSvmFail(&call, STATUS_HV_OPERATION_FAILED);
        }
    }
    /* Report the full rendezvous result. */
    return (NTSTATUS)call.Failure;
}

/* Execute a real one-shot guest on every prepared CPU under the shared phase. */
NTSTATUS KswordSvmSelfTest(KSW_HVM_RUNTIME* Runtime, ULONG Flags)
{
    /* Prepared runtime owns the exact tested topology. */
    KSW_SVM_STATE* state = Runtime->BackendContext;
    /* Reject unsupported controls before taking the transition. */
    NTSTATUS status = KswordSvmValidateFlags(Runtime, Flags);
    /* Iterate all Windows global processor indices. */
    ULONG index;
    /* Capture the power epoch, not just a transient pending bit. */
    LONG generation = Runtime->PowerTransitionGeneration;
    /* No self-test may interrupt a live resident or incomplete rollback. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Resource readiness and count both form the preparation contract. */
    if (state == NULL || Runtime->ResidentProcessorCount || Runtime->PreparedProcessorCount != state->Count ||
        state->PreparedPowerGeneration != generation) { return STATUS_DEVICE_NOT_READY; }
    /* A bounded probe can only consume resources deliberately prepared for that probe. */
    if ((Flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE) &&
        !(state->PreparedFlags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE)) { return STATUS_INVALID_DEVICE_STATE; }
    /* Share the same phase as resident start/stop and power callbacks. */
    status = KswordARKHvmAcquireResidentTransition(Runtime);
    /* Do not wait at an unsafe IRQL when another transition owns the phase. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Invalidate previous test evidence before beginning a new complete set. */
    Runtime->SelfTestPassedProcessorCount = 0;
    /* Partial tests never publish the aggregate success bit. */
    KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED);
    /* Clear all private test evidence, including CPUs not reached after a failure. */
    for (index = 0; index < state->Count; ++index) {
        /* Invalidate both private and protocol-visible evidence together. */
        state->Cpus[index].TestPassed = 0;
        /* A CPU not reached by a failed retest must not retain stale success. */
        state->Cpus[index].Resource->Row.stateFlags &= ~KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED;
    }
    /* No hardware is owned while moving the control thread between processors. */
    KswordARKHvmReleaseResidentTransition(Runtime);
    /* Each short hardware window stays on one fixed processor. */
    for (index = 0; index < state->Count; ++index) {
        /* Group-aware target binding. */
        GROUP_AFFINITY target = {0}, previous;
        /* IRQL protects the short local hardware window, not phase ownership. */
        KIRQL previousIrql;
        /* Select processor-private execution state. */
        KSW_SVM_CPU* cpu = &state->Cpus[index];
        /* A complete sleep/resume cycle invalidates the whole attempted set. */
        if (Runtime->PowerTransitionPending || Runtime->PowerTransitionGeneration != generation) { status = STATUS_POWER_STATE_INVALID; break; }
        /* Select the exact prepared group and logical processor. */
        target.Group = cpu->Resource->Row.processorGroup; target.Mask = (KAFFINITY)1 << cpu->Resource->Row.processorNumber;
        /* Restore caller affinity immediately after this processor's test. */
        KeSetSystemGroupAffinityThread(&target, &previous);
        /* Acquire the same phase only after the target affinity is established. */
        status = KswordARKHvmAcquireResidentTransition(Runtime);
        /* Restore affinity when another transition cannot be joined. */
        if (!NT_SUCCESS(status)) { KeRevertToUserGroupAffinityThread(&previous); break; }
        /* Prevent thread migration during the hardware ownership window. */
        KeRaiseIrql(DISPATCH_LEVEL, &previousIrql);
        /* Select the bounded one-shot CPUID guest. */
        cpu->SelfTest = (Flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE) ? 2U : 1U;
        /* Execute VMRUN and the full native restoration path. */
        status = Runtime->PowerTransitionPending || Runtime->PowerTransitionGeneration != generation
            ? STATUS_POWER_STATE_INVALID : KswordSvmEnterCurrent(cpu);
        /* Release phase before lowering IRQL so a queued power DPC cannot wait on its own preempted owner. */
        KswordARKHvmReleaseResidentTransition(Runtime);
        /* Restore scheduling context only after hardware ownership has returned. */
        KeLowerIrql(previousIrql);
        /* Return the control thread to its original affinity. */
        KeRevertToUserGroupAffinityThread(&previous);
        /* Preserve exact per-CPU self-test failure. */
        cpu->Resource->Row.lastStatus = status;
        /* One failed processor invalidates the aggregate result. */
        if (!NT_SUCCESS(status)) { break; }
        /* Record real execution evidence, never merely EFER.SVME=1. */
        cpu->TestPassed = 1; cpu->Stage = KSWORD_ARK_HVM_STAGE_TESTED;
        /* This generic state does not claim a VMXON instruction executed. */
        cpu->Resource->Row.stateFlags |= KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED;
        /* Count only fully restored successful tests. */
        Runtime->SelfTestPassedProcessorCount++;
    }
    /* Commit the complete test set while serialized with power invalidation. */
    {
        /* Retain the hardware failure if final phase acquisition also fails. */
        NTSTATUS phaseStatus = KswordARKHvmAcquireResidentTransition(Runtime);
        /* No aggregate success is published without this final phase. */
        if (!NT_SUCCESS(phaseStatus)) { return NT_SUCCESS(status) ? phaseStatus : status; }
    }
    /* Never join evidence across topology or power epochs. */
    if (NT_SUCCESS(status) && (Runtime->PowerTransitionPending || Runtime->PowerTransitionGeneration != generation ||
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != state->Count)) { status = STATUS_POWER_STATE_INVALID; }
    /* Publish only the complete validated set. */
    if (NT_SUCCESS(status) && Runtime->SelfTestPassedProcessorCount == state->Count) {
        /* Save the epoch that authorizes future start. */
        state->TestedPowerGeneration = generation;
        /* The entire CPU set passed an actual VMRUN/native-return test. */
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED);
    }
    /* Release the shared phase after all local hardware windows are closed. */
    KswordARKHvmReleaseResidentTransition(Runtime);
    /* Return the first failure or complete-set success. */
    return status;
}

/* Return unload ownership only after all CPUs are proven native. */
static NTSTATUS KswSvmDisarm(KSW_HVM_RUNTIME* Runtime)
{
    /* A power transition holds the unload guard until S0 resumes. */
    if (Runtime->PowerTransitionPending || !(Runtime->StateFlags & KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED)) { return STATUS_SUCCESS; }
    /* The common guard verifies it still owns the exact driver-unload slot. */
    return KswordARKHvmDisarmUnloadGuard(Runtime);
}

/* Two-phase start: enter all targets, then publish Active or roll all targets back. */
NTSTATUS KswordSvmStart(KSW_HVM_RUNTIME* Runtime, ULONG Flags)
{
    /* The prepared immutable topology/NPT is the transaction's resource set. */
    KSW_SVM_STATE* state = Runtime->BackendContext;
    /* Reject unsupported options before arming unload protection. */
    NTSTATUS status = KswordSvmValidateFlags(Runtime, Flags);
    /* Rollback status cannot hide the original entry failure. */
    NTSTATUS rollback;
    /* Validate common readiness plus AMD-specific resources. */
    if (!NT_SUCCESS(status)) { return status; }
    /* A passed bounded probe does not authorize an arbitrary nested Windows workload. */
    if (Flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE) { return STATUS_NOT_SUPPORTED; }
    /* Refuse missing lifecycle guards and partial self-test sets. */
    if (!Runtime->ResidentStartAllowed || state == NULL || !state->Npt.RootPa ||
        !(Runtime->StateFlags & KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) ||
        Runtime->PreparedProcessorCount != state->Count || Runtime->SelfTestPassedProcessorCount != state->Count) { return STATUS_DEVICE_NOT_READY; }
    /* Changing the command flags cannot convert a fixed probe preparation into ordinary residency. */
    if ((state->PreparedFlags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE) ||
        ((Flags ^ state->PreparedFlags) & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_SVM)) { return STATUS_INVALID_DEVICE_STATE; }
    /* Never replace a live or uncertain ownership state. */
    if (Runtime->ResidentProcessorCount || (Runtime->StateFlags & (KSWORD_ARK_HVM_STATE_FAULTED | KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED))) { return STATUS_INVALID_DEVICE_STATE; }
    /* Serialize against power and other hardware transitions. */
    status = KswordARKHvmAcquireResidentTransition(Runtime);
    /* Preserve busy semantics of the existing lifecycle. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Revalidate topology and power immediately before entering. */
    if (Runtime->PowerTransitionPending || Runtime->PowerTransitionGeneration != state->TestedPowerGeneration ||
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != state->Count) {
        /* Failed readiness has not changed hardware ownership. */
        KswordARKHvmReleaseResidentTransition(Runtime); return STATUS_POWER_STATE_INVALID;
    }
    /* Protect the driver image before the first CPU enters. */
    status = KswordARKHvmArmUnloadGuard(Runtime);
    /* Failed unload ownership must prevent every VMRUN. */
    if (!NT_SUCCESS(status)) { KswordARKHvmReleaseResidentTransition(Runtime); return status; }
    /* A fresh start begins a new per-CPU failure ledger after all readiness gates passed. */
    {
        /* Reset only when no CPU from an earlier attempt remains resident. */
        ULONG index;
        /* Keep cleanup evidence until the next authorized start. */
        for (index = 0; index < state->Count; ++index) {
            /* Every target receives the same explicitly requested mode before the IPI begins. */
            state->Cpus[index].GeneralRequested = (Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_SVM) != 0;
            /* Preserve old failure evidence until the new transition has acquired unload ownership. */
            state->Cpus[index].FailureStatus = STATUS_SUCCESS; state->Cpus[index].FailureStage = 0;
        }
    }
    /* Observers can see Starting, never premature Active. */
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STARTING);
    /* Each worker publishes a private native/guest continuation acknowledgement. */
    status = KswSvmBroadcast(state, TRUE);
    /* Report software scope separately from hardware feature bits and full OS acceptance. */
    if (Flags & KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_SVM) { Runtime->NestedImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL; }
    /* Recheck epoch after rendezvous, including complete sleep/resume cycles. */
    if (NT_SUCCESS(status) && (Runtime->PowerTransitionPending || Runtime->PowerTransitionGeneration != state->TestedPowerGeneration ||
        Runtime->ResidentProcessorCount != (LONG)state->Count)) { status = STATUS_POWER_STATE_INVALID; }
    /* Only full-set entry is a successful resident implementation. */
    if (NT_SUCCESS(status)) {
        /* Publish Active only after all exact target identities acknowledged. */
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE);
        /* The implementation enum now describes observed hardware state. */
        Runtime->ResidentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE;
    } else {
        /* Roll back already-entered CPUs while still holding the same transition. */
        rollback = KswSvmBroadcast(state, FALSE);
        /* Never free retained resources on incomplete rollback. */
        if (!NT_SUCCESS(rollback) || Runtime->ResidentProcessorCount != 0) {
            /* Keep the driver-unload guard armed for all surviving owners. */
            KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
            /* Distinguish partial hardware ownership from unsupported capability. */
            Runtime->ResidentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
        } else {
            /* Successful rollback leaves capability-only, not Active. */
            Runtime->ResidentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
            /* No general dispatcher remains active after complete rollback. */
            Runtime->NestedImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
            /* Return the unload entry only when power state permits it. */
            rollback = KswSvmDisarm(Runtime);
            /* Failed unload restoration is still an incomplete lifecycle. */
            if (!NT_SUCCESS(rollback)) { KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED); }
        }
    }
    /* Starting no longer describes this operation's final state. */
    KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STARTING);
    /* Release the transaction phase after commit or full rollback attempt. */
    KswordARKHvmReleaseResidentTransition(Runtime);
    /* Preserve the original cause of start failure. */
    return status;
}

/* Called both by controls and by the existing power/unload guards. */
NTSTATUS KswordSvmStop(KSW_HVM_RUNTIME* Runtime)
{
    /* Retain private state until the complete operation finishes. */
    KSW_SVM_STATE* state = Runtime->BackendContext;
    /* The common phase is required even for a currently empty runtime. */
    NTSTATUS status = KswordARKHvmAcquireResidentTransition(Runtime);
    /* Preserve the callback's busy/fail-closed behavior. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Publish the stop transition before sending any private hypercalls. */
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
    /* An absent context needs no IPI, but still needs unload-guard handling. */
    status = state && state->Cpus ? KswSvmBroadcast(state, FALSE) : STATUS_SUCCESS;
    /* Full-set native evidence is required in addition to the summary counter. */
    if (NT_SUCCESS(status) && Runtime->ResidentProcessorCount == 0) {
        /* Return the precise driver-unload entry when permitted by power state. */
        status = KswSvmDisarm(Runtime);
        /* Clear Active only after all processors are natively restored. */
        KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE);
        /* Keep the backend available for another tested start. */
        Runtime->ResidentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
        /* The general dispatch mode no longer executes on any processor. */
        Runtime->NestedImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    } else if (NT_SUCCESS(status)) { status = STATUS_HV_OPERATION_FAILED; }
    /* Failed stop retains all allocations and the unload guard. */
    if (!NT_SUCCESS(status)) { KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED); }
    /* The synchronous stop attempt has ended. */
    KswordARKHvmStateClear(Runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
    /* Release the same phase shared with power, self-test and start. */
    KswordARKHvmReleaseResidentTransition(Runtime);
    /* Never report a partially stopped machine as successful. */
    return status;
}
