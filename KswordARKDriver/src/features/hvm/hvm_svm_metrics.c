/* Snapshot sparse AMD exit telemetry without reinterpreting Intel exit numbers. */
#include "hvm_svm.h"
#include "hvm_svm_nested_runtime.h"

/* Query copies into the existing buffered response, never a large kernel-stack temporary. */
static VOID KswSvmFlightMetrics(KSW_SVM_NESTED* Nested, KSWORD_HVM_FLIGHT_RECORDER* Output)
{
    /* Bound reader retries; the root writer never waits for a query. */
    ULONG attempt;
    /* An unprepared backend has no recorder allocation. */
    if (!Nested) { return; }
    /* Acquire the immutable first incident even when subsequent general transitions are busy. */
    if (InterlockedCompareExchange(&Nested->FlightFrozen, 0, 0)) {
        /* All writers stop touching Flight after the release publication. */
        RtlCopyMemory(Output, &Nested->Flight, sizeof(*Output)); Output->coherent = 1; return;
    }
    /* Live history needs the same bounded sequence validation as other general observations. */
    for (attempt = 0; attempt < 3; ++attempt) {
        /* Odd means a root-side mutation is in flight. */
        LONG64 before = InterlockedCompareExchange64(&Nested->GeneralSequence, 0, 0);
        /* Do not wait for another processor at high exit frequency. */
        if (before & 1) { continue; }
        /* Readers own this response buffer under the common resource lifetime lock. */
        RtlCopyMemory(Output, &Nested->Flight, sizeof(*Output));
        /* Acquire recheck prevents publishing a mixed snapshot. */
        if (before == InterlockedCompareExchange64(&Nested->GeneralSequence, 0, 0)) { Output->coherent = 1; return; }
    }
    /* Never export stale addresses or partially copied VMCBs as a valid observation. */
    RtlZeroMemory(Output, sizeof(*Output));
}

/* No root CPU waits for telemetry: the reader makes at most three optimistic copies. */
static VOID KswSvmGeneralMetrics(KSW_SVM_CPU* Cpu, KSWORD_ARK_HVM_SVM_GENERAL_METRICS* Output)
{
    /* General state is optional and shares the caller's prepared-runtime lifetime. */
    KSW_SVM_NESTED* nested = Cpu->Nested;
    /* A failed copy leaves the public record invalid, never partially published. */
    ULONG attempt;
    /* Zero initialization distinguishes an absent coordinator from an executed successful guest. */
    RtlZeroMemory(Output, sizeof(*Output));
    /* The bounded probe does not supply general-run evidence. */
    if (!nested) { return; }
    /* Retry only a small fixed number of times under a high exit rate. */
    for (attempt = 0; attempt < 3; ++attempt) {
        /* The sequence covers entry preparation, exit dispatch and physical acknowledgement. */
        LONG64 before = InterlockedCompareExchange64(&nested->GeneralSequence, 0, 0);
        /* Use reader-owned storage so invalid attempts cannot leak into a valid record. */
        KSWORD_ARK_HVM_SVM_GENERAL_METRICS copy = {0};
        /* Zero or odd denotes absent or actively changing general state. */
        if (!before || (before & 1)) { continue; }
        /* Software activation and current session phase are not inner-OS proof. */
        copy.initialized = nested->GeneralInitialized; copy.enabled = (ULONG)Cpu->NestedEntryEnabled;
        /* Preserve actions/window failures even while generic VMEXIT counters continue. */
        copy.phase = nested->Session.Phase; copy.action = nested->GeneralMachine.LastAction;
        /* Virtual GIF and retained acknowledgements diagnose blocked event windows. */
        copy.gif = nested->GeneralExecution.Gif; copy.pending = nested->GeneralExecution.Pending.Count;
        /* The actual leaf count is separate from the coordinator's queued token. */
        copy.nmiCaptured = nested->Nmi.Count;
        /* Source instruction capture evidence identifies an opcode/width refusal without guessing. */
        copy.instructionStatus = nested->GeneralExecution.InstructionStatus; copy.instructionLength = nested->GeneralExecution.InstructionLength;
        /* Address width and page consumption are independent of physical CPU numbering. */
        copy.operandAddressBits = nested->GeneralExecution.OperandAddressBits; copy.shadowPages = nested->Shadow.Used;
        /* The two entry/exit counts intentionally have different semantics. */
        copy.preparedEntries = nested->GeneralMachine.Transitions; copy.hardwareExits = nested->GeneralHardwareExits;
        /* A raw code is sparse AMD data, never an Intel histogram index. */
        copy.exitCode = nested->GeneralLastHardwareExit; copy.leaseToken = nested->Session.Lease.Token;
        /* Both the VMCB owner and queued event identities survive a failed stop. */
        copy.operandHostPa = nested->Session.OperandHostPa; copy.armedToken = nested->GeneralMachine.ArmedToken;
        /* An interrupted injection must retry or transfer this same token. */
        copy.retryToken = nested->GeneralExecution.RetryEventToken;
        /* A queued/retried acknowledgement must not be counted as already delivered. */
        copy.delivered = nested->GeneralExecution.Pending.Delivered; copy.retried = nested->GeneralExecution.Pending.Retried;
        /* Cache eviction is a software action; hardware invalidation remains the separate TLB counter. */
        copy.cacheRecycles = nested->GeneralExecution.CacheRecycles;
        /* These are virtual register values, not MSR probes of the query CPU. */
        copy.virtualEfer = nested->Msrs.Efer; copy.virtualHsave = nested->Msrs.Hsave;
        /* XSTATE values refer to the owner CPU's current virtual execution context. */
        copy.guestXcr0 = Cpu->GuestXcr0; copy.guestXss = Cpu->GuestXss;
        /* Acquire ordering around the copy rejects any concurrent writer transition. */
        if (before == InterlockedCompareExchange64(&nested->GeneralSequence, 0, 0)) {
            /* Only a stable full-width sequence authorizes publishing all copied fields. */
            copy.sequence = (ULONGLONG)before; copy.valid = 1; *Output = copy; return;
        }
    }
}

/* Runtime lifetime is protected by the metrics query's existing shared lock. */
VOID KswordSvmMetrics(KSW_HVM_RUNTIME* Runtime, KSWORD_ARK_HVM_METRICS_RESPONSE* Response)
{
    /* No processor-private buffer is valid before preparation. */
    KSW_SVM_STATE* state = Runtime->BackendContext;
    /* Iterate the exact prepared set, bounded by the shared response capacity. */
    ULONG index;
    /* Always identify the selected architecture, including before prepare. */
    Response->backend = Runtime->BackendId;
    /* Intel shadow counters do not apply to AMD. */
    Response->shadowProcessorCount = 0;
    /* A failed or absent preparation leaves zero AMD rows. */
    if (state == NULL || state->Cpus == NULL) { return; }
    /* CPU identity remains meaningful even before the first recorded exit. */
    Response->svmProcessorCount = state->Count;
    /* Copy processor-local snapshots with bounded retries. */
    for (index = 0; index < state->Count; ++index) {
        /* Query storage is separate from the live ring. */
        KSWORD_ARK_HVM_SVM_METRICS* output = &Response->svmProcessors[index];
        /* Select this processor's private state. */
        KSW_SVM_CPU* cpu = &state->Cpus[index];
        /* Limit retry effort under a high exit rate. */
        ULONG attempt;
        /* Stable identity does not imply the exit snapshot is valid. */
        output->group = cpu->Resource->Row.processorGroup; output->number = cpu->Resource->Row.processorNumber;
        /* Preserve lifecycle stage independently from any exit record. */
        output->stage = (ULONG)cpu->Stage;
        /* Cleanup does not overwrite the cause that required it. */
        output->failureStatus = (ULONG)cpu->FailureStatus; output->failureStage = cpu->FailureStage;
        /* The initial implementation reserves ASID one per processor. */
        output->asid = 1;
        /* MSR validity is independent of whether a VMEXIT record exists. */
        output->msrValidMask = cpu->Caps.Valid; output->svmFeatures = cpu->Caps.Features;
        /* Preserve enumeration used by allocation and ASID selection. */
        output->asidCount = cpu->Caps.AsidCount; output->physicalBits = cpu->Caps.PhysicalBits;
        /* Preserve each raw ownership observation. */
        output->observedVmCr = cpu->Caps.VmCr; output->observedEfer = cpu->Caps.Efer; output->observedHsave = cpu->Caps.Hsave;
        /* Tag this snapshot with the public lifecycle generation. */
        output->generation = Runtime->Generation;
        /* The diagnostic record has its own validity and survives a successful stop. */
        KswSvmFlightMetrics(cpu->Nested, &output->flight);
        /* Prepared immutable resource addresses aid dump attribution. */
        output->vmcbPa = cpu->GuestPa; output->hsavePa = cpu->HsavePa; output->nptRootPa = state->Npt.RootPa;
        /* Observed VMRUN completions requested the baseline full flush. */
        output->tlbRequests = *(volatile ULONGLONG*)&cpu->TlbRequests;
        /* Bounded nested probes publish completion only after native MSR readback. */
        if (cpu->Nested) {
            /* A zero sequence means this prepared context has never executed a probe. */
            LONG sequence = InterlockedCompareExchange(&cpu->Nested->Sequence, 0, 0);
            /* Do not sample an in-progress test as a completed result. */
            if (sequence != 0 && !(sequence & 1)) {
                /* Retain exact status independently from the baseline self-test flags. */
                output->nestedProbeStatus = (ULONG)cpu->Nested->CompletionStatus;
                /* A VMRUN dispatch alone is insufficient; reflection and native return are separate evidence. */
                output->nestedProbeEntries = cpu->Nested->Entries;
                /* Publish the number of completed virtual host returns. */
                output->nestedProbeReflections = cpu->Nested->Reflections;
                /* Sparse shadow NPT faults establish that hardware used the composed root. */
                output->nestedProbeFaults = cpu->Nested->Faults;
                /* Preserve full-width raw inner exit evidence. */
                output->nestedProbeExit = cpu->Nested->LastExit;
                /* This marker was read from the real inner CPUID exit. */
                output->nestedProbeMarker = cpu->Nested->LastMarker;
                /* A racing new test makes this snapshot explicitly invalid. */
                if (sequence == InterlockedCompareExchange(&cpu->Nested->Sequence, 0, 0)) {
                    /* Publish coherent evidence without waiting for another processor. */
                    output->nestedProbeValid = 1; output->nestedProbeSequence = (ULONG)sequence;
                }
            }
        }
        /* General-run evidence uses an independent sequence from the raw exit ring and bounded probe. */
        KswSvmGeneralMetrics(cpu, &output->general);
        /* Read at most three times; an invalid snapshot is preferable to a root stall. */
        for (attempt = 0; attempt < 3; ++attempt) {
            /* Observe the last completely published ring position. */
            ULONG position = (ULONG)InterlockedCompareExchange((volatile LONG*)&cpu->TracePosition, 0, 0);
            /* No exit has been observed yet. */
            KSW_SVM_TRACE* row;
            /* Sequence values bracket the entire copy. */
            LONG before, after;
            /* Preserve empty-ring validity explicitly. */
            if (position == 0) { break; }
            /* Select the last published row; wrap is intentional and counted. */
            row = &cpu->Trace[(position - 1) % KSW_SVM_TRACE_ROWS];
            /* Odd sequence means a writer has begun reusing this slot. */
            before = InterlockedCompareExchange(&row->Sequence, 0, 0);
            /* Avoid copying an already inconsistent row. */
            if (before & 1) { continue; }
            /* Copy all raw 64-bit evidence with no narrowing. */
            output->exitCode = row->ExitCode; output->exitInfo1 = row->Info1; output->exitInfo2 = row->Info2;
            /* Preserve continuation identity. */
            output->rip = row->Rip; output->rsp = row->Rsp; output->cr3 = row->Cr3;
            /* Preserve instruction/event evidence and CPU-local timestamp. */
            output->nrip = row->Nrip; output->event = row->Event; output->tsc = row->Tsc;
            /* Acquire barrier detects a writer that raced the copy. */
            after = InterlockedCompareExchange(&row->Sequence, 0, 0);
            /* A stable even sequence proves this row's internal coherence. */
            if (before == after && !(after & 1)) {
                /* Publish the exact observed sequence and overwrite accounting. */
                output->valid = 1; output->sequence = (ULONG)after; output->ringPosition = position;
                /* Ring overwrite is not the same thing as publication failure. */
                output->ringOverwritten = position > KSW_SVM_TRACE_ROWS ? position - KSW_SVM_TRACE_ROWS : 0;
                /* No extra retries after obtaining a coherent snapshot. */
                break;
            }
        }
    }
}
