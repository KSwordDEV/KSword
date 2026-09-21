/* Two-phase stop for a frozen set of virtual SVM owners; waits occur only in guest IPI callbacks. */
#include "hvm_svm_nested_runtime.h"
#include <intrin.h>

/* This object remains on the synchronous caller's stack until every IPI has returned. */
typedef struct _KSW_NSVM_STOP_CALL {
    /* No processor set can change while the common resident transition is held. */
    KSW_SVM_STATE* State;
    /* Exact votes are independent of counts and APIC identifiers. */
    volatile LONG Seen[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* Decision: zero undecided, one commit, minus one abort. */
    volatile LONG Arrived, Decision, Returned, Failure;
    /* QPC deadlines bound guest rendezvous waits; they are not hardware rollback evidence. */
    LONGLONG VoteDeadline, ReturnDeadline, Budget;
} KSW_NSVM_STOP_CALL;

/* A refused vote never authorizes any processor to start native restoration. */
static VOID KswNsvmStopFailure(KSW_NSVM_STOP_CALL* Call, NTSTATUS Status)
{
    /* Keep the first specific error across later timeouts. */
    InterlockedCompareExchange(&Call->Failure, Status, STATUS_SUCCESS);
    /* A committed decision cannot be changed into a fictional all-or-none rollback. */
    InterlockedCompareExchange(&Call->Decision, -1, 0);
}

/* Preserve CPU-specific failure evidence without replacing an earlier start failure. */
static VOID KswNsvmStopRecord(KSW_SVM_CPU* Cpu, NTSTATUS Status)
{
    /* Unknown participants cannot publish into another CPU's row. */
    if (!Cpu || !Cpu->Resource) { return; }
    /* Complete native readback, not a zero CLI result, is authoritative. */
    if (!NT_SUCCESS(Status) && NT_SUCCESS(Cpu->FailureStatus)) {
        /* Preserve where the first local failure happened. */
        Cpu->FailureStatus = Status; Cpu->FailureStage = (ULONG)Cpu->Stage;
    }
    /* A later successful cleanup must not erase the original diagnosis. */
    Cpu->Resource->Row.lastStatus = NT_SUCCESS(Cpu->FailureStatus) ? Status : Cpu->FailureStatus;
}

/* Called in Windows guest execution at IPI_LEVEL, never from the root exit loop. */
static ULONG_PTR KswNsvmStopIpi(ULONG_PTR Parameter)
{
    /* Synchronous broadcast protects this stack-owned coordination object. */
    KSW_NSVM_STOP_CALL* call = (KSW_NSVM_STOP_CALL*)Parameter;
    /* The actual Windows index is checked against the frozen group:number pair. */
    ULONG index = KeGetCurrentProcessorIndex(), scan;
    /* Only a verified participant may access its hardware context. */
    KSW_SVM_CPU* cpu = NULL;
    /* These fields are local to this callback and cannot race another CPU's register image. */
    PROCESSOR_NUMBER number;
    /* A vote is a prerequisite, not an assertion that native restoration has occurred. */
    NTSTATUS status = STATUS_SUCCESS;
    /* Index failure still aborts the shared decision, so peers do not wait for a fictitious vote. */
    if (index >= call->State->Count) { KswNsvmStopFailure(call, STATUS_NOT_FOUND); return 0; }
    /* Resolve the processor after validating bounds. */
    cpu = &call->State->Cpus[index]; KeGetCurrentProcessorNumberEx(&number);
    /* Missing, mismatched and duplicate participants all invalidate the complete set. */
    if (!cpu->Resource || number.Group != cpu->Resource->Row.processorGroup ||
        number.Number != cpu->Resource->Row.processorNumber || InterlockedIncrement(&call->Seen[index]) != 1) {
        /* No native VMMCALL is issued on a CPU whose identity is uncertain. */
        KswNsvmStopFailure(call, STATUS_DATA_ERROR); return 0;
    }
    /* A previous unacknowledged native return must never execute a second VMMCALL. */
    if (cpu->NativeReturnSeen) { status = STATUS_HV_OPERATION_FAILED; }
    /* The private vote runs in root only long enough to inspect this CPU's live session. */
    else if (cpu->Active && cpu->Nested && cpu->Nested->GeneralInitialized) {
        /* Two is the read-only vote request; one remains the existing actual stop request. */
        InterlockedExchange(&cpu->StopRequested, 2);
        /* A nonzero vote includes virtual SVM ownership, a live L2, or undelivered events. */
        if (KswordSvmAsmCall(KSW_SVM_CALL_QUIESCE) != 0) { status = STATUS_DEVICE_BUSY; }
        /* Returning to the IPI barrier does not leave a stop request armed. */
        InterlockedExchange(&cpu->StopRequested, 0);
    }
    /* A negative vote wins over a still-undecided global commit. */
    if (!NT_SUCCESS(status)) { KswNsvmStopFailure(call, status); }
    /* Publication follows the local vote and exact identity check. */
    if (InterlockedIncrement(&call->Arrived) == (LONG)call->State->Count) {
        /* Counts alone cannot prove that the frozen target set participated. */
        for (scan = 0; scan < call->State->Count; ++scan) {
            /* Interlocked reads pair with each worker's published identity. */
            if (InterlockedCompareExchange(&call->Seen[scan], 0, 0) != 1) { KswNsvmStopFailure(call, STATUS_DATA_ERROR); }
        }
        /* Publish the second barrier's deadline before publishing permission to stop. */
        call->ReturnDeadline = KeQueryPerformanceCounter(NULL).QuadPart + call->Budget;
        /* A failed vote or timeout cannot be overwritten by the final successful arrival. */
        InterlockedCompareExchange(&call->Decision, 1, 0);
    }
    /* Only synchronously scheduled IPI peers are awaited; no root lock or preempted thread is involved. */
    while (InterlockedCompareExchange(&call->Decision, 0, 0) == 0) {
        /* A delayed or missing processor results in an aborted vote, not a partial forced stop. */
        if (KeQueryPerformanceCounter(NULL).QuadPart >= call->VoteDeadline) { KswNsvmStopFailure(call, STATUS_IO_TIMEOUT); }
        /* Avoid continuously issuing locked operations on the shared cache line. */
        YieldProcessor();
    }
    /* Every callback observes the same irreversible commit/abort decision. */
    if (InterlockedCompareExchange(&call->Decision, 0, 0) != 1) {
        /* Before commit, no processor has been instructed to leave resident execution. */
        KswNsvmStopRecord(cpu, NT_SUCCESS(status) ? (NTSTATUS)call->Failure : status); return 0;
    }
    /* Ordinary and general CPUs use the same final native restoration acknowledgement. */
    if (cpu->Active) {
        /* Recheck in the hypercall: a new asynchronous event may have arrived after the vote. */
        InterlockedExchange(&cpu->StopRequested, 1);
        /* A late refusal leaves this CPU resident and makes the aggregate result incomplete. */
        if (KswordSvmAsmCall(KSW_SVM_CALL_STOP) != 0) { status = STATUS_DEVICE_BUSY; }
        /* Current guest state must have been restored before interpreting any native register. */
        else if ((__readmsr(KSW_SVM_MSR_EFER) & KSW_SVM_EFER_SVME) ||
            __readmsr(KSW_SVM_MSR_HSAVE) != cpu->OriginalHsave || !KswordSvmVerifyNativeState(cpu)) {
            /* Record native return separately so a later retry never executes VMMCALL natively. */
            cpu->NativeReturnSeen = 1; status = STATUS_HV_OPERATION_FAILED;
        } else {
            /* Only independently acknowledged native state clears the resident owner. */
            InterlockedExchange(&cpu->Active, 0); InterlockedDecrement(&cpu->Runtime->ResidentProcessorCount);
            /* Publish generic CPU lifecycle evidence after the native readback. */
            cpu->Stage = KSWORD_ARK_HVM_STAGE_STOPPED;
            /* Clear only the actual owner; failed peers retain their own resources. */
            cpu->Resource->Row.stateFlags &= ~KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE;
            /* The flag denotes full native restoration on AMD as well as Intel. */
            cpu->Resource->Row.stateFlags |= KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED;
        }
        /* A failed operation cannot leave an unowned private stop request armed. */
        InterlockedExchange(&cpu->StopRequested, 0);
    }
    /* Late failure cannot revoke already completed native transitions. */
    if (!NT_SUCCESS(status)) { KswNsvmStopFailure(call, status); }
    /* Peers remain inside the IPI until every processor finishes its restoration attempt. */
    InterlockedIncrement(&call->Returned);
    /* The barrier protects against ordinary guest work resuming between planned CPU transitions. */
    while (InterlockedCompareExchange(&call->Returned, 0, 0) != (LONG)call->State->Count) {
        /* Timeout retains the actual per-CPU states; it does not infer that late peers stopped. */
        if (KeQueryPerformanceCounter(NULL).QuadPart >= call->ReturnDeadline) {
            /* The caller retains allocations and unload protection after an incomplete stop. */
            status = STATUS_IO_TIMEOUT; KswNsvmStopFailure(call, status); break;
        }
        /* Waiting is bounded Windows IPI execution, not a root-mode busy lock. */
        YieldProcessor();
    }
    /* Each row keeps its own result, while the synchronous caller checks the complete set. */
    KswNsvmStopRecord(cpu, status); return NT_SUCCESS(status) ? 1 : 0;
}

/* Select the stronger protocol only for a runtime containing a general nested coordinator. */
BOOLEAN KswordSvmHasGeneral(const KSW_SVM_STATE* State)
{
    /* This read occurs under the common lifecycle transition. */
    ULONG index;
    /* Partial preparation has no general hardware owner. */
    if (!State || !State->Cpus) { return FALSE; }
    /* A failed partial start may mix native, ordinary and general CPUs. */
    for (index = 0; index < State->Count; ++index) {
        /* Bound resources remain visible even when the current CPU is already native. */
        if (State->Cpus[index].Nested && State->Cpus[index].Nested->GeneralInitialized) { return TRUE; }
    }
    /* Preserve the established ordinary-resident stop path when no general context exists. */
    return FALSE;
}

/* Caller holds the common transition/unload protection for the complete synchronous broadcast. */
NTSTATUS KswordSvmNestedStopBroadcast(KSW_SVM_STATE* State)
{
    /* Zero initialization makes every participant and phase initially unacknowledged. */
    KSW_NSVM_STOP_CALL call = {0};
    /* QPC is read before any IPI callback; the callback only uses the established timebase. */
    LARGE_INTEGER frequency, now = KeQueryPerformanceCounter(&frequency);
    /* Final evidence is per CPU, not KeIpiGenericCall's single return value. */
    ULONG index;
    /* An invalid topology cannot be truncated into the fixed ballot capacity. */
    if (!State || !State->Cpus || !State->Count || State->Count > KSWORD_ARK_HVM_MAX_PROCESSORS || frequency.QuadPart < 4) { return STATUS_INVALID_DEVICE_STATE; }
    /* A fixed quarter-second bound avoids indefinite IPI waits on an oversubscribed guest. */
    call.State = State; call.Budget = frequency.QuadPart / 4; call.VoteDeadline = now.QuadPart + call.Budget;
    /* Broadcast completion, even after our internal timeout, still owns the stack object's lifetime. */
    (VOID)KeIpiGenericCall(KswNsvmStopIpi, (ULONG_PTR)&call);
    /* Returning from the API never substitutes for exact identity and native-state evidence. */
    for (index = 0; index < State->Count; ++index) {
        /* Any surviving owner leaves the whole operation incomplete. */
        if (call.Seen[index] != 1 || State->Cpus[index].Active || State->Cpus[index].NativeReturnSeen) { KswNsvmStopFailure(&call, STATUS_HV_OPERATION_FAILED); }
    }
    /* Common lifecycle preserves all uncertain resources and unload protection on failure. */
    return (NTSTATUS)call.Failure;
}
