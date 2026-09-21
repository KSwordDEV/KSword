/* AMD VMEXIT dispatcher: processor-local writes, no pageable code or allocation. */
#include "hvm_svm.h"
#include "hvm_svm_nested_runtime.h"
#include "hvm_svm_nested_event.h"
#include <intrin.h>

/* Publish raw evidence without global locks or kernel logging in the hot path. */
VOID KswordSvmTrace(KSW_SVM_CPU* Cpu, ULONG Stage)
{
    /* Only this CPU writes its ring; queries validate the sequence twice. */
    KSW_SVM_TRACE* row = &Cpu->Trace[Cpu->TracePosition % KSW_SVM_TRACE_ROWS];
    /* Odd sequence makes a concurrent reader reject an incomplete row. */
    InterlockedIncrement(&row->Sequence);
    /* Preserve stage separately from architecture exit code. */
    row->Stage = Stage;
    /* Raw codes are 64-bit and never index an Intel-sized histogram. */
    row->ExitCode = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITCODE);
    /* Preserve both architecture-specific exit operands. */
    row->Info1 = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITINFO1);
    /* NPF's fault GPA is carried in EXITINFO2. */
    row->Info2 = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITINFO2);
    /* Continuation evidence belongs to this exact exit. */
    row->Rip = KswSvmRead64(Cpu->Guest, KSW_VMCB_RIP);
    /* Preserve current guest stack identity. */
    row->Rsp = KswSvmRead64(Cpu->Guest, KSW_VMCB_RSP);
    /* Preserve current address-space identity. */
    row->Cr3 = KswSvmRead64(Cpu->Guest, KSW_VMCB_CR3);
    /* Retain NRIP even when it is invalid for the exit type. */
    row->Nrip = KswSvmRead64(Cpu->Guest, KSW_VMCB_NRIP);
    /* Event injection is part of the failure diagnosis. */
    row->Event = KswSvmRead64(Cpu->Guest, KSW_VMCB_EVENT);
    /* This is a local timestamp, not an assumed synchronized wall clock. */
    row->Tsc = __rdtsc();
    /* Even sequence publishes a complete record with release ordering. */
    InterlockedIncrement(&row->Sequence);
    /* The position is published only after the row is complete. */
    InterlockedIncrement((volatile LONG*)&Cpu->TracePosition);
}

/* A faulted root cannot safely resume arbitrary guest code. */
static DECLSPEC_NORETURN VOID KswSvmFatal(KSW_SVM_CPU* Cpu, ULONG Detail)
{
    /* Preserve the final root evidence before invoking the stop path. */
    Cpu->Stage = KSWORD_ARK_HVM_STAGE_FAILED;
    /* Keep all ownership alive until a known complete native return. */
    KswordARKHvmStateSet(Cpu->Runtime, KSWORD_ARK_HVM_STATE_FAULTED | KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
    /* A nonblocking final record avoids losing the triggering reason. */
    KswordSvmTrace(Cpu, KSWORD_ARK_HVM_STAGE_FAILED);
    /* Follow the existing lifecycle's fail-closed bugcheck convention. */
    KeBugCheckEx(0x20001, 0x53564dUL, (ULONG_PTR)Cpu, Detail, (ULONG_PTR)KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITCODE));
}

/* Called from assembly with complete host state, closed GIF/IF and a stable private host stack. */
VOID KswordSvmGeneralPrepareEntry(KSW_SVM_CPU* Cpu)
{
    /* Self-tests must keep their independent marker and restoration contracts. */
    ULONG action;
    /* No partial general binding can silently fall back to a baseline VMRUN. */
    if (!Cpu->NestedEntryEnabled || Cpu->SelfTest || !Cpu->Nested || !Cpu->Nested->GeneralInitialized) { KswSvmFatal(Cpu, 0x100); }
    /* This happens after assembly sets the actual continuation, including first-entry RFLAGS. */
    action = KswordSvmNestedGeneralEntry(Cpu);
    /* WINDOW/UNSUPPORTED/FAULT retain their original transaction and are not executable entries. */
    if (action != KSW_NSVM_MACHINE_READY) { KswSvmFatal(Cpu, 0x110U + action); }
}

/* Advance only completed instructions; exceptions keep the faulting RIP. */
static VOID KswSvmAdvance(KSW_SVM_CPU* Cpu)
{
    /* NRIP is mandatory for general intercepted guest instructions in v1. */
    ULONGLONG rip = KswSvmRead64(Cpu->Guest, KSW_VMCB_RIP);
    /* Hardware supplies the length including valid instruction prefixes. */
    ULONGLONG next = KswSvmRead64(Cpu->Guest, KSW_VMCB_NRIP);
    /* Never assume a zero or stale next-RIP means a two-byte instruction. */
    if (!KswSvmNextRipValid(rip, next)) { KswSvmFatal(Cpu, 1); }
    /* Commit only a valid, completed instruction continuation. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RIP, next);
}

/* Inject #GP(0) or #UD without advancing the faulting instruction. */
static VOID KswSvmInject(KSW_SVM_CPU* Cpu, ULONG Vector)
{
    /* Use the same architectural aggregation rules as future nested exception delivery. */
    KSW_NSVM_EVENT_PLAN plan;
    /* Ordinary residency has no L1 intercept owner; #GP/#UD keep their faulting RIP. */
    if (KswSvmNestedExceptionPlan(Cpu->Guest, NULL, Vector, 0, 0, &plan) != KSW_NSVM_EVENT_INJECT) {
        /* Preserve shutdown/invalid-event evidence until an ordinary-resident shutdown path exists. */
        KswSvmFatal(Cpu, 2);
    }
    /* This baseline has no acknowledged-IRQ queue; refuse instead of silently losing that event. */
    if (!KswSvmNestedExceptionInject(Cpu->Guest, &plan, 0)) { KswSvmFatal(Cpu, 2); }
}

/* Complete only MSRs intentionally owned/intercepted by this backend. */
static VOID KswSvmMsr(KSW_SVM_CPU* Cpu)
{
    /* The guest MSR number is carried in ECX. */
    ULONG msr = (ULONG)Cpu->Gpr[1];
    /* EXITINFO1 bit zero distinguishes WRMSR from RDMSR. */
    BOOLEAN write = (KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITINFO1) & 1ULL) != 0;
    /* Reconstruct the guest EDX:EAX operand. */
    ULONGLONG value = ((Cpu->Gpr[2] & 0xffffffffULL) << 32) | (KswSvmRead64(Cpu->Guest, KSW_VMCB_RAX) & 0xffffffffULL);
    /* EFER reads hide only the backend-owned SVME bit. */
    ULONGLONG efer = KswSvmRead64(Cpu->Guest, KSW_VMCB_EFER) & ~KSW_SVM_EFER_SVME;
    /* Kernel-only instruction semantics must not be bypassed. */
    if (((PUCHAR)Cpu->Guest)[KSW_VMCB_CPL] != 0) { KswSvmInject(Cpu, 13); return; }
    /* No other software may install SVM ownership or mutate the cache/XSTATE contract. */
    if (write) {
        /* Idempotent EFER writes preserve Windows behavior without permitting nested SVM. */
        if (msr == KSW_SVM_MSR_EFER && value == efer) { KswSvmAdvance(Cpu); return; }
        /* Preserve the prepared XSS mask, cache interpretation and disabled supervisor CET. */
        if (KswSvmStateMsrWriteAllowed(msr, value, Cpu->Caps.Pat, Cpu->Caps.Xss)) { KswSvmAdvance(Cpu); return; }
        /* Deny changes rather than forwarding writes to host state. */
        KswSvmInject(Cpu, 13); return;
    }
    /* Only the SVM ownership registers require emulated reads. */
    if (msr == KSW_SVM_MSR_EFER) { value = efer; }
    /* Never leak or permit replacement of the live HSAVE address. */
    else if (msr == KSW_SVM_MSR_HSAVE) { value = Cpu->OriginalHsave; }
    /* Preserve the firmware observation without changing its lock. */
    else if (msr == KSW_SVM_MSR_VM_CR) { value = Cpu->Caps.VmCr; }
    /* Out-of-bitmap unknown MSRs fault as unsupported, not as fabricated zero. */
    else { KswSvmInject(Cpu, 13); return; }
    /* RDMSR writes zero-extended EAX and EDX. */
    KswSvmWrite64(Cpu->Guest, KSW_VMCB_RAX, (ULONG)value);
    /* Preserve the high result separately from the host's scratch RDX. */
    Cpu->Gpr[2] = (ULONG)(value >> 32);
    /* Only a successfully completed access advances RIP. */
    KswSvmAdvance(Cpu);
}

/* Return 0 to resume and 1 to restore native Windows on this processor. */
ULONG KswordSvmExit(KSW_SVM_CPU* Cpu)
{
    /* Decode a full-width architecture code, including INVALID=-1. */
    ULONGLONG code = KswSvmRead64(Cpu->Guest, KSW_VMCB_EXITCODE);
    /* Count the VMRUN whose exit was actually observed. */
    Cpu->TlbRequests++;
    /* Count exits without any interprocessor contention. */
    Cpu->Resource->Row.vmExitCount++;
    /* Preserve a raw vendor-specific exit field for v5 consumers. */
    Cpu->Resource->Row.svmExitCode = code;
    /* Publish raw trace before emulation changes RIP or operands. */
    KswordSvmTrace(Cpu, KSWORD_ARK_HVM_STAGE_EXIT);
    /* Route the explicitly requested bounded nested probe before ordinary one-shot handling. */
    if (Cpu->SelfTest == 2U && Cpu->Nested) { return KswordSvmNestedProbeExit(Cpu); }
    /* INVALID means the guest never executed; return to the saved kernel caller. */
    if (code == KSW_SVM_EXIT_INVALID) {
        /* Keep the failed stage authoritative after native return. */
        Cpu->Stage = KSWORD_ARK_HVM_STAGE_FAILED;
        /* Preserve the actual failed-entry result. */
        Cpu->Result = STATUS_HV_OPERATION_FAILED;
        /* Return through the launch continuation only while guest state is still initial. */
        if (Cpu->Active || Cpu->Resource->Row.vmExitCount != 1) { KswSvmFatal(Cpu, 3); }
        /* Use a known kernel continuation with the captured launch stack. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmGuestResume);
        /* Restore the launch stack rather than any rejected RSP. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_RSP, Cpu->LaunchRsp);
        /* Request native restoration, never publication of Active. */
        return 1;
    }
    /* A successful self-test requires a specific executed guest CPUID marker. */
    if (Cpu->SelfTest) {
        /* No other exit counts as a successful hardware self-test. */
        Cpu->Result = code == KSW_SVM_EXIT_CPUID && (ULONG)KswSvmRead64(Cpu->Guest, KSW_VMCB_RAX) == KSW_SVM_TEST_LEAF ? STATUS_SUCCESS : STATUS_HV_OPERATION_FAILED;
        /* The one-shot guest never enters arbitrary Windows execution. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmGuestResume);
        /* Return through the original call stack. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_RSP, Cpu->LaunchRsp);
        /* Complete the self-test through the native-state restoration path. */
        return 1;
    }
    /* Raw exit accounting and bounded self-test handling precede every general dispatch. */
    if (Cpu->NestedEntryEnabled) {
        /* The coordinator restores temporary controls before interpreting L1/L2 ownership. */
        ULONG action = KswordSvmNestedGeneralExit(Cpu);
        /* Native return requires a quiescent private stop and still needs the caller's register readback. */
        if (action == KSW_NSVM_MACHINE_NATIVE) { return 1; }
        /* Only READY proceeds to a fresh event/control preparation in the assembly loop. */
        if (action == KSW_NSVM_MACHINE_READY) { return 0; }
        /* Unsupported guest shutdown/window cases are retained, never delegated to native Windows by accident. */
        KswSvmFatal(Cpu, 0x120U + action);
    }
    /* CPUID preserves outer VMware identity but hides unimplemented nested SVM. */
    if (code == KSW_SVM_EXIT_CPUID) {
        /* Decode guest leaf/subleaf without using host call operands. */
        ULONG leaf = (ULONG)KswSvmRead64(Cpu->Guest, KSW_VMCB_RAX);
        /* Intrinsics use signed integers, converted explicitly on both sides. */
        int r[4];
        /* Query the actual outer virtual CPU topology and features. */
        __cpuidex(r, (int)leaf, (int)(ULONG)Cpu->Gpr[1]);
        /* Nested SVM is not exposed to the monitored Windows instance. */
        KswSvmFilterCpuid(leaf, r);
        /* Store architectural EAX/EBX/ECX/EDX results with zero extension. */
        KswSvmWrite64(Cpu->Guest, KSW_VMCB_RAX, (ULONG)r[0]);
        /* RBX is not hardware-switched by VMRUN. */
        Cpu->Gpr[3] = (ULONG)r[1];
        /* RCX is not hardware-switched by VMRUN. */
        Cpu->Gpr[1] = (ULONG)r[2];
        /* RDX is not hardware-switched by VMRUN. */
        Cpu->Gpr[2] = (ULONG)r[3];
        /* CPUID completed successfully. */
        KswSvmAdvance(Cpu);
    } else if (code == KSW_SVM_EXIT_MSR) {
        /* Emulate ownership-controlled MSRs without root RDMSR exception hazards. */
        KswSvmMsr(Cpu);
    } else if (code == KSW_SVM_EXIT_VMMCALL && Cpu->Gpr[1] == KSW_SVM_CALL_SIGNATURE &&
        ((PUCHAR)Cpu->Guest)[KSW_VMCB_CPL] == 0) {
        /* A stop operation must have been requested by the pinned lifecycle worker. */
        if (Cpu->Gpr[2] == KSW_SVM_CALL_STOP && Cpu->StopRequested && Cpu->Active) {
            /* Advance beyond exactly the private hypercall instruction. */
            KswSvmAdvance(Cpu);
            /* Return success to the stopping Windows caller. */
            KswSvmWrite64(Cpu->Guest, KSW_VMCB_RAX, 0);
            /* Native completion is acknowledged by the caller after assembly returns. */
            return 1;
        }
        /* Query is the only non-mutating private operation. */
        if (Cpu->Gpr[2] == KSW_SVM_CALL_QUERY) {
            /* The caller can compare a private response without changing residency. */
            KswSvmWrite64(Cpu->Guest, KSW_VMCB_RAX, KSW_SVM_CALL_SIGNATURE);
            /* Query completed successfully. */
            KswSvmAdvance(Cpu);
        } else { KswSvmInject(Cpu, 6); }
    } else if ((code >= 0x80 && code <= 0x86) || code == 0x7a || code == 0x8d) {
        /* SVM operations are absent from CPUID; XSETBV contract changes are denied. */
        KswSvmInject(Cpu, code == 0x8d ? 13 : 6);
    } else {
        /* Unexpected NPF, shutdown, or unknown intercept requires retained evidence. */
        KswSvmFatal(Cpu, 4);
    }
    /* Resume only after one of the explicitly handled paths completed. */
    return 0;
}
