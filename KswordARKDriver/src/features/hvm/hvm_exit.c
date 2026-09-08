/*++

Module Name:

    hvm_exit.c

Abstract:

    Dispatches resident VM exits without allocation or waiting, records bounded
    evidence, restores allow-once EPT rules, and devirtualizes on unknown exits.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_exit.h"
#include "hvm_exit_emulate.h"
#include "hvm_cr_policy.h"
#include "hvm_ept_view.h"
#include "hvm_ept_switch.h"
#include "hvm_msr_policy.h"
#include "hvm_resident.h"
#include "hvm_ept.h"
#include "hvm_event.h"
#include "hvm_nested.h"
#include "hvm_inject.h"
#include "hvm_process.h"
#include "hvm_vmcs.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the VMCS primary processor-based controls field. */
#define KSW_VMCS_PRIMARY_CONTROLS 0x4002UL
/* Name the VMCS VM-exit reason field through shared telemetry. */
#define KSW_VMCS_GUEST_PHYSICAL_ADDRESS 0x2400UL
/* Name the VMCS guest linear address field. */
#define KSW_VMCS_GUEST_LINEAR_ADDRESS 0x640AUL
/* Name the VMCS guest instruction pointer field. */
#define KSW_VMCS_GUEST_RIP 0x681EUL
/*
 * 本处理器当前走的 EPT 层次。EPTP 切换后端在退出路径里改的就是这一个字段，
 * 而且**只改自己 VMCS 的这一份** —— 别的处理器的层次不受影响，这正是它不必
 * 把窗口压到一条指令的原因。
 */
#define KSW_VMCS_EPT_POINTER 0x201AUL
/* 客户 CR3；R-1 进程处置靠它认出正在跑的地址空间。 */
#define KSW_VMCS_GUEST_CR3 0x6802UL
/* Guest interruptibility state; bits 0 and 1 block interrupts at VM entry. */
#define KSW_VMCS_GUEST_INTERRUPTIBILITY 0x4824UL
/* Guest activity state; value one selects the architectural halt state. */
#define KSW_VMCS_GUEST_ACTIVITY 0x4826UL
/* The architectural halt activity state. */
#define KSW_VMX_ACTIVITY_HLT 1ULL
/* IA32_VMX_MISC bit 6 reports whether the halt activity state is supported. */
#define KSW_VMX_MISC_ACTIVITY_HLT (1ULL << 6)
/* Blocking by STI and by MOV SS both forbid a non-active activity state. */
#define KSW_VMX_INTERRUPTIBILITY_BLOCKING 3ULL
/*
 * Guest SS access rights.  Bits 6:5 carry the descriptor privilege level, which
 * is the architectural definition of the current privilege level.  This is SS,
 * not CS at 0x4816: the two encodings are adjacent and reading the wrong one
 * gives a plausible answer that is silently wrong across a conforming code
 * segment or a transition.
 */
#define KSW_VMCS_GUEST_SS_ACCESS 0x4818UL
/* Shift and mask that extract the privilege level from those access rights. */
#define KSW_VMX_ACCESS_RIGHTS_DPL_SHIFT 5U
#define KSW_VMX_ACCESS_RIGHTS_DPL_MASK 3ULL
/* The only privilege level allowed to reach a lifecycle or forwarded VMCALL. */
#define KSW_HVM_SUPERVISOR_CPL 0UL
/*
 * Synthetic guest-idle MSR.  Named here only so the comment in the dispatcher
 * that explains why it is deliberately NOT intercepted has something to point
 * at; nothing reads this value.
 */
#define KSW_HVM_MSR_GUEST_IDLE 0x400000F0UL

/* Identify the monitor-trap flag execution control. */
#define KSW_VMX_PRIMARY_MONITOR_TRAP_FLAG (1UL << 27)
/*
 * NMI-window exiting: exit as soon as the guest can accept an NMI again.
 *
 * Requested only while an NMI is being held for the guest, and cleared the
 * moment it is delivered.  Left on it would exit continuously, because the
 * condition it names is the guest's ordinary state.
 */
#define KSW_VMX_PRIMARY_NMI_WINDOW_EXITING (1UL << 22)

/* VM-exit interruption information; describes what caused an exception/NMI exit. */
#define KSW_VMCS_EXIT_INTERRUPTION_INFO 0x4404UL
/* VM-entry interruption information; writing it delivers an event on entry. */
#define KSW_VMCS_ENTRY_INTERRUPTION_INFO 0x4016UL
/* Bit 31 of either field marks the descriptor valid. */
#define KSW_VMX_INTERRUPTION_VALID (1ULL << 31)
/* Bits 10:8 carry the interruption type; type 2 is NMI. */
#define KSW_VMX_INTERRUPTION_TYPE_SHIFT 8
#define KSW_VMX_INTERRUPTION_TYPE_MASK 7ULL
#define KSW_VMX_INTERRUPTION_TYPE_NMI 2ULL
/* Valid | type NMI | vector 2: the exact descriptor that redelivers an NMI. */
#define KSW_VMX_ENTRY_INTERRUPTION_NMI 0x80000202ULL
/*
 * Guest interruptibility state bit 3: the guest is currently blocking NMIs,
 * which in practice means it is inside its own NMI handler and has not yet
 * executed the IRET that would end that.
 */
#define KSW_VMX_INTERRUPTIBILITY_BLOCKING_BY_NMI (1ULL << 3)
/* VM exit taken when the guest becomes able to accept an NMI again. */
#define KSW_VMX_EXIT_NMI_WINDOW 8UL

/*
 * TLFS call codes that ask the hypervisor to invalidate translations on
 * processors other than the caller.  Bits 15:0 of the hypercall input value,
 * which the guest passes in RCX.
 *
 * These four are the whole reason the NMI machinery exists.  Every other
 * forwarded call is a relay and nothing more; these are the ones whose effect
 * L0 cannot deliver on our behalf, because the sibling it would have to
 * invalidate is running our guest rather than L1 directly.
 *
 * Deliberately not listed: HvCallFlushGuestPhysicalAddressSpace/List.  Those
 * name a *nested* address space, which on this machine is ours to manage - we
 * invalidate EPT with INVEPT and never ask L0 to do it.
 */
#define KSW_HV_CALL_FLUSH_VA_SPACE 0x0002ULL
#define KSW_HV_CALL_FLUSH_VA_LIST 0x0003ULL
#define KSW_HV_CALL_FLUSH_VA_SPACE_EX 0x0013ULL
#define KSW_HV_CALL_FLUSH_VA_LIST_EX 0x0014ULL
/* Bits 15:0 of RCX carry the call code in both fast and slow hypercalls. */
#define KSW_HV_CALL_CODE_MASK 0xFFFFULL

/* Name architecturally common VM-exit reasons. */
#define KSW_VMX_EXIT_EXCEPTION_OR_NMI 0UL
/* Name the external-interrupt VM-exit reason. */
#define KSW_VMX_EXIT_EXTERNAL_INTERRUPT 1UL
/* Name the CPUID VM-exit reason. */
#define KSW_VMX_EXIT_CPUID 10UL
/* Name the HLT VM-exit reason. */
#define KSW_VMX_EXIT_HLT 12UL
/* Name the VMCALL VM-exit reason. */
#define KSW_VMX_EXIT_VMCALL 18UL
/* Name the VMFUNC VM-exit reason, taken only when the function fails. */
#define KSW_VMX_EXIT_VMFUNC 59UL
/* Name the INVD VM-exit reason, which no execution control can suppress. */
#define KSW_VMX_EXIT_INVD 13UL
/* Name the RDMSR VM-exit reason. */
#define KSW_VMX_EXIT_RDMSR 31UL
/* Name the WRMSR VM-exit reason. */
#define KSW_VMX_EXIT_WRMSR 32UL
/* Name the XSETBV VM-exit reason, which no execution control can suppress. */
#define KSW_VMX_EXIT_XSETBV 55UL
/* Name the MOV-CR VM-exit reason, reached only for masked bits. */
#define KSW_VMX_EXIT_MOV_CR 28UL
/* Name the MOV-DR VM-exit reason, reached only when interception is on. */
#define KSW_VMX_EXIT_MOV_DR 29UL
/* Name the monitor-trap VM-exit reason. */
#define KSW_VMX_EXIT_MONITOR_TRAP 37UL
/* Name the EPT-violation VM-exit reason. */
#define KSW_VMX_EXIT_EPT_VIOLATION 48UL
/* Name the EPT-misconfiguration VM-exit reason. */
#define KSW_VMX_EXIT_EPT_MISCONFIGURATION 49UL

/* Identify the first and last VMX instruction exit reasons in the base block. */
#define KSW_VMX_EXIT_VMCLEAR 19UL
/* Identify the last base VMX instruction exit reason. */
#define KSW_VMX_EXIT_VMXON 27UL
/* Identify INVEPT as a nested VMX instruction exit. */
#define KSW_VMX_EXIT_INVEPT 50UL
/* Identify INVVPID as a nested VMX instruction exit. */
#define KSW_VMX_EXIT_INVVPID 53UL

/* Advance guest RIP after one completely decoded exit instruction. */
static BOOLEAN
KswordARKHvmExitAdvanceRip(
    _In_ ULONG InstructionLength
    )
{
    SIZE_T guestRip = 0U;

    /* Require one architecturally valid instruction length. */
    if (InstructionLength == 0UL ||
        InstructionLength > 15UL) {
        /* Report that no safe guest continuation was written. */
        return FALSE;
    }
    /* Read the current guest instruction pointer. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_RIP,
            &guestRip) != 0U) {
        /* Report VMREAD failure to the dispatcher. */
        return FALSE;
    }
    /* Reject pointer addition overflow before advancing. */
    if (guestRip > MAXULONG_PTR - InstructionLength) {
        /* Report an unsafe guest continuation. */
        return FALSE;
    }
    /* Advance to the instruction following the intercepted operation. */
    guestRip += InstructionLength;
    /* Write the complete guest instruction continuation. */
    return KswordARKHvmVmcsFieldStore(
        KSW_VMCS_GUEST_RIP,
        guestRip) == 0U;
}

/* Enable or disable monitor-trap exit in the current VMCS. */
static BOOLEAN
KswordARKHvmExitSetMonitorTrap(
    _In_ BOOLEAN Enabled
    )
{
    SIZE_T controls = 0U;

    /* Read the current primary processor-based controls. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_PRIMARY_CONTROLS,
            &controls) != 0U) {
        /* Report VMREAD failure to the dispatcher. */
        return FALSE;
    }
    /* Set the monitor-trap flag for one allow-once instruction. */
    if (Enabled) {
        /* Enable the monitor-trap execution control. */
        controls |=
            (SIZE_T)KSW_VMX_PRIMARY_MONITOR_TRAP_FLAG;
    } else {
        /* Disable monitor-trap after restoring EPT permissions. */
        controls &=
            ~(SIZE_T)KSW_VMX_PRIMARY_MONITOR_TRAP_FLAG;
    }
    /* Write the complete updated primary controls. */
    return KswordARKHvmVmcsFieldStore(
        KSW_VMCS_PRIMARY_CONTROLS,
        controls) == 0U;
}

/* Request or clear NMI-window exiting on the current VMCS. */
static BOOLEAN
KswordARKHvmExitSetNmiWindow(
    _In_ BOOLEAN Enabled
    )
{
    SIZE_T controls = 0U;

    /* Read the current primary processor-based controls. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_PRIMARY_CONTROLS,
            &controls) != 0U) {
        /* Report VMREAD failure to the dispatcher. */
        return FALSE;
    }
    if (Enabled) {
        /* Ask to be told the moment the guest can take an NMI. */
        controls |=
            (SIZE_T)KSW_VMX_PRIMARY_NMI_WINDOW_EXITING;
    } else {
        /* Stop asking once the held NMI has been delivered. */
        controls &=
            ~(SIZE_T)KSW_VMX_PRIMARY_NMI_WINDOW_EXITING;
    }
    /* Write the complete updated primary controls. */
    return KswordARKHvmVmcsFieldStore(
        KSW_VMCS_PRIMARY_CONTROLS,
        controls) == 0U;
}

/*
 * Give the guest one NMI, now if it can take one and later if it cannot.
 *
 * Injection through the VM-entry interruption field is **unconditional**: the
 * processor delivers the event on entry no matter what the guest's
 * interruptibility state says.  So handing an NMI back while the guest is
 * inside its own NMI handler would nest one NMI inside another, which is
 * exactly the architectural situation IRET exists to end and which Windows
 * does not expect to see.  Checking blocking-by-NMI first, and holding the NMI
 * until an NMI window opens, is what makes redelivery faithful rather than
 * merely prompt.
 *
 * A held NMI is not lost and not queued deeper than one: the architecture
 * collapses multiple pending NMIs into one anyway, so a second arrival while
 * one is already held needs no additional storage.
 */
static BOOLEAN
KswordARKHvmExitDeliverGuestNmi(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context
    )
{
    SIZE_T interruptibility = 0U;

    /* Without the guest's interruptibility state, hold rather than guess. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_INTERRUPTIBILITY,
            &interruptibility) != 0U) {
        return FALSE;
    }
    if (((ULONGLONG)interruptibility &
            KSW_VMX_INTERRUPTIBILITY_BLOCKING_BY_NMI) != 0ULL) {
        /* Hold it and ask to be woken when the guest's handler returns. */
        InterlockedExchange(&Context->PendingGuestNmi, 1L);
        return KswordARKHvmExitSetNmiWindow(TRUE);
    }
    /* Deliver the guest's own NMI on the next VM entry. */
    return KswordARKHvmVmcsFieldStore(
        KSW_VMCS_ENTRY_INTERRUPTION_INFO,
        KSW_VMX_ENTRY_INTERRUPTION_NMI) == 0U;
}

/* Convert EPT qualification bits to the public access mask. */
static ULONG
KswordARKHvmExitDecodeEptAccess(
    _In_ ULONGLONG Qualification
    )
{
    ULONG access = 0UL;

    /* Decode an attempted data read. */
    if ((Qualification & (1ULL << 0)) != 0ULL) {
        /* Publish protocol-visible read access. */
        access |= KSWORD_ARK_HVM_EPT_ACCESS_READ;
    }
    /* Decode an attempted data write. */
    if ((Qualification & (1ULL << 1)) != 0ULL) {
        /* Publish protocol-visible write access. */
        access |= KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
    }
    /* Decode an attempted instruction fetch. */
    if ((Qualification & (1ULL << 2)) != 0ULL) {
        /* Publish protocol-visible execute access. */
        access |= KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
    }
    /* Return the complete attempted-access mask. */
    return access;
}

/* Capture optional guest physical and linear addresses for exit evidence. */
static VOID
KswordARKHvmExitReadAddresses(
    _Out_ ULONGLONG* GuestPhysicalAddress,
    _Out_ ULONGLONG* GuestLinearAddress
    )
{
    SIZE_T guestPhysical = 0U;
    SIZE_T guestLinear = 0U;

    /* Reject either missing fixed output pointer. */
    if (GuestPhysicalAddress == NULL ||
        GuestLinearAddress == NULL) {
        /* Return without publishing a partial address pair. */
        return;
    }
    /* Publish zero defaults before optional VMREAD operations. */
    *GuestPhysicalAddress = 0ULL;
    /* Publish the zero guest-linear default. */
    *GuestLinearAddress = 0ULL;
    /* Preserve guest physical address only when VMREAD succeeds. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_PHYSICAL_ADDRESS,
            &guestPhysical) == 0U) {
        /* Publish the complete guest physical address. */
        *GuestPhysicalAddress =
            (ULONGLONG)guestPhysical;
    }
    /* Preserve guest linear address only when VMREAD succeeds. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_LINEAR_ADDRESS,
            &guestLinear) == 0U) {
        /* Publish the complete guest linear address. */
        *GuestLinearAddress =
            (ULONGLONG)guestLinear;
    }
}

/* Publish one fixed VM-exit event and runtime snapshot. */
static VOID
KswordARKHvmExitPublishTelemetry(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _In_ const KSW_HVM_VMEXIT_TELEMETRY* Telemetry,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONGLONG GuestLinearAddress,
    _In_ ULONG EventType,
    _In_ ULONG Access,
    _In_ ULONG RuleId,
    _In_ NTSTATUS Status
    )
{
    KSWORD_ARK_HVM_EVENT_ROW eventRow = { 0 };
    ULONG basicReason = 0UL;

    /* Reject incomplete fixed telemetry state. */
    if (Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL ||
        Telemetry == NULL) {
        /* Return without publishing partial evidence. */
        return;
    }
    /* Decode the Intel basic reason for protocol state. */
    basicReason =
        Telemetry->Reason &
        KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    /* Increment the process-wide VM-exit count atomically. */
    InterlockedIncrement64(
        &Context->Runtime->VmExitCount);
    /* Publish the last exit qualification atomically. */
    InterlockedExchange64(
        &Context->Runtime->LastExitQualification,
        (LONG64)Telemetry->Qualification);
    /* Publish the last guest instruction pointer atomically. */
    InterlockedExchange64(
        &Context->Runtime->LastGuestRip,
        (LONG64)Telemetry->GuestRip);
    /* Publish the last guest stack pointer atomically. */
    InterlockedExchange64(
        &Context->Runtime->LastGuestRsp,
        (LONG64)Telemetry->GuestRsp);
    /* Publish the last basic exit reason atomically. */
    InterlockedExchange(
        &Context->Runtime->LastExitReason,
        (LONG)basicReason);
    /* Publish the last exit instruction length atomically. */
    InterlockedExchange(
        &Context->Runtime->LastExitInstructionLength,
        (LONG)Telemetry->InstructionLength);
    /* Publish the last VM-instruction error atomically. */
    InterlockedExchange(
        &Context->Runtime->LastVmInstructionError,
        (LONG)Telemetry->VmInstructionError);
    /* Increment the processor-local VM-exit count atomically. */
    InterlockedIncrement64(
        (volatile LONG64*)&Context->Resource->
            Row.vmExitCount);
    /* Publish the processor-local last exit reason. */
    Context->Resource->Row.lastExitReason =
        basicReason;
    /* Publish the processor-local nested state. */
    Context->Resource->Row.nestedState =
        Context->Nested.State;
    /* Publish the processor-local eVMCS version evidence. */
    Context->Resource->Row.evmcsVersion =
        Context->Runtime->EvmcsVersion;
    /* Preserve the exact group identity in the event row. */
    eventRow.processorGroup =
        Context->Resource->Row.processorGroup;
    /* Preserve the exact group-relative processor number. */
    eventRow.processorNumber =
        Context->Resource->Row.processorNumber;
    /* Preserve the selected event classification. */
    eventRow.type = EventType;
    /* Preserve the Intel basic exit reason. */
    eventRow.exitReason = basicReason;
    /* Preserve the attempted EPT access mask. */
    eventRow.access = Access;
    /* Preserve the matching EPT rule identifier. */
    eventRow.ruleId = RuleId;
    /* Preserve the guest physical address when available. */
    eventRow.guestPhysicalAddress =
        GuestPhysicalAddress;
    /* Preserve the guest linear address when available. */
    eventRow.guestLinearAddress =
        GuestLinearAddress;
    /* Preserve the guest instruction pointer. */
    eventRow.guestRip = Telemetry->GuestRip;
    /* Preserve the complete exit qualification. */
    eventRow.qualification =
        Telemetry->Qualification;
    /* Preserve the authoritative dispatch status. */
    eventRow.status = Status;
    /*
     * A routine exit reaches the ring only when a trace was asked for.
     *
     * Everything above this point still runs for every exit: the counters, the
     * lastExit* fields and the per-reason histogram are untouched, so "how many
     * exits", "what was the most recent one" and "where do they go" all answer
     * exactly as before.  What changes is only which rows occupy the 1024 ring
     * slots.
     *
     * Measured 2026-09-07 on 2 vCPU over 30 s of residency: 682829 published,
     * 0 that failed to claim a slot, 681805 pushed out by wrap.  The ring never
     * had a write problem - it turns over about twenty-two times a second, and
     * virtually all of that volume is this one routine class.  Keeping it meant
     * an EPT violation, a nested VMX instruction, a fatal exit or a lifecycle
     * event survived roughly 45 ms, so reading any of them required polling
     * faster than the ring wraps.  That is not a condition a user-mode reader
     * can meet on a real machine.
     *
     * The four evidence classes are rare by construction and are always kept.
     */
    if (eventRow.type != KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT ||
        InterlockedCompareExchange(
            &Context->Runtime->TraceRoutineExits,
            0L,
            0L) != 0L) {
        /* Publish the complete nonblocking event row. */
        KswordARKHvmEventPublish(&eventRow);
    }
    /* Publish protocol-visible event availability. */
    InterlockedOr(
        (volatile LONG*)&Context->Runtime->StateFlags,
        (LONG)KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE);
}

/*
 * Report the privilege level the guest executed the current instruction at.
 *
 * VMCALL exits before the processor performs any privilege check: SDM orders
 * "in VMX non-root operation - VM exit" ahead of "CPL > 0 - #GP(0)", so a
 * ring-3 VMCALL arrives at this dispatcher exactly like a ring-0 one.  Nothing
 * else supplies the level either - an EPT violation reports no CPL at all - so
 * every VMCALL disposition that does more than fault has to read it here.
 *
 * Failing to read the field yields supervisor-denied rather than supervisor:
 * the outer hypervisor is known to refuse some guest-state encodings (VMWRITE
 * of GUEST_SMBASE is refused on this target), and a refusal must never be able
 * to widen access.
 */
static ULONG
KswordARKHvmExitGuestCpl(
    VOID
    )
{
    SIZE_T accessRights = 0;

    /* Treat an unreadable privilege level as unprivileged. */
    if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_SS_ACCESS, &accessRights) != 0) {
        /* Report the least privileged level so callers fail closed. */
        return 3UL;
    }
    /* Extract the descriptor privilege level carried in bits 6:5. */
    return (ULONG)(((ULONGLONG)accessRights >>
        KSW_VMX_ACCESS_RIGHTS_DPL_SHIFT) & KSW_VMX_ACCESS_RIGHTS_DPL_MASK);
}

/*
 * Complete one guest HLT by entering the architectural halt state.
 *
 * Resident mode never asks for HLT exiting, but KswordARKHvmAdjustControls
 * cannot clear a bit the capability MSR reports as must-be-one, and the
 * hypervisor beneath us does exactly that: measured on nested Hyper-V, the
 * third exit of a resident guest was reason 12 from the idle loop.  Treating
 * it as unimplemented dropped the whole processor out of VMX within
 * milliseconds of VMLAUNCH - residency looked like it started and then simply
 * evaporated, with RESIDENT_ACTIVE already cleared by the time anything
 * queried it.
 *
 * The architectural answer is to retire the HLT and let VM entry put the
 * processor into the halt state, so the guest idles exactly as it asked and
 * wakes on its next interrupt.
 *
 * Retire the HLT first, then select the halt state.  An earlier revision read
 * the interrupt shadow first and, when it was set, resumed on the unretired
 * HLT expecting the shadow to expire - it does not, because the HLT never
 * completes, so the same exit repeats forever and the guest makes no progress.
 * That was a regression written to defend against a storm that a thirty-second
 * soak had already disproven: 33852 exits over 30s is roughly 1100 per second,
 * which is a healthy resident guest, not a spin.  Skipping the halt is the
 * conservative branch and it is taken only when VM entry would refuse the halt
 * state outright.
 *
 * A third-party implementation states the same symptom as an enlightened-VMCS
 * property - that HLT exiting is always delivered and cannot be disabled under
 * eVMCS.  The symptom matches what was measured here, but that attribution does
 * not hold: the TLFS enlightened VMCS field mapping carries both ProcessorControls
 * at 0x00004002 and GuestSleepState at 0x00004826, and nothing in it forces any
 * control bit to one.  What actually produces the symptom is ordinary control
 * adjustment.  The hypervisor beneath us reports HLT exiting in the allowed-zero
 * half of the capability MSR, so KswordARKHvmAdjustControls must set it however
 * little we want it - see the request site in hvm_vmcs.c, which asks for HLT
 * exiting only outside resident mode.  Nothing in this driver has ever activated
 * eVMCS: hvm_evmcs.c only performs CPUID discovery and returns
 * STATUS_NOT_IMPLEMENTED.  Keep the distinction, because an eVMCS attribution
 * would send the next reader to the wrong file.
 *
 * Two things can bring exit reason 33, invalid guest state, back.  One is moving
 * the retirement below the early returns, as described above.  The other is
 * selecting the halt state on an entry that also injects an event, since the
 * activity state and the VM-entry interruption-information valid bit constrain
 * each other.  That does not happen today because every injection path returns
 * on its own and never shares an exit with this one.
 *
 * One honest limit on all of the above: the VMWRITE below is the only one on
 * this path whose result is discarded, and no counter distinguishes a halt that
 * was entered from one skipped by the three conservative branches.  The soak
 * criterion counts unexpected devirtualizations and reads identically either
 * way, so there is no positive evidence here that the halt state was ever
 * actually entered.  Anyone tuning this path should add those counters first.
 */
static BOOLEAN
KswordARKHvmExitHandleHlt(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG InstructionLength
    )
{
    SIZE_T interruptibility = 0;

    /* Retire the HLT before choosing where the guest resumes. */
    if (!KswordARKHvmExitAdvanceRip(InstructionLength)) {
        /* Report an incomplete exit so the caller fails closed. */
        return FALSE;
    }
    /* A processor that does not advertise the halt state cannot enter it. */
    if ((Context->Runtime->VmxMisc & KSW_VMX_MISC_ACTIVITY_HLT) == 0ULL) {
        /* Resume without halting rather than risk a VM-entry failure. */
        return TRUE;
    }
    /* VM entry rejects a non-active activity state while interrupts block. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_INTERRUPTIBILITY,
            &interruptibility) != 0) {
        /* Resume without halting when the state cannot be verified. */
        return TRUE;
    }
    if (((ULONGLONG)interruptibility &
            KSW_VMX_INTERRUPTIBILITY_BLOCKING) != 0ULL) {
        /* Resume without halting while STI or MOV SS still blocks. */
        return TRUE;
    }
    /*
     * The processor stores the activity state back into the VMCS on every VM
     * exit, so this selection lasts exactly one entry and does not have to be
     * cleared on the paths that resume for other reasons.
     */
    (void)KswordARKHvmVmcsFieldStore(KSW_VMCS_GUEST_ACTIVITY, KSW_VMX_ACTIVITY_HLT);
    /* Report a completely handled halt. */
    return TRUE;
}

/* Emulate one CPUID exit and preserve nested-exposure policy. */
static BOOLEAN
KswordARKHvmExitHandleCpuid(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG InstructionLength
    )
{
    int registers[4] = { 0 };
    ULONG leaf = (ULONG)Frame->Rax;
    ULONG subleaf = (ULONG)Frame->Rcx;

    /* Execute the exact host CPUID leaf and subleaf. */
    __cpuidex(
        registers,
        (int)leaf,
        (int)subleaf);
    /* Hide guest VMX exposure unless nested dispatch was explicitly enabled. */
    if (leaf == 1UL &&
        !Context->Nested.Enabled) {
        /* Clear the VMX capability bit in guest CPUID.1:ECX. */
        registers[2] &= ~(1L << 5);
    }
    /* Publish zero-extended guest RAX. */
    Frame->Rax = (ULONG)registers[0];
    /* Publish zero-extended guest RBX. */
    Frame->Rbx = (ULONG)registers[1];
    /* Publish zero-extended guest RCX. */
    Frame->Rcx = (ULONG)registers[2];
    /* Publish zero-extended guest RDX. */
    Frame->Rdx = (ULONG)registers[3];
    /* Advance past the fully decoded CPUID instruction. */
    return KswordARKHvmExitAdvanceRip(
        InstructionLength);
}

/* Return whether one exit reason belongs to nested VMX instruction dispatch. */
static BOOLEAN
KswordARKHvmExitIsNestedInstruction(
    _In_ ULONG ExitReason
    )
{
    /* Accept the contiguous VMCLEAR through VMXON reason block. */
    if (ExitReason >= KSW_VMX_EXIT_VMCLEAR &&
        ExitReason <= KSW_VMX_EXIT_VMXON) {
        /* Report a base nested VMX instruction exit. */
        return TRUE;
    }
    /* Accept invalidation instructions that live outside the base block. */
    return ExitReason == KSW_VMX_EXIT_INVEPT ||
        ExitReason == KSW_VMX_EXIT_INVVPID;
}

ULONG
KswordARKHvmResidentVmExitDispatch(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context
    )
{
    KSW_HVM_VMEXIT_TELEMETRY telemetry = { 0 };
    ULONGLONG guestPhysicalAddress = 0ULL;
    ULONGLONG guestLinearAddress = 0ULL;
    ULONG basicReason = KSWORD_ARK_HVM_EXIT_REASON_NONE;
    ULONG access = 0UL;
    ULONG ruleId = 0UL;
    KSW_HVM_EPT_VIEW_SWITCH viewSwitch = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    ULONG eptDisposition = KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE;
    BOOLEAN handled = FALSE;
    BOOLEAN injectFault = FALSE;
    BOOLEAN guestLinearValid = FALSE;
    /* Set only where a guest hypercall was turned away instead of relayed. */
    BOOLEAN hypercallRefused = FALSE;

    /* Reject a VM exit without an exact active processor context. */
    if (Frame == NULL ||
        Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL ||
        InterlockedCompareExchange(
            &Context->Active,
            0L,
            0L) == 0L) {
        /* Request a bounded fatal trap with no unsafe continuation. */
        return KSW_HVM_EXIT_ACTION_FATAL;
    }
    /* Capture protocol-visible VMCS exit telemetry. */
    status = KswordARKHvmReadVmExitTelemetry(
        &telemetry);
    /* Stop when the current VMCS cannot be inspected safely. */
    if (!NT_SUCCESS(status)) {
        /* Attempt devirtualization without advancing an unknown instruction. */
        handled = KswordARKHvmResidentDeactivateCurrent(
            Context,
            0UL,
            TRUE);
        /* Return only a verified guest continuation. */
        return handled
            ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
            : KSW_HVM_EXIT_ACTION_FATAL;
    }
    /* Decode the Intel basic VM-exit reason. */
    basicReason =
        telemetry.Reason &
        KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    /*
     * Count the exit here, before anything can decide to leave.
     *
     * Placed immediately after the reason is decoded so the histogram counts
     * exits by what they *were*, independent of how they were later serviced -
     * including the ones that devirtualize a few lines below and never reach
     * the servicing switch at all.  An exit the driver refused to handle is
     * exactly the kind worth having a count of.
     *
     * Plain increment, no interlocked: this array belongs to the processor
     * executing this handler and no other writer exists.  Nothing reads it
     * concurrently either - the protocol path sums the columns while reporting,
     * where a torn count would cost a slightly stale diagnostic number and
     * nothing else.
     */
    if (basicReason < KSWORD_ARK_HVM_EXIT_REASON_SLOTS) {
        Context->Resource->ExitReasonCount[basicReason] += 1UL;
    }
    /*
     * Optional VMREAD load, for measuring what a VMCS field access costs here.
     *
     * The question this answers is whether moving field access off the VMREAD
     * instruction and onto a shared page would be worth its cost - a hundred
     * and fifty field mappings, and the loss of several fields the shared
     * layout does not carry.  Guessing at that from first principles is exactly
     * the kind of reasoning this codebase has been wrong about before.
     *
     * Adding load rather than timing a single instruction: a timestamp on the
     * exit path costs as much as the thing being measured, while N extra reads
     * show up cleanly as reduced exit throughput, and N is known.  The value is
     * discarded and no VMCS state is touched, so an armed run differs from an
     * unarmed one only in speed - which is the measurement.
     */
    if (InterlockedCompareExchange(
            &Context->Runtime->VmreadBenchArmed,
            0L,
            0L) != 0L) {
        LONG depth = InterlockedCompareExchange(
            &Context->Runtime->VmreadBenchIterations,
            0L,
            0L);
        LONG iteration = 0L;
        SIZE_T discard = 0U;

        for (iteration = 0L;
             iteration < depth;
             ++iteration) {
            /* Any always-present field; only the access cost is of interest. */
            (void)KswordARKHvmVmcsFieldLoad(
                KSW_VMCS_GUEST_RIP,
                &discard);
        }
    }
    /*
     * Another processor failed closed and asked everyone out.  Leave without
     * servicing this exit.
     *
     * Devirtualization only ever covers the current processor, and the IPI
     * rendezvous is unusable from a VM-exit handler, so this check is the only
     * way the request reaches the remaining processors on its own.  Without it
     * a fail-closed exit left the box half devirtualized - measured 2026-09-07
     * on 2 vCPU, where residentProcessorCount went 2 -> 1 and stayed.
     *
     * The gate is whether this exit's instruction, executed natively after
     * VMXOFF, means the same thing as servicing it here.  For every intercepted
     * exit it does: the instruction never executed, guest RIP still points at
     * it, and re-executing it on a machine with no hypervisor is exactly the
     * fail-open continuation the other fail-closed paths already rely on.  That
     * covers the VMX instruction exits we answer with an injected #UD too - a
     * native execution outside VMX operation raises the same #UD.
     *
     * VMCALL is the one exit where it does not.  It is the only instruction we
     * give a real meaning to (the private lifecycle contract, and the relay to
     * the L0 hypervisor), and natively it is #UD.  Leaving RIP on it and
     * dropping out of VMX turns the next native execution into a #UD - and when
     * the VMCALL came from the stop rendezvous, that #UD lands inside a
     * KeIpiGenericCall worker at IPI_LEVEL on a processor that just executed
     * VMXOFF.  Measured 2026-09-07 on 2 vCPU: Hyper-V event 18560, triple
     * fault, VM reset with no bugcheck and no dump.  So VMCALL falls through to
     * its own handler, which devirtualizes with the correct instruction length
     * and publishes the hypercall return value.  Nothing is lost by yielding:
     * the rendezvous is already walking every still-active processor, and a
     * relayed hypercall just re-enters the guest and meets this gate again at
     * its next exit.
     *
     * VMFUNC would need the same exemption for the same reason.  This version
     * never sees one - the EPTP-switching backend switches by VMWRITE from the
     * exit path and the guest issues no VMFUNC - so it is deliberately not
     * listed.  Anyone enabling a VMFUNC-based backend has to add it here.
     *
     * InstructionLength is 0 on purpose: this exit was never serviced, so the
     * intercepted instruction has to re-execute natively after VMXOFF.
     *
     * Faulted is FALSE on purpose: this processor is not the origin.  The
     * processor that failed already published FAULTED and ROLLBACK_REQUIRED,
     * and re-publishing here would make every follower look like a separate
     * fault in the telemetry.
     *
     * Read it, never consume it.  Every remaining processor has to see the same
     * request, and there is no way to know how many are still resident from
     * here.  An exchange would hand the request to whichever processor exited
     * first and hide it from the rest - correct by accident on two processors,
     * silently leaving two of four behind on a bigger box.  The flag stays up
     * until residency starts again, which is the one moment nobody is resident.
     *
     * No loop risk: a processor that takes this path leaves VMX and never
     * re-enters the dispatcher, and a failed devirtualization returns FATAL
     * rather than falling through.
     */
    if (basicReason != KSW_VMX_EXIT_VMCALL &&
        InterlockedCompareExchange(
            &Context->Runtime->ResidentFaultStopRequested,
            0L,
            0L) != 0L) {
        /* Leave VMX without advancing an unserviced instruction. */
        handled = KswordARKHvmResidentDeactivateCurrent(
            Context,
            0UL,
            FALSE);
        /* Return only a verified guest continuation. */
        return handled
            ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
            : KSW_HVM_EXIT_ACTION_FATAL;
    }
    /* Read address fields only for exits where Intel defines their content. */
    if (basicReason == KSW_VMX_EXIT_EPT_VIOLATION ||
        basicReason == KSW_VMX_EXIT_EPT_MISCONFIGURATION) {
        /* Capture EPT guest-physical and optional guest-linear evidence. */
        KswordARKHvmExitReadAddresses(
            &guestPhysicalAddress,
            &guestLinearAddress);
        /* Retain GLA only when EPT-violation qualification marks it valid. */
        if (basicReason != KSW_VMX_EXIT_EPT_VIOLATION ||
            (telemetry.Qualification & (1ULL << 7)) == 0ULL) {
            /* Clear architecturally unavailable guest-linear evidence. */
            guestLinearAddress = 0ULL;
        } else {
            /*
             * Record validity separately: a reported guest-linear address of
             * zero is legitimate, so the value alone cannot stand in for the
             * qualification bit that says the CPU supplied one.
             */
            guestLinearValid = TRUE;
        }
    }
    /* Emulate ordinary CPUID and continue the resident guest. */
    if (basicReason == KSW_VMX_EXIT_CPUID) {
        /* Execute CPUID under explicit nested-exposure policy. */
        handled = KswordARKHvmExitHandleCpuid(
            Context,
            Frame,
            telemetry.InstructionLength);
    /*
     * Dispatch KSword-private lifecycle VMCALLs.
     *
     * The privilege check is not decoration.  The signature is a plain
     * immediate in hvm_entry.asm and a plain constant in hvm_resident.h, the
     * processor performs no privilege check of its own before this exit, and
     * the STOP command below tears down residency - so without this gate any
     * user-mode instruction stream could devirtualize the processor with three
     * instructions.  Refusing at ring 3 costs nothing: the guest sees the same
     * #UD it would see on a machine with no hypervisor.
     *
     * All of the discrimination lives in RAX.  RCX contributes none: the
     * private subcommands 1, 2 and 3 collide exactly with the TLFS call codes
     * HvCallSwitchVirtualAddressSpace 0x0001, HvCallFlushVirtualAddressSpace
     * 0x0002 and HvCallFlushVirtualAddressList 0x0003, and the latter two are
     * the guest's own TLB flush and inter-processor interrupt hot paths.  RAX
     * carries the whole gate for two reasons, and both must be re-checked by
     * anyone who changes the constant.  First, RAX is not an input in the Hv#1
     * x64 hypercall contract at all - the control word is in RCX and the inputs
     * are in RDX, R8 and XMM0 through XMM5 - so no legitimate call sets it.
     * Second, the TLFS hypercall result value reserves bits 31:16 and 63:44 as
     * zero while this signature has bits set in both ranges, so no hypervisor's
     * legitimate return value can be left in RAX and be mistaken for it.
     */
    } else if (basicReason == KSW_VMX_EXIT_VMCALL &&
               Frame->Rax ==
                    KSW_HVM_HYPERCALL_SIGNATURE &&
               KswordARKHvmExitGuestCpl() ==
                    KSW_HVM_SUPERVISOR_CPL) {
        /* Complete a private stop by leaving VMX operation. */
        if (Frame->Rcx == KSW_HVM_HYPERCALL_STOP &&
            InterlockedCompareExchange(
                &Context->StopRequested,
                0L,
                1L) == 1L) {
            /* Publish successful private hypercall return value. */
            Frame->Rax = 0ULL;
            /* Devirtualize and continue after the exact VMCALL. */
            handled = KswordARKHvmResidentDeactivateCurrent(
                Context,
                telemetry.InstructionLength,
                FALSE);
            /* Publish the final VM-exit event before changing stacks. */
            KswordARKHvmExitPublishTelemetry(
                Context,
                &telemetry,
                guestPhysicalAddress,
                guestLinearAddress,
                KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE,
                0UL,
                0UL,
                handled
                    ? STATUS_SUCCESS
                    : STATUS_HV_OPERATION_FAILED);
            /* Return only a verified guest continuation. */
            return handled
                ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
                : KSW_HVM_EXIT_ACTION_FATAL;
        /* Execute one current-context INVEPT in VMX root. */
        } else if (Frame->Rcx ==
            KSW_HVM_HYPERCALL_INVEPT) {
            /* Require the exact active EPT pointer identity. */
            if (Frame->Rdx !=
                    Context->Runtime->EptPointer) {
                /* Publish a failed private hypercall result. */
                Frame->Rax = 1ULL;
            } else {
                /* Execute single-context INVEPT in VMX root. */
                Frame->Rax =
                    KswordARKHvmAsmInveptSingle(
                        Frame->Rdx);
            }
            /* Advance past the fully decoded private VMCALL. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        /* Return current resident state without mutation. */
        } else if (Frame->Rcx ==
            KSW_HVM_HYPERCALL_QUERY) {
            /* Return one for active resident state. */
            Frame->Rax = 1ULL;
            /* Advance past the fully decoded private VMCALL. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        } else {
            /*
             * Report an unknown private command through the return register
             * instead of tearing down residency, so a future protocol version
             * can probe this dispatcher without disabling the hypervisor.
             */
            Frame->Rax = MAXULONGLONG;
            /* Advance past the fully decoded private VMCALL. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Hand every other VMCALL to whatever hypervisor sits above us. */
    } else if (basicReason == KSW_VMX_EXIT_VMCALL) {
        /*
         * The resident guest IS the Windows that was running before residency
         * began, so its hypercalls belong to the hypervisor that was already
         * underneath it.  Answering them with #UD bugchecks the machine on the
         * first VMBus packet - measured as 0x1E / c000001d with
         * winhv!WinHvpFastHypercall on the stack, from storvsc writing a disk
         * block.  SDM 25.1.2 makes VMCALL exit unconditionally, so there is no
         * bitmap that could have let it through instead.
         *
         * Do not add an INVVPID here for the TLB flush hypercalls
         * (HvCallFlushVirtualAddressSpace 0x0002, List 0x0003, SpaceEx 0x0013,
         * ListEx 0x0014).  A third-party implementation does that because it
         * enables VPID; this one does not.  hvm_vmcs.c requests only EPT, the
         * optional #VE and VMFUNC bits, and requiredInstructionControls
         * (RDTSCP/INVPCID/XSAVES/USER_WAIT/PCONFIG) - never secondary bit 5 -
         * and VMCS field 0000H (VIRTUAL_PROCESSOR_ID) has no writer anywhere.
         * Two names mislead here and neither means "VPID is on":
         * KSW_HVM_VMX_ENABLE_VPID in hvm_runtime.c only decides whether reading
         * IA32_VMX_EPT_VPID_CAP is legal, and KSWORD_ARK_HVM_FEATURE_VPID
         * reports that the machine has the INVVPID instruction (CAP bit 32) for
         * one user interface label.
         *
         * With enable VPID clear every guest linear and combined mapping is
         * tagged VPID 0000H, and both VM exit and VM entry invalidate the
         * linear and combined mappings for VPID 0000H across all PCIDs and all
         * EPTRTA values.  SDM Vol 3C 31.4.3.1 in document 325462-092, numbered
         * 28.3.3.1 around revision 070; see docs/虚拟化规范要点.md:250.  The
         * direction is the opposite of what it looks like: an implementation
         * that enables VPID has to invalidate for itself, one that does not has
         * the hardware do it.  So the guest TLB is already empty on arrival
         * here and is emptied again on the way back, and this path touches
         * neither guest page tables nor EPT.
         *
         * Adding the instruction is not free either.  SDM 25.1.2, cited just
         * above for VMCALL, lists INVEPT and INVVPID as unconditional VM-exit
         * instructions in VMX non-root operation, and this VMX root is non-root
         * to the hypervisor beneath us - so the extra instruction buys another
         * round trip out of this partition on the hottest forwarding path.  Two
         * further reasons point the same way but were not confirmed against the
         * specification text here: VPID 0000H is reportedly the one tag INVVPID
         * cannot name, and INVVPID faults with #UD where VPID support is not
         * reported, which in VMX root is an immediate bugcheck.  This line has
         * already been burned once by a bare INVEPT.
         *
         * The one hazard that may be real is not on this processor but on the
         * remote ones, and this instruction would not address it: a sibling
         * logical processor running as our guest may hold stale translations
         * until its own next exit.  That window is bounded by the outer
         * hypervisor's own interrupt and scheduling tick, because it must
         * intercept external interrupts to schedule the virtual processor at
         * all - our own empty pin controls do not extend it.  What is genuinely
         * unknown is whether the outer flush also invalidates the nested guest
         * context, and that is unmeasured.  Its shape would be silent data
         * corruption with randomly signed bugchecks, needs two or more virtual
         * processors, and a soak that counts unexpected devirtualizations
         * cannot see it.  Measure it with a one-processor against
         * many-processor comparison before changing anything, and note that the
         * only fix that could address it - forcing every processor out before
         * returning the result - is the software rendezvous the third-party
         * implementation itself rejects as a watchdog deadlock.
         *
         * Forwarding is only meaningful when something is actually above us:
         * in root operation on a bare machine VMCALL merely VMfails, and the
         * guest would consume a fabricated result.  With no outer hypervisor
         * present the guest cannot have a hypercall page in the first place,
         * so the architectural #UD remains the correct answer there.
         *
         * Two gates, both mandatory.  Ring 3 never gets forwarded: the
         * processor performs no privilege check before this exit, so without
         * the CPL test a user-mode VMCALL would be laundered into a
         * supervisor-mode hypercall issued by us on the guest's behalf - an
         * escalation primitive the outer hypervisor would have refused itself.
         * And CPUID advertising a hypervisor is not proof that one answers
         * VMCALL, so an unserviced call falls back to the same #UD rather than
         * handing the guest its own pre-call RAX as a hypercall status.
         *
         * The interface check is the third gate and is not redundant with the
         * first.  HYPERVISOR_PRESENT is the generic CPUID.1:ECX[31] bit, while
         * the stub below hard-codes the Hv#1 register contract and overwrites
         * RAX with its unserviced sentinel.  Under an outer hypervisor whose
         * contract puts a live input in RAX, forwarding would corrupt the call
         * instead of relaying it, and residency is reachable on such a host.
         * Refusing there costs nothing: Windows builds its hypercall page only
         * after seeing the same Hv#1 signature, so a guest that does not
         * present it never issues the calls this gate turns away.
         */
        if ((Context->Runtime->FeatureFlags &
                KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
            Context->Runtime->HypervisorInterfaceIsHv1 &&
            KswordARKHvmExitGuestCpl() == KSW_HVM_SUPERVISOR_CPL) {
            /* Read the call code before forwarding overwrites the frame. */
            ULONGLONG callCode = Frame->Rcx & KSW_HV_CALL_CODE_MASK;

            /* Re-issue the exact call with the guest's own operands. */
            if (KswordARKHvmAsmForwardHypercall(
                    Frame,
                    Context->FxState) == 0UL) {
                /* Continue at the instruction following the forwarded call. */
                handled = KswordARKHvmExitAdvanceRip(
                    telemetry.InstructionLength);
                /*
                 * A remote flush L0 accepted still has not reached the siblings
                 * running as our guest, so finish what it could not: push every
                 * other resident processor through one VM entry, which is what
                 * actually drops their stale mappings.
                 *
                 * After forwarding, not instead of it - L1's own view of the
                 * flush is L0's to maintain, and the guest is entitled to the
                 * real hypercall result.
                 *
                 * Only when the forward was serviced and RIP advanced.  A
                 * refused call flushed nothing, so there is nothing to finish
                 * and the NMIs would be pure cost.
                 */
                if (handled &&
                    (callCode == KSW_HV_CALL_FLUSH_VA_SPACE ||
                     callCode == KSW_HV_CALL_FLUSH_VA_LIST ||
                     callCode == KSW_HV_CALL_FLUSH_VA_SPACE_EX ||
                     callCode == KSW_HV_CALL_FLUSH_VA_LIST_EX)) {
                    KswordARKHvmResidentRequestTlbNmi(Context);
                }
            } else {
                /*
                 * Nothing answered, so deliver the architectural fault.  Record
                 * it separately: this is the one path that can reproduce the
                 * 0x1E bugcheck the forwarding exists to prevent, and injecting
                 * the fault succeeds, so without its own status it would reach
                 * the event ring as an ordinary handled exit and be
                 * indistinguishable from a call that was relayed.
                 */
                hypercallRefused = TRUE;
                handled = KswordARKHvmExitInjectUndefinedOpcode();
            }
        } else {
            /*
             * Without a hypervisor VMCALL raises #UD, so unrelated software
             * that probes for one must see the same result.  Devirtualizing
             * here would let any user-mode instruction dismantle the resident
             * hypervisor.
             *
             * Record only the interface refusal, which is a policy decision
             * worth seeing.  A ring 3 VMCALL landing here is the ordinary
             * answer an anti-virtualization probe expects and is left
             * unrecorded so it cannot drown the signal.  The test below reads
             * cached capability state, never the VMCS.
             */
            if ((Context->Runtime->FeatureFlags &
                    KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
                !Context->Runtime->HypervisorInterfaceIsHv1) {
                hypercallRefused = TRUE;
            }
            handled = KswordARKHvmExitInjectUndefinedOpcode();
        }
    /*
     * A VMFUNC exit means the function failed - a successful EPTP switch does
     * not exit at all.  Guest code reached here by naming an entry outside the
     * list or one holding an invalid pointer, so the architectural answer is
     * the same one it would get on a processor without VM functions.
     *
     * Not advancing RIP is deliberate: #UD is a fault, and a fault restarts
     * the instruction it reports rather than skipping it.
     */
    } else if (basicReason == KSW_VMX_EXIT_VMFUNC) {
        /* Deliver the architectural undefined-opcode fault to the guest. */
        handled = KswordARKHvmExitInjectUndefinedOpcode();
    /* Complete the unconditional INVD exit without dropping modified lines. */
    } else if (basicReason == KSW_VMX_EXIT_INVD) {
        /* Write back and invalidate instead of discarding host cache lines. */
        handled = KswordARKHvmExitEmulateInvd();
        /* Advance only after the substituted instruction fully completed. */
        if (handled) {
            /* Continue at the instruction following INVD. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Apply one validated XSETBV or deliver its architectural fault. */
    } else if (basicReason == KSW_VMX_EXIT_XSETBV) {
        /* Validate every operand before touching XCR0 in VMX root. */
        handled = KswordARKHvmExitEmulateXsetbv(
            Frame,
            &injectFault);
        /* Advance only after the extended-state mask was actually applied. */
        if (handled) {
            /* Continue at the instruction following XSETBV. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        } else if (injectFault) {
            /* Restart the instruction after the guest takes #GP. */
            handled = KswordARKHvmExitInjectGeneralProtection();
        }
    /* Resolve MSR access the bitmap deliberately let exit. */
    } else if (basicReason == KSW_VMX_EXIT_RDMSR ||
               basicReason == KSW_VMX_EXIT_WRMSR) {
        const BOOLEAN isWrite =
            (BOOLEAN)(basicReason == KSW_VMX_EXIT_WRMSR);
        /*
         * An index inside the bitmap only exits because a policy opened a hole
         * for it, so the policy engine gets first refusal.  Anything it does
         * not claim fell outside the bitmap entirely.
         */
        const ULONG policyResult = KswordARKHvmMsrPolicyApply(
            Context->Runtime,
            Frame,
            isWrite);

        if (policyResult == KSW_HVM_MSR_POLICY_RESULT_HANDLED) {
            /* Continue at the instruction following the MSR access. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        } else if (policyResult ==
            KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT) {
            /* Restart the instruction after the guest takes #GP. */
            handled = KswordARKHvmExitInjectGeneralProtection();
        } else {
            /* Classify the index against the architectural bitmap coverage. */
            handled = KswordARKHvmExitEmulateMsr(
                Frame,
                isWrite,
                (BOOLEAN)((Context->Runtime->FeatureFlags &
                    KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL),
                &injectFault);
            /* Advance only after a complete emulation wrote every result. */
            if (handled) {
                /* Continue at the instruction following the MSR access. */
                handled = KswordARKHvmExitAdvanceRip(
                    telemetry.InstructionLength);
            } else if (injectFault) {
                /* Restart the instruction after the guest takes #GP. */
                handled = KswordARKHvmExitInjectGeneralProtection();
            }
        }
    /* Apply control-register policy to a masked bit or a tracked CR3 load. */
    } else if (basicReason == KSW_VMX_EXIT_MOV_CR) {
        /* Merge the write against the pinned bits, or replay a CR3 access. */
        handled = KswordARKHvmCrPolicyHandleControlRegister(
            Context->Runtime,
            Frame,
            telemetry.Qualification);
        /*
         * 地址空间换了，跟着换层次。
         *
         * R-1 进程处置的作用域完全靠这一步：命中的地址空间进入受限层次，其余
         * 一律回基座。放在这里而不是逐页判 CR3，是因为逐页那条路要求"拒绝一次
         * 再放行一次"的翻转，而翻转要 monitor-trap——嵌套靶机上没有那一位，
         * 那条路在那里根本跑不起来。
         *
         * 只在表非空时才碰 VMCS：表空时这一整段就是一次比较，而常驻期间每次
         * 地址空间切换都要走过它。
         */
        if (handled &&
            Context->Runtime->ProcessDispositionCount != 0UL) {
            SIZE_T guestCr3 = 0U;
            ULONGLONG targetEptp = 0ULL;

            if (KswordARKHvmVmcsFieldLoad(
                    KSW_VMCS_GUEST_CR3,
                    &guestCr3) == 0U) {
                if (!KswordARKHvmProcessSelectHierarchy(
                        Context->Runtime,
                        (ULONGLONG)guestCr3,
                        &targetEptp)) {
                    /*
                     * 回基座要用这个处理器**真正**装载的那一套：开了私有层次
                     * 时共享指针不是它在用的东西，写回去等于把这个核换到别人
                     * 的层次上。
                     */
                    targetEptp = (Context->EptLocal != NULL &&
                        Context->EptLocal->EptPointer != 0ULL)
                        ? Context->EptLocal->EptPointer
                        : Context->Runtime->EptPointer;
                }
                /* 算不出层次就不写：失败即维持现状，绝不切到零。 */
                if (targetEptp != 0ULL) {
                    handled = KswordARKHvmVmcsFieldStore(
                        KSW_VMCS_EPT_POINTER,
                        (SIZE_T)targetEptp) == 0U;
                }
            }
        }
        /* Advance only after the register state was completely written. */
        if (handled) {
            /* Continue at the instruction following the MOV. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Record and replay one intercepted debug-register access. */
    } else if (basicReason == KSW_VMX_EXIT_MOV_DR) {
        /* Observation only: the access is replayed unchanged. */
        handled = KswordARKHvmCrPolicyHandleDebugRegister(
            Context->Runtime,
            Frame,
            telemetry.Qualification);
        /* Advance only after the register state was completely written. */
        if (handled) {
            /* Continue at the instruction following the MOV. */
            handled = KswordARKHvmExitAdvanceRip(
                telemetry.InstructionLength);
        }
    /* Restore allow-once EPT permissions after one guest instruction. */
    } else if (basicReason ==
        KSW_VMX_EXIT_MONITOR_TRAP) {
        /* Restore and invalidate the exact restricted EPT entry. */
        handled = KswordARKHvmEptHandleMonitorTrap(
            Context->Runtime,
            &Context->EptTransient);
        /* Disable monitor-trap only after restoration is proven complete. */
        if (handled) {
            /* Return to ordinary execution controls after the one-shot step. */
            handled = KswordARKHvmExitSetMonitorTrap(
                FALSE);
        }
    /* Apply one bounded EPT violation rule. */
    } else if (basicReason ==
        KSW_VMX_EXIT_EPT_VIOLATION) {
        /* Decode attempted read, write, and execute access. */
        access = KswordARKHvmExitDecodeEptAccess(
            telemetry.Qualification);
        /*
         * R-1 进程处置排在视图与规则之前认领。
         *
         * 顺序不是偏好：处置的页只在它自己那套受限层次里没有执行位，而视图与
         * 规则装在基座上。同一个客户物理地址完全可能既被处置盯上、又被某条
         * 规则覆盖；这时先跑规则会把这次取指按规则的语义放行，处置就静默失效
         * 了——又是一次"装上了却什么都没发生"。
         *
         * 反过来不会伤到视图与规则：本模块只认取指违规，而且只认自己表里那一
         * 页，其余一律返回 None 落回原有路径。
         */
        {
            KSW_HVM_PROCESS_ACTION disposition =
                KswordARKHvmProcessHandleViolation(
                    Context->Runtime,
                    guestPhysicalAddress,
                    access);

            if (disposition != KswHvmProcessActionNone) {
                if (disposition == KswHvmProcessActionResume) {
                    /*
                     * 这一条已被解除，而本处理器还卡在受限层次里自旋。把指针换
                     * 回它**真正**该用的那一套并原地继续，什么都不注入。
                     *
                     * 这是解除对"已经冻住的那个核"唯一生效的地方：解除只改了
                     * 一个字段，正在自旋的核不会因此收到任何通知，它是在自己的
                     * 下一次违规上走到这里，把自己放出来的。
                     */
                    ULONGLONG baseEptp =
                        (Context->EptLocal != NULL &&
                            Context->EptLocal->EptPointer != 0ULL)
                        ? Context->EptLocal->EptPointer
                        : Context->Runtime->EptPointer;

                    handled = baseEptp != 0ULL &&
                        KswordARKHvmVmcsFieldStore(
                            KSW_VMCS_EPT_POINTER,
                            (SIZE_T)baseEptp) == 0U;
                } else if (disposition == KswHvmProcessActionTerminate) {
                    /*
                     * 硬件异常重启故障指令，所以 RIP 不动、指令长度为零。结束
                     * 靠的是客户机自己把这个未处理异常变成进程终止。
                     */
                    handled = KswordARKHvmExitInjectUndefinedOpcode();
                } else {
                    /*
                     * 同样重启故障指令——冻结要的正是"这条指令永远不退休"，
                     * 进程状态因此一个字节都没变，解除后从原地继续。
                     */
                    handled = KswordARKHvmExitInjectPageFault(
                        guestLinearAddress,
                        access);
                }
                /* 记事件并按注入结果收尾，不再往视图与规则走。 */
                KswordARKHvmExitPublishTelemetry(
                    Context,
                    &telemetry,
                    guestPhysicalAddress,
                    guestLinearAddress,
                    KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION,
                    access,
                    0UL,
                    handled
                        ? STATUS_SUCCESS
                        : STATUS_HV_OPERATION_FAILED);
                /* 完整地结束这一次退出派发。 */
                return handled
                    ? KSW_HVM_EXIT_ACTION_RESUME
                    : KSW_HVM_EXIT_ACTION_FATAL;
            }
        }
        /*
         * Views own their leaf exclusively, so a page covered by one never
         * reaches the rule backend.  A view match that could not be completed
         * returns its identity with a false result, which must fail closed
         * rather than fall through to a rule scan of the same page.
         */
        handled = KswordARKHvmEptViewHandleViolation(
            Context->Runtime,
            guestPhysicalAddress,
            access,
            Context->EptLocal,
            &Context->EptTransient,
            &ruleId,
            &viewSwitch);
        /*
         * Served by its own hierarchy: change the pointer, not the leaf.
         *
         * Handled before the monitor-trap branch below because arming the
         * trap here would be fatal in a way that leaves no evidence: on a
         * processor that does not offer the Monitor Trap Flag - the only kind
         * this backend exists for - the VMWRITE succeeds and the next VM
         * entry fails, so the machine silently drops out of VMX operation on
         * the first access to a viewed page.
         */
        if (handled && viewSwitch.Requested) {
            ULONG nextIndex = 0UL;
            ULONGLONG targetEptp = 0ULL;
            SIZE_T guestRip = 0U;
            NTSTATUS planStatus = STATUS_UNSUCCESSFUL;

            /* Refuse to plan against a RIP that could not be read. */
            if (KswordARKHvmVmcsFieldLoad(KSW_VMCS_GUEST_RIP, &guestRip) == 0U) {
                planStatus = KswordARKHvmEptSwitchPlanViolation(
                    Context->Runtime,
                    &Context->EptpSwitchProgress,
                    Context->ActiveEptpIndex,
                    viewSwitch.LeafSlot,
                    access,
                    viewSwitch.Kind,
                    (ULONGLONG)guestRip,
                    guestPhysicalAddress,
                    &nextIndex,
                    &targetEptp);
            }
            if (NT_SUCCESS(planStatus)) {
                /*
                 * Invalidate before the write, not after.  The descriptor has
                 * to name the hierarchy being left, and after the VMWRITE
                 * that value is no longer in the field to read back.
                 */
                (void)KswordARKHvmAsmInveptSingle(
                    Context->Runtime->EptSwitch.Eptp[Context->ActiveEptpIndex]);
                handled =
                    KswordARKHvmVmcsFieldStore(KSW_VMCS_EPT_POINTER, (SIZE_T)targetEptp) == 0U;
                if (handled) {
                    /*
                     * The ledger index is updated only after the field it
                     * describes actually changed.  Updating first and failing
                     * the write would leave this processor convinced it is on
                     * a hierarchy it is not on, and every later decision would
                     * be made from that - with no symptom until a leaf reads
                     * the wrong value.
                     */
                    Context->ActiveEptpIndex = nextIndex;
                }
            } else {
                /* Every refusal reason means fail closed, not switch anyway. */
                handled = FALSE;
            }
            /* Publish the complete exit evidence before resuming. */
            KswordARKHvmExitPublishTelemetry(
                Context,
                &telemetry,
                guestPhysicalAddress,
                guestLinearAddress,
                KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION,
                access,
                ruleId,
                handled ? STATUS_SUCCESS : planStatus);
            /*
             * 执行视图已经选好了，这时才轮到 R-1 注入决定要不要改 RIP。
             *
             * 顺序是硬的：RIP 指向的是影子页里的外壳，而影子只有在切到执行层次
             * 之后才是这一页的内容。反过来先改 RIP 再切，中间那一瞬客户机会从
             * 真页的同一个偏移取指——那里是原始字节，不是外壳。
             */
            if (handled) {
                SIZE_T injectCr3 = 0U;
                SIZE_T injectRip = 0U;
                ULONGLONG hijackRip = 0ULL;

                if (KswordARKHvmVmcsFieldLoad(
                        KSW_VMCS_GUEST_CR3, &injectCr3) == 0U &&
                    KswordARKHvmVmcsFieldLoad(
                        KSW_VMCS_GUEST_RIP, &injectRip) == 0U &&
                    KswordARKHvmInjectHijackRip(
                        Context->Runtime,
                        guestPhysicalAddress,
                        access,
                        (ULONGLONG)injectCr3,
                        (ULONGLONG)injectRip,
                        &hijackRip)) {
                    /*
                     * 写不进去就维持原 RIP 继续。载荷不跑是可以接受的结果，
                     * 把 RIP 改成一个半成品的值不是。
                     */
                    (void)KswordARKHvmVmcsFieldStore(
                        KSW_VMCS_GUEST_RIP, (SIZE_T)hijackRip);
                }
            }
            if (handled) {
                /* Resume on the newly selected hierarchy; no trap is armed. */
                return KSW_HVM_EXIT_ACTION_RESUME;
            }
            /* Take the shared fail-closed rollback. */
            handled = KswordARKHvmResidentDeactivateCurrent(
                Context,
                0UL,
                TRUE);
            /* Return only a verified guest continuation. */
            return handled
                ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
                : KSW_HVM_EXIT_ACTION_FATAL;
        }
        if (handled) {
            /* Restore the primary view value after one instruction. */
            handled = KswordARKHvmExitSetMonitorTrap(TRUE);
            /* Publish the complete exit evidence before resuming. */
            KswordARKHvmExitPublishTelemetry(
                Context,
                &telemetry,
                guestPhysicalAddress,
                guestLinearAddress,
                KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION,
                access,
                ruleId,
                handled
                    ? STATUS_SUCCESS
                    : STATUS_NOT_SUPPORTED);
            /* Resume only after the restoration step is actually armed. */
            if (handled) {
                /* Request VMRESUME with the flipped leaf in place. */
                return KSW_HVM_EXIT_ACTION_RESUME;
            }
            /* Fall through to the shared fail-closed rollback below. */
            handled = KswordARKHvmResidentDeactivateCurrent(
                Context,
                0UL,
                TRUE);
            /* Return only a verified guest continuation. */
            return handled
                ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
                : KSW_HVM_EXIT_ACTION_FATAL;
        }
        /* Resolve the violation against every rule covering this page. */
        handled = ruleId != 0UL
            ? FALSE
            : KswordARKHvmEptHandleViolation(
                Context->Runtime,
                guestPhysicalAddress,
                access,
                guestLinearValid,
                Context->EptLocal,
                &Context->EptTransient,
                &ruleId,
                &eptDisposition);
        /* Complete the disposition the rule aggregation selected. */
        if (handled) {
            if (eptDisposition ==
                KSW_HVM_EPT_DISPOSITION_INJECT_FAULT) {
                /*
                 * Durable denial: the guest takes a page fault at the address
                 * it touched and residency continues.  Nothing was granted,
                 * so no monitor-trap step is needed.
                 */
                handled = KswordARKHvmExitInjectPageFault(
                    guestLinearAddress,
                    access);
            } else {
                /* Arm one-instruction permission restoration. */
                handled = KswordARKHvmExitSetMonitorTrap(
                    TRUE);
            }
        }
    /* Dispatch bounded VMX instruction semantics without claiming L2 active. */
    } else if (KswordARKHvmExitIsNestedInstruction(
        basicReason)) {
        /* Execute the explicit partial vmcs12 state machine. */
        handled = KswordARKHvmNestedHandleExit(
            Context->Runtime,
            &Context->Nested,
            Frame,
            basicReason,
            telemetry.InstructionLength);
        /* Publish the latest nested state to the processor row. */
        Context->Resource->Row.nestedState =
            Context->Nested.State;
        /*
         * A refused VMX instruction must not cost us the hypervisor.  Falling
         * through to the fail-closed path would mean any guest that sets
         * CR4.VMXE and issues one VMX instruction tears the VMM down - and a
         * guest running WSL2 or a virtual machine does exactly that.
         *
         * #UD is also what the guest should architecturally receive: outside
         * nested dispatch its CPUID reports no VMX and its CR4.VMXE is clear,
         * so a VMX instruction is undefined by definition.
         */
        if (!handled) {
            /* Refuse the instruction without leaving VMX operation. */
            handled = KswordARKHvmExitInjectUndefinedOpcode();
        }
    /*
     * Resident mode does not request HLT exiting, but the hypervisor beneath
     * us reports the control as must-be-one, so the idle loop lands here.
     */
    } else if (basicReason == KSW_VMX_EXIT_HLT) {
        /* Retire the halt and let VM entry idle the processor. */
        handled = KswordARKHvmExitHandleHlt(
            Context,
            telemetry.InstructionLength);
    /*
     * The guest-idle MSR (KSW_HVM_MSR_GUEST_IDLE) was briefly intercepted here
     * and answered as a halt, on the theory that replaying its read in VMX root
     * would park this processor with interrupts masked and never wake it.  The
     * theory was never tested against the evidence already in hand: a
     * thirty-second soak had already run with that read forwarded to the
     * hypervisor beneath us, thirty-three thousand exits, zero unexpected
     * devirtualizations.  Whatever that read does there, it does not hang.
     * Intercepting it added a second way into the halt path for no measured
     * benefit, so it is deliberately absent - do not re-add it without a
     * reading that shows the forwarded read actually failing.
     */
    /*
     * Resident mode requests NMI exiting, so an NMI now stops here instead of
     * reaching the guest.  Hand it straight back.
     *
     * The control is not requested for the NMIs themselves - it is requested
     * because it is the only way to make a sibling processor leave VMX non-root
     * on demand, which is what a forwarded remote TLB flush needs (see the
     * KSW_VMX_PIN_NMI_EXITING comment in hvm_vmcs.c).  This handler is the toll
     * that control charges: having asked for the exits, we owe the guest every
     * NMI that was really meant for it.
     *
     * Two cases, told apart by the pending-flush ledger:
     *
     * Ours - raised before a broadcast that followed a forwarded remote TLB
     * flush.  Swallow it.  Swallowing *is* the point: the exit and the re-entry
     * are the work, because without VPID a VM entry invalidates the linear
     * mappings tagged VPID 0000H, which is exactly the stale state the
     * forwarded flush failed to clear on this processor.
     *
     * The guest's - Windows uses NMIs for its own watchdog and machine-check
     * paths and bugchecks on a lost one, so those go back untouched.
     *
     * The same ledger is consumed by the assembly stub for NMIs that land while
     * this processor is in VMX root, where no exit occurs at all.  Both halves
     * claim the same way and neither can claim a credit the other already took.
     *
     * Redelivery is safe here because we do not request virtual NMIs: the NMI
     * never reached the guest, so the processor set no NMI-blocking state that
     * a re-entry with this descriptor could violate.
     *
     * RIP is deliberately not advanced.  An NMI is not an instruction; the
     * guest has to resume at exactly the instruction it was about to run.
     */
    } else if (basicReason ==
                    KSW_VMX_EXIT_EXCEPTION_OR_NMI) {
        SIZE_T interruptionInfo = 0U;

        /* Redeliver only a descriptor the processor actually marked valid. */
        if (KswordARKHvmVmcsFieldLoad(
                KSW_VMCS_EXIT_INTERRUPTION_INFO,
                &interruptionInfo) == 0U &&
            ((ULONGLONG)interruptionInfo &
                KSW_VMX_INTERRUPTION_VALID) != 0ULL &&
            (((ULONGLONG)interruptionInfo >>
                KSW_VMX_INTERRUPTION_TYPE_SHIFT) &
                KSW_VMX_INTERRUPTION_TYPE_MASK) ==
                    KSW_VMX_INTERRUPTION_TYPE_NMI) {
            if (KswordARKHvmResidentClaimTlbNmi(Context->ApicId)) {
                /* Ours.  The re-entry below is the flush. */
                handled = TRUE;
            } else {
                /* The guest's own; deliver it when it can actually take one. */
                handled = KswordARKHvmExitDeliverGuestNmi(Context);
            }
        } else {
            /*
             * An exception, or an unreadable descriptor.  The exception bitmap
             * is constantly zero, so no exception should reach this dispatcher
             * at all - arriving here means an assumption broke, and guessing
             * at redelivery would be worse than leaving VMX.
             */
            handled = FALSE;
        }
    /*
     * The guest can take an NMI again, so hand over the one being held.
     *
     * This exit exists only because a held NMI asked for it, and the request
     * is cleared here unconditionally - including on the paths where there is
     * nothing to deliver.  Leaving the control set would exit continuously:
     * "the guest can accept an NMI" is its ordinary state, not an event.
     */
    } else if (basicReason == KSW_VMX_EXIT_NMI_WINDOW) {
        if (InterlockedExchange(
                &Context->PendingGuestNmi,
                0L) != 0L) {
            /* Deliver the NMI that was held while the guest blocked them. */
            handled = KswordARKHvmVmcsFieldStore(
                KSW_VMCS_ENTRY_INTERRUPTION_INFO,
                KSW_VMX_ENTRY_INTERRUPTION_NMI) == 0U;
        } else {
            /* Nothing held; the window was already stale when it opened. */
            handled = TRUE;
        }
        /* Stop asking, whether or not anything was delivered. */
        if (!KswordARKHvmExitSetNmiWindow(FALSE)) {
            handled = FALSE;
        }
        /* RIP is deliberately not advanced: no instruction caused this exit. */
    /* Fail closed for the mandatory exits that have no implementation yet. */
    } else if (basicReason ==
                    KSW_VMX_EXIT_EXTERNAL_INTERRUPT ||
               basicReason ==
                    KSW_VMX_EXIT_EPT_MISCONFIGURATION) {
        /* Fail closed into devirtualization for unimplemented mandatory exits. */
        handled = FALSE;
    } else {
        /* Unknown exits retain evidence and fail closed into devirtualization. */
        handled = FALSE;
    }
    /* Publish the complete exit evidence before resume or devirtualization. */
    KswordARKHvmExitPublishTelemetry(
        Context,
        &telemetry,
        guestPhysicalAddress,
        guestLinearAddress,
        basicReason == KSW_VMX_EXIT_EPT_VIOLATION
            ? KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION
            : (KswordARKHvmExitIsNestedInstruction(
                    basicReason)
                ? KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX
                : KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT),
        access,
        ruleId,
        hypercallRefused
            ? STATUS_HV_OPERATION_FAILED
            : (handled
                ? STATUS_SUCCESS
                : STATUS_NOT_SUPPORTED));
    /* Resume only exits whose complete semantics succeeded. */
    if (handled) {
        /* Request VMRESUME with the updated register frame and VMCS. */
        return KSW_HVM_EXIT_ACTION_RESUME;
    }
    /* Devirtualize unexpected or incomplete exits without advancing RIP. */
    handled = KswordARKHvmResidentDeactivateCurrent(
        Context,
        0UL,
        TRUE);
    /* Publish one explicit fatal-exit event after rollback preparation. */
    KswordARKHvmExitPublishTelemetry(
        Context,
        &telemetry,
        guestPhysicalAddress,
        guestLinearAddress,
        KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT,
        access,
        ruleId,
        handled
            ? STATUS_NOT_SUPPORTED
            : STATUS_HV_OPERATION_FAILED);
    /* Return only a verified guest continuation. */
    return handled
        ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
        : KSW_HVM_EXIT_ACTION_FATAL;
}

ULONG
KswordARKHvmResidentVmResumeFailure(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ UCHAR InstructionResult
    )
{
    BOOLEAN devirtualized = FALSE;

    /* Reject a missing processor context after VMRESUME failure. */
    if (Context == NULL ||
        Context->Runtime == NULL ||
        Context->Resource == NULL) {
        /* Request a bounded fatal trap with no unsafe continuation. */
        return KSW_HVM_EXIT_ACTION_FATAL;
    }
    /* Preserve the exact VMRESUME instruction result. */
    Context->Resource->Row.vmxInstructionResult =
        InstructionResult;
    /* Preserve the authoritative VMX operation failure. */
    Context->LastStatus =
        STATUS_HV_OPERATION_FAILED;
    /* Attempt devirtualization at the already advanced guest continuation. */
    devirtualized =
        KswordARKHvmResidentDeactivateCurrent(
            Context,
            0UL,
            TRUE);
    /* Return only a verified guest continuation. */
    return devirtualized
        ? KSW_HVM_EXIT_ACTION_DEVIRTUALIZE
        : KSW_HVM_EXIT_ACTION_FATAL;
}

#else

ULONG
KswordARKHvmResidentVmExitDispatch(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Frame);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Context);
    /* Request a bounded fatal path on unsupported architectures. */
    return KSW_HVM_EXIT_ACTION_FATAL;
}

ULONG
KswordARKHvmResidentVmResumeFailure(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ UCHAR InstructionResult
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Context);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(InstructionResult);
    /* Request a bounded fatal path on unsupported architectures. */
    return KSW_HVM_EXIT_ACTION_FATAL;
}

#endif
