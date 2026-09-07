/*++

Module Name:

    hvm_resident.h

Abstract:

    Defines the all-processor resident VMX lifecycle and rendezvous state.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_ept.h"
#include "hvm_nested.h"

/*
 * 前进性台账的类型来自共享算术头。这里必须用**真的**那个结构而不是镜像一份：
 * 镜像会让「切换是否在前进」有两个真值来源，而它判错的表现是整机静默死锁 ——
 * 没有蓝屏、没有事件、没有日志，每一次退出单独看都完全正常。
 */
#include "driver/KswordArkHvmEptSwitch.h"

/* Identify a KSword-private VMCALL emitted by the resident lifecycle. */
#define KSW_HVM_HYPERCALL_SIGNATURE 0x4B53574F52444856ULL
/* Request devirtualization from the current resident processor. */
#define KSW_HVM_HYPERCALL_STOP 1ULL
/* Request current-context EPT invalidation in VMX root. */
#define KSW_HVM_HYPERCALL_INVEPT 2ULL
/* Query the resident dispatcher without changing lifecycle state. */
#define KSW_HVM_HYPERCALL_QUERY 3ULL
/* Preserve x87, MMX, MXCSR, and XMM0-XMM15 across VM-exit C dispatch. */
#define KSW_HVM_FX_STATE_BYTES 512UL

/* Own one processor's resident VMX continuation and nonblocking exit state. */
typedef struct _KSW_HVM_RESIDENT_VCPU
{
    /* Preserve the assembly wrapper stack pointer at offset zero. */
    ULONGLONG LaunchStackPointer;
    /* Preserve the guest RFLAGS captured immediately before VM entry. */
    ULONGLONG LaunchRflags;
    /* Reference the process-wide HVM runtime. */
    KSW_HVM_RUNTIME* Runtime;
    /* Reference the processor-owned VMX resource pair. */
    KSW_HVM_CPU_RESOURCE* Resource;
    /* Own the base of the allocated VM-exit stack. */
    PVOID HostStack;
    /* Preserve the VMCS host RSP and context anchor. */
    ULONGLONG HostStackPointer;
    /* Preserve the exact pre-VMX CR4 value. */
    ULONGLONG OriginalCr4;
    /* Preserve the guest stack used by devirtualization. */
    ULONGLONG DevirtualizeRsp;
    /* Preserve the guest instruction pointer used by devirtualization. */
    ULONGLONG DevirtualizeRip;
    /* Preserve guest RFLAGS used by devirtualization. */
    ULONGLONG DevirtualizeRflags;
    /* Preserve the guest supervisor CET control state across VMXOFF. */
    ULONGLONG GuestSCet;
    /* Preserve the exact guest shadow-stack continuation. */
    ULONGLONG GuestSsp;
    /* Preserve the guest interrupt shadow-stack table address. */
    ULONGLONG GuestInterruptSspTable;
    /* Preserve the guest protection-key rights state. */
    ULONGLONG GuestPkrs;
    /* Preserve the guest user-interrupt notification vector. */
    ULONGLONG GuestUinv;
    /* Preserve the guest architectural debug-control state. */
    ULONGLONG GuestDebugControl;
    /* Preserve the guest hardware-breakpoint enable state. */
    ULONGLONG GuestDr7;
    /* Record whether VM-exit loads host CET state. */
    UCHAR CetStateManaged;
    /* Record whether VM-exit loads host PKRS state. */
    UCHAR PkrsStateManaged;
    /* Record whether VM-exit clears UINV state. */
    UCHAR UinvStateManaged;
    /* Record whether VM-exit saves guest debug state. */
    UCHAR DebugStateManaged;
    /* Keep the following FXSAVE64 area explicitly aligned. */
    ULONG ExtendedStateReserved;
    /*
     * Keep the architectural FXSAVE64 area 16-byte aligned.  HVM C sources
     * are compiled without AVX code generation, so legacy SSE instructions
     * cannot destroy the guest's YMM/ZMM upper halves that FXSAVE omits.
     */
    DECLSPEC_ALIGN(16) UCHAR FxState[KSW_HVM_FX_STATE_BYTES];
    /* Publish whether the processor currently runs in VMX non-root mode. */
    volatile LONG Active;
    /* Publish whether the processor still owns VMX root state. */
    volatile LONG VmxRoot;
    /* Publish whether an explicit stop VMCALL was requested. */
    volatile LONG StopRequested;
    /* Preserve the processor index in the runtime resource array. */
    ULONG ProcessorIndex;
    /* Preserve the last authoritative per-processor NTSTATUS. */
    NTSTATUS LastStatus;
    /* Preserve the last VM-instruction error. */
    ULONG LastVmInstructionError;
    /*
     * Reference this processor's private EPT hierarchy, or NULL when the
     * feature is off.  Placed here rather than appended at the end so it
     * shares the cache line already carrying Active and the transient: the
     * exit path reads it on every EPT violation, and the whole cost of the
     * feature being off is that this load returns NULL.
     */
    KSW_HVM_EPT_LOCAL* EptLocal;
    /* Preserve one allow-once EPT restoration. */
    KSW_HVM_EPT_TRANSIENT EptTransient;
    /* Preserve one bounded L1 nested-VMX state machine. */
    KSW_HVM_NESTED_VCPU Nested;
    /*
     * Address space the guest was running on, captured while the VMCS is still
     * current and reloaded immediately after VMXOFF.
     *
     * This used to be unnecessary by accident: HOST_CR3 and GUEST_CR3 were both
     * written from the same __readcr3(), so leaving the host value loaded after
     * VMXOFF happened to leave the guest on its own page tables.  Once HOST_CR3
     * became the System address space - which it must be, so residency can
     * outlive the process that requested it - the two diverge, and the thread
     * resumes on an address space whose kernel half is right and whose user
     * half belongs to somebody else.  The machine survives, so nothing reports
     * an error; the requesting process simply stops producing output.
     *
     * Placed at the end deliberately: the assembly entry addresses this
     * structure by literal offsets and hvm_resident.c asserts every one of
     * them, so no field may be inserted ahead of FxState or Active.
     */
    ULONGLONG GuestCr3;
    /*
     * Which EPT hierarchy this processor is currently running on, as an index
     * into the EPTP-switching backend's table: 0 is the base (every leaf at
     * its primary value, identical to today's steady state) and index k means
     * leaf k-1, and only leaf k-1, is relaxed.
     *
     * "Is any leaf relaxed" is therefore exactly "is this index non-zero" -
     * there is deliberately no second boolean to keep in step with it.
     *
     * Zero whenever EptpSwitchArmed is FALSE, and the MTF backend never reads
     * it, so an unarmed runtime behaves exactly as before.
     */
    ULONG ActiveEptpIndex;
    /*
     * Forward-progress ledger for the EPTP-switching backend.
     *
     * A switch that does not retire an instruction is legal once - the guest
     * re-executes the faulting instruction under the new hierarchy - but a
     * cycle of switches that keeps returning to the same index is a livelock,
     * and it presents as a whole-machine hang with no bugcheck, no event and
     * no log: every individual exit looks completely normal.  This counter is
     * what lets the exit path notice that and fail closed instead.
     *
     * Appended at the end for the same reason as GuestCr3: the assembly entry
     * addresses this structure by literal offsets and hvm_resident.c asserts
     * every one of them, so no field may be inserted ahead of FxState or
     * Active.
     */
    KSWORD_ARK_HVM_EPTSW_PROGRESS EptpSwitchProgress;
    /*
     * This processor's initial APIC id (CPUID.1:EBX[31:24]), captured at
     * launch.
     *
     * It is the index into the pending-flush-NMI ledger, and it is recorded
     * here so the send path can address a *remote* processor's slot - CPUID
     * only ever answers for the processor executing it.  The receiving halves
     * read their own id directly, so this field is written once and only ever
     * read by senders.
     *
     * Appended at the end for the same reason as the fields above it: the
     * assembly entry addresses this structure by literal offsets.
     */
    ULONG ApicId;
    /*
     * Set while an NMI belonging to the guest is being held because the guest
     * was blocking NMIs when it arrived.
     *
     * Injection through the VM-entry interruption field ignores the guest's
     * interruptibility state, so handing an NMI back during the guest's own
     * NMI handler would nest one inside another.  This flag, plus NMI-window
     * exiting, turns "deliver now" into "deliver as soon as it is legal".
     *
     * One bit is enough: the architecture already collapses multiple pending
     * NMIs into a single one, so a second arrival while one is held needs no
     * additional storage.
     *
     * Appended at the end for the same reason as the fields above it.
     */
    volatile LONG PendingGuestNmi;
} KSW_HVM_RESIDENT_VCPU;

EXTERN_C_START

/* Enter VMX non-root operation on every prepared processor. */
NTSTATUS
KswordARKHvmResidentStart(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Flags
    );

/* Leave VMX operation on every resident processor and release host stacks. */
NTSTATUS
KswordARKHvmResidentStop(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Invalidate one EPT context on every resident processor. */
NTSTATUS
KswordARKHvmResidentInvalidateEpt(
    _In_ ULONGLONG EptPointer
    );

/* Configure the resident VMCS after assembly captures exact guest RSP/RFLAGS. */
NTSTATUS
KswordARKHvmConfigureResidentVmcsFromAsm(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    );

/* Commit the exact assembly-captured resident SSP to the current VMCS. */
NTSTATUS
KswordARKHvmWriteResidentGuestSspFromAsm(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    );

/*
 * Ask every other resident processor to pass through one VM entry, so the
 * linear mappings a forwarded remote TLB flush just revoked are actually
 * dropped there.
 *
 * Callable from the VM-exit path.  Not a rendezvous and does not wait: it
 * raises each target's slot in the pending ledger and broadcasts one NMI with
 * the all-excluding-self shorthand, then returns.  Waiting is what turns this
 * into a watchdog deadlock - a remote that needs *this* processor to service
 * something would never answer.  Not waiting leaves a window the width of NMI
 * delivery instead of an unbounded one.
 *
 * Does nothing unless the private host IDT was installed: without it an NMI
 * that lands while a target is in VMX root goes to the guest's vector 2 and
 * Windows bugchecks 0x80.  Also does nothing when the local APIC is not in
 * x2APIC mode - xAPIC would need a mapped MMIO page this version does not
 * carry.  Either way the violation count `hvm_ctl tlb-probe` reports is what
 * says whether that mattered on a given machine.
 */
VOID
KswordARKHvmResidentRequestTlbNmi(
    _In_ KSW_HVM_RESIDENT_VCPU* Self
    );

/* Claim one pending flush NMI for a processor, by its recorded APIC id. */
BOOLEAN
KswordARKHvmResidentClaimTlbNmi(
    _In_ ULONG ApicId
    );

/*
 * Set how many throwaway VMREADs each exit performs while the measurement flag
 * is armed.  Zero selects the default; anything past the bound is clamped.
 *
 * Call before arming, so the exit path never sees an armed benchmark whose
 * depth has not been decided.
 */
VOID
KswordARKHvmSetVmreadBenchIterations(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG Requested
    );

/* Devirtualize one current processor from the VM-exit path. */
BOOLEAN
KswordARKHvmResidentDeactivateCurrent(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context,
    _In_ ULONG InstructionLength,
    _In_ BOOLEAN Faulted
    );

/* Return the current processor's resident context when it exists. */
KSW_HVM_RESIDENT_VCPU*
KswordARKHvmResidentFindCurrent(
    VOID
    );

/* Attempt VMLAUNCH after capturing the exact wrapper continuation. */
UCHAR
KswordARKHvmAsmLaunchResident(
    _Inout_ KSW_HVM_RESIDENT_VCPU* Context
    );

/* Issue one KSword-private resident VMCALL. */
ULONGLONG
KswordARKHvmAsmResidentHypercall(
    _In_ ULONGLONG Command,
    _In_ ULONGLONG Argument
    );

/* Resume the launch worker as an ordinary VMX non-root guest. */
VOID
KswordARKHvmResidentGuestResume(
    VOID
    );

/* Receive every resident VM exit on the processor-owned host stack. */
VOID
KswordARKHvmResidentVmExitEntry(
    VOID
    );

/*
 * Vector 2 of the private VMX-root IDT.
 *
 * Never called from C - its address is written into a gate descriptor, and it
 * runs on an interrupt frame the processor pushed, so it has no C-callable
 * signature and no return.  Declared only so the descriptor can name it.
 */
VOID
KswordARKHvmAsmHostNmiStub(
    VOID
    );

EXTERN_C_END
