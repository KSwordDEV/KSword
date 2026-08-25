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
    /* Preserve one allow-once EPT restoration. */
    KSW_HVM_EPT_TRANSIENT EptTransient;
    /* Preserve one bounded L1 nested-VMX state machine. */
    KSW_HVM_NESTED_VCPU Nested;
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

EXTERN_C_END
