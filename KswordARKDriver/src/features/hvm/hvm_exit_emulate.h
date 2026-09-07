/*++

Module Name:

    hvm_exit_emulate.h

Abstract:

    Declares root-mode emulation for the VM exits a resident guest cannot
    avoid, plus the architectural exception injection they depend on.

Environment:

    Kernel-mode Driver Framework, VMX root operation.

--*/

#pragma once

#include "hvm_exit.h"

EXTERN_C_START

/* Arm one hardware exception for the next VM entry without advancing RIP. */
BOOLEAN
KswordARKHvmExitInjectException(
    _In_ ULONG Vector,
    _In_ BOOLEAN DeliverErrorCode,
    _In_ ULONG ErrorCode
    );

/* Arm #UD for an instruction this hypervisor deliberately refuses. */
BOOLEAN
KswordARKHvmExitInjectUndefinedOpcode(
    VOID
    );

/* Arm #GP with a zero error code for an architecturally invalid operand. */
BOOLEAN
KswordARKHvmExitInjectGeneralProtection(
    VOID
    );

/*
 * Arm #PF for a durably denied EPT access.  CR2 is not part of the VMCS, so
 * the faulting address is published straight into the shared register.
 */
BOOLEAN
KswordARKHvmExitInjectPageFault(
    _In_ ULONGLONG GuestLinearAddress,
    _In_ ULONG Access
    );

/* Complete an unconditional INVD exit without discarding modified lines. */
BOOLEAN
KswordARKHvmExitEmulateInvd(
    VOID
    );

/* Validate and apply one guest XSETBV, or request the architectural fault. */
BOOLEAN
KswordARKHvmExitEmulateXsetbv(
    _In_ const KSW_HVM_GPR_FRAME* Frame,
    _Out_ BOOLEAN* InjectFault
    );

/*
 * Resolve one MSR exit that fell outside the architectural bitmap ranges.
 * HypervisorPresent enables forwarding the reserved 0x40000000-0x4FFFFFFF
 * window to the hypervisor beneath us; every other index still faults.
 */
BOOLEAN
KswordARKHvmExitEmulateMsr(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN HypervisorPresent,
    _Out_ BOOLEAN* InjectFault
    );

EXTERN_C_END
