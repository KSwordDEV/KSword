/*++

Module Name:

    hvm_exit.h

Abstract:

    Defines the resident VM-exit register frame and dispatcher contract.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Preserve guest GPRs in the exact order emitted by hvm_entry.asm. */
typedef struct _KSW_HVM_GPR_FRAME
{
    /* Preserve guest RAX. */
    ULONGLONG Rax;
    /* Preserve guest RCX. */
    ULONGLONG Rcx;
    /* Preserve guest RDX. */
    ULONGLONG Rdx;
    /* Preserve guest RBX. */
    ULONGLONG Rbx;
    /* Preserve guest RBP. */
    ULONGLONG Rbp;
    /* Preserve guest RSI. */
    ULONGLONG Rsi;
    /* Preserve guest RDI. */
    ULONGLONG Rdi;
    /* Preserve guest R8. */
    ULONGLONG R8;
    /* Preserve guest R9. */
    ULONGLONG R9;
    /* Preserve guest R10. */
    ULONGLONG R10;
    /* Preserve guest R11. */
    ULONGLONG R11;
    /* Preserve guest R12. */
    ULONGLONG R12;
    /* Preserve guest R13. */
    ULONGLONG R13;
    /* Preserve guest R14. */
    ULONGLONG R14;
    /* Preserve guest R15. */
    ULONGLONG R15;
} KSW_HVM_GPR_FRAME;

/*
 * KswordARKHvmAsmForwardHypercall indexes this frame with literal byte offsets
 * because it runs after the C dispatcher may have clobbered every scratch
 * register.  A field reordered here would silently hand the outer hypervisor
 * the wrong operands - a class of bug with no diagnostic surface at all, since
 * the forwarded call would simply return a wrong answer.  Lock the four
 * offsets the Hyper-V x64 hypercall ABI actually uses.
 */
C_ASSERT(FIELD_OFFSET(KSW_HVM_GPR_FRAME, Rax) == 0x00);
C_ASSERT(FIELD_OFFSET(KSW_HVM_GPR_FRAME, Rcx) == 0x08);
C_ASSERT(FIELD_OFFSET(KSW_HVM_GPR_FRAME, Rdx) == 0x10);
C_ASSERT(FIELD_OFFSET(KSW_HVM_GPR_FRAME, R8) == 0x38);
/* The assembly entry pushes exactly fifteen registers ahead of the context. */
C_ASSERT(sizeof(KSW_HVM_GPR_FRAME) == 15 * sizeof(ULONGLONG));

/* Forward-declare the per-processor resident context. */
struct _KSW_HVM_RESIDENT_VCPU;

/* Request VMRESUME after a fully handled exit. */
#define KSW_HVM_EXIT_ACTION_RESUME 0UL
/* Request devirtualization onto the captured guest continuation. */
#define KSW_HVM_EXIT_ACTION_DEVIRTUALIZE 1UL
/* Request a bounded fatal trap when no safe guest continuation exists. */
#define KSW_HVM_EXIT_ACTION_FATAL 2UL

EXTERN_C_START

/* Dispatch one resident VM exit without allocation or waiting. */
ULONG
KswordARKHvmResidentVmExitDispatch(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context
    );

/*
 * Re-issue one guest VMCALL from VMX root so the hypervisor above us answers
 * it.  Only legitimate while KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT is set.
 *
 * Returns zero when the call was answered and the frame now holds the result,
 * and one when nothing serviced it - in which case the frame is untouched and
 * the caller must not advance past the instruction.  CPUID advertising a
 * hypervisor is not proof that one answers VMCALL, and handing the guest back
 * its own pre-call RAX as a hypercall status would corrupt the VMBus paths
 * silently rather than stopping.
 */
ULONG
KswordARKHvmAsmForwardHypercall(
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _Inout_ PVOID FxState
    );

/* Convert VMRESUME failure into a bounded devirtualization continuation. */
ULONG
KswordARKHvmResidentVmResumeFailure(
    _Inout_ struct _KSW_HVM_RESIDENT_VCPU* Context,
    _In_ UCHAR InstructionResult
    );

EXTERN_C_END
