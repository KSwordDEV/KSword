/*++

Module Name:

    hvm_nested.c

Abstract:

    Implements a bounded vmcs12 state machine and explicit partial dispatch for
    VMX instructions.  L2 entry and shadow EPT are rejected with architectural
    VMfail semantics until their complete merge and invalidation paths exist.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested.h"
#include "hvm_exit.h"
/* VMCS access goes through the seam in hvm_vmcs.h, never the raw intrinsic. */
#include "hvm_vmcs.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the VMCS guest instruction pointer field. */
#define KSW_VMCS_GUEST_RIP 0x681EUL
/* Name the VMCS guest RFLAGS field. */
#define KSW_VMCS_GUEST_RFLAGS 0x6820UL

/* Name Intel VMX-instruction exit reasons handled by nested dispatch. */
#define KSW_VMX_EXIT_VMCLEAR   19UL
/* Name the Intel VMLAUNCH exit reason. */
#define KSW_VMX_EXIT_VMLAUNCH  20UL
/* Name the Intel VMPTRLD exit reason. */
#define KSW_VMX_EXIT_VMPTRLD   21UL
/* Name the Intel VMPTRST exit reason. */
#define KSW_VMX_EXIT_VMPTRST   22UL
/* Name the Intel VMREAD exit reason. */
#define KSW_VMX_EXIT_VMREAD    23UL
/* Name the Intel VMRESUME exit reason. */
#define KSW_VMX_EXIT_VMRESUME  24UL
/* Name the Intel VMWRITE exit reason. */
#define KSW_VMX_EXIT_VMWRITE   25UL
/* Name the Intel VMXOFF exit reason. */
#define KSW_VMX_EXIT_VMXOFF    26UL
/* Name the Intel VMXON exit reason. */
#define KSW_VMX_EXIT_VMXON     27UL
/* Name the Intel INVEPT exit reason. */
#define KSW_VMX_EXIT_INVEPT    50UL
/* Name the Intel INVVPID exit reason. */
#define KSW_VMX_EXIT_INVVPID   53UL

/* Identify carry and zero flags used by VMX instruction results. */
#define KSW_RFLAGS_CF (1ULL << 0)
/* Identify the zero flag used by VMfailValid. */
#define KSW_RFLAGS_ZF (1ULL << 6)

/* Name Intel VM-instruction error seven for incomplete L2 VM entry. */
#define KSW_VMX_ERROR_INVALID_CONTROL_FIELDS 7UL
/* Name Intel VM-instruction error five for resume before launch. */
#define KSW_VMX_ERROR_RESUME_NON_LAUNCHED_VMCS 5UL

/* Advance guest RIP after a fully decoded nested instruction. */
static BOOLEAN
KswordARKHvmNestedAdvanceRip(
    _In_ ULONG InstructionLength
    )
{
    SIZE_T guestRip = 0U;

    /* Reject a zero or architecturally oversized instruction length. */
    if (InstructionLength == 0UL ||
        InstructionLength > 15UL) {
        /* Report that the dispatcher cannot resume safely. */
        return FALSE;
    }
    /* Read the current guest instruction pointer. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_RIP,
            &guestRip) != 0U) {
        /* Report VMREAD failure to the caller. */
        return FALSE;
    }
    /* Advance to the instruction following the intercepted VMX operation. */
    guestRip += InstructionLength;
    /* Write the advanced guest instruction pointer. */
    return KswordARKHvmVmcsFieldStore(
        KSW_VMCS_GUEST_RIP,
        guestRip) == 0U;
}

/* Publish one VMX instruction result through guest CF and ZF. */
static BOOLEAN
KswordARKHvmNestedSetInstructionResult(
    _In_ UCHAR Result
    )
{
    SIZE_T guestRflags = 0U;

    /* Read the current guest RFLAGS field. */
    if (KswordARKHvmVmcsFieldLoad(
            KSW_VMCS_GUEST_RFLAGS,
            &guestRflags) != 0U) {
        /* Report VMREAD failure to the caller. */
        return FALSE;
    }
    /* Clear both VMX result flags before selecting the result. */
    guestRflags &=
        ~((SIZE_T)KSW_RFLAGS_CF |
          (SIZE_T)KSW_RFLAGS_ZF);
    /* Set carry for VMfailInvalid result two. */
    if (Result == 2U) {
        /* Publish VMfailInvalid through guest carry. */
        guestRflags |= (SIZE_T)KSW_RFLAGS_CF;
    /* Set zero for VMfailValid result one. */
    } else if (Result == 1U) {
        /* Publish VMfailValid through guest zero. */
        guestRflags |= (SIZE_T)KSW_RFLAGS_ZF;
    }
    /* Write the complete guest RFLAGS result. */
    return KswordARKHvmVmcsFieldStore(
        KSW_VMCS_GUEST_RFLAGS,
        guestRflags) == 0U;
}

VOID
KswordARKHvmNestedInitializeVcpu(
    _Out_ KSW_HVM_NESTED_VCPU* Nested,
    _In_ BOOLEAN Enabled,
    _In_ ULONGLONG L0EptPointer
    )
{
    /* Reject a missing per-processor state record. */
    if (Nested == NULL) {
        /* Return without publishing partial state. */
        return;
    }
    /* Initialize the complete bounded vmcs12 state. */
    RtlZeroMemory(Nested, sizeof(*Nested));
    /* Publish the caller-selected dispatch enable state. */
    Nested->Enabled = Enabled;
    /* Publish dispatch-ready only when explicitly enabled. */
    Nested->State = Enabled
        ? KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY
        : KSWORD_ARK_HVM_NESTED_STATE_DISABLED;
    /* Initialize bounded vmcs12 and explicit partial vmcs02 state. */
    KswordARKHvmNestedVmcsInitialize(
        &Nested->Vmcs12,
        &Nested->Vmcs02);
    /* Initialize shadow-EPT state from the exact L0 EPT pointer. */
    KswordARKHvmNestedEptInitialize(
        &Nested->ShadowEpt,
        L0EptPointer);
}

NTSTATUS
KswordARKHvmNestedValidate(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    /* Reject a missing runtime before evaluating nested capability. */
    if (Runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require VMX exposure before publishing instruction dispatch. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_VMX) == 0ULL) {
        /* Preserve explicit unsupported maturity. */
        Runtime->NestedImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
        /* Preserve explicit disabled nested state. */
        Runtime->NestedState =
            KSWORD_ARK_HVM_NESTED_STATE_DISABLED;
        /* Return the explicit processor capability boundary. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Publish bounded instruction-dispatch capability. */
    Runtime->FeatureFlags |=
        KSWORD_ARK_HVM_FEATURE_NESTED_VMX_DISPATCH |
        KSWORD_ARK_HVM_FEATURE_VMX_INSTRUCTION_EMULATION;
    /* Publish explicit partial maturity until vmcs02 and shadow EPT exist. */
    Runtime->NestedImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
    /* Publish dispatch-ready rather than active L2 state. */
    Runtime->NestedState =
        KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY;
    /* Publish protocol-visible partial state. */
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_NESTED_PARTIAL);
    /* Return not-implemented so validation cannot be mistaken for L2 support. */
    return STATUS_NOT_IMPLEMENTED;
}

BOOLEAN
KswordARKHvmNestedHandleExit(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_NESTED_VCPU* Nested,
    _Inout_ struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG ExitReason,
    _In_ ULONG InstructionLength
    )
{
    UCHAR instructionResult = 2U;
    ULONG instructionError = 0UL;

    /* Reject invalid fixed state or disabled nested dispatch. */
    if (Runtime == NULL ||
        Nested == NULL ||
        Frame == NULL ||
        !Nested->Enabled) {
        /* Report that the exit was not handled. */
        return FALSE;
    }
    /* Count every bounded nested instruction dispatch. */
    Nested->InstructionCount += 1ULL;
    /* VMXOFF has no memory operand and can complete from local state. */
    if (ExitReason == KSW_VMX_EXIT_VMXOFF) {
        /* Reject VMXOFF before a valid L1 VMXON state. */
        if (!Nested->Vmxon) {
            /* Select VMfailInvalid for an absent VMX operation. */
            instructionResult = 2U;
        } else {
            /* Leave the local L1 VMX operation. */
            Nested->Vmxon = FALSE;
            /* Clear the current vmcs12 pointer. */
            Nested->VmcsCurrent = FALSE;
            /* Clear any prior L2 launch attempt. */
            Nested->L2LaunchAttempted = FALSE;
            /* Publish dispatch-ready state after VMXOFF. */
            Nested->State =
                KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY;
            /* Select VMX instruction success. */
            instructionResult = 0U;
        }
    /* VMLAUNCH requires a complete vmcs02 merge that is not advertised. */
    } else if (ExitReason == KSW_VMX_EXIT_VMLAUNCH) {
        /* Report invalid current state before any vmcs12 pointer exists. */
        if (!Nested->Vmxon ||
            !Nested->VmcsCurrent) {
            /* Select VMfailInvalid for an absent current VMCS. */
            instructionResult = 2U;
        } else {
            NTSTATUS mergeStatus = STATUS_SUCCESS;

            /* Preserve that L1 attempted an L2 launch. */
            Nested->L2LaunchAttempted = TRUE;
            /*
             * Account the refusal on the runtime, not just on this VCPU.
             *
             * The per-VCPU flag above is cleared on the next VMXOFF along with
             * NestedState, so by the time anyone polls, both are gone.  This
             * counter is the only durable trace that some other hypervisor
             * asked to start a VM underneath us and was told no.
             */
            InterlockedIncrement(
                &Runtime->NestedL2LaunchRefusedCount);
            /* Validate vmcs12-to-vmcs02 merge prerequisites explicitly. */
            mergeStatus = KswordARKHvmNestedVmcs02Prepare(
                &Nested->Vmcs12,
                Nested->ShadowEpt.ComposedEptPointer,
                &Nested->Vmcs02);
            /* Publish explicit L2-partial state. */
            Nested->State =
                KSWORD_ARK_HVM_NESTED_STATE_L2_PARTIAL;
            /* Select VMfailValid for the deliberately incomplete merge. */
            instructionResult = 1U;
            /* Publish the exact invalid-control-fields failure class. */
            instructionError = NT_SUCCESS(mergeStatus)
                ? KSW_VMX_ERROR_INVALID_CONTROL_FIELDS
                : Nested->Vmcs02.InstructionError;
        }
    /* VMRESUME cannot succeed before a complete L2 launch. */
    } else if (ExitReason == KSW_VMX_EXIT_VMRESUME) {
        /* Select VMfailValid only when a current vmcs12 exists. */
        if (Nested->Vmxon &&
            Nested->VmcsCurrent) {
            /* Select VMfailValid for a non-launched vmcs12. */
            instructionResult = 1U;
            /* Publish the exact resume-before-launch failure class. */
            instructionError =
                KSW_VMX_ERROR_RESUME_NON_LAUNCHED_VMCS;
        } else {
            /* Select VMfailInvalid for an absent VMX/current-VMCS state. */
            instructionResult = 2U;
        }
    /* Operand-dependent VMX instructions remain explicit partial dispatch. */
    } else if (ExitReason == KSW_VMX_EXIT_VMXON ||
               ExitReason == KSW_VMX_EXIT_VMCLEAR ||
               ExitReason == KSW_VMX_EXIT_VMPTRLD ||
               ExitReason == KSW_VMX_EXIT_VMPTRST ||
               ExitReason == KSW_VMX_EXIT_VMREAD ||
               ExitReason == KSW_VMX_EXIT_VMWRITE ||
               ExitReason == KSW_VMX_EXIT_INVEPT ||
               ExitReason == KSW_VMX_EXIT_INVVPID) {
        /*
         * Instruction-information operand decoding is intentionally not
         * guessed.  Return VMfailInvalid until full guest-linear translation,
         * vmcs12 validation, vmcs02 merge, and shadow-EPT invalidation land.
         */
        instructionResult = 2U;
        /* Invalidate every partial shadow-EPT composition on L1 invalidation. */
        if (ExitReason == KSW_VMX_EXIT_INVEPT ||
            ExitReason == KSW_VMX_EXIT_INVVPID) {
            /* Advance shadow-EPT invalidation state without claiming active. */
            KswordARKHvmNestedEptInvalidate(
                &Nested->ShadowEpt);
        }
    } else {
        /* Report that this exit reason does not belong to nested dispatch. */
        return FALSE;
    }
    /* Preserve the last architectural VM-instruction error. */
    Nested->LastInstructionError = instructionError;
    /* Publish the current nested state to the runtime snapshot. */
    InterlockedExchange(
        (volatile LONG*)&Runtime->NestedState,
        (LONG)Nested->State);
    /* Publish VMX result flags before advancing guest RIP. */
    if (!KswordARKHvmNestedSetInstructionResult(
            instructionResult)) {
        /* Report a fatal VMCS write failure. */
        return FALSE;
    }
    /* Advance past the fully decoded VMX instruction. */
    return KswordARKHvmNestedAdvanceRip(
        InstructionLength);
}

#else

VOID
KswordARKHvmNestedInitializeVcpu(
    _Out_ KSW_HVM_NESTED_VCPU* Nested,
    _In_ BOOLEAN Enabled,
    _In_ ULONGLONG L0EptPointer
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Enabled);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(L0EptPointer);
    /* Clear a supplied state record before returning. */
    if (Nested != NULL) {
        /* Initialize the complete unsupported nested state. */
        RtlZeroMemory(Nested, sizeof(*Nested));
    }
}

NTSTATUS
KswordARKHvmNestedValidate(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

BOOLEAN
KswordARKHvmNestedHandleExit(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_NESTED_VCPU* Nested,
    _Inout_ struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG ExitReason,
    _In_ ULONG InstructionLength
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Nested);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Frame);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(ExitReason);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(InstructionLength);
    /* Report that no VMX instruction exit was handled. */
    return FALSE;
}

#endif
