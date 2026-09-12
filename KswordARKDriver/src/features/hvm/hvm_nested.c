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
#include "hvm_nested_decode.h"
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

/*
 * Name the VMX instruction results the dispatchers return.
 *
 * These are the three architectural outcomes, not status codes: success sets
 * neither CF nor ZF, VMfailValid sets ZF and publishes an error number that L1
 * can VMREAD, and VMfailInvalid sets CF and carries no error number because
 * there is no current VMCS to record one in.
 */
#define KSW_HVM_VMX_RESULT_SUCCEED 0U
#define KSW_HVM_VMX_RESULT_FAIL_VALID 1U
#define KSW_HVM_VMX_RESULT_FAIL_INVALID 2U

/* Name the Intel VM-instruction errors this dispatch can report. */
#define KSW_VMX_ERROR_VMCLEAR_INVALID_ADDRESS 2UL
#define KSW_VMX_ERROR_VMCLEAR_VMXON_POINTER 3UL
#define KSW_VMX_ERROR_VMPTRLD_INVALID_ADDRESS 9UL
#define KSW_VMX_ERROR_VMPTRLD_VMXON_POINTER 10UL
#define KSW_VMX_ERROR_UNSUPPORTED_COMPONENT 12UL
#define KSW_VMX_ERROR_VMWRITE_READ_ONLY 13UL
#define KSW_VMX_ERROR_VMXON_IN_ROOT 15UL

/* Name the VMCS field-encoding type that marks a read-only component. */
#define KSW_VMCS_ENCODING_TYPE_READ_ONLY 1UL

/*
 * Check one VMX region pointer against the constraints the architecture fixes.
 *
 * Deliberately absent: the revision-identifier check.  Verifying it means
 * reading the first four bytes of the region, and the region is named by a
 * *physical* address while the only VM-exit-safe accessor we have takes a
 * linear one.  Being more permissive than the architecture is safe here
 * because we never read or write the region at all: L1's VMX state lives in
 * our own records, not in the pages it nominated.  Revisit once a
 * VM-exit-safe physical accessor exists - vmcs02 merge will need one too.
 */
static BOOLEAN
KswordARKHvmNestedIsRegionPointerValid(
    _In_ ULONGLONG Pointer
    )
{
    /* Reject the null pointer the architecture never accepts. */
    if (Pointer == 0ULL) {
        /* Report the pointer as unusable. */
        return FALSE;
    }
    /* Reject a region that is not page aligned. */
    if ((Pointer & 0xFFFULL) != 0ULL) {
        /* Report the pointer as unusable. */
        return FALSE;
    }
    /* Reject bits beyond the architectural physical-address maximum. */
    if ((Pointer & ~0x000FFFFFFFFFF000ULL) != 0ULL) {
        /* Report the pointer as unusable. */
        return FALSE;
    }
    /* Report the pointer as architecturally usable. */
    return TRUE;
}

/* Read the region pointer one memory-operand VMX instruction named. */
static BOOLEAN
KswordARKHvmNestedLoadRegionPointer(
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _Out_ ULONGLONG* Pointer
    )
{
    KSW_HVM_VMX_OPERAND operand = { 0 };

    *Pointer = 0ULL;
    /* Decode the memory operand under the memory-only layout. */
    if (!NT_SUCCESS(KswordARKHvmNestedDecodeOperand(
            Frame,
            KSW_HVM_VMX_OPERAND_LAYOUT_MEMORY_ONLY,
            &operand))) {
        /* Report that no pointer could be produced. */
        return FALSE;
    }
    /* Read the eight-byte pointer the operand addresses. */
    if (!NT_SUCCESS(KswordARKHvmNestedReadGuestQword(
            operand.LinearAddress,
            Pointer))) {
        /* Report that no pointer could be produced. */
        return FALSE;
    }
    /* Report a complete region pointer. */
    return TRUE;
}

/* Dispatch VMXON and establish emulated L1 VMX operation. */
static UCHAR
KswordARKHvmNestedDispatchVmxon(
    _Inout_ KSW_HVM_NESTED_VCPU* Nested,
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _Out_ ULONG* InstructionError
    )
{
    ULONGLONG region = 0ULL;

    *InstructionError = 0UL;
    /* Report the architectural error for VMXON inside VMX operation. */
    if (Nested->Vmxon) {
        *InstructionError = KSW_VMX_ERROR_VMXON_IN_ROOT;
        /* Return the valid failure L1 can read an error number from. */
        return KSW_HVM_VMX_RESULT_FAIL_VALID;
    }
    /* Refuse when the operand could not be produced at all. */
    if (!KswordARKHvmNestedLoadRegionPointer(Frame, &region)) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /* Refuse a region pointer the architecture does not accept. */
    if (!KswordARKHvmNestedIsRegionPointerValid(region)) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /* Record the region L1 nominated without ever reading it. */
    Nested->VmxonRegion = region;
    /* Enter emulated L1 VMX operation. */
    Nested->Vmxon = TRUE;
    /* Start with no current vmcs12, exactly as the architecture requires. */
    Nested->VmcsCurrent = FALSE;
    Nested->CurrentVmcs = 0ULL;
    /* Publish that L1 now holds VMX operation. */
    Nested->State = KSWORD_ARK_HVM_NESTED_STATE_L1_VMXON;
    /* Return the complete success. */
    return KSW_HVM_VMX_RESULT_SUCCEED;
}

/* Dispatch VMCLEAR, VMPTRLD and VMPTRST against the current vmcs12. */
static UCHAR
KswordARKHvmNestedDispatchVmcsPointer(
    _Inout_ KSW_HVM_NESTED_VCPU* Nested,
    _In_ const struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG ExitReason,
    _Out_ ULONG* InstructionError
    )
{
    KSW_HVM_VMX_OPERAND operand = { 0 };
    ULONGLONG pointer = 0ULL;

    *InstructionError = 0UL;
    /* Refuse every vmcs12 instruction outside L1 VMX operation. */
    if (!Nested->Vmxon) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /* Decode the memory operand under the memory-only layout. */
    if (!NT_SUCCESS(KswordARKHvmNestedDecodeOperand(
            Frame,
            KSW_HVM_VMX_OPERAND_LAYOUT_MEMORY_ONLY,
            &operand))) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /* VMPTRST writes the current pointer out and reads no pointer in. */
    if (ExitReason == KSW_VMX_EXIT_VMPTRST) {
        /* Publish the architectural empty value when none is current. */
        const ULONGLONG stored = Nested->VmcsCurrent
            ? Nested->CurrentVmcs
            : 0xFFFFFFFFFFFFFFFFULL;

        if (!NT_SUCCESS(KswordARKHvmNestedWriteGuestQword(
                operand.LinearAddress,
                stored))) {
            /* Return the invalid failure that carries no error number. */
            return KSW_HVM_VMX_RESULT_FAIL_INVALID;
        }
        /* Return the complete success. */
        return KSW_HVM_VMX_RESULT_SUCCEED;
    }
    /* Read the vmcs12 pointer the operand addresses. */
    if (!NT_SUCCESS(KswordARKHvmNestedReadGuestQword(
            operand.LinearAddress,
            &pointer))) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /* Refuse a pointer the architecture does not accept. */
    if (!KswordARKHvmNestedIsRegionPointerValid(pointer)) {
        *InstructionError = (ExitReason == KSW_VMX_EXIT_VMCLEAR)
            ? KSW_VMX_ERROR_VMCLEAR_INVALID_ADDRESS
            : KSW_VMX_ERROR_VMPTRLD_INVALID_ADDRESS;
        /* Return the valid failure L1 can read an error number from. */
        return KSW_HVM_VMX_RESULT_FAIL_VALID;
    }
    /* Refuse aiming a vmcs12 instruction at the VMXON region. */
    if (pointer == Nested->VmxonRegion) {
        *InstructionError = (ExitReason == KSW_VMX_EXIT_VMCLEAR)
            ? KSW_VMX_ERROR_VMCLEAR_VMXON_POINTER
            : KSW_VMX_ERROR_VMPTRLD_VMXON_POINTER;
        /* Return the valid failure L1 can read an error number from. */
        return KSW_HVM_VMX_RESULT_FAIL_VALID;
    }
    if (ExitReason == KSW_VMX_EXIT_VMCLEAR) {
        /* Clear the current pointer only when VMCLEAR names it. */
        if (Nested->VmcsCurrent && Nested->CurrentVmcs == pointer) {
            Nested->VmcsCurrent = FALSE;
            Nested->CurrentVmcs = 0ULL;
            /* Drop the cached fields along with the pointer that owned them. */
            KswordARKHvmNestedVmcsInitialize(
                &Nested->Vmcs12,
                &Nested->Vmcs02);
            /* Fall back to holding VMX operation with no current VMCS. */
            Nested->State = KSWORD_ARK_HVM_NESTED_STATE_L1_VMXON;
        }
        /* Return the complete success. */
        return KSW_HVM_VMX_RESULT_SUCCEED;
    }
    /*
     * VMPTRLD makes one vmcs12 current.
     *
     * Switching pointers must drop the field cache.  We model exactly one
     * vmcs12, so keeping the previous VMCS's fields across a VMPTRLD would let
     * them answer VMREADs issued against a different VMCS entirely - and L1
     * would get plausible values for fields it never wrote, which is the
     * failure mode that produces a working-looking L2 on stale control state.
     */
    if (!Nested->VmcsCurrent || Nested->CurrentVmcs != pointer) {
        KswordARKHvmNestedVmcsInitialize(
            &Nested->Vmcs12,
            &Nested->Vmcs02);
    }
    Nested->CurrentVmcs = pointer;
    Nested->VmcsCurrent = TRUE;
    Nested->Vmcs12.Current = TRUE;
    Nested->Vmcs12.PhysicalAddress = pointer;
    /* Publish that one vmcs12 is current. */
    Nested->State = KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT;
    /* Return the complete success. */
    return KSW_HVM_VMX_RESULT_SUCCEED;
}

/* Dispatch VMREAD and VMWRITE against the bounded vmcs12 field cache. */
static UCHAR
KswordARKHvmNestedDispatchVmcsField(
    _Inout_ KSW_HVM_NESTED_VCPU* Nested,
    _Inout_ struct _KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONG ExitReason,
    _Out_ ULONG* InstructionError
    )
{
    KSW_HVM_VMX_OPERAND operand = { 0 };
    ULONGLONG encoding = 0ULL;
    ULONGLONG value = 0ULL;

    *InstructionError = 0UL;
    /* Refuse every field access without a current vmcs12. */
    if (!Nested->Vmxon || !Nested->VmcsCurrent) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /* Decode under the layout that spends bits on both register operands. */
    if (!NT_SUCCESS(KswordARKHvmNestedDecodeOperand(
            Frame,
            KSW_HVM_VMX_OPERAND_LAYOUT_VMREAD_WRITE,
            &operand))) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /*
     * The field encoding is the second register operand for both instructions.
     *
     * VMREAD writes the field's value into the first operand and VMWRITE reads
     * the new value out of it, so the two are mirror images - but the register
     * naming the *field* is the same one in both, which is why one decode
     * serves both.
     */
    if (KswordARKHvmNestedReadGpr(
            Frame,
            operand.SecondaryRegister,
            &encoding) != 0U) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    if (ExitReason == KSW_VMX_EXIT_VMREAD) {
        /* Refuse a field this bounded cache never accepted. */
        if (!NT_SUCCESS(KswordARKHvmNestedVmcs12Read(
                &Nested->Vmcs12,
                (ULONG)encoding,
                &value))) {
            *InstructionError = KSW_VMX_ERROR_UNSUPPORTED_COMPONENT;
            /* Return the valid failure L1 can read an error number from. */
            return KSW_HVM_VMX_RESULT_FAIL_VALID;
        }
        /* Deliver the value to whichever destination form was decoded. */
        if (operand.IsRegister) {
            if (KswordARKHvmNestedWriteGpr(
                    Frame,
                    operand.PrimaryRegister,
                    value) != 0U) {
                /* Return the invalid failure that carries no error number. */
                return KSW_HVM_VMX_RESULT_FAIL_INVALID;
            }
        } else if (!NT_SUCCESS(KswordARKHvmNestedWriteGuestQword(
                operand.LinearAddress,
                value))) {
            /* Return the invalid failure that carries no error number. */
            return KSW_HVM_VMX_RESULT_FAIL_INVALID;
        }
        /* Return the complete success. */
        return KSW_HVM_VMX_RESULT_SUCCEED;
    }
    /* Refuse writing a component the architecture marks read-only. */
    if (((encoding >> 10) & 0x3ULL) == KSW_VMCS_ENCODING_TYPE_READ_ONLY) {
        *InstructionError = KSW_VMX_ERROR_VMWRITE_READ_ONLY;
        /* Return the valid failure L1 can read an error number from. */
        return KSW_HVM_VMX_RESULT_FAIL_VALID;
    }
    /* Collect the new value from whichever source form was decoded. */
    if (operand.IsRegister) {
        if (KswordARKHvmNestedReadGpr(
                Frame,
                operand.PrimaryRegister,
                &value) != 0U) {
            /* Return the invalid failure that carries no error number. */
            return KSW_HVM_VMX_RESULT_FAIL_INVALID;
        }
    } else if (!NT_SUCCESS(KswordARKHvmNestedReadGuestQword(
            operand.LinearAddress,
            &value))) {
        /* Return the invalid failure that carries no error number. */
        return KSW_HVM_VMX_RESULT_FAIL_INVALID;
    }
    /*
     * A full cache reports the architectural unsupported-component error.
     *
     * That is not a euphemism.  The cache bounds which components this vmcs12
     * actually supports, and telling L1 the component is unsupported is the
     * one answer it already knows how to act on - far better than succeeding
     * and silently discarding a control it will later rely on.
     */
    if (!NT_SUCCESS(KswordARKHvmNestedVmcs12Write(
            &Nested->Vmcs12,
            (ULONG)encoding,
            value))) {
        *InstructionError = KSW_VMX_ERROR_UNSUPPORTED_COMPONENT;
        /* Return the valid failure L1 can read an error number from. */
        return KSW_HVM_VMX_RESULT_FAIL_VALID;
    }
    /* Return the complete success. */
    return KSW_HVM_VMX_RESULT_SUCCEED;
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
    /* VMXON establishes L1 VMX operation from a decoded region pointer. */
    } else if (ExitReason == KSW_VMX_EXIT_VMXON) {
        instructionResult = KswordARKHvmNestedDispatchVmxon(
            Nested,
            Frame,
            &instructionError);
    /* The vmcs12 pointer instructions share one decoded memory operand. */
    } else if (ExitReason == KSW_VMX_EXIT_VMCLEAR ||
               ExitReason == KSW_VMX_EXIT_VMPTRLD ||
               ExitReason == KSW_VMX_EXIT_VMPTRST) {
        instructionResult = KswordARKHvmNestedDispatchVmcsPointer(
            Nested,
            Frame,
            ExitReason,
            &instructionError);
    /* VMREAD and VMWRITE address the bounded vmcs12 field cache. */
    } else if (ExitReason == KSW_VMX_EXIT_VMREAD ||
               ExitReason == KSW_VMX_EXIT_VMWRITE) {
        instructionResult = KswordARKHvmNestedDispatchVmcsField(
            Nested,
            Frame,
            ExitReason,
            &instructionError);
    /* Invalidation instructions remain explicit partial dispatch. */
    } else if (ExitReason == KSW_VMX_EXIT_INVEPT ||
               ExitReason == KSW_VMX_EXIT_INVVPID) {
        /*
         * Invalidation is refused until shadow-EPT composition exists.
         *
         * Succeeding here would be worse than refusing.  L1 issues INVEPT
         * precisely because it believes a mapping it installed is now stale;
         * reporting success while no composed hierarchy exists tells it the
         * flush happened, and the only visible consequence arrives later, as
         * L2 running on a mapping L1 already retired.
         */
        instructionResult = 2U;
        /* Advance shadow-EPT invalidation state without claiming active. */
        KswordARKHvmNestedEptInvalidate(
            &Nested->ShadowEpt);
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
