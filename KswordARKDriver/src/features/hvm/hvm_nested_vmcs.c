/*++

Module Name:

    hvm_nested_vmcs.c

Abstract:

    Implements bounded vmcs12 field storage and fail-closed vmcs02 validation.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_vmcs.h"

/* Name Intel VM-entry invalid-control-fields error seven. */
#define KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS 7UL

VOID
KswordARKHvmNestedVmcsInitialize(
    _Out_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    )
{
    /* Initialize a supplied vmcs12 state. */
    if (Vmcs12 != NULL) {
        /* Clear every bounded vmcs12 field and identity. */
        RtlZeroMemory(Vmcs12, sizeof(*Vmcs12));
    }
    /* Initialize a supplied vmcs02 merge state. */
    if (Vmcs02 != NULL) {
        /* Clear every merge and active-state marker. */
        RtlZeroMemory(Vmcs02, sizeof(*Vmcs02));
        /* Publish explicit partial implementation status. */
        Vmcs02->LastStatus = STATUS_NOT_IMPLEMENTED;
    }
}

/*
 * Decompose one VMCS field encoding.
 *
 * Returns FALSE for an encoding this model does not address, which is what
 * makes the architectural "unsupported component" answer honest rather than a
 * stand-in for running out of room.
 */
static BOOLEAN
KswordARKHvmNestedVmcs12Decompose(
    _In_ ULONG Encoding,
    _Out_ ULONG* Slot,
    _Out_ ULONG* Width,
    _Out_ BOOLEAN* HighHalf
    )
{
    const ULONG index = (Encoding >> 1) & 0x1FFUL;
    const ULONG type = (Encoding >> 10) & 0x3UL;
    const ULONG width = (Encoding >> 13) & 0x3UL;
    const BOOLEAN high = ((Encoding & 0x1UL) != 0UL);

    *Slot = 0UL;
    *Width = 0UL;
    *HighHalf = FALSE;
    /* Reject bits above the encoding Intel defines. */
    if ((Encoding & ~0x00007FFFUL) != 0UL) {
        /* Report an encoding outside the model. */
        return FALSE;
    }
    /* Reject an index this bounded model does not address. */
    if (index >= KSW_HVM_VMCS12_INDEX_COUNT) {
        /* Report an encoding outside the model. */
        return FALSE;
    }
    /*
     * The high half exists only for 64-bit fields.
     *
     * Width one is the 64-bit class; every other class is a single storage
     * unit, so an access-type bit set on one is a malformed encoding rather
     * than a request for its upper half.
     */
    if (high && width != 1UL) {
        /* Report an encoding outside the model. */
        return FALSE;
    }
    /* Width is part of the identity, not a hint - see the header. */
    *Slot =
        (width * KSW_HVM_VMCS12_TYPE_COUNT * KSW_HVM_VMCS12_INDEX_COUNT) +
        (type * KSW_HVM_VMCS12_INDEX_COUNT) +
        index;
    *Width = width;
    *HighHalf = high;
    /* Report a complete decomposition. */
    return TRUE;
}

/* Narrow one stored value to the width its encoding declares. */
static ULONGLONG
KswordARKHvmNestedVmcs12Narrow(
    _In_ ULONGLONG Value,
    _In_ ULONG Width
    )
{
    /* Select the sixteen-bit field class. */
    if (Width == 0UL) {
        /* Return only the bits a sixteen-bit field holds. */
        return Value & 0xFFFFULL;
    }
    /* Select the thirty-two-bit field class. */
    if (Width == 2UL) {
        /* Return only the bits a thirty-two-bit field holds. */
        return Value & 0xFFFFFFFFULL;
    }
    /* Return the full value for the 64-bit and natural-width classes. */
    return Value;
}

NTSTATUS
KswordARKHvmNestedVmcs12Write(
    _Inout_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _In_ ULONGLONG Value
    )
{
    ULONG slot = 0UL;
    ULONG width = 0UL;
    BOOLEAN high = FALSE;

    /* Require one current vmcs12 before touching its storage. */
    if (Vmcs12 == NULL || !Vmcs12->Current) {
        /* Return the exact nested-state contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Reject an encoding this model does not address. */
    if (!KswordARKHvmNestedVmcs12Decompose(
            Encoding,
            &slot,
            &width,
            &high)) {
        /* Return the exact unsupported-component failure. */
        return STATUS_NOT_FOUND;
    }
    if (high) {
        /* Replace only the upper half the access type names. */
        Vmcs12->Fields[slot] =
            (Vmcs12->Fields[slot] & 0xFFFFFFFFULL) |
            ((Value & 0xFFFFFFFFULL) << 32);
    } else {
        Vmcs12->Fields[slot] =
            KswordARKHvmNestedVmcs12Narrow(Value, width);
    }
    /* Complete the field write successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmNestedVmcs12Read(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _Out_ ULONGLONG* Value
    )
{
    ULONG slot = 0UL;
    ULONG width = 0UL;
    BOOLEAN high = FALSE;

    /* Require one current vmcs12 and a fixed output. */
    if (Vmcs12 == NULL || Value == NULL || !Vmcs12->Current) {
        /* Return the exact nested-state contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    *Value = 0ULL;
    /* Reject an encoding this model does not address. */
    if (!KswordARKHvmNestedVmcs12Decompose(
            Encoding,
            &slot,
            &width,
            &high)) {
        /* Return the exact unsupported-component failure. */
        return STATUS_NOT_FOUND;
    }
    /*
     * A field never written reads as zero rather than failing.
     *
     * That is the architectural shape: whether a component is supported is a
     * property of its encoding, not of whether anyone has written it yet.
     * Failing on an unwritten field would make VMREAD-before-VMWRITE - which
     * L1 is entitled to do - look like an unsupported component.
     */
    *Value = high
        ? ((Vmcs12->Fields[slot] >> 32) & 0xFFFFFFFFULL)
        : KswordARKHvmNestedVmcs12Narrow(Vmcs12->Fields[slot], width);
    /* Complete the field read successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmNestedVmcs02Prepare(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONGLONG ComposedEptPointer,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    )
{
    /* Validate fixed merge-state pointers. */
    if (Vmcs12 == NULL ||
        Vmcs02 == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Clear stale merge state before evaluating prerequisites. */
    RtlZeroMemory(Vmcs02, sizeof(*Vmcs02));
    /* Require one current vmcs12 before merge validation. */
    if (!Vmcs12->Current) {
        /* Publish the exact invalid nested state. */
        Vmcs02->LastStatus =
            STATUS_INVALID_DEVICE_STATE;
        /* Publish Intel invalid-control-fields evidence. */
        Vmcs02->InstructionError =
            KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
        /* Return the exact invalid nested state. */
        return Vmcs02->LastStatus;
    }
    /* Require a fully composed L1-on-L0 EPT pointer before L2 entry. */
    if (ComposedEptPointer == 0ULL) {
        /* Publish explicit partial shadow-EPT status. */
        Vmcs02->LastStatus = STATUS_NOT_IMPLEMENTED;
        /* Publish Intel invalid-control-fields evidence. */
        Vmcs02->InstructionError =
            KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
        /* Return without claiming vmcs02 readiness. */
        return Vmcs02->LastStatus;
    }
    /*
     * Control/guest merge and exit reflection remain deliberately incomplete.
     * Preserve the composed EPT identity but do not publish an active vmcs02.
     */
    Vmcs02->EptPointer = ComposedEptPointer;
    /* Publish explicit partial merge status. */
    Vmcs02->LastStatus = STATUS_NOT_IMPLEMENTED;
    /* Publish Intel invalid-control-fields evidence. */
    Vmcs02->InstructionError =
        KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
    /* Return without claiming L2 active state. */
    return Vmcs02->LastStatus;
}
