/*++

Module Name:

    hvm_nested_vmcs.h

Abstract:

    Defines bounded vmcs12 storage and explicit partial vmcs02 merge state.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/*
 * Address vmcs12 storage by field encoding instead of searching for it.
 *
 * Intel's encoding carries the index in bits 9:1 and the field type in bits
 * 11:10, so (type, index) forms a dense 2048-entry space that indexes a plain
 * array.  The previous sparse cache held 64 entries and searched them
 * linearly, which had two problems worth naming:
 *
 *   - A real vmcs12 has well over a hundred fields.  L1 would fill the cache
 *     part-way through configuring its VMCS and start receiving
 *     unsupported-component errors - and L1 does not treat those as fatal, so
 *     it would carry on to VMLAUNCH holding a control state we silently
 *     truncated.
 *   - "Cache full" is our limitation wearing an architectural error's name.
 *     With direct indexing the failure mode does not exist.
 *
 * Access type (bit 0) is deliberately not part of the key: it selects the high
 * half of a 64-bit field, which is the same storage.  Bits 14:13 (width) are
 * likewise derived from the encoding rather than stored.
 */
#define KSW_HVM_VMCS12_TYPE_COUNT 4UL
#define KSW_HVM_VMCS12_INDEX_COUNT 512UL
#define KSW_HVM_VMCS12_SLOT_COUNT \
    (KSW_HVM_VMCS12_TYPE_COUNT * KSW_HVM_VMCS12_INDEX_COUNT)

/* Preserve bounded vmcs12 identity, launch state, and fields. */
typedef struct _KSW_HVM_VMCS12_STATE
{
    /* Record whether one vmcs12 pointer is current. */
    BOOLEAN Current;
    /* Record whether the current vmcs12 has launched. */
    BOOLEAN Launched;
    /* Keep the structure explicitly initialized across architectures. */
    USHORT Reserved0;
    /* Preserve the last VM-instruction error visible to L1. */
    ULONG InstructionError;
    /* Preserve the current vmcs12 physical address. */
    ULONGLONG PhysicalAddress;
    /* Preserve every field L1 wrote, indexed by (type, index). */
    ULONGLONG Fields[KSW_HVM_VMCS12_SLOT_COUNT];
} KSW_HVM_VMCS12_STATE;

/* Preserve explicit vmcs02 merge maturity without claiming L2 active. */
typedef struct _KSW_HVM_VMCS02_STATE
{
    /* Record whether control merge validation completed. */
    BOOLEAN ControlsValidated;
    /* Record whether guest-state merge validation completed. */
    BOOLEAN GuestStateValidated;
    /* Record whether exit-reflection metadata is complete. */
    BOOLEAN ExitReflectionReady;
    /* Record whether a hardware vmcs02 is active. */
    BOOLEAN Active;
    /* Preserve the last merge status. */
    NTSTATUS LastStatus;
    /* Preserve the last Intel VM-instruction error. */
    ULONG InstructionError;
    /* Preserve the merged EPT pointer when available. */
    ULONGLONG EptPointer;
} KSW_HVM_VMCS02_STATE;

EXTERN_C_START

/* Initialize bounded vmcs12 and vmcs02 state. */
VOID
KswordARKHvmNestedVmcsInitialize(
    _Out_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    );

/* Cache one vmcs12 field without dynamic allocation. */
NTSTATUS
KswordARKHvmNestedVmcs12Write(
    _Inout_ KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _In_ ULONGLONG Value
    );

/* Read one cached vmcs12 field. */
NTSTATUS
KswordARKHvmNestedVmcs12Read(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONG Encoding,
    _Out_ ULONGLONG* Value
    );

/* Validate merge prerequisites while retaining explicit partial state. */
NTSTATUS
KswordARKHvmNestedVmcs02Prepare(
    _In_ const KSW_HVM_VMCS12_STATE* Vmcs12,
    _In_ ULONGLONG ComposedEptPointer,
    _Out_ KSW_HVM_VMCS02_STATE* Vmcs02
    );

EXTERN_C_END
