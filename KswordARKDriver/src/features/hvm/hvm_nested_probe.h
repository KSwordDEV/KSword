/*++

Module Name:

    hvm_nested_probe.h

Abstract:

    Declares the guest-context nested VMX self-test.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/*
 * Execute one VMX instruction sequence from guest context and report each
 * step's architectural result.
 *
 * PASSIVE_LEVEL.  Pins itself to one processor for the duration, because VMX
 * operation is per-processor state and a migration between VMXON and VMXOFF
 * would strand it.
 */
NTSTATUS
KswordARKHvmNestedProbeRun(
    _In_ const KSWORD_ARK_HVM_NESTED_PROBE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE* Response
    );

EXTERN_C_END
