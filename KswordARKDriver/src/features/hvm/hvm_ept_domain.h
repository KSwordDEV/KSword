/*++

Module Name:

    hvm_ept_domain.h

Abstract:

    Declares EPT execution domains and the EPTP list that publishes them to
    VMFUNC.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Allocate the EPTP list and publish the default view as entry zero. */
NTSTATUS
KswordARKHvmEptDomainPrepareLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Fork one domain from the default view and publish it in the EPTP list. */
NTSTATUS
KswordARKHvmEptDomainCreateLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Out_ ULONG* DomainIndex
    );

/*
 * Remove permissions from one physical range inside one domain.
 *
 * Removal is the only direction this interface offers, and that is the whole
 * security argument for VMFUNC: because a domain can never grant more than the
 * default view, unprivileged guest code that switches into it cannot gain
 * anything it did not already have.  See the VMFUNC comment in the protocol
 * header for why that matters.
 */
NTSTATUS
KswordARKHvmEptDomainRestrictRangeLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG DomainIndex,
    _In_ ULONGLONG PhysicalAddress,
    _In_ ULONGLONG ByteCount,
    _In_ ULONG DeniedAccess
    );

/* Release every domain and the EPTP list without touching the default view. */
VOID
KswordARKHvmEptDomainResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Execute one versioned domain request under lifecycle ownership. */
NTSTATUS
KswordARKHvmEptDomainControl(
    _In_ const KSWORD_ARK_HVM_DOMAIN_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_DOMAIN_RESPONSE* Response
    );

EXTERN_C_END
