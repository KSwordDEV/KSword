/*++

Module Name:

    hvm_ept_view.h

Abstract:

    Declares EPT split views: one guest-physical page backed by two different
    frames depending on whether it is executed or read.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_ept.h"

EXTERN_C_START

/*
 * Execute one versioned EPT view operation, acquiring lifecycle ownership.
 * Mutating operations are refused while any processor is resident, because the
 * VM-exit path reads the view table without taking this PASSIVE_LEVEL lock.
 */
NTSTATUS
KswordARKHvmEptViewControl(
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* Response
    );

/* Execute one versioned EPT view operation under the runtime lock. */
NTSTATUS
KswordARKHvmEptViewControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* Response
    );

/* Restore every leaf and release every shadow before EPT pages are freed. */
VOID
KswordARKHvmEptViewResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/*
 * Flip one view's leaf to its secondary value for a single instruction.  The
 * caller arms monitor-trap so the primary value is restored afterwards, which
 * is the same mechanism allow-once rules use.
 */
BOOLEAN
KswordARKHvmEptViewHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* ViewId
    );

EXTERN_C_END
