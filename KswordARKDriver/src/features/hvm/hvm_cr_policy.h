/*++

Module Name:

    hvm_cr_policy.h

Abstract:

    Declares control- and debug-register policy: pinned CR0/CR4 bits, optional
    address-space switch observation, and debug-register interception.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_exit.h"

EXTERN_C_START

/* Execute one versioned CR policy operation, acquiring lifecycle ownership. */
NTSTATUS
KswordARKHvmCrPolicyControl(
    _In_ const KSWORD_ARK_HVM_CR_POLICY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_CR_POLICY_RESPONSE* Response
    );

/* Clear the configured policy and its counters. */
VOID
KswordARKHvmCrPolicyResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/*
 * Complete one MOV-CR exit.  Returns TRUE when the guest may resume with RIP
 * advanced; FALSE leaves the caller on its fail-closed path.
 */
BOOLEAN
KswordARKHvmCrPolicyHandleControlRegister(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONGLONG Qualification
    );

/* Complete one MOV-DR exit by recording it and replaying the access. */
BOOLEAN
KswordARKHvmCrPolicyHandleDebugRegister(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ ULONGLONG Qualification
    );

EXTERN_C_END
