/*++

Module Name:

    hvm_msr_policy.h

Abstract:

    Declares MSR policies: bitmap holes that turn selected MSR accesses back
    into VM exits so the dispatcher can log, deny, or fake them.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_exit.h"

/* The dispatcher completed the access; advance RIP and resume. */
#define KSW_HVM_MSR_POLICY_RESULT_HANDLED 0UL
/* No policy covers the index; the caller keeps its existing behavior. */
#define KSW_HVM_MSR_POLICY_RESULT_UNMATCHED 1UL
/* The access is refused; the caller injects #GP and resumes. */
#define KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT 2UL

EXTERN_C_START

/* Execute one versioned MSR policy operation, acquiring lifecycle ownership. */
NTSTATUS
KswordARKHvmMsrPolicyControl(
    _In_ const KSWORD_ARK_HVM_MSR_POLICY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* Response
    );

/* Close every bitmap hole and clear the table before resources are freed. */
VOID
KswordARKHvmMsrPolicyResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Apply the policy covering one intercepted MSR access, if any. */
ULONG
KswordARKHvmMsrPolicyApply(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_GPR_FRAME* Frame,
    _In_ BOOLEAN IsWrite
    );

EXTERN_C_END
