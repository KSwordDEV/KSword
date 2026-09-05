/*++

Module Name:

    hvm_ept.h

Abstract:

    Defines four-KiB EPT split, rule, and transient allow-once handling.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Preserve one temporary EPT permission grant until monitor-trap exit. */
typedef struct _KSW_HVM_EPT_TRANSIENT
{
    /* Record whether one permission restoration is pending. */
    BOOLEAN Armed;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Preserve the rule identifier that caused the temporary grant. */
    ULONG RuleId;
    /* Preserve the writable target EPT entry. */
    volatile ULONGLONG* Entry;
    /* Preserve the restricted value restored on monitor-trap exit. */
    ULONGLONG RestrictedValue;
} KSW_HVM_EPT_TRANSIENT;

/* The violation is unruled or unsafe to continue; leave EPT enforcement. */
#define KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE 0UL
/* One permission was granted for a single instruction; monitor-trap follows. */
#define KSW_HVM_EPT_DISPOSITION_ALLOW_ONCE 1UL
/* The access is denied durably; the dispatcher injects #PF and resumes. */
#define KSW_HVM_EPT_DISPOSITION_INJECT_FAULT 2UL

EXTERN_C_START

/* Build a continuous RAM-plus-MMIO identity window under the runtime lock. */
NTSTATUS
KswordARKHvmBuildEptLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Reset EPT rules and restore split leaves before table pages are freed. */
VOID
KswordARKHvmEptResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Execute one versioned EPT rule operation under the runtime lock. */
NTSTATUS
KswordARKHvmEptRuleControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* Response
    );

/*
 * Handle one EPT violation without allocating or waiting in VMX root.
 * GuestLinearAddressValid tells the aggregation whether a durable denial can
 * be expressed as an injected fault, since that requires a CR2 value.
 */
BOOLEAN
KswordARKHvmEptHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_ BOOLEAN GuestLinearAddressValid,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* RuleId,
    _Out_ ULONG* Disposition
    );

/* Restore and invalidate one armed allow-once permission set. */
BOOLEAN
KswordARKHvmEptRestoreTransient(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    );

/* Restore one allow-once permission set on monitor-trap exit. */
BOOLEAN
KswordARKHvmEptHandleMonitorTrap(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_EPT_TRANSIENT* Transient
    );

/* Execute single-context INVEPT for the current VMX root. */
UCHAR
KswordARKHvmAsmInveptSingle(
    _In_ ULONGLONG EptPointer
    );

EXTERN_C_END
