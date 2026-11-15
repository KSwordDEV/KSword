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

/*
 * Make every VMX capability MSR read exit, so it can be narrowed.
 *
 * Not a policy: it carries no table slot, cannot be removed, and is not
 * something a caller asked for.  It lives in this module only because the
 * bitmap's bits are owned here, and going through the same choke point is what
 * keeps the "does our half of the bitmap contribute anything" count exact.
 */
VOID
KswordARKHvmMsrArmVmxCapabilityInterceptLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/*
 * 锁 detection-surface MSR 为 read-exit, 配合 FilterDetectionMsr 关闭
 * CPUID.1 隐藏 VMX 后 FEATURE_CONTROL (0x3A) 还暴露 VMXON 使能位的洞。
 * 与 VMX cap 一样仅拦截读; 对这两个 MSR 的写路径架构上要么 #GP 要么是
 * Windows 启动期由 BIOS/UEFI 提早锁, 不构成我们的攻击面。
 */
VOID
KswordARKHvmMsrArmDetectionInterceptLocked(
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
