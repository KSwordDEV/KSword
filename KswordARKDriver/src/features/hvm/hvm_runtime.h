#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkHvmIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKHvmInitialize(
    VOID
    );

NTSTATUS
KswordARKHvmEnableResidentLifecycle(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
KswordARKHvmUninitialize(
    VOID
    );

NTSTATUS
KswordARKHvmQuery(
    _Out_ KSWORD_ARK_QUERY_HVM_RESPONSE* Response
    );

/*
 * 只读平台探针：读几个决定"退虚拟化能不能返回用户态"的寄存器。
 * 不进 VMX、不改任何状态、不分配、不加锁。每个字段自带 valid 位。
 */
NTSTATUS
KswordARKHvmPlatformProbe(
    _Out_ KSWORD_ARK_HVM_PLATFORM_RESPONSE* Response
    );

NTSTATUS
KswordARKHvmControl(
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request,
    _Out_ KSWORD_ARK_CONTROL_HVM_RESPONSE* Response
    );

NTSTATUS
KswordARKHvmEptRuleControl(
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* Response
    );

NTSTATUS
KswordARKHvmEventControl(
    _In_ const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* Response
    );

EXTERN_C_END
