#pragma once

#include <fltKernel.h>

#include "ark/ark_file_monitor.h"
#include "driver/KswordArkCallbackIoctl.h"

EXTERN_C_START

ULONG
KswordARKMinifilterMapMajorToOperation(
    _In_ UCHAR MajorFunction,
    _In_ UCHAR MinorFunction,
    _In_opt_ PFLT_PARAMETERS Parameters
    );

ULONG
KswordARKFileMonitorMapMajorToOperation(
    _In_ UCHAR MajorFunction,
    _In_ UCHAR MinorFunction,
    _In_opt_ PFLT_PARAMETERS Parameters
    );

FLT_PREOP_CALLBACK_STATUS
KswordArkMinifilterApplyRule(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG OperationType
    );

VOID
KswordArkMinifilterCallbackUpdateState(
    _In_opt_ PFLT_FILTER FilterHandle,
    _In_ NTSTATUS RegisterStatus,
    _In_ NTSTATUS StartStatus,
    _In_ BOOLEAN Started
    );

NTSTATUS
KswordARKRedirectTryRewriteFileCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ BOOLEAN* RedirectedOut
    );

// 确保共享 Minifilter 已执行一次 FltStartFiltering，不改变旧文件监控采集位。
NTSTATUS
KswordARKFileMonitorEnsureFilteringStarted(
    VOID
    );

EXTERN_C_END
