#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkFileMonitorIoctl.h"

EXTERN_C_START

// 中文说明：启用共享过滤引擎，不打开文件监控采集；重定向规则也必须启动引擎。
NTSTATUS KswordARKFileMonitorEnsureFilteringStarted(VOID);

NTSTATUS
KswordARKFileMonitorInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_opt_ WDFDEVICE Device
    );

VOID
KswordARKFileMonitorUninitialize(
    VOID
    );

NTSTATUS
KswordARKFileMonitorControl(
    _In_ const KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST* Request
    );

NTSTATUS
KswordARKFileMonitorQueryStatus(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKFileMonitorDrain(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

EXTERN_C_END
