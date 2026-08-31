/*++

Module Name:

    callback_monitor_ioctl.c

Abstract:

    WDF IOCTL adapters for the callback telemetry monitor.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

NTSTATUS
KswordARKCallbackMonitorIoctlControl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST* input = NULL;
    KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST requestSnapshot;
    KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* output = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // Device 只用于统一 handler 签名，业务状态归 callback runtime 所有。
    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    // METHOD_BUFFERED 输入输出共享系统缓冲，写响应前先保存请求。
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    requestSnapshot = *input;
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // 业务层验证版本、类别和 Minifilter 启动状态。
    status = KswordArkCallbackMonitorControl(&requestSnapshot, output);
    *BytesReturned = sizeof(*output);
    return status;
}

NTSTATUS
KswordARKCallbackMonitorIoctlQuery(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* output = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // Query 没有输入缓冲，也不依赖 WDFDEVICE。
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // 状态响应为固定尺寸，读取成功后完整返回。
    status = KswordArkCallbackMonitorQuery(output);
    if (NT_SUCCESS(status)) {
        *BytesReturned = sizeof(*output);
    }
    return status;
}

NTSTATUS
KswordARKCallbackMonitorIoctlRead(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST* input = NULL;
    KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST requestSnapshot;
    KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE* output = NULL;
    const size_t responseHeaderSize = FIELD_OFFSET(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records);
    NTSTATUS status = STATUS_SUCCESS;

    // Device 只用于统一 handler 签名，读取直接访问 callback runtime。
    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    // 保存游标后再取得共享的 METHOD_BUFFERED 输出区域。
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    requestSnapshot = *input;
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        responseHeaderSize,
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < responseHeaderSize) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // 高频轮询路径不写日志，避免自身形成事件和通知风暴。
    return KswordArkCallbackMonitorRead(
        &requestSnapshot,
        output,
        OutputBufferLength,
        BytesReturned);
}
