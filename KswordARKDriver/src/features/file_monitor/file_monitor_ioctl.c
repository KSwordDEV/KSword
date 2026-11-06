/*++

Module Name:

    file_monitor_ioctl.c

Abstract:

    IOCTL handlers for Phase-12 file-system monitor runtime.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE) - sizeof(KSWORD_ARK_FILE_MONITOR_EVENT))

static VOID
KswordARKFileMonitorIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    输出文件监控 IOCTL 日志。中文说明：日志只记录控制状态和事件数量，不记录
    大量路径明细，避免高频事件造成日志通道拥塞。

Arguments:

    Device - WDF 设备对象。
    LevelText - 日志等级。
    FormatText - printf 风格格式串。
    ... - 格式参数。

Return Value:

    None.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (VOID)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
KswordARKFileMonitorIoctlControl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理文件监控 Start/Stop/Clear 控制。中文说明：Start 可传 operationMask 和
    processId；Stop 只停止采集，不注销 filter；Clear 清空 ring buffer。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度，未使用。
    BytesReturned - 接收写入字节数，控制 IOCTL 始终为 0。

Return Value:

    NTSTATUS from validation or runtime control.

--*/
{
    KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST* controlRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKFileMonitorIoctlLog(Device, "Error", "R0 file-monitor control: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    controlRequest = (KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST*)inputBuffer;
    if ((controlRequest->operationMask & ~KSWORD_ARK_FILE_MONITOR_OPERATION_ALL) != 0UL) {
        KswordARKFileMonitorIoctlLog(Device, "Warn", "R0 file-monitor control: operation mask rejected, mask=0x%08X.", (unsigned int)controlRequest->operationMask);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKFileMonitorControl(controlRequest);
    KswordARKFileMonitorIoctlLog(
        Device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 file-monitor control: action=%lu, mask=0x%08X, pid=%lu, status=0x%08X.",
        (unsigned long)controlRequest->action,
        (unsigned int)controlRequest->operationMask,
        (unsigned long)controlRequest->processId,
        (unsigned int)status);
    return status;
}

NTSTATUS
KswordARKFileMonitorIoctlDrain(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理文件监控事件 drain。中文说明：输入包可选；输出包按容量返回事件，取出
    即消费，R3 根据 droppedCount 显示丢包提示。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；小于请求包时使用默认。
    OutputBufferLength - 输出长度。
    BytesReturned - 接收响应字节数。

Return Value:

    NTSTATUS from buffer retrieval or drain backend.

--*/
{
    KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST* drainRequest = NULL;
    KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST defaultRequest = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKFileMonitorIoctlLog(Device, "Error", "R0 file-monitor drain: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    if (hasInput) {
        /* METHOD_BUFFERED shares input/output: preserve options before output is cleared. */
        RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
        drainRequest = &requestSnapshot;
    }
    else {
        drainRequest = &defaultRequest;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKFileMonitorIoctlLog(Device, "Error", "R0 file-monitor drain: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKFileMonitorDrain(
        outputBuffer,
        actualOutputLength,
        drainRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKFileMonitorIoctlLog(Device, "Error", "R0 file-monitor drain failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE* response = (KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE*)outputBuffer;
        KswordARKFileMonitorIoctlLog(
            Device,
            "Info",
            "R0 file-monitor drain: returned=%lu, queuedBefore=%lu, dropped=%lu.",
            (unsigned long)response->returnedCount,
            (unsigned long)response->totalQueuedBeforeDrain,
            (unsigned long)response->droppedCount);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKFileMonitorIoctlQueryStatus(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    查询文件监控运行时状态。中文说明：供 R3 显示 minifilter 是否注册/启动、
    ring buffer 队列深度和 dropped count。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 未使用。
    OutputBufferLength - 输出长度。
    BytesReturned - 接收响应长度。

Return Value:

    NTSTATUS from output retrieval or status backend.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKFileMonitorIoctlLog(Device, "Error", "R0 file-monitor status: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKFileMonitorQueryStatus(
        outputBuffer,
        actualOutputLength,
        BytesReturned);
    if (NT_SUCCESS(status) && *BytesReturned >= sizeof(KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE)) {
        KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE* response = (KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE*)outputBuffer;
        KswordARKFileMonitorIoctlLog(
            Device,
            "Info",
            "R0 file-monitor status: flags=0x%08X, queued=%lu, dropped=%lu.",
            (unsigned int)response->runtimeFlags,
            (unsigned long)response->queuedCount,
            (unsigned long)response->droppedCount);
    }

    return status;
}
