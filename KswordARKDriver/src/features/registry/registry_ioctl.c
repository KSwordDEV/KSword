/*++

Module Name:

    registry_ioctl.c

Abstract:

    IOCTL handlers for KswordARK registry read operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

// 注册表 IOCTL 请求副本的非分页池标签，避免 METHOD_BUFFERED 输出覆写输入包。
#define KSWORD_ARK_REGISTRY_IOCTL_TAG 'iRsK'

static VOID
KswordARKRegistryIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    格式化并写入注册表 IOCTL 日志。中文说明：日志失败不影响主 IOCTL，
    因为读取结果已经通过结构化响应返回给 R3。

Arguments:

    Device - WDF 设备对象。
    LevelText - 日志级别。
    FormatText - printf 风格 ANSI 模板。
    ... - 模板参数。

Return Value:

    None. 本函数没有返回值。

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(
        logMessage,
        sizeof(logMessage),
        FormatText,
        arguments))) {
        (void)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

typedef NTSTATUS (*KSWORD_ARK_REGISTRY_OPERATION_BACKEND)(
    PVOID OutputBuffer,
    size_t OutputBufferLength,
    const VOID* Request,
    size_t* BytesWrittenOut);

NTSTATUS
KswordARKRegistryIoctlReadValue(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE。中文说明：handler 只负责
    WDF 缓冲校验，注册表读取由 registry_query.c 实现。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；必须包含固定请求。
    OutputBufferLength - 输出长度；必须容纳固定响应。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST* readRequest = NULL;
    KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST readRequestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry read ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    readRequest = (KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST*)inputBuffer;

    // METHOD_BUFFERED 的输入与输出可能指向同一 SystemBuffer。先复制完整请求，
    // 后续取得并初始化响应时不会破坏 version、keyPath、valueName 与读取长度参数。
    RtlCopyMemory(&readRequestCopy, readRequest, sizeof(readRequestCopy));
    readRequest = &readRequestCopy;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry read ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverReadRegistryValue(
        outputBuffer,
        actualOutputLength,
        readRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry read failed before response: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE)) {
        KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE* response =
            (KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE*)outputBuffer;
        KswordARKRegistryIoctlLog(
            Device,
            (response->status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS ||
             response->status == KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND) ? "Info" : "Warn",
            "R0 registry read response: status=%lu, type=%lu, data=%lu/%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->valueType,
            (unsigned long)response->dataBytes,
            (unsigned long)response->requiredBytes,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKRegistryIoctlEnumKey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST enumRequestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST), &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry enum ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    enumRequest = (KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST*)inputBuffer;

    // 枚举请求也必须在取得输出缓冲前复制。输出响应的 lastStatus 字段恰好会
    // 覆盖请求 keyPath 的起始位置，导致后端报告 STATUS_OBJECT_PATH_SYNTAX_BAD。
    RtlCopyMemory(&enumRequestCopy, enumRequest, sizeof(enumRequestCopy));
    enumRequest = &enumRequestCopy;

    if ((enumRequest->flags & ~(KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES)) != 0UL) {
        KswordARKRegistryIoctlLog(Device, "Warn", "R0 registry enum ioctl: flags rejected, flags=0x%08X.", (unsigned int)enumRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE), &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry enum ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumRegistryKey(outputBuffer, actualOutputLength, enumRequest, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry enum failed before response: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE)) {
        KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE* response = (KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE*)outputBuffer;
        KswordARKRegistryIoctlLog(
            Device,
            response->status == KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS ? "Info" : "Warn",
            "R0 registry enum response: status=%lu, subkeys=%lu/%lu, values=%lu/%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->returnedSubKeyCount,
            (unsigned long)response->subKeyCount,
            (unsigned long)response->returnedValueCount,
            (unsigned long)response->valueCount,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKRegistryIoctlOperation(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputStructureBytes,
    _In_ PCSTR OperationName,
    _In_ KSWORD_ARK_REGISTRY_OPERATION_BACKEND Backend,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID requestCopy = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (BytesReturned == NULL || Backend == NULL || InputStructureBytes == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Warn", "R0 registry %s denied: write access required, status=0x%08X.", OperationName, (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(Request, InputStructureBytes, &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry %s ioctl: input invalid, status=0x%08X.", OperationName, (unsigned int)status);
        return status;
    }

    // 写操作请求大小不一，使用非分页池副本统一规避 METHOD_BUFFERED 的输入输出
    // 共用 SystemBuffer 行为，避免后端清零 response 时毁坏 keyPath 或写入数据。
#pragma warning(push)
#pragma warning(disable:4996)
    requestCopy = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        InputStructureBytes,
        KSWORD_ARK_REGISTRY_IOCTL_TAG);
#pragma warning(pop)
    if (requestCopy == NULL) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry %s ioctl: request copy allocation failed.", OperationName);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(requestCopy, inputBuffer, InputStructureBytes);

    status = KswordARKRetrieveRequiredOutputBuffer(Request, sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE), &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        // 输出缓冲校验失败时也要释放已经分配的请求副本。
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_REGISTRY_IOCTL_TAG);
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry %s ioctl: output invalid, status=0x%08X.", OperationName, (unsigned int)status);
        return status;
    }

    status = Backend(outputBuffer, actualOutputLength, requestCopy, BytesReturned);
    // 后端已同步读取副本，请求生命周期到此结束。
    ExFreePoolWithTag(requestCopy, KSWORD_ARK_REGISTRY_IOCTL_TAG);
    if (!NT_SUCCESS(status)) {
        KswordARKRegistryIoctlLog(Device, "Error", "R0 registry %s failed before response: status=0x%08X.", OperationName, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = (KSWORD_ARK_REGISTRY_OPERATION_RESPONSE*)outputBuffer;
        KswordARKRegistryIoctlLog(
            Device,
            response->status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS ? "Info" : "Warn",
            "R0 registry %s response: status=%lu, last=0x%08X.",
            OperationName,
            (unsigned long)response->status,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS KswordARKRegistryIoctlSetValue(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return KswordARKRegistryIoctlOperation(Device, Request, sizeof(KSWORD_ARK_SET_REGISTRY_VALUE_REQUEST), "set-value", (KSWORD_ARK_REGISTRY_OPERATION_BACKEND)KswordARKDriverSetRegistryValue, BytesReturned);
}

NTSTATUS KswordARKRegistryIoctlDeleteValue(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return KswordARKRegistryIoctlOperation(Device, Request, sizeof(KSWORD_ARK_REGISTRY_VALUE_NAME_REQUEST), "delete-value", (KSWORD_ARK_REGISTRY_OPERATION_BACKEND)KswordARKDriverDeleteRegistryValue, BytesReturned);
}

NTSTATUS KswordARKRegistryIoctlCreateKey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return KswordARKRegistryIoctlOperation(Device, Request, sizeof(KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST), "create-key", (KSWORD_ARK_REGISTRY_OPERATION_BACKEND)KswordARKDriverCreateRegistryKey, BytesReturned);
}

NTSTATUS KswordARKRegistryIoctlDeleteKey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return KswordARKRegistryIoctlOperation(Device, Request, sizeof(KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST), "delete-key", (KSWORD_ARK_REGISTRY_OPERATION_BACKEND)KswordARKDriverDeleteRegistryKey, BytesReturned);
}

NTSTATUS KswordARKRegistryIoctlRenameValue(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return KswordARKRegistryIoctlOperation(Device, Request, sizeof(KSWORD_ARK_RENAME_REGISTRY_VALUE_REQUEST), "rename-value", (KSWORD_ARK_REGISTRY_OPERATION_BACKEND)KswordARKDriverRenameRegistryValue, BytesReturned);
}

NTSTATUS KswordARKRegistryIoctlRenameKey(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength, _Out_ size_t* BytesReturned)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    return KswordARKRegistryIoctlOperation(Device, Request, sizeof(KSWORD_ARK_RENAME_REGISTRY_KEY_REQUEST), "rename-key", (KSWORD_ARK_REGISTRY_OPERATION_BACKEND)KswordARKDriverRenameRegistryKey, BytesReturned);
}
