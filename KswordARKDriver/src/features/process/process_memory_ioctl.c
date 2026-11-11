/*++

Module Name:

    process_memory_ioctl.c

Abstract:

    IOCTL handlers for Phase-11 read-only process memory operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#define KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data)
#define KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data)
#define KSWORD_ARK_MEMORY_IOCTL_POOL_TAG 'iMsK'

static VOID
KswordARKMemoryIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    写入 Phase-11 内存 IOCTL 诊断日志。中文说明：这里只记录 PID、地址、
    状态和字节数，不记录读取到的数据，避免日志泄露目标进程内容。

Arguments:

    Device - WDF device that owns the log channel.
    LevelText - 日志等级文本。
    FormatText - printf 风格 ANSI 格式串。
    ... - 格式参数。

Return Value:

    None. 日志失败不影响 IOCTL 完成。

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
KswordARKMemoryIoctlQueryVirtualMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY。中文说明：handler 只负责
    WDF 缓冲获取、PID/flags/地址基础校验，真正的 ZwQueryVirtualMemory 查询
    由 process_memory.c 完成。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST* queryRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const ULONG allowedFlags = KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 query-vm ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出是同一个 SystemBuffer；后端清零输出后
     * 才读 processId/baseAddress，不做快照就会去枚举错误进程的错误区间。
     */
    queryRequest = (KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if ((queryRequest->flags & ~allowedFlags) != 0UL) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 query-vm ioctl: flags rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKValidateUserPid(queryRequest->processId);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 query-vm ioctl: pid rejected, pid=%lu.", (unsigned long)queryRequest->processId);
        return status;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 query-vm ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverQueryVirtualMemory(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 query-vm failed: pid=%lu, address=0x%I64X, status=0x%08X.", (unsigned long)queryRequest->processId, queryRequest->baseAddress, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE)) {
        KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE* response = (KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryIoctlLog(
            Device,
            "Info",
            "R0 query-vm success: pid=%lu, address=0x%I64X, status=%lu, fields=0x%08X.",
            (unsigned long)response->processId,
            response->requestedBaseAddress,
            (unsigned long)response->queryStatus,
            (unsigned int)response->fieldFlags);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlReadVirtualMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY。中文说明：第一版只读，不提供写、
    分配或改保护；读取失败以 response->readStatus/copyStatus 呈现给 R3。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST* readRequest = NULL;
    KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST readRequestValue;
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
        sizeof(KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 read-vm ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    readRequest = (KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST*)inputBuffer;
    RtlZeroMemory(&readRequestValue, sizeof(readRequestValue));
    RtlCopyMemory(&readRequestValue, readRequest, sizeof(readRequestValue));

    if ((readRequestValue.flags & ~(
        KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE |
        KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS)) != 0UL) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 read-vm ioctl: flags rejected, flags=0x%08X.", (unsigned int)readRequestValue.flags);
        return STATUS_INVALID_PARAMETER;
    }
    if ((readRequestValue.flags & KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS) == 0UL) {
        status = KswordARKValidateUserPid(readRequestValue.processId);
        if (!NT_SUCCESS(status)) {
            KswordARKMemoryIoctlLog(Device, "Warn", "R0 read-vm ioctl: pid rejected, pid=%lu.", (unsigned long)readRequestValue.processId);
            return status;
        }
    }
    if (readRequestValue.bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 read-vm ioctl: size rejected, pid=%lu, bytes=%lu.", (unsigned long)readRequestValue.processId, (unsigned long)readRequestValue.bytesToRead);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 read-vm ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverReadVirtualMemory(
        outputBuffer,
        actualOutputLength,
        &readRequestValue,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 read-vm failed: pid=%lu, address=0x%I64X, bytes=%lu, status=0x%08X.", (unsigned long)readRequestValue.processId, readRequestValue.baseAddress, (unsigned long)readRequestValue.bytesToRead, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE* response = (KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryIoctlLog(
            Device,
            "Info",
            "R0 read-vm success: pid=%lu, address=0x%I64X, status=%lu, requested=%lu, read=%lu.",
            (unsigned long)response->processId,
            response->requestedBaseAddress,
            (unsigned long)response->readStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesRead);
    }

    return STATUS_SUCCESS;
}

// 新入口用独立 IOCTL 承载创建时间，不能回退到旧 PID-only 读取。
NTSTATUS
KswordARKMemoryIoctlReadVirtualMemoryVerified(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED_REQUEST requestCopy; // 在 METHOD_BUFFERED 输出初始化前保留输入。
    PVOID inputBuffer = NULL; // WDF 输入视图。
    PVOID outputBuffer = NULL; // WDF 输出视图。
    size_t actualInputLength = 0U; // 实际输入长度。
    size_t actualOutputLength = 0U; // 实际输出长度。
    NTSTATUS status; // 保留各步原始状态。
    UNREFERENCED_PARAMETER(InputBufferLength); // 长度由 WDF 再次校验。
    UNREFERENCED_PARAMETER(OutputBufferLength); // 长度由 WDF 再次校验。
    if (BytesReturned == NULL) return STATUS_INVALID_PARAMETER; // 调用方必须提供响应长度。
    *BytesReturned = 0U; // 失败路径不得报告未初始化输出。
    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(requestCopy), &inputBuffer, &actualInputLength); // 检查完整身份请求。
    if (!NT_SUCCESS(status)) return status; // 输入不足时不执行读取。
    RtlCopyMemory(&requestCopy, inputBuffer, sizeof(requestCopy)); // 输入输出可能共享系统缓冲区。
    if (requestCopy.size != sizeof(requestCopy) || requestCopy.version != KSWORD_ARK_VERIFIED_MEMORY_READ_VERSION ||
        requestCopy.expectedCreationTime100ns == 0ULL || requestCopy.bytesToRead == 0UL ||
        requestCopy.bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES || requestCopy.reserved != 0UL ||
        (requestCopy.flags & ~KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE) != 0UL) return STATUS_INVALID_PARAMETER; // 不接受空身份、越界或内核地址模式。
    status = KswordARKValidateUserPid(requestCopy.processId); // 沿用原读取 PID 范围策略。
    if (!NT_SUCCESS(status)) return status; // 不向特权目标悄悄放宽限制。
    status = KswordARKRetrieveRequiredOutputBuffer(Request, KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength); // 获取有界输出。
    if (!NT_SUCCESS(status)) return status; // 输出不足时不读取目标。
    status = KswordARKDriverReadVirtualMemoryVerified(outputBuffer, actualOutputLength, &requestCopy, BytesReturned); // 同引用对象验证时间后复制。
    if (!NT_SUCCESS(status)) KswordARKMemoryIoctlLog(Device, "Error", "R0 verified read-vm failed: pid=%lu status=0x%08X.", (unsigned long)requestCopy.processId, (unsigned int)status); // 只记录错误元数据。
    return status; // 读取状态由响应头报告。
}

NTSTATUS
KswordARKMemoryIoctlWriteVirtualMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY。中文说明：该 handler 只接受
    R3 已确认的差异块写入请求，并在进入 feature 前完成访问权限、长度和策略检查。

Arguments:

    Device - WDF 设备对象，用于日志和 safety policy。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST* writeRequest = NULL;
    KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST* writeRequestCopy = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    const ULONG allowedFlags =
        KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED |
        KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE |
        KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS;
    BOOLEAN writeKernelAddress = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm ioctl denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 write-vm ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    writeRequest = (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*)inputBuffer;
    if ((writeRequest->flags & ~allowedFlags) != 0UL) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm ioctl: flags rejected, flags=0x%08X.", (unsigned int)writeRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    writeKernelAddress =
        ((writeRequest->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS) != 0UL) ? TRUE : FALSE;
    if (!writeKernelAddress) {
        status = KswordARKValidateUserPid(writeRequest->processId);
        if (!NT_SUCCESS(status)) {
            KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm ioctl: pid rejected, pid=%lu.", (unsigned long)writeRequest->processId);
            return status;
        }
    }
    if (writeRequest->bytesToWrite == 0UL ||
        writeRequest->bytesToWrite > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm ioctl: size rejected, pid=%lu, bytes=%lu.", (unsigned long)writeRequest->processId, (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }
    if ((SIZE_T)writeRequest->bytesToWrite >
        (MAXSIZE_T - KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE)) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm ioctl: size overflow rejected, bytes=%lu.", (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }
    requiredInputLength =
        KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE +
        (SIZE_T)writeRequest->bytesToWrite;
    if (actualInputLength < requiredInputLength) {
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm ioctl: input truncated, actual=%Iu, required=%Iu.", actualInputLength, requiredInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * METHOD_BUFFERED may alias the input and output system buffers.  Copy the
     * variable-length write request before retrieving/clearing the output
     * buffer, otherwise RtlZeroMemory(outputBuffer) can erase request->data.
     */
    writeRequestCopy = (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*)KswordARKAllocateNonPagedPool(
        requiredInputLength,
        KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
    if (writeRequestCopy == NULL) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 write-vm ioctl: input copy allocation failed, bytes=%Iu.", requiredInputLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(writeRequestCopy, writeRequest, requiredInputLength);
    writeRequest = writeRequestCopy;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 write-vm ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
        return status;
    }

    if ((writeRequest->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE) == 0UL) {
        KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        RtlZeroMemory(outputBuffer, actualOutputLength);
        response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->processId = writeKernelAddress ? 0UL : writeRequest->processId;
        response->fieldFlags =
            (writeKernelAddress
                ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
                : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE) |
            KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_REQUIRED;
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED;
        response->lookupStatus = STATUS_SUCCESS;
        response->copyStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->source = writeKernelAddress
            ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
            : KSWORD_ARK_MEMORY_SOURCE_R0_MM_WRITE_VIRTUAL_MEMORY;
        response->requestedBaseAddress = writeRequest->baseAddress;
        response->requestedBytes = writeRequest->bytesToWrite;
        response->maxBytesPerRequest = KSWORD_ARK_MEMORY_WRITE_MAX_BYTES;
        *BytesReturned = sizeof(*response);
        KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm requires force confirmation: pid=%lu, flags=0x%08X, address=0x%I64X, bytes=%lu.", (unsigned long)writeRequest->processId, (unsigned int)writeRequest->flags, writeRequest->baseAddress, (unsigned long)writeRequest->bytesToWrite);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
        return STATUS_SUCCESS;
    }

    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE;
        safetyContext.TargetProcessId = writeKernelAddress ? 0UL : writeRequest->processId;
        safetyContext.ContextFlags =
            ((writeRequest->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE) != 0UL) ?
            KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED :
            0UL;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKMemoryIoctlLog(Device, "Warn", "R0 write-vm denied by safety policy: pid=%lu, address=0x%I64X, bytes=%lu, status=0x%08X.", (unsigned long)writeRequest->processId, writeRequest->baseAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
            ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
            return status;
        }
    }

    status = KswordARKDriverWriteVirtualMemory(
        outputBuffer,
        actualOutputLength,
        writeRequest,
        actualInputLength,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryIoctlLog(Device, "Error", "R0 write-vm failed: pid=%lu, address=0x%I64X, bytes=%lu, status=0x%08X.", (unsigned long)writeRequest->processId, writeRequest->baseAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE)) {
        KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryIoctlLog(
            Device,
            "Info",
            "R0 write-vm success: pid=%lu, address=0x%I64X, status=%lu, requested=%lu, written=%lu.",
            (unsigned long)response->processId,
            response->requestedBaseAddress,
            (unsigned long)response->writeStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesWritten);
    }

    ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
    return STATUS_SUCCESS;
}
