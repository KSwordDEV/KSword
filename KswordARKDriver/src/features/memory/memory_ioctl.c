/*++

Module Name:

    memory_ioctl.c

Abstract:

    IOCTL handlers for physical memory and page-table inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_memory_evidence.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <ntimage.h>
#include <stdarg.h>

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID PcValue,
    _Outptr_ PVOID* BaseOfImage
    );

// 物理写入请求带尾随 data[]，栈快照放不下，改用池副本；tag 与其它 IOCTL 副本一致。
#define KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG 'pMsK'

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

// 物理读取响应头不包含尾随 data[1]，handler 只要求 R3 至少提供头部空间。
#define KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE) - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)0)->data))

// 物理写入请求头不包含尾随 data[1]，handler 用它计算完整输入长度。
#define KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST) - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)0)->data))

// 内核 executable page 扫描响应头不包含尾随 entries[1]。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY))

// 内核 executable scan v1 请求前缀，允许旧 R3 只传 flags/maxEntries/start/end。
#define KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE \
    FIELD_OFFSET(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST, maxBytes)

// 内核 memory evidence 扫描响应头不包含尾随 rows[1]。
#define KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW))

static VOID
KswordARKMemoryToolIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    写入物理内存/PTE 工具 IOCTL 诊断日志。中文说明：日志只记录地址、长度、
    状态和 PID，不记录物理内存内容，避免把敏感字节写入环形日志。

Arguments:

    Device - WDF 设备对象，用于投递日志。
    LevelText - 日志等级文本。
    FormatText - printf 风格 ANSI 格式串。
    ... - 格式参数。

Return Value:

    None. 日志失败不影响 IOCTL 请求完成。

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
KswordARKMemoryIoctlReadPhysicalMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY。中文说明：handler 负责 WDF
    缓冲获取、flags/长度初筛和读访问校验，实际 MmCopyMemory 读取在 backend。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or KswordARKDriverReadPhysicalMemory.

--*/
{
    KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST* readRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST requestSnapshot;
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
        sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST),
        (PVOID*)&readRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 read-physical ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出是同一个 SystemBuffer；后端会先
     * RtlZeroMemory 输出再读 physicalAddress/bytesToRead，不做快照就会
     * 拿响应头字节当物理地址和长度去 MmCopyMemory。
     */
    RtlCopyMemory(&requestSnapshot, readRequest, sizeof(requestSnapshot));
    readRequest = &requestSnapshot;

    if (readRequest->flags != 0UL ||
        readRequest->reserved != 0UL ||
        readRequest->reserved2 != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 read-physical ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)readRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (readRequest->bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 read-physical ioctl: size rejected, pa=0x%I64X, bytes=%lu.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 read-physical ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverReadPhysicalMemory(
        outputBuffer,
        actualOutputLength,
        readRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 read-physical failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 read-physical response: pa=0x%I64X, status=%lu, requested=%lu, read=%lu.",
            response->requestedPhysicalAddress,
            (unsigned long)response->readStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesRead);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlScanKernelExecutableMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY。中文说明：handler 只做
    METHOD_BUFFERED 缓冲获取、flags/range 初筛和日志；实际扫描为只读后端，
    不写 PTE，不改 CR0，也不承诺全内核地址空间覆盖。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；缺省时使用默认全模块保守扫描。
    OutputBufferLength - 输出长度；WDF 再确认。
    BytesReturned - 接收响应字节数。

Return Value:

    NTSTATUS from buffer validation or KswordARKDriverScanKernelExecutableMemory.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* scanRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST defaultRequest;
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST scanRequestCopy;
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

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&scanRequestCopy, sizeof(scanRequestCopy));
    defaultRequest.flags = KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE,
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 scan-kernel-exec ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    if (hasInput &&
        actualInputLength > KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE &&
        actualInputLength < sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST)) {
        KswordARKMemoryToolIoctlLog(
            Device,
            "Warn",
            "R0 scan-kernel-exec ioctl: partial v2 input rejected, actual=%Iu.",
            actualInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    if (hasInput) {
        size_t bytesToCopy = actualInputLength;
        if (bytesToCopy > sizeof(scanRequestCopy)) {
            bytesToCopy = sizeof(scanRequestCopy);
        }
        RtlCopyMemory(&scanRequestCopy, inputBuffer, bytesToCopy);
    }
    scanRequest = hasInput ? &scanRequestCopy : &defaultRequest;
    if ((scanRequest->flags & ~KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL) != 0UL ||
        scanRequest->reserved0 != 0UL ||
        (scanRequest->startAddress != 0ULL &&
            scanRequest->endAddress != 0ULL &&
            scanRequest->endAddress <= scanRequest->startAddress) ||
        scanRequest->maxBytes > KSWORD_ARK_KERNEL_EXEC_SCAN_HARD_MAX_BYTES ||
        scanRequest->hashBytes > KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX) {
        KswordARKMemoryToolIoctlLog(
            Device,
            "Warn",
            "R0 scan-kernel-exec ioctl: flags/range/budget rejected, flags=0x%08X, start=0x%I64X, end=0x%I64X.",
            (unsigned int)scanRequest->flags,
            scanRequest->startAddress,
            scanRequest->endAddress);
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * 中文说明：该 IOCTL 使用 METHOD_BUFFERED，输入和输出可能是同一个
     * SystemBuffer；backend 会清零响应缓冲，所以在获取输出缓冲前固定复制请求。
     */
    if (!hasInput) {
        RtlCopyMemory(&scanRequestCopy, scanRequest, sizeof(scanRequestCopy));
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 scan-kernel-exec ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverScanKernelExecutableMemory(
        outputBuffer,
        actualOutputLength,
        &scanRequestCopy,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 scan-kernel-exec failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE* response =
            (KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 scan-kernel-exec response: status=%lu, total=%lu, returned=%lu, modules=%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->moduleCount,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlWritePhysicalMemory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY。中文说明：写入物理内存要求
    FILE_WRITE_ACCESS、FORCE 确认和 safety policy 允许，backend 再执行映射写入。

Arguments:

    Device - WDF 设备对象，用于日志和 safety policy。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation, safety policy or KswordARKDriverWritePhysicalMemory.

--*/
{
    KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* writeRequest = NULL;
    // writeRequestCopy 是请求头加尾随 data[] 的完整池副本，长度不定所以不能放栈上。
    KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* writeRequestCopy = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    const ULONG allowedFlags =
        KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED |
        KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE,
        (PVOID*)&writeRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if ((writeRequest->flags & ~allowedFlags) != 0UL ||
        writeRequest->reserved != 0UL ||
        writeRequest->reserved2 != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)writeRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (writeRequest->bytesToWrite == 0UL ||
        writeRequest->bytesToWrite > KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: size rejected, pa=0x%I64X, bytes=%lu.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }
    if ((SIZE_T)writeRequest->bytesToWrite >
        (MAXSIZE_T - KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE)) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: size overflow rejected, bytes=%lu.", (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }

    requiredInputLength =
        KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE +
        (SIZE_T)writeRequest->bytesToWrite;
    if (actualInputLength < requiredInputLength) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical ioctl: input truncated, actual=%Iu, required=%Iu.", actualInputLength, requiredInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * METHOD_BUFFERED 的输入和输出共用同一个 SystemBuffer。后端会先
     * RtlZeroMemory 输出缓冲，再读 physicalAddress/bytesToWrite 并把
     * Request->data 拷进映射页；不先复制就等于拿响应头字节当物理地址，
     * 把响应内容写进一段错误的物理内存。
     */
    writeRequestCopy = (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)KswordARKAllocateNonPagedPool(
        requiredInputLength,
        KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
    if (writeRequestCopy == NULL) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical ioctl: input copy allocation failed, bytes=%Iu.", requiredInputLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(writeRequestCopy, writeRequest, requiredInputLength);
    writeRequest = writeRequestCopy;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return status;
    }

    if ((writeRequest->flags & KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE) == 0UL) {
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        RtlZeroMemory(outputBuffer, actualOutputLength);
        response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->fieldFlags =
            KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_REQUIRED;
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED;
        response->mapStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->copyStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->source = KSWORD_ARK_MEMORY_SOURCE_R0_MM_MAP_PHYSICAL_MEMORY;
        response->requestedBytes = writeRequest->bytesToWrite;
        response->maxBytesPerRequest = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES;
        response->requestedPhysicalAddress = writeRequest->physicalAddress;
        *BytesReturned = sizeof(*response);
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical requires force confirmation: pa=0x%I64X, bytes=%lu.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return STATUS_SUCCESS;
    }

    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.TargetProcessId = 0UL;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 write-physical denied by safety policy: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
            ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
            return status;
        }
    }

    // 后端只看得到池副本，长度也必须换成副本长度，不能再用 SystemBuffer 长度。
    status = KswordARKDriverWritePhysicalMemory(
        outputBuffer,
        actualOutputLength,
        writeRequest,
        requiredInputLength,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 write-physical failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE)) {
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 write-physical response: pa=0x%I64X, status=%lu, requested=%lu, written=%lu.",
            response->requestedPhysicalAddress,
            (unsigned long)response->writeStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesWritten);
    }

    ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlScanKernelMemoryEvidence(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理未注册的 IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE。中文说明：第 6
    会话统一在 ioctl_registry.c 接入；当前 handler 只做 METHOD_BUFFERED 输入
    复制、flags/range/cost 上限初筛、PASSIVE_LEVEL 约束和日志。后端只读采集
    PTE、BigPool、模块 section 样本，不写 PTE、不改 CR0、不写内核内存。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；缺省时使用默认只读全源扫描请求。
    OutputBufferLength - 输出长度；WDF 再确认。
    BytesReturned - 接收响应字节数。

Return Value:

    NTSTATUS from buffer validation or KswordARKDriverScanKernelMemoryEvidence.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* evidenceRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST defaultRequest;
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    const ULONG allowedFlags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_COMPARE_BIGPOOL_MODULES; // 可选目录归属核验不进入旧请求的默认源。
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 memory-evidence ioctl rejected: non-passive IRQL.");
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    defaultRequest.flags =
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
    defaultRequest.maxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS;
    defaultRequest.maxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES;
    defaultRequest.maxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS;
    defaultRequest.sampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 memory-evidence ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    evidenceRequest = hasInput ?
        (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST*)inputBuffer :
        &defaultRequest;
    if ((evidenceRequest->flags & ~allowedFlags) != 0UL ||
        evidenceRequest->reserved0 != 0UL ||
        evidenceRequest->reserved1 != 0UL ||
        (evidenceRequest->startAddress != 0ULL &&
            evidenceRequest->endAddress != 0ULL &&
            evidenceRequest->endAddress <= evidenceRequest->startAddress) ||
        (evidenceRequest->maxRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS) ||
        (evidenceRequest->maxBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BYTES) ||
        (evidenceRequest->maxBigPoolRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BIGPOOL_ROWS) ||
        (evidenceRequest->sampleBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_SAMPLE_BYTES) ||
        ((evidenceRequest->flags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) != 0UL &&
            (evidenceRequest->startAddress == 0ULL ||
                evidenceRequest->endAddress == 0ULL ||
                evidenceRequest->endAddress <= evidenceRequest->startAddress))) {
        KswordARKMemoryToolIoctlLog(
            Device,
            "Warn",
            "R0 memory-evidence ioctl rejected: flags=0x%08X, start=0x%I64X, end=0x%I64X.",
            (unsigned int)evidenceRequest->flags,
            evidenceRequest->startAddress,
            evidenceRequest->endAddress);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&requestCopy, evidenceRequest, sizeof(requestCopy));

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 memory-evidence ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverScanKernelMemoryEvidence(
        outputBuffer,
        actualOutputLength,
        &requestCopy,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 memory-evidence failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE* response =
            (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 memory-evidence response: status=%lu, total=%lu, returned=%lu, modules=%lu, bigpool=%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->totalRows,
            (unsigned long)response->returnedRows,
            (unsigned long)response->moduleCount,
            (unsigned long)response->bigPoolRowsSeen,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlTranslateVirtualAddress(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS。中文说明：handler 仅做
    缓冲和 flags 校验，实际 CR3/页表只读遍历由 backend 完成。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or KswordARKDriverTranslateVirtualAddress.

--*/
{
    KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST* translateRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST requestSnapshot;
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
        sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST),
        (PVOID*)&translateRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 translate-va ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出共用同一个 SystemBuffer；后端清零输出后
     * 才读 processId/virtualAddress，不做快照就会翻译一个错误的地址。
     */
    RtlCopyMemory(&requestSnapshot, translateRequest, sizeof(requestSnapshot));
    translateRequest = &requestSnapshot;

    if (translateRequest->flags != 0UL || translateRequest->reserved != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 translate-va ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)translateRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 translate-va ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverTranslateVirtualAddress(
        outputBuffer,
        actualOutputLength,
        translateRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 translate-va failed: pid=%lu, va=0x%I64X, status=0x%08X.", (unsigned long)translateRequest->processId, translateRequest->virtualAddress, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE)) {
        KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE* response =
            (KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 translate-va response: pid=%lu, va=0x%I64X, resolved=%lu, status=%lu, pa=0x%I64X.",
            (unsigned long)response->info.processId,
            response->info.virtualAddress,
            (unsigned long)response->info.resolved,
            (unsigned long)response->info.queryStatus,
            response->info.physicalAddress);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlQueryPageTableEntry(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY。中文说明：返回 PML4E/PDPTE/
    PDE/PTE 原始值、flags、索引、page size 和大页类型，默认不提供写页表能力。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    NTSTATUS from validation or KswordARKDriverQueryPageTableEntry.

--*/
{
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST* queryRequest = NULL;
    // requestSnapshot 在后端清零共用 SystemBuffer 前保存完整请求。
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST requestSnapshot;
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
        sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 query-pte ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED 的输入和输出共用同一个 SystemBuffer；后端清零输出后
     * 才读 processId/virtualAddress，不做快照就会查错页表项。
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if (queryRequest->flags != 0UL || queryRequest->reserved != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn", "R0 query-pte ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 query-pte ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverQueryPageTableEntry(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error", "R0 query-pte failed: pid=%lu, va=0x%I64X, status=0x%08X.", (unsigned long)queryRequest->processId, queryRequest->virtualAddress, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE)) {
        KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE* response =
            (KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE*)outputBuffer;
        KswordARKMemoryToolIoctlLog(
            Device,
            "Info",
            "R0 query-pte response: pid=%lu, va=0x%I64X, resolved=%lu, status=%lu, pageSize=%lu.",
            (unsigned long)response->info.processId,
            response->info.virtualAddress,
            (unsigned long)response->info.resolved,
            (unsigned long)response->info.queryStatus,
            (unsigned long)response->info.pageSize);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlChangeMappedPageProtection(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION。中文说明：
    通过 MDL 路径（IoAllocateMdl → MmProbeAndLockPages → MmMapLockedPagesSpecifyCache →
    MmProtectMdlSystemAddress）尝试对已有内核虚拟地址所在页变更保护属性。
    此 IOCTL 纯粹用于 HVCI 研究实验，观察 VTL1 是否允许通过合法 MM API
    把代码页从 RX 改为 RW。每个步骤的 NTSTATUS 都独立记录到响应结构，
    即使中途失败也会返回已完成步骤的状态供分析。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；METHOD_BUFFERED 下由 WDF 再校验。
    OutputBufferLength - 输出长度；METHOD_BUFFERED 下由 WDF 再校验。
    BytesReturned - 接收写入字节数。

Return Value:

    STATUS_SUCCESS（步骤级失败记在响应字段里），或验证阶段的 NTSTATUS。

--*/
{
    KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_REQUEST* changeRequest = NULL;
    /* METHOD_BUFFERED 输入输出共用 SystemBuffer，先快照再操作。 */
    KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_REQUEST requestSnapshot;
    KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_RESPONSE* responseOut = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* MDL 操作所需的局部变量。 */
    PMDL mdl = NULL;
    PVOID mappedVa = NULL;
    BOOLEAN pagesLocked = FALSE;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* 要求 FILE_WRITE_ACCESS：这是破坏性研究操作。 */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-mapped-protection denied: write access required, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /* 取得并校验输入缓冲。 */
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_REQUEST),
        (PVOID*)&changeRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error",
            "R0 change-mapped-protection ioctl: input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /* 快照输入，避免 METHOD_BUFFERED 混叠。 */
    RtlCopyMemory(&requestSnapshot, changeRequest, sizeof(requestSnapshot));
    changeRequest = &requestSnapshot;

    /* 校验 flags 只含已知位。 */
    if ((changeRequest->flags & ~(ULONG)KSWORD_ARK_CHANGE_PROTECTION_FLAG_WRITE_TEST) != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-mapped-protection ioctl: unknown flags rejected, flags=0x%08X.",
            (unsigned int)changeRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    /* 目标地址必须在内核空间。 */
    if (changeRequest->targetVirtualAddress < 0xFFFF800000000000ULL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-mapped-protection ioctl: user-space VA rejected, va=0x%I64X.",
            changeRequest->targetVirtualAddress);
        return STATUS_INVALID_PARAMETER;
    }

    /* 取得输出缓冲。 */
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error",
            "R0 change-mapped-protection ioctl: output invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /* 中央安全策略校验：保护变更属于破坏性内核操作。 */
    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.TargetProcessId = 0UL;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKMemoryToolIoctlLog(Device, "Warn",
                "R0 change-mapped-protection denied by safety policy: "
                "va=0x%I64X, status=0x%08X.",
                changeRequest->targetVirtualAddress, (unsigned int)status);
            return status;
        }
    }

    /* 初始化响应结构。 */
    responseOut = (KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_RESPONSE*)outputBuffer;
    RtlZeroMemory(responseOut, sizeof(*responseOut));
    responseOut->version = 1UL;
    responseOut->size = (unsigned long)sizeof(*responseOut);
    responseOut->mdlAllocStatus = (long)STATUS_PENDING;
    responseOut->lockStatus = (long)STATUS_PENDING;
    responseOut->mapStatus = (long)STATUS_PENDING;
    responseOut->protectStatus = (long)STATUS_PENDING;
    responseOut->writeTestStatus = (long)STATUS_NOT_SUPPORTED;

    KswordARKMemoryToolIoctlLog(Device, "Info",
        "R0 change-mapped-protection: va=0x%I64X, newProtection=0x%08X, flags=0x%08X.",
        changeRequest->targetVirtualAddress,
        (unsigned int)changeRequest->newProtection,
        (unsigned int)changeRequest->flags);

    /* Step 1: IoAllocateMdl 描述目标页（PAGE_SIZE 对齐，1 页）。 */
    mdl = IoAllocateMdl(
        (PVOID)(ULONG_PTR)changeRequest->targetVirtualAddress,
        PAGE_SIZE,
        FALSE,  /* SecondaryBuffer */
        FALSE,  /* ChargeQuota */
        NULL);  /* 不绑定 IRP */
    if (mdl == NULL) {
        responseOut->mdlAllocStatus = (long)STATUS_INSUFFICIENT_RESOURCES;
        KswordARKMemoryToolIoctlLog(Device, "Error",
            "R0 change-mapped-protection: IoAllocateMdl failed for va=0x%I64X.",
            changeRequest->targetVirtualAddress);
        goto DoneCleanup;
    }
    responseOut->mdlAllocStatus = (long)STATUS_SUCCESS;

    /* Step 2: MmProbeAndLockPages 锁定物理页。使用 KernelMode + IoReadAccess
     * 以避免额外的写权限要求——我们通过 MmProtectMdlSystemAddress 变更保护。 */
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        pagesLocked = TRUE;
        responseOut->lockStatus = (long)STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        responseOut->lockStatus = (long)GetExceptionCode();
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-mapped-protection: MmProbeAndLockPages exception, status=0x%08X.",
            (unsigned int)(NTSTATUS)GetExceptionCode());
        goto DoneCleanup;
    }

    /* Step 3: MmMapLockedPagesSpecifyCache 建立新的系统地址映射。 */
    mappedVa = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        NULL,   /* RequestedAddress: 让 MM 选基址 */
        FALSE,  /* BugCheckOnFailure */
        NormalPagePriority);
    if (mappedVa == NULL) {
        responseOut->mapStatus = (long)STATUS_INSUFFICIENT_RESOURCES;
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-mapped-protection: MmMapLockedPagesSpecifyCache returned NULL.");
        goto DoneCleanup;
    }
    responseOut->mapStatus = (long)STATUS_SUCCESS;
    responseOut->mappedVa = (unsigned long long)(ULONG_PTR)mappedVa;

    /* Step 4: MmProtectMdlSystemAddress 变更映射的保护属性。
     * 这是整个实验的核心——它会走 VTL1 secure call 路径更新 SLAT。 */
    status = MmProtectMdlSystemAddress(mdl, changeRequest->newProtection);
    responseOut->protectStatus = (long)status;
    KswordARKMemoryToolIoctlLog(Device, "Info",
        "R0 change-mapped-protection: MmProtectMdlSystemAddress returned 0x%08X, mappedVa=0x%I64X.",
        (unsigned int)status, (unsigned long long)(ULONG_PTR)mappedVa);

    /* Step 5: 如果保护变更成功且请求了写测试，尝试写入 1 字节并读回验证。 */
    if (NT_SUCCESS(status) &&
        (changeRequest->flags & KSWORD_ARK_CHANGE_PROTECTION_FLAG_WRITE_TEST) != 0UL) {
        __try {
            /* 读取原始字节、写入标记值、读回验证、恢复原值。 */
            volatile UCHAR* targetByte = (volatile UCHAR*)mappedVa;
            UCHAR originalByte = *targetByte;
            UCHAR testByte = (UCHAR)(originalByte ^ 0xFFU);
            *targetByte = testByte;
            if (*targetByte == testByte) {
                /* 写入成功且读回一致。立即恢复原值。 */
                *targetByte = originalByte;
                responseOut->writeTestStatus = (long)STATUS_SUCCESS;
                KswordARKMemoryToolIoctlLog(Device, "Info",
                    "R0 change-mapped-protection: write test PASSED, restored original byte.");
            } else {
                /* 读回值不一致——可能硬件或 hypervisor 拦截。 */
                responseOut->writeTestStatus = (long)STATUS_UNSUCCESSFUL;
                KswordARKMemoryToolIoctlLog(Device, "Warn",
                    "R0 change-mapped-protection: write test readback mismatch.");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            responseOut->writeTestStatus = (long)GetExceptionCode();
            KswordARKMemoryToolIoctlLog(Device, "Warn",
                "R0 change-mapped-protection: write test exception, status=0x%08X.",
                (unsigned int)(NTSTATUS)GetExceptionCode());
        }
    }

DoneCleanup:
    /* 清理：逆序释放所有资源。 */
    if (mappedVa != NULL) {
        MmUnmapLockedPages(mappedVa, mdl);
        mappedVa = NULL;
    }
    if (pagesLocked) {
        MmUnlockPages(mdl);
        pagesLocked = FALSE;
    }
    if (mdl != NULL) {
        IoFreeMdl(mdl);
        mdl = NULL;
    }

    *BytesReturned = sizeof(KSWORD_ARK_CHANGE_MAPPED_PAGE_PROTECTION_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * MmChangeImageProtection 签名：来自 RXPF build 26220 profile，
 * 作为启发式匹配在其它 build 上也可能命中。全 0xFF 掩码=精确匹配。
 * ================================================================ */

typedef NTSTATUS
(NTAPI* KSW_MEM_MM_CHANGE_IMAGE_PROTECTION)(
    _In_ PMDL Mdl,
    _In_ PVOID BaseAddress,
    _In_ ULONG NumberOfBytes,
    _In_ ULONG Operation
    );

static const UCHAR g_KswMemMmChangeSignature[64] = {
    0x48U, 0x8BU, 0xC4U, 0x48U, 0x89U, 0x58U, 0x08U, 0x48U,
    0x89U, 0x68U, 0x10U, 0x48U, 0x89U, 0x70U, 0x18U, 0x44U,
    0x89U, 0x48U, 0x20U, 0x57U, 0x41U, 0x54U, 0x41U, 0x55U,
    0x41U, 0x56U, 0x41U, 0x57U, 0x48U, 0x83U, 0xECU, 0x30U,
    0x83U, 0x60U, 0xC8U, 0x00U, 0x49U, 0x8BU, 0xD8U, 0x41U,
    0x8DU, 0x41U, 0xFFU, 0x4CU, 0x8BU, 0xE2U, 0x48U, 0x8BU,
    0xF9U, 0x83U, 0xF8U, 0x01U, 0x0FU, 0x87U, 0x41U, 0x02U,
    0x00U, 0x00U, 0x44U, 0x8BU, 0xEBU, 0x49U, 0x3BU, 0xDDU
};

/*++

Routine Description:

    在 ntoskrnl 的可执行节中扫描 MmChangeImageProtection 签名。
    使用 RtlPcToFileHeader 定位内核基址，解析 PE 节头，
    在每个可执行、非可丢弃节中逐字节比较 64 字节签名。

Arguments:

    FoundAddress - 接收匹配地址；未找到则为 NULL。

Return Value:

    STATUS_SUCCESS 表示扫描完成（不论是否找到）。
    STATUS_UNSUCCESSFUL 表示无法定位 ntoskrnl 或解析 PE。

--*/
static NTSTATUS
KswMemScanForMmChangeImageProtection(
    _Out_ KSW_MEM_MM_CHANGE_IMAGE_PROTECTION* FoundAddress
    )
{
    PVOID kernelBase = NULL;
    PIMAGE_DOS_HEADER dos = NULL;
    PIMAGE_NT_HEADERS64 nt = NULL;
    PIMAGE_SECTION_HEADER sections = NULL;
    USHORT numSections = 0U;
    USHORT i = 0U;

    *FoundAddress = NULL;

    /* 使用既有最低系统也提供的导出定位内核，避免硬导入 ExAllocatePool2。 */
    RtlPcToFileHeader((PVOID)(ULONG_PTR)&MmGetSystemRoutineAddress, &kernelBase);
    if (kernelBase == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    __try {
        dos = (PIMAGE_DOS_HEADER)kernelBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew <= 0 ||
            (ULONG)dos->e_lfanew > 0x1000UL) {
            return STATUS_UNSUCCESSFUL;
        }
        nt = (PIMAGE_NT_HEADERS64)((PUCHAR)kernelBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return STATUS_UNSUCCESSFUL;
        }

        sections = IMAGE_FIRST_SECTION(nt);
        numSections = nt->FileHeader.NumberOfSections;

        for (i = 0U; i < numSections; ++i) {
            ULONG sectionSize = 0UL;
            PUCHAR sectionStart = NULL;
            ULONG offset = 0UL;

            /* 只扫描可执行、非可丢弃的节。 */
            if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL) {
                continue;
            }
            if ((sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0UL) {
                continue;
            }

            sectionSize = sections[i].Misc.VirtualSize;
            if (sectionSize < sizeof(g_KswMemMmChangeSignature)) {
                continue;
            }
            sectionStart = (PUCHAR)kernelBase + sections[i].VirtualAddress;

            /* 逐字节滑动窗口匹配 64 字节签名。 */
            for (offset = 0UL;
                 offset <= sectionSize - sizeof(g_KswMemMmChangeSignature);
                 ++offset) {
                if (RtlEqualMemory(
                        sectionStart + offset,
                        g_KswMemMmChangeSignature,
                        sizeof(g_KswMemMmChangeSignature))) {
                    *FoundAddress =
                        (KSW_MEM_MM_CHANGE_IMAGE_PROTECTION)(sectionStart + offset);
                    return STATUS_SUCCESS;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return (NTSTATUS)GetExceptionCode();
    }

    /* 扫描完成但未找到匹配。 */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMemoryIoctlChangeImagePageProtection(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION。
    通过签名扫描定位 ntoskrnl!MmChangeImageProtection，
    然后在目标内核映像页上调用它，观察 VTL1 对映像保护变更的响应。
    可选测试：通过 MDL 别名映射创建可写视图并尝试写入。

Arguments:

    Device - WDF 设备对象。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度。
    OutputBufferLength - 输出长度。
    BytesReturned - 接收写入字节数。

Return Value:

    STATUS_SUCCESS（步骤级失败记在响应字段里），或验证阶段的 NTSTATUS。

--*/
{
    KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_REQUEST* imageRequest = NULL;
    KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_REQUEST requestSnapshot;
    KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_RESPONSE* responseOut = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    /* 运行时解析出的函数指针。 */
    KSW_MEM_MM_CHANGE_IMAGE_PROTECTION mmChangeFunc = NULL;

    /* MDL 操作所需的局部变量。 */
    PMDL mdl = NULL;
    PVOID aliasVa = NULL;
    BOOLEAN pagesLocked = FALSE;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    /* 要求 FILE_WRITE_ACCESS。 */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-image-protection denied: write access required, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /* 取得并校验输入缓冲。 */
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_REQUEST),
        (PVOID*)&imageRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error",
            "R0 change-image-protection: input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /* METHOD_BUFFERED 混叠保护：先快照输入。 */
    RtlCopyMemory(&requestSnapshot, imageRequest, sizeof(requestSnapshot));
    imageRequest = &requestSnapshot;

    /* 校验 flags 只含已知位。 */
    if ((imageRequest->flags &
         ~(ULONG)(KSWORD_ARK_IMAGE_PROT_FLAG_WRITE_TEST |
                  KSWORD_ARK_IMAGE_PROT_FLAG_RESTORE |
                  KSWORD_ARK_IMAGE_PROT_FLAG_UNMAP_BEFORE_RESTORE)) != 0UL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-image-protection: unknown flags rejected, flags=0x%08X.",
            (unsigned int)imageRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    /* 校验 operation 值。 */
    if (imageRequest->operation != KSWORD_ARK_IMAGE_PROT_OP_RX &&
        imageRequest->operation != KSWORD_ARK_IMAGE_PROT_OP_READONLY_NX) {
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-image-protection: invalid operation=%lu.",
            (unsigned long)imageRequest->operation);
        return STATUS_INVALID_PARAMETER;
    }

    /* 目标地址必须在内核空间。 */
    if (imageRequest->targetVirtualAddress < 0xFFFF800000000000ULL) {
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-image-protection: user-space VA rejected, va=0x%I64X.",
            imageRequest->targetVirtualAddress);
        return STATUS_INVALID_PARAMETER;
    }

    /* 取得输出缓冲。 */
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMemoryToolIoctlLog(Device, "Error",
            "R0 change-image-protection: output invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /* 中央安全策略校验：映像保护变更属于破坏性内核操作。 */
    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.TargetProcessId = 0UL;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKMemoryToolIoctlLog(Device, "Warn",
                "R0 change-image-protection denied by safety policy: "
                "va=0x%I64X, status=0x%08X.",
                imageRequest->targetVirtualAddress, (unsigned int)status);
            return status;
        }
    }

    /* 初始化响应结构，所有步骤标记为 PENDING。 */
    responseOut = (KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_RESPONSE*)outputBuffer;
    RtlZeroMemory(responseOut, sizeof(*responseOut));
    responseOut->version = 1UL;
    responseOut->size = (unsigned long)sizeof(*responseOut);
    responseOut->resolverStatus = (long)STATUS_PENDING;
    responseOut->mdlAllocStatus = (long)STATUS_PENDING;
    responseOut->lockStatus = (long)STATUS_PENDING;
    responseOut->imageProtectStatus = (long)STATUS_PENDING;
    responseOut->aliasMapStatus = (long)STATUS_NOT_SUPPORTED;
    responseOut->writeTestStatus = (long)STATUS_NOT_SUPPORTED;
    responseOut->restoreStatus = (long)STATUS_NOT_SUPPORTED;

    KswordARKMemoryToolIoctlLog(Device, "Info",
        "R0 change-image-protection: va=0x%I64X, operation=%lu, flags=0x%08X.",
        imageRequest->targetVirtualAddress,
        (unsigned long)imageRequest->operation,
        (unsigned int)imageRequest->flags);

    /* Step 1: 定位 MmChangeImageProtection。
     * 优先级：手动地址 > 签名扫描 > MmGetSystemRoutineAddress（导出名）。 */
    if (imageRequest->functionAddressOverride != 0ULL &&
        imageRequest->functionAddressOverride >= 0xFFFF800000000000ULL) {
        mmChangeFunc =
            (KSW_MEM_MM_CHANGE_IMAGE_PROTECTION)(ULONG_PTR)imageRequest->functionAddressOverride;
        responseOut->resolverStatus = (long)STATUS_SUCCESS;
        KswordARKMemoryToolIoctlLog(Device, "Info",
            "R0 change-image-protection: using manual override address 0x%I64X.",
            imageRequest->functionAddressOverride);
    } else {
        /* 先尝试签名扫描（覆盖未导出的 build）。 */
        status = KswMemScanForMmChangeImageProtection(&mmChangeFunc);
        if (!NT_SUCCESS(status) || mmChangeFunc == NULL) {
            /* 签名未匹配——回退到导出名解析（22621 等 build 上此函数被导出）。 */
            UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"MmChangeImageProtection");
            mmChangeFunc =
                (KSW_MEM_MM_CHANGE_IMAGE_PROTECTION)MmGetSystemRoutineAddress(&funcName);
            if (mmChangeFunc != NULL) {
                KswordARKMemoryToolIoctlLog(Device, "Info",
                    "R0 change-image-protection: resolved via MmGetSystemRoutineAddress.");
            }
        }
        if (mmChangeFunc == NULL) {
            responseOut->resolverStatus = (long)STATUS_NOT_FOUND;
            KswordARKMemoryToolIoctlLog(Device, "Error",
                "R0 change-image-protection: MmChangeImageProtection not found by any method.");
            goto ImageDoneCleanup;
        }
        responseOut->resolverStatus = (long)STATUS_SUCCESS;
    }
    responseOut->resolvedFunctionVa =
        (unsigned long long)(ULONG_PTR)mmChangeFunc;
    KswordARKMemoryToolIoctlLog(Device, "Info",
        "R0 change-image-protection: MmChangeImageProtection at 0x%I64X.",
        (unsigned long long)(ULONG_PTR)mmChangeFunc);

    /* Step 2: 为目标映像页创建 MDL。 */
    mdl = IoAllocateMdl(
        (PVOID)(ULONG_PTR)imageRequest->targetVirtualAddress,
        PAGE_SIZE,
        FALSE,
        FALSE,
        NULL);
    if (mdl == NULL) {
        responseOut->mdlAllocStatus = (long)STATUS_INSUFFICIENT_RESOURCES;
        KswordARKMemoryToolIoctlLog(Device, "Error",
            "R0 change-image-protection: IoAllocateMdl failed.");
        goto ImageDoneCleanup;
    }
    responseOut->mdlAllocStatus = (long)STATUS_SUCCESS;

    /* Step 3: MmProbeAndLockPages 锁定物理页。 */
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        pagesLocked = TRUE;
        responseOut->lockStatus = (long)STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        responseOut->lockStatus = (long)GetExceptionCode();
        KswordARKMemoryToolIoctlLog(Device, "Warn",
            "R0 change-image-protection: MmProbeAndLockPages exception=0x%08X.",
            (unsigned int)(NTSTATUS)GetExceptionCode());
        goto ImageDoneCleanup;
    }

    /* Step 3.5: 修改前从原始 VA 读一个字节作为基线。 */
    __try {
        volatile UCHAR* probeAddr =
            (volatile UCHAR*)(ULONG_PTR)imageRequest->targetVirtualAddress;
        responseOut->originalPte = (unsigned long long)(*probeAddr);
        KswordARKMemoryToolIoctlLog(Device, "Info",
            "R0 change-image-protection: pre-modify byte=0x%02X.",
            (unsigned int)(UCHAR)responseOut->originalPte);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        responseOut->originalPte = 0xDEADULL;
    }

    /* Step 4: 调用 MmChangeImageProtection 变更映像保护。
     * 这是核心实验——观察 VTL1 是否允许映像保护变更。 */
    __try {
        status = mmChangeFunc(
            mdl,
            (PVOID)(ULONG_PTR)imageRequest->targetVirtualAddress,
            PAGE_SIZE,
            imageRequest->operation);
        responseOut->imageProtectStatus = (long)status;
        KswordARKMemoryToolIoctlLog(Device, "Info",
            "R0 change-image-protection: MmChangeImageProtection returned 0x%08X.",
            (unsigned int)status);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        responseOut->imageProtectStatus = (long)GetExceptionCode();
        KswordARKMemoryToolIoctlLog(Device, "Error",
            "R0 change-image-protection: MmChangeImageProtection exception=0x%08X.",
            (unsigned int)(NTSTATUS)GetExceptionCode());
        goto ImageDoneCleanup;
    }

    /* Step 5: 如果请求了写测试，创建 RW/NX 别名映射并尝试写入。 */
    if ((imageRequest->flags & KSWORD_ARK_IMAGE_PROT_FLAG_WRITE_TEST) != 0UL) {
        aliasVa = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
        if (aliasVa == NULL) {
            responseOut->aliasMapStatus = (long)STATUS_INSUFFICIENT_RESOURCES;
            KswordARKMemoryToolIoctlLog(Device, "Warn",
                "R0 change-image-protection: alias MmMapLockedPagesSpecifyCache returned NULL.");
        } else {
            responseOut->aliasMapStatus = (long)STATUS_SUCCESS;
            responseOut->aliasVa =
                (unsigned long long)(ULONG_PTR)aliasVa;
            KswordARKMemoryToolIoctlLog(Device, "Info",
                "R0 change-image-protection: alias mapped at 0x%I64X.",
                (unsigned long long)(ULONG_PTR)aliasVa);

            /* 通过别名尝试写入。
             * UNMAP_BEFORE_RESTORE 模式下写入持久化（不恢复原字节），
             * 用于验证 NX→write→unmap→RX 全链路绕过。 */
            __try {
                volatile UCHAR* aliasByte = (volatile UCHAR*)aliasVa;
                UCHAR savedByte = *aliasByte;
                UCHAR testByte = (UCHAR)(savedByte ^ 0xFFU);
                *aliasByte = testByte;
                if (*aliasByte == testByte) {
                    ULONG persistWrite =
                        (imageRequest->flags &
                         KSWORD_ARK_IMAGE_PROT_FLAG_UNMAP_BEFORE_RESTORE);
                    if (persistWrite == 0UL) {
                        /* 非持久模式——恢复原字节。 */
                        *aliasByte = savedByte;
                    }
                    responseOut->writeTestStatus = (long)STATUS_SUCCESS;
                    KswordARKMemoryToolIoctlLog(Device, "Info",
                        "R0 change-image-protection: alias write PASSED "
                        "(0x%02X->0x%02X, persist=%u).",
                        (unsigned int)savedByte,
                        (unsigned int)testByte,
                        (unsigned int)(persistWrite != 0UL));
                } else {
                    responseOut->writeTestStatus = (long)STATUS_UNSUCCESSFUL;
                    KswordARKMemoryToolIoctlLog(Device, "Warn",
                        "R0 change-image-protection: alias write readback mismatch.");
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                responseOut->writeTestStatus = (long)GetExceptionCode();
                KswordARKMemoryToolIoctlLog(Device, "Warn",
                    "R0 change-image-protection: alias write exception=0x%08X.",
                    (unsigned int)(NTSTATUS)GetExceptionCode());
            }

            /* 写入后从原始 VA 读回，确认物理页已被修改。 */
            __try {
                volatile UCHAR* origAddr =
                    (volatile UCHAR*)(ULONG_PTR)imageRequest->targetVirtualAddress;
                responseOut->afterImageProtectPte =
                    (unsigned long long)(*origAddr);
                KswordARKMemoryToolIoctlLog(Device, "Info",
                    "R0 change-image-protection: post-write readback at "
                    "original VA=0x%02X.",
                    (unsigned int)(UCHAR)responseOut->afterImageProtectPte);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                responseOut->afterImageProtectPte = 0xDEADULL;
            }
        }
    }

    /* Step 6: 如果请求了恢复，调用反向操作。
     * UNMAP_BEFORE_RESTORE 先撤销可写别名，再尝试恢复 X 权限——
     * 用于验证 VTL1 是否因活跃的可写映射拒绝授予执行权限。 */
    if ((imageRequest->flags & KSWORD_ARK_IMAGE_PROT_FLAG_RESTORE) != 0UL) {
        if ((imageRequest->flags & KSWORD_ARK_IMAGE_PROT_FLAG_UNMAP_BEFORE_RESTORE) != 0UL
            && aliasVa != NULL) {
            MmUnmapLockedPages(aliasVa, mdl);
            aliasVa = NULL;
            KswordARKMemoryToolIoctlLog(Device, "Info",
                "R0 change-image-protection: alias unmapped before restore.");
        }
        ULONG restoreOp =
            (imageRequest->operation == KSWORD_ARK_IMAGE_PROT_OP_READONLY_NX)
            ? KSWORD_ARK_IMAGE_PROT_OP_RX
            : KSWORD_ARK_IMAGE_PROT_OP_READONLY_NX;
        __try {
            status = mmChangeFunc(
                mdl,
                (PVOID)(ULONG_PTR)imageRequest->targetVirtualAddress,
                PAGE_SIZE,
                restoreOp);
            responseOut->restoreStatus = (long)status;
            KswordARKMemoryToolIoctlLog(Device, "Info",
                "R0 change-image-protection: restore (op=%lu) returned 0x%08X.",
                (unsigned long)restoreOp, (unsigned int)status);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            responseOut->restoreStatus = (long)GetExceptionCode();
            KswordARKMemoryToolIoctlLog(Device, "Error",
                "R0 change-image-protection: restore exception=0x%08X.",
                (unsigned int)(NTSTATUS)GetExceptionCode());
        }

        /* 恢复后从原始 VA 读回——定案证据。
         * 如果读到被修改的字节且 restoreStatus=SUCCESS，
         * 则 HVCI W^X 不变式已被绕过。 */
        __try {
            volatile UCHAR* finalProbe =
                (volatile UCHAR*)(ULONG_PTR)imageRequest->targetVirtualAddress;
            responseOut->afterRestorePte =
                (unsigned long long)(*finalProbe);
            KswordARKMemoryToolIoctlLog(Device, "Info",
                "R0 change-image-protection: post-restore readback=0x%02X.",
                (unsigned int)(UCHAR)responseOut->afterRestorePte);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            responseOut->afterRestorePte = 0xDEADULL;
        }
    }

ImageDoneCleanup:
    /* 逆序释放所有资源。 */
    if (aliasVa != NULL) {
        MmUnmapLockedPages(aliasVa, mdl);
        aliasVa = NULL;
    }
    if (pagesLocked) {
        MmUnlockPages(mdl);
        pagesLocked = FALSE;
    }
    if (mdl != NULL) {
        IoFreeMdl(mdl);
        mdl = NULL;
    }

    *BytesReturned = sizeof(KSWORD_ARK_CHANGE_IMAGE_PAGE_PROTECTION_RESPONSE);
    return STATUS_SUCCESS;
}
