/*++

Module Name:

    kernel_ioctl.c

Abstract:

    IOCTL handlers for KswordARK kernel inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_SSDT_RESPONSE) - sizeof(KSWORD_ARK_SSDT_ENTRY))

#define KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY))

#define KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE))

#define KSWORD_ARK_INLINE_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY))

#define KSWORD_ARK_IAT_EAT_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY))

typedef VOID(NTAPI* KSWORD_HAL_RETURN_TO_FIRMWARE_FN)(
    _In_ LONG FirmwareAction
    );

static VOID
KswordARKKernelIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one kernel-handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    LevelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (void)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
KswordARKKernelIoctlExperimentalReturnToFirmware(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE_REQUEST* firmwareRequest = NULL;
    KSWORD_ARK_SAFETY_CONTEXT safetyContext;
    KSWORD_HAL_RETURN_TO_FIRMWARE_FN halReturnToFirmware = NULL;
    UNICODE_STRING routineName;
    size_t actualInputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(*firmwareRequest),
        (PVOID*)&firmwareRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (firmwareRequest->action !=
            KSWORD_ARK_FIRMWARE_RETURN_ACTION_HAL_REBOOT_ROUTINE ||
        (firmwareRequest->flags &
            KSWORD_ARK_FIRMWARE_RETURN_FLAG_UI_CONFIRMED) == 0UL ||
        firmwareRequest->confirmationToken !=
            KSWORD_ARK_FIRMWARE_RETURN_CONFIRMATION_TOKEN ||
        firmwareRequest->reserved != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_FIRMWARE_RETURN;
    safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    safetyContext.TargetText = L"HalReturnToFirmware(HalRebootRoutine)";
    safetyContext.TargetTextChars =
        (USHORT)(RTL_NUMBER_OF(L"HalReturnToFirmware(HalRebootRoutine)") - 1U);
    status = KswordARKSafetyEvaluate(Device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(
            Device,
            "Warn",
            "Experimental HalReturnToFirmware denied by safety policy: status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    RtlInitUnicodeString(&routineName, L"HalReturnToFirmware");
    halReturnToFirmware =
        (KSWORD_HAL_RETURN_TO_FIRMWARE_FN)MmGetSystemRoutineAddress(&routineName);
    if (halReturnToFirmware == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    KswordARKKernelIoctlLog(
        Device,
        "Warn",
        "Experimental raw API call starting: HalReturnToFirmware(HalRebootRoutine). This is a machine-wide unsupported action, not thread termination.");
    halReturnToFirmware(KSWORD_ARK_FIRMWARE_RETURN_ACTION_HAL_REBOOT_ROUTINE);

    // 成功路径通常不返回；若 HAL 拒绝或实现返回，则不能报告为已重启。
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
KswordARKKernelIoctlEnumSsdt(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_SSDT. Optional input preserves the legacy
    default request, and the feature function owns SSDT enumeration details.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF output retrieval.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or KswordARKDriverEnumerateSsdt.

--*/
{
    KSWORD_ARK_ENUM_SSDT_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_SSDT_REQUEST defaultRequest = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKRetrieveOptionalInputBuffer(Request, InputBufferLength, sizeof(KSWORD_ARK_ENUM_SSDT_REQUEST), &inputBuffer, &actualInputLength, &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-ssdt ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        enumRequest = (KSWORD_ARK_ENUM_SSDT_REQUEST*)inputBuffer;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->flags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED;
        enumRequest->reserved = 0UL;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(Request, KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-ssdt ioctl: output buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateSsdt(outputBuffer, actualOutputLength, enumRequest, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-ssdt failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_SSDT_RESPONSE* responseHeader = (KSWORD_ARK_ENUM_SSDT_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(Device, "Info", "R0 enum-ssdt success: total=%lu, returned=%lu, outBytes=%Iu.", (unsigned long)responseHeader->totalCount, (unsigned long)responseHeader->returnedCount, *BytesReturned);
    }
    else {
        KswordARKKernelIoctlLog(Device, "Warn", "R0 enum-ssdt success: outBytes=%Iu (header partial).", *BytesReturned);
    }

    return status;
}

NTSTATUS
KswordARKKernelIoctlQueryDriverObject(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT. The UI supplies only a driver
    object namespace name; kernel mode references the DriverObject itself and
    returns diagnostic-only addresses, dispatch table rows and device chains.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or KswordARKDriverQueryDriverObject.

--*/
{
    KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(
            Device,
            "Error",
            "R0 query-driver-object ioctl: input invalid, status=0x%08X, supplied=%Iu, required=%Iu.",
            (unsigned int)status,
            InputBufferLength,
            sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST));
        return status;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-driver-object ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverQueryDriverObject(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-driver-object failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE* responseHeader =
            (KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*)outputBuffer;
        if (responseHeader->queryStatus != KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND) {
            KswordARKKernelIoctlLog(
                Device,
                responseHeader->queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
                    responseHeader->queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL
                    ? "Info"
                    : "Warn",
                "R0 query-driver-object success: status=%lu, devices=%lu/%lu, outBytes=%Iu.",
                (unsigned long)responseHeader->queryStatus,
                (unsigned long)responseHeader->returnedDeviceCount,
                (unsigned long)responseHeader->totalDeviceCount,
                *BytesReturned);
        }
    }

    return status;
}

NTSTATUS
KswordARKKernelIoctlEnumShadowSsdt(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT。中文说明：handler 只负责缓冲
    获取与默认请求填充，SSSDT 解析策略由 ssdt_query.c 承担。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；缺省时使用 include-unresolved。
    OutputBufferLength - 输出长度；由 WDF 再确认。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_ENUM_SSDT_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_SSDT_REQUEST defaultRequest = { 0 };
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
        sizeof(KSWORD_ARK_ENUM_SSDT_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-shadow-ssdt ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        enumRequest = (KSWORD_ARK_ENUM_SSDT_REQUEST*)inputBuffer;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->flags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-shadow-ssdt ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateShadowSsdt(
        outputBuffer,
        actualOutputLength,
        enumRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-shadow-ssdt failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_ENUM_SSDT_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_SSDT_RESPONSE* responseHeader =
            (KSWORD_ARK_ENUM_SSDT_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            "Info",
            "R0 enum-shadow-ssdt success: total=%lu, returned=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            *BytesReturned);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlQueryDriverIntegrity(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY. The existing 0x849 IOCTL
    stays read-only and uses version/size fields so v1 rows remain a stable
    prefix while v2/v3 callers can consume typed DriverObject and descriptor
    evidence columns.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input length; absent input uses safe defaults.
    OutputBufferLength - Output length; WDF validates the concrete buffer.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from validation or the read-only integrity backend.

--*/
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST defaultRequest = { 0 };
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
        sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-driver-integrity ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    queryRequest = hasInput ?
        (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST*)inputBuffer :
        &defaultRequest;
    if (!hasInput) {
        defaultRequest.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
        defaultRequest.flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT;
        defaultRequest.requestSize = sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST);
        defaultRequest.maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS;
        defaultRequest.maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-driver-integrity ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverQueryDriverIntegrity(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-driver-integrity backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response =
            (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            "Info",
            "R0 query-driver-integrity staged response: status=%lu, total=%lu, returned=%lu, cpus=%lu, flags=0x%08lX.",
            (unsigned long)response->queryStatus,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->cpuCount,
            (unsigned long)response->flags);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlQueryCpuHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE. This is a fixed-size, read-only
    CPUID snapshot used by HardwareDock to enrich the utilization page with
    architectural CPU details.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; ignored because the query has no input.
    OutputBufferLength - Supplied output bytes; WDF validates the concrete buffer.
    BytesReturned - Receives sizeof(KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE).

Return Value:

    NTSTATUS from buffer retrieval or KswordARKDriverQueryCpuHardware.

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
        sizeof(KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-cpu-hardware ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverQueryCpuHardware(outputBuffer, actualOutputLength, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-cpu-hardware backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE)) {
        KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE* response =
            (KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            "Info",
            "R0 query-cpu-hardware success: vendor=%s, logical=%lu, active=%lu, family=%lu, model=%lu, features=0x%I64X.",
            response->vendor,
            (unsigned long)response->logicalProcessorCount,
            (unsigned long)response->activeProcessorCount,
            (unsigned long)response->family,
            (unsigned long)response->model,
            response->featureMask);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlQueryPhysicalMemoryLayout(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT. The handler returns
    aggregate R0 physical memory geometry for HardwareDock statistics and does
    not expose per-page or byte content.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; ignored because this query has no input.
    OutputBufferLength - Supplied output bytes; WDF validates the concrete buffer.
    BytesReturned - Receives sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE).

Return Value:

    NTSTATUS from buffer retrieval or KswordARKDriverQueryPhysicalMemoryLayout.

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
        sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-physical-memory-layout ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverQueryPhysicalMemoryLayout(outputBuffer, actualOutputLength, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 query-physical-memory-layout backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE)) {
        KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE* response =
            (KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            "Info",
            "R0 query-physical-memory-layout success: ranges=%lu, total=%I64u, highest=0x%I64X, largest=%I64u.",
            (unsigned long)response->rangeCount,
            response->totalPhysicalBytes,
            response->highestPhysicalAddress,
            response->largestRangeBytes);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlEnumTimerDpc(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_TIMER_DPC. The optional request carries only
    traversal budgets; the backend performs a bounded, read-only enumeration.

--*/
{
    KSWORD_ARK_ENUM_TIMER_DPC_REQUEST defaultRequest = { 0 };
    KSWORD_ARK_ENUM_TIMER_DPC_REQUEST requestCopy = { 0 };
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

    defaultRequest.version = KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION;
    defaultRequest.maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES;
    defaultRequest.maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_ENUM_TIMER_DPC_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-timer-dpc ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    requestCopy = hasInput ? *(KSWORD_ARK_ENUM_TIMER_DPC_REQUEST*)inputBuffer : defaultRequest;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-timer-dpc ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateTimerDpc(
        outputBuffer,
        actualOutputLength,
        &requestCopy,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-timer-dpc backend failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE) {
        const KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE* response =
            (const KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            response->queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK ? "Info" : "Warn",
            "R0 enum-timer-dpc completed: status=%lu flags=0x%08lX cpus=%lu buckets=%lu/%lu total=%lu returned=%lu corrupt=%lu readfail=%lu duplicate=%lu.",
            (unsigned long)response->queryStatus,
            (unsigned long)response->statusFlags,
            (unsigned long)response->processorCount,
            (unsigned long)response->bucketsVisited,
            (unsigned long)response->bucketCount,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->corruptBucketCount,
            (unsigned long)response->readFailureCount,
            (unsigned long)response->duplicateCount);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlScanInlineHooks(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS。中文说明：扫描为只读诊断，
    handler 支持可选请求；缺省时只返回可疑外跳行。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；缺省时使用默认扫描参数。
    OutputBufferLength - 输出长度；由 WDF 再确认。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* scanRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST defaultRequest = { 0 };
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
        sizeof(KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 scan-inline-hooks ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    scanRequest = hasInput ?
        (KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST*)inputBuffer :
        &defaultRequest;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_INLINE_HOOK_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 scan-inline-hooks ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverScanInlineHooks(
        outputBuffer,
        actualOutputLength,
        scanRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 scan-inline-hooks failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_INLINE_HOOK_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE* responseHeader =
            (KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            "Info",
            "R0 scan-inline-hooks success: total=%lu, returned=%lu, modules=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            (unsigned long)responseHeader->moduleCount,
            *BytesReturned);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlPatchInlineHook(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK。中文说明：普通请求返回
    FORCE_REQUIRED；强制请求必须带写访问并通过 safety policy。

Arguments:

    Device - WDF 设备对象，用于日志和 safety policy。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；必须包含固定修复请求。
    OutputBufferLength - 输出长度；必须容纳固定响应。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST* patchRequest = NULL;
    KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST patchRequestCopy;
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

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Warn", "R0 patch-inline-hook denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST),
        (PVOID*)&patchRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 patch-inline-hook ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    // 中文说明：PATCH_INLINE_HOOK 使用 METHOD_BUFFERED，WDF 的 input/output
    // 可能是同一个 SystemBuffer；backend 会清零输出缓冲，所以必须先复制请求。
    RtlZeroMemory(&patchRequestCopy, sizeof(patchRequestCopy));
    RtlCopyMemory(&patchRequestCopy, patchRequest, sizeof(patchRequestCopy));

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 patch-inline-hook ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if ((patchRequestCopy.flags & KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE) != 0UL) {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;

        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKKernelIoctlLog(Device, "Warn", "R0 patch-inline-hook denied by safety policy: target=0x%I64X, status=0x%08X.", patchRequestCopy.functionAddress, (unsigned int)status);
            return status;
        }
    }

    status = KswordARKDriverPatchInlineHook(
        outputBuffer,
        actualOutputLength,
        &patchRequestCopy,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 patch-inline-hook failed: target=0x%I64X, status=0x%08X.", patchRequestCopy.functionAddress, (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE)) {
        KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE* response =
            (KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            response->status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED ? "Info" : "Warn",
            "R0 patch-inline-hook response: target=0x%I64X, status=%lu, bytes=%lu, last=0x%08X.",
            response->functionAddress,
            (unsigned long)response->status,
            (unsigned long)response->bytesPatched,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlEnumIatEatHooks(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS。中文说明：枚举为只读诊断，
    支持模块名过滤、仅导入/仅导出以及包含干净项。

Arguments:

    Device - WDF 设备对象，用于日志。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；缺省时扫描 IAT 和 EAT 可疑项。
    OutputBufferLength - 输出长度；由 WDF 再确认。
    BytesReturned - 返回写入字节数。

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST* scanRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST defaultRequest = { 0 };
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

    defaultRequest.flags =
        KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS |
        KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-iat-eat ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    scanRequest = hasInput ?
        (KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST*)inputBuffer :
        &defaultRequest;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_IAT_EAT_HOOK_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-iat-eat ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateIatEatHooks(
        outputBuffer,
        actualOutputLength,
        scanRequest,
        BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 enum-iat-eat failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_IAT_EAT_HOOK_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE* responseHeader =
            (KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE*)outputBuffer;
        KswordARKKernelIoctlLog(
            Device,
            "Info",
            "R0 enum-iat-eat success: total=%lu, returned=%lu, modules=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            (unsigned long)responseHeader->moduleCount,
            *BytesReturned);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKernelIoctlForceUnloadDriver(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER。中文说明：handler 只负责写访问、
    fixed buffer 校验和 safety policy，真实卸载逻辑在 driver_unload.c。

Arguments:

    Device - WDF 设备对象，用于日志和 safety policy。
    Request - 当前 IOCTL 请求。
    InputBufferLength - 输入长度；必须包含固定请求。
    OutputBufferLength - 输出长度；必须容纳固定响应。
    BytesReturned - 返回响应字节数。

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* unloadRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    KSW_DRIVER_UNLOAD_DIAGNOSTICS unloadDiagnostics;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    RtlZeroMemory(&unloadDiagnostics, sizeof(unloadDiagnostics));

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Warn", "R0 force-unload-driver denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        FIELD_OFFSET(KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST, targetModuleBase),
        (PVOID*)&unloadRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 force-unload-driver ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 force-unload-driver ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    {
        KSWORD_ARK_SAFETY_CONTEXT safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_DRIVER_UNLOAD;
        safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.TargetText = unloadRequest->driverName;
        safetyContext.TargetTextChars = KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS;
        status = KswordARKSafetyEvaluate(Device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            KswordARKKernelIoctlLog(Device, "Warn", "R0 force-unload-driver denied by safety policy: status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = KswordARKDriverForceUnloadDriver(
        outputBuffer,
        actualOutputLength,
        unloadRequest,
        BytesReturned,
        &unloadDiagnostics);
    if (!NT_SUCCESS(status)) {
        KswordARKKernelIoctlLog(Device, "Error", "R0 force-unload-driver backend failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= sizeof(KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE)) {
        KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE* response =
            (KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE*)outputBuffer;
        const char* logLevel =
            (response->status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED ||
                response->status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP ||
                response->status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_CALLED)
            ? "Info"
            : "Warn";

        response->reserved2 = KSWORD_ARK_UNLOAD_DIAG_VALID | unloadDiagnostics.stages | unloadDiagnostics.blockingFlags; // 复用保留字段，结构和版本不变。
        if ((unloadDiagnostics.stages & KSW_DRIVER_UNLOAD_DIAG_STAGE_PREFLIGHT) != 0UL) {
            if (unloadDiagnostics.isSelfModule) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_SELF; // 自身模块门禁。
            if (unloadDiagnostics.isCoreKernelModule) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_CORE; // 核心模块门禁。
            if (NT_SUCCESS(unloadDiagnostics.preflightBuildStatus)) {
                if (unloadDiagnostics.hasModuleResidentThreads) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_RESIDENT_THREADS; // 驻留线程。
                if (unloadDiagnostics.hasModuleCallbacks) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_CALLBACKS; // 模块回调。
                if (unloadDiagnostics.hasAttachedDevice) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_ATTACHED_DEVICE; // 附加设备。
                if (unloadDiagnostics.hasBusyDeviceReference) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_DEVICE_REFERENCE; // 设备仍被引用。
                if (unloadDiagnostics.hasDeviceLoop) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_DEVICE_LOOP; // 设备链环。
                if (unloadDiagnostics.hasCrossDriverAttach) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_CROSS_DRIVER; // 设备归属不符。
                if (!unloadDiagnostics.hasThreadScan) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_THREAD_SCAN; // 线程证据不完整。
                if (!unloadDiagnostics.hasCallbackScan) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_CALLBACK_SCAN; // 回调证据不完整。
                if (!unloadDiagnostics.hasValidLoaderEvidence) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_LOADER_EVIDENCE; // loader 证据缺失。
                if (!unloadDiagnostics.hasValidDriverObjectOffsets) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_OBJECT_OFFSETS; // 对象偏移未验证。
                if (!unloadDiagnostics.hasValidDynData || !unloadDiagnostics.hasPdbBackedDynData) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_DYNDATA; // 动态布局不足。
                if (!unloadDiagnostics.hasServiceRegistryPath) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_SERVICE_PATH; // 无系统卸载路径。
                if (!unloadDiagnostics.hasDriverUnload) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_UNLOAD_ROUTINE; // 无卸载入口。
                if (unloadDiagnostics.hasLoaderLinkMismatch) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_LOADER_LINK; // loader 链不符。
                if (unloadDiagnostics.hasInvalidImageHeader) response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_IMAGE_HEADER; // 映像头不符。
            }
            if (!NT_SUCCESS(unloadDiagnostics.preflightBuildStatus) ||
                ((unloadDiagnostics.stages & (KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW | KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT)) == 0UL &&
                    !NT_SUCCESS(unloadDiagnostics.preflightDenyStatus))) {
                response->reserved2 |= KSWORD_ARK_UNLOAD_DIAG_PREFLIGHT_DENIED; // 标记具体发生的预检拒绝。
            }
        }
        KswordARKKernelIoctlLog(Device, logLevel, "R0 unload diag summary: flags=0x%08X blocking=0x%08X.",
            (unsigned int)response->reserved2, (unsigned int)unloadDiagnostics.blockingFlags); // 日志与 CLI 使用相同诊断摘要。

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 force-unload-driver response: status=%lu, requested=0x%08X, effective=0x%08X, applied=0x%08X, deleted=%lu, detached=%lu, object=0x%I64X, unload=0x%I64X, last=0x%08X, wait=0x%08X, callbacks=%lu/%lu, cbfail=%lu, cblast=0x%08X, threads=%lu/%lu, thfail=%lu, thlast=0x%08X.",
            (unsigned long)response->status,
            (unsigned int)response->reserved,
            (unsigned int)response->flags,
            (unsigned int)response->cleanupFlagsApplied,
            (unsigned long)response->deletedDeviceCount,
            (unsigned long)response->detachedDeviceCount,
            response->driverObjectAddress,
            response->driverUnloadAddress,
            (unsigned int)response->lastStatus,
            (unsigned int)response->waitStatus,
            (unsigned long)response->callbacksRemoved,
            (unsigned long)response->callbackCandidates,
            (unsigned long)response->callbackFailures,
            (unsigned int)response->callbackLastStatus,
            (unsigned long)response->threadsTerminated,
            (unsigned long)response->threadCandidates,
            (unsigned long)response->threadFailures,
            (unsigned int)response->threadLastStatus);

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 unload diag flags: stages=0x%08X req=0x%08X san=0x%08X fin=0x%08X ref=0x%08X pfBuild=0x%08X pf=0x%08X deny=0x%08X.",
            (unsigned int)unloadDiagnostics.stages,
            (unsigned int)unloadDiagnostics.requestedFlags,
            (unsigned int)unloadDiagnostics.sanitizedFlags,
            (unsigned int)unloadDiagnostics.finalFlags,
            (unsigned int)unloadDiagnostics.referenceStatus,
            (unsigned int)unloadDiagnostics.preflightBuildStatus,
            (unsigned int)unloadDiagnostics.preflightStatus,
            (unsigned int)unloadDiagnostics.preflightDenyStatus);

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 unload diag gates: allow=%u/%u/%u svc=%u unload=%u dyn=%u/%u/%u/%u dev=%u/%u/%u/%u/%u threads=%u/%u callbacks=%u/%u/%u loader=%u/%u image=%u/%u self=%u core=%u.",
            unloadDiagnostics.allowZwUnload ? 1U : 0U,
            unloadDiagnostics.allowDirectUnload ? 1U : 0U,
            unloadDiagnostics.allowDestructiveCleanup ? 1U : 0U,
            unloadDiagnostics.hasServiceRegistryPath ? 1U : 0U,
            unloadDiagnostics.hasDriverUnload ? 1U : 0U,
            unloadDiagnostics.hasValidDynData ? 1U : 0U,
            unloadDiagnostics.hasPdbBackedDynData ? 1U : 0U,
            unloadDiagnostics.hasValidDriverObjectOffsets ? 1U : 0U,
            unloadDiagnostics.hasValidLoaderEvidence ? 1U : 0U,
            unloadDiagnostics.hasDeviceChain ? 1U : 0U,
            unloadDiagnostics.hasAttachedDevice ? 1U : 0U,
            unloadDiagnostics.hasBusyDeviceReference ? 1U : 0U,
            unloadDiagnostics.hasCrossDriverAttach ? 1U : 0U,
            unloadDiagnostics.hasDeviceLoop ? 1U : 0U,
            unloadDiagnostics.hasThreadScan ? 1U : 0U,
            unloadDiagnostics.hasModuleResidentThreads ? 1U : 0U,
            unloadDiagnostics.hasCallbackScan ? 1U : 0U,
            unloadDiagnostics.hasModuleCallbacks ? 1U : 0U,
            unloadDiagnostics.hasNonRemovableModuleCallbacks ? 1U : 0U,
            unloadDiagnostics.hasLoaderLinkCheck ? 1U : 0U,
            unloadDiagnostics.hasLoaderLinkMismatch ? 1U : 0U,
            unloadDiagnostics.hasImageHeaderCheck ? 1U : 0U,
            unloadDiagnostics.hasInvalidImageHeader ? 1U : 0U,
            unloadDiagnostics.isSelfModule ? 1U : 0U,
            unloadDiagnostics.isCoreKernelModule ? 1U : 0U);

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 unload diag thread-evidence: status=0x%08X processes=%lu threads=%lu resident=%lu.",
            (unsigned int)unloadDiagnostics.threadScanStatus,
            (unsigned long)unloadDiagnostics.scannedProcessCount,
            (unsigned long)unloadDiagnostics.scannedThreadCount,
            (unsigned long)unloadDiagnostics.moduleResidentThreadCount);

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 unload diag callback-evidence: status=0x%08X enumerated=%lu module=%lu removable=%lu nonremovable=%lu.",
            (unsigned int)unloadDiagnostics.callbackScanStatus,
            (unsigned long)unloadDiagnostics.callbackEnumeratedCount,
            (unsigned long)unloadDiagnostics.moduleCallbackCount,
            (unsigned long)unloadDiagnostics.removableModuleCallbackCount,
            (unsigned long)unloadDiagnostics.nonRemovableModuleCallbackCount);

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 unload diag loader-image: link=0x%08X image=0x%08X headerSize=0x%08X ntOff=0x%08X.",
            (unsigned int)unloadDiagnostics.loaderLinkStatus,
            (unsigned int)unloadDiagnostics.imageHeaderStatus,
            (unsigned int)unloadDiagnostics.imageHeaderSizeOfImage,
            (unsigned int)unloadDiagnostics.imageNtHeaderOffset);

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 unload diag zw: run=0x%08X wait=0x%08X unload=0x%08X verify=0x%08X start=0x%I64X ldr=0x%I64X.",
            (unsigned int)unloadDiagnostics.zwRunStatus,
            (unsigned int)unloadDiagnostics.zwWaitStatus,
            (unsigned int)unloadDiagnostics.zwUnloadStatus,
            (unsigned int)unloadDiagnostics.zwVerifyStatus,
            unloadDiagnostics.driverStart,
            unloadDiagnostics.loaderDllBase);

        KswordARKKernelIoctlLog(
            Device,
            logLevel,
            "R0 unload diag direct: run=0x%08X wait=0x%08X unload=0x%08X cleanup=0x%08X verify=0x%08X ldrEntry=0x%I64X ldrSize=0x%08X.",
            (unsigned int)unloadDiagnostics.directRunStatus,
            (unsigned int)unloadDiagnostics.directWaitStatus,
            (unsigned int)unloadDiagnostics.directUnloadStatus,
            (unsigned int)unloadDiagnostics.directCleanupStatus,
            (unsigned int)unloadDiagnostics.directVerifyStatus,
            unloadDiagnostics.loaderEntryAddress,
            (unsigned int)unloadDiagnostics.loaderSizeOfImage);
    }

    return STATUS_SUCCESS;
}
