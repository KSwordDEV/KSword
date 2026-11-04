/*++

Module Name:

    storage_ioctl.c

Abstract:

    IOCTL handlers for read-only storage, BitLocker/FVE, MountMgr, and
    file-system integrity audit queries.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_STORAGE_VOLUME_STACK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE) - sizeof(KSWORD_ARK_VOLUME_STACK_ROW))

#define KSW_STORAGE_BITLOCKER_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE) - sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW))

#define KSW_STORAGE_MOUNTMGR_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE) - sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW))

#define KSW_STORAGE_FILESYSTEM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW))

static VOID
KswordARKStorageIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one storage audit handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    LevelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are intentionally ignored.

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

static NTSTATUS
KswordARKStorageRetrieveBuffers(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputHeaderBytes,
    _Out_ KSWORD_ARK_STORAGE_AUDIT_REQUEST* RequestSnapshot,
    _Outptr_result_maybenull_ KSWORD_ARK_STORAGE_AUDIT_REQUEST** QueryRequest,
    _Outptr_ PVOID* OutputBuffer,
    _Out_ size_t* ActualOutputLength
    )
/*++

Routine Description:

    Retrieve the optional common storage request and the required variable-row
    output buffer for a storage audit IOCTL.

Arguments:

    Request - Current WDF IOCTL request.
    InputBufferLength - User-supplied input length.
    OutputHeaderBytes - Minimum output header bytes for the specific response.
    RequestSnapshot - Receives a copy of input before the shared output is cleared.
    QueryRequest - Receives NULL for default options or the request snapshot.
    OutputBuffer - Receives the WDF output buffer.
    ActualOutputLength - Receives the WDF output buffer length.

Return Value:

    NTSTATUS from WDF buffer validation helpers.

--*/
{
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status;

    if (RequestSnapshot == NULL || QueryRequest == NULL || OutputBuffer == NULL || ActualOutputLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *QueryRequest = NULL;
    *OutputBuffer = NULL;
    *ActualOutputLength = 0U;
    status = KswordARKRetrieveOptionalInputBuffer(Request, InputBufferLength, sizeof(KSWORD_ARK_STORAGE_AUDIT_REQUEST), &inputBuffer, &actualInputLength, &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputLength);
    if (hasInput) {
        /* METHOD_BUFFERED shares input/output: preserve options before output is cleared. */
        RtlCopyMemory(RequestSnapshot, inputBuffer, sizeof(*RequestSnapshot));
        *QueryRequest = RequestSnapshot;
    }
    return KswordARKRetrieveRequiredOutputBuffer(Request, OutputHeaderBytes, OutputBuffer, ActualOutputLength);
}

NTSTATUS
KswordARKStorageIoctlQueryVolumeStackAudit(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT by forwarding validated
    METHOD_BUFFERED buffers to the read-only storage backend.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    /* 保存 METHOD_BUFFERED 输入，避免输出初始化覆盖查询参数。 */
    KSWORD_ARK_STORAGE_AUDIT_REQUEST requestSnapshot;
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = KswordARKStorageRetrieveBuffers(Request, InputBufferLength, KSW_STORAGE_VOLUME_STACK_RESPONSE_HEADER_SIZE, &requestSnapshot, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKStorageIoctlLog(Device, "Error", "R0 storage volume-stack ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = KswordARKStorageQueryVolumeStackAudit(outputBuffer, actualOutputLength, queryRequest, BytesReturned);
    KswordARKStorageIoctlLog(Device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage volume-stack audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
    return status;
}

NTSTATUS
KswordARKStorageIoctlQueryBitLockerFveAudit(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT by invoking the safe
    fvevol stack-position status backend.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    /* 保存 METHOD_BUFFERED 输入，避免输出初始化覆盖查询参数。 */
    KSWORD_ARK_STORAGE_AUDIT_REQUEST requestSnapshot;
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = KswordARKStorageRetrieveBuffers(Request, InputBufferLength, KSW_STORAGE_BITLOCKER_RESPONSE_HEADER_SIZE, &requestSnapshot, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKStorageIoctlLog(Device, "Error", "R0 storage bitlocker ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = KswordARKStorageQueryBitLockerFveAudit(outputBuffer, actualOutputLength, queryRequest, BytesReturned);
    KswordARKStorageIoctlLog(Device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage bitlocker audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
    return status;
}

NTSTATUS
KswordARKStorageIoctlQueryMountMgrMappingAudit(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT by returning read-only
    DOS drive-letter to NT device symbolic-link mappings.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    /* 保存 METHOD_BUFFERED 输入，避免输出初始化覆盖查询参数。 */
    KSWORD_ARK_STORAGE_AUDIT_REQUEST requestSnapshot;
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = KswordARKStorageRetrieveBuffers(Request, InputBufferLength, KSW_STORAGE_MOUNTMGR_RESPONSE_HEADER_SIZE, &requestSnapshot, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKStorageIoctlLog(Device, "Error", "R0 storage mountmgr ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = KswordARKStorageQueryMountMgrMappingAudit(outputBuffer, actualOutputLength, queryRequest, BytesReturned);
    KswordARKStorageIoctlLog(Device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage mountmgr audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
    return status;
}

NTSTATUS
KswordARKStorageIoctlQueryFileSystemIntegrityAudit(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT by invoking the
    read-only DriverObject dispatch/FastIo owner evidence backend.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes.
    OutputBufferLength - Supplied output bytes.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or the storage backend.

--*/
{
    /* 保存 METHOD_BUFFERED 输入，避免输出初始化覆盖查询参数。 */
    KSWORD_ARK_STORAGE_AUDIT_REQUEST requestSnapshot;
    KSWORD_ARK_STORAGE_AUDIT_REQUEST* queryRequest = NULL;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    status = KswordARKStorageRetrieveBuffers(Request, InputBufferLength, KSW_STORAGE_FILESYSTEM_RESPONSE_HEADER_SIZE, &requestSnapshot, &queryRequest, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKStorageIoctlLog(Device, "Error", "R0 storage filesystem ioctl buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = KswordARKStorageQueryFileSystemIntegrityAudit(outputBuffer, actualOutputLength, queryRequest, BytesReturned);
    KswordARKStorageIoctlLog(Device, NT_SUCCESS(status) ? "Info" : "Error", "R0 storage filesystem audit completed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
    return status;
}
