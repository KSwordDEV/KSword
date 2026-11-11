/*++

Module Name:

    minifilter_inventory.c

Abstract:

    Read-only Filter Manager minifilter inventory and callback-owner hint IOCTL.

Environment:

    Kernel-mode Driver Framework / Filter Manager

--*/

#include <fltKernel.h>
#include "ark/ark_driver.h"
#include "driver/KswordArkFilterIoctl.h"
#include "callback_internal.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_MINIFILTER_INVENTORY_TAG 'iFsK'
#define KSWORD_ARK_MINIFILTER_INVENTORY_MAX_ROWS 4096UL
#define KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY))

static VOID
KswordARKMinifilterInventoryLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one minifilter inventory log message. The log path is
    diagnostic only and never changes the IOCTL result.

Arguments:

    Device - WDF device that owns the shared log channel.
    LevelText - Log severity text.
    FormatText - printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. Formatting or enqueue failures are intentionally ignored.

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

static PVOID
KswordARKMinifilterInventoryAllocate(
    _In_ SIZE_T BufferBytes
    )
/*++

Routine Description:

    Allocate transient nonpaged memory for Filter Manager enumeration buffers.

Arguments:

    BufferBytes - Number of bytes requested.

Return Value:

    Allocation pointer, or NULL when the allocation fails.

--*/
{
    if (BufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, BufferBytes, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
#pragma warning(pop)
}

static VOID
KswordARKMinifilterInventoryCopyUnicode(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source
    )
/*++

Routine Description:

    Copy a bounded UNICODE_STRING into a fixed response string.

Arguments:

    Destination - Fixed-size output string.
    DestinationChars - Character capacity of Destination.
    Source - Optional source UNICODE_STRING.

Return Value:

    None. Destination is always NUL-terminated when capacity is nonzero.

--*/
{
    ULONG copyChars = 0UL;

    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    Destination[0] = L'\0';
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return;
    }

    copyChars = (ULONG)(Source->Length / sizeof(WCHAR));
    if (copyChars >= DestinationChars) {
        copyChars = DestinationChars - 1UL;
    }

    RtlCopyMemory(Destination, Source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
}

static NTSTATUS
KswordARKMinifilterInventoryQueryFilterInfo(
    _In_ PFLT_FILTER FilterObject,
    _Outptr_result_maybenull_ FILTER_AGGREGATE_STANDARD_INFORMATION** FilterInfoOut
    )
/*++

Routine Description:

    Query FilterAggregateStandardInformation for one referenced filter.

Arguments:

    FilterObject - Referenced Filter Manager filter object.
    FilterInfoOut - Receives an allocated information buffer.

Return Value:

    STATUS_SUCCESS when FilterInfoOut receives a buffer; otherwise the
    Filter Manager or allocation failure status.

--*/
{
    FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;
    ULONG bytesReturned = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (FilterInfoOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *FilterInfoOut = NULL;
    if (FilterObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetFilterInformation(
        FilterObject,
        FilterAggregateStandardInformation,
        NULL,
        0UL,
        &bytesReturned);
    if (status != STATUS_BUFFER_TOO_SMALL || bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION)) {
        return status;
    }

    filterInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION*)KswordARKMinifilterInventoryAllocate(bytesReturned);
    if (filterInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(filterInfo, bytesReturned);
    status = FltGetFilterInformation(
        FilterObject,
        FilterAggregateStandardInformation,
        filterInfo,
        bytesReturned,
        &bytesReturned);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(filterInfo, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        return status;
    }

    *FilterInfoOut = filterInfo;
    return STATUS_SUCCESS;
}

static VOID
KswordARKMinifilterInventoryFillFilterText(
    _In_ const FILTER_AGGREGATE_STANDARD_INFORMATION* FilterInfo,
    _Inout_ KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* Entry
    )
/*++

Routine Description:

    Copy filter name, altitude, frame ID, and instance count from public
    aggregate information into a response row.

Arguments:

    FilterInfo - Filter Manager aggregate information buffer.
    Entry - Response row being populated.

Return Value:

    None. Missing optional text leaves the corresponding string empty.

--*/
{
    UNICODE_STRING nameString;
    UNICODE_STRING altitudeString;

    if (FilterInfo == NULL || Entry == NULL) {
        return;
    }

    RtlZeroMemory(&nameString, sizeof(nameString));
    RtlZeroMemory(&altitudeString, sizeof(altitudeString));
    if ((FilterInfo->Flags & FLTFL_ASI_IS_MINIFILTER) == 0UL) {
        return;
    }

    Entry->instanceCount = FilterInfo->Type.MiniFilter.NumberOfInstances;
    Entry->frameId = FilterInfo->Type.MiniFilter.FrameID;

    if (FilterInfo->Type.MiniFilter.FilterNameBufferOffset != 0U &&
        FilterInfo->Type.MiniFilter.FilterNameLength != 0U) {
        nameString.Buffer = (PWCHAR)((PUCHAR)FilterInfo + FilterInfo->Type.MiniFilter.FilterNameBufferOffset);
        nameString.Length = FilterInfo->Type.MiniFilter.FilterNameLength;
        nameString.MaximumLength = FilterInfo->Type.MiniFilter.FilterNameLength;
        KswordARKMinifilterInventoryCopyUnicode(
            Entry->filterName,
            RTL_NUMBER_OF(Entry->filterName),
            &nameString);
        Entry->fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_NAME_PRESENT;
    }

    if (FilterInfo->Type.MiniFilter.FilterAltitudeBufferOffset != 0U &&
        FilterInfo->Type.MiniFilter.FilterAltitudeLength != 0U) {
        altitudeString.Buffer = (PWCHAR)((PUCHAR)FilterInfo + FilterInfo->Type.MiniFilter.FilterAltitudeBufferOffset);
        altitudeString.Length = FilterInfo->Type.MiniFilter.FilterAltitudeLength;
        altitudeString.MaximumLength = FilterInfo->Type.MiniFilter.FilterAltitudeLength;
        KswordARKMinifilterInventoryCopyUnicode(
            Entry->altitude,
            RTL_NUMBER_OF(Entry->altitude),
            &altitudeString);
        Entry->fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_ALTITUDE_PRESENT;
    }
}

static NTSTATUS
KswordARKMinifilterInventoryCopyVolumeName(
    _In_ PFLT_VOLUME VolumeObject,
    _Inout_ KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* Entry
    )
/*++

Routine Description:

    Query and copy the public Filter Manager volume name for a binding row.

Arguments:

    VolumeObject - Referenced Filter Manager volume object.
    Entry - Response row that receives volume name text.

Return Value:

    STATUS_SUCCESS when a name is copied; otherwise the Filter Manager or
    allocation status.

--*/
{
    UNICODE_STRING volumeName;
    ULONG bytesNeeded = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (VolumeObject == NULL || Entry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&volumeName, sizeof(volumeName));
    status = FltGetVolumeName(VolumeObject, NULL, &bytesNeeded);
    if (status != STATUS_BUFFER_TOO_SMALL || bytesNeeded == 0UL) {
        return status;
    }
    if (bytesNeeded > 0xFFFEUL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    volumeName.Buffer = (PWCHAR)KswordARKMinifilterInventoryAllocate(bytesNeeded + sizeof(WCHAR));
    if (volumeName.Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    volumeName.Length = 0U;
    volumeName.MaximumLength = (USHORT)bytesNeeded;
    RtlZeroMemory(volumeName.Buffer, bytesNeeded + sizeof(WCHAR));

    status = FltGetVolumeName(VolumeObject, &volumeName, &bytesNeeded);
    if (NT_SUCCESS(status)) {
        KswordARKMinifilterInventoryCopyUnicode(
            Entry->volumeName,
            RTL_NUMBER_OF(Entry->volumeName),
            &volumeName);
        Entry->fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_VOLUME_NAME_PRESENT;
    }

    ExFreePoolWithTag(volumeName.Buffer, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
    return status;
}

static VOID
KswordARKMinifilterInventoryAppendRow(
    _Inout_ KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* Response,
    _In_ ULONG EntryCapacity,
    _In_ const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* Entry
    )
/*++

Routine Description:

    Append one row to the variable inventory response while tracking truncation.

Arguments:

    Response - Response packet being built.
    EntryCapacity - Number of rows that fit in the caller output buffer.
    Entry - Source row.

Return Value:

    None. Response flags record truncation when capacity is exhausted.

--*/
{
    if (Response == NULL || Entry == NULL) {
        return;
    }

    if (Response->totalCount != MAXULONG) {
        Response->totalCount += 1UL;
    }

    if (Response->returnedCount >= EntryCapacity) {
        Response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_TRUNCATED;
        Response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_BUFFER_TRUNCATED;
        return;
    }

    RtlCopyMemory(&Response->entries[Response->returnedCount], Entry, sizeof(*Entry));
    Response->returnedCount += 1UL;
}

static VOID
KswordARKMinifilterInventorySeedRow(
    _In_ PFLT_FILTER FilterObject,
    _In_opt_ const FILTER_AGGREGATE_STANDARD_INFORMATION* FilterInfo,
    _Out_ KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* Entry
    )
/*++

Routine Description:

    Initialize a row with filter identity and conservative callback-owner status.

Arguments:

    FilterObject - Referenced Filter Manager filter object.
    FilterInfo - Optional aggregate information buffer.
    Entry - Output row.

Return Value:

    None. Entry is zeroed and then populated.

--*/
{
    if (Entry == NULL) {
        return;
    }

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->size = sizeof(*Entry);
    Entry->status = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_OK;
    Entry->sourceFlags = KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION;
    Entry->filterObject = (ULONG64)(ULONG_PTR)FilterObject;
    Entry->callbackOwnerStatus = STATUS_NOT_SUPPORTED;
    Entry->fieldFlags = KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_FILTER_PRESENT |
        KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_CALLBACK_OWNER_UNSUPPORTED;
    if (FilterInfo != NULL) {
        KswordARKMinifilterInventoryFillFilterText(FilterInfo, Entry);
    }
}

static VOID
KswordARKMinifilterInventoryAddVolumeRows(
    _In_ PFLT_FILTER FilterObject,
    _In_ const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY* BaseEntry,
    _Inout_ KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* Response,
    _In_ ULONG EntryCapacity
    )
/*++

Routine Description:

    Enumerate public volume bindings for one filter and append one row per
    bound volume. The routine only uses Filter Manager references and releases
    every object before returning.

Arguments:

    FilterObject - Referenced filter object.
    BaseEntry - Filter identity copied into each binding row.
    Response - Response packet being built.
    EntryCapacity - Number of rows available in Response.

Return Value:

    None. Partial failures set response flags and keep already-built rows.

--*/
{
    PFLT_VOLUME* volumeList = NULL;
    ULONG volumeCount = 0UL;
    ULONG volumeIndex = 0UL;
    SIZE_T allocationBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    status = FltEnumerateVolumes(FilterObject, NULL, 0UL, &volumeCount);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        Response->lastStatus = status;
        Response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        return;
    }
    if (volumeCount == 0UL) {
        return;
    }

    allocationBytes = (SIZE_T)volumeCount * sizeof(PFLT_VOLUME);
    volumeList = (PFLT_VOLUME*)KswordARKMinifilterInventoryAllocate(allocationBytes);
    if (volumeList == NULL) {
        Response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        Response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        return;
    }
    RtlZeroMemory(volumeList, allocationBytes);

    status = FltEnumerateVolumes(FilterObject, volumeList, volumeCount, &volumeCount);
    if (!NT_SUCCESS(status)) {
        Response->lastStatus = status;
        Response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        ExFreePoolWithTag(volumeList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        return;
    }

    for (volumeIndex = 0UL; volumeIndex < volumeCount; ++volumeIndex) {
        KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY row;
        PFLT_INSTANCE instanceProbe = NULL;
        ULONG bindingInstanceCount = 0UL;

        if (volumeList[volumeIndex] == NULL) {
            continue;
        }

        RtlCopyMemory(&row, BaseEntry, sizeof(row));
        row.volumeObject = (ULONG64)(ULONG_PTR)volumeList[volumeIndex];
        row.fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_VOLUME_PRESENT;
        (VOID)KswordARKMinifilterInventoryCopyVolumeName(volumeList[volumeIndex], &row);

        status = FltEnumerateInstances(volumeList[volumeIndex], FilterObject, &instanceProbe, 1UL, &bindingInstanceCount);
        if (NT_SUCCESS(status) && instanceProbe != NULL) {
            FltObjectDereference(instanceProbe);
        }
        if (status == STATUS_BUFFER_TOO_SMALL || NT_SUCCESS(status)) {
            row.volumeBindingInstanceCount = bindingInstanceCount;
        }
        else {
            row.status = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_PARTIAL;
            Response->lastStatus = status;
            Response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        }

        KswordARKMinifilterInventoryAppendRow(Response, EntryCapacity, &row);
    }

    for (volumeIndex = 0UL; volumeIndex < volumeCount; ++volumeIndex) {
        if (volumeList[volumeIndex] != NULL) {
            FltObjectDereference(volumeList[volumeIndex]);
        }
    }
    ExFreePoolWithTag(volumeList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
}

static NTSTATUS
KswordARKMinifilterInventoryBuild(
    _In_ const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST* Request,
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Build the read-only minifilter inventory response by using Filter Manager
    public enumeration APIs. When requested, the first validated Pre/Post
    callback supplies a module-owner hint without modifying fltMgr state.

Arguments:

    Request - Validated request packet.
    OutputBuffer - Caller output buffer.
    OutputBufferLength - Output buffer size.
    BytesWrittenOut - Receives the number of bytes populated.

Return Value:

    STATUS_SUCCESS when the response header is valid; hard failures represent
    only buffer or parameter errors.

--*/
{
    KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* response = NULL;
    PFLT_FILTER* filterList = NULL;
    ULONG filterCount = 0UL;
    ULONG filterIndex = 0UL;
    ULONG maxRows = 0UL;
    ULONG entryCapacity = 0UL;
    SIZE_T allocationBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Request == NULL || OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*)OutputBuffer;
    response->size = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
    response->version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY);
    response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;

    maxRows = Request->maxRows;
    if (maxRows == 0UL || maxRows > KSWORD_ARK_MINIFILTER_INVENTORY_MAX_ROWS) {
        maxRows = KSWORD_ARK_MINIFILTER_INVENTORY_MAX_ROWS;
    }
    entryCapacity = (ULONG)((OutputBufferLength - KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE) / sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY));
    if (entryCapacity > maxRows) {
        entryCapacity = maxRows;
    }

    status = FltEnumerateFilters(NULL, 0UL, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_SUCCESS) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_QUERY_FAILED;
        response->lastStatus = status;
        *BytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    if (filterCount == 0UL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_OK;
        *BytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    allocationBytes = (SIZE_T)filterCount * sizeof(PFLT_FILTER);
    filterList = (PFLT_FILTER*)KswordARKMinifilterInventoryAllocate(allocationBytes);
    if (filterList == NULL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_QUERY_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *BytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(filterList, allocationBytes);

    status = FltEnumerateFilters(filterList, filterCount, &filterCount);
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_QUERY_FAILED;
        response->lastStatus = status;
        ExFreePoolWithTag(filterList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        *BytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    for (filterIndex = 0UL; filterIndex < filterCount; ++filterIndex) {
        FILTER_AGGREGATE_STANDARD_INFORMATION* filterInfo = NULL;
        KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY row;

        if (filterList[filterIndex] == NULL) {
            continue;
        }

        status = KswordARKMinifilterInventoryQueryFilterInfo(filterList[filterIndex], &filterInfo);
        response->lastStatus = status;
        KswordARKMinifilterInventorySeedRow(filterList[filterIndex], filterInfo, &row);
        if ((Request->flags & KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_CALLBACK_OWNER_HINT) != 0UL) {
            row.callbackOwnerStatus = KswordArkMinifilterQueryFirstCallbackOwner(
                filterList[filterIndex],
                row.callbackOwnerModule,
                RTL_NUMBER_OF(row.callbackOwnerModule),
                &row.callbackOwnerModuleBase,
                &row.callbackOwnerModuleSize);
            if (NT_SUCCESS(row.callbackOwnerStatus)) {
                row.fieldFlags &= ~KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_CALLBACK_OWNER_UNSUPPORTED;
                row.fieldFlags |= KSWORD_ARK_MINIFILTER_INVENTORY_ROW_FLAG_CALLBACK_OWNER_PRESENT;
            }
        }
        if (!NT_SUCCESS(status)) {
            row.status = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_PARTIAL;
            response->flags |= KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL;
        }

        if ((Request->flags & KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_VOLUMES) != 0UL) {
            KswordARKMinifilterInventoryAddVolumeRows(filterList[filterIndex], &row, response, entryCapacity);
        }
        else {
            KswordARKMinifilterInventoryAppendRow(response, entryCapacity, &row);
        }

        if (filterInfo != NULL) {
            ExFreePoolWithTag(filterInfo, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
        }
        FltObjectDereference(filterList[filterIndex]);
    }

    ExFreePoolWithTag(filterList, KSWORD_ARK_MINIFILTER_INVENTORY_TAG);
    if ((response->flags & KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_BUFFER_TRUNCATED;
    }
    else if ((response->flags & KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_PARTIAL) != 0UL) {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_PARTIAL;
    }
    else {
        response->queryStatus = KSWORD_ARK_MINIFILTER_INVENTORY_STATUS_OK;
    }

    *BytesWrittenOut = KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY));
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKMinifilterIoctlQueryInventory(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY. The handler validates
    METHOD_BUFFERED buffers and delegates all collection to the feature builder.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input length supplied by the dispatch layer.
    OutputBufferLength - Output length supplied by the dispatch layer.
    BytesReturned - Receives the completed byte count.

Return Value:

    NTSTATUS from buffer validation or the inventory builder.

--*/
{
    KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST requestSnapshot;
    KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST defaultRequest;
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
    defaultRequest.size = sizeof(defaultRequest);
    defaultRequest.version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
    defaultRequest.flags = KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL;
    defaultRequest.maxRows = 1024UL;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        KswordARKMinifilterInventoryLog(Device, "Error", "R0 minifilter inventory ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputLength);

    queryRequest = hasInput ? (KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST*)inputBuffer : &defaultRequest;
    if (queryRequest->size != sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST) ||
        queryRequest->version != KSWORD_ARK_FILTER_PROTOCOL_VERSION ||
        (queryRequest->flags & ~KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL) != 0UL) {
        KswordARKMinifilterInventoryLog(Device, "Warn", "R0 minifilter inventory ioctl: request rejected, size=%lu, version=%lu, flags=0x%08X.",
            (unsigned long)queryRequest->size,
            (unsigned long)queryRequest->version,
            (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    if (hasInput) {
        /* METHOD_BUFFERED shares input/output: preserve options before output is cleared. */
        RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
        queryRequest = &requestSnapshot;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKMinifilterInventoryLog(Device, "Error", "R0 minifilter inventory ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKMinifilterInventoryBuild(queryRequest, outputBuffer, actualOutputLength, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKMinifilterInventoryLog(Device, "Error", "R0 minifilter inventory failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_MINIFILTER_INVENTORY_HEADER_SIZE) {
        const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE* response =
            (const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*)outputBuffer;
        KswordARKMinifilterInventoryLog(
            Device,
            "Info",
            "R0 minifilter inventory success: status=%lu, total=%lu, returned=%lu.",
            (unsigned long)response->queryStatus,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}
