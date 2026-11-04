/* Read-only kernel snapshot and per-process image mappings. */
#include "ark/ark_driver.h"
#include "driver/KswordArkModuleIoctl.h"
#include "hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400UL
#endif
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x01000000UL
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x00001000UL
#endif

NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTKERNELAPI NTSTATUS ObOpenObjectByPointer(_In_ PVOID Object, _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState, _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType, _In_ KPROCESSOR_MODE AccessMode, _Out_ PHANDLE Handle);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
    _In_ ULONG MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
NTKERNELAPI LONGLONG NTAPI PsGetProcessCreateTimeQuadPart(_In_ PEPROCESS Process);

typedef struct _KSW_MODULE_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} KSW_MODULE_BASIC_INFORMATION;

typedef struct _KSW_MODULE_NAME_BUFFER {
    UNICODE_STRING Name;
    WCHAR Storage[KSWORD_ARK_MODULE_PATH_CHARS];
} KSW_MODULE_NAME_BUFFER;

/* Copy the returned string only when the entire range is inside our buffer. */
static VOID KswordModuleCopyPath(KSWORD_ARK_MODULE_ENTRY* Row, KSW_MODULE_NAME_BUFFER* Buffer, NTSTATUS Status)
{
    ULONG_PTR start = (ULONG_PTR)Buffer; /* Bound the returned UNICODE_STRING pointer. */
    ULONG_PTR end = start + sizeof(*Buffer); /* The buffer is a fixed local object. */
    ULONG_PTR name = (ULONG_PTR)Buffer->Name.Buffer; /* Treat returned pointer as untrusted. */
    USHORT length = Buffer->Name.Length; /* Length is in bytes, not characters. */
    Row->pathStatus = Status; /* Preserve the actual query status. */
    if ((!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) || name < start || name > end ||
        (length & 1U) != 0U || (ULONG_PTR)length > end - name) { /* Reject malformed strings. */
        return; /* The row remains usable without its path. */
    } /* End string validation. */
    if (length >= sizeof(Row->path)) { /* Reserve the terminating character. */
        length = (USHORT)(sizeof(Row->path) - sizeof(WCHAR)); /* Truncate at a WCHAR boundary. */
        Row->flags |= KSWORD_ARK_MODULE_ROW_PATH_TRUNCATED; /* Do not claim a complete path. */
    } /* End path length handling. */
    if (length != 0U) { /* Empty paths do not establish a file identity. */
        RtlCopyMemory(Row->path, Buffer->Name.Buffer, length); /* Copy only validated kernel buffer bytes. */
        Row->path[length / sizeof(WCHAR)] = L'\0'; /* Ensure a terminator. */
        Row->flags |= KSWORD_ARK_MODULE_ROW_PATH_PRESENT; /* Publish the path availability. */
    } /* End nonempty path handling. */
    if (Status == STATUS_BUFFER_OVERFLOW) { Row->flags |= KSWORD_ARK_MODULE_ROW_PATH_TRUNCATED; } /* Preserve overflow. */
}

/* Publish the existing R0 SystemModuleInformation snapshot with strict bounds. */
static VOID KswordModuleKernel(const KSWORD_ARK_ENUM_MODULES_REQUEST* Request,
    KSWORD_ARK_ENUM_MODULES_RESPONSE* Response, ULONG Capacity)
{
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* modules = NULL; /* Shared snapshot owns pool memory. */
    ULONG bytes = 0UL; /* Actual snapshot size returned by the helper. */
    ULONG i = 0UL; /* Snapshot index. */
    ULONG count = 0UL; /* Validated snapshot count. */
    const size_t headerBytes = (size_t)FIELD_OFFSET(KSW_HOOK_SYSTEM_MODULE_INFORMATION, Modules); /* WDK FIELD_OFFSET is signed LONG. */
    NTSTATUS status = KswordARKHookBuildModuleSnapshot(&modules, &bytes); /* Execute R0 snapshot. */
    Response->lastStatus = status; /* Preserve native query status. */
    if (!NT_SUCCESS(status)) { return; } /* Unavailable is the initialized status. */
    if ((size_t)bytes < headerBytes ||
        (size_t)modules->NumberOfModules > ((size_t)bytes - headerBytes) / sizeof(KSW_HOOK_SYSTEM_MODULE_ENTRY)) { /* Validate returned count. */
        Response->lastStatus = STATUS_DATA_ERROR; /* Distinguish malformed native response. */
        ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG); /* Release the helper's pool. */
        return; /* Never parse beyond the snapshot. */
    } /* End snapshot validation. */
    count = modules->NumberOfModules; /* Count is now bounded. */
    Response->totalCount = count; /* The kernel source knows the whole snapshot count. */
    if (Request->cursor > count) { Response->status = KSWORD_ARK_MODULE_STATUS_INVALID; Response->lastStatus = STATUS_INVALID_PARAMETER; ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG); return; } /* Reject an invalid cursor. */
    for (i = (ULONG)Request->cursor; i < count; ++i) { /* Walk in this independent snapshot. */
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* source = &modules->Modules[i]; /* Current kernel record. */
        KSWORD_ARK_MODULE_ENTRY* row = NULL; /* Response row, only after capacity check. */
        ++Response->visitedCount; /* Count only rows examined by this request. */
        if (Request->filterBase != 0ULL && Request->filterBase != (ULONG64)(ULONG_PTR)source->ImageBase) { continue; } /* Apply exact identity filter. */
        if (Response->returnedCount >= Capacity) { Response->flags |= KSWORD_ARK_MODULE_FLAG_MORE; Response->nextCursor = i; break; } /* Preserve next unreturned index. */
        row = &Response->entries[Response->returnedCount++]; /* Reserve a zeroed row. */
        row->baseAddress = (ULONG64)(ULONG_PTR)source->ImageBase; /* Publish the observed base. */
        row->spanBytes = source->ImageSize; /* Snapshot provides image size directly. */
        row->nativeFlags = source->Flags; /* Preserve native module flags. */
        KswordARKHookCopyBoundedAnsiToWide(source->FullPathName, sizeof(source->FullPathName), row->path, RTL_NUMBER_OF(row->path)); /* The native snapshot uses an ANSI byte path. */
        if (row->path[0] != L'\0') { row->flags |= KSWORD_ARK_MODULE_ROW_PATH_PRESENT; } else { Response->flags |= KSWORD_ARK_MODULE_FLAG_PATH_UNAVAILABLE; } /* Mark missing path. */
        if (source->FullPathName[sizeof(source->FullPathName) - 1U] != 0U) { row->flags |= KSWORD_ARK_MODULE_ROW_PATH_TRUNCATED; Response->flags |= KSWORD_ARK_MODULE_FLAG_PATH_UNAVAILABLE; } /* The native fixed path did not terminate. */
        if (Request->filterBase != 0ULL) { break; } /* Exact base identifies a single row. */
    } /* End kernel snapshot walk. */
    Response->status = Response->flags ? KSWORD_ARK_MODULE_STATUS_PARTIAL : KSWORD_ARK_MODULE_STATUS_COMPLETE; /* Truncation and unavailable path remain partial. */
    ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG); /* Release the helper's pool. */
}

/* Enumerate MEM_IMAGE mappings in a referenced process, not its PEB loader list. */
static VOID KswordModuleProcess(const KSWORD_ARK_ENUM_MODULES_REQUEST* Request,
    KSWORD_ARK_ENUM_MODULES_RESPONSE* Response, ULONG Capacity)
{
    PEPROCESS process = NULL; /* Keep one process object for the entire request. */
    HANDLE handle = NULL; /* Kernel handle to the same referenced object. */
    ULONG64 cursor = Request->filterBase ? Request->filterBase : Request->cursor; /* Resume or inspect one base. */
    ULONG64 upper = (ULONG64)(ULONG_PTR)MmHighestUserAddress + 1ULL; /* Exclusive user limit. */
    ULONG64 deadline = KeQueryInterruptTime() + 50000000ULL; /* Five-second per-request budget. */
    ULONG64 currentBase = 0ULL; /* Allocation identity of the current response row. */
    KSWORD_ARK_MODULE_ENTRY* row = NULL; /* Last returned image mapping. */
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &process); /* Resolve process once. */
    Response->processId = Request->processId; /* Publish the requested PID. */
    Response->lastStatus = status; /* Preserve lookup failure. */
    if (!NT_SUCCESS(status)) { return; } /* No object means no scan. */
    Response->processCreateTime100ns = (ULONG64)PsGetProcessCreateTimeQuadPart(process); /* Publish real object identity. */
    if ((Request->expectedCreateTime100ns && Request->expectedCreateTime100ns != Response->processCreateTime100ns) ||
        (Request->cursor && !Request->expectedCreateTime100ns)) { Response->status = KSWORD_ARK_MODULE_STATUS_INVALID; Response->lastStatus = STATUS_INVALID_CID; goto Exit; } /* Reject PID reuse and unbound continuation. */
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) { Response->lastStatus = STATUS_PROCESS_IS_TERMINATING; goto Exit; } /* Do not scan an exited object. */
    if (cursor >= upper) { Response->status = KSWORD_ARK_MODULE_STATUS_INVALID; Response->lastStatus = STATUS_INVALID_PARAMETER; goto Exit; } /* Reject kernel or wrapped addresses. */
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &handle); /* Open the exact referenced object. */
    if (!NT_SUCCESS(status)) { Response->lastStatus = status; goto Exit; } /* Keep the original open failure. */
    Response->status = KSWORD_ARK_MODULE_STATUS_COMPLETE; /* Start complete until a condition disproves it. */
    Response->lastStatus = STATUS_SUCCESS; /* The scan has started. */
    while (cursor < upper) { /* Walk native virtual memory regions in ascending order. */
        KSW_MODULE_BASIC_INFORMATION basic; /* Query result, never a remote pointer. */
        SIZE_T returned = 0U; /* Native byte count. */
        ULONG64 base = 0ULL, next = 0ULL, allocation = 0ULL; /* Checked address arithmetic. */
        if (Response->visitedCount >= 65536UL || KeQueryInterruptTime() >= deadline) { Response->flags |= KSWORD_ARK_MODULE_FLAG_SCAN_BUDGET; if (cursor) { Response->flags |= KSWORD_ARK_MODULE_FLAG_MORE; Response->nextCursor = cursor; } if (row) { row->flags |= KSWORD_ARK_MODULE_ROW_SPAN_INCOMPLETE; } break; } /* Keep bounded work and a progressing continuation. */
        RtlZeroMemory(&basic, sizeof(basic)); /* Do not consume uninitialized native fields. */
        status = ZwQueryVirtualMemory(handle, (PVOID)(ULONG_PTR)cursor, 0UL, &basic, sizeof(basic), &returned); /* Query MemoryBasicInformation from R0. */
        if (!NT_SUCCESS(status) || returned < sizeof(basic)) { Response->lastStatus = NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status; if (cursor) { Response->flags |= KSWORD_ARK_MODULE_FLAG_MORE; Response->nextCursor = cursor; } if (row) { row->flags |= KSWORD_ARK_MODULE_ROW_SPAN_INCOMPLETE; } break; } /* Preserve failed position if it can be resumed. */
        ++Response->visitedCount; /* Count all visited regions, including gaps. */
        base = (ULONG64)(ULONG_PTR)basic.BaseAddress; /* Native region base. */
        allocation = (ULONG64)(ULONG_PTR)basic.AllocationBase; /* Stable mapping grouping key. */
        if (!basic.RegionSize || base > cursor || (ULONG64)basic.RegionSize > upper - base) { Response->lastStatus = STATUS_DATA_ERROR; if (cursor) { Response->flags |= KSWORD_ARK_MODULE_FLAG_MORE; Response->nextCursor = cursor; } if (row) { row->flags |= KSWORD_ARK_MODULE_ROW_SPAN_INCOMPLETE; } break; } /* Reject malformed or overflowing regions. */
        next = base + (ULONG64)basic.RegionSize; /* Compute the exclusive region end. */
        if (next <= cursor) { Response->lastStatus = STATUS_DATA_ERROR; if (cursor) { Response->flags |= KSWORD_ARK_MODULE_FLAG_MORE; Response->nextCursor = cursor; } if (row) { row->flags |= KSWORD_ARK_MODULE_ROW_SPAN_INCOMPLETE; } break; } /* Guarantee forward progress. */
        if (basic.Type == (ULONG)MEM_IMAGE && basic.State == (ULONG)MEM_COMMIT && allocation != 0ULL) { /* Only image mappings are modules in this view. */
            if (Request->filterBase && allocation != Request->filterBase) { cursor = next; break; } /* Exact query must not select a neighbouring image. */
            if (allocation != currentBase) { /* Start one row per consecutive allocation. */
                KSW_MODULE_NAME_BUFFER nameBuffer; /* Bounded returned section name. */
                if (Response->returnedCount >= Capacity) { Response->flags |= KSWORD_ARK_MODULE_FLAG_MORE; Response->nextCursor = cursor; break; } /* Resume at the next image. */
                row = &Response->entries[Response->returnedCount++]; /* Reserve one zeroed row. */
                currentBase = allocation; /* Retain allocation identity for region aggregation. */
                row->baseAddress = allocation; /* Report the observed allocation base. */
                RtlZeroMemory(&nameBuffer, sizeof(nameBuffer)); /* Start with no path. */
                returned = 0U; /* Clear native byte count. */
                status = ZwQueryVirtualMemory(handle, (PVOID)(ULONG_PTR)base, 2UL, &nameBuffer, sizeof(nameBuffer), &returned); /* Query mapped image name. */
                KswordModuleCopyPath(row, &nameBuffer, status); /* Bound and publish the name. */
                if (!(row->flags & KSWORD_ARK_MODULE_ROW_PATH_PRESENT) || (row->flags & KSWORD_ARK_MODULE_ROW_PATH_TRUNCATED)) { Response->flags |= KSWORD_ARK_MODULE_FLAG_PATH_UNAVAILABLE; } /* Path loss is a partial result. */
            } /* End new image allocation. */
            if (next >= allocation) { row->spanBytes = next - allocation; } /* Observed mapped span, not PE header size. */
        } else if (row && allocation == currentBase && allocation != 0ULL) { /* Reserved regions can separate image sections. */
            if (next >= allocation) { row->spanBytes = next - allocation; } /* Preserve the full observed allocation span. */
        } else if (Request->filterBase) { /* Exact-base query cannot cross allocation identity. */
            if (!row && allocation == Request->filterBase) { cursor = next; continue; } /* A reserved prefix can precede the image sections. */
            break; /* The target allocation has ended or is absent. */
        } /* End exact-base filtering. */
        cursor = next; /* Advance past the current native region. */
    } /* End bounded region walk. */
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) { Response->flags |= KSWORD_ARK_MODULE_FLAG_PROCESS_EXITED; Response->lastStatus = STATUS_PROCESS_IS_TERMINATING; } /* A post-scan exit invalidates completeness. */
    if (Response->flags || !NT_SUCCESS(Response->lastStatus)) { Response->status = Response->returnedCount ? KSWORD_ARK_MODULE_STATUS_PARTIAL : KSWORD_ARK_MODULE_STATUS_UNAVAILABLE; } /* Preserve partial data or an unavailable empty result. */
Exit:
    if (handle) { ZwClose(handle); } /* Close only our kernel handle. */
    ObDereferenceObject(process); /* Release the original process reference. */
}

/* METHOD_BUFFERED input and output overlap, therefore snapshot the request. */
NTSTATUS KswordARKKernelIoctlEnumModules(WDFDEVICE Device, WDFREQUEST Request,
    size_t InputBufferLength, size_t OutputBufferLength, size_t* BytesReturned)
{
    KSWORD_ARK_ENUM_MODULES_REQUEST snapshot; /* Preserve the input before clearing output. */
    KSWORD_ARK_ENUM_MODULES_RESPONSE* response = NULL; /* WDF output buffer. */
    PVOID input = NULL, output = NULL; /* WDF input and output views. */
    size_t inputBytes = 0U, outputBytes = 0U; /* Actual WDF buffer sizes. */
    ULONG capacity = 0UL, requested = 0UL; /* Safe response capacity. */
    NTSTATUS status = STATUS_SUCCESS; /* WDF transport status. */
    UNREFERENCED_PARAMETER(Device); UNREFERENCED_PARAMETER(InputBufferLength); UNREFERENCED_PARAMETER(OutputBufferLength); /* WDF already owns lengths. */
    if (!BytesReturned) { return STATUS_INVALID_PARAMETER; } /* Completion size is mandatory. */
    *BytesReturned = 0U; /* Failure never publishes stale bytes. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_INVALID_DEVICE_STATE; } /* Both sources can page. */
    status = KswordARKRetrieveRequiredInputBuffer(Request, sizeof(snapshot), &input, &inputBytes); /* Validate full request. */
    if (!NT_SUCCESS(status)) { return status; } /* Preserve transport failure. */
    RtlCopyMemory(&snapshot, input, sizeof(snapshot)); /* Snapshot shared METHOD_BUFFERED input. */
    if (snapshot.size != sizeof(snapshot) || snapshot.version != KSWORD_ARK_MODULE_PROTOCOL_VERSION || snapshot.reserved ||
        (snapshot.source != KSWORD_ARK_MODULE_SOURCE_KERNEL_SNAPSHOT && snapshot.source != KSWORD_ARK_MODULE_SOURCE_PROCESS_IMAGE_MAP) ||
        (snapshot.cursor && snapshot.filterBase) ||
        (snapshot.source == KSWORD_ARK_MODULE_SOURCE_KERNEL_SNAPSHOT && (snapshot.processId || snapshot.expectedCreateTime100ns)) ||
        (snapshot.source == KSWORD_ARK_MODULE_SOURCE_PROCESS_IMAGE_MAP && !snapshot.processId)) { return STATUS_INVALID_PARAMETER; } /* Enforce the protocol contract. */
    status = KswordARKRetrieveRequiredOutputBuffer(Request, KSWORD_ARK_ENUM_MODULES_RESPONSE_HEADER_SIZE, &output, &outputBytes); /* Validate response header capacity. */
    if (!NT_SUCCESS(status)) { return status; } /* Preserve transport failure. */
    requested = snapshot.maxRows ? snapshot.maxRows : KSWORD_ARK_MODULE_DEFAULT_ROWS; /* Apply documented default. */
    if (requested > KSWORD_ARK_MODULE_MAX_ROWS) { return STATUS_INVALID_PARAMETER; } /* Reject excess budgets. */
    capacity = (ULONG)((outputBytes - KSWORD_ARK_ENUM_MODULES_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_MODULE_ENTRY)); /* Bound rows by actual buffer. */
    if (capacity > requested) { capacity = requested; } /* Respect caller's row limit. */
    if (!capacity) { return STATUS_BUFFER_TOO_SMALL; } /* A zero-row buffer cannot progress. */
    RtlZeroMemory(output, outputBytes); /* Clear output only after snapshotting input. */
    response = (KSWORD_ARK_ENUM_MODULES_RESPONSE*)output; /* Interpret validated output. */
    response->version = KSWORD_ARK_MODULE_PROTOCOL_VERSION; response->source = snapshot.source; response->entrySize = sizeof(KSWORD_ARK_MODULE_ENTRY); /* Publish schema. */
    response->status = KSWORD_ARK_MODULE_STATUS_UNAVAILABLE; response->lastStatus = STATUS_NOT_SUPPORTED; /* Fail closed by default. */
    if (snapshot.source == KSWORD_ARK_MODULE_SOURCE_KERNEL_SNAPSHOT) { KswordModuleKernel(&snapshot, response, capacity); } else { KswordModuleProcess(&snapshot, response, capacity); } /* Select explicit R0 source. */
    response->size = (ULONG)(KSWORD_ARK_ENUM_MODULES_RESPONSE_HEADER_SIZE + (size_t)response->returnedCount * sizeof(KSWORD_ARK_MODULE_ENTRY)); /* Publish exact used size. */
    *BytesReturned = response->size; /* Complete only initialized bytes. */
    return STATUS_SUCCESS; /* Protocol status carries source failures. */
}
