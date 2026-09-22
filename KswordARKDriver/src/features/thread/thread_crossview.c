/*++

Module Name:

    thread_crossview.c

Abstract:

    Read-only thread cross-view evidence collection for orphan/list/CID
    diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "thread_crossview.h"
#include "..\kernel\hook_scan_support.h"
#include "..\kernel\object_header_fallback.h"
#include "..\..\dispatch\ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_THREAD_CROSSVIEW_TAG 'vTsK'
#define KSW_THREAD_CROSSVIEW_VISIT_TAG 'tVsK'
#define KSW_THREAD_CROSSVIEW_HEADER_SIZE \
    (sizeof(KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW))

#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

typedef PEPROCESS(NTAPI* KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_FN)(
    _In_opt_ PEPROCESS Process
    );

typedef PETHREAD(NTAPI* KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_THREAD_FN)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
    );

typedef struct _KSW_THREAD_CROSSVIEW_VISITED_SET
{
    ULONG_PTR* Items;
    ULONG Count;
    ULONG Capacity;
} KSW_THREAD_CROSSVIEW_VISITED_SET, *PKSW_THREAD_CROSSVIEW_VISITED_SET;

typedef struct _KSW_THREAD_CROSSVIEW_CONTEXT
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* Rows;
    ULONG RowCount;
    ULONG RowCapacity;
    ULONG Flags;
    ULONG ProcessId;
    ULONG StartTid;
    ULONG EndTid;
    ULONG MaxNodes;
    ULONG64 MissingCapabilityMask;
    NTSTATUS LastStatus;
    NTSTATUS ModuleStatus;
    BOOLEAN Truncated;
    BOOLEAN CapabilityMissing;
    BOOLEAN PublicProcessWalkComplete;
    KSW_DYN_STATE DynState;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS FieldOffsets;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo;
    ULONG ModuleInfoBytes;
    KSW_THREAD_CROSSVIEW_VISITED_SET ProcessSeen;
} KSW_THREAD_CROSSVIEW_CONTEXT, *PKSW_THREAD_CROSSVIEW_CONTEXT;

NTSYSAPI
PEPROCESS
NTAPI
PsGetThreadProcess(
    _In_ PETHREAD Thread
    );

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
    );

extern POBJECT_TYPE* PsThreadType;

static NTSTATUS
KswordARKThreadCrossViewReadCidFields(
    _In_ const KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ const VOID* ThreadObject,
    _Out_ ULONG* ProcessIdOut,
    _Out_ ULONG* ThreadIdOut
    );

static PVOID
KswordARKThreadCrossViewAllocate(
    _In_ SIZE_T BufferBytes,
    _In_ ULONG Tag
    )
/*++

Routine Description:

    Allocate a transient nonpaged buffer for one thread cross-view query.

Arguments:

    BufferBytes - Requested byte count.
    Tag - Pool tag for diagnostics.

Return Value:

    Allocation pointer on success; NULL for invalid size or allocation failure.

--*/
{
    if (BufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, BufferBytes, Tag);
#pragma warning(pop)
}

static VOID
KswordARKThreadCrossViewFree(
    _In_opt_ PVOID Buffer,
    _In_ ULONG Tag
    )
/*++

Routine Description:

    Free a transient thread cross-view allocation.

Arguments:

    Buffer - Optional allocation pointer.
    Tag - Pool tag used at allocation time.

Return Value:

    None.

--*/
{
    if (Buffer != NULL) {
        ExFreePoolWithTag(Buffer, Tag);
    }
}

static VOID
KswordARKThreadCrossViewFormatDetail(
    _Out_writes_bytes_(DestinationBytes) CHAR* Destination,
    _In_ SIZE_T DestinationBytes,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format a bounded ANSI detail string for one thread evidence row.

Arguments:

    Destination - Output protocol detail field.
    DestinationBytes - Size of Destination in bytes.
    FormatText - printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. The destination remains NUL-terminated when valid.

--*/
{
    va_list arguments;

    if (Destination == NULL || DestinationBytes == 0U) {
        return;
    }
    Destination[0] = '\0';
    if (FormatText == NULL) {
        return;
    }

    va_start(arguments, FormatText);
    (VOID)RtlStringCbVPrintfA(Destination, DestinationBytes, FormatText, arguments);
    va_end(arguments);
    Destination[DestinationBytes - 1U] = '\0';
}

static VOID
KswordARKThreadCrossViewCopyImageName(
    _Out_writes_all_(16) CHAR Destination[16],
    _In_opt_ PEPROCESS ProcessObject
    )
/*++

Routine Description:

    Copy the owning process image name into a fixed 16-byte thread row field.

Arguments:

    Destination - Output image-name field.
    ProcessObject - Optional owning process object.

Return Value:

    None. The destination is zero-filled when input is unavailable.

--*/
{
    const CHAR* source = NULL;
    ULONG index = 0UL;

    if (Destination == NULL) {
        return;
    }
    RtlZeroMemory(Destination, 16U);
    if (ProcessObject == NULL) {
        return;
    }

    __try {
        source = PsGetProcessImageFileName(ProcessObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        source = NULL;
    }
    if (source == NULL) {
        return;
    }

    for (index = 0UL; index < 15UL; ++index) {
        Destination[index] = source[index];
        if (source[index] == '\0') {
            break;
        }
    }
    Destination[15] = '\0';
}

static ULONG
KswordARKThreadCrossViewNormalizeMaxNodes(
    _In_ ULONG RequestedMaxNodes
    )
/*++

Routine Description:

    Normalize the request node budget to default and hard-cap values.

Arguments:

    RequestedMaxNodes - Raw caller value.

Return Value:

    Effective node budget for bounded traversals.

--*/
{
    if (RequestedMaxNodes == 0UL) {
        return KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;
    }
    if (RequestedMaxNodes > KSWORD_ARK_CROSSVIEW_HARD_MAX_NODES) {
        return KSWORD_ARK_CROSSVIEW_HARD_MAX_NODES;
    }
    return RequestedMaxNodes;
}

static KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_FN
KswordARKThreadCrossViewResolvePsGetNextProcess(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetNextProcess dynamically for public process walking.

Arguments:

    None.

Return Value:

    Function pointer when available; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}

static KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_THREAD_FN
KswordARKThreadCrossViewResolvePsGetNextProcessThread(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetNextProcessThread dynamically for public thread walking.

Arguments:

    None.

Return Value:

    Function pointer when available; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_THREAD_FN)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
KswordARKThreadCrossViewVisitedInitialize(
    _Out_ KSW_THREAD_CROSSVIEW_VISITED_SET* Visited,
    _In_ ULONG MaxNodes
    )
/*++

Routine Description:

    Allocate a visited-address set for thread-list loop detection.

Arguments:

    Visited - Output visited set.
    MaxNodes - Maximum list entries that can be recorded.

Return Value:

    STATUS_SUCCESS or validation/allocation status.

--*/
{
    SIZE_T bytes = 0U;

    if (Visited == NULL || MaxNodes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Visited, sizeof(*Visited));
    bytes = (SIZE_T)MaxNodes * sizeof(ULONG_PTR);
    if ((bytes / sizeof(ULONG_PTR)) != (SIZE_T)MaxNodes) {
        return STATUS_INTEGER_OVERFLOW;
    }

    Visited->Items = (ULONG_PTR*)KswordARKThreadCrossViewAllocate(bytes, KSW_THREAD_CROSSVIEW_VISIT_TAG);
    if (Visited->Items == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Visited->Items, bytes);
    Visited->Capacity = MaxNodes;
    return STATUS_SUCCESS;
}

static VOID
KswordARKThreadCrossViewVisitedDestroy(
    _Inout_ KSW_THREAD_CROSSVIEW_VISITED_SET* Visited
    )
/*++

Routine Description:

    Free a visited-address set.

Arguments:

    Visited - Mutable set descriptor to clear.

Return Value:

    None.

--*/
{
    if (Visited == NULL) {
        return;
    }

    KswordARKThreadCrossViewFree(Visited->Items, KSW_THREAD_CROSSVIEW_VISIT_TAG);
    RtlZeroMemory(Visited, sizeof(*Visited));
}

static BOOLEAN
KswordARKThreadCrossViewVisitedCheckAndAdd(
    _Inout_ KSW_THREAD_CROSSVIEW_VISITED_SET* Visited,
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    Check and record a thread-list entry address for loop detection.

Arguments:

    Visited - Mutable visited set.
    Address - Candidate LIST_ENTRY address.

Return Value:

    TRUE when Address was already seen or the set is full; FALSE when newly
    added.

--*/
{
    ULONG index = 0UL;

    if (Visited == NULL || Visited->Items == NULL || Address == 0U) {
        return TRUE;
    }

    for (index = 0UL; index < Visited->Count; ++index) {
        if (Visited->Items[index] == Address) {
            return TRUE;
        }
    }

    if (Visited->Count >= Visited->Capacity) {
        return TRUE;
    }

    Visited->Items[Visited->Count] = Address;
    Visited->Count += 1UL;
    return FALSE;
}

static VOID
KswordARKThreadCrossViewRecordProcessSeen(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Record one process ID observed by the public process walk for orphan checks.

Arguments:

    Context - Query context.
    ProcessId - PID observed by the public walk.

Return Value:

    None.

--*/
{
    if (Context == NULL || ProcessId == 0UL) {
        return;
    }

    (VOID)KswordARKThreadCrossViewVisitedCheckAndAdd(&Context->ProcessSeen, (ULONG_PTR)ProcessId);
}

static BOOLEAN
KswordARKThreadCrossViewHasProcessSeen(
    _In_ const KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Test whether a PID was seen during the public process walk.

Arguments:

    Context - Query context containing ProcessSeen.
    ProcessId - PID to test.

Return Value:

    TRUE when the PID was seen; otherwise FALSE.

--*/
{
    ULONG index = 0UL;

    if (Context == NULL || Context->ProcessSeen.Items == NULL || ProcessId == 0UL) {
        return FALSE;
    }

    for (index = 0UL; index < Context->ProcessSeen.Count; ++index) {
        if (Context->ProcessSeen.Items[index] == (ULONG_PTR)ProcessId) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
KswordARKThreadCrossViewTidInRequest(
    _In_ const KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG ThreadId
    )
/*++

Routine Description:

    Apply optional TID range filtering from the request.

Arguments:

    Context - Query context containing start/end TID.
    ThreadId - Candidate TID.

Return Value:

    TRUE when ThreadId should be included; otherwise FALSE.

--*/
{
    if (Context == NULL) {
        return FALSE;
    }
    if (Context->StartTid != 0UL && ThreadId < Context->StartTid) {
        return FALSE;
    }
    if (Context->EndTid != 0UL && ThreadId > Context->EndTid) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKThreadCrossViewProcessInRequest(
    _In_ const KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Apply the optional owning PID filter from the request.

Arguments:

    Context - Query context containing the PID filter.
    ProcessId - Candidate owning PID.

Return Value:

    TRUE when ProcessId should be included; otherwise FALSE.

--*/
{
    if (Context == NULL) {
        return FALSE;
    }
    return (Context->ProcessId == 0UL || Context->ProcessId == ProcessId) ? TRUE : FALSE;
}

static KSWORD_ARK_THREAD_CROSSVIEW_ROW*
KswordARKThreadCrossViewFindRow(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG64 ObjectAddress,
    _In_ ULONG ThreadId
    )
/*++

Routine Description:

    Locate an existing thread evidence row by ETHREAD address or TID fallback.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate ETHREAD address.
    ThreadId - Candidate TID.

Return Value:

    Existing row pointer when found; otherwise NULL.

--*/
{
    ULONG index = 0UL;

    if (Context == NULL || Context->Rows == NULL) {
        return NULL;
    }

    for (index = 0UL; index < Context->RowCount; ++index) {
        KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = &Context->Rows[index];
        if (ObjectAddress != 0ULL && row->objectAddress == ObjectAddress) {
            return row;
        }
        if (ObjectAddress == 0ULL && ThreadId != 0UL && row->threadId == ThreadId) {
            return row;
        }
    }

    return NULL;
}

static KSWORD_ARK_THREAD_CROSSVIEW_ROW*
KswordARKThreadCrossViewGetOrCreateRow(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG64 ObjectAddress,
    _In_ ULONG ThreadId
    )
/*++

Routine Description:

    Return an existing row or append a new internal row when capacity permits.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate ETHREAD address.
    ThreadId - Candidate TID.

Return Value:

    Mutable row pointer, or NULL when capacity is exhausted.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;

    row = KswordARKThreadCrossViewFindRow(Context, ObjectAddress, ThreadId);
    if (row != NULL) {
        return row;
    }

    if (Context == NULL || Context->Rows == NULL || Context->RowCount >= Context->RowCapacity) {
        if (Context != NULL) {
            Context->Truncated = TRUE;
            Context->LastStatus = STATUS_BUFFER_OVERFLOW;
        }
        return NULL;
    }

    row = &Context->Rows[Context->RowCount];
    RtlZeroMemory(row, sizeof(*row));
    row->objectAddress = ObjectAddress;
    row->threadId = ThreadId;
    row->dynDataCapabilityMask = Context->DynState.CapabilityMask;
    row->fieldOffsets = Context->FieldOffsets;
    row->lastStatus = STATUS_SUCCESS;
    row->publicWalkStatus = STATUS_NOT_FOUND;
    row->threadListStatus = STATUS_NOT_FOUND;
    row->cidTableStatus = STATUS_NOT_FOUND;
    row->startAddressStatus = STATUS_NOT_FOUND;
    row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK;
    Context->RowCount += 1UL;
    return row;
}

static VOID
KswordARKThreadCrossViewApplyDetailStatus(
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_ROW* Row,
    _In_ NTSTATUS SourceStatus,
    _In_ BOOLEAN UnsupportedField
    )
/*++

Routine Description:

    Update row-level partial, unsupported, and read-failure detail flags from one
    collector branch without inferring undocumented thread termination state.

Arguments:

    Row - Mutable thread evidence row.
    SourceStatus - NTSTATUS produced by the guarded source path.
    UnsupportedField - TRUE when the collector intentionally skipped private
        field access because DynData did not provide the PDB offset.

Return Value:

    None. The row is annotated in place.

--*/
{
    if (Row == NULL) {
        return;
    }

    if (UnsupportedField) {
        Row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_UNSUPPORTED;
        Row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_UNSUPPORTED_PDB_FIELD;
        return;
    }

    if (!NT_SUCCESS(SourceStatus)) {
        Row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
        if (SourceStatus == STATUS_PROCEDURE_NOT_FOUND) {
            Row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_UNSUPPORTED;
            Row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_UNSUPPORTED_PDB_FIELD;
        }
        else {
            Row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_READ_FAILED;
            Row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_READ_FAILURE;
        }
    }
}

static VOID
KswordARKThreadCrossViewRecordSourceEvidence(
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_ROW* Row,
    _In_ ULONG SourceMask,
    _In_ ULONG SourceProcessId,
    _In_ ULONG SourceThreadId,
    _In_ NTSTATUS SourceStatus
    )
/*++

Routine Description:

    Store per-source PID/TID/status values for public walk, ThreadListHead, and
    PspCidTable evidence.

Arguments:

    Row - Mutable thread evidence row.
    SourceMask - Single KSWORD_ARK_CROSSVIEW_SOURCE_* bit being merged.
    SourceProcessId - Process ID observed by that source.
    SourceThreadId - Thread ID observed by that source.
    SourceStatus - Status from the source collector branch.

Return Value:

    None. The source-specific evidence columns are updated in place.

--*/
{
    if (Row == NULL) {
        return;
    }

    if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) {
        Row->publicProcessId = SourceProcessId;
        Row->publicThreadId = SourceThreadId;
        Row->publicWalkStatus = SourceStatus;
    }
    if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0UL) {
        Row->threadListProcessId = SourceProcessId;
        Row->threadListThreadId = SourceThreadId;
        Row->threadListStatus = SourceStatus;
    }
    if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) {
        Row->cidTableProcessId = SourceProcessId;
        Row->cidTableThreadId = SourceThreadId;
        Row->cidTableStatus = SourceStatus;
    }

    KswordARKThreadCrossViewApplyDetailStatus(Row, SourceStatus, FALSE);
}

static VOID
KswordARKThreadCrossViewMergeThreadObject(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ PETHREAD ThreadObject,
    _In_ ULONG SourceMask,
    _In_ NTSTATUS SourceStatus,
    _In_ ULONG EvidenceProcessId,
    _In_ ULONG EvidenceThreadId,
    _In_opt_z_ PCSTR DetailText
    )
/*++

Routine Description:

    Merge one referenced ETHREAD into the thread evidence set.

Arguments:

    Context - Mutable query context.
    ThreadObject - Referenced thread object.
    SourceMask - KSWORD_ARK_CROSSVIEW_SOURCE_* bit for the evidence source.
    SourceStatus - Last read/reference status to record.
    EvidenceProcessId - PID observed by the source itself, or zero when absent.
    EvidenceThreadId - TID observed by the source itself, or zero when absent.
    DetailText - Optional detail text when the row has no detail yet.

Return Value:

    None.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;
    PEPROCESS processObject = NULL;
    ULONG processId = 0UL;
    ULONG threadId = 0UL;
    ULONG cidProcessId = 0UL;
    ULONG cidThreadId = 0UL;
    ULONG sourceProcessId = 0UL;
    ULONG sourceThreadId = 0UL;
    NTSTATUS cidStatus = STATUS_SUCCESS;

    if (Context == NULL || ThreadObject == NULL) {
        return;
    }

    processObject = PsGetThreadProcess(ThreadObject);
    if (processObject == NULL) {
        return;
    }

    threadId = HandleToULong(PsGetThreadId(ThreadObject));
    processId = HandleToULong(PsGetProcessId(processObject));
    sourceProcessId = (EvidenceProcessId != 0UL) ? EvidenceProcessId : processId;
    sourceThreadId = (EvidenceThreadId != 0UL) ? EvidenceThreadId : threadId;
    if ((!KswordARKThreadCrossViewProcessInRequest(Context, processId) &&
            !KswordARKThreadCrossViewProcessInRequest(Context, sourceProcessId)) ||
        (!KswordARKThreadCrossViewTidInRequest(Context, threadId) &&
            !KswordARKThreadCrossViewTidInRequest(Context, sourceThreadId))) {
        return;
    }

    row = KswordARKThreadCrossViewGetOrCreateRow(Context, (ULONG64)(ULONG_PTR)ThreadObject, threadId);
    if (row == NULL) {
        return;
    }

    row->sourceMask |= SourceMask;
    row->processId = processId;
    row->threadId = threadId;
    row->processObjectAddress = (ULONG64)(ULONG_PTR)processObject;
    row->lastStatus = SourceStatus;
    KswordARKThreadCrossViewCopyImageName(row->imageName, processObject);
    cidStatus = KswordARKThreadCrossViewReadCidFields(Context, ThreadObject, &cidProcessId, &cidThreadId);
    if (NT_SUCCESS(cidStatus)) {
        if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0UL) {
            sourceProcessId = (EvidenceProcessId != 0UL) ? EvidenceProcessId : cidProcessId;
            sourceThreadId = (EvidenceThreadId != 0UL) ? EvidenceThreadId : cidThreadId;
        }
        if (cidProcessId != processId || cidThreadId != threadId) {
            row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
            row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
            row->lastStatus = STATUS_DATA_ERROR;
        }
    }
    else if (cidStatus == STATUS_PROCEDURE_NOT_FOUND) {
        Context->CapabilityMissing = TRUE;
        Context->MissingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
        Context->LastStatus = cidStatus;
        row->lastStatus = cidStatus;
        KswordARKThreadCrossViewApplyDetailStatus(row, cidStatus, TRUE);
    }
    else {
        Context->LastStatus = cidStatus;
        row->lastStatus = cidStatus;
        KswordARKThreadCrossViewApplyDetailStatus(row, cidStatus, FALSE);
    }
    if ((EvidenceProcessId != 0UL && EvidenceProcessId != processId) ||
        (EvidenceThreadId != 0UL && EvidenceThreadId != threadId)) {
        row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
        row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
        row->lastStatus = STATUS_DATA_ERROR;
    }
    KswordARKThreadCrossViewRecordSourceEvidence(
        row,
        SourceMask,
        sourceProcessId,
        sourceThreadId,
        SourceStatus);
    if (DetailText != NULL && row->detail[0] == '\0') {
        KswordARKThreadCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", DetailText);
    }
}

static VOID
KswordARKThreadCrossViewMergeDanglingCandidate(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG64 ObjectAddress,
    _In_ ULONG ThreadId,
    _In_ ULONG ProcessId,
    _In_ ULONG SourceMask,
    _In_ NTSTATUS SourceStatus,
    _In_z_ PCSTR DetailText
    )
/*++

Routine Description:

    Merge a thread candidate that matched a source but could not be safely
    referenced.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate ETHREAD address.
    ThreadId - Candidate TID.
    ProcessId - Candidate owning PID.
    SourceMask - Evidence source bit.
    SourceStatus - Reference/read failure status.
    DetailText - Human-readable reason for the dangling classification.

Return Value:

    None.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;

    if (Context == NULL || ObjectAddress == 0ULL) {
        return;
    }
    if (!KswordARKThreadCrossViewProcessInRequest(Context, ProcessId) ||
        !KswordARKThreadCrossViewTidInRequest(Context, ThreadId)) {
        return;
    }

    row = KswordARKThreadCrossViewGetOrCreateRow(Context, ObjectAddress, ThreadId);
    if (row == NULL) {
        return;
    }

    row->sourceMask |= SourceMask;
    row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT;
    row->denoiseFlags |=
        KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE |
        KSWORD_ARK_CROSSVIEW_DENOISE_REFERENCE_FAILURE |
        KSWORD_ARK_CROSSVIEW_DENOISE_POSSIBLE_TERMINATING;
    row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_PARTIAL;
    row->processId = ProcessId;
    row->lastStatus = SourceStatus;
    KswordARKThreadCrossViewRecordSourceEvidence(
        row,
        SourceMask,
        ProcessId,
        ThreadId,
        SourceStatus);
    if (row->detail[0] == '\0') {
        KswordARKThreadCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", DetailText);
    }
}

static NTSTATUS
KswordARKThreadCrossViewTryReferenceTypedObject(
    _In_ PVOID CandidateObject,
    _In_ HANDLE CandidateId,
    _In_opt_ POBJECT_TYPE ExpectedObjectType,
    _Out_ BOOLEAN* TypeMatchedOut,
    _Out_ BOOLEAN* ReferencedOut
    )
/*++

Routine Description:

    Validate a decoded thread object by type and attempt a balanced reference.

Arguments:

    CandidateObject - Decoded thread object body pointer.
    CandidateId - ID observed from the source, used for a protected lookup.
    ExpectedObjectType - Required object type, such as PsThreadType.
    TypeMatchedOut - Receives whether ObGetObjectType matched ExpectedObjectType.
    ReferencedOut - Receives whether the reference was taken.

Return Value:

    STATUS_SUCCESS when a reference was taken; otherwise a validation or read
    status.

    A failed ID lookup or pointer comparison does not establish object lifetime.
    TypeMatchedOut remains only a guarded type observation on such a failure;
    retain unconfirmed evidence without dereferencing CandidateObject.

--*/
{
    POBJECT_TYPE objectType = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (TypeMatchedOut == NULL || ReferencedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TypeMatchedOut = FALSE;
    *ReferencedOut = FALSE;

    if (CandidateObject == NULL || ExpectedObjectType == NULL ||
        !KswordARKCrossViewPointerAligned((ULONG_PTR)CandidateObject)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        objectType = ObGetObjectType(CandidateObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (objectType != ExpectedObjectType) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    *TypeMatchedOut = TRUE;

    /* The type read is observational. Only a matching ID-based reference
       establishes storage lifetime; a failed lookup remains read-only evidence. */
    status = KswordARKObjectHeaderReferenceObjectSafe(
        CandidateObject, CandidateId, ExpectedObjectType);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Re-read the type now that deletion is blocked, so a body recycled between
    // the first read and the reference cannot be reported as a thread.
    //
    __try {
        objectType = ObGetObjectType(CandidateObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        objectType = NULL;
    }
    if (objectType != ExpectedObjectType) {
        ObDereferenceObject(CandidateObject);
        *TypeMatchedOut = FALSE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    *ReferencedOut = TRUE;
    return status;
}

static ULONG
KswordARKThreadCrossViewFlagsForProcess(
    _In_ const KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ PEPROCESS ProcessObject
    )
/*++

Routine Description:

    Derive thread cross-view flags from owner-process visibility.

Arguments:

    Context - Query context.
    ProcessObject - Owning process object.

Return Value:

    Thread flag bits for owner-process-hidden evidence.

--*/
{
    ULONG flags = KSWORD_ARK_THREAD_FLAG_KERNEL_ENUMERATED;
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ProcessObject);
    return flags;
}

static NTSTATUS
KswordARKThreadCrossViewReadCidFields(
    _In_ const KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ const VOID* ThreadObject,
    _Out_ ULONG* ProcessIdOut,
    _Out_ ULONG* ThreadIdOut
    )
/*++

Routine Description:

    Read ETHREAD.Cid.UniqueProcess and UniqueThread through DynData offsets with
    guarded reads.

Arguments:

    Context - Query context containing EtCid offset.
    ThreadObject - ETHREAD candidate address.
    ProcessIdOut - Receives UniqueProcess as ULONG.
    ThreadIdOut - Receives UniqueThread as ULONG.

Return Value:

    STATUS_SUCCESS on success, or capability/read status.

--*/
{
    PVOID processIdValue = NULL;
    PVOID threadIdValue = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Context == NULL || ThreadObject == NULL || ProcessIdOut == NULL || ThreadIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessIdOut = 0UL;
    *ThreadIdOut = 0UL;
    if (!KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EtCid)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = KswordARKCrossViewReadPointerAddress(
        (const UCHAR*)ThreadObject + Context->DynState.Kernel.EtCid,
        &processIdValue);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKCrossViewReadPointerAddress(
        (const UCHAR*)ThreadObject + Context->DynState.Kernel.EtCid + sizeof(PVOID),
        &threadIdValue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *ProcessIdOut = HandleToULong(processIdValue);
    *ThreadIdOut = HandleToULong(threadIdValue);
    return STATUS_SUCCESS;
}

static VOID
KswordARKThreadCrossViewPopulateStartAddress(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_ROW* Row,
    _In_ PETHREAD ThreadObject
    )
/*++

Routine Description:

    Read ETHREAD start-address evidence and optionally classify kernel-range
    starts against the loaded module snapshot.

Arguments:

    Context - Query context containing DynData and optional module snapshot.
    Row - Mutable thread evidence row.
    ThreadObject - Referenced ETHREAD object.

Return Value:

    None. Read failures update Row->lastStatus and detail.

--*/
{
    PVOID startAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Context == NULL || Row == NULL || ThreadObject == NULL) {
        return;
    }

    status = KswordARKCrossViewReadPointerField(
        ThreadObject,
        Context->DynState.Kernel.EtStartAddress,
        &startAddress);
    if (!NT_SUCCESS(status) && KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EtWin32StartAddress)) {
        status = KswordARKCrossViewReadPointerField(
            ThreadObject,
            Context->DynState.Kernel.EtWin32StartAddress,
            &startAddress);
    }

    if (!NT_SUCCESS(status)) {
        Row->lastStatus = status;
        Row->startAddressStatus = status;
        KswordARKThreadCrossViewApplyDetailStatus(
            Row,
            status,
            (status == STATUS_PROCEDURE_NOT_FOUND) ? TRUE : FALSE);
        if (Row->detail[0] == '\0') {
            KswordARKThreadCrossViewFormatDetail(
                Row->detail,
                sizeof(Row->detail),
                "Start address unavailable, status=0x%08lX.",
                (ULONG)status);
        }
        return;
    }

    Row->startAddress = (ULONG64)(ULONG_PTR)startAddress;
    Row->startAddressStatus = STATUS_SUCCESS;
    if ((Context->Flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START) != 0UL &&
        startAddress != NULL &&
        (ULONG_PTR)startAddress >= (ULONG_PTR)MmSystemRangeStart) {
        const KSW_HOOK_SYSTEM_MODULE_ENTRY* ownerModule =
            KswordARKHookFindModuleForAddress(Context->ModuleInfo, (ULONG_PTR)startAddress);
        if (Context->ModuleInfo != NULL && ownerModule == NULL) {
            Row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE;
            Row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
            KswordARKThreadCrossViewFormatDetail(
                Row->detail,
                sizeof(Row->detail),
                "Kernel start address 0x%I64X is outside loaded module snapshot.",
                Row->startAddress);
        }
    }
}

static VOID
KswordARKThreadCrossViewMergeThreadObjectWithStart(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ PETHREAD ThreadObject,
    _In_ ULONG SourceMask,
    _In_ NTSTATUS SourceStatus,
    _In_ ULONG EvidenceProcessId,
    _In_ ULONG EvidenceThreadId,
    _In_opt_z_ PCSTR DetailText
    )
/*++

Routine Description:

    Merge a referenced ETHREAD and enrich the row with start-address evidence.

Arguments:

    Context - Mutable query context.
    ThreadObject - Referenced thread object.
    SourceMask - Evidence source bit.
    SourceStatus - Source read/reference status.
    EvidenceProcessId - PID observed by the source itself, or zero when absent.
    EvidenceThreadId - TID observed by the source itself, or zero when absent.
    DetailText - Optional row detail text.

Return Value:

    None.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;
    ULONG threadId = 0UL;

    if (Context == NULL || ThreadObject == NULL) {
        return;
    }

    threadId = HandleToULong(PsGetThreadId(ThreadObject));
    KswordARKThreadCrossViewMergeThreadObject(
        Context,
        ThreadObject,
        SourceMask,
        SourceStatus,
        EvidenceProcessId,
        EvidenceThreadId,
        DetailText);
    row = KswordARKThreadCrossViewFindRow(
        Context,
        (ULONG64)(ULONG_PTR)ThreadObject,
        threadId);
    if (row != NULL) {
        KswordARKThreadCrossViewPopulateStartAddress(Context, row, ThreadObject);
    }
}

static VOID
KswordARKThreadCrossViewCollectPublicWalk(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Collect public thread evidence through PsGetNextProcess and
    PsGetNextProcessThread. All process/thread references are released exactly
    once after use.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Failures are recorded in Context.

--*/
{
    KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_FN psGetNextProcess = NULL;
    KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_THREAD_FN psGetNextProcessThread = NULL;
    PEPROCESS processCursor = NULL;
    ULONG visitedThreads = 0UL;

    if (Context == NULL) {
        return;
    }

    psGetNextProcess = KswordARKThreadCrossViewResolvePsGetNextProcess();
    psGetNextProcessThread = KswordARKThreadCrossViewResolvePsGetNextProcessThread();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL) {
        Context->CapabilityMissing = TRUE;
        Context->LastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PETHREAD threadCursor = NULL;
        const ULONG processId = HandleToULong(PsGetProcessId(processCursor));

        KswordARKThreadCrossViewRecordProcessSeen(Context, processId);

        if (KswordARKThreadCrossViewProcessInRequest(Context, processId)) {
            threadCursor = psGetNextProcessThread(processCursor, NULL);
            while (threadCursor != NULL) {
                if (visitedThreads >= Context->MaxNodes) {
                    Context->Truncated = TRUE;
                    Context->LastStatus = STATUS_BUFFER_OVERFLOW;
                    /* No advance occurs on early termination. */
                    ObDereferenceObject(threadCursor);
                    threadCursor = NULL;
                    break;
                }
                visitedThreads += 1UL;

                KswordARKThreadCrossViewMergeThreadObjectWithStart(
                    Context,
                    threadCursor,
                    KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK,
                    STATUS_SUCCESS,
                    processId,
                    HandleToULong(PsGetThreadId(threadCursor)),
                    "Observed through PsGetNextProcessThread.");
                /* The enumerator consumes the current cursor reference. */
                threadCursor = psGetNextProcessThread(processCursor, threadCursor);
            }
        }

        if (Context->Truncated) {
            /* An aborted walk must release the still-owned current cursor. */
            ObDereferenceObject(processCursor);
            processCursor = NULL;
            break;
        }
        processCursor = psGetNextProcess(processCursor);
    }

    if (!Context->Truncated) {
        Context->PublicProcessWalkComplete = TRUE;
    }
}

static VOID
KswordARKThreadCrossViewCollectOneThreadList(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _In_ PEPROCESS ProcessObject,
    _Inout_ ULONG* WalkedThreads
    )
/*++

Routine Description:

    Walk EPROCESS.ThreadListHead for one process using DynData offsets, bounded
    traversal, loop detection, pointer alignment checks, and balanced object
    references.

Arguments:

    Context - Mutable query context.
    ProcessObject - Referenced process object from the public process walk.
    WalkedThreads - Shared node counter across all process thread lists.

Return Value:

    None. Failures are recorded in Context and row details.

--*/
{
    LIST_ENTRY* head = NULL;
    LIST_ENTRY* current = NULL;
    KSW_THREAD_CROSSVIEW_VISITED_SET visited;
    NTSTATUS status = STATUS_SUCCESS;

    if (Context == NULL || ProcessObject == NULL || WalkedThreads == NULL) {
        return;
    }
    RtlZeroMemory(&visited, sizeof(visited));

    status = KswordARKThreadCrossViewVisitedInitialize(&visited, Context->MaxNodes);
    if (!NT_SUCCESS(status)) {
        Context->LastStatus = status;
        return;
    }

    head = (LIST_ENTRY*)((PUCHAR)ProcessObject + Context->DynState.Kernel.EpThreadListHead);
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)head)) {
        Context->LastStatus = STATUS_DATATYPE_MISALIGNMENT;
        KswordARKThreadCrossViewVisitedDestroy(&visited);
        return;
    }

    status = KswordARKCrossViewReadPointerAddress(&head->Flink, (PVOID*)&current);
    if (!NT_SUCCESS(status)) {
        Context->LastStatus = status;
        KswordARKThreadCrossViewVisitedDestroy(&visited);
        return;
    }

    while (current != NULL && current != head) {
        LIST_ENTRY* next = NULL;
        LIST_ENTRY* blink = NULL;
        PVOID candidateThread = NULL;
        PVOID ownerProcessByField = NULL;
        ULONG cidProcessId = 0UL;
        ULONG cidThreadId = 0UL;
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        BOOLEAN linkMismatch = FALSE;
        NTSTATUS readStatus = STATUS_SUCCESS;
        NTSTATUS referenceStatus = STATUS_SUCCESS;

        if (*WalkedThreads >= Context->MaxNodes) {
            Context->Truncated = TRUE;
            Context->LastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        *WalkedThreads += 1UL;

        if (!KswordARKCrossViewPointerAligned((ULONG_PTR)current) ||
            KswordARKThreadCrossViewVisitedCheckAndAdd(&visited, (ULONG_PTR)current)) {
            Context->LastStatus = STATUS_DATATYPE_MISALIGNMENT;
            break;
        }

        readStatus = KswordARKCrossViewReadPointerAddress(&current->Flink, (PVOID*)&next);
        if (!NT_SUCCESS(readStatus)) {
            Context->LastStatus = readStatus;
            break;
        }
        readStatus = KswordARKCrossViewReadPointerAddress(&current->Blink, (PVOID*)&blink);
        if (!NT_SUCCESS(readStatus)) {
            Context->LastStatus = readStatus;
            break;
        }
        if (next != NULL && next != head) {
            LIST_ENTRY* nextBlink = NULL;
            NTSTATUS nextBlinkStatus = STATUS_SUCCESS;
            if (!KswordARKCrossViewPointerAligned((ULONG_PTR)next)) {
                linkMismatch = TRUE;
                Context->LastStatus = STATUS_DATATYPE_MISALIGNMENT;
            }
            else {
                nextBlinkStatus = KswordARKCrossViewReadPointerAddress(&next->Blink, (PVOID*)&nextBlink);
            }
            if (NT_SUCCESS(nextBlinkStatus) && nextBlink != current) {
                linkMismatch = TRUE;
            }
        }
        if (blink != NULL && blink != head) {
            LIST_ENTRY* blinkFlink = NULL;
            NTSTATUS blinkFlinkStatus = STATUS_SUCCESS;
            if (!KswordARKCrossViewPointerAligned((ULONG_PTR)blink)) {
                linkMismatch = TRUE;
                Context->LastStatus = STATUS_DATATYPE_MISALIGNMENT;
            }
            else {
                blinkFlinkStatus = KswordARKCrossViewReadPointerAddress(&blink->Flink, (PVOID*)&blinkFlink);
            }
            if (NT_SUCCESS(blinkFlinkStatus) && blinkFlink != current) {
                linkMismatch = TRUE;
            }
        }

        candidateThread = (PVOID)((PUCHAR)current - Context->DynState.Kernel.EtThreadListEntry);
        (VOID)KswordARKThreadCrossViewReadCidFields(
            Context, candidateThread, &cidProcessId, &cidThreadId);
        referenceStatus = KswordARKThreadCrossViewTryReferenceTypedObject(
            candidateThread,
            ULongToHandle(cidThreadId),
            (PsThreadType != NULL) ? *PsThreadType : NULL,
            &typeMatched,
            &referenced);

        if (referenced) {
            PETHREAD threadObject = (PETHREAD)candidateThread;
            KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = NULL;
            ULONG tid = HandleToULong(PsGetThreadId(threadObject));
            KswordARKThreadCrossViewMergeThreadObjectWithStart(
                Context,
                threadObject,
                KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST,
                linkMismatch ? STATUS_DATA_ERROR : STATUS_SUCCESS,
                0UL,
                0UL,
                linkMismatch ? "ThreadListHead blink/flink mismatch observed." : "Observed through EPROCESS.ThreadListHead.");
            row = KswordARKThreadCrossViewFindRow(Context, (ULONG64)(ULONG_PTR)threadObject, tid);
            if (row != NULL && PsGetThreadProcess(threadObject) != ProcessObject) {
                row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN;
                row->lastStatus = STATUS_DATA_ERROR;
                KswordARKThreadCrossViewFormatDetail(
                    row->detail,
                    sizeof(row->detail),
                    "Thread list owner process does not match ETHREAD owner.");
            }
            ObDereferenceObject(threadObject);
        }
        else if (typeMatched) {
            (VOID)KswordARKThreadCrossViewReadCidFields(Context, candidateThread, &cidProcessId, &cidThreadId);
            (VOID)KswordARKCrossViewReadPointerField(
                candidateThread,
                Context->DynState.Kernel.KtProcess,
                &ownerProcessByField);
            KswordARKThreadCrossViewMergeDanglingCandidate(
                Context,
                (ULONG64)(ULONG_PTR)candidateThread,
                cidThreadId,
                cidProcessId,
                KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST,
                referenceStatus,
                "ThreadListHead candidate type matched but could not be referenced.");
            if (ownerProcessByField != NULL && ownerProcessByField != ProcessObject) {
                KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = KswordARKThreadCrossViewFindRow(
                    Context,
                    (ULONG64)(ULONG_PTR)candidateThread,
                    cidThreadId);
                if (row != NULL) {
                    row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN;
                }
            }
        }

        current = next;
    }

    KswordARKThreadCrossViewVisitedDestroy(&visited);
}

static VOID
KswordARKThreadCrossViewCollectThreadLists(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Collect EPROCESS.ThreadListHead evidence for all public processes, without
    accepting any R3-provided object address.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Capability and traversal failures are recorded in Context.

--*/
{
    KSW_THREAD_CROSSVIEW_PS_GET_NEXT_PROCESS_FN psGetNextProcess = NULL;
    PEPROCESS processCursor = NULL;
    ULONG walkedThreads = 0UL;

    if (Context == NULL) {
        return;
    }

    if ((Context->DynState.CapabilityMask & KSW_CAP_THREAD_LIST_FIELDS) != KSW_CAP_THREAD_LIST_FIELDS ||
        !KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EpThreadListHead) ||
        !KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EtThreadListEntry) ||
        !KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EtCid) ||
        !KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.KtProcess) ||
        PsThreadType == NULL ||
        *PsThreadType == NULL) {
        Context->CapabilityMissing = TRUE;
        Context->MissingCapabilityMask |= KSW_CAP_THREAD_LIST_FIELDS;
        Context->LastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    psGetNextProcess = KswordARKThreadCrossViewResolvePsGetNextProcess();
    if (psGetNextProcess == NULL) {
        Context->CapabilityMissing = TRUE;
        Context->LastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        const ULONG processId = HandleToULong(PsGetProcessId(processCursor));
        if (KswordARKThreadCrossViewProcessInRequest(Context, processId)) {
            KswordARKThreadCrossViewCollectOneThreadList(Context, processCursor, &walkedThreads);
        }
        if (Context->Truncated) {
            /* An aborted walk must release the still-owned current cursor. */
            ObDereferenceObject(processCursor);
            processCursor = NULL;
            break;
        }
        processCursor = psGetNextProcess(processCursor);
    }
}

static VOID
KswordARKThreadCrossViewCidCallback(
    _In_ const KSW_CROSSVIEW_CID_ENTRY* Entry,
    _Inout_opt_ PVOID Context
    )
/*++

Routine Description:

    Merge one ETHREAD candidate reported by the read-only CID table walker.

Arguments:

    Entry - CID walker payload with a temporary reference when Referenced is TRUE.
    Context - KSW_THREAD_CROSSVIEW_CONTEXT owned by the query.

Return Value:

    None.

--*/
{
    KSW_THREAD_CROSSVIEW_CONTEXT* context = (KSW_THREAD_CROSSVIEW_CONTEXT*)Context;
    ULONG processId = 0UL;
    ULONG threadId = 0UL;

    if (context == NULL || Entry == NULL) {
        return;
    }

    if (Entry->Referenced && Entry->Object != NULL) {
        (VOID)KswordARKThreadCrossViewReadCidFields(context, Entry->Object, &processId, &threadId);
        UNREFERENCED_PARAMETER(threadId);
        KswordARKThreadCrossViewMergeThreadObjectWithStart(
            context,
            (PETHREAD)Entry->Object,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            Entry->ReferenceStatus,
            processId,
            Entry->CidValue,
            "Observed through PspCidTable.");
    }
    else if (Entry->TypeMatched) {
        PVOID candidateObject = Entry->Object;

        if (candidateObject == NULL) {
            candidateObject = (PVOID)(ULONG_PTR)Entry->ObjectAddress;
        }

        (VOID)KswordARKThreadCrossViewReadCidFields(context, candidateObject, &processId, &threadId);
        if (threadId == 0UL) {
            threadId = Entry->CidValue;
        }
        KswordARKThreadCrossViewMergeDanglingCandidate(
            context,
            Entry->ObjectAddress,
            threadId,
            processId,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            Entry->ReferenceStatus,
            "PspCidTable thread candidate type matched but could not be referenced.");
    }
}

static VOID
KswordARKThreadCrossViewCollectCidTable(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Collect thread evidence from PspCidTable using the shared read-only CID table
    walker.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Resolver and walk failures are stored in Context.

--*/
{
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingMask = 0ULL;
    BOOLEAN usedDynGlobal = FALSE;
    ULONG visitedEntries = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Context == NULL) {
        return;
    }

    /*
     * The shared CID walker already supplies bounded, read-only defaults for
     * HANDLE_TABLE.TableCode and HANDLE_TABLE_ENTRY.LowValue.  Keep the same
     * fallback contract as the process cross-view path instead of disabling
     * thread CID evidence merely because an exact PDB profile is absent.
     * Object-type validation remains mandatory before a decoded entry is
     * referenced.
     */
    if (PsThreadType == NULL || *PsThreadType == NULL) {
        Context->CapabilityMissing = TRUE;
        Context->MissingCapabilityMask |= KSW_CAP_CID_TABLE_WALK;
        Context->LastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    status = KswordARKCrossViewResolvePspCidTableAddress(
        &Context->DynState,
        &Context->FieldOffsets,
        &pspCidTableAddress,
        &missingMask,
        &usedDynGlobal);
    UNREFERENCED_PARAMETER(usedDynGlobal);
    if (!NT_SUCCESS(status) || pspCidTableAddress == NULL) {
        Context->CapabilityMissing = TRUE;
        Context->MissingCapabilityMask |= (missingMask != 0ULL) ? missingMask : KSW_CAP_CID_TABLE_WALK;
        Context->LastStatus = status;
        return;
    }

    status = KswordARKCrossViewWalkCidTable(
        &Context->DynState,
        pspCidTableAddress,
        *PsThreadType,
        Context->MaxNodes,
        KswordARKThreadCrossViewCidCallback,
        Context,
        &visitedEntries);
    UNREFERENCED_PARAMETER(visitedEntries);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_BUFFER_OVERFLOW) {
            Context->Truncated = TRUE;
        }
        else if (status == STATUS_PROCEDURE_NOT_FOUND) {
            Context->CapabilityMissing = TRUE;
            Context->MissingCapabilityMask |= KSW_CAP_CID_TABLE_WALK;
        }
        Context->LastStatus = status;
    }
}

static VOID
KswordARKThreadCrossViewFinalizeRows(
    _Inout_ KSW_THREAD_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Compute thread anomaly flags and confidence after all selected source views
    have been merged.

Arguments:

    Context - Mutable query context containing internal rows.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (Context == NULL || Context->Rows == NULL) {
        return;
    }

    for (index = 0UL; index < Context->RowCount; ++index) {
        KSWORD_ARK_THREAD_CROSSVIEW_ROW* row = &Context->Rows[index];
        const BOOLEAN hasPublic = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN hasThreadList = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0UL) ? TRUE : FALSE;
        const BOOLEAN hasCid = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) ? TRUE : FALSE;
        const BOOLEAN expectPublic =
            ((Context->Flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN expectThreadList =
            ((Context->Flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST) != 0UL &&
                (Context->MissingCapabilityMask & KSW_CAP_THREAD_LIST_FIELDS) == 0ULL) ? TRUE : FALSE;
        const BOOLEAN expectCid =
            ((Context->Flags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL &&
                (Context->MissingCapabilityMask & KSW_CAP_CID_TABLE_WALK) == 0ULL) ? TRUE : FALSE;

        row->dynDataCapabilityMask = Context->DynState.CapabilityMask;
        row->fieldOffsets = Context->FieldOffsets;

        if (expectCid && hasCid &&
            (!expectPublic || !hasPublic) &&
            (!expectThreadList || !hasThreadList)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY;
        }
        if (expectThreadList && hasThreadList &&
            (!expectPublic || !hasPublic) &&
            (!expectCid || !hasCid)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY;
        }
        if (expectThreadList && (hasPublic || hasCid) && !hasThreadList) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST;
        }
        if (expectCid && (hasPublic || hasThreadList) && !hasCid) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE;
        }
        if (row->processId == 0UL ||
            row->processObjectAddress == 0ULL ||
            (Context->PublicProcessWalkComplete &&
                !KswordARKThreadCrossViewHasProcessSeen(Context, row->processId))) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN;
        }

        if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) != 0UL) {
            row->confidence = 30UL;
        }
        else if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) != 0UL) {
            row->confidence = 55UL;
        }
        else if (hasPublic && hasThreadList && hasCid) {
            row->confidence = 98UL;
        }
        else if ((hasPublic && hasThreadList) || (hasPublic && hasCid) || (hasThreadList && hasCid)) {
            row->confidence = 80UL;
        }
        else {
            row->confidence = 60UL;
        }

        if (Context->CapabilityMissing || Context->Truncated) {
            row->denoiseFlags |= KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE;
            if (row->detailStatus == KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK) {
                row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_PARTIAL;
            }
        }

        if (row->detail[0] == '\0') {
            KswordARKThreadCrossViewFormatDetail(
                row->detail,
                sizeof(row->detail),
                "sources=0x%08lX anomalies=0x%08lX.",
                row->sourceMask,
                row->anomalyFlags);
        }
    }
}

static VOID
KswordARKThreadCrossViewCopyResponse(
    _Inout_ KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_ const KSW_THREAD_CROSSVIEW_CONTEXT* Context,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Copy internal thread rows into the caller response while preserving totalCount
    when output capacity is smaller than collected evidence.

Arguments:

    Response - Output response header and flexible row array.
    OutputBufferLength - Writable response byte count.
    Context - Finalized query context.
    BytesWrittenOut - Receives bytes written.

Return Value:

    None.

--*/
{
    size_t entryCapacity = 0U;
    ULONG copyCount = 0UL;

    if (Response == NULL || Context == NULL || BytesWrittenOut == NULL) {
        return;
    }

    entryCapacity = (OutputBufferLength - KSW_THREAD_CROSSVIEW_HEADER_SIZE) / sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
    copyCount = (Context->RowCount < (ULONG)entryCapacity) ? Context->RowCount : (ULONG)entryCapacity;

    Response->version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
    Response->entrySize = sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
    Response->totalCount = Context->RowCount;
    Response->returnedCount = copyCount;
    Response->dynDataCapabilityMask = Context->DynState.CapabilityMask;
    Response->missingCapabilityMask = Context->MissingCapabilityMask;
    Response->lastStatus = Context->LastStatus;
    Response->fieldOffsets = Context->FieldOffsets;

    if (Context->CapabilityMissing && Context->RowCount == 0UL) {
        Response->status = KSWORD_ARK_CROSSVIEW_STATUS_CAPABILITY_MISSING;
    }
    else if (Context->CapabilityMissing || Context->Truncated || copyCount < Context->RowCount) {
        Response->status = KSWORD_ARK_CROSSVIEW_STATUS_PARTIAL;
    }
    else if (!NT_SUCCESS(Context->LastStatus)) {
        Response->status = KSWORD_ARK_CROSSVIEW_STATUS_READ_FAILED;
    }
    else {
        Response->status = KSWORD_ARK_CROSSVIEW_STATUS_OK;
    }

    if (copyCount != 0UL) {
        RtlCopyMemory(Response->entries, Context->Rows, (SIZE_T)copyCount * sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW));
    }

    *BytesWrittenOut = KSW_THREAD_CROSSVIEW_HEADER_SIZE + ((size_t)copyCount * sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW));
}

NTSTATUS
KswordARKDriverQueryThreadCrossView(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_THREAD_CROSSVIEW_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Query read-only thread cross-view evidence from PsGetNextProcessThread,
    EPROCESS.ThreadListHead, and PspCidTable.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output byte count.
    Request - Optional thread cross-view request.
    BytesWrittenOut - Receives bytes written to OutputBuffer.

Return Value:

    STATUS_SUCCESS when the response header is written; validation/allocation
    status otherwise. Per-source failures are reported in the response fields.

--*/
{
    KSW_THREAD_CROSSVIEW_CONTEXT context;
    KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE* response = NULL;
    SIZE_T rowBytes = 0U;
    ULONG requestFlags = KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSW_THREAD_CROSSVIEW_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.LastStatus = STATUS_SUCCESS;
    context.ModuleStatus = STATUS_SUCCESS;
    context.MaxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;
    if (Request != NULL) {
        if (Request->flags != 0UL) {
            requestFlags = Request->flags;
        }
        context.ProcessId = Request->processId;
        context.StartTid = Request->startTid;
        context.EndTid = Request->endTid;
        context.MaxNodes = KswordARKThreadCrossViewNormalizeMaxNodes(Request->maxNodes);
    }
    context.Flags = requestFlags;
    context.RowCapacity = context.MaxNodes;

    rowBytes = (SIZE_T)context.RowCapacity * sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
    if ((rowBytes / sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW)) != (SIZE_T)context.RowCapacity) {
        return STATUS_INTEGER_OVERFLOW;
    }

    context.Rows = (KSWORD_ARK_THREAD_CROSSVIEW_ROW*)KswordARKThreadCrossViewAllocate(rowBytes, KSW_THREAD_CROSSVIEW_TAG);
    if (context.Rows == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context.Rows, rowBytes);
    RtlZeroMemory(&context.ProcessSeen, sizeof(context.ProcessSeen));
    context.ProcessSeen.Capacity = context.MaxNodes;
    context.ProcessSeen.Items = (ULONG_PTR*)KswordARKThreadCrossViewAllocate(
        (SIZE_T)context.MaxNodes * sizeof(ULONG_PTR),
        KSW_THREAD_CROSSVIEW_VISIT_TAG);
    if (context.ProcessSeen.Items == NULL) {
        KswordARKThreadCrossViewFree(context.Rows, KSW_THREAD_CROSSVIEW_TAG);
        context.Rows = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context.ProcessSeen.Items, (SIZE_T)context.MaxNodes * sizeof(ULONG_PTR));

    KswordARKDynDataSnapshot(&context.DynState);
    KswordARKCrossViewFillFieldOffsets(&context.DynState, &context.FieldOffsets);

    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START) != 0UL) {
        context.ModuleStatus = KswordARKHookBuildModuleSnapshot(&context.ModuleInfo, &context.ModuleInfoBytes);
        if (!NT_SUCCESS(context.ModuleStatus)) {
            context.LastStatus = context.ModuleStatus;
        }
    }

    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) {
        KswordARKThreadCrossViewCollectPublicWalk(&context);
    }
    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST) != 0UL) {
        KswordARKThreadCrossViewCollectThreadLists(&context);
    }
    if ((requestFlags & KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL) {
        KswordARKThreadCrossViewCollectCidTable(&context);
    }

    KswordARKThreadCrossViewFinalizeRows(&context);

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE*)OutputBuffer;
    KswordARKThreadCrossViewCopyResponse(response, OutputBufferLength, &context, BytesWrittenOut);

    if (context.ModuleInfo != NULL) {
        ExFreePoolWithTag(context.ModuleInfo, KSW_HOOK_SCAN_TAG);
        context.ModuleInfo = NULL;
    }
    KswordARKThreadCrossViewFree(context.ProcessSeen.Items, KSW_THREAD_CROSSVIEW_VISIT_TAG);
    context.ProcessSeen.Items = NULL;
    KswordARKThreadCrossViewFree(context.Rows, KSW_THREAD_CROSSVIEW_TAG);
    context.Rows = NULL;
    return status;
}

NTSTATUS
KswordARKThreadIoctlQueryCrossView(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle the unregistered thread cross-view IOCTL. The handler validates
    buffers only, accepts an optional fixed request, and invokes the read-only
    backend without write access or caller-supplied object addresses.

Arguments:

    Device - WDF device used only for signature parity with other handlers.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF retrieval.
    BytesReturned - Receives backend response bytes.

Return Value:

    NTSTATUS from buffer retrieval or KswordARKDriverQueryThreadCrossView.

--*/
{
    KSWORD_ARK_THREAD_CROSSVIEW_REQUEST* queryRequest = NULL;
    KSWORD_ARK_THREAD_CROSSVIEW_REQUEST defaultRequest;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    defaultRequest.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
    defaultRequest.flags = KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL;
    defaultRequest.maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_THREAD_CROSSVIEW_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    queryRequest = hasInput ? (KSWORD_ARK_THREAD_CROSSVIEW_REQUEST*)inputBuffer : &defaultRequest;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_THREAD_CROSSVIEW_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return KswordARKDriverQueryThreadCrossView(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
}
