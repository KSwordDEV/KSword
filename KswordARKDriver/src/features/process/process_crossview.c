/*++

Module Name:

    process_crossview.c

Abstract:

    Read-only process cross-view evidence collection for DKOM diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "process_crossview.h"
#include "..\kernel\hook_scan_support.h"
#include "..\..\dispatch\ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_PROCESS_CROSSVIEW_TAG 'vPsK'
#define KSW_CROSSVIEW_SHARED_TAG 'vCsK'
#define KSW_PROCESS_CROSSVIEW_HEADER_SIZE \
    (sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW))
#define KSW_CROSSVIEW_CID_TABLE_LEVEL_MASK 0x3ULL
#define KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT 256UL
#define KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT 512UL
#define KSW_CROSSVIEW_CID_ENTRY_BYTES 16ULL
#define KSW_CROSSVIEW_CID_HANDLE_VALUE_STRIDE 4ULL
#define KSW_CROSSVIEW_PSP_CID_SCAN_BYTES 0x180UL
#define KSW_CROSSVIEW_FALLBACK_HT_TABLE_CODE_OFFSET ((ULONG)sizeof(PVOID))
#define KSW_CROSSVIEW_FALLBACK_HTE_LOW_VALUE_OFFSET 0UL

#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

typedef PEPROCESS(NTAPI* KSW_CROSSVIEW_PS_GET_NEXT_PROCESS_FN)(
    _In_opt_ PEPROCESS Process
    );

typedef struct _KSW_CROSSVIEW_VISITED_SET
{
    ULONG_PTR* Items;
    ULONG Count;
    ULONG Capacity;
} KSW_CROSSVIEW_VISITED_SET, *PKSW_CROSSVIEW_VISITED_SET;

typedef struct _KSW_PROCESS_CROSSVIEW_CONTEXT
{
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* Rows;
    ULONG RowCount;
    ULONG RowCapacity;
    ULONG Flags;
    ULONG StartPid;
    ULONG EndPid;
    ULONG MaxNodes;
    ULONG64 MissingCapabilityMask;
    NTSTATUS LastStatus;
    BOOLEAN Truncated;
    BOOLEAN CapabilityMissing;
    KSW_DYN_STATE DynState;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS FieldOffsets;
} KSW_PROCESS_CROSSVIEW_CONTEXT, *PKSW_PROCESS_CROSSVIEW_CONTEXT;

typedef struct _KSW_CROSSVIEW_CID_WALK_CONTEXT
{
    const KSW_DYN_STATE* DynState;
    POBJECT_TYPE ExpectedObjectType;
    ULONG MaxNodes;
    ULONG VisitedEntries;
    ULONG ReportedEntries;
    NTSTATUS LastStatus;
    KSW_CROSSVIEW_CID_CALLBACK Callback;
    PVOID CallbackContext;
} KSW_CROSSVIEW_CID_WALK_CONTEXT, *PKSW_CROSSVIEW_CID_WALK_CONTEXT;

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTSYSAPI
HANDLE
NTAPI
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process
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

extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;
extern POBJECT_TYPE* PsProcessType;

static PVOID
KswordARKCrossViewAllocate(
    _In_ SIZE_T BufferBytes,
    _In_ ULONG Tag
    )
/*++

Routine Description:

    Allocate a transient nonpaged buffer for one cross-view query.

Arguments:

    BufferBytes - Requested byte count.
    Tag - Pool tag used for diagnostics.

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
KswordARKCrossViewFree(
    _In_opt_ PVOID Buffer,
    _In_ ULONG Tag
    )
/*++

Routine Description:

    Free a buffer allocated by the cross-view collector.

Arguments:

    Buffer - Optional allocation pointer.
    Tag - Pool tag used during allocation.

Return Value:

    None. NULL input is ignored.

--*/
{
    if (Buffer != NULL) {
        ExFreePoolWithTag(Buffer, Tag);
    }
}

BOOLEAN
KswordARKCrossViewOffsetPresent(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    Normalize DynData offset availability before private-field reads.

Arguments:

    Offset - Candidate offset from the DynData snapshot.

Return Value:

    TRUE when the offset is usable; otherwise FALSE.

--*/
{
    return (Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKCrossViewGlobalRvaPresent(
    _In_ ULONG Rva
    )
/*++

Routine Description:

    Check availability for DynData global RVAs. Unlike structure fields, RVA
    zero is not accepted for kernel globals in this collector.

Arguments:

    Rva - Candidate ntoskrnl-relative global RVA.

Return Value:

    TRUE when Rva is nonzero and not an unavailable sentinel.

--*/
{
    return (Rva != 0UL && Rva != KSW_DYN_OFFSET_UNAVAILABLE && Rva != 0x0000FFFFUL) ? TRUE : FALSE;
}

ULONG
KswordARKCrossViewNormalizeOffset(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    Convert internal DynData sentinels into the shared cross-view sentinel.

Arguments:

    Offset - Raw DynData offset.

Return Value:

    Offset when usable; KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE otherwise.

--*/
{
    return KswordARKCrossViewOffsetPresent(Offset) ? Offset : KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
}

BOOLEAN
KswordARKCrossViewPointerAligned(
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    Check pointer alignment before list, table, or object dereferences.

Arguments:

    Address - Candidate kernel pointer value.

Return Value:

    TRUE when Address is nonzero and pointer-size aligned; otherwise FALSE.

--*/
{
    if (Address == 0U) {
        return FALSE;
    }
    return ((Address & (sizeof(PVOID) - 1U)) == 0U) ? TRUE : FALSE;
}

static ULONG
KswordARKCrossViewEffectiveHtTableCodeOffset(
    _In_opt_ const KSW_DYN_STATE* DynState,
    _Out_opt_ BOOLEAN* UsedFallbackOut
    )
/*++

Routine Description:

    Pick the HANDLE_TABLE.TableCode offset used by the CID-table walker.
    中文说明：终止进程路径不能因为当前 DynData 缺少 HtTableCode 就回退到
    PsLookupProcessByProcessId；现代 x64 Windows 的 TableCode 位于
    HANDLE_TABLE + sizeof(PVOID)，这里作为只读兜底偏移。

Arguments:

    DynState - Optional DynData snapshot.
    UsedFallbackOut - Receives whether the built-in fallback offset was used.

Return Value:

    A bounded offset used only for reading the kernel-owned HANDLE_TABLE.

--*/
{
    if (UsedFallbackOut != NULL) {
        *UsedFallbackOut = FALSE;
    }
    if (DynState != NULL && KswordARKCrossViewOffsetPresent(DynState->Kernel.HtTableCode)) {
        return DynState->Kernel.HtTableCode;
    }
    if (UsedFallbackOut != NULL) {
        *UsedFallbackOut = TRUE;
    }
    return KSW_CROSSVIEW_FALLBACK_HT_TABLE_CODE_OFFSET;
}

static ULONG
KswordARKCrossViewEffectiveHteLowValueOffset(
    _In_opt_ const KSW_DYN_STATE* DynState,
    _Out_opt_ BOOLEAN* UsedFallbackOut
    )
/*++

Routine Description:

    Pick the HANDLE_TABLE_ENTRY.LowValue offset used by the CID-table walker.
    中文说明：LowValue 是 entry 起始字段；当 DynData 没带该字段时仍可只读
    解码 PspCidTable，避免再调用可被 hook 的 PID/TID lookup 兜底。

Arguments:

    DynState - Optional DynData snapshot.
    UsedFallbackOut - Receives whether the built-in fallback offset was used.

Return Value:

    A bounded offset inside one HANDLE_TABLE_ENTRY.

--*/
{
    if (UsedFallbackOut != NULL) {
        *UsedFallbackOut = FALSE;
    }
    if (DynState != NULL && KswordARKCrossViewOffsetPresent(DynState->Kernel.HteLowValue)) {
        return DynState->Kernel.HteLowValue;
    }
    if (UsedFallbackOut != NULL) {
        *UsedFallbackOut = TRUE;
    }
    return KSW_CROSSVIEW_FALLBACK_HTE_LOW_VALUE_OFFSET;
}

VOID
KswordARKCrossViewFillFieldOffsets(
    _In_ const KSW_DYN_STATE* DynState,
    _Out_ KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS* Offsets
    )
/*++

Routine Description:

    Copy relevant DynData offsets and the PspCidTable global into a protocol
    field-offset packet.

Arguments:

    DynState - Snapshot captured at query start.
    Offsets - Output protocol structure.

Return Value:

    None. Invalid inputs are ignored after zeroing the output when possible.

--*/
{
    if (Offsets == NULL) {
        return;
    }

    RtlZeroMemory(Offsets, sizeof(*Offsets));
    Offsets->epUniqueProcessId = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->epActiveProcessLinks = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->epThreadListHead = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->epImageFileName = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->etCid = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->etThreadListEntry = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->etStartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->etWin32StartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->ktProcess = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->htTableCode = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->hteLowValue = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->pspCidTableRva = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;

    if (DynState == NULL) {
        return;
    }

    Offsets->epUniqueProcessId = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EpUniqueProcessId);
    Offsets->epActiveProcessLinks = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EpActiveProcessLinks);
    Offsets->epThreadListHead = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EpThreadListHead);
    Offsets->epImageFileName = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EpImageFileName);
    Offsets->etCid = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EtCid);
    Offsets->etThreadListEntry = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EtThreadListEntry);
    Offsets->etStartAddress = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EtStartAddress);
    Offsets->etWin32StartAddress = KswordARKCrossViewNormalizeOffset(DynState->Kernel.EtWin32StartAddress);
    Offsets->ktProcess = KswordARKCrossViewNormalizeOffset(DynState->Kernel.KtProcess);
    Offsets->htTableCode = KswordARKCrossViewOffsetPresent(DynState->Kernel.HtTableCode)
        ? DynState->Kernel.HtTableCode
        : KSW_CROSSVIEW_FALLBACK_HT_TABLE_CODE_OFFSET;
    Offsets->hteLowValue = KswordARKCrossViewOffsetPresent(DynState->Kernel.HteLowValue)
        ? DynState->Kernel.HteLowValue
        : KSW_CROSSVIEW_FALLBACK_HTE_LOW_VALUE_OFFSET;
    Offsets->pspCidTableRva = KswordARKCrossViewGlobalRvaPresent(DynState->KernelGlobals.PspCidTable)
        ? DynState->KernelGlobals.PspCidTable
        : KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
    Offsets->epUniqueProcessIdSource = DynState->KernelSources.EpUniqueProcessId;
    Offsets->epActiveProcessLinksSource = DynState->KernelSources.EpActiveProcessLinks;
    Offsets->epThreadListHeadSource = DynState->KernelSources.EpThreadListHead;
    Offsets->epImageFileNameSource = DynState->KernelSources.EpImageFileName;
    Offsets->etCidSource = DynState->KernelSources.EtCid;
    Offsets->etThreadListEntrySource = DynState->KernelSources.EtThreadListEntry;
    Offsets->etStartAddressSource = DynState->KernelSources.EtStartAddress;
    Offsets->etWin32StartAddressSource = DynState->KernelSources.EtWin32StartAddress;
    Offsets->ktProcessSource = DynState->KernelSources.KtProcess;
    Offsets->htTableCodeSource = KswordARKCrossViewOffsetPresent(DynState->Kernel.HtTableCode)
        ? DynState->KernelSources.HtTableCode
        : KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_RUNTIME_PATTERN;
    Offsets->hteLowValueSource = KswordARKCrossViewOffsetPresent(DynState->Kernel.HteLowValue)
        ? DynState->KernelSources.HteLowValue
        : KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_RUNTIME_PATTERN;
    Offsets->pspCidTableSource = DynState->KernelGlobalSources.PspCidTable;
}

NTSTATUS
KswordARKCrossViewReadMemory(
    _In_ const VOID* Address,
    _Out_writes_bytes_(BytesToRead) VOID* Buffer,
    _In_ SIZE_T BytesToRead
    )
/*++

Routine Description:

    Safely copy kernel memory for read-only evidence collection.

Arguments:

    Address - Kernel source address.
    Buffer - Caller-owned output buffer.
    BytesToRead - Exact number of bytes to copy.

Return Value:

    STATUS_SUCCESS on a complete copy, or a validation/exception/copy status.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Address == NULL || Buffer == NULL || BytesToRead == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)Address;

    __try {
        status = MmCopyMemory(
            Buffer,
            copyAddress,
            BytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }
    return (copiedBytes == BytesToRead) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

NTSTATUS
KswordARKCrossViewReadPointerAddress(
    _In_ const VOID* Address,
    _Out_ PVOID* PointerOut
    )
/*++

Routine Description:

    Read one pointer-sized value from a kernel address with SEH and MmCopyMemory
    protection.

Arguments:

    Address - Address of the pointer value.
    PointerOut - Receives the pointer value.

Return Value:

    STATUS_SUCCESS on success, otherwise the guarded read status.

--*/
{
    PVOID pointerValue = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (PointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PointerOut = NULL;

    status = KswordARKCrossViewReadMemory(Address, &pointerValue, sizeof(pointerValue));
    if (NT_SUCCESS(status)) {
        *PointerOut = pointerValue;
    }
    return status;
}

NTSTATUS
KswordARKCrossViewReadUlong64Address(
    _In_ const VOID* Address,
    _Out_ ULONGLONG* ValueOut
    )
/*++

Routine Description:

    Read one 64-bit value from a kernel address with SEH and MmCopyMemory
    protection.

Arguments:

    Address - Address of the value.
    ValueOut - Receives the copied 64-bit value.

Return Value:

    STATUS_SUCCESS on success, otherwise the guarded read status.

--*/
{
    ULONGLONG value = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ValueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ValueOut = 0ULL;

    status = KswordARKCrossViewReadMemory(Address, &value, sizeof(value));
    if (NT_SUCCESS(status)) {
        *ValueOut = value;
    }
    return status;
}

NTSTATUS
KswordARKCrossViewReadPointerField(
    _In_ const VOID* Object,
    _In_ ULONG Offset,
    _Out_ PVOID* PointerOut
    )
/*++

Routine Description:

    Read one pointer field from a kernel object using a DynData offset.

Arguments:

    Object - Base object address.
    Offset - Private field offset.
    PointerOut - Receives the pointer field value.

Return Value:

    STATUS_SUCCESS on success, STATUS_PROCEDURE_NOT_FOUND for missing offsets,
    or the guarded read status.

--*/
{
    if (PointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PointerOut = NULL;

    if (Object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKCrossViewOffsetPresent(Offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    return KswordARKCrossViewReadPointerAddress((const UCHAR*)Object + Offset, PointerOut);
}

static NTSTATUS
KswordARKCrossViewReadUlongField(
    _In_ const VOID* Object,
    _In_ ULONG Offset,
    _Out_ ULONG* ValueOut
    )
/*++

Routine Description:

    Read one ULONG field from a private kernel object offset.

Arguments:

    Object - Base object address.
    Offset - Private field offset.
    ValueOut - Receives the ULONG value.

Return Value:

    STATUS_SUCCESS on success, STATUS_PROCEDURE_NOT_FOUND for missing offsets,
    or the guarded read status.

--*/
{
    ULONG value = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Object == NULL || ValueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ValueOut = 0UL;
    if (!KswordARKCrossViewOffsetPresent(Offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = KswordARKCrossViewReadMemory((const UCHAR*)Object + Offset, &value, sizeof(value));
    if (NT_SUCCESS(status)) {
        *ValueOut = value;
    }
    return status;
}

static VOID
KswordARKCrossViewCopyImageName(
    _Out_writes_all_(16) CHAR Destination[16],
    _In_opt_z_ const CHAR* Source
    )
/*++

Routine Description:

    Copy a process image name into the fixed 16-byte protocol field.

Arguments:

    Destination - Output image-name buffer.
    Source - Optional NUL-terminated source string.

Return Value:

    None. The destination is always NUL-terminated when valid.

--*/
{
    ULONG index = 0UL;

    if (Destination == NULL) {
        return;
    }
    RtlZeroMemory(Destination, 16U);
    if (Source == NULL) {
        return;
    }

    for (index = 0UL; index < 15UL; ++index) {
        Destination[index] = Source[index];
        if (Source[index] == '\0') {
            break;
        }
    }
    Destination[15] = '\0';
}

static VOID
KswordARKCrossViewFormatDetail(
    _Out_writes_bytes_(DestinationBytes) CHAR* Destination,
    _In_ SIZE_T DestinationBytes,
    _In_z_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    Format a bounded ANSI detail string for a cross-view evidence row.

Arguments:

    Destination - Output detail buffer.
    DestinationBytes - Size of Destination in bytes.
    FormatText - printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. Formatting failure leaves an empty string.

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

static KSW_CROSSVIEW_PS_GET_NEXT_PROCESS_FN
KswordARKProcessCrossViewResolvePsGetNextProcess(
    VOID
    )
/*++

Routine Description:

    Resolve PsGetNextProcess dynamically so the driver does not extend its fixed
    import surface.

Arguments:

    None.

Return Value:

    Function pointer when exported by the running kernel; otherwise NULL.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KSW_CROSSVIEW_PS_GET_NEXT_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
KswordARKCrossViewVisitedInitialize(
    _Out_ KSW_CROSSVIEW_VISITED_SET* Visited,
    _In_ ULONG MaxNodes
    )
/*++

Routine Description:

    Allocate a per-walk visited-address set used for loop detection.

Arguments:

    Visited - Output set descriptor.
    MaxNodes - Maximum list nodes the caller will traverse.

Return Value:

    STATUS_SUCCESS when the set is ready; otherwise a validation/allocation
    status.

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

    Visited->Items = (ULONG_PTR*)KswordARKCrossViewAllocate(bytes, KSW_CROSSVIEW_SHARED_TAG);
    if (Visited->Items == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Visited->Items, bytes);
    Visited->Capacity = MaxNodes;
    return STATUS_SUCCESS;
}

static VOID
KswordARKCrossViewVisitedDestroy(
    _Inout_ KSW_CROSSVIEW_VISITED_SET* Visited
    )
/*++

Routine Description:

    Release a visited-address set allocated for loop detection.

Arguments:

    Visited - Set descriptor to release and clear.

Return Value:

    None.

--*/
{
    if (Visited == NULL) {
        return;
    }

    KswordARKCrossViewFree(Visited->Items, KSW_CROSSVIEW_SHARED_TAG);
    RtlZeroMemory(Visited, sizeof(*Visited));
}

static BOOLEAN
KswordARKCrossViewVisitedCheckAndAdd(
    _Inout_ KSW_CROSSVIEW_VISITED_SET* Visited,
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    Test whether a list address was already seen, and record it when new.

Arguments:

    Visited - Mutable visited-address set.
    Address - List entry address being examined.

Return Value:

    TRUE when Address was already present or the set is full; FALSE when the
    address was newly added and traversal may continue.

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

static BOOLEAN
KswordARKProcessCrossViewPidInRequest(
    _In_ const KSW_PROCESS_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Apply the optional PID range filter from the request.

Arguments:

    Context - Query context containing range boundaries.
    ProcessId - Candidate PID.

Return Value:

    TRUE when the PID should be included; otherwise FALSE.

--*/
{
    if (Context == NULL) {
        return FALSE;
    }
    if (Context->StartPid != 0UL && ProcessId < Context->StartPid) {
        return FALSE;
    }
    if (Context->EndPid != 0UL && ProcessId > Context->EndPid) {
        return FALSE;
    }
    return TRUE;
}

static KSWORD_ARK_PROCESS_CROSSVIEW_ROW*
KswordARKProcessCrossViewFindRow(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG64 ObjectAddress,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Locate an existing process evidence row by object address first and PID as a
    fallback for dangling CID rows.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate EPROCESS address.
    ProcessId - Candidate PID.

Return Value:

    Existing row pointer when found; otherwise NULL.

--*/
{
    ULONG index = 0UL;

    if (Context == NULL || Context->Rows == NULL) {
        return NULL;
    }

    for (index = 0UL; index < Context->RowCount; ++index) {
        KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = &Context->Rows[index];
        if (ObjectAddress != 0ULL && row->objectAddress == ObjectAddress) {
            return row;
        }
        if (ObjectAddress == 0ULL && ProcessId != 0UL && row->processId == ProcessId) {
            return row;
        }
    }

    return NULL;
}

static KSWORD_ARK_PROCESS_CROSSVIEW_ROW*
KswordARKProcessCrossViewGetOrCreateRow(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG64 ObjectAddress,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Return an existing process row or append a new internal row when capacity
    permits.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate EPROCESS address.
    ProcessId - Candidate PID.

Return Value:

    Mutable row pointer on success; NULL when the internal row limit is reached.

--*/
{
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = NULL;

    row = KswordARKProcessCrossViewFindRow(Context, ObjectAddress, ProcessId);
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
    row->processId = ProcessId;
    row->dynDataCapabilityMask = Context->DynState.CapabilityMask;
    row->fieldOffsets = Context->FieldOffsets;
    row->lastStatus = STATUS_SUCCESS;
    row->publicWalkStatus = STATUS_NOT_FOUND;
    row->activeListStatus = STATUS_NOT_FOUND;
    row->cidTableStatus = STATUS_NOT_FOUND;
    row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK;
    row->confidence = 0UL;
    Context->RowCount += 1UL;
    return row;
}

static VOID
KswordARKProcessCrossViewApplyDetailStatus(
    _Inout_ KSWORD_ARK_PROCESS_CROSSVIEW_ROW* Row,
    _In_ NTSTATUS SourceStatus,
    _In_ BOOLEAN UnsupportedField
    )
/*++

Routine Description:

    Update row-level detail status and denoise flags from one guarded read,
    source walk, or object-reference result.

Arguments:

    Row - Mutable process evidence row.
    SourceStatus - NTSTATUS reported by the source path.
    UnsupportedField - TRUE when the status means a required PDB field was not
        available and the collector intentionally avoided guessing an offset.

Return Value:

    None. The row is annotated in place for R3 display.

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
KswordARKProcessCrossViewRecordSourceEvidence(
    _Inout_ KSWORD_ARK_PROCESS_CROSSVIEW_ROW* Row,
    _In_ ULONG SourceMask,
    _In_ ULONG SourceProcessId,
    _In_ NTSTATUS SourceStatus
    )
/*++

Routine Description:

    Store per-source PID and status values without changing the source mask or
    performing any target mutation.

Arguments:

    Row - Mutable process evidence row.
    SourceMask - Single KSWORD_ARK_CROSSVIEW_SOURCE_* bit being merged.
    SourceProcessId - PID observed through that source.
    SourceStatus - Status returned by that source path.

Return Value:

    None. The protocol row receives source-specific evidence fields.

--*/
{
    if (Row == NULL) {
        return;
    }

    if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) {
        Row->publicProcessId = SourceProcessId;
        Row->publicWalkStatus = SourceStatus;
    }
    if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0UL) {
        Row->activeListProcessId = SourceProcessId;
        Row->activeListStatus = SourceStatus;
    }
    if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) {
        Row->cidTableProcessId = SourceProcessId;
        Row->cidTableStatus = SourceStatus;
    }

    KswordARKProcessCrossViewApplyDetailStatus(Row, SourceStatus, FALSE);
}

static NTSTATUS
KswordARKProcessCrossViewReadPrivatePid(
    _In_ const KSW_PROCESS_CROSSVIEW_CONTEXT* Context,
    _In_ PEPROCESS ProcessObject,
    _Out_ ULONG* ProcessIdOut
    )
/*++

Routine Description:

    Read EPROCESS.UniqueProcessId only when DynData exposes the PDB-backed
    offset, so PID mismatch detection remains capability-gated.

Arguments:

    Context - Query context containing the DynData snapshot.
    ProcessObject - Referenced EPROCESS object to inspect.
    ProcessIdOut - Receives the private UniqueProcessId value as ULONG.

Return Value:

    STATUS_SUCCESS when the field was read; STATUS_PROCEDURE_NOT_FOUND when the
    offset is unavailable; otherwise the guarded memory-read status.

--*/
{
    PVOID processIdPointer = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Context == NULL || ProcessObject == NULL || ProcessIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessIdOut = 0UL;

    if (!KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EpUniqueProcessId)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = KswordARKCrossViewReadPointerField(
        ProcessObject,
        Context->DynState.Kernel.EpUniqueProcessId,
        &processIdPointer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *ProcessIdOut = HandleToULong(processIdPointer);
    return STATUS_SUCCESS;
}

static VOID
KswordARKProcessCrossViewMergeProcessObject(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context,
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG SourceMask,
    _In_ NTSTATUS SourceStatus,
    _In_ ULONG EvidenceProcessId,
    _In_opt_z_ PCSTR DetailText
    )
/*++

Routine Description:

    Merge evidence from a referenced EPROCESS object into the process row set.

Arguments:

    Context - Mutable query context.
    ProcessObject - Referenced process object owned by the caller.
    SourceMask - KSWORD_ARK_CROSSVIEW_SOURCE_* bit for the evidence source.
    SourceStatus - Last read/reference status to record.
    EvidenceProcessId - PID observed by the source itself, or zero when the
        source has no independent PID key.
    DetailText - Optional detail text when the row has no detail yet.

Return Value:

    None. Reference ownership remains with the caller.

--*/
{
    ULONG processId = 0UL;
    ULONG privateProcessId = 0UL;
    ULONG sourceProcessId = 0UL;
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = NULL;
    NTSTATUS privatePidStatus = STATUS_SUCCESS;

    if (Context == NULL || ProcessObject == NULL) {
        return;
    }

    processId = HandleToULong(PsGetProcessId(ProcessObject));
    sourceProcessId = (EvidenceProcessId != 0UL) ? EvidenceProcessId : processId;
    if (!KswordARKProcessCrossViewPidInRequest(Context, processId) &&
        !KswordARKProcessCrossViewPidInRequest(Context, sourceProcessId)) {
        return;
    }

    row = KswordARKProcessCrossViewGetOrCreateRow(
        Context,
        (ULONG64)(ULONG_PTR)ProcessObject,
        processId);
    if (row == NULL) {
        return;
    }

    row->sourceMask |= SourceMask;
    row->processId = processId;
    row->parentProcessId = HandleToULong(PsGetProcessInheritedFromUniqueProcessId(ProcessObject));
    row->lastStatus = SourceStatus;
    KswordARKCrossViewCopyImageName(row->imageName, PsGetProcessImageFileName(ProcessObject));
    privatePidStatus = KswordARKProcessCrossViewReadPrivatePid(Context, ProcessObject, &privateProcessId);
    if (NT_SUCCESS(privatePidStatus)) {
        if ((SourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0UL &&
            EvidenceProcessId == 0UL) {
            sourceProcessId = privateProcessId;
        }
        if (privateProcessId != processId) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH;
            row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
            row->lastStatus = STATUS_DATA_ERROR;
        }
    }
    else if (privatePidStatus == STATUS_PROCEDURE_NOT_FOUND) {
        Context->CapabilityMissing = TRUE;
        Context->MissingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
        Context->LastStatus = privatePidStatus;
        row->lastStatus = privatePidStatus;
        KswordARKProcessCrossViewApplyDetailStatus(row, privatePidStatus, TRUE);
    }
    else {
        Context->LastStatus = privatePidStatus;
        row->lastStatus = privatePidStatus;
        KswordARKProcessCrossViewApplyDetailStatus(row, privatePidStatus, FALSE);
    }
    if (EvidenceProcessId != 0UL && EvidenceProcessId != processId) {
        row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH;
        row->detailStatus = KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH;
        row->lastStatus = STATUS_DATA_ERROR;
    }
    KswordARKProcessCrossViewRecordSourceEvidence(row, SourceMask, sourceProcessId, SourceStatus);
    if (DetailText != NULL && row->detail[0] == '\0') {
        KswordARKCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", DetailText);
    }
}

static VOID
KswordARKProcessCrossViewMergeDanglingCandidate(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context,
    _In_ ULONG64 ObjectAddress,
    _In_ ULONG ProcessId,
    _In_ ULONG SourceMask,
    _In_ NTSTATUS SourceStatus,
    _In_z_ PCSTR DetailText
    )
/*++

Routine Description:

    Merge a CID/list candidate whose object address could not be safely
    referenced, preserving it as read-only evidence.

Arguments:

    Context - Mutable query context.
    ObjectAddress - Candidate object body address.
    ProcessId - Candidate PID derived from the CID table or object field.
    SourceMask - Evidence source bit.
    SourceStatus - Reference/read failure status.
    DetailText - Human-readable reason for the dangling classification.

Return Value:

    None.

--*/
{
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = NULL;

    if (Context == NULL || ObjectAddress == 0ULL) {
        return;
    }
    if (!KswordARKProcessCrossViewPidInRequest(Context, ProcessId)) {
        return;
    }

    row = KswordARKProcessCrossViewGetOrCreateRow(Context, ObjectAddress, ProcessId);
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
    row->lastStatus = SourceStatus;
    KswordARKProcessCrossViewRecordSourceEvidence(row, SourceMask, ProcessId, SourceStatus);
    if (row->detail[0] == '\0') {
        KswordARKCrossViewFormatDetail(row->detail, sizeof(row->detail), "%s", DetailText);
    }
}

static NTSTATUS
KswordARKCrossViewTryReferenceTypedObject(
    _In_ PVOID CandidateObject,
    _In_ HANDLE CandidateId,
    _In_ POBJECT_TYPE ExpectedObjectType,
    _Out_ BOOLEAN* TypeMatchedOut,
    _Out_ BOOLEAN* ReferencedOut
    )
/*++

Routine Description:

    Validate a decoded kernel object by type and attempt to take a balanced
    reference without trusting caller-supplied addresses.

Arguments:

    CandidateObject - Decoded object body pointer from a kernel-owned source.
    CandidateId - ID observed from the source. It is retained for callers that
                  perform identity validation after the independent reference.
    ExpectedObjectType - Required object type, such as PsProcessType.
    TypeMatchedOut - Receives whether ObGetObjectType matched ExpectedObjectType.
    ReferencedOut - Receives whether the reference was taken.

Return Value:

    STATUS_SUCCESS when a reference was taken; object-type or reference status
    otherwise. Caller must dereference CandidateObject only when ReferencedOut is
    TRUE.

    The reference is established directly through the object manager pointer
    path. No PsLookupProcessByProcessId/PsLookupThreadByThreadId lookup is used,
    so a hooked lookup routine cannot substitute a different object.

--*/
{
    POBJECT_TYPE objectType = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(CandidateId);

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

    /* Establish lifetime through the independent object-manager pointer path.
       Zero desired access keeps this operation read-only. */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = ObReferenceObjectByPointer(
        CandidateObject,
        0UL,
        ExpectedObjectType,
        KernelMode);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // The type was read before the reference existed.  Read it again now that
    // the object cannot be deleted, so a body recycled between the two steps
    // cannot be reported as a process.
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

static NTSTATUS
KswordARKCrossViewResolveRelativeAddress(
    _In_reads_bytes_(InstructionLength) const UCHAR* InstructionAddress,
    _In_ ULONG DisplacementOffset,
    _In_ ULONG InstructionLength,
    _Out_ PVOID* AddressOut
    )
/*++

Routine Description:

    Resolve one x64 RIP-relative instruction target in read-only fashion.

Arguments:

    InstructionAddress - Address of the instruction bytes.
    DisplacementOffset - Offset of the signed displacement.
    InstructionLength - Full instruction length.
    AddressOut - Receives the resolved kernel address.

Return Value:

    STATUS_SUCCESS on success; otherwise validation or read status.

--*/
{
    LONG relativeOffset = 0;
    ULONG_PTR resolvedAddress = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (InstructionAddress == NULL || AddressOut == NULL ||
        DisplacementOffset > InstructionLength ||
        (InstructionLength - DisplacementOffset) < sizeof(relativeOffset)) {
        return STATUS_INVALID_PARAMETER;
    }
    *AddressOut = NULL;

    status = KswordARKCrossViewReadMemory(
        InstructionAddress + DisplacementOffset,
        &relativeOffset,
        sizeof(relativeOffset));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    resolvedAddress =
        (ULONG_PTR)InstructionAddress +
        (ULONG_PTR)InstructionLength +
        (ULONG_PTR)relativeOffset;
    if (resolvedAddress == 0U) {
        return STATUS_NOT_FOUND;
    }

    *AddressOut = (PVOID)resolvedAddress;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKCrossViewTryResolveMovRip(
    _In_reads_bytes_(KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) const UCHAR* ScanBase,
    _In_ ULONG Offset,
    _In_ UCHAR ModRmByte,
    _Out_ PVOID* PspCidTableAddressOut
    )
/*++

Routine Description:

    Match a RIP-relative mov r64, qword ptr [rip+disp32] instruction variant.

Arguments:

    ScanBase - Function bytes being scanned.
    Offset - Candidate instruction offset.
    ModRmByte - Expected ModR/M byte, for example 0x05 for RAX or 0x0D for RCX.
    PspCidTableAddressOut - Receives the resolved global-variable address.

Return Value:

    STATUS_SUCCESS when matched; STATUS_NOT_FOUND when the bytes do not match;
    otherwise guarded read status.

--*/
{
    UCHAR instructionBytes[3] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (ScanBase == NULL || PspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PspCidTableAddressOut = NULL;

    if ((Offset + 7UL) > KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) {
        return STATUS_NOT_FOUND;
    }

    status = KswordARKCrossViewReadMemory(ScanBase + Offset, instructionBytes, sizeof(instructionBytes));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (instructionBytes[0] != 0x48U || instructionBytes[1] != 0x8BU || instructionBytes[2] != ModRmByte) {
        return STATUS_NOT_FOUND;
    }

    return KswordARKCrossViewResolveRelativeAddress(
        ScanBase + Offset,
        3UL,
        7UL,
        PspCidTableAddressOut);
}

static NTSTATUS
KswordARKCrossViewTryResolveThroughCallTarget(
    _In_reads_bytes_(KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) const UCHAR* ScanBase,
    _In_ ULONG Offset,
    _Out_ PVOID* PspCidTableAddressOut
    )
/*++

Routine Description:

    Follow a nearby call in PsLookupProcessByProcessId and scan the target for a
    PspCidTable RIP-relative load, matching the existing DKOM resolver pattern
    without performing any write.

Arguments:

    ScanBase - Function bytes being scanned.
    Offset - Candidate call offset.
    PspCidTableAddressOut - Receives the resolved global-variable address.

Return Value:

    STATUS_SUCCESS when resolved; STATUS_NOT_FOUND for non-matches; otherwise a
    guarded read status.

--*/
{
    UCHAR opcode = 0U;
    PVOID callTarget = NULL;
    const UCHAR* targetBytes = NULL;
    ULONG targetOffset = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ScanBase == NULL || PspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PspCidTableAddressOut = NULL;

    if ((Offset + 5UL) > KSW_CROSSVIEW_PSP_CID_SCAN_BYTES) {
        return STATUS_NOT_FOUND;
    }

    status = KswordARKCrossViewReadMemory(ScanBase + Offset, &opcode, sizeof(opcode));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (opcode != 0xE8U) {
        return STATUS_NOT_FOUND;
    }

    status = KswordARKCrossViewResolveRelativeAddress(ScanBase + Offset, 1UL, 5UL, &callTarget);
    if (!NT_SUCCESS(status) || callTarget == NULL) {
        return status;
    }

    targetBytes = (const UCHAR*)callTarget;
    for (targetOffset = 0UL; targetOffset < 0x40UL; ++targetOffset) {
        PVOID resolvedAddress = NULL;
        NTSTATUS movStatus = STATUS_SUCCESS;

        movStatus = KswordARKCrossViewTryResolveMovRip(targetBytes, targetOffset, 0x05U, &resolvedAddress);
        if (NT_SUCCESS(movStatus) && resolvedAddress != NULL) {
            *PspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }

        movStatus = KswordARKCrossViewTryResolveMovRip(targetBytes, targetOffset, 0x0DU, &resolvedAddress);
        if (NT_SUCCESS(movStatus) && resolvedAddress != NULL) {
            *PspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
KswordARKCrossViewResolvePspCidTableByPattern(
    _Out_ PVOID* PspCidTableAddressOut
    )
/*++

Routine Description:

    Locate the PspCidTable global-variable address by scanning
    PsLookupProcessByProcessId, as a read-only fallback when DynData does not
    provide the global RVA.

Arguments:

    PspCidTableAddressOut - Receives the address of the PspCidTable global.

Return Value:

    STATUS_SUCCESS when found; STATUS_NOT_FOUND or last guarded-read status on
    failure.

--*/
{
    const UCHAR* lookupBytes = (const UCHAR*)PsLookupProcessByProcessId;
    ULONG offset = 0UL;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (PspCidTableAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PspCidTableAddressOut = NULL;

    if (lookupBytes == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    for (offset = 0UL; offset < KSW_CROSSVIEW_PSP_CID_SCAN_BYTES; ++offset) {
        PVOID resolvedAddress = NULL;
        NTSTATUS status = STATUS_SUCCESS;

        status = KswordARKCrossViewTryResolveMovRip(lookupBytes, offset, 0x05U, &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *PspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }

        status = KswordARKCrossViewTryResolveMovRip(lookupBytes, offset, 0x0DU, &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *PspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }

        status = KswordARKCrossViewTryResolveThroughCallTarget(lookupBytes, offset, &resolvedAddress);
        if (NT_SUCCESS(status) && resolvedAddress != NULL) {
            *PspCidTableAddressOut = resolvedAddress;
            return STATUS_SUCCESS;
        }
        if (status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

NTSTATUS
KswordARKCrossViewResolvePspCidTableAddress(
    _In_ const KSW_DYN_STATE* DynState,
    _Inout_ KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS* Offsets,
    _Out_ PVOID* PspCidTableAddressOut,
    _Out_ ULONG64* MissingCapabilityMaskOut,
    _Out_ BOOLEAN* UsedDynDataGlobalOut
    )
/*++

Routine Description:

    Resolve the PspCidTable global-variable address, preferring the DynData
    kernel global RVA and falling back to the existing pattern-resolver strategy.

Arguments:

    DynState - Query-time DynData snapshot.
    Offsets - Protocol offsets packet updated with the resolved VA.
    PspCidTableAddressOut - Receives the address of the PspCidTable global.
    MissingCapabilityMaskOut - Receives missing capability bits for diagnostics.
    UsedDynDataGlobalOut - Receives TRUE when the DynData global was used.

Return Value:

    STATUS_SUCCESS on success; otherwise a capability or resolver status.

--*/
{
    PVOID pspCidTableAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (PspCidTableAddressOut == NULL || MissingCapabilityMaskOut == NULL || UsedDynDataGlobalOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PspCidTableAddressOut = NULL;
    *MissingCapabilityMaskOut = 0ULL;
    *UsedDynDataGlobalOut = FALSE;

    if (DynState != NULL &&
        DynState->Initialized &&
        DynState->NtosActive &&
        DynState->Ntoskrnl.imageBase != 0ULL &&
        DynState->Ntoskrnl.sizeOfImage != 0UL &&
        KswordARKCrossViewGlobalRvaPresent(DynState->KernelGlobals.PspCidTable)) {
        const ULONG rva = DynState->KernelGlobals.PspCidTable;
        if (rva < DynState->Ntoskrnl.sizeOfImage &&
            (sizeof(PVOID) <= (SIZE_T)(DynState->Ntoskrnl.sizeOfImage - rva))) {
            pspCidTableAddress = (PVOID)(ULONG_PTR)(DynState->Ntoskrnl.imageBase + (ULONG64)rva);
            *PspCidTableAddressOut = pspCidTableAddress;
            *UsedDynDataGlobalOut = TRUE;
            if (Offsets != NULL) {
                Offsets->pspCidTableRva = rva;
                Offsets->pspCidTableAddress = (ULONG64)(ULONG_PTR)pspCidTableAddress;
                Offsets->pspCidTableSource = DynState->KernelGlobalSources.PspCidTable;
            }
            return STATUS_SUCCESS;
        }
    }

    status = KswordARKCrossViewResolvePspCidTableByPattern(&pspCidTableAddress);
    if (NT_SUCCESS(status) && pspCidTableAddress != NULL) {
        *PspCidTableAddressOut = pspCidTableAddress;
        if (Offsets != NULL) {
            Offsets->pspCidTableAddress = (ULONG64)(ULONG_PTR)pspCidTableAddress;
            Offsets->pspCidTableSource = KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_RUNTIME_PATTERN;
        }
        return STATUS_SUCCESS;
    }

    *MissingCapabilityMaskOut = KSW_CAP_KERNEL_GLOBALS | KSW_CAP_CID_TABLE_WALK;
    return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
}

static PVOID
KswordARKCrossViewDecodeCidEntryObject(
    _In_ ULONGLONG EntryValue
    )
/*++

Routine Description:

    Decode a HANDLE_TABLE_ENTRY LowValue into an object body pointer using the
    same read-only decoding used by the DKOM diagnostics.

Arguments:

    EntryValue - Raw LowValue field from the CID table entry.

Return Value:

    Decoded object body pointer, or NULL when the entry is empty.

--*/
{
    ULONGLONG objectValue = 0ULL;

    if (EntryValue == 0ULL) {
        return NULL;
    }

#if defined(_WIN64)
    objectValue = (ULONGLONG)(((LONGLONG)EntryValue) >> 0x10);
    objectValue &= 0xFFFFFFFFFFFFFFF0ULL;
#else
    objectValue = EntryValue & ~(ULONGLONG)0x7U;
#endif

    return (PVOID)(ULONG_PTR)objectValue;
}

static NTSTATUS
KswordARKCrossViewReadCidTableRoot(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ PVOID PspCidTableAddress,
    _Out_ ULONGLONG* TableRootOut,
    _Out_ ULONG* TableLevelOut
    )
/*++

Routine Description:

    Read PspCidTable -> HANDLE_TABLE -> TableCode and split the encoded root and
    table level.

Arguments:

    DynState - DynData snapshot containing HANDLE_TABLE.TableCode offset.
    PspCidTableAddress - Address of the PspCidTable global variable.
    TableRootOut - Receives the decoded table root address.
    TableLevelOut - Receives the table level bits.

Return Value:

    STATUS_SUCCESS on success; STATUS_PROCEDURE_NOT_FOUND when required offsets
    are missing; otherwise guarded read status.

--*/
{
    PVOID handleTable = NULL;
    ULONGLONG tableCode = 0ULL;
    ULONG tableCodeOffset = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (DynState == NULL || PspCidTableAddress == NULL || TableRootOut == NULL || TableLevelOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TableRootOut = 0ULL;
    *TableLevelOut = 0UL;

    tableCodeOffset = KswordARKCrossViewEffectiveHtTableCodeOffset(DynState, NULL);

    status = KswordARKCrossViewReadPointerAddress(PspCidTableAddress, &handleTable);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (handleTable == NULL || !KswordARKCrossViewPointerAligned((ULONG_PTR)handleTable)) {
        return STATUS_NOT_FOUND;
    }

    status = KswordARKCrossViewReadUlong64Address((PUCHAR)handleTable + tableCodeOffset, &tableCode);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *TableLevelOut = (ULONG)(tableCode & KSW_CROSSVIEW_CID_TABLE_LEVEL_MASK);
    *TableRootOut = tableCode & ~KSW_CROSSVIEW_CID_TABLE_LEVEL_MASK;
    return (*TableRootOut != 0ULL && KswordARKCrossViewPointerAligned((ULONG_PTR)*TableRootOut))
        ? STATUS_SUCCESS
        : STATUS_NOT_FOUND;
}

static VOID
KswordARKCrossViewReportCidCandidate(
    _Inout_ KSW_CROSSVIEW_CID_WALK_CONTEXT* Context,
    _In_ PVOID ObjectBody,
    _In_ ULONG CidValue,
    _In_ NTSTATUS EntryReadStatus
    )
/*++

Routine Description:

    Validate, reference, report, and dereference one decoded CID-table object.

Arguments:

    Context - CID walker context containing the callback and expected type.
    ObjectBody - Decoded object body pointer.
    CidValue - CID value represented by the table slot.
    EntryReadStatus - Status from reading the table entry.

Return Value:

    None. References are released before this function returns.

--*/
{
    KSW_CROSSVIEW_CID_ENTRY entry;
    BOOLEAN typeMatched = FALSE;
    BOOLEAN referenced = FALSE;
    NTSTATUS referenceStatus = STATUS_SUCCESS;

    if (Context == NULL || Context->Callback == NULL || ObjectBody == NULL) {
        return;
    }
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)ObjectBody)) {
        return;
    }

    RtlZeroMemory(&entry, sizeof(entry));
    referenceStatus = KswordARKCrossViewTryReferenceTypedObject(
        ObjectBody,
        ULongToHandle(CidValue),
        Context->ExpectedObjectType,
        &typeMatched,
        &referenced);
    if (!typeMatched) {
        return;
    }

    entry.Object = referenced ? ObjectBody : NULL;
    entry.ObjectAddress = (ULONG64)(ULONG_PTR)ObjectBody;
    entry.CidValue = CidValue;
    entry.Referenced = referenced;
    entry.TypeMatched = typeMatched;
    entry.ReferenceStatus = NT_SUCCESS(referenceStatus) ? EntryReadStatus : referenceStatus;

    Context->Callback(&entry, Context->CallbackContext);
    Context->ReportedEntries += 1UL;

    if (referenced) {
        ObDereferenceObject(ObjectBody);
    }
}

static NTSTATUS
KswordARKCrossViewWalkCidLevel0Table(
    _Inout_ KSW_CROSSVIEW_CID_WALK_CONTEXT* Context,
    _In_ ULONGLONG TableAddress,
    _In_ ULONGLONG HandleIndexBase
    )
/*++

Routine Description:

    Walk one leaf table of HANDLE_TABLE_ENTRY records in read-only mode.

Arguments:

    Context - CID walker state.
    TableAddress - Address of the leaf table.
    HandleIndexBase - Base handle index represented by entry zero.

Return Value:

    STATUS_SUCCESS when the leaf was bounded-scanned; STATUS_BUFFER_OVERFLOW
    when MaxNodes was reached; otherwise the most recent guarded read status.

--*/
{
    ULONG entryIndex = 0UL;
    ULONG lowValueOffset = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (Context == NULL || TableAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)TableAddress)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    lowValueOffset = KswordARKCrossViewEffectiveHteLowValueOffset(Context->DynState, NULL);

    for (entryIndex = 0UL; entryIndex < KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT; ++entryIndex) {
        ULONGLONG lowValue = 0ULL;
        PVOID objectBody = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        const ULONGLONG handleIndex = HandleIndexBase + (ULONGLONG)entryIndex;
        const ULONGLONG cidValue64 = handleIndex * KSW_CROSSVIEW_CID_HANDLE_VALUE_STRIDE;
        PVOID lowValueAddress = (PVOID)(ULONG_PTR)(
            TableAddress +
            ((ULONGLONG)entryIndex * KSW_CROSSVIEW_CID_ENTRY_BYTES) +
            (ULONGLONG)lowValueOffset);

        if (Context->VisitedEntries >= Context->MaxNodes) {
            Context->LastStatus = STATUS_BUFFER_OVERFLOW;
            return STATUS_BUFFER_OVERFLOW;
        }
        Context->VisitedEntries += 1UL;

        status = KswordARKCrossViewReadUlong64Address(lowValueAddress, &lowValue);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            Context->LastStatus = status;
            continue;
        }

        objectBody = KswordARKCrossViewDecodeCidEntryObject(lowValue);
        if (objectBody == NULL || cidValue64 > MAXULONG) {
            continue;
        }

        KswordARKCrossViewReportCidCandidate(
            Context,
            objectBody,
            (ULONG)cidValue64,
            status);
    }

    return lastStatus;
}

static NTSTATUS
KswordARKCrossViewWalkCidLevel1Table(
    _Inout_ KSW_CROSSVIEW_CID_WALK_CONTEXT* Context,
    _In_ ULONGLONG TableAddress,
    _In_ ULONGLONG HandleIndexBase
    )
/*++

Routine Description:

    Walk a level-1 CID table by reading child leaf pointers and scanning each
    child leaf with the same MaxNodes budget.

Arguments:

    Context - CID walker state.
    TableAddress - Address of the pointer table.
    HandleIndexBase - Base handle index represented by pointer slot zero.

Return Value:

    STATUS_SUCCESS or the last non-not-found child status; STATUS_BUFFER_OVERFLOW
    when the MaxNodes bound is reached.

--*/
{
    ULONG pointerIndex = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (Context == NULL || TableAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)TableAddress)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    for (pointerIndex = 0UL; pointerIndex < KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT; ++pointerIndex) {
        PVOID childTable = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        const ULONGLONG childBase =
            HandleIndexBase +
            ((ULONGLONG)pointerIndex * (ULONGLONG)KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT);

        status = KswordARKCrossViewReadPointerAddress(
            (PVOID)(ULONG_PTR)(TableAddress + ((ULONGLONG)pointerIndex * sizeof(PVOID))),
            &childTable);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            Context->LastStatus = status;
            continue;
        }
        if (childTable == NULL) {
            continue;
        }

        status = KswordARKCrossViewWalkCidLevel0Table(Context, (ULONGLONG)(ULONG_PTR)childTable, childBase);
        if (status == STATUS_BUFFER_OVERFLOW) {
            return status;
        }
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

static NTSTATUS
KswordARKCrossViewWalkCidLevel2Table(
    _Inout_ KSW_CROSSVIEW_CID_WALK_CONTEXT* Context,
    _In_ ULONGLONG TableAddress
    )
/*++

Routine Description:

    Walk a level-2 CID table by reading middle-table pointers and delegating to
    the level-1 walker under the same MaxNodes bound.

Arguments:

    Context - CID walker state.
    TableAddress - Address of the top-level pointer table.

Return Value:

    STATUS_SUCCESS or the last child status; STATUS_BUFFER_OVERFLOW when the
    MaxNodes bound is reached.

--*/
{
    ULONG pointerIndex = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;

    if (Context == NULL || TableAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)TableAddress)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    for (pointerIndex = 0UL; pointerIndex < KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT; ++pointerIndex) {
        PVOID childTable = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        const ULONGLONG childBase =
            (ULONGLONG)pointerIndex *
            (ULONGLONG)KSW_CROSSVIEW_CID_POINTER_ENTRY_COUNT *
            (ULONGLONG)KSW_CROSSVIEW_CID_LEVEL0_ENTRY_COUNT;

        status = KswordARKCrossViewReadPointerAddress(
            (PVOID)(ULONG_PTR)(TableAddress + ((ULONGLONG)pointerIndex * sizeof(PVOID))),
            &childTable);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            Context->LastStatus = status;
            continue;
        }
        if (childTable == NULL) {
            continue;
        }

        status = KswordARKCrossViewWalkCidLevel1Table(Context, (ULONGLONG)(ULONG_PTR)childTable, childBase);
        if (status == STATUS_BUFFER_OVERFLOW) {
            return status;
        }
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
            lastStatus = status;
        }
    }

    return lastStatus;
}

NTSTATUS
KswordARKCrossViewWalkCidTable(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ PVOID PspCidTableAddress,
    _In_ POBJECT_TYPE ExpectedObjectType,
    _In_ ULONG MaxNodes,
    _In_ KSW_CROSSVIEW_CID_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _Out_opt_ ULONG* VisitedEntriesOut
    )
/*++

Routine Description:

    Walk PspCidTable in read-only mode, validate decoded object types, and report
    referenced or dangling type-matched candidates to the caller callback.

Arguments:

    DynState - DynData snapshot containing handle-table decode offsets.
    PspCidTableAddress - Address of the PspCidTable global variable.
    ExpectedObjectType - Object type required for decoded candidates.
    MaxNodes - Maximum leaf entries to inspect.
    Callback - Caller callback for each type-matched candidate.
    Context - Caller-owned callback context.
    VisitedEntriesOut - Optional count of inspected leaf entries.

Return Value:

    STATUS_SUCCESS when the bounded walk completes; STATUS_BUFFER_OVERFLOW when
    MaxNodes is reached; or validation/read/capability status.

--*/
{
    KSW_CROSSVIEW_CID_WALK_CONTEXT walkContext;
    ULONGLONG tableRoot = 0ULL;
    ULONG tableLevel = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (VisitedEntriesOut != NULL) {
        *VisitedEntriesOut = 0UL;
    }
    if (DynState == NULL || PspCidTableAddress == NULL || ExpectedObjectType == NULL || Callback == NULL || MaxNodes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = KswordARKCrossViewReadCidTableRoot(DynState, PspCidTableAddress, &tableRoot, &tableLevel);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&walkContext, sizeof(walkContext));
    walkContext.DynState = DynState;
    walkContext.ExpectedObjectType = ExpectedObjectType;
    walkContext.MaxNodes = MaxNodes;
    walkContext.LastStatus = STATUS_SUCCESS;
    walkContext.Callback = Callback;
    walkContext.CallbackContext = Context;

    if (tableLevel == 0UL) {
        status = KswordARKCrossViewWalkCidLevel0Table(&walkContext, tableRoot, 0ULL);
    }
    else if (tableLevel == 1UL) {
        status = KswordARKCrossViewWalkCidLevel1Table(&walkContext, tableRoot, 0ULL);
    }
    else if (tableLevel == 2UL) {
        status = KswordARKCrossViewWalkCidLevel2Table(&walkContext, tableRoot);
    }
    else {
        status = STATUS_NOT_SUPPORTED;
    }

    if (VisitedEntriesOut != NULL) {
        *VisitedEntriesOut = walkContext.VisitedEntries;
    }
    if (status == STATUS_SUCCESS && !NT_SUCCESS(walkContext.LastStatus)) {
        status = walkContext.LastStatus;
    }
    return status;
}

NTSTATUS
KswordARKCrossViewReferenceProcessByActiveList(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONG ProcessId,
    _In_ ULONG MaxNodes,
    _Outptr_ PEPROCESS* ProcessOut,
    _Out_opt_ ULONG* UniqueProcessIdOut,
    _Out_opt_ ULONG* VisitedEntriesOut
    )
/*++

Routine Description:

    Resolve one process object from ActiveProcessLinks and return a stable
    reference to the caller. 中文说明：这是终止流程的独立对象引用解析后端；
    它只走内核链表和 ObReferenceObjectByPointer，不调用 NtOpenProcess、
    ZwOpenProcess 或 PsLookupProcessByProcessId。

Arguments:

    DynState - DynData snapshot with process list offsets.
    ProcessId - PID-like value requested by R3.
    MaxNodes - Maximum ActiveProcessLinks nodes to inspect.
    ProcessOut - Receives a referenced EPROCESS on success.
    UniqueProcessIdOut - Optionally receives the matched UniqueProcessId field.
    VisitedEntriesOut - Optionally receives the number of inspected nodes.

Return Value:

    STATUS_SUCCESS when a referenced EPROCESS was found; otherwise a validation,
    capability, read, or not-found status.

--*/
{
    LIST_ENTRY* head = NULL;
    LIST_ENTRY* current = NULL;
    KSW_CROSSVIEW_VISITED_SET visited;
    ULONG walked = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (ProcessOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessOut = NULL;
    if (UniqueProcessIdOut != NULL) {
        *UniqueProcessIdOut = 0UL;
    }
    if (VisitedEntriesOut != NULL) {
        *VisitedEntriesOut = 0UL;
    }
    if (DynState == NULL || ProcessId == 0UL || MaxNodes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKCrossViewOffsetPresent(DynState->Kernel.EpActiveProcessLinks) ||
        !KswordARKCrossViewOffsetPresent(DynState->Kernel.EpUniqueProcessId) ||
        PsInitialSystemProcess == NULL ||
        PsProcessType == NULL ||
        *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&visited, sizeof(visited));
    status = KswordARKCrossViewVisitedInitialize(&visited, MaxNodes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    head = (LIST_ENTRY*)((PUCHAR)PsInitialSystemProcess + DynState->Kernel.EpActiveProcessLinks);
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)head)) {
        KswordARKCrossViewVisitedDestroy(&visited);
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    status = KswordARKCrossViewReadPointerAddress(&head->Flink, (PVOID*)&current);
    if (!NT_SUCCESS(status)) {
        KswordARKCrossViewVisitedDestroy(&visited);
        return status;
    }

    while (current != NULL && current != head) {
        LIST_ENTRY* next = NULL;
        PVOID candidateObject = NULL;
        PVOID uniqueProcessIdPointer = NULL;
        ULONG uniqueProcessId = 0UL;
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        NTSTATUS referenceStatus = STATUS_SUCCESS;

        if (walked >= MaxNodes) {
            lastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        walked += 1UL;

        if (!KswordARKCrossViewPointerAligned((ULONG_PTR)current) ||
            KswordARKCrossViewVisitedCheckAndAdd(&visited, (ULONG_PTR)current)) {
            lastStatus = STATUS_DATATYPE_MISALIGNMENT;
            break;
        }

        status = KswordARKCrossViewReadPointerAddress(&current->Flink, (PVOID*)&next);
        if (!NT_SUCCESS(status)) {
            lastStatus = status;
            break;
        }

        candidateObject = (PVOID)((PUCHAR)current - DynState->Kernel.EpActiveProcessLinks);
        /* A guarded scalar observation is not an object reference. */
        (VOID)KswordARKCrossViewReadPointerField(candidateObject,
            DynState->Kernel.EpUniqueProcessId, &uniqueProcessIdPointer);
        referenceStatus = KswordARKCrossViewTryReferenceTypedObject(
            candidateObject,
            uniqueProcessIdPointer,
            *PsProcessType,
            &typeMatched,
            &referenced);
        if (!typeMatched) {
            lastStatus = referenceStatus;
            current = next;
            continue;
        }
        if (!referenced) {
            lastStatus = referenceStatus;
            current = next;
            continue;
        }

        status = KswordARKCrossViewReadPointerField(
            candidateObject,
            DynState->Kernel.EpUniqueProcessId,
            &uniqueProcessIdPointer);
        if (NT_SUCCESS(status)) {
            uniqueProcessId = HandleToULong(uniqueProcessIdPointer);
        }
        else {
            uniqueProcessId = HandleToULong(PsGetProcessId((PEPROCESS)candidateObject));
            lastStatus = status;
        }

        if (uniqueProcessId == ProcessId ||
            HandleToULong(PsGetProcessId((PEPROCESS)candidateObject)) == ProcessId) {
            *ProcessOut = (PEPROCESS)candidateObject;
            if (UniqueProcessIdOut != NULL) {
                *UniqueProcessIdOut = uniqueProcessId;
            }
            if (VisitedEntriesOut != NULL) {
                *VisitedEntriesOut = walked;
            }
            KswordARKCrossViewVisitedDestroy(&visited);
            return STATUS_SUCCESS;
        }

        ObDereferenceObject(candidateObject);
        current = next;
    }

    if (VisitedEntriesOut != NULL) {
        *VisitedEntriesOut = walked;
    }
    KswordARKCrossViewVisitedDestroy(&visited);
    return lastStatus;
}

static VOID
KswordARKProcessCrossViewCollectPublicWalk(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Collect the public PsGetNextProcess process view. Every returned process
    reference is dereferenced exactly once after row merging.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Failures are recorded in Context->LastStatus and response status.

--*/
{
    KSW_CROSSVIEW_PS_GET_NEXT_PROCESS_FN psGetNextProcess = NULL;
    PEPROCESS processCursor = NULL;
    ULONG visited = 0UL;

    if (Context == NULL) {
        return;
    }

    psGetNextProcess = KswordARKProcessCrossViewResolvePsGetNextProcess();
    if (psGetNextProcess == NULL) {
        Context->LastStatus = STATUS_PROCEDURE_NOT_FOUND;
        Context->CapabilityMissing = TRUE;
        return;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        if (visited >= Context->MaxNodes) {
            Context->Truncated = TRUE;
            Context->LastStatus = STATUS_BUFFER_OVERFLOW;
            ObDereferenceObject(processCursor);
            break;
        }
        visited += 1UL;

        KswordARKProcessCrossViewMergeProcessObject(
            Context,
            processCursor,
            KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK,
            STATUS_SUCCESS,
            HandleToULong(PsGetProcessId(processCursor)),
            "Observed through PsGetNextProcess.");
        /* Advancing consumes the previous enumeration reference. */
        processCursor = psGetNextProcess(processCursor);
    }
}

static VOID
KswordARKProcessCrossViewCollectActiveList(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Walk EPROCESS.ActiveProcessLinks from PsInitialSystemProcess using DynData
    offsets. Traversal uses a node budget, pointer alignment checks, loop
    detection, guarded reads, and object references before trusting rows.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Capability/read failures are recorded in Context.

--*/
{
    LIST_ENTRY* head = NULL;
    LIST_ENTRY* current = NULL;
    KSW_CROSSVIEW_VISITED_SET visited;
    ULONG walked = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Context == NULL) {
        return;
    }
    RtlZeroMemory(&visited, sizeof(visited));

    if ((Context->DynState.CapabilityMask & KSW_CAP_PROCESS_LIST_FIELDS) != KSW_CAP_PROCESS_LIST_FIELDS ||
        !KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EpActiveProcessLinks) ||
        !KswordARKCrossViewOffsetPresent(Context->DynState.Kernel.EpUniqueProcessId) ||
        PsProcessType == NULL ||
        *PsProcessType == NULL) {
        Context->CapabilityMissing = TRUE;
        Context->MissingCapabilityMask |= KSW_CAP_PROCESS_LIST_FIELDS;
        Context->LastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }
    if (PsInitialSystemProcess == NULL) {
        Context->LastStatus = STATUS_PROCEDURE_NOT_FOUND;
        return;
    }

    status = KswordARKCrossViewVisitedInitialize(&visited, Context->MaxNodes);
    if (!NT_SUCCESS(status)) {
        Context->LastStatus = status;
        return;
    }

    head = (LIST_ENTRY*)((PUCHAR)PsInitialSystemProcess + Context->DynState.Kernel.EpActiveProcessLinks);
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)head)) {
        Context->LastStatus = STATUS_DATATYPE_MISALIGNMENT;
        KswordARKCrossViewVisitedDestroy(&visited);
        return;
    }

    if (walked < Context->MaxNodes) {
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        NTSTATUS referenceStatus = STATUS_SUCCESS;

        referenceStatus = KswordARKCrossViewTryReferenceTypedObject(
            PsInitialSystemProcess,
            ULongToHandle(4UL),
            (PsProcessType != NULL) ? *PsProcessType : NULL,
            &typeMatched,
            &referenced);
        if (referenced) {
            KswordARKProcessCrossViewMergeProcessObject(
                Context,
                PsInitialSystemProcess,
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                STATUS_SUCCESS,
                0UL,
                "Observed through ActiveProcessLinks head process.");
            ObDereferenceObject(PsInitialSystemProcess);
        }
        else if (typeMatched) {
            KswordARKProcessCrossViewMergeDanglingCandidate(
                Context,
                (ULONG64)(ULONG_PTR)PsInitialSystemProcess,
                HandleToULong(PsGetProcessId(PsInitialSystemProcess)),
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                referenceStatus,
                "ActiveProcessLinks head process type matched but could not be referenced.");
        }
        walked += 1UL;
    }
    else {
        Context->Truncated = TRUE;
        Context->LastStatus = STATUS_BUFFER_OVERFLOW;
        KswordARKCrossViewVisitedDestroy(&visited);
        return;
    }

    status = KswordARKCrossViewReadPointerAddress(&head->Flink, (PVOID*)&current);
    if (!NT_SUCCESS(status)) {
        Context->LastStatus = status;
        KswordARKCrossViewVisitedDestroy(&visited);
        return;
    }

    while (current != NULL && current != head) {
        LIST_ENTRY* next = NULL;
        LIST_ENTRY* blink = NULL;
        PEPROCESS processObject = NULL;
        PVOID candidateObject = NULL;
        PVOID processIdPointer = NULL;
        ULONG processId = 0UL;
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;
        NTSTATUS referenceStatus = STATUS_SUCCESS;
        NTSTATUS readStatus = STATUS_SUCCESS;
        BOOLEAN linkMismatch = FALSE;

        if (walked >= Context->MaxNodes) {
            Context->Truncated = TRUE;
            Context->LastStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        walked += 1UL;

        if (!KswordARKCrossViewPointerAligned((ULONG_PTR)current) ||
            KswordARKCrossViewVisitedCheckAndAdd(&visited, (ULONG_PTR)current)) {
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

        candidateObject = (PVOID)((PUCHAR)current - Context->DynState.Kernel.EpActiveProcessLinks);
        /* A guarded scalar observation is not an object reference. */
        (VOID)KswordARKCrossViewReadPointerField(candidateObject,
            Context->DynState.Kernel.EpUniqueProcessId, &processIdPointer);
        referenceStatus = KswordARKCrossViewTryReferenceTypedObject(
            candidateObject,
            processIdPointer,
            (PsProcessType != NULL) ? *PsProcessType : NULL,
            &typeMatched,
            &referenced);

        if (referenced) {
            processObject = (PEPROCESS)candidateObject;
            KswordARKProcessCrossViewMergeProcessObject(
                Context,
                processObject,
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                linkMismatch ? STATUS_DATA_ERROR : STATUS_SUCCESS,
                0UL,
                linkMismatch ? "ActiveProcessLinks blink/flink mismatch observed." : "Observed through ActiveProcessLinks.");
            if (linkMismatch) {
                KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = KswordARKProcessCrossViewFindRow(
                    Context,
                    (ULONG64)(ULONG_PTR)processObject,
                    HandleToULong(PsGetProcessId(processObject)));
                if (row != NULL) {
                    row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY;
                }
            }
            ObDereferenceObject(processObject);
        }
        else if (typeMatched) {
            (VOID)KswordARKCrossViewReadPointerField(
                candidateObject,
                Context->DynState.Kernel.EpUniqueProcessId,
                &processIdPointer);
            processId = HandleToULong(processIdPointer);
            KswordARKProcessCrossViewMergeDanglingCandidate(
                Context,
                (ULONG64)(ULONG_PTR)candidateObject,
                processId,
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST,
                referenceStatus,
                "ActiveProcessLinks candidate type matched but could not be referenced.");
        }

        current = next;
    }

    KswordARKCrossViewVisitedDestroy(&visited);
}

static VOID
KswordARKProcessCrossViewCidCallback(
    _In_ const KSW_CROSSVIEW_CID_ENTRY* Entry,
    _Inout_opt_ PVOID Context
    )
/*++

Routine Description:

    Merge one process object reported by the read-only CID table walker.

Arguments:

    Entry - CID walker payload, with a temporary reference when Referenced is
    TRUE.
    Context - KSW_PROCESS_CROSSVIEW_CONTEXT owned by the query.

Return Value:

    None.

--*/
{
    KSW_PROCESS_CROSSVIEW_CONTEXT* context = (KSW_PROCESS_CROSSVIEW_CONTEXT*)Context;

    if (context == NULL || Entry == NULL) {
        return;
    }

    if (Entry->Referenced && Entry->Object != NULL) {
        KswordARKProcessCrossViewMergeProcessObject(
            context,
            (PEPROCESS)Entry->Object,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            Entry->ReferenceStatus,
            Entry->CidValue,
            "Observed through PspCidTable.");
    }
    else if (Entry->TypeMatched) {
        KswordARKProcessCrossViewMergeDanglingCandidate(
            context,
            Entry->ObjectAddress,
            Entry->CidValue,
            KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE,
            Entry->ReferenceStatus,
            "PspCidTable process candidate type matched but could not be referenced.");
    }
}

static VOID
KswordARKProcessCrossViewCollectCidTable(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Collect process evidence from PspCidTable without deleting, clearing, or
    modifying any table entry.

Arguments:

    Context - Mutable query context.

Return Value:

    None. Resolver, capability, and read statuses are recorded in Context.

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
     * HtTableCode and HteLowValue have bounded read-only fallbacks in the
     * walker, so a missing PDB field must not disable the entire CID view.
     * Object-type validation remains mandatory before any decoded entry is
     * referenced.
     */
    if (PsProcessType == NULL || *PsProcessType == NULL) {
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
        *PsProcessType,
        Context->MaxNodes,
        KswordARKProcessCrossViewCidCallback,
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
KswordARKProcessCrossViewFinalizeRows(
    _Inout_ KSW_PROCESS_CROSSVIEW_CONTEXT* Context
    )
/*++

Routine Description:

    Compute process anomaly flags and confidence after all selected evidence
    sources have been merged.

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
        KSWORD_ARK_PROCESS_CROSSVIEW_ROW* row = &Context->Rows[index];
        const BOOLEAN hasPublic = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN hasActive = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0UL) ? TRUE : FALSE;
        const BOOLEAN hasCid = ((row->sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0UL) ? TRUE : FALSE;
        const BOOLEAN expectPublic =
            ((Context->Flags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) ? TRUE : FALSE;
        const BOOLEAN expectActive =
            ((Context->Flags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ACTIVE_LIST) != 0UL &&
                (Context->MissingCapabilityMask & KSW_CAP_PROCESS_LIST_FIELDS) == 0ULL) ? TRUE : FALSE;
        const BOOLEAN expectCid =
            ((Context->Flags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL &&
                (Context->MissingCapabilityMask & KSW_CAP_CID_TABLE_WALK) == 0ULL) ? TRUE : FALSE;

        row->dynDataCapabilityMask = Context->DynState.CapabilityMask;
        row->fieldOffsets = Context->FieldOffsets;

        if (expectCid && hasCid &&
            (!expectPublic || !hasPublic) &&
            (!expectActive || !hasActive)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY;
        }
        if (expectActive && hasActive &&
            (!expectPublic || !hasPublic) &&
            (!expectCid || !hasCid)) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY;
        }
        if (expectActive && (hasPublic || hasCid) && !hasActive) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST;
        }
        if (expectCid && (hasPublic || hasActive) && !hasCid) {
            row->anomalyFlags |= KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE;
        }

        if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT) != 0UL) {
            row->confidence = 30UL;
        }
        else if ((row->anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0UL) {
            row->confidence = 45UL;
        }
        else if (hasPublic && hasActive && hasCid) {
            row->confidence = 98UL;
        }
        else if ((hasPublic && hasActive) || (hasPublic && hasCid) || (hasActive && hasCid)) {
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
            KswordARKCrossViewFormatDetail(
                row->detail,
                sizeof(row->detail),
                "sources=0x%08lX anomalies=0x%08lX.",
                row->sourceMask,
                row->anomalyFlags);
        }
    }
}

static VOID
KswordARKProcessCrossViewCopyResponse(
    _Inout_ KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_ const KSW_PROCESS_CROSSVIEW_CONTEXT* Context,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Copy internal process rows into the caller METHOD_BUFFERED response while
    preserving totalCount when the output buffer is smaller than the row set.

Arguments:

    Response - Output response buffer.
    OutputBufferLength - Writable response byte count.
    Context - Finalized query context.
    BytesWrittenOut - Receives exact response bytes written.

Return Value:

    None.

--*/
{
    size_t entryCapacity = 0U;
    ULONG copyCount = 0UL;

    if (Response == NULL || Context == NULL || BytesWrittenOut == NULL) {
        return;
    }

    entryCapacity = (OutputBufferLength - KSW_PROCESS_CROSSVIEW_HEADER_SIZE) / sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
    copyCount = (Context->RowCount < (ULONG)entryCapacity) ? Context->RowCount : (ULONG)entryCapacity;

    Response->version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
    Response->entrySize = sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
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
        RtlCopyMemory(Response->entries, Context->Rows, (SIZE_T)copyCount * sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW));
    }

    *BytesWrittenOut = KSW_PROCESS_CROSSVIEW_HEADER_SIZE + ((size_t)copyCount * sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW));
}

static ULONG
KswordARKCrossViewNormalizeMaxNodes(
    _In_ ULONG RequestedMaxNodes
    )
/*++

Routine Description:

    Normalize caller-provided node budget to protocol defaults and hard limits.

Arguments:

    RequestedMaxNodes - Raw request value.

Return Value:

    Default or bounded node count.

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

NTSTATUS
KswordARKDriverQueryProcessCrossView(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Query read-only process cross-view evidence from PsGetNextProcess,
    EPROCESS.ActiveProcessLinks, and PspCidTable.

Arguments:

    OutputBuffer - METHOD_BUFFERED output packet.
    OutputBufferLength - Writable output byte count.
    Request - Optional process cross-view request.
    BytesWrittenOut - Receives bytes written to OutputBuffer.

Return Value:

    STATUS_SUCCESS when the response header was written; validation/allocation
    status otherwise. Per-source failures are reported in the response fields.

--*/
{
    KSW_PROCESS_CROSSVIEW_CONTEXT context;
    KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE* response = NULL;
    SIZE_T rowBytes = 0U;
    ULONG requestFlags = KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSW_PROCESS_CROSSVIEW_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.LastStatus = STATUS_SUCCESS;
    context.MaxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;
    if (Request != NULL) {
        if (Request->flags != 0UL) {
            requestFlags = Request->flags;
        }
        context.StartPid = Request->startPid;
        context.EndPid = Request->endPid;
        context.MaxNodes = KswordARKCrossViewNormalizeMaxNodes(Request->maxNodes);
    }
    context.Flags = requestFlags;
    context.RowCapacity = context.MaxNodes;

    rowBytes = (SIZE_T)context.RowCapacity * sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
    if ((rowBytes / sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW)) != (SIZE_T)context.RowCapacity) {
        return STATUS_INTEGER_OVERFLOW;
    }

    context.Rows = (KSWORD_ARK_PROCESS_CROSSVIEW_ROW*)KswordARKCrossViewAllocate(rowBytes, KSW_PROCESS_CROSSVIEW_TAG);
    if (context.Rows == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context.Rows, rowBytes);

    KswordARKDynDataSnapshot(&context.DynState);
    KswordARKCrossViewFillFieldOffsets(&context.DynState, &context.FieldOffsets);

    if ((requestFlags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK) != 0UL) {
        KswordARKProcessCrossViewCollectPublicWalk(&context);
    }
    if ((requestFlags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ACTIVE_LIST) != 0UL) {
        KswordARKProcessCrossViewCollectActiveList(&context);
    }
    if ((requestFlags & KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE) != 0UL) {
        KswordARKProcessCrossViewCollectCidTable(&context);
    }

    KswordARKProcessCrossViewFinalizeRows(&context);

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE*)OutputBuffer;
    KswordARKProcessCrossViewCopyResponse(response, OutputBufferLength, &context, BytesWrittenOut);

    KswordARKCrossViewFree(context.Rows, KSW_PROCESS_CROSSVIEW_TAG);
    context.Rows = NULL;
    return status;
}

NTSTATUS
KswordARKCrossViewValidateActiveProcessLinks(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONG MaxNodes,
    _Out_opt_ ULONG* VisitedEntriesOut
    )
{
    KSW_CROSSVIEW_VISITED_SET visited;
    LIST_ENTRY* head = NULL;
    LIST_ENTRY* current = NULL;
    ULONG walked = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN headTypeMatched = FALSE;
    BOOLEAN headReferenced = FALSE;

    if (VisitedEntriesOut != NULL) {
        *VisitedEntriesOut = 0UL;
    }
    if (DynState == NULL || MaxNodes == 0UL || PsInitialSystemProcess == NULL ||
        !KswordARKCrossViewOffsetPresent(DynState->Kernel.EpActiveProcessLinks) ||
        PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&visited, sizeof(visited));
    status = KswordARKCrossViewVisitedInitialize(&visited, MaxNodes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    head = (LIST_ENTRY*)((PUCHAR)PsInitialSystemProcess + DynState->Kernel.EpActiveProcessLinks);
    if (!KswordARKCrossViewPointerAligned((ULONG_PTR)head) ||
        !NT_SUCCESS(KswordARKCrossViewReadPointerAddress(&head->Flink, (PVOID*)&current))) {
        KswordARKCrossViewVisitedDestroy(&visited);
        return STATUS_DATA_ERROR;
    }
    status = KswordARKCrossViewTryReferenceTypedObject(
        PsInitialSystemProcess,
        NULL,
        *PsProcessType,
        &headTypeMatched,
        &headReferenced);
    if (!NT_SUCCESS(status) || !headTypeMatched || !headReferenced) {
        KswordARKCrossViewVisitedDestroy(&visited);
        return NT_SUCCESS(status) ? STATUS_OBJECT_TYPE_MISMATCH : status;
    }
    ObDereferenceObject(PsInitialSystemProcess);

    while (current != NULL && current != head) {
        LIST_ENTRY* next = NULL;
        LIST_ENTRY* blink = NULL;
        PVOID candidateObject = NULL;
        BOOLEAN typeMatched = FALSE;
        BOOLEAN referenced = FALSE;

        if (walked >= MaxNodes ||
            !KswordARKCrossViewPointerAligned((ULONG_PTR)current) ||
            KswordARKCrossViewVisitedCheckAndAdd(&visited, (ULONG_PTR)current)) {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        ++walked;
        if (!NT_SUCCESS(KswordARKCrossViewReadPointerAddress(&current->Flink, (PVOID*)&next)) ||
            !NT_SUCCESS(KswordARKCrossViewReadPointerAddress(&current->Blink, (PVOID*)&blink)) ||
            next == NULL || blink == NULL) {
            status = STATUS_DATA_ERROR;
            break;
        }
        if (!KswordARKCrossViewPointerAligned((ULONG_PTR)next) ||
            !KswordARKCrossViewPointerAligned((ULONG_PTR)blink)) {
            status = STATUS_DATATYPE_MISALIGNMENT;
            break;
        }
        {
            LIST_ENTRY* nextBlink = NULL;
            LIST_ENTRY* blinkFlink = NULL;
            if (!NT_SUCCESS(KswordARKCrossViewReadPointerAddress(&next->Blink, (PVOID*)&nextBlink)) ||
                !NT_SUCCESS(KswordARKCrossViewReadPointerAddress(&blink->Flink, (PVOID*)&blinkFlink)) ||
                nextBlink != current || blinkFlink != current) {
                status = STATUS_DATA_ERROR;
                break;
            }
        }
        candidateObject = (PVOID)((PUCHAR)current - DynState->Kernel.EpActiveProcessLinks);
        status = KswordARKCrossViewTryReferenceTypedObject(
            candidateObject,
            NULL,
            *PsProcessType,
            &typeMatched,
            &referenced);
        if (!NT_SUCCESS(status) || !typeMatched || !referenced) {
            status = NT_SUCCESS(status) ? STATUS_OBJECT_TYPE_MISMATCH : status;
            break;
        }
        ObDereferenceObject(candidateObject);
        current = next;
    }

    if (VisitedEntriesOut != NULL) {
        *VisitedEntriesOut = walked;
    }
    if (NT_SUCCESS(status) && current != head) {
        status = STATUS_DATA_ERROR;
    }
    KswordARKCrossViewVisitedDestroy(&visited);
    return status;
}

NTSTATUS
KswordARKProcessIoctlQueryCrossView(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
/*++

Routine Description:

    Handle the unregistered process cross-view IOCTL. The handler accepts an
    optional fixed request, retrieves the output buffer, and invokes the read-only
    backend without requiring write access or trusting any R3 object address.

Arguments:

    Device - WDF device used only for signature parity with other handlers.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF retrieval.
    BytesReturned - Receives backend response bytes.

Return Value:

    NTSTATUS from buffer retrieval or KswordARKDriverQueryProcessCrossView.

--*/
{
    KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST* queryRequest = NULL;
    KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST defaultRequest;
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
    defaultRequest.flags = KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL;
    defaultRequest.maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    queryRequest = hasInput ? (KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST*)inputBuffer : &defaultRequest;

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_PROCESS_CROSSVIEW_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return KswordARKDriverQueryProcessCrossView(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        BytesReturned);
}
