/*++

Module Name:

    process_actions.c

Abstract:

    This file contains kernel process control operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "..\..\platform\process_resolver.h"
#include "process_crossview.h"
#include "process_extended.h"
#include "../../platform/runtime_signature_scan.h"
#include <ntstrsafe.h>
#include <stdarg.h>

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

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME (0x0800)
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef SE_GROUP_INTEGRITY
#define SE_GROUP_INTEGRITY 0x00000020L
#endif

#ifndef STATUS_INVALID_SID
#define STATUS_INVALID_SID ((NTSTATUS)0xC0000078L)
#endif

#ifndef SE_SIGNING_LEVEL_UNCHECKED
#define SE_SIGNING_LEVEL_UNCHECKED 0x00
#endif

#ifndef SE_SIGNING_LEVEL_AUTHENTICODE
#define SE_SIGNING_LEVEL_AUTHENTICODE 0x04
#endif

#ifndef SE_SIGNING_LEVEL_STORE
#define SE_SIGNING_LEVEL_STORE 0x06
#endif

#ifndef SE_SIGNING_LEVEL_ANTIMALWARE
#define SE_SIGNING_LEVEL_ANTIMALWARE 0x07
#endif

#ifndef SE_SIGNING_LEVEL_MICROSOFT
#define SE_SIGNING_LEVEL_MICROSOFT 0x08
#endif

#ifndef SE_SIGNING_LEVEL_DYNAMIC_CODEGEN
#define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN 0x0B
#endif

#ifndef SE_SIGNING_LEVEL_WINDOWS
#define SE_SIGNING_LEVEL_WINDOWS 0x0C
#endif

#ifndef SE_SIGNING_LEVEL_WINDOWS_TCB
#define SE_SIGNING_LEVEL_WINDOWS_TCB 0x0E
#endif

#define KSWORD_PS_PROTECTED_SIGNER_NONE ((UCHAR)0x00)
#define KSWORD_PS_PROTECTED_SIGNER_AUTHENTICODE ((UCHAR)0x01)
#define KSWORD_PS_PROTECTED_SIGNER_CODEGEN ((UCHAR)0x02)
#define KSWORD_PS_PROTECTED_SIGNER_ANTIMALWARE ((UCHAR)0x03)
#define KSWORD_PS_PROTECTED_SIGNER_LSA ((UCHAR)0x04)
#define KSWORD_PS_PROTECTED_SIGNER_WINDOWS ((UCHAR)0x05)
#define KSWORD_PS_PROTECTED_SIGNER_WINTCB ((UCHAR)0x06)
#define KSWORD_PS_PROTECTED_SIGNER_WINSYSTEM ((UCHAR)0x07)
#define KSWORD_PS_PROTECTED_SIGNER_APP ((UCHAR)0x08)

#define KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_PROCESS_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_ENTRY))
#define KSWORD_ARK_ENUM_PID_STEP 4UL
#define KSWORD_ARK_ENUM_SCAN_MAX_PID 0x00400000UL
#define KSWORD_ARK_ENUM_SCAN_MIN_PID KSWORD_ARK_ENUM_PID_STEP
#define KSWORD_ARK_ENUM_CID_WALK_MAX_NODES 0x00100000UL
#define KSWORD_ARK_PROCESS_HIDE_MAX_PIDS 256UL
#define KSWORD_ARK_PROCESS_OFFSET_SCAN_LIMIT 0x2000UL
#define KSWORD_ARK_PROCESS_HIDDEN_PID_TAG 0xE0000000UL
#define KSWORD_ARK_PROCESS_HIDDEN_PID_MASK 0x0FFFFFFCUL
#if defined(_WIN64)
#define KSWORD_ARK_EX_FAST_REF_MASK ((ULONG_PTR)0x0FULL)
#else
#define KSWORD_ARK_EX_FAST_REF_MASK ((ULONG_PTR)0x07UL)
#endif
#define KSWORD_ARK_TOKEN_INTEGRITY_MAX_GROUPS 1024UL
#define KSWORD_ARK_PROCESS_INTEGRITY_DIAG_CHARS 512UL

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_INVALID_DEVICE_STATE
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

typedef struct _KSWORD_ARK_PROCESS_INTEGRITY_ATTEMPT_DIAG
{
    ULONG ProcessId;
    ULONG IntegrityRid;
    NTSTATUS ApiStatus;
    NTSTATUS FallbackStatus;
    NTSTATUS FinalStatus;
    ULONG64 CapabilityMask;
    ULONG EpToken;
    ULONG TokUserAndGroupCount;
    ULONG TokUserAndGroups;
    ULONG TokIntegrityLevelIndex;
    ULONG TokMandatoryPolicy;
    ULONG EpTokenSource;
    ULONG TokUserAndGroupCountSource;
    ULONG TokUserAndGroupsSource;
    ULONG TokIntegrityLevelIndexSource;
    ULONG TokMandatoryPolicySource;
} KSWORD_ARK_PROCESS_INTEGRITY_ATTEMPT_DIAG, *PKSWORD_ARK_PROCESS_INTEGRITY_ATTEMPT_DIAG;

static KSWORD_ARK_PROCESS_INTEGRITY_ATTEMPT_DIAG g_KswordProcessIntegrityDiag;

typedef struct _KSWORD_ARK_PROCESS_INTEGRITY_TOKEN_INFORMATION
{
    TOKEN_MANDATORY_LABEL MandatoryLabel;
    UCHAR SidBuffer[SECURITY_MAX_SID_SIZE];
} KSWORD_ARK_PROCESS_INTEGRITY_TOKEN_INFORMATION;

extern POBJECT_TYPE* PsProcessType;

typedef PEPROCESS(NTAPI* KSWORD_PS_GET_NEXT_PROCESS_FN)(
    _In_opt_ PEPROCESS Process
    );

typedef struct _KSWORD_ARK_PROCESS_HIDE_RECORD
{
    ULONG Pid;
    ULONG UniqueProcessIdOffset;
    ULONG ActiveProcessLinksOffset;
    PEPROCESS ProcessObject;
    HANDLE OriginalUniqueProcessId;
    HANDLE HiddenUniqueProcessId;
    LIST_ENTRY* ActiveProcessLinks;
    LIST_ENTRY* PreviousLink;
    LIST_ENTRY* NextLink;
    BOOLEAN UniqueProcessIdPatched;
    BOOLEAN ActiveListUnlinked;
} KSWORD_ARK_PROCESS_HIDE_RECORD;

typedef struct _KSWORD_ARK_PROCESS_HIDE_STATE
{
    EX_PUSH_LOCK Lock;
    BOOLEAN Initialized;
    ULONG Count;
    KSWORD_ARK_PROCESS_HIDE_RECORD Records[KSWORD_ARK_PROCESS_HIDE_MAX_PIDS];
} KSWORD_ARK_PROCESS_HIDE_STATE;

typedef struct _KSWORD_ARK_ENUM_PROCESS_CID_CONTEXT
{
    KSWORD_ARK_ENUM_PROCESS_RESPONSE* Response;
    size_t EntryCapacity;
    const KSW_DYN_STATE* DynState;
    const UCHAR* ActivePidBitmap;
    size_t ActivePidBitmapBytes;
    ULONG ScanStartPid;
    ULONG ScanEndPid;
    BOOLEAN ActiveWalkAvailable;
} KSWORD_ARK_ENUM_PROCESS_CID_CONTEXT;

static KSWORD_ARK_PROCESS_HIDE_STATE g_KswordArkProcessHideState;

static VOID
KswordARKDriverEnsureProcessHideStateInitialized(
    VOID
    )
/*++

Routine Description:

    初始化驱动内进程隐藏状态表。中文说明：该表记录由 Ksword 执行的
    ActiveProcessLinks 摘链状态，包括目标 EPROCESS 引用和原前后节点，
    供后续取消隐藏或清空全部隐藏时恢复链表。

Arguments:

    None.

Return Value:

    None. 本函数没有返回值。

--*/
{
    if (g_KswordArkProcessHideState.Initialized) {
        return;
    }

    RtlZeroMemory(&g_KswordArkProcessHideState, sizeof(g_KswordArkProcessHideState));
    ExInitializePushLock(&g_KswordArkProcessHideState.Lock);
    g_KswordArkProcessHideState.Initialized = TRUE;
}

static BOOLEAN
KswordARKDriverIsProcessHiddenByUi(
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    查询 PID 是否被 Ksword R0 可恢复隐藏表记录。中文说明：真实隐藏
    通过 ActiveProcessLinks 摘链完成；该 helper 只用于枚举时补充
    KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI，方便 R3 识别和过滤。

Arguments:

    ProcessId - 目标 PID。

Return Value:

    TRUE 表示该 PID 当前被标记隐藏；FALSE 表示未隐藏。

--*/
{
    ULONG index = 0UL;
    BOOLEAN hidden = FALSE;

    KswordARKDriverEnsureProcessHideStateInitialized();
    KswordARKAcquirePushLockShared(&g_KswordArkProcessHideState.Lock);
    for (index = 0UL; index < g_KswordArkProcessHideState.Count; ++index) {
        if (g_KswordArkProcessHideState.Records[index].Pid == ProcessId) {
            hidden = TRUE;
            break;
        }
    }
    KswordARKReleasePushLockShared(&g_KswordArkProcessHideState.Lock);
    return hidden;
}

static BOOLEAN
KswordARKDriverIsOwnedHiddenObject(
    _In_ ULONG CidValue,
    _In_ PEPROCESS ProcessObject
    )
{
    ULONG index = 0UL;
    BOOLEAN owned = FALSE;

    if (ProcessObject == NULL) {
        return FALSE;
    }

    KswordARKDriverEnsureProcessHideStateInitialized();
    KswordARKAcquirePushLockShared(&g_KswordArkProcessHideState.Lock);
    for (index = 0UL; index < g_KswordArkProcessHideState.Count; ++index) {
        const KSWORD_ARK_PROCESS_HIDE_RECORD* record =
            &g_KswordArkProcessHideState.Records[index];
        if (record->ProcessObject == ProcessObject &&
            (record->Pid == CidValue ||
             HandleToULong(record->OriginalUniqueProcessId) == CidValue)) {
            owned = TRUE;
            break;
        }
    }
    KswordARKReleasePushLockShared(&g_KswordArkProcessHideState.Lock);
    return owned;
}

static KSWORD_PS_GET_NEXT_PROCESS_FN
KswordARKDriverResolvePsGetNextProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KSWORD_PS_GET_NEXT_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}

static ULONG
KswordARKDriverAlignPidToStep(
    _In_ ULONG pidValue
    )
{
    return pidValue - (pidValue % KSWORD_ARK_ENUM_PID_STEP);
}

static BOOLEAN
KswordARKDriverPidInScanRange(
    _In_ ULONG pidValue,
    _In_ ULONG scanStartPid,
    _In_ ULONG scanEndPid
    )
{
    if (pidValue < scanStartPid || pidValue > scanEndPid) {
        return FALSE;
    }
    return ((pidValue % KSWORD_ARK_ENUM_PID_STEP) == 0U) ? TRUE : FALSE;
}

static VOID
KswordARKDriverBitmapSetPid(
    _Inout_updates_bytes_(bitmapBytes) PUCHAR bitmap,
    _In_ size_t bitmapBytes,
    _In_ ULONG pidValue
    )
{
    size_t bitIndex = 0;
    size_t byteIndex = 0;
    UCHAR bitMask = 0;

    if (bitmap == NULL || bitmapBytes == 0U) {
        return;
    }

    bitIndex = (size_t)(pidValue / KSWORD_ARK_ENUM_PID_STEP);
    byteIndex = (bitIndex >> 3);
    if (byteIndex >= bitmapBytes) {
        return;
    }

    bitMask = (UCHAR)(1U << (bitIndex & 0x07U));
    bitmap[byteIndex] = (UCHAR)(bitmap[byteIndex] | bitMask);
}

static BOOLEAN
KswordARKDriverBitmapHasPid(
    _In_reads_bytes_(bitmapBytes) const UCHAR* bitmap,
    _In_ size_t bitmapBytes,
    _In_ ULONG pidValue
    )
{
    size_t bitIndex = 0;
    size_t byteIndex = 0;
    UCHAR bitMask = 0;

    if (bitmap == NULL || bitmapBytes == 0U) {
        return FALSE;
    }

    bitIndex = (size_t)(pidValue / KSWORD_ARK_ENUM_PID_STEP);
    byteIndex = (bitIndex >> 3);
    if (byteIndex >= bitmapBytes) {
        return FALSE;
    }

    bitMask = (UCHAR)(1U << (bitIndex & 0x07U));
    return ((bitmap[byteIndex] & bitMask) != 0U) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKDriverProcessDynOffsetPresent(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    判断 DynData 提供的 EPROCESS 偏移是否可以用于安全读取。

Arguments:

    Offset - 来自统一 DynData 状态的候选偏移。

Return Value:

    偏移有效时返回 TRUE；偏移缺失或为旧版哨兵值时返回 FALSE。

--*/
{
    return (Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKDriverProcessListPointerAligned(
    _In_ const VOID* Pointer
    )
/*++

Routine Description:

    Validate basic LIST_ENTRY pointer alignment before touching neighbor links.
    中文说明：该函数只做廉价格式检查，避免明显错误的 DynData 偏移或
    损坏链表指针导致后续读写落在非对齐地址。

Arguments:

    Pointer - 待检查的内核指针。

Return Value:

    TRUE 表示指针非空且满足指针宽度对齐；FALSE 表示不可安全用于链表读写。

--*/
{
    return (Pointer != NULL &&
        (((ULONG_PTR)Pointer & (sizeof(PVOID) - 1U)) == 0U)) ? TRUE : FALSE;
}

static NTSTATUS
KswordARKDriverReadProcessHandleField(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG Offset,
    _Out_ HANDLE* ValueOut
    )
/*++

Routine Description:

    Safely read one HANDLE-sized EPROCESS field. 中文说明：用于读取
    _EPROCESS.UniqueProcessId，避免直接解引用错误 DynData 偏移。

Arguments:

    ProcessObject - Target EPROCESS.
    Offset - Field offset inside EPROCESS.
    ValueOut - Receives the HANDLE-sized value.

Return Value:

    STATUS_SUCCESS or validation/exception status.

--*/
{
    HANDLE handleValue = NULL;

    if (ProcessObject == NULL || ValueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ValueOut = NULL;

    if (!KswordARKDriverProcessDynOffsetPresent(Offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!KswordARKRuntimeReadMemory(
            (const UCHAR*)ProcessObject + Offset,
            &handleValue,
            sizeof(handleValue))) {
        return STATUS_ACCESS_VIOLATION;
    }

    *ValueOut = handleValue;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverWriteProcessHandleField(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG Offset,
    _In_ HANDLE Value
    )
/*++

Routine Description:

    Safely write one HANDLE-sized EPROCESS field. 中文说明：用于 Ksword
    管理的 _EPROCESS.UniqueProcessId 修改和恢复。

Arguments:

    ProcessObject - Target EPROCESS.
    Offset - Field offset inside EPROCESS.
    Value - HANDLE-sized value to write.

Return Value:

    STATUS_SUCCESS or validation/exception status.

--*/
{
    if (ProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKDriverProcessDynOffsetPresent(Offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        RtlCopyMemory((PUCHAR)ProcessObject + Offset, &Value, sizeof(Value));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverValidateActiveProcessLinksForUnlink(
    _In_ LIST_ENTRY* Link,
    _Outptr_ LIST_ENTRY** PreviousOut,
    _Outptr_ LIST_ENTRY** NextOut
    )
/*++

Routine Description:

    Validate the target EPROCESS.ActiveProcessLinks node before DKOM unlink.
    中文说明：隐藏前必须确认目标节点仍在双向链中，且前后节点能回指
    当前节点；否则拒绝摘链，避免在已损坏链表上继续写入。

Arguments:

    Link - 目标进程的 ActiveProcessLinks 字段地址。
    PreviousOut - 返回 Link->Blink。
    NextOut - 返回 Link->Flink。

Return Value:

    STATUS_SUCCESS 表示可摘链；失败表示参数、对齐或邻居一致性检查未通过。

--*/
{
    LIST_ENTRY* next = NULL;
    LIST_ENTRY* previous = NULL;

    if (Link == NULL || PreviousOut == NULL || NextOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *PreviousOut = NULL;
    *NextOut = NULL;

    if (!KswordARKDriverProcessListPointerAligned(Link)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    __try {
        next = Link->Flink;
        previous = Link->Blink;
        if (!KswordARKDriverProcessListPointerAligned(next) ||
            !KswordARKDriverProcessListPointerAligned(previous) ||
            next == Link ||
            previous == Link ||
            next->Blink != Link ||
            previous->Flink != Link) {
            return STATUS_DATA_ERROR;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *PreviousOut = previous;
    *NextOut = next;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverTryProcessListOffsets(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_ ULONG UniqueProcessIdOffset,
    _In_ ULONG ActiveProcessLinksOffset
    )
/*++

Routine Description:

    Validate one candidate pair of _EPROCESS.UniqueProcessId and
    _EPROCESS.ActiveProcessLinks offsets.

Arguments:

    ProcessObject - Target EPROCESS.
    ProcessId - Original target PID.
    UniqueProcessIdOffset - Candidate UniqueProcessId offset.
    ActiveProcessLinksOffset - Candidate ActiveProcessLinks offset.

Return Value:

    STATUS_SUCCESS when the pair matches the target process and points to a
    consistent active-process list node.

--*/
{
    HANDLE uniqueProcessId = NULL;
    LIST_ENTRY* previous = NULL;
    LIST_ENTRY* next = NULL;
    LIST_ENTRY* link = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ProcessObject == NULL || ProcessId == 0UL || ProcessId <= 4UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKDriverProcessDynOffsetPresent(UniqueProcessIdOffset) ||
        !KswordARKDriverProcessDynOffsetPresent(ActiveProcessLinksOffset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = KswordARKDriverReadProcessHandleField(
        ProcessObject,
        UniqueProcessIdOffset,
        &uniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (HandleToULong(uniqueProcessId) != ProcessId) {
        return STATUS_NOT_FOUND;
    }

    link = (LIST_ENTRY*)((PUCHAR)ProcessObject + ActiveProcessLinksOffset);
    return KswordARKDriverValidateActiveProcessLinksForUnlink(link, &previous, &next);
}

static NTSTATUS
KswordARKDriverResolveProcessListOffsets(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_opt_ const KSW_DYN_STATE* DynState,
    _Out_ ULONG* UniqueProcessIdOffsetOut,
    _Out_ ULONG* ActiveProcessLinksOffsetOut
    )
/*++

Routine Description:

    Resolve _EPROCESS.UniqueProcessId and ActiveProcessLinks offsets for the
    target process. 中文说明：优先使用 DynData/PDB profile；缺失时利用这两个
    字段在 EPROCESS 中相邻的布局做保守运行时扫描，避免未刷新 Kernel
    DynData 页面时右键隐藏直接返回 STATUS_PROCEDURE_NOT_FOUND。

Arguments:

    ProcessObject - Target EPROCESS.
    ProcessId - Original target PID.
    DynState - Optional current DynData snapshot.
    UniqueProcessIdOffsetOut - Receives UniqueProcessId offset.
    ActiveProcessLinksOffsetOut - Receives ActiveProcessLinks offset.

Return Value:

    STATUS_SUCCESS or the best observed failure status.

--*/
{
    ULONG uniqueOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG activeOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG scanOffset = 0UL;
    NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
    NTSTATUS lastStatus = STATUS_PROCEDURE_NOT_FOUND;

    if (ProcessObject == NULL ||
        UniqueProcessIdOffsetOut == NULL ||
        ActiveProcessLinksOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *UniqueProcessIdOffsetOut = KSW_DYN_OFFSET_UNAVAILABLE;
    *ActiveProcessLinksOffsetOut = KSW_DYN_OFFSET_UNAVAILABLE;

    if (DynState != NULL && DynState->Initialized) {
        uniqueOffset = DynState->Kernel.EpUniqueProcessId;
        activeOffset = DynState->Kernel.EpActiveProcessLinks;
    }

    if (KswordARKDriverProcessDynOffsetPresent(activeOffset) &&
        !KswordARKDriverProcessDynOffsetPresent(uniqueOffset) &&
        activeOffset >= sizeof(HANDLE)) {
        uniqueOffset = activeOffset - (ULONG)sizeof(HANDLE);
    }
    if (KswordARKDriverProcessDynOffsetPresent(uniqueOffset) &&
        !KswordARKDriverProcessDynOffsetPresent(activeOffset) &&
        uniqueOffset <= (MAXULONG - (ULONG)sizeof(HANDLE))) {
        activeOffset = uniqueOffset + (ULONG)sizeof(HANDLE);
    }

    if (KswordARKDriverProcessDynOffsetPresent(uniqueOffset) &&
        KswordARKDriverProcessDynOffsetPresent(activeOffset)) {
        status = KswordARKDriverTryProcessListOffsets(
            ProcessObject,
            ProcessId,
            uniqueOffset,
            activeOffset);
        if (NT_SUCCESS(status)) {
            *UniqueProcessIdOffsetOut = uniqueOffset;
            *ActiveProcessLinksOffsetOut = activeOffset;
            return STATUS_SUCCESS;
        }
        lastStatus = status;
    }

    for (scanOffset = 0UL;
         scanOffset + (ULONG)sizeof(HANDLE) + (ULONG)sizeof(LIST_ENTRY) <= KSWORD_ARK_PROCESS_OFFSET_SCAN_LIMIT;
         scanOffset += (ULONG)sizeof(PVOID)) {
        HANDLE candidatePid = NULL;

        status = KswordARKDriverReadProcessHandleField(ProcessObject, scanOffset, &candidatePid);
        if (!NT_SUCCESS(status)) {
            if (status != STATUS_PROCEDURE_NOT_FOUND) {
                lastStatus = status;
            }
            continue;
        }
        if (HandleToULong(candidatePid) != ProcessId) {
            continue;
        }

        uniqueOffset = scanOffset;
        activeOffset = scanOffset + (ULONG)sizeof(HANDLE);
        status = KswordARKDriverTryProcessListOffsets(
            ProcessObject,
            ProcessId,
            uniqueOffset,
            activeOffset);
        if (NT_SUCCESS(status)) {
            *UniqueProcessIdOffsetOut = uniqueOffset;
            *ActiveProcessLinksOffsetOut = activeOffset;
            return STATUS_SUCCESS;
        }
        lastStatus = status;
    }

    return (lastStatus == STATUS_NOT_FOUND) ? STATUS_PROCEDURE_NOT_FOUND : lastStatus;
}

static HANDLE
KswordARKDriverBuildHiddenUniqueProcessId(
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Build a deterministic fake PID for the UniqueProcessId field. 中文说明：高位
    打标并保留低位 PID 信息，避免与正常低范围 PID 冲突，同时便于调试。

Arguments:

    ProcessId - Original PID.

Return Value:

    HANDLE-sized fake PID value.

--*/
{
    ULONG hiddenPid = KSWORD_ARK_PROCESS_HIDDEN_PID_TAG |
        (ProcessId & KSWORD_ARK_PROCESS_HIDDEN_PID_MASK);

    if (hiddenPid == ProcessId || hiddenPid <= 4UL) {
        hiddenPid = KSWORD_ARK_PROCESS_HIDDEN_PID_TAG;
    }
    return ULongToHandle(hiddenPid);
}

static NTSTATUS
KswordARKDriverPatchUniqueProcessIdForHide(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_ ULONG UniqueProcessIdOffset,
    _Out_ HANDLE* OriginalUniqueProcessIdOut,
    _Out_ HANDLE* HiddenUniqueProcessIdOut
    )
/*++

Routine Description:

    Patch _EPROCESS.UniqueProcessId for Ksword-managed hide.

Arguments:

    ProcessObject - Target EPROCESS.
    ProcessId - Original PID.
    UniqueProcessIdOffset - Offset resolved from DynData or runtime scan.
    OriginalUniqueProcessIdOut - Receives original HANDLE value.
    HiddenUniqueProcessIdOut - Receives written fake HANDLE value.

Return Value:

    STATUS_SUCCESS when the PID field was modified.

--*/
{
    HANDLE originalUniqueProcessId = NULL;
    HANDLE hiddenUniqueProcessId = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (OriginalUniqueProcessIdOut == NULL || HiddenUniqueProcessIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OriginalUniqueProcessIdOut = NULL;
    *HiddenUniqueProcessIdOut = NULL;

    status = KswordARKDriverReadProcessHandleField(
        ProcessObject,
        UniqueProcessIdOffset,
        &originalUniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (HandleToULong(originalUniqueProcessId) != ProcessId) {
        return STATUS_DATA_ERROR;
    }

    hiddenUniqueProcessId = KswordARKDriverBuildHiddenUniqueProcessId(ProcessId);
    status = KswordARKDriverWriteProcessHandleField(
        ProcessObject,
        UniqueProcessIdOffset,
        hiddenUniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *OriginalUniqueProcessIdOut = originalUniqueProcessId;
    *HiddenUniqueProcessIdOut = hiddenUniqueProcessId;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverUnlinkActiveProcessLinks(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ActiveProcessLinksOffset,
    _Outptr_ LIST_ENTRY** LinkOut,
    _Outptr_ LIST_ENTRY** PreviousOut,
    _Outptr_ LIST_ENTRY** NextOut
    )
/*++

Routine Description:

    Remove one process from the kernel ActiveProcessLinks list. 中文说明：本函数
    只摘 ActiveProcessLinks，不删除 PspCidTable，也不关闭句柄表；因此
    普通 NtQuerySystemInformation 视图不可见，但 Ksword 仍可通过 CID
    表对象指针和独立对象管理器引用路径重新验证 EPROCESS。

Arguments:

    ProcessObject - 已引用的目标 EPROCESS。
    ActiveProcessLinksOffset - DynData 给出的 EPROCESS.ActiveProcessLinks 偏移。
    LinkOut - 返回目标 LIST_ENTRY 地址。
    PreviousOut - 返回摘链前前驱节点。
    NextOut - 返回摘链前后继节点。

Return Value:

    STATUS_SUCCESS 表示摘链完成；失败表示偏移缺失、链表不一致或异常访问。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    LIST_ENTRY* link = NULL;
    LIST_ENTRY* previous = NULL;
    LIST_ENTRY* next = NULL;

    if (ProcessObject == NULL || LinkOut == NULL || PreviousOut == NULL || NextOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *LinkOut = NULL;
    *PreviousOut = NULL;
    *NextOut = NULL;

    if (!KswordARKDriverProcessDynOffsetPresent(ActiveProcessLinksOffset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    link = (LIST_ENTRY*)((PUCHAR)ProcessObject + ActiveProcessLinksOffset);
    status = KswordARKDriverValidateActiveProcessLinksForUnlink(link, &previous, &next);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        previous->Flink = next;
        next->Blink = previous;
        link->Flink = link;
        link->Blink = link;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *LinkOut = link;
    *PreviousOut = previous;
    *NextOut = next;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverRestoreUniqueProcessIdRecord(
    _Inout_ KSWORD_ARK_PROCESS_HIDE_RECORD* Record
    )
/*++

Routine Description:

    Restore _EPROCESS.UniqueProcessId for one Ksword hide record.

Arguments:

    Record - Hide record with original/fake PID values.

Return Value:

    STATUS_SUCCESS when restored or no PID patch is pending.

--*/
{
    HANDLE currentUniqueProcessId = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Record == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Record->UniqueProcessIdPatched) {
        return STATUS_SUCCESS;
    }
    if (Record->ProcessObject == NULL ||
        !KswordARKDriverProcessDynOffsetPresent(Record->UniqueProcessIdOffset)) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKDriverReadProcessHandleField(
        Record->ProcessObject,
        Record->UniqueProcessIdOffset,
        &currentUniqueProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (currentUniqueProcessId == Record->OriginalUniqueProcessId) {
        Record->UniqueProcessIdPatched = FALSE;
        return STATUS_SUCCESS;
    }
    if (currentUniqueProcessId != Record->HiddenUniqueProcessId) {
        return STATUS_DATA_ERROR;
    }

    status = KswordARKDriverWriteProcessHandleField(
        Record->ProcessObject,
        Record->UniqueProcessIdOffset,
        Record->OriginalUniqueProcessId);
    if (NT_SUCCESS(status)) {
        Record->UniqueProcessIdPatched = FALSE;
    }
    return status;
}

static NTSTATUS
KswordARKDriverRestoreActiveProcessLinksRecord(
    _Inout_ KSWORD_ARK_PROCESS_HIDE_RECORD* Record
    )
/*++

Routine Description:

    Restore one Ksword-hidden process back into ActiveProcessLinks. 中文说明：
    恢复时要求目标节点仍保持 self-loop。若隐藏时保存的前后节点仍然
    相邻，则放回原位置；若链表期间发生正常插入导致原邻居不再相邻，
    则退化为插到 PsInitialSystemProcess 后面，避免切断当前活动链。

Arguments:

    Record - 隐藏记录，包含目标 EPROCESS、目标链表节点和保存的前后节点。

Return Value:

    STATUS_SUCCESS 表示恢复完成或记录本来未摘链；失败表示链表状态不适合恢复。

--*/
{
    LIST_ENTRY* link = NULL;
    LIST_ENTRY* previous = NULL;
    LIST_ENTRY* next = NULL;
    LIST_ENTRY* insertAfter = NULL;
    LIST_ENTRY* insertBefore = NULL;
    LIST_ENTRY* systemHead = NULL;

    if (Record == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Record->ActiveListUnlinked) {
        return STATUS_SUCCESS;
    }

    link = Record->ActiveProcessLinks;
    previous = Record->PreviousLink;
    next = Record->NextLink;

    if (!KswordARKDriverProcessListPointerAligned(link) ||
        !KswordARKDriverProcessListPointerAligned(previous) ||
        !KswordARKDriverProcessListPointerAligned(next) ||
        !KswordARKDriverProcessDynOffsetPresent(Record->ActiveProcessLinksOffset)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    __try {
        if (link->Flink != link || link->Blink != link) {
            return STATUS_DATA_ERROR;
        }

        /*
         * Prefer exact original placement when the saved neighbors are still
         * adjacent.  If they are not, insert immediately after the System
         * process list head.  This fallback preserves all current nodes instead
         * of overwriting previous->Flink/next->Blink across a changed chain.
         */
        if (previous->Flink == next && next->Blink == previous) {
            insertAfter = previous;
            insertBefore = next;
        }
        else {
            if (PsInitialSystemProcess == NULL) {
                return STATUS_PROCEDURE_NOT_FOUND;
            }
            systemHead = (LIST_ENTRY*)((PUCHAR)PsInitialSystemProcess + Record->ActiveProcessLinksOffset);
            if (!KswordARKDriverProcessListPointerAligned(systemHead) ||
                !KswordARKDriverProcessListPointerAligned(systemHead->Flink) ||
                systemHead->Flink->Blink != systemHead) {
                return STATUS_DATA_ERROR;
            }
            insertAfter = systemHead;
            insertBefore = systemHead->Flink;
        }

        link->Blink = insertAfter;
        link->Flink = insertBefore;
        insertAfter->Flink = link;
        insertBefore->Blink = link;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    Record->ActiveListUnlinked = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverReadProcessPointerField(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG Offset,
    _Out_ ULONG64* ValueOut
    )
/*++

Routine Description:

    按 EPROCESS 偏移读取一个指针字段，统一通过 RuntimeReadMemory 访问候选地址。

Arguments:

    ProcessObject - 目标 EPROCESS 对象。
    Offset - 目标字段在 EPROCESS 内部的偏移。
    ValueOut - 返回读取到的指针值，统一扩展为 ULONG64。

Return Value:

    读取成功返回 STATUS_SUCCESS；参数错误、偏移缺失或异常读取返回对应状态。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID pointerValue = NULL;

    if (ProcessObject == NULL || ValueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ValueOut = 0ULL;
    if (!KswordARKDriverProcessDynOffsetPresent(Offset)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!KswordARKRuntimeReadMemory(
            (const UCHAR*)ProcessObject + Offset,
            &pointerValue,
            sizeof(pointerValue))) {
        status = STATUS_ACCESS_VIOLATION;
    }
    else {
        *ValueOut = (ULONG64)(ULONG_PTR)pointerValue;
    }

    return status;
}

static BOOLEAN
KswordARKDriverShouldSkipTerminatingProcess(
    _In_ PEPROCESS ProcessObject,
    _In_ const KSW_DYN_STATE* DynState
    )
/*++

Routine Description:

    判定候选 EPROCESS 是否已经退出或正在退出。
    首选导出例程 PsGetProcessExitStatus，它直接读 EPROCESS.ExitStatus，不依赖任何
    DynData 偏移；退化路径才回到 SKT64 那套 EPROCESS.ObjectTable 判据。

Arguments:

    ProcessObject - 候选进程 EPROCESS。
    DynState - 本次枚举开始时截取的统一 DynData 状态，可为 NULL。

Return Value:

    ExitStatus 不再是 STATUS_PENDING，或 ObjectTable 可读且为 NULL 时返回 TRUE，
    表示该进程处于 terminating/exited 状态。
    两条判据都拿不到结论时返回 FALSE，避免因为诊断数据缺失误隐藏正常进程。

--*/
{
    ULONG64 objectTableAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ProcessObject == NULL) {
        return FALSE;
    }

    //
    // EPROCESS.ExitStatus 在进程创建时被置为 STATUS_PENDING，终止时写入真实退出码。
    // PsGetProcessExitStatus 是导出例程，因此这条判据在 DynData 完全缺失时依然可用——
    // System Informer 偏移表按 ntoskrnl 的 TimeDateStamp 精确匹配，新内核往往不在表内，
    // 此时 EpObjectTable 不可用，只靠下面的 ObjectTable 判据会退化成“永远不是残骸”。
    //
    if (PsGetProcessExitStatus(ProcessObject) != STATUS_PENDING) {
        return TRUE;
    }

    if (DynState == NULL || !DynState->Initialized ||
        !KswordARKDriverProcessDynOffsetPresent(DynState->Kernel.EpObjectTable)) {
        return FALSE;
    }

    status = KswordARKDriverReadProcessPointerField(
        ProcessObject,
        DynState->Kernel.EpObjectTable,
        &objectTableAddress);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return (objectTableAddress == 0ULL) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKDriverHasStableProcessLifetime(
    _In_ PEPROCESS ProcessObject,
    _In_ const KSW_DYN_STATE* DynState
    )
{
    ULONG64 objectTableAddress = 0ULL;

    if (ProcessObject == NULL || PsGetProcessExitStatus(ProcessObject) != STATUS_PENDING) {
        return FALSE;
    }
    if (DynState == NULL || !DynState->Initialized ||
        !KswordARKDriverProcessDynOffsetPresent(DynState->Kernel.EpObjectTable)) {
        return TRUE;
    }
    if (!NT_SUCCESS(KswordARKDriverReadProcessPointerField(
            ProcessObject,
            DynState->Kernel.EpObjectTable,
            &objectTableAddress))) {
        return FALSE;
    }
    return objectTableAddress != 0ULL;
}

static VOID
KswordARKDriverCopyImageName(
    _Out_writes_all_(16) CHAR destinationImageName[16],
    _In_opt_z_ const CHAR* sourceImageName
    )
{
    ULONG copyIndex = 0;

    if (destinationImageName == NULL) {
        return;
    }

    RtlZeroMemory(destinationImageName, 16);
    if (sourceImageName == NULL) {
        return;
    }

    for (copyIndex = 0; copyIndex < 15U; ++copyIndex) {
        destinationImageName[copyIndex] = sourceImageName[copyIndex];
        if (sourceImageName[copyIndex] == '\0') {
            break;
        }
    }
    destinationImageName[15] = '\0';
}

static VOID
KswordARKDriverAppendProcessEntry(
    _Inout_ KSWORD_ARK_ENUM_PROCESS_RESPONSE* response,
    _In_ size_t entryCapacity,
    _In_ ULONG processId,
    _In_ ULONG parentProcessId,
    _In_ ULONG processFlags,
    _In_opt_z_ const CHAR* imageName,
    _In_opt_ PEPROCESS processObject
    )
{
    KSWORD_ARK_PROCESS_ENTRY* entry = NULL;

    if (response == NULL) {
        return;
    }

    if (response->totalCount != MAXULONG) {
        response->totalCount += 1UL;
    }

    if ((size_t)response->returnedCount >= entryCapacity) {
        return;
    }

    entry = &response->entries[response->returnedCount];
    RtlZeroMemory(entry, sizeof(*entry));
    entry->processId = processId;
    entry->parentProcessId = parentProcessId;
    entry->flags = processFlags;
    KswordARKDriverCopyImageName(entry->imageName, imageName);
    if (processObject != NULL) {
        KswordARKProcessPopulateExtendedEntry(entry, processObject);
    }
    else {
        /*
         * CID-only placeholder:
         * - Inputs: a decoded PspCidTable row whose object type matched Process
         *   but could not be safely referenced for detail sampling.
         * - Processing: keep the CID value visible and mark the detail state as
         *   read-failed instead of dropping the row.
         * - Return behavior: no return value; the partially populated row still
         *   lets R3 offer object-based R0 actions by CID.
         */
        entry->r0Status = KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED;
    }
    response->returnedCount += 1UL;
}

static VOID
KswordARKDriverEnumProcessCidCallback(
    _In_ const KSW_CROSSVIEW_CID_ENTRY* Entry,
    _Inout_opt_ PVOID Context
    )
/*++

Routine Description:

    Merge one direct PspCidTable process candidate into the enumeration
    response. Weak CID evidence is retained for diagnostics, but only a stable
    object reference plus complete active-list comparison receives the trusted
    hidden-process flags consumed by R3.

Arguments:

    Entry - CID walker payload.
    Context - KSWORD_ARK_ENUM_PROCESS_CID_CONTEXT.

Return Value:

    None. The response buffer is updated in place.

--*/
{
    KSWORD_ARK_ENUM_PROCESS_CID_CONTEXT* enumContext =
        (KSWORD_ARK_ENUM_PROCESS_CID_CONTEXT*)Context;
    ULONG processFlags =
        KSWORD_ARK_PROCESS_FLAG_KERNEL_ENUMERATED |
        KSWORD_ARK_PROCESS_FLAG_CID_TABLE_ENUMERATED;
    ULONG parentProcessId = 0UL;
    const CHAR* imageName = "CIDOnly";

    if (enumContext == NULL || Entry == NULL) {
        return;
    }
    if (!KswordARKDriverPidInScanRange(
            Entry->CidValue,
            enumContext->ScanStartPid,
            enumContext->ScanEndPid)) {
        return;
    }
    if (enumContext->ActivePidBitmap != NULL &&
        enumContext->ActivePidBitmapBytes != 0U &&
        KswordARKDriverBitmapHasPid(
            enumContext->ActivePidBitmap,
            enumContext->ActivePidBitmapBytes,
            Entry->CidValue)) {
        return;
    }

    if (enumContext->ActiveWalkAvailable) {
        processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_FROM_ACTIVE_LIST;
    }
    else {
        processFlags |= KSWORD_ARK_PROCESS_FLAG_CID_TABLE_UNCONFIRMED;
    }
    if (KswordARKDriverIsProcessHiddenByUi(Entry->CidValue)) {
        processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI;
    }

    if (Entry->Referenced && Entry->Object != NULL) {
        PEPROCESS processObject = (PEPROCESS)Entry->Object;
        const BOOLEAN terminating =
            KswordARKDriverShouldSkipTerminatingProcess(processObject, enumContext->DynState);
        const BOOLEAN identityMatches =
            (HandleToULong(PsGetProcessId(processObject)) == Entry->CidValue) ||
            KswordARKDriverIsOwnedHiddenObject(Entry->CidValue, processObject);
        const BOOLEAN stableLifetime =
            KswordARKDriverHasStableProcessLifetime(processObject, enumContext->DynState);

        if (terminating) {
            processFlags |= KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED;
        }
        if (!identityMatches || !stableLifetime || terminating ||
            !enumContext->ActiveWalkAvailable) {
            processFlags |= KSWORD_ARK_PROCESS_FLAG_CID_TABLE_UNCONFIRMED;
        }
        else {
            processFlags |= KSWORD_ARK_PROCESS_FLAG_CID_OBJECT_REFERENCE_STABLE;
        }
        parentProcessId = HandleToULong(PsGetProcessInheritedFromUniqueProcessId(processObject));
        imageName = PsGetProcessImageFileName(processObject);
        KswordARKDriverAppendProcessEntry(
            enumContext->Response,
            enumContext->EntryCapacity,
            Entry->CidValue,
            parentProcessId,
            processFlags,
            imageName,
            processObject);
        return;
    }

    processFlags |= KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED;
    processFlags |= KSWORD_ARK_PROCESS_FLAG_CID_TABLE_UNCONFIRMED;
    KswordARKDriverAppendProcessEntry(
        enumContext->Response,
        enumContext->EntryCapacity,
        Entry->CidValue,
        parentProcessId,
        processFlags,
        imageName,
        NULL);
}

static NTSTATUS
KswordARKDriverEnumerateProcessesByCidTable(
    _Inout_ KSWORD_ARK_ENUM_PROCESS_RESPONSE* Response,
    _In_ size_t EntryCapacity,
    _In_ const KSW_DYN_STATE* DynState,
    _In_reads_bytes_opt_(ActivePidBitmapBytes) const UCHAR* ActivePidBitmap,
    _In_ size_t ActivePidBitmapBytes,
    _In_ ULONG ScanStartPid,
    _In_ ULONG ScanEndPid,
    _In_ BOOLEAN ActiveWalkAvailable
    )
/*++

Routine Description:

    Enumerate process rows directly from PspCidTable. 中文说明：这替代旧的
    “按 PID 步进 + PsLookupProcessByProcessId”扫描，避免 PsLookup 被 hook
    或候选对象处于特殊状态时把 CID 表证据行隐藏。

Arguments:

    Response - Mutable enum-process response.
    EntryCapacity - Maximum number of entries that fit in Response.
    DynState - DynData snapshot captured by the caller.
    ActivePidBitmap - Optional bitmap of PIDs already seen by PsGetNextProcess.
    ActivePidBitmapBytes - Byte length of ActivePidBitmap.
    ScanStartPid - Lower inclusive CID range.
    ScanEndPid - Upper inclusive CID range.
    ActiveWalkAvailable - TRUE when ActivePidBitmap represents an active walk.

Return Value:

    STATUS_SUCCESS only when the CID table walk completed; overflow or any
    resolver/walker failure is returned so callers can veto trusted flags.
    Rows already appended remain diagnostic evidence.

--*/
{
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KSWORD_ARK_ENUM_PROCESS_CID_CONTEXT enumContext;
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingCapabilityMask = 0ULL;
    ULONG visitedEntries = 0UL;
    BOOLEAN usedDynDataGlobal = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL || DynState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&fieldOffsets, sizeof(fieldOffsets));
    RtlZeroMemory(&enumContext, sizeof(enumContext));
    KswordARKCrossViewFillFieldOffsets(DynState, &fieldOffsets);

    status = KswordARKCrossViewResolvePspCidTableAddress(
        DynState,
        &fieldOffsets,
        &pspCidTableAddress,
        &missingCapabilityMask,
        &usedDynDataGlobal);
    UNREFERENCED_PARAMETER(missingCapabilityMask);
    UNREFERENCED_PARAMETER(usedDynDataGlobal);
    if (!NT_SUCCESS(status) || pspCidTableAddress == NULL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    enumContext.Response = Response;
    enumContext.EntryCapacity = EntryCapacity;
    enumContext.DynState = DynState;
    enumContext.ActivePidBitmap = ActivePidBitmap;
    enumContext.ActivePidBitmapBytes = ActivePidBitmapBytes;
    enumContext.ScanStartPid = ScanStartPid;
    enumContext.ScanEndPid = ScanEndPid;
    enumContext.ActiveWalkAvailable = ActiveWalkAvailable;

    status = KswordARKCrossViewWalkCidTable(
        DynState,
        pspCidTableAddress,
        *PsProcessType,
        KSWORD_ARK_ENUM_CID_WALK_MAX_NODES,
        KswordARKDriverEnumProcessCidCallback,
        &enumContext,
        &visitedEntries);
    UNREFERENCED_PARAMETER(visitedEntries);
    return status;
}

static NTSTATUS
KswordARKDriverResolveSignatureLevelsFromSigner(
    _In_ UCHAR signerType,
    _Out_ UCHAR* signatureLevel,
    _Out_ UCHAR* sectionSignatureLevel
    )
{
    if (signatureLevel == NULL || sectionSignatureLevel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (signerType) {
    case KSWORD_PS_PROTECTED_SIGNER_NONE:
        *signatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_AUTHENTICODE:
        *signatureLevel = SE_SIGNING_LEVEL_AUTHENTICODE;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_AUTHENTICODE;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_CODEGEN:
        *signatureLevel = SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_STORE;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_ANTIMALWARE:
        *signatureLevel = SE_SIGNING_LEVEL_ANTIMALWARE;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_ANTIMALWARE;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_LSA:
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_MICROSOFT;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_WINDOWS:
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_WINTCB:
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS_TCB;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_WINSYSTEM:
        // WinSystem 是 System(PID 4) 使用的最高 signer。它本身没有用户态映像，
        // 因此内核里的签名级别不具参考性；这里沿用 WinTcb 的组合，section 保持
        // WINDOWS 而不是 WINDOWS_TCB——后者会让被提权的进程几乎加载不了任何 DLL。
        *signatureLevel = SE_SIGNING_LEVEL_WINDOWS_TCB;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_WINDOWS;
        return STATUS_SUCCESS;
    case KSWORD_PS_PROTECTED_SIGNER_APP:
        *signatureLevel = SE_SIGNING_LEVEL_STORE;
        *sectionSignatureLevel = SE_SIGNING_LEVEL_STORE;
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

// PPLcontrol-style fallback: calculate target bytes here, then let Phase-2
// DynData-owned process_extended.c perform the actual EPROCESS patch.
static NTSTATUS
KswordARKDriverPatchProcessProtectionStateByPid(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR signerType = (UCHAR)((protectionLevel & 0xF0U) >> 4U);
    UCHAR signatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
    UCHAR sectionSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;

    if (protectionLevel == 0U) {
        signerType = KSWORD_PS_PROTECTED_SIGNER_NONE;
    }

    status = KswordARKDriverResolveSignatureLevelsFromSigner(
        signerType,
        &signatureLevel,
        &sectionSignatureLevel);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return KswordARKProcessPatchProtectionByDynData(
        processId,
        protectionLevel,
        signatureLevel,
        sectionSignatureLevel);
}

NTSTATUS
KswordARKDriverSetProcessVisibility(
    _In_ ULONG ProcessId,
    _In_ ULONG Action,
    _In_ ULONG Flags,
    _Out_ ULONG* StatusOut,
    _Out_ ULONG* HiddenCountOut
    )
/*++

Routine Description:

    Execute Ksword-owned process visibility changes. 中文说明：HIDE 根据 Flags
    选择只修改 _EPROCESS.UniqueProcessId、只摘除 ActiveProcessLinks，或执行
    两者兼容旧版行为；所有模式都保留 PspCidTable，UNHIDE/CLEAR_ALL 只恢复
    由本驱动保存的 PID 和链表记录，不接受 R3 传入任何内核地址。

Arguments:

    ProcessId - 目标 PID；ClearAll 动作忽略该值。
    Action - HIDE/UNHIDE/CLEAR_ALL。
    Flags - HIDE 模式选择；0 表示兼容旧版双操作。
    StatusOut - 返回可读状态枚举。
    HiddenCountOut - 返回当前隐藏 PID 数量。

Return Value:

    STATUS_SUCCESS 表示动作完成；失败表示参数、查找、DynData 或链表状态异常。

--*/
{
    ULONG index = 0UL;
    ULONG foundIndex = MAXULONG;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS restoreStatus = STATUS_SUCCESS;
    PEPROCESS processObject = NULL;
    KSW_DYN_STATE dynState;
    ULONG uniqueProcessIdOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG activeProcessLinksOffset = KSW_DYN_OFFSET_UNAVAILABLE;
    ULONG visibilityFlags = 0UL;
    BOOLEAN shouldPatchUniquePid = FALSE;
    BOOLEAN shouldUnlinkActiveList = FALSE;

    if (StatusOut == NULL || HiddenCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
    *HiddenCountOut = 0UL;
    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDriverEnsureProcessHideStateInitialized();

    if (Action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE) {
        visibilityFlags = Flags;
        if (visibilityFlags == 0UL) {
            visibilityFlags = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH;
        }
        visibilityFlags &= KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH;
        if (visibilityFlags == 0UL) {
            return STATUS_INVALID_PARAMETER;
        }

        /*
         * The booleans are computed once before acquiring the state lock so the
         * actual mutation path has a single source of truth.  Return behavior:
         * UNHIDE/CLEAR_ALL ignore Flags and restore whatever a prior record says
         * was actually changed.
         */
        shouldPatchUniquePid =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID) != 0UL)
            ? TRUE
            : FALSE;
        shouldUnlinkActiveList =
            ((visibilityFlags & KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST) != 0UL)
            ? TRUE
            : FALSE;
    }

    if (Action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE &&
        (ProcessId == 0UL || ProcessId <= 4UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE &&
        (ProcessId == 0UL || ProcessId <= 4UL)) {
        *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE;
        KswordARKAcquirePushLockShared(&g_KswordArkProcessHideState.Lock);
        *HiddenCountOut = g_KswordArkProcessHideState.Count;
        KswordARKReleasePushLockShared(&g_KswordArkProcessHideState.Lock);
        return STATUS_SUCCESS;
    }
    if (Action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE) {
        BOOLEAN alreadyHidden = FALSE;
        KswordARKAcquirePushLockShared(&g_KswordArkProcessHideState.Lock);
        for (index = 0UL; index < g_KswordArkProcessHideState.Count; ++index) {
            if (g_KswordArkProcessHideState.Records[index].Pid == ProcessId) {
                alreadyHidden = TRUE;
                break;
            }
        }
        *HiddenCountOut = g_KswordArkProcessHideState.Count;
        KswordARKReleasePushLockShared(&g_KswordArkProcessHideState.Lock);
        if (alreadyHidden) {
            *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
            return STATUS_SUCCESS;
        }

        KswordARKDynDataSnapshot(&dynState);
        status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &processObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = KswordARKDriverResolveProcessListOffsets(
            processObject,
            ProcessId,
            &dynState,
            &uniqueProcessIdOffset,
            &activeProcessLinksOffset);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(processObject);
            processObject = NULL;
            return status;
        }
    }

    KswordARKAcquirePushLockExclusive(&g_KswordArkProcessHideState.Lock);
    __try {
        for (index = 0UL; index < g_KswordArkProcessHideState.Count; ++index) {
            if (g_KswordArkProcessHideState.Records[index].Pid == ProcessId) {
                foundIndex = index;
                break;
            }
        }

        if (Action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL) {
            index = 0UL;
            while (index < g_KswordArkProcessHideState.Count) {
                KSWORD_ARK_PROCESS_HIDE_RECORD* record =
                    &g_KswordArkProcessHideState.Records[index];
                restoreStatus = KswordARKDriverRestoreUniqueProcessIdRecord(record);
                if (NT_SUCCESS(restoreStatus)) {
                    restoreStatus = KswordARKDriverRestoreActiveProcessLinksRecord(record);
                }
                if (!NT_SUCCESS(restoreStatus)) {
                    if (NT_SUCCESS(status)) {
                        status = restoreStatus;
                    }
                    ++index;
                    continue;
                }

                if (record->ProcessObject != NULL) {
                    ObDereferenceObject(record->ProcessObject);
                    record->ProcessObject = NULL;
                }
                for (foundIndex = index + 1UL;
                     foundIndex < g_KswordArkProcessHideState.Count;
                     ++foundIndex) {
                    g_KswordArkProcessHideState.Records[foundIndex - 1UL] =
                        g_KswordArkProcessHideState.Records[foundIndex];
                }
                g_KswordArkProcessHideState.Count -= 1UL;
                RtlZeroMemory(
                    &g_KswordArkProcessHideState.Records[g_KswordArkProcessHideState.Count],
                    sizeof(g_KswordArkProcessHideState.Records[g_KswordArkProcessHideState.Count]));
            }
            *StatusOut = (g_KswordArkProcessHideState.Count == 0UL)
                ? KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED
                : KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
        }
        else if (Action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE) {
            if (foundIndex != MAXULONG) {
                *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
            }
            else if (g_KswordArkProcessHideState.Count >= KSWORD_ARK_PROCESS_HIDE_MAX_PIDS) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else {
                KSWORD_ARK_PROCESS_HIDE_RECORD* record =
                    &g_KswordArkProcessHideState.Records[g_KswordArkProcessHideState.Count];
                LIST_ENTRY* link = NULL;
                LIST_ENTRY* previous = NULL;
                LIST_ENTRY* next = NULL;
                HANDLE originalUniqueProcessId = NULL;
                HANDLE hiddenUniqueProcessId = NULL;

                if (shouldPatchUniquePid) {
                    status = KswordARKDriverPatchUniqueProcessIdForHide(
                        processObject,
                        ProcessId,
                        uniqueProcessIdOffset,
                        &originalUniqueProcessId,
                        &hiddenUniqueProcessId);
                    if (!NT_SUCCESS(status)) {
                        *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
                    }
                }
                if (NT_SUCCESS(status) && shouldUnlinkActiveList) {
                    status = KswordARKDriverUnlinkActiveProcessLinks(
                        processObject,
                        activeProcessLinksOffset,
                        &link,
                        &previous,
                        &next);
                    if (!NT_SUCCESS(status) && shouldPatchUniquePid) {
                        KSWORD_ARK_PROCESS_HIDE_RECORD rollbackRecord;
                        NTSTATUS rollbackStatus = STATUS_SUCCESS;
                        RtlZeroMemory(&rollbackRecord, sizeof(rollbackRecord));
                        rollbackRecord.ProcessObject = processObject;
                        rollbackRecord.Pid = ProcessId;
                        rollbackRecord.UniqueProcessIdOffset = uniqueProcessIdOffset;
                        rollbackRecord.OriginalUniqueProcessId = originalUniqueProcessId;
                        rollbackRecord.HiddenUniqueProcessId = hiddenUniqueProcessId;
                        rollbackRecord.UniqueProcessIdPatched = TRUE;
                        rollbackStatus = KswordARKDriverRestoreUniqueProcessIdRecord(&rollbackRecord);
                        if (!NT_SUCCESS(rollbackStatus)) {
                            RtlZeroMemory(record, sizeof(*record));
                            record->Pid = ProcessId;
                            record->UniqueProcessIdOffset = uniqueProcessIdOffset;
                            record->ActiveProcessLinksOffset = activeProcessLinksOffset;
                            record->ProcessObject = processObject;
                            record->OriginalUniqueProcessId = originalUniqueProcessId;
                            record->HiddenUniqueProcessId = hiddenUniqueProcessId;
                            record->UniqueProcessIdPatched = TRUE;
                            record->ActiveListUnlinked = FALSE;
                            processObject = NULL;
                            g_KswordArkProcessHideState.Count += 1UL;
                            *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
                            status = rollbackStatus;
                        }
                    }
                }
                if (NT_SUCCESS(status)) {
                    RtlZeroMemory(record, sizeof(*record));
                    record->Pid = ProcessId;
                    record->UniqueProcessIdOffset = uniqueProcessIdOffset;
                    record->ActiveProcessLinksOffset = activeProcessLinksOffset;
                    record->ProcessObject = processObject;
                    record->OriginalUniqueProcessId = originalUniqueProcessId;
                    record->HiddenUniqueProcessId = hiddenUniqueProcessId;
                    record->ActiveProcessLinks = link;
                    record->PreviousLink = previous;
                    record->NextLink = next;
                    record->UniqueProcessIdPatched = shouldPatchUniquePid;
                    record->ActiveListUnlinked = shouldUnlinkActiveList;
                    processObject = NULL;
                    g_KswordArkProcessHideState.Count += 1UL;
                    *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
                }
            }
        }
        else if (Action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE) {
            if (foundIndex != MAXULONG) {
                KSWORD_ARK_PROCESS_HIDE_RECORD* record =
                    &g_KswordArkProcessHideState.Records[foundIndex];
                status = KswordARKDriverRestoreUniqueProcessIdRecord(record);
                if (NT_SUCCESS(status)) {
                    status = KswordARKDriverRestoreActiveProcessLinksRecord(record);
                }
                if (!NT_SUCCESS(status)) {
                    *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN;
                    *HiddenCountOut = g_KswordArkProcessHideState.Count;
                    __leave;
                }

                if (record->ProcessObject != NULL) {
                    ObDereferenceObject(record->ProcessObject);
                    record->ProcessObject = NULL;
                }
                for (index = foundIndex + 1UL; index < g_KswordArkProcessHideState.Count; ++index) {
                    g_KswordArkProcessHideState.Records[index - 1UL] =
                        g_KswordArkProcessHideState.Records[index];
                }
                if (g_KswordArkProcessHideState.Count > 0UL) {
                    g_KswordArkProcessHideState.Count -= 1UL;
                    RtlZeroMemory(
                        &g_KswordArkProcessHideState.Records[g_KswordArkProcessHideState.Count],
                        sizeof(g_KswordArkProcessHideState.Records[g_KswordArkProcessHideState.Count]));
                }
            }
            *StatusOut = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE;
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }

        *HiddenCountOut = g_KswordArkProcessHideState.Count;
    }
    __finally {
        KswordARKReleasePushLockExclusive(&g_KswordArkProcessHideState.Lock);
    }

    if (processObject != NULL) {
        ObDereferenceObject(processObject);
        processObject = NULL;
    }

    return status;
}

NTSTATUS
KswordARKDriverSuspendProcessByPid(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Suspend target process by PID (PsSuspendProcess preferred, Zw/Nt fallback).

Arguments:

    processId - Target process ID.

Return Value:

    NTSTATUS

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KSWORD_PS_SUSPEND_PROCESS_FN psSuspendProcess = NULL;
    KSWORD_ZW_OR_NT_SUSPEND_PROCESS_FN zwOrNtSuspendProcess = NULL;

    if (processId == 0U || processId <= 4U) {
        return STATUS_INVALID_PARAMETER;
    }

    // Prefer PsSuspendProcess with PEPROCESS input for wider compatibility.
    psSuspendProcess = KswordARKDriverResolvePsSuspendProcess();
    if (psSuspendProcess != NULL) {
        status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = psSuspendProcess(processObject);
        ObDereferenceObject(processObject);
        return status;
    }

    // Fallback to Zw/NtSuspendProcess with process-handle input.
    zwOrNtSuspendProcess = KswordARKDriverResolveZwOrNtSuspendProcess();
    if (zwOrNtSuspendProcess == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(processId);
    clientId.UniqueThread = NULL;
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_SUSPEND_RESUME,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = zwOrNtSuspendProcess(processHandle);
    ZwClose(processHandle);
    return status;
}

NTSTATUS
KswordARKDriverResumeProcessByPid(
    _In_ ULONG processId
    )
/*++

Routine Description:

    Resume target process by PID (PsResumeProcess preferred, Zw/Nt fallback).
    中文说明：逐行对称于 KswordARKDriverSuspendProcessByPid，包括 PID 下界、
    解析顺序与回退时申请的访问权限。两条不对称会造成"挂得起来、恢复不了"，
    而那种状态从任何一侧的返回值上都看不出来。

Arguments:

    processId - Target process ID.

Return Value:

    NTSTATUS

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KSWORD_PS_RESUME_PROCESS_FN psResumeProcess = NULL;
    KSWORD_ZW_OR_NT_RESUME_PROCESS_FN zwOrNtResumeProcess = NULL;

    if (processId == 0U || processId <= 4U) {
        return STATUS_INVALID_PARAMETER;
    }

    // Prefer PsResumeProcess with PEPROCESS input for wider compatibility.
    psResumeProcess = KswordARKDriverResolvePsResumeProcess();
    if (psResumeProcess != NULL) {
        status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = psResumeProcess(processObject);
        ObDereferenceObject(processObject);
        return status;
    }

    // Fallback to Zw/NtResumeProcess with process-handle input.
    zwOrNtResumeProcess = KswordARKDriverResolveZwOrNtResumeProcess();
    if (zwOrNtResumeProcess == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(processId);
    clientId.UniqueThread = NULL;
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_SUSPEND_RESUME,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = zwOrNtResumeProcess(processHandle);
    ZwClose(processHandle);
    return status;
}

NTSTATUS
KswordARKDriverApplyProcessProtectionToObject(
    _In_ PEPROCESS processObject,
    _In_ UCHAR protectionLevel
    )
/*++

Routine Description:

    Apply a PS_PROTECTION byte to an already referenced process object.
    中文说明：PP 守护在进程创建回调和巡检里都只有 PEPROCESS 而没有可信 PID
    （PID 可能被 DKOM 改写，也可能已被复用），因此需要一个绕开
    PsLookupProcessByProcessId 的入口。签名级别表在本文件内，所以解析放这里，
    实际写入仍复用 DynData 拥有方的 process_extended.c。

Arguments:

    processObject - Referenced target EPROCESS.
    protectionLevel - Target PS_PROTECTION raw byte；0 表示清除保护。

Return Value:

    NTSTATUS from signer resolution or the EPROCESS patch.

--*/
{
    const UCHAR protectionType = (UCHAR)(protectionLevel & 0x07U);
    UCHAR signerType = (UCHAR)((protectionLevel & 0xF0U) >> 4U);
    UCHAR signatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
    UCHAR sectionSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (protectionLevel == 0U) {
        signerType = KSWORD_PS_PROTECTED_SIGNER_NONE;
    }
    else if ((protectionType != KSWORD_PS_PROTECTED_TYPE_LIGHT &&
              protectionType != KSWORD_PS_PROTECTED_TYPE_FULL) ||
             signerType == KSWORD_PS_PROTECTED_SIGNER_NONE ||
             signerType > KSWORD_PS_PROTECTED_SIGNER_APP) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKDriverResolveSignatureLevelsFromSigner(
        signerType,
        &signatureLevel,
        &sectionSignatureLevel);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return KswordARKProcessPatchProtectionByDynDataObject(
        processObject,
        protectionLevel,
        signatureLevel,
        sectionSignatureLevel);
}

NTSTATUS
KswordARKDriverSetProcessPplLevelByPid(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel
    )
/*++

Routine Description:

    Set target process protection state by PID using PPLcontrol-style direct
    EPROCESS patching (Protection + SignatureLevel + SectionSignatureLevel).

    中文说明：IOCTL 名沿用历史的 SET_PPL_LEVEL，但本入口同时受理两种保护类型：
    Type==1 是 PPL（PsProtectedTypeProtectedLight），Type==2 是完整 PP
    （PsProtectedTypeProtected）。两者只差 Protection 字节里的类型位，签名级别
    仍按 signer 查表——内核判定"谁能打开谁"只看 Protection 字节，签名级别影响的
    是该进程后续能加载哪些映像。

Arguments:

    processId - Target process ID.
    protectionLevel - Target PS_PROTECTION raw byte: Type 位 0-2、Audit 位 3、
        Signer 位 4-7。

Return Value:

    NTSTATUS

--*/
{
    const UCHAR protectionType = (UCHAR)(protectionLevel & 0x07U);
    const UCHAR signerType = (UCHAR)((protectionLevel & 0xF0U) >> 4U);

    if (processId == 0U || processId <= 4U) {
        return STATUS_INVALID_PARAMETER;
    }

    // 0x00 关闭保护并清空签名级别。
    if (protectionLevel == 0U) {
        return KswordARKDriverPatchProcessProtectionStateByPid(processId, 0U);
    }

    // 只接受 PPL 与 PP 两种类型；signer 必须落在有映射的 1..8 之内。
    // Audit 位（bit 3）与签名级别无关，沿用旧行为原样写入，不在这里拦。
    if ((protectionType != KSWORD_PS_PROTECTED_TYPE_LIGHT &&
         protectionType != KSWORD_PS_PROTECTED_TYPE_FULL) ||
        signerType == KSWORD_PS_PROTECTED_SIGNER_NONE ||
        signerType > KSWORD_PS_PROTECTED_SIGNER_APP) {
        return STATUS_INVALID_PARAMETER;
    }

    return KswordARKDriverPatchProcessProtectionStateByPid(processId, protectionLevel);
}

static NTSTATUS
KswordARKDriverBuildMandatoryIntegritySid(
    _In_ ULONG IntegrityRid,
    _Out_writes_bytes_(SECURITY_MAX_SID_SIZE) PSID SidBuffer
    )
/*++

Routine Description:

    Build an S-1-16-* mandatory integrity SID in caller-provided storage.

Arguments:

    IntegrityRid - Mandatory label RID.
    SidBuffer - SECURITY_MAX_SID_SIZE writable storage.

Return Value:

    STATUS_SUCCESS or an RTL SID construction failure.

--*/
{
    SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    NTSTATUS status = STATUS_SUCCESS;
    PULONG subAuthority = NULL;

    if (SidBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(SidBuffer, SECURITY_MAX_SID_SIZE);
    status = RtlInitializeSid(SidBuffer, &mandatoryLabelAuthority, 1);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    subAuthority = RtlSubAuthoritySid(SidBuffer, 0);
    if (subAuthority == NULL) {
        return STATUS_INVALID_SID;
    }

    *subAuthority = IntegrityRid;
    return RtlValidSid(SidBuffer) ? STATUS_SUCCESS : STATUS_INVALID_SID;
}

static BOOLEAN
KswordARKDriverDynOffsetPresent(
    _In_ ULONG Offset
    )
/*++

Routine Description:

    Test whether one DynData offset is usable by a private-field consumer.

Arguments:

    Offset - Normalized KSW_DYN offset value.

Return Value:

    TRUE when the offset is neither unavailable nor the legacy 0xffff sentinel;
    otherwise FALSE.

--*/
{
    return (Offset != KSW_DYN_OFFSET_UNAVAILABLE && Offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKDriverTokenIntegritySourceTrusted(
    _In_ ULONG Source
    )
/*++

Routine Description:

    Accept either an exact PDB profile or the live-validated runtime resolver.

Arguments:

    Source - DynData provenance value for one private token field.

Return Value:

    TRUE only for an identity-bound PDB fact or validated runtime pattern.

--*/
{
    return (Source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
            Source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)
        ? TRUE
        : FALSE;
}

static BOOLEAN
KswordARKDriverTokenIntegrityDynDataReady(
    _In_ const KSW_DYN_STATE* State
    )
/*++

Routine Description:

    Validate the exact DynData dependencies required to patch a process token
    mandatory-label SID. 中文说明：这里不接受猜测来源；_EPROCESS.Token 与
    _TOKEN.UserAndGroupCount/UserAndGroups/IntegrityLevelIndex 必须来自当前
    ntoskrnl PDB profile 或经过真实 Token 查询交叉验证的 runtime pattern，
    并且 capability 已经由 DynData 计算为可用。

Arguments:

    State - Immutable DynData snapshot captured by the caller.

Return Value:

    TRUE when the private token integrity path may run; otherwise FALSE.

--*/
{
    if (State == NULL) {
        return FALSE;
    }
    if ((State->CapabilityMask & KSW_CAP_TOKEN_INTEGRITY_FIELDS) == 0ULL) {
        return FALSE;
    }
    if (!KswordARKDriverDynOffsetPresent(State->Kernel.EpToken) ||
        !KswordARKDriverDynOffsetPresent(State->Kernel.TokUserAndGroupCount) ||
        !KswordARKDriverDynOffsetPresent(State->Kernel.TokUserAndGroups) ||
        !KswordARKDriverDynOffsetPresent(State->Kernel.TokIntegrityLevelIndex)) {
        return FALSE;
    }

    return KswordARKDriverTokenIntegritySourceTrusted(State->KernelSources.EpToken) &&
        KswordARKDriverTokenIntegritySourceTrusted(State->KernelSources.TokUserAndGroupCount) &&
        KswordARKDriverTokenIntegritySourceTrusted(State->KernelSources.TokUserAndGroups) &&
        KswordARKDriverTokenIntegritySourceTrusted(State->KernelSources.TokIntegrityLevelIndex);
}

static BOOLEAN
KswordARKDriverSidHasMandatoryAuthority(
    _In_ PSID Sid
    )
/*++

Routine Description:

    Check whether a SID uses SECURITY_MANDATORY_LABEL_AUTHORITY. This confirms
    the token entry being overwritten is the integrity label rather than a user,
    group, capability, or restricted SID.

Arguments:

    Sid - Candidate SID pointer from the token's SID_AND_ATTRIBUTES array.

Return Value:

    TRUE when the SID authority is S-1-16; otherwise FALSE.

--*/
{
    SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    SID* sidBody = NULL;

    if (Sid == NULL) {
        return FALSE;
    }

    if (!RtlValidSid(Sid)) {
        return FALSE;
    }

    sidBody = (SID*)Sid;
    return RtlCompareMemory(
        sidBody->IdentifierAuthority.Value,
        mandatoryLabelAuthority.Value,
        sizeof(mandatoryLabelAuthority.Value)) == sizeof(mandatoryLabelAuthority.Value) ? TRUE : FALSE;
}

static NTSTATUS
KswordARKDriverCopyMandatorySidInPlace(
    _Inout_ PSID ExistingSid,
    _In_ PSID NewSid
    )
/*++

Routine Description:

    Replace an existing token integrity SID by copying a caller-built
    S-1-16-* SID into the existing SID storage. 中文说明：本函数绝不把 Token
    中的 Sid 指针改成栈/临时缓冲区；只在现有 SID 有效、是 mandatory
    label authority、且目标缓冲区长度足够时原地覆盖 SID 字节。

Arguments:

    ExistingSid - SID pointer currently stored in the target token's integrity
        SID_AND_ATTRIBUTES entry.
    NewSid - Caller-built mandatory integrity SID.

Return Value:

    STATUS_SUCCESS when the copy completed; validation or exception status on
    failure.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG existingSidLength = 0UL;
    ULONG newSidLength = 0UL;
    PUCHAR existingSubAuthorityCount = NULL;

    if (ExistingSid == NULL || NewSid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        if (!RtlValidSid(ExistingSid) || !RtlValidSid(NewSid)) {
            status = STATUS_INVALID_SID;
            __leave;
        }
        if (!KswordARKDriverSidHasMandatoryAuthority(ExistingSid) ||
            !KswordARKDriverSidHasMandatoryAuthority(NewSid)) {
            status = STATUS_INVALID_SID;
            __leave;
        }

        existingSubAuthorityCount = RtlSubAuthorityCountSid(ExistingSid);
        if (existingSubAuthorityCount == NULL || *existingSubAuthorityCount == 0U) {
            status = STATUS_INVALID_SID;
            __leave;
        }

        existingSidLength = RtlLengthSid(ExistingSid);
        newSidLength = RtlLengthSid(NewSid);
        if (existingSidLength < newSidLength) {
            status = STATUS_BUFFER_TOO_SMALL;
            __leave;
        }

        RtlCopyMemory(ExistingSid, NewSid, newSidLength);
        status = RtlValidSid(ExistingSid) ? STATUS_SUCCESS : STATUS_INVALID_SID;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static NTSTATUS
KswordARKDriverSetProcessIntegrityByPrivateTokenOffsets(
    _In_ ULONG ProcessId,
    _In_ PSID MandatorySid
    )
/*++

Routine Description:

    Patch a process primary token's integrity SID through current-kernel
    validated DynData offsets. Processing steps:
    1. Snapshot DynData and require PDB-sourced or live-validated
       _EPROCESS.Token plus _TOKEN integrity fields.
    2. Reference the target process with PsLookupProcessByProcessId.
    3. Decode the EX_FAST_REF stored at EPROCESS.Token to obtain the token
       object pointer.
    4. Read UserAndGroupCount, UserAndGroups, and IntegrityLevelIndex from the
       token, bounds-check the index, then copy the new S-1-16-* SID into the
       existing SID storage.

Arguments:

    ProcessId - Target process ID.
    MandatorySid - Caller-built S-1-16-* SID that remains valid for this call.

Return Value:

    STATUS_SUCCESS when the private fallback applied; validation, DynData, or
    guarded-memory access status on failure.

--*/
{
    KSW_DYN_STATE dynState;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR tokenFastRef = 0U;
    PVOID tokenObject = NULL;
    PACCESS_TOKEN referencedPrimaryToken = NULL;
    ULONG userAndGroupCount = 0UL;
    ULONG integrityLevelIndex = 0UL;
    SID_AND_ATTRIBUTES* userAndGroups = NULL;
    SID_AND_ATTRIBUTES* integrityEntry = NULL;
    PSID existingSid = NULL;
    ULONG existingAttributes = 0UL;

    if (ProcessId == 0U || MandatorySid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!RtlValidSid(MandatorySid) || !KswordARKDriverSidHasMandatoryAuthority(MandatorySid)) {
        return STATUS_INVALID_SID;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);
    g_KswordProcessIntegrityDiag.CapabilityMask = dynState.CapabilityMask;
    g_KswordProcessIntegrityDiag.EpToken = dynState.Kernel.EpToken;
    g_KswordProcessIntegrityDiag.TokUserAndGroupCount = dynState.Kernel.TokUserAndGroupCount;
    g_KswordProcessIntegrityDiag.TokUserAndGroups = dynState.Kernel.TokUserAndGroups;
    g_KswordProcessIntegrityDiag.TokIntegrityLevelIndex = dynState.Kernel.TokIntegrityLevelIndex;
    g_KswordProcessIntegrityDiag.TokMandatoryPolicy = dynState.Kernel.TokMandatoryPolicy;
    g_KswordProcessIntegrityDiag.EpTokenSource = dynState.KernelSources.EpToken;
    g_KswordProcessIntegrityDiag.TokUserAndGroupCountSource = dynState.KernelSources.TokUserAndGroupCount;
    g_KswordProcessIntegrityDiag.TokUserAndGroupsSource = dynState.KernelSources.TokUserAndGroups;
    g_KswordProcessIntegrityDiag.TokIntegrityLevelIndexSource = dynState.KernelSources.TokIntegrityLevelIndex;
    g_KswordProcessIntegrityDiag.TokMandatoryPolicySource = dynState.KernelSources.TokMandatoryPolicy;
    if (!KswordARKDriverTokenIntegrityDynDataReady(&dynState)) {
        return STATUS_NOT_SUPPORTED;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        tokenFastRef = *(volatile ULONG_PTR*)((UCHAR*)processObject + dynState.Kernel.EpToken);
        tokenObject = (PVOID)(tokenFastRef & ~KSWORD_ARK_EX_FAST_REF_MASK);
        if (tokenObject == NULL) {
            status = STATUS_NOT_FOUND;
            __leave;
        }

        userAndGroupCount = *(volatile ULONG*)((UCHAR*)tokenObject + dynState.Kernel.TokUserAndGroupCount);
        integrityLevelIndex = *(volatile ULONG*)((UCHAR*)tokenObject + dynState.Kernel.TokIntegrityLevelIndex);
        userAndGroups = *(SID_AND_ATTRIBUTES**)((UCHAR*)tokenObject + dynState.Kernel.TokUserAndGroups);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObject);
        return status;
    }

    referencedPrimaryToken = PsReferencePrimaryToken(processObject);
    if (referencedPrimaryToken == NULL || tokenObject != referencedPrimaryToken) {
        if (referencedPrimaryToken != NULL) {
            PsDereferencePrimaryToken(referencedPrimaryToken);
        }
        ObDereferenceObject(processObject);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    PsDereferencePrimaryToken(referencedPrimaryToken);
    referencedPrimaryToken = NULL;

    if (userAndGroupCount == 0UL ||
        userAndGroupCount > KSWORD_ARK_TOKEN_INTEGRITY_MAX_GROUPS ||
        integrityLevelIndex >= userAndGroupCount ||
        userAndGroups == NULL) {
        ObDereferenceObject(processObject);
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        integrityEntry = &userAndGroups[integrityLevelIndex];
        existingSid = integrityEntry->Sid;
        existingAttributes = integrityEntry->Attributes;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObject);
        return status;
    }

    status = KswordARKDriverCopyMandatorySidInPlace(existingSid, MandatorySid);
    if (NT_SUCCESS(status)) {
        __try {
            integrityEntry->Attributes = existingAttributes | SE_GROUP_INTEGRITY;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    }

    ObDereferenceObject(processObject);
    return status;
}

static NTSTATUS
KswordARKDriverSelectProcessIntegrityStatus(
    _In_ NTSTATUS ApiStatus,
    _In_ NTSTATUS FallbackStatus
    )
/*++

Routine Description:

    Select the final status after the documented token API path failed and the
    private DynData fallback was attempted. 中文说明：如果私有路径不可用，保留
    原始 API 错误，避免把“系统拒绝标签”误报成“功能不支持”；如果私有
    路径实际运行并给出校验/访问错误，则返回该错误便于定位偏移问题。

Arguments:

    ApiStatus - Failure status from the documented process/token API path.
    FallbackStatus - Status from the private token-offset fallback.

Return Value:

    STATUS_SUCCESS if the fallback succeeded; ApiStatus when fallback was not
    available; otherwise FallbackStatus.

--*/
{
    if (NT_SUCCESS(FallbackStatus)) {
        return FallbackStatus;
    }

    return (FallbackStatus == STATUS_NOT_SUPPORTED) ? ApiStatus : FallbackStatus;
}

static VOID
KswordARKDriverRecordProcessIntegrityResult(
    _In_ ULONG ProcessId,
    _In_ ULONG IntegrityRid,
    _In_ NTSTATUS ApiStatus,
    _In_ NTSTATUS FallbackStatus,
    _In_ NTSTATUS FinalStatus
    )
/*++

Routine Description:

    Store the final status tuple for the latest process-integrity request. This
    best-effort diagnostic is read by the IOCTL layer immediately after the
    action returns so R0 logs can show why private-token fallback did or did not
    run.

Arguments:

    ProcessId - Target PID.
    IntegrityRid - Requested S-1-16-* RID.
    ApiStatus - Documented token API path status.
    FallbackStatus - Private offset fallback status, or STATUS_NOT_SUPPORTED.
    FinalStatus - Status returned to the IOCTL response.

Return Value:

    None.

--*/
{
    g_KswordProcessIntegrityDiag.ProcessId = ProcessId;
    g_KswordProcessIntegrityDiag.IntegrityRid = IntegrityRid;
    g_KswordProcessIntegrityDiag.ApiStatus = ApiStatus;
    g_KswordProcessIntegrityDiag.FallbackStatus = FallbackStatus;
    g_KswordProcessIntegrityDiag.FinalStatus = FinalStatus;
}

NTSTATUS
KswordARKDriverDescribeLastProcessIntegrityAttempt(
    _Out_writes_bytes_(BufferBytes) CHAR* Buffer,
    _In_ SIZE_T BufferBytes
    )
/*++

Routine Description:

    Format the latest process-integrity attempt diagnostic into caller storage.

Arguments:

    Buffer - Writable ANSI output buffer.
    BufferBytes - Size of Buffer in bytes.

Return Value:

    STATUS_SUCCESS when text was written; STATUS_INVALID_PARAMETER or
    STATUS_BUFFER_TOO_SMALL when storage is invalid.

--*/
{
    const KSWORD_ARK_PROCESS_INTEGRITY_ATTEMPT_DIAG diag = g_KswordProcessIntegrityDiag;

    if (Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (BufferBytes == 0U) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Buffer[0] = '\0';
    return RtlStringCbPrintfA(
        Buffer,
        BufferBytes,
        "pid=%lu, rid=0x%08lX, api=0x%08X, fallback=0x%08X, final=0x%08X, caps=0x%I64X, "
        "off={epToken=0x%lX,uagCount=0x%lX,uag=0x%lX,ilIndex=0x%lX,mandatory=0x%lX}, "
        "src={epToken=%lu,uagCount=%lu,uag=%lu,ilIndex=%lu,mandatory=%lu}.",
        (unsigned long)diag.ProcessId,
        (unsigned long)diag.IntegrityRid,
        (unsigned int)diag.ApiStatus,
        (unsigned int)diag.FallbackStatus,
        (unsigned int)diag.FinalStatus,
        diag.CapabilityMask,
        (unsigned long)diag.EpToken,
        (unsigned long)diag.TokUserAndGroupCount,
        (unsigned long)diag.TokUserAndGroups,
        (unsigned long)diag.TokIntegrityLevelIndex,
        (unsigned long)diag.TokMandatoryPolicy,
        (unsigned long)diag.EpTokenSource,
        (unsigned long)diag.TokUserAndGroupCountSource,
        (unsigned long)diag.TokUserAndGroupsSource,
        (unsigned long)diag.TokIntegrityLevelIndexSource,
        (unsigned long)diag.TokMandatoryPolicySource);
}

NTSTATUS
KswordARKDriverSetProcessIntegrityByPid(
    _In_ ULONG ProcessId,
    _In_ ULONG IntegrityRid
    )
/*++

Routine Description:

    Set a process primary-token mandatory integrity label. The preferred path
    calls documented kernel token APIs. If Windows rejects a syntactically valid
    mandatory label (for example System/ProtectedProcess raises), the routine
    falls back to PDB/DynData-validated private token offsets and overwrites the
    existing mandatory SID in place.

Arguments:

    ProcessId - Target process ID.
    IntegrityRid - S-1-16-* mandatory label RID.

Return Value:

    NTSTATUS from process open, token open, SID construction, or token update.

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    HANDLE processHandle = NULL;
    HANDLE tokenHandle = NULL;
    KSWORD_ARK_PROCESS_INTEGRITY_TOKEN_INFORMATION tokenInformation = { 0 };
    ULONG tokenInformationLength = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS apiStatus = STATUS_SUCCESS;
    NTSTATUS fallbackStatus = STATUS_SUCCESS;
    NTSTATUS finalStatus = STATUS_SUCCESS;

    RtlZeroMemory(&g_KswordProcessIntegrityDiag, sizeof(g_KswordProcessIntegrityDiag));
    g_KswordProcessIntegrityDiag.ProcessId = ProcessId;
    g_KswordProcessIntegrityDiag.IntegrityRid = IntegrityRid;
    g_KswordProcessIntegrityDiag.ApiStatus = STATUS_UNSUCCESSFUL;
    g_KswordProcessIntegrityDiag.FallbackStatus = STATUS_NOT_SUPPORTED;
    g_KswordProcessIntegrityDiag.FinalStatus = STATUS_UNSUCCESSFUL;

    if (ProcessId == 0U || ProcessId <= 4U) {
        KswordARKDriverRecordProcessIntegrityResult(
            ProcessId,
            IntegrityRid,
            STATUS_INVALID_PARAMETER,
            STATUS_NOT_SUPPORTED,
            STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKDriverBuildMandatoryIntegritySid(IntegrityRid, (PSID)tokenInformation.SidBuffer);
    if (!NT_SUCCESS(status)) {
        KswordARKDriverRecordProcessIntegrityResult(
            ProcessId,
            IntegrityRid,
            status,
            STATUS_NOT_SUPPORTED,
            status);
        return status;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ULongToHandle(ProcessId);
    clientId.UniqueThread = NULL;
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_INFORMATION,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        fallbackStatus = KswordARKDriverSetProcessIntegrityByPrivateTokenOffsets(
            ProcessId,
            (PSID)tokenInformation.SidBuffer);
        finalStatus = KswordARKDriverSelectProcessIntegrityStatus(status, fallbackStatus);
        KswordARKDriverRecordProcessIntegrityResult(
            ProcessId,
            IntegrityRid,
            status,
            fallbackStatus,
            finalStatus);
        return finalStatus;
    }

    status = ZwOpenProcessTokenEx(
        processHandle,
        TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
        OBJ_KERNEL_HANDLE,
        &tokenHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(processHandle);
        fallbackStatus = KswordARKDriverSetProcessIntegrityByPrivateTokenOffsets(
            ProcessId,
            (PSID)tokenInformation.SidBuffer);
        finalStatus = KswordARKDriverSelectProcessIntegrityStatus(status, fallbackStatus);
        KswordARKDriverRecordProcessIntegrityResult(
            ProcessId,
            IntegrityRid,
            status,
            fallbackStatus,
            finalStatus);
        return finalStatus;
    }

    RtlZeroMemory(&tokenInformation.MandatoryLabel, sizeof(tokenInformation.MandatoryLabel));
    tokenInformation.MandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
    tokenInformation.MandatoryLabel.Label.Sid = (PSID)tokenInformation.SidBuffer;
    tokenInformationLength =
        (ULONG)(FIELD_OFFSET(KSWORD_ARK_PROCESS_INTEGRITY_TOKEN_INFORMATION, SidBuffer) +
            RtlLengthSid((PSID)tokenInformation.SidBuffer));

    status = ZwSetInformationToken(
        tokenHandle,
        TokenIntegrityLevel,
        &tokenInformation,
        tokenInformationLength);
    apiStatus = status;

    ZwClose(tokenHandle);
    ZwClose(processHandle);

    if (NT_SUCCESS(apiStatus)) {
        KswordARKDriverRecordProcessIntegrityResult(
            ProcessId,
            IntegrityRid,
            apiStatus,
            STATUS_NOT_SUPPORTED,
            apiStatus);
        return apiStatus;
    }

    fallbackStatus = KswordARKDriverSetProcessIntegrityByPrivateTokenOffsets(
        ProcessId,
        (PSID)tokenInformation.SidBuffer);
    finalStatus = KswordARKDriverSelectProcessIntegrityStatus(apiStatus, fallbackStatus);
    KswordARKDriverRecordProcessIntegrityResult(
        ProcessId,
        IntegrityRid,
        apiStatus,
        fallbackStatus,
        finalStatus);
    return finalStatus;
}

NTSTATUS
KswordARKDriverEnumerateProcesses(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_PROCESS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_ENUM_PROCESS_RESPONSE* response = NULL;
    size_t entryCapacity = 0;
    size_t totalBytesWritten = 0;
    ULONG requestFlags = 0;
    ULONG scanStartPid = KSWORD_ARK_ENUM_SCAN_MIN_PID;
    ULONG scanEndPid = KSWORD_ARK_ENUM_SCAN_MAX_PID;
    BOOLEAN scanCidTable = FALSE;
    UCHAR* pidBitmap = NULL;
    size_t pidBitmapBytes = 0;
    BOOLEAN activeWalkComplete = FALSE;
    NTSTATUS cidWalkStatus = STATUS_SUCCESS;
    KSWORD_PS_GET_NEXT_PROCESS_FN psGetNextProcess = NULL;
    PEPROCESS processCursor = NULL;
    KSW_DYN_STATE dynState;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *bytesWrittenOut = 0;
    if (outputBufferLength < KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_PROCESS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_ENTRY);
    entryCapacity =
        (outputBufferLength - KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_PROCESS_ENTRY);

    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);

    if (request != NULL) {
        requestFlags = request->flags;
        if (request->startPid != 0U) {
            scanStartPid = request->startPid;
        }
        if (request->endPid != 0U) {
            scanEndPid = request->endPid;
        }
    }

    if (scanStartPid < KSWORD_ARK_ENUM_SCAN_MIN_PID) {
        scanStartPid = KSWORD_ARK_ENUM_SCAN_MIN_PID;
    }
    if (scanEndPid < scanStartPid) {
        scanEndPid = scanStartPid;
    }
    if (scanEndPid > KSWORD_ARK_ENUM_SCAN_MAX_PID) {
        scanEndPid = KSWORD_ARK_ENUM_SCAN_MAX_PID;
    }

    scanStartPid = KswordARKDriverAlignPidToStep(scanStartPid);
    if (scanStartPid < KSWORD_ARK_ENUM_SCAN_MIN_PID) {
        scanStartPid = KSWORD_ARK_ENUM_SCAN_MIN_PID;
    }
    scanEndPid = KswordARKDriverAlignPidToStep(scanEndPid);
    if (scanEndPid < scanStartPid) {
        scanEndPid = scanStartPid;
    }

    scanCidTable = ((requestFlags & KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE) != 0U) ? TRUE : FALSE;
    psGetNextProcess = KswordARKDriverResolvePsGetNextProcess();
    if (psGetNextProcess == NULL) {
        // Fallback: force CID scan when PsGetNextProcess is unavailable.
        scanCidTable = TRUE;
    }

    if (scanCidTable) {
        const size_t bitmapBitCount = (size_t)(scanEndPid / KSWORD_ARK_ENUM_PID_STEP) + 1U;
        pidBitmapBytes = (bitmapBitCount + 7U) >> 3;
#pragma warning(push)
#pragma warning(disable:4996)
        pidBitmap = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, pidBitmapBytes, 'pKsK');
#pragma warning(pop)
        if (pidBitmap == NULL) {
            scanCidTable = FALSE;
            pidBitmapBytes = 0U;
        }
        else {
            RtlZeroMemory(pidBitmap, pidBitmapBytes);
        }
    }

    if (psGetNextProcess != NULL) {
        processCursor = psGetNextProcess(NULL);
        while (processCursor != NULL) {
            const ULONG processId = HandleToULong(PsGetProcessId(processCursor));
            const ULONG parentProcessId =
                HandleToULong(PsGetProcessInheritedFromUniqueProcessId(processCursor));
            const CHAR* imageName = PsGetProcessImageFileName(processCursor);
            ULONG processFlags = KSWORD_ARK_PROCESS_FLAG_KERNEL_ENUMERATED;
            PEPROCESS nextProcess = NULL;
            const BOOLEAN terminatingProcess =
                KswordARKDriverShouldSkipTerminatingProcess(processCursor, &dynState);

            if (terminatingProcess) {
                processFlags |= KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED;
            }
            if (KswordARKDriverIsProcessHiddenByUi(processId)) {
                processFlags |= KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI;
            }
            KswordARKDriverAppendProcessEntry(
                response,
                entryCapacity,
                processId,
                parentProcessId,
                processFlags,
                imageName,
                processCursor);

            if (scanCidTable && KswordARKDriverPidInScanRange(processId, scanStartPid, scanEndPid)) {
                KswordARKDriverBitmapSetPid(pidBitmap, pidBitmapBytes, processId);
            }

            nextProcess = psGetNextProcess(processCursor);
            ObDereferenceObject(processCursor);
            processCursor = nextProcess;
        }
    }

    if (scanCidTable) {
        if (psGetNextProcess != NULL && pidBitmap != NULL) {
            activeWalkComplete = NT_SUCCESS(KswordARKCrossViewValidateActiveProcessLinks(
                &dynState,
                KSWORD_ARK_ENUM_CID_WALK_MAX_NODES,
                NULL));
        }
        cidWalkStatus = KswordARKDriverEnumerateProcessesByCidTable(
            response,
            entryCapacity,
            &dynState,
            pidBitmap,
            pidBitmapBytes,
            scanStartPid,
            scanEndPid,
            activeWalkComplete);
    }

    if (scanCidTable && !NT_SUCCESS(cidWalkStatus)) {
        ULONG entryIndex = 0UL;
        for (entryIndex = 0UL; entryIndex < response->returnedCount; ++entryIndex) {
            KSWORD_ARK_PROCESS_ENTRY* entry = &response->entries[entryIndex];
            if ((entry->flags & KSWORD_ARK_PROCESS_FLAG_CID_TABLE_ENUMERATED) == 0U) {
                continue;
            }
            entry->flags |= KSWORD_ARK_PROCESS_FLAG_CID_TABLE_UNCONFIRMED;
            entry->flags &= ~(
                KSWORD_ARK_PROCESS_FLAG_HIDDEN_FROM_ACTIVE_LIST |
                KSWORD_ARK_PROCESS_FLAG_CID_OBJECT_REFERENCE_STABLE);
        }
        if (response->totalCount != MAXULONG) {
            response->totalCount = response->returnedCount + 1UL;
        }
    }

    if (pidBitmap != NULL) {
        ExFreePoolWithTag(pidBitmap, 'pKsK');
        pidBitmap = NULL;
    }

    totalBytesWritten =
        KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PROCESS_ENTRY));
    *bytesWrittenOut = totalBytesWritten;
    return STATUS_SUCCESS;
}
