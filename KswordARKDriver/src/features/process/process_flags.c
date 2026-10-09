/*++

Module Name:

    process_flags.c

Abstract:

    Process BreakOnTermination and ETHREAD APC insertion controls.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../platform/process_resolver.h"
#include "process_crossview.h"
#include "../thread/work_queue_fallback.h" // 无线程枚举导出时复用真实 TID 快照。
#include "../../platform/runtime_signature_scan.h" // 候选代码与对象字段统一安全读取。

// 中文说明：ntddk.h 不声明这些线程身份查询，保持与现有线程模块一致的导入 ABI。
NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread);
NTSYSAPI PEPROCESS NTAPI PsGetThreadProcess(PETHREAD Thread);
NTKERNELAPI BOOLEAN NTAPI PsIsThreadTerminating(PETHREAD Thread);

/* 中文说明：PsLookupProcessByProcessId 用于引用目标 EPROCESS。 */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

/* 中文说明：公开内核例程返回目标 EPROCESS 的稳定创建时间。 */
NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
    );

extern POBJECT_TYPE* PsProcessType;

/* 中文说明：ProcessBreakOnTermination 是 ZwSetInformationProcess 的信息类 29。 */
#define KSWORD_ARK_PROCESS_INFORMATION_BREAK_ON_TERMINATION 29UL
/* 中文说明：EPROCESS.Flags 中 BreakOnTermination 对应 bit 13，SKT64 同样使用该位。 */
#define KSWORD_ARK_EPROCESS_FLAGS_BREAK_ON_TERMINATION_MASK 0x00002000UL
/* 中文说明：EPROCESS 结构体偏移必须来自 DynData/PDB，超过该上限视为异常 profile。 */
#define KSWORD_ARK_EPROCESS_FLAGS_OFFSET_MAX 0x3000UL
/* 中文说明：只在 KeInsertQueueApc 的实际指令验证通过后使用 KTHREAD.MiscFlags 偏移。 */
#define KSWORD_ARK_ETHREAD_APC_QUEUEABLE_OFFSET_X64 0x74UL
/* 中文说明：ApcQueueable 是 KTHREAD.MiscFlags bit 14，不是 CrossThreadFlags bit 18。 */
#define KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK 0x00004000UL

#ifndef PROCESS_SET_INFORMATION
/* 中文说明：旧 WDK 头可能没有用户态同名常量，按 ntifs/winnt 定义补齐。 */
#define PROCESS_SET_INFORMATION 0x0200
#endif

/* 中文说明：PsGetNextProcessThread 用于稳定遍历目标进程线程对象。 */
typedef PETHREAD(NTAPI* KSWORD_PS_GET_NEXT_PROCESS_THREAD_FN)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
    );

typedef struct _KSWORD_PROCESS_FLAGS_CID_MATCH_CONTEXT
{
    const KSW_DYN_STATE* DynState;
    ULONG ProcessId;
    PEPROCESS ProcessObject;
    ULONG UniqueProcessId;
    NTSTATUS LastStatus;
} KSWORD_PROCESS_FLAGS_CID_MATCH_CONTEXT;

/* 中文说明：运行时解析 PsGetNextProcessThread，避免链接期依赖差异。 */
static KSWORD_PS_GET_NEXT_PROCESS_THREAD_FN
KswordARKProcessFlagsResolvePsGetNextProcessThread(
    VOID
    )
{
    UNICODE_STRING routineName;

    /* 中文说明：名称来自 ntoskrnl 导出表；缺失时禁 APC 功能返回不支持。 */
    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    /* 中文说明：调用方检查 NULL，不在 resolver 内记录状态。 */
    return (KSWORD_PS_GET_NEXT_PROCESS_THREAD_FN)MmGetSystemRoutineAddress(&routineName);
}

static VOID
KswordARKProcessFlagsCidMatchCallback(
    _In_ const KSW_CROSSVIEW_CID_ENTRY* Entry,
    _Inout_opt_ PVOID Context
    )
{
    KSWORD_PROCESS_FLAGS_CID_MATCH_CONTEXT* matchContext =
        (KSWORD_PROCESS_FLAGS_CID_MATCH_CONTEXT*)Context;
    PVOID uniqueProcessIdPointer = NULL;
    ULONG uniqueProcessId = 0UL;

    if (matchContext == NULL ||
        matchContext->ProcessObject != NULL ||
        Entry == NULL ||
        !Entry->Referenced ||
        Entry->Object == NULL) {
        return;
    }

    uniqueProcessId = HandleToULong(PsGetProcessId((PEPROCESS)Entry->Object));
    if (matchContext->DynState != NULL &&
        KswordARKCrossViewOffsetPresent(matchContext->DynState->Kernel.EpUniqueProcessId)) {
        NTSTATUS readStatus = KswordARKCrossViewReadPointerField(
            Entry->Object,
            matchContext->DynState->Kernel.EpUniqueProcessId,
            &uniqueProcessIdPointer);
        if (NT_SUCCESS(readStatus)) {
            uniqueProcessId = HandleToULong(uniqueProcessIdPointer);
        }
        else if (NT_SUCCESS(matchContext->LastStatus)) {
            matchContext->LastStatus = readStatus;
        }
    }

    if (Entry->CidValue != matchContext->ProcessId &&
        uniqueProcessId != matchContext->ProcessId &&
        HandleToULong(PsGetProcessId((PEPROCESS)Entry->Object)) != matchContext->ProcessId) {
        return;
    }

    ObReferenceObject(Entry->Object);
    matchContext->ProcessObject = (PEPROCESS)Entry->Object;
    matchContext->UniqueProcessId = uniqueProcessId;
    matchContext->LastStatus = STATUS_SUCCESS;
}

static NTSTATUS
KswordARKProcessFlagsReferenceProcessByCidTable(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONG ProcessId,
    _Outptr_ PEPROCESS* ProcessObjectOut
    )
{
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KSWORD_PROCESS_FLAGS_CID_MATCH_CONTEXT matchContext;
    PVOID pspCidTableAddress = NULL;
    ULONG64 missingCapabilityMask = 0ULL;
    ULONG visitedEntries = 0UL;
    BOOLEAN usedDynDataGlobal = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (DynState == NULL || ProcessObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessObjectOut = NULL;
    if (PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlZeroMemory(&fieldOffsets, sizeof(fieldOffsets));
    RtlZeroMemory(&matchContext, sizeof(matchContext));
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

    matchContext.DynState = DynState;
    matchContext.ProcessId = ProcessId;
    matchContext.LastStatus = STATUS_NOT_FOUND;
    status = KswordARKCrossViewWalkCidTable(
        DynState,
        pspCidTableAddress,
        *PsProcessType,
        0x00100000UL,
        KswordARKProcessFlagsCidMatchCallback,
        &matchContext,
        &visitedEntries);
    UNREFERENCED_PARAMETER(visitedEntries);

    if (matchContext.ProcessObject != NULL) {
        *ProcessObjectOut = matchContext.ProcessObject;
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }
    return matchContext.LastStatus;
}

static NTSTATUS
KswordARKProcessFlagsValidateReferencedIdentity(
    _Inout_ PEPROCESS* ProcessObjectInOut,
    _In_ ULONG64 ExpectedCreateTime100ns
    )
/*++

Routine Description:

    Validate a referenced EPROCESS against the optional R3 snapshot creation
    time. 中文说明：失败时本函数释放引用并清空输出，调用方不会接触错对象。

Arguments:

    ProcessObjectInOut - Referenced target object owned by the caller.
    ExpectedCreateTime100ns - Optional stable identity timestamp.

Return Value:

    STATUS_SUCCESS when identity matches, otherwise STATUS_INVALID_CID.

--*/
{
    ULONG64 observedCreateTime100ns = 0ULL;

    /* 中文说明：空输出表示 resolver 未按约定返回有效对象。 */
    if (ProcessObjectInOut == NULL || *ProcessObjectInOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：零值用于兼容没有稳定快照的旧调用方。 */
    if (ExpectedCreateTime100ns == 0ULL) {
        return STATUS_SUCCESS;
    }

    /* 中文说明：在驱动已解析的对象上读取时间，避免 R3 OpenProcess 被隐藏链路误导。 */
    observedCreateTime100ns =
        (ULONG64)PsGetProcessCreateTimeQuadPart(*ProcessObjectInOut);
    if (observedCreateTime100ns == ExpectedCreateTime100ns) {
        return STATUS_SUCCESS;
    }

    /* 中文说明：身份不符时立即释放引用，阻止后续 BreakOnTermination/APC 写入。 */
    ObDereferenceObject(*ProcessObjectInOut);
    *ProcessObjectInOut = NULL;
    return STATUS_INVALID_CID;
}

static NTSTATUS
KswordARKProcessFlagsReferenceProcessObject(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _Outptr_ PEPROCESS* ProcessObjectOut
    )
{
    KSW_DYN_STATE dynState;
    ULONG uniqueProcessId = 0UL;
    ULONG visitedEntries = 0UL;
    NTSTATUS cidStatus = STATUS_SUCCESS;
    NTSTATUS activeStatus = STATUS_SUCCESS;
    NTSTATUS lookupStatus = STATUS_SUCCESS;

    if (ProcessObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessObjectOut = NULL;
    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);

    cidStatus = KswordARKProcessFlagsReferenceProcessByCidTable(
        &dynState,
        ProcessId,
        ProcessObjectOut);
    if (NT_SUCCESS(cidStatus)) {
        return KswordARKProcessFlagsValidateReferencedIdentity(
            ProcessObjectOut,
            ExpectedCreateTime100ns);
    }

    activeStatus = KswordARKCrossViewReferenceProcessByActiveList(
        &dynState,
        ProcessId,
        0x00100000UL,
        ProcessObjectOut,
        &uniqueProcessId,
        &visitedEntries);
    UNREFERENCED_PARAMETER(uniqueProcessId);
    UNREFERENCED_PARAMETER(visitedEntries);
    if (NT_SUCCESS(activeStatus)) {
        return KswordARKProcessFlagsValidateReferencedIdentity(
            ProcessObjectOut,
            ExpectedCreateTime100ns);
    }

    lookupStatus = PsLookupProcessByProcessId(ULongToHandle(ProcessId), ProcessObjectOut);
    if (NT_SUCCESS(lookupStatus)) {
        return KswordARKProcessFlagsValidateReferencedIdentity(
            ProcessObjectOut,
            ExpectedCreateTime100ns);
    }
    if (cidStatus != STATUS_PROCEDURE_NOT_FOUND &&
        cidStatus != STATUS_NOT_FOUND &&
        cidStatus != STATUS_NOT_SUPPORTED) {
        return cidStatus;
    }
    if (activeStatus != STATUS_PROCEDURE_NOT_FOUND &&
        activeStatus != STATUS_NOT_FOUND &&
        activeStatus != STATUS_NOT_SUPPORTED) {
        return activeStatus;
    }
    return lookupStatus;
}

/* 中文说明：打开目标进程句柄，只用于 ZwSetInformationProcess 官方入口。 */
static NTSTATUS
KswordARKProcessFlagsOpenProcessHandleByObject(
    _In_ PEPROCESS ProcessObject,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ HANDLE* ProcessHandleOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：输出参数先清空，失败分支不会留下无效句柄。 */
    if (ProcessHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessHandleOut = NULL;

    if (ProcessObject == NULL || PsProcessType == NULL || *PsProcessType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：PROCESS_SET_INFORMATION 足够设置 BreakOnTermination。 */
    status = ObOpenObjectByPointer(
        ProcessObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        DesiredAccess,
        *PsProcessType,
        KernelMode,
        ProcessHandleOut);
    return status;
}

/* 中文说明：通过 ZwSetInformationProcess 设置或清除 BreakOnTermination。 */
static NTSTATUS
KswordARKProcessFlagsSetBreakOnTerminationByZw(
    _In_ PEPROCESS ProcessObject,
    _In_ BOOLEAN EnableBreakOnTermination
    )
{
    HANDLE processHandle = NULL;
    ULONG breakValue = EnableBreakOnTermination ? 1UL : 0UL;
    KSWORD_ZW_SET_INFORMATION_PROCESS_FN zwSetInformationProcess = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：动态解析失败时不尝试 EPROCESS.Flags 硬编码写入。 */
    zwSetInformationProcess = KswordARKDriverResolveZwSetInformationProcess();
    if (zwSetInformationProcess == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* 中文说明：官方入口需要进程句柄，避免依赖未公开 EPROCESS 位布局。 */
    status = KswordARKProcessFlagsOpenProcessHandleByObject(
        ProcessObject,
        PROCESS_SET_INFORMATION,
        &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 中文说明：ZwSetInformationProcess 成功后目标进程 critical 标记立即生效。 */
    status = zwSetInformationProcess(
        processHandle,
        KSWORD_ARK_PROCESS_INFORMATION_BREAK_ON_TERMINATION,
        &breakValue,
        sizeof(breakValue));

    /* 中文说明：无论设置成功与否，内核句柄都必须关闭。 */
    ZwClose(processHandle);
    return status;
}

/* 中文说明：解析 EPROCESS.Flags 偏移；PDB 优先，特征码来源需再次活体验证。 */
static NTSTATUS
KswordARKProcessFlagsResolveEprocessFlagsOffset(
    _In_ PEPROCESS ProcessObject,
    _Out_ ULONG* FlagsOffsetOut
    )
{
    KSW_DYN_STATE dynState;
    LONG runtimeOffset = -1;

    if (ProcessObject == NULL || FlagsOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *FlagsOffsetOut = 0UL;

    /*
     * 中文说明：这里禁止按 Windows 版本猜偏移。精确 PDB profile 仍然
     * 优先；缺少 PDB 时只接受由 PsGetProcessExitProcessCalled 导出例程
     * 解码、并对当前目标 EPROCESS 再次做位语义校验的 runtime pattern。
     */
    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);
    if (dynState.Kernel.EpFlags == KSW_DYN_OFFSET_UNAVAILABLE ||
        dynState.Kernel.EpFlags == 0UL ||
        dynState.Kernel.EpFlags > KSWORD_ARK_EPROCESS_FLAGS_OFFSET_MAX ||
        (dynState.KernelSources.EpFlags != KSW_DYN_FIELD_SOURCE_PDB_PROFILE &&
         dynState.KernelSources.EpFlags != KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)) {
        return STATUS_NOT_SUPPORTED;
    }

    if (dynState.KernelSources.EpFlags == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN) {
        runtimeOffset = KswordARKDriverResolveProcessFlagsOffset(ProcessObject);
        if (runtimeOffset <= 0 || (ULONG)runtimeOffset != dynState.Kernel.EpFlags) {
            return STATUS_REVISION_MISMATCH;
        }
    }

    *FlagsOffsetOut = dynState.Kernel.EpFlags;
    return STATUS_SUCCESS;
}

/* 中文说明：通过直接写 EPROCESS.Flags 兜底设置 BreakOnTermination。 */
static NTSTATUS
KswordARKProcessFlagsSetBreakOnTerminationByEprocess(
    _In_ PEPROCESS ProcessObject,
    _In_ BOOLEAN EnableBreakOnTermination
    )
{
    ULONG flagsOffset = 0UL;
    volatile LONG* flagsAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (ProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：偏移解析失败时不猜测，避免误写 EPROCESS 其它字段。 */
    status = KswordARKProcessFlagsResolveEprocessFlagsOffset(ProcessObject, &flagsOffset);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (flagsOffset == 0UL || flagsOffset > KSWORD_ARK_EPROCESS_FLAGS_OFFSET_MAX) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        flagsAddress = (volatile LONG*)((PUCHAR)ProcessObject + flagsOffset);
        if (EnableBreakOnTermination) {
            (VOID)InterlockedOr(
                flagsAddress,
                (LONG)KSWORD_ARK_EPROCESS_FLAGS_BREAK_ON_TERMINATION_MASK);
        }
        else {
            (VOID)InterlockedAnd(
                flagsAddress,
                (LONG)(~KSWORD_ARK_EPROCESS_FLAGS_BREAK_ON_TERMINATION_MASK));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

/* 中文说明：先走官方 ZwSetInformationProcess，失败再用 EPROCESS.Flags 兜底。 */
static NTSTATUS
KswordARKProcessFlagsSetBreakOnTermination(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _In_ BOOLEAN EnableBreakOnTermination
    )
{
    PEPROCESS processObject = NULL;
    NTSTATUS zwStatus = STATUS_SUCCESS;
    NTSTATUS directStatus = STATUS_SUCCESS;

    zwStatus = KswordARKProcessFlagsReferenceProcessObject(
        ProcessId,
        ExpectedCreateTime100ns,
        &processObject);
    if (!NT_SUCCESS(zwStatus)) {
        return zwStatus;
    }

    zwStatus = KswordARKProcessFlagsSetBreakOnTerminationByZw(
        processObject,
        EnableBreakOnTermination);
    if (NT_SUCCESS(zwStatus)) {
        ObDereferenceObject(processObject);
        return zwStatus;
    }

    /* 中文说明：PPL/受限句柄路径可能拒绝 ZwOpenProcess，因此使用 R0 直写作为补强。 */
    directStatus = KswordARKProcessFlagsSetBreakOnTerminationByEprocess(
        processObject,
        EnableBreakOnTermination);
    ObDereferenceObject(processObject);
    if (NT_SUCCESS(directStatus)) {
        return directStatus;
    }

    /* 中文说明：优先保留官方路径失败原因；若官方入口缺失则返回兜底原因。 */
    if (zwStatus == STATUS_PROCEDURE_NOT_FOUND || zwStatus == STATUS_NOT_SUPPORTED) {
        return directStatus;
    }
    return zwStatus;
}

/* 中文说明：当前仅对 x64 使用经常见构建验证的 ETHREAD 偏移。 */
static NTSTATUS
KswordARKProcessFlagsResolveApcQueueableOffset(
    _Out_ ULONG* OffsetOut
    )
{
    /* 中文说明：输出为 ULONG 偏移，调用方会再次限制写入大小。 */
    if (OffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OffsetOut = 0UL;

#if defined(_M_X64)
    UCHAR code[0x300]; // 安全读取当前内核实际 APC 入队代码，不凭 OS build 猜布局。
    ULONG index; // 遍历有限入口窗口。
    ULONG matches = 0UL; // 不接受歧义的字段测试。
    BOOLEAN threadLoadFound = FALSE; // 验证 RDI 来自公开 KAPC.Thread 字段。
    UNICODE_STRING routineName; // 通过导出解析本机入队入口。
    PVOID routine; // 不依赖 WDK 对 KeInsertQueueApc 的导入声明。
    const UCHAR threadLoad[] = {0x48, 0x8B, 0x7E, 0x08}; // mov rdi,[rsi+8]。
    const UCHAR queueableTest[] = {0xF7, 0x47, 0x74, 0x00, 0x40, 0x00, 0x00}; // test dword [rdi+74h],4000h。
    RtlInitUnicodeString(&routineName, L"KeInsertQueueApc"); // 使用真正内核导出。
    routine = MmGetSystemRoutineAddress(&routineName); // NULL 不可进入读取。
    if (routine == NULL || !KswordARKRuntimeReadMemory(routine, code, sizeof(code))) return STATUS_NOT_SUPPORTED; // 拒绝不可读取的入口。
    for (index = 0UL; index + sizeof(queueableTest) + 2U <= sizeof(code); ++index) { // 确保测试和跳转字节完整。
        if (RtlCompareMemory(code + index, threadLoad, sizeof(threadLoad)) == sizeof(threadLoad)) threadLoadFound = TRUE; // 必须先加载 APC.Thread。
        if (threadLoadFound && RtlCompareMemory(code + index, queueableTest, sizeof(queueableTest)) == sizeof(queueableTest) &&
            code[index + sizeof(queueableTest)] == 0x0F && code[index + sizeof(queueableTest) + 1U] == 0x84) ++matches; // 相同线程字段为零时拒绝入队。
    }
    if (matches != 1UL) return STATUS_NOT_SUPPORTED; // 布局不同或代码已修改时不写猜测字段。
    *OffsetOut = KSWORD_ARK_ETHREAD_APC_QUEUEABLE_OFFSET_X64;
    return STATUS_SUCCESS;
#else
    /* 中文说明：ARM64/x86 未维护偏移表，拒绝执行避免误写线程对象。 */
    return STATUS_NOT_SUPPORTED;
#endif
}

/* 中文说明：清除单个 ETHREAD 的 ApcQueueable 位，异常时返回异常码。 */
static NTSTATUS
KswordARKProcessFlagsClearThreadApcQueueable(
    _In_ PETHREAD ThreadObject,
    _In_ ULONG ApcQueueableOffset,
    _Out_ BOOLEAN* ChangedOut
    )
{
    volatile LONG* fieldAddress = NULL;
    LONG oldValue = 0;
    LONG newValue = 0;

    /* 中文说明：ChangedOut 告诉调用方本次是否实际从 1 变成 0。 */
    if (ThreadObject == NULL || ChangedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ChangedOut = FALSE;

    /* 中文说明：偏移过大说明布局不可信，直接拒绝。 */
    if (ApcQueueableOffset > 0x1000UL) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        /* 中文说明：字段按 LONG 原子位清除，避免覆盖并发设置的其它位。 */
        fieldAddress = (volatile LONG*)((PUCHAR)ThreadObject + ApcQueueableOffset);
        oldValue = InterlockedAnd(fieldAddress, (LONG)(~KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK));
        newValue = oldValue & (LONG)(~KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK);
        *ChangedOut = ((oldValue ^ newValue) & (LONG)KSWORD_ARK_ETHREAD_APC_QUEUEABLE_MASK) != 0 ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/* 中文说明：遍历目标进程线程并清除每个线程的 ApcQueueable 位。 */
static NTSTATUS
KswordARKProcessFlagsDisableApcInsertion(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _Out_ ULONG* TouchedThreadCountOut
    )
{
    PEPROCESS processObject = NULL;
    PETHREAD threadCursor = NULL;
    ULONG apcQueueableOffset = 0UL;
    ULONG touchedThreadCount = 0UL;
    KSWORD_PS_GET_NEXT_PROCESS_THREAD_FN psGetNextProcessThread = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS lastFailureStatus = STATUS_SUCCESS;

    /* 中文说明：输出线程计数用于 UI 展示本次影响范围。 */
    if (TouchedThreadCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TouchedThreadCountOut = 0UL;

    /* 中文说明：先解析偏移，未知平台不进入对象写路径。 */
    status = KswordARKProcessFlagsResolveApcQueueableOffset(&apcQueueableOffset);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 中文说明：有导出则保留原遍历，否则使用系统真实 TID 快照。 */
    psGetNextProcessThread = KswordARKProcessFlagsResolvePsGetNextProcessThread();

    /* 中文说明：引用目标 EPROCESS，确保线程枚举期间进程对象有效。 */
    status = KswordARKProcessFlagsReferenceProcessObject(
        ProcessId,
        ExpectedCreateTime100ns,
        &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (psGetNextProcessThread == NULL) { // 现代 ntoskrnl 没有这个导出是常态。
        KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT snapshot; // 保存真实目标进程 TID。
        ULONG index; // 当前快照下标。
        status = KswordARKWorkQueueCaptureProcessThreads(ProcessId, &snapshot); // 快照由通用有界解析器产生。
        if (!NT_SUCCESS(status)) { // 无法枚举不得报告零线程成功。
            ObDereferenceObject(processObject); // 释放稳定目标身份。
            return status; // 保留真实枚举错误。
        }
        if (snapshot.Truncated) { // 截断快照不得开始部分写入。
            KswordARKWorkQueueReleaseSystemThreads(&snapshot); // 释放真实 TID 数组。
            ObDereferenceObject(processObject); // 释放目标引用。
            return STATUS_BUFFER_OVERFLOW; // 通知调用者未完成。
        }
        for (index = 0UL; index < snapshot.Count; ++index) { // 每项重新通过对象管理器引用，排除已退出和 TID 复用。
            PETHREAD thread = NULL; // 独立持有本次引用。
            BOOLEAN changed = FALSE; // 实际改位结果。
            NTSTATUS threadStatus = PsLookupThreadByThreadId(ULongToHandle(snapshot.Entries[index].ThreadId), &thread); // 不使用快照对象指针。
            if (!NT_SUCCESS(threadStatus)) continue; // 快照后退出的线程不需要更改。
            if (PsGetThreadProcess(thread) == processObject && !PsIsThreadTerminating(thread)) { // 比较进程对象，禁止写 PID 复用的新进程。
                threadStatus = KswordARKProcessFlagsClearThreadApcQueueable(thread, apcQueueableOffset, &changed); // 只清实际 APC 位。
                if (!NT_SUCCESS(threadStatus)) lastFailureStatus = threadStatus; // 记录所有部分失败。
                else if (changed) ++touchedThreadCount; // 仅计真实修改。
            }
            ObDereferenceObject(thread); // 每条线程引用严格释放一次。
        }
        KswordARKWorkQueueReleaseSystemThreads(&snapshot); // 回收快照数组。
        ObDereferenceObject(processObject); // 完成稳定目标操作。
        *TouchedThreadCountOut = touchedThreadCount; // 返回实际受影响数。
        return lastFailureStatus; // 不把部分失败掩盖成成功。
    }

    /* 中文说明：PsGetNextProcessThread 返回带引用的 ETHREAD，循环内必须释放。 */
    threadCursor = psGetNextProcessThread(processObject, NULL);
    while (threadCursor != NULL) {
        PETHREAD nextThread = psGetNextProcessThread(processObject, threadCursor);
        BOOLEAN changed = FALSE;
        NTSTATUS threadStatus = STATUS_SUCCESS;

        /* 中文说明：对每个线程独立 SEH，单线程异常不阻断剩余线程处理。 */
        threadStatus = KswordARKProcessFlagsClearThreadApcQueueable(
            threadCursor,
            apcQueueableOffset,
            &changed);
        if (NT_SUCCESS(threadStatus)) {
            if (changed && touchedThreadCount != MAXULONG) {
                touchedThreadCount += 1UL;
            }
        }
        else {
            lastFailureStatus = threadStatus;
        }

        /* 中文说明：释放当前线程引用后推进到下一项。 */
        ObDereferenceObject(threadCursor);
        threadCursor = nextThread;
    }

    /* 中文说明：释放进程引用，线程枚举已经结束。 */
    ObDereferenceObject(processObject);
    *TouchedThreadCountOut = touchedThreadCount;

    /* 中文说明：全部线程都失败时返回最后失败；部分成功由响应 status 表达。 */
    if (!NT_SUCCESS(lastFailureStatus)) { // 任一线程失败都保留失败状态，计数仍返回。
        return lastFailureStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKDriverSetProcessSpecialFlags(
    _In_ ULONG ProcessId,
    _In_ ULONG Action,
    _In_ ULONG Flags,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _Out_ ULONG* OperationStatusOut,
    _Out_ ULONG* AppliedFlagsOut,
    _Out_ ULONG* TouchedThreadCountOut
    )
/*++

Routine Description:

    Apply dangerous process special flags from R3. 中文说明：当前支持
    BreakOnTermination 开/关，以及清除目标进程现有线程的 APC 插入许可位。

Arguments:

    ProcessId - 目标 PID。
    Action - KSWORD_ARK_PROCESS_SPECIAL_ACTION_*。
    Flags - 预留策略位，当前只记录不改变语义。
    ExpectedCreateTime100ns - 可选进程创建时间，非零时必须精确匹配。
    OperationStatusOut - 返回协议状态。
    AppliedFlagsOut - 返回已经应用的语义 flag。
    TouchedThreadCountOut - 返回禁 APC 时实际改变的线程数。

Return Value:

    STATUS_SUCCESS 表示动作完成；失败返回底层 NTSTATUS。

--*/
{
    ULONG touchedThreadCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：Flags 当前预留，显式标记避免 W4 未引用告警。 */
    UNREFERENCED_PARAMETER(Flags);

    if (OperationStatusOut == NULL ||
        AppliedFlagsOut == NULL ||
        TouchedThreadCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNKNOWN;
    *AppliedFlagsOut = 0UL;
    *TouchedThreadCountOut = 0UL;

    if (ProcessId == 0UL || ProcessId <= 4UL) {
        *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_LOOKUP_FAILED;
        return STATUS_INVALID_PARAMETER;
    }

    if (Action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION ||
        Action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION) {
        const BOOLEAN enableBreak =
            (Action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION) ? TRUE : FALSE;

        /* 中文说明：优先使用 ZwSetInformationProcess；失败时用 EPROCESS.Flags 兜底。 */
        status = KswordARKProcessFlagsSetBreakOnTermination(
            ProcessId,
            ExpectedCreateTime100ns,
            enableBreak);
        if (NT_SUCCESS(status)) {
            *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
            if (enableBreak) {
                *AppliedFlagsOut |= KSWORD_ARK_PROCESS_SPECIAL_FLAG_BREAK_ON_TERMINATION;
            }
        }
        else if (status == STATUS_PROCEDURE_NOT_FOUND || status == STATUS_NOT_SUPPORTED) {
            *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNSUPPORTED;
        }
        else {
            *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED;
        }
        return status;
    }

    if (Action == KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION) {
        /* 中文说明：禁 APC 插入是线程级批量写，返回改变线程数量供 R3 审计。 */
        status = KswordARKProcessFlagsDisableApcInsertion(
            ProcessId,
            ExpectedCreateTime100ns,
            &touchedThreadCount);
        *TouchedThreadCountOut = touchedThreadCount;
        if (NT_SUCCESS(status)) {
            *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
            *AppliedFlagsOut |= KSWORD_ARK_PROCESS_SPECIAL_FLAG_APC_INSERT_DISABLED;
        }
        else if (status == STATUS_PROCEDURE_NOT_FOUND || status == STATUS_NOT_SUPPORTED) {
            *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNSUPPORTED;
        }
        else {
            *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED;
        }
        return status;
    }

    *OperationStatusOut = KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED;
    return STATUS_INVALID_PARAMETER;
}
