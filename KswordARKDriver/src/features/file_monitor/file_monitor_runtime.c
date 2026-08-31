/*++

Module Name:

    file_monitor_runtime.c

Abstract:

    Phase-12 file-system minifilter runtime and event ring buffer.

Environment:

    Kernel-mode minifilter + KMDF control device

--*/

#include <fltKernel.h>
#include "file_monitor_internal.h"
#include "ark/ark_driver.h"

#include <stdarg.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_FILE_MONITOR_TAG 'mFsK'
#define KSWORD_ARK_FILE_MONITOR_INSTANCE_KEY_NAME L"Instances"
#define KSWORD_ARK_FILE_MONITOR_DEFAULT_INSTANCE_NAME L"KswordARK Instance"
#define KSWORD_ARK_FILE_MONITOR_ALTITUDE_TEXT L"385210"

typedef struct _KSWORD_ARK_FILE_MONITOR_RUNTIME
{
    PFLT_FILTER Filter;
    WDFDEVICE Device;
    EX_PUSH_LOCK ControlLock;
    KSPIN_LOCK RingLock;
    ULONG HeadIndex;
    ULONG TailIndex;
    ULONG QueuedCount;
    ULONG DroppedCount;
    ULONG OperationMask;
    ULONG ProcessIdFilter;
    ULONG RuntimeFlags;
    LONG64 Sequence;
    NTSTATUS RegisterStatus;
    NTSTATUS StartStatus;
    NTSTATUS LastErrorStatus;
    KSWORD_ARK_FILE_MONITOR_EVENT Ring[KSWORD_ARK_FILE_MONITOR_RING_CAPACITY];
} KSWORD_ARK_FILE_MONITOR_RUNTIME;

static KSWORD_ARK_FILE_MONITOR_RUNTIME g_KswordArkFileMonitorRuntime;

static NTSTATUS FLTAPI
KswordARKFileMonitorUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FLTAPI
KswordArkMinifilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
KswordArkMinifilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

static const FLT_OPERATION_REGISTRATION g_KswordArkFileMonitorOperations[] =
{
    { IRP_MJ_CREATE, 0, KswordArkMinifilterPreOperation, KswordArkMinifilterPostOperation },
    { IRP_MJ_READ, 0, KswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_WRITE, 0, KswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_SET_INFORMATION, 0, KswordArkMinifilterPreOperation, KswordArkMinifilterPostOperation },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, KswordArkMinifilterPreOperation, KswordArkMinifilterPostOperation },
    { IRP_MJ_CLEANUP, 0, KswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_CLOSE, 0, KswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_KswordArkFileMonitorRegistration =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_KswordArkFileMonitorOperations,
    KswordARKFileMonitorUnloadCallback,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static ULONG
KswordARKFileMonitorAdvanceIndex(
    _In_ ULONG CurrentIndex
    )
/*++

Routine Description:

    推进 ring buffer 下标。中文说明：容量固定为 2^n 不做假设，统一用取模保持
    可读性和后续容量调整安全。

Arguments:

    CurrentIndex - 当前下标。

Return Value:

    下一个下标。

--*/
{
    return (CurrentIndex + 1UL) % KSWORD_ARK_FILE_MONITOR_RING_CAPACITY;
}

static VOID
KswordARKFileMonitorLog(
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR MessageText
    )
/*++

Routine Description:

    写入文件监控运行时日志。中文说明：minifilter 早期初始化时 Device 可能为空，
    此时只跳过 WDF 日志，不影响 FltMgr 注册。

Arguments:

    LevelText - 日志等级。
    MessageText - 日志正文。

Return Value:

    None.

--*/
{
    WDFDEVICE device = g_KswordArkFileMonitorRuntime.Device;

    if (device == WDF_NO_HANDLE || device == NULL) {
        return;
    }

    (VOID)KswordARKDriverEnqueueLogFrame(
        device,
        LevelText != NULL ? LevelText : "Info",
        MessageText != NULL ? MessageText : "");
}

static VOID
KswordARKFileMonitorLogFormat(
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    )
/*++

Routine Description:

    格式化写入文件监控运行时日志。中文说明：初始化/启动路径不是热路径，允许
    使用栈上小缓冲补充 NTSTATUS，避免 R3 只能看到 Win32 error=22。

Arguments:

    LevelText - 日志级别。
    FormatText - printf 风格格式串。
    ... - 格式化参数。

Return Value:

    None. 本函数没有返回值。

--*/
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    if (FormatText == NULL) {
        return;
    }

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), FormatText, arguments))) {
        KswordARKFileMonitorLog(LevelText, logBuffer);
    }
    va_end(arguments);
}

static NTSTATUS
KswordARKFileMonitorWriteRegistryStringValue(
    _In_ HANDLE KeyHandle,
    _In_z_ PCWSTR ValueNameText,
    _In_z_ PCWSTR ValueDataText
    )
/*++

Routine Description:

    写入 minifilter 实例注册表字符串值。中文说明：FltRegisterFilter 依赖
    Instances\DefaultInstance 和实例 Altitude；SCM CreateService 不会自动生成这些值。

Arguments:

    KeyHandle - 已打开的目标键句柄。
    ValueNameText - REG_SZ 值名。
    ValueDataText - REG_SZ 字符串数据。

Return Value:

    ZwSetValueKey 返回状态。

--*/
{
    UNICODE_STRING valueName;
    UNICODE_STRING valueData;

    if (KeyHandle == NULL || ValueNameText == NULL || ValueDataText == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&valueName, ValueNameText);
    RtlInitUnicodeString(&valueData, ValueDataText);
    return ZwSetValueKey(
        KeyHandle,
        &valueName,
        0UL,
        REG_SZ,
        valueData.Buffer,
        (ULONG)valueData.Length + sizeof(WCHAR));
}

static NTSTATUS
KswordARKFileMonitorWriteRegistryDwordValue(
    _In_ HANDLE KeyHandle,
    _In_z_ PCWSTR ValueNameText,
    _In_ ULONG ValueData
    )
/*++

Routine Description:

    写入 minifilter 实例注册表 DWORD 值。中文说明：Flags=0 表示默认实例可自动
    attach，和 INF 中的配置保持一致。

Arguments:

    KeyHandle - 已打开的目标键句柄。
    ValueNameText - REG_DWORD 值名。
    ValueData - DWORD 数据。

Return Value:

    ZwSetValueKey 返回状态。

--*/
{
    UNICODE_STRING valueName;

    if (KeyHandle == NULL || ValueNameText == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&valueName, ValueNameText);
    return ZwSetValueKey(
        KeyHandle,
        &valueName,
        0UL,
        REG_DWORD,
        &ValueData,
        sizeof(ValueData));
}

static NTSTATUS
KswordARKFileMonitorCreateSubKey(
    _In_opt_ HANDLE RootHandle,
    _In_ PUNICODE_STRING KeyName,
    _Out_ HANDLE* KeyHandleOut
    )
/*++

Routine Description:

    创建或打开一个相对注册表键。中文说明：使用 RootHandle 逐级创建，避免拼接
    RegistryPath 字符串时出现长度截断或转义错误。

Arguments:

    RootHandle - 父键句柄，可为空；为空时 KeyName 必须是绝对路径。
    KeyName - 子键名或绝对键路径。
    KeyHandleOut - 返回新打开的键句柄。

Return Value:

    ZwCreateKey 返回状态。

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    ULONG disposition = 0UL;

    if (KeyName == NULL || KeyName->Buffer == NULL || KeyHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *KeyHandleOut = NULL;
    InitializeObjectAttributes(
        &objectAttributes,
        KeyName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        RootHandle,
        NULL);
    return ZwCreateKey(
        KeyHandleOut,
        KEY_READ | KEY_WRITE,
        &objectAttributes,
        0UL,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition);
}

static NTSTATUS
KswordARKFileMonitorEnsureRegistryInstances(
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    确保服务键下存在 FltMgr 要求的 minifilter Instances 配置。中文说明：正式
    INF 安装会写入这些值，但当前 R3 快捷启动路径通过 CreateServiceW 直接注册
    .sys，因此驱动需要在 DriverEntry 内自愈，保证 FltRegisterFilter 可用。

Arguments:

    RegistryPath - DriverEntry 传入的服务注册表绝对路径。

Return Value:

    STATUS_SUCCESS 或底层注册表写入失败状态。

--*/
{
    UNICODE_STRING instancesKeyName;
    UNICODE_STRING instanceKeyName;
    HANDLE serviceKeyHandle = NULL;
    HANDLE instancesKeyHandle = NULL;
    HANDLE instanceKeyHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS closeStatus = STATUS_SUCCESS;

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL || RegistryPath->Length == 0U) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKFileMonitorCreateSubKey(NULL, RegistryPath, &serviceKeyHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&instancesKeyName, KSWORD_ARK_FILE_MONITOR_INSTANCE_KEY_NAME);
    status = KswordARKFileMonitorCreateSubKey(serviceKeyHandle, &instancesKeyName, &instancesKeyHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(serviceKeyHandle);
        return status;
    }

    status = KswordARKFileMonitorWriteRegistryStringValue(
        instancesKeyHandle,
        L"DefaultInstance",
        KSWORD_ARK_FILE_MONITOR_DEFAULT_INSTANCE_NAME);
    if (!NT_SUCCESS(status)) {
        ZwClose(instancesKeyHandle);
        ZwClose(serviceKeyHandle);
        return status;
    }

    RtlInitUnicodeString(&instanceKeyName, KSWORD_ARK_FILE_MONITOR_DEFAULT_INSTANCE_NAME);
    status = KswordARKFileMonitorCreateSubKey(instancesKeyHandle, &instanceKeyName, &instanceKeyHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(instancesKeyHandle);
        ZwClose(serviceKeyHandle);
        return status;
    }

    status = KswordARKFileMonitorWriteRegistryStringValue(
        instanceKeyHandle,
        L"Altitude",
        KSWORD_ARK_FILE_MONITOR_ALTITUDE_TEXT);
    if (NT_SUCCESS(status)) {
        status = KswordARKFileMonitorWriteRegistryDwordValue(
            instanceKeyHandle,
            L"Flags",
            0UL);
    }

    closeStatus = ZwClose(instanceKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }
    closeStatus = ZwClose(instancesKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }
    closeStatus = ZwClose(serviceKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }

    return status;
}

static VOID
KswordARKFileMonitorCopyNameToEvent(
    _Inout_ KSWORD_ARK_FILE_MONITOR_EVENT* Event,
    _In_opt_ PCUNICODE_STRING FileName
    )
/*++

Routine Description:

    将 FltMgr 返回的 normalized/opened name 复制到事件。中文说明：固定数组永远
    尾零，超长路径显式标记 TRUNCATED，避免 R3 误以为完整。

Arguments:

    Event - 待填充事件。
    FileName - 文件名 UNICODE_STRING，可为空。

Return Value:

    None.

--*/
{
    ULONG sourceChars = 0UL;
    ULONG charsToCopy = 0UL;

    if (Event == NULL || FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0U) {
        return;
    }

    sourceChars = (ULONG)(FileName->Length / sizeof(WCHAR));
    charsToCopy = sourceChars;
    if (charsToCopy >= KSWORD_ARK_FILE_MONITOR_PATH_CHARS) {
        charsToCopy = KSWORD_ARK_FILE_MONITOR_PATH_CHARS - 1UL;
        Event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_PATH_TRUNCATED;
    }

    if (charsToCopy > 0UL) {
        RtlCopyMemory(
            Event->path,
            FileName->Buffer,
            (SIZE_T)charsToCopy * sizeof(WCHAR));
        Event->path[charsToCopy] = L'\0';
        Event->pathLengthChars = charsToCopy;
        Event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_PATH_PRESENT;
    }
}

static VOID
KswordARKFileMonitorFillCommonEvent(
    _Out_ KSWORD_ARK_FILE_MONITOR_EVENT* Event,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG OperationType,
    _In_ BOOLEAN IsPostOperation,
    _In_ BOOLEAN IncludeLegacySequence
    )
/*++

Routine Description:

    填充文件事件公共字段。中文说明：这里不做阻断，只采集展示所需字段；路径
    解析失败时仍保留 PID、MajorFunction、FileObject 等上下文。

Arguments:

    Event - 输出事件。
    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    OperationType - 协议 operation type。
    IsPostOperation - TRUE 表示 post 回调记录结果。

Return Value:

    None.

--*/
{
    PFLT_FILE_NAME_INFORMATION nameInformation = NULL;
    NTSTATUS nameStatus = STATUS_SUCCESS;

    RtlZeroMemory(Event, sizeof(*Event));
    Event->version = KSWORD_ARK_FILE_MONITOR_PROTOCOL_VERSION;
    Event->size = sizeof(*Event);
    Event->operationType = OperationType;
    Event->majorFunction = Data->Iopb->MajorFunction;
    Event->minorFunction = Data->Iopb->MinorFunction;
    Event->processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    Event->threadId = HandleToULong(PsGetCurrentThreadId());
    if (IncludeLegacySequence) {
        Event->sequence = (ULONG64)InterlockedIncrement64(&g_KswordArkFileMonitorRuntime.Sequence);
    }
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&Event->timeUtc100ns);

    if (FltObjects != NULL && FltObjects->FileObject != NULL) {
        Event->fileObjectAddress = (ULONG64)(ULONG_PTR)FltObjects->FileObject;
    }

    if (IsPostOperation) {
        Event->resultStatus = Data->IoStatus.Status;
        Event->fieldFlags |=
            KSWORD_ARK_FILE_MONITOR_FIELD_RESULT_PRESENT |
            KSWORD_ARK_FILE_MONITOR_FIELD_POST_OPERATION;
    }

    if (Event->processId <= 4UL) {
        Event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_SYSTEM_PROCESS;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        Event->desiredAccess = Data->Iopb->Parameters.Create.SecurityContext != NULL ?
            Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess :
            0UL;
        Event->shareAccess = Data->Iopb->Parameters.Create.ShareAccess;
        Event->createOptions = Data->Iopb->Parameters.Create.Options;
        Event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_ACCESS_PRESENT;
    }
    else if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        Event->fileInformationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    }
    else if (Data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) {
        Event->fsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
        Event->fsInputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.InputBufferLength;
        Event->fsOutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength;
        Event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_FSCTL_PRESENT;
    }

    // post-operation 回调可在 DISPATCH_LEVEL 运行；名称查询及 FileName 缓冲区访问只允许 APC_LEVEL 及以下。
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    // 新回调监控单独采集时只复制现成 FileObject 名称，不触发名称查询分配。
    if (!IncludeLegacySequence) {
        if (FltObjects != NULL &&
            FltObjects->FileObject != NULL &&
            FltObjects->FileObject->FileName.Buffer != NULL) {
            KswordARKFileMonitorCopyNameToEvent(Event, &FltObjects->FileObject->FileName);
        }
        return;
    }

    nameStatus = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInformation);
    if (NT_SUCCESS(nameStatus) && nameInformation != NULL) {
        (VOID)FltParseFileNameInformation(nameInformation);
        KswordARKFileMonitorCopyNameToEvent(Event, &nameInformation->Name);
    }
    else if (FltObjects != NULL &&
        FltObjects->FileObject != NULL &&
        FltObjects->FileObject->FileName.Buffer != NULL) {
        KswordARKFileMonitorCopyNameToEvent(Event, &FltObjects->FileObject->FileName);
    }

    if (nameInformation != NULL) {
        FltReleaseFileNameInformation(nameInformation);
    }
}

static VOID
KswordARKFileMonitorPublishCallbackEvent(
    _In_ const KSWORD_ARK_FILE_MONITOR_EVENT* Event
    )
{
    KSWORD_ARK_CALLBACK_MONITOR_EVENT_INPUT monitorInput;
    UNICODE_STRING pathText;

    // 旧文件事件已经完成路径解析，直接映射到统一回调遥测结构，避免重复查询名称。
    if (Event == NULL ||
        !KswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)) {
        return;
    }
    RtlZeroMemory(&monitorInput, sizeof(monitorInput));
    RtlZeroMemory(&pathText, sizeof(pathText));
    if ((Event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_PATH_PRESENT) != 0UL) {
        RtlInitUnicodeString(&pathText, Event->path);
        monitorInput.Path = &pathText;
    }
    monitorInput.Category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
    monitorInput.Operation = Event->operationType;
    monitorInput.OriginatingProcessId = Event->processId;
    monitorInput.OriginatingThreadId = Event->threadId;
    monitorInput.DetailCode = ((Event->majorFunction & 0xFFUL) << 8) |
        (Event->minorFunction & 0xFFUL);
    monitorInput.OriginalAccess = Event->desiredAccess;
    monitorInput.DesiredAccess = Event->desiredAccess;
    monitorInput.Address = Event->fileObjectAddress;
    if ((Event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_ACCESS_PRESENT) != 0UL) {
        monitorInput.Flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_ACCESS_PRESENT;
    }
    if ((Event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_RESULT_PRESENT) != 0UL) {
        monitorInput.Flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_STATUS_PRESENT;
        monitorInput.ResultStatus = Event->resultStatus;
    }
    if ((Event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_POST_OPERATION) != 0UL) {
        monitorInput.Flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_POST_OPERATION;
    }
    KswordArkCallbackMonitorPublish(&monitorInput);
}

static VOID
KswordARKFileMonitorPushEvent(
    _In_ const KSWORD_ARK_FILE_MONITOR_EVENT* Event
    )
/*++

Routine Description:

    把事件放入固定 ring buffer。中文说明：满时丢弃最旧事件并增加 droppedCount，
    R3 后续在状态栏显示 dropped count，提醒用户缩小过滤范围。

Arguments:

    Event - 已填充事件。

Return Value:

    None.

--*/
{
    KIRQL oldIrql;
    ULONG slotIndex = 0UL;

    if (Event == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, &oldIrql);

    slotIndex = g_KswordArkFileMonitorRuntime.TailIndex;
    RtlCopyMemory(
        &g_KswordArkFileMonitorRuntime.Ring[slotIndex],
        Event,
        sizeof(*Event));
    g_KswordArkFileMonitorRuntime.TailIndex =
        KswordARKFileMonitorAdvanceIndex(g_KswordArkFileMonitorRuntime.TailIndex);

    if (g_KswordArkFileMonitorRuntime.QueuedCount == KSWORD_ARK_FILE_MONITOR_RING_CAPACITY) {
        g_KswordArkFileMonitorRuntime.HeadIndex =
            KswordARKFileMonitorAdvanceIndex(g_KswordArkFileMonitorRuntime.HeadIndex);
        g_KswordArkFileMonitorRuntime.DroppedCount += 1UL;
        g_KswordArkFileMonitorRuntime.RuntimeFlags |= KSWORD_ARK_FILE_MONITOR_RUNTIME_DROPPED;
    }
    else {
        g_KswordArkFileMonitorRuntime.QueuedCount += 1UL;
    }

    KeReleaseSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, oldIrql);
}

static BOOLEAN
KswordARKFileMonitorShouldCapture(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG OperationType
    )
/*++

Routine Description:

    判断当前事件是否符合运行时过滤条件。中文说明：第一版只按操作类型和 PID
    粗过滤，路径/扩展名过滤留给 R3 虚拟化列表和后续规则层。

Arguments:

    Data - FltMgr callback data。
    OperationType - 协议 operation type。

Return Value:

    TRUE 表示应采集。

--*/
{
    ULONG processId = 0UL;

    if ((g_KswordArkFileMonitorRuntime.RuntimeFlags & KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED) == 0UL) {
        return FALSE;
    }
    if (OperationType == 0UL ||
        (OperationType & g_KswordArkFileMonitorRuntime.OperationMask) == 0UL) {
        return FALSE;
    }

    processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    if (g_KswordArkFileMonitorRuntime.ProcessIdFilter != 0UL &&
        g_KswordArkFileMonitorRuntime.ProcessIdFilter != processId) {
        return FALSE;
    }

    return TRUE;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI
KswordArkMinifilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
/*++

Routine Description:

    minifilter pre-operation 回调。中文说明：Create/SetInfo 需要 post 结果时请求
    post callback；Read/Write/Cleanup/Close 直接记录 pre 事件以降低开销。

Arguments:

    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    CompletionContext - 本实现不分配上下文，始终返回 NULL。

Return Value:

    FLT_PREOP_SUCCESS_NO_CALLBACK 或 FLT_PREOP_SUCCESS_WITH_CALLBACK。

--*/
{
    ULONG operationType = 0UL;
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    KSWORD_ARK_FILE_MONITOR_EVENT event;
    BOOLEAN redirected = FALSE;
    BOOLEAN legacyCapture = FALSE;
    BOOLEAN callbackCapture = FALSE;

    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    operationType = KswordARKMinifilterMapMajorToOperation(
        Data->Iopb->MajorFunction,
        Data->Iopb->MinorFunction,
        &Data->Iopb->Parameters);

    if (operationType != 0UL &&
        KswordArkCallbackIsMinifilterBypassPid((ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    callbackStatus = KswordArkMinifilterApplyRule(
        Data,
        FltObjects,
        operationType);
    if (callbackStatus == FLT_PREOP_COMPLETE) {
        // 被规则拒绝的操作没有 post 回调，仍向独立遥测通道报告最终状态。
        if (KswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)) {
            operationType = KswordARKFileMonitorMapMajorToOperation(
                Data->Iopb->MajorFunction,
                Data->Iopb->MinorFunction,
                &Data->Iopb->Parameters);
            if (operationType != 0UL) {
                KswordARKFileMonitorFillCommonEvent(
                    &event,
                    Data,
                    FltObjects,
                    operationType,
                    TRUE,
                    FALSE);
                KswordARKFileMonitorPublishCallbackEvent(&event);
            }
        }
        return FLT_PREOP_COMPLETE;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        (VOID)KswordARKRedirectTryRewriteFileCreate(
            Data,
            FltObjects,
            &redirected);
        UNREFERENCED_PARAMETER(redirected);
    }

    operationType = KswordARKFileMonitorMapMajorToOperation(
        Data->Iopb->MajorFunction,
        Data->Iopb->MinorFunction,
        &Data->Iopb->Parameters);
    legacyCapture = KswordARKFileMonitorShouldCapture(Data, operationType);
    callbackCapture = operationType != 0UL &&
        KswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER);
    if (!legacyCapture && !callbackCapture) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE ||
        Data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL ||
        Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    KswordARKFileMonitorFillCommonEvent(
        &event,
        Data,
        FltObjects,
        operationType,
        FALSE,
        legacyCapture);
    if (legacyCapture) {
        KswordARKFileMonitorPushEvent(&event);
    }
    if (callbackCapture) {
        KswordARKFileMonitorPublishCallbackEvent(&event);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
KswordArkMinifilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    minifilter post-operation 回调。中文说明：这里记录 Create/SetInfo 的最终
    NTSTATUS；如果 FltMgr 正在 drain，则不访问可能不稳定的上下文。

Arguments:

    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    CompletionContext - 未使用。
    Flags - post operation flags。

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING。

--*/
{
    ULONG operationType = 0UL;
    KSWORD_ARK_FILE_MONITOR_EVENT event;
    BOOLEAN legacyCapture = FALSE;
    BOOLEAN callbackCapture = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) != 0UL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    operationType = KswordARKFileMonitorMapMajorToOperation(
        Data->Iopb->MajorFunction,
        Data->Iopb->MinorFunction,
        &Data->Iopb->Parameters);
    legacyCapture = KswordARKFileMonitorShouldCapture(Data, operationType);
    callbackCapture = operationType != 0UL &&
        KswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER);
    if (!legacyCapture && !callbackCapture) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    KswordARKFileMonitorFillCommonEvent(
        &event,
        Data,
        FltObjects,
        operationType,
        TRUE,
        legacyCapture);
    if (legacyCapture) {
        KswordARKFileMonitorPushEvent(&event);
    }
    if (callbackCapture) {
        KswordARKFileMonitorPublishCallbackEvent(&event);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static NTSTATUS FLTAPI
KswordARKFileMonitorUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    FltMgr 请求卸载过滤器。中文说明：实际资源释放由 WDF driver unload 调用
    KswordARKFileMonitorUninitialize 统一完成。

Arguments:

    Flags - FltMgr unload flags。

Return Value:

    STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKFileMonitorInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_opt_ WDFDEVICE Device
    )
/*++

Routine Description:

    初始化 Phase-12 minifilter runtime。中文说明：只注册 filter，不默认开始采集；
    StartFiltering 由 control IOCTL 显式触发，避免加载驱动就产生高频文件事件。

Arguments:

    DriverObject - DriverEntry 传入的驱动对象。
    RegistryPath - DriverEntry 传入的注册表路径。
    Device - 控制设备，用于日志；早期可为空。

Return Value:

    STATUS_SUCCESS 或 FltRegisterFilter 失败状态。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS registryStatus = STATUS_SUCCESS;

    RtlZeroMemory(&g_KswordArkFileMonitorRuntime, sizeof(g_KswordArkFileMonitorRuntime));
    g_KswordArkFileMonitorRuntime.Device = Device;
    g_KswordArkFileMonitorRuntime.OperationMask = KSWORD_ARK_FILE_MONITOR_OPERATION_ALL;
    g_KswordArkFileMonitorRuntime.RegisterStatus = STATUS_NOT_SUPPORTED;
    g_KswordArkFileMonitorRuntime.StartStatus = STATUS_NOT_SUPPORTED;
    ExInitializePushLock(&g_KswordArkFileMonitorRuntime.ControlLock);
    KeInitializeSpinLock(&g_KswordArkFileMonitorRuntime.RingLock);

    registryStatus = KswordARKFileMonitorEnsureRegistryInstances(RegistryPath);
    if (!NT_SUCCESS(registryStatus)) {
        /*
         * 中文说明：实例注册表补齐失败不立即终止初始化。若用户通过 INF 安装过驱动，
         * FltMgr 仍可能从已有配置完成注册；若确实缺失，后面的 FltRegisterFilter
         * 会返回更贴近 FltMgr 的失败状态并写入 RegisterStatus。
         */
        g_KswordArkFileMonitorRuntime.LastErrorStatus = registryStatus;
        KswordARKFileMonitorLogFormat(
            "Warn",
            "KswordARK file monitor ensure minifilter registry instances failed, status=0x%08X.",
            registryStatus);
    }

    status = FltRegisterFilter(
        DriverObject,
        &g_KswordArkFileMonitorRegistration,
        &g_KswordArkFileMonitorRuntime.Filter);
    g_KswordArkFileMonitorRuntime.RegisterStatus = status;
    if (!NT_SUCCESS(status)) {
        g_KswordArkFileMonitorRuntime.Filter = NULL;
        g_KswordArkFileMonitorRuntime.LastErrorStatus = status;
        KswordARKFileMonitorLogFormat(
            "Warn",
            "KswordARK file monitor FltRegisterFilter failed, status=0x%08X, registryStatus=0x%08X.",
            status,
            registryStatus);
        return status;
    }

    g_KswordArkFileMonitorRuntime.RuntimeFlags |= KSWORD_ARK_FILE_MONITOR_RUNTIME_REGISTERED;
    g_KswordArkFileMonitorRuntime.LastErrorStatus = STATUS_SUCCESS;
    KswordARKFileMonitorLog("Info", "KswordARK file monitor minifilter registered.");
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKFileMonitorEnsureFilteringStarted(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    // 两个监控入口共用一次性 FltStartFiltering，控制锁消除并发启动竞态。
    KswordARKAcquirePushLockExclusive(&g_KswordArkFileMonitorRuntime.ControlLock);
    if (g_KswordArkFileMonitorRuntime.Filter == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else if (g_KswordArkFileMonitorRuntime.StartStatus == STATUS_NOT_SUPPORTED) {
        status = FltStartFiltering(g_KswordArkFileMonitorRuntime.Filter);
        g_KswordArkFileMonitorRuntime.StartStatus = status;
    }
    else {
        status = g_KswordArkFileMonitorRuntime.StartStatus;
    }

    // Started 表示 FltMgr 引擎已启动，不再等同于旧文件监控页面是否采集。
    g_KswordArkFileMonitorRuntime.LastErrorStatus = status;
    KswordArkMinifilterCallbackUpdateState(
        g_KswordArkFileMonitorRuntime.Filter,
        g_KswordArkFileMonitorRuntime.RegisterStatus,
        g_KswordArkFileMonitorRuntime.StartStatus,
        NT_SUCCESS(status) ? TRUE : FALSE);
    KswordARKReleasePushLockExclusive(&g_KswordArkFileMonitorRuntime.ControlLock);
    return status;
}

VOID
KswordARKFileMonitorUninitialize(
    VOID
    )
/*++

Routine Description:

    注销 Phase-12 minifilter runtime。中文说明：卸载前先清 STARTED 标志，随后让
    FltUnregisterFilter 等待正在执行的 callback 完成。

Arguments:

    None.

Return Value:

    None.

--*/
{
    g_KswordArkFileMonitorRuntime.RuntimeFlags &= ~KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED;
    KswordArkMinifilterCallbackUpdateState(
        g_KswordArkFileMonitorRuntime.Filter,
        g_KswordArkFileMonitorRuntime.RegisterStatus,
        g_KswordArkFileMonitorRuntime.StartStatus,
        FALSE);

    if (g_KswordArkFileMonitorRuntime.Filter != NULL) {
        FltUnregisterFilter(g_KswordArkFileMonitorRuntime.Filter);
        g_KswordArkFileMonitorRuntime.Filter = NULL;
    }

    g_KswordArkFileMonitorRuntime.RuntimeFlags = 0UL;
    KswordArkMinifilterCallbackUpdateState(NULL, STATUS_NOT_SUPPORTED, STATUS_NOT_SUPPORTED, FALSE);
}

NTSTATUS
KswordARKFileMonitorControl(
    _In_ const KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST* Request
    )
/*++

Routine Description:

    处理 Start/Stop/Clear 控制命令。中文说明：Start 首次调用 FltStartFiltering，
    后续 Start 只更新过滤条件和 STARTED 标志。

Arguments:

    Request - 控制请求。

Return Value:

    STATUS_SUCCESS 或 FltStartFiltering/参数校验失败状态。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Request->action) {
    case KSWORD_ARK_FILE_MONITOR_ACTION_START:
        if (g_KswordArkFileMonitorRuntime.Filter == NULL) {
            g_KswordArkFileMonitorRuntime.LastErrorStatus = STATUS_INVALID_DEVICE_STATE;
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (Request->operationMask != 0UL) {
            g_KswordArkFileMonitorRuntime.OperationMask =
                Request->operationMask & KSWORD_ARK_FILE_MONITOR_OPERATION_ALL;
        }
        if (g_KswordArkFileMonitorRuntime.OperationMask == 0UL) {
            g_KswordArkFileMonitorRuntime.OperationMask = KSWORD_ARK_FILE_MONITOR_OPERATION_ALL;
        }
        g_KswordArkFileMonitorRuntime.ProcessIdFilter = Request->processId;

        status = KswordARKFileMonitorEnsureFilteringStarted();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        g_KswordArkFileMonitorRuntime.RuntimeFlags |= KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED;
        g_KswordArkFileMonitorRuntime.LastErrorStatus = STATUS_SUCCESS;
        KswordArkMinifilterCallbackUpdateState(
            g_KswordArkFileMonitorRuntime.Filter,
            g_KswordArkFileMonitorRuntime.RegisterStatus,
            g_KswordArkFileMonitorRuntime.StartStatus,
            TRUE);
        KswordARKFileMonitorLog("Info", "KswordARK file monitor started.");
        return STATUS_SUCCESS;

    case KSWORD_ARK_FILE_MONITOR_ACTION_STOP:
        g_KswordArkFileMonitorRuntime.RuntimeFlags &= ~KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED;
        KswordArkMinifilterCallbackUpdateState(
            g_KswordArkFileMonitorRuntime.Filter,
            g_KswordArkFileMonitorRuntime.RegisterStatus,
            g_KswordArkFileMonitorRuntime.StartStatus,
            NT_SUCCESS(g_KswordArkFileMonitorRuntime.StartStatus) ? TRUE : FALSE);
        KswordARKFileMonitorLog("Info", "KswordARK file monitor stopped.");
        return STATUS_SUCCESS;

    case KSWORD_ARK_FILE_MONITOR_ACTION_CLEAR:
        KeAcquireSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, &oldIrql);
        g_KswordArkFileMonitorRuntime.HeadIndex = 0UL;
        g_KswordArkFileMonitorRuntime.TailIndex = 0UL;
        g_KswordArkFileMonitorRuntime.QueuedCount = 0UL;
        g_KswordArkFileMonitorRuntime.DroppedCount = 0UL;
        g_KswordArkFileMonitorRuntime.RuntimeFlags &= ~KSWORD_ARK_FILE_MONITOR_RUNTIME_DROPPED;
        /*
         * 中文说明：QueuedCount 是 ring 中事件可见性的唯一依据。清空时只重置
         * 元数据，后续生产者会在重新发布槽位前完整覆盖旧事件。这里禁止在
         * DISPATCH_LEVEL 的自旋锁临界区清零超过 1 MiB 的静态 ring。
         */
        KeReleaseSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, oldIrql);
        return STATUS_SUCCESS;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS
KswordARKFileMonitorQueryStatus(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    返回文件监控运行时状态。中文说明：R3 可据此显示 registered/started、
    queuedCount 和 droppedCount。

Arguments:

    OutputBuffer - 响应缓冲区。
    OutputBufferLength - 响应长度。
    BytesWrittenOut - 接收写入字节数。

Return Value:

    STATUS_SUCCESS 或缓冲区错误。

--*/
{
    KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE* response = NULL;
    KIRQL oldIrql;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_FILE_MONITOR_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->operationMask = g_KswordArkFileMonitorRuntime.OperationMask;
    response->processIdFilter = g_KswordArkFileMonitorRuntime.ProcessIdFilter;
    response->ringCapacity = KSWORD_ARK_FILE_MONITOR_RING_CAPACITY;
    response->sequence = (ULONG64)g_KswordArkFileMonitorRuntime.Sequence;
    response->registerStatus = g_KswordArkFileMonitorRuntime.RegisterStatus;
    response->startStatus = g_KswordArkFileMonitorRuntime.StartStatus;
    response->lastErrorStatus = g_KswordArkFileMonitorRuntime.LastErrorStatus;

    KeAcquireSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, &oldIrql);
    response->runtimeFlags = g_KswordArkFileMonitorRuntime.RuntimeFlags;
    response->queuedCount = g_KswordArkFileMonitorRuntime.QueuedCount;
    response->droppedCount = g_KswordArkFileMonitorRuntime.DroppedCount;
    KeReleaseSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, oldIrql);

    *BytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKFileMonitorDrain(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    从文件监控 ring buffer 取出事件。中文说明：取出即消费，R3 应按 returnedCount
    追加到虚拟化列表；缓冲不足时只返回能容纳的事件。

Arguments:

    OutputBuffer - 响应缓冲区。
    OutputBufferLength - 响应长度。
    Request - 可选请求，限制 maxEvents。
    BytesWrittenOut - 接收实际写入长度。

Return Value:

    STATUS_SUCCESS 或缓冲区错误。

--*/
{
    KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE* response = NULL;
    ULONG maxEvents = 0UL;
    ULONG capacityByBuffer = 0UL;
    ULONG eventsToReturn = 0UL;
    ULONG eventIndex = 0UL;
    KIRQL oldIrql;
    const size_t headerSize =
        sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE) -
        sizeof(KSWORD_ARK_FILE_MONITOR_EVENT);

    if (OutputBuffer == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_FILE_MONITOR_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_FILE_MONITOR_EVENT);
    response->ringCapacity = KSWORD_ARK_FILE_MONITOR_RING_CAPACITY;

    capacityByBuffer = (ULONG)((OutputBufferLength - headerSize) / sizeof(KSWORD_ARK_FILE_MONITOR_EVENT));
    maxEvents = capacityByBuffer;
    if (Request != NULL && Request->maxEvents != 0UL && Request->maxEvents < maxEvents) {
        maxEvents = Request->maxEvents;
    }

    KeAcquireSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, &oldIrql);
    response->totalQueuedBeforeDrain = g_KswordArkFileMonitorRuntime.QueuedCount;
    response->droppedCount = g_KswordArkFileMonitorRuntime.DroppedCount;
    response->runtimeFlags = g_KswordArkFileMonitorRuntime.RuntimeFlags;

    eventsToReturn = g_KswordArkFileMonitorRuntime.QueuedCount;
    if (eventsToReturn > maxEvents) {
        eventsToReturn = maxEvents;
    }
    KeReleaseSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, oldIrql);

    /*
     * 中文说明：每次只在锁内认领并复制一个固定大小事件，随后立即释放锁。
     * 这样生产者不会覆盖正在复制的槽位，同时把原先最长超过 1 MiB 的单次
     * DISPATCH_LEVEL 临界区限制为一个事件。消费后的槽位无需清零；HeadIndex
     * 与 QueuedCount 已使其不可见，生产者重新发布该槽位前会完整覆盖内容。
     */
    for (eventIndex = 0UL; eventIndex < eventsToReturn; ++eventIndex) {
        ULONG slotIndex = 0UL;

        KeAcquireSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, &oldIrql);
        if (g_KswordArkFileMonitorRuntime.QueuedCount == 0UL) {
            KeReleaseSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, oldIrql);
            break;
        }

        slotIndex = g_KswordArkFileMonitorRuntime.HeadIndex;
        RtlCopyMemory(
            &response->events[eventIndex],
            &g_KswordArkFileMonitorRuntime.Ring[slotIndex],
            sizeof(KSWORD_ARK_FILE_MONITOR_EVENT));
        g_KswordArkFileMonitorRuntime.HeadIndex =
            KswordARKFileMonitorAdvanceIndex(g_KswordArkFileMonitorRuntime.HeadIndex);
        g_KswordArkFileMonitorRuntime.QueuedCount -= 1UL;
        KeReleaseSpinLock(&g_KswordArkFileMonitorRuntime.RingLock, oldIrql);
    }

    response->returnedCount = eventIndex;

    *BytesWrittenOut = headerSize + ((size_t)eventIndex * sizeof(KSWORD_ARK_FILE_MONITOR_EVENT));
    return STATUS_SUCCESS;
}
