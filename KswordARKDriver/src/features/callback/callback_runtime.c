/*++

Module Name:

    callback_runtime.c

Abstract:

    Callback interception runtime bootstrap and IOCTL entry wrappers.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_push_lock.h"
#include "ark/ark_startup.h"

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTSYSAPI
ULONG
NTAPI
PsGetProcessSessionId(
    _In_ PEPROCESS Process
    );

typedef PVOID
(NTAPI* KSWORD_ARK_EX_ALLOCATE_POOL2)(
    _In_ POOL_FLAGS Flags,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

static EX_PUSH_LOCK g_KswordArkCallbackRuntimeLock;
static KSWORD_ARK_CALLBACK_RUNTIME* g_KswordArkCallbackRuntime = NULL;
static KSWORD_ARK_EX_ALLOCATE_POOL2 g_KswordArkExAllocatePool2 = NULL;
static volatile LONG g_KswordArkPoolAllocatorResolved = 0;

KSWORD_ARK_CALLBACK_RUNTIME*
KswordArkCallbackGetRuntime(
    VOID
    )
{
    return g_KswordArkCallbackRuntime;
}

PVOID
KswordArkAllocateNonPaged(
    _In_ SIZE_T bytes,
    _In_ ULONG poolTag
    )
{
    if (bytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&g_KswordArkPoolAllocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        g_KswordArkExAllocatePool2 =
            (KSWORD_ARK_EX_ALLOCATE_POOL2)MmGetSystemRoutineAddress(&routineName);
    }

    if (g_KswordArkExAllocatePool2 != NULL) {
        return g_KswordArkExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, poolTag);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPool, bytes, poolTag);
#pragma warning(pop)
}

VOID
KswordArkCallbackLogFrameForRuntime(
    _In_opt_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    )
{
    // 调用方在初始化阶段持有正在构建的 runtime，此时全局发布尚未发生。
    if (runtime == NULL || runtime->Device == WDF_NO_HANDLE) {
        return;
    }

    (VOID)KswordARKDriverEnqueueLogFrame(
        runtime->Device,
        levelText != NULL ? levelText : "Info",
        messageText != NULL ? messageText : "");
}

VOID
KswordArkCallbackLogFormatForRuntime(
    _In_opt_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list argList;

    if (formatText == NULL) {
        KswordArkCallbackLogFrameForRuntime(runtime, levelText, "");
        return;
    }

    va_start(argList, formatText);
    (VOID)RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, argList);
    va_end(argList);

    KswordArkCallbackLogFrameForRuntime(runtime, levelText, logBuffer);
}

VOID
KswordArkCallbackLogFrame(
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    )
{
    // 稳态路径继续使用全局 runtime；启动期调用方必须改用 ForRuntime 版本。
    KswordArkCallbackLogFrameForRuntime(KswordArkCallbackGetRuntime(), levelText, messageText);
}

VOID
KswordArkCallbackLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list argList;

    if (formatText == NULL) {
        KswordArkCallbackLogFrame(levelText, "");
        return;
    }

    va_start(argList, formatText);
    (VOID)RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, argList);
    va_end(argList);

    KswordArkCallbackLogFrame(levelText, logBuffer);
}

VOID
KswordArkGetSystemTimeUtc100ns(
    _Out_ LARGE_INTEGER* utcOut
    )
{
    if (utcOut == NULL) {
        return;
    }
    KeQuerySystemTimePrecise(utcOut);
}

VOID
KswordArkCopyUnicodeToFixedBuffer(
    _In_opt_ PCUNICODE_STRING sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    )
{
    USHORT sourceChars = 0;
    USHORT copyChars = 0;

    if (destinationBuffer == NULL || destinationChars == 0U) {
        return;
    }

    destinationBuffer[0] = L'\0';
    if (sourceText == NULL || sourceText->Buffer == NULL || sourceText->Length == 0U) {
        return;
    }

    sourceChars = (USHORT)(sourceText->Length / sizeof(WCHAR));
    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = (USHORT)(destinationChars - 1U);
    }

    if (copyChars > 0U) {
        RtlCopyMemory(destinationBuffer, sourceText->Buffer, copyChars * sizeof(WCHAR));
    }
    destinationBuffer[copyChars] = L'\0';
}

VOID
KswordArkCopyWideStringToFixedBuffer(
    _In_opt_z_ PCWSTR sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    )
{
    size_t sourceChars = 0;
    size_t copyChars = 0;

    if (destinationBuffer == NULL || destinationChars == 0U) {
        return;
    }

    destinationBuffer[0] = L'\0';
    if (sourceText == NULL) {
        return;
    }

    if (!NT_SUCCESS(RtlStringCchLengthW(sourceText, destinationChars, &sourceChars))) {
        sourceChars = destinationChars - 1U;
    }

    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1U;
    }

    if (copyChars > 0U) {
        RtlCopyMemory(destinationBuffer, sourceText, copyChars * sizeof(WCHAR));
    }
    destinationBuffer[copyChars] = L'\0';
}

BOOLEAN
KswordArkResolveProcessImagePath(
    _In_opt_ PEPROCESS processObject,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars,
    _Out_opt_ BOOLEAN* pathUnavailableOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNICODE_STRING imagePath = NULL;
    BOOLEAN localUnavailable = TRUE;
    PEPROCESS targetProcess = processObject;

    if (destinationBuffer == NULL || destinationChars == 0U) {
        return FALSE;
    }

    destinationBuffer[0] = L'\0';
    if (targetProcess == NULL) {
        targetProcess = PsGetCurrentProcess();
    }

    status = SeLocateProcessImageName(targetProcess, &imagePath);
    if (NT_SUCCESS(status) && imagePath != NULL && imagePath->Buffer != NULL && imagePath->Length > 0U) {
        KswordArkCopyUnicodeToFixedBuffer(imagePath, destinationBuffer, destinationChars);
        ExFreePool(imagePath);
        localUnavailable = FALSE;
    }
    else {
        PCHAR shortImageName = PsGetProcessImageFileName(targetProcess);
        if (shortImageName != NULL && shortImageName[0] != '\0') {
            (VOID)RtlStringCbPrintfW(destinationBuffer, destinationChars * sizeof(WCHAR), L"%S", shortImageName);
            localUnavailable = TRUE;
        }
    }

    if (pathUnavailableOut != NULL) {
        *pathUnavailableOut = localUnavailable;
    }
    return (destinationBuffer[0] != L'\0') ? TRUE : FALSE;
}

ULONG
KswordArkGetProcessSessionIdSafe(
    _In_opt_ PEPROCESS processObject
    )
{
    PEPROCESS targetProcess = processObject;
    if (targetProcess == NULL) {
        targetProcess = PsGetCurrentProcess();
    }
    return PsGetProcessSessionId(targetProcess);
}

BOOLEAN
KswordArkGuidEquals(
    _In_ const KSWORD_ARK_GUID128* leftGuid,
    _In_ const KSWORD_ARK_GUID128* rightGuid
    )
{
    if (leftGuid == NULL || rightGuid == NULL) {
        return FALSE;
    }

    return (RtlCompareMemory(leftGuid->bytes, rightGuid->bytes, sizeof(leftGuid->bytes)) ==
        sizeof(leftGuid->bytes))
        ? TRUE
        : FALSE;
}

VOID
KswordArkGuidGenerate(
    _Out_ KSWORD_ARK_GUID128* guidOut
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    LARGE_INTEGER nowUtc = { 0 };
    ULONGLONG sequenceValue = 0;
    ULONG pidValue = HandleToULong(PsGetCurrentProcessId());
    ULONG tidValue = HandleToULong(PsGetCurrentThreadId());

    if (guidOut == NULL) {
        return;
    }

    KswordArkGetSystemTimeUtc100ns(&nowUtc);
    if (runtime != NULL) {
        sequenceValue = (ULONGLONG)InterlockedIncrement64(&runtime->EventSequence);
    }

    RtlZeroMemory(guidOut, sizeof(*guidOut));
    RtlCopyMemory(&guidOut->bytes[0], &nowUtc.QuadPart, sizeof(nowUtc.QuadPart));
    RtlCopyMemory(&guidOut->bytes[8], &sequenceValue, sizeof(sequenceValue));
    guidOut->bytes[0] ^= (UCHAR)(pidValue & 0xFFU);
    guidOut->bytes[1] ^= (UCHAR)((pidValue >> 8) & 0xFFU);
    guidOut->bytes[2] ^= (UCHAR)(tidValue & 0xFFU);
    guidOut->bytes[3] ^= (UCHAR)((tidValue >> 8) & 0xFFU);
}

static VOID
KswordArkCallbackDestroyRuntime(
    _In_opt_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    )
{
    KSWORD_ARK_CALLBACK_RULE_SNAPSHOT* oldSnapshot = NULL;

    if (runtime == NULL) {
        return;
    }

    // 先封闭新的 AskUser 等待项，再唤醒已有等待者，防止注销回调时等待线程阻塞卸载。
    (VOID)InterlockedExchange(&runtime->Stopping, 1L);
    // 同步关闭只读遥测，后续回调即使仍在注销窗口内执行也不会再写 ring。
    (VOID)InterlockedExchange(&runtime->MonitorCategoryMask, 0L);
    (VOID)KswordArkCallbackCancelAllPendingForRuntime(runtime);
    KswordArkMinifilterCallbackUnregister(runtime);
    // 只反注册真正注册成功的回调；降级启动时未注册的项必须原样跳过，
    // 否则会对内核发出一次注定失败的注销调用。
    if ((runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_OBJECT) != 0U) {
        KswordArkObjectCallbackUnregister(runtime);
    }
    if ((runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_IMAGE) != 0U) {
        KswordArkImageCallbackUnregister(runtime);
    }
    if ((runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_THREAD) != 0U) {
        KswordArkThreadCallbackUnregister(runtime);
    }
    if ((runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_PROCESS) != 0U) {
        KswordArkProcessCallbackUnregister(runtime);
    }
    if ((runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY) != 0U) {
        KswordArkRegistryCallbackUnregister(runtime);
    }
    KswordArkCallbackWaiterUninitialize(runtime);

    KswordARKAcquirePushLockExclusive(&runtime->SnapshotLock);
    oldSnapshot = runtime->ActiveSnapshot;
    runtime->ActiveSnapshot = NULL;
    KswordARKReleasePushLockExclusive(&runtime->SnapshotLock);

    if (oldSnapshot != NULL) {
        ExWaitForRundownProtectionRelease(&oldSnapshot->RundownRef);
        KswordArkCallbackFreeSnapshot(oldSnapshot);
    }

    ExFreePoolWithTag(runtime, KSWORD_ARK_CALLBACK_TAG_RUNTIME);
}

static NTSTATUS
KswordArkCallbackRegisterOne(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_ ULONG capabilityBit,
    _In_z_ PCSTR capabilityName,
    _In_ NTSTATUS registerStatus
    )
/*++

Routine Description:

    Fold one callback registration result into the runtime. Success sets the
    capability bit; failure only records the raw NTSTATUS and leaves the bit
    clear, so a single unavailable kernel callback can no longer take the whole
    driver down with it.

Arguments:

    runtime - Runtime being built. It is not published yet.
    capabilityBit - KSWORD_ARK_CALLBACK_REGISTERED_* bit for this callback.
    capabilityName - Short name used in the R3-visible log line.
    registerStatus - Raw NTSTATUS returned by the registration API.

Return Value:

    The registerStatus argument, unmodified.

--*/
{
    if (NT_SUCCESS(registerStatus)) {
        runtime->RegisteredCallbacksMask |= capabilityBit;
        return registerStatus;
    }

    // 常见原因：altitude 冲突、回调槽位已满、资源不足或重复注册。
    KswordArkCallbackLogFormatForRuntime(
        runtime,
        "Warn",
        "%s callback unavailable, status=0x%08lX. Driver continues without this capability.",
        capabilityName,
        (unsigned long)registerStatus);
    return registerStatus;
}

ULONG
KswordARKCallbackGetRegisteredMask(
    VOID
    )
/*++

Routine Description:

    Report which callback capabilities are currently registered. DriverEntry
    persists this into the startup breadcrumb so a degraded start is visible
    without querying the driver.

Arguments:

    None.

Return Value:

    KSWORD_ARK_CALLBACK_REGISTERED_* bitmask, or zero when no runtime exists.

--*/
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    return (runtime != NULL) ? runtime->RegisteredCallbacksMask : 0UL;
}

NTSTATUS
KswordARKCallbackInitialize(
    _In_ WDFDEVICE Device
    )
/*++

Routine Description:

    Build and publish the callback runtime. Every kernel callback here is an
    optional capability: registration failures are recorded and the affected
    feature is disabled, but the runtime is still published so the rest of the
    driver keeps working.

Arguments:

    Device - Control device that owns the runtime and its log channel.

Return Value:

    STATUS_SUCCESS when every callback registered. The first registration
    failure otherwise, purely as a diagnostic signal — the caller must treat a
    failure status as "degraded", not as a reason to fail the load.

--*/
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = NULL;
    NTSTATUS firstFailureStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    if (Device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    KswordARKAcquirePushLockExclusive(&g_KswordArkCallbackRuntimeLock);
    if (g_KswordArkCallbackRuntime != NULL) {
        KswordARKReleasePushLockExclusive(&g_KswordArkCallbackRuntimeLock);
        return STATUS_SUCCESS;
    }

    KswordArkStartupStage(KswordArkStartStageCallbackRuntimeAllocate);
    runtime = (KSWORD_ARK_CALLBACK_RUNTIME*)KswordArkAllocateNonPaged(
        sizeof(KSWORD_ARK_CALLBACK_RUNTIME),
        KSWORD_ARK_CALLBACK_TAG_RUNTIME);
    if (runtime == NULL) {
        KswordARKReleasePushLockExclusive(&g_KswordArkCallbackRuntimeLock);
        // 运行时分配失败同样只关闭回调模块；核心驱动仍然继续加载。
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(runtime, sizeof(*runtime));
    runtime->Device = Device;
    runtime->WaitQueue = WDF_NO_HANDLE;
    runtime->ObRegistrationHandle = NULL;
    runtime->MiniFilterHandle = NULL;
    runtime->MiniFilterStarted = FALSE;
    runtime->MiniFilterRegisterStatus = STATUS_NOT_SUPPORTED;
    runtime->MiniFilterStartStatus = STATUS_NOT_SUPPORTED;
    runtime->MiniFilterBypassPidCount = 0U;
    RtlZeroMemory(runtime->MiniFilterBypassPids, sizeof(runtime->MiniFilterBypassPids));
    runtime->RegisteredCallbacksMask = 0U;
    runtime->MonitorWriterLock = 0L;
    runtime->MonitorCategoryMask = 0L;
    runtime->MonitorLatestSequence = 0LL;
    runtime->MonitorDroppedCount = 0LL;
    runtime->MonitorLastStatus = STATUS_SUCCESS;
    runtime->Initialized = FALSE;
    // 发布前显式声明运行时可接收等待项；销毁路径会以原子方式切换到停止状态。
    runtime->Stopping = 0L;
    ExInitializePushLock(&runtime->SnapshotLock);
    ExInitializePushLock(&runtime->PendingLock);
    ExInitializePushLock(&runtime->MiniFilterBypassPidLock);
    InitializeListHead(&runtime->PendingDecisionList);

    // AskUser 等待队列失败只关闭"询问用户"能力，其余回调照常注册。
    KswordArkStartupStage(KswordArkStartStageCallbackWaitQueue);
    status = KswordArkCallbackWaiterInitialize(runtime);
    runtime->WaitQueueStatus = status;
    if (!NT_SUCCESS(status)) {
        KswordArkCallbackLogFormatForRuntime(
            runtime,
            "Warn",
            "AskUser wait queue unavailable, status=0x%08lX. Ask rules fall back to their default decision.",
            (unsigned long)status);
        firstFailureStatus = status;
    }

    // 注册表回调使用固定 altitude 385201.5141，同 altitude 的另一实例会让它
    // 返回 STATUS_FLT_INSTANCE_ALTITUDE_COLLISION。
    KswordArkStartupStage(KswordArkStartStageRegistryCallback);
    runtime->RegistryRegisterStatus = KswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY,
        "Registry",
        KswordArkRegistryCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->RegistryRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->RegistryRegisterStatus;
    }

    // 进程创建回调在重复注册或系统回调数量达上限时返回 STATUS_INVALID_PARAMETER。
    KswordArkStartupStage(KswordArkStartStageProcessCallback);
    runtime->ProcessRegisterStatus = KswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_PROCESS,
        "Process",
        KswordArkProcessCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->ProcessRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->ProcessRegisterStatus;
    }

    KswordArkStartupStage(KswordArkStartStageThreadCallback);
    runtime->ThreadRegisterStatus = KswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_THREAD,
        "Thread",
        KswordArkThreadCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->ThreadRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->ThreadRegisterStatus;
    }

    // 映像加载回调全系统最多 64 个；装有多套 EDR/反作弊的机器会先耗尽槽位。
    KswordArkStartupStage(KswordArkStartStageImageCallback);
    runtime->ImageRegisterStatus = KswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_IMAGE,
        "Image",
        KswordArkImageCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->ImageRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->ImageRegisterStatus;
    }

    // 对象回调使用固定 altitude 385201.5142，冲突、资源不足和参数错误
    // 现在与 STATUS_ACCESS_DENIED 一样只降级，不再区别对待。
    KswordArkStartupStage(KswordArkStartStageObjectCallback);
    runtime->ObjectRegisterStatus = KswordArkCallbackRegisterOne(
        runtime,
        KSWORD_ARK_CALLBACK_REGISTERED_OBJECT,
        "Object",
        KswordArkObjectCallbackRegister(runtime));
    if (!NT_SUCCESS(runtime->ObjectRegisterStatus) && NT_SUCCESS(firstFailureStatus)) {
        firstFailureStatus = runtime->ObjectRegisterStatus;
    }

    runtime->Initialized = TRUE;
    g_KswordArkCallbackRuntime = runtime;
    KswordARKReleasePushLockExclusive(&g_KswordArkCallbackRuntimeLock);

    KswordArkCallbackLogFormat(
        "Info",
        "Callback runtime initialized, registeredMask=0x%08lX, firstFailure=0x%08lX.",
        (unsigned long)runtime->RegisteredCallbacksMask,
        (unsigned long)firstFailureStatus);
    return firstFailureStatus;
}

VOID
KswordARKCallbackUninitialize(
    VOID
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = NULL;

    KswordARKAcquirePushLockExclusive(&g_KswordArkCallbackRuntimeLock);
    runtime = g_KswordArkCallbackRuntime;
    // 先撤销全局发布以拒绝新的外部查找；销毁路径改用显式 runtime 指针取消等待项。
    g_KswordArkCallbackRuntime = NULL;
    KswordARKReleasePushLockExclusive(&g_KswordArkCallbackRuntimeLock);

    if (runtime != NULL) {
        KswordArkCallbackDestroyRuntime(runtime);
    }
}

NTSTATUS
KswordArkCallbackSetMinifilterBypassPids(
    _In_reads_opt_(PidCount) const ULONG* ProcessIds,
    _In_ ULONG PidCount
    )
/*++

Routine Description:

    Replace the in-memory minifilter bypass PID list used by the hot-path
    pre-operation callback. PID zero is ignored because it is not a user-mode
    process identity that should be allowlisted from the UI.

Arguments:

    ProcessIds - Optional caller-owned PID array. It may be NULL only when
        PidCount is zero.
    PidCount - Number of input PID slots to inspect.

Return Value:

    STATUS_SUCCESS when the runtime list has been replaced. An NTSTATUS error
    is returned for invalid packet shape, over-limit counts or missing runtime.

--*/
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    ULONG uniquePids[KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT];
    ULONG readIndex = 0UL;
    ULONG scanIndex = 0UL;
    ULONG writeIndex = 0UL;

    if (PidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PidCount != 0UL && ProcessIds == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (runtime == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(uniquePids, sizeof(uniquePids));
    for (readIndex = 0UL; readIndex < PidCount; ++readIndex) {
        BOOLEAN duplicatePid = FALSE;
        ULONG candidatePid = ProcessIds[readIndex];

        if (candidatePid == 0UL) {
            continue;
        }

        for (scanIndex = 0UL; scanIndex < writeIndex; ++scanIndex) {
            if (uniquePids[scanIndex] == candidatePid) {
                duplicatePid = TRUE;
                break;
            }
        }

        if (!duplicatePid && writeIndex < KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
            uniquePids[writeIndex] = candidatePid;
            ++writeIndex;
        }
    }

    KswordARKAcquirePushLockExclusive(&runtime->MiniFilterBypassPidLock);
    RtlZeroMemory(runtime->MiniFilterBypassPids, sizeof(runtime->MiniFilterBypassPids));
    if (writeIndex != 0UL) {
        RtlCopyMemory(runtime->MiniFilterBypassPids, uniquePids, (SIZE_T)writeIndex * sizeof(ULONG));
    }
    runtime->MiniFilterBypassPidCount = writeIndex;
    KswordARKReleasePushLockExclusive(&runtime->MiniFilterBypassPidLock);

    KswordArkCallbackLogFormat(
        "Info",
        "Minifilter bypass PID whitelist updated, count=%lu.",
        (unsigned long)writeIndex);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordArkCallbackQueryMinifilterBypassPids(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Copy the current minifilter bypass PID list into the shared R3/R0 response
    structure. The copy is protected by the runtime push lock so user mode sees
    one consistent snapshot.

Arguments:

    OutputBuffer - Caller output buffer that receives the fixed response packet.
    OutputBufferLength - Output buffer size supplied by WDF.
    BytesWrittenOut - Receives sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE).

Return Value:

    STATUS_SUCCESS when the response packet was written; otherwise an NTSTATUS
    validation or runtime availability error.

--*/
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE* response = NULL;
    ULONG pidCount = 0UL;

    if (BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;

    if (OutputBuffer == NULL ||
        OutputBufferLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (runtime == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    response = (KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE*)OutputBuffer;
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;

    KswordARKAcquirePushLockShared(&runtime->MiniFilterBypassPidLock);
    pidCount = runtime->MiniFilterBypassPidCount;
    if (pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        pidCount = KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT;
    }
    response->pidCount = pidCount;
    if (pidCount != 0UL) {
        RtlCopyMemory(response->processIds, runtime->MiniFilterBypassPids, (SIZE_T)pidCount * sizeof(ULONG));
    }
    KswordARKReleasePushLockShared(&runtime->MiniFilterBypassPidLock);

    *BytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

BOOLEAN
KswordArkCallbackIsMinifilterBypassPid(
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Check whether a requestor PID is present in the minifilter bypass whitelist.
    The minifilter calls this before callback rules, redirect rewriting and file
    monitor capture so allowlisted requests pass through to the filesystem stack.

Arguments:

    ProcessId - Requestor process identifier from FltGetRequestorProcessId.

Return Value:

    TRUE when ProcessId is allowlisted; FALSE otherwise.

--*/
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    ULONG pidIndex = 0UL;
    ULONG pidCount = 0UL;
    BOOLEAN matchedPid = FALSE;

    if (ProcessId == 0UL || runtime == NULL) {
        return FALSE;
    }

    KswordARKAcquirePushLockShared(&runtime->MiniFilterBypassPidLock);
    pidCount = runtime->MiniFilterBypassPidCount;
    if (pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        pidCount = KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT;
    }
    for (pidIndex = 0UL; pidIndex < pidCount; ++pidIndex) {
        if (runtime->MiniFilterBypassPids[pidIndex] == ProcessId) {
            matchedPid = TRUE;
            break;
        }
    }
    KswordARKReleasePushLockShared(&runtime->MiniFilterBypassPidLock);

    return matchedPid;
}

NTSTATUS
KswordARKCallbackIoctlSetRules(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    KSWORD_ARK_CALLBACK_RULE_SNAPSHOT* snapshot = NULL;
    PVOID inputBuffer = NULL;
    size_t inputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (InputBufferLength < sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = KswordArkCallbackBuildSnapshotFromBlob(inputBuffer, inputLength, &snapshot);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordArkCallbackSwapSnapshot(snapshot);
    if (!NT_SUCCESS(status)) {
        KswordArkCallbackFreeSnapshot(snapshot);
        return status;
    }

    *CompleteBytesOut = inputLength;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKCallbackIoctlGetRuntimeState(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME_STATE* stateBuffer = NULL;
    size_t stateBufferLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CALLBACK_RUNTIME_STATE),
        (PVOID*)&stateBuffer,
        &stateBufferLength);
    if (!NT_SUCCESS(status)) {
        UNREFERENCED_PARAMETER(OutputBufferLength);
        return status;
    }

    KswordArkCallbackQueryRuntimeState(stateBuffer);
    *CompleteBytesOut = sizeof(KSWORD_ARK_CALLBACK_RUNTIME_STATE);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKCallbackIoctlSetMinifilterBypassPids(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
/*++

Routine Description:

    Validate the R3 minifilter bypass PID packet and replace the runtime PID
    whitelist. The actual storage update is delegated to the callback runtime
    helper so dispatch remains thin.

Arguments:

    Request - WDF request that carries KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST.
    InputBufferLength - Caller supplied input buffer length.
    CompleteBytesOut - Receives the consumed input byte count on success.

Return Value:

    STATUS_SUCCESS when the whitelist is updated; otherwise an NTSTATUS
    validation or WDF buffer retrieval error.

--*/
{
    KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST* requestPacket = NULL;
    PVOID inputBuffer = NULL;
    size_t inputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (InputBufferLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    requestPacket = (KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST*)inputBuffer;
    if (requestPacket->size < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST) ||
        requestPacket->version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION ||
        requestPacket->pidCount > KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordArkCallbackSetMinifilterBypassPids(
        requestPacket->processIds,
        requestPacket->pidCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *CompleteBytesOut = sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_REQUEST);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKCallbackIoctlQueryMinifilterBypassPids(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
/*++

Routine Description:

    Retrieve the caller output buffer and return the current minifilter bypass
    PID whitelist as one fixed shared-protocol response packet.

Arguments:

    Request - WDF request that owns the output buffer.
    OutputBufferLength - Caller supplied output buffer length.
    CompleteBytesOut - Receives the response byte count on success.

Return Value:

    STATUS_SUCCESS when the response is filled; otherwise an NTSTATUS
    validation or WDF buffer retrieval error.

--*/
{
    KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE* responsePacket = NULL;
    size_t outputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (OutputBufferLength < sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE),
        (PVOID*)&responsePacket,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return KswordArkCallbackQueryMinifilterBypassPids(
        responsePacket,
        outputLength,
        CompleteBytesOut);
}

NTSTATUS
KswordARKCallbackIoctlWaitEvent(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    return KswordArkCallbackIoctlWaitEventInternal(
        Request,
        OutputBufferLength,
        CompleteBytesOut);
}

NTSTATUS
KswordARKCallbackIoctlAnswerEvent(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
{
    return KswordArkCallbackIoctlAnswerEventInternal(
        Request,
        InputBufferLength,
        CompleteBytesOut);
}

NTSTATUS
KswordARKCallbackIoctlCancelAllPending(
    _Out_ size_t* CompleteBytesOut
    )
{
    NTSTATUS status = KswordArkCallbackCancelAllPendingInternal();
    if (CompleteBytesOut != NULL) {
        *CompleteBytesOut = 0U;
    }
    return status;
}
