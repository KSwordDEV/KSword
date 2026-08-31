/*++

Module Name:

    callback_monitor.c

Abstract:

    Non-blocking structured telemetry ring for kernel callback events.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "../file_monitor/file_monitor_internal.h"

C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST) == 24U);
C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE) == 56U);
C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT) == 1264U);
C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST) == 24U);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records) == 72U);

#define KSWORD_ARK_CALLBACK_MONITOR_CONTROL_SPIN_LIMIT 65536UL

static BOOLEAN
KswordArkCallbackMonitorTryAcquireWriterLockBounded(
    _Inout_ KSWORD_ARK_CALLBACK_RUNTIME* Runtime
    )
{
    ULONG spinIndex = 0UL;

    // 控制 IOCTL 允许等待正在提交的短记录，但必须有界，避免单核或优先级反转时无限占用 CPU。
    for (spinIndex = 0UL;
         spinIndex < KSWORD_ARK_CALLBACK_MONITOR_CONTROL_SPIN_LIMIT;
         ++spinIndex) {
        if (InterlockedCompareExchange(&Runtime->MonitorWriterLock, 1L, 0L) == 0L) {
            return TRUE;
        }
        YieldProcessor();
    }
    return FALSE;
}

static ULONG
KswordArkCallbackMonitorRegisteredMask(
    _In_ const KSWORD_ARK_CALLBACK_RUNTIME* Runtime
    )
{
    ULONG categoryMask = 0UL;

    // 每一位都只反映对应系统回调是否实际注册成功。
    if ((Runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_PROCESS) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
    }
    if ((Runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_THREAD) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    }
    if ((Runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_IMAGE) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
    }
    if ((Runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY;
    }
    if ((Runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_OBJECT) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
    }
    if ((Runtime->RegisteredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
    }
    return categoryMask;
}

static VOID
KswordArkCallbackMonitorCopyUnicode(
    _In_opt_ PCUNICODE_STRING Source,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_ ULONG PresentFlag,
    _In_ ULONG TruncatedFlag,
    _Inout_ ULONG* EventFlags
    )
{
    ULONG sourceChars = 0UL;
    ULONG copyChars = 0UL;

    // 输出缓冲无论成功与否都保持 NUL 结尾。
    if (Destination == NULL || DestinationChars == 0UL || EventFlags == NULL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return;
    }

    // UNICODE_STRING 长度以字节表示，协议缓冲区长度以 WCHAR 表示。
    sourceChars = (ULONG)(Source->Length / sizeof(WCHAR));
    copyChars = min(sourceChars, DestinationChars - 1UL);
    if (copyChars != 0UL) {
        RtlCopyMemory(Destination, Source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    }
    Destination[copyChars] = L'\0';
    *EventFlags |= PresentFlag;
    if (copyChars < sourceChars) {
        *EventFlags |= TruncatedFlag;
    }
}

static VOID
KswordArkCallbackMonitorFillStatus(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* Runtime,
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* Response
    )
{
    ULONG categoryMask = 0UL;
    ULONGLONG latestSequence = 0ULL;
    ULONGLONG droppedCount = 0ULL;

    // 固定头字段允许 R3 在后续协议扩展时安全判断响应版本。
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->ringCapacity = KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY;
    Response->registeredCategoryMask = KswordArkCallbackMonitorRegisteredMask(Runtime);

    // 原子读取热路径状态，避免查询 IOCTL 获取任何会阻塞回调的锁。
    categoryMask = (ULONG)InterlockedCompareExchange(&Runtime->MonitorCategoryMask, 0L, 0L);
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &Runtime->MonitorLatestSequence,
        0LL,
        0LL);
    droppedCount = (ULONGLONG)InterlockedCompareExchange64(
        &Runtime->MonitorDroppedCount,
        0LL,
        0LL);
    Response->categoryMask = categoryMask;
    Response->latestSequence = latestSequence;
    Response->droppedCount = droppedCount;
    Response->queuedCount = (ULONG)min(
        latestSequence,
        (ULONGLONG)KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY);
    Response->lastStatus = Runtime->MonitorLastStatus;
    Response->minifilterStartStatus = Runtime->MiniFilterStartStatus;
    if (categoryMask != 0UL) {
        Response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING;
    }
    if (droppedCount != 0ULL) {
        Response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_DROPPED;
    }
    if (InterlockedCompareExchange(&Runtime->Stopping, 0L, 0L) != 0L) {
        Response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_STOPPING;
    }
}

BOOLEAN
KswordArkCallbackMonitorIsEnabled(
    _In_ ULONG Category
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    ULONG categoryMask = 0UL;

    // 未发布或正在卸载的 runtime 不允许产生新的遥测记录。
    if (runtime == NULL || InterlockedCompareExchange(&runtime->Stopping, 0L, 0L) != 0L) {
        return FALSE;
    }
    categoryMask = (ULONG)InterlockedCompareExchange(&runtime->MonitorCategoryMask, 0L, 0L);
    return ((categoryMask & Category) != 0UL) ? TRUE : FALSE;
}

VOID
KswordArkCallbackMonitorPublish(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_EVENT_INPUT* EventInput
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    KSWORD_ARK_CALLBACK_MONITOR_SLOT* slot = NULL;
    KSWORD_ARK_CALLBACK_MONITOR_EVENT* eventRecord = NULL;
    ULONGLONG latestSequence = 0ULL;
    ULONGLONG sequence = 0ULL;
    ULONG categoryMask = 0UL;
    ULONG slotIndex = 0UL;

    // 先以无锁方式拒绝关闭类别，避免进入 try-lock 和字符串复制。
    if (runtime == NULL || EventInput == NULL) {
        return;
    }
    categoryMask = (ULONG)InterlockedCompareExchange(&runtime->MonitorCategoryMask, 0L, 0L);
    if ((categoryMask & EventInput->Category) == 0UL ||
        InterlockedCompareExchange(&runtime->Stopping, 0L, 0L) != 0L) {
        return;
    }

    // 系统回调不能等待；并发发布争用时只增加丢弃计数。
    if (InterlockedCompareExchange(&runtime->MonitorWriterLock, 1L, 0L) != 0L) {
        (VOID)InterlockedIncrement64(&runtime->MonitorDroppedCount);
        return;
    }

    // 取得写锁后再次检查控制位，防止 STOP 与回调并行时提交新记录。
    categoryMask = (ULONG)InterlockedCompareExchange(&runtime->MonitorCategoryMask, 0L, 0L);
    if ((categoryMask & EventInput->Category) == 0UL ||
        InterlockedCompareExchange(&runtime->Stopping, 0L, 0L) != 0L) {
        (VOID)InterlockedExchange(&runtime->MonitorWriterLock, 0L);
        return;
    }

    // 单调序号零保留给空 ring，槽位由序号稳定映射。
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->MonitorLatestSequence,
        0LL,
        0LL);
    sequence = latestSequence + 1ULL;
    slotIndex = (ULONG)((sequence - 1ULL) % KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY);
    slot = &runtime->MonitorSlots[slotIndex];
    eventRecord = &slot->Event;

    // 负提交序号表示该槽正在更新，读取端不会复制半条事件。
    (VOID)InterlockedExchange64(&slot->CommitSequence, -((LONG64)sequence));
    RtlZeroMemory(eventRecord, sizeof(*eventRecord));
    eventRecord->version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    eventRecord->size = sizeof(*eventRecord);
    eventRecord->sequence = sequence;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&eventRecord->timeUtc100ns);
    eventRecord->category = EventInput->Category;
    eventRecord->operation = EventInput->Operation;
    eventRecord->flags = EventInput->Flags;
    eventRecord->resultStatus = EventInput->ResultStatus;
    eventRecord->originatingProcessId = EventInput->OriginatingProcessId;
    eventRecord->originatingThreadId = EventInput->OriginatingThreadId;
    eventRecord->targetProcessId = EventInput->TargetProcessId;
    eventRecord->targetThreadId = EventInput->TargetThreadId;
    eventRecord->parentProcessId = EventInput->ParentProcessId;
    eventRecord->sessionId = EventInput->SessionId;
    eventRecord->originalAccess = EventInput->OriginalAccess;
    eventRecord->desiredAccess = EventInput->DesiredAccess;
    eventRecord->objectType = EventInput->ObjectType;
    eventRecord->detailCode = EventInput->DetailCode;
    eventRecord->address = EventInput->Address;
    eventRecord->regionSize = EventInput->RegionSize;
    if (eventRecord->originatingProcessId <= 4UL) {
        eventRecord->flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_SYSTEM_PROCESS;
    }
    KswordArkCallbackMonitorCopyUnicode(
        EventInput->ProcessName,
        eventRecord->processName,
        RTL_NUMBER_OF(eventRecord->processName),
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_PRESENT,
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_TRUNCATED,
        &eventRecord->flags);
    KswordArkCallbackMonitorCopyUnicode(
        EventInput->Path,
        eventRecord->path,
        RTL_NUMBER_OF(eventRecord->path),
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_PRESENT,
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_TRUNCATED,
        &eventRecord->flags);

    // 先发布完整记录，再发布槽提交序号和 ring 最新序号。
    KeMemoryBarrier();
    (VOID)InterlockedExchange64(&slot->CommitSequence, (LONG64)sequence);
    (VOID)InterlockedExchange64(&runtime->MonitorLatestSequence, (LONG64)sequence);
    (VOID)InterlockedExchange(&runtime->MonitorWriterLock, 0L);
}

NTSTATUS
KswordArkCallbackMonitorControl(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST* Request,
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* Response
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    ULONG requestedMask = 0UL;
    LONG previousMask = 0L;
    BOOLEAN writerLockHeld = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    // 所有控制响应都返回完整状态，便于 R3 解释失败原因。
    if (runtime == NULL || Request == NULL || Response == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Request->version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
        Request->size < sizeof(*Request)) {
        runtime->MonitorLastStatus = STATUS_REVISION_MISMATCH;
        KswordArkCallbackMonitorFillStatus(runtime, Response);
        return STATUS_REVISION_MISMATCH;
    }

    // START 只接受共享协议声明的六类类别位。
    if (Request->action == KSWORD_ARK_CALLBACK_MONITOR_ACTION_START) {
        requestedMask = Request->categoryMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_ALL;
        if (requestedMask == 0UL) {
            status = STATUS_INVALID_PARAMETER;
        }
        if (NT_SUCCESS(status) &&
            (requestedMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER) != 0UL) {
            status = KswordARKFileMonitorEnsureFilteringStarted();
        }
        if (NT_SUCCESS(status)) {
            // 控制线程可以等待短暂的单写者临界区；系统回调仍只做 try-lock。
            writerLockHeld = KswordArkCallbackMonitorTryAcquireWriterLockBounded(runtime);
            if (!writerLockHeld) {
                status = STATUS_DEVICE_BUSY;
            }
            else {
                previousMask = InterlockedCompareExchange(&runtime->MonitorCategoryMask, 0L, 0L);
                if (previousMask == 0L) {
                    // 没有回调可写时才能安全重置整个大 ring。
                    RtlZeroMemory(runtime->MonitorSlots, sizeof(runtime->MonitorSlots));
                    (VOID)InterlockedExchange64(&runtime->MonitorLatestSequence, 0LL);
                    (VOID)InterlockedExchange64(&runtime->MonitorDroppedCount, 0LL);
                }
                (VOID)InterlockedExchange(&runtime->MonitorCategoryMask, (LONG)requestedMask);
            }
        }
    }
    else if (Request->action == KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP) {
        // 与已进入提交临界区的回调同步，STOP 返回后不会再有尾部记录。
        writerLockHeld = KswordArkCallbackMonitorTryAcquireWriterLockBounded(runtime);
        if (!writerLockHeld) {
            status = STATUS_DEVICE_BUSY;
        }
        else {
            (VOID)InterlockedExchange(&runtime->MonitorCategoryMask, 0L);
            status = STATUS_SUCCESS;
        }
    }
    else {
        status = STATUS_INVALID_PARAMETER;
    }

    if (writerLockHeld) {
        (VOID)InterlockedExchange(&runtime->MonitorWriterLock, 0L);
    }
    runtime->MonitorLastStatus = status;
    KswordArkCallbackMonitorFillStatus(runtime, Response);
    return status;
}

NTSTATUS
KswordArkCallbackMonitorQuery(
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* Response
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();

    // 查询是只读快照，不改变类别或游标状态。
    if (runtime == NULL || Response == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    KswordArkCallbackMonitorFillStatus(runtime, Response);
    return STATUS_SUCCESS;
}

NTSTATUS
KswordArkCallbackMonitorRead(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    KSWORD_ARK_CALLBACK_MONITOR_SLOT* slot = NULL;
    const size_t responseHeaderSize = FIELD_OFFSET(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records);
    ULONGLONG latestSequence = 0ULL;
    ULONGLONG earliestSequence = 0ULL;
    ULONGLONG afterSequence = 0ULL;
    ULONGLONG nextSequence = 0ULL;
    ULONGLONG sequence = 0ULL;
    ULONG outputCapacity = 0UL;
    ULONG requestedCount = 0UL;
    ULONG recordCount = 0UL;
    LONG64 commitBefore = 0LL;
    LONG64 commitAfter = 0LL;

    // 先验证固定协议头和变长输出区边界。
    if (runtime == NULL || Request == NULL || Response == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (Request->version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
        Request->size < sizeof(*Request)) {
        return STATUS_REVISION_MISMATCH;
    }
    if (OutputBufferLength < responseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 按调用方缓冲、协议默认值和硬上限共同裁剪本次记录数。
    outputCapacity = (ULONG)((OutputBufferLength - responseHeaderSize) /
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT));
    requestedCount = Request->maxRecords;
    if (requestedCount == 0UL) {
        requestedCount = KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS;
    }
    requestedCount = min(requestedCount, KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS);
    requestedCount = min(requestedCount, outputCapacity);

    // 只清零真实可写长度，避免大输出缓冲携带旧内核数据。
    RtlZeroMemory(
        Response,
        responseHeaderSize + ((SIZE_T)requestedCount * sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT)));
    Response->version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    Response->size = (ULONG)responseHeaderSize;
    Response->entrySize = sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT);
    Response->ringCapacity = KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY;
    Response->categoryMask = (ULONG)InterlockedCompareExchange(
        &runtime->MonitorCategoryMask,
        0L,
        0L);
    if (Response->categoryMask != 0UL) {
        Response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING;
    }
    Response->droppedCount = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->MonitorDroppedCount,
        0LL,
        0LL);
    if (Response->droppedCount != 0ULL) {
        Response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_DROPPED;
    }

    // 快照最新和最早序号，落后调用方按 lostBeforeFirst 精确补账。
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->MonitorLatestSequence,
        0LL,
        0LL);
    earliestSequence = latestSequence > KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY
        ? latestSequence - KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY + 1ULL
        : (latestSequence == 0ULL ? 0ULL : 1ULL);
    Response->latestSequence = latestSequence;
    Response->firstAvailableSequence = earliestSequence;
    afterSequence = Request->afterSequence;
    if (afterSequence > latestSequence) {
        afterSequence = 0ULL;
        Response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_OVERFLOW;
    }
    nextSequence = afterSequence;
    if (earliestSequence != 0ULL && afterSequence + 1ULL < earliestSequence) {
        Response->lostBeforeFirst = earliestSequence - (afterSequence + 1ULL);
        Response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_OVERFLOW;
        nextSequence = earliestSequence - 1ULL;
    }

    // 每个槽复制前后核对提交序号；覆盖竞态保留游标，下一次读取再重试或补账。
    sequence = nextSequence + 1ULL;
    while (sequence != 0ULL && sequence <= latestSequence && recordCount < requestedCount) {
        slot = &runtime->MonitorSlots[(sequence - 1ULL) % KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY];
        commitBefore = InterlockedCompareExchange64(&slot->CommitSequence, 0LL, 0LL);
        if (commitBefore == (LONG64)sequence) {
            RtlCopyMemory(
                &Response->records[recordCount],
                &slot->Event,
                sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT));
            KeMemoryBarrier();
            commitAfter = InterlockedCompareExchange64(&slot->CommitSequence, 0LL, 0LL);
            if (commitAfter == commitBefore && Response->records[recordCount].sequence == sequence) {
                ++recordCount;
            }
            else {
                RtlZeroMemory(
                    &Response->records[recordCount],
                    sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT));
                Response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_SNAPSHOT_RACE;
                break;
            }
        }
        else {
            Response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_SNAPSHOT_RACE;
            break;
        }
        nextSequence = sequence;
        ++sequence;
    }

    // 最终长度只包含验证成功的记录。
    Response->returnedCount = recordCount;
    Response->nextSequence = nextSequence;
    if (nextSequence < latestSequence) {
        Response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_MORE_AVAILABLE;
    }
    Response->size = (ULONG)(responseHeaderSize +
        ((SIZE_T)recordCount * sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT)));
    *BytesWrittenOut = Response->size;
    return STATUS_SUCCESS;
}
