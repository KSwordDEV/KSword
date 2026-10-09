/*++

Module Name:

    work_queue_fallback.c

Abstract:

    Runtime-signature fallback for Ex worker queues.  ExQueueWorkItem is the
    stable entry anchor.  The resolver validates the partition pointer chain,
    every live node queue, all priority list heads, public WORK_QUEUE_ITEM
    fields, the ETHREAD queue pointer and the ETHREAD start address across
    referenced System threads.  No fixed private Windows offsets are used and
    no PDB profile is required.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query path.

--*/

#include "ark/ark_dyndata.h"
#include "work_queue_fallback.h"
#include "../../platform/runtime_signature_scan.h"
#include "../../platform/pool_compat.h"

#define KSW_WORK_QUEUE_FALLBACK_TAG 'qWsK'
#define KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES 256UL
#define KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES 0x0800UL
#define KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN 0x0100UL
#define KSW_WORK_QUEUE_FALLBACK_QUEUE_SCAN 0x0100UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_POOL_INDEX 8UL
// 优先级链表数组之后的自述字段窗口：队列自身的 partition 回指与队列序号都落在这里。
#define KSW_WORK_QUEUE_FALLBACK_TAIL_SCAN 0x0180UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_NODES 64UL
#define KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT 32UL
#define KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN 0x0800UL
#define KSW_WORK_QUEUE_FALLBACK_MAX_THREADS 512UL
#define KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES 8UL
#define KSW_WORK_QUEUE_FALLBACK_SYSTEM_PROCESS_ID 4UL
#define KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION_CLASS 5UL
#define KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_SLACK (64UL * 1024UL)
#define KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_LIMIT (32UL * 1024UL * 1024UL)
// 起始地址偏移的判据：所有工作线程在该偏移上取到同一个值，该值落在 ntoskrnl
// 可执行节内(即 ExpWorkerThread)，同时该偏移在整体样本上取值足够分散，
// 从而排除「全 System 线程共用同一个常量」和各类池指针字段。
#define KSW_WORK_QUEUE_FALLBACK_START_MIN_SAMPLES 8UL
#define KSW_WORK_QUEUE_FALLBACK_START_MIN_DISTINCT 3UL
#define KSW_WORK_QUEUE_FALLBACK_START_MIN_WORKERS 2UL
#define KSW_WORK_QUEUE_FALLBACK_START_DISTINCT_SLOTS 4UL

typedef PETHREAD(NTAPI* KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
    );

typedef struct _KSW_WORK_QUEUE_FALLBACK_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} KSW_WORK_QUEUE_FALLBACK_THREAD_INFORMATION;

typedef struct _KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
    KSW_WORK_QUEUE_FALLBACK_THREAD_INFORMATION Threads[1];
} KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Outptr_ PETHREAD* Thread
    );

// 每个候选偏移的证据累加器。ETHREAD 扫描窗口内每个指针宽槽位一份。
typedef struct _KSW_WORK_QUEUE_FALLBACK_SLOT_STATS
{
    ULONG QueueMatches;
    ULONG ZeroValues;
    ULONG StartMatches;
    ULONG StartMismatches;
    ULONG WorkerSamples;
    ULONG DistinctCount;
    BOOLEAN WorkerConflict;
    ULONG64 WorkerValue;
    ULONG64 DistinctValues[KSW_WORK_QUEUE_FALLBACK_START_DISTINCT_SLOTS];
} KSW_WORK_QUEUE_FALLBACK_SLOT_STATS;

typedef struct _KSW_WORK_QUEUE_CHAIN
{
    ULONG_PTR PartitionGlobal;
    ULONG PartitionExPartition;
    ULONG ExPartitionWorkQueues;
    ULONG PoolIndex;
    ULONG PriQueueOffset;
    ULONG PartitionBackOffset;
    ULONG QueueIndexOffset;
    ULONG NodeCount;
    ULONG ValidationScore;
    ULONG_PTR QueueAddresses[KSW_WORK_QUEUE_FALLBACK_MAX_NODES];
} KSW_WORK_QUEUE_CHAIN, *PKSW_WORK_QUEUE_CHAIN;

extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;

static KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN
KswordARKWorkQueueFallbackResolveNextThread(
    VOID
    )
/*++

Routine Description:

    Probe the public process-thread walker.  Current kernels do not export it,
    so callers must treat NULL as "use the TID snapshot path" instead of as a
    hard failure.

--*/
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KSW_WORK_QUEUE_FALLBACK_NEXT_THREAD_FN)
        MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
KswordARKWorkQueueFallbackCaptureProcessSnapshot(
    _Outptr_result_maybenull_ PVOID* SnapshotOut,
    _Out_ ULONG* SnapshotBytesOut
    )
/*++

Routine Description:

    Capture one SystemProcessInformation snapshot with a bounded grow-retry.

Return Value:

    STATUS_SUCCESS with a pool block the caller frees, otherwise a query status.

--*/
{
    ULONG requiredBytes = 0UL;
    ULONG attempt = 0UL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (SnapshotOut == NULL || SnapshotBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *SnapshotOut = NULL;
    *SnapshotBytesOut = 0UL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = ZwQuerySystemInformation(
        KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes < sizeof(KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION)) {
        requiredBytes = sizeof(KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION);
    }

    for (attempt = 0UL; attempt < 4UL; ++attempt) {
        PVOID snapshot = NULL;
        ULONG allocationBytes = 0UL;
        ULONG returnedBytes = 0UL;

        if (requiredBytes >
            KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_LIMIT -
                KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_SLACK) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        allocationBytes = requiredBytes + KSW_WORK_QUEUE_FALLBACK_SNAPSHOT_SLACK;
        snapshot = KswordARKAllocateNonPagedPool(
            allocationBytes,
            KSW_WORK_QUEUE_FALLBACK_TAG);
        if (snapshot == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(snapshot, allocationBytes);

        status = ZwQuerySystemInformation(
            KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION_CLASS,
            snapshot,
            allocationBytes,
            &returnedBytes);
        if (NT_SUCCESS(status)) {
            if (returnedBytes == 0UL || returnedBytes > allocationBytes) {
                returnedBytes = allocationBytes;
            }
            *SnapshotOut = snapshot;
            *SnapshotBytesOut = returnedBytes;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(snapshot, KSW_WORK_QUEUE_FALLBACK_TAG);
        if (status != STATUS_INFO_LENGTH_MISMATCH &&
            status != STATUS_BUFFER_TOO_SMALL) {
            return status;
        }
        requiredBytes = returnedBytes > allocationBytes
            ? returnedBytes
            : allocationBytes;
    }
    return status;
}

NTSTATUS
KswordARKWorkQueueCaptureProcessThreads(
    _In_ ULONG ProcessId, // 按真实进程 ID 选择快照项，原 System 入口仍传 4。
    _Out_ KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* SnapshotOut
    )
/*++

Routine Description:

    Build the bounded System(PID 4) TID / StartAddress table.  The kernel does
    not export a process-thread walker, so this table is what lets the work
    queue path reach Object Manager referenced ETHREADs without a PDB profile.

Return Value:

    STATUS_SUCCESS with at least one row, otherwise a fail-closed status.

--*/
{
    PVOID processSnapshot = NULL;
    ULONG processSnapshotBytes = 0UL;
    ULONG processOffset = 0UL;
    KSW_WORK_QUEUE_SYSTEM_THREAD* entries = NULL;
    ULONG count = 0UL;
    BOOLEAN truncated = FALSE;
    BOOLEAN found = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (SnapshotOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(SnapshotOut, sizeof(*SnapshotOut));

    status = KswordARKWorkQueueFallbackCaptureProcessSnapshot(
        &processSnapshot,
        &processSnapshotBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    entries = (KSW_WORK_QUEUE_SYSTEM_THREAD*)KswordARKAllocateNonPagedPool(
        KSW_WORK_QUEUE_SYSTEM_THREAD_MAX * sizeof(*entries),
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (entries == NULL) {
        ExFreePoolWithTag(processSnapshot, KSW_WORK_QUEUE_FALLBACK_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(entries, KSW_WORK_QUEUE_SYSTEM_THREAD_MAX * sizeof(*entries));

    while (processOffset < processSnapshotBytes && !found) {
        const KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION* processInfo =
            (const KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION*)
                ((const UCHAR*)processSnapshot + processOffset);
        ULONG remainingBytes = processSnapshotBytes - processOffset;
        ULONG entryBytes = 0UL;
        ULONG threadCapacity = 0UL;
        ULONG threadCount = 0UL;
        ULONG threadIndex = 0UL;

        if (remainingBytes <
            (ULONG)FIELD_OFFSET(
                KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION,
                Threads)) {
            break;
        }
        entryBytes = processInfo->NextEntryOffset != 0UL
            ? processInfo->NextEntryOffset
            : remainingBytes;
        if (entryBytes >
                remainingBytes ||
            entryBytes <
                (ULONG)FIELD_OFFSET(
                    KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION,
                    Threads)) {
            break;
        }
        if (HandleToULong(processInfo->UniqueProcessId) !=
            ProcessId) { // 复用同一快照解析与边界验证。
            if (processInfo->NextEntryOffset == 0UL) {
                break;
            }
            processOffset += processInfo->NextEntryOffset;
            continue;
        }

        found = TRUE;
        threadCapacity = (entryBytes -
            (ULONG)FIELD_OFFSET(
                KSW_WORK_QUEUE_FALLBACK_PROCESS_INFORMATION,
                Threads)) /
            (ULONG)sizeof(KSW_WORK_QUEUE_FALLBACK_THREAD_INFORMATION);
        threadCount = processInfo->NumberOfThreads;
        if (threadCount > threadCapacity) {
            threadCount = threadCapacity;
            truncated = TRUE;
        }
        for (threadIndex = 0UL; threadIndex < threadCount; ++threadIndex) {
            const KSW_WORK_QUEUE_FALLBACK_THREAD_INFORMATION* threadInfo =
                &processInfo->Threads[threadIndex];
            ULONG threadId = HandleToULong(threadInfo->ClientId.UniqueThread);

            if (threadId == 0UL ||
                HandleToULong(threadInfo->ClientId.UniqueProcess) !=
                    ProcessId) { // 每条线程必须归属所选进程。
                continue;
            }
            if (count >= KSW_WORK_QUEUE_SYSTEM_THREAD_MAX) {
                truncated = TRUE;
                break;
            }
            entries[count].ThreadId = threadId;
            entries[count].StartAddress =
                (ULONG64)(ULONG_PTR)threadInfo->StartAddress;
            count += 1UL;
        }
    }

    ExFreePoolWithTag(processSnapshot, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (count == 0UL) {
        ExFreePoolWithTag(entries, KSW_WORK_QUEUE_FALLBACK_TAG);
        return STATUS_NOT_FOUND;
    }
    SnapshotOut->Entries = entries;
    SnapshotOut->Count = count;
    SnapshotOut->Truncated = truncated;
    return STATUS_SUCCESS;
}

// 中文说明：保留原工作队列入口及 System 语义，现有消费者不需要改参数。
NTSTATUS KswordARKWorkQueueCaptureSystemThreads(KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* SnapshotOut)
{
    return KswordARKWorkQueueCaptureProcessThreads(KSW_WORK_QUEUE_FALLBACK_SYSTEM_PROCESS_ID, SnapshotOut); // 原有 PID 4 快照。
}

VOID
KswordARKWorkQueueReleaseSystemThreads(
    _Inout_ KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* Snapshot
    )
{
    if (Snapshot == NULL) {
        return;
    }
    if (Snapshot->Entries != NULL) {
        ExFreePoolWithTag(Snapshot->Entries, KSW_WORK_QUEUE_FALLBACK_TAG);
    }
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
}

VOID
KswordARKWorkQueueInitializeThreadWalker(
    _Out_ KSW_WORK_QUEUE_THREAD_WALKER* Walker,
    _In_opt_ const KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* Snapshot
    )
{
    if (Walker == NULL) {
        return;
    }
    RtlZeroMemory(Walker, sizeof(*Walker));
    if (PsInitialSystemProcess != NULL) {
        Walker->NextProcessThread =
            KswordARKWorkQueueFallbackResolveNextThread();
    }
    if (Snapshot != NULL && Snapshot->Entries != NULL && Snapshot->Count != 0UL) {
        Walker->Snapshot = Snapshot;
    }
}

BOOLEAN
KswordARKWorkQueueThreadWalkerUsable(
    _In_ const KSW_WORK_QUEUE_THREAD_WALKER* Walker
    )
{
    return Walker != NULL &&
        (Walker->NextProcessThread != NULL || Walker->Snapshot != NULL);
}

PETHREAD
KswordARKWorkQueueThreadWalkerNext(
    _Inout_ KSW_WORK_QUEUE_THREAD_WALKER* Walker
    )
/*++

Routine Description:

    Advance to the next referenced System thread.  The walker owns the returned
    reference and releases it on the next advance or on close.

Return Value:

    Referenced ETHREAD, or NULL when the walk is finished.

--*/
{
    PETHREAD previous = NULL;
    PETHREAD next = NULL;

    if (Walker == NULL || Walker->Finished) {
        return NULL;
    }
    previous = Walker->Current;

    if (Walker->NextProcessThread != NULL) {
        next = Walker->NextProcessThread(PsInitialSystemProcess, previous);
        if (previous != NULL) {
            ObDereferenceObject(previous);
        }
    }
    else {
        if (previous != NULL) {
            ObDereferenceObject(previous);
        }
        while (Walker->Snapshot != NULL &&
               Walker->NextIndex < Walker->Snapshot->Count) {
            PETHREAD candidate = NULL;
            ULONG threadId = Walker->Snapshot->Entries[Walker->NextIndex].ThreadId;

            Walker->NextIndex += 1UL;
            if (threadId == 0UL) {
                continue;
            }
            // 线程可能在快照与查找之间退出；跳过即可，仍在表内的行不受影响。
            if (NT_SUCCESS(PsLookupThreadByThreadId(
                    ULongToHandle(threadId),
                    &candidate)) &&
                candidate != NULL) {
                next = candidate;
                break;
            }
        }
    }

    Walker->Current = next;
    if (next == NULL) {
        Walker->Finished = TRUE;
    }
    return next;
}

VOID
KswordARKWorkQueueThreadWalkerClose(
    _Inout_ KSW_WORK_QUEUE_THREAD_WALKER* Walker
    )
{
    if (Walker == NULL) {
        return;
    }
    if (Walker->Current != NULL) {
        ObDereferenceObject(Walker->Current);
        Walker->Current = NULL;
    }
    Walker->Finished = TRUE;
}

static ULONG64
KswordARKWorkQueueFallbackLookupStartAddress(
    _In_opt_ const KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* Snapshot,
    _In_ ULONG ThreadId
    )
{
    ULONG index = 0UL;

    if (Snapshot == NULL || Snapshot->Entries == NULL || ThreadId == 0UL) {
        return 0ULL;
    }
    for (index = 0UL; index < Snapshot->Count; ++index) {
        if (Snapshot->Entries[index].ThreadId == ThreadId) {
            return Snapshot->Entries[index].StartAddress;
        }
    }
    return 0ULL;
}

static BOOLEAN
KswordARKWorkQueueFallbackIsKernelAddress(
    _In_ ULONG_PTR Address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
KswordARKWorkQueueFallbackReadPointer(
    _In_ ULONG_PTR Address,
    _Out_ ULONG_PTR* ValueOut
    )
{
    return ValueOut != NULL &&
        KswordARKRuntimeReadMemory(
            (const VOID*)Address,
            ValueOut,
            sizeof(*ValueOut));
}

static BOOLEAN
KswordARKWorkQueueFallbackValidateListHead(
    _In_ ULONG_PTR HeadAddress,
    _Out_opt_ BOOLEAN* NonEmptyOut
    )
{
    LIST_ENTRY head;
    LIST_ENTRY first;
    LIST_ENTRY last;

    if (NonEmptyOut != NULL) {
        *NonEmptyOut = FALSE;
    }
    RtlZeroMemory(&head, sizeof(head));
    RtlZeroMemory(&first, sizeof(first));
    RtlZeroMemory(&last, sizeof(last));
    if (!KswordARKWorkQueueFallbackIsKernelAddress(HeadAddress) ||
        !KswordARKRuntimeReadMemory(
            (const VOID*)HeadAddress,
            &head,
            sizeof(head)) ||
        head.Flink == NULL || head.Blink == NULL) {
        return FALSE;
    }
    if ((ULONG_PTR)head.Flink == HeadAddress ||
        (ULONG_PTR)head.Blink == HeadAddress) {
        return (ULONG_PTR)head.Flink == HeadAddress &&
            (ULONG_PTR)head.Blink == HeadAddress;
    }
    if (!KswordARKWorkQueueFallbackIsKernelAddress((ULONG_PTR)head.Flink) ||
        !KswordARKWorkQueueFallbackIsKernelAddress((ULONG_PTR)head.Blink) ||
        !KswordARKRuntimeReadMemory(head.Flink, &first, sizeof(first)) ||
        !KswordARKRuntimeReadMemory(head.Blink, &last, sizeof(last)) ||
        (ULONG_PTR)first.Blink != HeadAddress ||
        (ULONG_PTR)last.Flink != HeadAddress) {
        return FALSE;
    }
    if (NonEmptyOut != NULL) {
        *NonEmptyOut = TRUE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindPriQueueOffset(
    _In_ ULONG_PTR QueueAddress,
    _Out_ ULONG* OffsetOut,
    _Out_ ULONG* ScoreOut
    )
/*++

Routine Description:

    Locate the one array of 32 reciprocal priority list heads inside a live
    queue.

    The scan steps by one pointer while the array strides by one LIST_ENTRY,
    so a shape-only test always accepts two windows: the real EntryListHead
    array, and the window starting one pointer earlier, which pairs the
    preceding dispatcher-header wait list with the first 31 real heads. Both
    contain 32 reciprocal heads, so neither occupancy scoring nor a tie-break
    can separate them - the earlier window is not weaker evidence, it is an
    equally well-formed alias sitting exactly one pointer before the truth.

    The discriminator is the right edge: the real array must END. Probing one
    element past the window must fail, which is true only for the genuine
    array (whose successor field is a counter, not a list head). The aliased
    window's 33rd probe lands on the array's own last element and stays valid,
    so it is rejected. The left edge must never be used for this: the element
    before the real array is a valid list head, so a left-edge test would
    select the alias instead.

Return Value:

    TRUE only when exactly one window survives the right-edge test.

--*/
{
    ULONG candidateOffset = 0UL;
    ULONG bestOffset = 0UL;
    ULONG bestScore = 0UL;
    ULONG survivors = 0UL;

    if (OffsetOut == NULL || ScoreOut == NULL ||
        !KswordARKWorkQueueFallbackIsKernelAddress(QueueAddress)) {
        return FALSE;
    }
    for (candidateOffset = 0UL;
         candidateOffset < KSW_WORK_QUEUE_FALLBACK_QUEUE_SCAN;
         candidateOffset += sizeof(PVOID)) {
        ULONG priorityIndex = 0UL;
        ULONG score = 0UL;
        ULONG_PTR tailAddress = 0U;
        BOOLEAN valid = TRUE;

        for (priorityIndex = 0UL;
             priorityIndex < KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT;
             ++priorityIndex) {
            ULONG_PTR headAddress = QueueAddress + candidateOffset +
                ((ULONG_PTR)priorityIndex * sizeof(LIST_ENTRY));
            BOOLEAN nonEmpty = FALSE;

            if (headAddress < QueueAddress ||
                !KswordARKWorkQueueFallbackValidateListHead(
                    headAddress,
                    &nonEmpty)) {
                valid = FALSE;
                break;
            }
            score += nonEmpty ? 2UL : 1UL;
        }
        if (!valid) {
            continue;
        }
        tailAddress = QueueAddress + candidateOffset +
            ((ULONG_PTR)KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT *
             sizeof(LIST_ENTRY));
        if (tailAddress < QueueAddress ||
            KswordARKWorkQueueFallbackValidateListHead(tailAddress, NULL)) {
            // 第 33 项仍是合法链表头，说明这个窗口没有在数组真正的末尾结束。
            continue;
        }
        survivors += 1UL;
        bestOffset = candidateOffset;
        bestScore = score;
    }
    if (survivors != 1UL ||
        bestScore < KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT) {
        return FALSE;
    }
    *OffsetOut = bestOffset;
    *ScoreOut = bestScore;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindPartitionBackOffset(
    _In_ ULONG_PTR QueueAddress,
    _In_ ULONG PriQueueOffset,
    _In_ ULONG_PTR ExPartition,
    _Out_ ULONG* OffsetOut
    )
/*++

Routine Description:

    Find where the queue names its owning partition. Walking
    partition -> work queues -> queue only proves the forward direction; a
    lookalike global that happens to hold a plausible pointer chain would pass
    it. Requiring the queue to point back at the same partition object closes
    the loop, and the offset is discovered at runtime rather than assumed.

Return Value:

    TRUE when exactly one slot past the priority array holds ExPartition.

--*/
{
    ULONG offset = 0UL;
    ULONG found = 0UL;
    ULONG foundOffset = 0UL;
    const ULONG arrayEnd = PriQueueOffset +
        (KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT * (ULONG)sizeof(LIST_ENTRY));

    if (OffsetOut == NULL) {
        return FALSE;
    }
    *OffsetOut = 0UL;
    for (offset = arrayEnd;
         offset < arrayEnd + KSW_WORK_QUEUE_FALLBACK_TAIL_SCAN;
         offset += sizeof(PVOID)) {
        ULONG_PTR value = 0U;

        if (!KswordARKWorkQueueFallbackReadPointer(
                QueueAddress + offset,
                &value)) {
            continue;
        }
        if (value == ExPartition) {
            found += 1UL;
            foundOffset = offset;
        }
    }
    if (found != 1UL) {
        return FALSE;
    }
    *OffsetOut = foundOffset;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindQueueIndexOffset(
    _In_ ULONG_PTR FirstQueue,
    _In_ ULONG_PTR SecondQueue,
    _In_ ULONG PriQueueOffset,
    _Out_ ULONG* OffsetOut
    )
/*++

Routine Description:

    Find where a queue records its own slot number, by requiring slot 0 to read
    back 0 and slot 1 to read back 1 at the same offset. Optional evidence: it
    lets the consumer re-check on live memory that it is walking the slot it
    thinks it is.

Return Value:

    TRUE when exactly one offset satisfies both queues.

--*/
{
    ULONG offset = 0UL;
    ULONG found = 0UL;
    ULONG foundOffset = 0UL;
    const ULONG arrayEnd = PriQueueOffset +
        (KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT * (ULONG)sizeof(LIST_ENTRY));

    if (OffsetOut == NULL) {
        return FALSE;
    }
    *OffsetOut = 0UL;
    for (offset = arrayEnd;
         offset < arrayEnd + KSW_WORK_QUEUE_FALLBACK_TAIL_SCAN;
         offset += sizeof(ULONG)) {
        ULONG firstValue = 0UL;
        ULONG secondValue = 0UL;

        if (!KswordARKRuntimeReadMemory(
                (const VOID*)(FirstQueue + offset),
                &firstValue,
                sizeof(firstValue)) ||
            !KswordARKRuntimeReadMemory(
                (const VOID*)(SecondQueue + offset),
                &secondValue,
                sizeof(secondValue))) {
            continue;
        }
        if (firstValue == 0UL && secondValue == 1UL) {
            found += 1UL;
            foundOffset = offset;
        }
    }
    if (found != 1UL) {
        return FALSE;
    }
    *OffsetOut = foundOffset;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackValidateChainCandidate(
    _In_ ULONG_PTR PartitionGlobal,
    _In_ ULONG PartitionOffset,
    _In_ ULONG WorkQueuesOffset,
    _In_ ULONG PoolIndex,
    _Out_ KSW_WORK_QUEUE_CHAIN* ChainOut
    )
{
    ULONG_PTR partition = 0U;
    ULONG_PTR exPartition = 0U;
    ULONG_PTR workQueues = 0U;
    ULONG nodeCount = (ULONG)KeQueryHighestNodeNumber() + 1UL;
    ULONG nodeIndex = 0UL;
    ULONG sharedPriQueueOffset = MAXULONG;
    ULONG sharedBackOffset = MAXULONG;
    ULONG queueIndexOffset = 0UL;
    ULONG totalScore = 0UL;
    KSW_WORK_QUEUE_CHAIN candidate;

    if (ChainOut == NULL || nodeCount == 0UL ||
        nodeCount > KSW_WORK_QUEUE_FALLBACK_MAX_NODES ||
        !KswordARKWorkQueueFallbackReadPointer(
            PartitionGlobal,
            &partition) ||
        !KswordARKWorkQueueFallbackIsKernelAddress(partition) ||
        !KswordARKWorkQueueFallbackReadPointer(
            partition + PartitionOffset,
            &exPartition) ||
        !KswordARKWorkQueueFallbackIsKernelAddress(exPartition) ||
        !KswordARKWorkQueueFallbackReadPointer(
            exPartition + WorkQueuesOffset,
            &workQueues) ||
        !KswordARKWorkQueueFallbackIsKernelAddress(workQueues)) {
        return FALSE;
    }
    RtlZeroMemory(&candidate, sizeof(candidate));
    for (nodeIndex = 0UL; nodeIndex < nodeCount; ++nodeIndex) {
        ULONG_PTR nodeQueueArray = 0U;
        ULONG_PTR queueAddress = 0U;
        ULONG priQueueOffset = 0UL;
        ULONG backOffset = 0UL;
        ULONG queueScore = 0UL;

        if (!KswordARKWorkQueueFallbackReadPointer(
                workQueues + ((ULONG_PTR)nodeIndex * sizeof(PVOID)),
                &nodeQueueArray) ||
            !KswordARKWorkQueueFallbackIsKernelAddress(nodeQueueArray) ||
            !KswordARKWorkQueueFallbackReadPointer(
                nodeQueueArray + ((ULONG_PTR)PoolIndex * sizeof(PVOID)),
                &queueAddress) ||
            !KswordARKWorkQueueFallbackIsKernelAddress(queueAddress) ||
            !KswordARKWorkQueueFallbackFindPriQueueOffset(
                queueAddress,
                &priQueueOffset,
                &queueScore) ||
            (sharedPriQueueOffset != MAXULONG &&
             priQueueOffset != sharedPriQueueOffset) ||
            !KswordARKWorkQueueFallbackFindPartitionBackOffset(
                queueAddress,
                priQueueOffset,
                exPartition,
                &backOffset) ||
            (sharedBackOffset != MAXULONG && backOffset != sharedBackOffset)) {
            return FALSE;
        }
        sharedPriQueueOffset = priQueueOffset;
        sharedBackOffset = backOffset;
        candidate.QueueAddresses[nodeIndex] = queueAddress;
        totalScore += queueScore;

        if (nodeIndex == 0UL &&
            PoolIndex + 1UL < KSW_WORK_QUEUE_FALLBACK_MAX_POOL_INDEX) {
            ULONG_PTR siblingQueue = 0U;

            // 队列序号是可选的加分证据，解不出来不阻断链路判定。
            if (KswordARKWorkQueueFallbackReadPointer(
                    nodeQueueArray +
                        ((ULONG_PTR)(PoolIndex + 1UL) * sizeof(PVOID)),
                    &siblingQueue) &&
                KswordARKWorkQueueFallbackIsKernelAddress(siblingQueue)) {
                (VOID)KswordARKWorkQueueFallbackFindQueueIndexOffset(
                    queueAddress,
                    siblingQueue,
                    priQueueOffset,
                    &queueIndexOffset);
            }
        }
    }

    candidate.PartitionGlobal = PartitionGlobal;
    candidate.PartitionExPartition = PartitionOffset;
    candidate.ExPartitionWorkQueues = WorkQueuesOffset;
    candidate.PoolIndex = PoolIndex;
    candidate.PriQueueOffset = sharedPriQueueOffset;
    candidate.PartitionBackOffset = sharedBackOffset;
    candidate.QueueIndexOffset = queueIndexOffset;
    candidate.NodeCount = nodeCount;
    candidate.ValidationScore = totalScore;
    *ChainOut = candidate;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackChainsEqual(
    _In_ const KSW_WORK_QUEUE_CHAIN* Left,
    _In_ const KSW_WORK_QUEUE_CHAIN* Right
    )
/*++

Routine Description:

    Decide whether two candidates describe the same queues. Identity is the
    resolved result, not the description that produced it: two distinct globals
    both holding the same partition pointer reach the identical queue set and
    must not count as a contradiction, while candidates that reach different
    queues still do.

--*/
{
    ULONG nodeIndex = 0UL;

    if (Left->NodeCount != Right->NodeCount) {
        return FALSE;
    }
    for (nodeIndex = 0UL; nodeIndex < Left->NodeCount; ++nodeIndex) {
        if (Left->QueueAddresses[nodeIndex] != Right->QueueAddresses[nodeIndex]) {
            return FALSE;
        }
    }
    return Left->PoolIndex == Right->PoolIndex &&
        Left->PriQueueOffset == Right->PriQueueOffset;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindChain(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_reads_(ReferenceCount) const KSW_RUNTIME_DATA_REFERENCE* References,
    _In_ ULONG ReferenceCount,
    _Out_ KSW_WORK_QUEUE_CHAIN* ChainOut,
    _Out_ BOOLEAN* AmbiguousOut
    )
{
    KSW_WORK_QUEUE_CHAIN best;
    ULONG bestScore = 0UL;
    BOOLEAN ambiguous = FALSE;
    ULONG referenceIndex = 0UL;

    if (AmbiguousOut != NULL) {
        *AmbiguousOut = FALSE;
    }
    if (View == NULL || References == NULL || ChainOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&best, sizeof(best));
    for (referenceIndex = 0UL; referenceIndex < ReferenceCount; ++referenceIndex) {
        ULONG_PTR partition = 0U;
        ULONG partitionOffset = 0UL;

        // 分区指针在整条 reference 上是不变量，先读一次再进内层扫描。
        if (!KswordARKRuntimeAddressIsWritableData(
                View,
                References[referenceIndex].Address,
                sizeof(PVOID)) ||
            !KswordARKWorkQueueFallbackReadPointer(
                References[referenceIndex].Address,
                &partition) ||
            !KswordARKWorkQueueFallbackIsKernelAddress(partition)) {
            continue;
        }
        for (partitionOffset = 0UL;
             partitionOffset < KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN;
             partitionOffset += sizeof(PVOID)) {
            ULONG_PTR exPartition = 0U;
            ULONG workQueuesOffset = 0UL;

            if (!KswordARKWorkQueueFallbackReadPointer(
                    partition + partitionOffset,
                    &exPartition) ||
                !KswordARKWorkQueueFallbackIsKernelAddress(exPartition)) {
                continue;
            }
            for (workQueuesOffset = 0UL;
                 workQueuesOffset < KSW_WORK_QUEUE_FALLBACK_PARTITION_SCAN;
                 workQueuesOffset += sizeof(PVOID)) {
                ULONG_PTR workQueues = 0U;
                KSW_WORK_QUEUE_CHAIN candidate;

                if (!KswordARKWorkQueueFallbackReadPointer(
                        exPartition + workQueuesOffset,
                        &workQueues) ||
                    !KswordARKWorkQueueFallbackIsKernelAddress(workQueues)) {
                    continue;
                }

                /*
                 * 池序号不参与搜索。ExPoolUntrusted 是 _EXQUEUEINDEX 的序号 0，
                 * 是数组下标语义而不是需要猜的私有偏移；把它放进同一套打分里
                 * 只会让两个已分配的队列互相判成歧义，而打分本身对“哪个槽才对”
                 * 零信息量。选错槽会静默产出贴错标签的证据，因此这里固定取 0，
                 * 验不过就 fail-closed，不退而求其次去试别的槽。
                 */
                RtlZeroMemory(&candidate, sizeof(candidate));
                if (!KswordARKWorkQueueFallbackValidateChainCandidate(
                        References[referenceIndex].Address,
                        partitionOffset,
                        workQueuesOffset,
                        0UL,
                        &candidate) ||
                    candidate.ValidationScore < bestScore) {
                    continue;
                }
                if (candidate.ValidationScore == bestScore &&
                    bestScore != 0UL &&
                    !KswordARKWorkQueueFallbackChainsEqual(
                        &candidate,
                        &best)) {
                    ambiguous = TRUE;
                    continue;
                }
                /*
                 * 歧义标志必须是粘性的：只有严格更高分的候选才有资格清零。
                 * ChainsEqual 只比较解析结果，同一批队列会被多个候选重复命中，
                 * 若同分候选也清零，先前记录的「另一条同分矛盾链」就被抹掉，
                 * 唯一性判定这道 fail-closed 闸门等于失效。
                 */
                if (candidate.ValidationScore > bestScore) {
                    ambiguous = FALSE;
                }
                best = candidate;
                bestScore = candidate.ValidationScore;
            }
        }
    }
    if (AmbiguousOut != NULL) {
        *AmbiguousOut = ambiguous;
    }
    if (bestScore == 0UL || ambiguous) {
        return FALSE;
    }
    *ChainOut = best;
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackFindPriorityIndexes(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _Out_writes_(3) ULONG* PriorityIndexesOut
    )
/*++

Routine Description:

    Recover ExpBuiltinPriorities from an RVA displacement embedded in the
    bounded ExQueueWorkItem code.  The array must contain seven bounded values
    and the three supported built-in queues must map to distinct priorities.

Return Value:

    TRUE only for one matching array.

--*/
{
    ULONG_PTR routine = 0U;
    ULONG offset = 0UL;
    ULONG_PTR foundAddress = 0U;
    ULONG foundValues[3] = { 0UL, 0UL, 0UL };

    if (View == NULL || PriorityIndexesOut == NULL) {
        return FALSE;
    }
    routine = (ULONG_PTR)KswordARKRuntimeFindExport(View, "ExQueueWorkItem");
    if (routine == 0U) {
        return FALSE;
    }
    for (offset = 0UL; offset + sizeof(ULONG) <=
             KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES; ++offset) {
        ULONG candidateRva = 0UL;
        ULONG values[7];
        ULONG index = 0UL;
        ULONG_PTR candidateAddress = 0U;
        BOOLEAN valid = TRUE;

        RtlZeroMemory(values, sizeof(values));
        if (!KswordARKRuntimeAddressIsExecutable(
                View,
                routine + offset,
                sizeof(candidateRva)) ||
            !KswordARKRuntimeReadMemory(
                (const VOID*)(routine + offset),
                &candidateRva,
                sizeof(candidateRva)) ||
            candidateRva >= View->Size ||
            View->Base > MAXULONG_PTR - candidateRva) {
            continue;
        }
        candidateAddress = View->Base + candidateRva;
        if ((candidateAddress & (sizeof(ULONG) - 1U)) != 0U ||
            !KswordARKRuntimeAddressInImage(
                View,
                candidateAddress,
                sizeof(values)) ||
            KswordARKRuntimeAddressIsExecutable(View, candidateAddress, 1U) ||
            !KswordARKRuntimeReadMemory(
                (const VOID*)candidateAddress,
                values,
                sizeof(values))) {
            continue;
        }
        for (index = 0UL; index < RTL_NUMBER_OF(values); ++index) {
            if (values[index] >= KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT) {
                valid = FALSE;
                break;
            }
        }
        if (!valid || values[0] == values[1] || values[0] == values[2] ||
            values[1] == values[2]) {
            continue;
        }
        if (foundAddress != 0U && foundAddress != candidateAddress) {
            return FALSE;
        }
        foundAddress = candidateAddress;
        foundValues[0] = values[0];
        foundValues[1] = values[1];
        foundValues[2] = values[2];
    }
    if (foundAddress == 0U) {
        return FALSE;
    }
    PriorityIndexesOut[0] = foundValues[0];
    PriorityIndexesOut[1] = foundValues[1];
    PriorityIndexesOut[2] = foundValues[2];
    return TRUE;
}

static BOOLEAN
KswordARKWorkQueueFallbackQueueAddressMatches(
    _In_ ULONG_PTR Value,
    _In_ const KSW_WORK_QUEUE_CHAIN* Chain
    )
{
    ULONG nodeIndex = 0UL;

    for (nodeIndex = 0UL; nodeIndex < Chain->NodeCount; ++nodeIndex) {
        if (Value == Chain->QueueAddresses[nodeIndex]) {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
KswordARKWorkQueueFallbackAccumulateSlot(
    _Inout_ KSW_WORK_QUEUE_FALLBACK_SLOT_STATS* Slot,
    _In_ ULONG64 Value,
    _In_ BOOLEAN WorkerLike,
    _In_ ULONG64 ExpectedStart
    )
/*++

Routine Description:

    Fold one thread's value at one candidate offset into that offset's evidence.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (Value == 0ULL) {
        Slot->ZeroValues += 1UL;
    }
    if (Slot->DistinctCount < KSW_WORK_QUEUE_FALLBACK_START_DISTINCT_SLOTS) {
        for (index = 0UL; index < Slot->DistinctCount; ++index) {
            if (Slot->DistinctValues[index] == Value) {
                break;
            }
        }
        if (index == Slot->DistinctCount) {
            Slot->DistinctValues[Slot->DistinctCount] = Value;
            Slot->DistinctCount += 1UL;
        }
    }
    if (WorkerLike) {
        if (Slot->WorkerSamples == 0UL) {
            Slot->WorkerValue = Value;
        }
        else if (Slot->WorkerValue != Value) {
            Slot->WorkerConflict = TRUE;
        }
        Slot->WorkerSamples += 1UL;
    }
    if (ExpectedStart != 0ULL) {
        if (Value == ExpectedStart) {
            Slot->StartMatches += 1UL;
        }
        else {
            Slot->StartMismatches += 1UL;
        }
    }
}

static BOOLEAN
KswordARKWorkQueueFallbackInferThreadOffsets(
    _In_ const KSW_WORK_QUEUE_CHAIN* Chain,
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_opt_ const KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* Snapshot,
    _Out_ ULONG* QueueOffsetOut,
    _Out_ ULONG* StartAddressOffsetOut,
    _Out_ BOOLEAN* StartAddressResolvedOut
    )
/*++

Routine Description:

    Infer _KTHREAD.Queue and _ETHREAD.StartAddress from live System threads in
    one walk.  Queue wins by unique strongest match against the queues the
    pointer chain already validated.

    StartAddress is derived without any stored description: at the real offset
    every Ex worker thread holds one identical value - ExpWorkerThread - which
    must land inside ntoskrnl's executable range, while the same offset must
    still vary across ordinary System threads.  Pool pointers (Queue, WaitBlock
    objects, EPROCESS), data-section pointers and per-process constants all
    fail one of those three tests, and ambiguity fails closed.

    SystemProcessInformation start addresses are folded in as an extra
    constraint when the kernel hands them out; they are only a strengthener
    because unprivileged-caller hardening can zero that field.

Return Value:

    TRUE when the queue offset resolved; StartAddressResolvedOut reports the
    start-address offset separately because it is only needed for thread rows.

--*/
{
    const ULONG slotCount =
        KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN / (ULONG)sizeof(PVOID);
    KSW_WORK_QUEUE_THREAD_WALKER walker;
    KSW_WORK_QUEUE_FALLBACK_SLOT_STATS* slots = NULL;
    ULONG_PTR* values = NULL;
    BOOLEAN* readable = NULL;
    UCHAR* block = NULL;
    SIZE_T blockBytes = 0U;
    PETHREAD thread = NULL;
    ULONG threadCount = 0UL;
    ULONG expectedStartSamples = 0UL;
    ULONG slot = 0UL;
    ULONG bestQueueCount = 0UL;
    ULONG bestQueueZeros = 0UL;
    LONG bestQueueOffset = -1;
    BOOLEAN queueTied = FALSE;
    LONG startOffset = -1;
    BOOLEAN startTied = FALSE;

    if (Chain == NULL || View == NULL || QueueOffsetOut == NULL ||
        StartAddressOffsetOut == NULL || StartAddressResolvedOut == NULL) {
        return FALSE;
    }
    *QueueOffsetOut = 0UL;
    *StartAddressOffsetOut = 0UL;
    *StartAddressResolvedOut = FALSE;

    RtlZeroMemory(&walker, sizeof(walker));
    KswordARKWorkQueueInitializeThreadWalker(&walker, Snapshot);
    if (!KswordARKWorkQueueThreadWalkerUsable(&walker)) {
        return FALSE;
    }

    blockBytes = ((SIZE_T)slotCount * sizeof(*slots)) +
        ((SIZE_T)slotCount * sizeof(*values)) +
        ((SIZE_T)slotCount * sizeof(*readable));
    block = (UCHAR*)KswordARKAllocateNonPagedPool(
        blockBytes,
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (block == NULL) {
        KswordARKWorkQueueThreadWalkerClose(&walker);
        return FALSE;
    }
    RtlZeroMemory(block, blockBytes);
    slots = (KSW_WORK_QUEUE_FALLBACK_SLOT_STATS*)block;
    values = (ULONG_PTR*)(block + ((SIZE_T)slotCount * sizeof(*slots)));
    readable = (BOOLEAN*)(((UCHAR*)values) +
        ((SIZE_T)slotCount * sizeof(*values)));

    thread = KswordARKWorkQueueThreadWalkerNext(&walker);
    while (thread != NULL && threadCount < KSW_WORK_QUEUE_FALLBACK_MAX_THREADS) {
        ULONG64 expectedStart = KswordARKWorkQueueFallbackLookupStartAddress(
            Snapshot,
            HandleToULong(PsGetThreadId(thread)));
        BOOLEAN workerLike = FALSE;

        if (expectedStart != 0ULL &&
            !KswordARKWorkQueueFallbackIsKernelAddress(
                (ULONG_PTR)expectedStart)) {
            expectedStart = 0ULL;
        }
        if (expectedStart != 0ULL) {
            expectedStartSamples += 1UL;
        }

        for (slot = 0UL; slot < slotCount; ++slot) {
            readable[slot] = KswordARKRuntimeReadMemory(
                (const UCHAR*)thread + (slot * sizeof(PVOID)),
                &values[slot],
                sizeof(values[slot]));
            if (readable[slot] &&
                KswordARKWorkQueueFallbackQueueAddressMatches(
                    values[slot],
                    Chain)) {
                slots[slot].QueueMatches += 1UL;
                workerLike = TRUE;
            }
        }
        for (slot = 0UL; slot < slotCount; ++slot) {
            if (!readable[slot]) {
                continue;
            }
            KswordARKWorkQueueFallbackAccumulateSlot(
                &slots[slot],
                (ULONG64)values[slot],
                workerLike,
                expectedStart);
        }

        threadCount += 1UL;
        thread = KswordARKWorkQueueThreadWalkerNext(&walker);
    }
    KswordARKWorkQueueThreadWalkerClose(&walker);

    /*
     * _KTHREAD.Queue and the wait block object of a thread parked in
     * KeRemoveQueue can both hold the queue address, so a raw match count can
     * tie. The queue field is NULL on every System thread that never touched a
     * queue, while a wait block object is populated for anything that ever
     * waited, so the tie breaks on how often the slot reads back as NULL.
     */
    for (slot = 0UL; slot < slotCount; ++slot) {
        const KSW_WORK_QUEUE_FALLBACK_SLOT_STATS* stats = &slots[slot];

        if (stats->QueueMatches >= 2UL && stats->QueueMatches > bestQueueCount) {
            bestQueueCount = stats->QueueMatches;
        }
    }
    for (slot = 0UL; bestQueueCount != 0UL && slot < slotCount; ++slot) {
        const KSW_WORK_QUEUE_FALLBACK_SLOT_STATS* stats = &slots[slot];

        if (stats->QueueMatches != bestQueueCount) {
            continue;
        }
        if (bestQueueOffset < 0 || stats->ZeroValues > bestQueueZeros) {
            bestQueueOffset = (LONG)(slot * (ULONG)sizeof(PVOID));
            bestQueueZeros = stats->ZeroValues;
            queueTied = FALSE;
        }
        else if (stats->ZeroValues == bestQueueZeros) {
            queueTied = TRUE;
        }
    }

    for (slot = 0UL; slot < slotCount; ++slot) {
        const KSW_WORK_QUEUE_FALLBACK_SLOT_STATS* stats = &slots[slot];
        const ULONG offset = slot * (ULONG)sizeof(PVOID);
        BOOLEAN startCandidate = FALSE;

        if (expectedStartSamples >= KSW_WORK_QUEUE_FALLBACK_START_MIN_SAMPLES) {
            // 内核交出了真实起始地址，直接用零反例的逐线程比对定位偏移。
            startCandidate =
                stats->StartMismatches == 0UL &&
                stats->StartMatches >=
                    KSW_WORK_QUEUE_FALLBACK_START_MIN_SAMPLES;
        }
        else {
            // 起始地址被调用方加固抹零时，改用结构判据。
            startCandidate =
                stats->WorkerSamples >=
                    KSW_WORK_QUEUE_FALLBACK_START_MIN_WORKERS &&
                !stats->WorkerConflict &&
                stats->DistinctCount >=
                    KSW_WORK_QUEUE_FALLBACK_START_MIN_DISTINCT &&
                KswordARKWorkQueueFallbackIsKernelAddress(
                    (ULONG_PTR)stats->WorkerValue) &&
                KswordARKRuntimeAddressIsExecutable(
                    View,
                    (ULONG_PTR)stats->WorkerValue,
                    1U);
        }
        if (startCandidate) {
            if (startOffset >= 0) {
                startTied = TRUE;
            }
            else {
                startOffset = (LONG)offset;
            }
        }
    }
    ExFreePoolWithTag(block, KSW_WORK_QUEUE_FALLBACK_TAG);

    if (startOffset >= 0 && !startTied) {
        *StartAddressOffsetOut = (ULONG)startOffset;
        *StartAddressResolvedOut = TRUE;
    }
    if (bestQueueOffset < 0 || queueTied) {
        return FALSE;
    }
    *QueueOffsetOut = (ULONG)bestQueueOffset;
    return TRUE;
}

NTSTATUS
KswordARKWorkQueueResolveRuntimeLayout(
    _Out_ KSW_DYN_V4_WORK_QUEUE_LAYOUT* LayoutOut
    )
{
    static PCSTR const anchors[] = { "ExQueueWorkItem" };
    KSW_DYN_STATE state;
    KSW_RUNTIME_IMAGE_VIEW view;
    KSW_RUNTIME_DATA_REFERENCE* references = NULL;
    KSW_WORK_QUEUE_CHAIN chain;
    KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT systemThreads;
    ULONG referenceCount = 0UL;
    ULONG threadQueueOffset = 0UL;
    ULONG threadStartOffset = 0UL;
    BOOLEAN threadStartResolved = FALSE;
    BOOLEAN chainAmbiguous = FALSE;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (LayoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    RtlZeroMemory(&state, sizeof(state));
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&chain, sizeof(chain));
    RtlZeroMemory(&systemThreads, sizeof(systemThreads));
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /*
     * 签名回退只需要 ntoskrnl 的映像范围，而映像身份是无条件从已加载模块表
     * 采集的。NtosActive 表示“已应用 System Informer / PDB profile”，拿它
     * 当门槛会把这条本该无 profile 可用的回退重新绑回 PDB，
     * 于是没有 profile 时整条路径直接以 STATUS_DEVICE_NOT_READY 退出。
     */
    KswordARKDynDataSnapshot(&state);
    if (state.Ntoskrnl.imageBase == 0ULL ||
        state.Ntoskrnl.sizeOfImage == 0UL ||
        !KswordARKRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)state.Ntoskrnl.imageBase,
            state.Ntoskrnl.sizeOfImage,
            &view)) {
        return STATUS_DEVICE_NOT_READY;
    }

    references = (KSW_RUNTIME_DATA_REFERENCE*)KswordARKAllocateNonPagedPool(
        KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES * sizeof(*references),
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (references == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    referenceCount = KswordARKRuntimeCollectFunctionDataReferences( // 以 PE 函数边界约束 ExQueueWorkItem 调用链。
        &view,
        anchors,
        RTL_NUMBER_OF(anchors),
        2UL,
        KSW_WORK_QUEUE_FALLBACK_SCAN_BYTES,
        references,
        KSW_WORK_QUEUE_FALLBACK_MAX_REFERENCES);
    /*
     * 四个失败点各自返回可区分的 NTSTATUS：它们共用一个笼统的 NOT_SUPPORTED
     * 时，R3 只能看到“回退失败”，无法判断是锚点没产出引用、指针链没收敛、
     * 内建优先级表没定位，还是全局变量落在映像外。
     */
    if (referenceCount == 0UL) {
        // 锚点例程没扫出任何 RIP 相对数据引用。
        status = STATUS_NOT_FOUND;
        goto Exit;
    }
    if (!KswordARKWorkQueueFallbackFindChain(
            &view,
            references,
            referenceCount,
            &chain,
            &chainAmbiguous)) {
        // 分区 -> ExPartition -> WorkQueues 指针链没有唯一解：
        // 无任何候选通过与多条互相矛盾的链同分，是两种不同的失败，分开上报。
        status = chainAmbiguous
            ? STATUS_OBJECT_NAME_COLLISION
            : STATUS_OBJECT_PATH_NOT_FOUND;
        goto Exit;
    }
    if (!KswordARKWorkQueueFallbackFindPriorityIndexes(
            &view,
            LayoutOut->RuntimePriorityIndexes)) {
        // ExpBuiltinPriorities 未能从锚点代码的 RVA 位移还原。
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Exit;
    }
    if (chain.PartitionGlobal < view.Base ||
        chain.PartitionGlobal - view.Base > MAXULONG) {
        // 命中的全局变量不在 ntoskrnl 映像范围内。
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }

    LayoutOut->ModuleBase = view.Base;
    LayoutOut->ModuleSize = view.Size;
    LayoutOut->PspSystemPartitionRva =
        (ULONG)(chain.PartitionGlobal - view.Base);
    LayoutOut->EpartitionExPartition = chain.PartitionExPartition;
    LayoutOut->ExPartitionWorkQueues = chain.ExPartitionWorkQueues;
    LayoutOut->ExWorkQueueWorkPriQueue = 0UL;
    LayoutOut->KpriQueueEntryListHead = chain.PriQueueOffset;
    LayoutOut->WorkItemList = (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, List);
    LayoutOut->WorkItemRoutine =
        (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, WorkerRoutine);
    LayoutOut->WorkItemParameter =
        (ULONG)FIELD_OFFSET(WORK_QUEUE_ITEM, Parameter);
    LayoutOut->ExWorkQueueQueueIndex = chain.QueueIndexOffset;
    LayoutOut->ExPoolUntrusted = chain.PoolIndex;
    LayoutOut->EpartitionTypeSize = chain.PartitionExPartition + sizeof(PVOID);
    LayoutOut->ExPartitionTypeSize =
        chain.ExPartitionWorkQueues + sizeof(PVOID);
    LayoutOut->KpriQueueTypeSize = chain.PriQueueOffset +
        (KSW_WORK_QUEUE_FALLBACK_PRIORITY_COUNT * sizeof(LIST_ENTRY));
    /*
     * 队列类型大小取所有已验证字段的上界。沿用 KpriQueueTypeSize 会把
     * partition 回指和队列序号裁在结构之外，使下游的 FieldFits 校验退化成
     * “用偏移推出的大小去校验同一个偏移”，等于没有校验。
     */
    LayoutOut->ExWorkQueueTypeSize = LayoutOut->KpriQueueTypeSize;
    if (chain.PartitionBackOffset + sizeof(PVOID) >
        LayoutOut->ExWorkQueueTypeSize) {
        LayoutOut->ExWorkQueueTypeSize =
            chain.PartitionBackOffset + (ULONG)sizeof(PVOID);
    }
    if (chain.QueueIndexOffset != 0UL &&
        chain.QueueIndexOffset + sizeof(ULONG) >
            LayoutOut->ExWorkQueueTypeSize) {
        LayoutOut->ExWorkQueueTypeSize =
            chain.QueueIndexOffset + (ULONG)sizeof(ULONG);
    }
    LayoutOut->WorkItemTypeSize = sizeof(WORK_QUEUE_ITEM);
    LayoutOut->RuntimeFlags =
        KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE |
        KSW_DYN_V4_WORK_QUEUE_RUNTIME_ITEMS;

    /*
     * Worker-thread rows need _KTHREAD.Queue and _ETHREAD.StartAddress. Both
     * are inferred from live System threads here, so the thread half of this
     * page no longer depends on an applied PDB profile. A profile-supplied
     * offset is still accepted, but only when the live walk could not produce
     * its own evidence: live evidence outranks a stored description.
     */
    (VOID)KswordARKWorkQueueCaptureSystemThreads(&systemThreads);
    if (KswordARKWorkQueueFallbackInferThreadOffsets(
            &chain,
            &view,
            &systemThreads,
            &threadQueueOffset,
            &threadStartOffset,
            &threadStartResolved)) {
        if (!threadStartResolved &&
            state.Kernel.EtStartAddress != KSW_DYN_OFFSET_UNAVAILABLE &&
            (state.KernelSources.EtStartAddress ==
                 KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
             state.KernelSources.EtStartAddress ==
                 KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)) {
            threadStartOffset = state.Kernel.EtStartAddress;
            threadStartResolved = TRUE;
        }
        if (threadStartResolved) {
            LayoutOut->EthreadTcb = 0UL;
            LayoutOut->KthreadQueue = threadQueueOffset;
            LayoutOut->EthreadStartAddress = threadStartOffset;
            LayoutOut->KthreadTypeSize = threadQueueOffset + sizeof(PVOID);
            LayoutOut->EthreadTypeSize = max(
                LayoutOut->KthreadTypeSize,
                LayoutOut->EthreadStartAddress + (ULONG)sizeof(PVOID));
            LayoutOut->RuntimeFlags |= KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS;
        }
    }
    status = STATUS_SUCCESS;

Exit:
    KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
    ExFreePoolWithTag(references, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    }
    return status;
}

NTSTATUS
KswordARKWorkQueueResolveActiveExWorkerField(
    _Out_ KSW_DYN_V4_BIT_FIELD_LAYOUT* FieldOut
    )
/*++

Routine Description:

    Infer ActiveExWorker from System threads whose queue pointer matches the
    independently signature-resolved Ex queues. Worker and non-worker samples
    must produce exactly one distinguishing set bit; ambiguity fails closed.

Return Value:

    STATUS_SUCCESS for one live-validated bit, otherwise a fail-closed status.

--*/
{
    KSW_DYN_V4_WORK_QUEUE_LAYOUT layout;
    KSW_WORK_QUEUE_CHAIN chain;
    KSW_RUNTIME_IMAGE_VIEW view;
    KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT systemThreads;
    KSW_WORK_QUEUE_THREAD_WALKER walker;
    UCHAR* samples = NULL;
    UCHAR* workerSamples = NULL;
    UCHAR* otherSamples = NULL;
    ULONG workerCount = 0UL;
    ULONG otherCount = 0UL;
    ULONG threadQueueOffset = 0UL;
    ULONG threadStartOffset = 0UL;
    BOOLEAN threadStartResolved = FALSE;
    ULONG_PTR partitionGlobal = 0U;
    ULONG offset = 0UL;
    ULONG bit = 0UL;
    LONG foundOffset = -1;
    LONG foundBit = -1;
    PETHREAD thread = NULL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (FieldOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(FieldOut, sizeof(*FieldOut));
    RtlZeroMemory(&layout, sizeof(layout));
    RtlZeroMemory(&chain, sizeof(chain));
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&systemThreads, sizeof(systemThreads));
    RtlZeroMemory(&walker, sizeof(walker));
    status = KswordARKWorkQueueResolveRuntimeLayout(&layout);
    if (!NT_SUCCESS(status) ||
        (layout.RuntimeFlags & KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS) == 0UL ||
        layout.ModuleBase > MAXULONG_PTR - layout.PspSystemPartitionRva ||
        !KswordARKRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)layout.ModuleBase,
            layout.ModuleSize,
            &view)) {
        return STATUS_NOT_SUPPORTED;
    }
    partitionGlobal = (ULONG_PTR)layout.ModuleBase +
        layout.PspSystemPartitionRva;
    (VOID)KswordARKWorkQueueCaptureSystemThreads(&systemThreads);
    if (!KswordARKWorkQueueFallbackValidateChainCandidate(
            partitionGlobal,
            layout.EpartitionExPartition,
            layout.ExPartitionWorkQueues,
            layout.ExPoolUntrusted,
            &chain) ||
        !KswordARKWorkQueueFallbackInferThreadOffsets(
            &chain,
            &view,
            &systemThreads,
            &threadQueueOffset,
            &threadStartOffset,
            &threadStartResolved) ||
        threadQueueOffset != layout.KthreadQueue) {
        KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_NOT_SUPPORTED;
    }

    samples = (UCHAR*)KswordARKAllocateNonPagedPool(
        (2UL * KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) *
            KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN,
        KSW_WORK_QUEUE_FALLBACK_TAG);
    if (samples == NULL) {
        KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        samples,
        (2UL * KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) *
            KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
    workerSamples = samples;
    otherSamples = samples +
        (KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES *
         KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);

    KswordARKWorkQueueInitializeThreadWalker(&walker, &systemThreads);
    if (!KswordARKWorkQueueThreadWalkerUsable(&walker)) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }
    thread = KswordARKWorkQueueThreadWalkerNext(&walker);
    while (thread != NULL &&
           (workerCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES ||
            otherCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES)) {
        ULONG_PTR queueAddress = 0U;
        BOOLEAN worker = FALSE;
        UCHAR* destination = NULL;

        if (KswordARKRuntimeReadMemory(
                (const UCHAR*)thread + threadQueueOffset,
                &queueAddress,
                sizeof(queueAddress))) {
            worker = KswordARKWorkQueueFallbackQueueAddressMatches(
                queueAddress,
                &chain);
            if (worker && workerCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) {
                destination = workerSamples +
                    (workerCount * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
            }
            else if (!worker &&
                     otherCount < KSW_WORK_QUEUE_FALLBACK_WORKER_SAMPLES) {
                destination = otherSamples +
                    (otherCount * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN);
            }
            if (destination != NULL &&
                KswordARKRuntimeReadMemory(
                    thread,
                    destination,
                    KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN)) {
                if (worker) {
                    workerCount += 1UL;
                }
                else {
                    otherCount += 1UL;
                }
            }
        }
        thread = KswordARKWorkQueueThreadWalkerNext(&walker);
    }
    KswordARKWorkQueueThreadWalkerClose(&walker);
    if (workerCount < 2UL || otherCount < 2UL) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    for (offset = sizeof(DISPATCHER_HEADER);
         offset < KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN;
         ++offset) {
        for (bit = 0UL; bit < 8UL; ++bit) {
            UCHAR mask = (UCHAR)(1U << bit);
            ULONG sampleIndex = 0UL;
            BOOLEAN distinguishes = TRUE;

            for (sampleIndex = 0UL; sampleIndex < workerCount; ++sampleIndex) {
                if ((workerSamples[
                         sampleIndex * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN +
                         offset] & mask) == 0U) {
                    distinguishes = FALSE;
                    break;
                }
            }
            for (sampleIndex = 0UL;
                 distinguishes && sampleIndex < otherCount;
                 ++sampleIndex) {
                if ((otherSamples[
                         sampleIndex * KSW_WORK_QUEUE_FALLBACK_THREAD_SCAN +
                         offset] & mask) != 0U) {
                    distinguishes = FALSE;
                }
            }
            if (!distinguishes) {
                continue;
            }
            if (foundOffset >= 0) {
                status = STATUS_OBJECT_NAME_COLLISION;
                goto Exit;
            }
            foundOffset = (LONG)offset;
            foundBit = (LONG)bit;
        }
    }
    if (foundOffset < 0 || foundBit < 0) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }
    FieldOut->Offset = (ULONG)foundOffset;
    FieldOut->BitOffset = (ULONG)foundBit;
    FieldOut->BitCount = 1UL;
    FieldOut->StorageBytes = 1UL;
    status = STATUS_SUCCESS;

Exit:
    KswordARKWorkQueueThreadWalkerClose(&walker);
    KswordARKWorkQueueReleaseSystemThreads(&systemThreads);
    ExFreePoolWithTag(samples, KSW_WORK_QUEUE_FALLBACK_TAG);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(FieldOut, sizeof(*FieldOut));
    }
    return status;
}
