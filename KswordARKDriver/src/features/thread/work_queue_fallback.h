#pragma once

#include "../dyndata/dyndata_v4_internal.h"

EXTERN_C_START

// System 进程 TID 快照的硬上限。System 线程数远低于该值，超出部分按截断处理。
#define KSW_WORK_QUEUE_SYSTEM_THREAD_MAX 4096UL

// 一条 System 线程记录。StartAddress 取自 SystemProcessInformation，
// 只作为运行期推断 _ETHREAD.StartAddress 偏移的比对基准，不直接作为证据输出。
typedef struct _KSW_WORK_QUEUE_SYSTEM_THREAD
{
    ULONG ThreadId;
    ULONG64 StartAddress;
} KSW_WORK_QUEUE_SYSTEM_THREAD;

typedef struct _KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT
{
    ULONG Count;
    BOOLEAN Truncated;
    KSW_WORK_QUEUE_SYSTEM_THREAD* Entries;
} KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT;

typedef PETHREAD(NTAPI* KSW_WORK_QUEUE_NEXT_PROCESS_THREAD_FN)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
    );

// System 进程线程游标。ntoskrnl 并未导出 PsGetNextProcessThread，
// 因此主路径是 TID 快照 + PsLookupThreadByThreadId；若某版本确实导出了公开
// 遍历例程则优先使用它。两条路径交出的 ETHREAD 都经过对象管理器引用，
// 引用计数由游标自身持有并在下一次推进或关闭时释放，调用方不得自行解引用。
typedef struct _KSW_WORK_QUEUE_THREAD_WALKER
{
    KSW_WORK_QUEUE_NEXT_PROCESS_THREAD_FN NextProcessThread;
    const KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* Snapshot;
    ULONG NextIndex;
    BOOLEAN Finished;
    PETHREAD Current;
} KSW_WORK_QUEUE_THREAD_WALKER;

// 采集 System 进程(PID 4)的 TID / StartAddress 快照。仅 PASSIVE_LEVEL 可用。
NTSTATUS
KswordARKWorkQueueCaptureSystemThreads(
    _Out_ KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* SnapshotOut
    );

// 中文说明：复用有界 SystemProcessInformation 快照获取任意进程的真实 TID，不扫描猜测 ID。
NTSTATUS KswordARKWorkQueueCaptureProcessThreads(_In_ ULONG ProcessId,
    _Out_ KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* SnapshotOut);

VOID
KswordARKWorkQueueReleaseSystemThreads(
    _Inout_ KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* Snapshot
    );

VOID
KswordARKWorkQueueInitializeThreadWalker(
    _Out_ KSW_WORK_QUEUE_THREAD_WALKER* Walker,
    _In_opt_ const KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT* Snapshot
    );

// 游标是否具备可用的线程来源；为假时调用方应显式记为引用失败而不是空结果。
BOOLEAN
KswordARKWorkQueueThreadWalkerUsable(
    _In_ const KSW_WORK_QUEUE_THREAD_WALKER* Walker
    );

PETHREAD
KswordARKWorkQueueThreadWalkerNext(
    _Inout_ KSW_WORK_QUEUE_THREAD_WALKER* Walker
    );

VOID
KswordARKWorkQueueThreadWalkerClose(
    _Inout_ KSW_WORK_QUEUE_THREAD_WALKER* Walker
    );

NTSTATUS
KswordARKWorkQueueResolveRuntimeLayout(
    _Out_ KSW_DYN_V4_WORK_QUEUE_LAYOUT* LayoutOut
    );

NTSTATUS
KswordARKWorkQueueResolveActiveExWorkerField(
    _Out_ KSW_DYN_V4_BIT_FIELD_LAYOUT* FieldOut
    );

EXTERN_C_END
