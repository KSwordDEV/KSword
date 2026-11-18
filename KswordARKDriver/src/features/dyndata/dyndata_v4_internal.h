#pragma once

#include "ark/ark_dyndata.h"

EXTERN_C_START

// Per-capability-group v4 state. The public row is stored directly so query
// IOCTLs can copy stable coverage counters without recomputing them.
typedef struct _KSW_DYN_V4_GROUP_STATE
{
    KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY PublicEntry;
} KSW_DYN_V4_GROUP_STATE;

// Per-loaded-module v4 profile state. Occupied marks whether a module profile
// has passed identity validation, StoredItemCount bounds Items, PublicEntry is
// the module status returned to R3, Groups holds derived capability coverage,
// and Items preserves the accepted compact PDB facts for future consumers.
typedef struct _KSW_DYN_V4_MODULE_STATE
{
    BOOLEAN Occupied;
    ULONG StoredItemCount;
    KSW_DYN_V4_MODULE_STATUS_ENTRY PublicEntry;
    KSW_DYN_V4_GROUP_STATE Groups[KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE];
    KSW_DYN_V4_ITEM_PACKET Items[KSW_DYN_V4_MAX_ITEMS_PER_MODULE];
} KSW_DYN_V4_MODULE_STATE;

// Global v4 state. Modules is indexed by the compact v4 module-slot mapping,
// Missing stores bounded required/optional diagnostics, and MissingCount bounds
// the number of valid Missing rows.
typedef struct _KSW_DYN_V4_STATE
{
    KSW_DYN_V4_MODULE_STATE Modules[KSW_DYN_V4_MAX_MODULES];
    KSW_DYN_V4_MISSING_ITEM_ENTRY Missing[KSW_DYN_V4_MAX_MISSING_SUMMARY];
    ULONG MissingCount;
} KSW_DYN_V4_STATE;

extern EX_PUSH_LOCK g_KswordDynDataV4Lock;
extern KSW_DYN_V4_STATE g_KswordDynDataV4State;

// Copies only the fields consumed by the three read-only enumeration queries.
typedef struct _KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT {
    ULONG Pid, ActiveLinks, ThreadHead, Cid, ThreadEntry, ThreadStart, ThreadProcess;
    ULONG VadRoot, VadHint, VadCount;
} KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT;
NTSTATUS KswordARKDynDataV4VerifyProcessObserverProfile(
    _In_ const KSW_APPLY_DYN_PROFILE_V4_REQUEST* Request,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* Loaded);
BOOLEAN KswordARKDynDataV4SnapshotProcessObserver(_Out_ KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT* Layout);

// Timer/DPC 消费者只接收完成的一次性布局快照，不直接持有 v4 全局锁。
typedef struct _KSW_DYN_V4_TIMER_DPC_LAYOUT
{
    ULONG KprcbTimerTable;
    ULONG TimerTableTimerEntries;
    ULONG TimerTableEntryLock;
    ULONG TimerTableEntryEntry;
    ULONG TimerTableEntryTime;
    ULONG TimerTimerListEntry;
    ULONG TimerDueTime;
    ULONG TimerDpc;
    ULONG TimerType;
    ULONG TimerPeriod;
    ULONG DpcDeferredRoutine;
    ULONG DpcDeferredContext;
    ULONG TimerTableTypeSize;
    ULONG TimerTableEntryTypeSize;
    ULONG TimerTypeSize;
    ULONG DpcTypeSize;
} KSW_DYN_V4_TIMER_DPC_LAYOUT;

// Minifilter 回调枚举只消费 _FLT_FILTER.Operations，不直接持有 v4 状态锁。
typedef struct _KSW_DYN_V4_FLTMGR_MINIFILTER_LAYOUT
{
    ULONG FltFilterOperations;
} KSW_DYN_V4_FLTMGR_MINIFILTER_LAYOUT;

// 位域消费者使用固定快照，Offset 是对象内存偏移，BitOffset/BitCount 描述
// StorageBytes 宽度整数中的位范围。
typedef struct _KSW_DYN_V4_BIT_FIELD_LAYOUT
{
    ULONG Offset;
    ULONG BitOffset;
    ULONG BitCount;
    ULONG StorageBytes;
} KSW_DYN_V4_BIT_FIELD_LAYOUT;

// CI 哈希缓存消费者只接收已完成身份校验的一次性布局快照。
// Global 字段保存相对 ci.dll/ci.sys 当前映像基址的 RVA。
typedef struct _KSW_DYN_V4_CI_KERNEL_HASH_LAYOUT
{
    ULONGLONG ModuleBase;
    ULONG ModuleSize;
    ULONG KernelHashBucketListRva;
    ULONG HashCacheLockRva;
    ULONG EntryNext;
    ULONG EntryDriverName;
    ULONG EntryTimeDateStamp;
    ULONG EntryLoadStatus;
    ULONG EntryImageBase;
    ULONG EntryImageSize;
    ULONG EntryTypeSize;
} KSW_DYN_V4_CI_KERNEL_HASH_LAYOUT;

// Ex 工作队列消费者只接收与当前 ntoskrnl PE/PDB 身份匹配的完整布局。
// Global 字段为当前映像 RVA；其余字段均为 PDB 结构偏移、类型大小或枚举值。
typedef struct _KSW_DYN_V4_WORK_QUEUE_LAYOUT
{
    ULONGLONG ModuleBase;
    ULONG ModuleSize;
    ULONG PspSystemPartitionRva;
    ULONG ExpBuiltinPrioritiesRva;
    ULONG EpartitionExPartition;
    ULONG ExPartitionWorkQueues;
    ULONG ExWorkQueueWorkPriQueue;
    ULONG ExWorkQueueQueueIndex;
    ULONG KpriQueueEntryListHead;
    ULONG KpriQueueThreadListHead;
    ULONG KthreadQueue;
    ULONG KthreadQueueListEntry;
    ULONG EthreadTcb;
    ULONG EthreadStartAddress;
    ULONG WorkItemList;
    ULONG WorkItemRoutine;
    ULONG WorkItemParameter;
    ULONG ExPoolUntrusted;
    ULONG EpartitionTypeSize;
    ULONG ExPartitionTypeSize;
    ULONG ExWorkQueueTypeSize;
    ULONG KpriQueueTypeSize;
    ULONG KthreadTypeSize;
    ULONG EthreadTypeSize;
    ULONG WorkItemTypeSize;
    ULONG RuntimeFlags;
    ULONG RuntimePriorityIndexes[3];
} KSW_DYN_V4_WORK_QUEUE_LAYOUT;

#define KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE 0x00000001UL
#define KSW_DYN_V4_WORK_QUEUE_RUNTIME_ITEMS     0x00000002UL
#define KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS   0x00000004UL

NTSTATUS
KswordARKDynDataV4SnapshotTimerDpcLayout(
    _Out_ KSW_DYN_V4_TIMER_DPC_LAYOUT* LayoutOut
    );

// 获取与当前 fltMgr.sys 身份精确匹配的 _FLT_FILTER.Operations 偏移。
NTSTATUS
KswordARKDynDataV4SnapshotFltMgrMinifilterLayout(
    _Out_ KSW_DYN_V4_FLTMGR_MINIFILTER_LAYOUT* LayoutOut
    );

// 线程消费者获取 _ETHREAD.ActiveExWorker 的精确 PDB 位域布局。
NTSTATUS
KswordARKDynDataV4SnapshotActiveExWorkerField(
    _Out_ KSW_DYN_V4_BIT_FIELD_LAYOUT* FieldOut
    );

// 获取与当前 ci.dll/ci.sys 身份精确匹配的只读内核哈希缓存布局。
NTSTATUS
KswordARKDynDataV4SnapshotCiKernelHashLayout(
    _Out_ KSW_DYN_V4_CI_KERNEL_HASH_LAYOUT* LayoutOut
    );

// 获取当前 ntoskrnl 精确 PDB 描述的 Ex 工作队列布局；任一必需项缺失即不支持。
NTSTATUS
KswordARKDynDataV4SnapshotWorkQueueLayout(
    _Out_ KSW_DYN_V4_WORK_QUEUE_LAYOUT* LayoutOut
    );

// 枚举当前已加载且受 v4 支持的模块身份，并叠加已经应用的 profile 状态。
ULONG
KswordARKDynDataV4BuildModuleStatusSnapshot(
    _Out_writes_opt_(EntryCapacity) KSW_DYN_V4_MODULE_STATUS_ENTRY* Entries,
    _In_ ULONG EntryCapacity,
    _Out_ ULONG* TotalCountOut
    );

EXTERN_C_END
