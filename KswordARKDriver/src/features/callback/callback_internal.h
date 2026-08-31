#pragma once

#include <fltKernel.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "ark/ark_callback.h"
#include "ark/ark_log.h"

#define KSWORD_ARK_CALLBACK_TAG_RUNTIME 'rCbK'
#define KSWORD_ARK_CALLBACK_TAG_SNAPSHOT 'sCbK'
#define KSWORD_ARK_CALLBACK_TAG_PENDING 'pCbK'
#define KSWORD_ARK_CALLBACK_TAG_EXTERNAL 'xCbK'

typedef struct _KSWORD_ARK_CALLBACK_MONITOR_SLOT
{
    volatile LONG64 CommitSequence;
    KSWORD_ARK_CALLBACK_MONITOR_EVENT Event;
} KSWORD_ARK_CALLBACK_MONITOR_SLOT;

#define KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY 0x00000001UL
#define KSWORD_ARK_CALLBACK_REGISTERED_PROCESS 0x00000002UL
#define KSWORD_ARK_CALLBACK_REGISTERED_THREAD 0x00000004UL
#define KSWORD_ARK_CALLBACK_REGISTERED_IMAGE 0x00000008UL
#define KSWORD_ARK_CALLBACK_REGISTERED_OBJECT 0x00000010UL
#define KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER 0x00000020UL

typedef struct _KSWORD_ARK_CALLBACK_RULE_SNAPSHOT KSWORD_ARK_CALLBACK_RULE_SNAPSHOT;
typedef struct _KSWORD_ARK_PENDING_DECISION KSWORD_ARK_PENDING_DECISION;

typedef struct _KSWORD_ARK_CALLBACK_MATCH_RESULT
{
    BOOLEAN Matched;
    ULONG CallbackType;
    ULONG RuleOperationMask;
    ULONG Action;
    ULONG MatchMode;
    ULONG AskTimeoutMs;
    ULONG AskDefaultDecision;
    ULONG GroupId;
    ULONG RuleId;
    ULONG GroupPriority;
    ULONG RulePriority;
    WCHAR GroupName[KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS];
    WCHAR RuleName[KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS];
    WCHAR RuleInitiatorPattern[KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS];
    WCHAR RuleTargetPattern[KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS];
} KSWORD_ARK_CALLBACK_MATCH_RESULT;

typedef struct _KSWORD_ARK_CALLBACK_EVENT_INPUT
{
    ULONG CallbackType;
    ULONG OperationType;
    ULONG OriginatingPid;
    ULONG OriginatingTid;
    ULONG SessionId;
    ULONG PathUnavailable;
    UNICODE_STRING InitiatorPath;
    UNICODE_STRING TargetPath;
    KSWORD_ARK_CALLBACK_MATCH_RESULT Match;
} KSWORD_ARK_CALLBACK_EVENT_INPUT;

typedef struct _KSWORD_ARK_RUNTIME_RULE
{
    ULONG GroupId;
    ULONG RuleId;
    ULONG GroupPriority;
    ULONG RulePriority;
    ULONG CallbackType;
    ULONG OperationMask;
    ULONG Action;
    ULONG MatchMode;
    ULONG AskTimeoutMs;
    ULONG AskDefaultDecision;
    UNICODE_STRING InitiatorPattern;
    UNICODE_STRING TargetPattern;
    UNICODE_STRING GroupName;
    UNICODE_STRING RuleName;
} KSWORD_ARK_RUNTIME_RULE;

typedef struct _KSWORD_ARK_CALLBACK_RULE_SNAPSHOT
{
    EX_RUNDOWN_REF RundownRef;
    ULONG GlobalFlags;
    ULONG GroupCount;
    ULONG RuleCount;
    ULONG ActiveRuleCount;
    ULONG StringPoolBytes;
    ULONG BucketStart[KSWORD_ARK_CALLBACK_TYPE_MINIFILTER + 1];
    ULONG BucketCount[KSWORD_ARK_CALLBACK_TYPE_MINIFILTER + 1];
    ULONG64 RuleVersion;
    LARGE_INTEGER AppliedAtUtc100ns;
    KSWORD_ARK_RUNTIME_RULE Rules[1];
} KSWORD_ARK_CALLBACK_RULE_SNAPSHOT;

typedef struct _KSWORD_ARK_CALLBACK_RUNTIME
{
    WDFDEVICE Device;
    WDFQUEUE WaitQueue;

    EX_PUSH_LOCK SnapshotLock;
    KSWORD_ARK_CALLBACK_RULE_SNAPSHOT* ActiveSnapshot;

    EX_PUSH_LOCK PendingLock;
    LIST_ENTRY PendingDecisionList;
    volatile LONG PendingDecisionCount;
    // 卸载开始后拒绝创建新的等待项，确保注销回调前能够排空现有等待者。
    volatile LONG Stopping;
    volatile LONG64 EventSequence;

    LARGE_INTEGER RegistryCookie;
    PVOID ObRegistrationHandle;
    PFLT_FILTER MiniFilterHandle;
    BOOLEAN MiniFilterStarted;
    NTSTATUS MiniFilterRegisterStatus;
    NTSTATUS MiniFilterStartStatus;
    EX_PUSH_LOCK MiniFilterBypassPidLock;
    ULONG MiniFilterBypassPidCount;
    ULONG MiniFilterBypassPids[KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT];
    ULONG RegisteredCallbacksMask;
    // 遥测 ring 使用 try-lock 串行发布；争用宁可计数丢弃也不阻塞内核回调。
    volatile LONG MonitorWriterLock;
    volatile LONG MonitorCategoryMask;
    volatile LONG64 MonitorLatestSequence;
    volatile LONG64 MonitorDroppedCount;
    NTSTATUS MonitorLastStatus;
    KSWORD_ARK_CALLBACK_MONITOR_SLOT MonitorSlots[KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY];
    // 每一类回调的原始注册状态。降级启动后 R3 靠它解释某项能力为何缺失，
    // 而不是只看到一个"驱动在线但功能不全"的模糊结论。
    NTSTATUS WaitQueueStatus;
    NTSTATUS RegistryRegisterStatus;
    NTSTATUS ProcessRegisterStatus;
    NTSTATUS ThreadRegisterStatus;
    NTSTATUS ImageRegisterStatus;
    NTSTATUS ObjectRegisterStatus;
    BOOLEAN Initialized;
} KSWORD_ARK_CALLBACK_RUNTIME;

typedef struct _KSWORD_ARK_PENDING_DECISION
{
    LIST_ENTRY Link;
    LONG RefCount;
    volatile LONG Answered;
    KSWORD_ARK_GUID128 EventGuid;
    KEVENT DecisionEvent;
    ULONG FinalDecision;
    ULONG DefaultDecision;
    ULONG CallbackType;
    ULONG OperationType;
    ULONG OriginatingPid;
    ULONG OriginatingTid;
    ULONG SessionId;
    ULONG PathUnavailable;
    ULONG TimeoutMs;
    LARGE_INTEGER CreatedAtUtc100ns;
    LARGE_INTEGER DeadlineUtc100ns;
    KSWORD_ARK_CALLBACK_MATCH_RESULT Match;
    WCHAR InitiatorPath[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS];
    WCHAR TargetPath[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS];
} KSWORD_ARK_PENDING_DECISION;

typedef struct _KSWORD_ARK_CALLBACK_ENUM_BUILDER
{
    // Entries 指向当前分页的实际输出数组，容量由 METHOD_BUFFERED 长度限定。
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entries;
    ULONG EntryCapacity;
    // StartIndex 和计数器共同把全量逻辑枚举投影到当前分页。
    ULONG StartIndex;
    ULONG TotalCount;
    ULONG ReturnedCount;
    // Flags 与 LastStatus 汇总本页及完整快照状态。
    ULONG Flags;
    NTSTATUS LastStatus;
    // SnapshotRowCount 和 SnapshotHash 覆盖全部逻辑行，而不只覆盖当前页。
    ULONG SnapshotRowCount;
    ULONG64 SnapshotHash;
    // PendingEntry 在调用方填完一行后延迟计算身份哈希。
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* PendingEntry;
    // 分页范围外的行在 ScratchEntry 中构建，使其仍能参与快照哈希。
    KSWORD_ARK_CALLBACK_ENUM_ENTRY ScratchEntry;
} KSWORD_ARK_CALLBACK_ENUM_BUILDER;

typedef struct _KSWORD_ARK_CALLBACK_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} KSWORD_ARK_CALLBACK_MODULE_ENTRY;

typedef struct _KSWORD_ARK_CALLBACK_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    KSWORD_ARK_CALLBACK_MODULE_ENTRY Modules[1];
} KSWORD_ARK_CALLBACK_MODULE_INFORMATION;

typedef struct _KSWORD_ARK_CALLBACK_MODULE_CACHE
{
    KSWORD_ARK_CALLBACK_MODULE_INFORMATION* ModuleInfo;
    ULONG ModuleInfoBytes;
} KSWORD_ARK_CALLBACK_MODULE_CACHE;

EXTERN_C_START

KSWORD_ARK_CALLBACK_RUNTIME*
KswordArkCallbackGetRuntime(
    VOID
    );

VOID
KswordArkCallbackLogFrame(
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    );

VOID
KswordArkCallbackLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    );

// 初始化阶段必须使用显式 runtime 版本：全局 runtime 直到五类回调注册完毕
// 才会发布，用全局查找会让整段启动期日志被自己丢掉。
VOID
KswordArkCallbackLogFrameForRuntime(
    _In_opt_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    );

VOID
KswordArkCallbackLogFormatForRuntime(
    _In_opt_ KSWORD_ARK_CALLBACK_RUNTIME* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    );

VOID
KswordArkGetSystemTimeUtc100ns(
    _Out_ LARGE_INTEGER* utcOut
    );

VOID
KswordArkCopyUnicodeToFixedBuffer(
    _In_opt_ PCUNICODE_STRING sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    );

VOID
KswordArkCopyWideStringToFixedBuffer(
    _In_opt_z_ PCWSTR sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    );

BOOLEAN
KswordArkResolveProcessImagePath(
    _In_opt_ PEPROCESS processObject,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars,
    _Out_opt_ BOOLEAN* pathUnavailableOut
    );

ULONG
KswordArkGetProcessSessionIdSafe(
    _In_opt_ PEPROCESS processObject
    );

BOOLEAN
KswordArkGuidEquals(
    _In_ const KSWORD_ARK_GUID128* leftGuid,
    _In_ const KSWORD_ARK_GUID128* rightGuid
    );

PVOID
KswordArkAllocateNonPaged(
    _In_ SIZE_T bytes,
    _In_ ULONG poolTag
    );

VOID
KswordArkCallbackEnumCopyWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    );

VOID
KswordArkCallbackEnumCopyUnicode(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source
    );

VOID
KswordArkCallbackEnumInitModuleCache(
    _Out_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    );

VOID
KswordArkCallbackEnumFreeModuleCache(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    );

_Must_inspect_result_
NTSTATUS
KswordArkCallbackEnumEnsureModuleCache(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    );

_Must_inspect_result_
NTSTATUS
KswordArkCallbackEnumResolveModuleByAddressCached(
    _Inout_opt_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 CallbackAddress,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ ULONG64* ModuleBaseOut,
    _Out_opt_ ULONG* ModuleSizeOut
    );

BOOLEAN
KswordArkCallbackEnumIsKernelModuleAddress(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 CandidateAddress
    );

BOOLEAN
KswordArkCallbackEnumReadMemory(
    _In_ const VOID* SourceAddress,
    _Out_writes_bytes_(BytesToRead) VOID* DestinationBuffer,
    _In_ SIZE_T BytesToRead
    );

KSWORD_ARK_CALLBACK_ENUM_ENTRY*
KswordArkCallbackEnumReserveEntry(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackEnumSnapshotBegin(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackEnumSnapshotCommitPending(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackEnumSnapshotFinalize(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkCallbackEnumFinalizeModuleCached(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry
    );

VOID
KswordArkCallbackEnumAddUnsupportedRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _In_ ULONG CallbackClass,
    _In_opt_z_ PCWSTR NameText,
    _In_opt_z_ PCWSTR DetailText
    );

VOID
KswordArkCallbackEnumAddMinifilters(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

NTSTATUS
KswordArkMinifilterQueryFirstCallbackOwner(
    _In_ PFLT_FILTER FilterObject,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ ULONG64* ModuleBaseOut,
    _Out_opt_ ULONG* ModuleSizeOut
    );

VOID
KswordArkCallbackEnumAddPrivateCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    );

VOID
KswordArkGuidGenerate(
    _Out_ KSWORD_ARK_GUID128* guidOut
    );

NTSTATUS
KswordArkCallbackBuildSnapshotFromBlob(
    _In_reads_bytes_(blobBytes) const VOID* blobData,
    _In_ size_t blobBytes,
    _Outptr_ KSWORD_ARK_CALLBACK_RULE_SNAPSHOT** snapshotOut
    );

VOID
KswordArkCallbackFreeSnapshot(
    _In_opt_ KSWORD_ARK_CALLBACK_RULE_SNAPSHOT* snapshot
    );

NTSTATUS
KswordArkCallbackSwapSnapshot(
    _In_ KSWORD_ARK_CALLBACK_RULE_SNAPSHOT* newSnapshot
    );

VOID
KswordArkCallbackQueryRuntimeState(
    _Out_ KSWORD_ARK_CALLBACK_RUNTIME_STATE* runtimeStateOut
    );

NTSTATUS
KswordArkCallbackMatchRule(
    _In_ ULONG callbackType,
    _In_ ULONG operationType,
    _In_opt_ PCUNICODE_STRING initiatorPath,
    _In_opt_ PCUNICODE_STRING targetPath,
    _Out_ KSWORD_ARK_CALLBACK_MATCH_RESULT* matchResultOut
    );

NTSTATUS
KswordArkCallbackSetMinifilterBypassPids(
    _In_reads_opt_(PidCount) const ULONG* ProcessIds,
    _In_ ULONG PidCount
    );

NTSTATUS
KswordArkCallbackQueryMinifilterBypassPids(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

BOOLEAN
KswordArkCallbackIsMinifilterBypassPid(
    _In_ ULONG ProcessId
    );

NTSTATUS
KswordArkCallbackWaiterInitialize(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkCallbackWaiterUninitialize(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

NTSTATUS
KswordArkCallbackIoctlWaitEventInternal(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordArkCallbackIoctlAnswerEventInternal(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordArkCallbackCancelAllPendingInternal(
    VOID
    );

NTSTATUS
KswordArkCallbackCancelAllPendingForRuntime(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

NTSTATUS
KswordArkCallbackAskUserDecision(
    _In_ const KSWORD_ARK_CALLBACK_EVENT_INPUT* eventInput,
    _Out_ ULONG* decisionOut
    );

ULONG
KswordArkCallbackGetWaitingRequestCount(
    VOID
    );

ULONG
KswordArkCallbackGetPendingDecisionCount(
    VOID
    );

NTSTATUS
KswordArkRegistryCallbackRegister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkRegistryCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

NTSTATUS
KswordArkProcessCallbackRegister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkProcessCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

NTSTATUS
KswordArkThreadCallbackRegister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkThreadCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

NTSTATUS
KswordArkImageCallbackRegister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkImageCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

NTSTATUS
KswordArkObjectCallbackRegister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkObjectCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkMinifilterCallbackUnregister(
    _In_ KSWORD_ARK_CALLBACK_RUNTIME* runtime
    );

VOID
KswordArkMinifilterCallbackUpdateState(
    _In_opt_ PFLT_FILTER FilterHandle,
    _In_ NTSTATUS RegisterStatus,
    _In_ NTSTATUS StartStatus,
    _In_ BOOLEAN Started
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

FLT_PREOP_CALLBACK_STATUS
KswordArkMinifilterApplyRule(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG OperationType
    );

EXTERN_C_END
