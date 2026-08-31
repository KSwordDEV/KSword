#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkCallbackIoctl.h"
#include "driver/KswordArkCallbackMonitorIoctl.h"

EXTERN_C_START

// 回调热路径使用轻量输入描述符，遥测运行时负责把文本复制到固定 ring slot。
typedef struct _KSWORD_ARK_CALLBACK_MONITOR_EVENT_INPUT
{
    ULONG Category;
    ULONG Operation;
    ULONG Flags;
    NTSTATUS ResultStatus;
    ULONG OriginatingProcessId;
    ULONG OriginatingThreadId;
    ULONG TargetProcessId;
    ULONG TargetThreadId;
    ULONG ParentProcessId;
    ULONG SessionId;
    ULONG OriginalAccess;
    ULONG DesiredAccess;
    ULONG ObjectType;
    ULONG DetailCode;
    ULONG64 Address;
    ULONG64 RegionSize;
    PCUNICODE_STRING ProcessName;
    PCUNICODE_STRING Path;
} KSWORD_ARK_CALLBACK_MONITOR_EVENT_INPUT;

// 返回 STATUS_SUCCESS 表示全部回调都注册成功；返回失败状态表示回调层已经
// 降级运行，调用方必须继续加载驱动而不是把它当成致命错误。
NTSTATUS
KswordARKCallbackInitialize(
    _In_ WDFDEVICE Device
    );

// 当前实际注册成功的 KSWORD_ARK_CALLBACK_REGISTERED_* 能力位。
ULONG
KswordARKCallbackGetRegisteredMask(
    VOID
    );

VOID
KswordARKCallbackUninitialize(
    VOID
    );

NTSTATUS
KswordARKCallbackIoctlSetRules(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlGetRuntimeState(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlWaitEvent(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlAnswerEvent(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlCancelAllPending(
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlRemoveExternalCallback(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlRemoveExternalCallbackEx(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlEnumCallbacks(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlSetMinifilterBypassPids(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

NTSTATUS
KswordARKCallbackIoctlQueryMinifilterBypassPids(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

BOOLEAN
KswordArkCallbackIsMinifilterBypassPid(
    _In_ ULONG ProcessId
    );

// 仅检查原子类别掩码；关闭类别时调用方应尽早返回，避免额外路径解析。
BOOLEAN
KswordArkCallbackMonitorIsEnabled(
    _In_ ULONG Category
    );

// 把一条结构化事件提交到固定环形缓冲；争用时丢弃而不等待。
VOID
KswordArkCallbackMonitorPublish(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_EVENT_INPUT* EventInput
    );

NTSTATUS
KswordArkCallbackMonitorControl(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST* Request,
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* Response
    );

NTSTATUS
KswordArkCallbackMonitorQuery(
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* Response
    );

NTSTATUS
KswordArkCallbackMonitorRead(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

EXTERN_C_END
