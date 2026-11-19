#pragma once

#include <ntddk.h>
#include <wdf.h>

EXTERN_C_START

// Describes one isolated IOCTL implementation. The handler receives the WDF
// device/request, raw input/output byte counts, and writes the completion size.
typedef NTSTATUS
(*KSWORD_ARK_IOCTL_HANDLER)(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

// Registry row consumed by ioctl_dispatch.c. Name is for trace/log text, while
// RequiredCapability stores a KSW_CAP_* dependency used for Phase 1 fail-closed
// gating before dispatching private-offset features.
typedef struct _KSWORD_ARK_IOCTL_ENTRY
{
    ULONG IoControlCode;
    KSWORD_ARK_IOCTL_HANDLER Handler;
    const char* Name;
    ULONG64 RequiredCapability;
    ULONG Flags;
} KSWORD_ARK_IOCTL_ENTRY;

#define KSWORD_ARK_IOCTL_FLAG_NONE 0x00000000UL
// 中文说明：查询型高频 IOCTL 可设置该位，dispatch 层仅在失败/拒绝时记录完成日志。
#define KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS 0x00000001UL
// 可选的 best-effort IOCTL 可设置该位，成功与失败完成均不进入通用 R0 日志。
#define KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION 0x00000002UL
// 仅用于扫描型 IOCTL：进程在快照后退出会返回 STATUS_INVALID_CID，dispatch 层不将其当作错误记录。
#define KSWORD_ARK_IOCTL_FLAG_QUIET_INVALID_CID 0x00000004UL
// Controller entries require an exclusively opened PnP controller FDO. They
// cannot run on the primary control device or access its unrelated context.
#define KSWORD_ARK_IOCTL_FLAG_CONTROLLER_ONLY 0x00000008UL
#define KSWORD_ARK_IOCTL_CAPABILITY_NONE 0ULL

// DriverEntry 在设备可见之前建立只读请求索引，注册表导出顺序保持稳定。
VOID KswordARKInitializeIoctlIndex(VOID);

_Must_inspect_result_
const KSWORD_ARK_IOCTL_ENTRY*
KswordARKLookupIoctlEntry(
    _In_ ULONG IoControlCode
    );

ULONG
KswordARKGetRegisteredIoctlCount(
    VOID
    );

ULONG
KswordARKGetDuplicateIoctlCount(
    VOID
    );

// 中文说明：按稳定索引返回注册表项，供只读诊断 IOCTL 使用。
_Must_inspect_result_
const KSWORD_ARK_IOCTL_ENTRY*
KswordARKGetIoctlEntryByIndex(
    _In_ ULONG Index
    );

EXTERN_C_END
