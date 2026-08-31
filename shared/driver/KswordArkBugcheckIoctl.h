#pragma once

#include "KswordArkProcessIoctl.h"

// Optional R3 -> R0 packets for the on-demand BGP blue-screen diagnostics,
// VMware legacy bitmap resources, and the explicitly-confirmed one-shot guard.
// The diagnostic feature itself is detected and enabled entirely in R0.
#ifndef FILE_WRITE_ACCESS
#define FILE_WRITE_ACCESS 0x0002
#endif

#define KSWORD_ARK_BUGCHECK_BITMAP_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_BUGCHECK_BITMAP_MAGIC 0x4942534BUL /* 'KSBI' */
#define KSWORD_ARK_BUGCHECK_BITMAP_FORMAT_BGRA32 1UL

#define KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH 1024UL
#define KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT 384UL
#define KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES \
    (KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH * \
     KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT * 4UL)

#define KSWORD_ARK_IOCTL_FUNCTION_SET_BUGCHECK_BITMAP 0x8FAUL

#define IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_BUGCHECK_BITMAP, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_BUGCHECK_BITMAP_HEADER
{
    unsigned long version;
    unsigned long size;
    unsigned long magic;
    unsigned long width;
    unsigned long height;
    unsigned long stride;
    unsigned long format;
    unsigned long brandColorRgb;
    unsigned long dataLength;
    unsigned long flags;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_BUGCHECK_BITMAP_HEADER;

// Localized verdict cards are rendered by the Qt client with the system UI
// font, then parsed into BGP rectangles by the driver at PASSIVE_LEVEL.  The
// complete English/Chinese set is installed atomically so the crash callback
// never observes a partially updated resource table.
#define KSWORD_ARK_BUGCHECK_VERDICT_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_BUGCHECK_VERDICT_MAGIC 0x5256534BUL /* 'KSVR' */
#define KSWORD_ARK_BUGCHECK_VERDICT_FORMAT_BGRA32 1UL

#define KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_ENGLISH 0UL
#define KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_CHINESE 1UL
#define KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT 2UL

#define KSWORD_ARK_BUGCHECK_VERDICT_CLASS_UNKNOWN 0UL
#define KSWORD_ARK_BUGCHECK_VERDICT_CLASS_OURS 1UL
#define KSWORD_ARK_BUGCHECK_VERDICT_CLASS_MICROSOFT 2UL
#define KSWORD_ARK_BUGCHECK_VERDICT_CLASS_THIRD_PARTY 3UL
#define KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT 4UL

#define KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT \
    (KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT * \
     KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT)
#define KSWORD_ARK_BUGCHECK_VERDICT_MAX_WIDTH 320UL
#define KSWORD_ARK_BUGCHECK_VERDICT_MAX_HEIGHT 128UL
#define KSWORD_ARK_BUGCHECK_VERDICT_MAX_DATA_BYTES \
    (KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT * \
     KSWORD_ARK_BUGCHECK_VERDICT_MAX_WIDTH * \
     KSWORD_ARK_BUGCHECK_VERDICT_MAX_HEIGHT * 4UL)

#define KSWORD_ARK_IOCTL_FUNCTION_SET_BUGCHECK_VERDICT_RESOURCES 0x8FCUL

#define IOCTL_KSWORD_ARK_SET_BUGCHECK_VERDICT_RESOURCES \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_BUGCHECK_VERDICT_RESOURCES, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER
{
    unsigned long version;
    unsigned long size;
    unsigned long magic;
    unsigned long resourceCount;
    unsigned long entriesOffset;
    unsigned long totalSize;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER;

typedef struct _KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY
{
    unsigned long language;
    unsigned long classification;
    unsigned long width;
    unsigned long height;
    unsigned long stride;
    unsigned long format;
    unsigned long dataOffset;
    unsigned long dataLength;
} KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY;

// 蓝屏诊断的 BGP 解析、页面预生成与转储回调默认不在 DriverEntry 执行。
// INSTALL 只排队 R0 工作项并返回 BUSY；R3 通过 QUERY 轮询 OK 或失败终态。
// 工作项有 30 秒内核预算，驱动卸载会请求取消并排空工作项后再释放回调与资源。
// v2 changes INSTALL from a synchronous operation to an enqueue-and-query contract.
// The version bump makes a new R3 client fail fast against a loaded v1 driver instead of
// entering that driver's unbounded synchronous installation path.
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_PROTOCOL_VERSION 2UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONFIGURE_BUGCHECK_DIAGNOSTICS 0x8FDUL

#define IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_DIAGNOSTICS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONFIGURE_BUGCHECK_DIAGNOSTICS, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_QUERY   0UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL 1UL

#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK                 0UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INACTIVE           1UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY               2UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_UNSUPPORTED        3UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_PREPARATION_FAILED 4UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_INVALID_REQUEST    5UL

#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_INSTALLED          0x00000001UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_CALLBACKS_READY    0x00000002UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_BGP_BACKEND_READY  0x00000004UL
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATE_PANEL_READY        0x00000008UL

// 固定长度请求仅区分查询和本次驱动生命周期内的安装，不提供常驻卸载动作。
typedef struct _KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long action;
    unsigned long flags;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST;

// 响应保留回调与 BGP 准备摘要，R3 可展示失败阶段但不重新解释私有内核地址。
typedef struct _KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long status;
    unsigned long stateFlags;
    long lastStatus;
    unsigned long callbackMask;
    unsigned long bgpState;
    unsigned long bgpPreparationStage;
    long bgpPreparationStatus;
    long panelStatus;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE;

// The delay guard is deliberately separate from the VMware display panel.
// On systems where HVCI protects kernel code it uses a supported BugCheck
// callback as a delay-only backend. Otherwise it can intercept the exported
// KeBugCheckEx entry for one bugcheck and restore the entry before forwarding
// the call or attempting an unsupported return. Neither backend is a
// crash-recovery API.
#define KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION 4UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONFIGURE_BUGCHECK_GUARD 0x8FBUL

#define IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONFIGURE_BUGCHECK_GUARD, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY   0UL
#define KSWORD_ARK_BUGCHECK_GUARD_ACTION_ENABLE  1UL
#define KSWORD_ARK_BUGCHECK_GUARD_ACTION_DISABLE 2UL

#define KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED     0x00000001UL
#define KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR 0x00000002UL
#define KSWORD_ARK_BUGCHECK_GUARD_CONFIRMATION_TOKEN 0x4452474BUL /* 'KGRD' */
#define KSWORD_ARK_BUGCHECK_GUARD_MIN_DELAY_SECONDS 1UL
// delaySeconds accepts any nonzero value representable by its ULONG field.

#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_OK                  0UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE            1UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE              2UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFIRMATION_NEEDED 3UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_UNSUPPORTED          4UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFLICT            5UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_PATCH_FAILED        6UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY                7UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATUS_INVALID_REQUEST     8UL

#define KSWORD_ARK_BUGCHECK_GUARD_STATE_TARGET_RESOLVED  0x00000001UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE           0x00000002UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_PATCH_INSTALLED  0x00000004UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED            0x00000008UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_PREEXISTING_HOOK 0x00000010UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_TRY_IGNORE_ERROR 0x00000020UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_ERROR_IGNORED    0x00000040UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_HOOK_EXECUTING   0x00000080UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_HVCI_ENABLED      0x00000100UL
#define KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED 0x00000200UL

// 补丁快照属于固定线协议，Win32 R3 也必须与 x64 R0 保持相同的响应布局。
#define KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES 12UL

typedef struct _KSWORD_ARK_BUGCHECK_GUARD_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long action;
    unsigned long flags;
    unsigned long delaySeconds;
    unsigned long confirmationToken;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_BUGCHECK_GUARD_REQUEST;

typedef struct _KSWORD_ARK_BUGCHECK_GUARD_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long status;
    unsigned long stateFlags;
    unsigned long delaySeconds;
    long lastStatus;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long targetAddress;
    unsigned char originalBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
    unsigned char hookBytes[KSWORD_ARK_BUGCHECK_GUARD_HOOK_BYTES];
} KSWORD_ARK_BUGCHECK_GUARD_RESPONSE;

// Bugcheck Shield: PatchGuard-safe multi-stage bugcheck buffer.
//
// The Shield is an alternative buffer backend inspired by publicly circulated
// reverse-engineering notes on private-slot bugcheck-suppression drivers.
// Those samples hook undocumented ntoskrnl function-pointer slots and wait
// forever on unsignaled events; that design fails Windows integrity checks
// and cannot be presented as a supported feature. The Shield instead uses
// only documented KeRegisterBugCheckCallback / KeRegisterBugCheckReasonCallback
// entry points. PatchGuard has no visibility into these APIs, so the Shield
// is guaranteed to leave the kernel image untouched.
//
// The Shield stages a bounded delay across up to four reason callbacks so
// external observers (screenshot capture, out-of-band logging, remote
// telemetry) receive a longer window before the actual reboot. It never
// modifies private kernel state, never suppresses the underlying bugcheck,
// and always yields control back to Windows so a normal dump can be written.
#define KSWORD_ARK_BUGCHECK_SHIELD_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONFIGURE_BUGCHECK_SHIELD 0x8FEUL

#define IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_SHIELD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONFIGURE_BUGCHECK_SHIELD, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// Fixed-length action set. QUERY inspects state without altering it; ENABLE
// registers all requested reason callbacks; DISABLE deregisters everything
// and drains any in-flight callback invocations before returning.
#define KSWORD_ARK_BUGCHECK_SHIELD_ACTION_QUERY   0UL
#define KSWORD_ARK_BUGCHECK_SHIELD_ACTION_ENABLE  1UL
#define KSWORD_ARK_BUGCHECK_SHIELD_ACTION_DISABLE 2UL

// Enabling the Shield requires an explicit UI confirmation flag plus a
// well-known token, mirroring the KSword guard contract. This prevents an
// accidental or headless enable from installing crash-time callbacks.
#define KSWORD_ARK_BUGCHECK_SHIELD_FLAG_UI_CONFIRMED  0x00000001UL
#define KSWORD_ARK_BUGCHECK_SHIELD_CONFIRMATION_TOKEN 0x4C48534BUL /* 'KSHL' */

// Callback reason bitmask. R3 selects which reasons to register; every
// selected reason must succeed or the enable fails atomically.
#define KSWORD_ARK_BUGCHECK_SHIELD_REASON_CLASSIC              0x00000001UL
#define KSWORD_ARK_BUGCHECK_SHIELD_REASON_SECONDARY_DUMP_DATA  0x00000002UL
#define KSWORD_ARK_BUGCHECK_SHIELD_REASON_DUMP_IO              0x00000004UL
#define KSWORD_ARK_BUGCHECK_SHIELD_REASON_ADD_PAGES            0x00000008UL
#define KSWORD_ARK_BUGCHECK_SHIELD_REASON_ALL \
    (KSWORD_ARK_BUGCHECK_SHIELD_REASON_CLASSIC | \
     KSWORD_ARK_BUGCHECK_SHIELD_REASON_SECONDARY_DUMP_DATA | \
     KSWORD_ARK_BUGCHECK_SHIELD_REASON_DUMP_IO | \
     KSWORD_ARK_BUGCHECK_SHIELD_REASON_ADD_PAGES)

// Buffer budgets. Each active callback contributes up to per-stage seconds
// of stall; the total is capped so a slow storage stack or watchdog cannot
// be starved. Values are validated in the driver and clamped as required.
#define KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MIN_SECONDS  0UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STAGE_MAX_SECONDS  8UL
#define KSWORD_ARK_BUGCHECK_SHIELD_TOTAL_MAX_SECONDS  16UL
#define KSWORD_ARK_BUGCHECK_SHIELD_DEFAULT_STAGE_SECONDS 3UL
#define KSWORD_ARK_BUGCHECK_SHIELD_DEFAULT_TOTAL_SECONDS 10UL

// Status codes returned to R3. INACTIVE and ACTIVE describe the primary
// mode; the remaining values describe why an enable was refused.
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_OK                  0UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INACTIVE            1UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_ACTIVE              2UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_CONFIRMATION_NEEDED 3UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_UNSUPPORTED         4UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_BUSY                5UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_REGISTRATION_FAILED 6UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATUS_INVALID_REQUEST     7UL

// State flag bitmap: mirrors what the Shield has actually installed.
#define KSWORD_ARK_BUGCHECK_SHIELD_STATE_ACTIVE                0x00000001UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATE_FIRED                 0x00000002UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATE_CLASSIC_REGISTERED    0x00000004UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATE_SECONDARY_REGISTERED  0x00000008UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATE_DUMPIO_REGISTERED     0x00000010UL
#define KSWORD_ARK_BUGCHECK_SHIELD_STATE_ADDPAGES_REGISTERED   0x00000020UL

// Bounded timeline reported back to R3. Each callback records reason id,
// bug-check code, CPU and 100ns duration. The ring is intentionally small
// and only committed after the callback returns.
#define KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES 16UL

typedef struct _KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRY
{
    unsigned long reason;
    unsigned long bugcheckCode;
    unsigned long cpu;
    unsigned long stalledMilliseconds;
} KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRY;

// Request layout. Fields default to 0; ENABLE fills reasonMask plus stage
// and total seconds. Reserved fields must be zero and are rejected otherwise
// so future versions can safely repurpose them.
typedef struct _KSWORD_ARK_BUGCHECK_SHIELD_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long action;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long reasonMask;
    unsigned long stageSeconds;
    unsigned long totalSeconds;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_BUGCHECK_SHIELD_REQUEST;

// Response layout. The Shield never returns raw kernel pointers.
typedef struct _KSWORD_ARK_BUGCHECK_SHIELD_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long status;
    unsigned long stateFlags;
    unsigned long reasonMask;
    unsigned long stageSeconds;
    unsigned long totalSeconds;
    unsigned long fireCount;
    unsigned long timelineCount;
    long lastStatus;
    unsigned long reserved0;
    unsigned long reserved1;
    KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRY timeline
        [KSWORD_ARK_BUGCHECK_SHIELD_TIMELINE_ENTRIES];
} KSWORD_ARK_BUGCHECK_SHIELD_RESPONSE;


