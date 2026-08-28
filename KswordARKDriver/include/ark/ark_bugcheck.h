#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkBugcheckIoctl.h"

EXTERN_C_START

// Build gate for the complete driver-side blue screen diagnostic path. The
// default development image enables it; this does not affect the rest of the
// driver, Windows' native blue screen, dump creation, or user-mode dump UI.
#ifndef KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
#define KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED 1
#endif

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED != 0 && \
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED != 1
#error KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED must be 0 or 1
#endif

// 轻量控制器只保存驱动对象并初始化同步原语，不解析 ntoskrnl 或注册蓝屏回调。
// DriverEntry 调用 Initialize，驱动卸载前调用 Uninitialize；实际诊断由配置 IOCTL 按需安装。
NTSTATUS
KswordARKBugcheckControlInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ WDFDEVICE ControlDevice
    );

VOID
KswordARKBugcheckControlUninitialize(
    VOID
    );

// Resolve the physical-machine BGP backend, prepare every crash-time rectangle
// at PASSIVE_LEVEL, and register dump-preserving bugcheck callbacks. Missing
// private features leave the renderer fail-closed without blocking diagnostics.
NTSTATUS
KswordARKBugcheckInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ WDFDEVICE ControlDevice
    );

// Deregister callbacks before destroying the prebuilt BGP rectangles.
VOID
KswordARKBugcheckUninitialize(
    VOID
    );

// Feed the crash-safe process/module identity caches from the driver's existing
// notify callbacks. Writers run before a crash; the bugcheck path only reads
// fixed nonpaged snapshots and never dereferences an arbitrary crash parameter.
VOID
KswordARKBugcheckTrackProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

VOID
KswordARKBugcheckTrackLoadedImage(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

NTSTATUS
KswordARKBugcheckIoctlConfigureDiagnostics(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

// Optional bitmap upload adapter registered through ioctl_registry.c.
NTSTATUS
KswordARKBugcheckIoctlSetBitmap(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
KswordARKBugcheckIoctlSetVerdictResources(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );


// Initialize and tear down the independent one-shot BugCheck delay guard.
// HVCI systems use a delay-only callback; other systems may use the exported
// KeBugCheckEx entry hook and must restore it before driver unload. The guard
// is intentionally not coupled to the optional VMware panel.
VOID
KswordARKBugcheckGuardInitialize(
    VOID
    );

VOID
KswordARKBugcheckGuardUninitialize(
    VOID
    );

NTSTATUS
KswordARKBugcheckGuardIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

// Bugcheck Shield is a PatchGuard-safe buffer backend. Unlike the guard, it
// never patches KeBugCheckEx and never writes any private ntoskrnl state; it
// only registers up to four documented BugCheck reason callbacks and stalls
// each callback for a configurable, bounded window. Enabling and disabling
// stay fully R3-controlled, and DriverEntry only prepares the synchronization
// primitives — nothing observable happens until an IOCTL explicitly enables it.
VOID
KswordARKBugcheckShieldInitialize(
    VOID
    );

VOID
KswordARKBugcheckShieldUninitialize(
    VOID
    );

NTSTATUS
KswordARKBugcheckShieldIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

// Anti-BSOD reference implementation. Behaviorally reproduces the algorithm
// documented in the Disable-PatchGuard-BSOD.sys IDA analysis. The compile
// flag KSWORD_ARK_ANTIBSOD_REFERENCE_ENABLED gates the entire module and
// is OFF by default; when off, every entry point below is a no-op that
// returns STATUS_NOT_SUPPORTED. When on, the module still ships with an
// empty signature table so Install fails closed unless the operator adds
// build-specific ntoskrnl patterns manually. This is deliberate: publishing
// runnable private-slot signatures is outside the KSword scope.
VOID
KswordARKAntiBsodInitialize(
    VOID
    );

VOID
KswordARKAntiBsodUninitialize(
    VOID
    );

NTSTATUS
KswordARKAntiBsodIoctlConfigure(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );
EXTERN_C_END

