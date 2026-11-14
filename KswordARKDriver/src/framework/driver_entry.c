/*++

Module Name:

    driver_entry.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "ark/ark_mutation.h"
#include "src/features/kernel/kernel_idt_baseline.h"
#include "src/features/hvm/hvm_runtime.h"
#include "src/features/debugger/debugger.h"
#include "src/features/rxpf/rxpf_runtime.h"
#include "src/features/storage_controller/controller.h"
#include "driver_entry.tmh"

typedef struct _KSWORD_ARK_CORE_LIFECYCLE {
    EX_PUSH_LOCK Lock;
    KSPIN_LOCK DeviceLock;
    LIST_ENTRY ControllerDevices;
    EX_RUNDOWN_REF Requests;
    KEVENT ShutdownDone;
    WDFDRIVER Driver;
    PDRIVER_OBJECT DriverObject;
    UNICODE_STRING RegistryPath;
    WDFDEVICE ControlDevice;
    ULONG ControllerCount;
    BOOLEAN PnpProfile;
    BOOLEAN EarlyInitialized;
    BOOLEAN LateInitialized;
    volatile LONG Retiring;
    volatile LONG Ready;
    volatile LONG ShutdownStarted;
} KSWORD_ARK_CORE_LIFECYCLE;

static KSWORD_ARK_CORE_LIFECYCLE g_KswordArkCore;
static volatile LONG g_KswordArkTracingActive;
static NTSTATUS KswordARKDriverStartCore(_In_ WDFDRIVER Driver);
static VOID KswordARKDriverShutdownCore(VOID);

/* An optional INF selects PnP before the image is loaded. Default stays SCM. */
static NTSTATUS
KswordARKDriverReadPnpProfile(
    _In_ PUNICODE_STRING RegistryPath,
    _Out_ BOOLEAN* PnpProfile)
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE serviceKey = NULL;
    HANDLE parametersKey = NULL;
    UNICODE_STRING parametersName = RTL_CONSTANT_STRING(L"Parameters");
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"StorageControllerPnP");
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION value = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG resultBytes = 0U;
    ULONG mode = 0U;
    NTSTATUS status;

    *PnpProfile = FALSE;
    InitializeObjectAttributes(&attributes, RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&serviceKey, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    InitializeObjectAttributes(&attributes, &parametersName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, serviceKey, NULL);
    status = ZwOpenKey(&parametersKey, KEY_QUERY_VALUE, &attributes);
    ZwClose(serviceKey);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) {
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ZwQueryValueKey(parametersKey, &valueName, KeyValuePartialInformation,
        buffer, sizeof(buffer), &resultBytes);
    ZwClose(parametersKey);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (resultBytes < FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(mode) ||
        value->Type != REG_DWORD || value->DataLength != sizeof(mode)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(&mode, value->Data, sizeof(mode));
    if (mode > 1U) {
        return STATUS_INVALID_PARAMETER;
    }
    *PnpProfile = mode != 0U;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverInitializeCoreLifecycle(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    RtlZeroMemory(&g_KswordArkCore, sizeof(g_KswordArkCore));
    ExInitializePushLock(&g_KswordArkCore.Lock);
    KeInitializeSpinLock(&g_KswordArkCore.DeviceLock);
    InitializeListHead(&g_KswordArkCore.ControllerDevices);
    ExInitializeRundownProtection(&g_KswordArkCore.Requests);
    KeInitializeEvent(&g_KswordArkCore.ShutdownDone, NotificationEvent, FALSE);
    g_KswordArkCore.DriverObject = DriverObject;
    status = KswordARKDriverReadPnpProfile(RegistryPath, &g_KswordArkCore.PnpProfile);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (RegistryPath->Length > MAXUSHORT - sizeof(WCHAR)) {
        return STATUS_NAME_TOO_LONG;
    }
    g_KswordArkCore.RegistryPath.MaximumLength =
        (USHORT)(RegistryPath->Length + sizeof(WCHAR));
    g_KswordArkCore.RegistryPath.Buffer = KswordARKAllocateNonPagedPool(
        g_KswordArkCore.RegistryPath.MaximumLength, 'lfSK');
    if (g_KswordArkCore.RegistryPath.Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_KswordArkCore.RegistryPath.Buffer,
        g_KswordArkCore.RegistryPath.MaximumLength);
    RtlCopyMemory(g_KswordArkCore.RegistryPath.Buffer,
        RegistryPath->Buffer, RegistryPath->Length);
    g_KswordArkCore.RegistryPath.Length = RegistryPath->Length;
    return STATUS_SUCCESS;
}

BOOLEAN
KswordARKDriverCoreEnterRequest(VOID)
{
    if (g_KswordArkCore.Retiring || !g_KswordArkCore.Ready ||
        !ExAcquireRundownProtection(&g_KswordArkCore.Requests)) {
        return FALSE;
    }
    if (g_KswordArkCore.Retiring || !g_KswordArkCore.Ready) {
        ExReleaseRundownProtection(&g_KswordArkCore.Requests);
        return FALSE;
    }
    return TRUE;
}

VOID
KswordARKDriverCoreLeaveRequest(VOID)
{
    ExReleaseRundownProtection(&g_KswordArkCore.Requests);
}

BOOLEAN
KswordARKDriverCoreIsControllerDevice(
    _In_ WDFDEVICE Device)
{
    PLIST_ENTRY entry;
    KIRQL irql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_KswordArkCore.DeviceLock, &irql);
    for (entry = g_KswordArkCore.ControllerDevices.Flink;
         entry != &g_KswordArkCore.ControllerDevices; entry = entry->Flink) {
        KSCC_DEVICE_CONTEXT* context =
            CONTAINING_RECORD(entry, KSCC_DEVICE_CONTEXT, CoreLink);
        if (context->Device == Device) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_KswordArkCore.DeviceLock, irql);
    return found;
}

NTSTATUS
KswordARKDriverCoreAttachController(
    _In_ WDFDEVICE Device)
{
    KSCC_DEVICE_CONTEXT* context = KsccGetContext(Device);
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_KswordArkCore.Lock);
    if (!g_KswordArkCore.PnpProfile || g_KswordArkCore.Retiring) {
        status = STATUS_DELETE_PENDING;
    } else if (!context->CoreRegistered) {
        KeAcquireSpinLock(&g_KswordArkCore.DeviceLock, &irql);
        InsertTailList(&g_KswordArkCore.ControllerDevices, &context->CoreLink);
        context->CoreRegistered = TRUE;
        g_KswordArkCore.ControllerCount += 1U;
        KeReleaseSpinLock(&g_KswordArkCore.DeviceLock, irql);
        if (g_KswordArkCore.ControlDevice == WDF_NO_HANDLE) {
            status = KswordARKDriverStartCore(g_KswordArkCore.Driver);
            if (!NT_SUCCESS(status)) {
                InterlockedExchange(&g_KswordArkCore.Retiring, TRUE);
            }
        }
    }
    ExReleasePushLockExclusive(&g_KswordArkCore.Lock);
    KeLeaveCriticalRegion();
    if (!NT_SUCCESS(status) && g_KswordArkCore.Retiring) {
        KswordARKDriverShutdownCore();
    }
    return status;
}

VOID
KswordARKDriverCoreDetachController(
    _In_ WDFDEVICE Device)
{
    KSCC_DEVICE_CONTEXT* context = KsccGetContext(Device);
    WDFDEVICE controlDevice = WDF_NO_HANDLE;
    KIRQL irql;
    BOOLEAN last = FALSE;

    if (!context->CoreRegistered) {
        return;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_KswordArkCore.Lock);
    if (context->CoreRegistered) {
        KeAcquireSpinLock(&g_KswordArkCore.DeviceLock, &irql);
        RemoveEntryList(&context->CoreLink);
        InitializeListHead(&context->CoreLink);
        context->CoreRegistered = FALSE;
        g_KswordArkCore.ControllerCount -= 1U;
        KeReleaseSpinLock(&g_KswordArkCore.DeviceLock, irql);
        if (g_KswordArkCore.PnpProfile && g_KswordArkCore.ControllerCount == 0U) {
            InterlockedExchange(&g_KswordArkCore.Retiring, TRUE);
            InterlockedExchange(&g_KswordArkCore.Ready, FALSE);
            controlDevice = g_KswordArkCore.ControlDevice;
            g_KswordArkCore.ControlDevice = WDF_NO_HANDLE;
            last = TRUE;
        }
    }
    ExReleasePushLockExclusive(&g_KswordArkCore.Lock);
    KeLeaveCriticalRegion();
    if (last) {
        /* Global callbacks still need the CDO and its child queues/locks. */
        KswordARKDriverShutdownCore();
        if (controlDevice != WDF_NO_HANDLE) {
            WdfIoQueuePurgeSynchronously(WdfDeviceGetDefaultQueue(controlDevice));
            WdfObjectDelete(controlDevice);
        }
    }
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KswordARKDriverEvtDriverUnload)
#pragma alloc_text (PAGE, KswordARKDriverEvtDriverContextCleanup)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded.

Arguments:

    DriverObject - represents the instance of the function driver that is loaded
    into memory.
    RegistryPath - represents the driver specific path in the Registry.

Return Value:

    NTSTATUS

--*/
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driverHandle = WDF_NO_HANDLE;
    ULONG osBuildNumber = 0UL;

    // Initialize WPP tracing as soon as possible.
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    InterlockedExchange(&g_KswordArkTracingActive, TRUE);
    // 第一条 breadcrumb 必须先于任何可能失败的初始化，否则无法区分
    // “驱动根本没进 DriverEntry（签名/CI/导入/KMDF 绑定）”和“进来后某一步失败”。
    KswordArkStartupBreadcrumbInitialize(DriverObject, RegistryPath);

    // INF 声明的最低系统是 10.0.16299；更低的系统直接给出确定的不支持状态，
    // 而不是让后续内核回调注册产生一个无从解释的通用失败码。
    KswordArkStartupStage(KswordArkStartStageOsVersionCheck);
    osBuildNumber = KswordArkStartupGetOsBuildNumber();
    if (osBuildNumber != 0UL && osBuildNumber < KSWORD_ARK_MINIMUM_SUPPORTED_OS_BUILD) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER,
            "Unsupported OS build %lu, KswordARK requires 16299 or newer", osBuildNumber);
        if (InterlockedExchange(&g_KswordArkTracingActive, FALSE)) {
            WPP_CLEANUP(DriverObject);
        }
        return KswordArkStartupFailure(KswordArkStartStageOsVersionCheck, STATUS_NOT_SUPPORTED);
    }

    status = KswordARKDriverInitializeCoreLifecycle(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        if (InterlockedExchange(&g_KswordArkTracingActive, FALSE)) {
            WPP_CLEANUP(DriverObject);
        }
        return KswordArkStartupFailure(KswordArkStartStageWdfDriverCreate, status);
    }

    KswordARKCapabilityInitialize();
    KswordARKTrustInitialize();
    KswordARKSafetyInitialize();
    // HAL 编辑事务只初始化锁和空记录表，不在加载阶段修改任何函数槽。
    KswordARKPlatformAuditInitialize();
    // 系统变速加载阶段只准备同步和 DPC，不会在用户确认前修改系统计时源。
    KswordARKSystemTimeInitialize();
    // 在控制设备可见前捕获每 CPU 的不可变 IDT 基线；失败只禁用该诊断功能。
    status = KswordARKIdtBaselineInitialize();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKIdtBaselineInitialize unavailable %!STATUS!", status);
    }
    /*
     * HVM startup is read-only: capture CPU/MSR capability state now, while
     * all VMX/EPT allocations and tests remain explicit UI lifecycle actions.
     */
    status = KswordARKHvmInitialize();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKHvmInitialize unavailable %!STATUS!", status);
    }
    // 在线程控制 IOCTL 可见前初始化 APC 注册表和卸载排空事件。
    KswordARKThreadApcInitialize();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    // 中文说明：必须在 WdfDriverCreate 安装框架 dispatch 前捕获 I/O 管理器的内核拒绝入口。
    status = KswordARKDriverCommunicationInitialize(DriverObject);
    // 中文说明：通信控制是可选功能；无法证明内核拒绝入口时只禁用该功能。
    if (!NT_SUCCESS(status)) {
        // 中文说明：保留其它 KSword 能力可用，同时让新 IOCTL 返回 DEVICE_NOT_READY。
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverCommunicationInitialize unavailable %!STATUS!", status);
    }

    // 通用 IRP 编辑器不依赖 blind 的目标策略；只初始化事务表和自身身份。
    status = KswordARKDriverDispatchInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverDispatchInitialize unavailable %!STATUS!", status);
    }

    // 驱动映像编辑器保存自身身份；DynData/加载器能力在每次请求时实时解析。
    status = KswordARKDriverImageInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverImageInitialize unavailable %!STATUS!", status);
    }
    /* Preallocate RXPF state; exact-build ABI mismatch remains a safe feature gate. */
    status = KswRxpfRuntimeInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswRxpfRuntimeInitialize unavailable %!STATUS!", status);
    }


    // Register cleanup callback for WPP_CLEANUP during framework teardown.
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = KswordARKDriverEvtDriverContextCleanup;

    g_KswordArkCore.EarlyInitialized = TRUE;
    WDF_DRIVER_CONFIG_INIT(&config,
        g_KswordArkCore.PnpProfile ? KsccEvtDeviceAdd : WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = g_KswordArkCore.PnpProfile ? 0U : WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = KswordARKDriverEvtDriverUnload;

    KswordArkStartupStage(KswordArkStartStageWdfDriverCreate);
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        &driverHandle);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        KswordARKDriverShutdownCore();
        if (InterlockedExchange(&g_KswordArkTracingActive, FALSE)) {
            WPP_CLEANUP(DriverObject);
        }
        return KswordArkStartupFailure(KswordArkStartStageWdfDriverCreate, status);
    }

    g_KswordArkCore.Driver = driverHandle;
    /* PnP removal can retire this image; resident HVM must not pin its unload. */
    if (!g_KswordArkCore.PnpProfile) {
        status = KswordARKHvmEnableResidentLifecycle(DriverObject);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
                "Resident HVM lifecycle unavailable %!STATUS!", status);
        }
    }
    if (g_KswordArkCore.PnpProfile) {
        /* No orphan CDO: the first successfully created FDO starts the core. */
        KswordArkStartupReady();
        return STATUS_SUCCESS;
    }
    status = KswordARKDriverStartCore(driverHandle);
    if (!NT_SUCCESS(status)) {
        KswordARKDriverShutdownCore();
    }
    return status;
}

static NTSTATUS
KswordARKDriverStartCore(
    _In_ WDFDRIVER Driver)
{
    WDFDEVICE controlDevice = WDF_NO_HANDLE;
    NTSTATUS status;
    // 控制设备的内部阶段由 KswordARKDriverCreateControlDevice 自己登记，
    // 失败时它已经写好 breadcrumb，这里只做资源回滚。
    status = KswordARKDriverCreateControlDevice(Driver, &controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER,
            "KswordARKDriverCreateControlDevice failed %!STATUS!", status);
        return status;
    }
    g_KswordArkCore.ControlDevice = controlDevice;
    g_KswordArkCore.LateInitialized = TRUE;

    // 进程保护挂在对象回调的前置例程上，必须先于回调注册建好状态，
    // 否则回调一挂上就可能读到尚未初始化的配置。分配失败只关闭保护能力。
    status = KswordARKProcessProtectInitialize(controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswordARKProcessProtectInitialize degraded %!STATUS!", status);
    }

    // 剪贴板策略表不挂任何内核回调，纯粹是"存一张表供用户态 Agent 查询"，
    // 与进程保护配置放在一起初始化，分配失败只关闭这一项能力。
    status = KswordARKClipboardPolicyInitialize(controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswordARKClipboardPolicyInitialize degraded %!STATUS!", status);
    }

    // 内核回调是可选能力，不再是整个驱动的加载门槛：某台机器上的 altitude
    // 冲突、回调槽位耗尽或资源不足只会关闭对应能力，KSword 的驱动、进程、
    // 线程、内存、句柄、内核审计等其它功能仍然可用。
    status = KswordARKCallbackInitialize(controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswordARKCallbackInitialize degraded %!STATUS!", status);
    }
    // 把实际注册成功的回调能力写进 breadcrumb，用户报告缺功能时可直接对照。
    KswordArkStartupNoteCallbackMask(KswordARKCallbackGetRegisteredMask());

    status = KswordARKRedirectInitialize(g_KswordArkCore.DriverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKRedirectInitialize recorded failure %!STATUS!", status);
    }

    status = KswordARKNetworkInitialize(g_KswordArkCore.DriverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKNetworkInitialize recorded failure %!STATUS!", status);
    }

    status = KswordARKFileMonitorInitialize(g_KswordArkCore.DriverObject, &g_KswordArkCore.RegistryPath, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKFileMonitorInitialize recorded failure %!STATUS!", status);
    }

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // DriverEntry 只准备按需安装控制器，避免普通加载时扫描私有 BGP 字段或注册蓝屏回调。
    status = KswordARKBugcheckControlInitialize(g_KswordArkCore.DriverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(
            TRACE_LEVEL_WARNING,
            TRACE_DRIVER,
            "KswordARKBugcheckControlInitialize degraded %!STATUS!",
            status);
    }
    // Guard 仍是独立的一次性调试能力；初始化本身不会安装 KeBugCheckEx hook。
    KswordARKBugcheckGuardInitialize();
    // Shield 只准备同步原语，不注册任何 BugCheck 回调；R3 通过 IOCTL 显式启用。
    KswordARKBugcheckShieldInitialize();
#else
    // Fail closed while the crash-time renderer and guard are disabled.
    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_DRIVER,
        "KswordARK: driver-side bugcheck diagnostics disabled at build time");
#endif

    // 所有运行时都已建立后才让控制设备对用户态可见。
    KswordArkStartupStage(KswordArkStartStageControlDevicePublish);
    InterlockedExchange(&g_KswordArkCore.Ready, TRUE);
    KswordARKDriverPublishControlDevice(controlDevice);

    // 终态记录会覆盖上一次启动留下的失败记录。
    KswordArkStartupReady();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}


static VOID
KswordARKDriverShutdownBugcheckDiagnostics(
    VOID
    )
{
#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    LARGE_INTEGER retryInterval;

    /*
     * Callback/patch teardown may briefly report STATUS_DEVICE_BUSY while a
     * crash callback is still on another CPU.  Keep the image resident and
     * retry at PASSIVE_LEVEL; returning after a failed restore would leave a
     * callback target in an unloadable image.
     */
    retryInterval.QuadPart = -10000LL; /* 1 ms, relative. */
    for (;;) {
        NTSTATUS guardStatus = KswordARKBugcheckGuardUninitialize();
        NTSTATUS shieldStatus = KswordARKBugcheckShieldUninitialize();

        if (NT_SUCCESS(guardStatus) && NT_SUCCESS(shieldStatus)) {
            break;
        }
        KeDelayExecutionThread(
            KernelMode,
            FALSE,
            &retryInterval);
    }
#endif
}

static VOID
KswordARKDriverShutdownCore(VOID)
{
    PAGED_CODE();
    if (InterlockedCompareExchange(&g_KswordArkCore.ShutdownStarted, TRUE, FALSE)) {
        KeWaitForSingleObject(&g_KswordArkCore.ShutdownDone, Executive,
            KernelMode, FALSE, NULL);
        return;
    }
    InterlockedExchange(&g_KswordArkCore.Retiring, TRUE);
    InterlockedExchange(&g_KswordArkCore.Ready, FALSE);
    ExWaitForRundownProtectionRelease(&g_KswordArkCore.Requests);
    if (!g_KswordArkCore.EarlyInitialized) {
        goto Finalize;
    }

    /* Restore every RXPF shadow IDTR and drain #PF readers before other teardown. */
    KswRxpfRuntimeUninitialize();

    // 先恢复受控 HAL 表编辑记录，再停止系统计时钩子；两者都只覆盖各自最后发布值。
    KswordARKPlatformAuditUninitialize();
    KswordARKSystemTimeUninitialize();
    // 中文说明：最先恢复仍由本功能持有的 MajorFunction，并释放目标 DriverObject 引用。
    // 先撤销任意槽位编辑，再恢复可能位于其下层的五槽 communication blind。
    // 映像字段或加载器链可能包含自身身份，必须在驱动映像离开前优先恢复。
    KswordARKDriverImageUninitialize();
    KswordARKDriverDispatchUninitialize();
    // 中文说明：通用派遣编辑可能覆盖在 HWID hook 之上，必须先撤销编辑，
    // 再恢复 HWID 槽位并等待在途派遣和完成例程退出，避免目标驱动的
    // MajorFunction 在本驱动映像卸载后仍指向 passthrough/完成例程。
    KswordARKHwidUninitialize();
    KswordARKDriverCommunicationUninitialize();
    // Release all VMX/VMCS/EPT pages before the driver image can leave memory.
    KswordARKHvmUninitialize();
    // IOCTL 已停止后释放只读 IDT 基线，避免卸载后保留本驱动分配。
    if (g_KswordArkCore.LateInitialized) {
        KswordARKDebuggerShutdown();
    }
    KswordARKIdtBaselineUninitialize();
    // 释放危险写事务为防 PID 复用而持有的请求进程对象引用。
    if (g_KswordArkCore.LateInitialized) {
        KswordARKMutationUninitialize();
    }
    // 随后停止并排空所有可能回调到本驱动映像的线程终止 APC。
    KswordARKThreadApcUninitialize();
    // 目录枚举可能缓存了一个用于续扫的目录句柄，卸载前必须关闭。
    if (g_KswordArkCore.LateInitialized) {
        KswordARKDriverResetDirectoryScanCache();

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
        // 先还原 Guard 入口与 Shield 回调，再撤销 BGP 资源；失败时保留映像并重试。
        KswordARKDriverShutdownBugcheckDiagnostics();
        KswordARKBugcheckControlUninitialize();
#endif

        // 必须先注销内核调试回调，防止后续卸载阶段再次进入本驱动代码。
        KswordARKDebugOutputUninitialize();
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");
        KswordARKNetworkUninitialize();
        KswordARKRedirectUninitialize();
        // 先注销会进入回调规则层的 minifilter，并等待其 post-operation 回调全部退出。
        KswordARKFileMonitorUninitialize();
        // minifilter 已停止后才销毁 callback runtime，避免 post-operation 路径访问已释放状态。
        KswordARKCallbackUninitialize();
        // 对象回调已在上一步注销完毕，此时再没有前置例程会读保护配置，可以安全释放。
        KswordARKProcessProtectUninitialize();
        // 剪贴板策略没有注册任何回调，卸载顺序上不依赖其它模块，这里跟着一起收尾即可。
        KswordARKClipboardPolicyUninitialize();
        KswordARKDynDataUninitialize();
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
    }

Finalize:
    if (g_KswordArkCore.RegistryPath.Buffer != NULL) {
        ExFreePoolWithTag(g_KswordArkCore.RegistryPath.Buffer, 'lfSK');
        RtlZeroMemory(&g_KswordArkCore.RegistryPath, sizeof(g_KswordArkCore.RegistryPath));
    }
    KeSetEvent(&g_KswordArkCore.ShutdownDone, IO_NO_INCREMENT, FALSE);
}

VOID
KswordARKDriverEvtDriverUnload(
    _In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    KswordARKDriverShutdownCore();
}


VOID
KswordARKDriverEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
/*++

Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    KswordARKDriverShutdownCore();
    // DriverEntry failure and ordinary unload can both reach this callback.
    if (InterlockedExchange(&g_KswordArkTracingActive, FALSE)) {
        WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
    }
}
