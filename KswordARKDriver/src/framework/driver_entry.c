/*++

Module Name:

    driver_entry.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_mutation.h"
#include "src/features/kernel/kernel_idt_baseline.h"
#include "src/features/hvm/hvm_runtime.h"
#include "src/features/rxpf/rxpf_runtime.h"
#include "driver_entry.tmh"

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
    WDFDEVICE controlDevice = WDF_NO_HANDLE;
    ULONG osBuildNumber = 0UL;

    // Initialize WPP tracing as soon as possible.
    WPP_INIT_TRACING(DriverObject, RegistryPath);
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
        WPP_CLEANUP(DriverObject);
        return KswordArkStartupFailure(KswordArkStartStageOsVersionCheck, STATUS_NOT_SUPPORTED);
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

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
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
        // 框架失败时对称撤销系统变速状态，确保维护 DPC 不会残留。
        /* No RXPF exception-visible allocation may survive DriverEntry failure. */
        KswRxpfRuntimeUninitialize();
        KswordARKPlatformAuditUninitialize();
        KswordARKSystemTimeUninitialize();
        // 中文说明：框架创建失败时撤销通信控制状态和所有潜在引用。
        // 先恢复映像字段和加载器链，再恢复 IRP/communication 槽位。
        KswordARKDriverImageUninitialize();
        KswordARKDriverDispatchUninitialize();
        KswordARKDriverCommunicationUninitialize();
        // Release the optional HVM capability state on early framework failure.
        KswordARKHvmUninitialize();
        // Release the boot-captured IDT table when framework creation fails.
        KswordARKIdtBaselineUninitialize();
        // DriverEntry 失败时关闭 APC 接收状态，保持初始化与退出路径对称。
        KswordARKThreadApcUninitialize();
        WPP_CLEANUP(DriverObject);
        return KswordArkStartupFailure(KswordArkStartStageWdfDriverCreate, status);
    }

    /*
     * Bind resident-HVM lifecycle guards only after KMDF installs the final
     * DriverUnload entry.  Failure keeps resident VMX disabled without taking
     * down the rest of the driver.
     */
    status = KswordARKHvmEnableResidentLifecycle(DriverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(
            TRACE_LEVEL_WARNING,
            TRACE_DRIVER,
            "Resident HVM lifecycle unavailable %!STATUS!",
            status);
    }

    // 控制设备的内部阶段由 KswordARKDriverCreateControlDevice 自己登记，
    // 失败时它已经写好 breadcrumb，这里只做资源回滚。
    status = KswordARKDriverCreateControlDevice(driverHandle, &controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "KswordARKDriverCreateControlDevice failed %!STATUS!", status);
        // 控制设备不可见时不会有合法变速请求，立即释放其运行时状态。
        /* Restore any RXPF shadow IDT before the driver image can be discarded. */
        KswRxpfRuntimeUninitialize();
        KswordARKPlatformAuditUninitialize();
        KswordARKSystemTimeUninitialize();
        // 中文说明：控制设备创建失败时不保留通信控制全局状态。
        // 映像事务可能持有其它 DriverObject 引用，必须在失败返回前释放。
        KswordARKDriverImageUninitialize();
        KswordARKDriverDispatchUninitialize();
        KswordARKDriverCommunicationUninitialize();
        // Release the optional HVM capability state on early device failure.
        KswordARKHvmUninitialize();
        // Release the boot-captured IDT table when the control device is absent.
        KswordARKIdtBaselineUninitialize();
        // 控制设备不可用时不会接受线程请求，立即关闭 APC 生命周期管理。
        KswordARKThreadApcUninitialize();
        WPP_CLEANUP(DriverObject);
        return status;
    }

    // 进程保护挂在对象回调的前置例程上，必须先于回调注册建好状态，
    // 否则回调一挂上就可能读到尚未初始化的配置。分配失败只关闭保护能力。
    status = KswordARKProcessProtectInitialize(controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER,
            "KswordARKProcessProtectInitialize degraded %!STATUS!", status);
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

    status = KswordARKRedirectInitialize(DriverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKRedirectInitialize recorded failure %!STATUS!", status);
    }

    status = KswordARKNetworkInitialize(DriverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKNetworkInitialize recorded failure %!STATUS!", status);
    }

    status = KswordARKFileMonitorInitialize(DriverObject, RegistryPath, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKFileMonitorInitialize recorded failure %!STATUS!", status);
    }

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // DriverEntry 只准备按需安装控制器，避免普通加载时扫描私有 BGP 字段或注册蓝屏回调。
    status = KswordARKBugcheckControlInitialize(DriverObject, controlDevice);
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
    KswordARKDriverPublishControlDevice(controlDevice);

    // 终态记录会覆盖上一次启动留下的失败记录。
    KswordArkStartupReady();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

VOID
KswordARKDriverEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
/*++

Routine Description:

    Called when SCM requests to unload the non-PnP control driver.

Arguments:

    Driver - Handle to a WDF Driver object.

Return Value:

    VOID

--*/
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

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
    KswordARKDriverCommunicationUninitialize();
    // Release all VMX/VMCS/EPT pages before the driver image can leave memory.
    KswordARKHvmUninitialize();
    // IOCTL 已停止后释放只读 IDT 基线，避免卸载后保留本驱动分配。
    KswordARKIdtBaselineUninitialize();
    // 释放危险写事务为防 PID 复用而持有的请求进程对象引用。
    KswordARKMutationUninitialize();
    // 随后停止并排空所有可能回调到本驱动映像的线程终止 APC。
    KswordARKThreadApcUninitialize();
    // 目录枚举可能缓存了一个用于续扫的目录句柄，卸载前必须关闭。
    KswordARKDriverResetDirectoryScanCache();

#if KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    // 先还原一次性 Guard 与 Shield 回调，再撤销 BGP 资源。
    KswordARKBugcheckGuardUninitialize();
    KswordARKBugcheckShieldUninitialize();
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
    KswordARKDynDataUninitialize();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
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

    // Stop WPP tracing.
    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
}
