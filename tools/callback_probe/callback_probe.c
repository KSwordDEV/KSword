// 非 PnP 测试夹具：只注册本驱动自己的一个进程通知，不控制其他驱动。
#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry; // 保持 WDK 的 DriverEntry ABI。
DRIVER_UNLOAD KswordCallbackProbeUnload; // SCM 停止时只注销本驱动自己的回调。

static VOID
KswordCallbackProbeNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId); // 夹具不记录或处理进程信息。
    UNREFERENCED_PARAMETER(ProcessId); // 夹具不记录或处理进程信息。
    UNREFERENCED_PARAMETER(Create); // 夹具不修改目标进程。
}

VOID
KswordCallbackProbeUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject); // 测试驱动没有设备对象或异步工作。
    (VOID)PsSetCreateProcessNotifyRoutine(KswordCallbackProbeNotify, TRUE); // 即使 CLI 已注销也只尝试注销自身函数。
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath); // 不读取或修改注册表配置。
    DriverObject->DriverUnload = KswordCallbackProbeUnload; // 提供专用服务的清理路径。
    return PsSetCreateProcessNotifyRoutine(KswordCallbackProbeNotify, FALSE); // 仅注册自身测试回调。
}
