// 专用非 PnP 卸载对照：不创建设备、回调、线程或异步工作。
#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry; // 使用 WDK 的真实 DriverEntry ABI。
DRIVER_UNLOAD KswordUnloadProbeUnload; // 明确提供可卸载入口。

VOID
KswordUnloadProbeUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject); // 无资源需要释放，返回后由系统卸载镜像。
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath); // 不读写注册表或保存外部状态。
    DriverObject->DriverUnload = KswordUnloadProbeUnload; // 只注册自身卸载函数。
    return STATUS_SUCCESS; // 对照驱动加载完成。
}
