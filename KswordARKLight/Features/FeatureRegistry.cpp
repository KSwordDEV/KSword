#include "FeatureRegistry.h"

#include "Driver/DriverFeature.h"
#include "File/FileFeature.h"
#include "Hardware/HardwareFeature.h"
#include "Handle/HandleFeature.h"
#include "Kernel/KernelFeature.h"
#include "Memory/MemoryFeature.h"
#include "Misc/MiscFeature.h"
#include "Monitor/MonitorFeature.h"
#include "Network/NetworkFeature.h"
#include "Privilege/PrivilegeFeature.h"
#include "Process/ProcessFeature.h"
#include "Registry/RegistryFeature.h"
#include "Service/ServiceFeature.h"
#include "Startup/StartupFeature.h"
#include "SysTools/SysToolsFeature.h"
#include "Window/WindowFeature.h"

namespace Ksword::Features {

std::vector<Ksword::Ui::ModuleDescriptor> GetModuleDescriptors() {
    return {
        { 40001, L"进程", L"NtQuerySystemInformation 进程列表、友好视图/详细视图、多选、图标、拖动选择和进程右键菜单。", Process::CreateProcessFeaturePage },
        { 40002, L"内存", L"仅保留通过 KswordARK R0 驱动执行的内存读取和写入。", Memory::CreateMemoryFeaturePage },
        { 40010, L"注册表", L"WinAPI/R0 双模式注册表浏览与读写、创建、删除、重命名。", Registry::CreateRegistryFeaturePage },
        { 40003, L"文件", L"Windows API 路径枚举和文件右键菜单；文件属性页已移除。", File::CreateFileFeaturePage },
        { 40004, L"驱动", L"驱动概览和对象信息。", Driver::CreateDriverFeaturePage },
        { 40005, L"内核", L"保留 SSDT、Shadow SSDT、Hook、对象命名空间、回调等内核功能入口。", [](HWND parent, const RECT& bounds) -> HWND {
            return Kernel::CreateKernelFeaturePage(parent, 40005, bounds);
        } },
        { 40006, L"监控", L"ETW 监控主页面，筛选器通过弹窗配置。", Monitor::CreateMonitorFeaturePage },
        { 40007, L"硬件", L"设备、CPU/HWID 审计、性能监控、磁盘活动、USB 拓扑与系统总线。", Hardware::CreateHardwareFeaturePage },
        { 40008, L"窗口", L"窗口管理、剪贴板查看、捕获保护、层级诊断与全局热键占用探测。", Window::CreateWindowFeaturePage },
        { 40009, L"启动项", L"启动项管理。", Startup::CreateStartupFeaturePage },
        { 40014, L"服务", L"SCM 服务与驱动服务枚举、启停暂停继续、启动类型修改与配置风险标注。", Service::CreateServiceFeaturePage },
        { 40015, L"权限", L"当前进程令牌的身份、完整性级别、组与全部特权，可启用/禁用并标注越权类特权。", Privilege::CreatePrivilegeFeaturePage },
        { 40018, L"系统工具", L"文件占用扫描、事件日志查看、右键菜单扩展禁用与恢复、系统时间与时区信息。", SysTools::CreateSysToolsFeaturePage },
        { 40011, L"网络", L"连接管理、网络诊断、防火墙规则与 TCP/UDP/AFD/WFP/NDIS/NSI 网络栈审计。", Network::CreateNetworkFeaturePage },
        { 40012, L"句柄", L"HandleTable/ObjectHeader/ObjectType 只读审计，复用 ArkDriverClient 句柄查询协议。", Handle::CreateHandleFeaturePage },
        { 40013, L"杂项安全", L"Security / CI / VBS / Hyper-V 只读审计入口，显示 R3 证据与 R0 capability 状态。", Misc::CreateMiscFeaturePage }
    };
}

} // namespace Ksword::Features
