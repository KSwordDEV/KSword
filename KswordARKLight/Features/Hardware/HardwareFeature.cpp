#include "HardwareFeature.h"

#include "HardwareHwidDispatchView.h"
#include "HardwareView.h"
#include "../HardwareStats/BusDeviceView.h"
#include "../HardwareStats/DiskActivityView.h"
#include "../HardwareStats/PerformanceView.h"
#include "../HardwareStats/UsbTopologyView.h"
#include "../Kernel/KernelFeature.h"
#include "../../Ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace Ksword::Features::Hardware {
namespace {

constexpr int kDeviceManagerTab = 61100;
constexpr int kCpuIntegrityTab = 61101;
constexpr int kCpuSnapshotTab = 61102;
constexpr int kHwidDispatchTab = 61103;
constexpr int kPerformanceTab = 61104;
constexpr int kDiskActivityTab = 61105;
constexpr int kUsbTopologyTab = 61106;
constexpr int kBusDeviceTab = 61107;
constexpr int kEmbeddedKernelPrimaryTabId = 51001;
constexpr int kEmbeddedKernelSecondaryTabId = 51002;

HWND CreateEmbeddedKernelPage(HWND host, const RECT& bounds, const int controlId, const Kernel::KernelFeatureId featureId) {
    HWND page = Kernel::CreateKernelSingleFeaturePage(host, controlId, bounds, featureId);
    if (page) {
        if (HWND primary = ::GetDlgItem(page, kEmbeddedKernelPrimaryTabId)) {
            ::ShowWindow(primary, SW_HIDE);
        }
        if (HWND secondary = ::GetDlgItem(page, kEmbeddedKernelSecondaryTabId)) {
            ::ShowWindow(secondary, SW_HIDE);
        }
    }
    return page;
}

} // namespace

HWND CreateHardwareFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<Ksword::Ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kDeviceManagerTab, L"设备/输入链审计", L"设备页首次打开时枚举当前设备树。",
        [](HWND host, const RECT& pageBounds) { return CreateHardwareDeviceManagerView(host, pageBounds); } });
    tabs.push_back({ kCpuIntegrityTab, L"CPU/IDT 完整性", L"按需加载 Kernel CPU/IDT 完整性页。",
        [](HWND host, const RECT& pageBounds) {
            return CreateEmbeddedKernelPage(host, pageBounds, 61112, Kernel::KernelFeatureId::KernelCpuIntegrity);
        } });
    tabs.push_back({ kCpuSnapshotTab, L"CPU 硬件快照", L"按需加载 CPU 硬件快照。",
        [](HWND host, const RECT& pageBounds) {
            return CreateEmbeddedKernelPage(host, pageBounds, 61113, Kernel::KernelFeatureId::CpuHardwareSnapshot);
        } });
    tabs.push_back({ kHwidDispatchTab, L"HWID Dispatch", L"按需加载 HWID Dispatch 审计与控制页。",
        [](HWND host, const RECT& pageBounds) { return CreateHardwareHwidDispatchView(host, pageBounds); } });
    tabs.push_back({ kPerformanceTab, L"性能监控", L"按需启动性能采样。",
        [](HWND host, const RECT& pageBounds) { return HardwareStats::CreatePerformanceView(host, pageBounds); } });
    tabs.push_back({ kDiskActivityTab, L"磁盘活动", L"按需启动磁盘活动采样。",
        [](HWND host, const RECT& pageBounds) { return HardwareStats::CreateDiskActivityView(host, pageBounds); } });
    tabs.push_back({ kUsbTopologyTab, L"USB 拓扑", L"按需枚举 USB 拓扑。",
        [](HWND host, const RECT& pageBounds) { return HardwareStats::CreateUsbTopologyView(host, pageBounds); } });
    tabs.push_back({ kBusDeviceTab, L"系统总线", L"按需枚举系统总线设备。",
        [](HWND host, const RECT& pageBounds) { return HardwareStats::CreateBusDeviceView(host, pageBounds); } });

    Ksword::Ui::WorkspaceOptions options{};
    options.tabControlId = 61110;
    options.initialTabId = kDeviceManagerTab;
    return Ksword::Ui::CreateWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

} // namespace Ksword::Features::Hardware
