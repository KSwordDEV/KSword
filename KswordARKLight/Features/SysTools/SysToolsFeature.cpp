#include "SysToolsFeature.h"

#include "ContextMenuView.h"
#include "EventLogView.h"
#include "FileHolderView.h"
#include "IoctlDecoderView.h"
#include "SystemTimeView.h"
#include "../../Ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace Ksword::Features::SysTools {
namespace {

constexpr int kFileHolderTab = 67010;
constexpr int kEventLogTab = 67011;
constexpr int kContextMenuTab = 67012;
constexpr int kSystemTimeTab = 67013;
constexpr int kIoctlDecoderTab = 67014;

} // namespace

HWND CreateSysToolsFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<Ksword::Ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kFileHolderTab, L"文件占用", L"按需扫描文件占用者。",
        [](HWND host, const RECT& pageBounds) { return CreateFileHolderView(host, pageBounds); } });
    tabs.push_back({ kEventLogTab, L"事件日志", L"按需查询事件日志。",
        [](HWND host, const RECT& pageBounds) { return CreateEventLogView(host, pageBounds); } });
    tabs.push_back({ kContextMenuTab, L"右键菜单", L"按需扫描 Shell 扩展。",
        [](HWND host, const RECT& pageBounds) { return CreateContextMenuView(host, pageBounds); } });
    tabs.push_back({ kSystemTimeTab, L"系统时间", L"按需采集系统时间和时区证据。",
        [](HWND host, const RECT& pageBounds) { return CreateSystemTimeView(host, pageBounds); } });
    tabs.push_back({ kIoctlDecoderTab, L"IOCTL 解码", L"离线拆解 CTL_CODE 位字段，不访问驱动。",
        [](HWND host, const RECT& pageBounds) { return CreateIoctlDecoderView(host, pageBounds); } });

    Ksword::Ui::WorkspaceOptions options{};
    options.tabControlId = 67001;
    options.initialTabId = kFileHolderTab;
    options.margin = 8;
    return Ksword::Ui::CreateWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

} // namespace Ksword::Features::SysTools
