#include "WindowFeature.h"

#include "WindowView.h"
#include "../WindowTools/WindowToolsClipboardView.h"
#include "../WindowTools/WindowToolsHotkeyView.h"
#include "../WindowTools/WindowToolsHierarchyView.h"
#include "../../Ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace Ksword::Features::Window {
namespace {

constexpr int kWindowManagerTab = 62410;
constexpr int kClipboardTab = 62411;
constexpr int kHotkeyTab = 62412;
constexpr int kHierarchyTab = 62413;

} // namespace

HWND CreateWindowFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<Ksword::Ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kWindowManagerTab, L"窗口管理", L"按需枚举窗口并加载层级诊断。",
        [](HWND host, const RECT& pageBounds) { return CreateWindowFeatureView(host, pageBounds); } });
    tabs.push_back({ kClipboardTab, L"剪贴板查看", L"按需读取当前剪贴板格式。",
        [](HWND host, const RECT& pageBounds) {
            return WindowTools::CreateClipboardInspectorView(host, pageBounds);
        } });
    tabs.push_back({ kHotkeyTab, L"热键占用探测", L"按需扫描全局热键占用。",
        [](HWND host, const RECT& pageBounds) { return WindowTools::CreateHotkeyProbeView(host, pageBounds); } });
    tabs.push_back({ kHierarchyTab, L"层级诊断", L"按需枚举窗口层级并导出可见报告。",
        [](HWND host, const RECT& pageBounds) { return WindowTools::CreateWindowHierarchyView(host, pageBounds); } });

    Ksword::Ui::WorkspaceOptions options{};
    options.tabControlId = 62401;
    options.initialTabId = kWindowManagerTab;
    options.margin = 6;
    return Ksword::Ui::CreateWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

bool RequestWindowFeatureQuery(HWND page, const std::wstring& query) {
    if (!page || query.empty() || !Ksword::Ui::ActivateWorkspaceHostTab(page, kWindowManagerTab, true)) {
        return false;
    }
    HWND windowPage = Ksword::Ui::WorkspaceHostPage(page, kWindowManagerTab, true);
    return RequestWindowFeatureViewQuery(windowPage, query);
}

} // namespace Ksword::Features::Window
