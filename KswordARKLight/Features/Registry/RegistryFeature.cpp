#include "RegistryFeature.h"

#include "RegistrySearchView.h"
#include "RegistryView.h"
#include "../../Ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace Ksword::Features::Registry {
namespace {

constexpr int kRegistryBrowserTab = 63110;
constexpr int kRegistrySearchTab = 63111;

} // namespace

HWND CreateRegistryFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<Ksword::Ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kRegistryBrowserTab, L"注册表浏览", L"按需浏览当前 WinAPI 或现有 R0 注册表视图。",
        [](HWND host, const RECT& pageBounds) { return CreateRegistryView(host, pageBounds); } });
    tabs.push_back({ kRegistrySearchTab, L"递归搜索", L"只读、有界的当前进程 WinAPI 注册表搜索。",
        [](HWND host, const RECT& pageBounds) { return CreateRegistrySearchView(host, pageBounds); } });

    Ksword::Ui::WorkspaceOptions options{};
    options.tabControlId = 63101;
    options.initialTabId = kRegistryBrowserTab;
    options.margin = 6;
    return Ksword::Ui::CreateWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

bool RequestRegistryFeatureNavigate(HWND page, const std::wstring& path) {
    if (!page || path.empty() || !Ksword::Ui::ActivateWorkspaceHostTab(page, kRegistryBrowserTab, true)) {
        return false;
    }
    HWND browserPage = Ksword::Ui::WorkspaceHostPage(page, kRegistryBrowserTab, true);
    return RequestRegistryViewNavigate(browserPage, path);
}

} // namespace Ksword::Features::Registry
