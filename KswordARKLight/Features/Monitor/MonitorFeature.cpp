#include "MonitorFeature.h"

#include "EtwMonitorView.h"
#include "CallbackMonitorView.h"
#include "../ActionAnalyze/ActionAnalyzePage.h"
#include "../../Ui/WorkspaceHost.h"

#include <vector>

namespace Ksword::Features::Monitor {

HWND CreateMonitorFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<Ksword::Ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ 1, L"ETW 事件", L"用户态 ETW 事件监控。",
        [](HWND host, const RECT& pageBounds) { return CreateEtwMonitorPage(host, pageBounds); } });
    tabs.push_back({ 2, L"内核回调监控", L"R0 回调事件、状态和独立读取游标。",
        [](HWND host, const RECT& pageBounds) { return CreateCallbackMonitorPage(host, pageBounds); } });
    tabs.push_back({ 3, L"ActionAnalyze", L"只读查看 ActionAnalyze 归档段、事件与证据引用。",
        Ksword::Features::ActionAnalyze::CreateActionAnalyzePage });
    Ksword::Ui::WorkspaceOptions options{};
    options.tabControlId = 68100;
    options.initialTabId = 1;
    return Ksword::Ui::CreateWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

bool RequestMonitorFeatureProcess(HWND page, const DWORD processId) {
    if (!Ksword::Ui::ActivateWorkspaceHostTab(page, 1)) { return false; }
    return RequestEtwMonitorProcessFilter(Ksword::Ui::WorkspaceHostPage(page, 1, true), processId);
}

} // namespace Ksword::Features::Monitor
