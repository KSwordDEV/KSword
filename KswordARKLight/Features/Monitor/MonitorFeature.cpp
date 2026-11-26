#include "MonitorFeature.h"

#include "EtwMonitorView.h"
#include "CallbackMonitorView.h"
#include "../ActionAnalyze/ExecutionGroupPage.h"
#include "../../Ui/WorkspaceHost.h"

#include <vector>

namespace Ksword::Features::Monitor {

HWND CreateMonitorFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<Ksword::Ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ 1, L"ETW 事件", L"用户态 ETW 事件监控。",
        [](HWND host, const RECT& pageBounds) { return CreateEtwMonitorPage(host, pageBounds); } });
    tabs.push_back({ 2, L"内核回调监控", L"R0 回调事件、状态和独立读取游标。",
        [](HWND host, const RECT& pageBounds) { return CreateCallbackMonitorPage(host, pageBounds); } });
    // 外层目录增加执行集合；原工作台继续保留自身端口与owner。
    tabs.push_back({ 3, L"行为分析", L"采集和回放证据，控制显式进程集合。",
        [](HWND host, const RECT& pageBounds) {
            return Ksword::Features::ActionAnalyze::CreateActionAnalyzeExecutionWorkspace(host, pageBounds);
        } });
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
