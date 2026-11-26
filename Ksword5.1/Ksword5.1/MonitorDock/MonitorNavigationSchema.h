#pragma once
#include <array>
#include <QString>
#include <QTabWidget>
#include <QIcon>
#include <QVariant>
#include "../Internationalization/LanguageManager.h"

namespace ks::monitor
{
    struct MonitorNavigationSpec
    {
        const char* id; const char* parent; const wchar_t* title;
        const char* translationKey; const char* icon; const char* search;
        bool defaultCurrent;
    };
    // 行为分析及其子页的稳定 ID 同时供真实页签、冷目录与外部导航使用。
    inline constexpr char ActionAnalyzeRootId[] = "monitor.action_analyze";
    inline constexpr char ActionAnalyzeOverviewId[] = "monitor.action_analyze.overview";
    inline constexpr char ActionAnalyzeSamplesId[] = "monitor.action_analyze.samples";
    inline constexpr char ActionAnalyzeRulesId[] = "monitor.action_analyze.rules";
    inline constexpr char ActionAnalyzeBreakpointsId[] = "monitor.action_analyze.breakpoints";
    inline constexpr char ActionAnalyzeDataWatchId[] = "monitor.action_analyze.data_watch";
    inline constexpr char ActionAnalyzeProcessGroupId[] = "monitor.action_analyze.process_group";
    inline constexpr char ActionAnalyzeExecutionGroupId[] = "monitor.action_analyze.execution_group";
    inline constexpr std::array<MonitorNavigationSpec, 17> MonitorNavigationSpecs{{
        {"process-trace", "", L"进程定向", "monitor.tab.process_trace", ":/Icon/process_main.svg", "process|trace", true},
        {"kernel-callback", "", L"内核回调", "monitor.tab.kernel_callback", ":/Icon/process_threads.svg", "kernelcallback|callback", false},
        {"direct-kernel-call", "", L"直接内核调用", "monitor.tab.direct_kernel_call", ":/Icon/process_threads.svg", "directkernelcall|syscall", false},
        {"winapi", "", L"WinAPI", "monitor.tab.winapi", ":/Icon/process_details.svg", "api", false},
        {"winapi-events", "winapi", L"API 事件", "", "", "events|api", true},
        {"winapi-coverage", "winapi", L"API 覆盖", "", "", "coverage|hooks", false},
        {"wmi", "", L"WMI", "monitor.tab.wmi", "", "subscription|provider", false},
        {"etw", "", L"ETW监控", "monitor.tab.etw", "", "event|trace|provider", false},
        {"ark-risk", "", L"ARK 风险中心", "monitor.tab.ark_risk_center", ":/Icon/process_critical.svg", "risk|ark-risk-center", false},
        {ActionAnalyzeRootId, "", L"行为分析", "monitor.tab.action_analyze", ":/Icon/process_details.svg",
            "actionanalyze|behavior|behaviour|analysis|trace|offline", false},
        {ActionAnalyzeSamplesId, ActionAnalyzeRootId, L"项目与采样", "monitor.tab.action_analyze.samples", "", "project|sample|archive", true},
        {ActionAnalyzeOverviewId, ActionAnalyzeRootId, L"总览", "monitor.tab.action_analyze.overview", "", "overview|events|evidence|scan", false},
        {ActionAnalyzeRulesId, ActionAnalyzeRootId, L"行为规则", "monitor.tab.action_analyze.rules", "", "rule|editor", false},
        {ActionAnalyzeBreakpointsId, ActionAnalyzeRootId, L"全局断点", "monitor.tab.action_analyze.breakpoints", "", "breakpoint|debug", false},
        {ActionAnalyzeDataWatchId, ActionAnalyzeRootId, L"写入停点", "monitor.tab.action_analyze.data_watch", "", "watch|data|write", false},
        {ActionAnalyzeProcessGroupId, ActionAnalyzeRootId, L"进程集合控制", "monitor.tab.action_analyze.process_group", "", "process|group|pause|continue|recover", false},
        {ActionAnalyzeExecutionGroupId, ActionAnalyzeRootId, L"执行断点集合", "monitor.tab.action_analyze.execution_group", "", "execution|breakpoint|group|step|continue", false}
    }};
    inline const MonitorNavigationSpec* FindMonitorNavigationSpec(const QString& id)
    {
        for (const auto& spec : MonitorNavigationSpecs)
            if (id == QString::fromLatin1(spec.id)) return &spec;
        return nullptr;
    }
    inline QString MonitorNavigationTitle(const MonitorNavigationSpec& spec)
    {
        const QString title = QString::fromWCharArray(spec.title);
        return *spec.translationKey
            ? ks::i18n::LanguageManager::instance().text(QString::fromLatin1(spec.translationKey), title)
            : ks::i18n::sourceText(title);
    }
    inline int AddMonitorNavigationTab(QTabWidget* tabs, QWidget* page, const QString& id)
    {
        const auto* spec = FindMonitorNavigationSpec(id);
        if (!tabs || !page || !spec) return -1;
        page->setProperty("ksword_monitor_navigation_id", id);
        const int index = *spec->icon
            ? tabs->addTab(page, QIcon(QString::fromLatin1(spec->icon)), MonitorNavigationTitle(*spec))
            : tabs->addTab(page, MonitorNavigationTitle(*spec));
        if (*spec->translationKey)
            ks::i18n::LanguageManager::instance().bindTab(tabs, page,
                QString::fromLatin1(spec->translationKey), QString::fromWCharArray(spec->title));
        return index;
    }
}
