#pragma once

// ============================================================
// MonitorAgent.h
// 作用：
// 1) 暴露 DLL 入口初始化与停止接口；
// 2) 为 Hook 层提供当前监控配置与停止状态访问；
// 3) 把 APIMonitor_x64 的全局运行态收口在少量函数里。
// ============================================================

#include "pch.h"
#include "core/MonitorConfig.h"

namespace apimon
{
    // OnProcessAttach：
    // - 作用：在 DLL_PROCESS_ATTACH 时启动后台工作线程；
    // - 调用：只允许由 dllmain.cpp 调用。
    void OnProcessAttach(HMODULE moduleHandle);

    // OnProcessDetach：
    // - 作用：在 DLL_PROCESS_DETACH 时发出停止信号；
    // - 调用：只允许由 dllmain.cpp 调用。
    void OnProcessDetach();

    // ActiveConfig：
    // - 作用：返回当前已加载的监控配置；
    // - 调用：Hook 层根据该配置判断哪些分类已启用。
    const MonitorConfig& ActiveConfig();

    // ReplaceActiveConfig：
    // - 作用：用新配置替换当前运行态配置；
    // - 调用：后台工作线程在读完 INI 后调用一次。
    void ReplaceActiveConfig(const MonitorConfig& configValue);

    // StopRequested：
    // - 作用：判断当前监控是否已收到停止请求；
    // - 调用：后台线程与 Hook 层可据此减少额外处理。
    bool StopRequested();
    bool EventsPaused();

    // RequestStop：
    // - 作用：设置全局停止标志；
    // - 调用：后台线程、DllMain Detach 路径都可调用。
    void RequestStop();
}
