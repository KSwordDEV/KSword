#include "pch.h"
#include "MonitorAgent.h"
#include "core/MonitorDiagnostics.h"
#include "ApiMonitorDefinitionIdentity.h"
#include "core/MonitorPipe.h"
#include "hook/HookEngine.h"
#include "hook/HookTargets.h"
#include "hook/ClipboardGuardCommon.h"
#include "hook/ClipboardGuardWin32u.h"

namespace apimon
{
    namespace
    {
        std::atomic_bool g_stopRequested{ false };     // g_stopRequested：全局停止标志。
        std::atomic_bool g_eventsPaused{ false };
        std::atomic_bool g_processDetachRequested{ false }; // g_processDetachRequested：DLL 正在卸载，worker 不得重新开启会话。
        std::atomic<const MonitorConfig*> g_activeConfig{ new MonitorConfig{} };                // g_activeConfig：当前已加载的会话配置。
        constexpr DWORD kSessionIdlePollMs = 100;       // kSessionIdlePollMs：等待下一次 UI 会话配置时的低频轮询间隔。
        constexpr DWORD kSessionActivePollMs = 250;     // kSessionActivePollMs：已安装 Hook 后检查停止标记的轮询间隔。

        void TraceAgentFailure(const std::wstring& errorText)
        {
            if (errorText.empty())
            {
                return;
            }

            const std::wstring outputText = L"[APIMonitor_x64] " + errorText + L"\n";
            ::OutputDebugStringW(outputText.c_str());
        }

        // WaitForNextSessionConfig 作用：
        // - 输入：configOut 接收已完整加载且允许启动的下一份会话配置；
        // - 处理：停标记存在时保持 Agent 常驻，等 UI 原子提交新 INI 并清除停标记后才返回；
        // - 返回：获得可启动会话时为 true，DLL 卸载时为 false。
        bool WaitForNextSessionConfig(MonitorConfig* const configOut)
        {
            if (configOut == nullptr)
            {
                return false;
            }

            std::wstring lastErrorText;
            while (!g_processDetachRequested.load())
            {
                MonitorConfig candidateConfig;
                std::wstring errorText;
                if (!LoadMonitorConfigForCurrentProcess(&candidateConfig, &errorText))
                {
                    if (errorText != lastErrorText)
                    {
                        TraceAgentFailure(errorText);
                        lastErrorText = errorText;
                    }
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                lastErrorText.clear();
                if (IsStopFlagPresent(candidateConfig))
                {
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                // 新会话只能在停标记已经撤销后重置停止状态，避免旧会话刚结束就被立即重新启用。
                g_stopRequested.store(false);
                *configOut = candidateConfig;
                return true;
            }
            return false;
        }

        // SessionConfigWasReplaced 作用：
        // - 输入：activeConfigValue 为当前已安装 Hook 的会话配置；
        // - 处理：重新读取原子提交后的 INI，比对 UI 写入的唯一 session_id；
        // - 返回：检测到不同的新会话时为 true，读取失败或旧版无标识配置时为 false。
        bool SessionConfigWasReplaced(const MonitorConfig& activeConfigValue, bool syncClipboardHooks)
        {
            if (activeConfigValue.sessionId.empty())
            {
                return false;
            }

            MonitorConfig observedConfig;
            std::wstring ignoredErrorText;
            if (!LoadMonitorConfigForCurrentProcess(&observedConfig, &ignoredErrorText)
                || observedConfig.sessionId.empty())
            {
                return false;
            }
            // 顺带把剪贴板策略的最新取值刷进原子镜像：sessionId 没变说明还是同一个
            // 会话，只是策略字段被 UI 原地重写了（右键"拦截读"这类操作）。真的检测
            // 到 sessionId 变化时，调用方会立刻 RequestStop() 整体重建会话，
            // InstallConfiguredHooks 用全新配置重新起步，这里刷新的镜像值会被
            // 那次重建覆盖，不会遗留过期状态。这一步不引入新的 I/O——
            // observedConfig 是本函数原本就要读的同一份 INI。
            RefreshClipboardPolicyFromConfig(observedConfig);
            // tier2 hook 的装/卸取决于最新策略，同一轮顺带同步，
            // 保证"右键拦截读"之类的操作不但对 tier1 生效，也补上 win32u 深度防御。
            if (observedConfig.enableClipboard && syncClipboardHooks)
            {
                SyncClipboardWin32uHooks();
            }
            return observedConfig.sessionId != activeConfigValue.sessionId;
        }

        // WaitForCurrentSessionStop 作用：
        // - 输入：configValue 为本次已启动会话的稳定配置；
        // - 处理：等待 UI 写入停止标记或 DLL 卸载请求，并把文件标记同步到进程内停止状态；
        // - 返回：无返回值，返回后调用方必须卸载 Hook 并停止管道。
        void WaitForCurrentSessionStop(const MonitorConfig& configValue, HANDLE pauseEvent, bool initiallyPaused = false)
        {
            std::wstring lastRetryReport;
            bool hooksPaused = initiallyPaused;
            bool needsInstall = initiallyPaused;
            bool pauseFailureReported = false, resumeFailureReported = false;
            while (!g_processDetachRequested.load() && !StopRequested())
            {
                const bool pauseRequested = pauseEvent && ::WaitForSingleObject(pauseEvent, 0) == WAIT_OBJECT_0;
                if (IsStopFlagPresent(configValue) || SessionConfigWasReplaced(configValue, !pauseRequested && !needsInstall))
                {
                    APIMON_DIAG_MARK("stop-observed",0,0);
                    RequestStop();
                    break;
                }
                if (pauseRequested)
                {
                    g_eventsPaused.store(true);
                    needsInstall = true;
                    if (!hooksPaused) {
                        if (UninstallConfiguredHooks()) {
                            hooksPaused = true; pauseFailureReported = false;
                            SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"HooksPaused", 0,
                                L"Configured hooks have been removed while monitoring is paused.");
                        } else if (!pauseFailureReported) {
                            SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"HooksPauseFailed", 1,
                                L"Hook removal is incomplete; retrying while events are suppressed.");
                            pauseFailureReported = true;
                        }
                    }
                    ::Sleep(kSessionActivePollMs);
                    continue;
                }
                if (needsInstall)
                {
                    std::wstring resumeError;
                    if (InstallConfiguredHooks(&resumeError)) {
                        if (pauseEvent && ::WaitForSingleObject(pauseEvent, 0) == WAIT_OBJECT_0) {
                            hooksPaused = false; // Pause was requested again during installation.
                            ::Sleep(kSessionActivePollMs);
                            continue;
                        }
                        needsInstall = false; hooksPaused = false; resumeFailureReported = false;
                        g_eventsPaused.store(false);
                        if (!resumeError.empty())
                            SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"HooksPartial", 0, resumeError);
                        SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"HooksResumed", 0,
                            L"Configured hooks were reinstalled after pause.");
                    } else if (!resumeFailureReported) {
                        SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"HooksResumeFailed", 1, resumeError);
                        resumeFailureReported = true;
                    }
                    ::Sleep(kSessionActivePollMs);
                    continue;
                }
                std::wstring retryReport;
                RetryPendingHooks(&retryReport);
                // 重试可能持续数秒甚至更久；只在诊断内容变化时上报，避免 250ms
                // 轮询把同一条 DWM 线程安全失败刷满管道。空报告表示本轮没有新的
                // 强类型/Fake 失败，清除去重标记，让后续再次失败时可以重新报告。
                if (retryReport.empty())
                {
                    lastRetryReport.clear();
                }
                else if (retryReport != lastRetryReport)
                {
                    SendMonitorEvent(
                        ks::winapi_monitor::EventCategory::Internal,
                        L"Agent",
                        L"HooksRetry",
                        1,
                        retryReport);
                    lastRetryReport = retryReport;
                }
                ::Sleep(kSessionActivePollMs);
            }
        }

        DWORD WINAPI MonitorWorkerBody(LPVOID parameterValue);
        DWORD HandleMonitorWorkerFailure(DWORD failure)
        {
                // Agent exceptions must not terminate the host application.
                // Keep code resident, stop logging, and attempt safe restoration.
                ScopedInlineHookInternalBypass bypass;
                RequestStop();
                try {
                    SendMonitorEventRaw(ks::winapi_monitor::EventCategory::Internal,L"Agent",L"AgentFailure",
                        failure,L"Agent worker exception; monitoring stopped and cleanup attempted.");
                } catch (...) {}
                bool removed=false;
                for(unsigned attempt=0;attempt<3&&!removed;++attempt){
                    try { removed=UninstallConfiguredHooks(); } catch (...) {}
                    if(!removed)::Sleep(kSessionActivePollMs);
                }
                if(removed){try {SendHooksRemovedEvent(L"Hooks restored after Agent worker failure.");}catch(...) {}}
                try {(void)DrainMonitorPipeServer();StopMonitorPipeServer();}catch(...) {}
                return failure;
        }
        DWORD WINAPI MonitorWorkerThread(LPVOID parameterValue)
        {
            try { return MonitorWorkerBody(parameterValue); }
            catch (const std::bad_alloc&) {return HandleMonitorWorkerFailure(ERROR_NOT_ENOUGH_MEMORY);}
            catch (...) {return HandleMonitorWorkerFailure(ERROR_UNHANDLED_EXCEPTION);}
        }

        DWORD WINAPI MonitorWorkerBody(LPVOID parameterValue)
        {
            (void)parameterValue;

            // agentBypassScope：
            // - 输入：无；
            // - 处理：Agent worker 线程自身的会话等待、事件发送和卸载流程不进入监控事件流；
            // - 返回：无返回值，作用域覆盖可重启 worker 的完整生命周期。
            // - 原因：内部控制线程不是被测业务线程，监控它会引入 Wait/File/Loader 自递归噪声，并可能放大为退出期崩溃。
            HMODULE pinnedAgent = nullptr;
            if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    reinterpret_cast<LPCWSTR>(&MonitorWorkerThread), &pinnedAgent)) return 1;
            ScopedInlineHookInternalBypass agentBypassScope;
            while (!g_processDetachRequested.load())
            {
                MonitorConfig configValue;
                if (!WaitForNextSessionConfig(&configValue))
                {
                    break;
                }

                ReplaceActiveConfig(configValue);
                g_eventsPaused.store(false);
                APIMON_DIAG_RESET();
                APIMON_DIAG_MARK("session-begin",0,0);
                // 初始化剪贴板策略的原子镜像，确保 InstallConfiguredHooks 之后
                // 第一次 hook 调用就能读到正确的读/写/枚举动作，而不是默认值 Allow。
                RefreshClipboardPolicyFromConfig(configValue);
                std::wstring errorText;
                if (!StartMonitorPipeServer(configValue, &errorText))
                {
                    if (!g_processDetachRequested.load() && !IsStopFlagPresent(configValue))
                    {
                        TraceAgentFailure(errorText);
                    }
                    // 管道握手失败后保留 worker；UI 可能在下一轮重新建立读取端，不能因为一次 45 秒超时永久失去重启能力。
                    ::Sleep(kSessionIdlePollMs);
                    continue;
                }

                SendMonitorEvent(
                    ks::winapi_monitor::EventCategory::Internal,
                    L"Agent",
                    L"SessionReady",
                    0,
                    std::wstring(L"definitionSha256=") + std::wstring(kDefinitionSha256, kDefinitionSha256 + 64));

                struct PauseHandle { HANDLE value = nullptr; ~PauseHandle() { if (value) ::CloseHandle(value); } } pause;
                if (!configValue.pauseEventName.empty()) {
                    pause.value = ::OpenEventW(SYNCHRONIZE, FALSE, configValue.pauseEventName.c_str());
                    if (!pause.value)
                        SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"PauseControlUnavailable", 1,
                            L"Could not open the session pause event: " + std::to_wstring(::GetLastError()));
                    else
                        SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"PauseControlReady", 0,
                            L"Session pause control is ready.");
                }
                const bool initiallyPaused = pause.value && ::WaitForSingleObject(pause.value, 0) == WAIT_OBJECT_0;
                if (initiallyPaused) g_eventsPaused.store(true);

                APIMON_DIAG_MARK("install-begin",0,0);
                const bool installed = initiallyPaused || InstallConfiguredHooks(&errorText);
                const bool cancelled = StopRequested() || IsStopFlagPresent(configValue);
                if (!installed || cancelled)
                {
                    if(cancelled)RequestStop();
                    SendMonitorEvent(
                        ks::winapi_monitor::EventCategory::Internal,
                        L"Agent",
                        cancelled ? L"InstallHooksCancelled" : L"InstallHooksFailed",
                        1,
                        errorText);
                    if(!cancelled)WaitForCurrentSessionStop(configValue, pause.value);
                    while (!UninstallConfiguredHooks() && !g_processDetachRequested.load())
                    ::Sleep(kSessionActivePollMs);
                    SendHooksRemovedEvent(L"Inline hooks removed after incomplete installation.");
                    (void)DrainMonitorPipeServer();
                    StopMonitorPipeServer();
                    continue;
                }
                APIMON_DIAG_MARK("install-end",0,0);
                if (!errorText.empty())
                {
                    SendMonitorEvent(
                        ks::winapi_monitor::EventCategory::Internal,
                        L"Agent",
                        L"HooksPartial",
                        0,
                        errorText);
                }

                SendMonitorEvent(
                    ks::winapi_monitor::EventCategory::Internal,
                    L"Agent",
                    initiallyPaused ? L"HooksPaused" : L"HooksInstalled",
                    0,
                    initiallyPaused ? L"Session started paused; no hooks were installed." : L"Configured inline hooks are now active.");

                WaitForCurrentSessionStop(configValue, pause.value, initiallyPaused);
                APIMON_DIAG_MARK("uninstall-begin",0,0);
                while (!UninstallConfiguredHooks() && !g_processDetachRequested.load())
                    ::Sleep(kSessionActivePollMs);
                SendHooksRemovedEvent(L"Inline hooks removed and agent is waiting for the next session.");
                APIMON_DIAG_MARK("uninstall-end",0,0);
                (void)DrainMonitorPipeServer();
                StopMonitorPipeServer();
                g_eventsPaused.store(false);
            }
            return 0;
        }
    }

    void OnProcessAttach(const HMODULE moduleHandle)
    {
        ::DisableThreadLibraryCalls(moduleHandle);
        g_processDetachRequested.store(false);
        g_stopRequested.store(false);

        HANDLE workerHandle = ::CreateThread(
            nullptr,
            0,
            &MonitorWorkerThread,
            nullptr,
            0,
            nullptr);
        if (workerHandle != nullptr)
        {
            ::CloseHandle(workerHandle);
        }
        else
        {
            TraceAgentFailure(L"CreateThread for monitor worker failed.");
        }
    }

    void OnProcessDetach()
    {
        g_processDetachRequested.store(true);
        RequestStop();
    }

    const MonitorConfig& ActiveConfig()
    {
        return *g_activeConfig.load();
    }

    void ReplaceActiveConfig(const MonitorConfig& configValue)
    {
        // Immutable snapshots remain valid for detours from the retiring session.
        g_activeConfig.store(new MonitorConfig(configValue));
    }

    bool StopRequested()
    {
        return g_stopRequested.load();
    }

    bool EventsPaused() { return g_eventsPaused.load(); }

    void RequestStop()
    {
        g_stopRequested.store(true);
    }
}
