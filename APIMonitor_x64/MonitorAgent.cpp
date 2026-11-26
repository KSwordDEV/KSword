#include "pch.h"
#include "MonitorAgent.h"
#include "core/MonitorDiagnostics.h"
#include "ApiMonitorDefinitionIdentity.h"
#include "core/MonitorCoverage.h"
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
        enum class CooperativeState { Initializing, Unselected, AwaitingEnable, Enabled, Rejected };
        std::atomic<CooperativeState> g_cooperativeState{ CooperativeState::Initializing };
        // The application startup point belongs to the first cooperative attempt in this process.
        std::atomic<DWORD> g_cooperativeStartupResult{ ERROR_IO_PENDING };
        constexpr DWORD kCooperativeStartupMaxWaitMs = 120000;
        constexpr DWORD kCooperativeStartupPollMs = 10;
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

        void CompleteCooperativeStartup(DWORD status)
        {
            DWORD pending = ERROR_IO_PENDING;
            g_cooperativeStartupResult.compare_exchange_strong(pending, status);
        }

        bool HasCooperativeStartupCoverage()
        {
            using namespace ks::winapi_monitor;
            const auto snapshot = LatestCoverageSnapshot();
            if (!snapshot || !snapshot->revision || snapshot->session != CurrentMonitorSessionIdentity())
            {
                return false;
            }
            return std::any_of(snapshot->items.begin(), snapshot->items.end(), [](const auto& item) {
                const auto kind = static_cast<HookKind>(item.hookKind);
                const auto state = static_cast<CoverageState>(item.coverageState);
                return item.apiId && item.hookAddress
                    && (kind == HookKind::Strong || kind == HookKind::Raw || kind == HookKind::DynamicExtension)
                    && (state == CoverageState::Installed || state == CoverageState::SharedEntry);
            });
        }

        // WaitForNextSessionConfig 作用：
        // - 输入：configOut 接收已完整加载且允许启动的下一份会话配置；
        // - 处理：停标记存在时保持 Agent 常驻，等 UI 原子提交新 INI 并清除停标记后才返回；
        // - 返回：获得可启动会话时为 true，DLL 卸载时为 false。
        bool WaitForNextSessionConfig(MonitorConfig* const configOut, const CooperativeSessionFiles* cooperative)
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
                if (!LoadMonitorConfigForCurrentProcess(&candidateConfig, &errorText, cooperative))
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
        bool SessionConfigWasReplaced(const MonitorConfig& activeConfigValue, bool syncClipboardHooks,
            const CooperativeSessionFiles* cooperative)
        {
            if (activeConfigValue.sessionId.empty())
            {
                return false;
            }

            MonitorConfig observedConfig;
            std::wstring ignoredErrorText;
            if (!LoadMonitorConfigForCurrentProcess(&observedConfig, &ignoredErrorText, cooperative)
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
        void WaitForCurrentSessionStop(const MonitorConfig& configValue, HANDLE pauseEvent,
            const CooperativeSessionFiles* cooperative, bool initiallyPaused = false)
        {
            std::wstring lastRetryReport;
            bool hooksPaused = initiallyPaused;
            bool needsInstall = initiallyPaused;
            bool pauseFailureReported = false, resumeFailureReported = false;
            while (!g_processDetachRequested.load() && !StopRequested())
            {
                const bool pauseRequested = pauseEvent && ::WaitForSingleObject(pauseEvent, 0) == WAIT_OBJECT_0;
                if (IsStopFlagPresent(configValue) || SessionConfigWasReplaced(configValue, !pauseRequested && !needsInstall, cooperative))
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
                if (g_cooperativeState.load() == CooperativeState::Enabled)
                {
                    CompleteCooperativeStartup(failure);
                }
                // Agent exceptions must not terminate the host application.
                // Keep code resident, stop logging, and attempt safe restoration.
                ScopedInlineHookInternalBypass bypass;
                RequestStop();
                g_cooperativeState.store(CooperativeState::Rejected);
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
                    reinterpret_cast<LPCWSTR>(&MonitorWorkerThread), &pinnedAgent)) {
                g_cooperativeState.store(CooperativeState::Rejected);
                return 1;
            }
            ScopedInlineHookInternalBypass agentBypassScope;
            using Directory = ks::winapi_monitor::CooperativeSessionDirectory;
            Directory directory;
            DWORD directoryError = ERROR_SUCCESS;
            CooperativeSessionFiles files;
            switch (directory.open(directoryError)) {
            case Directory::Selection::Rejected:
                g_cooperativeState.store(CooperativeState::Rejected);
                TraceAgentFailure(L"Cooperative session directory rejected. error=" + std::to_wstring(directoryError));
                return directoryError;
            case Directory::Selection::Opened: {
                FILETIME created{}, exited{}, kernel{}, user{};
                if (!::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user)
                    || !ks::winapi_monitor::currentProcessUserSidString(&files.userSid)) {
                    g_cooperativeState.store(CooperativeState::Rejected);
                    TraceAgentFailure(L"Could not resolve cooperative Agent identity.");
                    return ERROR_ACCESS_DENIED;
                }
                const auto creation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
                const DWORD pid = ::GetCurrentProcessId();
                files.configPath = directory.configPath(pid, creation);
                files.stopPath = directory.stopPath(pid, creation);
                g_cooperativeState.store(CooperativeState::AwaitingEnable);
                while (!g_processDetachRequested.load() && g_cooperativeState.load() != CooperativeState::Enabled)
                    ::Sleep(kSessionIdlePollMs);
                break;
            }
            case Directory::Selection::Unset:
                g_cooperativeState.store(CooperativeState::Unselected);
                break;
            }
            const auto* cooperative = directory.selected() ? &files : nullptr;
            while (!g_processDetachRequested.load())
            {
                MonitorConfig configValue;
                if (!WaitForNextSessionConfig(&configValue, cooperative))
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
                    if (cooperative)
                    {
                        CompleteCooperativeStartup(IsStopFlagPresent(configValue) || StopRequested()
                            ? ERROR_OPERATION_ABORTED : ERROR_CONNECTION_ABORTED);
                    }
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
                    if (cooperative)
                    {
                        CompleteCooperativeStartup(cancelled ? ERROR_OPERATION_ABORTED : ERROR_GEN_FAILURE);
                    }
                    if(cancelled)RequestStop();
                    SendMonitorEvent(
                        ks::winapi_monitor::EventCategory::Internal,
                        L"Agent",
                        cancelled ? L"InstallHooksCancelled" : L"InstallHooksFailed",
                        1,
                        errorText);
                    if(!cancelled)WaitForCurrentSessionStop(configValue, pause.value, cooperative);
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

                constexpr auto installedDetail = L"Configured inline hooks are now active.";
                if (initiallyPaused)
                {
                    SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"HooksPaused", 0,
                        L"Session started paused; no hooks were installed.");
                }
                else if (cooperative)
                {
                    const bool announced = SendHooksInstalledEvent(installedDetail);
                    CompleteCooperativeStartup(!announced ? ERROR_WRITE_FAULT
                        : HasCooperativeStartupCoverage() ? ERROR_SUCCESS : ERROR_INVALID_DATA);
                }
                else
                {
                    SendMonitorEvent(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"HooksInstalled", 0,
                        installedDetail);
                }

                WaitForCurrentSessionStop(configValue, pause.value, cooperative, initiallyPaused);
                APIMON_DIAG_MARK("uninstall-begin",0,0);
                while (!UninstallConfiguredHooks() && !g_processDetachRequested.load())
                {
                    ::Sleep(kSessionActivePollMs);
                }
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
            g_cooperativeState.store(CooperativeState::Rejected);
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
        if (g_cooperativeState.load() == CooperativeState::Enabled)
        {
            DWORD result = g_cooperativeStartupResult.load();
            while (result == ERROR_IO_PENDING || result == ERROR_SUCCESS)
            {
                if (g_cooperativeStartupResult.compare_exchange_strong(result, ERROR_OPERATION_ABORTED))
                {
                    break;
                }
            }
        }
    }

    DWORD EnableCooperativeCapture()
    {
        auto state = CooperativeState::AwaitingEnable;
        if (g_cooperativeState.compare_exchange_strong(state, CooperativeState::Enabled)
            || state == CooperativeState::Enabled) return ERROR_SUCCESS;
        if (state == CooperativeState::Initializing) return ERROR_NOT_READY;
        if (state == CooperativeState::Unselected) return ERROR_NOT_SUPPORTED;
        return ERROR_ACCESS_DENIED;
    }

    DWORD WaitForCooperativeStartup(DWORD timeoutMs)
    {
        if (timeoutMs > kCooperativeStartupMaxWaitMs) return ERROR_INVALID_PARAMETER;
        ScopedInlineHookInternalBypass bypass;
        const auto started = ::GetTickCount64();
        const auto deadline = started + timeoutMs;
        for (auto now = started; ; now = ::GetTickCount64())
        {
            if (timeoutMs && now >= deadline) return ERROR_TIMEOUT;
            const auto state = g_cooperativeState.load();
            if (state == CooperativeState::Unselected) return ERROR_NOT_SUPPORTED;
            const DWORD result = g_cooperativeStartupResult.load();
            if (state == CooperativeState::Rejected)
            {
                return result != ERROR_IO_PENDING && result != ERROR_SUCCESS ? result : ERROR_ACCESS_DENIED;
            }
            if (state != CooperativeState::Enabled) return ERROR_NOT_READY;
            if (result != ERROR_IO_PENDING)
            {
                return result == ERROR_SUCCESS && StopRequested() ? ERROR_OPERATION_ABORTED : result;
            }

            if (!timeoutMs) return ERROR_TIMEOUT;
            ::Sleep(static_cast<DWORD>((std::min)(deadline - now, static_cast<ULONGLONG>(kCooperativeStartupPollMs))));
        }
    }
}

// Called by the target itself outside loader lock, after its Agent is resident.
// Success accepts the local opt-in. The existing pipe handshake reports session readiness.
#ifdef _M_IX86
#pragma comment(linker, "/export:KSwordApiMonitorEnableCooperativeCapture=_KSwordApiMonitorEnableCooperativeCapture@0")
#pragma comment(linker, "/export:KSwordApiMonitorWaitForCooperativeStartup=_KSwordApiMonitorWaitForCooperativeStartup@4")
#endif
extern "C" __declspec(dllexport) DWORD WINAPI KSwordApiMonitorEnableCooperativeCapture()
{
    return apimon::EnableCooperativeCapture();
}

// Call outside loader lock after explicit cooperative opt-in. Zero polls the local status.
// ERROR_SUCCESS confirms active local hooks and published coverage for the startup attempt.
// The controller independently verifies the packets on its own connection.
extern "C" __declspec(dllexport) DWORD WINAPI KSwordApiMonitorWaitForCooperativeStartup(DWORD timeoutMs)
{
    return apimon::WaitForCooperativeStartup(timeoutMs);
}
