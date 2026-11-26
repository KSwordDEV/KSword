#pragma once
#include "ApiMonitorCoverage.h"
#include "ApiMonitorCliView.h"
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>

namespace ks::winapi_monitor {
// Value-only, Qt-free controller. Injection, leases and wire decoding are the
// same implementations used by WinAPIDock; callers own output and cancellation.
struct CaptureRequest {
    DWORD pid = 0;
    std::wstring agentPath;
    // 合作驻留及显式严格附加可用 durationMs=0；启动及清退仍分别限时。
    DWORD durationMs = 1000, startupTimeoutMs = 30000, stopTimeoutMs = 15000;
    // A strict observational request with a packet callback may skip retention.
    std::size_t eventLimit = 5000;
    bool autoChildren = false;
    // Explicitly selected injection mechanism; never silently fall back.
    // A resident Agent may be reused without a new injection.
    bool useR0Injection = false;
    CliEventFilter preFilter, postFilter, importedPreFilter, importedPostFilter;
    bool collectTimeline = false;
    std::map<std::wstring, std::wstring> options;
    // Nonzero selects diagnostics for an authorized, cooperating target with
    // this exact creation FILETIME and an already loaded product Agent. The
    // caller owns authorization and supplies the trusted product agentPath.
    // Requires the private cooperative directory. R0, remote loading, child
    // capture and behavior-changing options are disabled.
    std::uint64_t residentCreationFileTime = 0;
    // Called synchronously on the capture thread for every packet that passes
    // framing, protocol version, PID and session checks on the verified pipe.
    // Includes control and raw coverage packets before CLI filtering/retention;
    // the coverage receiver validates snapshot sequencing separately. The packet
    // is borrowed for this call. Keep work bounded; a throw stops the capture
    // and further callbacks while the controller still drains for cleanup.
    std::function<void(const ApiMonitorEventPacket&)> onVerifiedPacket;
    // 严格观察模式调用。借用已核验的进程句柄，在发布配置前启动配套只读采集。
    std::function<void(HANDLE)> beforeResidentPublish;
    // 严格观察模式就绪时调用一次，提供同一管道会话及完整覆盖修订。
    std::function<void(std::uint64_t session, std::uint64_t coverageRevision)> onResidentReady;
    // 严格观察采样每轮读管道后调用，允许低频输入按时提交。
    std::function<void()> onResidentPoll;
    // Explicit R3 attachment is separate from resident cooperative admission.
    // All three fields are required together. The same exact process is retained
    // through publication, loading, pipe verification and stop/drain.
    std::uint64_t attachCreationFileTime = 0;
    bool attachConfirmed = false;
    bool strictReadOnlyObservation = false;
};
struct CaptureProcess {
    DWORD pid = 0, pipeError = 0;
    std::uint64_t creation = 0, session = 0, revision = 0, finalRevision = 0, agentDropped = 0;
    bool connected = false, installed = false, removed = false, exited = false;
    bool installFailed = false, partialHooks = false, coverageComplete = false, coverageStale = true;
    std::vector<ApiMonitorEventPacket> coverage;
    bool sessionReady = false; // 同一已核验管道报告 SessionReady，不代表 Hook 安装成功。
    bool cleanPipeEof = false; // 只在管道正常到达包边界 EOF 后为真，不等同于目标退出。
};
struct CaptureResult {
    int code = 3;
    std::wstring sessionId, agentPath, configPath, stopPath;
    std::vector<std::wstring> errors;
    bool configPublished = false, reusedResident = false, cancelled = false;
    // completedInterval 仅表示有限时区间已足时；持续模式停止不伪造到时完成。
    bool completedInterval = false, stopWritten = false, cleanupComplete = false;
    std::uint64_t elapsedMs = 0, received = 0, bufferDropped = 0, invalidPackets = 0, preFiltered = 0;
    std::optional<std::uint64_t> readyAfterMs; // 启动屏障成立时距调用开始的时间。
    std::optional<std::uint64_t> readyCoverageRevision; // 合作模式在启动时实际核验的完整覆盖修订。
    std::optional<std::uint64_t> intervalElapsedMs; // 从就绪到结束采样，不含清退。
    std::deque<ApiMonitorEventPacket> events;
    std::vector<CaptureProcess> processes;
    CliTimeline timeline;
    // Capture passed the startup barrier. A late install during cleanup can
    // appear in processes[].installed even if started is false.
    bool started = false;
    bool attachmentIdentityVerified = false;
    bool agentLoadAttempted = false;
    bool agentModuleVerified = false; // Module presence only; never Hook readiness.
};
CaptureResult captureApiMonitor(const CaptureRequest& request, const std::atomic_bool& cancel);
}
