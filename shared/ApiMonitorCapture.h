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
    DWORD durationMs = 1000, startupTimeoutMs = 30000, stopTimeoutMs = 15000;
    // A resident-only request with a packet callback may set 0 to skip retention.
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
    // 仅合作模式调用一次。传入已通过启动屏障的管道会话及覆盖修订，供调用方发布轻量进度。
    std::function<void(std::uint64_t session, std::uint64_t coverageRevision)> onResidentReady;
    // 合作采样线程每轮读管道后调用，允许低频输入的待写入数据按时提交。
    std::function<void()> onResidentPoll;
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
};
CaptureResult captureApiMonitor(const CaptureRequest& request, const std::atomic_bool& cancel);
}
