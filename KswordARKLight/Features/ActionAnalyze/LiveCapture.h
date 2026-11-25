#pragma once

#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"
#include "../../../shared/usermode/backend/monitor/PassiveEtwSource.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Ksword::Features::ActionAnalyze {

struct LiveCaptureProject {
    std::wstring manifestPath; // 用户明确选择的本地项目清单。
    std::string projectId; // 冻结的项目 UUID。
    std::string revisionId; // 冻结的项目修订 UUID。
};

struct LiveCaptureRequest {
    DWORD pid = 0; // 用户选定的进程号。
    std::uint64_t creationFileTime = 0; // 选择时已核对的创建时间。
    std::optional<ks::r3::monitor::PassiveEtwOptions> etw; // 显式选择的单一来源。
    std::optional<LiveCaptureProject> project; // 空值表示仅实时查看。
};

enum class LiveCaptureState { Idle, Running, Stopping, CleanupPending, Stopped, Failed };
enum class LiveCaptureEnd { None, Requested, TargetExited, ProcessError };

struct LiveProcessInterval {
    std::uint64_t sequence = 0; // 本次采样内的进程观察顺序。
    std::uint64_t beginTickMs = 0; // 单调时钟的上一基线。
    std::uint64_t endTickMs = 0; // 同一单调时钟的本次采样点。
    std::optional<std::uint64_t> receiveQpc; // 读数完成时的原生 QPC。
    std::uint64_t cpu100ns = 0; // 内核与用户 CPU 时间增量。
    std::optional<std::uint64_t> readBytes, writeBytes; // 进程 I/O 传输量，读取失败时为空。
    DWORD ioError = ERROR_SUCCESS; // I/O 读取或计数异常的具体原因。
};

struct LiveEtwObservation {
    ks::r3::monitor::PassiveEtwRecord record; // 实时与归档共用的实际观察值。
    std::uint64_t sequence = 0; // 本次会话接纳的 ETW 观察顺序。
    std::optional<std::uint64_t> segmentOrdinal, rawSequence; // 已提交的归档定位，失败时为空。
};

struct LiveCaptureStatus {
    LiveCaptureState state = LiveCaptureState::Idle; // 本端采集及清退的实际状态。
    LiveCaptureEnd end = LiveCaptureEnd::None; // 最早的终止原因。
    DWORD pid = 0; // 冻结目标的进程号。
    std::uint64_t creationFileTime = 0; // 冻结目标的创建时间。
    std::string sessionEpoch; // 本次本地会话的唯一身份。
    std::string projectId, sampleId; // 已登记项目／采样的真实身份。
    const char* processStage = ""; // Win32 失败阶段的稳定诊断值。
    DWORD processError = ERROR_SUCCESS; // 原始 Win32 错误码。
    std::optional<ks::r3::monitor::PassiveEtwStatus> etw; // 原生回执与来源独立计数。
    bool archiveRequested = false; // 区分纯观察、项目拒绝和项目已登记。
    Ksword::ActionAnalyze::ProjectResult archive; // 首个项目或提交失败。
    std::uint64_t processIntervals = 0; // 成功取得的进程区间。
    std::uint64_t etwObserved = 0, etwOutOfScope = 0; // 已出队的有效观察和超出冻结时间范围的记录。
    std::uint64_t archivedEtw = 0, verifiedSegments = 0; // 已发布的 ETW 数与段水位。
    bool finalCheckpoint = false; // 仅当终段标记实际发布才成立。
};

struct LiveCaptureUpdate {
    LiveCaptureStatus status; // 同一工作线程提交的状态快照。
    std::optional<LiveProcessInterval> process; // 一轮最多交付一个实际区间。
    std::vector<LiveEtwObservation> etw; // 一轮至多 kMaxEtwBatch 条观察。
};

// 对象仅服务一次采样。所有生命周期和回读在同一工作线程串行调用。
// GUI 可跨线调用 RequestStop。收到停止意图后继续 Poll 至终态，失败清退用 Stop 重试。
class LiveCapture final {
public:
    static constexpr std::size_t kMaxEtwBatch = 128; // 每次工作推进处理的记录量。
    static constexpr auto kPollInterval = std::chrono::milliseconds(100); // 空闲时建议的工作线程节拍。

    LiveCapture();
    ~LiveCapture(); // 工作线程在清退结束后销毁。
    LiveCapture(const LiveCapture&) = delete;
    LiveCapture& operator=(const LiveCapture&) = delete;

    // 校验冻结请求并尝试启动可选来源。返回可供调用者发布的真实状态。
    LiveCaptureStatus Start(const LiveCaptureRequest& request);
    // 推进一轮进程查询、ETW 排空和提交。返回本轮新增值及水位。
    LiveCaptureUpdate Poll();
    // 提交停止意图并推进一轮，或对原生清退失败执行一次显式重试。
    LiveCaptureUpdate Stop();
    // 仅设置协作停止标志。调用方可同时唤醒其工作线程。
    void RequestStop() noexcept;

private:
    struct Impl;
    std::atomic_bool stopRequested_{false}; // 唯一可跨线程修改的请求标志。
    std::unique_ptr<Impl> impl_; // 持有目标句柄、来源、项目租约和状态。
};

} // namespace Ksword::Features::ActionAnalyze
