#pragma once

#include "../../../shared/usermode/backend/Win32.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ks::cli::action_analyze::memory {

inline constexpr std::uint32_t kMaxTrackedPages = 64;
inline constexpr std::uint32_t kMaxSampleRounds = 64;
inline constexpr std::uint32_t kMaxReportedDiffRanges = 16;

struct Range {
    std::uint64_t base = 0;
    std::uint64_t length = 0; // 半开区间；0 不代表全部。
    bool operator==(const Range&) const = default;
};

struct ProcessInstance {
    std::string machineId;
    std::string bootId;
    std::string processInstanceId;
    std::uint32_t pid = 0;
    std::uint64_t creationFileTime100ns = 0;
    bool operator==(const ProcessInstance&) const = default;
};

struct Plan {
    std::string sampleId;
    std::string trackingEpoch; // 重新打开必须由控制者分配新代次。
    ProcessInstance target;
    Range range;
    std::optional<std::uint32_t> rounds = 20; // 有值为有限采样；nullopt 持续至停止、取消、目标退出或失败。
    std::uint32_t intervalMs = 100;
    bool authorizedOwnedProcess = false; // 调用方根据显式选择和授权给出，不由 PID 或 SID 推断所有权。
};

struct QpcWindow {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
};

enum class Stage {
    None, ValidatePlan, DuplicateProcess, ProcessId, ProcessCreation, ProcessMismatch, ProcessLifetime,
    OpenOwnerToken, OpenTargetToken, ReadTokenIdentity, TokenOwnerMismatch, CriticalProcess, TargetMachine,
    Clock, OpenHashProvider, QueryBeforeRead, ReadMemory, QueryAfterRead, CompareMappings, HashContent
};

struct Issue {
    Stage stage = Stage::None;
    std::uint32_t win32Error = 0;
    std::optional<std::int32_t> ntStatus;
};

struct Mapping {
    Range region; // VirtualQueryEx 返回的连续同属性区间，不是分配范围。
    std::uint64_t allocationBase = 0;
    std::uint32_t state = 0;
    std::uint32_t type = 0;
    std::uint32_t protection = 0;
    std::uint32_t allocationProtection = 0;
    bool operator==(const Mapping&) const = default;
};

struct Changes {
    bool firstMappingObservation = false;
    bool mappingContinuityReset = false;
    bool newlyCommitted = false;
    bool noLongerCommitted = false;
    bool mappingChanged = false;
    bool regionLayoutChanged = false;
    bool protectionChanged = false;
};

enum class ContentOrigin { Baseline, Unchanged, Changed };
using Sha256 = std::array<std::uint8_t, 32>;

struct ContentSample {
    std::uint64_t roundOrdinal = 0;
    std::uint64_t version = 0; // 在本页及本次 trackingEpoch 内递增；未知间隔后产生新基线。
    QpcWindow readQpc;
    Sha256 sha256{}; // 仅所选页内子范围的完整样本，不代表整个区域或执行时字节。
    ContentOrigin origin = ContentOrigin::Baseline;
};

struct Difference {
    std::uint32_t changedBytes = 0;
    std::uint32_t rangeCount = 0;
    std::vector<Range> ranges; // 绝对地址；遗漏数为 rangeCount - ranges.size()。
};

enum class PageStatus {
    NotCommitted, Guarded, UnsafeReadAttributes, NotReadable, QueryFailed, ReadFailed, MappingUnstable, HashFailed, Sampled
};

struct PageObservation {
    std::uint64_t pageBase = 0;
    Range sampledRange;
    PageStatus status = PageStatus::QueryFailed;
    std::optional<Mapping> before;
    std::optional<Mapping> after;
    std::optional<std::uint64_t> mappingGeneration; // 仅可见属性的观测代次，不保证识别同属性重建。
    Changes changes;
    Issue issue;
    std::optional<Issue> additionalIssue; // 保留读取失败与读后验证失败同时发生的事实。
    std::optional<QpcWindow> readQpc;
    std::optional<std::uint64_t> returnedBytes; // 只有实际调用 ReadProcessMemory 时才设置。
    std::optional<ContentSample> previousContent;
    std::optional<ContentSample> content;
    std::optional<Difference> difference;
};

struct Round {
    Plan effectivePlan; // 将结果与启动时冻结的样本、目标实例及范围绑定。
    std::uint64_t ordinal = 0;
    std::uint64_t beginQpc = 0;
    std::optional<std::uint64_t> endQpc;
    std::vector<PageObservation> pages; // 包含各页观测结果，失败页不会丢掉其余已完成结果。
    bool allPagesVisited = false;
};

enum class State { Idle, Active, Completed, Stopped, Canceled, TargetExited, Rejected, Failed };

struct Status {
    State state = State::Idle;
    Issue issue;
    std::uint32_t pointerWidth = 0;
    std::uint32_t pageSize = 0;
    std::uint32_t plannedPages = 0;
    std::uint64_t attemptedRounds = 0;
    std::uint64_t fullRounds = 0; // 每个范围均得到页观测（不代表全部内容读取成功）。
    std::uint64_t sampledPages = 0; // 跨轮累计，包含完整字节样本的页观测数。
    std::uint64_t unavailablePages = 0;
    std::uint64_t qpcFrequency = 0;
    std::optional<std::uint64_t> nextDueQpc;
};

struct PollResult {
    Status status;
    std::optional<Round> round; // 尚未到期或没有执行本轮时为空。
};

// 只在页内完整读取、前后映射相同且散列成功后调用；字节视图仅在同步回调期间有效。
// 回调不得重入观察器；由本端显式快照入口复制或归档，不给普通轮询隐式添加内存导出。
using CapturedPageVisitor = std::function<void(const PageObservation&, std::span<const std::uint8_t>)>;

enum class PollMode { SampleWhenDue, StatusOnly };

// 仅供内部、独立的可信证据适配器提供。供方须先验证原事件、进程实例、线程生存期和实际执行，
// 不得由公共请求反序列化后直接调用。这里的检查是关联检查，不能把上游声明验证成原生事实。
enum class ExecutionFact { Unverified, EnterAttempt, Executed };

struct ExecutionObservation {
    ExecutionFact fact = ExecutionFact::Unverified;
    ProcessInstance target;
    std::string sampleId;
    std::string sourceId;
    std::string sourceEpoch;
    std::uint64_t eventOrdinal = 0; // 外部样本事件的序号；与本模块的采样轮次不是同一序号。
    std::string threadInstanceId;
    std::uint32_t tid = 0;
    std::uint64_t threadCreationFileTime100ns = 0;
    std::uint64_t actualIp = 0;
    std::uint64_t qpc = 0;
    std::uint64_t qpcFrequency = 0;
};

enum class ExecutionRelation {
    NotVerified, InvalidEvidence, WrongInstance, ClockMismatch, OutsideSelectedRange, NoObservationWindow,
    OutsideObservationWindow, SameSampledVersionCandidate, VersionAmbiguous
};

struct ExecutionLink {
    ExecutionRelation relation = ExecutionRelation::NotVerified;
    std::string trackingEpoch;
    std::uint64_t pageBase = 0;
    Range sampledRange;
    std::optional<std::uint64_t> mappingGeneration;
    std::optional<ContentSample> before;
    std::optional<ContentSample> after;
    std::optional<ExecutionObservation> evidence; // 两次同代完整采样之间，独立证据确认该 IP 被执行。
};

// 单所有者串行调用，不开后台线程，不等待轮次间隔。每个对象只接受一次 Begin。
// Begin 临时借用已选进程的读句柄，独立持有最小权限副本；不会按 PID 重新打开。
// Poll 最多处理一轮，不积存历史轮次；调用者负责调度及输出预算。StatusOnly 仅推进取消/退出，
// 不读取页面、不改采样时钟；输出恢复后 SampleWhenDue 执行一次新观测，不补采过去的轮次。
// 取消在页采样之间合作生效，不打断正在执行的原生调用。Stop 必须由同一所有者调用。
// 终态释放句柄和比较用字节，保留每页最新的可比相邻观测对以供迟到证据关联。
class PassiveDirtyMemory final {
public:
    PassiveDirtyMemory();
    ~PassiveDirtyMemory();
    PassiveDirtyMemory(const PassiveDirtyMemory&) = delete;
    PassiveDirtyMemory& operator=(const PassiveDirtyMemory&) = delete;

    [[nodiscard]] Status Begin(HANDLE selectedProcess, const Plan& plan);
    [[nodiscard]] Status Query() const noexcept;
    [[nodiscard]] PollResult Poll(const std::atomic_bool* cancel = nullptr, PollMode mode = PollMode::SampleWhenDue);
    // 与 Poll 使用同一读取路径，额外将本轮成功页的原字节交给显式采样调用者。
    [[nodiscard]] PollResult PollCapture(const CapturedPageVisitor& visitor, const std::atomic_bool* cancel = nullptr);
    [[nodiscard]] Status Stop() noexcept;
    [[nodiscard]] ExecutionLink CorrelateExecution(const ExecutionObservation& observation) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ks::cli::action_analyze::memory
