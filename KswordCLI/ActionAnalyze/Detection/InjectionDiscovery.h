#pragma once

#include "../../../shared/evidence/ObjectIdentity.h"

#include <optional>
#include <variant>
#include <vector>

namespace Ksword::ActionAnalyze::Detection {

// 本端归档先校验采样及索引。原始段号从 1 开始；序号沿用 raw 段，不是事件 ordinal。
struct RawLocator {
    std::uint64_t segmentOrdinal = 0;
    std::uint64_t sequence = 0;
    friend bool operator==(const RawLocator&, const RawLocator&) = default;
};

// 由调用方从当前采样分配；至少提供一个可回读位置。来源序号不能代替事件或归档序号。
struct EvidenceRef {
    std::string projectId;
    std::string sampleId;
    std::string sourceId;
    std::string sourceEpoch;
    std::optional<std::uint64_t> eventOrdinal;
    std::optional<RawLocator> raw;
    std::optional<std::uint64_t> sourceSequence;
    std::string sourceGroup;                       // 同一底层来源的两层包装使用同组。
    bool operator==(const EvidenceRef&) const = default;
};

// 同一采样只能消费绑定到该机器及启动期的对象。调用方从可信采样元数据提供这些键。
struct SampleScope {
    std::string projectId;
    std::string sampleId;
    std::string machineId;
    std::string bootId;
};

struct ProcessBinding {
    std::string machineId;
    Evidence::ProcessInstanceId instance;
};

struct ThreadBinding {
    ProcessBinding owner;
    std::uint32_t tid = 0;
    std::uint64_t creationFileTime = 0;
};

// 已归一到相同可比较时钟域的闭区间，包括误差范围；收包时间不能代替事实时钟。
struct FactTime {
    std::string clockDomain;
    std::uint64_t earliest = 0;
    std::uint64_t latest = 0;
};

// 由现有区域及内容账本解析的样本内引用。写入侧是完成后的版本，执行侧是取指时版本。
struct RegionVersion {
    std::string regionId;
    std::uint64_t mappingGeneration = 0;
    std::uint64_t contentVersion = 0;
    std::uint64_t base = 0;
    std::uint64_t length = 0;
    friend bool operator==(const RegionVersion&, const RegionVersion&) = default;
};

enum class Phase { Entry, Return, Complete, Observation };
enum class Outcome { Unknown, Failed, Succeeded, PartiallySucceeded };
// Validated 必须来自已认证且按精确来源/阶段解码的记录；不从源包自称的标志读取。
enum class InputTrust { RawOnly, Validated };

struct ObservationHeader {
    EvidenceRef evidence;
    InputTrust trust = InputTrust::RawOnly;
    Phase phase = Phase::Observation;
    std::optional<FactTime> time;
    std::string operation;                         // 精确事件种类，不用于猜测缺失字段。
    std::optional<std::uint64_t> returnBits;        // 不截断；保留原始返回及独立错误域。
    std::string errorDomain;
    std::optional<std::uint32_t> nativeError;
};

struct WriteObservation {
    ObservationHeader header;
    std::optional<ProcessBinding> actor, target;    // 发生时已绑定；不能事后用裸句柄或 PID 填入。
    Outcome outcome = Outcome::Unknown;
    std::optional<std::uint64_t> address;          // 实际写入连续范围起点，不是未落实的请求起点。
    std::optional<std::uint64_t> requestedLength;
    std::optional<std::uint64_t> completedLength;  // 只有可信来源报告的实际成功字节数。
    std::optional<RegionVersion> regionAfter;
    std::uint32_t actorPidHint = 0, actorTidHint = 0;
};

struct ThreadCreationObservation {
    ObservationHeader header;
    std::optional<ProcessBinding> creator, target;  // creator 角色由来源定义，不借用任意事件头。
    std::optional<ThreadBinding> newThread;
    Outcome outcome = Outcome::Unknown;
    std::optional<std::uint64_t> startAddress;      // 线程报出的入口，不代表实际 RIP。
    std::uint32_t creatorPidHint = 0, targetPidHint = 0;
    std::uint32_t creatorTidHint = 0, targetTidHint = 0;
};

enum class ExecutionState { Unknown, FetchAttempt, Executed };
struct ExecutionObservation {
    ObservationHeader header;
    std::optional<ThreadBinding> observedThread;    // 执行者，不等于写入者或创建者。
    ExecutionState state = ExecutionState::Unknown;
    std::optional<std::uint64_t> instructionPointer;
    std::optional<RegionVersion> regionAtExecution;
};

using InjectionEvent = std::variant<WriteObservation, ThreadCreationObservation, ExecutionObservation>;

enum class FindingKind { ExternalWrite, ThreadCreated, ExecutionFetched, ExecutionConfirmed };
enum class Attribution { Unknown, DirectWriter, DirectThreadCreator };
enum class Issue {
    EvidenceUnavailable, SourceUnverified, WrongPhase, OutcomeUnknown, OutcomeInconsistent,
    ActorInstanceUnknown, TargetInstanceUnknown, IdentityConflict, ThreadInstanceUnknown,
    ActualWriteRangeUnknown, InvalidWriteRange, RegionVersionUnknown, InvalidRegionVersion,
    ExecutionUnknown, InstructionPointerUnknown, LegacySummaryOnly, EtwContextOnly,
    InvalidNativeRecord, SourceCoverageUnknown, SourceLoss, SourcePayloadTruncated,
};

// 告警表示直接外来操作事实，不代表攻击，也不把创建者写进执行者身份。
struct Finding {
    FindingKind kind;
    Attribution attribution = Attribution::Unknown;
    bool externalOperation = false;
};

struct EventProjection {
    std::optional<InjectionEvent> observation;     // 原样保留已绑定采样的事实/线索及回读锚点。
    std::optional<Finding> finding;
    std::vector<Issue> gaps;
};

// 校验定位是否匹配采样并可寻址。定位存在不等于归档已落盘；提交由样本写入者核对。
bool HasEvidenceLocation(const SampleScope& scope, const EvidenceRef& evidence) noexcept;
// 校验机器、启动期及强进程身份。该函数不从系统回填缺失字段。
bool IsBoundProcess(const SampleScope& scope, const ProcessBinding& process) noexcept;
// 两个实例均已核实。创建者必须在新线程创建时已经存在，且同 PID 时只能是宿主实例。
bool IsPossibleThreadCreator(const ProcessBinding& creator, const ThreadBinding& newThread) noexcept;
// 逐事件只读投影。没有扫描、定时器、目标写入或告警处置。结果持有输入，便于独立回读。
EventProjection ProjectInjectionEvent(const SampleScope& scope, InjectionEvent event);

struct ExecutionCorrelation {
    EvidenceRef write;
    EvidenceRef execution;
    RegionVersion version;
    // 只支持同版本同范围内的候选关联，不把独立执行事实反推成整条注入链的因果归因。
};

// 用不同来源的执行确认和外来写入做候选关联。要求同一目标/版本、真实 RIP 落在已写的
// 半开区间，且事实时钟严格先写后执行。范围/时间相似本身不能成为直接归因。
std::optional<ExecutionCorrelation> CorrelateWriteExecution(const SampleScope& scope,
    const WriteObservation& write, const ExecutionObservation& execution);

} // namespace Ksword::ActionAnalyze::Detection
