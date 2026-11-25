#pragma once

#include "FilterAst.h"

#include <optional>

namespace Ksword::ActionAnalyze::Rules {

struct EventTime {
    std::string_view clockId;
    std::uint64_t ticks100ns; // 适配器保证同域、顺序可比较且可无损表达。
    friend bool operator==(const EventTime&, const EventTime&) = default;
};

// 仅为离线执行器的只读投影。ID 和强身份由归档适配器解析、验真后提供。
// 无强 actor 线程时留空。不能用 PID/TID、ETW header 或收包序号填补。
struct ReplayEvent {
    std::string_view sampleId;
    std::uint64_t ordinal;
    std::string_view sourceId;
    std::string_view sourceEpoch;
    std::optional<std::uint64_t> sourceSequence;
    std::string_view strongActorThreadId;
    std::optional<EventTime> time;
    std::string_view eventType;
    Phase phase;
    std::span<const FieldSample> fields;
};

struct ReplayScope {
    // 归档解析器应按验证过的实例身份统一线程键，保留样本和来源命名空间。
    std::string_view sampleId;
    std::string_view sourceId;
    std::string_view sourceEpoch;
    std::string_view strongActorThreadId;
    std::string_view clockId;
    friend bool operator==(const ReplayScope&, const ReplayScope&) = default;
};

struct Selection {
    // 阶段取自已准备谓词，适配器负责为精确事件种类绑定目录。
    std::string_view eventType;
    const PreparedPredicate* predicate = nullptr;
};

enum class ReplayKind { CountAtLeast, CountEqual, Sequence };
inline constexpr std::uint64_t MaxWindow100ns = 3600ULL * 10'000'000ULL;

struct ReplayRule {
    ReplayKind kind;
    Selection step;
    Selection anchor;
    std::uint64_t window100ns;
    std::uint64_t threshold = 0; // Sequence 不使用该字段。
};

struct VerifiedCoverage {
    // 闭区间。覆盖凭证绑定到本次的样本、作用域和归档 cutoff。
    ReplayScope scope;
    std::uint64_t archiveThroughOrdinal;
    std::uint64_t from100ns;
    std::uint64_t through100ns;
};

struct ReplaySnapshot {
    std::string_view analysisRunId;
    ReplayScope scope;
    std::uint64_t archiveThroughOrdinal;
    // 调用方只在固定归档内确认所需 selector/字段连续覆盖、无 gap 且有效水位已达时传入。
    // coverage 适用于本次 rule/snapshot，不能由 sealed、流静默或收到的最后一条事件推导。
    std::optional<VerifiedCoverage> coverage;
    // 只有已登记保证发布顺序的来源才置 true。源序号缺失或相等时仍不能建立严格顺序。
    bool orderedSourceSequence = false;
};

struct ReplayBudget {
    // 可下调的原型硬上限，包含输入、窗口候选和运行计费。
    std::size_t maxInputEvents = 4096;
    std::size_t maxWindowCandidates = 256;
    std::size_t maxWorkUnits = 1'000'000;
};

enum class ReplayError { None, InvalidRequest, InvalidEvent, ConflictingEventId, InputLimit };
enum class ReplayIssue : unsigned {
    None = 0,
    Coverage = 1u << 0,
    ActorThread = 1u << 1,
    Clock = 1u << 2,
    Order = 1u << 3,
    PredicateUnknown = 1u << 4,
    PredicateInvalid = 1u << 5,
    Budget = 1u << 6,
    WindowLimit = 1u << 7,
};

constexpr bool HasIssue(ReplayIssue set, ReplayIssue issue) noexcept
{
    return (static_cast<unsigned>(set) & static_cast<unsigned>(issue)) != 0;
}

// 可比较锚点对应的闭区间。弱身份或缺时间的候选锚点不出区间。
struct WindowRange {
    std::uint64_t start100ns;
    std::uint64_t end100ns;
};

struct WindowEvidence {
    std::uint64_t anchorOrdinal;
    Truth truth = Truth::Unknown;
    ReplayIssue issues = ReplayIssue::None;
    std::optional<WindowRange> range;
    // 每个 ordinal 是确定的单事件计数依据，或与 anchorOrdinal 组成一组确定序列。
    // 缺口或预算导致的不完整窗口中，这里只枚举已经确认的下界。
    std::vector<std::uint64_t> stepOrdinals;
};

struct ReplayResult {
    ReplayError error = ReplayError::None;
    ReplayIssue issues = ReplayIssue::None;
    std::string analysisRunId;
    std::string sampleId;
    std::uint64_t archiveThroughOrdinal = 0;
    std::size_t duplicateEvents = 0;
    std::vector<WindowEvidence> windows;
};

// 一个固定样本、一源 epoch、一强 actor 线程、一比较时钟。只读 committed 前缀。
// 计数是 CountEvents，区间 [anchor-window, anchor]。序列为两步、有序、不要求相邻。
// 输出按 anchor/step ordinal 确定性排列，ordinal 只作事件身份及展示次序。
// 各视图或指针在调用期间有效；结果仅拥有分析身份、判定和证据引用。
ReplayResult Replay(const ReplaySnapshot& snapshot, const ReplayRule& rule,
                    std::span<const ReplayEvent> events, ReplayBudget budget = {});

} // namespace Ksword::ActionAnalyze::Rules
