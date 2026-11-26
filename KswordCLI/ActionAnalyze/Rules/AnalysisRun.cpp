#include "AnalysisRun.h"

#include <algorithm>
#include <map>
#include <utility>

namespace Ksword::ActionAnalyze::Rules {
namespace {

constexpr std::size_t MaxProjectedBytes = 8 * 1024 * 1024;
constexpr ReplayBudget HardBudget;

// 汇总诊断时保留窗口内的全部已发现原因。
ReplayIssue& operator|=(ReplayIssue& left, ReplayIssue right)
{
    left = static_cast<ReplayIssue>(static_cast<unsigned>(left) | static_cast<unsigned>(right));
    return left;
}

bool Key(std::string_view key)
{
    return !key.empty() && key.size() <= MaxKeyBytes;
}

bool ValidRequest(const ReplaySnapshot& snapshot, const ReplayRule& rule, ReplayBudget budget)
{
    // 请求必须固定分析身份和作用域。无可信覆盖凭证时仍可回放正证据。
    const auto& scope = snapshot.scope;
    if (!Key(snapshot.analysisRunId) || !Key(scope.sampleId) || !Key(scope.sourceId) ||
        !Key(scope.sourceEpoch) || !Key(scope.strongActorThreadId) || !Key(scope.clockId)) {
        return false;
    }
    if (snapshot.coverage &&
        (snapshot.coverage->scope != scope || snapshot.coverage->archiveThroughOrdinal != snapshot.archiveThroughOrdinal ||
         snapshot.coverage->from100ns > snapshot.coverage->through100ns)) {
        return false;
    }
    for (const Selection* selector : {&rule.step, &rule.anchor}) {
        if (!Key(selector->eventType) || !selector->predicate || !selector->predicate->valid()) {
            return false;
        }
    }
    // 只接受本切片支持的规则和可兑现的窗口、输入与工作预算。
    if (rule.window100ns > MaxWindow100ns || budget.maxInputEvents == 0 ||
        budget.maxInputEvents > HardBudget.maxInputEvents || budget.maxWindowCandidates == 0 ||
        budget.maxWindowCandidates > HardBudget.maxWindowCandidates || budget.maxWorkUnits == 0 ||
        budget.maxWorkUnits > HardBudget.maxWorkUnits) {
        return false;
    }
    switch (rule.kind) {
    case ReplayKind::CountAtLeast: case ReplayKind::CountEqual:
        return true;
    case ReplayKind::Sequence:
        return rule.threshold == 0;
    }
    return false;
}

bool SameRecord(const ReplayEvent& left, const ReplayEvent& right)
{
    // sample 和 ordinal 已包含在本次唯一键内。sourceSequence 自身可能对应多条规范事件。
    return left.sourceId == right.sourceId && left.sourceEpoch == right.sourceEpoch &&
           left.sourceSequence == right.sourceSequence && left.strongActorThreadId == right.strongActorThreadId &&
           left.time == right.time && left.eventType == right.eventType && left.phase == right.phase &&
           std::equal(left.fields.begin(), left.fields.end(), right.fields.begin(), right.fields.end());
}

using FrozenEvents = std::map<std::uint64_t, const ReplayEvent*>;

// 先冻结 committed 前缀并验证事件身份。冲突时整次请求不产生窗口结果。
ReplayError FreezeEvents(const ReplaySnapshot& snapshot, std::span<const ReplayEvent> events,
                         FrozenEvents& frozen, std::size_t& duplicates)
{
    std::size_t remainingBytes = MaxProjectedBytes;
    const auto charge = [&](std::size_t n) {
        if (n > remainingBytes) {
            return false;
        }
        remainingBytes -= n;
        return true;
    };
    for (const auto& event : events) {
        if (event.ordinal > snapshot.archiveThroughOrdinal) {
            continue;
        }
        if (event.sampleId != snapshot.scope.sampleId || !Key(event.sourceId) ||
            !Key(event.sourceEpoch) || !Key(event.eventType) ||
            event.strongActorThreadId.size() > MaxKeyBytes || (event.time && !Key(event.time->clockId)) ||
            event.phase < Phase::Entry || event.phase > Phase::Observation) {
            return ReplayError::InvalidEvent;
        }
        if (event.fields.size() > MaxEventFields) {
            return ReplayError::InputLimit;
        }
        // 大小计入重复行，以限制后续一致性比较成本。
        std::string_view previous;
        for (const auto& field : event.fields) {
            if (!Key(field.id) || previous >= field.id) {
                return ReplayError::InvalidEvent;
            }
            if (!charge(sizeof(FieldSample) + field.id.size())) {
                return ReplayError::InputLimit;
            }
            if (const auto* text = std::get_if<std::string_view>(&field.value); text && !charge(text->size())) {
                return ReplayError::InputLimit;
            }
            previous = field.id;
        }
        const auto [it, inserted] = frozen.emplace(event.ordinal, &event);
        if (!inserted) {
            if (!SameRecord(*it->second, event)) {
                return ReplayError::ConflictingEventId;
            }
            ++duplicates;
        }
    }
    return ReplayError::None;
}

bool Selects(const Selection& selector, const ReplayEvent& event)
{
    return selector.eventType == event.eventType && selector.predicate->phase() == event.phase;
}

ReplayIssue IssueFor(const Evaluation& evaluation)
{
    switch (evaluation.fault) {
    case EvaluationFault::Budget: return ReplayIssue::Budget;
    case EvaluationFault::InvalidInput: return ReplayIssue::PredicateInvalid;
    case EvaluationFault::DivisionByZero: return ReplayIssue::PredicateInvalid;
    case EvaluationFault::None:
        return evaluation.truth == Truth::Unknown ? ReplayIssue::PredicateUnknown : ReplayIssue::None;
    }
    return ReplayIssue::PredicateInvalid;
}

struct EvaluatedEvent {
    const ReplayEvent* event;
    Evaluation predicate;
};

// 每次回放私有的暂存状态。只借用输入，窗口结果由 ReplayResult 拥有。
class WindowReplay {
public:
    WindowReplay(const ReplaySnapshot& snapshot, const ReplayRule& rule,
                 ReplayBudget budget, ReplayResult& result)
        : snapshot_(snapshot), rule_(rule), budget_(budget), remainingWork_(budget.maxWorkUnits), result_(result)
    {
    }

    void Run(const FrozenEvents& frozen)
    {
        // 先以精确类型和阶段匹配。候选字段只求值一次，再用于各个窗口。
        std::vector<EvaluatedEvent> anchors;
        for (const auto& entry : frozen) {
            const auto* row = entry.second;
            if (row->sourceId != snapshot_.scope.sourceId || row->sourceEpoch != snapshot_.scope.sourceEpoch ||
                (!row->strongActorThreadId.empty() && row->strongActorThreadId != snapshot_.scope.strongActorThreadId)) {
                continue;
            }
            if (Selects(rule_.step, *row)) {
                const auto evaluation = Test(rule_.step, *row);
                if (evaluation.truth != Truth::False) {
                    candidates_.push_back({row, evaluation});
                }
            }
            if (Selects(rule_.anchor, *row)) {
                const auto evaluation = Test(rule_.anchor, *row);
                if (evaluation.truth != Truth::False) {
                    anchors.push_back({row, evaluation});
                }
            }
        }
        // 按事件 ordinal 输出固定次序。时序证明独立使用源序号。
        for (const auto& anchor : anchors) {
            auto window = Match(anchor);
            result_.issues |= window.issues;
            result_.windows.push_back(std::move(window));
        }
    }

private:
    Evaluation Test(const Selection& selector, const ReplayEvent& event)
    {
        const auto evaluation = EvaluatePredicate(*selector.predicate, event.phase, event.fields, remainingWork_);
        remainingWork_ -= evaluation.workUsed;
        // 即便没有锚点，读到的执行错误仍需在运行回执可见。
        if (evaluation.fault != EvaluationFault::None) {
            result_.issues |= IssueFor(evaluation);
        }
        return evaluation;
    }

    bool Comparable(const ReplayEvent& event) const
    {
        return event.time && event.time->clockId == snapshot_.scope.clockId;
    }

    WindowEvidence Match(const EvaluatedEvent& anchor)
    {
        // 只有强线程、可比较的时钟以及明确匹配的锚点才能建立窗口。
        const auto& last = *anchor.event;
        WindowEvidence window{last.ordinal, Truth::Unknown, IssueFor(anchor.predicate), {}, {}};
        if (last.strongActorThreadId.empty()) {
            window.issues |= ReplayIssue::ActorThread;
        }
        if (!Comparable(last)) {
            window.issues |= ReplayIssue::Clock;
        }
        if (window.issues != ReplayIssue::None) {
            return window;
        }

        // 无符号时域以零为最小值。首尾都算进窗口，且须分别达到覆盖边界。
        const auto end = last.time->ticks100ns;
        const auto start = end >= rule_.window100ns ? end - rule_.window100ns : 0;
        window.range = WindowRange{start, end};
        const auto& coverage = snapshot_.coverage;
        if (!coverage || coverage->from100ns > start || coverage->through100ns < end) {
            window.issues |= ReplayIssue::Coverage;
        }

        const bool sequence = rule_.kind == ReplayKind::Sequence;
        std::size_t windowCandidates = 0;
        for (const auto& candidate : candidates_) {
            // 比较候选消耗总工作量。耗尽时保留已有的正证据和不完整原因。
            if (remainingWork_ == 0) {
                window.issues |= ReplayIssue::Budget;
                break;
            }
            --remainingWork_;
            const auto& first = *candidate.event;
            // 同一事件不能充当序列两步。计数可以包含当前锚点。
            if (sequence && first.ordinal == last.ordinal) {
                continue;
            }
            const bool timeComparable = Comparable(first);
            if (timeComparable && (first.time->ticks100ns < start || first.time->ticks100ns > end)) {
                continue;
            }
            const bool orderComparable = snapshot_.orderedSourceSequence && first.sourceSequence && last.sourceSequence;
            if (sequence && orderComparable && *first.sourceSequence > *last.sourceSequence) {
                continue;
            }
            if (windowCandidates == budget_.maxWindowCandidates) {
                window.issues |= ReplayIssue::WindowLimit;
                break;
            }
            ++windowCandidates;
            // 时间、身份、顺序或条件未知会影响完整性，但不会凑阈值。
            auto issue = IssueFor(candidate.predicate);
            if (first.strongActorThreadId.empty()) {
                issue |= ReplayIssue::ActorThread;
            }
            if (!timeComparable) {
                issue |= ReplayIssue::Clock;
            }
            if (sequence && (!orderComparable || *first.sourceSequence == *last.sourceSequence)) {
                issue |= ReplayIssue::Order;
            }
            window.issues |= issue;
            if (issue == ReplayIssue::None) {
                window.stepOrdinals.push_back(first.ordinal);
            }
        }

        const auto lowerBound = window.stepOrdinals.size();
        // 正命中下界仍有价值。精确计数需要完整窗口。
        const bool complete = window.issues == ReplayIssue::None;
        switch (rule_.kind) {
        case ReplayKind::CountAtLeast:
            window.truth = lowerBound >= rule_.threshold ? Truth::True : (complete ? Truth::False : Truth::Unknown);
            break;
        case ReplayKind::CountEqual:
            if (complete) {
                window.truth = lowerBound == rule_.threshold ? Truth::True : Truth::False;
            }
            break;
        case ReplayKind::Sequence:
            window.truth = lowerBound != 0 ? Truth::True : (complete ? Truth::False : Truth::Unknown);
            break;
        }
        return window;
    }

    const ReplaySnapshot& snapshot_;
    const ReplayRule& rule_;
    ReplayBudget budget_;
    std::size_t remainingWork_;
    ReplayResult& result_;
    std::vector<EvaluatedEvent> candidates_;
};

} // namespace

ReplayResult Replay(const ReplaySnapshot& snapshot, const ReplayRule& rule,
                    std::span<const ReplayEvent> events, ReplayBudget budget)
{
    ReplayResult result;
    // 归档读入、规则持久化和派生结果提交留给 CLI 调用方。
    if (!ValidRequest(snapshot, rule, budget)) {
        result.error = ReplayError::InvalidRequest;
        return result;
    }
    result.analysisRunId = snapshot.analysisRunId;
    result.sampleId = snapshot.scope.sampleId;
    result.archiveThroughOrdinal = snapshot.archiveThroughOrdinal;
    if (events.size() > budget.maxInputEvents) {
        result.error = ReplayError::InputLimit;
        return result;
    }
    FrozenEvents frozen;
    result.error = FreezeEvents(snapshot, events, frozen, result.duplicateEvents);
    if (result.error == ReplayError::None) {
        if (!snapshot.coverage) {
            result.issues |= ReplayIssue::Coverage;
        }
        WindowReplay(snapshot, rule, budget, result).Run(frozen);
    }
    return result;
}

} // namespace Ksword::ActionAnalyze::Rules
