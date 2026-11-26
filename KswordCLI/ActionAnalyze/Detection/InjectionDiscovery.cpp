#include "InjectionDiscovery.h"

#include <limits>
#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {

// 区间不准回绕；无法表示的尾地址不进入关联。
bool ValidRange(std::uint64_t base, std::uint64_t length) noexcept
{
    return length != 0 && length <= (std::numeric_limits<std::uint64_t>::max)() - base;
}

bool Covers(const RegionVersion& version, std::uint64_t base, std::uint64_t length) noexcept
{
    if (version.regionId.empty() || !ValidRange(version.base, version.length) ||
        !ValidRange(base, length) || base < version.base) {
        return false;
    }
    return base + length <= version.base + version.length;
}

// Return/Complete 是唯一可落实源侧请求的阶段。生命周期通知另有明确 Observation。
bool IsCompletion(Phase phase) noexcept
{
    return phase == Phase::Return || phase == Phase::Complete;
}

bool SameProcess(const ProcessBinding& left, const ProcessBinding& right) noexcept
{
    return left.machineId == right.machineId &&
        Evidence::MatchProcessInstance(left.instance, right.instance) == Evidence::MatchResult::Confirmed;
}

bool IsBoundThread(const SampleScope& scope, const ThreadBinding& thread) noexcept
{
    return IsBoundProcess(scope, thread.owner) && thread.tid != 0 &&
        thread.creationFileTime >= thread.owner.instance.createTime100ns.value;
}

// 来源约束及机器身份不满足时仍保留事实原文，但绝不建立 A→B 边。
bool CheckSource(const ObservationHeader& header, bool validPhase, EventProjection& result)
{
    if (header.trust != InputTrust::Validated) {
        result.gaps.push_back(Issue::SourceUnverified);
    }
    if (!validPhase) {
        result.gaps.push_back(Issue::WrongPhase);
    }
    return header.trust == InputTrust::Validated && validPhase;
}

bool CheckBinding(const SampleScope& scope, const std::optional<ProcessBinding>& binding,
    Issue absentIssue, EventProjection& result)
{
    if (!binding || !IsBoundProcess(scope, *binding)) {
        result.gaps.push_back(absentIssue);
        return false;
    }
    return true;
}

void Evaluate(const SampleScope& scope, const WriteObservation& row, EventProjection& result)
{
    const bool source = CheckSource(row.header, IsCompletion(row.header.phase), result);
    const bool actor = CheckBinding(scope, row.actor, Issue::ActorInstanceUnknown, result);
    const bool target = CheckBinding(scope, row.target, Issue::TargetInstanceUnknown, result);
    if (row.outcome == Outcome::Unknown) {
        result.gaps.push_back(Issue::OutcomeUnknown);
    }
    if (row.outcome == Outcome::Failed) {
        // 失败有非零实际写长而未被来源判定为可信的部分完成，不能假定其语义。
        if (row.completedLength.value_or(0) != 0) {
            result.gaps.push_back(Issue::OutcomeInconsistent);
        }
        return;
    }

    // 请求长只用来做一致性核对，不填补缺失的实际成功范围。
    if (!row.completedLength) {
        result.gaps.push_back(Issue::ActualWriteRangeUnknown);
        return;
    }
    if (*row.completedLength == 0) {
        if (row.outcome == Outcome::PartiallySucceeded) {
            result.gaps.push_back(Issue::OutcomeInconsistent);
        }
        return;
    }
    if (!row.address) {
        result.gaps.push_back(Issue::ActualWriteRangeUnknown);
        return;
    }
    if (!ValidRange(*row.address, *row.completedLength) ||
        (row.requestedLength && (*row.completedLength > *row.requestedLength ||
            (row.outcome == Outcome::PartiallySucceeded && *row.completedLength == *row.requestedLength)))) {
        result.gaps.push_back(Issue::InvalidWriteRange);
        return;
    }

    if (!row.regionAfter) {
        result.gaps.push_back(Issue::RegionVersionUnknown);
    } else if (!Covers(*row.regionAfter, *row.address, *row.completedLength)) {
        result.gaps.push_back(Issue::InvalidRegionVersion);
    }
    // 区域版本只改变与目标执行的关联资格，不能抹掉已经验证的成功写入事实。
    if (source && actor && target && !SameProcess(*row.actor, *row.target) &&
        (row.outcome == Outcome::Succeeded || row.outcome == Outcome::PartiallySucceeded)) {
        // 单条事件里的相同 PID 不可能同时指向两个存活的进程实例。
        if (row.actor->instance.pid == row.target->instance.pid ||
            (row.actorPidHint != 0 && row.actorPidHint != row.actor->instance.pid.value)) {
            result.gaps.push_back(Issue::IdentityConflict);
        } else {
            result.finding = Finding{FindingKind::ExternalWrite, Attribution::DirectWriter, true};
        }
    }
}

void Evaluate(const SampleScope& scope, const ThreadCreationObservation& row, EventProjection& result)
{
    const bool source = CheckSource(row.header,
        IsCompletion(row.header.phase) || row.header.phase == Phase::Observation, result);
    const bool creator = CheckBinding(scope, row.creator, Issue::ActorInstanceUnknown, result);
    const bool target = CheckBinding(scope, row.target, Issue::TargetInstanceUnknown, result);
    if (row.outcome == Outcome::Unknown) {
        result.gaps.push_back(Issue::OutcomeUnknown);
    } else if (row.outcome == Outcome::PartiallySucceeded) {
        result.gaps.push_back(Issue::OutcomeInconsistent);
    }
    if (!row.newThread || !IsBoundThread(scope, *row.newThread)) {
        result.gaps.push_back(Issue::ThreadInstanceUnknown);
        return;
    }
    // 线程所属进程必须由来源独立绑定，不能因目标 PID 重合就认领。
    if (!target || !SameProcess(row.newThread->owner, *row.target) ||
        (row.targetTidHint != 0 && row.targetTidHint != row.newThread->tid) ||
        (row.targetPidHint != 0 && row.targetPidHint != row.target->instance.pid.value)) {
        result.gaps.push_back(Issue::IdentityConflict);
        return;
    }
    bool consistentCreator = creator;
    if (creator && ((row.creatorPidHint != 0 && row.creatorPidHint != row.creator->instance.pid.value) ||
            !IsPossibleThreadCreator(*row.creator, *row.newThread))) {
        result.gaps.push_back(Issue::IdentityConflict);
        consistentCreator = false;
    }
    if (source && row.outcome == Outcome::Succeeded) {
        result.finding = Finding{FindingKind::ThreadCreated,
            consistentCreator ? Attribution::DirectThreadCreator : Attribution::Unknown,
            consistentCreator && !SameProcess(*row.creator, *row.target)};
    }
}

void Evaluate(const SampleScope& scope, const ExecutionObservation& row, EventProjection& result)
{
    const bool source = CheckSource(row.header, row.header.phase == Phase::Observation, result);
    const bool thread = row.observedThread && IsBoundThread(scope, *row.observedThread);
    if (!thread) {
        result.gaps.push_back(Issue::ThreadInstanceUnknown);
    }
    if (!row.instructionPointer) {
        result.gaps.push_back(Issue::InstructionPointerUnknown);
    }
    if (row.state != ExecutionState::FetchAttempt && row.state != ExecutionState::Executed) {
        result.gaps.push_back(Issue::ExecutionUnknown);
        return;
    }

    if (!row.regionAtExecution) {
        result.gaps.push_back(Issue::RegionVersionUnknown);
    } else if (row.instructionPointer && !Covers(*row.regionAtExecution, *row.instructionPointer, 1)) {
        result.gaps.push_back(Issue::InvalidRegionVersion);
    }
    // 取指尝试不等于完成。执行早于任何来源证据时，归因也保持未知。
    if (source && thread && row.instructionPointer) {
        result.finding = Finding{row.state == ExecutionState::Executed
                ? FindingKind::ExecutionConfirmed : FindingKind::ExecutionFetched};
    }
}

bool StrictlyBefore(const std::optional<FactTime>& a, const std::optional<FactTime>& b) noexcept
{
    return a && b && !a->clockDomain.empty() && a->clockDomain == b->clockDomain &&
        a->earliest <= a->latest && b->earliest <= b->latest && a->latest < b->earliest;
}

bool SameEvidence(const EvidenceRef& a, const EvidenceRef& b) noexcept
{
    // 调用时两边已匹配同一采样；任一共同定位相同，都不算独立原始事实。
    return (a.eventOrdinal && a.eventOrdinal == b.eventOrdinal) || (a.raw && a.raw == b.raw);
}

} // namespace

bool HasEvidenceLocation(const SampleScope& scope, const EvidenceRef& evidence) noexcept
{
    return !scope.projectId.empty() && !scope.sampleId.empty() && !scope.machineId.empty() &&
        !scope.bootId.empty() && scope.bootId != "live" &&
        scope.projectId == evidence.projectId && scope.sampleId == evidence.sampleId &&
        !evidence.sourceId.empty() && !evidence.sourceEpoch.empty() &&
        (!evidence.raw || (evidence.raw->segmentOrdinal != 0 && evidence.raw->sequence != 0)) &&
        (evidence.eventOrdinal || evidence.raw);
}

bool IsBoundProcess(const SampleScope& scope, const ProcessBinding& process) noexcept
{
    const auto& id = process.instance;
    return !scope.machineId.empty() && process.machineId == scope.machineId &&
        !scope.bootId.empty() && scope.bootId != "live" && id.bootId == scope.bootId &&
        id.pid.present && id.pid.value != 0 && id.pid.value <= UINT32_MAX &&
        id.createTime100ns.present && id.createTime100ns.value != 0 &&
        id.strength() == Evidence::IdentityStrength::Strong;
}

bool IsPossibleThreadCreator(const ProcessBinding& creator, const ThreadBinding& newThread) noexcept
{
    return creator.instance.createTime100ns.value <= newThread.creationFileTime &&
        (creator.instance.pid != newThread.owner.instance.pid || SameProcess(creator, newThread.owner));
}

EventProjection ProjectInjectionEvent(const SampleScope& scope, InjectionEvent event)
{
    EventProjection result;
    const auto& evidence = std::visit([](const auto& row) -> const EvidenceRef& {
        return row.header.evidence;
    }, event);
    if (!HasEvidenceLocation(scope, evidence)) {
        result.gaps.push_back(Issue::EvidenceUnavailable);
        return result;
    }
    std::visit([&](const auto& row) { Evaluate(scope, row, result); }, event);
    result.observation = std::move(event);
    return result;
}

std::optional<ExecutionCorrelation> CorrelateWriteExecution(const SampleScope& scope,
    const WriteObservation& write, const ExecutionObservation& execution)
{
    // 分别应用事实闸门；独立来源、版本及严格时序为额外门槛。
    if (!HasEvidenceLocation(scope, write.header.evidence) || !HasEvidenceLocation(scope, execution.header.evidence) ||
        write.header.evidence.sourceId == execution.header.evidence.sourceId ||
        write.header.evidence.sourceGroup.empty() || execution.header.evidence.sourceGroup.empty() ||
        write.header.evidence.sourceGroup == execution.header.evidence.sourceGroup ||
        SameEvidence(write.header.evidence, execution.header.evidence) ||
        !StrictlyBefore(write.header.time, execution.header.time)) {
        return std::nullopt;
    }
    EventProjection d, x;
    Evaluate(scope, write, d);
    Evaluate(scope, execution, x);
    if (!d.finding || !x.finding || x.finding->kind != FindingKind::ExecutionConfirmed ||
        !SameProcess(*write.target, execution.observedThread->owner) ||
        !write.regionAfter || write.regionAfter != execution.regionAtExecution ||
        !Covers(*write.regionAfter, *write.address, *write.completedLength)) {
        return std::nullopt;
    }
    const auto rip = *execution.instructionPointer;
    if (rip < *write.address || rip - *write.address >= *write.completedLength) {
        return std::nullopt;
    }
    return ExecutionCorrelation{write.header.evidence, execution.header.evidence, *write.regionAfter};
}

} // namespace Ksword::ActionAnalyze::Detection
