#include "OwnedExecutionGroup.h"
#include "NativeBreakpointImageIdentity.h"

#include "../Project/ProjectStorage.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <limits>
#include <set>

namespace ks::cli::action_analyze::control {
namespace {
namespace storage = Ksword::ActionAnalyze::ProjectStorage;

bool ValidSite(const ExecutionGroupSite& site)
{
    if (!site.pid || !site.creationFileTime) return false;
    if (site.imageSha256 && !ValidNativeImageSha256(*site.imageSha256))
    {
        return false; // 所有成员在任何附加前核对约束格式，不把空值或大写隐式改写。
    }
    if (site.address) {
        return site.modulePath.empty() && !site.rva && site.exactExport.empty() && !site.imageSha256 &&
            (!site.rangeBytes || (!(site.address % 4096) && !(site.rangeBytes % 4096) &&
                site.rangeBytes <= 64ull * 4096 && site.address <= UINT64_MAX - site.rangeBytes));
    }
    const auto& path = site.modulePath;
    return !site.rangeBytes && path.size() > 3 && path.size() <= 32767 &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\' && path.find_first_of(L"\"\r\n") == std::wstring::npos &&
        path.find(L'\0') == std::wstring::npos && (site.rva.has_value() != !site.exactExport.empty()) && (!site.rva || *site.rva) &&
        site.exactExport.size() <= 4096 && site.exactExport.find('\0') == std::string::npos;
}

bool SameInstance(const NativeControlResult& left, const NativeControlResult& right)
{
    return left.pid && left.pid == right.pid && left.processCreationTime &&
        left.processCreationTime == right.processCreationTime &&
        !left.processInstanceId.empty() && left.processInstanceId == right.processInstanceId;
}

// 输入完整显示快照与原回读，核对同一个活执行绑定；Held、Armed分别在后续分类。
bool SameBinding(const NativeControlResult& displayed, const NativeControlResult& current)
{
    return SameInstance(displayed, current) && displayed.attached && current.attached &&
        !displayed.clean && !current.clean && displayed.breakpoint && current.breakpoint &&
        !displayed.breakpoint->requestId.empty() && displayed.breakpoint->requestId == current.breakpoint->requestId &&
        displayed.breakpoint->address == current.breakpoint->address &&
        displayed.breakpoint->imageSha256 == current.breakpoint->imageSha256 &&
        displayed.breakpoint->rangeBytes == current.breakpoint->rangeBytes &&
        displayed.breakpoint->executionRanges == current.breakpoint->executionRanges;
}

// 明确恢复失败不能被已有Held或运行状态覆盖；原控制回执和恢复责任原样保留。
bool Unresolved(const NativeControlResult& state)
{
    return state.status == NativeControlStatus::RecoveryRequired || state.status == NativeControlStatus::Rejected ||
        state.status == NativeControlStatus::ClosePending || state.firstRecoveryFailure.has_value() ||
        (state.breakpoint && state.breakpoint->state == NativeBreakpointState::RecoveryRequired) ||
        (state.step && state.step->state == NativeStepState::RecoveryRequired) ||
        (state.armedPause && state.armedPause->state == NativeArmedPauseState::RecoveryRequired);
}

// 输入成员条件和完整Held回执，只允许本事件同修订真条件；手动暂停与步进不沿用执行条件。
bool ReleaseEligible(const ExecutionGroupSite& site, const NativeControlResult& state, const DataWatchConditionReport& condition)
{
    // 条件自动释放失败仍由原会话持有责任，不能因无条件回读恢复成Held而授予新动作。
    if (Unresolved(state) || (condition.last && condition.last->failureStage) ||
        !SameBinding(state, state) || !OwnedExecutionGroup::Matches(state, state))
    {
        return false;
    }
    if (state.stopReason == NativeStopReason::ManualPause || IsDataWatchStepStop(state) || !site.condition.valid())
    {
        return true;
    }
    const auto* stop = DataWatchHeldStop(state); // Matches已保证stop及group完整存在。
    const auto& last = condition.last; // 只接受本事件及修订实际求值的条件。
    return last && last->event == stop->event && last->groupId == stop->groupId &&
        last->stateRevision == state.group->stateRevision && last->evaluation.truth == Ksword::ActionAnalyze::Rules::Truth::True;
}
} // namespace

class OwnedExecutionGroup::Impl final {
public:
    struct Member {
        ExecutionGroupSite site;
        std::unique_ptr<OwnedDataWatchSession> session;
        NativeControlResult current;
        bool accepted = false;
    };
    std::vector<Member> members;
    std::string collectionId;
    bool started = false;
    bool closing = false;
    std::optional<ExecutionGroupOperation> operation;

    Member* Find(const NativeControlResult& state)
    {
        const auto found = std::find_if(members.begin(), members.end(), [&](const Member& member) {
            return member.site.pid == state.pid && member.site.creationFileTime == state.processCreationTime;
        });
        return found == members.end() ? nullptr : &*found;
    }

    void Observe(bool applyCondition = true)
    {
        for (auto& member : members) {
            // 在原会话建立 owner 前拒绝的附加没有新的原生状态；保留其明确失败而非改成 idle。
            if (!member.session->Identity().backendInstanceId.empty()) {
                auto current = applyCondition ? member.session->Query() : member.session->QueryWithoutCondition();
                // 两种共享回读都保留原会话恢复失败，集合不维护第二份条件故障投影。
                if (current.status != NativeControlStatus::Idle || member.current.status != NativeControlStatus::Rejected)
                    member.current = std::move(current);
            }
        }
    }

    bool Eligible(const Member& member) const
    {
        // UI与实际批次共用同一资格规则，不能因显示/调用两份逻辑漂移放行失败条件。
        return ReleaseEligible(member.site, member.current, member.session->ConditionReport());
    }

    ExecutionGroupResult Result() const
    {
        ExecutionGroupResult result;
        result.collectionId = collectionId;
        result.operation = operation;
        std::size_t held = 0;
        bool failure = false, recovery = false;
        for (const auto& member : members) {
            result.members.push_back({member.site, member.session->Identity(), member.current,
                member.session->ConditionReport(), member.accepted});
            result.clean = result.clean && member.current.clean;
            if (DataWatchHeldStop(member.current)) ++held;
            failure = failure || !member.accepted || member.current.status == NativeControlStatus::Rejected;
            recovery = recovery || member.current.status == NativeControlStatus::RecoveryRequired;
        }
        if (!started) result.state = closing ? ExecutionGroupState::Closed : ExecutionGroupState::Idle;
        else if (closing) result.state = result.clean ? ExecutionGroupState::Closed :
            recovery ? ExecutionGroupState::RecoveryRequired : ExecutionGroupState::Closing;
        else if (recovery) result.state = ExecutionGroupState::RecoveryRequired;
        else if (held == members.size()) result.state = ExecutionGroupState::HeldComplete;
        else if (held) result.state = ExecutionGroupState::HeldPartial;
        else if (failure) result.state = ExecutionGroupState::PartialFailure;
        else if (result.clean) result.state = ExecutionGroupState::Closed;
        else result.state = ExecutionGroupState::Active;
        return result;
    }

    ExecutionGroupResult Reject(ExecutionGroupAction action, const char* stage, std::uint32_t error)
    {
        operation = ExecutionGroupOperation{action, false, stage, error, {}};
        return Result();
    }

    void Outcome(Member& member, NativeControlResult state)
    {
        member.current = std::move(state);
        operation->outcomes.push_back({member.site.pid, member.site.creationFileTime, member.current});
        if (member.current.win32Error || member.current.status == NativeControlStatus::Rejected ||
            member.current.status == NativeControlStatus::RecoveryRequired) {
            operation->stage = "execution-group-partial-operation";
            if (!operation->win32Error) operation->win32Error = member.current.win32Error ?
                member.current.win32Error : ERROR_INVALID_STATE;
        }
    }

    // already结果只复制原当前状态，不调用原session，不生成新stop或继续回执。
    void Already(const Member& member, const char* disposition)
    {
        operation->outcomes.push_back({member.site.pid, member.site.creationFileTime, member.current, false, disposition});
    }
};

OwnedExecutionGroup::OwnedExecutionGroup() : impl_(std::make_unique<Impl>()) {}
OwnedExecutionGroup::~OwnedExecutionGroup() = default;

ExecutionGroupResult OwnedExecutionGroup::Start(std::vector<ExecutionGroupSite> sites, bool explicitlyAuthorized,
    NativeTargetDisposition disposition, std::string_view sampleId)
{
    auto& self = *impl_;
    if (self.started || self.closing)
        return self.Reject(ExecutionGroupAction::Start, "execution-group-already-used", ERROR_BUSY);
    if (!explicitlyAuthorized || disposition != NativeTargetDisposition::ResumeAndDetach ||
        sites.empty() || sites.size() > kOwnedExecutionGroupLimit || (!sampleId.empty() && !storage::IsUuid(sampleId)))
        return self.Reject(ExecutionGroupAction::Start, "execution-group-explicit-sites-required", ERROR_INVALID_PARAMETER);
    std::set<std::uint32_t> pids;
    for (const auto& site : sites) {
        if (!ValidSite(site) || !pids.insert(site.pid).second)
            return self.Reject(ExecutionGroupAction::Start, "execution-group-invalid-or-duplicate-site", ERROR_INVALID_PARAMETER);
    }
    if (!storage::NewId(self.collectionId))
        return self.Reject(ExecutionGroupAction::Start, "execution-group-identity-failed", ERROR_GEN_FAILURE);
    // 先完成全部配置及会话的分配，再进行任何附加；启动失败也不覆盖既有成功 owner。
    std::vector<Impl::Member> frozen;
    frozen.reserve(sites.size());
    for (auto& site : sites) frozen.push_back({std::move(site), std::make_unique<OwnedDataWatchSession>(), {}, false});
    self.members = std::move(frozen);
    self.started = true;
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::Start, true, "execution-group-start-submitted", 0, {}};
    for (auto& member : self.members) {
        const auto& site = member.site;
        auto state = site.address ? member.session->AttachPrivateAddress(site.pid, site.creationFileTime,
            site.address, 0, site.condition, sampleId, site.rangeBytes) :
            member.session->AttachImageExecution(site.pid, site.creationFileTime, site.modulePath,
                site.rva, site.exactExport, site.condition, sampleId, site.imageSha256);
        if (!state.pid) {
            state.pid = site.pid;
            state.processCreationTime = site.creationFileTime;
        }
        member.accepted = !state.win32Error && state.status != NativeControlStatus::Rejected &&
            state.status != NativeControlStatus::RecoveryRequired;
        self.Outcome(member, std::move(state));
    }
    return self.Result();
}

ExecutionGroupResult OwnedExecutionGroup::Query()
{
    impl_->Observe();
    return impl_->Result();
}

bool OwnedExecutionGroup::Matches(const NativeControlResult& displayed, const NativeControlResult& current)
{
    const auto* selected = DataWatchHeldStop(displayed);
    const auto* live = DataWatchHeldStop(current);
    if (!SameBinding(displayed, current) || Unresolved(displayed) || Unresolved(current) ||
        displayed.status != NativeControlStatus::Held || current.status != NativeControlStatus::Held ||
        !selected || !live || !displayed.pending || !current.pending ||
        selected->event != live->event || selected->groupId != live->groupId || selected->stopId != live->stopId ||
        selected->actualEventThread != live->actualEventThread || selected->state != live->state ||
        selected->lastRequestId != live->lastRequestId || displayed.status != current.status ||
        displayed.stopReason != current.stopReason) return false;
    // 手动暂停必须保留同一原owner的pause/N回执；不能套用后来的停止事件。
    if (displayed.stopReason == NativeStopReason::ManualPause &&
        (!displayed.armedPause || !current.armedPause || displayed.armedPause->owner != current.armedPause->owner ||
            displayed.armedPause->request != current.armedPause->request ||
            displayed.armedPause->state != current.armedPause->state ||
            displayed.armedPause->event != current.armedPause->event ||
            displayed.armedPause->groupId != current.armedPause->groupId)) return false;
    const auto& a = *displayed.group;
    const auto& b = *current.group;
    if (a.sampleId != b.sampleId || a.sessionId != b.sessionId || a.epoch != b.epoch || a.groupId != b.groupId ||
        a.stateRevision != b.stateRevision || a.membershipRevision != b.membershipRevision ||
        a.membershipSha256 != b.membershipSha256 || a.historical || b.historical ||
        a.state != b.state || a.members.size() != b.members.size() ||
        a.nativeEventState != b.nativeEventState || a.incidentalQuality != b.incidentalQuality ||
        a.incidentalThreadIds != b.incidentalThreadIds || a.origin.has_value() != b.origin.has_value()) return false;
    if (a.origin && (a.origin->threadId != b.origin->threadId || a.origin->phase != b.origin->phase || a.origin->hold != b.origin->hold)) return false;
    for (std::size_t i = 0; i < a.members.size(); ++i) {
        const auto& x = a.members[i];
        const auto& y = b.members[i];
        if (x.threadId != y.threadId || x.state != y.state || x.stopId != y.stopId || x.evidence != y.evidence) return false;
    }
    const auto& x = *displayed.pending;
    const auto& y = *current.pending;
    if (x.event != y.event || x.pid != y.pid || x.tid != y.tid || x.eventCode != y.eventCode ||
        x.exceptionCode != y.exceptionCode || x.exceptionFirstChance != y.exceptionFirstChance ||
        x.ledgerOwned != y.ledgerOwned || x.continuationIndeterminate != y.continuationIndeterminate ||
        displayed.frozenThreads.size() != current.frozenThreads.size()) return false;
    if (displayed.breakpoint.has_value() != current.breakpoint.has_value() ||
        displayed.breakpointHit.has_value() != current.breakpointHit.has_value()) return false;
    if (displayed.breakpoint && (displayed.breakpoint->state != current.breakpoint->state ||
        displayed.breakpoint->address != current.breakpoint->address || displayed.breakpoint->rangeBytes != current.breakpoint->rangeBytes ||
        displayed.breakpoint->executionRanges != current.breakpoint->executionRanges)) return false;
    if (displayed.breakpointHit && displayed.breakpointHit->address != current.breakpointHit->address) return false;
    for (std::size_t i = 0; i < displayed.frozenThreads.size(); ++i) {
        const auto& first = displayed.frozenThreads[i];
        const auto& second = current.frozenThreads[i];
        if (first.identity != second.identity || first.tid != second.tid || first.creationTime != second.creationTime) return false;
    }
    return true;
}

bool OwnedExecutionGroup::MatchesStep(const NativeControlResult& displayed, const NativeControlResult& current)
{
    return SameInstance(displayed, current) && displayed.step && current.step &&
        displayed.step->request == current.step->request;
}

// 输入显示会话及真实回读，输出活绑定是否仍可暂停；不要求旧停止组和事件。
bool OwnedExecutionGroup::MatchesPause(const NativeControlResult& displayed, const NativeControlResult& current)
{
    return SameBinding(displayed, current) && !Unresolved(displayed) && !Unresolved(current) && CanPauseDataWatchSession(displayed) &&
        CanPauseDataWatchSession(current) &&
        (displayed.status == NativeControlStatus::Accepted || displayed.status == NativeControlStatus::Released) &&
        (current.status == NativeControlStatus::Accepted || current.status == NativeControlStatus::Released);
}

bool OwnedExecutionGroup::CanPauseMember(const ExecutionGroupMember& member)
{
    const auto& state = member.control; // 混合暂停允许保留精确Held，无须重新提交Pause。
    return !(member.condition.last && member.condition.last->failureStage) && !Unresolved(state) && SameBinding(state, state) &&
        (Matches(state, state) || MatchesPause(state, state));
}

bool OwnedExecutionGroup::CanContinueMember(const ExecutionGroupMember& member)
{
    // 明确条件恢复责任不能因当前原生看似Armed就变成already-running。
    return !(member.condition.last && member.condition.last->failureStage) &&
        (ReleaseEligible(member.site, member.control, member.condition) || MatchesPause(member.control, member.control));
}

// 输入同一成员的配置、条件和当前回执，返回完整NX停点的追加资格；不查询或改变页保护。
bool OwnedExecutionGroup::CanAddRangeMember(const ExecutionGroupMember& member)
{
    const auto& state = member.control; // 显示值必须仍是原NX绑定，不能把普通DR0站点升级为页范围。
    return state.breakpoint && state.breakpoint->rangeBytes && !state.breakpoint->writeWatchBytes &&
        ReleaseEligible(member.site, state, member.condition);
}

// 新session表先核验全体原owner，不把裸PID转换为权威票据。后续旧接口再次回读并核对完整状态。
ExecutionGroupResult OwnedExecutionGroup::ApplySessions(std::span<const ExecutionGroupSessionEntry> sessions, bool all, bool pause)
{
    std::vector<NativeControlResult> states; // 只复制调用方完整快照，不从当前状态补造stop。
    for (const auto& entry : sessions)
    {
        const auto* member = impl_->Find(entry.control); // PID+creation仅用于找原成员，完整owner必须一致。
        if (!member || entry.owner != member->session->Identity() || entry.owner.backendInstanceId.empty())
        {
            return impl_->Reject(pause ? ExecutionGroupAction::Pause : ExecutionGroupAction::Continue,
                "execution-group-foreign-owner", ERROR_INVALID_STATE);
        }
        states.push_back(entry.control);
    }
    return pause ? Pause(std::span<const NativeControlResult>(states), all) : Continue(std::span<const NativeControlResult>(states), all);
}

ExecutionGroupResult OwnedExecutionGroup::Pause(std::span<const ExecutionGroupSessionEntry> sessions, bool all)
{
    return ApplySessions(sessions, all, true); // 原owner全体核验后复用唯一串行混合实现。
}

ExecutionGroupResult OwnedExecutionGroup::Continue(std::span<const ExecutionGroupSessionEntry> sessions, bool all)
{
    return ApplySessions(sessions, all, false); // 不创建新owner、不填充缺失成员。
}

// 全集或所选子集必须先全部通过准入，之后才逐成员调用同一个原session.Pause。
ExecutionGroupResult OwnedExecutionGroup::Pause(std::span<const NativeControlResult> displayedSessions, bool all)
{
    auto& self = *impl_; // 所有访问仍在调用方唯一串行worker。
    self.Observe(false); // 批次核验期间不让条件查询自动Continue任何成员。
    if (self.closing || !self.started || displayedSessions.empty() || displayedSessions.size() > self.members.size() ||
        (all && displayedSessions.size() != self.members.size()))
    {
        return self.Reject(ExecutionGroupAction::Pause, "execution-group-explicit-sessions-required", ERROR_INVALID_PARAMETER);
    }
    std::set<std::uint32_t> seen; // 重复/外来/重用PID在任何原生Pause调用前拒绝整个批次。
    for (const auto& state : displayedSessions)
    {
        const auto* member = self.Find(state); // 站点的PID+creation与原owner当前实例共同核对。
        if (!member || !seen.insert(state.pid).second || !SameBinding(state, member->current) ||
            Unresolved(state) || Unresolved(member->current) ||
            !(Matches(state, member->current) || MatchesPause(state, member->current)))
        {
            return self.Reject(ExecutionGroupAction::Pause, "execution-group-stale-or-foreign-session", ERROR_INVALID_STATE);
        }
    }
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::Pause, true, "execution-group-pause-submitted", 0, {}};
    for (const auto& state : displayedSessions)
    {
        auto& member = *self.Find(state); // 原session再次核对活绑定并分配自身pause/N，不创建第二owner。
        if (Matches(state, member.current))
        {
            self.Already(member, "already-held");
        }
        else
        {
            self.Outcome(member, member.session->Pause(state));
        }
    }
    return self.Result(); // 逐成员原回执分列；Pending与Held不混为同时冻结。
}

ExecutionGroupResult OwnedExecutionGroup::Continue(std::span<const NativeControlResult> displayedStops, bool all)
{
    auto& self = *impl_;
    self.Observe(false); // 全部显示票据和分类核对之前不提交任何自动或手动释放。
    if (self.closing || !self.started || displayedStops.empty() || displayedStops.size() > self.members.size() ||
        (all && displayedStops.size() != self.members.size()))
        return self.Reject(ExecutionGroupAction::Continue, "execution-group-explicit-stops-required", ERROR_INVALID_PARAMETER);
    std::set<std::uint32_t> seen;
    for (const auto& stop : displayedStops) {
        const auto* member = self.Find(stop);
        if (!member || !seen.insert(stop.pid).second || !SameBinding(stop, member->current) ||
            Unresolved(stop) || Unresolved(member->current) ||
            !((Matches(stop, member->current) && self.Eligible(*member)) || MatchesPause(stop, member->current)))
            return self.Reject(ExecutionGroupAction::Continue, "execution-group-stale-or-foreign-stop", ERROR_INVALID_STATE);
    }
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::Continue, true, "execution-group-continue-submitted", 0, {}};
    // 前置核对不是跨进程事务；每个原会话仍在实际调用前再次核对自己的完整票据。
    for (const auto& stop : displayedStops) {
        auto& member = *self.Find(stop);
        if (MatchesPause(stop, member.current))
        {
            self.Already(member, "already-running");
        }
        else
        {
            self.Outcome(member, member.session->Continue(stop));
        }
    }
    return self.Result();
}

ExecutionGroupResult OwnedExecutionGroup::Step(const NativeControlResult& displayedStop, NativeStepMode mode)
{
    auto& self = *impl_;
    self.Observe();
    auto* member = self.Find(displayedStop);
    if (self.closing || !member || member->current.stopReason == NativeStopReason::ManualPause ||
        !Matches(displayedStop, member->current) || !self.Eligible(*member) ||
        (mode != NativeStepMode::Into && mode != NativeStepMode::OverCall && mode != NativeStepMode::Out))
        return self.Reject(ExecutionGroupAction::Step, "execution-group-step-stale-stop", ERROR_INVALID_STATE);
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::Step, true, "execution-group-step-submitted", 0, {}};
    self.Outcome(*member, member->session->Step(displayedStop, mode));
    return self.Result();
}

ExecutionGroupResult OwnedExecutionGroup::CancelStep(const NativeControlResult& displayedStep)
{
    auto& self = *impl_;
    self.Observe();
    auto* member = self.Find(displayedStep);
    if (self.closing || !member || !MatchesStep(displayedStep, member->current))
        return self.Reject(ExecutionGroupAction::CancelStep, "execution-group-step-request-stale", ERROR_INVALID_STATE);
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::CancelStep, true, "execution-group-step-cancel-submitted", 0, {}};
    self.Outcome(*member, member->session->CancelStep(displayedStep));
    return self.Result();
}

// 输入点击时冻结的完整单成员停点和新范围，输出原范围事务回执；其它成员只作无条件回读。
ExecutionGroupResult OwnedExecutionGroup::AddRange(const NativeControlResult& displayedStop,
    std::uint64_t address, std::uint64_t bytes)
{
    auto& self = *impl_; // 原集合的串行worker持有所有成员，不引入第二个owner。
    self.Observe(false); // 准入失败不能触发其它成员条件自动Continue。
    auto* member = self.Find(displayedStop); // 仅定位原成员，下面核对完整绑定、事件和修订。
    if (self.closing || !member || !SameBinding(displayedStop, member->current) ||
        !Matches(displayedStop, member->current) || !member->current.breakpoint ||
        !member->current.breakpoint->rangeBytes || member->current.breakpoint->writeWatchBytes || !self.Eligible(*member))
    {
        return self.Reject(ExecutionGroupAction::AddRange, "execution-group-range-stale-stop", ERROR_INVALID_STATE);
    }
    if (!address || address % 4096 || !bytes || bytes % 4096 || bytes > 64ull * 4096 || address > UINT64_MAX - bytes)
    {
        return self.Reject(ExecutionGroupAction::AddRange, "execution-group-range-invalid-range", ERROR_INVALID_PARAMETER);
    }
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::AddRange, true, "execution-group-range-submitted", 0, {}};
    self.Outcome(*member, member->session->AddPrivateExecutionRange(displayedStop, address, bytes));
    return self.Result(); // 原生层负责总64页预算与新增页回滚，site保留Start时初始配置。
}

ExecutionGroupResult OwnedExecutionGroup::Close()
{
    auto& self = *impl_;
    self.closing = true; // 任何原生清退开始前关闭全部新控制准入。
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::Close, true, "execution-group-close-submitted", 0, {}};
    for (auto& member : self.members) self.Outcome(member, member.session->Close());
    return self.Result();
}

} // namespace ks::cli::action_analyze::control
