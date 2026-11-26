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
        return site.modulePath.empty() && !site.rva && site.exactExport.empty() && !site.imageSha256 && site.definitionId.empty() &&
            (!site.rangeBytes || (!(site.address % 4096) && !(site.rangeBytes % 4096) &&
                site.address <= UINT64_MAX - site.rangeBytes));
    }
    if (!site.definitionId.empty() && (!Ksword::ActionAnalyze::ProjectStorage::IsUuid(site.definitionId) || !site.rva))
    {
        return false; // 冻结定义只支持模块RVA，不把PDB符号或私有地址混入同一激活语义。
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

// 输入成员原回执，返回当前是否仍承担失败的恢复责任；clean后的首次失败只作历史保留。
// 此函数只聚合已有原生事实，不执行恢复，也不按错误文本推断资源已归还。
bool NeedsRecovery(const NativeControlResult& state)
{
    if (state.clean)
    {
        return false;
    }
    return state.status == NativeControlStatus::RecoveryRequired || state.firstRecoveryFailure.has_value() ||
        (state.breakpoint && state.breakpoint->state == NativeBreakpointState::RecoveryRequired) ||
        (state.step && state.step->state == NativeStepState::RecoveryRequired) ||
        (state.armedPause && state.armedPause->state == NativeArmedPauseState::RecoveryRequired) ||
        (state.pending && state.pending->continuationIndeterminate) ||
        (state.executionRange && !state.executionRange->rollbackComplete) ||
        (state.executionFollow && !state.executionFollow->rollbackComplete);
}

// 明确恢复失败和未决清退不能被Held或运行状态覆盖；原控制回执和恢复责任原样保留。
bool Unresolved(const NativeControlResult& state)
{
    return NeedsRecovery(state) || state.status == NativeControlStatus::Rejected ||
        state.status == NativeControlStatus::ClosePending;
}

// 输入成员条件和完整Held回执，允许本事件同修订真/未知条件显式操作；假值仍自动继续。
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
        last->stateRevision == state.group->stateRevision &&
        (last->evaluation.truth == Ksword::ActionAnalyze::Rules::Truth::True ||
            last->evaluation.truth == Ksword::ActionAnalyze::Rules::Truth::Unknown);
}
} // namespace

class OwnedExecutionGroup::Impl final {
public:
    struct Member {
        ExecutionGroupSite site;
        std::unique_ptr<OwnedDataWatchSession> session;
        NativeControlResult current;
        bool accepted = false;
        std::optional<NativeEventKey> peerHoldEvent; // 本成员已触发联停的事件；重复Query不重复Pause。
    };
    std::vector<Member> members;
    std::string collectionId;
    std::string sampleId; // 整个集合唯一采样；无项目时也生成一次，追加成员不另起采样。
    bool started = false;
    bool closing = false;
    std::optional<ExecutionGroupOperation> operation;
    bool holdPeersOnHit = false; // 显式Start策略，追加成员不能热改本轮行为。
    std::optional<ExecutionGroupPeerHold> peerHold; // 独立保留联停回执，不覆盖用户操作回执。

    // 由普通Query在条件处理之后调用；只对新保留的断点发起一次逐成员Pause，不重试或Continue。
    void HoldPeers()
    {
        if (!holdPeersOnHit || closing)
        {
            return;
        }
        Member* trigger = nullptr; // 本轮首个新断点作为回执关联源，其它新命中也在此轮登记。
        for (auto& member : members)
        {
            const auto* stop = DataWatchHeldStop(member.current); // 假条件已由原session继续，未知条件仍保持。
            if (member.current.stopReason != NativeStopReason::Breakpoint || !stop ||
                !OwnedExecutionGroup::Matches(member.current, member.current) ||
                member.peerHoldEvent == std::optional<NativeEventKey>{stop->event})
            {
                continue;
            }
            member.peerHoldEvent = stop->event;
            if (!trigger)
            {
                trigger = &member;
            }
        }
        if (!trigger)
        {
            return;
        }
        ExecutionGroupPeerHold receipt; // 先分配完整结果目录，再请求任何原生暂停。
        receipt.triggerOwner = trigger->session->Identity();
        receipt.triggerEvent = DataWatchHeldStop(trigger->current)->event;
        receipt.outcomes.reserve(members.size());
        for (auto& member : members)
        {
            const auto& state = member.current; // Observe已回读本轮原会话；Pause仍会核验实际绑定。
            const bool held = OwnedExecutionGroup::Matches(state, state); // 不替换已经持有的原始事件。
            if (held || state.clean || !OwnedExecutionGroup::MatchesPause(state, state))
            {
                receipt.outcomes.push_back({member.site.pid, member.site.creationFileTime, state, false,
                    held ? "already-held" : state.clean ? "member-clean" : "pause-unavailable"});
                continue;
            }
            member.current = member.session->Pause(state); // 唯一原owner登记pause/N；接纳后仍等后续Query确认Held。
            receipt.outcomes.push_back({member.site.pid, member.site.creationFileTime, member.current, true, "pause-requested"});
        }
        peerHold = std::move(receipt);
    }

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
        result.holdPeersOnHit = holdPeersOnHit;
        result.peerHold = peerHold;
        std::size_t held = 0;
        bool failure = false, recovery = false;
        for (const auto& member : members) {
            result.members.push_back({member.site, member.session->Identity(), member.current,
                member.session->ConditionReport(), member.accepted});
            result.clean = result.clean && member.current.clean;
            if (DataWatchHeldStop(member.current)) ++held;
            failure = failure || !member.accepted || member.current.status == NativeControlStatus::Rejected;
            // 嵌套步进、范围回滚及事件继续失败的责任优先于Held数量；历史错误在clean后不阻塞关闭。
            recovery = recovery || NeedsRecovery(member.current) ||
                (!member.current.clean && member.session->ConditionReport().last &&
                    member.session->ConditionReport().last->failureStage);
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
            NeedsRecovery(member.current)) {
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

    // 输入已冻结的新成员，调用其唯一原session附加；回执及恢复责任始终保留在该成员中。
    void Attach(Member& member)
    {
        const auto& site = member.site; // 只使用入队时冻结的身份和站点，不从当前选择补值。
        auto state = site.address ? member.session->AttachPrivateAddress(site.pid, site.creationFileTime,
            site.address, 0, site.condition, sampleId, site.rangeBytes) :
            member.session->AttachImageExecution(site.pid, site.creationFileTime, site.modulePath,
                site.rva, site.exactExport, site.condition, sampleId, site.imageSha256, true);
        if (!state.pid)
        {
            state.pid = site.pid;
            state.processCreationTime = site.creationFileTime;
        }
        member.accepted = !state.win32Error && state.status != NativeControlStatus::Rejected &&
            state.status != NativeControlStatus::RecoveryRequired;
        Outcome(member, std::move(state)); // 部分失败不删除失败项，也不清退此前成功成员。
    }
};

OwnedExecutionGroup::OwnedExecutionGroup() : impl_(std::make_unique<Impl>()) {}
OwnedExecutionGroup::~OwnedExecutionGroup() = default;

// 同一串行worker的只读控制快照；更新原成员事实，不推进任何成员的假条件释放。
ExecutionGroupResult OwnedExecutionGroup::QueryWithoutCondition()
{
    impl_->Observe(false);
    return impl_->Result();
}

ExecutionGroupResult OwnedExecutionGroup::Start(std::vector<ExecutionGroupSite> sites, bool explicitlyAuthorized,
    NativeTargetDisposition disposition, std::string_view sampleId, bool holdPeersOnHit)
{
    auto& self = *impl_;
    if (self.started || self.closing)
        return self.Reject(ExecutionGroupAction::Start, "execution-group-already-used", ERROR_BUSY);
    if (!explicitlyAuthorized || disposition != NativeTargetDisposition::ResumeAndDetach ||
        sites.empty() || (!sampleId.empty() && !storage::IsUuid(sampleId)))
        return self.Reject(ExecutionGroupAction::Start, "execution-group-explicit-sites-required", ERROR_INVALID_PARAMETER);
    std::set<std::uint32_t> pids;
    for (const auto& site : sites) {
        if (!ValidSite(site) || !pids.insert(site.pid).second)
            return self.Reject(ExecutionGroupAction::Start, "execution-group-invalid-or-duplicate-site", ERROR_INVALID_PARAMETER);
    }
    if (!storage::NewId(self.collectionId))
        return self.Reject(ExecutionGroupAction::Start, "execution-group-identity-failed", ERROR_GEN_FAILURE);
    self.sampleId = sampleId;
    if (self.sampleId.empty() && !storage::NewId(self.sampleId))
        return self.Reject(ExecutionGroupAction::Start, "execution-group-sample-identity-failed", ERROR_GEN_FAILURE);
    // 先完成全部配置及会话的分配，再进行任何附加；启动失败也不覆盖既有成功 owner。
    std::vector<Impl::Member> frozen;
    frozen.reserve(sites.size());
    for (auto& site : sites)
    {
        // 每个集合成员由同一原会话保留Unknown，联停和归档才能看到该真实事件。
        frozen.push_back({std::move(site), std::make_unique<OwnedDataWatchSession>(true), {}, false, {}});
    }
    self.members = std::move(frozen);
    self.holdPeersOnHit = holdPeersOnHit;
    self.started = true;
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::Start, true, "execution-group-start-submitted", 0, {}};
    for (auto& member : self.members) {
        self.Attach(member);
    }
    return self.Result();
}

// 输入当前纯值快照，返回是否可显式追加；清退/恢复阶段不扩张原控制责任。
bool OwnedExecutionGroup::CanAppendMembers(const ExecutionGroupResult& current)
{
    return !current.collectionId.empty() && !current.clean &&
        (current.state == ExecutionGroupState::Active || current.state == ExecutionGroupState::HeldPartial ||
            current.state == ExecutionGroupState::HeldComplete || current.state == ExecutionGroupState::PartialFailure);
}

// 新成员在任何附加前统一核对并分配；已有成员只无条件回读，保持原停点、条件和恢复资源。
ExecutionGroupResult OwnedExecutionGroup::AppendMembers(std::vector<ExecutionGroupSite> sites,
    bool explicitlyAuthorized, std::string_view collectionId)
{
    auto& self = *impl_; // 本端原串行worker唯一持有的集合。
    self.Observe(false);
    if (collectionId != self.collectionId || !CanAppendMembers(self.Result()))
    {
        return self.Reject(ExecutionGroupAction::AppendMembers, "execution-group-append-unavailable", ERROR_INVALID_STATE);
    }
    if (!explicitlyAuthorized || sites.empty())
    {
        return self.Reject(ExecutionGroupAction::AppendMembers, "execution-group-append-explicit-sites-required", ERROR_INVALID_PARAMETER);
    }
    // 先按容器真实剩余容量比较，后续reserve相加不会溢出；没有人为成员额度。
    if (sites.size() > self.members.max_size() - self.members.size())
    {
        return self.Reject(ExecutionGroupAction::AppendMembers, "execution-group-member-capacity-exhausted", ERROR_NOT_ENOUGH_MEMORY);
    }
    std::set<std::uint32_t> pids; // 同PID也不替换旧代次；原成员必须先沿原owner清退。
    for (const auto& member : self.members)
    {
        pids.insert(member.site.pid);
    }
    for (const auto& site : sites)
    {
        if (!ValidSite(site) || !pids.insert(site.pid).second)
        {
            return self.Reject(ExecutionGroupAction::AppendMembers, "execution-group-invalid-or-duplicate-site", ERROR_INVALID_PARAMETER);
        }
    }
    std::vector<Impl::Member> frozen; // 全部配置与session先分配，避免中途分配失败丢失已附加owner。
    frozen.reserve(sites.size());
    for (auto& site : sites)
    {
        frozen.push_back({std::move(site), std::make_unique<OwnedDataWatchSession>(true), {}, false, {}});
    }
    const auto first = self.members.size(); // 原目录索引保持稳定，新成员仅追加到末尾。
    self.members.reserve(first + frozen.size());
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::AppendMembers, true, "execution-group-append-submitted", 0, {}};
    self.operation->outcomes.reserve(frozen.size());
    for (auto& member : frozen)
    {
        self.members.push_back(std::move(member));
    }
    for (std::size_t index = first; index < self.members.size(); ++index)
    {
        self.Attach(self.members[index]); // 逐项原生结果，不承诺同时附加或同时冻结。
    }
    return self.Result();
}

ExecutionGroupResult OwnedExecutionGroup::Query()
{
    impl_->Observe();
    impl_->HoldPeers(); // 只由正常监控回读推进显式联停；保存/调查的QueryWithoutCondition不产生控制副作用。
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
    self.Observe(false); // 单成员动作只核对现状，失败准入不能触发其它成员条件自动继续。
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
    self.Observe(false); // 中止原成员步进时不替其它成员执行条件；控制副作用只属于明确目标。
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
    if (!address || address % 4096 || !bytes || bytes % 4096 || address > UINT64_MAX - bytes)
    {
        return self.Reject(ExecutionGroupAction::AddRange, "execution-group-range-invalid-range", ERROR_INVALID_PARAMETER);
    }
    self.operation = ExecutionGroupOperation{ExecutionGroupAction::AddRange, true, "execution-group-range-submitted", 0, {}};
    self.Outcome(*member, member->session->AddPrivateExecutionRange(displayedStop, address, bytes));
    return self.Result(); // 原生层负责实际页准入与新增页回滚，site保留Start时初始配置。
}

// 原集合只核对成员目录和精确事件；实际前后停点、强实例及逐页读取由原会话负责。
ProcessMemorySnapshotResult OwnedExecutionGroup::CaptureMemory(const ExecutionGroupSessionEntry& displayed,
    const memory::Plan& plan, const std::atomic_bool* cancel)
{
    auto& self = *impl_; // 必须由拥有原集合的同一个串行worker调用。
    self.Observe(false);
    auto* member = self.Find(displayed.control); // PID+创建时间定位，下面再核对完整原owner和停止身份。
    if (self.closing || !member || member->session->Identity() != displayed.owner ||
        !Matches(displayed.control, member->current))
    {
        ProcessMemorySnapshotResult rejected; // 拒绝也保留实际请求，不伪造空读取成功。
        rejected.request.plan = plan;
        rejected.request.source = ProcessMemorySource::HeldEvent;
        rejected.stage = "execution-group-memory-stale-stop";
        rejected.win32Error = ERROR_INVALID_STATE;
        return rejected;
    }
    return member->session->CaptureMemory(displayed.control, plan, cancel); // 不创建新暂停组或调试owner。
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
