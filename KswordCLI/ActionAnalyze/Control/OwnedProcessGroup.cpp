#include "OwnedProcessGroup.h"

#include "../Project/ProjectStorage.h"
#include "../../../shared/usermode/backend/Common.h"

#include <algorithm>
#include <charconv>
#include <map>

namespace ks::cli::action_analyze::control {
namespace {
using ks::r3::common::UniqueHandle;
constexpr std::size_t kReceipts = 128; // 已结束票据的有界保留容量。

// 所有组层动作共享严格递增的 group/N；淘汰后的 ID 不会重新执行。
std::optional<std::uint64_t> RequestSequence(std::string_view id)
{
    constexpr std::string_view prefix = "group/"; // 与原生 continue/N 分开编号。
    if (!id.starts_with(prefix)) return {};
    id.remove_prefix(prefix.size());
    if (id.empty() || id.front() == '0') return {};
    std::uint64_t sequence = 0; // 十进制请求序号，零无效。
    const auto parsed = std::from_chars(id.data(), id.data() + id.size(), sequence);
    if (parsed.ec != std::errc{} || parsed.ptr != id.data() + id.size() || !sequence) return {};
    return sequence;
}

// 持有真实进程句柄，以创建时间阻止 PID 回收后的重新绑定；不提升权限。
DWORD Pin(const ProcessGroupTarget& target, UniqueHandle& output)
{
    if (!target.pid || target.pid == GetCurrentProcessId() || !target.creationFileTime) return ERROR_INVALID_PARAMETER;
    UniqueHandle handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, target.pid));
    if (!handle.valid()) return GetLastError();
    FILETIME creation{}, exit{}, kernel{}, user{}; // 系统回读的进程时间，只有 creation 用于身份。
    if (!GetProcessTimes(handle.get(), &creation, &exit, &kernel, &user)) return GetLastError();
    const auto actual = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    if (actual != target.creationFileTime || WaitForSingleObject(handle.get(), 0) != WAIT_TIMEOUT) {
        return ERROR_PROCESS_ABORTED;
    }
    output = std::move(handle);
    return ERROR_SUCCESS;
}

// 仅从同一原生快照构造释放资格；来源提示和旧历史停点没有此资格。
std::optional<ProcessGroupStop> HeldStop(const ProcessGroupTarget& target, const NativeControlResult& state)
{
    if (!state.attached || state.status != NativeControlStatus::Held || !state.pending || !state.group ||
        !state.responsibility || !state.pending->ledgerOwned || state.pending->continuationIndeterminate ||
        state.group->historical || state.responsibility->state != EventState::Held ||
        state.group->groupId != state.responsibility->groupId ||
        state.pending->event != state.responsibility->event || state.pid != target.pid ||
        state.processCreationTime != target.creationFileTime) return {};
    return ProcessGroupStop{target, state.group->groupId, state.responsibility->stopId,
        state.responsibility->event, state.group->stateRevision};
}
} // namespace

class OwnedProcessGroup::Impl {
public:
    explicit Impl(OwnerIdentity identity) : identity_(std::move(identity)) {}
    ProcessGroupResult Configure(std::vector<ProcessGroupTarget> targets, bool authorized,
        NativeTargetDisposition disposition);
    ProcessGroupResult Pause(std::string id, std::span<const ProcessGroupTarget> targets);
    ProcessGroupResult Continue(std::string id, std::span<const ProcessGroupStop> stops);
    ProcessGroupResult Recover(std::string_view id);
    ProcessGroupResult Query();
    ProcessGroupResult Close();

private:
    struct Member {
        ProcessGroupTarget target; // 初始化时冻结的真实实例。
        UniqueHandle pin; // 集合生命周期中持有的原始进程对象。
        std::shared_ptr<NativeDebugOwner> owner; // 当前暂停代次的唯一原生执行者。
        std::optional<NativeControlResult> state; // 最近一次原生回读，不从票据推断现态。
    };
    struct Saved {
        ProcessGroupOperation receipt; // 重复请求返回最初票据，不覆盖其首次结果。
        std::vector<ProcessGroupTarget> targets; // 暂停请求的冻结成员顺序。
        std::vector<ProcessGroupStop> stops; // 继续请求的冻结令牌顺序。
        std::vector<ReleaseRequest> releases; // 每个继续成员对应的实际原生请求。
        std::vector<std::weak_ptr<NativeDebugOwner>> owners; // 控制块标识原代次，不保留已清退的后台线程。
    };

    // 在任何副作用之前判断重放或冲突；返回 true 表示调用方直接返回 out。
    bool Replay(const std::string& id, ProcessGroupAction action, std::span<const ProcessGroupTarget> targets,
        std::span<const ProcessGroupStop> stops, ProcessGroupResult& out);
    bool Reserve(); // 仅淘汰原生责任已结清的最老票据，不丢弃恢复入口。
    Member* Find(const ProcessGroupTarget& target);
    ProcessGroupResult Snapshot() const;
    ProcessGroupResult Reject(const char* stage, DWORD error, LedgerResult result) const;
    ProcessGroupResult Save(std::uint64_t sequence, Saved saved);
    ProcessGroupResult SaveRejected(std::string id, ProcessGroupAction action,
        std::span<const ProcessGroupTarget> targets, std::span<const ProcessGroupStop> stops,
        const char* stage, DWORD error, LedgerResult result); // 拒绝也固定原内容与高水位。
    void Refresh(); // 查询仍由各自专用调试线程执行，组层不接触原生事件。

    OwnerIdentity identity_; // 同一客户端样本和控制会话的身份。
    std::vector<Member> members_; // Configure 后不可增删的目标目录。
    std::map<std::uint64_t, Saved> saved_; // 单调 ID 的有界精确重放目录。
    std::uint64_t highWater_ = 0; // 淘汰后仍保留的请求高水位。
    bool configured_ = false; // 成功配置仅一次。
    bool closing_ = false; // 关闭后拒绝新动作，保留查询和恢复。
};

OwnedProcessGroup::Impl::Member* OwnedProcessGroup::Impl::Find(const ProcessGroupTarget& target)
{
    const auto found = std::find_if(members_.begin(), members_.end(), [&](const Member& member) {
        return member.target == target;
    });
    return found == members_.end() ? nullptr : &*found;
}

void OwnedProcessGroup::Impl::Refresh()
{
    for (auto& member : members_) {
        if (member.owner) member.state = member.owner->Query();
    }
}

ProcessGroupResult OwnedProcessGroup::Impl::Snapshot() const
{
    ProcessGroupResult result; // 默认空闲；逐成员归纳真实附加和停止责任。
    std::size_t held = 0; // 具有精确继续资格的成员数。
    bool recovery = false; // 任一未决原生错误阻止汇总为完整成功。
    bool touched = false; // 是否已实际提交过原生操作。
    for (const auto& member : members_) {
        ProcessGroupMember projected; // 固定身份与其当前独立回读。
        projected.target = member.target;
        projected.control = member.state;
        if (member.state) {
            touched = true;
            projected.clean = member.state->clean;
            projected.stop = HeldStop(member.target, *member.state);
            held += projected.stop.has_value() && member.state->group &&
                member.state->group->state == GroupState::HeldComplete;
            recovery = recovery || member.state->status == NativeControlStatus::RecoveryRequired;
        }
        result.clean = result.clean && projected.clean;
        result.members.push_back(std::move(projected));
    }
    result.state = !configured_ ? ProcessGroupState::Idle : recovery ? ProcessGroupState::RecoveryRequired :
        closing_ ? (result.clean ? ProcessGroupState::Closed : ProcessGroupState::Closing) :
        held == members_.size() ? ProcessGroupState::HeldComplete : held ? ProcessGroupState::HeldPartial :
        touched ? ProcessGroupState::Active : ProcessGroupState::Ready;
    result.stage = recovery ? "process-group-recovery-required" : closing_ ? "process-group-closing" :
        held ? "process-group-held" : "process-group-observed";
    return result;
}

ProcessGroupResult OwnedProcessGroup::Impl::Reject(const char* stage, DWORD error, LedgerResult ledger) const
{
    auto result = Snapshot(); // 拒绝保持原集合及未决责任，不能用空回执掩盖已有停点。
    result.stage = stage;
    result.win32Error = error;
    result.ledgerResult = ledger;
    return result;
}

ProcessGroupResult OwnedProcessGroup::Impl::Configure(std::vector<ProcessGroupTarget> targets, bool authorized,
    NativeTargetDisposition disposition)
{
    if (configured_ || closing_) return Reject("process-group-already-configured", ERROR_INVALID_STATE, LedgerResult::Conflict);
    if (!authorized || disposition != NativeTargetDisposition::ResumeAndDetach || targets.empty() ||
        identity_.sampleId.empty() || identity_.sessionId.empty() ||
        identity_.epoch.empty() || identity_.backendInstanceId.empty()) {
        return Reject("process-group-explicit-instances-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    }
    std::vector<Member> prepared; // 全部核对成功前不发布部分集合，也不附加任何目标。
    for (const auto& target : targets) {
        if (std::any_of(prepared.begin(), prepared.end(), [&](const Member& item) { return item.target.pid == target.pid; })) {
            return Reject("process-group-duplicate-pid", ERROR_INVALID_PARAMETER, LedgerResult::Conflict);
        }
        Member member;
        member.target = target;
        if (const auto error = Pin(target, member.pin)) {
            return Reject("process-group-pin-instance", error, LedgerResult::IdentityMismatch);
        }
        prepared.push_back(std::move(member));
    }
    members_ = std::move(prepared);
    configured_ = true;
    return Snapshot();
}

bool OwnedProcessGroup::Impl::Replay(const std::string& id, ProcessGroupAction action,
    std::span<const ProcessGroupTarget> targets, std::span<const ProcessGroupStop> stops, ProcessGroupResult& out)
{
    const auto sequence = RequestSequence(id); // 非规范 ID 从不进入执行或回执目录。
    if (!sequence) {
        out = Reject("process-group-require-group-sequence", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
        return true;
    }
    const auto prior = saved_.find(*sequence); // 同一个票据必须具有同种动作与逐项相同的冻结内容。
    if (prior != saved_.end()) {
        const auto& saved = prior->second;
        if (saved.receipt.action != action || !std::ranges::equal(saved.targets, targets) || !std::ranges::equal(saved.stops, stops)) {
            out = Reject("process-group-request-conflict", ERROR_INVALID_PARAMETER, LedgerResult::Conflict);
        } else {
            out = Snapshot();
            out.ledgerResult = LedgerResult::Duplicate;
            out.operation = saved.receipt;
            out.stage = saved.receipt.stage;
            out.win32Error = saved.receipt.win32Error;
        }
        return true;
    }
    if (*sequence <= highWater_) {
        out = Reject("process-group-replay-expired", ERROR_INVALID_STATE, LedgerResult::ReplayExpired);
        return true;
    }
    return false;
}

bool OwnedProcessGroup::Impl::Reserve()
{
    if (saved_.size() < kReceipts) return true;
    // 有未决成员的继续票据不可淘汰：Recover 必须仍能指向原所有者和原请求。
    for (auto it = saved_.begin(); it != saved_.end(); ++it) {
        const auto& saved = it->second;
        if (saved.receipt.action == ProcessGroupAction::Continue &&
            std::any_of(saved.owners.begin(), saved.owners.end(), [&](const std::weak_ptr<NativeDebugOwner>& original) {
                const auto owner = original.lock(); // 已销毁代次可淘汰；控制块防止分配地址重用误认。
                if (!owner) return false;
                return std::any_of(members_.begin(), members_.end(), [&](const Member& member) {
                    return member.owner == owner && member.state && !member.state->clean;
                });
            })) continue;
        saved_.erase(it);
        return true;
    }
    return false;
}

ProcessGroupResult OwnedProcessGroup::Impl::Save(std::uint64_t sequence, Saved saved)
{
    highWater_ = sequence;
    auto result = Snapshot(); // 票据与现态分开：首次结果不因后续 Query 或 Recover 而被改写。
    result.operation = saved.receipt;
    result.ledgerResult = saved.receipt.ledgerResult;
    if (saved.receipt.ledgerResult != LedgerResult::Applied) {
        result.stage = saved.receipt.stage;
        result.win32Error = saved.receipt.win32Error;
    }
    saved_.emplace(sequence, std::move(saved));
    return result;
}

ProcessGroupResult OwnedProcessGroup::Impl::SaveRejected(std::string id, ProcessGroupAction action,
    std::span<const ProcessGroupTarget> targets, std::span<const ProcessGroupStop> stops,
    const char* stage, DWORD error, LedgerResult ledger)
{
    if (!Reserve()) return Reject("process-group-receipt-capacity", ERROR_BUFFER_OVERFLOW, LedgerResult::Capacity);
    Saved saved; // 仅值化错误票据，不创建原生所有者、不读取或释放任何线程。
    saved.receipt.requestId = std::move(id);
    saved.receipt.action = action;
    saved.receipt.stage = stage;
    saved.receipt.win32Error = error;
    saved.receipt.ledgerResult = ledger;
    saved.targets.assign(targets.begin(), targets.end());
    saved.stops.assign(stops.begin(), stops.end());
    const auto sequence = *RequestSequence(saved.receipt.requestId); // 调用前 Replay 已验证格式及新序号。
    return Save(sequence, std::move(saved));
}

ProcessGroupResult OwnedProcessGroup::Impl::Pause(std::string id, std::span<const ProcessGroupTarget> targets)
{
    Refresh();
    ProcessGroupResult replay; // 重放在关闭后也允许回读，不重新执行。
    if (Replay(id, ProcessGroupAction::Pause, targets, {}, replay)) return replay;
    if (!configured_ || closing_ || targets.empty() || targets.size() > members_.size()) {
        return SaveRejected(id, ProcessGroupAction::Pause, targets, {},
            "process-group-pause-unavailable", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    }
    std::vector<Member*> selected; // 完整检查所有选择后才产生第一个原生副作用。
    for (const auto& target : targets) {
        auto* member = Find(target);
        if (!member || std::find(selected.begin(), selected.end(), member) != selected.end()) {
            return SaveRejected(id, ProcessGroupAction::Pause, targets, {},
                "process-group-selection-mismatch", ERROR_INVALID_PARAMETER, LedgerResult::IdentityMismatch);
        }
        if (member->state && !member->state->clean) {
            return SaveRejected(id, ProcessGroupAction::Pause, targets, {},
                "process-group-member-still-owned", ERROR_BUSY, LedgerResult::InvalidTransition);
        }
        selected.push_back(member);
    }
    if (!Reserve()) return Reject("process-group-receipt-capacity", ERROR_BUFFER_OVERFLOW, LedgerResult::Capacity);
    Saved saved;
    saved.receipt = {id, ProcessGroupAction::Pause, {}};
    saved.targets.assign(targets.begin(), targets.end());
    for (auto* member : selected) {
        auto ownerId = identity_; // 每个暂停代次取得新的后端实例，旧事件键不迁移。
        if (!Ksword::ActionAnalyze::ProjectStorage::NewId(ownerId.backendInstanceId)) {
            NativeControlResult failed;
            failed.status = NativeControlStatus::Rejected;
            failed.stage = "process-group-allocate-owner";
            failed.win32Error = ERROR_GEN_FAILURE;
            saved.receipt.outcomes.push_back({member->target, std::move(failed)});
            continue;
        }
        member->owner = std::make_shared<NativeDebugOwner>(std::move(ownerId));
        NativePauseRequest request{id, member->target.pid, member->target.creationFileTime, true,
            NativeTargetDisposition::ResumeAndDetach}; // 原生所有者再次核对真实句柄与架构。
        member->state = member->owner->Pause(request);
        saved.receipt.outcomes.push_back({member->target, *member->state});
    }
    return Save(*RequestSequence(id), std::move(saved));
}

ProcessGroupResult OwnedProcessGroup::Impl::Continue(std::string id, std::span<const ProcessGroupStop> stops)
{
    Refresh();
    ProcessGroupResult replay; // 重放使用首次冻结令牌，不要求现在仍是同一停点。
    if (Replay(id, ProcessGroupAction::Continue, {}, stops, replay)) return replay;
    if (!configured_ || closing_ || stops.empty() || stops.size() > members_.size()) {
        return SaveRejected(id, ProcessGroupAction::Continue, {}, stops,
            "process-group-continue-unavailable", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    }
    std::vector<Member*> selected; // 旧令牌导致整个新请求在释放第一项之前拒绝。
    for (const auto& stop : stops) {
        auto* member = Find(stop.target);
        if (!member || !member->state || !member->owner ||
            std::find(selected.begin(), selected.end(), member) != selected.end()) {
            return SaveRejected(id, ProcessGroupAction::Continue, {}, stops,
                "process-group-selection-mismatch", ERROR_INVALID_PARAMETER, LedgerResult::IdentityMismatch);
        }
        const auto current = HeldStop(member->target, *member->state);
        if (!current || *current != stop) {
            return SaveRejected(id, ProcessGroupAction::Continue, {}, stops,
                "process-group-stale-stop", ERROR_INVALID_STATE, LedgerResult::StaleRevision);
        }
        selected.push_back(member);
    }
    if (!Reserve()) return Reject("process-group-receipt-capacity", ERROR_BUFFER_OVERFLOW, LedgerResult::Capacity);
    Saved saved;
    saved.receipt = {id, ProcessGroupAction::Continue, {}};
    saved.stops.assign(stops.begin(), stops.end());
    for (std::size_t index = 0; index < selected.size(); ++index) {
        auto& member = *selected[index];
        const auto& stop = stops[index];
        // 每个一次性 Pause 所有者仅有一次公开继续；Recover 重用同一原生请求。
        ReleaseRequest request{identity_, stop.groupId,
            stop.stopId, stop.event, "continue/1", stop.stateRevision};
        request.owner.backendInstanceId = stop.event.backendInstanceId;
        saved.releases.push_back(request);
        saved.owners.push_back(member.owner);
        member.state = member.owner->Continue(request);
        saved.receipt.outcomes.push_back({member.target, *member.state});
    }
    return Save(*RequestSequence(id), std::move(saved));
}

ProcessGroupResult OwnedProcessGroup::Impl::Recover(std::string_view id)
{
    Refresh();
    const auto sequence = RequestSequence(id); // 只允许查询一个已实际提交的继续票据。
    const auto prior = sequence ? saved_.find(*sequence) : saved_.end();
    if (prior == saved_.end() || prior->second.receipt.action != ProcessGroupAction::Continue) {
        return Reject("process-group-original-release-required", ERROR_NOT_FOUND, LedgerResult::ReadbackRequired);
    }
    auto& saved = prior->second;
    if (saved.receipt.ledgerResult != LedgerResult::Applied) {
        auto rejected = Snapshot(); // 拒绝的 Continue 从未释放事件，没有可执行的 Recover。
        rejected.operation = saved.receipt;
        rejected.stage = saved.receipt.stage;
        rejected.win32Error = saved.receipt.win32Error;
        rejected.ledgerResult = LedgerResult::ReadbackRequired;
        return rejected;
    }
    auto result = Snapshot();
    ProcessGroupOperation recovery{std::string(id), ProcessGroupAction::Recover, {}};
    for (std::size_t index = 0; index < saved.releases.size(); ++index) {
        auto* member = Find(saved.stops[index].target);
        if (!member || member->owner != saved.owners[index].lock()) {
            // 已完成并开始新代次的成员只回读旧结果；不向新所有者重放旧请求。
            recovery.outcomes.push_back(saved.receipt.outcomes[index]);
            continue;
        }
        if (member->state && !member->state->clean) member->state = member->owner->Recover(saved.releases[index]);
        recovery.outcomes.push_back({member->target, *member->state});
    }
    result = Snapshot();
    result.operation = std::move(recovery);
    return result;
}

ProcessGroupResult OwnedProcessGroup::Impl::Query()
{
    Refresh();
    return Snapshot();
}

ProcessGroupResult OwnedProcessGroup::Impl::Close()
{
    closing_ = true; // 即便部分清退失败，也不再允许新目标或新暂停。
    for (auto& member : members_) {
        if (member.owner) member.state = member.owner->Close();
    }
    return Snapshot();
}

OwnedProcessGroup::OwnedProcessGroup(OwnerIdentity identity) : impl_(std::make_unique<Impl>(std::move(identity))) {}
OwnedProcessGroup::~OwnedProcessGroup() = default;

ProcessGroupResult OwnedProcessGroup::Configure(std::vector<ProcessGroupTarget> targets, bool authorized,
    NativeTargetDisposition disposition)
{
    return impl_->Configure(std::move(targets), authorized, disposition);
}

ProcessGroupResult OwnedProcessGroup::Pause(std::string id, std::span<const ProcessGroupTarget> targets)
{
    return impl_->Pause(std::move(id), targets);
}

ProcessGroupResult OwnedProcessGroup::Continue(std::string id, std::span<const ProcessGroupStop> stops)
{
    return impl_->Continue(std::move(id), stops);
}

ProcessGroupResult OwnedProcessGroup::Recover(std::string_view id) { return impl_->Recover(id); }
ProcessGroupResult OwnedProcessGroup::Query() { return impl_->Query(); }
ProcessGroupResult OwnedProcessGroup::Close() { return impl_->Close(); }

} // namespace ks::cli::action_analyze::control
