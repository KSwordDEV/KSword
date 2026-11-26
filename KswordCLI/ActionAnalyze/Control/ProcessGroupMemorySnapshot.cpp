#include "ProcessGroupMemorySnapshot.h"

#include "../../../shared/usermode/backend/Common.h"

#include <algorithm>

namespace ks::cli::action_analyze::control {
namespace {
// 目标必须属于当前已配置集合；弱 PID 图节点或另一次控制会话不能授权这次读取。
const ProcessGroupMember* FindMember(const ProcessGroupResult& group, const ProcessGroupTarget& target)
{
    const auto member = std::find_if(group.members.begin(), group.members.end(), [&](const ProcessGroupMember& item) {
        return item.target == target;
    });
    return member == group.members.end() ? nullptr : &*member;
}

bool MatchesHeld(const ProcessGroupMember& member, const ProcessGroupStop& stop)
{
    return member.control && member.control->group &&
        member.control->group->state == GroupState::HeldComplete && member.stop && *member.stop == stop;
}

// 这里的令牌始终从原 owner 当前快照提取，不从历史 JSON 或裸 PID 构造控制权。
std::optional<ProcessGroupStop> HeldNativeStop(const NativeControlResult& state, const OwnerIdentity& identity)
{
    const auto& group = state.group;
    const auto& pending = state.pending;
    const auto& responsibility = state.responsibility;
    if (state.status != NativeControlStatus::Held || !state.attached || state.clean || !state.pid ||
        !state.processCreationTime || !group || group->historical || group->state != GroupState::HeldComplete ||
        group->sampleId != identity.sampleId || group->sessionId != identity.sessionId || group->epoch != identity.epoch ||
        !pending || !pending->ledgerOwned || pending->continuationIndeterminate || pending->pid != state.pid ||
        pending->event.backendInstanceId != identity.backendInstanceId || !pending->event.serial ||
        !responsibility || responsibility->state != EventState::Held || responsibility->groupId != group->groupId ||
        responsibility->event != pending->event || responsibility->stopId.empty() || !group->stateRevision)
        return {};
    return ProcessGroupStop{{state.pid, state.processCreationTime}, group->groupId, responsibility->stopId,
        pending->event, group->stateRevision};
}

void ReadOriginalInstance(ProcessMemorySnapshotResult& result, const std::atomic_bool* cancel)
{
    // 只借用精确实例的只读句柄；共享采样器再次核对时间、身份、同用户和实际区域。
    const auto& target = result.request.plan.target;
    ks::r3::common::UniqueHandle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
        FALSE, target.pid));
    if (!process.valid()) {
        result.stage = "process-memory-open-original-instance";
        result.win32Error = GetLastError();
        return;
    }
    result.snapshot = memory::CaptureSelectedMemory(process.get(), result.request.plan, cancel);
    result.stage = "process-memory-read-observed";
}
} // namespace

ProcessMemorySnapshotResult CaptureProcessGroupMemory(OwnedProcessGroup& group,
    const ProcessMemorySnapshotRequest& request, const std::atomic_bool* cancel)
{
    ProcessMemorySnapshotResult result; // 请求身份及读前/读后证据分别保留。
    result.request = request;
    const ProcessGroupTarget target{request.plan.target.pid, request.plan.target.creationFileTime100ns};
    const auto before = group.Query(); // 在当前串行控制者上读取同一批所有者，不借用历史图行。
    const auto* member = FindMember(before, target);
    if (!member || (request.source != ProcessMemorySource::LiveRead && request.source != ProcessMemorySource::HeldEvent)) {
        result.stage = "process-memory-target-not-configured";
        result.win32Error = ERROR_INVALID_PARAMETER;
        return result;
    }
    if (request.source == ProcessMemorySource::HeldEvent) {
        if (!request.stop || !MatchesHeld(*member, *request.stop) ||
            member->control->group->sampleId != request.plan.sampleId) {
            result.stage = "process-memory-stale-stop";
            result.win32Error = ERROR_INVALID_STATE;
            return result;
        }
        result.before = member->stop;
    } else if (request.stop) {
        result.stage = "process-memory-live-read-cannot-borrow-stop";
        result.win32Error = ERROR_INVALID_PARAMETER;
        return result;
    }

    ReadOriginalInstance(result, cancel);
    if (!result.snapshot) return result;
    if (request.source == ProcessMemorySource::HeldEvent) {
        const auto after = group.Query(); // 不调用 Continue，不把用户停点让给调查作业。
        const auto* observed = FindMember(after, target);
        if (observed) result.after = observed->stop;
        result.heldAtBothChecks = observed && MatchesHeld(*observed, *request.stop);
        if (!result.heldAtBothChecks) {
            result.stage = "process-memory-stop-changed-during-read";
            result.win32Error = ERROR_RETRY;
        }
    }
    return result;
}

ProcessMemorySnapshotResult CaptureNativeStopMemory(NativeDebugOwner& owner, const OwnerIdentity& identity,
    const ProcessMemorySnapshotRequest& request, const std::atomic_bool* cancel)
{
    ProcessMemorySnapshotResult result;
    result.request = request;
    if (request.source != ProcessMemorySource::HeldEvent || !request.stop ||
        request.plan.sampleId != identity.sampleId || !request.plan.authorizedOwnedProcess) {
        result.stage = "process-memory-held-request-required";
        result.win32Error = ERROR_INVALID_PARAMETER;
        return result;
    }
    const ProcessGroupTarget target{request.plan.target.pid, request.plan.target.creationFileTime100ns};
    result.before = HeldNativeStop(owner.Query(), identity);
    if (!result.before || *result.before != *request.stop || result.before->target != target) {
        result.stage = "process-memory-stale-stop";
        result.win32Error = ERROR_INVALID_STATE;
        return result;
    }
    ReadOriginalInstance(result, cancel);
    if (!result.snapshot) return result;
    result.after = HeldNativeStop(owner.Query(), identity);
    result.heldAtBothChecks = result.after && *result.after == *result.before;
    if (!result.heldAtBothChecks) {
        result.stage = "process-memory-stop-changed-during-read";
        result.win32Error = ERROR_RETRY;
    }
    return result;
}

} // namespace ks::cli::action_analyze::control
