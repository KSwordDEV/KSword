#include "NativeExecutionEvidence.h"

// 步进验收批次补入：控制头链路已不再传递 Windows.h，DEBUG 事件常量需要直接包含。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>

namespace ks::cli::action_analyze::control {

bool NativeExecutionAddressInBinding(const NativeBreakpointBinding& binding, std::uint64_t address) noexcept
{
    if (!binding.executionRanges.empty())
    {
        // 使用真正已接纳范围；失败且仍待恢复的新增页不在成功范围中，不生成执行证据。
        return std::any_of(binding.executionRanges.begin(), binding.executionRanges.end(),
            [address](const NativeExecutionRange& range) {
                return range.base && range.bytes && address >= range.base && address - range.base < range.bytes;
            });
    }
    return binding.address && address >= binding.address &&
        (binding.rangeBytes ? address - binding.address < binding.rangeBytes : address == binding.address);
}

std::optional<NativeExecutionEvidence> NativeExecutionFromOwnedStop(const NativeControlResult& state)
{
    if (state.status != NativeControlStatus::Held || !state.attached || state.clean || !state.group ||
        state.group->historical || !state.pending || !state.pending->ledgerOwned ||
        state.pending->continuationIndeterminate || !state.responsibility ||
        state.responsibility->state != EventState::Held || state.responsibility->groupId != state.group->groupId ||
        state.responsibility->event != state.pending->event || !state.pid || !state.processCreationTime ||
        state.pending->pid != state.pid || state.pending->eventCode != EXCEPTION_DEBUG_EVENT ||
        state.pending->exceptionFirstChance != true) return {};
    const bool singleStep = state.pending->exceptionCode == EXCEPTION_SINGLE_STEP; // DR0或真实用户TF。
    const bool pageEntry = state.pending->exceptionCode == EXCEPTION_ACCESS_VIOLATION && state.breakpoint &&
        state.breakpoint->rangeBytes && state.breakpointHit && !state.breakpointHit->dataChange;
    if (!singleStep && !pageEntry) return {};

    const auto thread = std::find_if(state.frozenThreads.begin(), state.frozenThreads.end(), [&](const NativeFrozenThread& item) {
        return item.identity == state.responsibility->actualEventThread && item.tid == state.pending->tid &&
            item.creationTime >= state.processCreationTime && item.creationTime != 0;
    });
    if (thread == state.frozenThreads.end()) return {};

    NativeExecutionEvidence result; // 每个字段来自同一次所有者停止快照，不事后枚举补身份。
    result.pid = state.pid;
    result.processCreationFileTime = state.processCreationTime;
    result.thread = *thread;
    result.event = state.pending->event;
    result.groupId = state.group->groupId;
    result.stopId = state.responsibility->stopId;
    result.stateRevision = state.group->stateRevision;
    result.observedQpc = state.timing.eventObservedQpc;
    result.qpcFrequency = state.timing.qpcFrequency;
    result.binding = state.breakpoint; // 冻结成功纳入的当前范围，不从后续Query或参数草稿回填历史。
    if (state.registers && state.registers->thread == thread->identity)
    {
        result.registers = state.registers; // 与实际执行阶段一起保存，Query不会补读现场。
    }

    // Into或非CALL步过的真实单条TF回执；CALL的DR1返回边界不能冒充单条指令完成。
    if (singleStep && state.step && NativeStepUsesSingleInstructionTrap(*state.step) &&
        state.step->state == NativeStepState::Completed && state.step->resourcesRestored &&
        state.step->observedEvent == state.pending->event && state.step->stopGroupId == state.group->groupId &&
        state.step->request.thread == thread->identity && state.step->request.tid == thread->tid &&
        state.step->request.threadCreationTime == thread->creationTime && state.step->startIp &&
        state.step->observedIp) {
        result.kind = NativeExecutionKind::InstructionCompleted;
        result.instructionAddress = state.step->startIp;
        result.nextInstructionAddress = state.step->observedIp;
        return result;
    }
    // 数据写入停点是 store 完成后的数据观测，不能冒充关注地址的执行证据。
    if (!state.breakpoint || !state.breakpointHit || state.breakpoint->writeWatchBytes ||
        state.breakpointHit->dataChange || state.breakpoint->state != NativeBreakpointState::Held ||
        !NativeExecutionAddressInBinding(*state.breakpoint, state.breakpointHit->address) ||
        !state.group->origin || state.group->origin->phase != StopPhase::ExecutionEnterAttempt ||
        state.group->origin->threadId != thread->identity.threadId) return {};
    result.kind = NativeExecutionKind::EnterAttempt;
    result.instructionAddress = state.breakpointHit->address;
    return result;
}

} // namespace ks::cli::action_analyze::control
