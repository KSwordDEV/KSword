#include "NativeWriteExecutionTransition.h"

#include <charconv>
#include <algorithm>
#include <vector>

namespace ks::cli::action_analyze::control {
namespace {

constexpr DWORD64 kSlotMask = 0x000f0003; // 仅DR0启用、访问类型和长度，保留其它调试槽。
constexpr DWORD64 kExecutionControl = 1; // 槽0本地启用，执行类型和长度均为零。

// 输入稳定阶段，读取刚失败的Win32错误，输出非零错误；不掩盖原始失败。
NativeFollowError Failure(const char* stage)
{
    const auto error = GetLastError(); // 必须在任何恢复调用之前保存。
    return {stage, error ? error : ERROR_GEN_FAILURE, true};
}

// 每个预读项保留原完整上下文；仅在全部预读通过后才开始任何Set。
struct PreparedThread {
    NativeFollowThread slot; // 指向原owner槽位恢复账，不取得句柄所有权。
    CONTEXT before{}; // 真实旧DR0/DR7，回滚不借用已经转换的全局类型。
};

// 输入同址槽当前上下文，输出是否仍是本端的旧写入/新执行状态；外来状态不得覆盖。
bool OwnedControl(const CONTEXT& context, std::uint64_t address, std::uint64_t writeControl)
{
    const auto control = context.Dr7 & kSlotMask; // 只判断本端负责的槽0位。
    return context.Dr0 == address && (control == writeControl || control == kExecutionControl);
}

// 输入互斥的原始候选，回读同址执行资格；明确地址不借用任何映像指针选择器。
DWORD VerifyFollowSite(HANDLE process, const NativePrivateExecutionSite* pointerSite,
    const NativeExplicitMemorySite* explicitSite)
{
    if (static_cast<bool>(pointerSite) == static_cast<bool>(explicitSite))
    {
        return ERROR_INVALID_PARAMETER;
    }
    return explicitSite ? VerifyNativeExplicitMemorySite(process, *explicitSite, 0) :
        VerifyNativePrivateExecutionSite(process, *pointerSite);
}

// 输入已尝试槽和原写设置，尽力回滚并读回；输出确认结果，任何未知/冲突仍留在原恢复账。
bool RollbackThread(const PreparedThread& prepared, std::uint64_t address, std::uint64_t writeControl)
{
    auto& state = *prepared.slot.state; // 恢复状态始终保存在原owner，Close继续使用。
    state.expectedControl = writeControl;
    state.alternateControl = kExecutionControl;
    state.observedControl.reset();
    const auto lifetime = WaitForSingleObject(prepared.slot.thread, 0); // 已退出的精确线程对象无需恢复DR。
    if (lifetime == WAIT_OBJECT_0)
    {
        state.alternateControl.reset();
        return true;
    }
    if (lifetime != WAIT_TIMEOUT)
    {
        return false;
    }

    CONTEXT current{}; // 回滚前重新读取，不覆盖其它槽及之后可见的系统状态。
    current.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(prepared.slot.thread, &current))
    {
        return false;
    }
    state.observedControl = current.Dr7 & kSlotMask;
    if (!OwnedControl(current, address, writeControl))
    {
        return false; // 外来寄存器冲突只能由原owner报告并保留，不能强行覆盖。
    }
    if ((current.Dr7 & kSlotMask) != writeControl)
    {
        current.Dr7 = static_cast<decltype(current.Dr7)>((current.Dr7 & ~kSlotMask) | writeControl);
        (void)SetThreadContext(prepared.slot.thread, &current); // 即使Set失败，仍必须回读真实结果。
    }
    if (!GetThreadContext(prepared.slot.thread, &current))
    {
        state.observedControl.reset();
        return false;
    }
    state.observedControl = current.Dr7 & kSlotMask;
    if (!OwnedControl(current, address, writeControl))
    {
        return false;
    }
    state.expectedControl = current.Dr7 & kSlotMask; // 保留每线程实际已确认的旧或新状态。
    state.alternateControl.reset();
    return state.expectedControl == writeControl;
}

} // namespace

std::optional<std::uint64_t> NativeExecutionFollowSequence(std::string_view id) noexcept
{
    constexpr std::string_view prefix = "follow/"; // 与释放和步进序列完全独立。
    if (!id.starts_with(prefix))
    {
        return {};
    }
    id.remove_prefix(prefix.size());
    if (id.empty() || id.front() == '0')
    {
        return {};
    }
    std::uint64_t sequence = 0; // 解析后的严格单调请求序号。
    const auto parsed = std::from_chars(id.data(), id.data() + id.size(), sequence);
    return parsed.ec == std::errc{} && parsed.ptr == id.data() + id.size() && sequence
        ? std::optional(sequence) : std::nullopt;
}

NativeFollowError ValidateNativeExecutionFollow(const OwnerIdentity& owner,
    const NativeExecutionFollowRequest& request, const NativeControlResult& current,
    const NativeImageSite* frozen)
{
    const auto& stop = request.stop; // 请求内完整授权，仅用于核对，不交给释放账本。
    const auto& group = current.group; // 同owner此刻实际停止组。
    const auto& responsibility = current.responsibility; // 原生事件仍须由该owner持有。
    if (stop.owner != owner || !group || group->sampleId != owner.sampleId ||
        group->sessionId != owner.sessionId || group->epoch != owner.epoch || !responsibility ||
        stop.event.backendInstanceId != owner.backendInstanceId || !current.pending ||
        stop.groupId != group->groupId || stop.groupId != responsibility->groupId ||
        stop.stopId != responsibility->stopId || stop.event != responsibility->event ||
        stop.event != current.pending->event || stop.expectedStateRevision != group->stateRevision)
    {
        return {"private-execution-follow-stale-stop", ERROR_INVALID_DATA};
    }
    if (!current.attached || current.clean || current.status != NativeControlStatus::Held || group->historical ||
        group->state != GroupState::HeldComplete || !group->origin ||
        group->origin->phase != StopPhase::DataWriteObserved || responsibility->state != EventState::Held ||
        !current.pending->ledgerOwned || current.pending->continuationIndeterminate ||
        current.pending->eventCode != EXCEPTION_DEBUG_EVENT || current.pending->exceptionCode != EXCEPTION_SINGLE_STEP ||
        current.pending->exceptionFirstChance != true || !current.breakpointHit || !current.breakpointHit->dataChange)
    {
        return {"private-execution-follow-complete-write-stop-required", ERROR_INVALID_STATE};
    }
    const auto& binding = current.breakpoint; // 必须仍是最初同址的私有写关注。
    if (!binding || binding->state != NativeBreakpointState::Held || !binding->writeWatchBytes ||
        binding->executePointerExport || (!binding->explicitPrivateAddress && !binding->pointerExportAddress) ||
        (binding->explicitPrivateAddress && binding->pointerExportAddress) || !binding->privateExecutionFollowAvailable ||
        !frozen || !request.address || request.address != binding->address || request.address != frozen->address ||
        current.breakpointHit->address != request.address || frozen->regionProtection != PAGE_EXECUTE_READWRITE ||
        frozen->regionBase != request.address || binding->regionProtection != frozen->regionProtection ||
        binding->regionBase != frozen->regionBase || binding->regionBytes != frozen->regionBytes ||
        binding->allocationBase != frozen->allocationBase || binding->moduleBase != frozen->base ||
        binding->pointerExportAddress != frozen->pointerExportAddress || binding->rva != frozen->rva)
    {
        return {"private-execution-follow-original-rwx-start-required", ERROR_INVALID_ADDRESS};
    }
    return {};
}

NativeFollowError SwitchNativeWriteToExecution(std::span<NativeFollowThread> threads,
    std::uint64_t address, std::uint64_t writeControl, HANDLE process,
    const NativePrivateExecutionSite* pointerSite, const NativeExplicitMemorySite* explicitSite)
{
    std::vector<PreparedThread> prepared; // 所有分配与上下文预读均发生在首个Set之前。
    prepared.reserve(threads.size());
    for (const auto& slot : threads)
    {
        if (!slot.thread || !slot.state || slot.state->alternateControl || slot.state->expectedControl != writeControl)
        {
            return {"private-execution-follow-slot-state-conflict", ERROR_INVALID_STATE};
        }
        const auto lifetime = WaitForSingleObject(slot.thread, 0); // 跳过已确认退出对象，未知必须拒绝。
        if (lifetime == WAIT_OBJECT_0)
        {
            continue;
        }
        if (lifetime != WAIT_TIMEOUT)
        {
            return {"private-execution-follow-thread-lifetime", ERROR_INVALID_DATA};
        }
        PreparedThread item{slot}; // 预读时不改写任何线程上下文。
        item.before.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(slot.thread, &item.before))
        {
            return Failure("private-execution-follow-preread-context");
        }
        if (item.before.Dr0 != address || (item.before.Dr7 & kSlotMask) != writeControl ||
            (item.before.Dr7 & 0xfc) || (item.before.EFlags & 0x100))
        {
            return {"private-execution-follow-preread-conflict", ERROR_INVALID_DATA};
        }
        prepared.push_back(item);
    }
    if (prepared.empty())
    {
        return {"private-execution-follow-no-live-slots", ERROR_NOT_FOUND};
    }
    if (const auto error = VerifyFollowSite(process, pointerSite, explicitSite))
    {
        return {"private-execution-follow-preread-site-changed", error}; // 尚未Set，原写关注完整保留。
    }

    NativeFollowError failure; // 记录首次Set/验证错误，回滚不得覆盖其原因。
    std::size_t attempted = 0; // 包含结果不明的失败Set，回滚不能漏掉这一线程。
    for (auto& item : prepared)
    {
        auto context = item.before; // 保留所有其它DR值，只切换槽0类型和长度位。
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        context.Dr7 = static_cast<decltype(context.Dr7)>((context.Dr7 & ~kSlotMask) | kExecutionControl);
        ++attempted;
        if (!SetThreadContext(item.slot.thread, &context))
        {
            failure = Failure("private-execution-follow-set-context");
            break;
        }
        if (!GetThreadContext(item.slot.thread, &context))
        {
            failure = Failure("private-execution-follow-readback-context");
            break;
        }
        if (context.Dr0 != address || (context.Dr7 & kSlotMask) != kExecutionControl)
        {
            failure = {"private-execution-follow-readback-conflict", ERROR_INVALID_DATA};
            break;
        }
    }
    if (!failure.code)
    {
        if (const auto error = VerifyFollowSite(process, pointerSite, explicitSite))
        {
            failure = {"private-execution-follow-postread-site-changed", error}; // 已Set也必须走完整回滚。
        }
    }
    if (failure.code)
    {
        for (std::size_t index = attempted; index > 0; --index)
        {
            if (!RollbackThread(prepared[index - 1], address, writeControl))
            {
                failure.rollbackComplete = false;
            }
        }
        return failure;
    }
    for (const auto& item : prepared)
    {
        item.slot.state->expectedControl = kExecutionControl;
        item.slot.state->alternateControl.reset();
        item.slot.state->observedControl = kExecutionControl;
    }
    return {};
}

NativeFollowError ValidateNativeFollowThreads(const NativeControlResult& current,
    std::span<const NativeFollowThread> threads)
{
    std::size_t live = 0; // 双向比较活槽数量，不能遗漏尚未登记的冻结成员。
    for (const auto& slot : threads)
    {
        const auto lifetime = WaitForSingleObject(slot.thread, 0); // 只确认原句柄，不重开同TID。
        if (lifetime == WAIT_OBJECT_0)
        {
            continue;
        }
        if (lifetime != WAIT_TIMEOUT || GetProcessIdOfThread(slot.thread) != current.pid)
        {
            return {"private-execution-follow-thread-owner-mismatch", ERROR_INVALID_DATA};
        }
        FILETIME created{}, exited{}, kernel{}, user{}; // 精确线程对象的创建身份。
        if (!GetThreadTimes(slot.thread, &created, &exited, &kernel, &user))
        {
            return Failure("private-execution-follow-thread-times");
        }
        const auto creation = (std::uint64_t{created.dwHighDateTime} << 32) | created.dwLowDateTime;
        const auto tid = GetThreadId(slot.thread); // TID仅与同一原句柄读取的创建时间一起核对。
        const auto member = std::find_if(current.frozenThreads.begin(), current.frozenThreads.end(), [&](const auto& value) {
            return value.tid == tid && value.creationTime == creation && !value.identity.threadId.empty();
        });
        if (member == current.frozenThreads.end())
        {
            return {"private-execution-follow-thread-not-frozen", ERROR_INVALID_DATA};
        }
        ++live;
    }
    return live && live == current.frozenThreads.size() ? NativeFollowError{}
        : NativeFollowError{"private-execution-follow-incomplete-threads", ERROR_INVALID_DATA};
}

} // namespace ks::cli::action_analyze::control
