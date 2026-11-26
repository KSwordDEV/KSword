#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "NativeDebugOwner.h"
#include "NativePrivateExecutionSite.h"
#include "NativeExplicitMemorySite.h"

#include <span>

namespace ks::cli::action_analyze::control {

// 每个原owner槽位独立保留恢复预期，不能用全局类型覆盖部分转换后的实际状态。
struct NativeFollowSlotState {
    std::uint64_t expectedControl = 0; // 最近一次确认属于本端的DR0控制位。
    std::optional<std::uint64_t> alternateControl; // Set结果/回读未知时，本端唯一另一种可能值。
    std::optional<std::uint64_t> observedControl; // 最近回读值，包含冲突值，不据此取得外来状态所有权。
};

struct NativeFollowThread {
    HANDLE thread = nullptr; // 借用原owner保持的线程对象，不按裸TID重开。
    NativeFollowSlotState* state = nullptr; // 借用对应槽位恢复账，任何失败都原位保留。
};

struct NativeFollowError {
    const char* stage = "private-execution-follow-converted"; // 返回本次转换或首次失败的稳定阶段。
    DWORD code = ERROR_SUCCESS; // 输入检查或原生操作的错误码。
    bool rollbackComplete = true; // 未写入或全部回滚确认时为真。
};

// 输入独立请求ID，输出严格正数序号；不接受前导零、溢出、尾随字符或continue命名空间。
[[nodiscard]] std::optional<std::uint64_t> NativeExecutionFollowSequence(std::string_view id) noexcept;

// 输入原owner快照及冻结候选，输出授权核对结果；不访问现场、不修改原事件阶段。
[[nodiscard]] NativeFollowError ValidateNativeExecutionFollow(const OwnerIdentity& owner,
    const NativeExecutionFollowRequest& request, const NativeControlResult& current,
    const NativeImageSite* frozen);

// 输入当前完整冻结成员及原槽位句柄，核对活成员双向覆盖与创建时间，返回身份错误或成功。
[[nodiscard]] NativeFollowError ValidateNativeFollowThreads(const NativeControlResult& current,
    std::span<const NativeFollowThread> threads);

// 调用方持有完整原生debug停止事件；先预读全部活槽，再只切换DR0类型，失败回滚全部已尝试槽。
// 返回值保留原失败，每线程恢复预期写回state；函数不Resume、不Continue、不接管外来寄存器。
[[nodiscard]] NativeFollowError SwitchNativeWriteToExecution(std::span<NativeFollowThread> threads,
    std::uint64_t address, std::uint64_t writeControl, HANDLE process,
    const NativePrivateExecutionSite* pointerSite, const NativeExplicitMemorySite* explicitSite);

} // namespace ks::cli::action_analyze::control
