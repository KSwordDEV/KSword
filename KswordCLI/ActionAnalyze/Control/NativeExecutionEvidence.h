#pragma once

#include "NativeDebugOwner.h"

namespace ks::cli::action_analyze::control {

enum class NativeExecutionKind { EnterAttempt, InstructionCompleted };

// 同一绑定内的实际取指地址：单地址必须精确相等，NX范围采用无溢出的半开区间。
bool NativeExecutionAddressInBinding(const NativeBreakpointBinding& binding, std::uint64_t address) noexcept;

// 本对象只能由原生所有者回读适配器构造；不会将 API 请求入口、线程创建或内存变化视为执行。
struct NativeExecutionEvidence {
    NativeExecutionKind kind = NativeExecutionKind::EnterAttempt; // DR0/NX执行停点或真实TF步进完成。
    std::uint32_t pid = 0; // 冻结的执行进程身份。
    std::uint64_t processCreationFileTime = 0;
    NativeFrozenThread thread; // 原生事件核对的实际执行线程，不是 API 创建者或写入者。
    NativeEventKey event; // 支撑本观测的精确原生事件。
    std::string groupId; // 当前实际仍持有的停止组。
    std::string stopId; // 当前事件停止令牌。
    std::uint64_t stateRevision = 0; // 该观测对应的实时停止组修订。
    std::uint64_t instructionAddress = 0; // 尝试进入或确认完成的指令起点。
    std::optional<std::uint64_t> nextInstructionAddress; // TF 完成时实际回读的下一 RIP。
    std::optional<std::uint64_t> observedQpc; // 所有者观察本事件的时刻，不伪造 CPU 精确取指时刻。
    std::uint64_t qpcFrequency = 0;
};

// 内部原生边界：输入必须是同一活 NativeDebugOwner 的 Query/Step 回执，禁止用于外来 JSON 解码。
// 仅确认精确当前执行DR0或Into模式完成的单指令TF；步过/跳出完成不升级成入口指令已执行。
std::optional<NativeExecutionEvidence> NativeExecutionFromOwnedStop(const NativeControlResult& state);

} // namespace ks::cli::action_analyze::control
