#pragma once

#include "StopLedger.h"

namespace ks::cli::action_analyze::control {

enum class NativeStepMode { Into, OverCall, Out };
enum class NativeStepState { Running, Completed, Interrupted, Cancelled, Exited, RecoveryRequired };

// Authorization applies to the exact held event and ledger revision. The selected
// thread must be that event's strong origin, never a TID-only lookup.
struct NativeStepRequest {
    ReleaseRequest release;
    ThreadIdentity thread;
    std::uint32_t tid = 0;
    std::uint64_t threadCreationTime = 0;
    NativeStepMode mode = NativeStepMode::Into;
    bool operator==(const NativeStepRequest&) const = default;
};

struct NativeStepReceipt {
    NativeStepRequest request;
    NativeStepState state = NativeStepState::Running;
    const char* stage = "step-running";
    std::uint32_t win32Error = 0;
    std::uint64_t startIp = 0;
    std::uint64_t startSp = 0;
    std::optional<std::uint64_t> destination;
    std::optional<std::uint64_t> observedIp;
    std::optional<std::uint64_t> observedSp;
    std::optional<NativeEventKey> observedEvent;
    std::optional<std::string> stopGroupId;
    bool resourcesRestored = false;
};

// 输入receipt为已经准备的原步进回执，返回是否使用单条TF；OverCall只有非CALL分支不设DR1目的地。
// 这里只分类实际机制，完成、事件身份和资源恢复仍由原owner及证据投影分别核对。
inline bool NativeStepUsesSingleInstructionTrap(const NativeStepReceipt& receipt) noexcept
{
    return !receipt.destination && (receipt.request.mode == NativeStepMode::Into ||
        receipt.request.mode == NativeStepMode::OverCall);
}

} // namespace ks::cli::action_analyze::control
