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

} // namespace ks::cli::action_analyze::control
