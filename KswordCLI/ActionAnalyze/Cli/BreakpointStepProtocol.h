#pragma once

#include "Protocol.h"
#include "../Control/NativeDebugOwner.h"

#include <map>

namespace ks::cli::action_analyze {

struct BreakpointStepReply {
    bool handled = false;
    Fault error;
    std::optional<control::NativeControlResult> control;
};

// 协议仅保存请求映射和有界回执；原生事件及所有恢复责任仍由 NativeDebugOwner 持有。
class BreakpointStepProtocol final {
public:
    [[nodiscard]] BreakpointStepReply Dispatch(const Request& request, bool jsonl, bool supported,
        const control::OwnerIdentity& identity, control::NativeDebugOwner& owner,
        std::uint64_t& nativeReleaseSequence);
    [[nodiscard]] JsonValue Report(const control::NativeStepReceipt& receipt) const;
    [[nodiscard]] JsonValue Capabilities() const;

private:
    struct SavedStep {
        std::string signature;
        std::string nativeRequestId;
        Fault error;
        std::optional<control::NativeControlResult> control;
    };
    std::map<std::uint64_t, SavedStep> requests_;
    std::uint64_t highWater_ = 0;
};

} // namespace ks::cli::action_analyze
