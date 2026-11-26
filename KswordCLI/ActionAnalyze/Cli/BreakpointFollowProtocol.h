#pragma once

#include "BreakpointStepProtocol.h"

namespace ks::cli::action_analyze {

// 私有写入后显式转执行的协议；不占用 Continue/Step 序列，不保留第二份原生恢复账。
class BreakpointFollowProtocol final {
public:
    BreakpointStepReply Dispatch(const Request& request, bool jsonl, bool supported,
        const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);
    JsonValue Report(const control::NativeExecutionFollowReceipt& receipt) const;
    JsonValue Capabilities() const;

private:
    struct Saved {
        std::string signature; // 相同请求ID只能重放相同地址和停点。
        Fault error;
        std::optional<control::NativeControlResult> result;
    };
    std::map<std::uint64_t, Saved> requests_; // 仅保留最近128个协议回执。
    std::uint64_t highWater_ = 0;
};

} // namespace ks::cli::action_analyze
