#pragma once

#include "BreakpointStepProtocol.h"

namespace ks::cli::action_analyze
{
    // 原执行owner的主动暂停协议；不创建额外调试附加，不持有停止责任副本。
    class BreakpointPauseProtocol final
    {
    public:
        // 输入当前活会话及REPL/JSONL请求，返回原owner暂停或回执查询结果。
        [[nodiscard]] BreakpointStepReply Dispatch(const Request& request, bool jsonl, bool supported,
            const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);
        // 将独立暂停回执投影为JSON；接受、真实停止和被命中抢先分别保留。
        [[nodiscard]] static JsonValue Report(const control::NativeArmedPauseReceipt& receipt);
        // 返回命令、独立票据空间及实际停止的观察方式。
        [[nodiscard]] static JsonValue Capabilities();

    private:
        std::uint64_t highWater_ = 0; // 连续CLI票据水位；实际幂等回执由原生owner保留。
    };
}
