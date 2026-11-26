#pragma once

#include "BreakpointStepProtocol.h"

namespace ks::cli::action_analyze
{
    // CLI只保存已解析的原生请求供重放，页面/历史坐标不能替代当前完整停点令牌。
    class BreakpointRangeProtocol final
    {
    public:
        // 输入REPL或JSONL请求及当前单目标owner；未命中本方法时返回handled=false。
        [[nodiscard]] BreakpointStepReply Dispatch(const Request& request, bool jsonl, bool supported,
            const control::OwnerIdentity& identity, control::NativeDebugOwner& owner);

        // 将原生范围事务投影为独立JSON回执；地址和长度以十进制字符串保持64位精度。
        [[nodiscard]] static JsonValue Report(const control::NativeExecutionRangeReceipt& receipt);

        // 返回此协议的票据空间、重放窗口和不自动继续语义。
        [[nodiscard]] static JsonValue Capabilities();

    private:
        struct Saved
        {
            std::string signature; // 地址、长度、stopId及修订的规范编码。
            Fault error; // 原解析/准入失败回执，重放不再次执行。
            std::optional<control::NativeControlResult> result; // 首次原生事务快照，保留原恢复诊断。
        };

        std::map<std::uint64_t, Saved> requests_; // 最近128个独立range/N回执。
        std::uint64_t highWater_ = 0; // 已消费的协议序号，不与Continue/Step共享。
    };
}
