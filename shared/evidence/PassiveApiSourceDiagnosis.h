#pragma once

#include "PassiveApiArchiveTail.h"

namespace Ksword::Evidence {

// 针对授权文件的打开失败。输入为原生错误码，返回可供 CLI 采用的稳定原因。
[[nodiscard]] std::string_view PassiveApiOpenFailureName(DWORD error) noexcept;

// 每个已绑定的只读档案有独立历史。调用者在原有串行读取路径中维护它。
class PassiveApiSourceDiagnosis final {
public:
    // 从文件尾读器交付的已核验连续前缀逐行传入。不复制原包，不执行 I/O。
    void Observe(const ArchivedApiMonitorClue& row) noexcept;

    // 投影本轮尾读状态和此前观察到的生产方声明。ended 表示本端已释放源句柄。
    [[nodiscard]] JsonValue Report(const PassiveApiTailStatus& tail, bool ended) const;

private:
    std::uint64_t observedThrough_ = 0; // 已传入的最新源行号，防止旧通知覆盖新通知。
    std::uint64_t sessionReadySequence_ = 0; // 最新的 SessionReady 声明原行号，零表示未见。
    std::uint64_t captureNoticeSequence_ = 0; // 当前声明代次的最新采集状态原行号。
    std::uint64_t partialNoticeSequence_ = 0; // 当前声明代次的最近一次部分覆盖提示。
    std::string_view captureNotice_; // 已知状态的静态协议名，空表示未见。
};

} // namespace Ksword::Evidence
