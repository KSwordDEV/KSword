#pragma once

#include "NativeBreakpointImage.h"

namespace ks::cli::action_analyze::control {

// 用户直接选择的私有地址，不依赖映像导出或合作目标中的指针选择器。
struct NativeExplicitMemorySite {
    NativeImageSite site;
    DWORD allocationProtection = 0;
};

// writeBytes=0 表示执行，1/2/4/8 表示实际硬件写关注宽度。
// 只查询当前区域，不修改保护、内容或线程状态。
[[nodiscard]] DWORD ResolveNativeExplicitMemorySite(HANDLE process, DWORD pid,
    std::uint64_t address, std::uint32_t writeBytes, NativeExplicitMemorySite& result);

// 原调试事件暂停期间回读冻结区域；同址重新分配代次仍未知，不自动重绑。
[[nodiscard]] DWORD VerifyNativeExplicitMemorySite(HANDLE process,
    const NativeExplicitMemorySite& frozen, std::uint32_t writeBytes);

} // namespace ks::cli::action_analyze::control
