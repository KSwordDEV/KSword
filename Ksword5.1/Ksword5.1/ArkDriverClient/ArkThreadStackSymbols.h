#pragma once

#include "ArkThreadStackCapture.h"
#include "../../../shared/usermode/backend/driver/DriverTypes.h"

namespace ksword::ark
{
    // 输入同次采集前后的模块表及有效回执；输出原帧的本地注释，不联网、不读取内核地址。
    // 调用者在 worker 中使用；模块不稳定、PDB 缺失时保留裸地址，不使采集整体失败。
    std::vector<ThreadStackFrameSymbol> ResolveThreadStackFrames(
        const KSWORD_ARK_THREAD_STACK_RESPONSE& response,
        const std::vector<ks::r3::driver::DriverOverviewRow>& before,
        const std::vector<ks::r3::driver::DriverOverviewRow>& after,
        const std::wstring& localSymbolPath);
}
