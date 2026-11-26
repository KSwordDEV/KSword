#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NetworkTrafficRead.h"

namespace Ksword::Features::ActionAnalyze {

struct LightNetworkTrafficView {
    Ksword::ActionAnalyze::NetworkTrafficResult result; // 实际冻结请求及原采集/读端返回值。
    std::wstring text; // 同一结果的完整文本，搜索/复制/导出不另造副本来源。
};

// Light后台调用，独占正式ProjectDocument租约；输入不含HWND，返回前释放writer。
LightNetworkTrafficView RunLightNetworkTraffic(Ksword::ActionAnalyze::NetworkTrafficRequest request,
    const std::atomic_bool& cancelled);

} // namespace Ksword::Features::ActionAnalyze
