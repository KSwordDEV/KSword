#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::ActionAnalyze {

// Light行为分析宿主调用的原生工厂；仅创建页面，不自动采集或新建sample。
// parent为现有Tab宿主，bounds为其客户区；成功返回子页HWND，失败为空。
HWND CreateNetworkTrafficPage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::ActionAnalyze
