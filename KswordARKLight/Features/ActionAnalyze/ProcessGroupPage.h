#pragma once

#include "../../Core/Win32Lean.h"
#include <memory>

namespace Ksword::Features::ActionAnalyze {
class LightNativeControlPort;

// 创建本端进程集合页面。导航入口由调用方登记，本模块不改动共享工作区。
HWND CreateProcessGroupPage(HWND parent, const RECT& bounds);
HWND CreateProcessGroupPage(HWND parent, const RECT& bounds, const std::shared_ptr<LightNativeControlPort>& port);

} // namespace Ksword::Features::ActionAnalyze
