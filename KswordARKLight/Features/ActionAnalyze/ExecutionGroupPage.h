#pragma once
#include "../../Core/Win32Lean.h"

namespace Ksword::Features::ActionAnalyze {
HWND CreateExecutionGroupPage(HWND parent, const RECT& bounds);
// 在原工作台外增加独立执行集合入口，不接管单目标页的端口或owner。
HWND CreateActionAnalyzeExecutionWorkspace(HWND parent, const RECT& bounds);
}
