#pragma once
#include "../../Core/Win32Lean.h"
#include "../../../shared/evidence/ApiNativeExecutionProjection.h"

namespace Ksword::Features::ActionAnalyze {
HWND CreateExecutionGroupPage(HWND parent, const RECT& bounds);
// 在原工作台外增加独立执行集合入口，不接管单目标页的端口或owner。
HWND CreateActionAnalyzeExecutionWorkspace(HWND parent, const RECT& bounds);
// 从当前归档页沿同一工作台导航，把纯值草稿加入未启动的原集合页；不附加或覆盖输入。
bool PrepareExecutionGroupEvidenceDraft(HWND source, const Ksword::Evidence::NativeExecutionSiteDraft& draft);
}
