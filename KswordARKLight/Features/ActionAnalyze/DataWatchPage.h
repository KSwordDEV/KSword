#pragma once

#include "../../Core/Win32Lean.h"
#include <cstdint>
#include <string>

namespace Ksword::Features::ActionAnalyze {

struct LightImageExecutionDraft {
    std::wstring modulePath;
    std::uint32_t rva = 0;
    std::string definitionId;
    std::wstring projectPath; // 原后台目录发布的project.ksaproj，准备时选择打开，不在UI读盘。
    std::string projectId; // 原定义项目身份，Start后还须匹配真实打开项目。
};
// 纯UI准备：拒绝活owner，确认已有位置替换；保留实例、条件和旧结果，不Arm。
bool PrepareDataWatchImageExecutionDraft(HWND page, const LightImageExecutionDraft& draft);

// 输入父窗口和内容边界，返回现有工作台；工程采集仍为默认页，写入/私有执行复用原停点子页。
HWND CreateActionAnalyzeWorkspace(HWND parent, const RECT& bounds);
// 行为分析外层宿主统一持有纯UI控制端口，保留原工作台及独立集合页的导航层级。
HWND CreateActionAnalyzeControlWorkspace(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::ActionAnalyze
