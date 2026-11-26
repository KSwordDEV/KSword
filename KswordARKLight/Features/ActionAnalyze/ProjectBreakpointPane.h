#pragma once

#include "DataWatchPage.h"
#include "ProjectReplay.h"
#include <functional>

namespace Ksword::Features::ActionAnalyze {

// 原项目总览外的自然高度定义选择区；仅消费原后台已发布目录，无文件查询或原生owner。
HWND CreateProjectBreakpointPane(HWND parent, const RECT& bounds,
    std::function<bool(const LightImageExecutionDraft&)> prepare);
// 原项目页成功发布目录时同步向其明确祖先宿主传值，失败不覆盖上次有效目录。
void PublishProjectBreakpointCatalog(HWND source, const ProjectReplayCatalog& catalog);

}
