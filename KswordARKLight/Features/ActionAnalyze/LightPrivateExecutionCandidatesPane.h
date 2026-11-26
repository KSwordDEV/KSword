#pragma once
#include "../../Core/Win32Lean.h"
#include "LightPrivateExecutionCandidatesFields.h"
#include <functional>

namespace Ksword::Features::ActionAnalyze {
// 原DataWatchPage提供纯UI端口；本Pane不拥有后台会话、document或writer。
struct LightPrivateExecutionCandidatesPort {
    std::function<LightPrivateExecutionCandidatesContext()> read;
    std::function<bool(const std::shared_ptr<const std::uint8_t>&, const LightPrivateExecutionCandidatesRequest&)> request;
    std::function<bool(const LightPrivateExecutionCandidateSelection&)> prepare;
};
HWND CreateLightPrivateExecutionCandidatesPane(HWND parent, const RECT& bounds, LightPrivateExecutionCandidatesPort port);
} // namespace Ksword::Features::ActionAnalyze
