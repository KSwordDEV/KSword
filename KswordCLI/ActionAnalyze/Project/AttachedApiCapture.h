#pragma once
#include "CooperativeApiCapture.h"

namespace Ksword::ActionAnalyze {
// 与驻留合作准入分开；只允许精确实例、显式确认和 R3。字符串在本次调用内借用。
struct AttachedApiRequest {
    DWORD pid = 0;
    std::uint64_t creationFileTime = 0;
    bool confirmed = false;
    bool useR0Injection = false;
    DWORD durationMs = 3000;
    std::string_view title;
    std::string_view revisionId;
    std::string_view boundSampleId; // 非空时仅写原采样的空API流，不创建另一采样或writer。
};
// 在原工作线程借用document；输入精确实例、确认及可选原sample，输出原采集/归档完整回执。
// boundSampleId为空沿用独立采样；非空由同一核心核验原API流未使用，不另开writer。
CooperativeApiReceipt CaptureAttachedApi(ProjectDocument& document, const AttachedApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady = {},
    const CooperativeApiCommitted& onCommitted = {}, const CooperativeApiTransferCommitted& onTransfers = {},
    const CooperativeApiStartup& onStartup = {});
}
