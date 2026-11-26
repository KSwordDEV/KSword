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
};
CooperativeApiReceipt CaptureAttachedApi(ProjectDocument& document, const AttachedApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady = {},
    const CooperativeApiCommitted& onCommitted = {}, const CooperativeApiTransferCommitted& onTransfers = {});
}
