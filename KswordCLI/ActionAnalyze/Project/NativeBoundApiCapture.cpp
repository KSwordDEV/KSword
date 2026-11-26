#include "NativeBoundApiCapture.h"

namespace Ksword::ActionAnalyze {

NativeBoundApiRejection ValidateNativeBoundApiRequest(const NativeBoundApiRequest& request,
    const NativeBoundApiTarget& nativeTarget) noexcept
{
    // 显式授权及强实例缺一不可，有限区间不允许0或持续模式。
    if (!request.confirmed || request.sourcePid <= 4 || request.sourcePid == GetCurrentProcessId() ||
        !request.sourceCreationFileTime || request.durationMs < 1000 || request.durationMs > 10000)
    {
        return NativeBoundApiRejection::InvalidSource;
    }
    if (!nativeTarget.attached || !nativeTarget.pid || !nativeTarget.creationFileTime)
    {
        return NativeBoundApiRejection::NativeUnavailable;
    }
    // 即使输入了另一创建时间也拒绝同PID；不能向原调试owner控制的进程装载API来源。
    if (request.sourcePid == nativeTarget.pid)
    {
        return NativeBoundApiRejection::SourceIsNativeTarget;
    }
    return NativeBoundApiRejection::None;
}

int NativeBoundApiResult::CaptureExitCode() const noexcept
{
    const auto& capture = receipt.capture; // 原采集器实际回执。
    const bool incomplete = receipt.omittedClues || receipt.rules.failed || !capture.started ||
        !capture.completedInterval || !capture.cleanupComplete; // 各独立缺口不被code=0掩盖。
    return capture.code == 0 && incomplete ? 6 : capture.code;
}

int NativeBoundApiResult::ExitCode() const noexcept
{
    // 原CLI约定项目/归档/Agent定位失败为3；其余保持原采集码。
    if (!accepted || !receipt.sampleStatus || !receipt.archiveStatus || !receipt.agentPathAvailable)
    {
        return 3;
    }
    return CaptureExitCode();
}

NativeBoundApiResult CaptureNativeBoundApi(ProjectDocument& document, std::string_view sampleId,
    const NativeBoundApiRequest& request, const NativeBoundApiTarget& nativeTarget,
    const std::atomic_bool& cancel)
{
    NativeBoundApiResult result; // 所有失败路径也保留实际请求和原目标。
    result.request = request;
    result.nativeTarget = nativeTarget;
    result.sampleId = sampleId;
    result.rejection = ValidateNativeBoundApiRequest(request, nativeTarget);
    if (result.rejection != NativeBoundApiRejection::None)
    {
        result.admission = {ProjectError::InvalidArgument, ERROR_INVALID_PARAMETER, "nativeBoundApiTarget"};
        return result;
    }

    const auto* info = document.Info(); // 仅借用原worker独占document，不重新打开项目。
    if (!info || info->access != ProjectAccess::ReadWrite || sampleId.empty())
    {
        result.rejection = NativeBoundApiRejection::ProjectUnavailable;
        result.admission = {ProjectError::InvalidArgument, ERROR_INVALID_PARAMETER, "nativeBoundApiWriter"};
        return result;
    }
    result.projectId = info->projectId;
    result.accepted = true;
    SampleRecord sample; // 读取原采样冻结修订，不采用当前项目新修订替换。
    result.receipt.sampleStatus = document.ReadSample(sampleId, sample);
    if (!result.receipt.sampleStatus)
    {
        return result;
    }

    // 唯一显式附加入口负责强实例、管道、单包归档、规则与清退；本层不复制采集器。
    AttachedApiRequest capture; // 字符串只在本同步调用内借用。
    capture.pid = request.sourcePid;
    capture.creationFileTime = request.sourceCreationFileTime;
    capture.confirmed = request.confirmed;
    capture.durationMs = request.durationMs;
    capture.title = "Native session API source";
    capture.revisionId = sample.info.revisionId;
    capture.boundSampleId = result.sampleId;
    result.receipt = CaptureAttachedApi(document, capture, cancel);
    return result;
}

} // namespace Ksword::ActionAnalyze
