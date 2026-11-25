#include "InjectionSurveyProjection.h"

#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {

// 共享绑定门槛；仅由明确选择的同次本地调用路径接纳旧占位启动标识。
SurveyProjection BindSurvey(const SampleScope& scope, const EvidenceRef& evidence,
    const ProcessBinding& expectedTarget, Evidence::SurveyReport report, bool currentLocalCollector)
{
    SurveyProjection result;
    if (!HasEvidenceLocation(scope, evidence)) {
        return result;
    }
    result.evidence = evidence;
    // expectedTarget 来自当前采样的绑定，而非根据报告 PID 反查活动进程。
    if (report.identity == Evidence::IdentityRecheckVerdict::Changed) {
        result.status = SurveyProjectionStatus::IdentityMismatch;
        return result;
    }
    auto observed = report.process;
    if (currentLocalCollector && observed.bootId == "live") {
        observed.bootId = scope.bootId;
    }
    if (report.identity != Evidence::IdentityRecheckVerdict::Same || !IsBoundProcess(scope, expectedTarget) ||
        !IsBoundProcess(scope, {expectedTarget.machineId, observed})) {
        result.status = SurveyProjectionStatus::IdentityUnverifiable;
        return result;
    }
    if (Evidence::MatchProcessInstance(expectedTarget.instance, observed) != Evidence::MatchResult::Confirmed) {
        result.status = SurveyProjectionStatus::IdentityMismatch;
        return result;
    }
    // 不重跑判据，也不把可靠栈帧与外来写入或本次确证取指混为一谈。
    result.status = SurveyProjectionStatus::Bound;
    result.target = expectedTarget;
    result.report = std::move(report);
    return result;
}

} // namespace

SurveyProjection ProjectSurveySnapshot(const SampleScope& scope, const EvidenceRef& evidence,
    const ProcessBinding& expectedTarget, Evidence::SurveyReport report)
{
    return BindSurvey(scope, evidence, expectedTarget, std::move(report), false);
}

SurveyProjection ProjectCurrentLocalSurveySnapshot(const SampleScope& scope, const EvidenceRef& evidence,
    const ProcessBinding& expectedTarget, Evidence::SurveyReport report)
{
    return BindSurvey(scope, evidence, expectedTarget, std::move(report), true);
}

const Evidence::InjectionFinding* ReadSurveyFinding(const SurveyProjection& projection,
    std::size_t itemIndex) noexcept
{
    if (projection.status != SurveyProjectionStatus::Bound || !projection.report ||
        itemIndex >= projection.report->findings.size()) {
        return nullptr;
    }
    return &projection.report->findings[itemIndex];
}

} // namespace Ksword::ActionAnalyze::Detection
