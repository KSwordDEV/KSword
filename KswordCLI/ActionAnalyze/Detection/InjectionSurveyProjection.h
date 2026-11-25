#pragma once

#include "InjectionDiscovery.h"
#include "../../../shared/evidence/InjectionSurvey.h"

namespace Ksword::ActionAnalyze::Detection {

enum class SurveyProjectionStatus { Bound, EvidenceUnavailable, IdentityUnverifiable, IdentityMismatch };

// 复用已经结束的按需 InjectionSurvey 报告；摘要、单项原始事实、规则版本和两类缺口均原样保留。
// 整份记录只属于现场补证，不生成实时写入、创建者或执行确认事实。
struct SurveyProjection {
    SurveyProjectionStatus status = SurveyProjectionStatus::EvidenceUnavailable;
    std::optional<EvidenceRef> evidence;
    std::optional<ProcessBinding> target; // ActionAnalyze 绑定；原报告里的启动字段不改写。
    std::optional<Evidence::SurveyReport> report;
};

// 只有报告前后身份一致，且与本次已冻结目标、采样机器及启动期匹配才发布。
SurveyProjection ProjectSurveySnapshot(const SampleScope& scope, const EvidenceRef& evidence,
    const ProcessBinding& expectedTarget, Evidence::SurveyReport report);

// 仅供当前本地采样直接调用既有采集器后使用。调用前应确认 scope 是当前本机启动期，
// 并把 expectedTarget 的 PID/创建时间传给既有采集器。接受其现场专用的 live 占位符，
// 从不接受历史导入或回放。原报告继续保存 live，规范目标身份单独放在 target。
SurveyProjection ProjectCurrentLocalSurveySnapshot(const SampleScope& scope, const EvidenceRef& evidence,
    const ProcessBinding& expectedTarget, Evidence::SurveyReport report);

// 单项回读沿用报告中的稳定顺序。返回的指针借用投影，越界或未绑定时为空。
const Evidence::InjectionFinding* ReadSurveyFinding(const SurveyProjection& projection,
    std::size_t itemIndex) noexcept;

} // namespace Ksword::ActionAnalyze::Detection
