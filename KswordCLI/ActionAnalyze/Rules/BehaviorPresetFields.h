#pragma once

#include "FilterAst.h"
#include "ApiBehaviorObservation.h"
#include "../../../shared/evidence/ApiMonitorClue.h"
#include "../../../shared/evidence/ApiMemoryLifecycleFields.h"
#include "../../../shared/evidence/ApiApcFields.h"
#include "../../../shared/evidence/ApiContextFields.h"
#include "../../../shared/evidence/ApiSectionMapFields.h"

namespace Ksword::ActionAnalyze::Rules {

// 每行只保留已核验原包的值；归档声明不认证生产者，也不授予活控制资格。
struct ApiPresetEvidence {
    std::uint32_t actorPid = 0; // 同一原包的调用方 PID；零表示未提供。
    std::optional<Evidence::ApiMemoryLifecycleFieldsV1> memory; // AAIM1 请求及返回。
    std::optional<Evidence::ApiApcFieldsV1> apc; // AAAP1 入队请求。
    Evidence::ApiApcQueueOutcome apcOutcome = Evidence::ApiApcQueueOutcome::Unknown; // 精确入队返回。
    std::optional<Evidence::ApiContextFieldsV1> context; // AACT1 请求寄存器。
    Evidence::ApiContextOutcome contextOutcome = Evidence::ApiContextOutcome::Unknown; // 精确上下文返回。
    std::optional<Evidence::ApiSectionMapFieldsV1> map; // AASM1 请求和映射输出。
    Evidence::ApiSectionMapOutcome mapOutcome = Evidence::ApiSectionMapOutcome::Unknown; // 精确映射返回。
    std::optional<ApiBehaviorObservation> behavior; // 同一原包的普通强类型返回与严格参数解码。
};

// 从完整原包调用各协议自己的严格读侧；缺少或无效协议不补造字段。
ApiPresetEvidence ReadApiPresetEvidence(const ks::winapi_monitor::ApiMonitorEventPacket& packet);
// 目录和实际投影共用稳定字段 ID，全部表示一次已归档的返回观察。
std::span<const FieldBinding> ApiPresetBehaviorFields();
// 目录说明借用静态文本，说明参数来源和缺失策略，不声称所有 API 都携带该字段。
std::string_view ApiPresetFieldSource(std::string_view id) noexcept;
// 为一次同步求值构造已排序字段；字符串均借用参数，调用期间须保持有效。
std::vector<FieldSample> ProjectApiPresetFields(std::string_view api, std::string_view family,
    std::optional<Evidence::ApiMonitorMemoryWriteReturn> returned, const ApiPresetEvidence& evidence);
// 格式化生产投影器实际提交规则的已知字段；仅用于归档详情显示，不重新求值。
std::string FormatApiPresetFields(std::span<const FieldSample> fields);

} // namespace Ksword::ActionAnalyze::Rules
