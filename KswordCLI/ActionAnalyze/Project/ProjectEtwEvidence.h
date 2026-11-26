#pragma once

#include "ProjectRawEvidence.h"
#include "../../../shared/usermode/backend/monitor/PassiveEtwSource.h"

namespace Ksword::ActionAnalyze {

// 在现有项目租约下将已停止的有限 ETW 采样写入指定流。plan 为冻结计划，reason 为结束原因。
// source 的队列由此函数排空。raw、checkpoint 分别返回写入与发布结果，函数返回 raw 写入及校验结果。
ProjectResult CommitFiniteEtwEvidence(ProjectDocument& project, std::string_view sampleId,
    ProjectEvidenceLane lane, const Evidence::JsonValue& plan, std::string_view reason,
    ks::r3::monitor::PassiveEtwSource& source, ks::cli::action_analyze::archive::RawEvidenceReceipt& raw,
    ProjectResult& checkpoint);

// 将只读 ETW 状态投影为活会话和归档共用的原生回执。
Evidence::JsonValue EtwSourceReceipt(const ks::r3::monitor::PassiveEtwStatus& status);

// 向打开的 Stored 段追加一批 ETW 观察，并返回归档写入状态。
ProjectResult AppendEtwObservations(ks::cli::action_analyze::archive::RawEvidenceArchive& writer,
    std::span<const ks::r3::monitor::PassiveEtwRecord> rows);

} // namespace Ksword::ActionAnalyze
