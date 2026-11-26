#pragma once

#include "ProjectRawEvidence.h"
#include "../../../shared/evidence/ApiMonitorClue.h"

namespace Ksword::ActionAnalyze {

// 将已核验的线索原包写入新采样的首段，按输入方式保存来源序号。
// 调用方持有项目写租约；成功后的刷盘边界从 receipt 读取。
ProjectResult WriteApiClueArchive(ProjectDocument& document, const SampleInfo& sample,
    std::span<const Evidence::ArchivedApiMonitorClue> rows, std::uint64_t sourceRows,
    Evidence::ApiMonitorArchiveSource source, ks::cli::action_analyze::archive::RawEvidenceReceipt& receipt,
    bool mixedEtw = false);

} // namespace Ksword::ActionAnalyze
