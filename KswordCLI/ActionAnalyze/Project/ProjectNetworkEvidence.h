#pragma once

#include "ProjectDocument.h"
#include "../Archive/NetworkEvidenceArchive.h"

namespace Ksword::ActionAnalyze {

struct ProjectNetworkObservation {
    ks::cli::action_analyze::archive::NetworkFlowMetadata flow; // 已绑定到采样目标的流元数据。
    ks::cli::action_analyze::archive::NetworkCapturedBytes capture = {}; // 可选正文借用到同步写入返回为止。
};

struct ProjectNetworkRecordLocation {
    std::uint64_t sequence = 0;
    std::uint64_t offset = 0;
};

struct ProjectNetworkEvidenceReceipt {
    ks::cli::action_analyze::archive::NetworkArchiveReceipt raw;
    std::vector<ProjectNetworkRecordLocation> locations;
};

// 在项目写锁下写入新采样的第一条 raw 段。归档已归属的元数据与可选正文，刷盘后回读完整段。
// 此回执表示单段已核验，不发布跨流检查点。
ProjectResult WriteInitialNetworkEvidence(ProjectDocument& project, std::string_view sampleId,
    const ks::cli::action_analyze::archive::NetworkEvidenceBinding& source,
    std::span<const ProjectNetworkObservation> observations,
    const ks::cli::action_analyze::archive::NetworkLoss& sourceLoss,
    ks::cli::action_analyze::archive::NetworkArchiveEnd end, ProjectNetworkEvidenceReceipt& out);

} // namespace Ksword::ActionAnalyze
