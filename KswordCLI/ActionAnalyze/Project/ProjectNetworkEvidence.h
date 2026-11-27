#pragma once

#include "ProjectDocument.h"
#include "../Archive/NetworkEvidenceArchive.h"

namespace Ksword::ActionAnalyze {

struct ProjectNetworkObservation {
    ks::cli::action_analyze::archive::NetworkFlowMetadata flow; // 原始流观测及明确归属强度；请求目标独立保存在检查点。
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

// 采样期间实际接管过的进程实例窗口；PID 只是筛选目录身份，不能把弱端口线索升级为强归属。
struct ProjectNetworkTargetWindow {
    std::uint32_t pid = 0; // 已核验对象的数值PID，仅用于来源线索筛选。
    std::uint64_t creationFileTime = 0; // 准入时从持有句柄读回的创建时刻。
    std::uint64_t startUtc = 0; // 本会话接纳该对象的FILETIME，之前的包不补采。
    std::uint64_t endUtc = 0; // 窗口开放时为0，关闭后记录截止时刻；不等同于对象退出。
    bool root = false; // 区分原请求根与显式追加成员。
    std::string endReason = "active"; // 生命周期状态，退出时间不可读时与精确退出分开标记。
};

// 原采样的网络附属流，与 API 的 raw/checkpoints 独立占用目录，保持同一项目写租约。
struct ProjectNetworkCheckpoint {
    std::uint64_t ordinal = 0; // 已发布的网络段号，零表示尚未提交。
    std::uint64_t endOffset = 0; // 完整、刷盘且回读通过的段末偏移。
    std::uint64_t lastSequence = 0; // 网络流自身序号，不借用主流序号。
    std::string sha256; // 当前网络段的已核验字节摘要。
    ks::cli::action_analyze::archive::NetworkEvidenceBinding source; // 本段真实来源代次及时钟。
    std::uint32_t requestedPid = 0; // 原请求根的过滤目录身份，不限制段内每条PID，不构成强归属。
    std::uint64_t requestedCreation = 0; // 请求目标的创建 FILETIME，不回填到端口表线索。
    std::string stopReason; // 本段来源的实际结束原因。
    std::vector<ProjectNetworkTargetWindow> targetWindows; // 本段已接管实例窗口快照，不改变旧 raw 记录格式。
    ks::cli::action_analyze::archive::NetworkLoss loss; // 从本段正文核验的损失，不从包数或目录标记推定。
};

// 向原 sample 的 raw-network 新增段，逐字节回读后发布 checkpoints-network/N.json。
// checkpoint 由上次成功提交或 LoadNetworkEvidenceTail 提供；失败不推进其水位。
ProjectResult CommitNetworkEvidence(ProjectDocument& project, std::string_view sampleId,
    const ks::cli::action_analyze::archive::NetworkEvidenceBinding& source,
    std::span<const ProjectNetworkObservation> observations,
    const ks::cli::action_analyze::archive::NetworkLoss& loss,
    ks::cli::action_analyze::archive::NetworkArchiveEnd end,
    std::uint32_t requestedPid, std::uint64_t requestedCreation, std::string_view stopReason,
    ProjectNetworkCheckpoint& checkpoint, ProjectNetworkEvidenceReceipt& out,
    std::span<const ProjectNetworkTargetWindow> targetWindows = {});

// 只读核验网络段、来源、摘要和前段链。visitor 内容在返回成功前不得发布给页面。
ProjectResult ReadNetworkEvidence(const ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, ProjectNetworkCheckpoint& out,
    const ks::cli::action_analyze::archive::NetworkFlowBlockVisitor& visitor = {});

// 顺序读取已提交网络链，返回可续写水位；坏尾保留原文件并拒绝自动跳过。
ProjectResult LoadNetworkEvidenceTail(const ProjectDocument& project, std::string_view sampleId,
    ProjectNetworkCheckpoint& out);

// 在项目写锁下写入新采样的第一条 raw 段。归档已归属的元数据与可选正文，刷盘后回读完整段。
// 此回执表示单段已核验，不发布跨流检查点。
ProjectResult WriteInitialNetworkEvidence(ProjectDocument& project, std::string_view sampleId,
    const ks::cli::action_analyze::archive::NetworkEvidenceBinding& source,
    std::span<const ProjectNetworkObservation> observations,
    const ks::cli::action_analyze::archive::NetworkLoss& sourceLoss,
    ks::cli::action_analyze::archive::NetworkArchiveEnd end, ProjectNetworkEvidenceReceipt& out);

} // namespace Ksword::ActionAnalyze
