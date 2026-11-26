#pragma once

#include "StoredEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectCallbackEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"

namespace Ksword::Features::ActionAnalyze {

// 从已登记目录行冻结的回放请求。重读沿用相同身份和描述散列。
struct ProjectReplayRequest {
    std::wstring manifestPath; // 用户明确选中的 project.ksaproj。
    std::string projectId; // 清单项目 UUID。
    std::string sampleId; // 目录行采样 UUID。
    std::string descriptionHash; // 目录记录的采样描述 SHA-256。
    bool operator==(const ProjectReplayRequest&) const = default;
};

struct ProjectReplayChoice {
    std::string title; // 目录记录的 UTF-8 采样名称。
    ProjectReplayRequest request; // 确认选择时提交的完整请求值。
};

struct ProjectReplayCatalog {
    std::string diagnostic; // 空值表示已读到目录，包括成功的空目录。
    std::uint32_t systemError = 0; // 原生错误码（若有）。
    std::wstring manifestPath;
    std::string projectId; // 空目录也有可用的项目身份。
    std::string revisionId;
    bool recoveredPrevious = false; // 目录来自恢复的上一次项目提交。
    std::vector<ProjectReplayChoice> choices; // 仅含已提交的目录记录。
    std::optional<std::vector<Ksword::ActionAnalyze::BreakpointDefinition>> breakpointDefinitions; // 同一后台项目快照的已保存定义。
};

enum class CheckpointState { NotChecked, NotPublished, Pending, Partial, Verified, PreviewLimited };
enum class ReplayCheckpointKind { None, Etw, PassiveApi };
enum class ProjectReplayMode { Explicit, SelectionPreview };

struct ReplayCheckpoint {
    CheckpointState state = CheckpointState::NotChecked; // 区分独立读取、等待、部分与终态。
    std::uint64_t lastVerifiedOrdinal = 0; // 已核对的连续段上界。
    std::uint64_t pendingOrdinal = 0; // 缺失或失败的下一段。
    std::uint64_t recordsEnd = 0; // 最近核验段的 records 文件端点。
    ReplayCheckpointKind kind = ReplayCheckpointKind::None;
    std::uint64_t rawEnd = 0; // 最近核验段的 raw 文件端点。
    std::optional<Ksword::Evidence::ApiMonitorArchiveSource> apiArchiveSource; // 经已核验的 API 检查点计划声明。
    std::string recordedRuleSourceSha256; // 已核验计划内的采集规则内容摘要，旧档为空。
    std::string apiStartupJson; // 已核验API终段的历史启动快照全文，非终段和旧档为空。
};

// 独立归档批次，不是持续采样的终态检查点，也不代表采集覆盖。
struct CallbackReplayBatch {
    Ksword::ActionAnalyze::ProjectCallbackEvidencePlan plan;
    Ksword::ActionAnalyze::ProjectCallbackEvidenceEnd end;
    std::string prefixSha256;
};

struct MixedEtwReplay {
    SegmentEvidence raw; // 独立于 API 的已核验前缀与最近窗口。
    ReplayCheckpoint checkpoint;
};

struct ProjectReplayEvidence {
    SegmentEvidence raw; // 已验证前缀的最近窗口，字节计数属于最近的已核验段。
    ReplayCheckpoint checkpoint; // 已核验范围及下一段的状态。
    std::optional<CallbackReplayBatch> callback; // 完整空批次也携带已核验的首尾回执。
    std::optional<MixedEtwReplay> mixedEtw; // 存在时，raw 和 checkpoint 仅描述主流 API。
    std::uint64_t apiSourcePackets = 0; // 已核验检查点的累计来源包数，含未分类包。
};

std::wstring CallbackReplayDetails(const CallbackReplayBatch& batch);
std::wstring ReplayDiagnosticText(const SegmentEvidence& evidence);
std::wstring DescribeReplayCheckpoint(const ReplayCheckpoint& checkpoint, const SegmentEvidence& evidence);
std::wstring DescribeReplayPreview(const ReplayCheckpoint& checkpoint, const SegmentEvidence& evidence);
std::wstring DescribeMixedReplay(const ProjectReplayEvidence& evidence);

// 供现有打开入口识别固定清单文件名，不从孤立段自动推断它所属的项目。
bool IsProjectReplayManifest(const std::wstring& path);
// 在后台读取已提交目录，返回供选择的值快照。
ProjectReplayCatalog ReadProjectReplayCatalog(const std::wstring& manifestPath);
// 通过共享写入器在尚不存在的本地目录建立项目。
ProjectReplayCatalog CreateProjectReplayCatalog(const std::wstring& directory);
// 选择预览核对首段。显式回放继续核验后续已提交段。
ProjectReplayEvidence ReadProjectReplay(const ProjectReplayRequest& request,
    ProjectReplayMode mode = ProjectReplayMode::Explicit);

} // namespace Ksword::Features::ActionAnalyze
