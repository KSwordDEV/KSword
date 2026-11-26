#pragma once

#include "ProjectRawEvidence.h"
#include "../../../shared/evidence/ApiMonitorClue.h"

#include <span>

namespace Ksword::ActionAnalyze {

inline constexpr char kApiFollowPlanKind[] = "api-archive-follow-plan-v1"; // 每段首个冻结计划。
inline constexpr char kApiFollowCheckpointField[] = "checkpointRequired"; // 标识必须通过检查点的计划字段。
inline constexpr char kApiFollowPacketKind[] = "api-archive-packet-v1"; // 定长原包及源行号。
inline constexpr char kApiFollowEndKind[] = "api-archive-follow-end-v1"; // 本端结束跟随的回执。

enum class ApiFollowArchiveKind { Other, Legacy, Checkpointed };

// 判断原包是否属于合作采样的普通调用。源序号只为这些包递增。
bool IsCooperativeApiCall(const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept;

// 在原项目写租约下准入同采样首次 API 采集。已有 raw 或 checkpoints 目录即拒绝，
// 不把空目录、缺标记、损坏段或坏尾当作可覆盖空档；不检查或修改独立 native/memory 流。
ProjectResult RequireUnusedApiArchive(const ProjectDocument& project, std::string_view sampleId);

// 只保存已核验的一段。调用方从 1 开始逐段传入上次成功返回的对象，不能越过缺段。
struct ProjectApiCheckpoint {
    std::string sampleId; // 此水位属于已登记的采样。
    std::uint64_t ordinal = 0; // 同一 raw 流中的连续段号。
    ks::cli::action_analyze::archive::RawEvidenceBoundary rawEnd; // 已提交完整块的字节、块号和末序号。
    std::uint64_t rawFileBytes = 0; // 同一核验句柄观察到的文件长度，可包含未提交尾部。
    std::string rawSha256; // 实际读回的 raw 前缀摘要。
    std::uint64_t planRawSequence = 0; // 段首计划的 Stored 序号。
    std::string planJson; // 冻结计划原文，后续段必须逐字节一致。
    std::string rulePresetSet; // 采集计划声明的规则版本，旧档为空。
    std::string ruleSourceSha256; // 已核验计划声明的实际规则内容摘要，旧档或配置失败时为空。
    Evidence::ApiMonitorArchiveSource source = Evidence::ApiMonitorArchiveSource::LegacyUnspecified; // 旧跟随档沿用原来源标识。
    std::uint64_t previousSourceSequence = 0; // 本段之前最后提交的源行号。
    std::uint64_t lastSourceSequence = 0; // 原包为零时与上一段相同。
    bool finalSegment = false; // 本端跟随终段，源文件可能继续追加。
    bool mixedEtw = false; // 来自已核验计划，不代表 ETW 已启动或有数据。
    std::string stopReason; // 终段归档声明的本端结束原因。
    std::string sourceState; // 终段归档声明的源读取状态。
    bool sourceCutoffReached = false; // 已读到本端冻结的字节截止点。
    std::uint64_t partialLineBytes = 0; // 已读入但未形成完整行的字节数。
    Evidence::JsonValue startup = Evidence::JsonValue::makeNull(); // 仅终段携带的历史启动快照；旧档为null，不授予活控制权。
};

// 只从第一个标记或 raw 首块探测格式。结果只用于选择读路径，不授予已提交水位。
ProjectResult ProbeApiFollowArchive(const ProjectDocument& project, std::string_view sampleId,
    ApiFollowArchiveKind& out);

// 在项目写租约下核对成功关档的原包，逐字节比对本次写入内容，最后发布不可覆盖的标记。
// previous 仅在首段为空，后续使用本进程前一次发布结果。失败时 out 保持原值。
ProjectResult PublishApiCheckpoint(ProjectDocument& project, std::string_view sampleId, std::uint64_t ordinal,
    const ks::cli::action_analyze::archive::RawEvidenceReceipt& receipt,
    std::span<const ks::cli::action_analyze::archive::RawEvidenceInput> expected,
    const ProjectApiCheckpoint* previous, ProjectApiCheckpoint& out);

// 写入一批完整记录，刷盘后核验并发布检查点。失败时保留上次检查点和刷盘回执。
ProjectResult CommitApiCheckpoint(ProjectDocument& project, std::string_view sampleId,
    std::span<const ks::cli::action_analyze::archive::RawEvidenceInput> records,
    ProjectApiCheckpoint& checkpoint, ks::cli::action_analyze::archive::RawEvidenceReceipt& receipt);

// 只读验证一个标记及其 raw 前缀，成功后更新 out。NotFound 只代表标记缺失。
// previous 和 out 可为同一对象。投影回调的行须暂存，函数成功后才可发布。
ProjectResult ReadApiCheckpoint(const ProjectDocument& project, std::string_view sampleId, std::uint64_t ordinal,
    const ProjectApiCheckpoint* previous, ProjectApiCheckpoint& out,
    const ks::cli::action_analyze::archive::SegmentBodyVisitor& visitor = {});

// 为已核验的段投影命中原包的线索。回调内可暂存，须等 ReadApiCheckpoint 成功才发布。
std::optional<Evidence::ArchivedApiMonitorClue> ReadCommittedApiClue(
    const ks::cli::action_analyze::archive::RawRecordV1& raw);

} // namespace Ksword::ActionAnalyze
