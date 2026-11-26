#pragma once

#include "ProjectRawEvidence.h"
#include "../Rules/BehaviorPresets.h"
#include "../../../shared/ApiMonitorCapture.h"

namespace Ksword::ActionAnalyze {

struct ProjectApiCheckpoint;

// 只描述已授权的合作目标和本轮采样，不接受 Agent 路径、注入或行为修改选项。
struct CooperativeApiRequest {
    DWORD pid = 0; // 与创建时间一起标识目标实例。
    std::uint64_t creationFileTime = 0; // 必须非零，后端不允许退回普通采集入口。
    DWORD durationMs = 3000; // 先等就绪，再开始计时。
    std::string_view title; // 调用期间借用的 UTF-8 采样标题。
    std::string_view revisionId; // 冻结的项目配置修订。
};

// 按段求值的累计回执。失败时保留已完成段的命中及坐标。
struct CooperativeApiRuleReceipt {
    std::string presetSet; // 本次开始时加载的规则版本。
    std::string configError; // 规则配置失败只影响派生规则结果。
    std::uint64_t matchedRows = 0; // 已求值并命中的分类线索数。
    std::uint64_t latestSegment = 0; // 最近命中所在的段号。
    std::optional<Rules::ApiPresetMatch> latest; // 最近命中的原始坐标及规则解释。
    bool failed = false; // 规则失败与存储失败独立报告。
};

struct CooperativeApiReceipt {
    bool agentPathAvailable = false; // 能否定位控制端同目录的产品 Agent 路径，不表示目标已加载。
    ProjectResult sampleStatus; // 创建采样的项目结果，失败时不启动管道控制器。
    SampleInfo sample; // 已创建采样的实际目录身份。
    ks::winapi_monitor::CaptureResult capture; // 管道、就绪、清退和丢失的独立回执。
    std::uint64_t ordinaryPackets = 0; // 通过管道核验的普通调用数。
    std::uint64_t archivedPackets = 0; // 通过回读并发布检查点的普通调用数。
    std::uint64_t committedSegments = 0; // 最后连续提交的段号，含终段。
    std::uint64_t retainedClues = 0; // 已提交原包中可重新投影的线索数。
    std::uint64_t omittedClues = 0; // 收到但未提交的线索数。
    ProjectResult archiveStatus; // 封段故障不覆盖采集回执。
    ks::cli::action_analyze::archive::RawEvidenceReceipt archive; // 最后一次已发布的刷盘边界。
    CooperativeApiRuleReceipt rules; // 仅从已发布并回读的原包求值。
};

// 在调用端自己的工作线程运行。调用方须确认授权并提供项目写租约；
// cancel 仅停止本采样。采集中分段提交原包，管道清退后尝试发布终段。
// onReady 在同一线程报告已核验的会话与覆盖修订，不表示归档成功。
using CooperativeApiReady = std::function<void(std::uint64_t session, std::uint64_t coverageRevision)>;
// onCommitted 在采集线程发布冻结身份、已核验段及累计规则回执；参数只在本次通知内借用。
using CooperativeApiCommitted = std::function<void(const SampleInfo&, const ProjectApiCheckpoint&,
    const CooperativeApiRuleReceipt&)>;
CooperativeApiReceipt CaptureCooperativeApi(ProjectDocument& document, const CooperativeApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady = {},
    const CooperativeApiCommitted& onCommitted = {});

} // namespace Ksword::ActionAnalyze
