#pragma once

#include "ProjectRawEvidence.h"
#include "ProjectDocument.h"
#include "NetworkTrafficCapture.h"
#include "ApiTransferControl.h"
#include "../Rules/BehaviorPresets.h"
#include "../Detection/ApiTransferChain.h"
#include "../../../shared/ApiMonitorCapture.h"
#include "../../../shared/usermode/backend/monitor/PassiveEtwSource.h"
#include <memory>

namespace Ksword::ActionAnalyze {

struct ProjectApiCheckpoint;
enum class ApiCaptureMode { CooperativeResident, ExplicitAttachment };

// 描述已授权的合作目标或显式附加实例；不接受 Agent 路径、注入策略或行为修改选项。
struct CooperativeApiRequest {
    DWORD pid = 0; // 与创建时间一起标识目标实例。
    std::uint64_t creationFileTime = 0; // 必须非零，后端不允许退回普通采集入口。
    DWORD durationMs = 3000; // 先等就绪再计时；0 持续到显式停止或目标退出。
    std::string_view title; // 调用期间借用的 UTF-8 采样标题。
    std::string_view revisionId; // 冻结的项目配置修订。
    bool captureAgentEtw = false; // 订阅同一目标的 KSword Agent 生命周期事件。
    ApiCaptureMode mode = ApiCaptureMode::CooperativeResident; // 默认保持合作准入；显式附加由调用端确认授权。
    std::string_view boundSampleId = {}; // 非空时借用原项目写租约与冻结采样；只允许首次写入空的 API 流。
    bool autoTransfer = false; // 采集时冻结调用前自动解析及接管私有执行目标的策略。
    std::optional<NetworkTrafficBackend> networkTraffic; // 有值时由同一writer采集根来源网络；空值不启动抓包。
    std::shared_ptr<ApiTransferControl> transferControl; // 末尾追加以兼容桌面已有聚合调用；空值保持原自动追踪。
};

// 同采样 ETW 的启动、清退及封段回执，独立于 API 管道。
struct CooperativeEtwReceipt {
    ProjectResult setup; // 构造冻结计划及持有目标句柄的结果。
    bool started = false; // ETW 控制器确认启动。
    bool stopped = false; // ETW 控制器确认清退。
    ks::r3::monitor::PassiveEtwStatus source; // 原生状态及源端和队列计数。
    ProjectResult archiveStatus; // ETW 原始段写入及回读结果。
    ProjectResult checkpointStatus; // ETW 覆盖、散列及检查点发布结果。
    ks::cli::action_analyze::archive::RawEvidenceReceipt raw; // raw-etw 最近已发布段的刷盘边界。
    std::uint64_t segmentOrdinal = 0; // ETW独立段号，不套用API段号。
    std::uint64_t archivedObservations = 0; // 检查点成功发布的累计观察数。
    Evidence::JsonValue published; // 最近已发布ETW段的同源定位文档，不读盘、不借当前列表行号。
    bool finalSegment = false; // 来源停止并排空后才封ETW终段。

    // 当配套ETW仍有未完成责任、缺失观察或来源丢失时返回真；完整封段的零观察区间不单独判失败。
    bool Incomplete() const noexcept;
};

// 已提交原包上的行为命中，段号与匹配值一起保留，不借当前段或当前UI选择补坐标。
struct CooperativeApiBehaviorMatch {
    std::uint64_t segmentOrdinal = 0; // 命中所在的真实API段。
    Rules::ApiPresetMatch match; // 原求值结果及双语行为释义，独立拥有其字符串。
};

// 按段求值的累计回执。失败时保留已完成段的命中及坐标。
struct CooperativeApiRuleReceipt {
    std::string presetSet; // 本次开始时加载的规则版本。
    std::string sourceSha256; // 与冻结规则谓词绑定的实际文件字节摘要，失败时为空。
    std::string configError; // 规则配置失败只影响派生规则结果。
    std::uint64_t matchedRows = 0; // 已求值并命中的分类线索数。
    std::uint64_t latestSegment = 0; // 最近命中所在的段号。
    std::optional<Rules::ApiPresetMatch> latest; // 最近命中的原始坐标及规则解释。
    std::uint64_t behaviorMatches = 0; // 实际具有行为释义的累计命中数，与普通分类命中数分开。
    std::vector<CooperativeApiBehaviorMatch> recentBehaviors; // 最近至多32条行为命中，普通分类不挤掉行为释义。
    bool failed = false; // 规则失败与存储失败独立报告。
};

// 候选只由已发布检查点内的原包产生；滚动窗口不改变累计计数和旧写入淘汰数。
struct CooperativeApiTransferReceipt {
    std::uint64_t candidateCount = 0; // 同一采样中写入到创建请求的候选累计数。
    std::uint64_t evictedWrites = 0; // 先前写入因链路容量被移出的数量。
    std::vector<Detection::ApiTransferLink> recent; // 最近至多 32 条，保留两端的真实归档坐标。
    std::uint64_t apcCandidateCount = 0; // 写入到APC例程请求的独立累计候选数。
    std::vector<Detection::ApiApcTransferLink> recentApc; // 最近至多32条APC候选，不挤占创建候选窗口。
    std::uint64_t contextCandidateCount = 0; // 写入到请求IP的累计上下文候选数。
    std::vector<Detection::ApiContextTransferLink> recentContext; // 最近32条上下文候选，与APC独立。
    Evidence::JsonValue handoff; // 同一writer发布的接管状态快照，和已归档API候选分开，不表示采集终态。
    std::optional<SampleInfo> handoffSample; // 接管或配套来源活动快照的真实采样身份，不借用UI草稿。
    Evidence::JsonValue networkTraffic; // 原网络会话已发布水位及来源状态；未请求为null，不等API终段才显示。
    Evidence::JsonValue agentEtw; // 原ETW游标已发布水位及独立丢失/清退状态；未请求为null。
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
    CooperativeApiTransferReceipt transfers; // 同一已提交前缀中的跨段 API 转移候选。
    std::optional<CooperativeEtwReceipt> etw; // 请求配套 ETW 时提供独立回执。
    Evidence::JsonValue transferHandoff; // 本轮原生交接与归档回执；未请求时为null。
    std::optional<NetworkTrafficCaptureReceipt> networkTraffic; // 原sample的网络源、字节及清退事实。
};

// 在调用端自己的工作线程运行。调用方须确认授权并提供项目写租约；
// cancel 仅停止本采样。采集中分段提交原包，管道清退后尝试发布终段。
// onReady 在同一线程报告已核验的会话与覆盖修订，不表示归档成功。
using CooperativeApiReady = std::function<void(std::uint64_t session, std::uint64_t coverageRevision)>;
// onCommitted 在采集线程发布冻结身份、已核验段及累计规则回执；参数只在本次通知内借用。
using CooperativeApiCommitted = std::function<void(const SampleInfo&, const ProjectApiCheckpoint&,
    const CooperativeApiRuleReceipt&)>;
// 与规则通知独立；候选来自已提交原包，接管/网络/ETW为原writer快照，参数仅在通知期间借用。
using CooperativeApiTransferCommitted = std::function<void(const CooperativeApiTransferReceipt&)>;
// 启动中同步通知原控制器里程碑；不等于原包已归档，参数仅在回调期间借用。
using CooperativeApiStartup = std::function<void(const ks::winapi_monitor::CaptureStartupProgress&)>;
// 输入可缺省的最后启动事实，输出统一JSON投影；空值返回null，不查询当前进程或补造阶段。
Evidence::JsonValue ApiCaptureStartupJson(const std::optional<ks::winapi_monitor::CaptureStartupProgress>& startup);
// 输入同采样网络终态，输出三端共用JSON；未启用时返回null，不重新查询现场。
Evidence::JsonValue ApiCaptureNetworkJson(const std::optional<NetworkTrafficCaptureReceipt>& network);
// 三端与API终段共用同一ETW结果文档；缺回执返回null，阶段失败不被API成功覆盖。
Evidence::JsonValue ApiCaptureEtwJson(const std::optional<CooperativeEtwReceipt>& receipt);
CooperativeApiReceipt CaptureCooperativeApi(ProjectDocument& document, const CooperativeApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady = {},
    const CooperativeApiCommitted& onCommitted = {}, const CooperativeApiTransferCommitted& onTransfers = {},
    const CooperativeApiStartup& onStartup = {});

} // namespace Ksword::ActionAnalyze
