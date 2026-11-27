#pragma once

#include "OfflineProjectReader.h"
#include "../../../KswordCLI/ActionAnalyze/Detection/ApiTransferChain.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NetworkTrafficCapture.h"
#include "../../../shared/ApiMonitorCapture.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <QVector>

namespace ks::ui
{
    class AsyncOperationToken;
}

namespace ks::action_analyze
{
    // 启动时冻结用户明确选择的文件、来源及项目，不借用控件或活动目录。
    struct PassiveApiCaptureRequest
    {
        QString path; // 已授权的本地 JSONL 绝对路径。
        QString manifest; // 当前项目的清单路径。
        QString projectId; // 当前项目 UUID。
        QString revisionId; // 打开项目时读到的配置修订。
        quint64 sessionId = 0; // JSONL 来源会话 ID。
        quint32 pid = 0; // JSONL 来源 PID。
        quint64 creationTime = 0; // JSONL 来源进程创建 FILETIME。
        bool cooperative = false; // true 时只接收目标主动加载的产品 Agent。
        QString cooperativeTitle; // UI 线程冻结的本次合作采样标题，后台不访问翻译管理器。
        bool explicitAttachment = false; // 用户明确选择普通目标附加，与合作模式互斥。
        bool attachmentConfirmed = false; // UI 在冻结 PID 与创建时间后取得的本次附加确认。
        quint32 durationMs = 0; // 两种活采均从 Ready 起计时；零为持续到停止或目标退出。
        bool autoTransfer = false; // 本轮明确选择的自动跨进程执行接管策略。
        bool launched = false; // 第四来源：创建普通EXE并在入口交接到API Agent。
        QString executable; // 独立EXE草稿，不借用JSONL路径或手填身份。
        std::optional<std::uint32_t> entryRva; // 空值使用PE入口，供共享后端调用。
        std::optional<Ksword::ActionAnalyze::NetworkTrafficBackend> networkTraffic; // 原worker同采样网络来源，空值关闭。
        bool captureAgentEtw = false; // 本轮冻结的自有Agent配套ETW策略，JSONL不得启用。
    };

    // 单条已提交行为释义的拥有型快照；工作线程填充，界面仅按当前语言选择文本。
    struct PassiveApiBehaviorMatch
    {
        quint64 segment = 0; // 命中所属的实际 raw 段。
        quint64 rawSequence = 0; // 段内原包序号，不是界面行号。
        quint64 sourceSequence = 0; // 原普通包流水号或 JSONL 来源行。
        QString ruleId; // 原分类规则 ID。
        QString behaviorId; // 原行为释义规则 ID。
        QString evidence; // 该释义的证据级别。
        QString summary; // 冻结规则库的默认释义。
        QString summaryZh; // 同一释义的可选中文文本。

        bool operator==(const PassiveApiBehaviorMatch&) const = default;
    };

    // GUI 只读快照。数据水位与归档状态来自同一轮后端回读。
    struct PassiveApiCaptureReceipt
    {
        std::shared_ptr<const SampleRequest> sample; // 实际登记的目录行，存活到 UI 读回结束。
        QString sourceState; // 文件尾部状态，不表示目标连接状态。
        QString fileId; // 已固定的卷内文件标识。
        QString epoch; // 采集所有者的会话代次。
        QString rulePresetSet; // 本次规则求值使用的规则库标识。
        QString ruleSourceSha256; // 启动时冻结的实际规则内容摘要，规则故障时为空。
        QString ruleConfigError; // 规则库加载诊断，不改变归档状态。
        QString latestRuleId; // 最近已提交原包的规则 ID。
        QString latestBehaviorId; // 同一命中的可选行为规则，为空时仅有分类。
        QString latestBehaviorEvidence; // 行为释义依赖的证据级别。
        QString latestBehaviorSummary; // 规则库中的默认释义。
        QString latestBehaviorSummaryZh; // 同一释义的可选简体中文文本。
        quint64 behaviorMatches = 0; // 同次采样中实际附带释义的累计命中数。
        QVector<PassiveApiBehaviorMatch> recentBehaviors; // 最近至多32条行为，不被普通分类挤出。
        QString error; // 后端阶段、失败细节及原生错误码。
        quint64 validatedRows = 0; // 已核验的来源行。
        quint64 recordedRows = 0; // 已提交且读回的原始包。
        quint64 partialLineBytes = 0; // 读到但仍未形成完整原包记录的末行字节。
        quint64 segment = 0; // 已核验的最后一个 raw 段。
        quint64 ruleMatches = 0; // 已提交证据中的命中行数。
        quint64 ruleSegment = 0; // 最近命中的段号。
        quint64 ruleRawSequence = 0; // 最近命中的 Stored 序号。
        quint64 ruleSourceSequence = 0; // 最近命中的原 JSONL 行号。
        bool ruleFailed = false; // 不把部分求值失败报告为无命中。
        bool incomplete = false; // 收尾后仍存在缺口。
        quint64 cooperativeSession = 0; // 通过管道身份核验后才能报告会话。
        quint64 readyCoverageRevision = 0; // 启动屏障确认的覆盖修订，零表示尚未就绪。
        bool agentReady = false; // 同一会话就绪并安装 Hook。
        bool cleanPipeEof = false; // 正常读到包边界 EOF。
        bool hooksRemoved = false; // Agent 确认停钩，与 EOF 独立。
        bool cleanupComplete = false; // 控制器已确认本轮清退。
        bool targetExited = false; // 已冻结目标确实退出。
        quint64 transferCandidates = 0; // 已发布原包中的写入到创建候选累计数。
        quint64 evictedTransferWrites = 0; // 最近写入状态窗口移出的数量。
        std::optional<Ksword::ActionAnalyze::Detection::ApiTransferLink> latestTransfer; // 同采样最近候选及双方坐标。
        quint64 apcTransferCandidates = 0; // 同一已提交前缀的独立 APC 累计候选数。
        std::optional<Ksword::ActionAnalyze::Detection::ApiApcTransferLink> latestApcTransfer; // 原回执最近 APC 候选，只用于显示。
        quint64 contextTransferCandidates = 0; // 同一已提交前缀的上下文候选独立累计数。
        std::optional<Ksword::ActionAnalyze::Detection::ApiContextTransferLink> latestContextTransfer; // 最近 write/context 候选原值。
        bool attachmentIdentityVerified = false; // 控制器已固定并核验本次普通目标实例。
        bool agentLoadAttempted = false; // 本轮是否尝试装载产品 Agent，与 Ready 独立。
        bool agentModuleVerified = false; // 已核验所选架构 Agent 模块，不代表 Hook 已就绪。
        std::optional<ks::winapi_monitor::CaptureStartupProgress> startup; // 同一次启动最后确认的阶段，终态保留失败前快照。
        QString transferHandoff; // 原后端规范JSON回执，供同一字段文档搜索/复制/导出。
        QString transferHandoffStatus; // 同一采集worker发布的活动快照；与终态回执及参数草稿分开。
        quint32 actualPid = 0; // 原worker发布的实际新建实例，不能用空手填PID替代。
        quint64 actualCreationTime = 0; // 同一创建对象的强实例身份。
        QString launchProgress; // 两端共用LaunchedApiProgressJson规范文档。
        QString networkTraffic; // 原后端ApiCaptureNetworkJson全文，不从页面草稿推断源状态。
        bool captureAgentEtw = false; // 回执所属请求的实际ETW开关，不读取后续草稿。
        QString agentEtw; // 原ETW来源全文和独立阶段回执，供同一字段文档复制与导出。

        bool operator==(const PassiveApiCaptureReceipt&) const = default;
    };

    // 单个 Qt 采样所有者；只有 collect 所在线程访问项目写租约和被动后端。
    class PassiveApiCaptureOwner final
    {
    public:
        // 由 UI 创建；冻结请求后等待 AsyncOperation 启动，不在构造时读文件。
        explicit PassiveApiCaptureOwner(PassiveApiCaptureRequest request);
        // 从单个工作线程依次启动、跟随、收尾，返回已释放项目写租约的最终回执。
        PassiveApiCaptureReceipt collect(const ks::ui::AsyncOperationToken& token);
        // 从 GUI 或销毁路径发出停止意图。只结束读端，不影响文件写入方。
        void requestStop() noexcept { m_stop.store(true); }
        // 取不可变请求；调用方在本对象存活期间借用。
        const PassiveApiCaptureRequest& request() const noexcept { return m_request; }
        // GUI 回读最新值，不调用后端或查询文件。
        PassiveApiCaptureReceipt receipt() const;
        // 后台任务中心只读实际跟随状态；项目租约未打开时不是运行中。
        bool running() const noexcept { return m_running.load(); }

    private:
        // 发布同一工作线程生成的回执，不向 GUI 传递项目或句柄。
        void publish(const PassiveApiCaptureReceipt& receipt);
        // 同一工作线程运行合作或显式附加管道；停止令牌属于本端，封段后用既有读侧核验。
        PassiveApiCaptureReceipt collectCooperative();

        const PassiveApiCaptureRequest m_request; // 启动时冻结的项目和源身份。
        std::atomic_bool m_stop{false}; // GUI 请求工作线程进入收尾。
        std::atomic_bool m_running{false}; // 成功启动后至租约释放的实际会话状态。
        mutable std::mutex m_receiptMutex; // GUI 与工作线程仅共享下方值回执。
        PassiveApiCaptureReceipt m_receipt; // 上一次发布的回读。
    };
}
