#include "../Framework.h"
#include "PassiveApiCaptureOwner.h"
#include "OfflineSegmentReader.h"
#include "../UI/AsyncOperation.h"
#include "../../../KswordCLI/ActionAnalyze/Cli/PassiveApiCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/CooperativeApiCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/LaunchedApiCapture.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.h"

#include <QScopeGuard>
#include <algorithm>
#include <thread>

namespace ks::action_analyze
{
namespace
{
    namespace backend = ks::cli::action_analyze;
    namespace project = Ksword::ActionAnalyze;
    using Json = Ksword::Evidence::JsonValue;
    using Clock = std::chrono::steady_clock;

    // 读取后端回执中的字符串；缺项保持空，不把未知状态转成成功。
    QString Text(const Json& object, std::string_view key)
    {
        const auto* field = object.find(key); // 只借用本轮回执的字段。
        std::string value; // 由后端保证 UTF-8。
        return field && field->tryGetString(value) ? QString::fromStdString(value) : QString();
    }

    // 读取无损十进制水位。零表示这些累计字段尚无提交或无原包坐标。
    quint64 Count(const Json& object, std::string_view key)
    {
        const auto* field = object.find(key); // 字段可能是字符串或 JSON 整数。
        std::uint64_t value = 0; // 避免经 double 损失精度。
        return field && field->tryGetU64(value) ? value : 0;
    }

    // 给启动失败保留所属阶段、项目错误和原生错误码，供 GUI 诊断。
    QString StartError(backend::PassiveApiStartStage stage, const project::ProjectResult& result)
    {
        const char* name = "project"; // 打开租约失败默认归项目。
        switch (stage)
        {
        case backend::PassiveApiStartStage::Source: name = "source"; break;
        case backend::PassiveApiStartStage::Session: name = "session"; break;
        case backend::PassiveApiStartStage::Sample: name = "sample"; break;
        case backend::PassiveApiStartStage::Project: break;
        }
        return QStringLiteral("%1: %2 / %3 (%4)").arg(QString::fromLatin1(name),
            QString::fromLatin1(project::ProjectErrorName(result.error)), QString::fromLatin1(result.detail),
            QString::number(result.nativeError));
    }

    // 只在后端线程取值。已提交规则坐标与源文件读入水位分开报告。
    void ReadProgress(const backend::PassiveApiCapture& capture, PassiveApiCaptureReceipt& out)
    {
        const auto source = capture.SourceReport(); // 源端已核验前缀。
        const auto archive = capture.ArchiveReport(); // 刷盘、回读、检查点均成功的前缀。
        const auto rules = capture.RulesReport(); // 只包含已提交原包上的求值。
        out.sourceState = Text(source, "state");
        out.validatedRows = Count(source, "validatedRows");
        out.partialLineBytes = Count(source, "partialLineBytes");
        out.recordedRows = Count(archive, "recordedRows");
        out.segment = Count(archive, "segmentOrdinal");
        out.rulePresetSet = Text(rules, "presetSet");
        out.ruleSourceSha256 = Text(rules, "sourceSha256");
        out.ruleConfigError = Text(rules, "configError");
        out.ruleMatches = Count(rules, "matchedRows");
        out.ruleFailed = Text(rules, "state") == QStringLiteral("evaluation-failed");
        // 每次按同一份回执刷新坐标和释义；缺字段时清除上一条命中的值。
        out.latestRuleId.clear();
        out.ruleSegment = 0;
        out.ruleRawSequence = 0;
        out.ruleSourceSequence = 0;
        out.latestBehaviorId.clear();
        out.latestBehaviorEvidence.clear();
        out.latestBehaviorSummary.clear();
        out.latestBehaviorSummaryZh.clear();
        if (const auto* latest = rules.find("latest"))
        {
            out.latestRuleId = Text(*latest, "ruleId");
            out.ruleSegment = Count(*latest, "segmentOrdinal");
            out.ruleRawSequence = Count(*latest, "rawSequence");
            out.ruleSourceSequence = Count(*latest, "sourceSequence");
            if (const auto* behavior = latest->find("behavior")) // 与上面的已提交坐标同源。
            {
                out.latestBehaviorId = Text(*behavior, "ruleId");
                out.latestBehaviorEvidence = Text(*behavior, "evidence");
                out.latestBehaviorSummary = Text(*behavior, "summary");
                out.latestBehaviorSummaryZh = Text(*behavior, "summaryZh");
            }
        }
        if (Text(archive, "status") == QStringLiteral("failed"))
        {
            out.error = QStringLiteral("archive: %1 (%2)").arg(Text(archive, "error"),
                QString::number(Count(archive, "win32Error")));
        }
        else if (const auto code = Count(source, "win32Error"))
        {
            out.error = QStringLiteral("source: %1 (%2)").arg(out.sourceState, QString::number(code));
        }
        out.incomplete = capture.Incomplete();
    }

    // 将共享端按段累计的命中投影到现有回执，接收规则回执并更新 out。
    void ApplyCooperativeRules(const project::CooperativeApiRuleReceipt& rules, PassiveApiCaptureReceipt& out)
    {
        out.rulePresetSet = QString::fromStdString(rules.presetSet);
        out.ruleSourceSha256 = QString::fromStdString(rules.sourceSha256);
        out.ruleConfigError = QString::fromStdString(rules.configError);
        out.ruleMatches = rules.matchedRows;
        out.ruleFailed = rules.failed;
        out.ruleSegment = rules.latestSegment;
        const auto& latest = rules.latest; // 最近命中的实际原包坐标，可为空。
        out.ruleRawSequence = latest ? latest->rawSequence : 0;
        out.ruleSourceSequence = latest ? latest->sourceSequence : 0;
        out.latestRuleId = latest ? QString::fromStdString(latest->ruleId) : QString();
        // 与最近命中一同复制，不把规则库对象或短生命周期视图传给 UI。
        const auto* behavior = latest && latest->behavior ? &*latest->behavior : nullptr;
        out.latestBehaviorId = behavior ? QString::fromStdString(behavior->ruleId) : QString();
        out.latestBehaviorEvidence = behavior ? QString::fromStdString(behavior->evidence) : QString();
        out.latestBehaviorSummary = behavior ? QString::fromStdString(behavior->summary) : QString();
        out.latestBehaviorSummaryZh = behavior ? QString::fromStdString(behavior->summaryZh) : QString();
    }
}

// GUI 创建所有者时只保存冻结值。
PassiveApiCaptureOwner::PassiveApiCaptureOwner(PassiveApiCaptureRequest request) : m_request(std::move(request)) {}

// 返回可跨线程复制的值；锁内不执行 I/O。
PassiveApiCaptureReceipt PassiveApiCaptureOwner::receipt() const
{
    const std::lock_guard lock(m_receiptMutex); // 与后台发布共用同一把锁。
    return m_receipt;
}

// 发布瞬时读回，不把后端对象暴露给 GUI。
void PassiveApiCaptureOwner::publish(const PassiveApiCaptureReceipt& receipt)
{
    const std::lock_guard lock(m_receiptMutex); // 保护整份回执的一致性。
    m_receipt = receipt;
}

// 单个异步 worker 串行决定启动、正常停止及故障收尾。
PassiveApiCaptureReceipt PassiveApiCaptureOwner::collect(const ks::ui::AsyncOperationToken& token)
{
    // 只消费本次冻结的确认；缺确认、混合来源或残留确认均不回退到文件跟随。
    if ((m_request.launched && (m_request.cooperative || m_request.explicitAttachment ||
            m_request.attachmentConfirmed || m_request.executable.isEmpty() || m_request.pid || m_request.creationTime)) ||
        (!m_request.launched && (!m_request.executable.isEmpty() || m_request.entryRva.has_value())) ||
        (!(m_request.launched || m_request.cooperative || m_request.explicitAttachment) && m_request.networkTraffic.has_value()) ||
        (m_request.explicitAttachment && (!m_request.attachmentConfirmed || m_request.cooperative)) ||
        (!m_request.explicitAttachment && m_request.attachmentConfirmed) ||
        ((m_request.explicitAttachment || m_request.cooperative || m_request.launched) &&
            (!m_request.path.isEmpty() || m_request.sessionId)))
    {
        PassiveApiCaptureReceipt rejected; // 准入失败不打开项目、不发布配置、不装载 Agent。
        rejected.error = QStringLiteral("attachedApiAdmission");
        rejected.incomplete = true;
        return rejected;
    }
    if (m_request.cooperative || m_request.explicitAttachment || m_request.launched)
    {
        return token.isCanceled() || m_stop.load() ? PassiveApiCaptureReceipt{} : collectCooperative();
    }
    PassiveApiCaptureReceipt out; // 最终交回 UI 的状态和只读目录引用。
    project::ProjectDocument document; // 只在本工作线程访问的写租约。
    backend::PassiveApiCapture capture; // 本端独有文件游标及规则计数。
    const auto stopping = [&]() { return m_stop.load() || token.isCanceled(); }; // 页面退出也走同一收尾链。
    if (stopping())
    {
        return out;
    }
    // 路径和身份分别冻结；未经项目当前修订确认，不登记新采样。
    auto stage = backend::PassiveApiStartStage::Project; // 失败时保留实际阶段。
    auto result = document.Open(m_request.manifest.toStdWString(), project::ProjectAccess::ReadWrite); // 打开写租约。
    if (result && !stopping())
    {
        const auto path = m_request.path.toStdString(); // 保证 string_view 在 BeginProject 调用期间有效。
        const auto id = m_request.projectId.toStdString(); // 冻结目录 ID。
        const auto revision = m_request.revisionId.toStdString(); // 冻结配置修订。
        const auto title = std::string("API JSONL (PID ") + std::to_string(m_request.pid) + ")"; // 不保存本地化标题。
        const backend::PassiveApiStartRequest parameters{path, id, revision, title,
            {m_request.sessionId, m_request.pid, m_request.creationTime}, 0}; // 仅由本端显式停止。
        project::SampleInfo sample; // 项目实际写入的目录身份。
        std::string epoch; // 本端采集代次，不等于来源会话 ID。
        result = capture.BeginProject(document, parameters, sample, epoch, stage);
        if (result)
        {
            // 一旦登记成功，先报告该目录行，再进入可被请求停止的读取循环。
            out.sample = std::make_shared<const SampleRequest>(SampleRequest{m_request.manifest, m_request.projectId,
                {QString::fromStdString(sample.sampleId), QString::fromStdString(sample.title), sample.createdUtc,
                    QString::fromStdString(sample.revisionId), QString::fromStdString(sample.snapshotId),
                    QString::fromStdString(sample.descriptionHash)}});
            out.epoch = QString::fromStdString(epoch);
            out.fileId = Text(capture.FileIdentity(), "fileId");
            m_running.store(true);
            const auto clearRunning = qScopeGuard([&]() { m_running.store(false); }); // 异常退出亦清理运行标志。
            publish(out);
            bool canContinue = true; // 后端返回 false 即停止轮询，不复活旧会话。
            auto nextReport = Clock::now(); // 显示回执不随每轮文件读取重复构建。
            while (!stopping() && canContinue)
            {
                canContinue = capture.Tick(document, sample.sampleId);
                if (const auto now = Clock::now(); now >= nextReport)
                {
                    nextReport = now + std::chrono::milliseconds(250);
                    ReadProgress(capture, out);
                    publish(out);
                }
                if (canContinue && !stopping())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // 后端同样限速，无忙等。
                }
            }
            // 原写入方可以继续追加；Finish 仅冻结并排空本端可见前缀。
            capture.Finish(document, sample.sampleId, canContinue ? std::string_view("requested") : capture.FailureReason());
            ReadProgress(capture, out);
            document.Close();
            publish(out);
        }
    }
    if (!result)
    {
        out.error = StartError(stage, result);
    }
    return out;
}

PassiveApiCaptureReceipt PassiveApiCaptureOwner::collectCooperative()
{
    PassiveApiCaptureReceipt out; // 新结果只绑定本次登记的采样。
    project::ProjectDocument document; // 工作线程持有本端写租约。
    const auto opened = document.Open(m_request.manifest.toStdWString(), project::ProjectAccess::ReadWrite);
    const auto id = m_request.projectId.toStdString(); // 用户选择时冻结的项目 ID。
    const auto revision = m_request.revisionId.toStdString(); // 在 CreateSample 时校验该修订。
    if (!opened || document.Info()->projectId != id)
    {
        out.error = StartError(backend::PassiveApiStartStage::Project,
            opened ? project::ProjectResult{project::ProjectError::StaleRevision, 0, "cooperativeApiProject"} : opened);
        return out;
    }
    if (m_stop.load())
    {
        return out;
    }

    // 持续或有限区间均由当前原生会话负责计时、排空和收尾。
    const auto title = m_request.cooperativeTitle.toStdString(); // 本轮启动前由 UI 冻结的标题。
    const DWORD durationMs = m_request.durationMs; // 冻结时限只控制 Ready 后区间，不改变启动及清退超时。
    const auto mode = m_request.explicitAttachment ? project::ApiCaptureMode::ExplicitAttachment :
        project::ApiCaptureMode::CooperativeResident; // 明确选择准入，不用装载失败或合作标记推断模式。
    m_running.store(true);
    const auto clearRunning = qScopeGuard([&]() { m_running.store(false); });
    // 各段共享同一个冻结目录请求；无提交时由终态补上实际登记的采样。
    const auto bindSample = [&](const project::SampleInfo& sample) {
        if (!out.sample)
        {
            out.sample = std::make_shared<const SampleRequest>(SampleRequest{m_request.manifest, m_request.projectId,
                {QString::fromStdString(sample.sampleId), QString::fromStdString(sample.title), sample.createdUtc,
                    QString::fromStdString(sample.revisionId), QString::fromStdString(sample.snapshotId),
                    QString::fromStdString(sample.descriptionHash)}});
        }
    };
    out.actualPid = m_request.pid; // 已有实例保持冻结身份，新建来源由launch回调替换。
    out.actualCreationTime = m_request.creationTime;
    const project::CooperativeApiReady ready = [&](std::uint64_t session, std::uint64_t coverageRevision) {
            // 只发布同一会话的就绪证据，归档字段仍等待实际提交和回读。
            out.cooperativeSession = session;
            out.readyCoverageRevision = coverageRevision;
            out.agentReady = true;
            publish(out);
        };
    const project::CooperativeApiCommitted committed = [&](const project::SampleInfo& sample, const project::ProjectApiCheckpoint& checkpoint,
            const project::CooperativeApiRuleReceipt& rules) {
            // 通过发布水位更新活动回执；终段标记不代表采集线程已退出或资源已清退。
            bindSample(sample);
            out.segment = checkpoint.ordinal;
            out.recordedRows = checkpoint.lastSourceSequence;
            out.validatedRows = checkpoint.lastSourceSequence; // 活采中只报告已知的已核验普通包下界。
            ApplyCooperativeRules(rules, out);
            publish(out);
        };
    const project::CooperativeApiTransferCommitted transferred = [&](const project::CooperativeApiTransferReceipt& transfers) {
            // 只发布已提交前缀内的候选，原始包继续由该采样的归档入口读取。
            out.transferCandidates = transfers.candidateCount;
            out.evictedTransferWrites = transfers.evictedWrites;
            if (!transfers.recent.empty())
            {
                out.latestTransfer = transfers.recent.back();
            }
            // 复用同一次已发布回调搬运 APC 值，不增加采集、查询或轮询入口。
            out.apcTransferCandidates = transfers.apcCandidateCount;
            out.latestApcTransfer.reset();
            if (!transfers.recentApc.empty())
            {
                out.latestApcTransfer = transfers.recentApc.back();
            }
            // 原 transfers 回调同时携带上下文候选，只复制已发布值，不新增 timer/query。
            out.contextTransferCandidates = transfers.contextCandidateCount;
            out.latestContextTransfer.reset();
            if (!transfers.recentContext.empty())
            {
                out.latestContextTransfer = transfers.recentContext.back();
            }
            publish(out);
        };
    const project::CooperativeApiStartup startupProgress = [&](const ks::winapi_monitor::CaptureStartupProgress& startup) {
            // 只复制控制器已确认的事实；模块存在和装载开始都不能推进本端 Ready。
            if (out.startup == startup)
            {
                return;
            }
            out.startup = startup;
            out.attachmentIdentityVerified = startup.attachmentIdentityVerified;
            out.agentLoadAttempted = startup.agentLoadAttempted;
            out.agentModuleVerified = startup.agentModuleVerified;
            publish(out);
        };
    project::CooperativeApiReceipt run; // 两种调用共享原回调、writer与回读处理。
    if (m_request.launched)
    {
        const auto launched = project::CaptureLaunchedApi(document,
            {m_request.executable.toStdWString(), m_request.entryRva, durationMs, title, revision,
                m_request.autoTransfer, m_request.networkTraffic},
            m_stop, ready, committed, transferred, startupProgress, [&](const project::LaunchedApiProgress& progress) {
                if (progress.launch)
                {
                    out.actualPid = progress.launch->pid;
                    out.actualCreationTime = progress.launch->creationFileTime;
                }
                out.launchProgress = QString::fromStdString(Ksword::Evidence::WriteJson(project::LaunchedApiProgressJson(progress)));
                publish(out); // 只回投值，UI线程不查进程。
            });
        run = launched.api;
        if (launched.error)
        {
            out.error = QString::fromLatin1(launched.stage) + QStringLiteral(" · Win32 ") + QString::number(launched.error);
            out.incomplete = true;
        }
    }
    else
    {
        run = project::CaptureCooperativeApi(document,
            {m_request.pid, m_request.creationTime, durationMs, title, revision, false, mode, {},
                m_request.autoTransfer, m_request.networkTraffic},
            m_stop, ready, committed, transferred, startupProgress);
    }
    document.Close(); // 回读前先交还写租约。
    if (m_request.networkTraffic || run.networkTraffic)
    {
        // 同一worker已经关闭网络源；仅搬运规范全文，网络失败不被API成功或空结果覆盖。
        out.networkTraffic = QString::fromStdString(Ksword::Evidence::WriteJson(project::ApiCaptureNetworkJson(run.networkTraffic)));
    }
    const auto& capture = run.capture; // 即使采样登记失败，也保留控制器实际返回的附加事实。
    out.attachmentIdentityVerified = capture.attachmentIdentityVerified;
    out.agentLoadAttempted = capture.agentLoadAttempted;
    out.agentModuleVerified = capture.agentModuleVerified;
    if (capture.startup)
    {
        // 终态使用原控制器冻结的启动快照，不从清退期收到的包推导更晚阶段。
        out.startup = capture.startup;
    }
    if (!run.sampleStatus || !run.agentPathAvailable)
    {
        if (out.error.isEmpty())
        {
            out.error = StartError(backend::PassiveApiStartStage::Sample, !run.sampleStatus ? run.sampleStatus :
                project::ProjectResult{project::ProjectError::NotFound, 0, "cooperativeApiAgentPath"});
        }
        return out;
    }

    bindSample(run.sample);
    ApplyCooperativeRules(run.rules, out);
    // 不能用归档成功代替采集就绪或清退，各字段继续消费原控制器的独立值。
    out.agentReady = capture.started;
    out.readyCoverageRevision = capture.readyCoverageRevision.value_or(0);
    out.cleanupComplete = capture.cleanupComplete;
    if (m_request.autoTransfer)
    {
        out.transferHandoff = QString::fromStdString(Ksword::Evidence::WriteJson(run.transferHandoff)); // 回执归本轮采样，不查询当前目标。
    }
    out.validatedRows = run.ordinaryPackets;
    out.incomplete = out.incomplete || capture.code != 0 || run.archivedPackets != run.ordinaryPackets || !run.archiveStatus;
    if (!capture.errors.empty())
    {
        const auto diagnostic = QString::fromStdWString(capture.errors.front()); // 保留入口交接首错，追加管道诊断。
        out.error = out.error.isEmpty() ? diagnostic : out.error + QStringLiteral(" · ") + diagnostic;
    }
    const auto root = std::find_if(capture.processes.begin(), capture.processes.end(), [&](const auto& process) {
        return process.pid == out.actualPid && process.creation == out.actualCreationTime;
    }); // 只投影同一实际目标的回执。
    if (root != capture.processes.end())
    {
        out.cooperativeSession = root->connected ? root->session : 0;
        out.hooksRemoved = root->removed;
        out.cleanPipeEof = root->cleanPipeEof;
        out.targetExited = root->exited;
    }
    if (!run.archiveStatus)
    {
        out.error = StartError(backend::PassiveApiStartStage::Sample, run.archiveStatus);
    }
    if (run.archive.flushed && run.committedSegments)
    {
        // 独立读回同一次采样的已发布前缀，规则累计值继续使用共享回执。
        const auto replay = ReadOfflineSegment(SampleRawSegmentPath(*out.sample), [] { return false; }, out.sample.get(),
            run.committedSegments, SegmentProjection::ApiClues);
        if (replay.lastVerifiedOrdinal != run.committedSegments || replay.verifiedApiClueRows != run.retainedClues ||
            replay.prefixBytes != run.archive.flushed->byteOffset || replay.verifiedRows != run.archive.flushed->lastSequence ||
            replay.apiFollowSourceRows != run.archivedPackets ||
            replay.apiArchiveSource != Ksword::Evidence::ApiMonitorArchiveSource::CooperativePipe ||
            (run.archiveStatus && replay.end != SegmentEnd::Complete))
        {
            out.incomplete = true;
            const auto diagnostic = QStringLiteral("cooperative-api-readback-mismatch"); // 已发布水位与关闭后读回不同。
            out.error = out.error.isEmpty() ? diagnostic : out.error + QStringLiteral(" · ") + diagnostic;
        }
        if (replay.apiFollowSourceRows && replay.apiArchiveSource == Ksword::Evidence::ApiMonitorArchiveSource::CooperativePipe)
        {
            // 若后段失效，仍显示关闭后可独立确认的较短前缀。
            out.recordedRows = *replay.apiFollowSourceRows;
            out.segment = replay.lastVerifiedOrdinal;
        }
    }
    return out;
}
}
