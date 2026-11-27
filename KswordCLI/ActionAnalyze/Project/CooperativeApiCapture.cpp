#include "CooperativeApiCapture.h"
#include "ProjectApiCheckpoint.h"
#include "ProjectEtwEvidence.h"
#include "ProjectEtwStream.h"
#include "ProjectStorage.h"
#include "ApiTransferHandoff.h"
#include "NetworkTrafficRead.h"
#include "../../../shared/ApiMonitorPlatform.h"
#include "../../../shared/evidence/ActionAnalyzeEtwProvider.h"

namespace Ksword::ActionAnalyze {
namespace {

namespace Monitor = ks::winapi_monitor;
namespace Etw = ks::r3::monitor;
namespace AgentEtw = ks::action_analyze::etw;
namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
constexpr std::size_t kApiBatchPackets = 256; // 与 API 检查点的最大原包数一致。
constexpr ULONGLONG kApiBatchMs = 1000; // 低频活动的待提交窗口。

// 由本端正式程序的映像路径派生，不接收外部提供的 DLL 路径。
std::wstring ResidentAgentPath()
{
    std::wstring path(32768, L'\0'); // Win32 映像绝对路径缓冲。
    const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())); // 实际字符数。
    if (!length || length >= path.size()) {
        return {};
    }
    path.resize(length);
    return Monitor::platformDirectory(path) + L"\\APIMonitor_x64.dll";
}

// 按实际项目、采样修订和管道会话生成每段共享的冻结计划。
std::string ApiPlan(const ProjectInfo& project, const SampleRecord& sample, const CooperativeApiRequest& target,
    std::string_view epoch, std::uint64_t session, const Rules::ApiPresetDatabase& database)
{
    JsonObject fields{{"kind", Text(kApiFollowPlanKind)}, {kApiFollowCheckpointField, JsonValue::makeBool(true)},
        {"archiveSource", Text("cooperative-pipe")}, {"projectId", Text(project.projectId)},
        {"session", Object({{"id", Text(sample.info.sampleId)}, {"epoch", Text(epoch)}})},
        {"sourceEpoch", Text(epoch)}, {"revisionId", Text(sample.info.revisionId)},
        {"snapshotId", Text(sample.info.snapshotId)}, {"revisionHash", Text(sample.revisionHash)},
        {"configSemanticHash", Text(sample.configSemanticHash)}, {"durationMs", JsonValue::makeUInt(target.durationMs)},
        {"readerPid", JsonValue::makeUInt(target.pid)}, {"readerCreation100ns", Number(target.creationFileTime)},
        {"sessionIdentity", Number(session)}};
    if (target.mode == ApiCaptureMode::ExplicitAttachment) {
        fields.emplace_back("captureMode", Text("explicit-r3-attachment"));
    }
    if (target.autoTransfer)
    {
        // 计划冻结多来源能力，原包身份仍逐条来自各自核验过的Agent管道。
        fields.emplace_back("multiProcessApi", JsonValue::makeBool(true));
    }
    if (!database.presetSet.empty()) {
        fields.emplace_back("rulePresetSet", Text(database.presetSet)); // 同一次采样的每段使用同一版本。
        fields.emplace_back("ruleSourceSha256", Text(database.sourceSha256)); // 与实际解析字节对应。
    }
    if (target.captureAgentEtw) {
        fields.emplace_back("mixedEtw", JsonValue::makeBool(true));
    }
    return Evidence::WriteJson(Object(std::move(fields)));
}

// 将本批普通包按连续源序号写入。空包批次只用于真实管道的终段。
ProjectResult CommitApiPackets(ProjectDocument& document, const SampleInfo& sample, std::string_view plan,
    std::span<const Monitor::ApiMonitorEventPacket> packets, std::span<const std::uint64_t> creations,
    bool multiProcess, std::string_view end,
    ProjectApiCheckpoint& checkpoint, Archive::RawEvidenceReceipt& receipt)
{
    if (packets.size() != creations.size())
    {
        return Failure(ProjectError::InvalidArgument, "apiPacketIdentityCount");
    }
    std::vector<std::string> metadata; // 原包的元数据由本次调用持有至读回完成。
    metadata.reserve(packets.size());
    std::vector<Archive::RawEvidenceInput> records; // 借用计划、元数据和未改写的原包字节。
    records.reserve(packets.size() + 2);
    records.push_back({plan, {}});
    auto sequence = checkpoint.lastSourceSequence; // 源序与封装序列使用各自坐标。
    for (std::size_t index = 0; index < packets.size(); ++index) {
        const auto& packet = packets[index]; // 同一位置的原包与核验过的来源创建时间共同冻结。
        JsonObject identity{{"kind", Text(kApiFollowPacketKind)},
            {"sourceSequence", Number(++sequence)}, {"readerCreation100ns", Number(creations[index])}};
        if (multiProcess)
        {
            identity.emplace_back("readerPid", JsonValue::makeUInt(packet.pid));
            identity.emplace_back("sessionIdentity", Number(packet.sessionIdentity));
        }
        metadata.push_back(Evidence::WriteJson(Object(std::move(identity))));
        records.push_back({metadata.back(), {reinterpret_cast<const char*>(&packet), sizeof(packet)}});
    }
    if (!end.empty()) {
        records.push_back({end, {}});
    }
    return CommitApiCheckpoint(document, sample.sampleId, records, checkpoint, receipt);
}

// 用本次冻结的项目采样和 ETW 来源创建兼容的 Stored 计划。
JsonValue AgentEtwPlan(const SampleRecord& sample, const CooperativeApiRequest& target, std::string_view epoch,
    const Etw::PassiveEtwStatus& status, const Etw::PassiveEtwOptions& options)
{
    JsonArray filters; // 来源实际生效的报头PID筛选，不把根创建时间套到子来源事件上。
    for (const auto pid : status.headerPidFilters)
    {
        filters.push_back(JsonValue::makeUInt(pid));
    }
    return Object({{"kind", Text("etw-capture-plan-v1")}, {"backend", Text("r3")},
        {"session", Object({{"id", Text(sample.info.sampleId)}, {"epoch", Text(epoch)}})},
        {"sourceEpoch", Text(status.sourceEpoch)}, {"revisionId", Text(sample.info.revisionId)},
        {"snapshotId", Text(sample.info.snapshotId)}, {"revisionHash", Text(sample.revisionHash)},
        {"configSemanticHash", Text(sample.configSemanticHash)}, {"providerId", Text(AgentEtw::kProviderId)},
        {"headerPid", JsonValue::makeUInt(target.pid)}, {"processCreationFileTime", Number(target.creationFileTime)},
        {"headerPidFilters", JsonValue::makeArray(std::move(filters))},
        {"targetScope", Text("registered-process-header-hints")},
        {"segmented", JsonValue::makeBool(true)},
        {"durationMs", JsonValue::makeUInt(target.durationMs)}, {"headerRole", Text("record-context")},
        {"sourceClock", Text("filetime-100ns")}, {"receiveClock", Text("local-qpc")},
        {"maxRecords", JsonValue::makeUInt(static_cast<std::uint32_t>(options.maxQueuedRecords))},
        {"maxPayloadBytes", JsonValue::makeUInt(static_cast<std::uint32_t>(options.maxPayloadBytes))},
        {"mixedEtw", JsonValue::makeBool(true)}});
}

} // namespace

bool CooperativeEtwReceipt::Incomplete() const noexcept
{
    const auto& native = source.native; // 队列和原生丢失分别判为缺口。
    return !setup || !started || !stopped || !archiveStatus || !checkpointStatus || !raw.flushed ||
        source.state != Etw::PassiveEtwState::Stopped || !source.enqueued || !native.statisticsKnown ||
        !native.processCompleted || native.processStatus != ERROR_SUCCESS || native.tailDeliveryUnconfirmed ||
        native.callbackFailed || native.eventsLost || native.logBuffersLost || native.realTimeBuffersLost ||
        source.queueDropped || source.payloadTruncated || source.malformedPayload ||
        !finalSegment || archivedObservations != source.enqueued;
}

// 输入本轮独立ETW终态；输出完整阶段和原生来源，历史回放不查询当前PID或新会话。
Evidence::JsonValue ApiCaptureEtwJson(const std::optional<CooperativeEtwReceipt>& receipt)
{
    if (!receipt)
    {
        return JsonValue::makeNull();
    }
    const auto result = [](const ProjectResult& status) { // 每个阶段保留自己的失败码和错误位置。
        return Object({{"ok", JsonValue::makeBool(static_cast<bool>(status))},
            {"error", Text(ProjectErrorName(status.error))}, {"detail", Text(status.detail)},
            {"nativeError", JsonValue::makeUInt(status.nativeError)}});
    };
    const auto& etw = *receipt; // 只借用同一次采集已清退的来源和已发布检查点。
    return Object({{"receiptAvailable", JsonValue::makeBool(true)}, {"source", EtwSourceReceipt(etw.source)},
        {"setup", result(etw.setup)}, {"started", JsonValue::makeBool(etw.started)},
        {"stopped", JsonValue::makeBool(etw.stopped)}, {"archive", result(etw.archiveStatus)},
        {"checkpoint", result(etw.checkpointStatus)}, {"flushed", JsonValue::makeBool(etw.raw.flushed.has_value())},
        {"segmentOrdinal", Number(etw.segmentOrdinal)}, {"archivedObservations", Number(etw.archivedObservations)},
        {"finalSegment", JsonValue::makeBool(etw.finalSegment)},
        {"incomplete", JsonValue::makeBool(etw.Incomplete())}});
}

Evidence::JsonValue ApiCaptureStartupJson(const std::optional<ks::winapi_monitor::CaptureStartupProgress>& startup)
{
    if (!startup)
    {
        return JsonValue::makeNull(); // 准入之前失败，没有到达任何实例核验阶段。
    }
    const auto& progress = *startup; // 只投影同一控制器冻结的启动值。
    return Object({
        {"stage", Text(Monitor::CaptureStartupStageName(progress.stage))},
        {"pid", JsonValue::makeUInt(progress.pid)},
        {"creationFileTime", Number(progress.creationFileTime)},
        {"elapsedMs", Number(progress.elapsedMs)},
        {"sessionIdentity", progress.session ? Number(progress.session) : JsonValue::makeNull()},
        {"coverageRevision", progress.coverageRevision ? Number(progress.coverageRevision) : JsonValue::makeNull()},
        {"attachmentIdentityVerified", JsonValue::makeBool(progress.attachmentIdentityVerified)},
        {"agentLoadAttempted", JsonValue::makeBool(progress.agentLoadAttempted)},
        {"agentModuleVerified", JsonValue::makeBool(progress.agentModuleVerified)},
        {"reusedResident", JsonValue::makeBool(progress.reusedResident)},
        {"configPublished", JsonValue::makeBool(progress.configPublished)}
    });
}

// 网络与API共用原sample，回执保留弱PID线索边界及独立来源/归档/清退结果。
Evidence::JsonValue ApiCaptureNetworkJson(const std::optional<NetworkTrafficCaptureReceipt>& network)
{
    if (!network)
    {
        return JsonValue::makeNull();
    }
    const auto& receipt = *network; // 原worker当前已发布的网络结果，cleanupConfirmed仅在真实清退后成立。
    JsonArray diagnostics; // 完整源诊断，不查询当前抓包服务补值。
    for (const auto& diagnostic : receipt.diagnostics)
    {
        diagnostics.push_back(Text(diagnostic));
    }
    JsonArray targets; // 原归档同步保存的强实例采集窗口，不给逐包PID线索补造创建身份。
    for (const auto& window : receipt.targets)
    {
        targets.push_back(Object({{"pid", JsonValue::makeUInt(window.pid)},
            {"creationFileTime", Number(window.creationFileTime)}, {"startUtc", Number(window.startUtc)},
            {"endUtc", window.endUtc ? Number(window.endUtc) : JsonValue::makeNull()},
            {"root", JsonValue::makeBool(window.root)}, {"endReason", Text(window.endReason)}}));
    }
    return Object({
        {"status", Text(ProjectErrorName(receipt.status.error))},
        {"detail", Text(receipt.status.detail)},
        {"win32Error", JsonValue::makeUInt(receipt.status.nativeError)},
        {"reason", Text(receipt.reason)},
        {"sourceReady", JsonValue::makeBool(receipt.sourceReady)},
        {"cleanupConfirmed", JsonValue::makeBool(receipt.cleanupConfirmed)},
        {"packets", Number(receipt.packets)},
        {"capturedBytes", Number(receipt.capturedBytes)},
        {"queueDropped", Number(receipt.queueDropped)},
        {"sourceGap", Number(receipt.sourceGap)},
        {"unsupportedPackets", Number(receipt.unsupportedPackets)},
        {"segmentOrdinal", Number(receipt.checkpoint.ordinal)},
        {"targetScope", Text(receipt.targets.size() > 1 ? "registered-process-pid-hints" : "root-process-pid-hints")},
        {"targets", JsonValue::makeArray(std::move(targets))},
        {"eventTimeProcessIdentity", JsonValue::makeNull()},
        {"coverage", Text("unknown")},
        {"diagnostics", JsonValue::makeArray(std::move(diagnostics))}
    });
}

CooperativeApiReceipt CaptureCooperativeApi(ProjectDocument& document, const CooperativeApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady, const CooperativeApiCommitted& onCommitted,
    const CooperativeApiTransferCommitted& onTransfers, const CooperativeApiStartup& onStartup)
{
    CooperativeApiReceipt out; // 工作线程独占，封段后交给本端投影。
    if (target.pid <= 4 || target.pid == GetCurrentProcessId() || !target.creationFileTime ||
        (target.boundSampleId.empty() && target.title.empty()) ||
        (!target.boundSampleId.empty() && target.captureAgentEtw) ||
        (target.durationMs != 0 && (target.durationMs < 1000 || target.durationMs > 120000))) {
        out.sampleStatus = {ProjectError::InvalidArgument, ERROR_INVALID_PARAMETER, "cooperativeApiTarget"};
        return out;
    }

    Monitor::CaptureRequest request; // 显式附加仅用原 R3 装载器，不配置 R0、子进程或行为改写。
    request.agentPath = ResidentAgentPath();
    out.agentPathAvailable = !request.agentPath.empty();
    if (!out.agentPathAvailable) {
        return out;
    }
    request.pid = target.pid;
    if (target.mode == ApiCaptureMode::ExplicitAttachment) {
        request.attachCreationFileTime = target.creationFileTime;
        request.attachConfirmed = true; // 仅显式附加封装完成授权准入后选择此模式。
        request.strictReadOnlyObservation = true;
    } else {
        request.residentCreationFileTime = target.creationFileTime;
    }
    request.durationMs = target.durationMs;
    request.eventLimit = 0; // 由项目端分段归档，不重复缓存旧展示数据。
    ApiTransferHandoff* activeHandoff = nullptr; // 仅借用稍后创建的服务，Ready回调不拥有其生命周期。
    std::uint64_t rootSession = 0; // 根Agent真实会话，子来源先有普通包时仍由它生成稳定段首计划。
    std::optional<ULONGLONG> readyAt; // 整条转移链沿根来源真实Ready计时，根退出不重新计时。
    request.onResidentReady = [&](std::uint64_t session, std::uint64_t revision)
    {
        rootSession = session;
        readyAt = GetTickCount64();
        if (activeHandoff)
        {
            activeHandoff->OriginalSourceReady(session, revision);
        }
        if (onReady)
        {
            onReady(session, revision);
        }
    };
    request.onStartupProgress = [&](const Monitor::CaptureStartupProgress& progress)
    {
        // 管道核验后即可冻结根会话；Hook安装期间出现首个转移也能绑定同一计划。
        if (progress.session)
        {
            rootSession = progress.session;
        }
        if (onStartup)
        {
            onStartup(progress);
        }
    };

    const auto database = Rules::LoadApiPresetDatabase(); // 采集途中编辑文件不会更换规则。
    out.rules.presetSet = database.presetSet;
    out.rules.sourceSha256 = database.sourceSha256;
    out.rules.configError = database.error;
    out.rules.failed = !database.error.empty();

    SampleRecord apiSample; // 读回项目层为本采样冻结的配置身份。
    if (target.boundSampleId.empty()) {
        // 旧入口仍在本端项目写租约下创建独立采样，不改变桌面与既有 CLI 的默认行为。
        out.sampleStatus = document.CreateSample(target.title, out.sample, target.revisionId);
        if (out.sampleStatus) out.sampleStatus = document.ReadSample(out.sample.sampleId, apiSample);
    } else {
        // 原生停点会话借用同一项目对象，不申请第二写者、不创建新 sample 或迁移控制身份。
        out.sampleStatus = document.ReadSample(target.boundSampleId, apiSample);
        if (out.sampleStatus) {
            out.sample = apiSample.info;
            if (!target.revisionId.empty() && target.revisionId != apiSample.info.revisionId) {
                out.sampleStatus = Failure(ProjectError::InvalidArgument, "apiCaptureBoundRevisionMismatch");
            } else {
                out.sampleStatus = RequireUnusedApiArchive(document, target.boundSampleId);
            }
        }
    }
    std::string apiEpoch; // 归档计划中的样本代次，独立于管道会话数字。
    if (out.sampleStatus) {
        out.sampleStatus = NewId(apiEpoch);
    }
    if (!out.sampleStatus) {
        return out;
    }

    // 配套来源在合作准入通过后启动，目标句柄跨过管道控制器退出保留到 ETW 停止。
    Handle etwTarget; // 本次冻结的进程对象引用。
    std::optional<Etw::PassiveEtwSource> etwSource; // 仅在调用方请求配套 ETW 时创建。
    SampleRecord etwSample; // ETW 计划所需的冻结项目散列。
    std::string etwEpoch; // 本次 ETW 归档的会话代次。
    Etw::PassiveEtwOptions etwOptions; // 仅订阅自有Provider，调用前同步追加已准入目标的报头PID。
    ProjectEtwStream etwStream; // 沿原writer累计已发布ETW段，不取得第二租约。
    auto etwNextFlush = GetTickCount64() + 1000; // 静默时每秒检查一次待写队列。
    if (target.captureAgentEtw) {
        auto& etw = out.etw.emplace(); // 配套流程的独立阶段回执。
        etw.setup = document.ReadSample(out.sample.sampleId, etwSample);
        if (etw.setup) {
            etw.setup = NewId(etwEpoch);
        }
        if (etw.setup) {
            etwOptions.provider = AgentEtw::kProviderGuid;
            etwOptions.headerPid = target.pid;
            etwOptions.maxPayloadBytes = 0; // 自有生命周期描述符只使用标准头。
            etwSource.emplace();
            request.beforeResidentPublish = [&](HANDLE verifiedTarget) {
                HANDLE pinned = nullptr; // 复制合作控制器已核验的对象句柄。
                const auto current = GetCurrentProcess(); // 本地复制的源和目标句柄表。
                if (!DuplicateHandle(current, verifiedTarget, current, &pinned, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    etw.setup = WinFailure("pinCooperativeEtwTarget", GetLastError());
                    return;
                }
                etwTarget = Handle(pinned);
                etw.started = etwSource->start(etwOptions);
            };
        }
    }

    ProjectApiCheckpoint checkpoint; // 仅在刷盘、逐字节回读并发布标记后推进。
    Detection::ApiTransferChain transferChain({document.Info()->projectId, out.sample.sampleId, {}, {}});
    std::string plan; // 由首个核验原包绑定实际管道会话。
    std::vector<Monitor::ApiMonitorEventPacket> pending; // 单批内存上限，包含分类和未分类原包。
    pending.reserve(kApiBatchPackets);
    std::vector<std::uint64_t> pendingCreations; // 与pending同索引，保持各实际来源的强实例身份。
    pendingCreations.reserve(kApiBatchPackets);
    std::uint64_t receivedClues = 0; // 根据验证过的普通包计算待归档与已提交的差额。
    std::uint64_t pendingClues = 0; // 本批可从原包重新投影的线索数。
    auto batchStarted = GetTickCount64(); // 当前批次开始缓冲的时间。
    bool notifyCommitted = static_cast<bool>(onCommitted); // 终态回执独立于实时通知。
    bool notifyTransfers = static_cast<bool>(onTransfers); // 消费端显示故障不停止原始采集清退。
    const auto commit = [&](std::string_view end) {
        out.archiveStatus = CommitApiPackets(document, out.sample, plan, pending, pendingCreations,
            target.autoTransfer, end, checkpoint, out.archive);
        if (out.archiveStatus) {
            out.archivedPackets = checkpoint.lastSourceSequence;
            out.committedSegments = checkpoint.ordinal;
            out.retainedClues += pendingClues;
            // CommitApiCheckpoint 已逐字节验证同一批原包及元数据；这里只处理已经发布的精确坐标。
            for (std::size_t index = 0; index < pending.size(); ++index) {
                const auto& packet = pending[index]; // 同批次成功提交的普通包，没有接收时间推测。
                Detection::EvidenceRef evidence;
                evidence.projectId = document.Info()->projectId;
                evidence.sampleId = out.sample.sampleId;
                evidence.sourceId = "api-monitor-follow:" + std::to_string(packet.sessionIdentity);
                evidence.sourceEpoch = apiEpoch;
                evidence.raw = Detection::RawLocator{checkpoint.ordinal, checkpoint.planRawSequence + 1 + index};
                evidence.sourceSequence = checkpoint.previousSourceSequence + 1 + index;
                evidence.sourceGroup = "api-monitor";
                const auto links = transferChain.Accept(evidence, packet); // 跨段状态由本次采样独占。
                out.transfers.candidateCount += links.size();
                for (const auto& link : links) {
                    if (out.transfers.recent.size() == 32) {
                        out.transfers.recent.erase(out.transfers.recent.begin());
                    }
                    out.transfers.recent.push_back(link);
                }
                const auto apcLinks = transferChain.AcceptApc(evidence, packet); // 只消费已提交前缀，与线程创建共用写入状态。
                out.transfers.apcCandidateCount += apcLinks.size();
                for (const auto& link : apcLinks) {
                    if (out.transfers.recentApc.size() == 32) {
                        out.transfers.recentApc.erase(out.transfers.recentApc.begin());
                    }
                    out.transfers.recentApc.push_back(link);
                }
                const auto contextLinks = transferChain.AcceptContext(evidence, packet); // 复用同一1024条实际写入窗口。
                out.transfers.contextCandidateCount += contextLinks.size();
                for (const auto& link : contextLinks) {
                    if (out.transfers.recentContext.size() == 32) {
                        out.transfers.recentContext.erase(out.transfers.recentContext.begin());
                    }
                    out.transfers.recentContext.push_back(link);
                }
            }
            out.transfers.evictedWrites = transferChain.EvictedWrites();
            if (notifyTransfers) {
                try {
                    onTransfers(out.transfers);
                } catch (...) {
                    notifyTransfers = false; // 与原有规则通知一样，保留终态供调用方回查。
                }
            }
            if (!out.rules.failed && !pending.empty()) {
                auto evaluated = Rules::AnalyzeCommittedApiPresetBatch(database, pending, checkpoint.planRawSequence,
                    checkpoint.previousSourceSequence); // 使用逐字节读回确认的同一批原包。
                out.rules.failed = evaluated.error != Rules::ApiPresetError::None;
                if (!evaluated.matches.empty()) {
                    out.rules.matchedRows += evaluated.matches.size();
                    out.rules.latestSegment = checkpoint.ordinal;
                    out.rules.latest = std::move(evaluated.matches.back());
                }
            }
            if (notifyCommitted) {
                try {
                    onCommitted(out.sample, checkpoint, out.rules);
                } catch (...) {
                    // 消费端通知失败不能中断已提交的采样或管道清退；终态仍可回查。
                    notifyCommitted = false;
                }
            }
        }
        // 写入失败后保留已发布前缀，继续读取和清退管道，避免重复发布失败段。
        pending.clear();
        pendingCreations.clear();
        pendingClues = 0;
    };
    // 根管道与自动接管管道在原worker串行进入同一批次，不在Agent线程访问项目。
    const auto acceptPacket = [&](const Monitor::ApiMonitorEventPacket& packet, std::uint64_t creation) {
        if (!IsCooperativeApiCall(packet)) {
            return;
        }
        ++out.ordinaryPackets;
        const bool clue = Evidence::ClassifyApiMonitorClue(packet) != nullptr; // 原包仍按原字节存储。
        receivedClues += clue;
        if (!out.archiveStatus) {
            return;
        }
        if (plan.empty()) {
            const auto session = rootSession ? rootSession : packet.pid == target.pid ? packet.sessionIdentity : 0;
            if (!session)
            {
                out.archiveStatus = Failure(ProjectError::InvalidArgument, "apiRootSessionUnavailable");
                return;
            }
            plan = ApiPlan(*document.Info(), apiSample, target, apiEpoch, session, database);
        }
        if (pending.empty()) {
            batchStarted = GetTickCount64();
        }
        pending.push_back(packet);
        pendingCreations.push_back(creation);
        pendingClues += clue;
        if (pending.size() == kApiBatchPackets) {
            commit({});
        }
    };
    request.onVerifiedPacket = [&](const Monitor::ApiMonitorEventPacket& packet)
    {
        // 根管道也在归档前核对实际包身份；不能让一个非根PID或空会话包借用根创建时间进入同一流。
        if (packet.pid != target.pid || !packet.sessionIdentity || (rootSession &&
            packet.sessionIdentity != rootSession))
        {
            out.archiveStatus = Failure(ProjectError::InvalidArgument, "apiRootPacketIdentity");
            return;
        }
        acceptPacket(packet, target.creationFileTime);
    };

    // network先构造，保证handoff清退及其登记回调结束后才销毁原网络会话。
    std::optional<NetworkTrafficSession> network; // 同一writer、单一来源覆盖根及明确接管的目标。
    std::uint64_t networkTargetFailures = 0; // 追加失败独立使网络结果不完整，不阻止原生目标清退。
    if (target.networkTraffic)
    {
        NetworkTrafficCapturePlan networkPlan; // 时长及整链退出由原API所有者控制。
        networkPlan.sampleId = out.sample.sampleId;
        networkPlan.bootId = ReadNetworkTrafficBootId();
        networkPlan.pid = target.pid;
        networkPlan.creationFileTime = target.creationFileTime;
        networkPlan.durationMs = 0;
        networkPlan.backend = *target.networkTraffic;
        networkPlan.keepAliveForAppendedTargets = target.autoTransfer;
        network.emplace(document, std::move(networkPlan), cancel);
        const auto beforePublish = request.beforeResidentPublish;
        request.beforeResidentPublish = [&, beforePublish](HANDLE verifiedTarget)
        {
            if (beforePublish) beforePublish(verifiedTarget);
            // 挂起启动主线程尚未放行；网络先于Agent Ready及根业务执行启动。
            network->Start();
        };
    }
    // 服务须晚于其回调借用的批次容器构造，异常析构也先排空来源再销毁归档缓冲。
    std::optional<ApiTransferHandoff> handoff; // 唯一writer线程的自动接管所有者。
    if (target.autoTransfer)
    {
        handoff.emplace(document, out.sample.sampleId, target.pid, target.creationFileTime, cancel,
            request.agentPath, [&](DWORD pid, std::uint64_t creation, const Monitor::ApiMonitorEventPacket& packet)
            {
                // 回调只由handoff原worker排队交付；后台Agent采集线程不访问项目写者。
                if (pid != packet.pid || !creation)
                {
                    out.archiveStatus = Failure(ProjectError::InvalidArgument, "apiTransferPacketIdentity");
                    return;
                }
                acceptPacket(packet, creation);
            }, [&](DWORD pid, std::uint64_t creation)
            {
                // 在调用前交接期间登记，不能等目标首包到达后才开始保留网络流量。
                // 采集失败由networkTraffic独立回执报告，不撤销已承担恢复责任的原生owner。
                if (network && !network->AppendTarget(pid, creation))
                {
                    ++networkTargetFailures;
                }
                if (etwSource && !etwSource->appendHeaderPid(pid) && out.etw->setup)
                {
                    // 保留已归档来源及原生接管；追加失败只进入ETW独立的部分结果。
                    out.etw->setup = Failure(ProjectError::InvalidArgument, "appendCooperativeEtwTarget");
                }
            });
        activeHandoff = &*handoff;
        if (!target.boundSampleId.empty() || !handoff->Start())
        {
            // 已有原生会话有自己的owner和执行流，不能在这里另起竞争者。
            out.sampleStatus = {ProjectError::InvalidArgument, ERROR_NOT_SUPPORTED, "autoTransferAdmission"};
            out.transferHandoff = handoff->Describe();
            return out;
        }
        request.transferHandoff = handoff->Endpoint();
    }
    // 同一API worker写ETW，终段也沿同一游标排空；故障后保留首错，不重试坏段。
    const auto flushEtw = [&](bool final, std::string_view reason)
    {
        if (!etwSource || !out.etw->started)
        {
            return;
        }
        auto& etw = *out.etw; // 每端及终段共用的独立ETW结果。
        const auto status = etwSource->status(); // 排空前冻结本段实际PID筛选。
        const auto now = GetTickCount64(); // 与API根Ready时钟分开，仅决定封段频率。
        if (!final && status.queued < 256 && now < etwNextFlush)
        {
            return;
        }
        etwNextFlush = now + 1000;
        etwStream.Flush(document, out.sample.sampleId, ProjectEvidenceLane::MixedEtw,
            AgentEtwPlan(etwSample, target, etwEpoch, status, etwOptions), reason, *etwSource, final);
        etw.archiveStatus = etwStream.archiveStatus;
        etw.checkpointStatus = etwStream.checkpointStatus;
        etw.raw = etwStream.raw;
        etw.segmentOrdinal = etwStream.ordinal;
        etw.archivedObservations = etwStream.observations;
        etw.finalSegment = etwStream.finalized;
        etw.source = etwSource->status();
    };
    // 接管及配套来源共用原writer回调；静默API期间也能看到真实网络/ETW水位，不另设采集轮询。
    ULONGLONG nextProgressPublish = 0; // 下一次允许发布不可变活动快照的时刻。
    std::string publishedProgress; // 上次已通知正文，无变化时不重发界面或重建字段文档。
    const auto publishProgress = [&](bool final)
    {
        if ((!handoff && !network && !out.etw) || !notifyTransfers)
        {
            return;
        }
        const auto now = GetTickCount64(); // 只控制展示频率，不参与Hook准入或保护判定。
        if (!final && now < nextProgressPublish)
        {
            return;
        }
        nextProgressPublish = now + 500;
        auto snapshot = handoff ? handoff->Describe() : JsonValue::makeNull(); // 原控制器值，无handoff不制造控制身份。
        auto traffic = network ? ApiCaptureNetworkJson(network->Receipt()) : JsonValue::makeNull(); // 已提交网络段及来源状态。
        auto telemetry = ApiCaptureEtwJson(out.etw); // ETW沿原封段游标更新，绝不在通知路径读档或追加Flush。
        if (final && out.networkTraffic)
        {
            traffic = ApiCaptureNetworkJson(out.networkTraffic); // 最终追加目标失败也保留，不能被来源正常清退覆盖。
        }
        const auto encoded = Evidence::WriteJson(Object({{"handoff", snapshot},
            {"networkTraffic", traffic}, {"agentEtw", telemetry}})); // 组合检测，不让任一路变化被另一条静默掩盖。
        if (!final && encoded == publishedProgress)
        {
            return;
        }
        publishedProgress = encoded;
        out.transfers.handoff = std::move(snapshot);
        out.transfers.networkTraffic = std::move(traffic);
        out.transfers.agentEtw = std::move(telemetry);
        if (!out.sample.sampleId.empty())
        {
            out.transfers.handoffSample = out.sample;
        }
        try
        {
            onTransfers(out.transfers);
        }
        catch (...)
        {
            notifyTransfers = false; // 展示失败不打断已承担的保护恢复及归档责任。
        }
    };
    request.onControlPoll = [&]
    {
        if (handoff)
        {
            handoff->Poll();
        }
        if (network)
        {
            network->Poll();
        }
        flushEtw(false, {});
        publishProgress(false); // 三路更新后发布同轮值；无API包也不需要额外线程或读盘。
    };
    request.onResidentPoll = [&]() {
        // 静默期间也及时提交此前的普通调用，终段仍在实际清退后写出。
        if (!pending.empty() && GetTickCount64() - batchStarted >= kApiBatchMs) {
            commit({});
        }
    };

    // 即使本轮提前结束，也先由原控制器清退，再尝试保存已收取的证据。
    const auto captureStarted = GetTickCount64(); // 包含根来源、后续来源以及全部清退的本轮耗时。
    out.capture = Monitor::captureApiMonitor(request, cancel);
    if (handoff) {
        handoff->OriginalSourceFinished();
        handoff->Poll();
        const bool rootExited = !out.capture.processes.empty() && out.capture.processes.front().exited;
        if (out.capture.started && rootExited && readyAt)
        {
            // 根进程自然退出后仍保留已接管来源及在途准入，直到原区间结束、取消或整链退出。
            while (!cancel.load() && (target.durationMs == 0 || GetTickCount64() - *readyAt < target.durationMs) &&
                handoff->HasActiveAgents())
            {
                request.onControlPoll();
                request.onResidentPoll();
                Sleep(5);
            }
            out.capture.cancelled = cancel.load();
            out.capture.intervalElapsedMs = GetTickCount64() - *readyAt;
            if (target.durationMs && !out.capture.cancelled && *out.capture.intervalElapsedMs >= target.durationMs)
            {
                out.capture.completedInterval = true;
            }
        }
        // 先停止并排空各子来源，最后一批仍经同一acceptPacket归档，随后才能封原API终段。
        handoff->Close();
        out.capture.cancelled = out.capture.cancelled || cancel.load();
        out.transferHandoff = handoff->Describe();
        if (handoff->Incomplete())
        {
            // 三端继续使用原采集状态投影；自动接管缺口独立进入回执，不能仍返回全部完成。
            if (out.capture.code == 0) out.capture.code = 6;
            out.capture.errors.emplace_back(L"automatic transfer handoff incomplete; inspect transferHandoff receipt");
        }
    }
    if (network)
    {
        network->Close(); // 抓包回调结束、队列排空并发布最后网络段后才能封API终段。
        out.networkTraffic = network->Receipt();
        if (networkTargetFailures && out.networkTraffic->status)
        {
            // 来源可正常清退但下一目标未加入时仍报告部分结果；具体准入原因保留在diagnostics。
            out.networkTraffic->status = Failure(ProjectError::InvalidArgument, "networkTargetAdmission");
        }
        const auto& receipt = *out.networkTraffic; // 网络失败保留API已发布前缀并单独报告。
        const bool failed = !receipt.status || !receipt.sourceReady || !receipt.cleanupConfirmed ||
            receipt.queueDropped || receipt.sourceGap || receipt.unsupportedPackets ||
            (receipt.reason != "cancelled" && receipt.reason != "target-exited" &&
                receipt.reason != "duration-elapsed" && receipt.reason != "stopped");
        if (failed)
        {
            if (out.capture.code == 0)
            {
                out.capture.code = 6;
            }
            out.capture.errors.emplace_back(L"network capture incomplete; inspect networkTraffic receipt");
        }
    }
    // 先清退和封存ETW，API终段才能冻结其独立结果；两路仍复用原worker串行写入。
    if (etwSource && etwTarget) {
        auto& etw = *out.etw;
        etw.stopped = etwSource->stop();
        etw.source = etwSource->status();
        if (etw.started && etw.stopped) {
            const auto* reason = out.capture.cancelled ? "cancelled" :
                out.capture.completedInterval ? "duration-limit" : "cooperative-ended";
            flushEtw(true, reason);
            etw.source = etwSource->status();
        }
    }
    publishProgress(true); // 接管、网络及ETW分别完成真实清退/封段后再发布终态，不能提前显示clean。
    if (out.archiveStatus && !out.capture.processes.empty() && out.capture.processes.front().connected) {
        const auto& process = out.capture.processes.front(); // 合作入口固定单个进程实例。
        if (plan.empty()) {
            plan = ApiPlan(*document.Info(), apiSample, target, apiEpoch, process.session, database);
        }
        const auto* reason = out.capture.cancelled ? "cancelled" : out.capture.completedInterval ? "duration-limit" :
            process.exited ? "target-exited" : target.mode == ApiCaptureMode::ExplicitAttachment ?
            "attachment-ended" : "cooperative-ended"; // 停止原因独立于 Agent 丢失和 EOF。
        JsonObject endFields{{"kind", Text(kApiFollowEndKind)}, {"stopReason", Text(reason)},
            {"startup", ApiCaptureStartupJson(out.capture.startup)},
            {"transferHandoff", out.transferHandoff},
            {"networkTraffic", ApiCaptureNetworkJson(out.networkTraffic)},
            {"agentEtw", ApiCaptureEtwJson(out.etw)},
            {"source", Object({{"kind", Text("cooperative-pipe")}, {"readerPid", JsonValue::makeUInt(process.pid)},
                {"readerCreation100ns", Number(process.creation)}, {"sessionIdentity", Number(process.session)},
                {"validatedRows", Number(out.ordinaryPackets)}, {"agentReportedDrops", Number(process.agentDropped)},
                {"invalidPackets", Number(out.capture.invalidPackets)},
                {"state", Text(process.cleanPipeEof ? "pipe-eof" : "unconfirmed-end")}})}};
        if (target.mode == ApiCaptureMode::ExplicitAttachment) {
            // 保存控制器当时的独立回执；重开归档不因此取得新的控制权或认证生产者。
            endFields.emplace_back("attachmentReceipt", Object({
                {"identityVerified", JsonValue::makeBool(out.capture.attachmentIdentityVerified)},
                {"agentLoadAttempted", JsonValue::makeBool(out.capture.agentLoadAttempted)},
                {"agentModuleVerified", JsonValue::makeBool(out.capture.agentModuleVerified)},
                {"agentReady", JsonValue::makeBool(out.capture.started)},
                {"hooksRemoved", JsonValue::makeBool(process.removed)},
                {"cleanPipeEof", JsonValue::makeBool(process.cleanPipeEof)},
                {"cleanupComplete", JsonValue::makeBool(out.capture.cleanupComplete)}}));
        }
        const auto end = Evidence::WriteJson(Object(std::move(endFields)));
        commit(end);
    }
    out.omittedClues = receivedClues - out.retainedClues;
    out.capture.elapsedMs = GetTickCount64() - captureStarted; // 包含网络与ETW实际清退/封段；Ready区间仍用intervalElapsedMs。
    return out;
}

} // namespace Ksword::ActionAnalyze
