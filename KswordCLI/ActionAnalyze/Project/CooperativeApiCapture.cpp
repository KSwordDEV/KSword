#include "CooperativeApiCapture.h"
#include "ProjectApiCheckpoint.h"
#include "ProjectEtwEvidence.h"
#include "ProjectStorage.h"
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
    std::span<const Monitor::ApiMonitorEventPacket> packets, std::uint64_t creation, std::string_view end,
    ProjectApiCheckpoint& checkpoint, Archive::RawEvidenceReceipt& receipt)
{
    std::vector<std::string> metadata; // 原包的元数据由本次调用持有至读回完成。
    metadata.reserve(packets.size());
    std::vector<Archive::RawEvidenceInput> records; // 借用计划、元数据和未改写的原包字节。
    records.reserve(packets.size() + 2);
    records.push_back({plan, {}});
    auto sequence = checkpoint.lastSourceSequence; // 源序与封装序列使用各自坐标。
    for (const auto& packet : packets) {
        metadata.push_back(Evidence::WriteJson(Object({{"kind", Text(kApiFollowPacketKind)},
            {"sourceSequence", Number(++sequence)}, {"readerCreation100ns", Number(creation)}})));
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
    return Object({{"kind", Text("etw-capture-plan-v1")}, {"backend", Text("r3")},
        {"session", Object({{"id", Text(sample.info.sampleId)}, {"epoch", Text(epoch)}})},
        {"sourceEpoch", Text(status.sourceEpoch)}, {"revisionId", Text(sample.info.revisionId)},
        {"snapshotId", Text(sample.info.snapshotId)}, {"revisionHash", Text(sample.revisionHash)},
        {"configSemanticHash", Text(sample.configSemanticHash)}, {"providerId", Text(AgentEtw::kProviderId)},
        {"headerPid", JsonValue::makeUInt(target.pid)}, {"processCreationFileTime", Number(target.creationFileTime)},
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
        source.queueDropped || source.payloadTruncated || source.malformedPayload;
}

CooperativeApiReceipt CaptureCooperativeApi(ProjectDocument& document, const CooperativeApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady, const CooperativeApiCommitted& onCommitted,
    const CooperativeApiTransferCommitted& onTransfers)
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
    request.onResidentReady = onReady; // 直接传递已核验的启动回执，避免桌面端重新解释协议。

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
    Etw::PassiveEtwOptions etwOptions; // 仅订阅自有 Provider 及被冻结的报头 PID。
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
    std::uint64_t receivedClues = 0; // 根据验证过的普通包计算待归档与已提交的差额。
    std::uint64_t pendingClues = 0; // 本批可从原包重新投影的线索数。
    auto batchStarted = GetTickCount64(); // 当前批次开始缓冲的时间。
    bool notifyCommitted = static_cast<bool>(onCommitted); // 终态回执独立于实时通知。
    bool notifyTransfers = static_cast<bool>(onTransfers); // 消费端显示故障不停止原始采集清退。
    const auto commit = [&](std::string_view end) {
        out.archiveStatus = CommitApiPackets(document, out.sample, plan, pending, target.creationFileTime,
            end, checkpoint, out.archive);
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
        pendingClues = 0;
    };
    request.onVerifiedPacket = [&](const Monitor::ApiMonitorEventPacket& packet) {
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
            plan = ApiPlan(*document.Info(), apiSample, target, apiEpoch, packet.sessionIdentity, database);
        }
        if (pending.empty()) {
            batchStarted = GetTickCount64();
        }
        pending.push_back(packet);
        pendingClues += clue;
        if (pending.size() == kApiBatchPackets) {
            commit({});
        }
    };
    request.onResidentPoll = [&]() {
        // 静默期间也及时提交此前的普通调用，终段仍在实际清退后写出。
        if (!pending.empty() && GetTickCount64() - batchStarted >= kApiBatchMs) {
            commit({});
        }
    };

    // 即使本轮提前结束，也先由原控制器清退，再尝试保存已收取的证据。
    out.capture = Monitor::captureApiMonitor(request, cancel);
    if (out.archiveStatus && !out.capture.processes.empty() && out.capture.processes.front().connected) {
        const auto& process = out.capture.processes.front(); // 合作入口固定单个进程实例。
        if (plan.empty()) {
            plan = ApiPlan(*document.Info(), apiSample, target, apiEpoch, process.session, database);
        }
        const auto* reason = out.capture.cancelled ? "cancelled" : out.capture.completedInterval ? "duration-limit" :
            process.exited ? "target-exited" : target.mode == ApiCaptureMode::ExplicitAttachment ?
            "attachment-ended" : "cooperative-ended"; // 停止原因独立于 Agent 丢失和 EOF。
        JsonObject endFields{{"kind", Text(kApiFollowEndKind)}, {"stopReason", Text(reason)},
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
    if (etwSource && etwTarget) {
        auto& etw = *out.etw; // 原生状态与 API 管道回执分别保存。
        etw.stopped = etwSource->stop();
        etw.source = etwSource->status();
        if (etw.started && etw.stopped) {
            const auto etwPlan = AgentEtwPlan(etwSample, target, etwEpoch, etw.source, etwOptions); // 冻结 ETW 段头。
            const auto* reason = out.capture.cancelled ? "cancelled" :
                out.capture.completedInterval ? "duration-limit" : "cooperative-ended"; // API 区间结束原因。
            etw.archiveStatus = CommitFiniteEtwEvidence(document, out.sample.sampleId, ProjectEvidenceLane::MixedEtw,
                etwPlan, reason, *etwSource, etw.raw, etw.checkpointStatus);
            etw.source = etwSource->status();
        }
    }
    return out;
}

} // namespace Ksword::ActionAnalyze
