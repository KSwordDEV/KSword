#include "CooperativeApiCapture.h"
#include "ProjectApiCheckpoint.h"
#include "ProjectStorage.h"
#include "../../../shared/ApiMonitorPlatform.h"

namespace Ksword::ActionAnalyze {
namespace {

namespace Monitor = ks::winapi_monitor;
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
    std::string_view epoch, std::uint64_t session, std::string_view presetSet)
{
    JsonObject fields{{"kind", Text(kApiFollowPlanKind)}, {kApiFollowCheckpointField, JsonValue::makeBool(true)},
        {"archiveSource", Text("cooperative-pipe")}, {"projectId", Text(project.projectId)},
        {"session", Object({{"id", Text(sample.info.sampleId)}, {"epoch", Text(epoch)}})},
        {"sourceEpoch", Text(epoch)}, {"revisionId", Text(sample.info.revisionId)},
        {"snapshotId", Text(sample.info.snapshotId)}, {"revisionHash", Text(sample.revisionHash)},
        {"configSemanticHash", Text(sample.configSemanticHash)}, {"durationMs", JsonValue::makeUInt(target.durationMs)},
        {"readerPid", JsonValue::makeUInt(target.pid)}, {"readerCreation100ns", Number(target.creationFileTime)},
        {"sessionIdentity", Number(session)}};
    if (!presetSet.empty()) {
        fields.emplace_back("rulePresetSet", Text(presetSet)); // 同一次采样的每段使用同一版本。
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

} // namespace

CooperativeApiReceipt CaptureCooperativeApi(ProjectDocument& document, const CooperativeApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady, const CooperativeApiCommitted& onCommitted)
{
    CooperativeApiReceipt out; // 工作线程独占，封段后交给本端投影。
    if (target.pid <= 4 || target.pid == GetCurrentProcessId() || !target.creationFileTime ||
        target.title.empty() || target.durationMs < 1000 || target.durationMs > 120000) {
        out.sampleStatus = {ProjectError::InvalidArgument, ERROR_INVALID_PARAMETER, "cooperativeApiTarget"};
        return out;
    }

    Monitor::CaptureRequest request; // 不配置 R0、远程装载、子进程或行为改写。
    request.agentPath = ResidentAgentPath();
    out.agentPathAvailable = !request.agentPath.empty();
    if (!out.agentPathAvailable) {
        return out;
    }
    request.pid = target.pid;
    request.residentCreationFileTime = target.creationFileTime;
    request.durationMs = target.durationMs;
    request.eventLimit = 0; // 由项目端分段归档，不重复缓存旧展示数据。
    request.onResidentReady = onReady; // 直接传递已核验的启动回执，避免桌面端重新解释协议。

    const auto database = Rules::LoadApiPresetDatabase(); // 采集途中编辑文件不会更换规则。
    out.rules.presetSet = database.presetSet;
    out.rules.configError = database.error;
    out.rules.failed = !database.error.empty();

    // 采样在本端的项目写租约下创建，目标与修订在运行期间不变。
    out.sampleStatus = document.CreateSample(target.title, out.sample, target.revisionId);
    if (!out.sampleStatus) {
        return out;
    }
    SampleRecord apiSample; // 读回项目层为本采样冻结的配置身份。
    out.sampleStatus = document.ReadSample(out.sample.sampleId, apiSample);
    std::string apiEpoch; // 归档计划中的样本代次，独立于管道会话数字。
    if (out.sampleStatus) {
        out.sampleStatus = NewId(apiEpoch);
    }
    if (!out.sampleStatus) {
        return out;
    }

    ProjectApiCheckpoint checkpoint; // 仅在刷盘、逐字节回读并发布标记后推进。
    std::string plan; // 由首个核验原包绑定实际管道会话。
    std::vector<Monitor::ApiMonitorEventPacket> pending; // 单批内存上限，包含分类和未分类原包。
    pending.reserve(kApiBatchPackets);
    std::uint64_t receivedClues = 0; // 根据验证过的普通包计算待归档与已提交的差额。
    std::uint64_t pendingClues = 0; // 本批可从原包重新投影的线索数。
    auto batchStarted = GetTickCount64(); // 当前批次开始缓冲的时间。
    bool notifyCommitted = static_cast<bool>(onCommitted); // 终态回执独立于实时通知。
    const auto commit = [&](std::string_view end) {
        out.archiveStatus = CommitApiPackets(document, out.sample, plan, pending, target.creationFileTime,
            end, checkpoint, out.archive);
        if (out.archiveStatus) {
            out.archivedPackets = checkpoint.lastSourceSequence;
            out.committedSegments = checkpoint.ordinal;
            out.retainedClues += pendingClues;
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
            plan = ApiPlan(*document.Info(), apiSample, target, apiEpoch, packet.sessionIdentity, database.presetSet);
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
            plan = ApiPlan(*document.Info(), apiSample, target, apiEpoch, process.session, database.presetSet);
        }
        const auto* reason = out.capture.cancelled ? "cancelled" : out.capture.completedInterval ? "duration-limit" :
            process.exited ? "target-exited" : "cooperative-ended"; // 停止原因独立于 Agent 丢失和 EOF。
        const auto end = Evidence::WriteJson(Object({{"kind", Text(kApiFollowEndKind)}, {"stopReason", Text(reason)},
            {"source", Object({{"kind", Text("cooperative-pipe")}, {"readerPid", JsonValue::makeUInt(process.pid)},
                {"readerCreation100ns", Number(process.creation)}, {"sessionIdentity", Number(process.session)},
                {"validatedRows", Number(out.ordinaryPackets)}, {"agentReportedDrops", Number(process.agentDropped)},
                {"invalidPackets", Number(out.capture.invalidPackets)},
                {"state", Text(process.cleanPipeEof ? "pipe-eof" : "unconfirmed-end")}})}}));
        commit(end);
    }
    out.omittedClues = receivedClues - out.retainedClues;
    return out;
}

} // namespace Ksword::ActionAnalyze
