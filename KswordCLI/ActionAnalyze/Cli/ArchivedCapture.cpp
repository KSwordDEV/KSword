#include "ArchivedCapture.h"

#include "../Project/ProjectApiCheckpoint.h"
#include "../Project/ProjectEtwCheckpoint.h"
#include "../Project/ProjectRawEvidence.h"
#include "../Project/ProjectStorage.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"

#include <cstring>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
using namespace Ksword::ActionAnalyze::ProjectStorage;
using V = JsonValue;

constexpr std::uint64_t kCaptureFileLimit = 4u << 20; // 覆盖此版本单个有限 ETW 采样。
constexpr std::uint64_t kObservationLimit = 512; // 采集器每轮最多留存的观察数。
constexpr std::uint64_t kApiCaptureSegments = 128; // 每个历史查询最多核验 128 个 API 段。

// 单独报告读取状态。缺失、格式不适用、损坏和限额均可与冻结设置同时返回。
JsonObject Status(const char* status, const char* checkpoint = nullptr)
{
    JsonObject fields{{"status", Text(status)}};
    if (checkpoint) fields.emplace_back("checkpoint", Text(checkpoint));
    return fields;
}

V FirstObservation(std::uint64_t ordinal, std::uint64_t rawSequence, std::uint64_t sourceSequence = 0)
{
    JsonObject fields{{"segmentOrdinal", Number(ordinal)}, {"rawSequence", Number(rawSequence)}};
    if (sourceSequence) fields.emplace_back("sourceSequence", Number(sourceSequence));
    return Object(std::move(fields));
}

struct Capture {
    std::string providerId; // 采集计划中的提供程序 GUID。
    std::string sourceEpoch; // 计划、观察和结束记录共用的来源代次。
    std::uint64_t headerPid = 0; // 按采集计划过滤的报头 PID。
    std::uint64_t creationTime = 0; // 计划绑定的目标创建时间。
    std::uint64_t observations = 0; // 本次重开实际核对的 ETW 观察数。
    std::string reason; // 已归档的结束原因。
    bool nativeStopped = false; // 结束记录声明的原生会话清退结果。
    bool complete = false; // 结束记录已通过覆盖计数检查。
    bool continuous = false; // 持续采样的段尾使用段内计数而非本次运行累计值。
    bool finalSegment = true; // 旧单段采样默认就是整次采样的结尾。

    // 核对计划身份和冻结配置。成功时保留后续观察所需字段。
    bool ReadPlan(const V& plan, const Ksword::ActionAnalyze::SampleRecord& sample)
    {
        const auto* session = plan.find("session"); // 计划中声明的原会话身份。
        const auto* pid = plan.find("headerPid"); // 原生事件头使用的数字 PID。
        const auto* duration = plan.find("durationMs"); // 归档计划用 0 表示未设时限。
        std::uint64_t milliseconds = 0;
        continuous = duration && duration->type() == Ksword::Evidence::JsonType::UInt &&
            duration->tryGetU64(milliseconds) && milliseconds == 0;
        std::string epoch; // 仅校验原会话代次格式，不对外授予控制身份。
        return IsString(plan, "backend", "r3") && session && IsString(*session, "id", sample.info.sampleId) &&
            GetUuid(*session, "epoch", epoch) && IsString(plan, "revisionId", sample.info.revisionId) &&
            IsString(plan, "snapshotId", sample.info.snapshotId) && IsString(plan, "revisionHash", sample.revisionHash) &&
            IsString(plan, "configSemanticHash", sample.configSemanticHash) && GetUuid(plan, "providerId", providerId) &&
            GetUuid(plan, "sourceEpoch", sourceEpoch) && pid && pid->type() == Ksword::Evidence::JsonType::UInt &&
            pid->tryGetU64(headerPid) && headerPid > 0 && headerPid <= UINT32_MAX &&
            GetNumber(plan, "processCreationFileTime", creationTime) && creationTime > 0;
    }

    // 核对结束记录和段内计数。清退结果按归档声明保留。
    bool ReadEnd(const V& end)
    {
        const auto* source = end.find("source"); // 采集器在排空后记录的来源覆盖。
        const auto* stopped = source ? source->find("nativeSessionStopped") : nullptr; // 原生清退标志。
        std::uint64_t enqueued = 0; // 采集器声明的总入队条数。
        std::uint64_t queued = 0; // 收尾后应已排空的观察条数。
        const auto* final = end.find("finalSegment"); // 仅持续模式存在。
        const bool countValid = continuous ? final && final->tryGetBool(finalSegment) &&
            GetNumber(end, "segmentObservations", enqueued) && enqueued == observations :
            source && GetNumber(*source, "enqueued", enqueued) && enqueued == observations;
        complete = source && IsString(*source, "sourceEpoch", sourceEpoch) &&
            countValid && GetNumber(*source, "queued", queued) && (!finalSegment || queued == 0) &&
            stopped && stopped->tryGetBool(nativeStopped) &&
            GetString(end, "stopReason", reason) && IsText(reason, 64);
        return complete;
    }
};

// 从首段开始核验指定 API 段。失败回执保留可信前序且不给出未提交段的内容。
JsonObject ReadApiCapture(const Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sampleId,
    std::uint64_t requested, Ksword::ActionAnalyze::ApiFollowArchiveKind kind, std::optional<bool>& mixedEtw)
{
    using namespace Ksword::ActionAnalyze;
    namespace Monitor = ks::winapi_monitor;
    ProjectApiCheckpoint committed; // 在本次只读查询核验的最近连续段。
    const auto failure = [&](const char* status, std::uint64_t failedOrdinal) {
        JsonObject fields{{"kind", Text("api-archive-follow")}, {"status", Text(status)},
            {"requestedOrdinal", Number(requested)}, {"failedOrdinal", Number(failedOrdinal)},
            {"lastVerifiedOrdinal", Number(committed.ordinal)}, {"lastSourceSequence", Number(committed.lastSourceSequence)}};
        if (mixedEtw.value_or(false)) fields.emplace_back("sourceCoverage", Text("unknown"));
        return fields;
    };
    if (kind == ApiFollowArchiveKind::Legacy) {
        mixedEtw = false;
        return failure("legacy-unpublished", 1);
    }
    if (requested > kApiCaptureSegments) {
        // 只识别采集类型；不把首段的坐标或水位记入超限请求的回执。
        if (ReadApiCheckpoint(project, sampleId, 1, nullptr, committed)) {
            mixedEtw = committed.mixedEtw;
            committed = {};
        }
        return failure("limit-exceeded", requested);
    }
    std::uint64_t firstApiSequence = 0; // 暂存坐标，只有所请求段成功核验后才公布。
    const archive::SegmentBodyVisitor noVisitor;
    const archive::SegmentBodyVisitor firstApi = [&](const auto&, const auto&, const auto& records) {
        if (firstApiSequence) return true;
        for (const auto& record : records) {
            const auto& raw = std::get<archive::RawRecordV1>(record.body);
            Monitor::ApiMonitorEventPacket packet;
            if (raw.inlineRawData.size() != sizeof(packet)) continue;
            std::memcpy(&packet, raw.inlineRawData.data(), sizeof(packet));
            const auto module = Ksword::Evidence::ApiMonitorPacketText(packet.moduleName);
            // 与活会话首条普通 API 调用的口径一致，不包括 Agent 内部包或覆盖包。
            if (packet.eventKind == static_cast<std::uint32_t>(Monitor::EventKind::ApiCall) &&
                packet.category != static_cast<std::uint32_t>(Monitor::EventCategory::Internal) &&
                !module.empty() && module != L"Agent" && !Ksword::Evidence::ApiMonitorPacketText(packet.apiName).empty()) {
                firstApiSequence = record.recordSequence;
                break;
            }
        }
        return true;
    };
    for (std::uint64_t ordinal = 1; ordinal <= requested; ++ordinal) {
        if (committed.finalSegment) {
            return failure("missing", ordinal);
        }
        const auto& visitor = ordinal == requested && mixedEtw != false ? firstApi : noVisitor;
        const auto result = ReadApiCheckpoint(project, sampleId, ordinal,
            committed.ordinal ? &committed : nullptr, committed, visitor); // 只传上次成功核验的同采样水位。
        switch (result.error) {
        case ProjectError::None:
            mixedEtw = committed.mixedEtw;
            break;
        case ProjectError::NotFound:
            return failure("pending", ordinal);
        case ProjectError::LimitExceeded:
            return failure("limit-exceeded", ordinal);
        case ProjectError::IoError:
            return failure("unavailable", ordinal);
        default:
            return failure("invalid", ordinal);
        }
    }

    // 源覆盖仍未知。终段回执描述的是本端停止跟随时观察到的状态。
    auto terminal = V::makeNull(); // 普通分段没有终态回执。
    if (committed.finalSegment) {
        terminal = Object({{"stopReason", Text(committed.stopReason)}, {"sourceState", Text(committed.sourceState)},
            {"startup", committed.startup},
            {"sourceCutoffReached", V::makeBool(committed.sourceCutoffReached)},
            {"partialLineBytes", Number(committed.partialLineBytes)}});
    }
    JsonObject fields{{"kind", Text("api-archive-follow")}, {"status", Text("readback-verified")},
        {"checkpoint", Text("verified")}, {"segmentOrdinal", Number(committed.ordinal)},
        {"checkedBytes", Number(committed.rawEnd.byteOffset)}, {"blockOrdinal", Number(committed.rawEnd.blockOrdinal)},
        {"planRawSequence", Number(committed.planRawSequence)}, {"lastSequence", Number(committed.rawEnd.lastSequence)},
        {"sha256", Text(committed.rawSha256)}, {"previousSourceSequence", Number(committed.previousSourceSequence)},
        {"lastSourceSequence", Number(committed.lastSourceSequence)}, {"finalSegment", V::makeBool(committed.finalSegment)},
        {"sourceCoverage", Text("unknown")}, {"terminal", std::move(terminal)}};
    if (committed.mixedEtw) {
        auto first = V::makeNull();
        if (firstApiSequence) {
            const auto offset = firstApiSequence - committed.planRawSequence;
            first = FirstObservation(committed.ordinal, firstApiSequence, committed.previousSourceSequence + offset);
        }
        fields.emplace_back("firstObservation", std::move(first));
    }
    return fields;
}

JsonObject ReadEtwCapture(const Ksword::ActionAnalyze::ProjectDocument& project,
    const Ksword::ActionAnalyze::SampleRecord& sample, std::uint64_t ordinal,
    Ksword::ActionAnalyze::ProjectEvidenceLane lane, const Ksword::ActionAnalyze::ProjectEtwCheckpoint& checkpoint,
    const Ksword::ActionAnalyze::ProjectResult& checkpointStatus)
{
    using namespace Ksword::ActionAnalyze;
    const bool mixed = lane == ProjectEvidenceLane::MixedEtw;
    if (!checkpointStatus && checkpointStatus.error != ProjectError::NotFound) {
        if (mixed && checkpointStatus.error == ProjectError::LimitExceeded) return Status("limit-exceeded");
        if (mixed && checkpointStatus.error == ProjectError::IoError) return Status("unavailable");
        return Status("invalid", "invalid");
    }
    // 只有旧单段格式允许无标记回退。连续段必须经过双流校验才能公布。
    if (!checkpointStatus && (mixed || ordinal != 1)) return Status("missing");
    Capture capture; // 同一次扫描内核对计划、观察和结束记录。
    bool recognized = false; // 首条记录是否声明此版本 ETW 计划。
    JsonObject coverage; // 混采时只公布已与检查点覆盖记录交叉验证的统计。
    archive::RawEvidenceScanResult scan; // 段身份、CRC、序号和完整端点回执。
    const auto endOffset = checkpointStatus ? std::optional(checkpoint.raw.end.byteOffset) : std::nullopt;
    const auto firstSequence = checkpointStatus ? checkpoint.planRawSequence : 1;
    const ProjectRawEvidenceRead request{project.Info()->projectId, sample.info.sampleId, ordinal, endOffset, firstSequence - 1,
        [&](const archive::SegmentIdentity&, const archive::BlockInfo&, const std::vector<archive::DecodedRecord>& records) {
            for (const auto& record : records) {
                // Raw 扫描已确认正文类型，解析视图仅在本块回调中使用。
                const auto& raw = std::get<archive::RawRecordV1>(record.body); // 原始元数据和内联字节。
                const auto parsed = Ksword::Evidence::ParseJson(raw.metadataJson); // Stored 正文已过结构校验。
                if (!parsed.ok()) {
                    return false;
                }
                if (record.recordSequence == firstSequence) {
                    recognized = IsString(parsed.value, "kind", "etw-capture-plan-v1");
                    if (!recognized || raw.inlineRawBytes || !capture.ReadPlan(parsed.value, sample)) {
                        return false;
                    }
                } else if (capture.complete) {
                    return false;
                } else if (IsString(parsed.value, "kind", "etw-capture-end-v1")) {
                    if (raw.inlineRawBytes || !capture.ReadEnd(parsed.value)) {
                        return false;
                    }
                    if (mixed) {
                        const auto* source = parsed.value.find("source");
                        if (!source) return false;
                        for (const char* key : {"eventsLost", "logBuffersLost", "realTimeBuffersLost", "queueDropped",
                                "payloadTruncated", "malformedPayload"}) {
                            const auto* value = source->find(key);
                            if (!value) return false;
                            coverage.emplace_back(key, *value);
                        }
                    }
                } else {
                    // 每条观察必须绑定同一来源和 PID，完整段的计数才能用于回执。
                    const auto observation = Ksword::Evidence::ReadArchivedEtwObservation(parsed.value, raw.inlineRawBytes);
                    if (!observation || observation->providerId != capture.providerId ||
                        observation->sourceEpoch != capture.sourceEpoch || observation->headerPid != capture.headerPid ||
                        ++capture.observations > kObservationLimit) {
                        return false;
                    }
                }
            }
            return true;
        }, kCaptureFileLimit, lane};

    std::string rawHash;
    const auto result = project.ReadRawEvidenceSegment(request, scan, checkpointStatus ? &rawHash : nullptr);
    if (checkpointStatus && (!result || rawHash != checkpoint.raw.sha256)) return Status("invalid", "invalid");
    if (!result) {
        switch (result.error) {
        case ProjectError::NotFound: return Status("missing");
        case ProjectError::LimitExceeded: return Status("limit-exceeded");
        default: return Status("unavailable");
        }
    }
    if (!recognized && scan.checked) {
        return Status("unrecognized");
    }
    if (capture.continuous && !checkpointStatus) return Status("missing");
    if (!capture.complete || !scan.checked || !scan.VerifiedBoundary(*scan.checked)) {
        return Status("invalid");
    }

    // 只报告本次读到的完整段及归档声明，历史采样不会恢复任何会话状态。
    JsonObject fields{{"status", Text("readback-verified")}, {"segmentOrdinal", Number(ordinal)},
        {"checkedBytes", Number(scan.checked->byteOffset)}, {"observationCount", Number(capture.observations)},
        {"plan", Object({{"providerId", Text(capture.providerId)}, {"sourceEpoch", Text(capture.sourceEpoch)},
            {"headerPid", V::makeUInt(capture.headerPid)}, {"processCreationFileTime", Number(capture.creationTime)}})},
        {"terminal", Object({{"stopReason", Text(capture.reason)}, {"nativeSessionStopped", V::makeBool(capture.nativeStopped)}})}};
    if (checkpointStatus) fields.emplace_back("checkpoint", Text("verified"));
    if (capture.continuous) fields.emplace_back("finalSegment", V::makeBool(capture.finalSegment));
    if (mixed) {
        fields.emplace_back("blockOrdinal", Number(scan.checked->blockOrdinal));
        fields.emplace_back("planRawSequence", Number(firstSequence));
        fields.emplace_back("lastSequence", Number(scan.checked->lastSequence));
        fields.emplace_back("sha256", Text(rawHash));
        fields.emplace_back("firstObservation", capture.observations ? FirstObservation(ordinal, firstSequence + 1) : V::makeNull());
        fields.emplace_back("coverage", Object(std::move(coverage)));
    }
    return fields;
}
} // namespace

JsonValue ReadArchivedCapture(const Ksword::ActionAnalyze::ProjectDocument& project,
                              const Ksword::ActionAnalyze::SampleRecord& sample, std::uint64_t ordinal)
{
    using namespace Ksword::ActionAnalyze;
    const auto& sampleId = sample.info.sampleId;
    ApiFollowArchiveKind api = ApiFollowArchiveKind::Other;
    const bool hasApi = ProbeApiFollowArchive(project, sampleId, api) && api != ApiFollowArchiveKind::Other;
    std::optional<bool> mixedEtw; // 未核验 API 首段时，仍允许独立核验 ETW 专用流。
    JsonObject apiFields;
    if (hasApi) {
        apiFields = ReadApiCapture(project, sampleId, ordinal, api, mixedEtw);
        if (mixedEtw == false) return Object(std::move(apiFields));
    }

    constexpr auto lane = ProjectEvidenceLane::MixedEtw;
    ProjectEtwCheckpoint checkpoint;
    auto status = project.ReadEtwCheckpoint(sampleId, checkpoint, ordinal, lane);
    bool mixed = mixedEtw.value_or(false) || static_cast<bool>(status);
    if (!mixed && ordinal != 1) {
        ProjectEtwCheckpoint first;
        mixed = static_cast<bool>(project.ReadEtwCheckpoint(sampleId, first, 1, lane));
    }
    if (mixed) {
        if (!hasApi) {
            apiFields = ReadApiCapture(project, sampleId, ordinal, ApiFollowArchiveKind::Checkpointed, mixedEtw);
            if (mixedEtw == false) return Object(std::move(apiFields));
        }
        if (!mixedEtw.has_value()) apiFields.emplace_back("sourceCoverage", Text("unknown"));
        apiFields.emplace_back("stream", Text("raw"));
        auto etwFields = ReadEtwCapture(project, sample, ordinal, lane, checkpoint, status);
        etwFields.emplace_back("stream", Text("raw-etw"));
        return Object({{"kind", Text("mixed-api-etw")}, {"requestedOrdinal", Number(ordinal)},
            {"api", Object(std::move(apiFields))}, {"etw", Object(std::move(etwFields))}});
    }
    if (hasApi) return Object(std::move(apiFields));

    status = project.ReadEtwCheckpoint(sampleId, checkpoint, ordinal);
    return Object(ReadEtwCapture(project, sample, ordinal, ProjectEvidenceLane::Primary, checkpoint, status));
}

} // namespace ks::cli::action_analyze
