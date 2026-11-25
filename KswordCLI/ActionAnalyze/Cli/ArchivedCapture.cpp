#include "ArchivedCapture.h"

#include "../Project/ProjectRawEvidence.h"
#include "../Project/ProjectStorage.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"

namespace ks::cli::action_analyze {
namespace {
using namespace Ksword::ActionAnalyze::ProjectStorage;
using V = JsonValue;

constexpr std::uint64_t kCaptureFileLimit = 4u << 20; // 覆盖此版本单个有限 ETW 采样。
constexpr std::uint64_t kObservationLimit = 512; // 采集器每轮最多留存的观察数。

// 单独报告读取状态。缺失、格式不适用、损坏和限额均可与冻结设置同时返回。
V Status(const char* status)
{
    return Object({{"status", Text(status)}});
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

    // 核对计划身份和冻结配置。成功时保留后续观察所需字段。
    bool ReadPlan(const V& plan, const Ksword::ActionAnalyze::SampleRecord& sample)
    {
        const auto* session = plan.find("session"); // 计划中声明的原会话身份。
        const auto* pid = plan.find("headerPid"); // 原生事件头使用的数字 PID。
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
        complete = source && IsString(*source, "sourceEpoch", sourceEpoch) &&
            GetNumber(*source, "enqueued", enqueued) && enqueued == observations &&
            GetNumber(*source, "queued", queued) && queued == 0 && stopped && stopped->tryGetBool(nativeStopped) &&
            GetString(end, "stopReason", reason) && IsText(reason, 64);
        return complete;
    }
};
} // namespace

JsonValue ReadArchivedCapture(const Ksword::ActionAnalyze::ProjectDocument& project,
                              const Ksword::ActionAnalyze::SampleRecord& sample)
{
    using namespace Ksword::ActionAnalyze;
    Capture capture; // 同一次扫描内核对计划、观察和结束记录。
    bool recognized = false; // 首条记录是否声明此版本 ETW 计划。
    archive::RawEvidenceScanResult scan; // 段身份、CRC、序号和完整端点回执。
    const ProjectRawEvidenceRead request{project.Info()->projectId, sample.info.sampleId, 1, {}, 0,
        [&](const archive::SegmentIdentity&, const archive::BlockInfo&, const std::vector<archive::DecodedRecord>& records) {
            for (const auto& record : records) {
                // Raw 扫描已确认正文类型，解析视图仅在本块回调中使用。
                const auto& raw = std::get<archive::RawRecordV1>(record.body); // 原始元数据和内联字节。
                const auto parsed = Ksword::Evidence::ParseJson(raw.metadataJson); // Stored 正文已过结构校验。
                if (!parsed.ok()) {
                    return false;
                }
                if (record.recordSequence == 1) {
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
        }, kCaptureFileLimit};

    const auto result = project.ReadRawEvidenceSegment(request, scan); // 固定路径及同句柄只读扫描。
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
    if (!capture.complete || !scan.checked || !scan.VerifiedBoundary(*scan.checked)) {
        return Status("invalid");
    }

    // 只报告本次读到的完整段及归档声明，历史采样不会恢复任何会话状态。
    return Object({{"status", Text("readback-verified")}, {"segmentOrdinal", Number(1)},
        {"checkedBytes", Number(scan.checked->byteOffset)}, {"observationCount", Number(capture.observations)},
        {"plan", Object({{"providerId", Text(capture.providerId)}, {"sourceEpoch", Text(capture.sourceEpoch)},
            {"headerPid", V::makeUInt(capture.headerPid)}, {"processCreationFileTime", Number(capture.creationTime)}})},
        {"terminal", Object({{"stopReason", Text(capture.reason)}, {"nativeSessionStopped", V::makeBool(capture.nativeStopped)}})}});
}

} // namespace ks::cli::action_analyze
