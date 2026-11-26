#include "ProjectEtwEvidence.h"

#include "ProjectEtwCheckpoint.h"
#include "ProjectStorage.h"

namespace Ksword::ActionAnalyze {
namespace {
namespace Archive = ks::cli::action_analyze::archive;
using namespace ks::r3::monitor;
using namespace ProjectStorage;
using V = Evidence::JsonValue;

// 按原生状态返回稳定的回执标识，供 CLI 和 Stored 尾记使用。
const char* SourceState(PassiveEtwState state)
{
    switch (state) {
    case PassiveEtwState::Idle: return "idle";
    case PassiveEtwState::Starting: return "starting";
    case PassiveEtwState::Running: return "running";
    case PassiveEtwState::Stopping: return "stopping";
    case PassiveEtwState::Stopped: return "stopped";
    case PassiveEtwState::AccessDenied: return "access-denied";
    case PassiveEtwState::ProviderUnavailable: return "provider-unavailable";
    case PassiveEtwState::CleanupPending: return "cleanup-pending";
    case PassiveEtwState::Failed: return "failed";
    }
    return "failed";
}

// 将原生启动中止阶段投影为稳定字符串，未中止时返回空值。
V StartupAbort(EtwStartupAbort stage)
{
    switch (stage) {
    case EtwStartupAbort::BeforeOpenTrace: return Text("before-open-trace");
    case EtwStartupAbort::BeforeProcessTrace: return Text("before-process-trace");
    case EtwStartupAbort::None: return V::makeNull();
    }
    return V::makeNull();
}

// 将本地 GUID 转为归档使用的小写无括号形式。
std::string GuidText(const GUID& guid)
{
    const auto native = GuidToString(guid); // 系统 ETW 控制器使用带大括号的 GUID。
    std::string text; // 归档 JSON 中的 UUID。
    for (std::size_t i = 1; i + 1 < native.size(); ++i) {
        const auto ch = native[i]; // 当前 ASCII 字符。
        text.push_back(static_cast<char>(ch >= L'A' && ch <= L'F' ? ch + (L'a' - L'A') : ch));
    }
    return text;
}

// 将一条已复制的 ETW 记录编码为原始段元数据，载荷由调用方独立保存。
std::string RecordMetadata(const PassiveEtwRecord& record)
{
    const auto& desc = record.descriptor; // 保留所有事件描述符的原值。
    return Evidence::WriteJson(Object({{"kind", Text("etw-observation-v1")},
        {"sourceEpoch", Text(record.sourceEpoch)}, {"providerId", Text(GuidText(record.provider))},
        {"descriptor", Object({{"id", V::makeUInt(desc.id)}, {"version", V::makeUInt(desc.version)},
            {"channel", V::makeUInt(desc.channel)}, {"level", V::makeUInt(desc.level)},
            {"opcode", V::makeUInt(desc.opcode)}, {"task", V::makeUInt(desc.task)}, {"keyword", Number(desc.keyword)}})},
        {"headerPid", V::makeUInt(record.headerPid)}, {"headerTid", V::makeUInt(record.headerTid)},
        {"headerFlags", V::makeUInt(record.headerFlags)}, {"sourceFileTime100ns", Number(record.sourceFileTime100ns)},
        {"receiveQpc", record.receivedQpc ? Number(*record.receivedQpc) : V::makeNull()},
        {"qpcFrequencyHz", record.receivedQpc ? Number(record.qpcFrequencyHz) : V::makeNull()},
        {"activityId", Text(GuidText(record.activityId))},
        {"relatedActivityId", record.relatedActivityId ? Text(GuidText(*record.relatedActivityId)) : V::makeNull()},
        {"extendedDataCount", V::makeUInt(record.extendedDataCount)},
        {"originalPayloadBytes", V::makeUInt(record.originalPayloadBytes)},
        {"malformedPayload", V::makeBool(record.malformedPayload)},
        {"storedPayloadBytes", Number(record.payloadPrefix.size())}}));
}

// 将 Stored 追加回执转换成项目错误，并保留底层 Win32 失败码。
ProjectResult AppendResult(const Archive::RawEvidenceReceipt& receipt)
{
    if (receipt.result.status == Archive::SegmentWriteStatus::Ok) return {};
    if (receipt.result.status == Archive::SegmentWriteStatus::IoError) {
        return WinFailure("archiveRawWrite", receipt.result.error.win32Error);
    }
    return Failure(ProjectError::InvalidArgument, "archiveRawInput");
}
} // namespace

Evidence::JsonValue EtwSourceReceipt(const PassiveEtwStatus& status)
{
    const auto& native = status.native; // 来源的实际原生状态。
    const auto& stop = native.stopStatuses; // 历次 STOP 的底层返回码。
    // 未尝试的操作或未知计数保留为空，避免与原生零值混淆。
    const auto optional = [](bool known, ULONG value) { return known ? V::makeUInt(value) : V::makeNull(); };
    return Object({{"state", Text(SourceState(status.state))}, {"sourceEpoch", Text(status.sourceEpoch)},
        {"inputWin32Error", V::makeUInt(status.inputError)},
        {"startWin32Error", optional(native.startAttempted, native.startStatus)},
        {"enableWin32Error", native.providers.empty() ? V::makeNull() : V::makeUInt(native.providers.front().status)},
        {"openWin32Error", optional(native.openAttempted, native.openStatus)},
        {"startupAbort", StartupAbort(native.startupAbort)},
        {"processAttempted", V::makeBool(native.processAttempted)},
        {"processWin32Error", optional(native.processCompleted, native.processStatus)},
        {"tailDeliveryUnconfirmed", V::makeBool(native.tailDeliveryUnconfirmed)},
        {"closeWin32Error", optional(native.closeAttempted, native.closeStatus)},
        {"firstStopWin32Error", stop.empty() ? V::makeNull() : V::makeUInt(stop.front())},
        {"lastStopWin32Error", stop.empty() ? V::makeNull() : V::makeUInt(stop.back())},
        {"stopAttempts", Number(stop.size())}, {"nativeSessionStopped", V::makeBool(native.sessionStopped)},
        {"callbackFailed", V::makeBool(native.callbackFailed)},
        {"eventsLost", optional(native.statisticsKnown, native.eventsLost)},
        {"logBuffersLost", optional(native.statisticsKnown, native.logBuffersLost)},
        {"realTimeBuffersLost", optional(native.statisticsKnown, native.realTimeBuffersLost)},
        {"providerEvents", Number(status.providerEvents)}, {"headerFiltered", Number(status.headerFiltered)},
        {"enqueued", Number(status.enqueued)}, {"queued", Number(status.queued)},
        {"queueDropped", Number(status.queueDropped)}, {"payloadTruncated", Number(status.payloadTruncated)},
        {"malformedPayload", Number(status.malformedPayload)}});
}

ProjectResult AppendEtwObservations(Archive::RawEvidenceArchive& writer, std::span<const PassiveEtwRecord> rows)
{
    std::vector<std::string> metadata; // 保留每条 JSON 到本批 Append 完成为止。
    std::vector<Archive::RawEvidenceInput> inputs; // 借用本批元数据与载荷。
    metadata.reserve(rows.size());
    inputs.reserve(rows.size());
    for (const auto& row : rows) {
        metadata.push_back(RecordMetadata(row));
        const auto& bytes = row.payloadPrefix; // 本条实际保存的载荷前缀。
        inputs.push_back({metadata.back(), bytes.empty() ? std::string_view{} :
            std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size())});
    }
    return AppendResult(writer.Append(inputs));
}

ProjectResult CommitFiniteEtwEvidence(ProjectDocument& project, std::string_view sampleId,
    ProjectEvidenceLane lane, const V& plan, std::string_view reason, PassiveEtwSource& source,
    Archive::RawEvidenceReceipt& raw, ProjectResult& checkpoint)
{
    const auto* info = project.Info(); // 当前项目写租约对应的真实身份。
    auto status = source.status(); // 原生停止后，入队总数不再推进。
    std::string provider; // 冻结计划声明的唯一 provider。
    if (!info || !GetUuid(plan, "providerId", provider) || status.sourceEpoch.empty()) {
        return Failure(ProjectError::InvalidArgument, "archiveEtwPlan");
    }

    // 有限采样固定为首段。封段顺序为冻结计划、实际观察和排空后的尾记。
    const auto append = [&](Archive::RawEvidenceArchive& writer) -> ProjectResult {
        const auto planText = Evidence::WriteJson(plan); // 采样计划的 UTF-8 正文。
        const Archive::RawEvidenceInput head{planText, {}}; // 计划记录无原始字节。
        if (const auto result = AppendResult(writer.Append(std::span(&head, 1))); !result) return result;
        constexpr std::size_t batchSize = 32; // 每批限制元数据和暂存字节。
        for (auto rows = source.drain(batchSize); !rows.empty(); rows = source.drain(batchSize)) {
            if (const auto result = AppendEtwObservations(writer, rows); !result) return result;
        }
        status = source.status();
        const auto endText = Evidence::WriteJson(Object({{"kind", Text("etw-capture-end-v1")},
            {"stopReason", Text(reason)}, {"source", EtwSourceReceipt(status)}})); // 排空后的实际回执。
        const Archive::RawEvidenceInput tail{endText, {}}; // 终态记录无原始字节。
        return AppendResult(writer.Append(std::span(&tail, 1)));
    };
    const auto written = project.WriteRawEvidenceSegment({info->projectId, sampleId, 1, {}, append, lane}, raw);
    if (!written) return written;
    if (!raw.flushed || raw.flushed->lastSequence != status.enqueued + 2) {
        return Failure(ProjectError::Corrupt, "archiveRawVerification");
    }

    // 保留原始段独立核验。发布覆盖记录时再校验计数、来源和散列。
    Archive::RawEvidenceScanResult checked; // Stored 读侧实际验证的段边界。
    const auto read = project.ReadRawEvidenceSegment({info->projectId, sampleId, 1,
        raw.flushed->byteOffset, 0, {}, std::nullopt, lane}, checked);
    if (!read) return read;
    if (!checked.VerifiedBoundary(*raw.flushed)) return Failure(ProjectError::Corrupt, "archiveRawVerification");

    const auto statistic = [known = status.native.statisticsKnown](ULONG value) -> std::optional<std::uint32_t> {
        if (!known) return std::nullopt;
        return static_cast<std::uint32_t>(value);
    }; // 未知的原生统计不能写成零。
    const Archive::EtwCoverageV1 coverage{provider, status.sourceEpoch, 1, 1, raw.flushed->lastSequence,
        status.enqueued, statistic(status.native.eventsLost), statistic(status.native.logBuffersLost),
        statistic(status.native.realTimeBuffersLost), status.queueDropped, status.payloadTruncated, status.malformedPayload};
    ProjectEtwCheckpoint published; // 已提交的 raw／records 前缀，由项目保存。
    checkpoint = project.PublishEtwCheckpoint(sampleId, *raw.flushed, coverage, published, lane);
    return {};
}

} // namespace Ksword::ActionAnalyze
