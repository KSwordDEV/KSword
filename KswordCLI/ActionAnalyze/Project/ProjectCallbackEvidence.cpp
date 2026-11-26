#include "ProjectCallbackEvidence.h"

#include "ProjectStorage.h"
#include "../../../shared/driver/KswordArkCallbackIoctl.h"

#include <cstring>
#include <utility>

namespace Ksword::ActionAnalyze {

std::string_view CallbackBatchStateName(CallbackBatchState state) noexcept
{
    switch (state) {
    case CallbackBatchState::CaughtUp: return "caught-up";
    case CallbackBatchState::MoreAvailable: return "more-available";
    case CallbackBatchState::SnapshotRace: return "snapshot-race";
    case CallbackBatchState::NotRead: break;
    }
    return {};
}

namespace {

namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
using CallbackEvent = KSWORD_ARK_CALLBACK_MONITOR_EVENT;

// 专用采样写一个 Stored 块，除观测外始终有计划及终态两行。
constexpr std::uint64_t kOrdinal = 1;
constexpr std::size_t kMaxEvents = KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS;
constexpr std::size_t kMetadataLimit = 512;
constexpr auto kMaxBlockBytes = (kMaxEvents + 2) *
    (Archive::kRecordHeaderBytes + Archive::kRawRecordV1PrefixBytes + kMetadataLimit) +
    kMaxEvents * sizeof(CallbackEvent);
static_assert(kMaxBlockBytes <= Archive::kMaxDecodedBlockBytes);
static_assert(kMaxEvents + 2 <= Archive::kMaxBlockRecords);
constexpr auto kMaxFileBytes = Archive::kSegmentHeaderBytes + Archive::kBlockHeaderBytes + kMaxBlockBytes;

constexpr char kEndKind[] = "kswordark-callback-thread-create-end-v1";
constexpr char kObservation[] = R"({"kind":"kswordark-callback-thread-create-observation-v1"})";

// 验证源游标属于同一代次，及覆盖跳跃和原生返回数是否能解释游标推进。
bool ValidBatch(const ProjectCallbackEvidencePlan& plan, const ProjectCallbackEvidenceEnd& end,
    std::size_t observationCount)
{
    if (!IsUuid(plan.sourceEpoch) || plan.maxRecords == 0 || plan.maxRecords > kMaxEvents ||
        end.returnedCount > plan.maxRecords || observationCount > end.returnedCount ||
        end.nextSequence < plan.afterSequence || end.latestSequence < end.nextSequence) {
        return false;
    }
    const auto advance = end.nextSequence - plan.afterSequence;
    if (advance < end.returnedCount ||
        (end.lostBeforeFirst && *end.lostBeforeFirst != advance - end.returnedCount)) {
        return false;
    }
    // 尚有尾部时，原生读要么达到批上限，要么遇到槽位快照竞态。
    return end.nextSequence == end.latestSequence ? end.state == CallbackBatchState::CaughtUp :
        (end.returnedCount == plan.maxRecords ? end.state == CallbackBatchState::MoreAvailable :
            end.state == CallbackBatchState::SnapshotRace);
}

// 与回调观察入口使用同一 v1 字段约束；原生返回区间只允许递增的线程创建子集。
bool ValidObservation(const CallbackEvent& event, const ProjectCallbackEvidenceEnd& end,
    std::uint64_t previousSequence) noexcept
{
    return event.version == KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION && event.size == sizeof(event) &&
        event.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD && event.operation == KSWORD_ARK_THREAD_OP_CREATE &&
        event.sequence != 0 && event.sequence > previousSequence && event.sequence <= end.nextSequence &&
        event.targetProcessId != 0 && event.targetThreadId != 0;
}

// 借用上游已核验的 ABI 对象字节，直接写入 raw 内联区。
std::string_view EventBytes(const CallbackEvent& event) noexcept
{
    return {reinterpret_cast<const char*>(&event), sizeof(event)};
}

// 计划绑定已冻结的采样描述；项目和采样 UUID 已由段头负责。
std::string EncodePlan(const SampleRecord& sample, const ProjectCallbackEvidencePlan& plan)
{
    return Evidence::WriteJson(Object({{"kind", Text(kProjectCallbackPlanKind)}, {"sourceId", Text(kProjectCallbackSourceId)},
        {"descriptionHash", Text(sample.info.descriptionHash)}, {"sourceEpoch", Text(plan.sourceEpoch)},
        {"afterSequence", Number(plan.afterSequence)}, {"maxRecords", Number(plan.maxRecords)}}));
}

bool DecodePlan(const JsonValue& doc, const SampleRecord& sample, ProjectCallbackEvidencePlan& plan)
{
    std::uint64_t maxRecords = 0; // 先读取无损数值，再按原生上限收窄。
    if (!Fields(doc, {"kind", "sourceId", "descriptionHash", "sourceEpoch", "afterSequence", "maxRecords"}) ||
        !IsString(doc, "kind", kProjectCallbackPlanKind) || !IsString(doc, "sourceId", kProjectCallbackSourceId) ||
        !IsString(doc, "descriptionHash", sample.info.descriptionHash) || !GetUuid(doc, "sourceEpoch", plan.sourceEpoch) ||
        !GetNumber(doc, "afterSequence", plan.afterSequence) ||
        !GetNumber(doc, "maxRecords", maxRecords) || maxRecords == 0 || maxRecords > kMaxEvents) {
        return false;
    }
    plan.maxRecords = static_cast<std::uint32_t>(maxRecords);
    return true;
}

// 可空的计数代表没有回执，绝不把空值变成已知零。
JsonValue OptionalNumber(const std::optional<std::uint64_t>& value)
{
    return value ? Number(*value) : JsonValue::makeNull();
}

bool ReadOptionalNumber(const JsonValue& doc, const char* name, std::optional<std::uint64_t>& out)
{
    if (IsNull(doc, name)) {
        out.reset();
        return true;
    }
    return GetNumber(doc, name, out.emplace());
}

// 终态分别保存已知源计数、游标和实际归档观测数；覆盖始终未知。
std::string EncodeEnd(const ProjectCallbackEvidenceEnd& end, std::size_t count)
{
    return Evidence::WriteJson(Object({{"kind", Text(kEndKind)}, {"state", Text(CallbackBatchStateName(end.state))},
        {"nextSequence", Number(end.nextSequence)}, {"latestSequence", Number(end.latestSequence)},
        {"returnedCount", Number(end.returnedCount)}, {"observationCount", Number(count)},
        {"lostBeforeFirst", OptionalNumber(end.lostBeforeFirst)}, {"droppedCount", OptionalNumber(end.droppedCount)},
        {"coverage", Text("unknown")}}));
}

bool DecodeEnd(const JsonValue& doc, std::size_t recordCount, ProjectCallbackEvidenceEnd& end)
{
    std::uint64_t observations = 0; // 终态声明的归档观测数，不含首尾记录。
    std::uint64_t returned = 0; // 终态声明的原生返回数，按原生上限收窄。
    std::string state;
    if (!Fields(doc, {"kind", "state", "nextSequence", "latestSequence", "returnedCount", "observationCount",
            "lostBeforeFirst", "droppedCount", "coverage"}) || !IsString(doc, "kind", kEndKind) ||
        !IsString(doc, "coverage", "unknown") || !GetString(doc, "state", state) ||
        !GetNumber(doc, "nextSequence", end.nextSequence) || !GetNumber(doc, "latestSequence", end.latestSequence) ||
        !GetNumber(doc, "returnedCount", returned) || returned > kMaxEvents ||
        !GetNumber(doc, "observationCount", observations) || observations != recordCount ||
        !ReadOptionalNumber(doc, "lostBeforeFirst", end.lostBeforeFirst) ||
        !ReadOptionalNumber(doc, "droppedCount", end.droppedCount)) {
        return false;
    }
    end.returnedCount = static_cast<std::uint32_t>(returned);
    for (const auto candidate : {CallbackBatchState::CaughtUp, CallbackBatchState::MoreAvailable, CallbackBatchState::SnapshotRace}) {
        if (state == CallbackBatchStateName(candidate)) {
            end.state = candidate;
            return true;
        }
    }
    return false;
}

// 专用块只接受约定形状；写后回读时也逐字节核对本次提交的元数据和原包。
bool DecodeBatch(const Archive::BlockInfo& block, const std::vector<Archive::DecodedRecord>& rows,
    std::span<const Archive::RawEvidenceInput> expected, const SampleRecord& sample,
    ProjectCallbackEvidenceReceipt& draft)
{
    if (block.ordinal != 1 || block.receiveQpc || rows.size() < 2 || rows.size() > kMaxEvents + 2 ||
        (!expected.empty() && rows.size() != expected.size())) {
        return false;
    }
    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index];
        const auto& raw = std::get<Archive::RawRecordV1>(row.body);
        if (row.flags != 0 || raw.metadataJson.size() > kMetadataLimit ||
            (!expected.empty() && (raw.metadataJson != expected[index].metadataJson ||
                raw.inlineRawData != expected[index].inlineRawData))) {
            return false;
        }
    }

    // 先验首尾与源区间，之后才复制记录并保存回读坐标。
    const auto& first = std::get<Archive::RawRecordV1>(rows.front().body);
    const auto& last = std::get<Archive::RawRecordV1>(rows.back().body);
    const auto plan = Evidence::ParseJson(first.metadataJson);
    const auto end = Evidence::ParseJson(last.metadataJson);
    const auto count = rows.size() - 2;
    if (first.inlineRawBytes != 0 || last.inlineRawBytes != 0 || !plan.ok() || !end.ok() ||
        !DecodePlan(plan.value, sample, draft.plan) || !DecodeEnd(end.value, count, draft.end) ||
        !ValidBatch(draft.plan, draft.end, count)) {
        return false;
    }
    auto previous = draft.end.nextSequence - draft.end.returnedCount;
    draft.records.reserve(count);
    for (std::size_t index = 1; index + 1 < rows.size(); ++index) {
        const auto& row = rows[index];
        const auto& raw = std::get<Archive::RawRecordV1>(row.body);
        if (raw.metadataJson != kObservation || raw.inlineRawData.size() != sizeof(CallbackEvent)) {
            return false;
        }
        auto& record = draft.records.emplace_back();
        std::memcpy(&record.event, raw.inlineRawData.data(), sizeof(record.event));
        if (!ValidObservation(record.event, draft.end, previous)) {
            return false;
        }
        previous = record.event.sequence;
        record.rawSequence = row.recordSequence;
        record.rawOffset = row.recordOffset;
        record.inlineOffset = row.recordOffset + Archive::kRecordHeaderBytes + raw.inlineRawOffsetInPayload;
    }
    return true;
}

// 在同一固定读句柄上扫描全文件和散列。出错时只返回诊断，不转交暂存结果。
ProjectResult Scan(const ProjectDocument& project, const SampleRecord& sample,
    std::span<const Archive::RawEvidenceInput> expected, ProjectCallbackEvidenceReceipt& out)
{
    ProjectCallbackEvidenceReceipt draft;
    draft.projectId = project.Info()->projectId;
    draft.sampleId = sample.info.sampleId;
    draft.descriptionHash = sample.info.descriptionHash;
    bool decoded = false;
    const ProjectRawEvidenceRead request{draft.projectId, draft.sampleId, kOrdinal, std::nullopt, 0,
        [&](const Archive::SegmentIdentity&, const Archive::BlockInfo& block,
            const std::vector<Archive::DecodedRecord>& rows) {
            if (decoded) {
                return false;
            }
            decoded = DecodeBatch(block, rows, expected, sample, draft);
            return decoded;
        }, kMaxFileBytes};
    Archive::RawEvidenceScanResult scan;
    if (const auto status = project.ReadRawEvidenceSegment(request, scan, &draft.prefixSha256); !status) {
        return status;
    }
    const auto& framing = scan.segment.framing;
    if (framing.status == Archive::SegmentScanStatus::IoError) {
        return WinFailure("callbackRawRead", framing.error.win32Error);
    }
    if (framing.status == Archive::SegmentScanStatus::Truncated) {
        return Failure(ProjectError::Corrupt, "callbackRawTruncated");
    }
    // 一个可核验的空批次也有两条记录；拒绝仅段头、额外的块和残尾。
    if (!decoded || !scan.checked || !scan.VerifiedBoundary(*scan.checked) || !framing.fileSizeKnown ||
        scan.checked->byteOffset != framing.fileBytes || scan.checked->blockOrdinal != 1 ||
        scan.checked->lastSequence != draft.records.size() + 2 || !IsHash(draft.prefixSha256)) {
        return Failure(ProjectError::Corrupt, "callbackRawBatch");
    }
    draft.segmentOrdinal = kOrdinal;
    draft.boundary = *scan.checked;
    out = std::move(draft);
    return {};
}

} // namespace

ProjectResult WriteInitialCallbackEvidence(ProjectDocument& project, std::string_view sampleId,
    const ProjectCallbackEvidencePlan& plan, const ProjectCallbackEvidenceEnd& end,
    std::span<const KSWORD_ARK_CALLBACK_MONITOR_EVENT> records, ProjectCallbackEvidenceReceipt& out)
{
    out = {};
    const auto* info = project.Info();
    if (!info) {
        return Failure(ProjectError::NotOpen, "project");
    }
    if (info->access != ProjectAccess::ReadWrite) {
        return Failure(ProjectError::ReadOnly, "project");
    }
    SampleRecord sample;
    if (const auto status = project.ReadSample(sampleId, sample); !status) {
        return status;
    }

    // 所有源范围与记录先验证，通过后才交给公共写入器创建新段。
    if (!ValidBatch(plan, end, records.size())) {
        return Failure(ProjectError::InvalidArgument, "callbackSourceBoundary");
    }
    auto previous = end.nextSequence - end.returnedCount;
    for (const auto& event : records) {
        if (!ValidObservation(event, end, previous)) {
            return Failure(ProjectError::InvalidArgument, "callbackSourceObservation");
        }
        previous = event.sequence;
    }
    const auto planJson = EncodePlan(sample, plan);
    const auto endJson = EncodeEnd(end, records.size());
    if (planJson.size() > kMetadataLimit || endJson.size() > kMetadataLimit) {
        return Failure(ProjectError::LimitExceeded, "callbackRawMetadata");
    }

    // 输入视图借用原包与本函数中的元数据，直到同步写入和回读完成。
    std::vector<Archive::RawEvidenceInput> inputs;
    inputs.reserve(records.size() + 2);
    inputs.push_back({planJson, {}});
    for (const auto& event : records) {
        inputs.push_back({kObservation, EventBytes(event)});
    }
    inputs.push_back({endJson, {}});
    const ProjectRawEvidenceWrite request{info->projectId, sample.info.sampleId, kOrdinal, std::nullopt,
        [&](Archive::RawEvidenceArchive& writer) {
            const auto appended = writer.Append(inputs);
            if (appended.result.status == Archive::SegmentWriteStatus::Ok) {
                return ProjectResult{};
            }
            return appended.result.error.win32Error ? WinFailure("callbackRawAppend", appended.result.error.win32Error) :
                Failure(ProjectError::InvalidArgument, "callbackRawAppend");
        }};

    // 仅在刷盘回执与实际回读一致时发布 out；不把写入失败或前缀当成空批次。
    Archive::RawEvidenceReceipt written;
    if (const auto status = project.WriteRawEvidenceSegment(request, written); !status) {
        return status;
    }
    if (written.result.status != Archive::SegmentWriteStatus::Ok || !written.flushed) {
        return Failure(ProjectError::IoError, "callbackRawFinish", written.result.error.win32Error);
    }
    ProjectCallbackEvidenceReceipt checked;
    if (const auto status = Scan(project, sample, inputs, checked); !status) {
        return status;
    }
    if (checked.boundary.byteOffset != written.flushed->byteOffset ||
        checked.boundary.blockOrdinal != written.flushed->blockOrdinal ||
        checked.boundary.lastSequence != written.flushed->lastSequence) {
        return Failure(ProjectError::Corrupt, "callbackRawReadback");
    }
    out = std::move(checked);
    return {};
}

ProjectResult ReadInitialCallbackEvidence(const ProjectDocument& project, std::string_view sampleId,
    ProjectCallbackEvidenceReceipt& out)
{
    out = {};
    if (!project.Info()) {
        return Failure(ProjectError::NotOpen, "project");
    }
    SampleRecord sample;
    if (const auto status = project.ReadSample(sampleId, sample); !status) {
        return status;
    }
    return Scan(project, sample, {}, out);
}

} // namespace Ksword::ActionAnalyze
