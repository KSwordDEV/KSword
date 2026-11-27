#include "ProjectEtwCheckpoint.h"

#include "ProjectRawEvidence.h"
#include "ProjectStorage.h"
#include "../Archive/SegmentInspection.h"
#include "../../../shared/evidence/ActionAnalyzeEtwProvider.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"
#include <algorithm>

namespace Ksword::ActionAnalyze {
namespace {

namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
using Archive::EtwCoverageV1;
constexpr std::uint64_t kRawLimit = 4u << 20;

std::wstring_view CheckpointDirectory(ProjectEvidenceLane lane) {
    return lane == ProjectEvidenceLane::MixedEtw ? L"checkpoints-etw" : L"checkpoints";
}

std::wstring_view RecordsDirectory(ProjectEvidenceLane lane) {
    return lane == ProjectEvidenceLane::MixedEtw ? L"records-etw" : L"records";
}

std::wstring CheckpointFile(std::uint64_t ordinal) {
    const auto digits = std::to_wstring(ordinal);
    return std::wstring(20 - digits.size(), L'0') + digits + L".json";
}

JsonValue PrefixDocument(const EtwCheckpointPrefix& prefix, std::uint64_t ordinal) {
    return Object({{"ordinal", Number(ordinal)}, {"block", Number(prefix.end.blockOrdinal)},
        {"endOffset", Number(prefix.end.byteOffset)}, {"lastSequence", Number(prefix.end.lastSequence)},
        {"sha256", Text(prefix.sha256)}});
}

bool ReadPrefix(const JsonValue* doc, EtwCheckpointPrefix& prefix, std::uint64_t ordinal) {
    if (!doc || !Fields(*doc, {"ordinal", "block", "endOffset", "lastSequence", "sha256"})) return false;
    std::uint64_t actual = 0;
    return GetNumber(*doc, "ordinal", actual) && actual == ordinal && GetNumber(*doc, "block", prefix.end.blockOrdinal) &&
        prefix.end.blockOrdinal > 0 && GetNumber(*doc, "endOffset", prefix.end.byteOffset) &&
        prefix.end.byteOffset > Archive::kSegmentHeaderBytes && prefix.end.byteOffset <= kRawLimit &&
        GetNumber(*doc, "lastSequence", prefix.end.lastSequence) && prefix.end.lastSequence > 0 &&
        GetHash(*doc, "sha256", prefix.sha256);
}

bool MatchesCount(const JsonValue& doc, std::string_view key, std::uint64_t expected) {
    std::uint64_t actual = 0;
    return GetNumber(doc, key, actual) && actual == expected;
}

bool MatchesStatistic(const JsonValue& doc, std::string_view key, std::optional<std::uint32_t> expected) {
    if (!expected) return IsNull(doc, key);
    const auto* field = doc.find(key);
    std::uint64_t actual = 0;
    return field && field->type() == JsonType::UInt && field->tryGetU64(actual) && actual == *expected;
}

ProjectResult VerifyRaw(const ProjectDocument& project, const SampleRecord& sample, const EtwCoverageV1& coverage,
                        ProjectEtwCheckpoint& checkpoint, ProjectEvidenceLane lane) {
    auto& prefix = checkpoint.raw; // 已刷盘端点与同一文件句柄读回的摘要。
    if (!coverage.rawSegmentOrdinal || !coverage.planRawSequence ||
        (lane == ProjectEvidenceLane::MixedEtw && coverage.providerId != ks::action_analyze::etw::kProviderId) ||
        (coverage.rawSegmentOrdinal == 1 && coverage.planRawSequence != 1) ||
        coverage.endRawSequence != prefix.end.lastSequence || coverage.endRawSequence <= coverage.planRawSequence ||
        coverage.observationCount != coverage.endRawSequence - coverage.planRawSequence - 1) {
        return Failure(ProjectError::Corrupt, "checkpointRawRange");
    }
    std::uint64_t headerPid = 0; // 兼容原单PID计划，仍保留根筛选身份。
    std::vector<std::uint32_t> headerPidFilters; // 新混合ETW计划实际登记的报头PID集合，不表示事件时创建身份。
    bool continuous = false;
    Archive::RawEvidenceScanResult scan;
    const ProjectRawEvidenceRead request{project.Info()->projectId, sample.info.sampleId,
        coverage.rawSegmentOrdinal, prefix.end.byteOffset, coverage.planRawSequence - 1,
        [&](const auto&, const auto&, const auto& records) {
            for (const auto& record : records) {
                const auto& raw = std::get<Archive::RawRecordV1>(record.body);
                const auto doc = Evidence::ParseJson(raw.metadataJson);
                if (!doc.ok()) return false;
                if (record.recordSequence == coverage.planRawSequence) {
                    const auto* session = doc.value.find("session");
                    const auto* pid = doc.value.find("headerPid");
                    const auto* mixed = doc.value.find("mixedEtw");
                    bool mixedPlan = false;
                    if (lane == ProjectEvidenceLane::MixedEtw ?
                        (!mixed || !mixed->tryGetBool(mixedPlan) || !mixedPlan) : mixed != nullptr) return false;
                    if (raw.inlineRawBytes || !IsString(doc.value, "kind", "etw-capture-plan-v1") ||
                        !IsString(doc.value, "backend", "r3") || !session || !IsString(*session, "id", sample.info.sampleId) ||
                        !IsString(doc.value, "revisionId", sample.info.revisionId) ||
                        !IsString(doc.value, "snapshotId", sample.info.snapshotId) ||
                        !IsString(doc.value, "revisionHash", sample.revisionHash) ||
                        !IsString(doc.value, "configSemanticHash", sample.configSemanticHash) ||
                        !IsString(doc.value, "providerId", coverage.providerId) ||
                        !IsString(doc.value, "sourceEpoch", coverage.sourceEpoch) || !pid ||
                         pid->type() != JsonType::UInt || !pid->tryGetU64(headerPid) || !headerPid || headerPid > UINT32_MAX) return false;
                    headerPidFilters.push_back(static_cast<std::uint32_t>(headerPid));
                    if (const auto* filters = doc.value.find("headerPidFilters"))
                    {
                        // 旧计划没有列表时严格维持根PID；新列表必须非空、无重复并包含根。
                        const auto* members = filters->asArray(); // 同段计划冻结的实际过滤成员。
                        if (lane != ProjectEvidenceLane::MixedEtw || !members || members->empty()) return false;
                        headerPidFilters.clear();
                        for (const auto& value : *members)
                        {
                            std::uint64_t memberPid = 0; // 逐项核对原JSON数值，不接纳字符串或零。
                            if (value.type() != JsonType::UInt || !value.tryGetU64(memberPid) || !memberPid ||
                                memberPid > UINT32_MAX || std::find(headerPidFilters.begin(), headerPidFilters.end(),
                                    static_cast<std::uint32_t>(memberPid)) != headerPidFilters.end()) return false;
                            headerPidFilters.push_back(static_cast<std::uint32_t>(memberPid));
                        }
                        if (std::find(headerPidFilters.begin(), headerPidFilters.end(), headerPid) == headerPidFilters.end()) return false;
                    }
                    const auto* duration = doc.value.find("durationMs");
                    std::uint64_t ms = 0;
                    continuous = duration && duration->type() == Evidence::JsonType::UInt && duration->tryGetU64(ms) && ms == 0;
                    if (coverage.rawSegmentOrdinal > 1 && !continuous) return false;
                } else if (record.recordSequence == coverage.endRawSequence) {
                    const auto* source = doc.value.find("source");
                    if (continuous) {
                        const auto* final = doc.value.find("finalSegment"); // 区别普通分段与整次采样终止。
                        if (!source || !final || !final->tryGetBool(checkpoint.finalSegment) ||
                            checkpoint.finalSegment == IsString(doc.value, "stopReason", "segment-rotated") ||
                            (checkpoint.finalSegment && !MatchesCount(*source, "queued", 0))) return false;
                    }
                    if (raw.inlineRawBytes || !IsString(doc.value, "kind", "etw-capture-end-v1") || !source ||
                        !IsString(*source, "sourceEpoch", coverage.sourceEpoch) ||
                        (continuous ? !MatchesCount(doc.value, "segmentObservations", coverage.observationCount) :
                            (!MatchesCount(*source, "enqueued", coverage.observationCount) || !MatchesCount(*source, "queued", 0))) ||
                        !MatchesStatistic(*source, "eventsLost", coverage.eventsLost) ||
                        !MatchesStatistic(*source, "logBuffersLost", coverage.logBuffersLost) ||
                        !MatchesStatistic(*source, "realTimeBuffersLost", coverage.realTimeBuffersLost) ||
                        !MatchesCount(*source, "queueDropped", coverage.queueDropped) ||
                        !MatchesCount(*source, "payloadTruncated", coverage.payloadTruncated) ||
                        !MatchesCount(*source, "malformedPayload", coverage.malformedPayload)) return false;
                } else {
                    const auto observation = Evidence::ReadArchivedEtwObservation(doc.value, raw.inlineRawBytes);
                    if (!observation || observation->providerId != coverage.providerId ||
                        observation->sourceEpoch != coverage.sourceEpoch ||
                        std::find(headerPidFilters.begin(), headerPidFilters.end(), observation->headerPid) == headerPidFilters.end()) return false;
                }
            }
            return true;
         }, kRawLimit, lane};
    std::string hash;
    if (const auto result = project.ReadRawEvidenceSegment(request, scan, &hash); !result) return result;
    if (!scan.VerifiedBoundary(prefix.end) || hash.empty() || (!prefix.sha256.empty() && hash != prefix.sha256)) {
        return Failure(ProjectError::Corrupt, "checkpointRawPrefix");
    }
    prefix.sha256 = std::move(hash);
    return {};
}

ProjectResult VerifyRecords(const Directory& root, const Archive::SegmentIdentity& identity, std::string_view sampleId,
                            EtwCheckpointPrefix& prefix, EtwCoverageV1& coverage, ProjectEvidenceLane lane) {
    const auto name = Archive::NameInspectionSegment(identity);
    if (!name || prefix.end.blockOrdinal != 1 || prefix.end.lastSequence != identity.ordinal ||
        prefix.end.byteOffset > Archive::kSegmentHeaderBytes + Archive::kMaxEtwCoverageV1Bytes + 256) {
        return Failure(ProjectError::Corrupt, "checkpointRecordsRange");
    }
    Directory directory;
    if (const auto result = OpenDirectory(root, {L"samples", WideAscii(sampleId), RecordsDirectory(lane)}, directory); !result) return result;
    Handle file;
    if (const auto result = OpenFile(directory, name->fileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, file); !result) return result;
    bool valid = false;
    const auto scan = Archive::ScanOpenSegmentBodies(file.get(), identity, prefix.end.byteOffset,
        [&](const auto&, const auto& block, const auto& records) {
            if (block.ordinal != 1 || records.size() != 1 || records.front().recordSequence != identity.ordinal) return false;
            if (const auto* body = std::get_if<EtwCoverageV1>(&records.front().body)) {
                coverage = *body;
                valid = true;
            }
            return valid;
        });
    if (!valid || scan.framing.status != Archive::SegmentScanStatus::FramingComplete ||
        scan.bodyFailure.issue != Archive::BodyIssue::None || scan.bodyCheckedBlocks != 1 ||
        scan.bodyCheckedBytes != prefix.end.byteOffset) {
        return Failure(ProjectError::Corrupt, "checkpointRecordsPrefix");
    }
    std::string hash;
    if (const auto result = HashArchivePrefix(file.get(), prefix.end.byteOffset, hash); !result) return result;
    if (!prefix.sha256.empty() && hash != prefix.sha256) return Failure(ProjectError::Corrupt, "checkpointRecordsHash");
    prefix.sha256 = std::move(hash);
    return {};
}

Archive::SegmentIdentity RecordsIdentity(const ProjectInfo& project, const SampleRecord& sample, std::uint64_t ordinal) {
    return {Archive::StreamKind::Records, ordinal, UuidBytes(project.projectId), UuidBytes(sample.info.sampleId)};
}

} // namespace

ProjectResult ProjectDocument::PublishEtwCheckpoint(std::string_view sampleId, const Archive::RawEvidenceBoundary& rawEnd,
                                                     const EtwCoverageV1& coverage, ProjectEtwCheckpoint& out,
                                                     ProjectEvidenceLane lane) {
    out = {};
    const auto* root = RootForRead();
    if (!root) return Failure(ProjectError::NotOpen, "project");
    if (Info()->access != ProjectAccess::ReadWrite) return Failure(ProjectError::ReadOnly, "project");
    SampleRecord sample;
    if (const auto result = ReadSample(sampleId, sample); !result) return result;
    std::vector<std::uint8_t> bytes;
    if (Archive::EncodeEtwCoverageV1(coverage, bytes) != Archive::BodyIssue::None) {
        return Failure(ProjectError::InvalidArgument, "checkpointCoverage");
    }
    ProjectEtwCheckpoint draft;
    draft.raw.end = rawEnd;
    if (const auto result = VerifyRaw(*this, sample, coverage, draft, lane); !result) return result;

    const auto ordinal = coverage.rawSegmentOrdinal;
    const auto identity = RecordsIdentity(*Info(), sample, ordinal);
    const auto name = Archive::NameInspectionSegment(identity);
    if (!name) return Failure(ProjectError::InvalidArgument, "checkpointRecordsIdentity");
    const auto sampleDirectory = WideAscii(sample.info.sampleId);
    Directory records;
    const auto recordPath = {std::wstring_view(L"samples"), std::wstring_view(sampleDirectory), RecordsDirectory(lane)};
    auto directoryResult = OpenDirectory(*root, recordPath, records);
    if (directoryResult.error == ProjectError::NotFound) {
        directoryResult = OpenDirectory(*root, recordPath, records, true);
    }
    if (!directoryResult) return directoryResult;
    Archive::SegmentWriter writer(std::filesystem::path(records.path) / name->fileName, {identity, UtcNow()}, ordinal - 1);
    auto written = writer.AppendBlock({{Archive::kCoverageRecordType, 1, Archive::kRequiredRecord, ordinal, std::move(bytes)}});
    if (written.status == Archive::SegmentWriteStatus::Ok) written = writer.Flush();
    if (written.status == Archive::SegmentWriteStatus::Ok) written = writer.Close();
    if (written.status != Archive::SegmentWriteStatus::Ok) return Failure(ProjectError::IoError, "checkpointRecordsWrite", written.error.win32Error);
    draft.records.end = {writer.FlushedBytes(), 1, ordinal};
    draft.planRawSequence = coverage.planRawSequence;
    EtwCoverageV1 checked;
    if (const auto result = VerifyRecords(*root, identity, sampleId, draft.records, checked, lane); !result) return result;
    if (const auto result = VerifyRaw(*this, sample, checked, draft, lane); !result) return result;

    Directory checkpoints;
    const auto markerPath = {std::wstring_view(L"samples"), std::wstring_view(sampleDirectory), CheckpointDirectory(lane)};
    directoryResult = OpenDirectory(*root, markerPath, checkpoints);
    if (directoryResult.error == ProjectError::NotFound) {
        directoryResult = OpenDirectory(*root, markerPath, checkpoints, true);
    }
    if (!directoryResult) return directoryResult;
    const auto document = Object({{"kind", Text("etw-terminal-checkpoint-v1")}, {"generation", Number(ordinal)},
        {"projectId", Text(Info()->projectId)}, {"sampleId", Text(sample.info.sampleId)},
        {"descriptionHash", Text(sample.info.descriptionHash)}, {"raw", PrefixDocument(draft.raw, ordinal)},
        {"records", PrefixDocument(draft.records, ordinal)}});
    if (const auto result = Publish(*root, markerPath, CheckpointFile(ordinal), document, false); !result) return result;
    out = std::move(draft);
    return {};
}

// 从项目快照读取采样描述与终态标记，只有标记缺失时返回 NotFound。
ProjectResult ProjectDocument::ReadEtwCheckpoint(std::string_view sampleId, ProjectEtwCheckpoint& out,
                                                 std::uint64_t ordinal, ProjectEvidenceLane lane) const {
    out = {};
    if (!ordinal) return Failure(ProjectError::InvalidArgument, "checkpointOrdinal");
    const auto* root = RootForRead(); // 当前项目持有的目录句柄。
    if (!root) return Failure(ProjectError::NotOpen, "project");
    SampleRecord sample; // 已登记采样及其冻结描述。
    if (const auto result = ReadSample(sampleId, sample); !result) {
        return result.error == ProjectError::NotFound ? Failure(ProjectError::Corrupt, "checkpointSampleMissing") : result;
    }
    JsonValue document; // 本次读取的检查点标记。
    if (const auto result = Read(*root, {L"samples", WideAscii(sample.info.sampleId), CheckpointDirectory(lane)},
            CheckpointFile(ordinal), {}, document); !result) return result;
    ProjectEtwCheckpoint checked;
    std::uint64_t generation = 0;
    if (!Fields(document, {"kind", "generation", "projectId", "sampleId", "descriptionHash", "raw", "records"}) ||
        !IsString(document, "kind", "etw-terminal-checkpoint-v1") || !GetNumber(document, "generation", generation) || generation != ordinal ||
        !IsString(document, "projectId", Info()->projectId) || !IsString(document, "sampleId", sample.info.sampleId) ||
        !IsString(document, "descriptionHash", sample.info.descriptionHash) ||
        !ReadPrefix(document.find("raw"), checked.raw, ordinal) || !ReadPrefix(document.find("records"), checked.records, ordinal)) {
        return Failure(ProjectError::Corrupt, "checkpointDocument");
    }
    EtwCoverageV1 coverage;
    if (const auto result = VerifyRecords(*root, RecordsIdentity(*Info(), sample, ordinal), sampleId, checked.records, coverage, lane); !result) {
        return result.error == ProjectError::NotFound ? Failure(ProjectError::Corrupt, "checkpointRecordsMissing") : result;
    }
    if (coverage.rawSegmentOrdinal != ordinal) return Failure(ProjectError::Corrupt, "checkpointOrdinalMismatch");
    if (const auto result = VerifyRaw(*this, sample, coverage, checked, lane); !result) {
        return result.error == ProjectError::NotFound ? Failure(ProjectError::Corrupt, "checkpointRawMissing") : result;
    }
    checked.planRawSequence = coverage.planRawSequence;
    out = std::move(checked);
    return {};
}

} // namespace Ksword::ActionAnalyze
