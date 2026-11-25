#include "ProjectEtwCheckpoint.h"

#include "ProjectRawEvidence.h"
#include "ProjectStorage.h"
#include "../Archive/SegmentInspection.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"

namespace Ksword::ActionAnalyze {
namespace {

namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
using Archive::EtwCoverageV1;
constexpr std::wstring_view kCheckpointFile = L"00000000000000000001.json";
constexpr std::uint64_t kRawLimit = 4u << 20;

JsonValue PrefixDocument(const EtwCheckpointPrefix& prefix) {
    return Object({{"ordinal", Number(1)}, {"block", Number(prefix.end.blockOrdinal)},
        {"endOffset", Number(prefix.end.byteOffset)}, {"lastSequence", Number(prefix.end.lastSequence)},
        {"sha256", Text(prefix.sha256)}});
}

bool ReadPrefix(const JsonValue* doc, EtwCheckpointPrefix& prefix) {
    if (!doc || !Fields(*doc, {"ordinal", "block", "endOffset", "lastSequence", "sha256"})) return false;
    return IsString(*doc, "ordinal", "1") && GetNumber(*doc, "block", prefix.end.blockOrdinal) &&
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
                        EtwCheckpointPrefix& prefix) {
    if (coverage.rawSegmentOrdinal != 1 || coverage.planRawSequence != 1 ||
        coverage.endRawSequence != prefix.end.lastSequence || coverage.observationCount + 2 != coverage.endRawSequence) {
        return Failure(ProjectError::Corrupt, "checkpointRawRange");
    }
    std::uint64_t headerPid = 0;
    Archive::RawEvidenceScanResult scan;
    const ProjectRawEvidenceRead request{project.Info()->projectId, sample.info.sampleId, 1, prefix.end.byteOffset, 0,
        [&](const auto&, const auto&, const auto& records) {
            for (const auto& record : records) {
                const auto& raw = std::get<Archive::RawRecordV1>(record.body);
                const auto doc = Evidence::ParseJson(raw.metadataJson);
                if (!doc.ok()) return false;
                if (record.recordSequence == coverage.planRawSequence) {
                    const auto* session = doc.value.find("session");
                    const auto* pid = doc.value.find("headerPid");
                    if (raw.inlineRawBytes || !IsString(doc.value, "kind", "etw-capture-plan-v1") ||
                        !IsString(doc.value, "backend", "r3") || !session || !IsString(*session, "id", sample.info.sampleId) ||
                        !IsString(doc.value, "revisionId", sample.info.revisionId) ||
                        !IsString(doc.value, "snapshotId", sample.info.snapshotId) ||
                        !IsString(doc.value, "revisionHash", sample.revisionHash) ||
                        !IsString(doc.value, "configSemanticHash", sample.configSemanticHash) ||
                        !IsString(doc.value, "providerId", coverage.providerId) ||
                        !IsString(doc.value, "sourceEpoch", coverage.sourceEpoch) || !pid ||
                        pid->type() != JsonType::UInt || !pid->tryGetU64(headerPid) || !headerPid || headerPid > UINT32_MAX) return false;
                } else if (record.recordSequence == coverage.endRawSequence) {
                    const auto* source = doc.value.find("source");
                    if (raw.inlineRawBytes || !IsString(doc.value, "kind", "etw-capture-end-v1") || !source ||
                        !IsString(*source, "sourceEpoch", coverage.sourceEpoch) ||
                        !MatchesCount(*source, "enqueued", coverage.observationCount) || !MatchesCount(*source, "queued", 0) ||
                        !MatchesStatistic(*source, "eventsLost", coverage.eventsLost) ||
                        !MatchesStatistic(*source, "logBuffersLost", coverage.logBuffersLost) ||
                        !MatchesStatistic(*source, "realTimeBuffersLost", coverage.realTimeBuffersLost) ||
                        !MatchesCount(*source, "queueDropped", coverage.queueDropped) ||
                        !MatchesCount(*source, "payloadTruncated", coverage.payloadTruncated) ||
                        !MatchesCount(*source, "malformedPayload", coverage.malformedPayload)) return false;
                } else {
                    const auto observation = Evidence::ReadArchivedEtwObservation(doc.value, raw.inlineRawBytes);
                    if (!observation || observation->providerId != coverage.providerId ||
                        observation->sourceEpoch != coverage.sourceEpoch || observation->headerPid != headerPid) return false;
                }
            }
            return true;
        }, kRawLimit};
    std::string hash;
    if (const auto result = project.ReadRawEvidenceSegment(request, scan, &hash); !result) return result;
    if (!scan.VerifiedBoundary(prefix.end) || hash.empty() || (!prefix.sha256.empty() && hash != prefix.sha256)) {
        return Failure(ProjectError::Corrupt, "checkpointRawPrefix");
    }
    prefix.sha256 = std::move(hash);
    return {};
}

ProjectResult VerifyRecords(const Directory& root, const Archive::SegmentIdentity& identity, std::string_view sampleId,
                            EtwCheckpointPrefix& prefix, EtwCoverageV1& coverage) {
    const auto name = Archive::NameInspectionSegment(identity);
    if (!name || prefix.end.blockOrdinal != 1 || prefix.end.lastSequence != 1 ||
        prefix.end.byteOffset > Archive::kSegmentHeaderBytes + Archive::kMaxEtwCoverageV1Bytes + 256) {
        return Failure(ProjectError::Corrupt, "checkpointRecordsRange");
    }
    Directory directory;
    if (const auto result = OpenDirectory(root, {L"samples", WideAscii(sampleId), name->streamDirectory}, directory); !result) return result;
    Handle file;
    if (const auto result = OpenFile(directory, name->fileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, file); !result) return result;
    bool valid = false;
    const auto scan = Archive::ScanOpenSegmentBodies(file.get(), identity, prefix.end.byteOffset,
        [&](const auto&, const auto& block, const auto& records) {
            if (block.ordinal != 1 || records.size() != 1 || records.front().recordSequence != 1) return false;
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
    if (const auto result = HashArchivePrefix(file, prefix.end.byteOffset, hash); !result) return result;
    if (!prefix.sha256.empty() && hash != prefix.sha256) return Failure(ProjectError::Corrupt, "checkpointRecordsHash");
    prefix.sha256 = std::move(hash);
    return {};
}

Archive::SegmentIdentity RecordsIdentity(const ProjectInfo& project, const SampleRecord& sample) {
    return {Archive::StreamKind::Records, 1, UuidBytes(project.projectId), UuidBytes(sample.info.sampleId)};
}

} // namespace

ProjectResult ProjectDocument::PublishEtwCheckpoint(std::string_view sampleId, const Archive::RawEvidenceBoundary& rawEnd,
                                                    const EtwCoverageV1& coverage, ProjectEtwCheckpoint& out) {
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
    if (const auto result = VerifyRaw(*this, sample, coverage, draft.raw); !result) return result;

    const auto identity = RecordsIdentity(*Info(), sample);
    const auto name = Archive::NameInspectionSegment(identity);
    if (!name) return Failure(ProjectError::InvalidArgument, "checkpointRecordsIdentity");
    const auto sampleDirectory = WideAscii(sample.info.sampleId);
    Directory records;
    if (const auto result = OpenDirectory(*root, {L"samples", sampleDirectory, name->streamDirectory}, records, true); !result) return result;
    Archive::SegmentWriter writer(std::filesystem::path(records.path) / name->fileName, {identity, UtcNow()}, 0);
    auto written = writer.AppendBlock({{Archive::kCoverageRecordType, 1, Archive::kRequiredRecord, 1, std::move(bytes)}});
    if (written.status == Archive::SegmentWriteStatus::Ok) written = writer.Flush();
    if (written.status == Archive::SegmentWriteStatus::Ok) written = writer.Close();
    if (written.status != Archive::SegmentWriteStatus::Ok) return Failure(ProjectError::IoError, "checkpointRecordsWrite", written.error.win32Error);
    draft.records.end = {writer.FlushedBytes(), 1, 1};
    EtwCoverageV1 checked;
    if (const auto result = VerifyRecords(*root, identity, sampleId, draft.records, checked); !result) return result;
    if (const auto result = VerifyRaw(*this, sample, checked, draft.raw); !result) return result;

    Directory checkpoints;
    if (const auto result = OpenDirectory(*root, {L"samples", sampleDirectory, L"checkpoints"}, checkpoints, true); !result) return result;
    const auto document = Object({{"kind", Text("etw-terminal-checkpoint-v1")}, {"generation", Number(1)},
        {"projectId", Text(Info()->projectId)}, {"sampleId", Text(sample.info.sampleId)},
        {"descriptionHash", Text(sample.info.descriptionHash)}, {"raw", PrefixDocument(draft.raw)},
        {"records", PrefixDocument(draft.records)}});
    if (const auto result = Publish(*root, {L"samples", sampleDirectory, L"checkpoints"}, kCheckpointFile, document, false); !result) return result;
    out = std::move(draft);
    return {};
}

ProjectResult ProjectDocument::ReadEtwCheckpoint(std::string_view sampleId, ProjectEtwCheckpoint& out) const {
    out = {};
    const auto* root = RootForRead();
    if (!root) return Failure(ProjectError::NotOpen, "project");
    SampleRecord sample;
    if (const auto result = ReadSample(sampleId, sample); !result) return result;
    JsonValue document;
    if (const auto result = Read(*root, {L"samples", WideAscii(sample.info.sampleId), L"checkpoints"},
            kCheckpointFile, {}, document); !result) return result;
    ProjectEtwCheckpoint checked;
    if (!Fields(document, {"kind", "generation", "projectId", "sampleId", "descriptionHash", "raw", "records"}) ||
        !IsString(document, "kind", "etw-terminal-checkpoint-v1") || !IsString(document, "generation", "1") ||
        !IsString(document, "projectId", Info()->projectId) || !IsString(document, "sampleId", sample.info.sampleId) ||
        !IsString(document, "descriptionHash", sample.info.descriptionHash) ||
        !ReadPrefix(document.find("raw"), checked.raw) || !ReadPrefix(document.find("records"), checked.records)) {
        return Failure(ProjectError::Corrupt, "checkpointDocument");
    }
    EtwCoverageV1 coverage;
    if (const auto result = VerifyRecords(*root, RecordsIdentity(*Info(), sample), sampleId, checked.records, coverage); !result) {
        return result.error == ProjectError::NotFound ? Failure(ProjectError::Corrupt, "checkpointRecordsMissing") : result;
    }
    if (const auto result = VerifyRaw(*this, sample, coverage, checked.raw); !result) {
        return result.error == ProjectError::NotFound ? Failure(ProjectError::Corrupt, "checkpointRawMissing") : result;
    }
    out = std::move(checked);
    return {};
}

} // namespace Ksword::ActionAnalyze
