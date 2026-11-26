#include "ProjectSysmonEvidence.h"

#include "ProjectStorage.h"

#include <array>
#include <limits>
#include <utility>

namespace Ksword::ActionAnalyze {

struct ProjectSysmonEvidenceAccess {
    static const ProjectStorage::Directory* Root(const ProjectDocument& project) { return project.RootForRead(); }
};

namespace {

namespace Archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
using Detection::SysmonLimit;
using Detection::SysmonReadState;
using Detection::SysmonThreadFields;
using Detection::SysmonThreadObservation;
using Detection::SysmonThreadQuery;

constexpr auto kMarkerName = L"sysmon-retained-1.json";
constexpr auto kMarkerKind = "sysmon-retained-checkpoint-v1";
constexpr auto kPlanKind = "sysmon-retained-plan-v1";
constexpr auto kObservationKind = "sysmon-event8-v2-observation";
constexpr auto kEndKind = "sysmon-retained-end-v1";
constexpr auto kScope = "local-windows-event-log";
constexpr auto kIdentity = "sysmon-process-guid";
constexpr auto kNotObserved = "not-observed-by-this-source";
constexpr std::uint64_t kOrdinal = 1;
constexpr std::size_t kMaxFieldChars = 1024; // Mirrors the native rendered-field cap.
constexpr std::size_t kMaxMetadataBytes = 32 * 1024; // Five escaped UTF-16 fields and the fixed envelope.
constexpr auto kMaxBlockBytes = (Detection::kSysmonMaxMatches + 2) *
    (Archive::kRecordHeaderBytes + Archive::kRawRecordV1PrefixBytes + kMaxMetadataBytes);
static_assert(kMaxBlockBytes <= Archive::kMaxDecodedBlockBytes);
constexpr auto kMaxFileBytes = Archive::kSegmentHeaderBytes + Archive::kBlockHeaderBytes + kMaxBlockBytes;

constexpr std::array kLimits{
    std::pair{SysmonLimit::None, std::string_view("none")},
    std::pair{SysmonLimit::Scan, std::string_view("scan-limit")},
    std::pair{SysmonLimit::Matches, std::string_view("match-limit")},
    std::pair{SysmonLimit::Time, std::string_view("read-budget")}};

std::optional<std::string> EncodeText(std::wstring_view text)
{
    if (text.size() > kMaxFieldChars || text.find(L'\0') != text.npos) return std::nullopt;
    if (text.empty()) return std::string{};
    const auto chars = static_cast<int>(text.size());
    const auto bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), chars, nullptr, 0, nullptr, nullptr);
    if (!bytes) return std::nullopt;
    std::string result(static_cast<std::size_t>(bytes), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), chars, result.data(), bytes, nullptr, nullptr)) {
        return std::nullopt;
    }
    return result;
}

bool GetWideText(const JsonValue& object, std::string_view key, std::wstring& out)
{
    std::string text;
    if (!GetString(object, key, text) || text.size() > 4 * kMaxFieldChars || text.find('\0') != text.npos) return false;
    if (text.empty()) { out.clear(); return true; }
    const auto bytes = static_cast<int>(text.size());
    const auto chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), bytes, nullptr, 0);
    if (!chars || static_cast<std::size_t>(chars) > kMaxFieldChars) return false;
    out.resize(static_cast<std::size_t>(chars));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), bytes, out.data(), chars) == chars;
}

bool GetOptionalWide(const JsonValue& object, std::string_view key, std::optional<std::wstring>& out)
{
    if (IsNull(object, key)) { out.reset(); return true; }
    return GetWideText(object, key, out.emplace());
}

bool GetU32(const JsonValue& object, std::string_view key, std::uint32_t& out)
{
    std::uint64_t value = 0;
    if (!GetNumber(object, key, value) || value > (std::numeric_limits<std::uint32_t>::max)()) return false;
    out = static_cast<std::uint32_t>(value);
    return true;
}

bool ValidQuery(const SysmonThreadQuery& query)
{
    const auto target = Detection::NormalizeSysmonGuid(query.targetGuid);
    return target && *target == query.targetGuid && query.maxMatches > 0 && query.maxMatches <= Detection::kSysmonMaxMatches &&
        (!query.recordId || *query.recordId != 0);
}

bool ValidBoundary(const ProjectSysmonEvidenceReceipt& data, std::size_t count)
{
    const auto invalidRows = std::uint64_t{data.unsupportedVersions} + data.malformed + data.renderFailed;
    if (count > data.query.maxMatches || invalidRows + count > data.examined ||
        data.examined > Detection::kSysmonScanLimit || (data.query.recordId && count > 1) ||
        ((data.nativeError != 0) != !data.nativeStage.empty()) || (data.renderFailed && !data.nativeError)) return false;

    if (data.reachedEnd && (data.sourceLimit != SysmonLimit::None || (data.nativeError && !data.renderFailed))) return false;
    if (data.nativeError && !data.examined) return false;
    if (data.sourceLimit == SysmonLimit::Scan && data.examined != Detection::kSysmonScanLimit) return false;
    if (data.sourceLimit == SysmonLimit::Matches && count != data.query.maxMatches) return false;
    const bool exhausted = data.reachedEnd && invalidRows == 0 && !data.nativeError;
    if (data.sourceState == SysmonReadState::Exhausted) return exhausted;
    return data.sourceState == SysmonReadState::Partial && !exhausted &&
        (data.reachedEnd || data.sourceLimit != SysmonLimit::None || data.nativeError);
}

JsonValue EncodePlan(const SampleRecord& sample, const ProjectSysmonEvidenceReceipt& data)
{
    return Object({{"kind", Text(kPlanKind)}, {"projectId", Text(data.projectId)}, {"sampleId", Text(data.sampleId)},
        {"descriptionHash", Text(sample.info.descriptionHash)}, {"scope", Text(kScope)}, {"order", Text("reverse-record-id")},
        {"channel", Text("Microsoft-Windows-Sysmon/Operational")}, {"provider", Text("Microsoft-Windows-Sysmon")},
        {"providerGuid", Text("5770385f-c22a-43e0-bf4c-06f5698ffbd9")},
        {"eventId", Number(Detection::kSysmonThreadEventId)}, {"eventVersion", Number(Detection::kSysmonThreadEventVersion)},
        {"targetGuid", Text(EncodeText(data.query.targetGuid).value())},
        {"eventRecordId", data.query.recordId ? Number(*data.query.recordId) : JsonValue::makeNull()},
        {"maxMatches", Number(data.query.maxMatches)}, {"scanLimit", Number(Detection::kSysmonScanLimit)},
        {"readBudgetMs", Number(Detection::kSysmonReadBudgetMs)}, {"coverage", Text("unknown")},
        {"processIdentity", Text(kIdentity)},
        {"nativeProcessInstance", JsonValue::makeNull()}, {"nativeThreadInstance", JsonValue::makeNull()},
        {"execution", Text(kNotObserved)}, {"memoryWrite", Text(kNotObserved)}});
}

bool DecodePlan(const JsonValue& doc, const SampleRecord& sample, ProjectSysmonEvidenceReceipt& out)
{
    std::uint64_t recordId = 0;
    if (!IsNull(doc, "eventRecordId")) {
        if (!GetNumber(doc, "eventRecordId", recordId)) return false;
        out.query.recordId = recordId;
    }
    if (!GetWideText(doc, "targetGuid", out.query.targetGuid) || !GetU32(doc, "maxMatches", out.query.maxMatches) ||
        !ValidQuery(out.query)) return false;
    // The plan is fixed apart from the validated query and the already resolved sample identity.
    auto expected = EncodePlan(sample, out);
    for (const auto& [key, value] : *expected.asObject()) {
        const auto* actual = doc.find(key);
        if (!actual || Evidence::WriteJson(*actual) != Evidence::WriteJson(value)) return false;
    }
    const auto* fields = doc.asObject();
    return fields && fields->size() == expected.asObject()->size();
}

std::optional<JsonValue> EncodeObservation(const SysmonThreadFields& fields)
{
    JsonObject values{{"kind", Text(kObservationKind)}, {"eventId", Number(fields.eventId)},
        {"eventVersion", Number(*fields.version)}, {"eventRecordId", Number(fields.recordId)},
        {"timeCreatedFileTime", Number(fields.timeCreatedFileTime)}, {"sourcePid", Number(fields.sourcePid)},
        {"targetPid", Number(fields.targetPid)}, {"newThreadId", Number(fields.newThreadId)}};
    const auto append = [&](const char* key, std::wstring_view text) {
        auto value = EncodeText(text);
        if (!value) return false;
        values.emplace_back(key, JsonValue::makeString(std::move(*value)));
        return true;
    };
    const auto appendOptional = [&](const char* key, const std::optional<std::wstring>& text) {
        if (text) return append(key, *text);
        values.emplace_back(key, JsonValue::makeNull());
        return true;
    };
    if (!append("channel", fields.channel) || !append("provider", fields.provider) ||
        !append("providerGuid", fields.providerGuid) || !append("computer", fields.computer) ||
        !append("sourceGuid", fields.sourceGuid) || !append("targetGuid", fields.targetGuid) ||
        !append("startAddress", fields.startAddress) || !appendOptional("sourceImage", fields.sourceImage) ||
        !appendOptional("targetImage", fields.targetImage) || !appendOptional("startModule", fields.startModule) ||
        !appendOptional("startFunction", fields.startFunction)) return std::nullopt;
    return Object(std::move(values));
}

std::optional<SysmonThreadObservation> DecodeObservation(const JsonValue& doc, const SysmonThreadQuery& query)
{
    SysmonThreadFields fields;
    if (!Fields(doc, {"kind", "channel", "provider", "providerGuid", "computer", "eventId", "eventVersion",
            "eventRecordId", "timeCreatedFileTime", "sourceGuid", "targetGuid", "sourcePid", "targetPid", "newThreadId",
            "startAddress", "sourceImage", "targetImage", "startModule", "startFunction"}) ||
        !IsString(doc, "kind", kObservationKind) || !GetWideText(doc, "channel", fields.channel) ||
        !GetWideText(doc, "provider", fields.provider) || !GetWideText(doc, "providerGuid", fields.providerGuid) ||
        !GetWideText(doc, "computer", fields.computer) || !GetU32(doc, "eventId", fields.eventId) ||
        !GetU32(doc, "eventVersion", fields.version.emplace()) || !GetNumber(doc, "eventRecordId", fields.recordId) ||
        !GetNumber(doc, "timeCreatedFileTime", fields.timeCreatedFileTime) || !GetWideText(doc, "sourceGuid", fields.sourceGuid) ||
        !GetWideText(doc, "targetGuid", fields.targetGuid) || !GetU32(doc, "sourcePid", fields.sourcePid) ||
        !GetU32(doc, "targetPid", fields.targetPid) || !GetU32(doc, "newThreadId", fields.newThreadId) ||
        !GetWideText(doc, "startAddress", fields.startAddress) || !GetOptionalWide(doc, "sourceImage", fields.sourceImage) ||
        !GetOptionalWide(doc, "targetImage", fields.targetImage) || !GetOptionalWide(doc, "startModule", fields.startModule) ||
        !GetOptionalWide(doc, "startFunction", fields.startFunction) || (query.recordId && fields.recordId != *query.recordId)) {
        return std::nullopt;
    }
    auto decoded = Detection::DecodeSysmonThreadEvent(query.targetGuid, fields);
    if (!decoded.observation || decoded.observation->fields.providerGuid != fields.providerGuid ||
        decoded.observation->fields.sourceGuid != fields.sourceGuid || decoded.observation->fields.targetGuid != fields.targetGuid) {
        return std::nullopt;
    }
    return std::move(decoded.observation);
}

std::optional<JsonValue> EncodeEnd(const ProjectSysmonEvidenceReceipt& data, std::size_t count)
{
    std::string_view limitText;
    for (const auto& [limit, text] : kLimits) if (data.sourceLimit == limit) limitText = text;
    const auto stage = EncodeText(data.nativeStage);
    if (limitText.empty() || !stage) return std::nullopt;
    return Object({{"kind", Text(kEndKind)}, {"observationCount", Number(count)},
        {"state", Text(data.sourceState == SysmonReadState::Exhausted ? "retained-log-exhausted" : "partial")},
        {"limit", Text(limitText)}, {"examined", Number(data.examined)}, {"unsupportedVersions", Number(data.unsupportedVersions)},
        {"malformed", Number(data.malformed)}, {"renderFailed", Number(data.renderFailed)}, {"nativeStage", Text(*stage)},
        {"nativeError", Number(data.nativeError)}, {"reachedEnd", JsonValue::makeBool(data.reachedEnd)}});
}

bool DecodeEnd(const JsonValue& doc, ProjectSysmonEvidenceReceipt& out)
{
    std::uint64_t count = 0;
    std::string state, limit;
    if (!Fields(doc, {"kind", "observationCount", "state", "limit", "examined", "unsupportedVersions", "malformed",
            "renderFailed", "nativeStage", "nativeError", "reachedEnd"}) || !IsString(doc, "kind", kEndKind) ||
        !GetNumber(doc, "observationCount", count) || count != out.records.size() || !GetString(doc, "state", state) ||
        !GetString(doc, "limit", limit) || !GetU32(doc, "examined", out.examined) ||
        !GetU32(doc, "unsupportedVersions", out.unsupportedVersions) || !GetU32(doc, "malformed", out.malformed) ||
        !GetU32(doc, "renderFailed", out.renderFailed) || !GetWideText(doc, "nativeStage", out.nativeStage) ||
        !GetU32(doc, "nativeError", out.nativeError) || !doc.find("reachedEnd")->tryGetBool(out.reachedEnd)) return false;

    if (state == "retained-log-exhausted") out.sourceState = SysmonReadState::Exhausted;
    else if (state == "partial") out.sourceState = SysmonReadState::Partial;
    else return false;
    for (const auto& [value, text] : kLimits) {
        if (limit == text) {
            out.sourceLimit = value;
            return ValidBoundary(out, out.records.size());
        }
    }
    return false;
}

ProjectResult Scan(const ProjectDocument& project, const SampleRecord& sample,
    std::span<const std::string> expectedMetadata, ProjectSysmonEvidenceReceipt& out)
{
    ProjectSysmonEvidenceReceipt draft;
    draft.projectId = project.Info()->projectId;
    draft.sampleId = sample.info.sampleId;
    bool terminal = false;
    const ProjectRawEvidenceRead request{draft.projectId, draft.sampleId, kOrdinal, std::nullopt, 0,
        [&](const auto&, const auto& block, const auto& records) {
            if (block.ordinal != 1 || block.receiveQpc || records.size() < 2 ||
                records.size() > Detection::kSysmonMaxMatches + 2 ||
                (!expectedMetadata.empty() && records.size() != expectedMetadata.size())) return false;
            for (std::size_t i = 0; i < records.size(); ++i) {
                const auto& record = records[i];
                const auto& raw = std::get<Archive::RawRecordV1>(record.body);
                if (record.flags || raw.inlineRawBytes || raw.metadataJson.size() > kMaxMetadataBytes ||
                    (!expectedMetadata.empty() && raw.metadataJson != expectedMetadata[i])) return false;
                const auto json = Evidence::ParseJson(raw.metadataJson);
                if (!json.ok()) return false;
                if (i == 0) {
                    if (!DecodePlan(json.value, sample, draft) || records.size() > draft.query.maxMatches + 2) return false;
                    draft.records.reserve(records.size() - 2);
                } else if (i + 1 == records.size()) {
                    terminal = DecodeEnd(json.value, draft);
                    if (!terminal) return false;
                } else {
                    auto observation = DecodeObservation(json.value, draft.query);
                    if (!observation || (!draft.records.empty() &&
                        observation->fields.recordId >= draft.records.back().observation.fields.recordId)) return false;
                    draft.records.push_back({std::move(*observation), record.recordSequence, record.recordOffset});
                }
            }
            return true;
        }, kMaxFileBytes};
    Archive::RawEvidenceScanResult result;
    if (const auto status = project.ReadRawEvidenceSegment(request, result, &draft.prefixSha256); !status) return status;
    const auto& framing = result.segment.framing;
    if (framing.status == Archive::SegmentScanStatus::IoError) return WinFailure("sysmonRawRead", framing.error.win32Error);
    if (!terminal || !result.checked || !result.VerifiedBoundary(*result.checked) || !framing.fileSizeKnown ||
        !IsHash(draft.prefixSha256) || result.checked->byteOffset != framing.fileBytes || result.checked->blockOrdinal != 1 ||
        result.checked->lastSequence != draft.records.size() + 2) return Failure(ProjectError::Corrupt, "sysmonRawTail");
    draft.boundary = *result.checked;
    out = std::move(draft);
    return {};
}

} // namespace

ProjectResult WriteInitialSysmonEvidence(ProjectDocument& project, std::string_view sampleId,
    const SysmonThreadQuery& query, const Detection::SysmonThreadReadResult& source, ProjectSysmonEvidenceReceipt& out)
{
    out = {};
    const auto* root = ProjectSysmonEvidenceAccess::Root(project);
    if (!root) return Failure(ProjectError::NotOpen, "project");
    if (project.Info()->access != ProjectAccess::ReadWrite) return Failure(ProjectError::ReadOnly, "project");
    SampleRecord sample;
    if (const auto status = project.ReadSample(sampleId, sample); !status) return status;

    ProjectSysmonEvidenceReceipt draft;
    draft.projectId = project.Info()->projectId;
    draft.sampleId = sample.info.sampleId;
    draft.query = query;
    if (const auto guid = Detection::NormalizeSysmonGuid(query.targetGuid)) draft.query.targetGuid = *guid;
    draft.sourceState = source.state;
    draft.sourceLimit = source.limit;
    draft.nativeStage = source.nativeStage;
    draft.nativeError = source.nativeError;
    draft.examined = source.examined;
    draft.unsupportedVersions = source.unsupportedVersions;
    draft.malformed = source.malformed;
    draft.renderFailed = source.renderFailed;
    draft.reachedEnd = source.reachedEnd;
    if (!ValidQuery(draft.query) || source.targetGuid != draft.query.targetGuid ||
        !ValidBoundary(draft, source.observations.size())) return Failure(ProjectError::InvalidArgument, "sysmonSourceBoundary");

    std::vector<std::string> metadata;
    metadata.reserve(source.observations.size() + 2);
    metadata.push_back(Evidence::WriteJson(EncodePlan(sample, draft)));
    std::optional<std::uint64_t> previousRecordId;
    for (const auto& row : source.observations) {
        auto decoded = Detection::DecodeSysmonThreadEvent(draft.query.targetGuid, row.fields);
        if (!decoded.observation || decoded.observation->reportedStartAddress != row.reportedStartAddress ||
            (query.recordId && row.fields.recordId != *query.recordId) ||
            (previousRecordId && row.fields.recordId >= *previousRecordId)) {
            return Failure(ProjectError::InvalidArgument, "sysmonSourceObservation");
        }
        const auto encoded = EncodeObservation(decoded.observation->fields);
        if (!encoded) return Failure(ProjectError::InvalidArgument, "sysmonSourceText");
        metadata.push_back(Evidence::WriteJson(*encoded));
        previousRecordId = row.fields.recordId;
    }
    const auto end = EncodeEnd(draft, source.observations.size());
    if (!end) return Failure(ProjectError::InvalidArgument, "sysmonSourceEnd");
    metadata.push_back(Evidence::WriteJson(*end));
    std::vector<Archive::RawEvidenceInput> inputs;
    inputs.reserve(metadata.size());
    for (const auto& entry : metadata) {
        if (entry.size() > kMaxMetadataBytes) return Failure(ProjectError::LimitExceeded, "sysmonRawMetadata");
        inputs.push_back({entry, {}});
    }

    // One block carries the plan, all matched observations, and the explicit source end, even for zero matches.
    const ProjectRawEvidenceWrite request{draft.projectId, draft.sampleId, kOrdinal, std::nullopt,
        [&](Archive::RawEvidenceArchive& writer) {
            const auto appended = writer.Append(inputs);
            if (appended.result.status == Archive::SegmentWriteStatus::Ok) return ProjectResult{};
            return appended.result.error.win32Error ? WinFailure("sysmonRawAppend", appended.result.error.win32Error) :
                Failure(ProjectError::InvalidArgument, "sysmonRawAppend");
        }};
    Archive::RawEvidenceReceipt receipt;
    if (const auto status = project.WriteRawEvidenceSegment(request, receipt); !status) return status;
    if (receipt.result.status != Archive::SegmentWriteStatus::Ok || !receipt.flushed) {
        return Failure(ProjectError::IoError, "sysmonRawFinish", receipt.result.error.win32Error);
    }
    ProjectSysmonEvidenceReceipt checked;
    if (const auto status = Scan(project, sample, metadata, checked); !status) return status;
    if (checked.boundary.byteOffset != receipt.flushed->byteOffset || checked.boundary.blockOrdinal != receipt.flushed->blockOrdinal ||
        checked.boundary.lastSequence != receipt.flushed->lastSequence) return Failure(ProjectError::Corrupt, "sysmonRawReadback");

    const auto sampleDirectory = WideAscii(sample.info.sampleId);
    const Parts dirs{L"samples", sampleDirectory, L"checkpoints"};
    Directory checkpoints;
    auto opened = OpenDirectory(*root, dirs, checkpoints);
    if (opened.error == ProjectError::NotFound) opened = OpenDirectory(*root, dirs, checkpoints, true);
    if (!opened) return opened;
    const auto marker = Object({{"kind", Text(kMarkerKind)}, {"projectId", Text(checked.projectId)},
        {"sampleId", Text(checked.sampleId)}, {"descriptionHash", Text(sample.info.descriptionHash)},
        {"segmentOrdinal", Number(kOrdinal)}, {"blockOrdinal", Number(checked.boundary.blockOrdinal)},
        {"endOffset", Number(checked.boundary.byteOffset)}, {"lastSequence", Number(checked.boundary.lastSequence)},
        {"sha256", Text(checked.prefixSha256)}});
    if (const auto status = Publish(*root, dirs, kMarkerName, marker, false); !status) return status;
    out = std::move(checked);
    return {};
}

ProjectResult ReadInitialSysmonEvidence(const ProjectDocument& project, std::string_view sampleId,
    ProjectSysmonEvidenceReceipt& out)
{
    out = {};
    const auto* root = ProjectSysmonEvidenceAccess::Root(project);
    if (!root) return Failure(ProjectError::NotOpen, "project");
    SampleRecord sample;
    if (const auto status = project.ReadSample(sampleId, sample); !status) return status;
    JsonValue marker;
    if (const auto status = Read(*root, {L"samples", WideAscii(sample.info.sampleId), L"checkpoints"},
            kMarkerName, {}, marker); !status) return status;
    Archive::RawEvidenceBoundary boundary;
    std::uint64_t ordinal = 0;
    std::string hash;
    if (!Fields(marker, {"kind", "projectId", "sampleId", "descriptionHash", "segmentOrdinal", "blockOrdinal",
            "endOffset", "lastSequence", "sha256"}) || !IsString(marker, "kind", kMarkerKind) ||
        !IsString(marker, "projectId", project.Info()->projectId) || !IsString(marker, "sampleId", sample.info.sampleId) ||
        !IsString(marker, "descriptionHash", sample.info.descriptionHash) || !GetNumber(marker, "segmentOrdinal", ordinal) ||
        ordinal != kOrdinal || !GetNumber(marker, "blockOrdinal", boundary.blockOrdinal) || boundary.blockOrdinal != 1 ||
        !GetNumber(marker, "endOffset", boundary.byteOffset) || boundary.byteOffset > kMaxFileBytes ||
        !GetNumber(marker, "lastSequence", boundary.lastSequence) || boundary.lastSequence < 2 ||
        boundary.lastSequence > Detection::kSysmonMaxMatches + 2 || !GetHash(marker, "sha256", hash)) {
        return Failure(ProjectError::Corrupt, "sysmonCheckpointDocument");
    }
    ProjectSysmonEvidenceReceipt checked;
    if (const auto status = Scan(project, sample, {}, checked); !status) {
        return status.error == ProjectError::NotFound ? Failure(ProjectError::Corrupt, "sysmonCheckpointRawMissing") : status;
    }
    if (checked.boundary.byteOffset != boundary.byteOffset || checked.boundary.blockOrdinal != boundary.blockOrdinal ||
        checked.boundary.lastSequence != boundary.lastSequence || checked.prefixSha256 != hash) {
        return Failure(ProjectError::Corrupt, "sysmonCheckpointMismatch");
    }
    out = std::move(checked);
    return {};
}

} // namespace Ksword::ActionAnalyze
