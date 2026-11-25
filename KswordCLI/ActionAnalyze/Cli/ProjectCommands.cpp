#include "ProjectCommands.h"

#include "ArchivedCapture.h"
#include "Controller.h"
#include "../Archive/SegmentInspection.h"
#include "../Project/ProjectStorage.h"

#include <algorithm>
#include <charconv>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
using namespace Ksword::ActionAnalyze;
using namespace Ksword::ActionAnalyze::ProjectStorage;
using Ksword::Evidence::WriteJson;
using V = JsonValue;
using M = ProjectMethod;

constexpr ProjectCommand kMethods[] = {
    {M::Open, "project.open", "project open", "PATH [read-only|read-write]", "Open a saved project. Defaults to read-only.", true},
    {M::Query, "project.query", "project status", "", "Read the open project and its current saved revision.", false},
    {M::Close, "project.close", "project close", "", "Release the open project and its lock.", true},
    {M::Create, "project.create", "project create", "PATH TITLE [NOTES]", "Create a project in a new directory and open it for writing.", true},
    {M::Save, "project.save", "project save", "TITLE [NOTES]", "Save the project settings against its current revision.", true},
    {M::ListSamples, "sample.list", "sample list", "[START GENERATION [LIMIT]]", "List the samples at one project generation.", false},
    {M::QuerySample, "sample.query", "sample status", "SAMPLE_ID [capture [ORDINAL]]", "Read a sample and its frozen project settings.", false},
    {M::CreateSample, "sample.create", "sample create", "TITLE", "Save a sample descriptor and its frozen settings without collecting data.", true},
    {M::InspectArchive, "archive.inspect", "archive inspect", "SAMPLE_ID raw|records|control ORDINAL [END_OFFSET]",
        "Inspect Stored segment framing in the open project. End offset is an optional byte boundary.", false},
};

Reply Invalid(const char* message) {
    return {{}, {}, {"invalid-params", message}};
}

Fault StorageFault(const ProjectResult& result) {
    const char* id = "project-io-error";
    int code = 3;
    switch (result.error) {
    case ProjectError::None: return {};
    case ProjectError::InvalidArgument: id = "invalid-params"; code = 1; break;
    case ProjectError::AlreadyOpen: id = "project-already-open"; code = 1; break;
    case ProjectError::NotOpen: id = "project-not-open"; code = 1; break;
    case ProjectError::NotFound:
        id = "project-data-not-found";
        if (std::string_view(result.detail) == "archiveStreamUnavailable") id = "archive-stream-unavailable";
        if (std::string_view(result.detail) == "archiveSegmentUnavailable") id = "archive-segment-unavailable";
        code = 5;
        break;
    case ProjectError::AlreadyExists: id = "project-already-exists"; code = 1; break;
    case ProjectError::ReadOnly: id = "project-read-only"; code = 1; break;
    case ProjectError::WriterBusy: id = "project-writer-busy"; break;
    case ProjectError::StaleRevision: id = "stale-revision"; code = 1; break;
    case ProjectError::Unsupported: id = "project-unsupported"; code = 5; break;
    case ProjectError::RecoveryRequired: id = "project-recovery-required"; code = 6; break;
    case ProjectError::UnsafePath: id = "project-unsafe-path"; code = 1; break;
    case ProjectError::Corrupt: id = "project-corrupt"; code = 4; break;
    case ProjectError::LimitExceeded: id = "project-limit-exceeded"; code = 6; break;
    case ProjectError::IoError: break;
    }
    return {id, *result.detail ? result.detail : "Project operation failed", {}, code,
        result.nativeError ? "win32" : "cli", result.nativeError};
}

Reply FromError(const ProjectResult& result) { return {{}, {}, StorageFault(result)}; }

bool KnownKeys(const V& value, std::initializer_list<std::string_view> keys) {
    const auto* members = value.asObject();
    return members && std::all_of(members->begin(), members->end(), [&](const auto& field) {
        return std::find(keys.begin(), keys.end(), field.first) != keys.end();
    });
}

bool ReadPath(const V& params, std::wstring& out) {
    std::string value;
    if (!GetString(params, "path", value) || value.empty() || value.find('\0') != value.npos) return false;
    const auto length = static_cast<int>(value.size());
    const auto wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), length, nullptr, 0);
    if (!wideLength) return false;
    out.resize(wideLength);
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), length, out.data(), wideLength) == wideLength;
}

V ProjectJson(const ProjectInfo& info) {
    return Object({{"projectId", Text(info.projectId)}, {"createdUtc", Number(info.createdUtc)},
        {"settings", Settings(info.settings)}, {"revisionId", Text(info.revisionId)},
        {"revisionHash", Text(info.revisionHash)}, {"configSemanticHash", Text(info.configSemanticHash)},
        {"generation", Number(info.generation)}, {"sampleCount", Number(info.sampleCount)},
        {"access", Text(info.access == ProjectAccess::ReadWrite ? "read-write" : "read-only")},
        {"recoveredPrevious", V::makeBool(info.recoveredPrevious)}, {"primaryFailure", FaultJson(StorageFault(info.primaryFailure))}});
}

JsonObject SampleFields(const SampleInfo& sample) {
    return {{"sampleId", Text(sample.sampleId)}, {"title", Text(sample.title)}, {"createdUtc", Number(sample.createdUtc)},
        {"revisionId", Text(sample.revisionId)}, {"snapshotId", Text(sample.snapshotId)},
        {"descriptionHash", Text(sample.descriptionHash)}, {"status", Text(kOfflineSampleStatus)}};
}

V SampleResult(const ProjectInfo& info, const SampleInfo& sample, const RevisionSettings& settings,
                std::string_view revisionHash, std::string_view configSemanticHash,
                std::optional<V> capture = std::nullopt) {
    auto fields = SampleFields(sample);
    fields.emplace_back("projectId", Text(info.projectId));
    fields.emplace_back("generation", Number(info.generation));
    fields.emplace_back("frozenSettings", Settings(settings));
    fields.emplace_back("revisionHash", Text(revisionHash));
    fields.emplace_back("configSemanticHash", Text(configSemanticHash));
    if (capture) {
        fields.emplace_back("captureArchive", std::move(*capture)); // 仅按显式请求回读归档。
    }
    return Object(std::move(fields));
}

V PageJson(const ProjectInfo& info, std::uint64_t start, JsonArray rows) {
    const auto next = start + rows.size();
    return Object({{"projectId", Text(info.projectId)}, {"generation", Number(info.generation)},
        {"start", Number(start)}, {"sampleCount", Number(info.sampleCount)},
        {"nextStart", next < info.sampleCount ? Number(next) : V::makeNull()}, {"samples", V::makeArray(std::move(rows))}});
}

Reply Success(V result, bool effect = false) { return {std::move(result), {}, {}, false, effect}; }

std::optional<archive::StreamKind> ArchiveStream(std::string_view name) {
    if (name == "raw") return archive::StreamKind::Raw;
    if (name == "records") return archive::StreamKind::Records;
    if (name == "control") return archive::StreamKind::Control;
    return std::nullopt;
}

const char* FramingStatus(archive::SegmentScanStatus status) {
    using S = archive::SegmentScanStatus;
    switch (status) {
    case S::FramingComplete: return "framing-complete";
    case S::Truncated: return "truncated";
    case S::Corrupt: return "corrupt";
    case S::Unsupported: return "unsupported";
    case S::IoError: return "io-error";
    case S::Stopped: break; // 此检查没有可中断扫描的访问器。
    }
    throw std::logic_error("Unexpected archive inspection status");
}

const char* FramingReason(archive::SegmentIssue issue) {
    using I = archive::SegmentIssue;
    switch (issue) {
    case I::Magic: return "magic";
    case I::HeaderCrc: return "header-crc";
    case I::Version: return "version";
    case I::HeaderLength: return "header-length";
    case I::Flags: return "flags";
    case I::Reserved: return "reserved";
    case I::Stream: return "stream";
    case I::Identity: return "identity";
    case I::Ordinal: return "ordinal";
    case I::BlockLength: return "block-length";
    case I::RecordCount: return "record-count";
    case I::Sequence: return "sequence";
    case I::QpcRange: return "qpc-range";
    case I::Codec: return "codec";
    case I::StoredCrc: return "stored-crc";
    case I::DecodedCrc: return "decoded-crc";
    case I::RecordLength: return "record-length";
    case I::RecordPayloadCrc: return "record-payload-crc";
    case I::SegmentLimit: return "segment-limit";
    case I::EndOfFile: return "end-of-file";
    case I::FileSize: return "file-size";
    case I::FileRead: return "file-read";
    case I::None:
    case I::RecordSchema:
    case I::FileOpen:
    case I::FileWrite:
    case I::FileFlush:
    case I::FileClose: break;
    }
    throw std::logic_error("Unexpected archive inspection reason");
}

V OptionalNumber(std::optional<std::uint64_t> value) {
    return value ? Number(*value) : V::makeNull();
}

// 将读取失败与扫描质量分开。坏尾或未知格式仍可报告已经验证的封装前缀。
V ArchiveJson(const ProjectInfo& project, std::string_view sampleId, std::string_view stream,
              const archive::SegmentInspection& inspected) {
    const auto& coverage = inspected.framingCoverage;
    const auto& error = inspected.error;
    auto framingError = error.issue == archive::SegmentIssue::None ? V::makeNull() : Object({
        {"reason", Text(FramingReason(error.issue))}, {"offset", Number(error.offset)},
        {"win32Error", error.win32Error ? V::makeUInt(error.win32Error) : V::makeNull()}});
    return Object({{"projectId", Text(project.projectId)}, {"sampleId", Text(sampleId)},
        {"generation", Number(project.generation)}, {"stream", Text(stream)},
        {"ordinal", Number(inspected.expectedIdentity.ordinal)}, {"createdUtc100ns", OptionalNumber(inspected.createdUtc100ns)},
        {"framingStatus", Text(FramingStatus(inspected.framingStatus))}, {"framingError", std::move(framingError)},
        {"framingCoverage", Object({{"requestedEndOffset", OptionalNumber(coverage.requestedEndOffset)},
            {"fileBytes", OptionalNumber(coverage.fileBytes)}, {"scanLimitBytes", OptionalNumber(coverage.scanLimitBytes)},
            {"framedBytes", Number(coverage.framedBytes)}, {"blockCount", Number(coverage.blockCount)},
            {"lastBlockOrdinal", OptionalNumber(coverage.lastBlockOrdinal)}, {"lastSequence", OptionalNumber(coverage.lastSequence)}})},
        {"requiredRecordCount", Number(inspected.requiredRecordCount)},
        {"unsupportedOptionalRecords", Number(inspected.unsupportedOptionalRecords)},
        {"unsupportedRequiredRecords", Number(inspected.unsupportedRequiredRecords)},
        {"interpretedBytes", V::makeNull()}, {"durableBytes", V::makeNull()}});
}
} // namespace

std::span<const ProjectCommand> ProjectCommands::Catalog() noexcept { return kMethods; }

bool ProjectCommands::CanClose(const V& params) const {
    const auto* info = document_.Info();
    return info && Fields(params, {"projectId"}) && IsString(params, "projectId", info->projectId);
}

Reply ProjectCommands::Dispatch(ProjectMethod method, const V& params) {
    if (method == M::Open || method == M::Create) {
        const bool create = method == M::Create;
        std::wstring path;
        if (!KnownKeys(params, create ? std::initializer_list<std::string_view>{"path", "settings"}
                                      : std::initializer_list<std::string_view>{"path", "access"}) || !ReadPath(params, path))
            return Invalid("Expected a nonempty project path and the declared project options");
        ProjectResult result;
        if (create) {
            RevisionSettings settings;
            const auto* draft = params.find("settings");
            if (!draft || !ParseSettings(*draft, settings)) return Invalid("Expected settings with a valid title and notes");
            result = document_.Create(path, settings);
        } else {
            ProjectAccess mode = ProjectAccess::ReadOnly;
            if (const auto* field = params.find("access")) {
                std::string access;
                if (!field->tryGetString(access) || (access != "read-only" && access != "read-write"))
                    return Invalid("access must be read-only or read-write");
                if (access == "read-write") mode = ProjectAccess::ReadWrite;
            }
            result = document_.Open(path, mode);
        }
        return result ? Success(ProjectJson(*document_.Info()), true) : FromError(result);
    }

    std::string projectId;
    if (!GetUuid(params, "projectId", projectId)) return Invalid("Expected a canonical projectId UUID");
    const auto* info = document_.Info();
    const auto checkProject = [&]() -> Fault {
        if (!info) return {"project-not-open", "No project is open"};
        if (info->projectId != projectId) return {"project-id-mismatch", "projectId does not match the open project"};
        return {};
    };

    switch (method) {
    case M::Query:
        if (!Fields(params, {"projectId"})) return Invalid("Expected projectId only");
        if (const auto error = checkProject()) return {{}, {}, error};
        return Success(ProjectJson(*info));
    case M::Close:
        if (!Fields(params, {"projectId"})) return Invalid("Expected projectId only");
        if (const auto error = checkProject()) return {{}, {}, error};
        document_.Close();
        return Success(Object({{"projectId", Text(projectId)}, {"closed", V::makeBool(true)}}), true);
    case M::Save: {
        RevisionSettings settings;
        std::string revision;
        const auto* draft = params.find("settings");
        if (!Fields(params, {"projectId", "expectedRevisionId", "settings"}) || !draft || !ParseSettings(*draft, settings) ||
            !GetUuid(params, "expectedRevisionId", revision)) return Invalid("Expected projectId, expectedRevisionId and settings");
        if (const auto error = checkProject()) return {{}, {}, error};
        if (revision != info->revisionId) return FromError({ProjectError::StaleRevision, 0, "Project revision has changed"});
        const auto result = document_.Save(settings, revision);
        return result ? Success(ProjectJson(*document_.Info()), true) : FromError(result);
    }
    case M::CreateSample: {
        std::string revision, title;
        if (!Fields(params, {"projectId", "expectedRevisionId", "title"}) || !GetUuid(params, "expectedRevisionId", revision) ||
            !GetString(params, "title", title) || !IsText(title, kMaxTitleBytes))
            return Invalid("Expected projectId, expectedRevisionId and a valid title");
        if (const auto error = checkProject()) return {{}, {}, error};
        if (revision != info->revisionId) return FromError({ProjectError::StaleRevision, 0, "Project revision has changed"});
        SampleInfo sample;
        const auto result = document_.CreateSample(title, sample);
        if (!result) return FromError(result);
        const auto& saved = *document_.Info();
        return Success(SampleResult(saved, sample, saved.settings, saved.revisionHash, saved.configSemanticHash), true);
    }
    case M::QuerySample: {
        std::string id; // 要读取的采样 UUID。
        const auto* option = params.find("includeCapture"); // 选择读取历史原始段。
        const auto* ordinalField = params.find("captureOrdinal"); // 未指定时仍读首段。
        std::uint64_t ordinal = 1;
        bool includeCapture = false; // 默认只查询冻结配置。
        if (!KnownKeys(params, {"projectId", "sampleId", "includeCapture", "captureOrdinal"}) || !GetUuid(params, "sampleId", id) ||
            (option && !option->tryGetBool(includeCapture)) ||
            (ordinalField && (!includeCapture || !GetNumber(params, "captureOrdinal", ordinal) || !ordinal))) {
            return Invalid("Expected projectId, sampleId, optional boolean includeCapture and positive captureOrdinal when enabled");
        }
        if (const auto error = checkProject()) return {{}, {}, error};
        SampleRecord sample; // 验证过的创建描述及冻结配置。
        const auto result = document_.ReadSample(id, sample); // 归档扫描依赖此采样已登记。
        if (!result) {
            return FromError(result);
        }
        std::optional<V> capture; // 仅在请求指定时返回归档回执。
        if (includeCapture) {
            capture = ReadArchivedCapture(document_, sample, ordinal);
        }
        return Success(SampleResult(*info, sample.info, sample.frozenSettings, sample.revisionHash,
            sample.configSemanticHash, std::move(capture)));
    }
    case M::InspectArchive: {
        std::string sampleId, stream;
        std::uint64_t ordinal = 0, end = 0;
        const bool hasEnd = params.find("endOffset") != nullptr;
        if (!KnownKeys(params, {"projectId", "sampleId", "stream", "ordinal", "endOffset"}) ||
            !GetUuid(params, "sampleId", sampleId) || !GetString(params, "stream", stream) ||
            !GetNumber(params, "ordinal", ordinal) || ordinal == 0 ||
            (hasEnd && (!GetNumber(params, "endOffset", end) || end > archive::kMaxSegmentBytes))) {
            return Invalid("Expected sampleId, stream, a positive ordinal and optional endOffset in 0..1073741824");
        }
        const auto streamKind = ArchiveStream(stream);
        if (!streamKind) return Invalid("stream must be raw, records or control");
        if (const auto error = checkProject()) return {{}, {}, error};
        archive::SegmentInspection inspected;
        const auto result = document_.InspectSegment(projectId, sampleId, *streamKind, ordinal,
            hasEnd ? std::optional(end) : std::nullopt, inspected);
        return result ? Success(ArchiveJson(*info, sampleId, stream, inspected)) : FromError(result);
    }
    case M::ListSamples: {
        std::uint64_t start = 0, generation = 0, limit = kProjectCatalogPageSize;
        const auto* count = params.find("limit");
        const bool hasGeneration = params.find("generation") != nullptr;
        if (!KnownKeys(params, {"projectId", "generation", "start", "limit"}) ||
            (hasGeneration && !GetNumber(params, "generation", generation)) ||
            (params.find("start") && (!hasGeneration || !GetNumber(params, "start", start))) ||
            (count && (count->type() != JsonType::UInt || !count->tryGetU64(limit) || !limit || limit > kProjectCatalogPageSize)))
            return Invalid("Expected canonical generation/start strings, with generation required for start and limit in 1..256");
        if (const auto error = checkProject()) return {{}, {}, error};
        if (hasGeneration && generation != info->generation)
            return {{}, {}, {"stale-generation", "Project generation has changed. Restart sample paging."}};
        std::vector<SampleInfo> page;
        const auto result = document_.ListSamples(start, limit, page);
        if (!result) return FromError(result);
        JsonArray rows;
        // 预留行包络和 nextStart 的最大增量，只把实际可编码的完整样本放入本页。
        auto bytes = WriteJson(PageJson(*info, start, {})).size() + 24;
        for (const auto& item : page) {
            auto row = Object(SampleFields(item));
            const auto rowBytes = WriteJson(row).size() + 1;
            if (bytes + rowBytes > kResultBytes) break;
            bytes += rowBytes;
            rows.push_back(std::move(row));
        }
        if (!page.empty() && rows.empty()) return {{}, {}, {"response-too-large", "A sample row exceeds the response budget", {}, 6}};
        return Success(PageJson(*info, start, std::move(rows)));
    }
    case M::Open:
    case M::Create: break;
    }
    return Invalid("Unknown project command");
}

Reply ProjectCommands::DispatchRepl(ProjectMethod method, const JsonArray& args) {
    std::vector<std::string> words;
    for (const auto& item : args) {
        std::string word;
        if (!item.tryGetString(word)) return Invalid("Expected a REPL argument");
        words.push_back(std::move(word));
    }
    const auto* info = document_.Info();
    JsonObject fields;
    if (method != M::Open && method != M::Create) {
        if (!info) return FromError({ProjectError::NotOpen, 0, "No project is open"});
        fields.emplace_back("projectId", Text(info->projectId));
    }
    switch (method) {
    case M::Open:
        if (words.empty() || words.size() > 2) return Invalid("Usage: project open PATH [read-only|read-write]");
        fields.emplace_back("path", Text(words[0]));
        if (words.size() == 2) fields.emplace_back("access", Text(words[1]));
        break;
    case M::Create:
    case M::Save: {
        const bool create = method == M::Create;
        const std::size_t offset = create ? 1 : 0;
        if (words.size() < offset + 1 || words.size() > offset + 2) return Invalid("Expected a title and optional notes (plus path for project create)");
        if (create) fields.emplace_back("path", Text(words[0]));
        else fields.emplace_back("expectedRevisionId", Text(info->revisionId));
        fields.emplace_back("settings", Settings({words[offset], words.size() == offset + 2 ? words.back() : ""}));
        break;
    }
    case M::Query:
    case M::Close:
        if (!words.empty()) return Invalid("This command takes no arguments");
        break;
    case M::QuerySample:
        if (words.empty() || words.size() > 3 || (words.size() >= 2 && words[1] != "capture")) {
            return Invalid("Usage: sample status SAMPLE_ID [capture [ORDINAL]]");
        }
        fields.emplace_back("sampleId", Text(words[0]));
        if (words.size() >= 2) {
            fields.emplace_back("includeCapture", V::makeBool(true));
        }
        if (words.size() == 3) fields.emplace_back("captureOrdinal", Text(words[2]));
        break;
    case M::InspectArchive:
        if (words.size() < 3 || words.size() > 4)
            return Invalid("Usage: archive inspect SAMPLE_ID raw|records|control ORDINAL [END_OFFSET]");
        fields.emplace_back("sampleId", Text(words[0]));
        fields.emplace_back("stream", Text(words[1]));
        fields.emplace_back("ordinal", Text(words[2]));
        if (words.size() == 4) fields.emplace_back("endOffset", Text(words[3]));
        break;
    case M::CreateSample:
        if (words.size() != 1) return Invalid("Usage: sample create TITLE");
        fields.emplace_back("expectedRevisionId", Text(info->revisionId));
        fields.emplace_back("title", Text(words[0]));
        break;
    case M::ListSamples:
        if (words.size() == 1 || words.size() > 3) return Invalid("Usage: sample list [START GENERATION [LIMIT]]");
        if (!words.empty()) {
            fields.emplace_back("start", Text(words[0]));
            fields.emplace_back("generation", Text(words[1]));
        }
        if (words.size() == 3) {
            std::uint64_t limit = 0;
            const auto& raw = words[2];
            const auto end = raw.data() + raw.size();
            const auto parsed = std::from_chars(raw.data(), end, limit);
            if (parsed.ec != std::errc{} || parsed.ptr != end) return Invalid("LIMIT must be a decimal integer");
            fields.emplace_back("limit", V::makeUInt(limit));
        }
        break;
    }
    auto reply = Dispatch(method, Object(std::move(fields)));
    if (!reply.error) reply.text = WriteJson(reply.result);
    return reply;
}

} // namespace ks::cli::action_analyze
