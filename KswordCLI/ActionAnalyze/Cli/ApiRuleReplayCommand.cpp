#include "ApiRuleReplayCommand.h"

#include "../../CommandRegistry.h"
#include "../Project/ProjectApiCheckpoint.h"
#include "../Project/ProjectStorage.h"
#include "../Rules/BehaviorPresets.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/string/string.h"

#include <utility>

namespace ks::cli::action_analyze {
namespace {

namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
namespace rules = project::Rules;
namespace evidence = Ksword::Evidence;
using project::ProjectError;
using project::ProjectResult;

constexpr std::uint64_t kMaxSegments = 128; // 与项目历史查询使用相同的检查点链预算。
constexpr std::uint64_t kMaxImportBytes = 32u << 20; // 与 API 导入回放使用相同的段扫描预算。
constexpr std::uint64_t kMaxPageRows = 100;
static_assert(kMaxPageRows <= rules::MaxApiPresetRows);

std::wstring Wide(std::string_view ascii)
{
    return {ascii.begin(), ascii.end()};
}

std::string NarrowAscii(std::wstring_view ascii)
{
    std::string result;
    result.reserve(ascii.size());
    for (const auto character : ascii) {
        result.push_back(static_cast<char>(character));
    }
    return result;
}

struct LocatedClue {
    std::uint64_t segment;
    std::uint64_t block;
    std::uint64_t sequence;
    std::uint64_t sourceSequence;
    std::uint64_t recordOffset;
    std::uint64_t packetOffset;
    std::uint32_t packetBytes;
    std::string api;
    std::string_view family;
    std::optional<rules::ArchivedApiMemoryWriteReturn> memoryWriteReturn; // 同一原包的显式返回字段。
};

// 页索引只用于选中线索。位置字段直接取自同一次 Stored 扫描。
struct CluePage {
    std::uint64_t offset;
    std::uint64_t limit;
    std::uint64_t seen = 0;
    std::vector<LocatedClue> rows{};

    void Add(const archive::SegmentIdentity& segment, const archive::BlockInfo& block,
        const archive::DecodedRecord& record, const archive::RawRecordV1& raw,
        const evidence::ArchivedApiMonitorClue& clue)
    {
        const auto index = seen++;
        if (index < offset || rows.size() == limit) {
            return;
        }
        const auto outcome = evidence::ReadApiMonitorMemoryWriteReturn(clue.packet); // 不从摘要推断返回结果。
        rows.push_back({segment.ordinal, block.ordinal, record.recordSequence, clue.sourceSequence,
            record.recordOffset, record.recordOffset + archive::kRecordHeaderBytes + raw.inlineRawOffsetInPayload,
            raw.inlineRawBytes, NarrowAscii(clue.clue->api), clue.clue->family,
            outcome ? std::optional{rules::ArchivedApiMemoryWriteReturn{outcome->returned, outcome->statusCode}} : std::nullopt});
    }
};

struct Readback {
    std::uint64_t verifiedSegments = 0;
    std::uint64_t verifiedPacketRows = 0;
    std::uint64_t verifiedClueRows = 0;
    std::optional<std::uint64_t> declaredImportSourceRows;
    evidence::ApiMonitorArchiveSource source = evidence::ApiMonitorArchiveSource::LegacyUnspecified; // 单段尾记声明。
    archive::RawEvidenceBoundary end{};
    std::string sha256;
    bool terminalVerified = false;
    std::optional<project::ProjectApiCheckpoint> lastCheckpoint;
};

// 单段导入必须核验全部封装和尾记。页外的证据也参与验证。
ProjectResult ReadImport(const project::ProjectDocument& document, std::string_view sampleId,
    CluePage& page, Readback& out)
{
    evidence::ApiMonitorClueReadback api;
    ProjectResult decode;
    const archive::SegmentBodyVisitor visit = [&](const auto& identity, const auto& block, const auto& records) {
        for (const auto& record : records) {
            const auto& raw = std::get<archive::RawRecordV1>(record.body);
            const auto metadata = evidence::ParseJson(raw.metadataJson);
            if (!metadata.ok()) {
                decode = storage::Failure(ProjectError::Corrupt, "apiRuleReplayMetadata");
                return false;
            }
            if (record.recordSequence == 1 && !evidence::IsApiMonitorClueImport(metadata.value)) {
                decode = storage::Failure(ProjectError::Unsupported, "apiRuleReplayArchiveSource");
                return false;
            }
            std::optional<evidence::ArchivedApiMonitorClue> clue;
            if (!api.Accept(metadata.value, raw.inlineRawData, clue)) {
                decode = storage::Failure(ProjectError::Corrupt, "apiRuleReplayImportTailOrRecord");
                return false;
            }
            if (clue) {
                page.Add(identity, block, record, raw, *clue);
            }
        }
        return true;
    };

    archive::RawEvidenceScanResult scan;
    std::string hash;
    const auto read = document.ReadRawEvidenceSegment({document.Info()->projectId, sampleId, 1, {}, 0,
        visit, kMaxImportBytes}, scan, &hash);
    if (!read) {
        return read;
    }
    if (!decode) {
        return decode;
    }
    const auto& framing = scan.segment.framing;
    if (framing.status == archive::SegmentScanStatus::IoError) {
        return storage::WinFailure("apiRuleReplayImportRead", framing.error.win32Error);
    }
    if (framing.status == archive::SegmentScanStatus::Unsupported) {
        return storage::Failure(ProjectError::Unsupported, "apiRuleReplayImportFraming");
    }
    if (!api.ended || !scan.checked || !scan.VerifiedBoundary(*scan.checked) || hash.empty()) {
        return storage::Failure(ProjectError::Corrupt, "apiRuleReplayImportBoundary");
    }
    out.verifiedSegments = 1;
    out.verifiedPacketRows = api.clues;
    out.verifiedClueRows = api.clues;
    out.declaredImportSourceRows = api.sourceRows;
    out.source = api.source;
    out.end = *scan.checked;
    out.sha256 = std::move(hash);
    out.terminalVerified = true;
    return {};
}

ProjectResult ReadFollow(const project::ProjectDocument& document, std::string_view sampleId,
    CluePage& page, Readback& out)
{
    const archive::SegmentBodyVisitor visit = [&](const auto& identity, const auto& block, const auto& records) {
        for (const auto& record : records) {
            const auto& raw = std::get<archive::RawRecordV1>(record.body);
            if (const auto clue = project::ReadCommittedApiClue(raw)) {
                page.Add(identity, block, record, raw, *clue);
            }
        }
        return true;
    };

    for (std::uint64_t ordinal = 1; ordinal <= kMaxSegments; ++ordinal) {
        const auto rowsBefore = page.rows.size();
        project::ProjectApiCheckpoint checkpoint;
        const auto read = project::ReadApiCheckpoint(document, sampleId, ordinal,
            out.lastCheckpoint ? &*out.lastCheckpoint : nullptr, checkpoint, visit);
        if (!read) {
            // 回调先于摘要比对。失败段的任何线索都不得进入求值器。
            page.rows.resize(rowsBefore);
            page.seen = out.verifiedClueRows;
            return read;
        }
        out.verifiedSegments = ordinal;
        out.verifiedPacketRows = checkpoint.lastSourceSequence;
        out.verifiedClueRows = page.seen;
        out.source = checkpoint.source;
        out.end = checkpoint.rawEnd;
        out.sha256 = checkpoint.rawSha256;
        out.terminalVerified = checkpoint.finalSegment;
        out.lastCheckpoint = std::move(checkpoint);
        if (out.terminalVerified) {
            return {};
        }
    }
    return storage::Failure(ProjectError::LimitExceeded, "apiRuleReplayCheckpointLimit");
}

Json ErrorJson(const ProjectResult& error)
{
    return Json::object({{L"code", Json::string(Wide(project::ProjectErrorName(error.error)))},
        {L"detail", Json::string(Wide(error.detail))},
        {L"win32Error", error.nativeError ? Json::number(error.nativeError) : Json{}}});
}

Result Failure(int code, const wchar_t* status, std::wstring_view projectId, std::wstring_view sampleId,
    const ProjectResult& error)
{
    return {code, Json::object({{L"status", Json::string(status)},
        {L"projectId", projectId.empty() ? Json{} : Json::string(std::wstring(projectId))},
        {L"sampleId", Json::string(std::wstring(sampleId))}, {L"error", ErrorJson(error)}}), {status}};
}

Json Coverage(const Readback& read, const ProjectResult& stop)
{
    const auto* final = read.lastCheckpoint && read.terminalVerified ? &*read.lastCheckpoint : nullptr;
    return Json::object({
        {L"collection", Json::string(L"unknown")},
        {L"ruleInput", Json::string(L"classified-api-observations-only")},
        {L"verifiedSegments", Json::count(read.verifiedSegments)},
        {L"verifiedPacketRows", Json::count(read.verifiedPacketRows)},
        {L"eligibleClueRows", Json::count(read.verifiedClueRows)},
        {L"importDeclaredSourceRows", read.declaredImportSourceRows ? Json::count(*read.declaredImportSourceRows) : Json{}},
        {L"terminalVerified", Json::boolean(read.terminalVerified)},
        {L"lastVerifiedRaw", Json::object({{L"segment", Json::count(read.verifiedSegments)},
            {L"block", Json::count(read.end.blockOrdinal)}, {L"endOffset", Json::count(read.end.byteOffset)},
            {L"lastSequence", Json::count(read.end.lastSequence)}, {L"sha256", Json::string(Wide(read.sha256))}})},
        {L"uncheckedTailBytesInLastSegment", read.lastCheckpoint ?
            Json::count(read.lastCheckpoint->rawFileBytes - read.end.byteOffset) : Json{}},
        {L"firstUnverifiedSegment", stop ? Json{} : Json::count(read.verifiedSegments + 1)},
        {L"readError", stop ? Json{} : ErrorJson(stop)},
        {L"followEnd", final ? Json::object({{L"reason", Json::string(Wide(final->stopReason))},
            {L"sourceState", Json::string(Wide(final->sourceState))},
            {L"cutoffReached", Json::boolean(final->sourceCutoffReached)},
            {L"partialLineBytes", Json::count(final->partialLineBytes)}}) : Json{}}
    });
}

Result RunReplay(const Args& args)
{
    const auto sampleId = args.require(L"--sample");
    const auto path = args.require(L"--project");
    if (sampleId.size() != 36 || sampleId.find_first_not_of(L"0123456789abcdef-") != sampleId.npos) {
        return Failure(1, L"invalid-sample-id", {}, sampleId, storage::Failure(ProjectError::InvalidArgument, "sampleId"));
    }
    const auto id = NarrowAscii(sampleId);
    if (!storage::IsUuid(id)) {
        return Failure(1, L"invalid-sample-id", {}, sampleId, storage::Failure(ProjectError::InvalidArgument, "sampleId"));
    }
    const auto profileName = args.get(L"--profile", L"grouped");
    if (profileName != L"grouped" && profileName != L"by-category") {
        return Failure(1, L"invalid-profile", {}, sampleId, storage::Failure(ProjectError::InvalidArgument, "profile"));
    }
    const auto profile = profileName == L"grouped" ? rules::ApiPresetProfile::Grouped : rules::ApiPresetProfile::ByCategory;
    CluePage page{args.integer(L"--offset", 0), args.integer(L"--limit", 25)};
    if (!page.limit || page.limit > kMaxPageRows) {
        return Failure(1, L"invalid-page-limit", {}, sampleId, storage::Failure(ProjectError::InvalidArgument, "limit"));
    }
    page.rows.reserve(static_cast<std::size_t>(page.limit));

    project::ProjectDocument document;
    if (const auto opened = document.Open(path, project::ProjectAccess::ReadOnly); !opened) {
        return Failure(3, L"project-unavailable", {}, sampleId, opened);
    }
    const auto projectId = Wide(document.Info()->projectId);
    project::SampleRecord sample;
    if (const auto found = document.ReadSample(id, sample); !found) {
        return Failure(5, L"sample-unavailable", projectId, sampleId, found);
    }

    project::ApiFollowArchiveKind kind{};
    if (const auto probed = project::ProbeApiFollowArchive(document, id, kind); !probed) {
        return Failure(4, L"archive-unavailable", projectId, sampleId, probed);
    }
    if (kind == project::ApiFollowArchiveKind::Legacy) {
        return Failure(5, L"archive-unsupported", projectId, sampleId,
            storage::Failure(ProjectError::Unsupported, "apiRuleReplayUnpublishedLegacyFollow"));
    }

    const bool follow = kind == project::ApiFollowArchiveKind::Checkpointed;
    Readback read;
    const auto stop = follow ? ReadFollow(document, id, page, read) : ReadImport(document, id, page, read);
    if (!read.verifiedSegments) {
        const bool missing = stop.error == ProjectError::NotFound;
        const bool unsupported = stop.error == ProjectError::Unsupported;
        return Failure(missing || unsupported ? 5 : 4, missing ? L"archive-unavailable" :
            unsupported ? L"archive-unsupported" : L"archive-invalid", projectId, sampleId, stop);
    }

    std::vector<rules::ArchivedApiObservation> observations;
    observations.reserve(page.rows.size());
    for (const auto& clue : page.rows) {
        observations.push_back({clue.sequence, clue.sourceSequence, clue.api, clue.family, clue.memoryWriteReturn});
    }
    const auto database = rules::LoadApiPresetDatabase(); // 每次离线回放独立冻结当前规则库。
    if (!database.error.empty()) {
        return Failure(4, L"rule-profile-unavailable", projectId, sampleId,
            storage::Failure(ProjectError::Corrupt, database.error.c_str()));
    }
    const auto report = rules::AnalyzeVerifiedApiPresetPage(database, observations, read.verifiedClueRows, profile);
    if (report.error != rules::ApiPresetError::None) {
        const char* detail = report.error == rules::ApiPresetError::InvalidPreset ? "apiRuleReplayPreset" : "apiRuleReplayInput";
        return Failure(4, L"rule-evaluation-failed", projectId, sampleId, storage::Failure(ProjectError::Corrupt, detail));
    }

    std::vector<Json> matches;
    matches.reserve(report.matches.size());
    for (std::size_t i = 0; i < report.matches.size(); ++i) {
        const auto& match = report.matches[i];
        const auto& clue = page.rows[i];
        std::vector<std::pair<std::wstring, Json>> fields{{L"ruleId", Json::string(Wide(match.ruleId))},
            {L"result", Json::string(L"matched")}, {L"api", Json::string(Wide(match.api))},
            {L"family", Json::string(Wide(clue.family))}, {L"sourceSequence", Json::count(match.sourceSequence)},
            {L"raw", Json::object({{L"segment", Json::count(clue.segment)}, {L"block", Json::count(clue.block)},
                {L"sequence", Json::count(match.rawSequence)}, {L"recordOffset", Json::count(clue.recordOffset)},
                 {L"packetOffset", Json::count(clue.packetOffset)}, {L"packetBytes", Json::number(clue.packetBytes)}})}};
        if (match.behavior) { // 行为释义和证据级别与同一原包坐标一起返回。
            fields.emplace_back(L"behavior", Json::object({{L"ruleId", Json::string(Wide(match.behavior->ruleId))},
                {L"evidence", Json::string(Wide(match.behavior->evidence))},
                 {L"summary", Json::string(ks::str::Utf8ToUtf16(match.behavior->summary))},
                 {L"summaryZh", match.behavior->summaryZh.empty() ? Json{} :
                     Json::string(ks::str::Utf8ToUtf16(match.behavior->summaryZh))}}));
        }
        matches.push_back(Json::object(fields));
    }

    const auto next = page.rows.empty() ? read.verifiedClueRows : page.offset + report.analyzedRows;
    const bool more = next < read.verifiedClueRows;
    const wchar_t* status = stop ? L"readback-verified" : L"verified-prefix-only";
    // 来源与旧 archiveKind 分开输出，保留已有查询方对封装类型的判断。
    const auto source = follow && read.source == evidence::ApiMonitorArchiveSource::LegacyUnspecified ?
        std::string_view("jsonl-follow") : evidence::ApiMonitorArchiveSourceName(read.source);
    return {stop ? 0 : 6, Json::object({{L"status", Json::string(status)}, {L"projectId", Json::string(projectId)},
        {L"sampleId", Json::string(sampleId)}, {L"sampleDescriptionHash", Json::string(Wide(sample.info.descriptionHash))},
        {L"archiveKind", Json::string(follow ? L"checkpointed-api-follow" : L"closed-api-import")},
        {L"archiveSource", Json::string(Wide(source))},
        {L"presetSet", Json::string(Wide(database.presetSet))},
        {L"recordedPresetSet", read.lastCheckpoint && !read.lastCheckpoint->rulePresetSet.empty() ?
            Json::string(Wide(read.lastCheckpoint->rulePresetSet)) : Json{}},
        {L"profile", Json::string(profileName)}, {L"coverage", Coverage(read, stop)},
        {L"offset", Json::count(page.offset)}, {L"evaluatedClueRows", Json::count(report.analyzedRows)},
        {L"nextOffset", more ? Json::count(next) : Json{}}, {L"matches", Json::array(matches)}}), {}};
}

// 序列化外置规则目录的一组条目；字段白名单由实际解释器提供。
Json DescribePresets(std::span<const rules::ApiPresetDefinition> definitions, bool behavior)
{
    std::vector<Json> entries; // 保留规则文件中的顺序及覆盖语义。
    entries.reserve(definitions.size());
    for (const auto& preset : definitions) {
        const auto& text = preset.description;
        entries.push_back(Json::object({{L"ruleId", Json::string(Wide(text.ruleId))},
            {L"predicate", Json::string(ks::str::Utf8ToUtf16(preset.predicate))},
            {L"evidence", Json::string(Wide(text.evidence))}, {L"summary", Json::string(ks::str::Utf8ToUtf16(text.summary))},
            {L"summaryZh", text.summaryZh.empty() ? Json{} : Json::string(ks::str::Utf8ToUtf16(text.summaryZh))}}));
    }
    std::vector<std::wstring> fields; // 这组规则表达式可引用的实际观测字段。
    for (const auto& field : rules::ApiPresetFields(behavior)) {
        fields.push_back(Wide(field.id));
    }
    return Json::object({{L"fields", Json::strings(fields)}, {L"rules", Json::array(entries)}});
}

// 查询实际可装载规则，退出码 4 携带配置诊断。
Result RunCatalog(const Args&)
{
    const auto database = rules::LoadApiPresetDatabase(); // 同一文件同时提供版本、条件和释义。
    if (!database.error.empty()) {
        return {4, Json::object({{L"status", Json::string(L"rule-profile-unavailable")},
            {L"source", Json::string(rules::ApiPresetProfilePath)}, {L"configError", Json::string(Wide(database.error))}}), {}};
    }
    return {0, Json::object({{L"presetSet", Json::string(Wide(database.presetSet))},
        {L"source", Json::string(rules::ApiPresetProfilePath)}, {L"scope", Json::string(L"verified-single-api-observation")},
        {L"profiles", Json::object({
            {L"grouped", DescribePresets(rules::ApiClassificationPresets(database, rules::ApiPresetProfile::Grouped), false)},
            {L"by-category", DescribePresets(rules::ApiClassificationPresets(database, rules::ApiPresetProfile::ByCategory), false)}})},
        {L"behaviorRules", DescribePresets(database.behaviorRules, true)}}), {}};
}

} // namespace

void RegisterApiRuleReplayCommand()
{
    Command catalog;
    catalog.path = L"analyze api-rule-catalog";
    catalog.syntax = L"KswordCLI.exe analyze api-rule-catalog [--json]";
    catalog.summary = L"List the API behavior presets from profiles/action_analyze_api_rules.json.";
    catalog.notes = L"Lists rule IDs, predicates, available fields and evidence scope. No project or live source is opened.";
    catalog.defaultBackend = L"offline";
    catalog.supportsR3 = false;
    catalog.run = RunCatalog;
    addCommand(std::move(catalog));

    Command replay;
    replay.path = L"analyze replay-api-rules";
    replay.syntax = L"KswordCLI.exe analyze replay-api-rules --project PATH --sample UUID "
        L"[--profile grouped|by-category] [--offset N] [--limit N] [--json]";
    replay.summary = L"Replay configured API behavior presets on verified evidence from one project sample.";
    replay.options = L"Required: --project and --sample. Default profile: grouped. Offset is zero-based. Limit: 1-100 (default 25).";
    replay.notes = L"Use nextOffset for the next page. Collection coverage is unknown. presetSet identifies the replay rules; recordedPresetSet identifies the capture plan's declared version when present. Matches refer to individual archived API observations.";
    replay.defaultBackend = L"offline";
    replay.supportsR3 = false;
    replay.run = RunReplay;
    addCommand(std::move(replay));
}

} // namespace ks::cli::action_analyze
