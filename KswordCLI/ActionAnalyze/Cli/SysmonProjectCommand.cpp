#include "SysmonThreadCommand.h"

#include "../Project/ProjectSysmonEvidence.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"

#include <stdexcept>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace detection = project::Detection;
namespace storage = project::ProjectStorage;

// 返回存储失败。已有目录 ID 仅供诊断，不表示该归档发布成功。
Result ProjectFailure(const project::ProjectResult& issue, std::string_view sample = {})
{
    return {3, Json::object({{L"sampleId", sample.empty() ? Json{} : Json::string(storage::WideAscii(sample))},
        {L"archiveVerified", Json::boolean(false)},
        {L"projectError", Json::string(storage::WideAscii(project::ProjectErrorName(issue.error)))},
        {L"detail", Json::string(storage::WideAscii(issue.detail))}, {L"win32Error", Json::number(issue.nativeError)}}), {}};
}

// 将经过读取器核验的回执转换成命令结果，并保留原生来源的部分读取状态。
Result Receipt(const project::ProjectSysmonEvidenceReceipt& receipt)
{
    std::vector<Json> rows; // 每项都包含原始坐标和同一记录的来源字段。
    rows.reserve(receipt.records.size());
    for (const auto& row : receipt.records) {
        rows.push_back(Json::object({{L"observation", SysmonObservationJson(row.observation)},
            {L"rawSequence", Json::count(row.sequence)}, {L"recordOffset", Json::count(row.offset)}}));
    }
    const auto& query = receipt.query; // 实际归档冻结的目标和读取范围。
    return {receipt.sourceState == detection::SysmonReadState::Partial ? 6 : 0, Json::object({
        {L"projectId", Json::string(storage::WideAscii(receipt.projectId))},
        {L"sampleId", Json::string(storage::WideAscii(receipt.sampleId))},
        {L"archiveVerified", Json::boolean(true)},
        {L"channel", Json::string(detection::kSysmonChannel)},
        {L"targetProcessGuid", Json::string(query.targetGuid)}, {L"maxMatches", Json::number(query.maxMatches)},
        {L"requestedRecordId", query.recordId ? Json::count(*query.recordId) : Json{}},
        {L"readState", Json::string(SysmonReadStateText(receipt.sourceState))}, {L"limit", Json::string(SysmonLimitText(receipt.sourceLimit))},
        {L"reachedEndOfRetainedResults", Json::boolean(receipt.reachedEnd)}, {L"captureCoverage", Json::string(L"unknown")},
        {L"examined", Json::number(receipt.examined)}, {L"unsupportedVersionCount", Json::number(receipt.unsupportedVersions)},
        {L"malformedCount", Json::number(receipt.malformed)}, {L"renderFailedCount", Json::number(receipt.renderFailed)},
        {L"win32Error", receipt.nativeError ? Json::number(receipt.nativeError) : Json{}},
        {L"nativeStage", receipt.nativeStage.empty() ? Json{} : Json::string(receipt.nativeStage)},
        {L"raw", Json::object({{L"segmentOrdinal", Json::count(receipt.segmentOrdinal)},
            {L"byteOffset", Json::count(receipt.boundary.byteOffset)}, {L"blockOrdinal", Json::count(receipt.boundary.blockOrdinal)},
            {L"lastSequence", Json::count(receipt.boundary.lastSequence)},
            {L"sha256", Json::string(storage::WideAscii(receipt.prefixSha256))}})},
        {L"observations", Json::array(rows)}}), {}};
}

// 查询现有本机日志，仅在取得可归档的结果后创建一次独立采样。
Result Archive(const Args& args)
{
    const auto path = args.require(L"--project"); // 用户显式选中的项目。
    const auto query = ParseSysmonThreadQuery(args); // 只读日志的目标与条数限制。
    if (path.empty()) throw std::invalid_argument("--project must name an existing project");

    project::ProjectDocument document; // 对本项目的写锁贯穿查询和归档发布。
    if (const auto opened = document.Open(path, project::ProjectAccess::ReadWrite); !opened) {
        return ProjectFailure(opened);
    }
    const auto source = detection::ReadLocalSysmonThreadEvents(query); // 原生状态和已解码的观测。
    using enum detection::SysmonReadState;
    if (source.state != Exhausted && source.state != Partial) {
        const int code = source.state == ChannelUnavailable ? 5 : source.state == InvalidRequest ? 1 : 3; // 同既有查询约定。
        return {code, Json::object({{L"sampleId", Json{}}, {L"archiveVerified", Json::boolean(false)},
            {L"channel", Json::string(detection::kSysmonChannel)}, {L"readState", Json::string(SysmonReadStateText(source.state))},
            {L"nativeStage", Json::string(std::wstring(source.nativeStage))},
            {L"win32Error", Json::number(source.nativeError)}}), {}};
    }
    const auto revision = document.Info()->revisionId; // 与创建采样冻结的项目修订相同。
    project::SampleInfo sample; // 写前获得的采样身份。
    if (const auto created = document.CreateSample("Sysmon Event 8 (retained log)", sample, revision); !created) {
        return ProjectFailure(created);
    }
    project::ProjectSysmonEvidenceReceipt receipt; // 只有归档发布后才拥有可以输出的坐标。
    if (const auto written = project::WriteInitialSysmonEvidence(document, sample.sampleId, query, source, receipt); !written) {
        return ProjectFailure(written, sample.sampleId);
    }
    return Receipt(receipt);
}

// 从已登记采样离线回读归档，不重新查询日志或创建采样。
Result Replay(const Args& args)
{
    const auto path = args.require(L"--project"); // 项目目录或清单。
    const auto id = args.require(L"--sample"); // 只有 ASCII 规范 UUID 可以参与定位。
    if (path.empty() || id.size() != 36 || id.find_first_not_of(L"0123456789abcdef-") != std::wstring::npos) {
        throw std::invalid_argument("Expected --project PATH and --sample UUID");
    }
    std::string sample; // 已通过 ASCII 字符范围检查，可以无损窄化。
    sample.reserve(id.size());
    for (const wchar_t ch : id) {
        sample.push_back(static_cast<char>(ch));
    }
    if (!storage::IsUuid(sample)) {
        throw std::invalid_argument("--sample must be a canonical UUID");
    }
    project::ProjectDocument document; // 只读项目快照。
    if (const auto opened = document.Open(path); !opened) {
        return ProjectFailure(opened);
    }
    project::ProjectSysmonEvidenceReceipt receipt; // 仅在依赖和归档边界核验成功时填充。
    if (const auto loaded = project::ReadInitialSysmonEvidence(document, sample, receipt); !loaded) {
        return ProjectFailure(loaded, sample);
    }
    return Receipt(receipt);
}
} // namespace

// 由 analyze 命令族注册，参数与内置帮助使用同一份元数据。
void RegisterSysmonProjectCommands()
{
    Command archive; // 受限的本机历史查询和项目写入。
    archive.path = L"analyze sysmon-thread-create archive";
    archive.syntax = L"KswordCLI.exe analyze sysmon-thread-create archive --project PATH --target-guid GUID [--record-id N] [--max-matches N] [--json]";
    archive.summary = L"Save an existing local Sysmon Event 8 query as a separate project sample.";
    archive.options = L"Required: --project, --target-guid. Optional: --record-id, --max-matches 1..128 (default 32), --json.";
    archive.notes = L"Read-only to the event log. An unavailable source creates no sample. Retained observations do not establish execution or memory writes.";
    archive.run = Archive;
    addCommand(std::move(archive));

    Command replay; // 不依赖本机日志服务的离线核验入口。
    replay.path = L"analyze sysmon-thread-create replay";
    replay.syntax = L"KswordCLI.exe analyze sysmon-thread-create replay --project PATH --sample UUID [--json]";
    replay.summary = L"Verify and read a committed project Sysmon Event 8 sample without accessing Sysmon.";
    replay.options = L"Required: --project, --sample. Optional: --json.";
    replay.notes = L"Returns stored record offsets, the archive boundary and the original query state. Partial source results exit 6.";
    replay.run = Replay;
    addCommand(std::move(replay));
}
} // namespace ks::cli::action_analyze
