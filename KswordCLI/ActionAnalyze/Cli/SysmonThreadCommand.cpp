#include "SysmonThreadCommand.h"

#include "../Detection/SysmonThreadSource.h"
#include "../../CommandRegistry.h"

#include <stdexcept>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
namespace detection = Ksword::ActionAnalyze::Detection;

const wchar_t* StateText(detection::SysmonReadState state) noexcept
{
    using detection::SysmonReadState;
    switch (state) {
    case SysmonReadState::InvalidRequest: return L"invalid-request";
    case SysmonReadState::ChannelUnavailable: return L"channel-unavailable";
    case SysmonReadState::AccessDenied: return L"access-denied";
    case SysmonReadState::ReadFailed: return L"read-failed";
    case SysmonReadState::Exhausted: return L"retained-log-exhausted";
    case SysmonReadState::Partial: return L"partial";
    }
    return L"unknown";
}

const wchar_t* LimitText(detection::SysmonLimit limit) noexcept
{
    using detection::SysmonLimit;
    switch (limit) {
    case SysmonLimit::Scan: return L"scan-limit";
    case SysmonLimit::Matches: return L"match-limit";
    case SysmonLimit::Time: return L"read-budget";
    case SysmonLimit::None: return L"none";
    }
    return L"unknown";
}

Json OptionalText(const std::optional<std::wstring>& value)
{
    return value ? Json::string(*value) : Json{};
}

// 固定 16 位的小写文本，地址未经 double，报告零也不等于未提供。
Json StartAddress(std::uint64_t address)
{
    std::wstring text(18, L'0');
    text[1] = L'x';
    for (std::size_t pos = text.size(); pos > 2; --pos) {
        text[pos - 1] = L"0123456789abcdef"[address & 15];
        address >>= 4;
    }
    return Json::string(text);
}

Json ProcessJson(const std::wstring& guid, std::uint32_t pid, const std::optional<std::wstring>& image)
{
    return Json::object({{L"identityKind", Json::string(L"sysmon-process-guid")},
        {L"processGuid", Json::string(guid)}, {L"reportedPid", Json::number(pid)},
        {L"image", OptionalText(image)}, {L"actionAnalyzeProcessInstance", Json{}}});
}

// 每条发现自带来源和保留日志定位。事件时间不是源/目标进程的创建时间。
Json ObservationJson(const detection::SysmonThreadObservation& observation)
{
    const auto& fields = observation.fields;
    return Json::object({{L"kind", Json::string(L"remote-thread-creation-observed")},
        {L"attribution", Json::string(L"sysmon-provider-reported")},
        {L"source", ProcessJson(fields.sourceGuid, fields.sourcePid, fields.sourceImage)},
        {L"target", ProcessJson(fields.targetGuid, fields.targetPid, fields.targetImage)},
        {L"reportedNewThreadId", Json::number(fields.newThreadId)}, {L"actionAnalyzeThreadInstance", Json{}},
        {L"reportedStartAddress", StartAddress(observation.reportedStartAddress)},
        {L"providerInferredStartModule", OptionalText(fields.startModule)},
        {L"providerInferredStartFunction", OptionalText(fields.startFunction)},
        {L"execution", Json::string(L"not-observed-by-this-source")},
        {L"memoryWrite", Json::string(L"not-observed-by-this-source")},
        {L"evidence", Json::object({{L"scope", Json::string(L"local-windows-event-log")},
            {L"channel", Json::string(fields.channel)}, {L"provider", Json::string(fields.provider)},
            {L"providerGuid", Json::string(fields.providerGuid)}, {L"computer", Json::string(fields.computer)},
            {L"eventId", Json::number(fields.eventId)}, {L"eventVersion", Json::number(*fields.version)},
            {L"eventRecordId", Json::count(fields.recordId)},
            {L"timeCreatedFileTime", Json::count(fields.timeCreatedFileTime)}})}});
}

Result RunSysmonThreadCommand(const Args& args)
{
    detection::SysmonThreadQuery query;
    query.targetGuid = args.require(L"--target-guid");
    if (!detection::NormalizeSysmonGuid(query.targetGuid)) {
        throw std::invalid_argument("--target-guid must be a nonzero Sysmon ProcessGuid");
    }
    query.maxMatches = args.u32(L"--max-matches", query.maxMatches);
    if (!query.maxMatches || query.maxMatches > detection::kSysmonMaxMatches) {
        throw std::invalid_argument("--max-matches must be in 1..128");
    }
    if (args.has(L"--record-id")) {
        query.recordId = args.integer(L"--record-id");
        if (*query.recordId == 0) { throw std::invalid_argument("--record-id must be nonzero"); }
    }

    const auto report = detection::ReadLocalSysmonThreadEvents(query);
    std::vector<Json> rows;
    rows.reserve(report.observations.size());
    for (const auto& observation : report.observations) {
        rows.push_back(ObservationJson(observation));
    }

    // 通道不存在与成功查空是两类结果。保留系统错误和未读完的具体原因。
    using detection::SysmonReadState;
    Result result;
    switch (report.state) {
    case SysmonReadState::Exhausted: result.code = 0; break;
    case SysmonReadState::Partial: result.code = 6; break;
    case SysmonReadState::ChannelUnavailable:
        result.code = 5;
        result.diagnostics.push_back(L"The local Sysmon Operational channel is unavailable. No installation was attempted.");
        break;
    case SysmonReadState::AccessDenied:
        result.code = 3;
        result.diagnostics.push_back(L"Access to the local Sysmon Operational channel was denied.");
        break;
    case SysmonReadState::ReadFailed: result.code = 3; break;
    case SysmonReadState::InvalidRequest: result.code = 1; break;
    }
    result.data = Json::object({{L"targetProcessGuid", Json::string(report.targetGuid)},
        {L"channel", Json::string(detection::kSysmonChannel)},
        {L"requestedRecordId", query.recordId ? Json::count(*query.recordId) : Json{}},
        {L"readState", Json::string(StateText(report.state))}, {L"limit", Json::string(LimitText(report.limit))},
        {L"reachedEndOfRetainedResults", Json::boolean(report.reachedEnd)},
        {L"captureCoverage", Json::string(L"unknown")},
        {L"maxMatches", Json::number(query.maxMatches)}, {L"scanLimit", Json::number(detection::kSysmonScanLimit)},
        {L"readBudgetMs", Json::number(detection::kSysmonReadBudgetMs)}, {L"examined", Json::number(report.examined)},
        {L"unsupportedVersionCount", Json::number(report.unsupportedVersions)}, {L"malformedCount", Json::number(report.malformed)},
        {L"renderFailedCount", Json::number(report.renderFailed)},
        {L"win32Error", report.nativeError ? Json::number(report.nativeError) : Json{}},
        {L"nativeStage", report.nativeError ? Json::string(std::wstring(report.nativeStage)) : Json{}},
        {L"observations", Json::array(rows)}});
    return result;
}

} // namespace

void RegisterSysmonThreadCommand()
{
    // 元数据由命令注册表同时用于参数许可、内置帮助及命令路由。
    Command command;
    command.path = L"analyze sysmon-thread-create";
    command.syntax = L"KswordCLI.exe analyze sysmon-thread-create --target-guid GUID [--record-id N] [--max-matches N] [--json]";
    command.summary = L"Read existing local Sysmon Event 8 records for one explicit target ProcessGuid.";
    command.options = L"Required: --target-guid. Optional: --record-id for retained-record lookup, --max-matches 1..128 (default 32), --json.";
    command.notes = L"Read-only, newest first. Validates Sysmon Event 8 v2. No process lookup, execution or write attribution, or installation. "
        L"Searches at most 4096 retained Event 8 candidates, with a 5-second read budget. An empty result is not proof of no activity.";
    command.run = RunSysmonThreadCommand;
    command.supportsR3 = true;
    command.supportsR0 = false;
    addCommand(std::move(command));
}

} // namespace ks::cli::action_analyze
