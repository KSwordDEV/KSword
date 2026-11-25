#include "SysmonThreadCommand.h"

#include "../Detection/SysmonThreadSource.h"
#include "../../CommandRegistry.h"
#include "../../../shared/usermode/backend/Win32.h"
#include "Transport.h"

#include <iostream>
#include <stdexcept>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
namespace detection = Ksword::ActionAnalyze::Detection;
using V = JsonValue;
using SubscriptionState = detection::SysmonSubscriptionState;

constexpr std::size_t kFollowBatch = 8;

V Text(std::string_view value) { return V::makeString(std::string(value)); }
V Count(std::uint64_t value) { return V::makeString(std::to_string(value)); }

Json OptionalNativeText(std::wstring_view value)
{
    return value.empty() ? Json{} : Json::string(std::wstring(value));
}

Json OptionalError(std::uint32_t error) { return error ? Json::number(error) : Json{}; }

const wchar_t* SubscriptionStateText(SubscriptionState state) noexcept
{
    using enum SubscriptionState;
    switch (state) {
    case Idle: return L"idle";
    case InvalidRequest: return L"invalid-request";
    case Starting: return L"starting";
    case Running: return L"running";
    case Stopping: return L"stopping";
    case Stopped: return L"stopped";
    case ChannelUnavailable: return L"channel-unavailable";
    case AccessDenied: return L"access-denied";
    case Discontinuous: return L"discontinuous";
    case Failed: return L"failed";
    }
    return L"unknown";
}

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

} // namespace

// 每条观察自带来源和日志定位。事件时间不是源/目标进程的创建时间。
Json SysmonObservationJson(const detection::SysmonThreadObservation& observation)
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

Json SysmonSubscriptionJson(const detection::SysmonSubscriptionStatus& status)
{
    return Json::object({{L"state", Json::string(SubscriptionStateText(status.state))},
        {L"targetProcessGuid", OptionalNativeText(status.targetGuid)}, {L"channel", Json::string(detection::kSysmonChannel)},
        {L"subscribed", Json::boolean(status.subscribed)}, {L"captureCoverage", Json::string(L"unknown")},
        {L"queueCapacity", Json::count(status.capacity)}, {L"queued", Json::count(status.queued)},
        {L"examined", Json::count(status.examined)}, {L"enqueued", Json::count(status.enqueued)}, {L"queueDropped", Json::count(status.queueDropped)},
        {L"unsupportedVersionCount", Json::count(status.unsupportedVersions)}, {L"malformedCount", Json::count(status.malformed)},
        {L"renderFailedCount", Json::count(status.renderFailed)}, {L"win32Error", OptionalError(status.nativeError)},
        {L"nativeStage", OptionalNativeText(status.nativeStage)},
        {L"firstRenderFailureStage", OptionalNativeText(status.firstRenderFailureStage)}, {L"firstRenderError", OptionalError(status.firstRenderError)},
        {L"closeError", OptionalError(status.closeError)}, {L"tailDeliveryUnconfirmed", Json::boolean(status.tailDeliveryUnconfirmed)}});
}

namespace {

V CheckedUtf8Value(const Json& json)
{
    if (json.text.size() > kResultBytes) { return {}; }
    const auto chars = static_cast<int>(json.text.size());
    const auto bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, json.text.data(), chars,
        nullptr, 0, nullptr, nullptr);
    if (!bytes || static_cast<std::size_t>(bytes) > kResultBytes) { return {}; }
    std::string utf8(bytes, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, json.text.data(), chars,
            utf8.data(), bytes, nullptr, nullptr)) { return {}; }
    auto parsed = Ksword::Evidence::ParseJson(utf8);
    return parsed.ok() ? std::move(parsed.value) : V::makeNull();
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
        rows.push_back(SysmonObservationJson(observation));
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

Fault SubscriptionFault(const detection::SysmonSubscriptionStatus& status)
{
    const auto fault = [&](const char* id, const char* message, int code) -> Fault {
        return {id, message, std::nullopt, code, status.nativeError ? "win32" : "cli", status.nativeError, "sysmon-follow"};
    };
    using enum SubscriptionState;
    switch (status.state) {
    case ChannelUnavailable:
        return fault("channel-unavailable", "The local Sysmon Operational channel is unavailable", 5);
    case AccessDenied:
        return fault("access-denied", "Access to the local Sysmon Operational channel was denied", 3);
    case Discontinuous:
        return fault("subscription-discontinuous", "Windows Event Log reported a discontinuity in the subscription", 6);
    case InvalidRequest:
        return fault("invalid-request", "An explicit nonzero Sysmon target ProcessGuid is required", 1);
    case Failed:
        return fault("subscription-failed", "The local Sysmon subscription failed", 3);
    default:
        return {};
    }
}

class SysmonFollowSession {
public:
    explicit SysmonFollowSession(bool jsonl) : jsonl_(jsonl) {}

    int Run(std::wstring_view target)
    {
        if (const auto error = transport_.Start(jsonl_)) {
            std::cerr << "error: " << error.message << '\n';
            return error.code;
        }
        try {
            if (!source_.start(target)) { return Complete("source-ended"); }
            if (!Emit("hello", {}, V::makeObject({{"source", Status(source_.status())},
                    {"repl", Text("status | stop | help")}, {"jsonlMethods", V::makeArray({Text("sysmon.status"), Text("sysmon.stop")})}}))) {
                return 3;
            }
            return Loop();
        } catch (const std::exception&) {
            return Complete("internal-error", {}, {"internal-error", "The Sysmon follow session failed", std::nullopt, 3});
        }
    }

private:
    bool Emit(const char* type, std::string_view requestId, V result, const Fault& error = {})
    {
        // REPL 和 JSONL 接收相同的整行流帧，输入语法由 --input 选择。
        const auto frame = V::makeObject({{"schemaVersion", V::makeUInt(kSchemaVersion)}, {"type", Text(type)},
            {"streamSequence", Count(sequence_ + 1)}, {"requestId", requestId.empty() ? V::makeNull() : Text(requestId)},
            {"result", std::move(result)}, {"error", FaultJson(error)}});
        if (!transport_.Send(Ksword::Evidence::WriteJson(frame) + '\n')) { return false; }
        ++sequence_;
        return true;
    }

    V Status(const detection::SysmonSubscriptionStatus& status) const
    {
        return V::makeObject({{"subscription", CheckedUtf8Value(SysmonSubscriptionJson(status))},
            {"projectionFailed", Count(projectionFailed_)}, {"observationFramesQueued", Count(observationFramesQueued_)}});
    }

    bool Drain()
    {
        for (const auto& observation : source_.drain(kFollowBatch)) {
            auto row = CheckedUtf8Value(SysmonObservationJson(observation));
            if (row.isNull()) {
                ++projectionFailed_;
                if (!Emit("observationError", {}, V::makeObject({{"eventRecordId", Count(observation.fields.recordId)}}),
                        {"invalid-observation-text", "The observation exceeds the output limit or contains invalid Unicode", std::nullopt, 6})) {
                    return false;
                }
                continue;
            }
            if (!Emit("observation", {}, std::move(row))) { return false; }
            ++observationFramesQueued_;
        }
        return true;
    }

    int Complete(const char* reason, std::string_view requestId = {}, const Fault& error = {})
    {
        source_.stop();
        auto status = source_.status();
        while (status.queued) {
            if (!Drain()) { return 3; }
            status = source_.status();
        }
        const auto sourceError = SubscriptionFault(status);
        const auto& finalError = error ? error : sourceError;
        const bool partial = status.queueDropped || status.renderFailed || status.unsupportedVersions || status.malformed || projectionFailed_;
        const int code = finalError ? finalError.code : partial ? 6 : 0;
        if (!requestId.empty() && !Emit("response", requestId, Status(status), finalError)) { return 3; }
        const bool sent = Emit("summary", {}, V::makeObject({{"reason", Text(reason)}, {"exitCode", V::makeUInt(code)},
            {"source", Status(status)}}), finalError);
        return sent && transport_.Finish() ? code : 3;
    }

    int Loop()
    {
        bool eof = false;
        bool readySent = false;
        for (;;) {
            const auto status = source_.status();
            if (SubscriptionFault(status) || status.state == SubscriptionState::Stopped) { return Complete("source-ended"); }
            if (status.state == SubscriptionState::Running) {
                if (!readySent) {
                    if (!Emit("sourceReady", {}, Status(status))) { return 3; }
                    readySent = true;
                }
                if (eof) { return Complete("eof"); }
            }
            if (!Drain()) { return 3; }
            // Tick rouses the host even with no input. The source has an independent Event Log worker.
            const auto input = transport_.Next(true);
            switch (input.kind) {
            case InputKind::Eof: eof = true; continue; // 首次订阅结果先于 EOF，保留缺通道等诊断。
            case InputKind::Break: return Complete("ctrl-break");
            case InputKind::OutputLost: return 3;
            case InputKind::Fatal: return Complete("input-failed", {}, input.fault);
            case InputKind::Tick: continue;
            case InputKind::Line: break;
            }

            const auto decoded = jsonl_ ? DecodeJsonLine(input.line, RequestProfile::Offline) : DecodeReplLine(input.line);
            const auto& request = decoded.request;
            if (decoded.error) {
                if (!Emit("error", request.id, V::makeNull(), decoded.error)) { return 3; }
                continue;
            }
            if (request.method.empty()) { continue; }
            const bool empty = jsonl_ ? request.params.asObject()->empty() : request.params.asArray()->empty();
            if (!empty) {
                if (!Emit("error", request.id, V::makeNull(), {"invalid-params", "Sysmon follow commands take no parameters"})) { return 3; }
            } else if (request.method == (jsonl_ ? "sysmon.stop" : "stop")) {
                return Complete("requested", request.id);
            } else if (request.method == (jsonl_ ? "sysmon.status" : "status")) {
                const auto current = source_.status();
                if (!Emit("response", request.id, Status(current), SubscriptionFault(current))) { return 3; }
            } else if (!jsonl_ && request.method == "help") {
                if (!Emit("response", {}, Text("status | stop | help"))) { return 3; }
            } else {
                if (!Emit("error", request.id, V::makeNull(), {"unsupported-method", jsonl_ ?
                        "Use sysmon.status or sysmon.stop" : "Use status, stop or help"})) { return 3; }
            }
        }
    }

    bool jsonl_;
    Transport transport_;
    detection::SysmonThreadSubscription source_;
    std::uint64_t sequence_ = 0, observationFramesQueued_ = 0, projectionFailed_ = 0;
};

int RunSysmonFollowCommand(const Args& args)
{
    const auto target = args.require(L"--target-guid");
    const auto input = args.get(L"--input", L"repl");
    if (!detection::NormalizeSysmonGuid(target)) {
        throw std::invalid_argument("--target-guid must be a nonzero Sysmon ProcessGuid");
    }
    if (input != L"repl" && input != L"jsonl") { throw std::invalid_argument("--input must be repl or jsonl"); }
    return SysmonFollowSession(input == L"jsonl").Run(target);
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

    Command follow;
    follow.path = L"analyze sysmon-thread-create follow";
    follow.syntax = L"KswordCLI.exe analyze sysmon-thread-create follow --target-guid GUID [--input repl|jsonl]";
    follow.summary = L"Follow new local Sysmon Event 8 observations for one explicit target ProcessGuid.";
    follow.options = L"Required: --target-guid. --input defaults to repl. JSONL requires UTF-8 byte streams and LF or CRLF.";
    follow.notes = L"Read-only R3. Both inputs produce JSON lines. REPL: status, stop, help. JSONL: sysmon.status and sysmon.stop with empty params. "
        L"EOF or Ctrl+Break also closes the session. Coverage is unknown. The local queue is bounded and reports drops.";
    follow.runStreaming = RunSysmonFollowCommand;
    addCommand(std::move(follow));
}

} // namespace ks::cli::action_analyze
