#include "CommandRegistry.h"
#include "../shared/ApiMonitorCapture.h"
#include <algorithm>
#include <filesystem>
#include <set>
#include <sstream>
#include <stdexcept>

namespace ks::cli {
namespace {
namespace m = ks::winapi_monitor;
template<std::size_t N> std::wstring wide(const wchar_t (&value)[N]) { return {value, std::find(value, value + N, L'\0')}; }
std::wstring sha(const m::ApiMonitorEventPacket& packet) {
    std::wstring value;
    for (const auto ch : packet.definitionSha256) { if (!ch) break; value += static_cast<unsigned char>(ch); }
    return value;
}
Json packetJson(const m::ApiMonitorEventPacket& p) {
    const bool known = p.resultKind == static_cast<std::uint32_t>(m::EventResultKind::StatusCode);
    return Json::object({{L"pid",Json::number(p.pid)},{L"tid",Json::number(p.tid)},
        {L"timestampFileTime",Json::count(p.timestamp100ns)},{L"category",Json::number(p.category)},
        {L"module",Json::string(wide(p.moduleName))},{L"api",Json::string(wide(p.apiName))},{L"detail",Json::string(wide(p.detailText))},
        {L"resultKind",Json::number(p.resultKind)},{L"resultCode",known?Json::signedNumber(p.resultCode):Json{}},
        {L"eventKind",Json::number(p.eventKind)},{L"apiId",Json::number(p.apiId)},{L"operationId",Json::count(p.operationId)},
        {L"sessionIdentity",Json::hex(p.sessionIdentity)},{L"definitionSha256",Json::string(sha(p))}});
}
void scalar(const std::wstring& value) {
    if (value.size() > 16000 || value.find_first_of(L"\r\n\0", 0, 3) != std::wstring::npos)
        throw std::invalid_argument("monitor option must be one INI value, at most 16000 characters");
}
bool boolean(const Args& a, const wchar_t* key, bool fallback) {
    if (!a.has(key)) return fallback;
    const auto value = a.get(key);
    if (value != L"0" && value != L"1") throw std::invalid_argument("boolean monitor options require 0 or 1");
    return value == L"1";
}
std::wstring defaultAgent() {
    std::vector<wchar_t> path(32768);
    const auto length = ::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) throw std::runtime_error("CLI executable path unavailable");
    return (std::filesystem::path(path.data()).parent_path() / L"APIMonitor_x64.dll").wstring();
}
void loadOptions(const std::wstring& input, m::CaptureRequest& request) {
    const auto path = std::filesystem::absolute(input).wstring();
    const auto attr = ::GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) throw std::invalid_argument("--options-file must be an existing INI file");
    // Import business options only. PID, pipes, SID, session, broker and stop
    // paths always come from this controller, even when importing a GUI INI.
    const std::vector<std::wstring> booleans{L"enable_file",L"enable_registry",L"enable_network",L"enable_process",L"enable_loader",L"enable_clipboard",
        L"auto_inject_child",L"enable_raw_fallback",L"raw_use_default_denylist",L"fake_success_enabled",L"fake_success_raw_fallback"};
    auto keys = booleans;
    for (const auto key : {L"raw_modules",L"raw_denylist",L"fake_success_rules",L"detail_limit",L"clipboard_read_action",L"clipboard_write_action",L"clipboard_enum_action"}) keys.emplace_back(key);
    for (const auto& key : keys) {
        std::vector<wchar_t> value(16384);
        const auto length = ::GetPrivateProfileStringW(L"monitor",key.c_str(),L"__absent__",value.data(),static_cast<DWORD>(value.size()),path.c_str());
        if (length >= value.size()-1) throw std::invalid_argument("INI option too long");
        const std::wstring text(value.data()); if (text == L"__absent__") continue;
        scalar(text);
        if (std::find(booleans.begin(),booleans.end(),key)!=booleans.end() && text!=L"0" && text!=L"1") throw std::invalid_argument("INI booleans must be 0 or 1");
        if (key == L"auto_inject_child") request.autoChildren = text == L"1";
        else request.options[key] = text;
    }
}
Result capture(const Args& a) {
    if (!a.has(L"--confirm")) throw std::invalid_argument("API monitoring requires --confirm (loads Agent and installs hooks)");
    m::CaptureRequest request; request.pid=a.u32(L"--pid");
    if (request.pid<=4 || request.pid==::GetCurrentProcessId()) throw std::invalid_argument("--pid must identify another user process, PID > 4");
    request.durationMs=a.u32(L"--duration-ms",1000); request.eventLimit=a.u32(L"--limit",5000);
    request.startupTimeoutMs=a.u32(L"--startup-timeout-ms",30000);request.stopTimeoutMs=a.u32(L"--stop-timeout-ms",15000);
    if(request.durationMs<100||request.durationMs>120000)throw std::invalid_argument("--duration-ms must be 100..120000");
    if(!request.eventLimit||request.eventLimit>100000)throw std::invalid_argument("--limit must be 1..100000");
    if(request.startupTimeoutMs<1000||request.startupTimeoutMs>120000||request.stopTimeoutMs<1000||request.stopTimeoutMs>120000)
        throw std::invalid_argument("startup/stop timeout must be 1000..120000 ms");
    request.agentPath=a.get(L"--agent",defaultAgent()); if(request.agentPath.empty())throw std::invalid_argument("empty --agent");
    if(a.has(L"--options-file"))loadOptions(a.require(L"--options-file"),request);
    if(a.has(L"--categories")) {
        const auto text=a.require(L"--categories");std::set<std::wstring> selected;std::wistringstream stream(text);
        for(std::wstring part;std::getline(stream,part,L',');) { if(part.empty())throw std::invalid_argument("empty category");selected.insert(part); }
        const std::set<std::wstring> valid{L"file",L"registry",L"network",L"process",L"loader",L"clipboard"};
        if(text.empty()||text.back()==L','||selected.empty())throw std::invalid_argument("empty category list");
        for(const auto& value:selected)if(!valid.contains(value))throw std::invalid_argument("unknown API category");
        for(const auto& value:valid)request.options[L"enable_"+value]=selected.contains(value)?L"1":L"0";
    }
    if(a.has(L"--raw"))request.options[L"enable_raw_fallback"]=boolean(a,L"--raw",false)?L"1":L"0";
    if(a.has(L"--raw-default-denylist"))request.options[L"raw_use_default_denylist"]=boolean(a,L"--raw-default-denylist",true)?L"1":L"0";
    if(a.has(L"--auto-children"))request.autoChildren=boolean(a,L"--auto-children",false);
    for(const auto& names : {std::pair{L"--raw-modules",L"raw_modules"},std::pair{L"--raw-exclude",L"raw_denylist"}})
        if(a.has(names.first)){const auto value=a.require(names.first);scalar(value);request.options[names.second]=value;}
    Cancellation cancel;const auto result=m::captureApiMonitor(request,*cancel.token);
    std::vector<Json> events,processes;
    for(const auto& packet:result.events)events.push_back(packetJson(packet));
    for(const auto& p:result.processes){std::vector<Json> coverage;std::map<std::uint32_t,std::uint32_t> counts;
        for(const auto& item:p.coverage){++counts[item.coverageState];coverage.push_back(Json::object({{L"apiId",Json::number(item.apiId)},
            {L"module",Json::string(wide(item.moduleName))},{L"api",Json::string(wide(item.apiName))},{L"state",Json::number(item.coverageState)},
            {L"hookKind",Json::number(item.hookKind)},{L"address",Json::hex(item.hookAddress)},{L"detail",Json::string(wide(item.detailText))},{L"definitionSha256",Json::string(sha(item))}}));}
        std::vector<std::pair<std::wstring,Json>> states;for(const auto& [state,count]:counts)states.emplace_back(std::to_wstring(state),Json::number(count));
        processes.push_back(Json::object({{L"pid",Json::number(p.pid)},{L"creationFileTime",Json::count(p.creation)},{L"sessionIdentity",Json::hex(p.session)},
            {L"connected",Json::boolean(p.connected)},{L"hooksInstalled",Json::boolean(p.installed)},{L"hooksRemoved",Json::boolean(p.removed)},
            {L"targetExited",Json::boolean(p.exited)},{L"installFailed",Json::boolean(p.installFailed)},{L"partialHooks",Json::boolean(p.partialHooks)},
            {L"pipeWin32Error",Json::number(p.pipeError)},{L"agentDroppedCount",Json::count(p.agentDropped)},
            {L"coverageComplete",Json::boolean(p.coverageComplete)},{L"coverageStale",Json::boolean(p.coverageStale)},
            {L"coverageRevision",Json::count(p.revision)},{L"coverageStateCounts",Json::object(states)},{L"coverage",Json::array(coverage)}}));}
    std::vector<std::pair<std::wstring,Json>> options;for(const auto& [key,value]:request.options)options.emplace_back(key,Json::string(value));
    return {result.code,Json::object({{L"source",Json::string(L"API Monitor Agent; shared native injection/session/coverage protocol")},
        {L"pid",Json::number(request.pid)},{L"sessionId",Json::string(result.sessionId)},{L"agentPath",Json::string(result.agentPath)},
        {L"configPath",Json::string(result.configPath)},{L"stopPath",Json::string(result.stopPath)},{L"configPublished",Json::boolean(result.configPublished)},
        {L"reusedResident",Json::boolean(result.reusedResident)},{L"requestedDurationMs",Json::number(request.durationMs)},{L"elapsedMs",Json::count(result.elapsedMs)},
        {L"cancelled",Json::boolean(result.cancelled)},{L"completedRequestedInterval",Json::boolean(result.completedInterval)},
        {L"stopWritten",Json::boolean(result.stopWritten)},{L"cleanupComplete",Json::boolean(result.cleanupComplete)},
        {L"receivedCount",Json::count(result.received)},{L"returnedCount",Json::count(result.events.size())},{L"bufferDroppedCount",Json::count(result.bufferDropped)},
        {L"invalidPacketCount",Json::count(result.invalidPackets)},{L"autoChildren",Json::boolean(request.autoChildren)},
        {L"options",Json::object(options)},{L"processes",Json::array(processes)},{L"events",Json::array(events)}}),result.errors};
}
}
void registerMonitorApi() {
    addCommand({L"monitor api capture",
        L"KswordCLI.exe monitor api capture --pid PID [--agent PATH] [--duration-ms N] [--limit N] [--categories LIST] [--raw 0|1] [--raw-modules LIST] [--raw-exclude LIST] [--raw-default-denylist 0|1] [--auto-children 0|1] [--options-file PATH] [--startup-timeout-ms N] [--stop-timeout-ms N] --confirm [--backend r3] [--json]",
        L"Capture API Monitor events and coverage, then request and verify hook removal.",
        L"Required: --pid >4, --confirm. Default Agent beside CLI, auto-selected x64/x86. --duration-ms 100..120000 (1000 after HooksInstalled); --limit 1..100000 (5000 latest events); --categories comma-separated file,registry,network,process,loader,clipboard (Agent defaults); --raw, --auto-children, --raw-default-denylist use 0/1. Raw modules/exclusions use semicolons. --options-file imports [monitor] business options including Fake Success and clipboard policy, never controller paths/identity. CLI options override INI. --startup-timeout-ms 1000..120000 (30000); --stop-timeout-ms 1000..120000 (15000).",
        L"Uses the main application's native injector and session lease, no R0 fallback. Target creation identity and named-pipe server PID are checked. Requires target injection/VM permissions; no elevation. JSON/text include events, complete per-PID coverage, hook install/remove, loss and cleanup evidence. Raw resultCode is null. Latest-event truncation, Agent loss, partial hooks, cancellation, interrupted capture or unconfirmed cleanup returns 6; startup failure 3; parameter error 1. Only complete ordered coverage snapshots are committed. Stop markers stay for resident/late Agents; DLL and retired trampolines remain until target exit. Cross-bitness needs matching Agent DLLs beside the CLI. Help never injects.",capture});
}
}
