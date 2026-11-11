#include "CommandRegistry.h"
#include "../shared/ApiMonitorCapture.h"
#include "../shared/ApiMonitorCallStack.h"
#include "ApiMonitorSignatureCatalog.h"
#include "ApiMonitorFilterImport.h"
#include <algorithm>
#include <filesystem>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace ks::cli {
namespace {
namespace m = ks::winapi_monitor;
template<std::size_t N> std::wstring wide(const wchar_t (&value)[N]) { return {value, std::find(value, value + N, L'\0')}; }
std::wstring sha(const m::ApiMonitorEventPacket& packet) {
    std::wstring value;
    for (const auto ch : packet.definitionSha256) { if (!ch) break; value += static_cast<unsigned char>(ch); }
    return value;
}
Json packetJson(const m::ApiMonitorEventPacket& p, const Json& declaration=Json{}, const Json& catalogMatch=Json{}) {
    const bool known = p.resultKind == static_cast<std::uint32_t>(m::EventResultKind::StatusCode);
    const bool completedCall = known || p.resultKind == static_cast<std::uint32_t>(m::EventResultKind::StatusUnknown);
    const bool businessCall = completedCall && p.eventKind == static_cast<std::uint32_t>(m::EventKind::ApiCall)
        && p.category != static_cast<std::uint32_t>(m::EventCategory::Internal);
    const bool returnAvailable = businessCall && p.snapshotIndex == m::kApiCallReturnValueMarker;
    const bool durationAvailable = businessCall && p.snapshotCount == m::kApiCallDurationMarker;
    m::CallStackTrailer stack{};
    const bool stackAvailable = m::ReadCallStackTrailer(p, stack);
    std::vector<Json> frames;
    if (stackAvailable) {
        frames.reserve(stack.count);
        for (std::size_t i = 0; i < stack.count; ++i) frames.push_back(Json::hex(stack.frames[i]));
    }
    m::CliRawAbi raw;
    Json rawAbi;
    if(m::cliParseRawAbi(p,raw)) {
        std::vector<std::pair<std::wstring,Json>> registers;
        for(const auto& [name,value]:raw.registers) registers.emplace_back(name,Json::hex(value));
        std::vector<Json> stackWords;for(const auto value:raw.stack)stackWords.push_back(Json::hex(value));
        rawAbi=Json::object({{L"architecture",Json::string(raw.bits==64?L"x64":L"x86")},
            {L"registers",Json::object(registers)},{L"stackSlots",Json::array(stackWords)},
            {L"meaning",Json::string(L"captured ABI locations; argument types and count are unknown")}});
    }
    return Json::object({{L"pid",Json::number(p.pid)},{L"tid",Json::number(p.tid)},
        {L"timestampFileTime",Json::count(p.timestamp100ns)},{L"category",Json::number(p.category)},
        {L"module",Json::string(wide(p.moduleName))},{L"api",Json::string(wide(p.apiName))},{L"detail",Json::string(wide(p.detailText))},
        {L"resultKind",Json::number(p.resultKind)},{L"resultCode",known?Json::signedNumber(p.resultCode):Json{}},
        {L"returnValueAvailable",Json::boolean(returnAvailable)},{L"returnValue",returnAvailable?Json::hex(p.hookAddress):Json{}},
        {L"durationAvailable",Json::boolean(durationAvailable)},{L"duration100ns",durationAvailable?Json::count(p.snapshotRevision):Json{}},
        {L"eventKind",Json::number(p.eventKind)},{L"apiId",Json::number(p.apiId)},{L"operationId",Json::count(p.operationId)},
        {L"sessionIdentity",Json::hex(p.sessionIdentity)},{L"definitionSha256",Json::string(sha(p))},
        {L"callStackAvailable",Json::boolean(stackAvailable)},{L"callStack",Json::array(frames)},{L"rawAbi",rawAbi},
        {L"declaration",declaration},{L"declarationCatalogMatchesAgent",catalogMatch}});
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
Json signatureJson(const CliSignature& signature) {
    std::vector<Json> parameters;
    for(const auto& p:signature.parameters)parameters.push_back(Json::object({{L"name",Json::string(p.name)},
        {L"type",Json::string(p.type)},{L"direction",Json::string(p.direction)}}));
    return Json::object({{L"module",Json::string(signature.module)},{L"function",Json::string(signature.function)},
        {L"callingConvention",Json::string(signature.callingConvention)},{L"returnType",Json::string(signature.returnType)},
        {L"parameters",Json::array(parameters)},{L"source",Json::string(signature.source)},
        {L"sourceFile",signature.sourceFile.empty()?Json{}:Json::string(signature.sourceFile)},
        {L"abiEvidence",Json::string(signature.abiEvidence)}});
}
void loadOptions(const std::wstring& input, m::CaptureRequest& request) {
    const auto path = std::filesystem::absolute(input).wstring();
    const auto attr = ::GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) throw std::invalid_argument("--options-file must be an existing INI file");
    // Import business options only. PID, pipes, SID, session, broker and stop
    // paths always come from this controller, even when importing a GUI INI.
    const std::vector<std::wstring> booleans{L"enable_file",L"enable_registry",L"enable_network",L"enable_process",L"enable_memory",L"enable_thread",L"enable_service",L"enable_security",L"enable_crypto",L"enable_com",L"enable_window",L"enable_gui",L"enable_loader",L"enable_clipboard",
        L"auto_inject_child",L"capture_call_stack",L"enable_raw_fallback",L"raw_use_default_denylist",L"fake_success_enabled",L"fake_success_raw_fallback"};
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
        const std::set<std::wstring> valid{L"file",L"registry",L"network",L"process",L"loader",L"clipboard",L"memory",L"thread",L"service",L"security",L"crypto",L"com",L"window",L"gui"};
        if(text.empty()||text.back()==L','||selected.empty())throw std::invalid_argument("empty category list");
        for(const auto& value:selected)if(!valid.contains(value))throw std::invalid_argument("unknown API category");
        for(const auto& value:valid)request.options[L"enable_"+value]=selected.contains(value)?L"1":L"0";
    }
    if(a.has(L"--raw"))request.options[L"enable_raw_fallback"]=boolean(a,L"--raw",false)?L"1":L"0";
    if(a.has(L"--raw-default-denylist"))request.options[L"raw_use_default_denylist"]=boolean(a,L"--raw-default-denylist",true)?L"1":L"0";
    if(a.has(L"--auto-children"))request.autoChildren=boolean(a,L"--auto-children",false);
    request.useR0Injection=boolean(a,L"--r0-inject",false);
    if(a.has(L"--call-stack"))request.options[L"capture_call_stack"]=boolean(a,L"--call-stack",false)?L"1":L"0";
    request.collectTimeline=boolean(a,L"--timeline",false);
    std::wstring filterFile;
    if(a.has(L"--filter-file")) {
        filterFile=std::filesystem::absolute(a.require(L"--filter-file")).wstring();
        auto imported=loadApiFilters(filterFile);
        request.importedPreFilter=std::move(imported.pre);request.importedPostFilter=std::move(imported.post);
    }
    std::unique_ptr<CliSignatureCatalog> signatures;
    if(boolean(a,L"--signatures",false)) {
        signatures=std::make_unique<CliSignatureCatalog>();
        signatures->load(std::filesystem::path(defaultAgent()).parent_path()/L"profiles"/L"api_monitor_definitions.json");
    }
    for(const auto& [option,filter,isApi] : {
        std::tuple{L"--pre-exclude-modules",&request.preFilter,false},
        std::tuple{L"--pre-exclude-apis",&request.preFilter,true},
        std::tuple{L"--post-exclude-modules",&request.postFilter,false},
        std::tuple{L"--post-exclude-apis",&request.postFilter,true}})
        if(a.has(option))filter->addList(a.require(option),isApi);
    for(const auto& names : {std::pair{L"--raw-modules",L"raw_modules"},std::pair{L"--raw-exclude",L"raw_denylist"}})
        if(a.has(names.first)){const auto value=a.require(names.first);scalar(value);request.options[names.second]=value;}
    Cancellation cancel;const auto result=m::captureApiMonitor(request,*cancel.token);
    std::vector<Json> events,processes;
    std::uint64_t postFiltered = 0;
    for(const auto& packet:result.events) {
        if(request.postFilter.excludes(packet) || request.importedPostFilter.excludes(packet)) { ++postFiltered; continue; }
        Json declaration,match;
        if(signatures && !m::isCoverageEvent(packet.eventKind)
            && packet.category!=static_cast<std::uint32_t>(m::EventCategory::Internal)) {
            const auto remote=sha(packet);
            const std::wstring local(signatures->sha256.begin(),signatures->sha256.end());
            if(remote.size()==64) {
                const bool same=::CompareStringOrdinal(remote.c_str(),64,local.c_str(),64,TRUE)==CSTR_EQUAL;
                match=Json::boolean(same);
                if(same)if(const auto* s=signatures->find(wide(packet.moduleName),wide(packet.apiName)))declaration=signatureJson(*s);
            }
        }
        events.push_back(packetJson(packet,declaration,match));
    }
    Json timeline;
    if(request.collectTimeline) {
        static constexpr const wchar_t* names[]={L"file",L"registry",L"network",L"process",L"loader",L"clipboard",L"memory",L"thread",L"service",L"security",L"crypto",L"com",L"window",L"gui",L"other"};
        std::vector<Json> cells;
        for(const auto& [index,counts]:result.timeline.buckets) for(std::size_t i=0;i<counts.size();++i) {
            const auto& c=counts[i];if(!c.count)continue;
            cells.push_back(Json::object({{L"category",Json::string(names[i])},{L"bucketStartFileTime",Json::count(index*result.timeline.width)},
                {L"firstFileTime",Json::count(c.first)},{L"lastFileTime",Json::count(c.last)},{L"count",Json::count(c.count)}}));
        }
        timeline=Json::object({{L"bucketWidth100ns",Json::count(result.timeline.width)},
            {L"firstFileTime",Json::count(result.timeline.first)},{L"lastFileTime",Json::count(result.timeline.last)},
            {L"eventCount",Json::count(result.timeline.count)},{L"missingTimeCount",Json::count(result.timeline.missing)},
            {L"cells",Json::array(cells)}});
    }
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
            {L"coverageRevision",Json::count(p.revision)},{L"finalCoverageRevision",Json::count(p.finalRevision)},
            {L"coverageStateCounts",Json::object(states)},{L"coverage",Json::array(coverage)}}));}
    std::vector<std::pair<std::wstring,Json>> options;for(const auto& [key,value]:request.options)options.emplace_back(key,Json::string(value));
    return {result.code,Json::object({{L"source",Json::string(L"API Monitor Agent; shared native injection/session/coverage protocol")},
        {L"pid",Json::number(request.pid)},{L"sessionId",Json::string(result.sessionId)},{L"agentPath",Json::string(result.agentPath)},
        {L"configPath",Json::string(result.configPath)},{L"stopPath",Json::string(result.stopPath)},{L"configPublished",Json::boolean(result.configPublished)},
        {L"reusedResident",Json::boolean(result.reusedResident)},{L"injectionBackendRequested",Json::string(request.useR0Injection?L"r0":L"r3")},
        {L"requestedDurationMs",Json::number(request.durationMs)},{L"elapsedMs",Json::count(result.elapsedMs)},
        {L"cancelled",Json::boolean(result.cancelled)},{L"completedRequestedInterval",Json::boolean(result.completedInterval)},
        {L"stopWritten",Json::boolean(result.stopWritten)},{L"cleanupComplete",Json::boolean(result.cleanupComplete)},
        {L"receivedCount",Json::count(result.received)},{L"returnedCount",Json::count(events.size())},{L"bufferDroppedCount",Json::count(result.bufferDropped)},
        {L"preFilteredCount",Json::count(result.preFiltered)},{L"postFilteredRetainedCount",Json::count(postFiltered)},
        {L"filterFile",filterFile.empty()?Json{}:Json::string(filterFile)},
        {L"timeline",timeline},
        {L"signatureCatalog",signatures?Json::object({{L"path",Json::string(signatures->filePath)},
            {L"sha256",Json::string(std::wstring(signatures->sha256.begin(),signatures->sha256.end()))},
            {L"count",Json::count(signatures->size())}}):Json{}},
        {L"invalidPacketCount",Json::count(result.invalidPackets)},{L"autoChildren",Json::boolean(request.autoChildren)},
        {L"options",Json::object(options)},{L"processes",Json::array(processes)},{L"events",Json::array(events)}}),result.errors};
}
}
void registerMonitorApi() {
    addCommand({L"monitor api capture",
        L"KswordCLI.exe monitor api capture --pid PID [--agent PATH] [--duration-ms N] [--limit N] [--categories LIST] [--raw 0|1] [--raw-modules LIST] [--raw-exclude LIST] [--raw-default-denylist 0|1] [--auto-children 0|1] [--r0-inject 0|1] [--call-stack 0|1] [--timeline 0|1] [--signatures 0|1] [--filter-file PATH] [--pre-exclude-modules LIST] [--pre-exclude-apis LIST] [--post-exclude-modules LIST] [--post-exclude-apis LIST] [--options-file PATH] [--startup-timeout-ms N] [--stop-timeout-ms N] --confirm [--backend r3] [--json]",
        L"Capture API Monitor events and coverage, then request and verify hook removal.",
        L"Required: --pid >4, --confirm. Default Agent beside CLI, auto-selected x64/x86. --duration-ms 100..120000 (1000 after HooksInstalled); --limit 1..100000 (5000 latest events); --categories comma-separated file,registry,network,process,loader,clipboard,memory,thread,service,security,crypto,com,window,gui (Agent defaults; gui defaults off); --raw, --auto-children, --raw-default-denylist, --r0-inject, --call-stack, --timeline and --signatures use 0/1. --r0-inject defaults to 0 and explicitly selects the existing R0 injection driver for the root and any auto-injected children. --filter-file imports GUI winapi-filter.cfg v1/v2; explicit excludes add unconditional rejections. Raw modules/exclusions and pre/post exclude lists use semicolons; API identities are exact module!function. --signatures 1 loads profiles/api_monitor_definitions.json beside CLI. --options-file imports [monitor] business options including Fake Success and clipboard policy, never controller paths/identity. CLI options override INI. --startup-timeout-ms 1000..120000 (30000); --stop-timeout-ms 1000..120000 (15000).",
        L"Uses the main application's injection and session lease; R3 is default, --r0-inject 1 requires the existing R0 driver and does not fall back. injectionBackendRequested records the selection; reusedResident indicates no new injection was required. R0 checks target creation identity in user mode before and after the driver request, but the existing PID-only driver protocol has a residual PID-reuse race. Target creation identity and named-pipe server PID are checked. Requires target injection/VM permissions; no elevation. JSON/text include events, complete per-PID coverage, hook install/remove, loss and cleanup evidence. --call-stack 1 or INI capture_call_stack=1 enables optional bounded strong-hook stacks. --pre-exclude-* rejects received business events before the bounded buffer; --post-exclude-* hides only retained output events. Internal and coverage events are never filtered; neither changes installed hooks. preFilteredCount and postFilteredRetainedCount report different stages. --timeline 1 aggregates pre-accepted ApiCall events by time and category, including post-hidden and buffer-evicted events, not lost/pre-rejected events; it is approximate and bounded to 2048 buckets. Raw entry snapshots expose captured registers/stack words without assuming argument types. --signatures 1 displays declarations only when the local file SHA-256 matches the Agent hash; project, SDK-checked and unverified reference sources are distinct, and no argument values are inferred. Marked business calls expose returnValueAvailable/returnValue (hex bit pattern) and durationAvailable/duration100ns (decimal string); unavailable values are null. Raw resultCode is null. Latest-event truncation, Agent loss, partial hooks, cancellation, interrupted capture or unconfirmed cleanup returns 6; startup failure 3; parameter error 1. Only complete ordered coverage snapshots are committed. Stop markers stay for resident/late Agents; DLL and retired trampolines remain until target exit. Cross-bitness needs matching Agent DLLs beside the CLI. Help never injects.",capture});
}
}
