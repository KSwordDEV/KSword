#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessPeb.h"
#include <algorithm>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process_detail::peb;
Json evidence(const ks::r3::process_detail::ProcessQueryEvidence& e) {return Json::object({{L"available",Json::boolean(e.available)},
    {L"win32Error",e.win32ErrorKnown ? Json::number(e.win32Error) : Json{}}, {L"ntStatus",e.ntStatusKnown ? Json::hex(static_cast<DWORD>(e.ntStatus)) : Json{}}});}
std::wstring view(const Args& args) {
    const auto name=args.get(L"--view",L"auto");if (name!=L"auto" && name!=L"native" && name!=L"wow64") throw std::invalid_argument("--view must be auto, native or wow64");return name;
}
const backend::PebReadResult* selected(const backend::PebCollectionEvidence& data,const std::wstring& mode) {
    if (mode!=L"native") for (const auto& r:data.pebs) if (r.wow64) return &r;
    if (mode==L"wow64") return nullptr;
    for (const auto& r:data.pebs) if (!r.wow64) return &r;
    return nullptr;
}
int missing(const backend::PebCollectionEvidence& data,const std::wstring& mode) {
    const auto& q=mode==L"wow64" ? data.wow64Query : data.nativeQuery;
    if (q.win32ErrorKnown && q.win32Error==ERROR_INVALID_DATA) return 4;
    const auto status=static_cast<DWORD>(q.ntStatus);
    return q.available || (q.win32ErrorKnown && q.win32Error==ERROR_PROC_NOT_FOUND) ||
        (q.ntStatusKnown && (status==0xc0000002 || status==0xc0000003 || status==0xc00000bb)) ? 5 : 3;
}
Json context(const process::Lease& lease,const backend::PebCollectionEvidence& data) {return Json::object({{L"target",lease.json()},
    {L"source",Json::string(L"shared R3 PEB collection")}, {L"nativeQuery",evidence(data.nativeQuery)}, {L"wow64Query",evidence(data.wow64Query)}});}
Result query(const Args& args) {
    const auto mode=view(args);process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    backend::PebCollectionEvidence data;backend::CollectPebSnapshot(lease.pid,lease.creationTime,mode==L"wow64"?1:0,&data,false,false);
    if (!data.identityMatched || !lease.alive()) return {3,context(lease,data),{L"PEB target could not be retained or exited during collection."}};
    const auto* r=selected(data,mode);
    if (!r) return {missing(data,mode),context(lease,data),{L"Requested PEB view is absent or its native query failed."}};
    const auto field=[r](const wchar_t* key,const std::wstring& text) {
        const auto found=r->evidence.find(key);const auto e=found==r->evidence.end()?ks::r3::process_detail::ProcessQueryEvidence{}:found->second;
        return Json::object({{L"value",e.available?Json::string(text):Json{}}, {L"evidence",evidence(e)}});
    };
    bool complete=r->headerKnown && r->parametersKnown, malformed=false;
    for (const auto* key:{L"command-line",L"image-path",L"current-directory"}) {
        const auto found=r->evidence.find(key);complete=complete && found!=r->evidence.end() && found->second.available;
    }
    std::vector<std::pair<std::wstring,Json>> errors;
    for (const auto& [name,e]:r->evidence) {errors.emplace_back(name,evidence(e));malformed=malformed || (e.win32ErrorKnown && e.win32Error==ERROR_INVALID_DATA);}
    return {malformed?4:!r->headerKnown?3:complete?0:6,Json::object({{L"context",context(lease,data)}, {L"view",Json::string(r->wow64?L"wow64":L"native")},
        {L"pebAddress",Json::hex(r->pebAddress)}, {L"headerKnown",Json::boolean(r->headerKnown)}, {L"parametersKnown",Json::boolean(r->parametersKnown)},
        {L"beingDebugged",r->headerKnown?Json::boolean(r->beingDebugged):Json{}}, {L"imageBase",r->headerKnown?Json::hex(r->imageBaseAddress):Json{}},
        {L"processParameters",r->headerKnown?Json::hex(r->processParametersAddress):Json{}}, {L"environmentAddress",r->parametersKnown?Json::hex(r->environmentAddress):Json{}},
        {L"commandLine",field(L"command-line",r->commandLine)}, {L"imagePath",field(L"image-path",r->imagePath)}, {L"currentDirectory",field(L"current-directory",r->currentDirectory)},
        {L"readEvidence",Json::object(errors)}}),complete?std::vector<std::wstring>{}:std::vector<std::wstring>{r->diagnostic,L"Unavailable fields are null; a readable PEB header does not imply readable process parameters or strings."}};
}
Result environment(const Args& args) {
    const auto mode=view(args);const auto limit=args.u32(L"--limit",20);if (!limit || limit>65535) throw std::invalid_argument("--limit must be 1..65535");
    process::Lease lease(args,PROCESS_QUERY_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ|SYNCHRONIZE);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Readable process identity is unavailable, mismatched or has exited."}};
    backend::PebCollectionEvidence data;backend::CollectPebSnapshot(lease.pid,lease.creationTime,mode==L"wow64"?1:0,&data,false,false);
    const auto* r=selected(data,mode);
    if (!data.identityMatched || !lease.alive()) return {3,context(lease,data),{L"PEB target exited or could not be retained."}};
    if (!r) return {missing(data,mode),context(lease,data),{L"Requested PEB view is absent."}};
    if (!r->parametersKnown || !r->environmentAddress) return {5,context(lease,data),{L"Selected process parameters do not provide a readable environment address."}};
    backend::EnvironmentEvidence state;std::wstring diagnostic;
    backend::ReadEnvironmentPreview(lease.handle.get(),r->environmentAddress,diagnostic,&state);
    std::vector<Json> rows;DWORD matched=0;
    for (const auto& line:state.lines) {
        const auto separator=line.find(L'=',line.starts_with(L"=")?1:0);
        const auto name=separator==std::wstring::npos?line:line.substr(0,separator);
        if (args.has(L"--name") && _wcsicmp(name.c_str(),args.get(L"--name").c_str())!=0) continue;
        ++matched;if (rows.size()>=limit) continue;
        rows.push_back(Json::object({{L"name",Json::string(name)}, {L"value",separator==std::wstring::npos?Json{}:Json::string(line.substr(separator+1))}, {L"raw",Json::string(line)}}));
    }
    if (!lease.alive()) return {3,context(lease,data),{L"Target exited during environment collection."}};
    const bool truncated=matched>rows.size();
    const int code=state.win32Error==ERROR_INVALID_DATA?4:state.complete?truncated?6:0:state.lines.empty()&&!state.limited?3:6;
    return {code,Json::object({{L"target",lease.json()}, {L"view",Json::string(r->wow64?L"wow64":L"native")}, {L"environmentAddress",Json::hex(r->environmentAddress)},
        {L"complete",Json::boolean(state.complete)}, {L"budgetLimited",Json::boolean(state.limited)}, {L"win32Error",Json::number(state.win32Error)},
        {L"bytesRead",Json::count(state.bytesRead)}, {L"matchedCount",Json::number(matched)}, {L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},
        {L"truncated",Json::boolean(truncated)}, {L"entries",Json::array(rows)}}),code?std::vector<std::wstring>{diagnostic,L"Environment read or output is incomplete; values describe a read-only point-in-time view."}:std::vector<std::wstring>{}};
}
Json region(const backend::RegionInfo& r) {return Json::object({{L"base",Json::hex(r.base)}, {L"allocationBase",Json::hex(r.allocationBase)},
    {L"size",Json::count(r.size)}, {L"state",Json::hex(r.state)}, {L"stateText",Json::string(backend::MemoryStateText(r.state))},
    {L"type",Json::hex(r.type)}, {L"typeText",Json::string(backend::MemoryTypeText(r.type))}, {L"protect",Json::hex(r.protect)},
    {L"protectText",Json::string(backend::MemoryProtectText(r.protect))}, {L"allocationProtect",Json::hex(r.allocationProtect)},
    {L"mappedPath",r.mappedPathKnown?Json::string(r.mappedPath):Json{}}, {L"mappedPathWin32Error",r.type==MEM_IMAGE||r.type==MEM_MAPPED?Json::number(r.mappedPathError):Json{}}});}
Result memory(const Args& args) {
    const auto limit=args.u32(L"--limit",40);if (!limit || limit>40) throw std::invalid_argument("--limit must be 1..40");
    const auto address=args.integer(L"--address");
    process::Lease lease(args,PROCESS_QUERY_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ|SYNCHRONIZE);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Queryable process identity is unavailable, mismatched or has exited."}};
    if (args.has(L"--address")) {
        backend::RegionInfo r;DWORD error=0;const bool ok=backend::QueryMemoryRegion(lease.handle.get(),address,r,error);
        if (!lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Target exited during memory query."}};
        const bool pathMissing=ok && (r.type==MEM_IMAGE||r.type==MEM_MAPPED) && !r.mappedPathKnown;
        return {error==ERROR_INVALID_DATA?4:!ok?3:pathMissing?6:0,Json::object({{L"target",lease.json()}, {L"source",Json::string(L"shared R3 VirtualQueryEx")},
            {L"address",Json::hex(address)}, {L"win32Error",Json::number(error)}, {L"region",ok?region(r):Json{}}}),!ok?std::vector<std::wstring>{L"Native memory-region query failed or returned an invalid extent."}:pathMissing?std::vector<std::wstring>{L"Region is valid but mapped path is unavailable."}:std::vector<std::wstring>{}};
    }
    backend::PebCollectionEvidence data;backend::CollectPebSnapshot(lease.pid,lease.creationTime,0,&data,false,true);
    if (!data.identityMatched || !lease.alive()) return {3,context(lease,data),{L"Memory target exited or could not be retained."}};
    std::vector<Json> rows;bool pathsMissing=false;
    for (const auto& r:data.regions) {if (rows.size()>=limit) break;rows.push_back(region(r));pathsMissing=pathsMissing || ((r.type==MEM_IMAGE||r.type==MEM_MAPPED)&&!r.mappedPathKnown);}
    const bool truncated=data.committedRegionCount>rows.size();
    const int code=data.regionsMalformed?4:!data.regionCount?3:!data.regionsComplete||data.regionsLimited||truncated||pathsMissing?6:0;
    return {code,Json::object({{L"target",lease.json()}, {L"source",Json::string(L"shared R3 bounded virtual-region collection")},
        {L"complete",Json::boolean(data.regionsComplete)}, {L"budgetLimited",Json::boolean(data.regionsLimited)}, {L"win32Error",Json::number(data.regionsError)},
        {L"regionCount",Json::count(data.regionCount)}, {L"committedRegionCount",Json::count(data.committedRegionCount)}, {L"commitBytes",Json::count(data.commitBytes)},
        {L"mappedBytes",Json::count(data.mappedBytes)}, {L"imageBytes",Json::count(data.imageBytes)}, {L"privateBytes",Json::count(data.privateBytes)},
        {L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))}, {L"truncated",Json::boolean(truncated)}, {L"regions",Json::array(rows)}}),code?std::vector<std::wstring>{L"Committed preview, mapped metadata or address-space traversal is incomplete. Backend limits: 40 preview rows, 60000 regions, 8 seconds."}:std::vector<std::wstring>{}};
}
Result affinity(const Args& args) {
    (void)args.require(L"--confirm");const auto mask=args.integer(L"--mask");(void)args.require(L"--mask");
    if (!mask) throw std::invalid_argument("--mask must be positive");process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    DWORD_PTR before=0,beforeSystem=0,after=0,afterSystem=0;
    const bool beforeKnown=GetProcessAffinityMask(lease.handle.get(),&before,&beforeSystem)!=FALSE;
    const DWORD beforeError=beforeKnown?ERROR_SUCCESS:GetLastError();
    const auto outcome=backend::SetProcessAffinity(lease.pid,lease.creationTime,mask);
    const bool afterKnown=GetProcessAffinityMask(lease.handle.get(),&after,&afterSystem)!=FALSE;
    const DWORD afterError=afterKnown?ERROR_SUCCESS:GetLastError();const bool verified=outcome.requestSucceeded&&afterKnown&&after==mask&&lease.alive();
    return {!outcome.requestSucceeded?3:verified?0:6,Json::object({{L"target",lease.json()}, {L"requestedMask",Json::hex(mask)},
        {L"requestSucceeded",Json::boolean(outcome.requestSucceeded)}, {L"writeAttempted",Json::boolean(outcome.writeAttempted)}, {L"verified",Json::boolean(verified)},
        {L"win32Error",outcome.win32ErrorKnown?Json::number(outcome.win32Error):Json{}},
        {L"before",Json::object({{L"known",Json::boolean(beforeKnown)}, {L"mask",beforeKnown?Json::hex(before):Json{}}, {L"systemMask",beforeKnown?Json::hex(beforeSystem):Json{}}, {L"win32Error",Json::number(beforeError)}})},
        {L"after",Json::object({{L"known",Json::boolean(afterKnown)}, {L"mask",afterKnown?Json::hex(after):Json{}}, {L"systemMask",afterKnown?Json::hex(afterSystem):Json{}}, {L"win32Error",Json::number(afterError)}})}}),verified?std::vector<std::wstring>{}:std::vector<std::wstring>{outcome.statusText,L"Affinity request failed or its readback did not match."}};
}
}
void registerProcessPeb() {
    addCommand({L"process peb query",L"KswordCLI.exe process peb query --pid PID [--creation-time FILETIME] [--view auto|native|wow64] [--backend r3] [--json]",
        L"Read PEB identity, addresses, debugger state and process-parameter strings.",L"Required: --pid. Optional: --creation-time, --view (auto), --backend r3, --json.",
        L"Output: context with native/wow64 query evidence, selected view, PEB/image/parameters/environment addresses, beingDebugged, strings with value/read evidence. Auto prefers WOW64 when present. Missing view returns 5, failed reads 3, invalid data 4, partial fields 6. No remote PEB writes, skipped UI edits or heap-block enumeration are published.",query});
    addCommand({L"process peb environment query",L"KswordCLI.exe process peb environment query --pid PID [--creation-time FILETIME] [--view auto|native|wow64] [--name NAME] [--limit N] [--backend r3] [--json]",
        L"Read a bounded environment block and optionally filter one variable.",L"Required: --pid. Optional: --creation-time, --view (auto), --name (case-insensitive), --limit (20), --backend r3, --json.",
        L"Output: target/view/address, complete/budgetLimited, win32Error, bytesRead, counts, truncated, entries name/value/raw. Reads at most 128 KiB until double NUL. Filtering applies to the received complete lines before output limiting. Valid empty results succeed; incomplete block or limited output returns 6.",environment});
    addCommand({L"process memory regions query",L"KswordCLI.exe process memory regions query --pid PID [--creation-time FILETIME] [--address ADDRESS] [--limit N] [--backend r3] [--json]",
        L"Query one address or bounded committed-region preview with totals.",L"Required: --pid. Optional: --creation-time, --address, --limit (1..40, default 40), --backend r3, --json.",
        L"Output: one region for address, or traversal counters/complete/budgetLimited and committed regions. Region fields: base/allocationBase/size/state/type/protect/allocationProtect/mappedPath and native error. Addresses/masks use hex strings; 64-bit counters decimal strings. Global backend limits 60000 regions and 8 seconds. Missing mapped path or preview/traversal truncation returns 6. Read-only; no R0 fallback.",memory});
    addCommand({L"process settings set-affinity",L"KswordCLI.exe process settings set-affinity --pid PID --mask MASK [--creation-time FILETIME] --confirm [--backend r3] [--json]",
        L"Set the implemented process affinity mask and verify it.",L"Required: --pid, --mask (positive decimal/hex), --confirm. Optional: --creation-time, --backend r3, --json.",
        L"Output: target, requestedMask, requestSucceeded/writeAttempted/verified, before/after process and system masks and original errors. Uses SetProcessAffinityMask within its processor-group limits; does not modify priority or PEB fields. Query/set rights required. Native failure returns 3, unconfirmed readback 6. Priority is available separately through process settings set-priority.",affinity});
}
}
