#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessThreadsSupport.h"
#include "../shared/usermode/backend/process/ThreadActions.h"
#include <algorithm>
#include <sstream>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process_detail;
namespace affinity = ksword::thread_affinity_r3;
Json evidence(const backend::ProcessQueryEvidence& e) {
    return Json::object({{L"available",Json::boolean(e.available)}, {L"win32Error",e.win32ErrorKnown ? Json::number(e.win32Error) : Json{}},
        {L"ntStatus",e.ntStatusKnown ? Json::hex(static_cast<DWORD>(e.ntStatus)) : Json{}}});
}
Result enumeration(const Args& args) {
    const auto limit = args.u32(L"--limit",1000), tid = args.u32(L"--tid");
    if (!limit) throw std::invalid_argument("--limit must be positive");
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    bool ok = false; std::wstring detail; backend::detail::ThreadEnumerationEvidence state;
    const auto items = backend::detail::CollectThreads(lease.pid,ok,detail,&state);
    if (!lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process exited during thread enumeration."}};
    std::vector<Json> rows; std::uint32_t matched = 0; bool partial = !state.complete || state.skippedCount != 0;
    for (const auto& r : items) {
        if (args.has(L"--tid") && r.threadId != tid) continue;
        ++matched; if (rows.size() >= limit) continue;
        partial = partial || !r.identityKnown || !r.startAddressKnown || !r.suspendCountKnown;
        rows.push_back(Json::object({{L"tid",Json::number(r.threadId)}, {L"pid",Json::number(r.ownerProcessId)},
            {L"creationTime",r.identityKnown ? Json::count(r.creationTime100ns) : Json{}}, {L"basePriority",Json::signedNumber(r.basePriority)},
            {L"deltaPriority",Json::signedNumber(r.deltaPriority)}, {L"startAddress",r.startAddressKnown ? Json::hex(r.startAddress) : Json{}},
            {L"suspendCount",r.suspendCountKnown ? Json::number(r.suspendCount) : Json{}}, {L"identityEvidence",evidence(r.queryEvidence)},
            {L"startEvidence",evidence(r.startEvidence)}, {L"suspendEvidence",evidence(r.suspendEvidence)}}));
    }
    const bool truncated = matched > rows.size();
    return {!ok ? 3 : partial || truncated ? 6 : 0,Json::object({{L"target",lease.json()}, {L"source",Json::string(L"Toolhelp and native thread queries")},
        {L"complete",Json::boolean(state.complete)}, {L"skippedCount",Json::number(state.skippedCount)}, {L"win32Error",Json::number(state.win32Error)},
        {L"matchedCount",Json::number(matched)}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))},
        {L"truncated",Json::boolean(truncated)}, {L"threads",Json::array(rows)}}), !ok ? std::vector<std::wstring>{detail} :
        partial || truncated ? std::vector<std::wstring>{L"Some thread evidence is unavailable, stale rows were skipped, or output was limited."} : std::vector<std::wstring>{}};
}
struct ThreadLease {
    process::Lease process;
    ks::r3::common::UniqueHandle handle;
    DWORD tid = 0, error = 0;
    std::uint64_t creation = 0;
    bool matches = false;
    explicit ThreadLease(const Args& args) : process(args) {
        tid = args.u32(L"--tid"); (void)args.require(L"--tid");
        const auto expected = args.integer(L"--thread-creation-time");
        (void)args.require(L"--thread-creation-time");
        if (!tid || !expected) throw std::invalid_argument("--tid and --thread-creation-time must be positive");
        if (!process.matches || !process.alive()) return;
        handle.reset(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,FALSE,tid));
        if (!handle.valid()) {error = GetLastError();return;}
        const auto owner = GetProcessIdOfThread(handle.get());
        if (!owner) {error = GetLastError();return;}
        FILETIME c{},x{},k{},u{};
        if (!GetThreadTimes(handle.get(),&c,&x,&k,&u)) {error = GetLastError();return;}
        creation = (static_cast<std::uint64_t>(c.dwHighDateTime)<<32) | c.dwLowDateTime;
        matches = owner == process.pid && creation == expected && WaitForSingleObject(handle.get(),0) == WAIT_TIMEOUT;
    }
    Json json() const {return Json::object({{L"process",process.json()}, {L"tid",Json::number(tid)},
        {L"creationTime",creation ? Json::count(creation) : Json{}}, {L"identityMatched",Json::boolean(matches)}, {L"win32Error",Json::number(error)}});}
};
Json affinityJson(const affinity::Snapshot& state, bool ok) {
    std::vector<Json> rows;
    if (ok) for (const auto& p : state.processors) rows.push_back(Json::object({{L"group",Json::number(p.coordinate.group)},
        {L"logicalIndex",Json::number(p.coordinate.logicalIndex)}, {L"cpuSetId",Json::number(p.cpuSetId)}, {L"coreIndex",Json::number(p.coreIndex)},
        {L"efficiencyClass",Json::number(p.efficiencyClass)}, {L"available",Json::boolean(p.available)}, {L"selected",Json::boolean(p.selected)},
        {L"parked",Json::boolean(p.parked)}, {L"constrained",Json::boolean(p.constrainedByThreadOrProcessAffinity)}}));
    return Json::object({{L"known",Json::boolean(ok)}, {L"usesCpuSets",ok ? Json::boolean(state.usesCpuSets) : Json{}},
        {L"followsProcess",ok ? Json::boolean(state.followsProcessCpuSets) : Json{}}, {L"processors",ok ? Json::array(rows) : Json{}}});
}
affinity::Rule rule(const Args& args) {
    const auto input = args.require(L"--processors"); affinity::Rule result;
    if (input == L"follow") {result.followProcessCpuSets = true;return result;}
    std::wistringstream stream(input);std::wstring item;
    while (std::getline(stream,item,L',')) {
        const auto sep = item.find(L':');
        if (sep == std::wstring::npos) throw std::invalid_argument("--processors expects GROUP:INDEX[,GROUP:INDEX] or follow");
        Args numbers; numbers.values[L"--group"] = item.substr(0,sep); numbers.values[L"--index"] = item.substr(sep+1);
        const auto group = numbers.u32(L"--group"), index = numbers.u32(L"--index");
        if (group > 65535 || index > 63) throw std::invalid_argument("processor coordinate is out of range");
        const affinity::LogicalProcessorCoordinate c{static_cast<std::uint16_t>(group),static_cast<std::uint16_t>(index)};
        if (std::find(result.processors.begin(),result.processors.end(),c) != result.processors.end()) throw std::invalid_argument("duplicate processor coordinate");
        result.processors.push_back(c);
    }
    if (result.processors.empty() || input.back() == L',') throw std::invalid_argument("empty processor coordinate");
    affinity::normalizeCoordinates(&result.processors); return result;
}
Result queryAffinity(const Args& args) {
    ThreadLease lease(args);
    if (!lease.matches) return {3,Json::object({{L"target",lease.json()}}),{L"Thread or process identity is unavailable, changed, or has exited."}};
    affinity::Snapshot state;std::string detail;
    const bool ok = affinity::QueryThreadAffinityState(lease.tid,lease.process.pid,lease.creation,&state,&detail);
    const bool alive = lease.process.alive() && WaitForSingleObject(lease.handle.get(),0) == WAIT_TIMEOUT;
    return {ok && alive ? 0 : 3,Json::object({{L"target",lease.json()}, {L"source",Json::string(L"shared R3 CPU Sets / group affinity")},
        {L"state",affinityJson(state,ok && alive)}}), ok && alive ? std::vector<std::wstring>{} : std::vector<std::wstring>{backend::thread_actions::Utf8ToWide(detail),L"Thread affinity query failed or target exited."}};
}
struct SuspendState {bool known = false;ULONG count = 0;bool statusKnown = false;LONG status = 0;};
SuspendState suspended(HANDLE h) {
    SuspendState result; const auto api = backend::detail::LoadNtThreadApi();
    if (api.available()) {result.statusKnown = true;result.status = api.queryInformationThread(h,35,&result.count,sizeof(result.count),nullptr);result.known = result.status == 0;}
    return result;
}
Json suspendJson(const SuspendState& value) {return Json::object({{L"known",Json::boolean(value.known)},
    {L"count",value.known ? Json::number(value.count) : Json{}}, {L"ntStatus",value.statusKnown ? Json::hex(static_cast<DWORD>(value.status)) : Json{}}});}
Result action(const Args& args, const std::wstring& verb) {
    (void)args.require(L"--confirm"); const auto requested = verb == L"set-affinity" ? rule(args) : affinity::Rule{};
    ThreadLease lease(args);
    if (!lease.matches) return {3,Json::object({{L"target",lease.json()}}),{L"Thread or process identity is unavailable, changed, or has exited."}};
    const auto before = suspended(lease.handle.get()); backend::ProcessDetailActionResult outcome;
    affinity::Snapshot affinityBefore;std::string affinityDetail;
    const bool affinityBeforeKnown = verb == L"set-affinity" &&
        affinity::QueryThreadAffinityState(lease.tid,lease.process.pid,lease.creation,&affinityBefore,&affinityDetail);
    if (verb == L"suspend") outcome = backend::SuspendDetailThread(lease.tid,lease.creation,lease.process.pid,lease.process.creationTime);
    else if (verb == L"resume") outcome = backend::ResumeDetailThread(lease.tid,lease.creation,lease.process.pid,lease.process.creationTime);
    else if (verb == L"terminate") outcome = backend::TerminateDetailThread(lease.tid,lease.creation,lease.process.pid,lease.process.creationTime);
    else outcome = backend::SetDetailThreadAffinity(lease.tid,lease.creation,lease.process.pid,lease.process.creationTime,requested);
    bool verified = false, rollbackVerified = false; Json observed;
    if (verb == L"terminate") {
        const DWORD wait = WaitForSingleObject(lease.handle.get(),outcome.requestSucceeded ? 2000 : 0); DWORD exitCode = STILL_ACTIVE;
        const bool known = GetExitCodeThread(lease.handle.get(),&exitCode) != FALSE;
        verified = wait == WAIT_OBJECT_0 && known && exitCode == 1;
        observed = Json::object({{L"exited",Json::boolean(wait == WAIT_OBJECT_0)}, {L"exitCode",known ? Json::number(exitCode) : Json{}}});
    } else if (verb == L"set-affinity") {
        affinity::Snapshot state;std::string detail;
        const bool ok = affinity::QueryThreadAffinityState(lease.tid,lease.process.pid,lease.creation,&state,&detail);
        std::vector<affinity::LogicalProcessorCoordinate> selected;
        for (const auto& p : state.processors) if (p.selected) selected.push_back(p.coordinate);
        affinity::normalizeCoordinates(&selected);
        verified = ok && (requested.followProcessCpuSets ? state.followsProcessCpuSets : !state.followsProcessCpuSets && selected == requested.processors);
        std::vector<affinity::LogicalProcessorCoordinate> original;
        for (const auto& p : affinityBefore.processors) if (p.selected) original.push_back(p.coordinate);
        affinity::normalizeCoordinates(&original);
        rollbackVerified = outcome.rollbackAttempted && affinityBeforeKnown && ok && state.usesCpuSets == affinityBefore.usesCpuSets &&
            state.followsProcessCpuSets == affinityBefore.followsProcessCpuSets && original == selected;
        observed = affinityJson(state,ok);
    } else {
        const auto after = suspended(lease.handle.get());
        const auto previous = outcome.previousSuspendCount;
        verified = outcome.previousSuspendCountKnown && after.known && after.count == (verb == L"suspend" ? previous+1 : previous ? previous-1 : 0);
        observed = Json::object({{L"before",suspendJson(before)}, {L"after",suspendJson(after)}});
    }
    if (verb != L"terminate" && (!lease.process.alive() || WaitForSingleObject(lease.handle.get(),0) != WAIT_TIMEOUT)) {verified = false;rollbackVerified = false;}
    const int code = !outcome.requestSucceeded ? outcome.writeSucceeded && !rollbackVerified ? 6 : 3 : verified ? 0 : 6;
    return {code,Json::object({{L"target",lease.json()}, {L"action",Json::string(verb)}, {L"requestSucceeded",Json::boolean(outcome.requestSucceeded)},
        {L"verified",Json::boolean(outcome.requestSucceeded && verified)}, {L"identityMatched",Json::boolean(outcome.identityMatched)},
        {L"previousSuspendCount",outcome.previousSuspendCountKnown ? Json::number(outcome.previousSuspendCount) : Json{}},
        {L"win32Error",outcome.win32ErrorKnown ? Json::number(outcome.win32Error) : Json{}},
        {L"writeAttempted",Json::boolean(outcome.writeAttempted)}, {L"writeSucceeded",Json::boolean(outcome.writeSucceeded)},
        {L"rollbackAttempted",Json::boolean(outcome.rollbackAttempted)}, {L"rollbackSucceeded",outcome.rollbackAttempted ? Json::boolean(outcome.rollbackSucceeded) : Json{}},
        {L"rollbackVerified",outcome.rollbackAttempted ? Json::boolean(rollbackVerified) : Json{}},
        {L"observed",observed}}),code ? std::vector<std::wstring>{outcome.statusText,L"The request failed or its effect could not be confirmed."} : std::vector<std::wstring>{}};
}
}
void registerProcessThreads() {
    addCommand({L"process thread enum",L"KswordCLI.exe process thread enum --pid PID [--creation-time FILETIME] [--tid TID] [--limit N] [--backend r3] [--json]",
        L"Enumerate threads with creation identity and native query evidence.",L"Required: --pid. Optional: --creation-time, --tid, --limit (1000), --backend r3, --json.",
        L"Output: target, counts, complete, skippedCount, threads with signed priorities, creationTime, startAddress, suspendCount and per-query evidence. Unknown values are null. Limited output or missing evidence returns 6. A valid empty filter returns 0.",enumeration});
    addCommand({L"process thread affinity query",L"KswordCLI.exe process thread affinity query --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] [--backend r3] [--json]",
        L"Read verified thread CPU Set or group affinity.",L"Required: --pid, --tid, --thread-creation-time. Optional: --creation-time, --backend r3, --json.",
        L"Output: target, state with usesCpuSets, followsProcess and logical processor coordinates/availability/selection. Retains thread and process handles; stale identity fails before querying. Legacy fallback covers the current processor group.",queryAffinity});
    for (const auto* verb : {L"suspend",L"resume",L"terminate",L"set-affinity"}) {
        const std::wstring name = verb;
        addCommand({L"process thread " + name,L"KswordCLI.exe process thread " + name + L" --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME]" +
            (name == L"set-affinity" ? L" --processors GROUP:INDEX[,GROUP:INDEX]|follow" : L"") + L" --confirm [--backend r3] [--json]",
            L"Apply " + name + L" to a thread after checking both identities.",
            L"Required: --pid, --tid, --thread-creation-time, --confirm." + std::wstring(name == L"set-affinity" ? L" --processors uses group:index or follow." : L"") + L" Optional: --creation-time, --backend r3, --json.",
            L"Output: target, requestSucceeded, verified, previousSuspendCount, win32Error, observed and affinity write/rollback evidence including rollbackVerified. Suspend/resume changes the count once; terminate uses exit code 1 and waits up to 2 seconds. API success without matching readback returns 6. Affinity prefers CPU Sets; legacy follow selects the active mask of the current group. No R0 fallback.",
            [name](const Args& a){return action(a,name);}});
    }
}
}
