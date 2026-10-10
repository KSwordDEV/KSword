#include "R3ProcessShared.h"
#include "R3ThreadShared.h"
#include "../shared/usermode/backend/process/ProcessModulesSupport.h"
#include "../shared/usermode/backend/process/ModuleActions.h"
#include <algorithm>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process_detail;
Json fieldEvidence(const backend::ProcessQueryEvidence& e) {return Json::object({{L"available",Json::boolean(e.available)},
    {L"win32Error",e.win32ErrorKnown ? Json::number(e.win32Error) : Json{}}, {L"ntStatus",e.ntStatusKnown ? Json::hex(static_cast<DWORD>(e.ntStatus)) : Json{}}});}
struct Snapshot {
    std::vector<backend::ProcessModuleInfo> modules;
    backend::detail::ModuleEnumerationEvidence evidence;
    bool ok = false;
    std::wstring detail;
    explicit Snapshot(DWORD pid) {modules = backend::detail::CollectModules(pid,ok,detail,&evidence);}
    int code() const {return evidence.malformed ? 4 : evidence.unsupported ? 5 : !ok ? 3 : evidence.complete ? 0 : 6;}
    Json json() const {return Json::object({{L"complete",Json::boolean(evidence.complete)}, {L"malformed",Json::boolean(evidence.malformed)},
        {L"unsupported",Json::boolean(evidence.unsupported)}, {L"win32Error",Json::number(evidence.win32Error)}});}
};
Json module(const backend::ProcessModuleInfo& r) {
    return Json::object({{L"handle",Json::hex(r.moduleHandle)}, {L"name",r.pathKnown ? Json::string(r.moduleName) : Json{}},
        {L"path",r.pathKnown ? Json::string(r.modulePath) : Json{}}, {L"base",r.infoKnown ? Json::hex(r.baseAddress) : Json{}},
        {L"imageSize",r.infoKnown ? Json::number(r.imageSize) : Json{}}, {L"infoEvidence",fieldEvidence(r.infoEvidence)}, {L"pathEvidence",fieldEvidence(r.pathEvidence)},
        {L"representativeThread",r.representativeThreadId ? Json::object({{L"tid",Json::number(r.representativeThreadId)},
            {L"creationTime",Json::count(r.representativeThreadCreationTime100ns)}}) : Json{}}});
}
Result enumeration(const Args& args) {
    const auto limit = args.u32(L"--limit",1000);
    const auto base = args.integer(L"--base");
    if (!limit) throw std::invalid_argument("--limit must be positive");
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    Snapshot snapshot(lease.pid);
    if (!snapshot.ok) return {snapshot.code(),Json::object({{L"target",lease.json()}, {L"enumeration",snapshot.json()}}),{snapshot.detail}};
    bool threadsOk = false;std::wstring threadDetail;backend::detail::ThreadEnumerationEvidence threadState;
    const auto threads = backend::detail::CollectThreads(lease.pid,threadsOk,threadDetail,&threadState);
    backend::detail::AttachRepresentativeThreads(snapshot.modules,threads);
    if (!lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process exited during module enumeration."}};
    std::vector<Json> rows;std::uint32_t matched = 0;
    bool partial = !snapshot.evidence.complete || !threadsOk || !threadState.complete || threadState.skippedCount != 0;
    for (const auto& t : threads) partial = partial || !t.identityKnown || !t.startAddressKnown;
    for (const auto& r : snapshot.modules) {
        if (args.has(L"--base") && r.moduleHandle != base) continue;
        if (args.has(L"--name") && (!r.pathKnown || _wcsicmp(r.moduleName.c_str(),args.get(L"--name").c_str()) != 0)) continue;
        ++matched;if (rows.size() >= limit) continue;
        partial = partial || !r.infoKnown || !r.pathKnown;
        rows.push_back(module(r));
    }
    const bool truncated = matched > rows.size();
    return {partial || truncated ? 6 : 0,Json::object({{L"target",lease.json()}, {L"source",Json::string(L"shared R3 PSAPI module snapshot / native thread starts")},
        {L"enumeration",snapshot.json()}, {L"threadEnumeration",Json::object({{L"complete",Json::boolean(threadsOk && threadState.complete)},
            {L"win32Error",Json::number(threadState.win32Error)}, {L"skippedCount",Json::number(threadState.skippedCount)}})},
        {L"matchedCount",Json::number(matched)}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"truncated",Json::boolean(truncated)},
        {L"modules",Json::array(rows)}}), partial || truncated ? std::vector<std::wstring>{L"Some module or representative-thread evidence is missing, or output was limited."} : std::vector<std::wstring>{}};
}
void validateSelection(const Args& args) {
    const auto base = args.integer(L"--base");(void)args.require(L"--base");
    if (!base) throw std::invalid_argument("--base must be positive");
    if (args.has(L"--image-size") && !args.u32(L"--image-size")) throw std::invalid_argument("--image-size must be positive");
    if (args.has(L"--module-path")) (void)args.require(L"--module-path");
}
const backend::ProcessModuleInfo* selected(const Args& args,const Snapshot& snapshot) {
    const auto base = args.integer(L"--base");
    for (const auto& r : snapshot.modules) if (r.infoKnown && r.pathKnown && r.baseAddress == base &&
        (!args.has(L"--module-path") || _wcsicmp(r.modulePath.c_str(),args.get(L"--module-path").c_str()) == 0) &&
        (!args.has(L"--image-size") || r.imageSize == args.u32(L"--image-size"))) return &r;
    return nullptr;
}
Result unload(const Args& args) {
    (void)args.require(L"--confirm");validateSelection(args);
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    Snapshot before(lease.pid);const auto* target = selected(args,before);
    if (!before.ok || !before.evidence.complete || !target) return {!before.ok ? before.code() : !before.evidence.complete ? 6 : 3,
        Json::object({{L"target",lease.json()}, {L"enumeration",before.json()}}),{L"A complete module snapshot and matching base/path/size are required before unloading."}};
    const auto original = *target;
    const auto source = std::make_shared<const std::vector<backend::ProcessModuleInfo>>(before.modules);
    const auto result = backend::UnloadDetailModule(original.baseAddress,lease.pid,lease.creationTime,source);
    Snapshot after(lease.pid);
    bool present = false;
    for (const auto& r : after.modules) if (r.moduleHandle == original.baseAddress) present = true;
    const bool known = after.ok && after.evidence.complete && lease.alive();
    const bool verified = result.requestSucceeded && known && !present;
    const int code = result.unsupported ? 5 : result.requestSucceeded ? verified ? 0 : 6 :
        result.writeAttempted && (!result.exitCodeKnown || result.waitResult != WAIT_OBJECT_0) ? 6 : 3;
    return {code,Json::object({{L"target",lease.json()}, {L"module",module(original)}, {L"action",Json::string(L"unload")},
        {L"identityMatched",Json::boolean(result.identityMatched)}, {L"requestSucceeded",Json::boolean(result.requestSucceeded)}, {L"verified",Json::boolean(verified)},
        {L"remoteThreadCreated",Json::boolean(result.writeAttempted)}, {L"waitResult",result.waitKnown ? Json::number(result.waitResult) : Json{}},
        {L"freeLibraryResult",result.exitCodeKnown ? Json::number(result.exitCode) : Json{}}, {L"win32Error",result.win32ErrorKnown ? Json::number(result.win32Error) : Json{}},
        {L"observed",Json::object({{L"known",Json::boolean(known)}, {L"basePresent",known ? Json::boolean(present) : Json{}}, {L"enumeration",after.json()}})}}),
        code ? std::vector<std::wstring>{result.statusText,L"FreeLibrary failure, timeout, remaining references or missing readback cannot be reported as an unloaded module."} : std::vector<std::wstring>{}};
}
Result threadAction(const Args& args,const std::wstring& verb) {
    (void)args.require(L"--confirm");validateSelection(args);(void)args.require(L"--tid");(void)args.require(L"--thread-creation-time");
    if (!args.u32(L"--tid") || !args.integer(L"--thread-creation-time")) throw std::invalid_argument("--tid and --thread-creation-time must be positive");
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    Snapshot snapshot(lease.pid);const auto* target = selected(args,snapshot);
    if (!snapshot.ok || !snapshot.evidence.complete || !target) return {!snapshot.ok ? snapshot.code() : !snapshot.evidence.complete ? 6 : 3,
        Json::object({{L"target",lease.json()}, {L"enumeration",snapshot.json()}}),{L"Target module identity is absent or lacks reliable metadata."}};
    bool ok = false;std::wstring detail;backend::detail::ThreadEnumerationEvidence threadState;
    const auto threads = backend::detail::CollectThreads(lease.pid,ok,detail,&threadState);
    const auto tid = args.u32(L"--tid");const auto creation = args.integer(L"--thread-creation-time");
    bool associated = false;
    for (const auto& t : threads) if (t.identityKnown && t.startAddressKnown && t.threadId == tid && t.creationTime100ns == creation &&
        t.startAddress >= target->baseAddress && t.startAddress - target->baseAddress < target->imageSize) associated = true;
    if (!ok || !associated) return {3,Json::object({{L"target",lease.json()}, {L"module",module(*target)}}),{L"Thread identity/start address does not confirm an association with this module."}};
    Args guarded = args;guarded.values[L"--creation-time"] = std::to_wstring(lease.creationTime);
    ThreadAction callback;
    if (verb == L"suspend") callback = backend::SuspendModuleThread;
    else if (verb == L"resume") callback = backend::ResumeModuleThread;
    else callback = backend::TerminateModuleThread;
    const auto result = executeThreadAction(guarded,verb,callback,0);
    return {result.code,Json::object({{L"module",module(*target)}, {L"threadAction",result.data}}),result.diagnostics};
}
}
void registerProcessModules() {
    addCommand({L"process module enum",L"KswordCLI.exe process module enum --pid PID [--creation-time FILETIME] [--base ADDRESS] [--name NAME] [--limit N] [--backend r3] [--json]",
        L"Enumerate R3 modules and representative threads.",L"Required: --pid. Optional: --creation-time, --base, --name (exact case-insensitive module name), --limit (1000), --backend r3, --json.",
        L"Output: target, enumeration/threadEnumeration, counts, modules with handle/name/path/base/imageSize, per-query evidence and representativeThread. Missing metadata is null. Truncation or incomplete evidence returns 6; malformed module counts return 4. Requires QUERY_INFORMATION and VM_READ. No driver or R0 fallback.",enumeration});
    addCommand({L"process module unload",L"KswordCLI.exe process module unload --pid PID --base ADDRESS [--creation-time FILETIME] [--module-path PATH] [--image-size N] --confirm [--backend r3] [--json]",
        L"Invoke shared remote FreeLibrary and verify module disappearance.",L"Required: --pid, --base, --confirm. Optional: --creation-time, --module-path and --image-size expected snapshot identity, --backend r3, --json.",
        L"Output: target, module, requestSucceeded, verified, remoteThreadCreated, waitResult, freeLibraryResult, win32Error and observed.basePresent. Waits up to 10 seconds. Remaining references or unavailable readback return 6. Cross-bitness or unresolved remote function module returns 5 before execution. A timed-out remote thread may continue after CLI exits; it is not forcibly killed. Unloading in-use modules can destabilize the target.",unload});
    for (const auto* verb : {L"suspend",L"resume",L"terminate"}) {
        const std::wstring name = verb;
        addCommand({L"process module thread " + name,L"KswordCLI.exe process module thread " + name +
            L" --pid PID --base ADDRESS --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] [--module-path PATH] [--image-size N] --confirm [--backend r3] [--json]",
            L"Apply " + name + L" to a verified thread starting within a module.",
            L"Required: --pid, --base, --tid, --thread-creation-time, --confirm. Optional: --creation-time, --module-path, --image-size, --backend r3, --json.",
            L"Output: module, threadAction with identities/requestSucceeded/verified/previousSuspendCount/observed. Start address must fall within the selected module snapshot. Suspend/resume changes the count once. The module backend's terminate uses exit code 0. Failed or stale identities return 3; unconfirmed effects return 6.",
            [name](const Args& a){return threadAction(a,name);}});
    }
}
}
