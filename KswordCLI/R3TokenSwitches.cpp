#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessTokenSwitches.h"
namespace ks::cli {
namespace {
namespace backend = ks::r3::process_detail::token;
struct Flag {const wchar_t* name;std::size_t index;bool writable;const wchar_t* notes;};
const Flag flags[] = {
    {L"sandbox-inert",0,false,L"Native query-only flag."},
    {L"virtualization-allowed",1,true,L"Setting requires SeCreateTokenPrivilege; changing the flag does not grant that privilege."},
    {L"virtualization-enabled",2,true,L"The target must permit virtualization; elevated/native-64-bit tokens can reject enable."},
    {L"ui-access",3,true,L"Setting can require caller SeTcbPrivilege. Use privilege run in a context that already owns it."},
    {L"has-restrictions",4,false,L"Native query-only flag."}, {L"app-container",5,false,L"Native query-only flag."},
    {L"restricted",6,false,L"Native query-only flag."}, {L"less-privileged-app-container",7,false,L"Native query-only flag; can be absent on older OS versions."},
    {L"sandboxed",8,false,L"Native query-only flag; can be absent on older OS versions."},
    {L"app-silo",9,false,L"Queries SDK information class 48; class 51 is not AppSilo. Older OS versions can lack this class."},
    {L"mandatory-no-write-up",10,true,L"Read/modify/write of policy bit 1 preserves other bits. SeTcbPrivilege can be required; running tokens can reject changes."},
    {L"mandatory-new-process-min",11,true,L"Read/modify/write of policy bit 2 preserves other bits. SeTcbPrivilege can be required; running tokens can reject changes."}
};
int unavailable(DWORD error) {return error == ERROR_INVALID_DATA ? 4 : error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_SUPPORTED ||
    error == ERROR_INVALID_FUNCTION || error == ERROR_INSUFFICIENT_BUFFER ? 5 : 3;}
Json flagJson(const Flag& flag,const ks::r3::process_detail::ProcessTokenSwitchSnapshot& s) {
    const auto id = flag.index < 10 ? backend::kTokenBooleanInformationClasses[flag.index] : TokenMandatoryPolicy;
    return Json::object({{L"name",Json::string(flag.name)}, {L"informationClass",Json::number(id)}, {L"className",Json::string(backend::NativeTokenClassName(id))},
        {L"mask",flag.index >= 10 ? Json::hex(flag.index == 10 ? 1 : 2) : Json{}}, {L"writable",Json::boolean(flag.writable)},
        {L"policy",flag.index >= 10 && s.mandatoryPolicyKnown ? Json::hex(s.mandatoryPolicy) : Json{}},
        {L"available",Json::boolean(s.updated[flag.index])}, {L"value",s.updated[flag.index] ? Json::boolean(s.values[flag.index]) : Json{}},
        {L"win32Error",Json::number(s.queryErrors[flag.index])}, {L"returnLength",Json::number(s.returnLengths[flag.index])}});
}
Result query(const Args& args) {
    const Flag* selected = nullptr;
    if (args.has(L"--name")) {
        for (const auto& flag : flags) if (args.get(L"--name") == flag.name) selected = &flag;
        if (!selected) throw std::invalid_argument("unknown --name; use help process token switches");
    }
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    const auto snapshot = backend::CollectTokenSwitchSnapshot(lease.pid,lease.creationTime);
    if (!snapshot.succeeded || !snapshot.identityMatched || !lease.alive()) return {3,Json::object({{L"target",lease.json()},
        {L"win32Error",snapshot.win32ErrorKnown ? Json::number(snapshot.win32Error) : Json{}}}),{snapshot.statusText,L"Token switch acquisition failed or target exited."}};
    std::vector<Json> rows;DWORD count=0,available=0;bool malformed=false,failed=false;
    for (const auto& flag : flags) {
        if (selected && selected != &flag) continue;
        ++count;if (snapshot.updated[flag.index]) ++available;
        else {const int code = unavailable(snapshot.queryErrors[flag.index]);malformed = malformed || code == 4;failed = failed || code == 3;}
        rows.push_back(flagJson(flag,snapshot));
    }
    return {malformed ? 4 : available == count ? 0 : available ? 6 : failed ? 3 : 5,Json::object({{L"target",lease.json()},
        {L"source",Json::string(L"shared R3 token switches")}, {L"requestedCount",Json::number(count)}, {L"availableCount",Json::number(available)},
        {L"switches",Json::array(rows)}}),available == count ? std::vector<std::wstring>{} : std::vector<std::wstring>{L"Unknown switch values are null, not disabled. Per-field errors and native return lengths are preserved."}};
}
Result write(const Args& args,const Flag& flag,bool enable) {
    (void)args.require(L"--confirm");process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,Json::object({{L"target",lease.json()}}),{L"Process identity is unavailable, mismatched or has exited."}};
    const auto before = backend::CollectTokenSwitchSnapshot(lease.pid,lease.creationTime);
    if (!before.succeeded || !before.identityMatched || !before.updated[flag.index]) return {
        !before.succeeded || !before.identityMatched ? 3 : unavailable(before.queryErrors[flag.index]),
        Json::object({{L"target",lease.json()}, {L"before",flagJson(flag,before)}}),{L"Reliable before-state is required; no write was issued."}};
    const auto result = backend::WriteTokenSwitch(lease.pid,lease.creationTime,flag.index,enable);
    const auto after = backend::CollectTokenSwitchSnapshot(lease.pid,lease.creationTime);
    const bool policy = flag.index >= 10;
    const DWORD mask = flag.index == 10 ? 1U : 2U;
    const bool preserved = !policy || (before.mandatoryPolicyKnown && after.mandatoryPolicyKnown &&
        (before.mandatoryPolicy & ~mask) == (after.mandatoryPolicy & ~mask));
    const bool verified = result.requestSucceeded && lease.alive() && after.identityMatched && after.succeeded && after.updated[flag.index] && after.values[flag.index] == enable && preserved;
    const auto status = static_cast<DWORD>(result.ntStatus);
    const bool unsupported = result.unsupported || (result.ntStatusKnown && (status == 0xc0000002 || status == 0xc0000003 || status == 0xc00000bb));
    return {unsupported ? 5 : !result.requestSucceeded ? 3 : verified ? 0 : 6,Json::object({{L"target",lease.json()}, {L"name",Json::string(flag.name)},
        {L"enable",Json::boolean(enable)}, {L"identityMatched",Json::boolean(result.identityMatched)}, {L"writeAttempted",Json::boolean(result.writeAttempted)},
        {L"requestSucceeded",Json::boolean(result.requestSucceeded)}, {L"verified",Json::boolean(verified)},
        {L"ntStatus",result.ntStatusKnown ? Json::hex(status) : Json{}}, {L"win32Error",result.win32ErrorKnown ? Json::number(result.win32Error) : Json{}},
        {L"before",flagJson(flag,before)}, {L"after",flagJson(flag,after)}, {L"otherPolicyBitPreserved",policy ? Json::boolean(preserved) : Json{}}}),
        verified ? std::vector<std::wstring>{} : std::vector<std::wstring>{result.statusText,flag.notes,L"Native request failure or missing/mismatched readback cannot be reported as a successful switch change."}};
}
}
void registerTokenSwitches() {
    addCommand({L"process token switches query",L"KswordCLI.exe process token switches query --pid PID [--creation-time FILETIME] [--name NAME] [--backend r3] [--json]",
        L"Read all twelve token switch states with availability.",L"Required: --pid. Optional: --creation-time, --name (direct switch name from help), --backend r3, --json.",
        L"Output: target, counts, switches with informationClass/className/mask/writable/available/value/win32Error/returnLength. Unknown is null. Native query-only fields have no enable/disable commands. AppSilo uses SDK class 48. Missing states return 6; unsupported-only results return 5.",query});
    for (const auto& flag : flags) {
        const auto* selected = &flag;
        const std::wstring base = L"process token switches " + std::wstring(flag.name);
        addCommand({base + L" query",L"KswordCLI.exe " + base + L" query --pid PID [--creation-time FILETIME] [--backend r3] [--json]",
            L"Read the " + std::wstring(flag.name) + L" flag.",L"Required: --pid. Optional: --creation-time, --backend r3, --json.",
            L"Output: one switch with availability/value/error/native class identity. " + std::wstring(flag.notes),[selected](const Args& args){
                Args filter=args;filter.values[L"--name"]=selected->name;return query(filter);
            }});
        if (!flag.writable) continue;
        for (const bool enable : {true,false}) {
            const std::wstring action = enable ? L"enable" : L"disable";
            addCommand({base + L" " + action,L"KswordCLI.exe " + base + L" " + action + L" --pid PID [--creation-time FILETIME] --confirm [--backend r3] [--json]",
                action + L" the " + flag.name + L" token flag with readback.",L"Required: --pid, --confirm. Optional: --creation-time, --backend r3, --json.",
                L"Output: target, name, enable, requestSucceeded, writeAttempted, verified, ntStatus/win32Error, before/after and otherPolicyBitPreserved. Only this selected native field is set; policy updates preserve other observed bits. Identity/permission failure returns 3, native unsupported returns 5, unconfirmed effect returns 6. " + std::wstring(flag.notes),
                [selected,enable](const Args& args){return write(args,*selected,enable);}});
        }
    }
}
}
