#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessBasicInfo.h"
namespace ks::cli {
namespace {
Result query(const Args& args) {
    process::Lease lease(args);
    if (!lease.handle.valid() || !lease.matches || !lease.alive())
        return {3, Json::object({{L"target",lease.json()}}), {L"Target identity could not be acquired, changed, or has exited."}};
    bool opened = false;
    const auto info = ks::r3::process_detail::CollectBasicInfo(lease.pid, opened);
    if (!opened || !lease.alive() || (info.creationTime100ns && info.creationTime100ns != lease.creationTime)) {
        const auto failedOpen = info.evidence.find(L"open");
        return {3, Json::object({{L"target",lease.json()}, {L"backendDetail",Json::string(info.statusText)},
            {L"win32Error",failedOpen != info.evidence.end() && failedOpen->second.win32ErrorKnown ? Json::number(failedOpen->second.win32Error) : Json{}}}),
            {L"Basic collection failed or the target exited or changed."}};
    }
    std::vector<Json> rows;
    std::uint32_t available = 0;
    const auto evidence = [&info](const wchar_t* key) {
        const auto found = info.evidence.find(key);
        return found == info.evidence.end() ? ks::r3::process_detail::ProcessQueryEvidence{} : found->second;
    };
    const auto field = [&](const wchar_t* name, const wchar_t* key, const Json& value, bool valid = true) {
        const auto observed = evidence(key);
        const bool known = observed.available && valid;
        if (known) ++available;
        rows.push_back(Json::object({{L"name",Json::string(name)}, {L"available",Json::boolean(known)},
            {L"value",known ? value : Json{}}, {L"win32Error",observed.win32ErrorKnown ? Json::number(observed.win32Error) : Json{}},
            {L"ntStatus",observed.ntStatusKnown ? Json::hex(static_cast<DWORD>(observed.ntStatus)) : Json{}}}));
    };
    field(L"name",L"snapshot",Json::string(info.processName));
    field(L"parent-pid",L"snapshot",Json::number(info.parentProcessId));
    field(L"parent-name",L"snapshot",Json::string(info.parentProcessName),!info.parentProcessName.empty());
    field(L"threads",L"snapshot",Json::number(info.threadCount));
    field(L"image-path",L"image-path",Json::string(info.imagePath));
    field(L"command-line",L"command-line",Json::string(evidence(L"command-line").emptyValue ? L"" : info.commandLine));
    field(L"bitness",L"bitness",Json::string(info.bitness));
    field(L"session",L"session",Json::number(info.sessionId));
    field(L"user",L"token-user",Json::string(info.userName));
    field(L"integrity",L"integrity",Json::string(info.integrityLevel));
    field(L"elevated",L"elevation",Json::boolean(info.isAdmin));
    field(L"creation-time",L"start-time",Json::count(info.creationTime100ns));
    field(L"priority-class",L"priority",Json::number(info.priorityClass));
    field(L"handles",L"handles",Json::number(info.handleCount));
    field(L"peb",L"native-basic",Json::hex(info.pebAddress),info.pebAddressKnown);
    field(L"affinity",L"affinity",Json::hex(info.affinityMask),info.affinityKnown);
    field(L"working-set",L"memory",Json::count(info.workingSetBytes));
    field(L"private-bytes",L"memory",Json::count(info.privateBytes));
    field(L"io-bytes",L"io",Json::count(info.ioBytes));
    const auto requested = static_cast<std::uint32_t>(rows.size());
    return {available == requested ? 0 : available ? 6 : 5, Json::object({{L"target",lease.json()},
        {L"source",Json::string(L"shared R3 basic process queries")}, {L"requestedCount",Json::number(requested)},
        {L"availableCount",Json::number(available)}, {L"fields",Json::array(rows)}}), available == requested ?
        std::vector<std::wstring>{} : std::vector<std::wstring>{L"Missing field evidence is null. The parent may have exited; command-line reads require VM_READ access."}};
}
}
void registerProcessBasic() {
    addCommand({L"process detail basic query",L"KswordCLI.exe process detail basic query --pid PID [--creation-time FILETIME] [--backend r3] [--json]",
        L"Read basic process identity, token, PEB, memory and I/O fields.",
        L"Required: --pid. Optional: --creation-time expected identity, --backend r3, --json.",
        L"Output: target, source, availableCount, fields with available/value/win32Error/ntStatus. Retains the identity handle. Addresses are hex strings and 64-bit counters decimal strings. Unknown values are null; partial results return 6. Parent-name may be unavailable after parent exit. Command-line preserves the backend's remote text; empty text is valid. No PEB write is performed.",query});
}
}
