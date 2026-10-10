#include "CommandRegistry.h"
#include "../shared/usermode/backend/hardware/HardwareEnumerator.h"
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::hardware;
std::wstring deviceState(b::HardwareDeviceState s) {
    switch(s) {case b::HardwareDeviceState::Started:return L"started";case b::HardwareDeviceState::Stopped:return L"stopped";
    case b::HardwareDeviceState::Disabled:return L"disabled";case b::HardwareDeviceState::Problem:return L"problem";
    case b::HardwareDeviceState::Phantom:return L"phantom";default:return L"unknown";}
}
Json node(const b::HardwareDeviceNode& n) {
    std::vector<std::pair<std::wstring,Json>> fields;
    for(const auto& [key,e]:n.evidence) fields.push_back({key,Json::object({{L"available",Json::boolean(e.available)},
        {L"absent",Json::boolean(e.absent)},{L"malformed",Json::boolean(e.malformed)},
        {L"registryType",e.type==REG_NONE?Json{}:Json::number(e.type)},{L"win32Error",e.error?Json::number(e.error):Json{}},
        {L"configRet",Json::number(e.cmStatus)},{L"values",e.available&&!e.numeric?Json::strings(e.values):Json{}},
        {L"number",e.available&&e.numeric?Json::count(e.number):Json{}}})});
    const auto status=n.evidence.find(L"status");const bool known=status!=n.evidence.end()&&status->second.available;
    return Json::object({{L"instanceId",n.instanceId.empty()?Json{}:Json::string(n.instanceId)},
        {L"parentInstanceId",n.parentInstanceId.empty()?Json{}:Json::string(n.parentInstanceId)},
        {L"devInst",Json::hex(n.devInst)},{L"displayName",n.displayName.empty()?Json{}:Json::string(n.displayName)},
        {L"className",n.className.empty()?Json{}:Json::string(n.className)},{L"classGuid",Json::string(n.classGuid)},
        {L"state",known?Json::string(deviceState(n.state)):Json{}},{L"statusFlags",known?Json::hex(n.statusFlags):Json{}},
        {L"problemCode",known?Json::number(n.problemCode):Json{}},{L"properties",Json::object(fields)}});
}
void completeness(const b::HardwareDeviceNode& n,bool& partial,bool& malformed) {
    for(const auto& [key,e]:n.evidence) {static_cast<void>(key);partial=partial||(!e.available&&!e.absent);malformed=malformed||e.malformed;}
}
Result enumerate(const Args& a) {
    const auto scope=a.get(L"--scope",L"all");if(scope!=L"all"&&scope!=L"present") throw std::invalid_argument("--scope must be all or present");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000) throw std::invalid_argument("--limit must be 1..100000");
    const auto classFilter=a.get(L"--class");if(a.has(L"--class")&&classFilter.empty()) throw std::invalid_argument("--class must not be empty");
    const auto snapshot=b::EnumerateDeviceManagerTree(scope==L"present");bool partial=!snapshot.complete,malformed=false;
    std::vector<Json> rows;std::size_t matched=0;
    for(const auto& n:snapshot.devices) {
        if(!classFilter.empty()&&_wcsicmp(classFilter.c_str(),n.className.c_str())&&_wcsicmp(classFilter.c_str(),n.classGuid.c_str())) continue;
        ++matched;completeness(n,partial,malformed);if(rows.size()<limit) rows.push_back(node(n));
    }
    const bool truncated=matched>rows.size();const int code=malformed?4:!snapshot.success&&snapshot.devices.empty()?3:partial||truncated?6:0;
    return {code,Json::object({{L"source",Json::string(L"SetupAPI + Configuration Manager")},{L"scope",Json::string(scope)},
        {L"complete",Json::boolean(snapshot.complete)},{L"limited",Json::boolean(snapshot.limited)},
        {L"win32Error",snapshot.win32Error?Json::number(snapshot.win32Error):Json{}},
        {L"enumeratedCount",Json::count(snapshot.devices.size())},{L"matchedCount",Json::count(matched)},
        {L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},{L"truncated",Json::boolean(truncated)},{L"devices",Json::array(rows)}}),
        code?std::vector<std::wstring>{L"Enumeration, selected properties or output were incomplete; raw field errors distinguish absent values from unavailable evidence.",snapshot.diagnosticText}:std::vector<std::wstring>{}};
}
Result detail(const Args& a) {
    const auto id=a.require(L"--instance-id");if(id.empty()||id.size()>32767) throw std::invalid_argument("--instance-id must have 1..32767 characters");
    const auto value=b::QueryDeviceManagerDetails(id);bool partial=false,malformed=false;completeness(value.node,partial,malformed);
    return {!value.found?3:malformed?4:partial?6:0,Json::object({{L"source",Json::string(L"SetupAPI + Configuration Manager")},
        {L"requestedInstanceId",Json::string(id)},{L"found",Json::boolean(value.found)},
        {L"win32Error",value.win32Error?Json::number(value.win32Error):Json{}},{L"device",value.found?node(value.node):Json{}}}),
        !value.found?std::vector<std::wstring>{L"Device instance could not be opened; it may have been removed or access denied."}:
        partial?std::vector<std::wstring>{L"Some fields are unavailable; missing optional registry properties are separately marked absent."}:std::vector<std::wstring>{}};
}
}
void registerHardwareDevices() {
    const auto notes=L"Output: source/scope, completeness and counts, devices with instance/parent identity, class, state, raw CM statusFlags/problemCode and typed property evidence. Multi-string properties are arrays (never split display text); unknowns null. Missing optional registry values are absent, not failures; access/CM failures make results partial (6), malformed properties 4. Enumerates installed devices including non-present entries by default; --scope present excludes them. IDs are live snapshots and devices may disappear. Read-only R3, no device control or R0 fallback. Backend cap 100000 devnodes, property cap 16 MiB with 4 growth attempts.";
    addCommand({L"hardware devices enum",L"KswordCLI.exe hardware devices enum [--scope all|present] [--class NAME_OR_GUID] [--limit N] [--backend r3] [--json]",
        L"Enumerate installed or present PnP devices through R3.",L"Optional: --scope all|present (all), --class exact name/GUID, --limit (1..100000, default 1000), --backend r3, --json.",notes,enumerate});
    addCommand({L"hardware devices query",L"KswordCLI.exe hardware devices query --instance-id ID [--backend r3] [--json]",
        L"Read live PnP device properties and status.",L"Required: --instance-id. Optional: --backend r3, --json.",std::wstring(notes)+L" Open failure or removed target returns 3. Display name uses friendly name, falling back to device description.",detail});
}
}
