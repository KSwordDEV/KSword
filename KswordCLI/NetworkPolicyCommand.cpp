#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/NetworkPolicy.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverNetworkPolicy.h"
#include <Windows.h>
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace ks::cli {
namespace {
namespace net = ks::r3::network;

bool driver(const Args& args) { return args.get(L"--backend", L"r3") == L"r0"; }
void requireConfirmation(const Args& args) {
    if (!args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
}
std::vector<std::wstring> splitPrefixes(const std::wstring& value) {
    std::vector<std::wstring> result;
    if (value.empty()) return result;
    for (std::size_t start = 0; start <= value.size();) {
        const auto end = value.find(L';', start);
        const auto entry = value.substr(start, end == std::wstring::npos ? end : end - start);
        net::NetworkAddressPrefix parsed;
        if (entry.empty() || !net::ParseNetworkAddressPrefix(entry, parsed))
            throw std::invalid_argument("--remote requires semicolon-separated numeric IP addresses or CIDR prefixes");
        result.push_back(entry);
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return result;
}
Json blockRow(const net::ManagedNetworkBlock& item) {
    const auto scope = item.scope == net::PolicyScope::ApplicationImage ? L"image" :
        item.scope == net::PolicyScope::ProcessInstance ? L"process" : L"all";
    return Json::object({{L"id",Json::string(item.policyId)},
        {L"backend",Json::string(item.backend == net::PolicyBackend::Driver ? L"r0" : L"r3")},
        {L"scope",Json::string(scope)}, {L"applicationPath",item.applicationPath.empty()?Json{}:Json::string(item.applicationPath)},
        {L"pid",item.processId?Json::number(item.processId):Json{}},
        {L"creationTime",item.creationTime100ns?Json::count(item.creationTime100ns):Json{}},
        {L"remotePrefixes",Json::strings(item.remotePrefixes)}, {L"inbound",Json::boolean(item.inbound)},
        {L"outbound",Json::boolean(item.outbound)}, {L"enabled",Json::boolean(item.enabled)},
        {L"complete",Json::boolean(item.complete)}});
}
bool sourceAvailable(const net::NetworkBlockList& list, bool useDriver) {
    return useDriver ? list.driverAvailable : list.firewallAvailable;
}
bool matchesSource(const net::ManagedNetworkBlock& item, bool useDriver) {
    return (item.backend == net::PolicyBackend::Driver) == useDriver;
}
bool samePrefixes(const std::vector<std::wstring>& left, const std::vector<std::wstring>& right) {
    if (left.size() != right.size()) return false;
    for (const auto& expected : left) {
        net::NetworkAddressPrefix a;
        if (!net::ParseNetworkAddressPrefix(expected,a)) return false;
        const auto match = std::find_if(right.begin(),right.end(),[&](const auto& value) {
            net::NetworkAddressPrefix b;
            return net::ParseNetworkAddressPrefix(value,b) && a.family == b.family &&
                a.prefixLength == b.prefixLength && a.address == b.address;
        });
        if (match == right.end()) return false;
    }
    return true;
}
net::NetworkBlockList blocks() {
    ksword::ark::InstallDriverNetworkPolicies();
    return net::ListNetworkBlocks();
}
Result listBlocks(const Args& args, bool single) {
    const bool useDriver = driver(args); const auto snapshot = blocks();
    const auto id = single ? args.require(L"--id") : std::wstring{};
    std::vector<Json> rows; bool complete = sourceAvailable(snapshot,useDriver);
    for (const auto& row : snapshot.entries) {
        if (!matchesSource(row,useDriver) || (single && row.policyId != id)) continue;
        complete &= row.complete; rows.push_back(blockRow(row));
    }
    const bool available = sourceAvailable(snapshot,useDriver);
    const int code = !available ? 5 : !complete ? 6 : single && rows.empty() ? 3 : 0;
    return {code,Json::object({{L"source",Json::string(useDriver?L"Ksword driver managed policies":L"Windows Firewall owned rules")},
        {L"sourceAvailable",Json::boolean(available)}, {L"driverProcessInstanceAvailable",Json::boolean(snapshot.driverProcessInstanceAvailable)},
        {L"complete",Json::boolean(complete)}, {L"count",Json::number(static_cast<std::uint32_t>(rows.size()))},
        {L"policies",Json::array(rows)}}),{snapshot.diagnostic}};
}
net::NetworkBlockRequest blockRequest(const Args& args) {
    net::NetworkBlockRequest request;
    request.backend = driver(args) ? net::PolicyBackend::Driver : net::PolicyBackend::Firewall;
    const auto scope = args.require(L"--scope");
    if (scope == L"image") request.scope = net::PolicyScope::ApplicationImage;
    else if (scope == L"process") request.scope = net::PolicyScope::ProcessInstance;
    else if (scope == L"all") request.scope = net::PolicyScope::AllApplications;
    else throw std::invalid_argument("--scope must be image, process or all");
    if ((driver(args) && request.scope == net::PolicyScope::ApplicationImage) ||
        (!driver(args) && request.scope == net::PolicyScope::ProcessInstance))
        throw std::invalid_argument("scope is not supported by the selected backend");
    request.target.applicationPath = args.get(L"--path");
    request.target.processId = args.u32(L"--pid");
    request.target.creationTime100ns = args.integer(L"--creation-time");
    if (request.scope == net::PolicyScope::ApplicationImage && request.target.applicationPath.empty())
        throw std::invalid_argument("image scope requires --path");
    if (request.scope == net::PolicyScope::ProcessInstance && (!request.target.processId || !request.target.creationTime100ns))
        throw std::invalid_argument("process scope requires --pid and --creation-time");
    if ((request.target.processId == 0) != (request.target.creationTime100ns == 0))
        throw std::invalid_argument("--pid and --creation-time must be provided together");
    if (request.scope == net::PolicyScope::AllApplications &&
        (args.has(L"--path") || args.has(L"--pid") || args.has(L"--creation-time")))
        throw std::invalid_argument("all scope does not accept a process or image identity");
    if (request.scope == net::PolicyScope::ProcessInstance && args.has(L"--path"))
        throw std::invalid_argument("r0 process policies use PID and creation time, not --path");
    request.remotePrefixes = splitPrefixes(args.get(L"--remote"));
    if (request.scope == net::PolicyScope::AllApplications && request.remotePrefixes.empty())
        throw std::invalid_argument("all scope requires --remote");
    const auto direction = args.get(L"--direction",L"both");
    if (direction != L"in" && direction != L"out" && direction != L"both")
        throw std::invalid_argument("--direction must be in, out or both");
    request.inbound = direction != L"out"; request.outbound = direction != L"in";
    return request;
}
Result changeBlock(const Args& args, const std::wstring& operation) {
    requireConfirmation(args); const bool useDriver = driver(args);
    ksword::ark::InstallDriverNetworkPolicies();
    net::NetworkPolicyResult action;
    net::NetworkBlockRequest requested;
    if (operation == L"create") { requested = blockRequest(args); action = net::CreateNetworkBlock(requested); }
    else {
        const auto id = args.require(L"--id");
        const std::wstring prefix = useDriver ? L"KSword.Driver." : L"KSword.Network.";
        if (!id.starts_with(prefix)) throw std::invalid_argument("policy ID does not belong to the selected backend");
        if (operation == L"remove") action = net::RemoveNetworkBlock(id);
        else action = net::SetNetworkBlockEnabled(id, operation == L"enable");
    }
    const auto after = blocks(); const bool available = sourceAvailable(after,useDriver);
    const auto found = std::find_if(after.entries.begin(),after.entries.end(),[&](const auto& row) {
        return matchesSource(row,useDriver) && row.policyId == action.policyId;
    });
    const bool present = found != after.entries.end();
    bool verified = available && !action.policyId.empty();
    if (operation == L"remove") verified &= !present;
    else verified &= present && found->complete && found->enabled == (operation != L"disable");
    if (verified && operation == L"create") {
        verified = found->scope == requested.scope && found->inbound == requested.inbound && found->outbound == requested.outbound &&
            samePrefixes(found->remotePrefixes,requested.remotePrefixes);
        if (verified && requested.scope == net::PolicyScope::ApplicationImage)
            verified = _wcsicmp(found->applicationPath.c_str(),requested.target.applicationPath.c_str()) == 0;
        if (verified && requested.scope == net::PolicyScope::ProcessInstance)
            verified = found->processId == requested.target.processId && found->creationTime100ns == requested.target.creationTime100ns;
    }
    const int code = action.success && verified ? 0 : action.success ? 6 :
        (action.nativeError == ERROR_INVALID_PARAMETER || action.nativeError == ERROR_NOT_SUPPORTED ||
         action.nativeError == ERROR_ACCESS_DENIED || action.nativeError == ERROR_NOT_FOUND) ? 3 : 6;
    return {code,Json::object({{L"operation",Json::string(operation)}, {L"policyId",Json::string(action.policyId)},
        {L"requestSucceeded",Json::boolean(action.success)}, {L"nativeError",Json::number(action.nativeError)},
        {L"postcheckAvailable",Json::boolean(available)}, {L"postcheckPresent",available?Json::boolean(present):Json{}},
        {L"postcheck",present?blockRow(*found):Json{}}, {L"verified",Json::boolean(action.success&&verified)}}),
        {action.diagnostic, L"A failed or partial request may have changed policy state; inspect the returned identity before retrying."}};
}

Json qosRow(const net::QosPolicy& p) {
    const wchar_t* protocol = p.protocol == net::QosProtocol::Tcp ? L"tcp" : p.protocol == net::QosProtocol::Udp ? L"udp" :
        p.protocol == net::QosProtocol::TcpAndUdp ? L"tcp-udp" : L"any";
    return Json::object({{L"id",Json::string(p.policyId)}, {L"scope",Json::string(p.scope == net::PolicyScope::AllApplications?L"all":L"image")},
        {L"applicationPath",p.applicationPath.empty()?Json{}:Json::string(p.applicationPath)},
        {L"outboundBytesPerSecond",Json::count(p.outboundBytesPerSecond)}, {L"protocol",Json::string(protocol)},
        {L"sourcePrefix",p.sourcePrefix.empty()?Json{}:Json::string(p.sourcePrefix)},
        {L"destinationPrefix",p.destinationPrefix.empty()?Json{}:Json::string(p.destinationPrefix)},
        {L"sourcePortStart",Json::number(p.sourcePortStart)}, {L"sourcePortEnd",Json::number(p.sourcePortEnd)},
        {L"destinationPortStart",Json::number(p.destinationPortStart)}, {L"destinationPortEnd",Json::number(p.destinationPortEnd)},
        {L"dscp",p.dscp < 0 ? Json{} : Json::number(static_cast<std::uint32_t>(p.dscp))},
        {L"priority8021",p.priority8021 < 0 ? Json{} : Json::number(static_cast<std::uint32_t>(p.priority8021))},
        {L"precedence",Json::number(p.precedence)}, {L"enabled",Json::boolean(p.enabled)}, {L"managed",Json::boolean(p.managed)},
        {L"providerOwner",Json::string(p.providerOwner)}, {L"providerDetails",Json::string(p.providerDetails)}});
}
Result listQos(const Args& args, bool single) {
    const auto list = net::ListQosPolicies(); const auto id = single ? args.require(L"--id") : std::wstring{};
    std::vector<Json> rows; for (const auto& row : list.entries) if (!single || row.policyId == id) rows.push_back(qosRow(row));
    return {list.success ? single && rows.empty() ? 3 : 0 : 3,
        Json::object({{L"source",Json::string(L"Windows Policy QoS ActiveStore and KSword disabled definitions")},
            {L"querySucceeded",Json::boolean(list.success)}, {L"nativeError",Json::number(list.nativeError)},
            {L"count",Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"policies",Json::array(rows)}}),{list.diagnostic}};
}
std::uint16_t port(const Args& args, const wchar_t* option) {
    const auto value = args.u32(option);
    if (value > 65535) throw std::invalid_argument("port exceeds 65535");
    return static_cast<std::uint16_t>(value);
}
net::QosPolicy qosRequest(const Args& args) {
    net::QosPolicy p; p.policyId = args.get(L"--id");
    const auto scope = args.require(L"--scope");
    if (scope == L"all") p.scope = net::PolicyScope::AllApplications;
    else if (scope == L"image") p.scope = net::PolicyScope::ApplicationImage;
    else throw std::invalid_argument("QoS scope must be image or all");
    p.applicationPath = args.get(L"--path");
    if ((p.scope == net::PolicyScope::ApplicationImage) != !p.applicationPath.empty())
        throw std::invalid_argument("image scope requires --path and all scope forbids it");
    p.outboundBytesPerSecond = args.integer(L"--rate");
    const auto protocol = args.get(L"--protocol",L"any");
    if (protocol == L"any") p.protocol = net::QosProtocol::Any;
    else if (protocol == L"tcp") p.protocol = net::QosProtocol::Tcp;
    else if (protocol == L"udp") p.protocol = net::QosProtocol::Udp;
    else if (protocol == L"tcp-udp") p.protocol = net::QosProtocol::TcpAndUdp;
    else throw std::invalid_argument("--protocol must be any, tcp, udp or tcp-udp");
    p.sourcePrefix = args.get(L"--source-prefix"); p.destinationPrefix = args.get(L"--destination-prefix");
    p.sourcePortStart = port(args,L"--source-port-start"); p.sourcePortEnd = port(args,L"--source-port-end");
    p.destinationPortStart = port(args,L"--destination-port-start"); p.destinationPortEnd = port(args,L"--destination-port-end");
    const auto dscp = args.u32(L"--dscp",64), priority = args.u32(L"--priority",8);
    if ((args.has(L"--dscp") && dscp > 63) || (args.has(L"--priority") && priority > 7))
        throw std::invalid_argument("--dscp must be 0..63 and --priority must be 0..7");
    p.dscp = args.has(L"--dscp") ? static_cast<int>(dscp) : -1;
    p.priority8021 = args.has(L"--priority") ? static_cast<int>(priority) : -1;
    p.precedence = args.u32(L"--precedence",127);
    const auto enabled = args.get(L"--enabled",L"on");
    if (enabled != L"on" && enabled != L"off") throw std::invalid_argument("--enabled must be on or off");
    p.enabled = enabled == L"on";
    return p;
}
Result changeQos(const Args& args, const std::wstring& operation) {
    requireConfirmation(args); net::NetworkPolicyResult action;
    const auto desired = operation == L"save" ? qosRequest(args) : net::QosPolicy{};
    if (operation == L"save") action = net::SaveQosPolicy(desired);
    else if (operation == L"remove") action = net::RemoveQosPolicy(args.require(L"--id"));
    else action = net::SetQosPolicyEnabled(args.require(L"--id"),operation == L"enable");
    const auto after = net::ListQosPolicies();
    const auto found = std::find_if(after.entries.begin(),after.entries.end(),[&](const auto& p){return p.policyId == action.policyId;});
    const bool present = found != after.entries.end();
    const bool expectedEnabled = operation == L"save" ? desired.enabled : operation == L"enable";
    const bool verified = after.success && !action.policyId.empty() && (operation == L"remove" ? !present : present && found->enabled == expectedEnabled);
    const int code = action.success && verified ? 0 : action.success ? 6 :
        (action.nativeError == ERROR_INVALID_PARAMETER || action.nativeError == ERROR_NOT_SUPPORTED || action.nativeError == ERROR_ACCESS_DENIED || action.nativeError == ERROR_NOT_FOUND) ? 3 : 6;
    return {code,Json::object({{L"operation",Json::string(operation)}, {L"policyId",Json::string(action.policyId)},
        {L"requestSucceeded",Json::boolean(action.success)}, {L"nativeError",Json::number(action.nativeError)},
        {L"postcheckAvailable",Json::boolean(after.success)}, {L"postcheckPresent",after.success?Json::boolean(present):Json{}},
        {L"postcheck",present?qosRow(*found):Json{}}, {L"verified",Json::boolean(action.success&&verified)}}),
        {action.diagnostic,L"QoS affects outbound traffic for an image or all applications; the live ActiveStore expires after restart."}};
}
void addPolicy(Command command) { command.supportsR0 = true; addCommand(std::move(command)); }
}
void registerNetworkPolicy() {
    const std::wstring blockNotes = L"R3 uses KSword-owned Windows Firewall rules (image or explicit remote host); R0 uses driver-managed process-instance or remote-host rules. No automatic fallback. Each backend has distinct identities and capabilities.";
    addPolicy({L"network policy enum",L"KswordCLI.exe network policy enum [--backend r3|r0] [--json]",L"List owned network block policies for one backend.",L"Optional: --backend r3|r0, --json.",blockNotes,[](const Args& a){return listBlocks(a,false);}});
    addPolicy({L"network policy query",L"KswordCLI.exe network policy query --id ID [--backend r3|r0] [--json]",L"Read one owned network block policy.",L"Required: --id. Optional: --backend r3|r0, --json.",blockNotes,[](const Args& a){return listBlocks(a,true);}});
    addPolicy({L"network policy create",L"KswordCLI.exe network policy create --scope image|process|all [--path PATH] [--pid PID] [--creation-time FILETIME] [--remote PREFIXES] [--direction in|out|both] --confirm [--backend r3|r0] [--json]",L"Create an owned network block policy.",L"Required: --scope, --confirm. Remote prefixes are semicolon-separated numeric addresses/CIDRs; all scope requires a remote prefix. R3 image scope requires --path; R0 process scope requires PID and creation time.",blockNotes,[](const Args& a){return changeBlock(a,L"create");}});
    for(const auto* name : {L"enable",L"disable",L"remove"}) {
        const std::wstring op=name;
        addPolicy({L"network policy "+op,L"KswordCLI.exe network policy "+op+L" --id ID --confirm [--backend r3|r0] [--json]",L"Change one owned network block policy.",L"Required: --id, --confirm. Optional: --backend r3|r0, --json.",blockNotes,[op](const Args& a){return changeBlock(a,op);}});
    }
    const std::wstring qosNotes=L"Windows Policy QoS shapes outbound traffic by image or global scope, never a PID instance. ActiveStore expires at restart; disabled KSword definitions are retained for restoration. Actions only modify KSword-owned IDs; postcheck verifies presence and enabled state.";
    addCommand({L"network qos enum",L"KswordCLI.exe network qos enum [--backend r3] [--json]",L"List active and saved QoS policies.",L"Optional: --backend r3, --json.",qosNotes,[](const Args& a){return listQos(a,false);}});
    addCommand({L"network qos query",L"KswordCLI.exe network qos query --id ID [--backend r3] [--json]",L"Read one QoS policy.",L"Required: --id. Optional: --backend r3, --json.",qosNotes,[](const Args& a){return listQos(a,true);}});
    addCommand({L"network qos save",L"KswordCLI.exe network qos save --scope image|all [--path PATH] [--id ID] [--rate BYTES_PER_SEC] [--dscp N] [--priority N] [--protocol any|tcp|udp|tcp-udp] [--source-prefix PREFIX] [--destination-prefix PREFIX] [--source-port-start N] [--source-port-end N] [--destination-port-start N] [--destination-port-end N] [--precedence N] [--enabled on|off] --confirm [--backend r3] [--json]",L"Create or update an owned QoS policy.",L"Required: --scope, --confirm and at least one rate, DSCP or priority action. Image scope requires --path; supply all desired fields when updating.",qosNotes,[](const Args& a){return changeQos(a,L"save");}});
    for(const auto* name : {L"enable",L"disable",L"remove"}) {
        const std::wstring op=name;
        addCommand({L"network qos "+op,L"KswordCLI.exe network qos "+op+L" --id ID --confirm [--backend r3] [--json]",L"Change one owned QoS policy.",L"Required: --id, --confirm. Optional: --backend r3, --json.",qosNotes,[op](const Args& a){return changeQos(a,op);}});
    }
}
}
