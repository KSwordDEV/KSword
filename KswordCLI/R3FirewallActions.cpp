#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/FirewallOperations.h"
#include <algorithm>
#include <cwctype>
#include <stdexcept>

namespace ks::cli {
namespace {
using namespace ks::r3::network;
Json ruleJson(const FirewallRuleEntry& r) {
    const auto text = [&](unsigned bit, const std::wstring& value) { return r.fieldFlags & (1u << bit) ? Json::string(value) : Json{}; };
    const auto number = [&](unsigned bit, std::int32_t value) { return r.fieldFlags & (1u << bit) ? Json::number(static_cast<std::uint32_t>(value)) : Json{}; };
    const auto boolean = [&](unsigned bit, bool value) { return r.fieldFlags & (1u << bit) ? Json::boolean(value) : Json{}; };
    return Json::object({{L"name",text(0,r.name)}, {L"description",text(1,r.description)}, {L"grouping",text(2,r.grouping)},
        {L"applicationName",text(3,r.applicationName)}, {L"serviceName",text(4,r.serviceName)}, {L"localPorts",text(5,r.localPorts)},
        {L"remotePorts",text(6,r.remotePorts)}, {L"localAddresses",text(7,r.localAddresses)}, {L"remoteAddresses",text(8,r.remoteAddresses)},
        {L"interfaceTypes",text(9,r.interfaceTypes)}, {L"direction",number(10,r.direction)}, {L"action",number(11,r.action)},
        {L"protocol",number(12,r.protocol)}, {L"profiles",number(13,r.profiles)}, {L"enabled",boolean(14,r.enabled)},
        {L"edgeTraversal",boolean(15,r.edgeTraversal)}, {L"icmpTypesAndCodes",text(16,r.icmpTypesAndCodes)}, {L"fieldFlags",Json::hex(r.fieldFlags)}});
}
Json lookupJson(const FirewallRuleLookup& value) {
    std::vector<Json> candidates;
    for (const auto& candidate : value.candidates)
        candidates.push_back(Json::object({{L"fingerprint",Json::string(candidate.fingerprint)}, {L"rule",ruleJson(candidate.entry)}}));
    return Json::object({{L"success",Json::boolean(value.success)}, {L"complete",Json::boolean(value.complete)},
        {L"matchingCount",Json::number(value.matchingCount)}, {L"nameMatchingCount",Json::number(value.nameMatchingCount)}, {L"hresult",Json::hex(value.hresult)},
        {L"fingerprint",value.matchingCount == 1 && !value.fingerprint.empty() ? Json::string(value.fingerprint) : Json{}},
        {L"rule",value.matchingCount == 1 ? ruleJson(value.entry) : Json{}}, {L"candidates",Json::array(candidates)}});
}
std::wstring lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}
bool onOff(const Args& args, const wchar_t* name) {
    const auto text = lower(args.require(name));
    if (text == L"on" || text == L"true" || text == L"1") return true;
    if (text == L"off" || text == L"false" || text == L"0") return false;
    throw std::invalid_argument("boolean option must be on or off");
}
std::uint32_t protocol(const Args& args) {
    const auto text = lower(args.require(L"--protocol"));
    if (text == L"any") return 256;
    if (text == L"tcp") return 6;
    if (text == L"udp") return 17;
    const auto value = args.u32(L"--protocol");
    if (value > 255) throw std::invalid_argument("--protocol must be any, tcp, udp or 0..255");
    return value;
}
FirewallRuleMutation mutation(const Args& args, bool creation, const wchar_t* forcedEnabled = nullptr) {
    FirewallRuleMutation result;
    result.name = args.require(L"--name");
    if (result.name.empty()) throw std::invalid_argument("--name must not be empty");
    if (!args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    if (!creation) {
        result.expectedFingerprint = lower(args.require(L"--fingerprint"));
        if (result.expectedFingerprint.size() != 64 ||
            !std::all_of(result.expectedFingerprint.begin(),result.expectedFingerprint.end(),[](wchar_t c) { return (c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f'); }))
            throw std::invalid_argument("--fingerprint must be a 64-digit SHA-256 from rule query");
    }
    auto& f = result.fields;
    if (args.has(L"--new-name")) { result.rename=true; result.newName=args.get(L"--new-name");
        if (result.newName.empty()) throw std::invalid_argument("--new-name must not be empty"); }
    const auto setText = [&](const wchar_t* key, unsigned bit, std::wstring& target) {
        if (args.has(key)) { target=args.get(key); f.fieldFlags |= 1u << bit; }
    };
    setText(L"--description",1,f.description); setText(L"--grouping",2,f.grouping);
    setText(L"--application",3,f.applicationName); setText(L"--service",4,f.serviceName);
    setText(L"--local-ports",5,f.localPorts); setText(L"--remote-ports",6,f.remotePorts);
    setText(L"--local-addresses",7,f.localAddresses); setText(L"--remote-addresses",8,f.remoteAddresses);
    setText(L"--interface-types",9,f.interfaceTypes);
    setText(L"--icmp-types",16,f.icmpTypesAndCodes);
    if (args.has(L"--direction")) {
        const auto v=lower(args.require(L"--direction"));
        if (v==L"in" || v==L"inbound") f.direction=1;
        else if (v==L"out" || v==L"outbound") f.direction=2;
        else throw std::invalid_argument("--direction must be in or out");
        f.fieldFlags |= 1u << 10;
    }
    if (args.has(L"--action")) {
        const auto v=lower(args.require(L"--action"));
        if (v==L"block") f.action=0;
        else if (v==L"allow") f.action=1;
        else throw std::invalid_argument("--action must be allow or block");
        f.fieldFlags |= 1u << 11;
    }
    if (args.has(L"--protocol")) { f.protocol=static_cast<std::int32_t>(protocol(args)); f.fieldFlags |= 1u << 12; }
    if (args.has(L"--profiles")) {
        const auto profiles=lower(args.get(L"--profiles"))==L"all" ? 0x7fffffffu : args.u32(L"--profiles");
        if (!profiles || (profiles != 0x7fffffffu && (profiles & ~7u))) throw std::invalid_argument("--profiles must be all or a nonzero domain/private/public bitmask (1..7)");
        f.profiles=static_cast<std::int32_t>(profiles); f.fieldFlags |= 1u << 13;
    }
    if (forcedEnabled) { f.enabled=std::wstring(forcedEnabled)==L"on"; f.fieldFlags |= 1u << 14; }
    else if (args.has(L"--enabled")) { f.enabled=onOff(args,L"--enabled"); f.fieldFlags |= 1u << 14; }
    if (args.has(L"--edge-traversal")) { f.edgeTraversal=onOff(args,L"--edge-traversal"); f.fieldFlags |= 1u << 15; }
    constexpr std::uint32_t required = (1u<<10)|(1u<<11)|(1u<<12)|(1u<<13)|(1u<<14);
    if (creation && (f.fieldFlags & required) != required)
        throw std::invalid_argument("create requires --direction, --action, --protocol, --profiles and --enabled");
    return result;
}
Result query(const Args& args) {
    const auto name=args.require(L"--name");
    if (name.empty()) throw std::invalid_argument("--name must not be empty");
    const auto r=QueryFirewallRule(name,lower(args.get(L"--fingerprint")));
    const int code=!r.success ? 3 : !r.complete ? 6 : r.matchingCount==0 ? 3 : r.matchingCount==1 ? 0 : 6;
    std::vector<std::wstring> diagnostics;
    if (!r.diagnostic.empty()) diagnostics.push_back(r.diagnostic);
    if (r.matchingCount>1) diagnostics.push_back(L"Multiple rules match; select a candidate fingerprint for an individual rule.");
    return {code,lookupJson(r),diagnostics};
}
Result change(const Args& args, const std::wstring& operation) {
    const bool create=operation==L"create";
    const auto m=mutation(args,create,operation==L"enable"?L"on":operation==L"disable"?L"off":nullptr);
    if (operation==L"update" && m.fields.fieldFlags==0 && !m.rename) throw std::invalid_argument("update requires at least one rule field");
    const auto r=create ? CreateFirewallRule(m) : operation==L"delete" ? RemoveFirewallRule(m) : UpdateFirewallRule(m);
    const int code=r.requestSucceeded ? r.verified?0:6 : r.partialEffectPossible?6:3;
    std::vector<std::wstring> diagnostics;
    if (!r.diagnostic.empty()) diagnostics.push_back(r.diagnostic);
    diagnostics.push_back(L"Fingerprint revalidation is a snapshot check; Windows Firewall does not offer atomic compare-and-update or compare-and-remove.");
    return {code,Json::object({{L"operation",Json::string(operation)}, {L"preflightComplete",Json::boolean(r.preflightComplete)},
        {L"requestAttempted",Json::boolean(r.requestAttempted)}, {L"requestSucceeded",Json::boolean(r.requestSucceeded)},
        {L"partialEffectPossible",Json::boolean(r.partialEffectPossible)}, {L"postcheckComplete",Json::boolean(r.postcheckComplete)},
        {L"verified",Json::boolean(r.verified)}, {L"hresult",Json::hex(r.hresult)}, {L"stage",Json::string(r.stage)},
        {L"before",lookupJson(r.before)}, {L"after",lookupJson(r.after)}}),diagnostics};
}
}
void registerFirewallActions() {
    addCommand({L"network firewall rule query",L"KswordCLI.exe network firewall rule query --name NAME [--fingerprint SHA256] [--backend r3] [--json]",
        L"Query Windows Firewall rules by name and optional snapshot fingerprint.",L"Required: --name. Optional: --fingerprint, --backend r3, --json.",
        L"Returns fields supported by the shared inventory and SHA-256 fingerprints for same-name candidates. A fingerprint selects one matching rule; identical duplicates remain ambiguous. Duplicate matches or incomplete enumeration return 6; absent matches return 3. No driver or mutation.",query});
    const std::wstring fields=L" [--description TEXT] [--grouping TEXT] [--application PATH] [--service NAME] [--local-ports PORTS] [--remote-ports PORTS] [--local-addresses ADDRS] [--remote-addresses ADDRS] [--interface-types TYPES] [--icmp-types TYPES] [--direction in|out] [--action allow|block] [--protocol any|tcp|udp|N] [--profiles all|MASK] [--enabled on|off] [--edge-traversal on|off]";
    const std::wstring notes=L"R3 Windows Firewall COM; --profiles uses domain=1, private=2, public=4. Query a rule and pass its fingerprint to update/delete/enable/disable. Updates match the enumerated COM rule; delete requires a unique name because Windows removes by name. Empty text can clear a supplied string property. Preflight and postcheck are snapshots, not atomic; a failed update may have applied earlier setters. No automatic rollback or R0 fallback.";
    addCommand({L"network firewall rule create",L"KswordCLI.exe network firewall rule create --name NAME"+fields+L" --confirm [--backend r3] [--json]",
        L"Create one uniquely named Windows Firewall rule.",L"Required: --name, --direction, --action, --protocol, --profiles, --enabled, --confirm. Other fields optional.",notes,
        [](const Args& a) { return change(a,L"create"); }});
    addCommand({L"network firewall rule update",L"KswordCLI.exe network firewall rule update --name NAME --fingerprint SHA256 [--new-name NAME]"+fields+L" --confirm [--backend r3] [--json]",
        L"Update selected properties of one previously inspected rule.",L"Required: --name, --fingerprint, at least one field, --confirm.",notes,
        [](const Args& a) { return change(a,L"update"); }});
    for (const auto* action : {L"enable",L"disable",L"delete"}) {
        const std::wstring word=action;
        addCommand({L"network firewall rule "+word,L"KswordCLI.exe network firewall rule "+word+L" --name NAME --fingerprint SHA256 --confirm [--backend r3] [--json]",
        L"Apply "+word+L" to an identified firewall rule.",L"Required: --name, --fingerprint, --confirm. Optional: --backend r3, --json.",notes,
            [word](const Args& a) { return change(a,word); }});
    }
}
}
