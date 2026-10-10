#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/Firewall.h"
namespace ks::cli {
void registerNetworkFirewall() {
    addCommand({L"network firewall enum", L"KswordCLI.exe network firewall enum [--name NAME] [--limit N] [--backend r3] [--json]",
        L"Read Windows Firewall profiles and rules through INetFwPolicy2.", L"Optional: --name exact display-name match, --limit (default 100), --backend r3, --json.",
        L"Read-only; requires the firewall service. Unknown properties are null. Data: profiles, profileSummary, hresult, complete, matchedCount, returnedCount, truncated, rules.",
        [](const Args& args) {
            const auto limit = args.u32(L"--limit", 100); const auto snapshot = ks::r3::network::EnumerateFirewallRules();
            std::vector<Json> rows; std::uint32_t matched = 0;
            for (const auto& rule : snapshot.entries) {
                if (args.has(L"--name") && rule.name != args.get(L"--name")) continue;
                ++matched; if (rows.size() >= limit) continue;
                const auto text = [&](unsigned bit, const std::wstring& value) { return rule.fieldFlags & (1u << bit) ? Json::string(value) : Json{}; };
                const auto number = [&](unsigned bit, std::int32_t value) { return rule.fieldFlags & (1u << bit) ? Json::number(static_cast<std::uint32_t>(value)) : Json{}; };
                const auto boolean = [&](unsigned bit, bool value) { return rule.fieldFlags & (1u << bit) ? Json::boolean(value) : Json{}; };
                rows.push_back(Json::object({{L"name", text(0,rule.name)}, {L"description",text(1,rule.description)}, {L"grouping",text(2,rule.grouping)},
                    {L"applicationName",text(3,rule.applicationName)}, {L"serviceName",text(4,rule.serviceName)}, {L"localPorts",text(5,rule.localPorts)},
                    {L"remotePorts",text(6,rule.remotePorts)}, {L"localAddresses",text(7,rule.localAddresses)}, {L"remoteAddresses",text(8,rule.remoteAddresses)},
                    {L"interfaceTypes",text(9,rule.interfaceTypes)}, {L"direction",number(10,rule.direction)}, {L"action",number(11,rule.action)},
                    {L"protocol",number(12,rule.protocol)}, {L"profiles",number(13,rule.profiles)}, {L"enabled",boolean(14,rule.enabled)}, {L"edgeTraversal",boolean(15,rule.edgeTraversal)}}));
            }
            const auto profile = [&](unsigned flag) { return snapshot.profileKnownFlags & flag ? Json::boolean((snapshot.profileEnabledFlags & flag) != 0) : Json{}; };
            Result result{snapshot.success ? (snapshot.complete && snapshot.profileKnownFlags == 7 ? 0 : 6) : 3,
                Json::object({{L"profiles",Json::object({{L"domain",profile(1)}, {L"private",profile(2)}, {L"public",profile(4)}})},
                    {L"profileSummary",Json::string(snapshot.profileSummary)}, {L"hresult",Json::number(snapshot.hresult)}, {L"complete",Json::boolean(snapshot.complete)},
                    {L"matchedCount",Json::number(matched)}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))},
                    {L"truncated",Json::boolean(rows.size() < matched)}, {L"rules",Json::array(rows)}}), {}};
            if (!snapshot.diagnosticText.empty()) result.diagnostics.push_back(snapshot.diagnosticText);
            return result;
        }});
}
}
