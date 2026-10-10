#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/Connections.h"
#include <algorithm>
#include <stdexcept>

namespace ks::cli {
namespace {
using namespace ks::r3::network;
const wchar_t* protocol(ConnectionProtocol value) {
    switch (value) { case ConnectionProtocol::Tcp4: return L"tcp4"; case ConnectionProtocol::Tcp6: return L"tcp6";
        case ConnectionProtocol::Udp4: return L"udp4"; default: return L"udp6"; }
}
Json row(const ConnectionEntry& value) {
    return Json::object({{L"protocol", Json::string(protocol(value.protocol))}, {L"pid", Json::number(value.processId)},
        {L"processName", Json::string(value.processName)}, {L"localAddress", Json::string(value.localAddress)},
        {L"localPort", Json::number(value.localPort)}, {L"remoteAddress", Json::string(value.remoteAddress)},
        {L"remotePort", Json::number(value.remotePort)}, {L"state", value.hasState ? Json::number(value.state) : Json{}},
        {L"canClose", Json::boolean(ConnectionCanClose(value))}});
}
Result enumerate(const Args& args) {
    const auto filter = args.get(L"--protocol", L"all");
    if (filter != L"all" && filter != L"tcp4" && filter != L"tcp6" && filter != L"udp4" && filter != L"udp6") throw std::invalid_argument("invalid --protocol");
    const auto pid = args.u32(L"--pid"); const auto limit = args.u32(L"--limit", 100);
    const auto snapshot = EnumerateConnections(); std::vector<Json> rows; std::uint32_t matched = 0;
    for (const auto& value : snapshot.entries) {
        if ((args.has(L"--pid") && value.processId != pid) || (filter != L"all" && filter != protocol(value.protocol))) continue;
        ++matched; if (rows.size() < limit) rows.push_back(row(value));
    }
    Result result{snapshot.success ? (snapshot.diagnosticText.empty() ? 0 : 6) : 3,
        Json::object({{L"matchedCount", Json::number(matched)}, {L"returnedCount", Json::number(static_cast<std::uint32_t>(rows.size()))},
            {L"truncated", Json::boolean(rows.size() < matched)}, {L"entries", Json::array(rows)}}), {}};
    if (!snapshot.diagnosticText.empty()) result.diagnostics.push_back(snapshot.diagnosticText);
    return result;
}
Result close(const Args& args) {
    args.require(L"--pid"); args.require(L"--local-address"); args.require(L"--local-port"); args.require(L"--remote-address"); args.require(L"--remote-port");
    if (!args.has(L"--confirm")) throw std::invalid_argument("missing option --confirm");
    const auto pid = args.u32(L"--pid"); const auto local = args.u32(L"--local-port"), remote = args.u32(L"--remote-port");
    if (local > 65535 || remote > 65535) throw std::invalid_argument("port exceeds 65535");
    const auto snapshot = EnumerateConnections();
    if (!snapshot.success || !snapshot.diagnosticText.empty()) return {snapshot.success ? 6 : 3, Json::object({}), {snapshot.diagnosticText}};
    const auto match = [&](const ConnectionEntry& value) { return value.protocol == ConnectionProtocol::Tcp4 && value.processId == pid &&
        value.localAddress == args.get(L"--local-address") && value.localPort == local && value.remoteAddress == args.get(L"--remote-address") && value.remotePort == remote; };
    const auto it = std::find_if(snapshot.entries.begin(), snapshot.entries.end(), match);
    if (it == snapshot.entries.end()) return {3, Json::object({}), {L"The selected IPv4 TCP tuple and owner no longer exist."}};
    if (!ConnectionCanClose(*it)) return {5, row(*it), {L"IPv4 TCP listeners and closed entries cannot be deleted."}};
    const auto action = CloseTcpConnection(*it);
    const auto after = EnumerateConnections();
    const bool present = std::any_of(after.entries.begin(), after.entries.end(), match);
    const bool complete = after.success && after.diagnosticText.empty();
    Result result{!action.success ? 3 : complete && !present ? 0 : 6,
        Json::object({{L"target", row(*it)}, {L"win32Error", Json::number(action.win32Error)},
            {L"requestSucceeded", Json::boolean(action.success)}, {L"postcheckPresent", complete ? Json::boolean(present) : Json{}},
            {L"postcheckComplete", Json::boolean(complete)}}),
        {action.success ? action.message : L"SetTcpEntry failed. win32Error is the native status; target presence is reported separately by the postcheck. An API error alone does not prove the connection disappeared."}};
    if (!after.diagnosticText.empty()) result.diagnostics.push_back(after.diagnosticText);
    return result;
}
}
void registerNetworkConnections() {
    addCommand({L"network connections enum", L"KswordCLI.exe network connections enum [--pid PID] [--protocol all|tcp4|tcp6|udp4|udp6] [--limit N] [--backend r3] [--json]",
        L"Enumerate TCP/UDP endpoints through IP Helper.", L"Optional: --pid, --protocol defaults to all, --limit defaults to 100, --backend r3, --json.",
        L"No driver required. UDP state is null; limit affects display only. JSON data: matchedCount, returnedCount, truncated, entries.", enumerate});
    addCommand({L"network connections close", L"KswordCLI.exe network connections close --pid PID --local-address IP --local-port N --remote-address IP --remote-port N --confirm [--backend r3] [--json]",
        L"Close one live IPv4 TCP connection by its exact tuple and owner.", L"Required: --pid, --local-address, --local-port, --remote-address, --remote-port, --confirm. Optional: --backend r3, --json.",
        L"Administrator required. IPv6/UDP/listeners are unsupported. Re-enumerates before closing and after success or failure. Output: target, native win32Error, requestSucceeded, postcheckPresent (null if incomplete), postcheckComplete. API failure returns 3 even if the tuple disappeared independently; error 317 alone does not prove disappearance. Success with absent tuple returns 0; incomplete/present postcheck returns 6.", close});
}
}
