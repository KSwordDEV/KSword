#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/Diagnostics.h"
#include <stdexcept>
namespace ks::cli {
void registerNetworkPing() {
    addCommand({L"network ping query", L"KswordCLI.exe network ping query --target HOST [--count N] [--timeout-ms N] [--backend r3] [--json]",
        L"Probe an IPv4 host using ICMP echo.", L"Required: --target. Optional: --count 1..32 (default 4), --timeout-ms 1..60000 (default 2000), --backend r3, --json.",
        L"IPv4 only; timeout applies to each echo. Data contains resolvedAddress, sent, received, lossPercent, win32Error and probes with raw IP status.",
        [](const Args& args) {
            ks::r3::network::DiagnosticRequest request;
            request.target = args.require(L"--target"); request.echoCount = args.u32(L"--count", 4); request.timeoutMs = args.u32(L"--timeout-ms", 2000);
            if (request.target.empty() || request.echoCount == 0 || request.echoCount > 32 || request.timeoutMs == 0 || request.timeoutMs > 60000) throw std::invalid_argument("invalid target, count or timeout");
            const auto response = ks::r3::network::RunPing(request); std::vector<Json> probes;
            for (const auto& probe : response.probes) probes.push_back(Json::object({{L"sequence", Json::number(probe.sequence)},
                {L"address", Json::string(probe.address)}, {L"status", Json::number(probe.status)}, {L"replied", Json::boolean(probe.replied)},
                {L"roundTripMs", probe.replied ? Json::number(probe.roundTripMs) : Json{}}, {L"ttl", probe.replied ? Json::number(probe.ttl) : Json{}},
                {L"dataBytes", Json::number(probe.dataBytes)}}));
            return Result{response.success ? (response.received == response.sent ? 0 : 6) : 3,
                Json::object({{L"target", Json::string(request.target)}, {L"resolvedAddress", Json::string(response.resolvedAddress)},
                    {L"sent", Json::number(response.sent)}, {L"received", Json::number(response.received)},
                    {L"lossPercent", response.sent ? Json::number((response.sent - response.received) * 100 / response.sent) : Json{}},
                    {L"win32Error", Json::number(response.win32Error)}, {L"probes", Json::array(probes)}}), {response.summary, response.text}};
        }});
}
}
