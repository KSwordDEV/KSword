#include "CommandRegistry.h"
#include "../shared/usermode/backend/network/Diagnostics.h"
#include <stdexcept>
namespace ks::cli {
void registerNetworkTraceRoute() {
    addCommand({L"network trace-route query", L"KswordCLI.exe network trace-route query --target HOST [--max-hops N] [--timeout-ms N] [--backend r3] [--json]",
        L"Trace an IPv4 route using ICMP with increasing TTL.", L"Required: --target. Optional: --max-hops 1..64 (default 30), --timeout-ms 1..60000 (default 2000), --backend r3, --json.",
        L"One probe per hop. Reached target returns 0, responding hops without reaching target return 6, no replies return 3. Data: resolvedAddress, reached, attemptedHops, hops, win32Error.",
        [](const Args& args) {
            ks::r3::network::DiagnosticRequest request;
            request.kind = ks::r3::network::DiagnosticKind::TraceRoute;
            request.target = args.require(L"--target"); request.maxHops = args.u32(L"--max-hops", 30); request.timeoutMs = args.u32(L"--timeout-ms", 2000);
            if (request.target.empty() || request.maxHops == 0 || request.maxHops > 64 || request.timeoutMs == 0 || request.timeoutMs > 60000) throw std::invalid_argument("invalid target, max-hops or timeout");
            const auto response = ks::r3::network::RunTraceRoute(request); std::vector<Json> hops;
            for (const auto& probe : response.probes) hops.push_back(Json::object({{L"hop", Json::number(probe.sequence)},
                {L"address", Json::string(probe.address)}, {L"status", Json::number(probe.status)}, {L"replied", Json::boolean(probe.replied)},
                {L"roundTripMs", probe.replied ? Json::number(probe.roundTripMs) : Json{}}, {L"replyTtl", probe.replied ? Json::number(probe.ttl) : Json{}}}));
            return Result{response.reached ? 0 : response.received ? 6 : 3,
                Json::object({{L"target", Json::string(request.target)}, {L"resolvedAddress", Json::string(response.resolvedAddress)},
                    {L"reached", Json::boolean(response.reached)}, {L"attemptedHops", Json::number(response.sent)},
                    {L"win32Error", Json::number(response.win32Error)}, {L"hops", Json::array(hops)}}), {response.summary, response.text}};
        }});
}
}
