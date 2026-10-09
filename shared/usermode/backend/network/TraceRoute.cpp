#include "IcmpSupport.h"
#pragma comment(lib, "Iphlpapi.lib")
namespace ks::r3::network {
using namespace detail;
DiagnosticResult RunTraceRoute(const DiagnosticRequest& request) {
    DiagnosticResult result{};
    const ResolvedTarget target = ResolveIpv4(request.target);
    result.resolvedAddress = target.addressText;
    result.win32Error = target.error;
    if (!target.resolved) {
        result.text = target.diagnostic;
        result.summary = L"路由跟踪未执行：目标解析失败。";
        return result;
    }

    IcmpSession session;
    if (!session.valid()) {
        result.win32Error = ::GetLastError();
        result.text = L"无法创建 ICMP 句柄：" + FormatWin32Error(::GetLastError()) + L"。";
        result.summary = L"路由跟踪未执行：ICMP 句柄创建失败。";
        return result;
    }

    const std::uint32_t maxHops = std::clamp<std::uint32_t>(request.maxHops, 1, kMaxHopCount);
    unsigned char payload[kEchoPayloadSize]{};
    for (std::size_t index = 0; index < sizeof(payload); ++index) {
        payload[index] = static_cast<unsigned char>(L'a' + (index % 23));
    }
    std::vector<unsigned char> replyBuffer(sizeof(ICMP_ECHO_REPLY) + kEchoPayloadSize + kReplySlack, 0);

    AppendLine(result.text, L"通过最多 " + std::to_wstring(maxHops) + L" 个跃点跟踪到 " + request.target +
        L" [" + target.addressText + L"] 的路由：");
    AppendLine(result.text, L"");

    bool reached = false;
    std::uint32_t lastHop = 0;
    for (std::uint32_t hop = 1; hop <= maxHops && !reached; ++hop) {
        ++result.sent;
        lastHop = hop;
        IP_OPTION_INFORMATION options{};
        options.Ttl = static_cast<UCHAR>(hop);
        const DWORD replies = ::IcmpSendEcho2(
            session.get(),
            nullptr,
            nullptr,
            nullptr,
            static_cast<IPAddr>(target.address),
            payload,
            kEchoPayloadSize,
            &options,
            replyBuffer.data(),
            static_cast<DWORD>(replyBuffer.size()),
            request.timeoutMs);
        const std::wstring prefix = (hop < 10 ? L"  " : L" ") + std::to_wstring(hop);
        if (replies == 0) {
            const DWORD error = ::GetLastError();
            result.probes.push_back({hop, error, 0, 0, 0, L"", false});
            if (error == IP_REQ_TIMED_OUT) {
                AppendLine(result.text, prefix + L"\t*\t请求超时");
                continue;
            }
            AppendLine(result.text, prefix + L"\t*\t" + FormatWin32Error(error));
            continue;
        }

        const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.data());
        ++result.received;
        result.probes.push_back({hop, reply->Status, reply->RoundTripTime, reply->Options.Ttl,
            reply->DataSize, FormatIpv4Address(static_cast<std::uint32_t>(reply->Address)), true});
        const std::wstring hopAddress = FormatIpv4Address(static_cast<std::uint32_t>(reply->Address));
        if (reply->Status == IP_SUCCESS) {
            reached = true;
            AppendLine(result.text, prefix + L"\t" + FormatMilliseconds(static_cast<std::uint32_t>(reply->RoundTripTime)) +
                L"\t" + hopAddress + L"\t（已到达目标）");
            continue;
        }
        if (reply->Status == IP_TTL_EXPIRED_TRANSIT) {
            AppendLine(result.text, prefix + L"\t" + FormatMilliseconds(static_cast<std::uint32_t>(reply->RoundTripTime)) +
                L"\t" + hopAddress);
            continue;
        }
        // Anything else is still a real router answering, so the hop address is
        // printed alongside the reason rather than collapsed into a timeout.
        AppendLine(result.text, prefix + L"\t*\t" + hopAddress + L"\t" + IcmpStatusText(reply->Status));
    }

    AppendLine(result.text, L"");
    AppendLine(result.text, reached ? L"跟踪完成。" : L"未在跃点上限内到达目标，跟踪结束。");
    result.success = reached;
    result.reached = reached;
    result.summary = reached
        ? L"路由跟踪完成：" + std::to_wstring(lastHop) + L" 跳到达 " + target.addressText + L"。"
        : L"路由跟踪结束：" + std::to_wstring(lastHop) + L" 跳内未到达 " + target.addressText + L"。";
    return result;
}
}
