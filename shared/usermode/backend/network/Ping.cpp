#include "IcmpSupport.h"
#pragma comment(lib, "Iphlpapi.lib")
namespace ks::r3::network {
using namespace detail;
DiagnosticResult RunPing(const DiagnosticRequest& request) {
    DiagnosticResult result{};
    const ResolvedTarget target = ResolveIpv4(request.target);
    if (!target.resolved) {
        result.text = target.diagnostic;
        result.summary = L"Ping 未执行：目标解析失败。";
        return result;
    }

    IcmpSession session;
    if (!session.valid()) {
        result.text = L"无法创建 ICMP 句柄：" + FormatWin32Error(::GetLastError()) + L"。";
        result.summary = L"Ping 未执行：ICMP 句柄创建失败。";
        return result;
    }

    const std::uint32_t echoCount = std::clamp<std::uint32_t>(request.echoCount, 1, kMaxEchoCount);
    unsigned char payload[kEchoPayloadSize]{};
    for (std::size_t index = 0; index < sizeof(payload); ++index) {
        payload[index] = static_cast<unsigned char>(L'a' + (index % 23));
    }
    std::vector<unsigned char> replyBuffer(sizeof(ICMP_ECHO_REPLY) + kEchoPayloadSize + kReplySlack, 0);

    AppendLine(result.text, L"正在 Ping " + request.target + L" [" + target.addressText + L"]，数据 " +
        std::to_wstring(kEchoPayloadSize) + L" 字节：");

    std::uint32_t received = 0;
    std::uint32_t minimum = (std::numeric_limits<std::uint32_t>::max)();
    std::uint32_t maximum = 0;
    std::uint64_t total = 0;
    for (std::uint32_t attempt = 0; attempt < echoCount; ++attempt) {
        const DWORD replies = ::IcmpSendEcho2(
            session.get(),
            nullptr,
            nullptr,
            nullptr,
            static_cast<IPAddr>(target.address),
            payload,
            kEchoPayloadSize,
            nullptr,
            replyBuffer.data(),
            static_cast<DWORD>(replyBuffer.size()),
            request.timeoutMs);
        if (replies == 0) {
            AppendLine(result.text, L"请求失败：" + FormatWin32Error(::GetLastError()));
            continue;
        }
        const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.data());
        if (reply->Status != IP_SUCCESS) {
            AppendLine(result.text, L"来自 " + FormatIpv4Address(static_cast<std::uint32_t>(reply->Address)) +
                L" 的回应：" + IcmpStatusText(reply->Status));
            continue;
        }
        ++received;
        const std::uint32_t roundTrip = static_cast<std::uint32_t>(reply->RoundTripTime);
        minimum = (std::min)(minimum, roundTrip);
        maximum = (std::max)(maximum, roundTrip);
        total += roundTrip;
        AppendLine(result.text, L"来自 " + FormatIpv4Address(static_cast<std::uint32_t>(reply->Address)) +
            L" 的回复：字节=" + std::to_wstring(reply->DataSize) +
            L" 时间=" + FormatMilliseconds(roundTrip) +
            L" TTL=" + std::to_wstring(reply->Options.Ttl));
    }

    const std::uint32_t lost = echoCount - received;
    const std::uint32_t lossPercent = echoCount == 0 ? 0 : lost * 100 / echoCount;
    AppendLine(result.text, L"");
    AppendLine(result.text, L"Ping 统计：已发送 = " + std::to_wstring(echoCount) +
        L"，已接收 = " + std::to_wstring(received) +
        L"，丢失 = " + std::to_wstring(lost) + L"（" + std::to_wstring(lossPercent) + L"% 丢失）");
    if (received != 0) {
        AppendLine(result.text, L"往返行程时间：最短 = " + FormatMilliseconds(minimum) +
            L"，最长 = " + FormatMilliseconds(maximum) +
            L"，平均 = " + FormatMilliseconds(static_cast<std::uint32_t>(total / received)));
    }

    result.success = received != 0;
    result.summary = L"Ping " + target.addressText + L" 完成：接收 " + std::to_wstring(received) + L"/" +
        std::to_wstring(echoCount) + L"，丢失 " + std::to_wstring(lossPercent) + L"%。";
    return result;
}
}
