#include "NetToolsDiagnostics.h"
#include "../../../shared/usermode/backend/network/IcmpSupport.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windns.h>

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Dnsapi.lib")

namespace Ksword::Features::NetTools {
namespace {
using namespace ks::r3::network::detail;


DiagnosticResult RunTraceRoute(const DiagnosticRequest& request) {
    DiagnosticResult result{};
    const ResolvedTarget target = ResolveIpv4(request.target);
    if (!target.resolved) {
        result.text = target.diagnostic;
        result.summary = L"路由跟踪未执行：目标解析失败。";
        return result;
    }

    IcmpSession session;
    if (!session.valid()) {
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
            if (error == IP_REQ_TIMED_OUT) {
                AppendLine(result.text, prefix + L"\t*\t请求超时");
                continue;
            }
            AppendLine(result.text, prefix + L"\t*\t" + FormatWin32Error(error));
            continue;
        }

        const auto* reply = reinterpret_cast<const ICMP_ECHO_REPLY*>(replyBuffer.data());
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
    result.summary = reached
        ? L"路由跟踪完成：" + std::to_wstring(lastHop) + L" 跳到达 " + target.addressText + L"。"
        : L"路由跟踪结束：" + std::to_wstring(lastHop) + L" 跳内未到达 " + target.addressText + L"。";
    return result;
}

std::wstring DnsTypeText(const WORD type) {
    switch (type) {
    case DNS_TYPE_A: return L"A";
    case DNS_TYPE_NS: return L"NS";
    case DNS_TYPE_CNAME: return L"CNAME";
    case DNS_TYPE_SOA: return L"SOA";
    case DNS_TYPE_PTR: return L"PTR";
    case DNS_TYPE_MX: return L"MX";
    case DNS_TYPE_TEXT: return L"TXT";
    case DNS_TYPE_AAAA: return L"AAAA";
    case DNS_TYPE_SRV: return L"SRV";
    case DNS_TYPE_ANY: return L"ANY";
    default: break;
    }
    return L"类型 " + std::to_wstring(type);
}

std::wstring SafeName(PCWSTR name) {
    return name == nullptr ? std::wstring{} : std::wstring(name);
}

// DnsRecordValueText renders one answer. Only the record types the combo offers
// are decoded; anything else still shows up as a row with its type and TTL so an
// unexpected answer in an ANY query is visible rather than dropped.
std::wstring DnsRecordValueText(const DNS_RECORDW& record) {
    switch (record.wType) {
    case DNS_TYPE_A:
        return FormatIpv4Address(static_cast<std::uint32_t>(record.Data.A.IpAddress));
    case DNS_TYPE_AAAA:
        return FormatIpv6Address(reinterpret_cast<const std::uint8_t*>(record.Data.AAAA.Ip6Address.IP6Byte), 0);
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        return SafeName(record.Data.PTR.pNameHost);
    case DNS_TYPE_MX:
        return L"优先级 " + std::to_wstring(record.Data.MX.wPreference) + L" " + SafeName(record.Data.MX.pNameExchange);
    case DNS_TYPE_SRV:
        return SafeName(record.Data.SRV.pNameTarget) + L":" + std::to_wstring(record.Data.SRV.wPort) +
            L"（优先级 " + std::to_wstring(record.Data.SRV.wPriority) +
            L"，权重 " + std::to_wstring(record.Data.SRV.wWeight) + L"）";
    case DNS_TYPE_SOA:
        return L"主服务器 " + SafeName(record.Data.SOA.pNamePrimaryServer) +
            L"，管理员 " + SafeName(record.Data.SOA.pNameAdministrator) +
            L"，序列号 " + std::to_wstring(record.Data.SOA.dwSerialNo) +
            L"，刷新 " + std::to_wstring(record.Data.SOA.dwRefresh) +
            L"，重试 " + std::to_wstring(record.Data.SOA.dwRetry) +
            L"，过期 " + std::to_wstring(record.Data.SOA.dwExpire);
    case DNS_TYPE_TEXT: {
        std::wstring text;
        for (DWORD index = 0; index < record.Data.TXT.dwStringCount; ++index) {
            if (!text.empty()) {
                text += L" ";
            }
            text += L"\"" + SafeName(record.Data.TXT.pStringArray[index]) + L"\"";
        }
        return text;
    }
    default:
        break;
    }
    return L"（未解码，数据长度 " + std::to_wstring(record.wDataLength) + L" 字节）";
}

DiagnosticResult RunDnsLookup(const DiagnosticRequest& request) {
    DiagnosticResult result{};
    if (request.target.empty()) {
        result.text = L"请先填写要查询的域名。";
        result.summary = L"DNS 查询未执行：域名为空。";
        return result;
    }

    const WORD recordType = request.dnsRecordType == 0 ? static_cast<WORD>(DNS_TYPE_A) : request.dnsRecordType;
    PDNS_RECORD records = nullptr;
    const DNS_STATUS status = ::DnsQuery_W(
        request.target.c_str(), recordType, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
    if (status != ERROR_SUCCESS) {
        if (records != nullptr) {
            ::DnsFree(records, DnsFreeRecordList);
        }
        result.text = L"DNS 查询 " + request.target + L"（" + DnsTypeText(recordType) + L"）失败：" +
            FormatWin32Error(static_cast<std::uint32_t>(status)) + L"。";
        result.summary = L"DNS 查询失败。";
        return result;
    }

    AppendLine(result.text, L"DNS 查询：" + request.target + L"，记录类型 " + DnsTypeText(recordType));
    AppendLine(result.text, L"");
    std::size_t count = 0;
    for (const DNS_RECORDW* cursor = records; cursor != nullptr; cursor = cursor->pNext) {
        ++count;
        AppendLine(result.text, DnsTypeText(cursor->wType) + L"\t" + SafeName(cursor->pName) +
            L"\tTTL=" + std::to_wstring(cursor->dwTtl) + L"\t" + DnsRecordValueText(*cursor));
    }
    ::DnsFree(records, DnsFreeRecordList);

    AppendLine(result.text, L"");
    AppendLine(result.text, L"共 " + std::to_wstring(count) + L" 条记录。");
    result.success = count != 0;
    result.summary = L"DNS 查询 " + request.target + L" 返回 " + std::to_wstring(count) + L" 条记录。";
    return result;
}

// DnsRecordTypeChoice pairs one combo label with its DNS_TYPE_* value. The two
// are declared together so adding a record type cannot leave the label list and
// the value list out of step.
struct DnsRecordTypeChoice final {
    const wchar_t* label;
    WORD value;
};

constexpr DnsRecordTypeChoice kDnsRecordTypeChoices[] = {
    { L"A", DNS_TYPE_A },
    { L"AAAA", DNS_TYPE_AAAA },
    { L"CNAME", DNS_TYPE_CNAME },
    { L"MX", DNS_TYPE_MX },
    { L"NS", DNS_TYPE_NS },
    { L"TXT", DNS_TYPE_TEXT },
    { L"PTR", DNS_TYPE_PTR },
    { L"SOA", DNS_TYPE_SOA },
    { L"SRV", DNS_TYPE_SRV },
    { L"ANY", DNS_TYPE_ANY },
};

} // namespace

int DnsRecordTypeChoiceCount() {
    return static_cast<int>(std::size(kDnsRecordTypeChoices));
}

const wchar_t* DnsRecordTypeChoiceLabel(const int index) {
    if (index < 0 || index >= DnsRecordTypeChoiceCount()) {
        return L"A";
    }
    return kDnsRecordTypeChoices[static_cast<std::size_t>(index)].label;
}

std::uint16_t DnsRecordTypeChoiceValue(const int index) {
    if (index < 0 || index >= DnsRecordTypeChoiceCount()) {
        return static_cast<std::uint16_t>(DNS_TYPE_A);
    }
    return static_cast<std::uint16_t>(kDnsRecordTypeChoices[static_cast<std::size_t>(index)].value);
}

DiagnosticResult RunDiagnostic(const DiagnosticRequest& request) {
    switch (request.kind) {
    case DiagnosticKind::Ping:
        return ks::r3::network::RunPing(request);
    case DiagnosticKind::TraceRoute:
        return RunTraceRoute(request);
    case DiagnosticKind::DnsLookup:
        return RunDnsLookup(request);
    }
    DiagnosticResult result{};
    result.text = L"未知的网络诊断类型。";
    result.summary = result.text;
    return result;
}

} // namespace Ksword::Features::NetTools
