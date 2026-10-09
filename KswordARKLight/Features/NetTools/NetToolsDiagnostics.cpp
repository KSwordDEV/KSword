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
        return ks::r3::network::RunTraceRoute(request);
    case DiagnosticKind::DnsLookup:
        return RunDnsLookup(request);
    }
    DiagnosticResult result{};
    result.text = L"未知的网络诊断类型。";
    result.summary = result.text;
    return result;
}

} // namespace Ksword::Features::NetTools
