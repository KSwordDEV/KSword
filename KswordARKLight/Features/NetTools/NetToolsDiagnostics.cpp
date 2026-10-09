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








// DnsRecordValueText renders one answer. Only the record types the combo offers
// are decoded; anything else still shows up as a row with its type and TTL so an
// unexpected answer in an ANY query is visible rather than dropped.




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
        return ks::r3::network::RunDnsLookup(request);
    }
    DiagnosticResult result{};
    result.text = L"未知的网络诊断类型。";
    result.summary = result.text;
    return result;
}

} // namespace Ksword::Features::NetTools
