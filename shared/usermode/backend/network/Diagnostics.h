#pragma once
#include <cstdint>
#include <string>
namespace ks::r3::network {
enum class DiagnosticKind {
    Ping,
    TraceRoute,
    DnsLookup
};

struct DiagnosticRequest {
    DiagnosticKind kind = DiagnosticKind::Ping;
    std::wstring target;
    std::uint16_t dnsRecordType = 0;      // DNS_TYPE_*, only read for DnsLookup.
    std::uint32_t echoCount = 4;          // Ping only.
    std::uint32_t maxHops = 30;           // TraceRoute only.
    std::uint32_t timeoutMs = 2000;       // Per probe.
};

struct DiagnosticResult {
    bool success = false;
    std::wstring text;
    std::wstring summary;
};
DiagnosticResult RunPing(const DiagnosticRequest& request);
DiagnosticResult RunTraceRoute(const DiagnosticRequest& request);
DiagnosticResult RunDnsLookup(const DiagnosticRequest& request);
}
