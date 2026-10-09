#pragma once
#include <cstdint>
#include <string>
#include <vector>
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
    struct Probe {
        std::uint32_t sequence = 0, status = 0, roundTripMs = 0, ttl = 0, dataBytes = 0;
        std::wstring address;
        bool replied = false;
    };
    std::wstring resolvedAddress;
    std::uint32_t win32Error = 0, sent = 0, received = 0;
    std::vector<Probe> probes;
};
DiagnosticResult RunPing(const DiagnosticRequest& request);
DiagnosticResult RunTraceRoute(const DiagnosticRequest& request);
DiagnosticResult RunDnsLookup(const DiagnosticRequest& request);
}
