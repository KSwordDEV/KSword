#pragma once
#include "NetworkSupport.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::network {
enum class ConnectionProtocol {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6
};

struct ConnectionEntry {
    ConnectionProtocol protocol = ConnectionProtocol::Tcp4;
    std::wstring localAddress;
    std::wstring remoteAddress;
    std::uint16_t localPort = 0;
    std::uint16_t remotePort = 0;
    std::uint32_t state = 0;            // MIB_TCP_STATE_*, meaningless for UDP.
    bool hasState = false;              // UDP endpoints carry no connection state.
    std::uint32_t processId = 0;
    std::wstring processName;           // Empty when the owner could not be named.
    std::uint32_t rawLocalAddress = 0;  // IPv4 only, network byte order.
    std::uint32_t rawRemoteAddress = 0; // IPv4 only, network byte order.
    std::uint32_t rawLocalPort = 0;     // Table-reported port DWORD, unmodified.
    std::uint32_t rawRemotePort = 0;    // Table-reported port DWORD, unmodified.
};

struct ConnectionEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<ConnectionEntry> entries;
};

struct NetToolsActionResult {
    bool success = false;
    std::wstring message;
};
ConnectionEnumerationResult EnumerateConnections();
NetToolsActionResult CloseTcpConnection(const ConnectionEntry& entry);
bool ConnectionCanClose(const ConnectionEntry& entry);
bool ConnectionIsEstablished(const ConnectionEntry& entry);
bool ConnectionIsListening(const ConnectionEntry& entry);
}
