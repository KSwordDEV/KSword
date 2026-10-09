#include "../shared/usermode/backend/network/Firewall.h"
#include "../shared/usermode/backend/network/Diagnostics.h"
#include "../shared/usermode/backend/network/Connections.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "TestSupport.h"
#include <algorithm>

int RunR3NetworkBackendTests() {
    using namespace ks::r3::network;
    KswordTests::Suite suite(L"R3 network backend");
    ConnectionEntry entry{};
    entry.hasState = true;
    entry.state = MIB_TCP_STATE_ESTAB;
    suite.expect(ConnectionCanClose(entry), L"IPv4 established TCP is closable");
    suite.expect(ConnectionIsEstablished(entry), L"established state is preserved");
    entry.protocol = ConnectionProtocol::Tcp6;
    suite.expect(!ConnectionCanClose(entry), L"IPv6 cannot enter SetTcpEntry");
    entry.protocol = ConnectionProtocol::Udp4;
    const auto rejected = CloseTcpConnection(entry);
    suite.expect(!rejected.success && rejected.message == L"该连接不支持结束：SetTcpEntry 只能删除 IPv4 TCP 已连接状态的 TCB。", L"UDP rejection preserves the original text");
    entry.protocol = ConnectionProtocol::Tcp4;
    entry.state = MIB_TCP_STATE_LISTEN;
    suite.expect(!ConnectionCanClose(entry) && ConnectionIsListening(entry), L"listeners remain read-only");
    entry.state = MIB_TCP_STATE_CLOSED;
    suite.expect(!ConnectionCanClose(entry), L"closed rows cannot be deleted");
    entry.state = MIB_TCP_STATE_DELETE_TCB;
    suite.expect(!ConnectionCanClose(entry), L"already deleting rows cannot be deleted");
    entry.state = MIB_TCP_STATE_TIME_WAIT;
    suite.expect(ConnectionCanClose(entry), L"last original closable state is preserved");
    entry.hasState = false;
    suite.expect(!ConnectionCanClose(entry) && !ConnectionIsEstablished(entry), L"unknown state is not treated as established");
    const std::uint8_t ipv6[16] = {0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    suite.expect(FormatIpv6Address(ipv6, 7) == L"fe80::1%7", L"IPv6 scope identity is preserved");
    suite.expect(FormatIpv6Address(nullptr, 0) == L"::", L"missing IPv6 address retains placeholder");
    EnsureWinsockInitialized();
    const SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    suite.expect(listener != INVALID_SOCKET, L"own loopback listener created");
    if (listener != INVALID_SOCKET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
        const bool listening = ::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && ::listen(listener, 1) == 0;
        suite.expect(listening, L"own loopback listener bound");
        int length = sizeof(address);
        const bool named = ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0;
        suite.expect(named, L"own endpoint identity captured");
        const auto snapshot = EnumerateConnections();
        const auto found = std::find_if(snapshot.entries.begin(), snapshot.entries.end(), [&](const ConnectionEntry& row) {
            return row.protocol == ConnectionProtocol::Tcp4 && row.processId == ::GetCurrentProcessId() && row.localPort == ::ntohs(address.sin_port);
        });
        suite.expect(snapshot.success && found != snapshot.entries.end(), L"real enumeration returns own endpoint");
        if (found != snapshot.entries.end()) {
            suite.expect(found->rawLocalAddress == address.sin_addr.s_addr && found->rawLocalPort == address.sin_port, L"raw table tuple remains byte-exact");
        }
        ::closesocket(listener);
    }
    const auto pingEmpty = RunPing(DiagnosticRequest{});
    suite.expect(!pingEmpty.success && pingEmpty.text == L"请先填写目标主机名或 IP 地址。", L"empty ping input preserves original failure");
    suite.expect(pingEmpty.summary == L"Ping 未执行：目标解析失败。", L"ping failure summary preserved");
    const auto traceEmpty = RunTraceRoute(DiagnosticRequest{});
    suite.expect(!traceEmpty.success && traceEmpty.summary == L"路由跟踪未执行：目标解析失败。", L"trace failure semantics preserved");
    const auto dnsEmpty = RunDnsLookup(DiagnosticRequest{});
    suite.expect(!dnsEmpty.success && !dnsEmpty.text.empty(), L"DNS empty input retains failure result");
    suite.report();
    return suite.failures();
}
