#include "Connections.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cstddef>
#include <unordered_map>
#include <utility>
#pragma comment(lib, "Iphlpapi.lib")
namespace ks::r3::network {
namespace {

// kTableRetryLimit bounds the size/read retry loop. The connection tables change
// between the sizing call and the read whenever anything on the machine opens a
// socket, so one retry is normal and an endless loop is not.
constexpr int kTableRetryLimit = 8;

using ProcessNameMap = std::unordered_map<std::uint32_t, std::wstring>;

// BuildProcessNameMap snapshots every process image name once per refresh.
// Opening each owner process individually would cost one handle per connection
// row and still fail for protected processes; the toolhelp snapshot names them
// all in a single pass without any access rights.
ProcessNameMap BuildProcessNameMap() {
    ProcessNameMap names;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return names;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (::Process32FirstW(snapshot, &entry)) {
        do {
            names.emplace(static_cast<std::uint32_t>(entry.th32ProcessID), entry.szExeFile);
        } while (::Process32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return names;
}

std::wstring ProcessNameFor(const ProcessNameMap& names, const std::uint32_t processId) {
    if (processId == 0) {
        return L"System Idle Process";
    }
    if (processId == 4) {
        return L"System";
    }
    const auto found = names.find(processId);
    return found == names.end() ? std::wstring{} : found->second;
}

// HostPort converts a table port field to host order. The tables report the port
// in network order inside a DWORD, so the upper half is padding and must not
// reach the conversion.
std::uint16_t HostPort(const DWORD tablePort) {
    return ::ntohs(static_cast<u_short>(tablePort & 0xFFFFu));
}

// FetchTable runs the two-call size/read protocol into a growable buffer. Input
// is a callable taking (buffer, &size); output is true when the final read
// succeeded, with the Win32 status left in lastError either way.
template <typename Fetch>
bool FetchTable(std::vector<unsigned char>& buffer, DWORD& lastError, Fetch fetch) {
    buffer.clear();
    DWORD size = 0;
    lastError = fetch(nullptr, &size);
    for (int attempt = 0; attempt < kTableRetryLimit && lastError == ERROR_INSUFFICIENT_BUFFER; ++attempt) {
        buffer.assign(static_cast<std::size_t>(size), 0);
        lastError = fetch(buffer.data(), &size);
    }
    if (lastError != NO_ERROR) {
        buffer.clear();
        return false;
    }
    return true;
}

void AppendDiagnostic(std::wstring& diagnostic, const wchar_t* tableName, const DWORD error) {
    if (!diagnostic.empty()) {
        diagnostic += L" ";
    }
    diagnostic += std::wstring(tableName) + L" 读取失败：" + FormatWin32Error(error) + L"。";
}

void CollectTcp4(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedTcpTable(target, size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv4 TCP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_TCPROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Tcp4;
        entry.localAddress = FormatIpv4Address(row.dwLocalAddr);
        entry.remoteAddress = FormatIpv4Address(row.dwRemoteAddr);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.remotePort = HostPort(row.dwRemotePort);
        entry.state = row.dwState;
        entry.hasState = true;
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entry.rawLocalAddress = row.dwLocalAddr;
        entry.rawRemoteAddress = row.dwRemoteAddr;
        entry.rawLocalPort = row.dwLocalPort;
        entry.rawRemotePort = row.dwRemotePort;
        entries.push_back(std::move(entry));
    }
}

void CollectTcp6(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedTcpTable(target, size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv6 TCP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_TCP6ROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Tcp6;
        entry.localAddress = FormatIpv6Address(row.ucLocalAddr, row.dwLocalScopeId);
        entry.remoteAddress = FormatIpv6Address(row.ucRemoteAddr, row.dwRemoteScopeId);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.remotePort = HostPort(row.dwRemotePort);
        entry.state = row.dwState;
        entry.hasState = true;
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entries.push_back(std::move(entry));
    }
}

void CollectUdp4(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedUdpTable(target, size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv4 UDP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_UDPROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Udp4;
        entry.localAddress = FormatIpv4Address(row.dwLocalAddr);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entry.rawLocalAddress = row.dwLocalAddr;
        entry.rawLocalPort = row.dwLocalPort;
        entries.push_back(std::move(entry));
    }
}

void CollectUdp6(std::vector<ConnectionEntry>& entries, const ProcessNameMap& names, std::wstring& diagnostic) {
    std::vector<unsigned char> buffer;
    DWORD error = NO_ERROR;
    if (!FetchTable(buffer, error, [](void* target, DWORD* size) {
            return ::GetExtendedUdpTable(target, size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        })) {
        AppendDiagnostic(diagnostic, L"IPv6 UDP 表", error);
        return;
    }
    if (buffer.empty()) {
        return;
    }
    const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const MIB_UDP6ROW_OWNER_PID& row = table->table[index];
        ConnectionEntry entry{};
        entry.protocol = ConnectionProtocol::Udp6;
        entry.localAddress = FormatIpv6Address(row.ucLocalAddr, row.dwLocalScopeId);
        entry.localPort = HostPort(row.dwLocalPort);
        entry.processId = row.dwOwningPid;
        entry.processName = ProcessNameFor(names, entry.processId);
        entries.push_back(std::move(entry));
    }
}

// ComHandle owns one COM interface pointer. It exists because the firewall walk
// has half a dozen early-exit paths and hand-written Release calls on each of
// them are exactly how leaks get in.

} // namespace

ConnectionEnumerationResult EnumerateConnections() {
    ConnectionEnumerationResult result{};
    EnsureWinsockInitialized();
    const ProcessNameMap names = BuildProcessNameMap();
    CollectTcp4(result.entries, names, result.diagnosticText);
    CollectTcp6(result.entries, names, result.diagnosticText);
    CollectUdp4(result.entries, names, result.diagnosticText);
    CollectUdp6(result.entries, names, result.diagnosticText);
    // Partial success is still success: the diagnostic names whichever table was
    // unreadable, and the rows that were read remain useful on their own.
    result.success = !result.entries.empty() || result.diagnosticText.empty();
    return result;
}
namespace {

std::wstring DescribeEntry(const ConnectionEntry& entry) {
    return entry.localAddress + L":" + std::to_wstring(entry.localPort) + L" -> " +
        entry.remoteAddress + L":" + std::to_wstring(entry.remotePort);
}

} // namespace

NetToolsActionResult CloseTcpConnection(const ConnectionEntry& entry) {
    NetToolsActionResult result{};
    if (!ConnectionCanClose(entry)) {
        result.message = L"该连接不支持结束：SetTcpEntry 只能删除 IPv4 TCP 已连接状态的 TCB。";
        return result;
    }

    MIB_TCPROW row{};
    // The tuple is copied back exactly as the table reported it. Re-deriving the
    // addresses from the display text would go through two conversions and any
    // rounding of a scope or a leading zero would silently target a different
    // connection than the one on screen.
    row.dwState = MIB_TCP_STATE_DELETE_TCB;
    row.dwLocalAddr = static_cast<DWORD>(entry.rawLocalAddress);
    row.dwLocalPort = static_cast<DWORD>(entry.rawLocalPort);
    row.dwRemoteAddr = static_cast<DWORD>(entry.rawRemoteAddress);
    row.dwRemotePort = static_cast<DWORD>(entry.rawRemotePort);

    const DWORD status = ::SetTcpEntry(&row);
    if (status == NO_ERROR) {
        result.success = true;
        result.message = L"已结束连接 " + DescribeEntry(entry) + L"。";
        return result;
    }
    if (status == ERROR_ACCESS_DENIED) {
        result.message = L"结束连接 " + DescribeEntry(entry) +
            L" 失败：需要管理员权限，请以管理员身份重新运行。";
        return result;
    }
    if (status == ERROR_MR_MID_NOT_FOUND) {
        // The stack returns this when the tuple no longer matches a live TCB,
        // which usually means the connection already closed between the snapshot
        // and the click rather than that anything went wrong.
        result.message = L"结束连接 " + DescribeEntry(entry) +
            L" 失败：该连接已不存在，请刷新后重试。";
        return result;
    }
    result.message = L"结束连接 " + DescribeEntry(entry) + L" 失败：" + FormatWin32Error(status) + L"。";
    return result;
}


bool ConnectionCanClose(const ConnectionEntry& entry) {
    if (entry.protocol != ConnectionProtocol::Tcp4 || !entry.hasState) {
        return false;
    }
    // SYN_SENT through TIME_WAIT are the states that own a TCB worth deleting.
    // CLOSED and LISTEN sit outside that window, and DELETE_TCB means the stack
    // is already tearing the entry down.
    return entry.state >= MIB_TCP_STATE_SYN_SENT && entry.state <= MIB_TCP_STATE_TIME_WAIT;
}
bool ConnectionIsEstablished(const ConnectionEntry& entry) {
    return entry.hasState && entry.state == MIB_TCP_STATE_ESTAB;
}
bool ConnectionIsListening(const ConnectionEntry& entry) {
    return entry.hasState && entry.state == MIB_TCP_STATE_LISTEN;
}
}
