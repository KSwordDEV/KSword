#include "EndpointAudit.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <utility>
namespace ks::r3::network {
namespace {
constexpr ULONG kNetworkAfInet = 2UL;
EndpointAuditRow RowVec(std::vector<std::wstring> cells) {
    EndpointAuditRow row;
    row.cells = std::move(cells);
    return row;
}
std::wstring HexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}
struct IpHelperApi {
    using GetExtendedTcpTableFn = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
    using GetExtendedUdpTableFn = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG);
    using GetIfTableFn = DWORD(WINAPI*)(PMIB_IFTABLE, PULONG, BOOL);
    using GetIpAddrTableFn = DWORD(WINAPI*)(PMIB_IPADDRTABLE, PULONG, BOOL);
    using GetIpForwardTableFn = DWORD(WINAPI*)(PMIB_IPFORWARDTABLE, PULONG, BOOL);

    HMODULE module = nullptr;
    GetExtendedTcpTableFn getExtendedTcpTable = nullptr;
    GetExtendedUdpTableFn getExtendedUdpTable = nullptr;
    GetIfTableFn getIfTable = nullptr;
    GetIpAddrTableFn getIpAddrTable = nullptr;
    GetIpForwardTableFn getIpForwardTable = nullptr;
};
std::wstring Ipv4Text(const DWORD addr) {
    std::wostringstream stream;
    stream << static_cast<unsigned int>(addr & 0xFFU) << L'.'
           << static_cast<unsigned int>((addr >> 8U) & 0xFFU) << L'.'
           << static_cast<unsigned int>((addr >> 16U) & 0xFFU) << L'.'
           << static_cast<unsigned int>((addr >> 24U) & 0xFFU);
    return stream.str();
}
std::wstring NetworkPortText(const DWORD portValue) {
    const DWORD port = ((portValue & 0xFF00U) >> 8U) | ((portValue & 0x00FFU) << 8U);
    return std::to_wstring(port & 0xFFFFU);
}
std::wstring Win32StatusText(const wchar_t* apiName, const DWORD status) {
    std::wostringstream stream;
    stream << apiName << L" failed, status=" << status << L" (" << HexText(status) << L")";
    return stream.str();
}
bool LoadIpHelperApi(IpHelperApi& api, std::wstring& errorText) {
    api.module = ::LoadLibraryW(L"iphlpapi.dll");
    if (api.module == nullptr) {
        errorText = Win32StatusText(L"LoadLibrary(iphlpapi.dll)", ::GetLastError());
        return false;
    }

    auto resolve = [&api](const char* name) -> FARPROC {
        return ::GetProcAddress(api.module, name);
    };

    api.getExtendedTcpTable = reinterpret_cast<IpHelperApi::GetExtendedTcpTableFn>(resolve("GetExtendedTcpTable"));
    api.getExtendedUdpTable = reinterpret_cast<IpHelperApi::GetExtendedUdpTableFn>(resolve("GetExtendedUdpTable"));
    api.getIfTable = reinterpret_cast<IpHelperApi::GetIfTableFn>(resolve("GetIfTable"));
    api.getIpAddrTable = reinterpret_cast<IpHelperApi::GetIpAddrTableFn>(resolve("GetIpAddrTable"));
    api.getIpForwardTable = reinterpret_cast<IpHelperApi::GetIpForwardTableFn>(resolve("GetIpForwardTable"));

    if (api.getExtendedTcpTable == nullptr ||
        api.getExtendedUdpTable == nullptr ||
        api.getIfTable == nullptr ||
        api.getIpAddrTable == nullptr ||
        api.getIpForwardTable == nullptr) {
        errorText = L"iphlpapi.dll 缺少 Network 页所需的只读枚举入口。";
        ::FreeLibrary(api.module);
        api = {};
        return false;
    }
    return true;
}
void AppendTcpAfdProjectionRows(const IpHelperApi& api, std::vector<EndpointAuditRow>& rows, const std::size_t maxRows) {
    DWORD bufferSize = 0UL;
    DWORD status = api.getExtendedTcpTable(nullptr, &bufferSize, FALSE, kNetworkAfInet, TCP_TABLE_OWNER_PID_ALL, 0UL);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0UL) {
        rows.push_back(RowVec({ L"AFD/TCPv4", L"Unavailable", L"GetExtendedTcpTable", L"-", Win32StatusText(L"GetExtendedTcpTable(size)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    std::vector<unsigned char> buffer(bufferSize, 0U);
    status = api.getExtendedTcpTable(buffer.data(), &bufferSize, FALSE, kNetworkAfInet, TCP_TABLE_OWNER_PID_ALL, 0UL);
    if (status != ERROR_SUCCESS) {
        rows.push_back(RowVec({ L"AFD/TCPv4", L"Unavailable", L"GetExtendedTcpTable", L"-", Win32StatusText(L"GetExtendedTcpTable(data)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    rows.push_back(RowVec({ L"AFD/TCPv4", L"OK", L"GetExtendedTcpTable", L"Owner PID table", L"entries=" + std::to_wstring(table->dwNumEntries), L"R3 documented projection，可与 R0 TCP endpoint 交叉验证。" }));
    const std::size_t count = (std::min)(static_cast<std::size_t>(table->dwNumEntries), maxRows);
    for (std::size_t index = 0U; index < count; ++index) {
        const MIB_TCPROW_OWNER_PID& entry = table->table[index];
        rows.push_back(RowVec({
            L"TCP",
            L"state=" + std::to_wstring(entry.dwState),
            L"pid=" + std::to_wstring(entry.dwOwningPid),
            Ipv4Text(entry.dwLocalAddr) + L":" + NetworkPortText(entry.dwLocalPort),
            Ipv4Text(entry.dwRemoteAddr) + L":" + NetworkPortText(entry.dwRemotePort),
            L"AFD-facing R3 endpoint; no disconnect/no patch"
        }));
    }
}
void AppendUdpAfdProjectionRows(const IpHelperApi& api, std::vector<EndpointAuditRow>& rows, const std::size_t maxRows) {
    DWORD bufferSize = 0UL;
    DWORD status = api.getExtendedUdpTable(nullptr, &bufferSize, FALSE, kNetworkAfInet, UDP_TABLE_OWNER_PID, 0UL);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0UL) {
        rows.push_back(RowVec({ L"AFD/UDPv4", L"Unavailable", L"GetExtendedUdpTable", L"-", Win32StatusText(L"GetExtendedUdpTable(size)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    std::vector<unsigned char> buffer(bufferSize, 0U);
    status = api.getExtendedUdpTable(buffer.data(), &bufferSize, FALSE, kNetworkAfInet, UDP_TABLE_OWNER_PID, 0UL);
    if (status != ERROR_SUCCESS) {
        rows.push_back(RowVec({ L"AFD/UDPv4", L"Unavailable", L"GetExtendedUdpTable", L"-", Win32StatusText(L"GetExtendedUdpTable(data)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    rows.push_back(RowVec({ L"AFD/UDPv4", L"OK", L"GetExtendedUdpTable", L"Owner PID table", L"entries=" + std::to_wstring(table->dwNumEntries), L"R3 documented projection，可与 R0 UDP endpoint 交叉验证。" }));
    const std::size_t count = (std::min)(static_cast<std::size_t>(table->dwNumEntries), maxRows);
    for (std::size_t index = 0U; index < count; ++index) {
        const MIB_UDPROW_OWNER_PID& entry = table->table[index];
        rows.push_back(RowVec({
            L"UDP",
            L"listen",
            L"pid=" + std::to_wstring(entry.dwOwningPid),
            Ipv4Text(entry.dwLocalAddr) + L":" + NetworkPortText(entry.dwLocalPort),
            L"-",
            L"AFD-facing R3 endpoint; no disconnect/no patch"
        }));
    }
}
}
std::vector<EndpointAuditRow> BuildAfdRows() {
    std::vector<EndpointAuditRow> rows;
    IpHelperApi api;
    std::wstring errorText;
    if (!LoadIpHelperApi(api, errorText)) {
        rows.push_back(RowVec({ L"AFD endpoint", L"Unavailable", L"iphlpapi.dll", L"-", errorText, L"未新增 R0 协议；不猜 AFD 私有结构。" }));
        return rows;
    }

    AppendTcpAfdProjectionRows(api, rows, 128U);
    AppendUdpAfdProjectionRows(api, rows, 128U);
    rows.push_back(RowVec({ L"安全边界", L"只读", L"R3 documented API", L"TCP/UDP owner table", L"无 AFD IOCTL 时以公开端点表替代空占位。", L"不 detach/disable/bypass，不读取 AFD 私有对象。" }));
    ::FreeLibrary(api.module);
    return rows;
}
std::vector<EndpointAuditRow> BuildNsiRows() {
    std::vector<EndpointAuditRow> rows;
    IpHelperApi api;
    std::wstring errorText;
    if (!LoadIpHelperApi(api, errorText)) {
        rows.push_back(RowVec({ L"NSI summary", L"Unavailable", L"iphlpapi.dll", L"-", errorText, L"未新增 R0 协议；不猜 NSI 私有表。" }));
        return rows;
    }

    ULONG ifBytes = 0UL;
    DWORD status = api.getIfTable(nullptr, &ifBytes, FALSE);
    if (status == ERROR_INSUFFICIENT_BUFFER && ifBytes != 0UL) {
        std::vector<unsigned char> buffer(ifBytes, 0U);
        auto* ifTable = reinterpret_cast<PMIB_IFTABLE>(buffer.data());
        status = api.getIfTable(ifTable, &ifBytes, FALSE);
        if (status == NO_ERROR) {
            rows.push_back(RowVec({ L"Interface table", L"OK", L"GetIfTable", L"NETIO/NSI public projection", L"entries=" + std::to_wstring(ifTable->dwNumEntries), L"只读接口清单。" }));
            const DWORD count = (std::min)(ifTable->dwNumEntries, 64UL);
            for (DWORD index = 0UL; index < count; ++index) {
                const MIB_IFROW& entry = ifTable->table[index];
                rows.push_back(RowVec({
                    L"Interface",
                    L"ifType=" + std::to_wstring(entry.dwType),
                    L"ifIndex=" + std::to_wstring(entry.dwIndex),
                    std::wstring(entry.wszName),
                    L"mtu=" + std::to_wstring(entry.dwMtu) + L" speed=" + std::to_wstring(entry.dwSpeed),
                    L"documented IP Helper row"
                }));
            }
        }
        else {
            rows.push_back(RowVec({ L"Interface table", L"Unavailable", L"GetIfTable", L"-", Win32StatusText(L"GetIfTable(data)", status), L"只读失败。" }));
        }
    }
    else {
        rows.push_back(RowVec({ L"Interface table", L"Unavailable", L"GetIfTable", L"-", Win32StatusText(L"GetIfTable(size)", status), L"只读失败。" }));
    }

    ULONG addressBytes = 0UL;
    status = api.getIpAddrTable(nullptr, &addressBytes, FALSE);
    if (status == ERROR_INSUFFICIENT_BUFFER && addressBytes != 0UL) {
        std::vector<unsigned char> buffer(addressBytes, 0U);
        auto* addressTable = reinterpret_cast<PMIB_IPADDRTABLE>(buffer.data());
        status = api.getIpAddrTable(addressTable, &addressBytes, FALSE);
        if (status == NO_ERROR) {
            rows.push_back(RowVec({ L"IPv4 address table", L"OK", L"GetIpAddrTable", L"IPv4", L"entries=" + std::to_wstring(addressTable->dwNumEntries), L"只读地址摘要。" }));
        }
        else {
            rows.push_back(RowVec({ L"IPv4 address table", L"Unavailable", L"GetIpAddrTable", L"IPv4", Win32StatusText(L"GetIpAddrTable(data)", status), L"只读失败。" }));
        }
    }
    else {
        rows.push_back(RowVec({ L"IPv4 address table", L"Unavailable", L"GetIpAddrTable", L"IPv4", Win32StatusText(L"GetIpAddrTable(size)", status), L"只读失败。" }));
    }

    ULONG routeBytes = 0UL;
    status = api.getIpForwardTable(nullptr, &routeBytes, FALSE);
    if (status == ERROR_INSUFFICIENT_BUFFER && routeBytes != 0UL) {
        std::vector<unsigned char> buffer(routeBytes, 0U);
        auto* routeTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
        status = api.getIpForwardTable(routeTable, &routeBytes, FALSE);
        if (status == NO_ERROR) {
            rows.push_back(RowVec({ L"IPv4 route table", L"OK", L"GetIpForwardTable", L"IPv4", L"entries=" + std::to_wstring(routeTable->dwNumEntries), L"只读路由摘要。" }));
        }
        else {
            rows.push_back(RowVec({ L"IPv4 route table", L"Unavailable", L"GetIpForwardTable", L"IPv4", Win32StatusText(L"GetIpForwardTable(data)", status), L"只读失败。" }));
        }
    }
    else {
        rows.push_back(RowVec({ L"IPv4 route table", L"Unavailable", L"GetIpForwardTable", L"IPv4", Win32StatusText(L"GetIpForwardTable(size)", status), L"只读失败。" }));
    }

    rows.push_back(RowVec({ L"安全边界", L"只读", L"R3 documented API", L"IP Helper", L"无 NSI R0 IOCTL 时以公开 NETIO/NSI 投影替代空占位。", L"不读取 NSI 私有结构，不修改接口/路由。" }));
    ::FreeLibrary(api.module);
    return rows;
}
}
