#pragma once
#include "Diagnostics.h"
#include "NetworkSupport.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <algorithm>
#include <cstdio>
#include <iterator>
#include <limits>
#include <vector>
namespace ks::r3::network::detail {


// kEchoPayloadSize matches what the Windows ping tool sends. Keeping it identical
// means a result from this page can be compared with one from a console session
// without wondering whether the payload size changed the path MTU behaviour.
constexpr WORD kEchoPayloadSize = 32;

// kReplySlack covers the ICMP error message the stack may append after the reply
// structure. IcmpSendEcho2 rejects a buffer that has no room for it, and the
// documented minimum is 8 bytes; the extra room here costs nothing.
constexpr std::size_t kReplySlack = 64;

constexpr std::uint32_t kMaxEchoCount = 32;
constexpr std::uint32_t kMaxHopCount = 64;

inline void AppendLine(std::wstring& text, const std::wstring& line) {
    text += line;
    text += L"\r\n";
}

inline std::wstring FormatMilliseconds(const std::uint32_t value) {
    return value == 0 ? std::wstring(L"<1 ms") : std::to_wstring(value) + L" ms";
}

// IcmpStatusText turns an IP_STATUS into wording an operator can act on. The raw
// codes are not in the system message table, so FormatMessage would only produce
// "unknown error" for the interesting half of them.
inline std::wstring IcmpStatusText(const ULONG status) {
    switch (status) {
    case IP_SUCCESS: return L"成功";
    case IP_BUF_TOO_SMALL: return L"回复缓冲区太小";
    case IP_DEST_NET_UNREACHABLE: return L"目标网络不可达";
    case IP_DEST_HOST_UNREACHABLE: return L"目标主机不可达";
    case IP_DEST_PROT_UNREACHABLE: return L"目标协议不可达";
    case IP_DEST_PORT_UNREACHABLE: return L"目标端口不可达";
    case IP_NO_RESOURCES: return L"IP 资源不足";
    case IP_BAD_OPTION: return L"IP 选项无效";
    case IP_HW_ERROR: return L"硬件错误";
    case IP_PACKET_TOO_BIG: return L"数据包过大";
    case IP_REQ_TIMED_OUT: return L"请求超时";
    case IP_BAD_REQ: return L"请求无效";
    case IP_BAD_ROUTE: return L"路由无效";
    case IP_TTL_EXPIRED_TRANSIT: return L"传输中 TTL 过期";
    case IP_TTL_EXPIRED_REASSEM: return L"重组时 TTL 过期";
    case IP_PARAM_PROBLEM: return L"参数错误";
    case IP_SOURCE_QUENCH: return L"源抑制";
    case IP_OPTION_TOO_BIG: return L"IP 选项过长";
    case IP_BAD_DESTINATION: return L"目标地址无效";
    case IP_GENERAL_FAILURE: return L"常规故障";
    default: break;
    }
    return L"ICMP 状态 " + std::to_wstring(status);
}

struct ResolvedTarget final {
    bool resolved = false;
    std::uint32_t address = 0;    // Network byte order.
    std::wstring addressText;
    std::wstring diagnostic;
    std::uint32_t error = 0;
};

// ResolveIpv4 turns a host name or literal into one IPv4 address. Input is the
// user's text; processing asks the resolver for AF_INET only; output carries the
// first answer, because an operator asking to ping a name wants the address the
// system itself would use and that is the first one the resolver ranks.
inline ResolvedTarget ResolveIpv4(const std::wstring& target) {
    ResolvedTarget resolved{};
    if (target.empty()) {
        resolved.error = ERROR_INVALID_PARAMETER;
        resolved.diagnostic = L"请先填写目标主机名或 IP 地址。";
        return resolved;
    }

    EnsureWinsockInitialized();
    ADDRINFOW hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOW info = nullptr;
    const int status = ::GetAddrInfoW(target.c_str(), nullptr, &hints, &info);
    if (status != 0 || info == nullptr) {
        resolved.error = status != 0 ? static_cast<std::uint32_t>(status) : WSAHOST_NOT_FOUND;
        if (info != nullptr) {
            ::FreeAddrInfoW(info);
        }
        resolved.diagnostic = L"无法解析目标 " + target + L" 的 IPv4 地址：" +
            FormatWin32Error(static_cast<std::uint32_t>(status)) +
            L"。该目标可能只提供 IPv6 地址，本页的 ICMP 探测仅支持 IPv4。";
        return resolved;
    }

    for (const ADDRINFOW* cursor = info; cursor != nullptr; cursor = cursor->ai_next) {
        if (cursor->ai_family != AF_INET || cursor->ai_addr == nullptr ||
            cursor->ai_addrlen < sizeof(sockaddr_in)) {
            continue;
        }
        const auto* address = reinterpret_cast<const sockaddr_in*>(cursor->ai_addr);
        resolved.address = static_cast<std::uint32_t>(address->sin_addr.S_un.S_addr);
        resolved.addressText = FormatIpv4Address(resolved.address);
        resolved.resolved = true;
        break;
    }
    ::FreeAddrInfoW(info);
    if (!resolved.resolved) {
        resolved.error = WSAEAFNOSUPPORT;
        resolved.diagnostic = L"目标 " + target + L" 没有可用的 IPv4 地址。";
    }
    return resolved;
}

// IcmpSession owns the ICMP handle for one probe run. Both ping and traceroute
// have several early exits and the handle has to be closed on all of them.
class IcmpSession final {
public:
    IcmpSession() : handle_(::IcmpCreateFile()) {
    }

    ~IcmpSession() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            ::IcmpCloseHandle(handle_);
        }
    }

    IcmpSession(const IcmpSession&) = delete;
    IcmpSession& operator=(const IcmpSession&) = delete;

    bool valid() const noexcept {
        return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr;
    }

    HANDLE get() const noexcept {
        return handle_;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};


}
