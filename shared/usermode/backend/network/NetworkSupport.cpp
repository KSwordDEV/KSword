#include "NetworkSupport.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <iterator>
#include <mutex>
#pragma comment(lib, "Ws2_32.lib")
namespace ks::r3::network {
void EnsureWinsockInitialized() {
    // A function-local static is the guard here because this is reached from the
    // async worker threads of three separate tabs at once, and WSAStartup is only
    // reference-counted, not race-free against a first-ever call.
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA data{};
        (void)::WSAStartup(MAKEWORD(2, 2), &data);
    });
}

std::wstring FormatIpv4Address(const std::uint32_t networkOrderAddress) {
    EnsureWinsockInitialized();
    IN_ADDR address{};
    address.S_un.S_addr = static_cast<ULONG>(networkOrderAddress);
    wchar_t buffer[INET_ADDRSTRLEN + 1]{};
    if (::InetNtopW(AF_INET, &address, buffer, std::size(buffer)) == nullptr) {
        return L"0.0.0.0";
    }
    return buffer;
}

std::wstring FormatIpv6Address(const std::uint8_t* address, const std::uint32_t scopeId) {
    if (address == nullptr) {
        return L"::";
    }
    EnsureWinsockInitialized();
    IN6_ADDR value{};
    std::copy_n(address, sizeof(value.u.Byte), value.u.Byte);
    wchar_t buffer[INET6_ADDRSTRLEN + 1]{};
    if (::InetNtopW(AF_INET6, &value, buffer, std::size(buffer)) == nullptr) {
        return L"::";
    }
    std::wstring text = buffer;
    // The scope id is not cosmetic for link-local addresses: fe80::1 on two
    // different interfaces are two different endpoints.
    if (scopeId != 0) {
        text += L"%" + std::to_wstring(scopeId);
    }
    return text;
}

std::wstring FormatWin32Error(const std::uint32_t code) {
    LPWSTR text = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&text),
        0,
        nullptr);
    std::wstring message;
    if (length != 0 && text != nullptr) {
        message.assign(text, length);
    }
    if (text != nullptr) {
        ::LocalFree(text);
    }
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
        message.pop_back();
    }
    if (message.empty()) {
        return L"错误码 " + std::to_wstring(code);
    }
    return message + L"（错误码 " + std::to_wstring(code) + L"）";
}
}
