#pragma once
#include <cstdint>
#include <string>
namespace ks::r3::network {
void EnsureWinsockInitialized();
std::wstring FormatIpv4Address(std::uint32_t address);
std::wstring FormatIpv6Address(const std::uint8_t* address, std::uint32_t scopeId);
std::wstring FormatWin32Error(std::uint32_t code);
}
