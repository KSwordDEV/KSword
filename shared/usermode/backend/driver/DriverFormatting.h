#pragma once
#include "../Common.h"
#include "DriverTypes.h"
namespace ks::r3::driver {
std::wstring FormatHexAddress(const std::uint64_t value, const std::size_t width);
std::wstring FormatByteSize(const std::uint64_t bytes);
}
