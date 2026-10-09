#include "DriverFormatting.h"
#include <algorithm>
#include <array>
#include <cwctype>
#include <iomanip>
#include <sstream>
namespace ks::r3::driver {
std::wstring FormatHexAddress(const std::uint64_t value, const std::size_t width) {
    std::wostringstream out;
    out << L"0x" << std::uppercase << std::hex << std::setw(static_cast<int>(width)) << std::setfill(L'0') << value;
    return out.str();
}
std::wstring FormatByteSize(const std::uint64_t bytes) {
    constexpr std::uint64_t kKiB = 1024ULL;
    constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
    constexpr std::uint64_t kGiB = 1024ULL * 1024ULL * 1024ULL;

    std::wostringstream out;
    out << std::fixed << std::setprecision(1);
    if (bytes >= kGiB) {
        out << (static_cast<long double>(bytes) / kGiB) << L" GiB";
    } else if (bytes >= kMiB) {
        out << (static_cast<long double>(bytes) / kMiB) << L" MiB";
    } else if (bytes >= kKiB) {
        out << (static_cast<long double>(bytes) / kKiB) << L" KiB";
    } else {
        out.unsetf(std::ios::floatfield);
        out << bytes << L" B";
    }
    return out.str();
}
}
