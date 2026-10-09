#include "HardwareStatsTypes.h"

#include <cmath>
#include <cstdio>

namespace ks::r3::hardware_stats {
namespace {

constexpr double kKibi = 1024.0;

// IsUsable rejects the values PDH produces for a counter that has not settled.
// A NaN or infinity rendered through swprintf_s becomes "nan"/"inf" in the
// table, which reads like a real measurement instead of a missing one.
bool IsUsable(double value) {
    return std::isfinite(value);
}

} // namespace

std::wstring FormatByteSize(const double bytes) {
    if (!IsUsable(bytes)) {
        return L"—";
    }
    const double magnitude = bytes < 0.0 ? -bytes : bytes;
    const wchar_t* unit = L"B";
    double scaled = bytes;
    if (magnitude >= kKibi * kKibi * kKibi * kKibi) {
        scaled = bytes / (kKibi * kKibi * kKibi * kKibi);
        unit = L"TiB";
    } else if (magnitude >= kKibi * kKibi * kKibi) {
        scaled = bytes / (kKibi * kKibi * kKibi);
        unit = L"GiB";
    } else if (magnitude >= kKibi * kKibi) {
        scaled = bytes / (kKibi * kKibi);
        unit = L"MiB";
    } else if (magnitude >= kKibi) {
        scaled = bytes / kKibi;
        unit = L"KiB";
    } else {
        wchar_t whole[64] = {};
        swprintf_s(whole, L"%.0f B", bytes);
        return std::wstring(whole);
    }

    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.2f %s", scaled, unit);
    return std::wstring(buffer);
}

std::wstring FormatByteRate(const double bytesPerSecond) {
    if (!IsUsable(bytesPerSecond)) {
        return L"—";
    }
    return FormatByteSize(bytesPerSecond) + L"/s";
}

std::wstring FormatPercent(const double value) {
    if (!IsUsable(value)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.1f %%", value);
    return std::wstring(buffer);
}

std::wstring FormatRate(const double perSecond) {
    if (!IsUsable(perSecond)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.1f /s", perSecond);
    return std::wstring(buffer);
}

std::wstring FormatCount(const double value) {
    if (!IsUsable(value)) {
        return L"—";
    }

    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.0f", value);
    std::wstring digits(buffer);
    const bool negative = !digits.empty() && digits.front() == L'-';
    if (negative) {
        digits.erase(digits.begin());
    }

    std::wstring grouped;
    grouped.reserve(digits.size() + digits.size() / 3 + 1);
    // The first group is whatever is left over above a multiple of three, and a
    // separator is only due once that group has been emitted. The index >= leading
    // guard is what keeps the unsigned subtraction from wrapping on short numbers,
    // which would otherwise put a separator inside a two-digit value.
    const std::size_t leading = digits.size() % 3 == 0 ? 3 : digits.size() % 3;
    for (std::size_t index = 0; index < digits.size(); ++index) {
        if (index >= leading && (index - leading) % 3 == 0) {
            grouped += L',';
        }
        grouped += digits[index];
    }
    return negative ? L"-" + grouped : grouped;
}

std::wstring FormatDecimal(const double value) {
    if (!IsUsable(value)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.2f", value);
    return std::wstring(buffer);
}

std::wstring FormatLatency(const double seconds) {
    if (!IsUsable(seconds)) {
        return L"—";
    }
    wchar_t buffer[64] = {};
    swprintf_s(buffer, L"%.2f ms", seconds * 1000.0);
    return std::wstring(buffer);
}

std::wstring FormatUpTime(const double seconds) {
    if (!IsUsable(seconds) || seconds < 0.0) {
        return L"—";
    }
    const unsigned long long total = static_cast<unsigned long long>(seconds);
    const unsigned long long days = total / 86400ULL;
    const unsigned long long hours = (total % 86400ULL) / 3600ULL;
    const unsigned long long minutes = (total % 3600ULL) / 60ULL;
    const unsigned long long remainder = total % 60ULL;

    wchar_t buffer[96] = {};
    if (days > 0) {
        swprintf_s(buffer, L"%llu 天 %llu 小时 %llu 分", days, hours, minutes);
    } else if (hours > 0) {
        swprintf_s(buffer, L"%llu 小时 %llu 分 %llu 秒", hours, minutes, remainder);
    } else {
        swprintf_s(buffer, L"%llu 分 %llu 秒", minutes, remainder);
    }
    return std::wstring(buffer);
}

std::wstring UsbNodeKindText(const UsbNodeKind kind) {
    switch (kind) {
    case UsbNodeKind::HostController:
        return L"主控制器";
    case UsbNodeKind::Hub:
        return L"集线器";
    case UsbNodeKind::Device:
    default:
        return L"设备";
    }
}

std::wstring IndentedName(const std::wstring& name, const int depth) {
    // The indent is capped because a malformed parent chain would otherwise push
    // the name off the right edge of the column and hide it entirely.
    const int levels = depth < 0 ? 0 : (depth > 16 ? 16 : depth);
    if (levels == 0) {
        return name;
    }
    std::wstring prefix;
    prefix.reserve(static_cast<std::size_t>(levels) * 4);
    for (int level = 0; level < levels - 1; ++level) {
        prefix += L"    ";
    }
    prefix += L"└─ ";
    return prefix + name;
}

} // namespace ks::r3::hardware_stats
