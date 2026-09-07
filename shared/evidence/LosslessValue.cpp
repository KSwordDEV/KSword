#include "LosslessValue.h"

#include <limits>

namespace Ksword::Evidence {
namespace {

constexpr char kHexDigits[] = "0123456789ABCDEF";

bool HexDigitValue(char c, std::uint32_t& out) noexcept {
    if (c >= '0' && c <= '9') {
        out = static_cast<std::uint32_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        out = static_cast<std::uint32_t>(c - 'a') + 10U;
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        out = static_cast<std::uint32_t>(c - 'A') + 10U;
        return true;
    }
    return false;
}

bool ParseHexBody(std::string_view text, std::uint64_t& out) noexcept {
    if (text.empty() || text.size() > 16U) {
        return false;
    }
    std::uint64_t value = 0U;
    for (const char c : text) {
        std::uint32_t digit = 0U;
        if (!HexDigitValue(c, digit)) {
            return false;
        }
        value = (value << 4U) | digit;
    }
    out = value;
    return true;
}

bool ParseDecimalBody(std::string_view text, std::uint64_t& out) noexcept {
    if (text.empty()) {
        return false;
    }
    constexpr std::uint64_t kMax = (std::numeric_limits<std::uint64_t>::max)();
    std::uint64_t value = 0U;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (kMax - digit) / 10U) {
            return false; // 溢出：拒绝，不截断
        }
        value = value * 10U + digit;
    }
    out = value;
    return true;
}

} // namespace

std::string FormatU64(std::uint64_t value, U64Format format) {
    if (format == U64Format::HexAddress) {
        std::string text(18U, '0');
        text[0] = '0';
        text[1] = 'x';
        for (std::size_t i = 0U; i < 16U; ++i) {
            const std::uint32_t shift = static_cast<std::uint32_t>((15U - i) * 4U);
            text[2U + i] = kHexDigits[(value >> shift) & 0xFULL];
        }
        return text;
    }

    if (value == 0U) {
        return std::string("0");
    }
    char buffer[20];
    std::size_t length = 0U;
    while (value != 0U) {
        buffer[length++] = static_cast<char>('0' + static_cast<char>(value % 10U));
        value /= 10U;
    }
    std::string text;
    text.reserve(length);
    for (std::size_t i = length; i > 0U; --i) {
        text.push_back(buffer[i - 1U]);
    }
    return text;
}

std::string FormatOptionalU64(const OptionalU64& value, U64Format format) {
    if (!value.present) {
        return std::string();
    }
    return FormatU64(value.value, format);
}

bool ParseU64(std::string_view text, std::uint64_t& out) noexcept {
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        return ParseHexBody(text.substr(2U), out);
    }
    return ParseDecimalBody(text, out);
}

bool ParseOptionalU64(std::string_view text, OptionalU64& out) noexcept {
    if (text.empty()) {
        out = OptionalU64::unset();
        return true;
    }
    std::uint64_t value = 0U;
    if (!ParseU64(text, value)) {
        return false;
    }
    out = OptionalU64::of(value);
    return true;
}

std::string FormatI64(std::int64_t value) {
    if (value < 0) {
        // 先转成无符号再取反，避免 INT64_MIN 取负的未定义行为。
        const std::uint64_t magnitude = ~static_cast<std::uint64_t>(value) + 1ULL;
        return std::string("-") + FormatU64(magnitude, U64Format::Decimal);
    }
    return FormatU64(static_cast<std::uint64_t>(value), U64Format::Decimal);
}

bool ParseI64(std::string_view text, std::int64_t& out) noexcept {
    if (text.empty()) {
        return false;
    }
    const bool negative = text[0] == '-';
    const std::string_view body = negative ? text.substr(1U) : text;
    std::uint64_t magnitude = 0U;
    if (!ParseDecimalBody(body, magnitude)) {
        return false;
    }
    constexpr std::uint64_t kPositiveMax =
        static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    if (negative) {
        if (magnitude > kPositiveMax + 1ULL) {
            return false;
        }
        if (magnitude == kPositiveMax + 1ULL) {
            out = (std::numeric_limits<std::int64_t>::min)();
            return true;
        }
        out = -static_cast<std::int64_t>(magnitude);
        return true;
    }
    if (magnitude > kPositiveMax) {
        return false;
    }
    out = static_cast<std::int64_t>(magnitude);
    return true;
}

} // namespace Ksword::Evidence
