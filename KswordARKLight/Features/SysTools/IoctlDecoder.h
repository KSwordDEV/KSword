#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace Ksword::Features::SysTools {

// IoctlDecodeState distinguishes an unfinished input from malformed text and a
// valid 32-bit CTL_CODE. It is value-only so the decoder can be tested without
// a window, driver, or device handle.
enum class IoctlDecodeState : std::uint8_t {
    Empty,
    Invalid,
    Valid
};

// IoctlDecodedFields is the complete static CTL_CODE bit projection. Every
// field is derived from code only; no kernel API or driver protocol is used.
struct IoctlDecodedFields {
    IoctlDecodeState state = IoctlDecodeState::Empty;
    std::uint32_t code = 0;
    std::uint16_t deviceType = 0;
    std::uint16_t function = 0;
    std::uint8_t access = 0;
    std::uint8_t method = 0;
    bool common = false;
    bool custom = false;
};

// DecodeIoctlCode accepts trimmed hexadecimal text with an optional 0x prefix.
// Input must contain one to eight hexadecimal digits; output is a complete
// static field projection or an explicit Empty/Invalid state.
IoctlDecodedFields DecodeIoctlCode(std::wstring_view input);

// IoctlAccessName and IoctlMethodName return the standard Windows CTL_CODE
// macro names for their two-bit fields. Inputs outside the valid range are
// masked to two bits for defensive display behavior.
const wchar_t* IoctlAccessName(std::uint8_t access);
const wchar_t* IoctlMethodName(std::uint8_t method);

// FormatIoctlCode normalizes a valid value as an eight-digit uppercase code.
// BuildIoctlDecodedReport returns a compact field/bit-layout report, or an
// empty string when the supplied result is not valid.
std::wstring FormatIoctlCode(std::uint32_t code);
std::wstring BuildIoctlDecodedReport(const IoctlDecodedFields& decoded);

} // namespace Ksword::Features::SysTools
