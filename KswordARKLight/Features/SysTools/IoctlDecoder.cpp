#include "IoctlDecoder.h"

#include <cwchar>
#include <cwctype>
#include <sstream>

namespace Ksword::Features::SysTools {
namespace {

std::wstring_view Trim(std::wstring_view value) {
    while (!value.empty() && std::iswspace(static_cast<wint_t>(value.front())) != 0) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::iswspace(static_cast<wint_t>(value.back())) != 0) {
        value.remove_suffix(1);
    }
    return value;
}

int HexDigit(const wchar_t character) {
    if (character >= L'0' && character <= L'9') {
        return character - L'0';
    }
    if (character >= L'a' && character <= L'f') {
        return character - L'a' + 10;
    }
    if (character >= L'A' && character <= L'F') {
        return character - L'A' + 10;
    }
    return -1;
}

std::wstring FormatField(const std::uint32_t value, const int hexDigits) {
    wchar_t buffer[64] = {};
    const int written = std::swprintf(buffer,
        sizeof(buffer) / sizeof(buffer[0]),
        L"0x%0*X (%u)",
        hexDigits,
        value,
        value);
    return written > 0 ? std::wstring(buffer, static_cast<std::size_t>(written)) : std::wstring{};
}

} // namespace

IoctlDecodedFields DecodeIoctlCode(std::wstring_view input) {
    IoctlDecodedFields decoded{};
    input = Trim(input);
    if (input.empty()) {
        return decoded;
    }
    if (input.size() >= 2U && input[0] == L'0' && (input[1] == L'x' || input[1] == L'X')) {
        input.remove_prefix(2U);
    }
    if (input.empty() || input.size() > 8U) {
        decoded.state = IoctlDecodeState::Invalid;
        return decoded;
    }

    std::uint32_t code = 0;
    for (const wchar_t character : input) {
        const int digit = HexDigit(character);
        if (digit < 0) {
            decoded.state = IoctlDecodeState::Invalid;
            return decoded;
        }
        code = static_cast<std::uint32_t>((code << 4U) | static_cast<std::uint32_t>(digit));
    }

    decoded.state = IoctlDecodeState::Valid;
    decoded.code = code;
    decoded.deviceType = static_cast<std::uint16_t>((code >> 16U) & 0xFFFFU);
    decoded.access = static_cast<std::uint8_t>((code >> 14U) & 0x3U);
    decoded.custom = (code & 0x2000U) != 0U;
    decoded.function = static_cast<std::uint16_t>((code >> 2U) & 0x0FFFU);
    decoded.method = static_cast<std::uint8_t>(code & 0x3U);
    decoded.common = (code & 0x80000000U) != 0U;
    return decoded;
}

const wchar_t* IoctlAccessName(const std::uint8_t access) {
    switch (access & 0x3U) {
    case 0U: return L"FILE_ANY_ACCESS";
    case 1U: return L"FILE_READ_ACCESS";
    case 2U: return L"FILE_WRITE_ACCESS";
    case 3U: return L"FILE_READ_ACCESS | FILE_WRITE_ACCESS";
    default: return L"FILE_ANY_ACCESS";
    }
}

const wchar_t* IoctlMethodName(const std::uint8_t method) {
    switch (method & 0x3U) {
    case 0U: return L"METHOD_BUFFERED";
    case 1U: return L"METHOD_IN_DIRECT";
    case 2U: return L"METHOD_OUT_DIRECT";
    case 3U: return L"METHOD_NEITHER";
    default: return L"METHOD_BUFFERED";
    }
}

std::wstring FormatIoctlCode(const std::uint32_t code) {
    wchar_t buffer[16] = {};
    const int written = std::swprintf(buffer,
        sizeof(buffer) / sizeof(buffer[0]),
        L"0x%08X",
        code);
    return written > 0 ? std::wstring(buffer, static_cast<std::size_t>(written)) : std::wstring{};
}

std::wstring BuildIoctlDecodedReport(const IoctlDecodedFields& decoded) {
    if (decoded.state != IoctlDecodeState::Valid) {
        return {};
    }
    std::wostringstream report;
    report << L"IOCTL: " << FormatIoctlCode(decoded.code) << L"\r\n\r\n"
           << L"Device: " << FormatField(decoded.deviceType, 4) << L"\r\n"
           << L"Function: " << FormatField(decoded.function, 3) << L"\r\n"
           << L"Access: " << FormatField(decoded.access, 1) << L"  " << IoctlAccessName(decoded.access) << L"\r\n"
           << L"Method: " << FormatField(decoded.method, 1) << L"  " << IoctlMethodName(decoded.method) << L"\r\n"
           << L"Common (bit 31): " << (decoded.common ? L"1" : L"0") << L"\r\n"
           << L"Custom (bit 13): " << (decoded.custom ? L"1" : L"0") << L"\r\n\r\n"
           << L"CTL_CODE 位布局\r\n"
           << L"[31] Common | [30:16] Device | [15:14] Access | [13] Custom | [12:2] Function | [1:0] Method\r\n"
           << L"此结果仅在本地拆解控制码，不会读取驱动或打开设备。\r\n";
    return report.str();
}

} // namespace Ksword::Features::SysTools
