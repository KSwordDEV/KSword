#include "RegistryModel.h"

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <sstream>

namespace ks::r3::registry {
namespace {

// Trim removes leading and trailing whitespace from a path or data token. Input
// is copied text; output is the trimmed copy.
std::wstring Trim(std::wstring text) {
    text.erase(text.begin(), std::find_if(text.begin(), text.end(), [](wchar_t ch) {
        return !std::iswspace(ch);
    }));
    text.erase(std::find_if(text.rbegin(), text.rend(), [](wchar_t ch) {
        return !std::iswspace(ch);
    }).base(), text.end());
    return text;
}

// StartsWithNoCase tests one prefix without depending on locale-sensitive
// transforms. Inputs are two strings; output is true when text starts with
// prefix ignoring case.
bool StartsWithNoCase(const std::wstring& text, const wchar_t* prefix) {
    const std::size_t length = std::wcslen(prefix);
    return text.size() >= length && _wcsnicmp(text.c_str(), prefix, length) == 0;
}

// AppendLittleEndianDword appends a 32-bit value to a byte vector. Input is the
// numeric value; processing writes Win32 registry native little-endian bytes.
void AppendLittleEndianDword(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFU));
}

// ParseUnsigned parses decimal or 0x-prefixed integer text. Inputs are text and
// output value; output is false when the full token cannot be consumed.
bool ParseUnsigned(const std::wstring& text, unsigned long long& value) {
    const std::wstring trimmed = Trim(text);
    if (trimmed.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    const int base = StartsWithNoCase(trimmed, L"0x") ? 16 : 10;
    value = std::wcstoull(trimmed.c_str(), &end, base);
    return end != trimmed.c_str() && *end == L'\0';
}

// HexByteText formats bytes with spaces. Input is raw data; output is a compact
// uppercase hex string.
std::wstring HexByteText(const std::vector<std::uint8_t>& data) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex;
    for (std::size_t index = 0; index < data.size(); ++index) {
        if (index != 0) {
            stream << L' ';
        }
        stream.width(2);
        stream.fill(L'0');
        stream << static_cast<unsigned int>(data[index]);
    }
    return stream.str();
}

} // namespace

RegistryPathInfo ParseRegistryPath(const std::wstring& text) {
    RegistryPathInfo info;
    std::wstring path = Trim(text);
    std::replace(path.begin(), path.end(), L'/', L'\\');
    while (!path.empty() && path.front() == L'\\' && !StartsWithNoCase(path, L"\\REGISTRY\\")) {
        path.erase(path.begin());
    }
    if (path.empty()) {
        info.errorText = L"Registry path is empty.";
        return info;
    }

    if (StartsWithNoCase(path, L"\\REGISTRY\\MACHINE")) {
        info.root = HKEY_LOCAL_MACHINE;
        info.rootText = L"HKLM";
        info.subKey = path.size() > 17 ? path.substr(18) : std::wstring();
        info.kernelPath = L"\\REGISTRY\\MACHINE" + (info.subKey.empty() ? std::wstring() : L"\\" + info.subKey);
    } else if (StartsWithNoCase(path, L"\\REGISTRY\\USER")) {
        info.root = HKEY_USERS;
        info.rootText = L"HKU";
        info.subKey = path.size() > 14 ? path.substr(15) : std::wstring();
        info.kernelPath = L"\\REGISTRY\\USER" + (info.subKey.empty() ? std::wstring() : L"\\" + info.subKey);
    } else {
        struct RootAlias {
            const wchar_t* alias;
            HKEY root;
            const wchar_t* rootText;
            const wchar_t* kernelPrefix;
        };
        const RootAlias aliases[] = {
            { L"HKLM", HKEY_LOCAL_MACHINE, L"HKLM", L"\\REGISTRY\\MACHINE" },
            { L"HKLM\\", HKEY_LOCAL_MACHINE, L"HKLM", L"\\REGISTRY\\MACHINE" },
            { L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE, L"HKLM", L"\\REGISTRY\\MACHINE" },
            { L"HKEY_LOCAL_MACHINE\\", HKEY_LOCAL_MACHINE, L"HKLM", L"\\REGISTRY\\MACHINE" },
            { L"HKU", HKEY_USERS, L"HKU", L"\\REGISTRY\\USER" },
            { L"HKU\\", HKEY_USERS, L"HKU", L"\\REGISTRY\\USER" },
            { L"HKEY_USERS", HKEY_USERS, L"HKU", L"\\REGISTRY\\USER" },
            { L"HKEY_USERS\\", HKEY_USERS, L"HKU", L"\\REGISTRY\\USER" },
            { L"HKCU", HKEY_CURRENT_USER, L"HKCU", L"" },
            { L"HKCU\\", HKEY_CURRENT_USER, L"HKCU", L"" },
            { L"HKEY_CURRENT_USER", HKEY_CURRENT_USER, L"HKCU", L"" },
            { L"HKEY_CURRENT_USER\\", HKEY_CURRENT_USER, L"HKCU", L"" },
            { L"HKCR", HKEY_CLASSES_ROOT, L"HKCR", L"" },
            { L"HKCR\\", HKEY_CLASSES_ROOT, L"HKCR", L"" },
            { L"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT, L"HKCR", L"" },
            { L"HKEY_CLASSES_ROOT\\", HKEY_CLASSES_ROOT, L"HKCR", L"" },
            { L"HKCC", HKEY_CURRENT_CONFIG, L"HKCC", L"" },
            { L"HKCC\\", HKEY_CURRENT_CONFIG, L"HKCC", L"" },
            { L"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG, L"HKCC", L"" },
            { L"HKEY_CURRENT_CONFIG\\", HKEY_CURRENT_CONFIG, L"HKCC", L"" },
        };
        for (const RootAlias& alias : aliases) {
            if (!StartsWithNoCase(path, alias.alias)) {
                continue;
            }
            const std::size_t aliasLength = std::wcslen(alias.alias);
            if (path.size() > aliasLength && path[aliasLength] != L'\\') {
                continue;
            }
            info.root = alias.root;
            info.rootText = alias.rootText;
            info.subKey = path.size() > aliasLength ? path.substr(aliasLength) : std::wstring();
            if (!info.subKey.empty() && info.subKey.front() == L'\\') {
                info.subKey.erase(info.subKey.begin());
            }
            if (alias.kernelPrefix[0] != L'\0') {
                info.kernelPath = std::wstring(alias.kernelPrefix) + (info.subKey.empty() ? std::wstring() : L"\\" + info.subKey);
            }
            break;
        }
    }

    if (!info.root) {
        info.errorText = L"Unsupported root. Use HKLM, HKU, HKCU, HKCR, HKCC, or \\REGISTRY\\MACHINE/USER.";
        return info;
    }
    if (info.kernelPath.empty() && (info.root == HKEY_CURRENT_USER || info.root == HKEY_CLASSES_ROOT || info.root == HKEY_CURRENT_CONFIG)) {
        info.kernelPath = L"";
    }
    info.displayPath = info.rootText + (info.subKey.empty() ? std::wstring() : L"\\" + info.subKey);
    info.valid = true;
    return info;
}

std::wstring RootRegistryPath(const std::wstring& text) {
    // Input is any registry display path. Processing parses the root alias and
    // drops all child segments. Output is the root-only display path used by the
    // TreeView root items and the parent-navigation boundary.
    const RegistryPathInfo parsed = ParseRegistryPath(text);
    if (!parsed.valid) {
        return {};
    }
    return parsed.rootText;
}

std::wstring ParentRegistryPath(const std::wstring& text) {
    // Input is a registry display/kernel path. Processing removes the trailing
    // child segment only; if the path is already a root key, the same path is
    // returned so the caller can keep the current selection unchanged.
    const RegistryPathInfo parsed = ParseRegistryPath(text);
    if (!parsed.valid || parsed.subKey.empty()) {
        return parsed.valid ? parsed.displayPath : std::wstring();
    }
    const std::size_t slash = parsed.subKey.find_last_of(L'\\');
    if (slash == std::wstring::npos) {
        return parsed.rootText;
    }
    return parsed.rootText + L"\\" + parsed.subKey.substr(0, slash);
}

std::wstring RegistryTypeText(const std::uint32_t type) {
    switch (type) {
    case REG_NONE: return L"REG_NONE";
    case REG_SZ: return L"REG_SZ";
    case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
    case REG_BINARY: return L"REG_BINARY";
    case REG_DWORD: return L"REG_DWORD";
    case REG_DWORD_BIG_ENDIAN: return L"REG_DWORD_BIG_ENDIAN";
    case REG_MULTI_SZ: return L"REG_MULTI_SZ";
    case REG_QWORD: return L"REG_QWORD";
    default: return L"REG_" + std::to_wstring(type);
    }
}

std::wstring FormatRegistryData(const std::uint32_t type, const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        return {};
    }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        const wchar_t* text = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t chars = data.size() / sizeof(wchar_t);
        std::wstring value(text, text + chars);
        while (!value.empty() && value.back() == L'\0') {
            value.pop_back();
        }
        return value;
    }
    if (type == REG_MULTI_SZ) {
        const wchar_t* text = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t chars = data.size() / sizeof(wchar_t);
        std::wstring value(text, text + chars);
        for (wchar_t& ch : value) {
            if (ch == L'\0') {
                ch = L';';
            }
        }
        while (!value.empty() && (value.back() == L';' || value.back() == L'\0')) {
            value.pop_back();
        }
        return value;
    }
    if (type == REG_DWORD && data.size() >= sizeof(std::uint32_t)) {
        const std::uint32_t value = static_cast<std::uint32_t>(data[0]) |
            (static_cast<std::uint32_t>(data[1]) << 8) |
            (static_cast<std::uint32_t>(data[2]) << 16) |
            (static_cast<std::uint32_t>(data[3]) << 24);
        std::wostringstream stream;
        stream << value << L" (0x" << std::uppercase << std::hex << value << L")";
        return stream.str();
    }
    return HexByteText(data);
}

bool ParseRegistryDataText(const std::uint32_t type, const std::wstring& text, std::vector<std::uint8_t>& bytes, std::wstring& errorText) {
    bytes.clear();
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        std::wstring value = text;
        value.push_back(L'\0');
        const auto* begin = reinterpret_cast<const std::uint8_t*>(value.data());
        bytes.assign(begin, begin + value.size() * sizeof(wchar_t));
        return true;
    }
    if (type == REG_MULTI_SZ) {
        std::wstring value = text;
        std::replace(value.begin(), value.end(), L';', L'\0');
        value.push_back(L'\0');
        value.push_back(L'\0');
        const auto* begin = reinterpret_cast<const std::uint8_t*>(value.data());
        bytes.assign(begin, begin + value.size() * sizeof(wchar_t));
        return true;
    }
    if (type == REG_DWORD) {
        unsigned long long value = 0;
        if (!ParseUnsigned(text, value) || value > 0xFFFFFFFFULL) {
            errorText = L"REG_DWORD value must be decimal or 0x-prefixed 32-bit integer.";
            return false;
        }
        AppendLittleEndianDword(bytes, static_cast<std::uint32_t>(value));
        return true;
    }

    std::wistringstream stream(text);
    std::wstring token;
    while (stream >> token) {
        if (StartsWithNoCase(token, L"0x")) {
            token = token.substr(2);
        }
        if (token.empty() || token.size() > 2) {
            errorText = L"Binary data must be hex byte tokens.";
            return false;
        }
        wchar_t* end = nullptr;
        const unsigned long value = std::wcstoul(token.c_str(), &end, 16);
        if (end == token.c_str() || *end != L'\0' || value > 0xFFUL) {
            errorText = L"Binary data contains an invalid hex byte.";
            return false;
        }
        bytes.push_back(static_cast<std::uint8_t>(value));
    }
    return true;
}

} // namespace ks::r3::registry
