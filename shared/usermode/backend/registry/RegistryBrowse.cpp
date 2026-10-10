#include "RegistryBackend.h"
#include "RegistrySupport.h"
namespace ks::r3::registry {
using namespace detail;
RegistrySnapshot EnumerateRegistryKey(const std::wstring& path) {
    constexpr RegistryViewMode mode = RegistryViewMode::WinApi;
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakePathError(path, mode, parsed);
    }

    RegistrySnapshot snapshot;
    snapshot.mode = mode;
    snapshot.displayPath = parsed.displayPath;
    snapshot.kernelPath = parsed.kernelPath;



    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = OpenKey(parsed, KEY_READ, &openStatus);
    if (!key.valid()) {
        snapshot.success = false;
        snapshot.win32Error = static_cast<std::uint32_t>(openStatus);
        snapshot.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return snapshot;
    }
    snapshot.complete = true;
    AppendWinApiSubKeys(key.get(), snapshot);
    AppendWinApiValues(key.get(), snapshot);
    snapshot.success = true;
    snapshot.statusText = L"WinAPI registry enum OK; rows=" + std::to_wstring(snapshot.rows.size());
    return snapshot;
}
std::vector<std::wstring> EnumerateRegistrySubKeyNames(const std::wstring& path, std::wstring* statusTextOut) {
    // Inputs:
    // - path: one registry key in display or kernel form.
    // - mode: WinAPI or R0 transport.
    // - statusTextOut: optional status sink for UI feedback.
    // Processing:
    // - parses only the current key;
    // - enumerates direct child key names only;
    // - never walks recursively, so TreeView expansion stays lazy.
    // Output:
    // - direct child key names only.
    std::vector<std::wstring> childNames;
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        if (statusTextOut) {
            *statusTextOut = parsed.errorText;
        }
        return childNames;
    }



    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = OpenKey(parsed, KEY_READ, &openStatus);
    if (!key.valid()) {
        if (statusTextOut) {
            *statusTextOut = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        }
        return childNames;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKey = 0;
    if (::RegQueryInfoKeyW(key.get(), nullptr, nullptr, nullptr, &subKeyCount, &maxSubKey, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        if (statusTextOut) {
            *statusTextOut = L"RegQueryInfoKeyW failed.";
        }
        return childNames;
    }
    std::vector<wchar_t> name(static_cast<std::size_t>(maxSubKey) + 2U);
    for (DWORD index = 0; index < subKeyCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        const LONG rc = ::RegEnumKeyExW(key.get(), index, name.data(), &nameChars, nullptr, nullptr, nullptr, nullptr);
        if (rc != ERROR_SUCCESS) {
            continue;
        }
        childNames.emplace_back(name.data(), name.data() + nameChars);
    }
    if (statusTextOut) {
        *statusTextOut = L"WinAPI subkey enum OK; subkeys=" + std::to_wstring(childNames.size());
    }
    return childNames;
}
RegistryOperationResult ReadRegistryValue(const std::wstring& path, const std::wstring& valueName) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;


    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = OpenKey(parsed, KEY_QUERY_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    DWORD type = 0;
    DWORD bytes = 0;
    const wchar_t* valuePtr = valueName.empty() ? nullptr : valueName.c_str();
    LONG rc = ::RegQueryValueExW(key.get(), valuePtr, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS) {
        result.win32Error = static_cast<DWORD>(rc);
        result.statusText = L"RegQueryValueExW(size) failed: " + std::to_wstring(rc);
        return result;
    }
    result.data.resize(bytes);
    rc = ::RegQueryValueExW(key.get(), valuePtr, nullptr, &type, result.data.data(), &bytes);
    if (rc != ERROR_SUCCESS) {
        result.win32Error = static_cast<DWORD>(rc);
        result.statusText = L"RegQueryValueExW(data) failed: " + std::to_wstring(rc);
        return result;
    }
    result.data.resize(bytes);
    result.valueType = type;
    result.success = true;
    result.statusText = L"WinAPI read OK; type=" + RegistryTypeText(type) + L"; bytes=" + std::to_wstring(bytes);
    return result;
}
}
