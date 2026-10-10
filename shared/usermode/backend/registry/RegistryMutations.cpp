#include "RegistryBackend.h"
#include "RegistrySupport.h"
namespace ks::r3::registry {
using namespace detail;
RegistryOperationResult WriteRegistryValue(const std::wstring& path, const std::wstring& valueName, const std::uint32_t type, const std::vector<std::uint8_t>& data) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;


    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = OpenKey(parsed, KEY_SET_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    const LONG rc = ::RegSetValueExW(key.get(), valueName.empty() ? nullptr : valueName.c_str(), 0, type,
        data.empty() ? nullptr : data.data(), static_cast<DWORD>(data.size()));
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI write OK." : L"RegSetValueExW failed: " + std::to_wstring(rc);
    return result;
}
RegistryOperationResult DeleteRegistryValue(const std::wstring& path, const std::wstring& valueName) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;


    LONG openStatus = ERROR_SUCCESS;
    UniqueRegKey key = OpenKey(parsed, KEY_SET_VALUE, &openStatus);
    if (!key.valid()) {
        result.win32Error = static_cast<DWORD>(openStatus);
        result.statusText = L"RegOpenKeyExW failed: " + std::to_wstring(openStatus);
        return result;
    }
    const LONG rc = ::RegDeleteValueW(key.get(), valueName.empty() ? nullptr : valueName.c_str());
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI delete value OK." : L"RegDeleteValueW failed: " + std::to_wstring(rc);
    return result;
}
RegistryOperationResult CreateRegistryKey(const std::wstring& path) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;


    HKEY raw = nullptr;
    DWORD disposition = 0;
    const LONG rc = ::RegCreateKeyExW(parsed.root, parsed.subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE, nullptr, &raw, &disposition);
    UniqueRegKey key(raw);
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI create/open key OK." : L"RegCreateKeyExW failed: " + std::to_wstring(rc);
    result.dispositionKnown = result.success;
    result.created = result.success && disposition == REG_CREATED_NEW_KEY;
    return result;
}
RegistryOperationResult DeleteRegistryKey(const std::wstring& path) {
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }
    RegistryOperationResult result;


    const LONG rc = ::RegDeleteTreeW(parsed.root, parsed.subKey.c_str());
    result.success = rc == ERROR_SUCCESS;
    result.win32Error = static_cast<DWORD>(rc);
    result.statusText = result.success ? L"WinAPI delete key tree OK." : L"RegDeleteTreeW failed: " + std::to_wstring(rc);
    return result;
}
RegistryOperationResult RenameRegistryValue(const std::wstring& path, const std::wstring& oldName, const std::wstring& newName) {
    RegistryOperationResult result;
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }


    RegistryOperationResult read = ReadRegistryValue(path, oldName);
    if (!read.success) {
        return read;
    }
    if (::CompareStringOrdinal(oldName.c_str(), -1, newName.c_str(), -1, TRUE) == CSTR_EQUAL) {
        read.unchanged = true;
        read.statusText = L"WinAPI rename value unchanged (case-insensitive name).";
        return read;
    }
    RegistryOperationResult write = WriteRegistryValue(path, newName, read.valueType, read.data);
    if (!write.success) {
        return write;
    }
    auto removed = DeleteRegistryValue(path, oldName);
    removed.partial = !removed.success;
    return removed;
}
RegistryOperationResult RenameRegistryKey(const std::wstring& path, const std::wstring& /*newName*/) {
    RegistryOperationResult result;
    RegistryPathInfo parsed = ParseRegistryPath(path);
    if (!parsed.valid) {
        return MakeOperationPathError(parsed);
    }

    result.success = false;
    result.win32Error = ERROR_NOT_SUPPORTED;
    result.statusText = L"WinAPI key rename is not exposed here; use R0 mode for rename key.";
    return result;
}
}
