#pragma once
#include "RegistryModel.h"
#include <algorithm>
#include <cstring>
namespace ks::r3::registry::detail {
class UniqueRegKey final {
public:
    UniqueRegKey() = default;
    explicit UniqueRegKey(HKEY key) noexcept : key_(key) {}
    ~UniqueRegKey() { reset(); }
    UniqueRegKey(const UniqueRegKey&) = delete;
    UniqueRegKey& operator=(const UniqueRegKey&) = delete;
    HKEY get() const noexcept { return key_; }
    bool valid() const noexcept { return key_ != nullptr; }
    void reset(HKEY key = nullptr) noexcept {
        if (key_) {
            ::RegCloseKey(key_);
        }
        key_ = key;
    }

private:
    HKEY key_ = nullptr;
};
inline RegistrySnapshot MakePathError(const std::wstring& path, const RegistryViewMode mode, const RegistryPathInfo& parsed) {
    RegistrySnapshot snapshot;
    snapshot.mode = mode;
    snapshot.displayPath = path;
    snapshot.statusText = parsed.errorText;
    snapshot.win32Error = ERROR_INVALID_PARAMETER;
    return snapshot;
}
inline RegistryOperationResult MakeOperationPathError(const RegistryPathInfo& parsed) {
    RegistryOperationResult result;
    result.success = false;
    result.win32Error = ERROR_INVALID_PARAMETER;
    result.statusText = parsed.errorText;
    return result;
}
inline UniqueRegKey OpenKey(const RegistryPathInfo& path, const REGSAM access, LONG* statusOut = nullptr) {
    HKEY raw = nullptr;
    const LONG status = ::RegOpenKeyExW(path.root, path.subKey.c_str(), 0, access, &raw);
    if (statusOut) {
        *statusOut = status;
    }
    if (status != ERROR_SUCCESS) {
        return UniqueRegKey();
    }
    return UniqueRegKey(raw);
}
inline void AppendWinApiValues(HKEY key, RegistrySnapshot& snapshot) {
    DWORD valueCount = 0;
    DWORD maxValueName = 0;
    DWORD maxData = 0;
    const auto queryStatus = ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            &valueCount, &maxValueName, &maxData, nullptr, nullptr);
    if (queryStatus != ERROR_SUCCESS) {
        snapshot.complete = false; snapshot.win32Error = static_cast<std::uint32_t>(queryStatus);
        return;
    }
    std::vector<wchar_t> name(static_cast<std::size_t>(maxValueName) + 2U);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(std::max<DWORD>(maxData, 1)));
    for (DWORD index = 0; index < valueCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        DWORD dataBytes = static_cast<DWORD>(data.size());
        DWORD type = REG_NONE;
        const LONG rc = ::RegEnumValueW(key, index, name.data(), &nameChars, nullptr, &type, data.data(), &dataBytes);
        if (rc != ERROR_SUCCESS) {
            snapshot.complete = false; snapshot.win32Error = static_cast<std::uint32_t>(rc);
            continue;
        }
        RegistryEntry row;
        row.kind = RegistryRowKind::Value;
        row.name.assign(name.data(), name.data() + nameChars);
        row.valueType = type;
        row.typeText = RegistryTypeText(type);
        row.data.assign(data.begin(), data.begin() + dataBytes);
        row.dataText = FormatRegistryData(type, row.data);
        row.detailText = L"WinAPI value; bytes=" + std::to_wstring(dataBytes);
        snapshot.rows.push_back(std::move(row));
    }
}
inline void AppendWinApiSubKeys(HKEY key, RegistrySnapshot& snapshot) {
    DWORD subKeyCount = 0;
    DWORD maxSubKey = 0;
    const auto queryStatus = ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKey, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr);
    if (queryStatus != ERROR_SUCCESS) {
        snapshot.complete = false; snapshot.win32Error = static_cast<std::uint32_t>(queryStatus);
        return;
    }
    std::vector<wchar_t> name(static_cast<std::size_t>(maxSubKey) + 2U);
    for (DWORD index = 0; index < subKeyCount; ++index) {
        DWORD nameChars = static_cast<DWORD>(name.size());
        const LONG rc = ::RegEnumKeyExW(key, index, name.data(), &nameChars, nullptr, nullptr, nullptr, nullptr);
        if (rc != ERROR_SUCCESS) {
            snapshot.complete = false; snapshot.win32Error = static_cast<std::uint32_t>(rc);
            continue;
        }
        RegistryEntry row;
        row.kind = RegistryRowKind::SubKey;
        row.name.assign(name.data(), name.data() + nameChars);
        row.typeText = L"Key";
        row.detailText = L"WinAPI subkey";
        snapshot.rows.push_back(std::move(row));
    }
}
}
