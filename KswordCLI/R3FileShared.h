#pragma once
#include "CommandRegistry.h"
#include "../shared/usermode/backend/file/PathNavigator.h"
#include <stdexcept>
namespace ks::cli::file {
inline std::wstring path(const Args& args, const std::wstring& key) {
    const auto value = ks::r3::file::PathNavigator::normalizeDirectoryPath(args.require(key));
    if (value.empty()) throw std::invalid_argument("empty path");
    const DWORD needed = GetFullPathNameW(value.c_str(), 0, nullptr, nullptr);
    if (!needed) throw std::invalid_argument("invalid path");
    std::wstring full(needed, L'\0'); const DWORD written = GetFullPathNameW(value.c_str(), needed, full.data(), nullptr);
    if (!written || written >= needed) throw std::invalid_argument("cannot resolve path");
    full.resize(written); return full;
}
struct Evidence {
    bool known = false, present = false;
    DWORD error = 0;
    WIN32_FILE_ATTRIBUTE_DATA data{};
    std::uint64_t size() const { return (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow; }
    bool directory() const { return present && (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0; }
    Json json() const { return Json::object({{L"known", Json::boolean(known)}, {L"present", known ? Json::boolean(present) : Json{}},
        {L"win32Error", Json::number(error)}, {L"attributes", present ? Json::hex(data.dwFileAttributes) : Json{}},
        {L"sizeBytes", present && !directory() ? Json::count(size()) : Json{}}}); }
};
inline Evidence evidence(const std::wstring& path) {
    Evidence result;
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &result.data)) result.known = result.present = true;
    else { result.error = GetLastError(); result.known = result.error == ERROR_FILE_NOT_FOUND || result.error == ERROR_PATH_NOT_FOUND; }
    return result;
}
}
