#include "Directory.h"
#include "DirectorySupport.h"
#include "PathNavigator.h"
#include <algorithm>
#include <cwchar>
namespace ks::r3::file {
using namespace detail;
std::wstring formatAttributes(DWORD attributes) {
    std::wstring text;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        text += L"D";
    }
    if (attributes & FILE_ATTRIBUTE_READONLY) {
        text += L"R";
    }
    if (attributes & FILE_ATTRIBUTE_HIDDEN) {
        text += L"H";
    }
    if (attributes & FILE_ATTRIBUTE_SYSTEM) {
        text += L"S";
    }
    if (attributes & FILE_ATTRIBUTE_ARCHIVE) {
        text += L"A";
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        text += L"L";
    }
    return text.empty() ? L"-" : text;
}
std::wstring formatSize(ULONGLONG bytes, FileEntryKind kind) {
    if (kind != FileEntryKind::File) {
        return {};
    }
    return std::to_wstring(bytes);
}
std::wstring formatLastWriteTime(const FILETIME& fileTime) {
    if (FileTimeIsZero(fileTime)) {
        return {};
    }
    FILETIME localTime{};
    SYSTEMTIME systemTime{};
    if (!::FileTimeToLocalFileTime(&fileTime, &localTime)) {
        return {};
    }
    if (!::FileTimeToSystemTime(&localTime, &systemTime)) {
        return {};
    }
    wchar_t buffer[32]{};
    if (std::swprintf(buffer, 32, L"%04u-%02u-%02u %02u:%02u:%02u",
            systemTime.wYear,
            systemTime.wMonth,
            systemTime.wDay,
            systemTime.wHour,
            systemTime.wMinute,
            systemTime.wSecond) <= 0) {
        return {};
    }
    return buffer;
}
DirectoryEnumerationResult enumerateDrives() {
    DirectoryEnumerationResult result;
    result.virtualDriveRoot = true;
    result.statusText = L"列出逻辑驱动器";

    const DWORD mask = ::GetLogicalDrives();
    const DWORD bufferChars = ::GetLogicalDriveStringsW(0, nullptr);
    if (mask == 0 && bufferChars == 0) {
        result.errorCode = ::GetLastError();
        result.statusText = MakeStatusText(result.errorCode);
        return result;
    }

    std::vector<wchar_t> buffer(bufferChars + 2, L'\0');
    const DWORD written = ::GetLogicalDriveStringsW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (written == 0 || written >= buffer.size()) {
        result.errorCode = ::GetLastError();
        result.statusText = MakeStatusText(result.errorCode);
        return result;
    }

    for (const wchar_t* drive = buffer.data(); drive && *drive; drive += std::wcslen(drive) + 1) {
        FileEntry entry;
        entry.kind = FileEntryKind::Drive;
        entry.name = drive;
        entry.fullPath = drive;
        entry.attributes = FILE_ATTRIBUTE_DIRECTORY;
        result.entries.push_back(entry);
    }
    result.errorCode = ERROR_SUCCESS;
    result.statusText = L"逻辑驱动器 " + std::to_wstring(result.entries.size()) + L" 项";
    return result;
}
DirectoryEnumerationResult enumerateDirectory(const std::wstring& directory) {
    DirectoryEnumerationResult result;
    result.directory = directory;

    const std::wstring pattern = PathNavigator::makeSearchPattern(directory);
    WIN32_FIND_DATAW data{};
    HANDLE find = ::FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        result.errorCode = ::GetLastError();
        result.statusText = MakeStatusText(result.errorCode);
        return result;
    }

    do {
        const std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") {
            continue;
        }
        FileEntry entry;
        entry.name = name;
        entry.fullPath = PathNavigator::joinChildPath(directory, name);
        entry.attributes = data.dwFileAttributes;
        entry.kind = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? FileEntryKind::Directory : FileEntryKind::File;
        entry.reparsePoint = (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        entry.lastWriteTime = data.ftLastWriteTime;
        entry.size = (static_cast<ULONGLONG>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        result.entries.push_back(entry);
    } while (::FindNextFileW(find, &data));

    const DWORD lastError = ::GetLastError();
    ::FindClose(find);
    if (lastError != ERROR_NO_MORE_FILES) {
        result.errorCode = lastError;
        result.statusText = MakeStatusText(lastError);
        return result;
    }

    std::sort(result.entries.begin(), result.entries.end(), EntryLess);
    result.errorCode = ERROR_SUCCESS;
    result.statusText = L"枚举完成 " + std::to_wstring(result.entries.size()) + L" 项";
    return result;
}
}
