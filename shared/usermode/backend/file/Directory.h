#pragma once
#include "../Win32.h"
#include <string>
#include <vector>
namespace ks::r3::file {
enum class FileEntryKind {
    Drive,
    Directory,
    File
};
struct FileEntry {
    FileEntryKind kind = FileEntryKind::File;
    std::wstring name;
    std::wstring fullPath;
    DWORD attributes = 0;
    ULONGLONG size = 0;
    FILETIME lastWriteTime{};
    bool reparsePoint = false;
};
struct DirectoryEnumerationResult {
    std::wstring directory;
    std::vector<FileEntry> entries;
    DWORD errorCode = ERROR_SUCCESS;
    std::wstring statusText;
    bool virtualDriveRoot = false;
};
DirectoryEnumerationResult enumerateDrives();
DirectoryEnumerationResult enumerateDirectory(const std::wstring& directory);
std::wstring formatAttributes(DWORD attributes);
std::wstring formatSize(ULONGLONG bytes, FileEntryKind kind);
std::wstring formatLastWriteTime(const FILETIME& fileTime);
}
