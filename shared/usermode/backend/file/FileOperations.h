#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::file {

struct FileOperationResult {
    bool success = false;
    bool partial = false;
    bool copied = false;
    bool sourceRemoved = false;
    std::wstring target;
    DWORD errorCode = ERROR_SUCCESS;
    std::string errorCategory;
    std::wstring message;
};
FileOperationResult TransferPathToFolder(const std::wstring& source, const std::wstring& folder, bool move);
FileOperationResult CreateEmptyFileResult(const std::wstring& directory);
FileOperationResult CreateNewDirectoryResult(const std::wstring& directory);


bool CopyOrMovePathToFolder(
    const std::wstring& sourcePath,
    const std::wstring& targetFolder,
    bool move,
    std::wstring& statusOut);
std::wstring CreateEmptyFile(const std::wstring& directory);
std::wstring CreateNewDirectory(const std::wstring& directory);
std::wstring ShortPathForFile(const std::wstring& path);
std::wstring ResolveLinkTarget(const std::wstring& path, HRESULT* statusOut = nullptr);
BOOL RenamePath(const std::wstring& source, const std::wstring& target);
BOOL DeleteFilePath(const std::wstring& path);
BOOL DeleteEmptyDirectory(const std::wstring& path);
}
