#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::file {

bool CopyOrMovePathToFolder(
    const std::wstring& sourcePath,
    const std::wstring& targetFolder,
    bool move,
    std::wstring& statusOut);
std::wstring CreateEmptyFile(const std::wstring& directory);
std::wstring CreateNewDirectory(const std::wstring& directory);
std::wstring ShortPathForFile(const std::wstring& path);
std::wstring ResolveLinkTarget(const std::wstring& path);
BOOL RenamePath(const std::wstring& source, const std::wstring& target);
BOOL DeleteFilePath(const std::wstring& path);
BOOL DeleteEmptyDirectory(const std::wstring& path);
}
