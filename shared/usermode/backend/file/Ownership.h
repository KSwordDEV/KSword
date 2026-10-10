#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::file {

struct OwnershipResult {
    bool success = false;
    bool privilegeEnabled = false;
    DWORD errorCode = ERROR_SUCCESS;
    std::wstring callerSid;
    std::wstring message;
};
struct FileLocker {
    DWORD pid = 0;
    std::uint64_t creationTime = 0;
    std::wstring application, service;
    DWORD applicationType = 0, status = 0, sessionId = 0;
    bool restartable = false;
};
struct FileLockersResult {
    bool success = false;
    DWORD errorCode = ERROR_SUCCESS;
    DWORD rebootReason = 0;
    std::vector<FileLocker> processes;
    std::wstring report;
};
OwnershipResult TakeOwnership(const std::wstring& path);
FileLockersResult ReadFileLockers(const std::wstring& path);

bool EnablePrivilege(const wchar_t* privilegeName);
std::wstring TakeOwnershipPath(const std::wstring& path);
std::wstring QueryFileLockers(const std::wstring& path);
}
