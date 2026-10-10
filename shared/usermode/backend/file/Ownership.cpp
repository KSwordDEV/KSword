#include "Ownership.h"
#include "PathNavigator.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <vector>
#include <Aclapi.h>
#include <sddl.h>
#include <restartmanager.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Rstrtmgr.lib")
namespace ks::r3::file {
bool EnablePrivilege(const wchar_t* privilegeName) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!::LookupPrivilegeValueW(nullptr, privilegeName, &privileges.Privileges[0].Luid)) {
        ::CloseHandle(token);
        return false;
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ::SetLastError(ERROR_SUCCESS);
    const BOOL adjusted = ::AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    const DWORD error = ::GetLastError();
    ::CloseHandle(token);
    return adjusted && error == ERROR_SUCCESS;
}
std::wstring TakeOwnershipPath(const std::wstring& path) {
    return TakeOwnership(path).message;
}
OwnershipResult TakeOwnership(const std::wstring& path) {
    OwnershipResult outcome;
    if (path.empty()) {
        outcome.errorCode = ERROR_INVALID_PARAMETER;
        outcome.message = L"路径为空，无法取得所有权。";
        return outcome;
    }
    const bool privilegeEnabled = EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
    outcome.privilegeEnabled = privilegeEnabled;

    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        outcome.errorCode = ::GetLastError();
        outcome.message = L"OpenProcessToken 失败，错误 " + std::to_wstring(outcome.errorCode);
        return outcome;
    }

    DWORD bytes = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    std::vector<BYTE> buffer(bytes);
    if (bytes == 0 || !::GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(token);
        outcome.errorCode = error;
        outcome.message = L"GetTokenInformation(TokenUser) 失败，错误 " + std::to_wstring(error);
        return outcome;
    }
    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR sid = nullptr;
    if (::ConvertSidToStringSidW(tokenUser->User.Sid, &sid)) {
        outcome.callerSid = sid;
        ::LocalFree(sid);
    }
    const DWORD result = ::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        tokenUser->User.Sid,
        nullptr,
        nullptr,
        nullptr);
    ::CloseHandle(token);
    outcome.errorCode = result;

    if (result == ERROR_SUCCESS) {
        outcome.success = true;
        outcome.message = std::wstring(L"已取得所有权。") + (privilegeEnabled ? L"" : L"（SeTakeOwnershipPrivilege 未显式启用，但操作成功。）");
        return outcome;
    }
    outcome.message = std::wstring(L"取得所有权失败，错误 ") + std::to_wstring(result) +
        (privilegeEnabled ? L"" : L"；同时无法启用 SeTakeOwnershipPrivilege。");
    return outcome;
}
std::wstring QueryFileLockers(const std::wstring& path) {
    return ReadFileLockers(path).report;
}
FileLockersResult ReadFileLockers(const std::wstring& path) {
    FileLockersResult outcome;
    if (path.empty()) {
        outcome.errorCode = ERROR_INVALID_PARAMETER;
        outcome.report = L"路径为空，无法扫描占用进程。";
        return outcome;
    }

    DWORD session = 0;
    wchar_t sessionKey[CCH_RM_SESSION_KEY + 1]{};
    DWORD status = ::RmStartSession(&session, 0, sessionKey);
    if (status != ERROR_SUCCESS) {
        outcome.errorCode = status;
        outcome.report = L"RmStartSession 失败，错误 " + std::to_wstring(status);
        return outcome;
    }

    const wchar_t* resources[] = { path.c_str() };
    status = ::RmRegisterResources(session, 1, resources, 0, nullptr, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        ::RmEndSession(session);
        outcome.errorCode = status;
        outcome.report = L"RmRegisterResources 失败，错误 " + std::to_wstring(status);
        return outcome;
    }

    UINT needed = 0;
    UINT count = 0;
    DWORD reason = 0;
    status = ::RmGetList(session, &needed, &count, nullptr, &reason);
    std::vector<RM_PROCESS_INFO> processes(needed == 0 ? 1 : needed);
    count = static_cast<UINT>(processes.size());
    if (status == ERROR_MORE_DATA || status == ERROR_SUCCESS) {
        status = ::RmGetList(session, &needed, &count, processes.data(), &reason);
    }
    ::RmEndSession(session);

    if (status != ERROR_SUCCESS) {
        outcome.errorCode = status;
        outcome.report = L"RmGetList 失败，错误 " + std::to_wstring(status);
        return outcome;
    }
    outcome.success = true;
    outcome.rebootReason = reason;

    std::wostringstream report;
    report << L"文件解锁器(R3/R0) - Restart Manager 占用扫描\r\n\r\n"
           << L"目标: " << path << L"\r\n"
           << L"占用进程数: " << count << L"\r\n"
           << L"RebootReason: 0x" << std::hex << std::uppercase << reason << L"\r\n\r\n";
    if (count == 0) {
        report << L"未发现 Restart Manager 可见的占用进程。";
        outcome.report = report.str();
        return outcome;
    }
    for (UINT index = 0; index < count && index < processes.size(); ++index) {
        const RM_PROCESS_INFO& process = processes[index];
        outcome.processes.push_back({process.Process.dwProcessId,
            (static_cast<std::uint64_t>(process.Process.ProcessStartTime.dwHighDateTime) << 32) | process.Process.ProcessStartTime.dwLowDateTime,
            process.strAppName, process.strServiceShortName, static_cast<DWORD>(process.ApplicationType), process.AppStatus,
            process.TSSessionId, process.bRestartable != FALSE});
        report << L"PID=" << std::dec << process.Process.dwProcessId
               << L" App=" << process.strAppName
               << L" Service=" << process.strServiceShortName
               << L" Type=" << process.ApplicationType
               << L" Status=0x" << std::hex << std::uppercase << process.AppStatus
               << L"\r\n";
    }
    report << L"\r\n轻量版仅枚举占用者，不执行强制关闭/解锁。";
    outcome.report = report.str();
    return outcome;
}
}
