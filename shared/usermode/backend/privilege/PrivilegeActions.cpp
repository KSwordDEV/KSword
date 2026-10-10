#include "PrivilegeActions.h"

#include <string>

namespace ks::r3::privilege {
namespace {

std::wstring Win32ErrorText(const DWORD errorCode) {
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);
    if (length == 0 || buffer == nullptr) {
        return L"错误码 " + std::to_wstring(errorCode);
    }
    std::wstring message(buffer, length);
    ::LocalFree(buffer);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message + L"（错误码 " + std::to_wstring(errorCode) + L"）";
}

} // namespace

PrivilegeActionResult SetPrivilegeEnabled(const std::wstring& privilegeName, const bool enable) {
    PrivilegeActionResult result{};
    if (privilegeName.empty()) {
        result.win32Error = ERROR_INVALID_PARAMETER;
        result.message = L"未选择权限。";
        return result;
    }

    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
        result.win32Error = ::GetLastError();
        result.message = L"解析权限名失败：" + Win32ErrorText(result.win32Error);
        return result;
    }

    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        result.win32Error = ::GetLastError();
        result.message = L"打开当前进程令牌失败：" + Win32ErrorText(result.win32Error);
        return result;
    }

    TOKEN_PRIVILEGES adjustment{};
    adjustment.PrivilegeCount = 1;
    adjustment.Privileges[0].Luid = luid;
    adjustment.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    ::SetLastError(ERROR_SUCCESS);
    const BOOL adjusted = ::AdjustTokenPrivileges(token, FALSE, &adjustment, 0, nullptr, nullptr);
    const DWORD lastError = ::GetLastError();
    result.win32Error = lastError;
    ::CloseHandle(token);

    if (!adjusted) {
        result.message = std::wstring(enable ? L"启用" : L"禁用") + L"权限失败：" + Win32ErrorText(lastError);
        return result;
    }
    // The API reports success for a well-formed call even when it changed
    // nothing, so this check is what separates "enabled" from "the token never
    // had it to begin with".
    if (lastError == ERROR_NOT_ALL_ASSIGNED) {
        result.message = L"当前令牌未被授予 " + privilegeName + L"，无法" + (enable ? L"启用" : L"禁用") +
            L"。该权限需要由本地安全策略或所属组授予后重新登录才会出现在令牌中。";
        return result;
    }

    result.success = true;
    result.message = privilegeName + (enable ? L" 已启用。" : L" 已禁用。");
    return result;
}

} // namespace ks::r3::privilege
