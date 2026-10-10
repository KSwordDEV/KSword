#include "ProcessToken.h"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <iterator>
namespace ks::r3::process_detail::token {
std::wstring TokenClassName(int informationClass) {
    if (informationClass >= 1 && informationClass <= static_cast<int>(kTokenClassNames.size())) {
        return kTokenClassNames[static_cast<std::size_t>(informationClass - 1)];
    }
    return L"TokenClass" + std::to_wstring(informationClass);
}
std::wstring SidText(PSID sid) {
    if (!sid) {
        return L"<null sid>";
    }
    LPWSTR rawSid = nullptr;
    std::wstring sidValue;
    if (::ConvertSidToStringSidW(sid, &rawSid) && rawSid) {
        sidValue = rawSid;
        ::LocalFree(rawSid);
    }
    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD nameLength = static_cast<DWORD>(std::size(name));
    DWORD domainLength = static_cast<DWORD>(std::size(domain));
    SID_NAME_USE use{};
    if (::LookupAccountSidW(nullptr, sid, name, &nameLength, domain, &domainLength, &use)) {
        std::wstring account;
        if (*domain) { account = std::wstring(domain) + L"\\"; }
        account += name;
        return account + L" (SID=" + sidValue + L")";
    }
    return L"SID=" + (sidValue.empty() ? std::wstring(L"<unavailable>") : sidValue);
}
bool QueryTokenBytes(HANDLE token, int informationClass, std::vector<std::byte>& bytes, DWORD& error,bool* malformed) {
    if (malformed) *malformed = false;
    bytes.clear();
    DWORD required = 0;
    ::SetLastError(ERROR_SUCCESS);
    ::GetTokenInformation(token, static_cast<TOKEN_INFORMATION_CLASS>(informationClass), nullptr, 0, &required);
    error = ::GetLastError();
    if (required == 0 || required > 16 * 1024 * 1024) {
        if (required > 16 * 1024 * 1024) error = ERROR_FILE_TOO_LARGE;
        else if (error == ERROR_SUCCESS) {error = ERROR_INVALID_DATA;if (malformed) *malformed = true;}
        return false;
    }
    bytes.resize(required);
    if (!::GetTokenInformation(
            token,
            static_cast<TOKEN_INFORMATION_CLASS>(informationClass),
            bytes.data(),
            required,
            &required)) {
        error = ::GetLastError();
        bytes.clear();
        return false;
    }
    if (required == 0 || required > bytes.size()) {error = ERROR_INVALID_DATA;if (malformed) *malformed = true;bytes.clear();return false;}
    bytes.resize(required);
    if (informationClass == TokenLinkedToken && bytes.size() >= sizeof(TOKEN_LINKED_TOKEN)) {
        // GetTokenInformation transfers an owned handle for this class. The
        // report/CLI snapshot records its numeric value, then releases it.
        const auto linked = reinterpret_cast<const TOKEN_LINKED_TOKEN*>(bytes.data())->LinkedToken;
        if (linked) ::CloseHandle(linked);
    }
    error = ERROR_SUCCESS;
    return true;
}
TokenQuerySnapshot QueryTokenClasses(DWORD processId,ULONGLONG expectedCreationTime,const std::vector<int>& classes) {
    TokenQuerySnapshot snapshot;
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,processId));
    if (!process) {snapshot.win32ErrorKnown = true;snapshot.win32Error = ::GetLastError();return snapshot;}
    std::wstring error;
    if (!VerifyProcessIdentity(process.get(),expectedCreationTime,error)) return snapshot;
    snapshot.identityMatched = true;
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process.get(),TOKEN_QUERY,&rawToken)) {
        snapshot.win32ErrorKnown = true;snapshot.win32Error = ::GetLastError();return snapshot;
    }
    ScopedHandle token(rawToken);snapshot.tokenOpened = true;
    for (const auto informationClass : classes) {
        TokenClassSnapshot row;row.informationClass = informationClass;
        row.available = QueryTokenBytes(token.get(),informationClass,row.bytes,row.win32Error,&row.malformed);
        snapshot.classes.push_back(std::move(row));
    }
    return snapshot;
}
std::wstring RawPreview(const std::vector<std::byte>& bytes) {
    std::wostringstream text;
    text << std::uppercase << std::hex << std::setfill(L'0');
    const std::size_t count = std::min<std::size_t>(24, bytes.size());
    for (std::size_t index = 0; index < count; ++index) {
        if (index) { text << L' '; }
        text << std::setw(2) << std::to_integer<unsigned int>(bytes[index]);
    }
    if (bytes.size() > count) { text << L" ..."; }
    return text.str();
}
bool VerifyProcessIdentity(
    HANDLE process,
    ULONGLONG expectedProcessCreationTime100ns,
    std::wstring& errorText) {
    errorText.clear();
    if (!process || expectedProcessCreationTime100ns == 0U) {
        errorText = L"进程身份不可用。";
        return false;
    }
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
        errorText = L"GetProcessTimes失败(" + std::to_wstring(::GetLastError()) + L")";
        return false;
    }
    const ULONGLONG actualProcessCreationTime100ns =
        (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(creationTime.dwLowDateTime);
    if (actualProcessCreationTime100ns == 0U ||
        actualProcessCreationTime100ns != expectedProcessCreationTime100ns) {
        errorText = L"目标进程实例已变更（PID 已复用）。";
        return false;
    }
    return true;
}
ProcessTokenReportSnapshot QueryTokenReportSnapshotR3(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns,
    const std::function<void(ProcessTokenReportSnapshot&, DWORD)>& fallback) {
    ProcessTokenReportSnapshot snapshot{};
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process) {
        const DWORD error = ::GetLastError();
        snapshot.statusText = L"● 刷新失败：无法打开目标令牌";
        snapshot.reportText = L"OpenProcess failed: " + std::to_wstring(error);
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }
    std::wstring identityError;
    if (!VerifyProcessIdentity(process.get(), expectedProcessCreationTime100ns, identityError)) {
        snapshot.statusText = L"● 刷新已取消：" + identityError;
        snapshot.reportText = L"Process identity verification failed: " + identityError;
        snapshot.editorStatusText = L"行:1 列:1 字符:0 文件:<未命名> 模式:只读 编码:UTF-16";
        return snapshot;
    }
    snapshot.identityMatched = true;

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken)) {
        const DWORD error = ::GetLastError();
        if (fallback) { fallback(snapshot, error); }
        return snapshot;
    }

    ScopedHandle token(rawToken);
    std::wostringstream report;
    report << L"[Token / Security Information]\r\nPID: " << processId << L"\r\n";

    std::vector<std::byte> bytes;
    DWORD error = 0;
    if (QueryTokenBytes(token.get(), TokenUser, bytes, error)) {
        const auto* user = reinterpret_cast<const TOKEN_USER*>(bytes.data());
        report << L"User: " << SidText(user->User.Sid) << L"\r\n";
    }
    if (QueryTokenBytes(token.get(), TokenElevationType, bytes, error)) {
        const auto value = *reinterpret_cast<const TOKEN_ELEVATION_TYPE*>(bytes.data());
        report << L"ElevationType: " << (value == TokenElevationTypeFull ? L"Full" : value == TokenElevationTypeLimited ? L"Limited" : L"Default") << L"\r\n";
    }
    if (QueryTokenBytes(token.get(), TokenElevation, bytes, error)) {
        report << L"IsElevated: " << (reinterpret_cast<const TOKEN_ELEVATION*>(bytes.data())->TokenIsElevated ? L"true" : L"false") << L"\r\n";
    }
    if (QueryTokenBytes(token.get(), TokenGroups, bytes, error)) {
        const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(bytes.data());
        report << L"GroupCount: " << groups->GroupCount << L"\r\n";
        for (DWORD index = 0; index < std::min<DWORD>(groups->GroupCount, 16); ++index) {
            report << L"  - " << SidText(groups->Groups[index].Sid) << L"\r\n";
        }
    }
    if (QueryTokenBytes(token.get(), TokenPrivileges, bytes, error)) {
        const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(bytes.data());
        report << L"PrivilegeCount: " << privileges->PrivilegeCount << L"\r\n";
        for (DWORD index = 0; index < std::min<DWORD>(privileges->PrivilegeCount, 24); ++index) {
            wchar_t name[256]{};
            DWORD length = static_cast<DWORD>(std::size(name));
            ::LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&privileges->Privileges[index].Luid), name, &length);
            report << L"  - " << (*name ? name : L"<unknown>") << L" ["
                   << ((privileges->Privileges[index].Attributes & SE_PRIVILEGE_ENABLED) ? L"Enabled" : L"Disabled")
                   << L"]\r\n";
        }
    }

    report << L"\r\n[All TokenInformationClass Snapshot]\r\n";
    for (int informationClass = 1; informationClass <= 80; ++informationClass) {
        if (QueryTokenBytes(token.get(), informationClass, bytes, error)) {
            report << L"  [" << informationClass << L"] " << TokenClassName(informationClass)
                   << L": size=" << bytes.size() << L", raw=" << RawPreview(bytes) << L"\r\n";
        } else {
            report << L"  [" << informationClass << L"] " << TokenClassName(informationClass)
                   << L": queryFailed(" << error << L")\r\n";
        }
    }
    DWORD sessionId = 0;
    DWORD returnLength = 0;
    if (::GetTokenInformation(token.get(), TokenSessionId, &sessionId, sizeof(sessionId), &returnLength)) {
        report << L"SessionId: " << sessionId << L"\r\n";
    }

    snapshot.succeeded = true;
    snapshot.reportText = report.str();
    snapshot.statusText = L"● 刷新完成";
    snapshot.editorStatusText =
        L"行:1 列:1 字符:" + std::to_wstring(snapshot.reportText.size()) + L" 文件:<未命名> 模式:只读 编码:UTF-16";
    return snapshot;
}
ProcessDetailActionResult AdjustTokenPrivilegeR3(DWORD processId, ULONGLONG expectedCreationTime, const std::wstring& name, LUID luid, bool enable, ks::r3::common::UniqueHandle& process, DWORD& r3Error) {
 ProcessDetailActionResult result{};

            std::wstring identityError;
            const bool r3ProcessAvailable = OpenVerifiedProcessActionTarget(
                processId, expectedCreationTime, PROCESS_QUERY_LIMITED_INFORMATION,
                process, identityError);
            HANDLE rawToken = nullptr;
            result.identityMatched = r3ProcessAvailable;

            if (r3ProcessAvailable &&
                ::OpenProcessToken(process.get(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &rawToken)) {
                ScopedHandle token(rawToken);
                TOKEN_PRIVILEGES privileges{};
                privileges.PrivilegeCount = 1;
                privileges.Privileges[0].Luid = luid;
                privileges.Privileges[0].Attributes =
                    enable ? SE_PRIVILEGE_ENABLED : 0;
                ::SetLastError(ERROR_SUCCESS);
                const BOOL adjusted = ::AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr);
                r3Error = ::GetLastError();
                result.win32ErrorKnown = true;result.win32Error = r3Error;
                if (adjusted && r3Error == ERROR_SUCCESS) {
                    result.requestSucceeded = true;
                    result.statusText = L"● R3 已调整 " + name;
                    result.refreshTokenReport = true;
                    return result;
                }
            } else if (r3ProcessAvailable) {
                r3Error = ::GetLastError();
                result.win32ErrorKnown = true;result.win32Error = r3Error;
            }

 return result;
}
ProcessDetailActionResult WriteRawTokenValue(int informationClass, DWORD processId, ULONGLONG expectedProcessCreationTime100ns, std::vector<std::byte> payload) {

            ProcessDetailActionResult action{};
            const auto setInformation = reinterpret_cast<NtSetInformationTokenFn>(
                ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtSetInformationToken"));
            ks::r3::common::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!OpenVerifiedProcessActionTarget(
                    processId,
                    expectedProcessCreationTime100ns,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● 原始设置失败：" + identityError;
                return action;
            }
            action.identityMatched = true;
            HANDLE rawToken = nullptr;
            if (!setInformation || !::OpenProcessToken(
                    verifiedProcess.get(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &rawToken)) {
                action.unsupported = !setInformation;
                if (setInformation) {action.win32ErrorKnown = true;action.win32Error = ::GetLastError();}
                action.statusText = L"● 原始设置失败：无法打开目标令牌";
                return action;
            }
            ScopedHandle token(rawToken);
            const NTSTATUS status = setInformation(
                token.get(),
                static_cast<TOKEN_INFORMATION_CLASS>(informationClass),
                payload.data(),
                static_cast<ULONG>(payload.size()));
            action.ntStatusKnown = true;action.ntStatus = status;action.requestSucceeded = status == 0;
            std::wostringstream message;
            message << (status >= 0 ? L"● 原始设置成功：" : L"● 原始设置失败：")
                    << L"[" << informationClass << L"] " << TokenClassName(informationClass)
                    << L", size=" << payload.size() << L", status=0x"
                    << std::uppercase << std::hex << static_cast<std::uint32_t>(status);
            action.statusText = message.str();
            action.refreshTokenSwitches = true;
            action.refreshTokenReport = true;
            return action;

}
}
