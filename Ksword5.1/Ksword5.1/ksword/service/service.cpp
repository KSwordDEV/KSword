#include "service.h"

#include "../string/string.h"
#include "../../../../shared/usermode/KswordArkServiceMode.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>
#include <winsvc.h>

#pragma comment(lib, "Advapi32.lib")

namespace
{
    // Guard owns an SC_HANDLE input and closes it on destruction; it returns the raw handle via get().
    class Guard
    {
    public:
        explicit Guard(SC_HANDLE h = nullptr) : handle(h) {}
        ~Guard() { reset(nullptr); }
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        Guard(Guard&& other) noexcept : handle(other.handle) { other.handle = nullptr; }
        Guard& operator=(Guard&& other) noexcept
        {
            if (this != &other)
            {
                reset(other.handle);
                other.handle = nullptr;
            }
            return *this;
        }
        SC_HANDLE get() const { return handle; }
        bool ok() const { return handle != nullptr; }
        void reset(SC_HANDLE h) { if (handle != nullptr) { ::CloseServiceHandle(handle); } handle = h; }
    private:
        SC_HANDLE handle = nullptr;
    };

    // Clear outputs before each public call; returns no value and tolerates null output pointers.
    void clearOutputs(std::string* textOut, std::uint32_t* codeOut)
    {
        if (textOut != nullptr) { textOut->clear(); }
        if (codeOut != nullptr) { *codeOut = 0; }
    }

    // failWin32 formats a Win32 error with context and returns false for direct use in return statements.
    bool failWin32(const char* context, DWORD code, std::string* textOut, std::uint32_t* codeOut)
    {
        if (codeOut != nullptr) { *codeOut = static_cast<std::uint32_t>(code); }
        if (textOut != nullptr)
        {
            std::ostringstream os;
            if (context != nullptr && context[0] != '\0') { os << context << ": "; }
            os << ks::service::FormatWin32ErrorText(static_cast<std::uint32_t>(code));
            *textOut = os.str();
        }
        return false;
    }

    // failText writes a validation error and returns false; it does not claim a Win32 error code.
    bool failText(const char* text, std::string* textOut, std::uint32_t* codeOut)
    {
        if (codeOut != nullptr) { *codeOut = 0; }
        if (textOut != nullptr) { *textOut = (text == nullptr) ? std::string() : std::string(text); }
        return false;
    }

    bool allowScmMutation(const std::wstring& name, std::string* textOut, std::uint32_t* codeOut)
    {
        if (!ksword::ark::isKswordArkService(name)) return true;
        const auto profile = ksword::ark::queryServiceProfile();
        if (profile.scmManagementAllowed()) return true;
        return failWin32(
            "KswordARK PnP binding must be managed in Device Manager; service configuration is preserved",
            ksword::ark::serviceProfileManagementError(profile), textOut, codeOut);
    }

    // trimWide removes FormatMessage CR/LF and surrounding whitespace; it mutates the input string in place.
    void trimWide(std::wstring& text)
    {
        const auto isNotSpace = [](wchar_t ch) { return std::iswspace(static_cast<wint_t>(ch)) == 0; };
        const auto first = std::find_if(text.begin(), text.end(), isNotSpace);
        const auto last = std::find_if(text.rbegin(), text.rend(), isNotSpace).base();
        if (first >= last) { text.clear(); return; }
        text.assign(first, last);
    }

    // copyString owns a possibly null SCM string pointer as std::wstring.
    std::wstring copyString(const wchar_t* value)
    {
        return value == nullptr ? std::wstring() : std::wstring(value);
    }

    // writableOrNull exposes an owned std::wstring buffer to Win32 structs that require LPWSTR fields.
    // It returns nullptr for empty values so SCM receives "not configured" rather than a dangling pointer.
    wchar_t* writableOrNull(std::wstring& value)
    {
        return value.empty() ? nullptr : &value[0];
    }

    // copyMultiSz owns a double-null-terminated dependency list; empty MULTI_SZ returns an empty string.
    std::wstring copyMultiSz(const wchar_t* value)
    {
        if (value == nullptr || value[0] == L'\0') { return std::wstring(); }
        const wchar_t* cur = value;
        while (!(cur[0] == L'\0' && cur[1] == L'\0')) { ++cur; }
        return std::wstring(value, static_cast<std::size_t>(cur - value + 2));
    }

    // copyStatus maps SERVICE_STATUS_PROCESS into the public Qt-free data carrier.
    ks::service::ServiceStatus copyStatus(const SERVICE_STATUS_PROCESS& s)
    {
        ks::service::ServiceStatus r;
        r.serviceType = s.dwServiceType; r.currentState = s.dwCurrentState;
        r.controlsAccepted = s.dwControlsAccepted; r.win32ExitCode = s.dwWin32ExitCode;
        r.serviceSpecificExitCode = s.dwServiceSpecificExitCode; r.checkPoint = s.dwCheckPoint;
        r.waitHint = s.dwWaitHint; r.processId = s.dwProcessId; r.serviceFlags = s.dwServiceFlags;
        return r;
    }

    // openScm opens the local SCM database with the requested access and reports failure through outputs.
    Guard openScm(DWORD access, std::string* textOut, std::uint32_t* codeOut)
    {
        Guard g(::OpenSCManagerW(nullptr, nullptr, access));
        if (!g.ok()) { (void)failWin32("OpenSCManagerW failed", ::GetLastError(), textOut, codeOut); }
        return g;
    }

    // openSvc opens one service by short name; the caller provides the already-open SCM handle.
    Guard openSvc(SC_HANDLE scm, const std::wstring& name, DWORD access, std::string* textOut, std::uint32_t* codeOut)
    {
        if (scm == nullptr || name.empty())
        {
            (void)failText("openSvc received invalid arguments", textOut, codeOut);
            return Guard();
        }
        Guard g(::OpenServiceW(scm, name.c_str(), access));
        if (!g.ok()) { (void)failWin32("OpenServiceW failed", ::GetLastError(), textOut, codeOut); }
        return g;
    }

    // queryStatusByHandle reads status from an opened service handle and copies it to the public type.
    bool queryStatusByHandle(SC_HANDLE svc, ks::service::ServiceStatus* out, std::string* textOut, std::uint32_t* codeOut)
    {
        if (svc == nullptr || out == nullptr) { return failText("queryStatusByHandle received invalid arguments", textOut, codeOut); }
        SERVICE_STATUS_PROCESS s{};
        DWORD needed = 0;
        if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&s), sizeof(s), &needed) == FALSE)
        {
            return failWin32("QueryServiceStatusEx failed", ::GetLastError(), textOut, codeOut);
        }
        *out = copyStatus(s);
        return true;
    }

    // queryConfigByHandle reads QueryServiceConfigW and copies all pointer fields into owned strings.
    bool queryConfigByHandle(SC_HANDLE svc, ks::service::ServiceConfig* out, std::string* textOut, std::uint32_t* codeOut)
    {
        if (svc == nullptr || out == nullptr) { return failText("queryConfigByHandle received invalid arguments", textOut, codeOut); }
        DWORD needed = 0;
        ::SetLastError(ERROR_SUCCESS);
        (void)::QueryServiceConfigW(svc, nullptr, 0, &needed);
        const DWORD probeError = ::GetLastError();
        if (needed == 0) { return failWin32("QueryServiceConfigW size probe failed", probeError, textOut, codeOut); }
        std::vector<std::uint8_t> buf(needed, 0);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (::QueryServiceConfigW(svc, cfg, needed, &needed) == FALSE)
        {
            return failWin32("QueryServiceConfigW failed", ::GetLastError(), textOut, codeOut);
        }
        ks::service::ServiceConfig c;
        c.serviceType = cfg->dwServiceType; c.startType = cfg->dwStartType; c.errorControl = cfg->dwErrorControl;
        c.binaryPath = copyString(cfg->lpBinaryPathName); c.loadOrderGroup = copyString(cfg->lpLoadOrderGroup);
        c.tagId = cfg->dwTagId; c.dependenciesMultiSz = copyMultiSz(cfg->lpDependencies);
        c.accountName = copyString(cfg->lpServiceStartName); c.displayName = copyString(cfg->lpDisplayName);
        *out = std::move(c);
        return true;
    }

    // queryDescriptionByHandle reads SERVICE_CONFIG_DESCRIPTION; missing description is an empty successful result.
    bool queryDescriptionByHandle(SC_HANDLE svc, std::wstring* out, std::string* textOut, std::uint32_t* codeOut)
    {
        if (out != nullptr) { out->clear(); }
        if (svc == nullptr || out == nullptr) { return failText("queryDescriptionByHandle received invalid arguments", textOut, codeOut); }
        DWORD needed = 0;
        ::SetLastError(ERROR_SUCCESS);
        const BOOL probeOk = ::QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &needed);
        const DWORD probeError = ::GetLastError();
        if (needed == 0)
        {
            if (probeOk != FALSE || probeError == ERROR_SUCCESS || probeError == ERROR_INSUFFICIENT_BUFFER) { return true; }
            return failWin32("QueryServiceConfig2W(description) size probe failed", probeError, textOut, codeOut);
        }
        std::vector<std::uint8_t> buf(needed, 0);
        if (::QueryServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, buf.data(), needed, &needed) == FALSE)
        {
            return failWin32("QueryServiceConfig2W(description) failed", ::GetLastError(), textOut, codeOut);
        }
        const auto* desc = reinterpret_cast<const SERVICE_DESCRIPTIONW*>(buf.data());
        *out = copyString(desc->lpDescription);
        return true;
    }

    // queryDelayedByHandle reads the optional delayed auto-start flag and returns false when unsupported.
    bool queryDelayedByHandle(SC_HANDLE svc, bool* out)
    {
        if (out != nullptr) { *out = false; }
        if (svc == nullptr || out == nullptr) { return false; }
        SERVICE_DELAYED_AUTO_START_INFO info{};
        DWORD needed = 0;
        if (::QueryServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, reinterpret_cast<LPBYTE>(&info), sizeof(info), &needed) == FALSE)
        {
            return false;
        }
        *out = info.fDelayedAutostart != FALSE;
        return true;
    }

    // queryFullConfigByHandle requires base config and best-effort appends description/delayed-auto data.
    bool queryFullConfigByHandle(SC_HANDLE svc, ks::service::ServiceConfig* cfgOut, std::wstring* descOut, bool* hasDescOut, std::string* textOut, std::uint32_t* codeOut)
    {
        if (!queryConfigByHandle(svc, cfgOut, textOut, codeOut)) { return false; }
        bool delayed = false;
        if (queryDelayedByHandle(svc, &delayed)) { cfgOut->delayedAutoStart = delayed; cfgOut->hasDelayedAutoStart = true; }
        std::wstring desc;
        const bool descOk = queryDescriptionByHandle(svc, &desc, nullptr, nullptr);
        if (descOut != nullptr && descOk) { *descOut = std::move(desc); }
        if (hasDescOut != nullptr) { *hasDescOut = descOk; }
        return true;
    }

    // kWaitInitialSleepMs / kWaitMaxSleepMs bound the exponential backoff used by waitByHandle.
    // The first probes stay tight so a fast transition is still reported promptly, while a slow
    // one settles at two wakeups per second instead of the previous five-plus.
    constexpr DWORD kWaitInitialSleepMs = 50;
    constexpr DWORD kWaitMaxSleepMs = 500;

    // waitByHandle polls status until expectedState or timeout; finalStatus receives the last observed state.
    // The idle gap grows 50ms -> 100ms -> ... -> 500ms instead of burning a fixed 180ms tick, and each sleep is
    // clamped to the remaining budget so the caller-visible timeout is honoured at least as tightly as before.
    // Deliberately not switched to NotifyServiceStatusChange: that API keeps writing into the SERVICE_NOTIFY
    // buffer until its APC fires, and this helper does not own the SC_HANDLE it is given, so a pending
    // notification could outlive both the buffer and the handle when the wait times out.
    bool waitByHandle(SC_HANDLE svc, DWORD expectedState, DWORD timeoutMs, ks::service::ServiceStatus* finalStatus)
    {
        if (svc == nullptr) { return false; }
        if (expectedState == 0) { return queryStatusByHandle(svc, finalStatus, nullptr, nullptr); }
        const auto start = std::chrono::steady_clock::now();
        DWORD nextSleepMs = kWaitInitialSleepMs;
        for (;;)
        {
            ks::service::ServiceStatus current;
            if (!queryStatusByHandle(svc, &current, nullptr, nullptr)) { if (finalStatus != nullptr) { *finalStatus = {}; } return false; }
            if (finalStatus != nullptr) { *finalStatus = current; }
            if (current.currentState == expectedState) { return true; }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
            if (elapsed >= static_cast<long long>(timeoutMs)) { return false; }
            const long long remainingMs = static_cast<long long>(timeoutMs) - elapsed;
            const long long sleepThisRoundMs = (std::min)(static_cast<long long>(nextSleepMs), remainingMs);
            std::this_thread::sleep_for(std::chrono::milliseconds(sleepThisRoundMs));
            nextSleepMs = (std::min)(static_cast<DWORD>(nextSleepMs * 2), kWaitMaxSleepMs);
        }
    }

    // buildEnumRecord converts one enum row into a ServiceRecord and enriches config on a best-effort basis.
    ks::service::ServiceRecord buildEnumRecord(SC_HANDLE scm, const ENUM_SERVICE_STATUS_PROCESSW& item)
    {
        ks::service::ServiceRecord r;
        r.serviceName = copyString(item.lpServiceName); r.displayName = copyString(item.lpDisplayName);
        r.status = copyStatus(item.ServiceStatusProcess); r.hasStatus = true;
        std::string openError;
        Guard svc = openSvc(scm, r.serviceName, SERVICE_QUERY_CONFIG, &openError, nullptr);
        if (!svc.ok()) { r.configErrorText = openError; return r; }
        bool hasDesc = false;
        if (queryFullConfigByHandle(svc.get(), &r.config, &r.description, &hasDesc, &r.configErrorText, nullptr))
        {
            r.hasConfig = true; r.hasDescription = hasDesc;
        }
        return r;
    }
}

namespace ks::service
{
    std::string FormatWin32ErrorText(const std::uint32_t errorCode)
    {
        LPWSTR buffer = nullptr;
        const DWORD len = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            static_cast<DWORD>(errorCode),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buffer),
            0,
            nullptr);

        std::wstring message;
        if (len > 0 && buffer != nullptr)
        {
            message.assign(buffer, len);
            ::LocalFree(buffer);
        }
        trimWide(message);
        if (message.empty()) { message = L"unknown error"; }

        std::ostringstream os;
        os << errorCode << ": " << ks::str::Utf16ToUtf8(message);
        return os.str();
    }

    bool EnumerateServiceRecords(std::uint32_t typeMask, std::uint32_t stateMask, std::vector<ServiceRecord>* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr) { return failText("EnumerateServiceRecords received a null output vector", textOut, codeOut); }
        out->clear();

        Guard scm = openScm(SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }

        DWORD resume = 0;
        for (;;)
        {
            DWORD needed = 0;
            DWORD returned = 0;
            DWORD probeResume = resume;
            ::SetLastError(ERROR_SUCCESS);
            const BOOL probeOk = ::EnumServicesStatusExW(
                scm.get(),
                SC_ENUM_PROCESS_INFO,
                static_cast<DWORD>(typeMask),
                static_cast<DWORD>(stateMask),
                nullptr,
                0,
                &needed,
                &returned,
                &probeResume,
                nullptr);
            const DWORD probeError = ::GetLastError();
            if (probeOk != FALSE) { break; }
            if (probeError != ERROR_MORE_DATA) { return failWin32("EnumServicesStatusExW size probe failed", probeError, textOut, codeOut); }
            if (needed == 0) { break; }

            std::vector<std::uint8_t> buf(needed, 0);
            returned = 0;
            if (::EnumServicesStatusExW(
                scm.get(),
                SC_ENUM_PROCESS_INFO,
                static_cast<DWORD>(typeMask),
                static_cast<DWORD>(stateMask),
                buf.data(),
                static_cast<DWORD>(buf.size()),
                &needed,
                &returned,
                &resume,
                nullptr) == FALSE)
            {
                return failWin32("EnumServicesStatusExW failed", ::GetLastError(), textOut, codeOut);
            }

            const auto* rows = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
            for (DWORD i = 0; i < returned; ++i)
            {
                out->push_back(buildEnumRecord(scm.get(), rows[i]));
            }
            if (resume == 0) { break; }
        }
        return true;
    }

    bool QueryServiceRecord(const std::wstring& name, ServiceRecord* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryServiceRecord received invalid arguments", textOut, codeOut); }
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS, textOut, codeOut);
        if (!svc.ok()) { return false; }

        ServiceRecord r;
        r.serviceName = name;
        if (!queryStatusByHandle(svc.get(), &r.status, textOut, codeOut)) { return false; }
        r.hasStatus = true;
        bool hasDesc = false;
        if (!queryFullConfigByHandle(svc.get(), &r.config, &r.description, &hasDesc, textOut, codeOut)) { return false; }
        r.hasConfig = true;
        r.hasDescription = hasDesc;
        r.displayName = r.config.displayName.empty() ? name : r.config.displayName;
        *out = std::move(r);
        return true;
    }

    bool QueryServiceStatus(const std::wstring& name, ServiceStatus* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryServiceStatus received invalid arguments", textOut, codeOut); }
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_QUERY_STATUS, textOut, codeOut);
        if (!svc.ok()) { return false; }
        return queryStatusByHandle(svc.get(), out, textOut, codeOut);
    }

    bool QueryServiceConfig(const std::wstring& name, ServiceConfig* out, std::wstring* descOut, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryServiceConfig received invalid arguments", textOut, codeOut); }
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_QUERY_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }
        bool hasDesc = false;
        return queryFullConfigByHandle(svc.get(), out, descOut, &hasDesc, textOut, codeOut);
    }

    bool QueryServiceDescription(const std::wstring& name, std::wstring* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryServiceDescription received invalid arguments", textOut, codeOut); }
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_QUERY_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }
        return queryDescriptionByHandle(svc.get(), out, textOut, codeOut);
    }

    bool QueryServiceConfig2Raw(const std::wstring& name, std::uint32_t infoLevel, std::vector<std::uint8_t>* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryServiceConfig2Raw received invalid arguments", textOut, codeOut); }
        out->clear();
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_QUERY_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }

        DWORD needed = 0;
        ::SetLastError(ERROR_SUCCESS);
        (void)::QueryServiceConfig2W(svc.get(), static_cast<DWORD>(infoLevel), nullptr, 0, &needed);
        const DWORD probeError = ::GetLastError();
        if (needed == 0)
        {
            return failWin32("QueryServiceConfig2W size probe failed", probeError, textOut, codeOut);
        }
        out->assign(needed, 0);
        if (::QueryServiceConfig2W(svc.get(), static_cast<DWORD>(infoLevel), out->data(), needed, &needed) == FALSE)
        {
            out->clear();
            return failWin32("QueryServiceConfig2W failed", ::GetLastError(), textOut, codeOut);
        }
        return true;
    }

    bool QueryDependentServiceNames(const std::wstring& name, std::uint32_t stateMask, std::vector<std::wstring>* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryDependentServiceNames received invalid arguments", textOut, codeOut); }
        out->clear();
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_ENUMERATE_DEPENDENTS, textOut, codeOut);
        if (!svc.ok()) { return false; }

        DWORD needed = 0;
        DWORD count = 0;
        ::SetLastError(ERROR_SUCCESS);
        const BOOL probeOk = ::EnumDependentServicesW(svc.get(), static_cast<DWORD>(stateMask), nullptr, 0, &needed, &count);
        const DWORD probeError = ::GetLastError();
        if (needed == 0)
        {
            if (probeOk != FALSE || probeError == ERROR_SUCCESS || probeError == ERROR_MORE_DATA) { return true; }
            return failWin32("EnumDependentServicesW size probe failed", probeError, textOut, codeOut);
        }

        std::vector<std::uint8_t> buf(needed, 0);
        if (::EnumDependentServicesW(
            svc.get(),
            static_cast<DWORD>(stateMask),
            reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data()),
            needed,
            &needed,
            &count) == FALSE)
        {
            return failWin32("EnumDependentServicesW failed", ::GetLastError(), textOut, codeOut);
        }

        const auto* rows = reinterpret_cast<const ENUM_SERVICE_STATUSW*>(buf.data());
        out->reserve(count);
        for (DWORD i = 0; i < count; ++i)
        {
            out->push_back(copyString(rows[i].lpServiceName));
        }
        return true;
    }

    bool QueryServiceSecuritySddl(const std::wstring& name, std::uint32_t securityInformation, std::wstring* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryServiceSecuritySddl received invalid arguments", textOut, codeOut); }
        out->clear();
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, READ_CONTROL, textOut, codeOut);
        if (!svc.ok()) { return false; }

        DWORD needed = 0;
        ::SetLastError(ERROR_SUCCESS);
        (void)::QueryServiceObjectSecurity(svc.get(), static_cast<SECURITY_INFORMATION>(securityInformation), nullptr, 0, &needed);
        const DWORD probeError = ::GetLastError();
        if (needed == 0) { return failWin32("QueryServiceObjectSecurity size probe failed", probeError, textOut, codeOut); }
        std::vector<std::uint8_t> buf(needed, 0);
        if (::QueryServiceObjectSecurity(
            svc.get(),
            static_cast<SECURITY_INFORMATION>(securityInformation),
            reinterpret_cast<PSECURITY_DESCRIPTOR>(buf.data()),
            needed,
            &needed) == FALSE)
        {
            return failWin32("QueryServiceObjectSecurity failed", ::GetLastError(), textOut, codeOut);
        }

        LPWSTR sddl = nullptr;
        if (::ConvertSecurityDescriptorToStringSecurityDescriptorW(
            reinterpret_cast<PSECURITY_DESCRIPTOR>(buf.data()),
            SDDL_REVISION_1,
            static_cast<SECURITY_INFORMATION>(securityInformation),
            &sddl,
            nullptr) == FALSE || sddl == nullptr)
        {
            return failWin32("ConvertSecurityDescriptorToStringSecurityDescriptorW failed", ::GetLastError(), textOut, codeOut);
        }
        *out = sddl;
        ::LocalFree(sddl);
        return true;
    }

    bool CanOpenServiceWithAccess(const std::wstring& name, std::uint32_t desiredAccess)
    {
        if (name.empty()) { return false; }
        Guard scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm.ok()) { return false; }
        Guard svc(::OpenServiceW(scm.get(), name.c_str(), static_cast<DWORD>(desiredAccess)));
        return svc.ok();
    }

    bool StartServiceByName(const std::wstring& name, std::uint32_t timeoutMs, std::uint32_t expectedState, ServiceStatus* finalStatus, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (name.empty()) { return failText("StartServiceByName received an empty service name", textOut, codeOut); }
        if (ksword::ark::isKswordArkService(name))
        {
            const auto profile = ksword::ark::queryServiceProfile();
            if (profile.profile == ksword::ark::ServiceProfile::Unknown)
                return failWin32(
                    "Cannot read the KswordARK service profile; service configuration is preserved",
                    ksword::ark::serviceProfileManagementError(profile), textOut, codeOut);
            if (profile.profile == ksword::ark::ServiceProfile::StorageControllerPnp)
            {
                Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
                if (!scm.ok()) return false;
                Guard svc = openSvc(scm.get(), name, SERVICE_QUERY_STATUS, textOut, codeOut);
                if (!svc.ok()) return false;
                ServiceStatus current;
                if (!queryStatusByHandle(svc.get(), &current, textOut, codeOut)) return false;
                if (finalStatus) *finalStatus = current;
                if (current.currentState == SERVICE_RUNNING) return true;
                return failWin32(
                    "Start the bound KswordARK storage controller in Device Manager",
                    ERROR_SERVICE_NOT_ACTIVE, textOut, codeOut);
            }
        }
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_START | SERVICE_QUERY_STATUS, textOut, codeOut);
        if (!svc.ok()) { return false; }
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        if (::StartServiceW(svc.get(), 0, nullptr) == FALSE)
        {
            const DWORD err = ::GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) { return failWin32("StartServiceW failed", err, textOut, codeOut); }
        }
        (void)waitByHandle(svc.get(), static_cast<DWORD>(expectedState), static_cast<DWORD>(timeoutMs), finalStatus);
        return true;
    }

    bool ControlServiceByName(const std::wstring& name, std::uint32_t access, std::uint32_t controlCode, std::uint32_t timeoutMs, std::uint32_t expectedState, ServiceStatus* finalStatus, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (name.empty()) { return failText("ControlServiceByName received an empty service name", textOut, codeOut); }
        if (controlCode != SERVICE_CONTROL_INTERROGATE && !allowScmMutation(name, textOut, codeOut)) return false;
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, static_cast<DWORD>(access) | SERVICE_QUERY_STATUS, textOut, codeOut);
        if (!svc.ok()) { return false; }
        SERVICE_STATUS ignored{};
        if (controlCode != SERVICE_CONTROL_INTERROGATE && !allowScmMutation(name, textOut, codeOut)) return false;
        if (::ControlService(svc.get(), static_cast<DWORD>(controlCode), &ignored) == FALSE)
        {
            const DWORD err = ::GetLastError();
            if (!(controlCode == SERVICE_CONTROL_STOP && err == ERROR_SERVICE_NOT_ACTIVE)) { return failWin32("ControlService failed", err, textOut, codeOut); }
        }
        (void)waitByHandle(svc.get(), static_cast<DWORD>(expectedState), static_cast<DWORD>(timeoutMs), finalStatus);
        return true;
    }

    bool StopServiceByName(const std::wstring& name, std::uint32_t timeoutMs, std::uint32_t expectedState, ServiceStatus* finalStatus, std::string* textOut, std::uint32_t* codeOut)
    {
        return ControlServiceByName(name, SERVICE_STOP, SERVICE_CONTROL_STOP, timeoutMs, expectedState, finalStatus, textOut, codeOut);
    }

    bool DeleteServiceByName(const std::wstring& name, bool stopFirst, std::uint32_t stopTimeoutMs, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (name.empty()) { return failText("DeleteServiceByName received an empty service name", textOut, codeOut); }
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS, textOut, codeOut);
        if (!svc.ok()) { return false; }
        if (stopFirst)
        {
            ServiceStatus current;
            if (queryStatusByHandle(svc.get(), &current, nullptr, nullptr) && current.currentState != SERVICE_STOPPED)
            {
                SERVICE_STATUS ignored{};
                if (!allowScmMutation(name, textOut, codeOut)) return false;
                (void)::ControlService(svc.get(), SERVICE_CONTROL_STOP, &ignored);
                ServiceStatus finalStatus;
                (void)waitByHandle(svc.get(), SERVICE_STOPPED, static_cast<DWORD>(stopTimeoutMs), &finalStatus);
            }
        }
        if (!stopFirst)
        {
            ServiceStatus verifiedStatus;
            if (!queryStatusByHandle(svc.get(), &verifiedStatus, textOut, codeOut)) { return false; }
            if (verifiedStatus.currentState != SERVICE_STOPPED)
            {
                return failWin32(
                    "DeleteServiceByName refused a service that is not stopped",
                    ERROR_BUSY,
                    textOut,
                    codeOut);
            }
        }
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        if (::DeleteService(svc.get()) == FALSE)
        {
            const DWORD err = ::GetLastError();
            if (err != ERROR_SERVICE_MARKED_FOR_DELETE) { return failWin32("DeleteService failed", err, textOut, codeOut); }
        }
        return true;
    }

    bool CreateOrUpdateKernelDriverService(const KernelDriverServiceConfig& cfg, bool* createdOut, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (createdOut != nullptr) { *createdOut = false; }
        if (cfg.serviceName.empty() || cfg.binaryPath.empty())
        {
            return failText("CreateOrUpdateKernelDriverService requires serviceName and binaryPath", textOut, codeOut);
        }
        if (!allowScmMutation(cfg.serviceName, textOut, codeOut)) return false;

        Guard scm = openScm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE, textOut, codeOut);
        if (!scm.ok()) { return false; }
        // Create/update only requires config access; avoid over-requesting start/stop/delete rights.
        constexpr DWORD desired = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG;

        Guard svc(::OpenServiceW(scm.get(), cfg.serviceName.c_str(), desired));
        bool created = false;
        if (!svc.ok())
        {
            const DWORD openErr = ::GetLastError();
            if (openErr != ERROR_SERVICE_DOES_NOT_EXIST) { return failWin32("OpenServiceW failed", openErr, textOut, codeOut); }
            if (!allowScmMutation(cfg.serviceName, textOut, codeOut)) return false;
            SC_HANDLE raw = ::CreateServiceW(
                scm.get(),
                cfg.serviceName.c_str(),
                cfg.displayName.empty() ? cfg.serviceName.c_str() : cfg.displayName.c_str(),
                desired,
                SERVICE_KERNEL_DRIVER,
                static_cast<DWORD>(cfg.startType),
                static_cast<DWORD>(cfg.errorControl),
                cfg.binaryPath.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr);
            if (raw == nullptr) { return failWin32("CreateServiceW failed", ::GetLastError(), textOut, codeOut); }
            svc.reset(raw);
            created = true;
        }

        if (!allowScmMutation(cfg.serviceName, textOut, codeOut)) return false;
        if (::ChangeServiceConfigW(
            svc.get(),
            SERVICE_KERNEL_DRIVER,
            static_cast<DWORD>(cfg.startType),
            static_cast<DWORD>(cfg.errorControl),
            cfg.binaryPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            cfg.displayName.empty() ? nullptr : cfg.displayName.c_str()) == FALSE)
        {
            return failWin32("ChangeServiceConfigW failed", ::GetLastError(), textOut, codeOut);
        }

        SERVICE_DESCRIPTIONW desc{};
        std::wstring mutableDesc = cfg.description;
        desc.lpDescription = writableOrNull(mutableDesc);
        if (!allowScmMutation(cfg.serviceName, textOut, codeOut)) return false;
        (void)::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, reinterpret_cast<LPBYTE>(&desc));
        if (createdOut != nullptr) { *createdOut = created; }
        return true;
    }

    bool ChangeServiceConfiguration(const std::wstring& name, const ServiceConfigUpdate& update, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (name.empty()) { return failText("ChangeServiceConfiguration received an empty service name", textOut, codeOut); }
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_CHANGE_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }

        const DWORD serviceType = update.changeServiceType ? static_cast<DWORD>(update.serviceType) : SERVICE_NO_CHANGE;
        const DWORD startType = update.changeStartType ? static_cast<DWORD>(update.startType) : SERVICE_NO_CHANGE;
        const DWORD errorControl = update.changeErrorControl ? static_cast<DWORD>(update.errorControl) : SERVICE_NO_CHANGE;
        const wchar_t* binaryPath = update.changeBinaryPath ? update.binaryPath.c_str() : nullptr;
        const wchar_t* group = update.changeLoadOrderGroup ? update.loadOrderGroup.c_str() : nullptr;
        const wchar_t* deps = update.changeDependencies ? update.dependenciesMultiSz.c_str() : nullptr;
        const wchar_t* account = update.changeAccount ? update.accountName.c_str() : nullptr;
        const wchar_t* password = update.changePassword ? update.password.c_str() : nullptr;
        const wchar_t* display = update.changeDisplayName ? update.displayName.c_str() : nullptr;

        if (!allowScmMutation(name, textOut, codeOut)) return false;
        if (::ChangeServiceConfigW(svc.get(), serviceType, startType, errorControl, binaryPath, group, nullptr, deps, account, password, display) == FALSE)
        {
            return failWin32("ChangeServiceConfigW failed", ::GetLastError(), textOut, codeOut);
        }
        return true;
    }

    bool SetServiceDescription(const std::wstring& name, const std::wstring& description, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (name.empty()) { return failText("SetServiceDescription received an empty service name", textOut, codeOut); }
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_CHANGE_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }
        SERVICE_DESCRIPTIONW desc{};
        std::wstring mutableDesc = description;
        desc.lpDescription = writableOrNull(mutableDesc);
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        if (::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, reinterpret_cast<LPBYTE>(&desc)) == FALSE)
        {
            return failWin32("ChangeServiceConfig2W(description) failed", ::GetLastError(), textOut, codeOut);
        }
        return true;
    }

    bool SetDelayedAutoStart(const std::wstring& name, bool delayedAutoStart, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (name.empty()) { return failText("SetDelayedAutoStart received an empty service name", textOut, codeOut); }
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_CHANGE_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }
        SERVICE_DELAYED_AUTO_START_INFO info{};
        info.fDelayedAutostart = delayedAutoStart ? TRUE : FALSE;
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        if (::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DELAYED_AUTO_START_INFO, reinterpret_cast<LPBYTE>(&info)) == FALSE)
        {
            return failWin32("ChangeServiceConfig2W(delayed auto-start) failed", ::GetLastError(), textOut, codeOut);
        }
        return true;
    }

    bool QueryServiceFailureSettings(const std::wstring& name, FailureSettings* out, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (out == nullptr || name.empty()) { return failText("QueryServiceFailureSettings received invalid arguments", textOut, codeOut); }
        *out = FailureSettings{};
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_QUERY_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }

        DWORD needed = 0;
        ::SetLastError(ERROR_SUCCESS);
        const BOOL probeOk = ::QueryServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, nullptr, 0, &needed);
        const DWORD probeErr = ::GetLastError();
        if (needed > 0)
        {
            std::vector<std::uint8_t> buf(needed, 0);
            if (::QueryServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, buf.data(), needed, &needed) == FALSE)
            {
                return failWin32("QueryServiceConfig2W(failure actions) failed", ::GetLastError(), textOut, codeOut);
            }
            const auto* src = reinterpret_cast<const SERVICE_FAILURE_ACTIONSW*>(buf.data());
            out->hasFailureActions = true;
            out->resetPeriodSeconds = src->dwResetPeriod;
            out->rebootMessage = copyString(src->lpRebootMsg);
            out->command = copyString(src->lpCommand);
            if (src->lpsaActions != nullptr)
            {
                for (DWORD i = 0; i < src->cActions; ++i)
                {
                    FailureAction action;
                    action.type = static_cast<std::uint32_t>(src->lpsaActions[i].Type);
                    action.delayMs = src->lpsaActions[i].Delay;
                    out->actions.push_back(action);
                }
            }
        }
        else if (probeOk == FALSE && probeErr != ERROR_SUCCESS && probeErr != ERROR_INSUFFICIENT_BUFFER)
        {
            return failWin32("QueryServiceConfig2W(failure actions) size probe failed", probeErr, textOut, codeOut);
        }

        SERVICE_FAILURE_ACTIONS_FLAG flag{};
        DWORD flagBytes = 0;
        if (::QueryServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, reinterpret_cast<LPBYTE>(&flag), sizeof(flag), &flagBytes) != FALSE)
        {
            out->hasFailureActionsFlag = true;
            out->failureActionsOnNonCrash = flag.fFailureActionsOnNonCrashFailures != FALSE;
        }
        return true;
    }

    bool ApplyServiceFailureSettings(const std::wstring& name, const FailureSettings& settings, std::string* textOut, std::uint32_t* codeOut)
    {
        clearOutputs(textOut, codeOut);
        if (name.empty()) { return failText("ApplyServiceFailureSettings received an empty service name", textOut, codeOut); }
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        Guard scm = openScm(SC_MANAGER_CONNECT, textOut, codeOut);
        if (!scm.ok()) { return false; }
        Guard svc = openSvc(scm.get(), name, SERVICE_CHANGE_CONFIG, textOut, codeOut);
        if (!svc.ok()) { return false; }

        std::vector<SC_ACTION> actions;
        actions.reserve(settings.actions.size());
        for (const FailureAction& item : settings.actions)
        {
            SC_ACTION a{};
            a.Type = static_cast<SC_ACTION_TYPE>(item.type);
            a.Delay = static_cast<DWORD>(item.delayMs);
            actions.push_back(a);
        }

        std::wstring reboot = settings.rebootMessage;
        std::wstring command = settings.command;
        SERVICE_FAILURE_ACTIONSW info{};
        info.dwResetPeriod = static_cast<DWORD>(settings.resetPeriodSeconds);
        info.lpRebootMsg = writableOrNull(reboot);
        info.lpCommand = writableOrNull(command);
        info.cActions = static_cast<DWORD>(actions.size());
        info.lpsaActions = actions.empty() ? nullptr : actions.data();
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        if (::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, reinterpret_cast<LPBYTE>(&info)) == FALSE)
        {
            return failWin32("ChangeServiceConfig2W(failure actions) failed", ::GetLastError(), textOut, codeOut);
        }

        SERVICE_FAILURE_ACTIONS_FLAG flag{};
        flag.fFailureActionsOnNonCrashFailures = settings.failureActionsOnNonCrash ? TRUE : FALSE;
        if (!allowScmMutation(name, textOut, codeOut)) return false;
        if (::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, reinterpret_cast<LPBYTE>(&flag)) == FALSE)
        {
            return failWin32("ChangeServiceConfig2W(failure actions flag) failed", ::GetLastError(), textOut, codeOut);
        }
        return true;
    }
}
