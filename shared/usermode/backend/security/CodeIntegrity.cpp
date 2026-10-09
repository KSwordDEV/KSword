#include "CodeIntegrity.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
std::wstring TrimCopy(const std::wstring& text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::iswspace(text[begin])) {
        ++begin;
    }
    std::size_t end = text.size();
    while (end > begin && std::iswspace(text[end - 1])) {
        --end;
    }
    return text.substr(begin, end - begin);
}
std::wstring CollapseWhitespace(const std::wstring& text) {
    std::wstring out;
    bool inWhitespace = false;
    for (wchar_t ch : text) {
        if (std::iswspace(ch)) {
            if (!inWhitespace && !out.empty()) {
                out.push_back(L' ');
            }
            inWhitespace = true;
            continue;
        }
        inWhitespace = false;
        out.push_back(ch);
    }
    return TrimCopy(out);
}
std::wstring QuotePowerShellCommand(const std::wstring& text) {
    return L"\"& { " + text + L" }\"";
}
std::wstring GetLastErrorText(const DWORD error) {
    if (error == 0) {
        return L"0";
    }
    wchar_t* message = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD chars = ::FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::wstring result = L"Win32=" + std::to_wstring(error);
    if (chars != 0 && message) {
        result += L" (" + TrimCopy(message) + L")";
    }
    if (message) {
        ::LocalFree(message);
    }
    return result;
}
void AppendRow(
    std::vector<MiscAuditRow>& rows,
    std::wstring category,
    std::wstring item,
    std::wstring state,
    std::wstring source,
    std::wstring risk,
    std::wstring detail) {
    rows.push_back(MiscAuditRow{
        std::move(category),
        std::move(item),
        std::move(state),
        std::move(source),
        std::move(risk),
        std::move(detail),
    });
}
CommandResult RunCaptureCommand(const std::wstring& commandLine, const DWORD timeoutMs) {
    CommandResult result;
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!::CreatePipe(&readPipe, &writePipe, &security, 0)) {
        result.win32Error = ::GetLastError();
        result.errorText = L"CreatePipe failed: " + GetLastErrorText(result.win32Error);
        return result;
    }
    ::SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdOutput = writePipe;
    startup.hStdError = writePipe;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION process{};
    std::wstring mutableCommand = commandLine;
    const BOOL created = ::CreateProcessW(
        nullptr,
        mutableCommand.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup,
        &process);
    ::CloseHandle(writePipe);

    if (!created) {
        result.win32Error = ::GetLastError();
        result.errorText = L"CreateProcessW failed: " + GetLastErrorText(result.win32Error);
        ::CloseHandle(readPipe);
        return result;
    }

    result.started = true;
    std::string bytes;
    std::array<char, 4096> buffer{};
    const ULONGLONG deadline = ::GetTickCount64() + timeoutMs;
    bool processFinished = false;
    bool outputLimitHit = false;
    while (!processFinished) {
        DWORD available = 0;
        while (!outputLimitHit &&
            ::PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) &&
            available > 0) {
            DWORD read = 0;
            const DWORD chunk = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
            if (!::ReadFile(readPipe, buffer.data(), chunk, &read, nullptr) || read == 0) {
                break;
            }
            bytes.append(buffer.data(), buffer.data() + read);
            if (bytes.size() > 128 * 1024) {
                result.errorText += L" 输出超过 128KB，已截断。";
                outputLimitHit = true;
                break;
            }
        }

        const DWORD wait = ::WaitForSingleObject(process.hProcess, 25);
        if (wait == WAIT_OBJECT_0) {
            processFinished = true;
        } else if (wait == WAIT_FAILED) {
            result.win32Error = ::GetLastError();
            result.errorText = L"WaitForSingleObject failed: " + GetLastErrorText(result.win32Error);
            processFinished = true;
        } else if (::GetTickCount64() >= deadline) {
            ::TerminateProcess(process.hProcess, 258);
            result.exitCode = 258;
            result.errorText = L"查询超时，已停止本地只读辅助进程。";
            processFinished = true;
        }
    }

    if (!outputLimitHit) {
        DWORD available = 0;
        while (::PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available > 0) {
            DWORD read = 0;
            const DWORD chunk = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
            if (!::ReadFile(readPipe, buffer.data(), chunk, &read, nullptr) || read == 0) {
                break;
            }
            bytes.append(buffer.data(), buffer.data() + read);
            if (bytes.size() > 128 * 1024) {
                result.errorText += L" 输出超过 128KB，已截断。";
                break;
            }
        }
    }

    DWORD exitCode = ERROR_PROCESS_ABORTED;
    if (::GetExitCodeProcess(process.hProcess, &exitCode)) {
        result.exitCode = exitCode;
    }
    else {
        const DWORD exitCodeError = ::GetLastError();
        if (result.win32Error == ERROR_SUCCESS) {
            result.win32Error = exitCodeError;
        }
        if (result.errorText.empty()) {
            result.errorText = GetLastErrorText(exitCodeError);
        }
    }
    if (result.exitCode == STILL_ACTIVE) {
        result.exitCode = 258;
    }

    if (!bytes.empty()) {
        const int required = ::MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
        if (required > 0) {
            result.output.assign(static_cast<std::size_t>(required), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), result.output.data(), required);
        } else {
            const int fallback = ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
            if (fallback > 0) {
                result.output.assign(static_cast<std::size_t>(fallback), L'\0');
                ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), result.output.data(), fallback);
            }
        }
    }

    ::CloseHandle(readPipe);
    ::CloseHandle(process.hThread);
    ::CloseHandle(process.hProcess);
    return result;
}
std::wstring PowerShellCommand(const std::wstring& script) {
    return L"powershell.exe -NoLogo -NoProfile -NonInteractive -Command " +
        QuotePowerShellCommand(script);
}
CommandResult RunPowerShellScalar(const std::wstring& script, const DWORD timeoutMs) {
    return RunCaptureCommand(PowerShellCommand(script), timeoutMs);
}
void AddCommandRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& source,
    const CommandResult& command,
    const std::wstring& cleanHint) {
    const std::wstring output = CollapseWhitespace(command.output);
    if (command.started
        && command.win32Error == ERROR_SUCCESS
        && command.errorText.empty()
        && command.exitCode == 0
        && !output.empty()) {
        AppendRow(rows, category, item, cleanHint, source, L"Info", output);
        return;
    }

    std::wstring detail = command.errorText;
    if (!output.empty()) {
        if (!detail.empty()) {
            detail += L" ";
        }
        detail += output;
    }
    if (detail.empty()) {
        detail = command.started
            ? (L"查询进程退出码=" + std::to_wstring(command.exitCode))
            : (L"查询未启动，" + GetLastErrorText(command.win32Error));
    }
    AppendRow(rows, category, item, L"Unavailable", source, L"Unknown", detail);
}
bool QueryRegistryValueString(const std::wstring& subKey, const std::wstring& valueName, std::wstring& valueOut, std::wstring& errorOut) {
    HKEY key = nullptr;
    const LONG open = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (open != ERROR_SUCCESS) {
        errorOut = L"RegOpenKeyExW failed: " + GetLastErrorText(static_cast<DWORD>(open));
        return false;
    }

    DWORD type = 0;
    DWORD bytes = 0;
    LONG query = ::RegQueryValueExW(key, valueName.c_str(), nullptr, &type, nullptr, &bytes);
    if (query != ERROR_SUCCESS) {
        ::RegCloseKey(key);
        errorOut = L"RegQueryValueExW(size) failed: " + GetLastErrorText(static_cast<DWORD>(query));
        return false;
    }

    std::vector<unsigned char> data(std::max<DWORD>(bytes, sizeof(wchar_t)) + sizeof(wchar_t), 0);
    query = ::RegQueryValueExW(key, valueName.c_str(), nullptr, &type, data.data(), &bytes);
    ::RegCloseKey(key);
    if (query != ERROR_SUCCESS) {
        errorOut = L"RegQueryValueExW(data) failed: " + GetLastErrorText(static_cast<DWORD>(query));
        return false;
    }

    if (type == REG_DWORD && bytes >= sizeof(DWORD)) {
        DWORD value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        valueOut = std::to_wstring(value) + L" (0x";
        std::wostringstream stream;
        stream << std::hex << std::uppercase << value;
        valueOut += stream.str() + L")";
        return true;
    }
    if ((type == REG_SZ || type == REG_EXPAND_SZ) && bytes >= sizeof(wchar_t)) {
        valueOut.assign(reinterpret_cast<const wchar_t*>(data.data()));
        return true;
    }
    if (type == REG_MULTI_SZ && bytes >= sizeof(wchar_t)) {
        const wchar_t* multi = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t chars = bytes / sizeof(wchar_t);
        std::wstring joined;
        std::size_t offset = 0;
        while (offset < chars && multi[offset] != L'\0') {
            std::wstring part = &multi[offset];
            if (!joined.empty()) {
                joined += L"; ";
            }
            joined += part;
            offset += part.size() + 1;
        }
        valueOut = joined;
        return true;
    }

    valueOut = L"Type=" + std::to_wstring(type) + L", Bytes=" + std::to_wstring(bytes);
    return true;
}
void AddRegistryRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& subKey,
    const std::wstring& valueName) {
    std::wstring value;
    std::wstring error;
    if (QueryRegistryValueString(subKey, valueName, value, error)) {
        AppendRow(rows, category, item, L"已查询", L"Registry HKLM", L"Info", value);
    } else {
        AppendRow(rows, category, item, L"Unavailable", L"Registry HKLM", L"Unknown", error);
    }
}
bool QueryServiceStatusText(const std::wstring& serviceName, std::wstring& statusOut, std::wstring& errorOut) {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        errorOut = L"OpenSCManagerW failed: " + GetLastErrorText(::GetLastError());
        return false;
    }
    SC_HANDLE service = ::OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        const DWORD error = ::GetLastError();
        ::CloseServiceHandle(scm);
        errorOut = L"OpenServiceW failed: " + GetLastErrorText(error);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!::QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
        const DWORD error = ::GetLastError();
        ::CloseServiceHandle(service);
        ::CloseServiceHandle(scm);
        errorOut = L"QueryServiceStatusEx failed: " + GetLastErrorText(error);
        return false;
    }

    const wchar_t* stateText = L"Unknown";
    switch (status.dwCurrentState) {
    case SERVICE_STOPPED: stateText = L"Stopped"; break;
    case SERVICE_START_PENDING: stateText = L"StartPending"; break;
    case SERVICE_STOP_PENDING: stateText = L"StopPending"; break;
    case SERVICE_RUNNING: stateText = L"Running"; break;
    case SERVICE_CONTINUE_PENDING: stateText = L"ContinuePending"; break;
    case SERVICE_PAUSE_PENDING: stateText = L"PausePending"; break;
    case SERVICE_PAUSED: stateText = L"Paused"; break;
    default: break;
    }
    statusOut = stateText;
    statusOut += L"; Type=0x";
    std::wostringstream stream;
    stream << std::hex << std::uppercase << status.dwServiceType;
    statusOut += stream.str();
    if (status.dwProcessId != 0) {
        statusOut += L"; PID=" + std::to_wstring(status.dwProcessId);
    }

    ::CloseServiceHandle(service);
    ::CloseServiceHandle(scm);
    return true;
}
void AddServiceRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& serviceName) {
    std::wstring status;
    std::wstring error;
    if (QueryServiceStatusText(serviceName, status, error)) {
        const bool running = status.find(L"Running") != std::wstring::npos;
        AppendRow(rows, category, item, running ? L"Present" : L"Not running", L"SCM query", running ? L"Info" : L"Unknown", serviceName + L": " + status);
    } else {
        AppendRow(rows, category, item, L"Unavailable", L"SCM query", L"Unknown", serviceName + L": " + error);
    }
}
void AppendCodeIntegrityR3(std::vector<MiscAuditRow>& rows) {




    AddCommandRow(rows, L"Code Integrity / WDAC", L"SystemCodeIntegrityInformation", L"PowerShell Get-CimInstance Win32_DeviceGuard", RunPowerShellScalar(
        L"$dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop; "
        L"'AvailableSecurityProperties=' + (($dg.AvailableSecurityProperties)-join ',') + '; SecurityServicesConfigured=' + (($dg.SecurityServicesConfigured)-join ',') + '; SecurityServicesRunning=' + (($dg.SecurityServicesRunning)-join ',') + '; CodeIntegrityPolicyEnforcementStatus=' + $dg.CodeIntegrityPolicyEnforcementStatus + '; UsermodeCodeIntegrityPolicyEnforcementStatus=' + $dg.UsermodeCodeIntegrityPolicyEnforcementStatus"));
    AddCommandRow(rows, L"Code Integrity / WDAC", L"CI policy files", L"PowerShell Get-ChildItem", RunPowerShellScalar(
        L"$paths=@('$env:windir\\System32\\CodeIntegrity\\CiPolicies\\Active','$env:windir\\System32\\CodeIntegrity'); "
        L"foreach($p in $paths){ if(Test-Path $p){ $c=(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | Measure-Object).Count; Write-Output ($p + '=' + $c) } else { Write-Output ($p + '=missing') } }"));
    AddRegistryRow(rows, L"Code Integrity / WDAC", L"Policy UpgradedSystem", L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"UpgradedSystem");
    AddRegistryRow(rows, L"Code Integrity / WDAC", L"Code Integrity Enabled", L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"Enabled");
    AddRegistryRow(rows, L"Code Integrity / WDAC", L"Secure Boot state cache", L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled");
    AddServiceRow(rows, L"Code Integrity / WDAC", L"Code Integrity driver", L"CI");


}
}
