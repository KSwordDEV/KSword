#include "CodeIntegrity.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
#include <wincrypt.h>
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
CommandResult RunCaptureCommand(const std::wstring& commandLine, const DWORD timeoutMs,const std::function<bool()>& cancelled) {
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
    if(!::SetHandleInformation(readPipe,HANDLE_FLAG_INHERIT,0)){result.win32Error=::GetLastError();::CloseHandle(readPipe);::CloseHandle(writePipe);return result;}
    const auto close=[&](HANDLE handle){::SetLastError(0);if(!::CloseHandle(handle)&&!result.closeError)result.closeError=::GetLastError();};

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
    const DWORD createError=created?0: ::GetLastError();close(writePipe);

    if (!created) {
        result.win32Error = createError;
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
        DWORD available=0;for(unsigned batch=0;batch<32;++batch){
            if(!::PeekNamedPipe(readPipe,nullptr,0,nullptr,&available,nullptr)){const auto error=::GetLastError();if(error!=ERROR_BROKEN_PIPE)result.outputError=error;break;}if(!available)break;
            DWORD read=0;const auto chunk=(std::min<DWORD>)(available,static_cast<DWORD>(buffer.size()));
            if(!::ReadFile(readPipe,buffer.data(),chunk,&read,nullptr)){const auto error=::GetLastError();if(error!=ERROR_BROKEN_PIPE)result.outputError=error;break;}if(!read)break;
            const auto room=128u*1024u-bytes.size(),retain=(std::min<std::size_t>)(room,read);bytes.append(buffer.data(),retain);
            if(retain<read&&!outputLimitHit){result.errorText+=L" 输出超过 128KB，已截断。";outputLimitHit=result.outputTruncated=true;}
        }
        const DWORD wait = ::WaitForSingleObject(process.hProcess, 25);
        if (wait == WAIT_OBJECT_0) {
            result.waitCompleted=true;processFinished = true;
        } else if (wait == WAIT_FAILED) {
            result.win32Error = ::GetLastError();
            result.errorText = L"WaitForSingleObject failed: " + GetLastErrorText(result.win32Error);
            processFinished = true;
        } else if ((cancelled&&cancelled())||::GetTickCount64() >= deadline) {
            result.cancelled=cancelled&&cancelled();result.timedOut=!result.cancelled;
            result.exitCode = 258;
            result.errorText = L"查询超时，已停止本地只读辅助进程。";
            processFinished = true;
        }
    }

    if(!result.waitCompleted){result.terminated=::TerminateProcess(process.hProcess,258)!=FALSE;result.terminationError=result.terminated?0: ::GetLastError();result.terminationWait=::WaitForSingleObject(process.hProcess,2000);}
    DWORD available=0;for(unsigned batch=0;batch<32;++batch){if(!::PeekNamedPipe(readPipe,nullptr,0,nullptr,&available,nullptr)){const auto error=::GetLastError();if(error!=ERROR_BROKEN_PIPE)result.outputError=error;break;}if(!available)break;
        DWORD read=0;const auto chunk=(std::min<DWORD>)(available,static_cast<DWORD>(buffer.size()));if(!::ReadFile(readPipe,buffer.data(),chunk,&read,nullptr)){const auto error=::GetLastError();if(error!=ERROR_BROKEN_PIPE)result.outputError=error;break;}if(!read)break;
        const auto room=128u*1024u-bytes.size(),retain=(std::min<std::size_t>)(room,read);bytes.append(buffer.data(),retain);if(retain<read&&!outputLimitHit){result.errorText+=L" 输出超过 128KB，已截断。";outputLimitHit=result.outputTruncated=true;}}
    DWORD exitCode = ERROR_PROCESS_ABORTED;
    if (::GetExitCodeProcess(process.hProcess, &exitCode)) {
        result.exitCode = exitCode;result.exitCodeKnown=exitCode!=STILL_ACTIVE;
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
        const int required = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
        if (required > 0) {
            result.output.assign(static_cast<std::size_t>(required), L'\0');
            ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), result.output.data(), required);
        } else {
            result.decodeMalformed=true;const int fallback = ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
            if (fallback > 0) {
                result.output.assign(static_cast<std::size_t>(fallback), L'\0');
                ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), result.output.data(), fallback);
            }
        }
    }

    close(readPipe);close(process.hThread);close(process.hProcess);
    return result;
}
std::wstring PowerShellCommand(const std::wstring& script) {
    return L"powershell.exe -NoLogo -NoProfile -NonInteractive -Command " +
        QuotePowerShellCommand(script);
}
CommandResult RunPowerShellJson(const std::wstring& body,DWORD timeoutMs,const std::function<bool()>& cancelled){
    const auto script=L"[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';try { "+body+
        L" } catch { [ordered]@{available=$false;exceptionType=$_.Exception.GetType().FullName;exceptionHResult=('0x{0:x8}' -f $_.Exception.HResult);errorId=$_.FullyQualifiedErrorId;message=$_.Exception.Message}|ConvertTo-Json -Compress -Depth 8; exit 5 }";
    CommandResult failed;DWORD chars=0;const auto bytes=static_cast<DWORD>(script.size()*sizeof(wchar_t));
    if(!::CryptBinaryToStringW(reinterpret_cast<const BYTE*>(script.data()),bytes,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,nullptr,&chars)){failed.win32Error=::GetLastError();return failed;}
    std::wstring encoded(chars,L'\0');if(!::CryptBinaryToStringW(reinterpret_cast<const BYTE*>(script.data()),bytes,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,encoded.data(),&chars)){failed.win32Error=::GetLastError();return failed;}while(!encoded.empty()&&encoded.back()==L'\0')encoded.pop_back();
    wchar_t directory[MAX_PATH]{};const auto count=::GetSystemDirectoryW(directory,MAX_PATH);if(!count||count>=MAX_PATH){failed.win32Error=count?ERROR_INSUFFICIENT_BUFFER: ::GetLastError();return failed;}
    return RunCaptureCommand(L"\""+std::wstring(directory)+L"\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -NonInteractive -EncodedCommand "+encoded,timeoutMs,cancelled);
}
SecuritySnapshot CollectSecurityProbes(const std::vector<SecurityProbe>& probes,const SecurityProbeOptions& options){SecuritySnapshot snapshot;snapshot.requestedCount=probes.size();const auto deadline=::GetTickCount64()+options.durationMs;
    for(const auto& probe:probes){if(options.cancelled&&options.cancelled()){snapshot.cancelled=true;break;}const auto now=::GetTickCount64();if(now>=deadline){snapshot.limited=true;break;}SecurityProbeResult result;result.probe=probe;
        if(probe.kind==SecurityProbeKind::Command){result.command=RunPowerShellJson(probe.body,static_cast<DWORD>((std::min<ULONGLONG>)(options.timeoutMs,deadline-now)),options.cancelled);const auto& c=result.command;
            result.code=c.decodeMalformed?4:c.outputTruncated||c.cancelled?6:c.timedOut||!c.started||c.win32Error||c.outputError||!c.exitCodeKnown||!c.waitCompleted?3:c.closeError?6:c.exitCode==0?0:c.exitCode==5?5:c.exitCode==6?6:3;
        }else if(probe.kind==SecurityProbeKind::Registry){auto& e=result.registry;
            [&]{HKEY key=nullptr;e.openAttempted=true;e.openError=static_cast<DWORD>(::RegOpenKeyExW(HKEY_LOCAL_MACHINE,probe.path.c_str(),0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key));
                if(e.openError){e.absent=e.openError==ERROR_FILE_NOT_FOUND||e.openError==ERROR_PATH_NOT_FOUND;return;}if(!key){e.malformed=true;return;}
                struct Owner{HKEY key;SecurityRegistryEvidence& e;~Owner(){e.closeAttempted=true;e.closeError=static_cast<DWORD>(::RegCloseKey(key));e.closed=e.closeError==0;}} owner{key,e};e.opened=true;e.queryAttempted=true;
                DWORD size=0;e.queryError=static_cast<DWORD>(::RegQueryValueExW(key,probe.name.c_str(),nullptr,&e.type,nullptr,&size));e.reportedBytes=size;
                if(e.queryError){e.absent=e.queryError==ERROR_FILE_NOT_FOUND;return;}
                for(int attempt=0;attempt<4;++attempt){if(size>65536){e.limited=true;return;}e.bytes.assign(size,std::uint8_t{});DWORD actual=size;BYTE empty=0;
                    e.queryError=static_cast<DWORD>(::RegQueryValueExW(key,probe.name.c_str(),nullptr,&e.type,size?e.bytes.data():&empty,&actual));e.reportedBytes=actual;
                    if(e.queryError==ERROR_MORE_DATA){size=actual;continue;}if(e.queryError){e.absent=e.queryError==ERROR_FILE_NOT_FOUND;return;}if(actual>size){e.malformed=true;return;}e.bytes.resize(actual);
                    e.malformed=(e.type==REG_DWORD&&actual!=4)||(e.type==REG_QWORD&&actual!=8)||((e.type==REG_SZ||e.type==REG_EXPAND_SZ||e.type==REG_MULTI_SZ)&&(actual%2));e.available=!e.malformed;return;
                }e.limited=true;
            }();result.code=e.malformed?4:e.limited||(e.closeAttempted&&!e.closed)?6:e.absent?0:!e.available?3:0;
        }else{auto& e=result.service;
            [&]{SC_HANDLE scm=::OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!scm){e.error=::GetLastError();return;}
                struct Manager{SC_HANDLE handle;SecurityServiceEvidence& e;~Manager(){e.scmCloseAttempted=true;e.scmClosed=::CloseServiceHandle(handle)!=FALSE;if(!e.scmClosed&&!e.closeError)e.closeError=::GetLastError();}} manager{scm,e};e.scmOpened=true;
                SC_HANDLE service=::OpenServiceW(scm,probe.name.c_str(),SERVICE_QUERY_STATUS);if(!service){e.error=::GetLastError();e.absent=e.error==ERROR_SERVICE_DOES_NOT_EXIST;return;}
                struct Service{SC_HANDLE handle;SecurityServiceEvidence& e;~Service(){e.serviceCloseAttempted=true;e.serviceClosed=::CloseServiceHandle(handle)!=FALSE;if(!e.serviceClosed&&!e.closeError)e.closeError=::GetLastError();}} owner{service,e};e.opened=true;
                DWORD needed=0;e.available=::QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&e.status),sizeof(e.status),&needed)!=FALSE;e.error=e.available?0: ::GetLastError();
            }();result.code=!e.available&&!e.absent?3:(e.serviceCloseAttempted&&!e.serviceClosed)||(e.scmCloseAttempted&&!e.scmClosed)?6:0;
        }snapshot.results.push_back(std::move(result));
    }return snapshot;
}
const std::vector<SecurityProbe>& CodeIntegrityProbes(){static const std::vector<SecurityProbe> probes{
    {L"device-guard",L"CIM root/Microsoft/Windows/DeviceGuard:Win32_DeviceGuard",SecurityProbeKind::Command,
        L"$dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop;if($null -eq $dg){[ordered]@{available=$false}|ConvertTo-Json -Compress;exit 5};[ordered]@{available=$true;availableSecurityProperties=@($dg.AvailableSecurityProperties);securityServicesConfigured=@($dg.SecurityServicesConfigured);securityServicesRunning=@($dg.SecurityServicesRunning);codeIntegrityPolicyEnforcementStatus=$dg.CodeIntegrityPolicyEnforcementStatus;usermodeCodeIntegrityPolicyEnforcementStatus=$dg.UsermodeCodeIntegrityPolicyEnforcementStatus}|ConvertTo-Json -Compress -Depth 8",{},{}},
    {L"policy-files",L"CodeIntegrity disk directory file counts",SecurityProbeKind::Command,
        L"$partial=$false;$paths=@((Join-Path $env:windir 'System32\\CodeIntegrity\\CiPolicies\\Active'),(Join-Path $env:windir 'System32\\CodeIntegrity'));$items=@(foreach($p in $paths){try{if(Test-Path -LiteralPath $p -ErrorAction Stop){$files=@(Get-ChildItem -LiteralPath $p -File -ErrorAction Stop);[ordered]@{path=$p;known=$true;present=$true;fileCount=[string]$files.Count}}else{[ordered]@{path=$p;known=$true;present=$false;fileCount=$null}}}catch{$partial=$true;[ordered]@{path=$p;known=$false;present=$null;fileCount=$null;error=$_.Exception.Message}}});[ordered]@{available=$true;directories=$items}|ConvertTo-Json -Compress -Depth 8;if($partial){exit 6}",{},{}},
    {L"upgraded-system",L"HKLM64 CI Policy UpgradedSystem",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy",L"UpgradedSystem"},
    {L"enabled",L"HKLM64 CI Config Enabled",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",L"Enabled"},
    {L"secure-boot-cache",L"HKLM64 cached SecureBoot state",SecurityProbeKind::Registry,{},L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",L"UEFISecureBootEnabled"},
    {L"ci-service",L"SCM CI driver service status",SecurityProbeKind::Service,{},{},L"CI"}};return probes;}
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
        L"$paths=@((Join-Path $env:windir 'System32\\CodeIntegrity\\CiPolicies\\Active'),(Join-Path $env:windir 'System32\\CodeIntegrity')); "
        L"foreach($p in $paths){ if(Test-Path $p){ $c=(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | Measure-Object).Count; Write-Output ($p + '=' + $c) } else { Write-Output ($p + '=missing') } }"));
    AddRegistryRow(rows, L"Code Integrity / WDAC", L"Policy UpgradedSystem", L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"UpgradedSystem");
    AddRegistryRow(rows, L"Code Integrity / WDAC", L"Code Integrity Enabled", L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"Enabled");
    AddRegistryRow(rows, L"Code Integrity / WDAC", L"Secure Boot state cache", L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled");
    AddServiceRow(rows, L"Code Integrity / WDAC", L"Code Integrity driver", L"CI");


}
}
