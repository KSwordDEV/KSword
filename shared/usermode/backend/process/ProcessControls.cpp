#include "ProcessControls.h"
#include "../../../../shared/ProcessTerminateMethods.h"
#include <algorithm>
#include <functional>
#include <iomanip>
#include <sstream>
#include <tlhelp32.h>
#include <unordered_map>
#include <unordered_set>
namespace ks::r3::process {
namespace {
constexpr ULONG kProcessBreakOnTerminationInfoClass = 29UL;
constexpr ULONG kProcessPowerThrottlingInfoClass = 4UL;
constexpr ULONG kProcessPowerThrottlingCurrentVersion = 1UL;
constexpr ULONG kProcessPowerThrottlingExecutionSpeed = 0x1UL;
constexpr DWORD kProcessSuspendResumeAccess = 0x0800UL;
using NtSuspendProcessFn = LONG(NTAPI*)(HANDLE);
using NtResumeProcessFn = LONG(NTAPI*)(HANDLE);
using NtSetInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using SetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);
struct ProcessPowerThrottlingStateNative {
    ULONG version = 0;
    ULONG controlMask = 0;
    ULONG stateMask = 0;
};
}
std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    const int required = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (required > 0) {
        std::wstring wide(static_cast<std::size_t>(required), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), wide.data(), required);
        return wide;
    }

    std::wstring fallback;
    fallback.reserve(text.size());
    for (const unsigned char ch : text) {
        fallback.push_back(static_cast<wchar_t>(ch));
    }
    return fallback;
}
std::wstring PidListText(const std::vector<DWORD>& pids) {
    std::wstring text;
    for (std::size_t i = 0; i < pids.size(); ++i) {
        if (i != 0) {
            text += L", ";
        }
        text += std::to_wstring(pids[i]);
    }
    return text.empty() ? L"<none>" : text;
}
const ProcessSnapshotRow* FindRowByPid(const std::vector<ProcessSnapshotRow>& rows, DWORD pid) {
    const auto it = std::find_if(rows.begin(), rows.end(), [pid](const ProcessSnapshotRow& row) {
        return row.processId == pid;
    });
    return it == rows.end() ? nullptr : &*it;
}
std::vector<ProcessSnapshotRow> BuildProcessActionTargets(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows) {
    std::vector<ProcessSnapshotRow> targets;
    targets.reserve(selectedPids.size());
    std::unordered_set<DWORD> visitedPids;
    visitedPids.reserve(selectedPids.size());
    for (const DWORD pid : selectedPids) {
        if (pid == 0U || !visitedPids.insert(pid).second) {
            continue;
        }
        const ProcessSnapshotRow* row = FindRowByPid(snapshotRows, pid);
        if (row != nullptr) {
            targets.push_back(*row);
            continue;
        }
        ProcessSnapshotRow missingTarget{};
        missingTarget.processId = pid;
        targets.push_back(std::move(missingTarget));
    }
    return targets;
}
std::vector<DWORD> CollectR3ProcessTreePids(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows) {
    std::unordered_map<DWORD, std::vector<DWORD>> childrenByParentPid;
    std::unordered_set<DWORD> r3PidSet;
    childrenByParentPid.reserve(snapshotRows.size());
    r3PidSet.reserve(snapshotRows.size());

    for (const ProcessSnapshotRow& row : snapshotRows) {
        if (row.r0KernelOnly || row.processId == 0U || !r3PidSet.insert(row.processId).second) {
            continue;
        }
        childrenByParentPid[row.parentProcessId].push_back(row.processId);
    }

    for (auto& childPair : childrenByParentPid) {
        std::vector<DWORD>& childPids = childPair.second;
        std::sort(childPids.begin(), childPids.end());
    }

    std::vector<DWORD> treePids;
    treePids.reserve(r3PidSet.size());
    std::unordered_set<DWORD> visitedPids;
    visitedPids.reserve(r3PidSet.size());
    std::function<void(DWORD)> appendSubtree;
    appendSubtree =
        [&childrenByParentPid, &treePids, &visitedPids, &appendSubtree](const DWORD processId) {
        if (!visitedPids.insert(processId).second) {
            return;
        }

        const auto childIt = childrenByParentPid.find(processId);
        if (childIt != childrenByParentPid.end()) {
            for (const DWORD childPid : childIt->second) {
                appendSubtree(childPid);
            }
        }
        treePids.push_back(processId);
    };

    for (const DWORD selectedPid : selectedPids) {
        if (r3PidSet.find(selectedPid) != r3PidSet.end()) {
            appendSubtree(selectedPid);
        }
    }
    return treePids;
}
ProcessActionResult FailureResult(const wchar_t* title, const std::vector<DWORD>& pids, const wchar_t* reason) {
    ProcessActionResult result;
    result.success = false;
    result.title = title;
    result.detail = std::wstring(reason) + L"\r\nTarget PID(s): " + PidListText(pids);
    return result;
}
std::wstring Win32ErrorText(const DWORD error) {
    return L"Win32 " + std::to_wstring(error) + L": " + ks::r3::common::LastErrorMessage(error);
}
std::wstring Hex32(const LONG status) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<std::uint32_t>(status);
    return stream.str();
}
std::wstring Hex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}
std::wstring AsciiLiteralToWide(const char* text) {
    if (!text) {
        return {};
    }
    std::wstring wide;
    while (*text) {
        wide.push_back(static_cast<wchar_t>(*text));
        ++text;
    }
    return wide;
}
FARPROC NtProc(const char* name) {
    if (!name || name[0] == '\0') {
        return nullptr;
    }
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    return ntdll ? ::GetProcAddress(ntdll, name) : nullptr;
}
bool EnableCurrentProcessPrivilege(const wchar_t* privilegeName, std::wstring& detail) {
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
        detail = L"OpenProcessToken failed: " + Win32ErrorText(::GetLastError());
        return false;
    }
    ks::r3::common::UniqueHandle token(rawToken);

    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        detail = L"LookupPrivilegeValueW failed: " + Win32ErrorText(::GetLastError());
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!::AdjustTokenPrivileges(token.get(), FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        detail = L"AdjustTokenPrivileges failed: " + Win32ErrorText(::GetLastError());
        return false;
    }

    const DWORD adjustError = ::GetLastError();
    if (adjustError != ERROR_SUCCESS) {
        detail = L"AdjustTokenPrivileges did not assign privilege: " + Win32ErrorText(adjustError);
        return false;
    }
    detail = std::wstring(privilegeName ? privilegeName : L"<null>") + L" enabled";
    return true;
}
void AppendIoLine(std::wstring& detail, DWORD pid, const wchar_t* operation, bool ok, const std::wstring& message) {
    detail += L"PID " + std::to_wstring(pid) + L" ";
    detail += operation;
    detail += ok ? L": OK" : L": FAIL";
    if (!message.empty()) {
        detail += L" | ";
        detail += message;
    }
    detail += L"\r\n";
}
void AppendIoLine(std::wstring& detail, const wchar_t* operation, bool ok, const std::wstring& message) {
    detail += operation;
    detail += ok ? L": OK" : L": FAIL";
    if (!message.empty()) {
        detail += L" | ";
        detail += message;
    }
    detail += L"\r\n";
}
bool IsProtectedSystemPid(DWORD pid) {
    return pid == 0 || pid <= 4;
}
bool IsProcessPresentBySnapshot(DWORD pid, bool* queryOkOut) {
    if (queryOkOut) {
        *queryOkOut = false;
    }

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return true;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot, &entry)) {
        ::CloseHandle(snapshot);
        return true;
    }

    bool present = false;
    do {
        if (entry.th32ProcessID == pid) {
            present = true;
            break;
        }
    } while (::Process32NextW(snapshot, &entry));

    ::CloseHandle(snapshot);
    if (queryOkOut) {
        *queryOkOut = true;
    }
    return present;
}
ks::r3::common::UniqueHandle OpenProcessForAction(
    const DWORD pid,
    const ULONGLONG expectedCreationTime100ns,
    const DWORD access,
    std::wstring& errorText,
    const bool rejectProtected) {
    if (rejectProtected && IsProtectedSystemPid(pid)) {
        errorText = L"protected system PID";
        return ks::r3::common::UniqueHandle();
    }
    if (expectedCreationTime100ns == 0U) {
        errorText = L"process identity is unavailable; action skipped";
        return ks::r3::common::UniqueHandle();
    }

    const DWORD requestedAccess = access | PROCESS_QUERY_LIMITED_INFORMATION;
    HANDLE process = ::OpenProcess(requestedAccess, FALSE, pid);
    if (!process) {
        errorText = L"OpenProcess failed: " + Win32ErrorText(::GetLastError());
        return ks::r3::common::UniqueHandle();
    }

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
        errorText = L"GetProcessTimes failed: " + Win32ErrorText(::GetLastError());
        ::CloseHandle(process);
        return ks::r3::common::UniqueHandle();
    }
    const ULONGLONG actualCreationTime100ns =
        (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(creationTime.dwLowDateTime);
    if (actualCreationTime100ns == 0U || actualCreationTime100ns != expectedCreationTime100ns) {
        errorText = L"process identity changed (PID was reused); action skipped";
        ::CloseHandle(process);
        return ks::r3::common::UniqueHandle();
    }
    return ks::r3::common::UniqueHandle(process);
}
ProcessActionResult ExecuteMultiMethodTerminate(const std::vector<ProcessSnapshotRow>& actionTargets) {
    ProcessActionResult result;
    result.title = L"结束进程(组合方法链)";
    result.success = true;

    const auto& methods = ks::process::TerminateMethodTable();

    for (const ProcessSnapshotRow& target : actionTargets) {
        const DWORD pid = target.processId;
        if (IsProtectedSystemPid(pid)) {
            AppendIoLine(result.detail, pid, L"组合结束", false, L"protected system PID");
            result.success = false;
            continue;
        }

        std::wstring identityError;
        ks::r3::common::UniqueHandle verifiedProcess = OpenProcessForAction(
            pid,
            target.creationTime100ns,
            PROCESS_QUERY_LIMITED_INFORMATION,
            identityError);
        if (!verifiedProcess.valid()) {
            AppendIoLine(result.detail, pid, L"组合结束", false, identityError);
            result.success = false;
            continue;
        }
        // verifiedProcess stays open through all PID-only fallback methods.

        bool queryOk = false;
        if (!IsProcessPresentBySnapshot(pid, &queryOk)) {
            AppendIoLine(result.detail, pid, L"组合结束", true, L"目标进程已不存在，无需执行结束动作。");
            continue;
        }

        std::wostringstream detail;
        detail << L"PID " << pid;
        if (!queryOk) {
            detail << L" | 初始存在性检查失败，继续执行方法链";
        }

        bool processExited = false;
        constexpr int kTerminateRoundLimit = 2;
        for (int round = 1; round <= kTerminateRoundLimit && !processExited; ++round) {
            for (const auto& method : methods) {
                std::string methodDetail;
                const bool invokeOk = method.invokeMethod(pid, &methodDetail);
                bool postQueryOk = false;
                const bool stillPresent = IsProcessPresentBySnapshot(pid, &postQueryOk);
                detail << L"\r\n  Round " << round << L" | " << method.wideName
                       << L" | " << (invokeOk ? L"调用成功" : L"调用失败")
                       << L" | " << Utf8ToWide(methodDetail.empty() ? "无附加信息" : methodDetail.c_str());
                if (postQueryOk) {
                    detail << (stillPresent ? L" | 进程仍在运行" : L" | 已确认退出");
                } else {
                    detail << L" | 存在性检查失败，按仍在运行处理";
                }
                if (!stillPresent) {
                    processExited = true;
                    break;
                }
            }
        }

        detail << (processExited ? L"\r\n  结果：已确认退出。" : L"\r\n  结果：两轮方法链后进程仍在运行。");
        result.detail += detail.str();
        result.detail += L"\r\n";
        result.success = result.success && processExited;
    }
    return result;
}
bool NtSuspendOrResumeProcess(DWORD pid, ULONGLONG expectedCreationTime100ns, bool resume, std::wstring& message) {
    const char* exportName = resume ? "NtResumeProcess" : "NtSuspendProcess";
    const FARPROC proc = NtProc(exportName);
    if (!proc) {
        message = AsciiLiteralToWide(exportName) + L" not available";
        return false;
    }

    std::wstring openError;
    ks::r3::common::UniqueHandle process = OpenProcessForAction(pid, expectedCreationTime100ns, kProcessSuspendResumeAccess, openError);
    if (!process.valid()) {
        message = openError;
        return false;
    }

    const LONG status = resume
        ? reinterpret_cast<NtResumeProcessFn>(proc)(process.get())
        : reinterpret_cast<NtSuspendProcessFn>(proc)(process.get());
    if (status >= 0) {
        message = Hex32(status);
        return true;
    }
    message = AsciiLiteralToWide(exportName) + L" failed: " + Hex32(status);
    return false;
}
bool SetCriticalFlagForPid(DWORD pid, ULONGLONG expectedCreationTime100ns, bool enable, std::wstring& message) {
    std::wstring privilegeDetail;
    (void)EnableCurrentProcessPrivilege(SE_DEBUG_NAME, privilegeDetail);

    const FARPROC proc = NtProc("NtSetInformationProcess");
    if (!proc) {
        message = L"NtSetInformationProcess not available";
        return false;
    }

    std::wstring openError;
    ks::r3::common::UniqueHandle process = OpenProcessForAction(pid, expectedCreationTime100ns, PROCESS_SET_INFORMATION, openError);
    if (!process.valid()) {
        message = openError;
        return false;
    }

    ULONG critical = enable ? 1UL : 0UL;
    const LONG status = reinterpret_cast<NtSetInformationProcessFn>(proc)(
        process.get(),
        kProcessBreakOnTerminationInfoClass,
        &critical,
        static_cast<ULONG>(sizeof(critical)));
    if (status >= 0) {
        message = privilegeDetail.empty() ? Hex32(status) : privilegeDetail + L"; " + Hex32(status);
        return true;
    }
    message = L"NtSetInformationProcess(ProcessBreakOnTermination) failed: " + Hex32(status);
    if (!privilegeDetail.empty()) {
        message += L"; " + privilegeDetail;
    }
    return false;
}
bool SetEfficiencyModeForPid(DWORD pid, ULONGLONG expectedCreationTime100ns, bool enable, std::wstring& message) {
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const FARPROC proc = kernel32 ? ::GetProcAddress(kernel32, "SetProcessInformation") : nullptr;
    if (!proc) {
        message = L"SetProcessInformation(ProcessPowerThrottling) not available";
        return false;
    }

    std::wstring openError;
    ks::r3::common::UniqueHandle process = OpenProcessForAction(pid, expectedCreationTime100ns, PROCESS_SET_INFORMATION, openError);
    if (!process.valid()) {
        message = openError;
        return false;
    }

    ProcessPowerThrottlingStateNative powerState{};
    powerState.version = kProcessPowerThrottlingCurrentVersion;
    powerState.controlMask = kProcessPowerThrottlingExecutionSpeed;
    powerState.stateMask = enable ? kProcessPowerThrottlingExecutionSpeed : 0UL;
    const BOOL ok = reinterpret_cast<SetProcessInformationFn>(proc)(
        process.get(),
        kProcessPowerThrottlingInfoClass,
        &powerState,
        static_cast<DWORD>(sizeof(powerState)));
    if (ok) {
        message = enable ? L"Efficiency mode enabled" : L"Efficiency mode disabled";
        return true;
    }
    message = L"SetProcessInformation(ProcessPowerThrottling) failed: " + Win32ErrorText(::GetLastError());
    return false;
}
bool SetPriorityForPid(
    DWORD pid,
    ULONGLONG expectedCreationTime100ns,
    DWORD priorityClass,
    std::wstring& detail) {
    std::wstring openError;
    ks::r3::common::UniqueHandle process = OpenProcessForAction(
        pid,
        expectedCreationTime100ns,
        PROCESS_SET_INFORMATION,
        openError);
    if (!process.valid()) {
        detail += L"PID " + std::to_wstring(pid) + L": " + openError + L"\r\n";
        return false;
    }
    const BOOL ok = ::SetPriorityClass(process.get(), priorityClass);
    const DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
    detail += L"PID " + std::to_wstring(pid) + (ok ? L": SetPriorityClass OK" : L": SetPriorityClass failed ") +
        (ok ? L"" : std::to_wstring(error)) + L"\r\n";
    return ok != FALSE;
}
ProcessActionResult ExecuteLocalProcessAction(
    ProcessActionId actionId,
    const std::vector<ProcessSnapshotRow>& actionTargets) {
    ProcessActionResult result;
    result.success = true;
    bool handled = true;
    const wchar_t* operation = L"";
    switch (actionId) {
    case ProcessActionId::SuspendProcess:
        result.title = L"挂起进程";
        operation = L"NtSuspendProcess";
        break;
    case ProcessActionId::ResumeProcess:
        result.title = L"恢复进程";
        operation = L"NtResumeProcess";
        break;
    case ProcessActionId::EnableEfficiencyMode:
        result.title = L"开启效率模式";
        operation = L"Efficiency on";
        break;
    case ProcessActionId::DisableEfficiencyMode:
        result.title = L"关闭效率模式";
        operation = L"Efficiency off";
        break;
    case ProcessActionId::SetCriticalProcess:
        result.title = L"设为关键进程";
        operation = L"Critical on";
        break;
    case ProcessActionId::ClearCriticalProcess:
        result.title = L"取消关键进程";
        operation = L"Critical off";
        break;
    default:
        handled = false;
        break;
    }

    if (!handled) {
        result.success = false;
        result.title = L"进程动作";
        result.detail = L"未知本地进程动作。";
        return result;
    }

    for (const ProcessSnapshotRow& target : actionTargets) {
        const DWORD pid = target.processId;
        const ULONGLONG expectedCreationTime100ns = target.creationTime100ns;
        std::wstring message;
        bool ok = false;
        switch (actionId) {
        case ProcessActionId::SuspendProcess:
            ok = NtSuspendOrResumeProcess(pid, expectedCreationTime100ns, false, message);
            break;
        case ProcessActionId::ResumeProcess:
            ok = NtSuspendOrResumeProcess(pid, expectedCreationTime100ns, true, message);
            break;
        case ProcessActionId::EnableEfficiencyMode:
            ok = SetEfficiencyModeForPid(pid, expectedCreationTime100ns, true, message);
            break;
        case ProcessActionId::DisableEfficiencyMode:
            ok = SetEfficiencyModeForPid(pid, expectedCreationTime100ns, false, message);
            break;
        case ProcessActionId::SetCriticalProcess:
            ok = SetCriticalFlagForPid(pid, expectedCreationTime100ns, true, message);
            break;
        case ProcessActionId::ClearCriticalProcess:
            ok = SetCriticalFlagForPid(pid, expectedCreationTime100ns, false, message);
            break;
        default:
            message = L"unknown action";
            ok = false;
            break;
        }
        AppendIoLine(result.detail, pid, operation, ok, message);
        result.success = result.success && ok;
    }
    return result;
}
DWORD PriorityClassForAction(ProcessActionId actionId) {
    switch (actionId) {
    case ProcessActionId::SetPriorityIdle: return IDLE_PRIORITY_CLASS;
    case ProcessActionId::SetPriorityBelowNormal: return BELOW_NORMAL_PRIORITY_CLASS;
    case ProcessActionId::SetPriorityNormal: return NORMAL_PRIORITY_CLASS;
    case ProcessActionId::SetPriorityAboveNormal: return ABOVE_NORMAL_PRIORITY_CLASS;
    case ProcessActionId::SetPriorityHigh: return HIGH_PRIORITY_CLASS;
    case ProcessActionId::SetPriorityRealtime: return REALTIME_PRIORITY_CLASS;
    default: return 0;
    }
}
ProcessActionResult TerminateProcesses(const std::vector<ProcessSnapshotRow>& actionTargets) {

        ProcessActionResult result;
        result.title = L"结束进程";
        result.success = true;
        for (const ProcessSnapshotRow& target : actionTargets) {
            const DWORD pid = target.processId;
            if (IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, L"TerminateProcess", false, L"protected system PID");
                result.success = false;
                continue;
            }
            std::wstring openError;
            ks::r3::common::UniqueHandle process = OpenProcessForAction(
                pid,
                target.creationTime100ns,
                PROCESS_TERMINATE,
                openError);
            if (!process.valid()) {
                AppendIoLine(result.detail, pid, L"TerminateProcess", false, openError);
                result.success = false;
                continue;
            }
            const BOOL ok = ::TerminateProcess(process.get(), static_cast<UINT>(0xC0000005u));
            const DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
            AppendIoLine(result.detail, pid, L"TerminateProcess", ok != FALSE, ok ? L"" : L"Win32 error " + std::to_wstring(error));
            result.success = result.success && ok != FALSE;
        }
        return result;

}
}
