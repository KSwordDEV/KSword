#include "ProcessBasicInfoSupport.h"
#include "ProcessBasicInfo.h"
#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <sstream>
#include <utility>
#pragma comment(lib, "Psapi.lib")
namespace ks::r3::process_detail::detail {
std::wstring Win32ErrorText(const wchar_t* operation, DWORD errorCode) {
    return std::wstring(operation) + L" failed: " + ks::r3::common::LastErrorMessage(errorCode);
}
std::wstring QueryProcessImagePath(HANDLE process, ProcessQueryEvidence* evidence) {
    if (evidence) *evidence = {};
    std::wstring path(kMaxPathBufferChars, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    if (::QueryFullProcessImageNameW(process, 0, path.data(), &length)) {
        if (evidence) evidence->available = true;
        path.resize(length);
        return path;
    }
    const DWORD error = ::GetLastError();
    if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = error;}
    return L"<image path unavailable: " + ks::r3::common::LastErrorMessage(error) + L">";
}
std::wstring LeafNameFromPath(const std::wstring& path) {
    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return path;
    }
    return separator + 1U < path.size() ? path.substr(separator + 1U) : std::wstring{};
}
void QuerySnapshotIdentity(
    DWORD processId,
    DWORD& parentProcessIdInOut,
    std::wstring& processNameOut,
    std::wstring& parentProcessNameOut,
    DWORD& threadCountOut, ProcessQueryEvidence* evidence) {
    if (evidence) *evidence = {};
    ks::r3::common::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid()) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ::GetLastError();}
        return;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot.get(), &entry)) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ::GetLastError();}
        return;
    }
    do {
        if (entry.th32ProcessID == processId) {
            if (evidence) evidence->available = true;
            processNameOut = entry.szExeFile;
            threadCountOut = entry.cntThreads;
            if (parentProcessIdInOut == 0) {
                parentProcessIdInOut = entry.th32ParentProcessID;
            }
        }
        if (parentProcessIdInOut != 0 && entry.th32ProcessID == parentProcessIdInOut) {
            parentProcessNameOut = entry.szExeFile;
        }
    } while (::Process32NextW(snapshot.get(), &entry));
    const DWORD snapshotError = ::GetLastError();
    if (evidence && snapshotError != ERROR_NO_MORE_FILES) { evidence->win32ErrorKnown = true; evidence->win32Error = snapshotError; }

    // The parent row can sort before the target row, so restart once when the
    // target supplied its PPID after that row had already passed.
    if (parentProcessIdInOut != 0 && parentProcessNameOut.empty()) {
        entry = {};
        entry.dwSize = sizeof(entry);
        if (::Process32FirstW(snapshot.get(), &entry)) {
            do {
                if (entry.th32ProcessID == parentProcessIdInOut) {
                    parentProcessNameOut = entry.szExeFile;
                    break;
                }
            } while (::Process32NextW(snapshot.get(), &entry));
        }
    }
}
std::wstring FormatProcessStartTime(const FILETIME& creationTime) {
    FILETIME localTime{};
    SYSTEMTIME systemTime{};
    if (!::FileTimeToLocalFileTime(&creationTime, &localTime) ||
        !::FileTimeToSystemTime(&localTime, &systemTime)) {
        return L"<start time unavailable>";
    }

    wchar_t text[32]{};
    _snwprintf_s(
        text,
        _countof(text),
        _TRUNCATE,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond);
    return text;
}
std::wstring PriorityClassText(DWORD priorityClass) {
    switch (priorityClass) {
    case IDLE_PRIORITY_CLASS: return L"Idle";
    case BELOW_NORMAL_PRIORITY_CLASS: return L"Below Normal";
    case NORMAL_PRIORITY_CLASS: return L"Normal";
    case ABOVE_NORMAL_PRIORITY_CLASS: return L"Above Normal";
    case HIGH_PRIORITY_CLASS: return L"High";
    case REALTIME_PRIORITY_CLASS: return L"Realtime";
    default: return L"<priority unavailable>";
    }
}
ULONGLONG SaturatingAdd64(ULONGLONG left, ULONGLONG right) {
    const ULONGLONG maximum = (std::numeric_limits<ULONGLONG>::max)();
    return right > maximum - left ? maximum : left + right;
}
DWORD QueryProcessSession(DWORD processId, bool& okOut) {
    DWORD sessionId = 0;
    okOut = ::ProcessIdToSessionId(processId, &sessionId) != FALSE;
    return sessionId;
}
void QueryTokenText(
    HANDLE process,
    std::wstring& userOut,
    std::wstring& integrityOut,
    bool& isAdminOut,
    bool& adminKnownOut, ProcessBasicInfo* evidenceOut) {
    ProcessBasicInfo local;
    if (!evidenceOut) evidenceOut = &local;
    auto& userEvidence = evidenceOut->evidence[L"token-user"];
    auto& integrityEvidence = evidenceOut->evidence[L"integrity"];
    auto& elevationEvidence = evidenceOut->evidence[L"elevation"];
    userEvidence = {}; integrityEvidence = {}; elevationEvidence = {};
    isAdminOut = false;
    adminKnownOut = false;
    ks::r3::common::UniqueHandle token;
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process, TOKEN_QUERY, &rawToken)) {
        const DWORD errorCode = ::GetLastError();
        for (auto* item : {&userEvidence, &integrityEvidence, &elevationEvidence}) {item->win32ErrorKnown = true; item->win32Error = errorCode;}
        const std::wstring error = ks::r3::common::LastErrorMessage(errorCode);
        userOut = L"<token unavailable: " + error + L">";
        integrityOut = L"<token unavailable: " + error + L">";
        return;
    }
    token.reset(rawToken);

    TOKEN_ELEVATION elevation{};
    DWORD elevationBytes = 0;
    if (::GetTokenInformation(
            token.get(),
            TokenElevation,
            &elevation,
            sizeof(elevation),
            &elevationBytes)) {
        isAdminOut = elevation.TokenIsElevated != 0;
        adminKnownOut = true;
        elevationEvidence.available = true;
    } else {elevationEvidence.win32ErrorKnown = true; elevationEvidence.win32Error = ::GetLastError();}

    DWORD userBytes = 0;
    ::GetTokenInformation(token.get(), TokenUser, nullptr, 0, &userBytes);
    userEvidence.win32ErrorKnown = true; userEvidence.win32Error = ::GetLastError();
    if (userBytes > 0) {
        std::vector<BYTE> userBuffer(userBytes);
        if (::GetTokenInformation(token.get(), TokenUser, userBuffer.data(), userBytes, &userBytes)) {
            const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
            wchar_t name[256]{};
            wchar_t domain[256]{};
            DWORD nameChars = static_cast<DWORD>(_countof(name));
            DWORD domainChars = static_cast<DWORD>(_countof(domain));
            SID_NAME_USE use{};
            if (::LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameChars, domain, &domainChars, &use)) {
                userOut = std::wstring(domain) + L"\\" + name;
                userEvidence.available = true;
                userEvidence.win32Error = ERROR_SUCCESS;
            } else {
                userEvidence.win32ErrorKnown = true; userEvidence.win32Error = ::GetLastError();
                userOut = L"<sid lookup failed: " + ks::r3::common::LastErrorMessage(userEvidence.win32Error) + L">";
            }
        } else {userEvidence.win32Error = ::GetLastError();}
    }
    if (userOut.empty()) {
        userOut = L"<user unavailable>";
    }

    DWORD integrityBytes = 0;
    ::GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &integrityBytes);
    integrityEvidence.win32ErrorKnown = true; integrityEvidence.win32Error = ::GetLastError();
    if (integrityBytes > 0) {
        std::vector<BYTE> integrityBuffer(integrityBytes);
        if (::GetTokenInformation(token.get(), TokenIntegrityLevel, integrityBuffer.data(), integrityBytes, &integrityBytes)) {
            const TOKEN_MANDATORY_LABEL* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());
            const DWORD rid = *::GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(*::GetSidSubAuthorityCount(label->Label.Sid) - 1));
            integrityEvidence.available = true;
            integrityEvidence.win32Error = ERROR_SUCCESS;
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID) {
                integrityOut = L"System";
            } else if (rid >= SECURITY_MANDATORY_HIGH_RID) {
                integrityOut = L"High";
            } else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) {
                integrityOut = L"Medium";
            } else if (rid >= SECURITY_MANDATORY_LOW_RID) {
                integrityOut = L"Low";
            } else {
                integrityOut = L"Untrusted";
            }
        } else {integrityEvidence.win32Error = ::GetLastError();}
    }
    if (integrityOut.empty()) {
        integrityOut = L"<integrity unavailable>";
    }
}
std::wstring QueryBitnessText(HANDLE process, ProcessQueryEvidence* evidence) {
    if (evidence) *evidence = {};
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const auto isWow64Process2 = kernel32
        ? reinterpret_cast<IsWow64Process2Fn>(::GetProcAddress(kernel32, "IsWow64Process2"))
        : nullptr;
    if (isWow64Process2) {
        USHORT processMachine = 0;
        USHORT nativeMachine = 0;
        if (isWow64Process2(process, &processMachine, &nativeMachine)) {
            if (evidence) evidence->available = true;
            if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
                return sizeof(void*) == 8 ? L"64-bit native" : L"32-bit native";
            }
            return L"32-bit WOW64";
        }
    }

    BOOL wow64 = FALSE;
    if (::IsWow64Process(process, &wow64)) {
        if (evidence) evidence->available = true;
        if (wow64) {
            return L"32-bit WOW64";
        }
        return sizeof(void*) == 8 ? L"64-bit native" : L"32-bit native";
    }
    const DWORD error = ::GetLastError();
    if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = error;}
    return L"<bitness unavailable: " + ks::r3::common::LastErrorMessage(error) + L">";
}
bool QueryNativeProcessBasicInformation(HANDLE process, NativeProcessBasicInformation& basicOut, ProcessQueryEvidence* evidence) {
    if (evidence) *evidence = {};
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const auto queryProcess = ntdll
        ? reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(ntdll, "NtQueryInformationProcess"))
        : nullptr;
    if (!queryProcess) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ERROR_PROC_NOT_FOUND;}
        return false;
    }

    basicOut = {};
    ULONG returned = 0;
    const LONG status = queryProcess(
        process,
        kProcessBasicInformationClass,
        &basicOut,
        sizeof(basicOut),
        &returned);
    if (evidence) {evidence->ntStatusKnown = true; evidence->ntStatus = status; evidence->available = status == 0 && returned >= sizeof(basicOut);}
    return status == 0 && returned >= sizeof(basicOut);
}
DWORD QueryParentProcessId(HANDLE process) {
    NativeProcessBasicInformation basic{};
    return QueryNativeProcessBasicInformation(process, basic)
        ? static_cast<DWORD>(basic.inheritedFromUniqueProcessId)
        : 0;
}
std::wstring ReadRemoteUnicodeString(HANDLE process, const UNICODE_STRING& remoteText, ProcessQueryEvidence* evidence) {
    if (evidence) *evidence = {};
    if (remoteText.Length == 0) {
        if (evidence) {evidence->available = true; evidence->emptyValue = true;}
        return L"";
    }
    if (!remoteText.Buffer || remoteText.Length % sizeof(wchar_t) != 0 || remoteText.Length > kMaxPathBufferChars * sizeof(wchar_t)) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ERROR_INVALID_DATA;}
        return L"<remote string too large>";
    }

    std::wstring text(remoteText.Length / sizeof(wchar_t), L'\0');
    SIZE_T bytesRead = 0;
    if (!::ReadProcessMemory(process, remoteText.Buffer, text.data(), remoteText.Length, &bytesRead)) {
        const DWORD error = ::GetLastError();
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = error;}
        return L"<ReadProcessMemory failed: " + ks::r3::common::LastErrorMessage(error) + L">";
    }
    if (evidence) evidence->available = bytesRead == remoteText.Length;
    if (evidence && bytesRead != remoteText.Length) {evidence->win32ErrorKnown = true; evidence->win32Error = ERROR_PARTIAL_COPY;}
    text.resize(bytesRead / sizeof(wchar_t));
    return text;
}
std::wstring QueryCommandLineText(HANDLE process, ProcessQueryEvidence* evidence) {
    if (evidence) *evidence = {};
    NativeProcessBasicInformation basic{};
    if (!QueryNativeProcessBasicInformation(process, basic, evidence) || !basic.pebBaseAddress) {
        if (evidence) evidence->available = false;
        return L"<ProcessBasicInformation unavailable>";
    }

    RemotePeb peb{};
    SIZE_T bytesRead = 0;
    if (evidence) evidence->available = false;
    if (!::ReadProcessMemory(process, basic.pebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ::GetLastError();}
        return L"<PEB read failed: " + ks::r3::common::LastErrorMessage() + L">";
    }

    if (bytesRead != sizeof(peb)) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ERROR_PARTIAL_COPY;}
        return L"<PEB read failed: " + ks::r3::common::LastErrorMessage(ERROR_PARTIAL_COPY) + L">";
    }
    RemoteProcessParameters parameters{};
    if (!::ReadProcessMemory(process, peb.processParameters, &parameters, sizeof(parameters), &bytesRead)) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ::GetLastError();}
        return L"<ProcessParameters read failed: " + ks::r3::common::LastErrorMessage() + L">";
    }

    if (bytesRead != sizeof(parameters)) {
        if (evidence) {evidence->win32ErrorKnown = true; evidence->win32Error = ERROR_PARTIAL_COPY;}
        return L"<ProcessParameters read failed: " + ks::r3::common::LastErrorMessage(ERROR_PARTIAL_COPY) + L">";
    }
    std::wstring commandLine = ReadRemoteUnicodeString(process, parameters.commandLine, evidence);
    if (commandLine.empty()) {
        commandLine = L"<empty command line>";
    }
    return commandLine;
}

}

namespace ks::r3::process_detail {
using namespace detail;
ProcessBasicInfo CollectBasicInfo(DWORD processId, bool& succeededOut) {
    ProcessBasicInfo info{};
    info.processId = processId;
    succeededOut = false;

    QuerySnapshotIdentity(
        processId,
        info.parentProcessId,
        info.processName,
        info.parentProcessName,
        info.threadCount, &info.evidence[L"snapshot"]);

    HANDLE rawProcess = ::OpenProcess(kProcessBasicAccess, FALSE, processId);
    ks::r3::common::UniqueHandle process(rawProcess);
    if (!process.valid()) {
        const DWORD error = ::GetLastError();
        info.evidence[L"open"] = {false,true,false,error};
        info.statusText = Win32ErrorText(L"OpenProcess", error);
        return info;
    }

    succeededOut = true;
    const DWORD nativeParentProcessId = QueryParentProcessId(process.get());
    if (nativeParentProcessId != 0) {
        info.parentProcessId = nativeParentProcessId;
    }
    info.imagePath = QueryProcessImagePath(process.get(), &info.evidence[L"image-path"]);
    if (!info.imagePath.empty() && info.imagePath.front() != L'<') {
        info.processName = LeafNameFromPath(info.imagePath);
    }
    QuerySnapshotIdentity(
        processId,
        info.parentProcessId,
        info.processName,
        info.parentProcessName,
        info.threadCount, &info.evidence[L"snapshot"]);

    NativeProcessBasicInformation nativeBasic{};
    if (QueryNativeProcessBasicInformation(process.get(), nativeBasic, &info.evidence[L"native-basic"])) {
        if (nativeBasic.pebBaseAddress) {
            info.pebAddress = reinterpret_cast<std::uintptr_t>(nativeBasic.pebBaseAddress);
            info.pebAddressKnown = true;
        }
        if (nativeBasic.affinityMask != 0) {
            info.affinityMask = static_cast<std::uint64_t>(nativeBasic.affinityMask);
            info.affinityKnown = true;
        }
    }

    ks::r3::common::UniqueHandle readableProcess(::OpenProcess(kProcessReadAccess, FALSE, processId));
    const DWORD readableError = readableProcess.valid() ? ERROR_SUCCESS : ::GetLastError();
    info.commandLine = readableProcess.valid()
        ? QueryCommandLineText(readableProcess.get(), &info.evidence[L"command-line"])
        : L"<command line unavailable: " + ks::r3::common::LastErrorMessage(readableError) + L">";
    if (!readableProcess.valid()) info.evidence[L"command-line"] = {false,true,false,readableError};
    info.bitness = QueryBitnessText(process.get(), &info.evidence[L"bitness"]);
    bool sessionOk = false;
    info.sessionId = QueryProcessSession(processId, sessionOk);
    const DWORD sessionError = sessionOk ? ERROR_SUCCESS : ::GetLastError();
    info.evidence[L"session"] = {sessionOk,true,false,sessionError};
    QueryTokenText(
        process.get(),
        info.userName,
        info.integrityLevel,
        info.isAdmin,
        info.adminKnown, &info);

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    const bool timesOk = ::GetProcessTimes(
        process.get(),
        &creationTime,
        &exitTime,
        &kernelTime,
        &userTime) != FALSE;
    info.evidence[L"start-time"] = {timesOk,true,false,timesOk ? ERROR_SUCCESS : ::GetLastError()};
    info.startTimeText = timesOk ? FormatProcessStartTime(creationTime) : L"<start time unavailable>";
    if (timesOk) info.creationTime100ns = (static_cast<ULONGLONG>(creationTime.dwHighDateTime)<<32) | creationTime.dwLowDateTime;

    info.priorityClass = ::GetPriorityClass(process.get());
    info.evidence[L"priority"] = {info.priorityClass != 0,true,false,info.priorityClass ? ERROR_SUCCESS : ::GetLastError()};
    info.priorityText = PriorityClassText(info.priorityClass);
    DWORD handleCount = 0;
    if (::GetProcessHandleCount(process.get(), &handleCount)) {
        info.handleCount = handleCount;
        info.evidence[L"handles"].available = true;
    } else {info.evidence[L"handles"] = {false,true,false,::GetLastError()};}

    DWORD_PTR processAffinity = 0;
    DWORD_PTR systemAffinity = 0;
    if (::GetProcessAffinityMask(process.get(), &processAffinity, &systemAffinity)) {
        info.affinityMask = static_cast<std::uint64_t>(processAffinity);
        info.affinityKnown = true;
        info.evidence[L"affinity"].available = true;
    } else {
        info.evidence[L"affinity"] = {info.affinityKnown,true,false,::GetLastError()};
    }

    PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
    memoryCounters.cb = sizeof(memoryCounters);
    HANDLE memoryProcess = readableProcess.valid() ? readableProcess.get() : process.get();
    if (::GetProcessMemoryInfo(
            memoryProcess,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
            sizeof(memoryCounters))) {
        info.evidence[L"memory"].available = true;
        info.workingSetBytes = static_cast<ULONGLONG>(memoryCounters.WorkingSetSize);
        info.privateBytes = static_cast<ULONGLONG>(memoryCounters.PrivateUsage);
    } else {info.evidence[L"memory"] = {false,true,false,::GetLastError()};}

    IO_COUNTERS ioCounters{};
    if (::GetProcessIoCounters(process.get(), &ioCounters)) {
        info.evidence[L"io"].available = true;
        info.ioBytes = SaturatingAdd64(
            SaturatingAdd64(ioCounters.ReadTransferCount, ioCounters.WriteTransferCount),
            ioCounters.OtherTransferCount);
    } else {info.evidence[L"io"] = {false,true,false,::GetLastError()};}
    info.statusText = sessionOk
        ? L"OK"
        : L"OK; session unavailable: " + ks::r3::common::LastErrorMessage(sessionError);
    return info;
}
}
