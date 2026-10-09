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
std::wstring QueryProcessImagePath(HANDLE process) {
    std::wstring path(kMaxPathBufferChars, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    if (::QueryFullProcessImageNameW(process, 0, path.data(), &length)) {
        path.resize(length);
        return path;
    }
    return L"<image path unavailable: " + ks::r3::common::LastErrorMessage() + L">";
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
    DWORD& threadCountOut) {
    ks::r3::common::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid()) {
        return;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot.get(), &entry)) {
        return;
    }
    do {
        if (entry.th32ProcessID == processId) {
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
    bool& adminKnownOut) {
    isAdminOut = false;
    adminKnownOut = false;
    ks::r3::common::UniqueHandle token;
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process, TOKEN_QUERY, &rawToken)) {
        const std::wstring error = ks::r3::common::LastErrorMessage();
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
    }

    DWORD userBytes = 0;
    ::GetTokenInformation(token.get(), TokenUser, nullptr, 0, &userBytes);
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
            } else {
                userOut = L"<sid lookup failed: " + ks::r3::common::LastErrorMessage() + L">";
            }
        }
    }
    if (userOut.empty()) {
        userOut = L"<user unavailable>";
    }

    DWORD integrityBytes = 0;
    ::GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &integrityBytes);
    if (integrityBytes > 0) {
        std::vector<BYTE> integrityBuffer(integrityBytes);
        if (::GetTokenInformation(token.get(), TokenIntegrityLevel, integrityBuffer.data(), integrityBytes, &integrityBytes)) {
            const TOKEN_MANDATORY_LABEL* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());
            const DWORD rid = *::GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(*::GetSidSubAuthorityCount(label->Label.Sid) - 1));
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
        }
    }
    if (integrityOut.empty()) {
        integrityOut = L"<integrity unavailable>";
    }
}
std::wstring QueryBitnessText(HANDLE process) {
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const auto isWow64Process2 = kernel32
        ? reinterpret_cast<IsWow64Process2Fn>(::GetProcAddress(kernel32, "IsWow64Process2"))
        : nullptr;
    if (isWow64Process2) {
        USHORT processMachine = 0;
        USHORT nativeMachine = 0;
        if (isWow64Process2(process, &processMachine, &nativeMachine)) {
            if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
                return sizeof(void*) == 8 ? L"64-bit native" : L"32-bit native";
            }
            return L"32-bit WOW64";
        }
    }

    BOOL wow64 = FALSE;
    if (::IsWow64Process(process, &wow64)) {
        if (wow64) {
            return L"32-bit WOW64";
        }
        return sizeof(void*) == 8 ? L"64-bit native" : L"32-bit native";
    }
    return L"<bitness unavailable: " + ks::r3::common::LastErrorMessage() + L">";
}
bool QueryNativeProcessBasicInformation(HANDLE process, NativeProcessBasicInformation& basicOut) {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const auto queryProcess = ntdll
        ? reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(ntdll, "NtQueryInformationProcess"))
        : nullptr;
    if (!queryProcess) {
        return false;
    }

    basicOut = {};
    ULONG returned = 0;
    return queryProcess(
        process,
        kProcessBasicInformationClass,
        &basicOut,
        sizeof(basicOut),
        &returned) >= 0;
}
DWORD QueryParentProcessId(HANDLE process) {
    NativeProcessBasicInformation basic{};
    return QueryNativeProcessBasicInformation(process, basic)
        ? static_cast<DWORD>(basic.inheritedFromUniqueProcessId)
        : 0;
}
std::wstring ReadRemoteUnicodeString(HANDLE process, const UNICODE_STRING& remoteText) {
    if (!remoteText.Buffer || remoteText.Length == 0) {
        return L"";
    }
    if (remoteText.Length > kMaxPathBufferChars * sizeof(wchar_t)) {
        return L"<remote string too large>";
    }

    std::wstring text(remoteText.Length / sizeof(wchar_t), L'\0');
    SIZE_T bytesRead = 0;
    if (!::ReadProcessMemory(process, remoteText.Buffer, text.data(), remoteText.Length, &bytesRead)) {
        return L"<ReadProcessMemory failed: " + ks::r3::common::LastErrorMessage() + L">";
    }
    text.resize(bytesRead / sizeof(wchar_t));
    return text;
}
std::wstring QueryCommandLineText(HANDLE process) {
    NativeProcessBasicInformation basic{};
    if (!QueryNativeProcessBasicInformation(process, basic) || !basic.pebBaseAddress) {
        return L"<ProcessBasicInformation unavailable>";
    }

    RemotePeb peb{};
    SIZE_T bytesRead = 0;
    if (!::ReadProcessMemory(process, basic.pebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        return L"<PEB read failed: " + ks::r3::common::LastErrorMessage() + L">";
    }

    RemoteProcessParameters parameters{};
    if (!::ReadProcessMemory(process, peb.processParameters, &parameters, sizeof(parameters), &bytesRead)) {
        return L"<ProcessParameters read failed: " + ks::r3::common::LastErrorMessage() + L">";
    }

    std::wstring commandLine = ReadRemoteUnicodeString(process, parameters.commandLine);
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
        info.threadCount);

    HANDLE rawProcess = ::OpenProcess(kProcessBasicAccess, FALSE, processId);
    ks::r3::common::UniqueHandle process(rawProcess);
    if (!process.valid()) {
        info.statusText = Win32ErrorText(L"OpenProcess", ::GetLastError());
        return info;
    }

    succeededOut = true;
    const DWORD nativeParentProcessId = QueryParentProcessId(process.get());
    if (nativeParentProcessId != 0) {
        info.parentProcessId = nativeParentProcessId;
    }
    info.imagePath = QueryProcessImagePath(process.get());
    if (!info.imagePath.empty() && info.imagePath.front() != L'<') {
        info.processName = LeafNameFromPath(info.imagePath);
    }
    QuerySnapshotIdentity(
        processId,
        info.parentProcessId,
        info.processName,
        info.parentProcessName,
        info.threadCount);

    NativeProcessBasicInformation nativeBasic{};
    if (QueryNativeProcessBasicInformation(process.get(), nativeBasic)) {
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
    info.commandLine = readableProcess.valid()
        ? QueryCommandLineText(readableProcess.get())
        : L"<command line unavailable: " + ks::r3::common::LastErrorMessage() + L">";
    info.bitness = QueryBitnessText(process.get());
    bool sessionOk = false;
    info.sessionId = QueryProcessSession(processId, sessionOk);
    const DWORD sessionError = sessionOk ? ERROR_SUCCESS : ::GetLastError();
    QueryTokenText(
        process.get(),
        info.userName,
        info.integrityLevel,
        info.isAdmin,
        info.adminKnown);

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    info.startTimeText = ::GetProcessTimes(
        process.get(),
        &creationTime,
        &exitTime,
        &kernelTime,
        &userTime)
        ? FormatProcessStartTime(creationTime)
        : L"<start time unavailable>";

    info.priorityText = PriorityClassText(::GetPriorityClass(process.get()));
    DWORD handleCount = 0;
    if (::GetProcessHandleCount(process.get(), &handleCount)) {
        info.handleCount = handleCount;
    }

    DWORD_PTR processAffinity = 0;
    DWORD_PTR systemAffinity = 0;
    if (::GetProcessAffinityMask(process.get(), &processAffinity, &systemAffinity)) {
        info.affinityMask = static_cast<std::uint64_t>(processAffinity);
        info.affinityKnown = true;
    }

    PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
    memoryCounters.cb = sizeof(memoryCounters);
    HANDLE memoryProcess = readableProcess.valid() ? readableProcess.get() : process.get();
    if (::GetProcessMemoryInfo(
            memoryProcess,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
            sizeof(memoryCounters))) {
        info.workingSetBytes = static_cast<ULONGLONG>(memoryCounters.WorkingSetSize);
        info.privateBytes = static_cast<ULONGLONG>(memoryCounters.PrivateUsage);
    }

    IO_COUNTERS ioCounters{};
    if (::GetProcessIoCounters(process.get(), &ioCounters)) {
        info.ioBytes = SaturatingAdd64(
            SaturatingAdd64(ioCounters.ReadTransferCount, ioCounters.WriteTransferCount),
            ioCounters.OtherTransferCount);
    }
    info.statusText = sessionOk
        ? L"OK"
        : L"OK; session unavailable: " + ks::r3::common::LastErrorMessage(sessionError);
    return info;
}
}
