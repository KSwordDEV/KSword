#pragma once
#include "ProcessDetailTypes.h"
#include "../Common.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <limits>
namespace ks::r3::process_detail::detail {
constexpr DWORD kProcessBasicAccess = PROCESS_QUERY_LIMITED_INFORMATION;
constexpr DWORD kProcessReadAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
constexpr DWORD kMaxPathBufferChars = 32768;
constexpr ULONG kProcessBasicInformationClass = 0;
using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct NativeProcessBasicInformation {
    LONG exitStatus = 0;
    PVOID pebBaseAddress = nullptr;
    ULONG_PTR affinityMask = 0;
    LONG basePriority = 0;
    ULONG_PTR uniqueProcessId = 0;
    ULONG_PTR inheritedFromUniqueProcessId = 0;
};
struct RemotePeb {
    BYTE reserved1[2];
    BYTE beingDebugged = 0;
    BYTE reserved2[1];
    PVOID reserved3[2];
    PVOID ldr = nullptr;
    PVOID processParameters = nullptr;
};
struct RemoteProcessParameters {
    BYTE reserved1[16];
    PVOID reserved2[10];
    UNICODE_STRING imagePathName;
    UNICODE_STRING commandLine;
};
std::wstring Win32ErrorText(const wchar_t* operation, DWORD errorCode);
std::wstring QueryProcessImagePath(HANDLE process);
std::wstring LeafNameFromPath(const std::wstring& path);
void QuerySnapshotIdentity(
    DWORD processId,
    DWORD& parentProcessIdInOut,
    std::wstring& processNameOut,
    std::wstring& parentProcessNameOut,
    DWORD& threadCountOut);
std::wstring FormatProcessStartTime(const FILETIME& creationTime);
std::wstring PriorityClassText(DWORD priorityClass);
ULONGLONG SaturatingAdd64(ULONGLONG left, ULONGLONG right);
DWORD QueryProcessSession(DWORD processId, bool& okOut);
void QueryTokenText(
    HANDLE process,
    std::wstring& userOut,
    std::wstring& integrityOut,
    bool& isAdminOut,
    bool& adminKnownOut);
std::wstring QueryBitnessText(HANDLE process);
bool QueryNativeProcessBasicInformation(HANDLE process, NativeProcessBasicInformation& basicOut);
DWORD QueryParentProcessId(HANDLE process);
std::wstring ReadRemoteUnicodeString(HANDLE process, const UNICODE_STRING& remoteText);
std::wstring QueryCommandLineText(HANDLE process);

}
