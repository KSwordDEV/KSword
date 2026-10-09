#pragma once
#include "../Common.h"
#include "DriverTypes.h"
#include "../NtApi.h"
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>
#include <winternl.h>
#include <array>
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif
namespace ks::r3::driver {
constexpr LONG kStatusSuccess = 0x00000000L;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005UL);
constexpr LONG kStatusNoMoreEntries = static_cast<LONG>(0x8000001AL);
constexpr LONG kStatusProcedureNotFound = static_cast<LONG>(0xC000007AUL);
using NtOpenDirectoryObjectFn = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtQueryDirectoryObjectFn = NTSTATUS (NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
using NtOpenSymbolicLinkObjectFn = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtQuerySymbolicLinkObjectFn = NTSTATUS (NTAPI*)(HANDLE, PUNICODE_STRING, PULONG);
using NtQueryObjectFn = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct KRTL_PROCESS_MODULE_INFORMATION {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};
struct KRTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    KRTL_PROCESS_MODULE_INFORMATION Modules[1];
};
struct KOBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
};
struct KOBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInfoSize;
    ULONG TypeInfoSize;
    ULONG SecurityDescriptorSize;
    LARGE_INTEGER CreationTime;
};
struct NtLibrary {
    NtOpenDirectoryObjectFn openDirectoryObject = nullptr;
    NtQueryDirectoryObjectFn queryDirectoryObject = nullptr;
    NtOpenSymbolicLinkObjectFn openSymbolicLinkObject = nullptr;
    NtQuerySymbolicLinkObjectFn querySymbolicLinkObject = nullptr;
    NtQueryObjectFn queryObject = nullptr;
};
bool IsRetryStatus(LONG status);
std::wstring WideText(const UNICODE_STRING& value);
std::wstring AnsiTextToWide(const char* text, std::size_t length);
std::wstring AnsiPathFromModule(const KRTL_PROCESS_MODULE_INFORMATION& module);
std::wstring CompactHex(const std::uint64_t value);
std::wstring NtStatusText(const long status);
std::wstring ResolveKernelImagePathForTrust(const std::wstring& path);
std::wstring VerifyDriverImageSignature(const std::wstring& displayPath);
std::wstring LeafName(const std::wstring& text);
std::wstring JoinObjectPath(const std::wstring& root, const std::wstring& name);
std::wstring StatusForObjectType(const std::wstring& typeName, bool querySucceeded, bool hasTarget);
std::wstring CapabilityForObjectType(const std::wstring& typeName, bool hasTarget);
HANDLE OpenNtDirectory(const NtLibrary& library, const std::wstring& path);
bool QueryBasicCounts(const NtLibrary& library, HANDLE handle, std::wstring& handleCountText, std::wstring& referenceCountText);
std::wstring QuerySymbolicLinkTarget(const NtLibrary& library, HANDLE handle);
DriverObjectRow AppendDirectoryRow(const NtLibrary& library, const std::wstring& directoryPath, const std::wstring& name, const std::wstring& typeName);
bool QueryModuleInformation(std::vector<DriverOverviewRow>& rows, std::wstring& diagnosticText);
bool QueryPsapiModules(std::vector<DriverOverviewRow>& rows, std::wstring& diagnosticText);
void QueryObjectDirectory(
    const NtLibrary& library,
    const std::wstring& directoryPath,
    std::vector<DriverObjectRow>& rows,
    std::vector<std::wstring>& warnings);
}
