#pragma once
#include "../Common.h"
#include "KernelTypes.h"
#include <winternl.h>
#include <array>
#include <deque>
#include <functional>
#include <set>
#include <string_view>
#include <unordered_map>
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

#ifndef FILE_LIST_DIRECTORY
#define FILE_LIST_DIRECTORY 0x0001
#endif

#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef OBJ_INHERIT
#define OBJ_INHERIT 0x00000002L
#endif

#ifndef OBJ_PERMANENT
#define OBJ_PERMANENT 0x00000010L
#endif

#ifndef OBJ_EXCLUSIVE
#define OBJ_EXCLUSIVE 0x00000020L
#endif

#ifndef OBJ_OPENIF
#define OBJ_OPENIF 0x00000080L
#endif

#ifndef OBJ_OPENLINK
#define OBJ_OPENLINK 0x00000100L
#endif

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif

#ifndef OBJ_FORCE_ACCESS_CHECK
#define OBJ_FORCE_ACCESS_CHECK 0x00000400L
#endif

#ifndef OBJ_IGNORE_IMPERSONATED_DEVICEMAP
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 0x00000800L
#endif

#ifndef OBJ_DONT_REPARSE
#define OBJ_DONT_REPARSE 0x00001000L
#endif


namespace ks::r3::kernel {
constexpr LONG kStatusSuccess = 0x00000000L;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005UL);
constexpr LONG kStatusNoMoreEntries = static_cast<LONG>(0x8000001AUL);
constexpr LONG kStatusNoSuchFile = static_cast<LONG>(0xC000000FUL);
constexpr LONG kStatusUnsuccessful = static_cast<LONG>(0xC0000001UL);
constexpr LONG kStatusInvalidHandle = static_cast<LONG>(0xC0000008UL);
constexpr LONG kStatusAccessDenied = static_cast<LONG>(0xC0000022UL);
constexpr LONG kStatusObjectTypeMismatch = static_cast<LONG>(0xC0000024UL);
constexpr LONG kStatusObjectNameNotFound = static_cast<LONG>(0xC0000034UL);
constexpr LONG kStatusObjectPathNotFound = static_cast<LONG>(0xC000003AUL);
constexpr LONG kStatusNameTooLong = static_cast<LONG>(0xC0000106UL);
constexpr LONG kStatusPipeDisconnected = static_cast<LONG>(0xC00000B0UL);
constexpr LONG kStatusPipeBusy = static_cast<LONG>(0xC00000AEUL);
constexpr LONG kStatusInstanceNotAvailable = static_cast<LONG>(0xC00000ABUL);
constexpr ULONG kObjectBasicInformation = 0;
constexpr ULONG kObjectNameInformation = 1;
constexpr ULONG kObjectTypeInformation = 2;
using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
using NtOpenSymbolicLinkObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtQuerySymbolicLinkObjectFn = NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING, PULONG);
using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtOpenFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
using NtQueryDirectoryFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN, PUNICODE_STRING, BOOLEAN);
using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
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
struct NtRuntime {
    NtOpenDirectoryObjectFn openDirectoryObject = nullptr;
    NtQueryDirectoryObjectFn queryDirectoryObject = nullptr;
    NtOpenSymbolicLinkObjectFn openSymbolicLinkObject = nullptr;
    NtQuerySymbolicLinkObjectFn querySymbolicLinkObject = nullptr;
    NtQueryObjectFn queryObject = nullptr;
    NtOpenFileFn openFile = nullptr;
    NtQueryDirectoryFileFn queryDirectoryFile = nullptr;
    NtQuerySystemInformationFn querySystemInformation = nullptr;
    NtQueryInformationProcessFn queryInformationProcess = nullptr;
    NtQueryInformationThreadFn queryInformationThread = nullptr;
    NtQueryInformationTokenFn queryInformationToken = nullptr;
};
struct DirectoryEntry {
    struct BasicEvidence {bool attempted=false,available=false,malformed=false;LONG status=0;ULONG returned=0;KOBJECT_BASIC_INFORMATION value{};};
    struct TargetEvidence {bool attempted=false,available=false,malformed=false,limited=false;LONG status=0;ULONG required=0;};
    bool metadataRequested=false,openAttempted=false,closeAttempted=false,closed=false;
    LONG openStatus=0;
    DWORD closeError=0;
    BasicEvidence basic;
    TargetEvidence target;
    std::wstring parentPath;
    std::wstring name;
    std::wstring typeName;
    std::wstring fullPath;
    std::wstring targetPath;
    std::wstring statusText;
    std::wstring handleCountText;
    std::wstring pointerCountText;
    bool canOpen = false;
};
struct QueryPacket {
    std::vector<KernelResultRow> rows;
    std::vector<std::wstring> warnings;
};
struct DirectoryQueryEvidence {
    std::wstring path;
    bool apiAvailable=false,openAttempted=false,opened=false,queryAttempted=false,complete=false,limited=false,cancelled=false,cycle=false,malformed=false;
    LONG openStatus=0,lastQueryStatus=0;
    ULONG returned=0,queried=0;
    bool closeAttempted=false,closed=false;
    DWORD closeError=0;
};
struct DirectoryQueryOptions {
    bool probeMetadata=true;
    DWORD maxEntries=100000,maxDurationMs=8000;
    ULONGLONG deadlineTick=0;
    std::function<bool()> cancelled;
};
KernelResultRow Row(std::initializer_list<std::pair<std::wstring, std::wstring>> columns, const std::wstring& detail = {});
std::wstring HexText(const std::uint64_t value);
std::wstring StatusText(const LONG status);
void AppendFlagText(std::wstring& text, const ULONG value, const ULONG flag, const wchar_t* name);
std::wstring ObjectAttributesText(const ULONG attributes);
std::wstring AccessMaskText(const ACCESS_MASK access);
bool IsSuccessStatus(const LONG status);
std::wstring StatusMeaningText(const LONG status);
bool IsRetryStatus(const LONG status);
std::wstring CountedString(const UNICODE_STRING& value);
UNICODE_STRING MakeUnicodeString(const std::wstring& text);
OBJECT_ATTRIBUTES MakeObjectAttributes(UNICODE_STRING& name, HANDLE root = nullptr);
std::wstring JoinObjectPath(const std::wstring& directoryPath, const std::wstring& name);
std::wstring ToLowerCopy(std::wstring text);
bool ContainsI(const std::wstring& text, const std::wstring& fragment);
bool StartsWithI(const std::wstring& text, const std::wstring& prefix);
ACCESS_MASK ParseHexOrDecimal(const std::wstring& text);
std::wstring JoinStrings(const std::vector<std::wstring>& values, const std::wstring& separator);
std::vector<std::wstring> DosPathCandidatesFromNtPath(const std::wstring& ntPath);
bool MatchesDirectoryFilter(const DirectoryEntry& entry, const std::wstring& filter);
std::wstring FieldValue(const KernelActionRequest& request, const std::wstring& key);
std::wstring FirstNonEmpty(std::initializer_list<std::wstring> values);
std::wstring NativePathFromAction(const KernelActionRequest& request);
std::wstring ObjectTypeNameFromAction(const KernelActionRequest& request);
void AppendObjectTypeDetailRow(const KernelActionRequest& request, const std::wstring& type, QueryPacket& packet);
KernelOperationResult MakeNativeActionResult(const KernelActionRequest& request, const bool success, const std::wstring& operation, QueryPacket&& packet);
void AppendObjectBasicInfoRow(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& path, HANDLE handle, const LONG openStatus);
void AppendQueriedObjectText(QueryPacket& packet, const NtRuntime& runtime, HANDLE handle, const ULONG infoClass, const std::wstring& label);
const NtRuntime& Runtime();
HANDLE OpenDirectory(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut = nullptr);
HANDLE OpenSymbolicLink(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut = nullptr);
std::wstring QuerySymbolicLinkTarget(const NtRuntime& runtime, HANDLE link,DirectoryEntry::TargetEvidence* evidence=nullptr);
void QueryBasicObjectCounts(const NtRuntime& runtime, HANDLE handle, std::wstring& handleCountText, std::wstring& pointerCountText,DirectoryEntry::BasicEvidence* evidence=nullptr);
HANDLE OpenNamedPipeReadOnly(const NtRuntime& runtime, const std::wstring& path, LONG* statusOut, IO_STATUS_BLOCK* ioStatusOut);
void AppendDirectoryPreviewRows(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& path, const std::size_t limit);
std::wstring DirectoryStatusText(const std::wstring& typeName, const bool canOpen, const bool hasTarget);
std::vector<DirectoryEntry> EnumerateDirectoryFlat(const NtRuntime& runtime, const std::wstring& directoryPath, std::vector<std::wstring>& warnings,DirectoryQueryEvidence* evidence=nullptr,const DirectoryQueryOptions& options={});
void AppendDirectoryEntryRow(
    QueryPacket& packet,
    const std::wstring& source,
    const std::size_t depth,
    const DirectoryEntry& entry,
    const std::wstring& enumApi = L"NtOpenDirectoryObject + NtQueryDirectoryObject");
KernelOperationResult MakeResult(KernelFeatureId id, const bool success, const std::wstring& operation, QueryPacket&& packet);
void AppendDirectoryRoot(QueryPacket& packet, const NtRuntime& runtime, const std::wstring& root, const std::wstring& source, const std::wstring& filter);
std::vector<DWORD> DiscoverSessionIds(const NtRuntime& runtime,DirectoryQueryEvidence* evidence=nullptr,DWORD* currentSessionError=nullptr,const DirectoryQueryOptions& options={},bool* currentSessionKnown=nullptr);
std::vector<std::wstring> CommonNamespaceRoots(DirectoryQueryEvidence* discovery=nullptr,DWORD* currentSessionError=nullptr,const DirectoryQueryOptions& options={},bool* currentSessionKnown=nullptr);
KernelOperationResult QueryObjectNamespaceOverview(const KernelRequest& request);
KernelOperationResult ExecuteNativeObjectDetail(const KernelActionRequest& request);
}
