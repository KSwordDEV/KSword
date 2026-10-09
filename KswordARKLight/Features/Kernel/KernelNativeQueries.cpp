#include "../../../shared/usermode/backend/kernel/AtomTable.h"
#include "../../../shared/usermode/backend/kernel/NamedPipes.h"
#include "../../../shared/usermode/backend/kernel/ObjectTypes.h"
#include "../../../shared/usermode/backend/kernel/CommunicationEndpoints.h"
#include "../../../shared/usermode/backend/kernel/BaseNamedObjects.h"
#include "../../../shared/usermode/backend/kernel/DeviceDriverObjects.h"
#include "../../../shared/usermode/backend/kernel/SymbolicLinks.h"
#include "../../../shared/usermode/backend/kernel/ObjectDirectory.h"
#include "../../../shared/usermode/backend/kernel/ObjectNamespace.h"
#include "KernelNativeQueries.h"

#include "../../Core/Win32Lean.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <cwchar>
#include <deque>
#include <functional>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <unordered_map>
#include <vector>

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

namespace Ksword::Features::Kernel {
namespace {
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
using namespace ks::r3::kernel;
























constexpr std::size_t kMaxExportRows = 512;













// KOBJECT_DIRECTORY_INFORMATION is the compact entry returned by
// NtQueryDirectoryObject. Inputs are ntdll-owned counted strings; processing
// copies them immediately into std::wstring before the buffer is reused.


// KOBJECT_BASIC_INFORMATION contains the small count fields needed for object
// diagnostics. Input bytes come from NtQueryObject(ObjectBasicInformation);
// output is copied to display text only.


// KOBJECT_TYPE_INFORMATION mirrors the object type block used by
// NtQueryObject(ObjectTypesInformation). The trailing TypeName buffer is stored
// after this structure and aligned by pointer size.


// KFILE_DIRECTORY_INFORMATION is the native directory result used for the
// named-pipe namespace. Input is a byte chain with NextEntryOffset links;
// processing copies names and timestamps into rows.


// NtRuntime stores all dynamically resolved ntdll calls needed by the native
// kernel pages. Input is the loaded ntdll module; output is a best-effort table
// so individual pages can degrade without crashing.


// DirectoryEntry is one object-manager child. Inputs are a parent path plus the
// native name/type; processing derives FullPath and optional symlink target;
// output is converted into KernelResultRow by the query workers.


// QueryPacket carries rows and warnings while one worker runs. Inputs are row
// append calls and warning text; processing later turns it into a facade result;
// output is value-only and owns all strings.


// MakeResult is defined after the directory row helpers, but the Native action
// helpers also need the same result finalizer. This forward declaration keeps
// all R3 Native code inside one translation unit without introducing another
// wrapper file or direct UI dependency.




// Row builds one generic result row from named columns. Inputs are key/value
// pairs and optional detail text; processing copies all strings; return is the
// common model row used by KernelPage.


// HexText formats a 64-bit diagnostic integer. Input is an integer value;
// processing uses uppercase hexadecimal; return is display text.


// StatusText formats NTSTATUS values without losing the original 32-bit code.
// Input is a signed NTSTATUS; return is uppercase hex display text.


// AppendFlagText appends a symbolic flag name into a compact "A|B|C" string.
// Inputs are the output text, tested value, one flag and its display name; there
// is no return value because the function mutates the output accumulator.


// ObjectAttributesText converts OBJ_* bits returned by NtQueryObject into
// readable text. Input is the raw Attributes field; return includes unknown bits
// as hex so no diagnostic information is lost.


// AccessMaskText explains common access-mask bits for native object handles.
// Input is ACCESS_MASK from ObjectBasicInformation; return is a compact
// high-level description plus unknown bits when present.


// IsSuccessStatus reports whether an NTSTATUS indicates success. Input is the
// native status code; return follows the NT_SUCCESS convention.


// StatusMeaningText explains common native status values shown by object and
// pipe actions. Input is one NTSTATUS; return is a short human-readable reason
// while preserving the raw hex in adjacent columns.


// IsRetryStatus reports whether a native query should retry with a larger
// buffer. Input is an NTSTATUS; return is true for common size statuses.


// CountedString copies a UNICODE_STRING into std::wstring. Input is the native
// string descriptor; return is empty when the descriptor has no buffer.


// MakeUnicodeString creates a temporary UNICODE_STRING view over a std::wstring.
// Input must outlive the call using the returned descriptor; return contains no
// owned memory and is safe for immediate Nt* calls only.


// MakeObjectAttributes creates case-insensitive object attributes for one
// native path. Inputs are a UNICODE_STRING and optional root handle; output is a
// stack-only OBJECT_ATTRIBUTES value for immediate Nt* calls.


// JoinObjectPath combines a directory path with a child name. Inputs are object
// manager path components; processing avoids duplicate separators; return is the
// child full path.


// ToLowerCopy normalizes type names for case-insensitive comparisons. Input is
// display text; return is a lower-case copy without modifying the original.


// ContainsI checks whether text contains a fragment ignoring case. Inputs are
// two strings; return is true when the fragment appears in text.


// StartsWithI checks whether text starts with a prefix ignoring case. Inputs are
// two strings; return is true when the prefix occupies the beginning of text.


// ParseHexOrDecimal converts display numbers such as "0x001F0003" or "123" to
// a native access mask. Input is one cell string; processing accepts hex or
// decimal and rejects partial parses; output is zero when the cell is empty or
// malformed, which keeps detail rendering safe for non-numeric rows.


// JoinStrings joins short display fragments with one separator. Inputs are
// already formatted fragments; return is empty when there are no fragments.


// DosPathCandidatesFromNtPath mirrors the original KernelSymbolicLinkWorker
// helper: it maps \Device\... targets back to visible DOS drive candidates with
// QueryDosDeviceW. Input is one NT target path; return is a de-duplicated list.


// JoinStrings joins a short list for display/filter matching. Inputs are copied
// strings and a separator; processing is linear and side-effect free; output is
// empty when there are no values.


// MatchesDirectoryFilter checks all meaningful object row fields against the
// user's filter. Inputs are one object-manager entry and a filter string;
// processing is case-insensitive; return controls whether the row is displayed.


// MatchesColumnsFilter checks generic key/value columns against user text.
// Inputs are a generic row and filter string; return is true when any key,
// value, or detail field matches case-insensitively.


// FieldValue extracts one selected-row field from an action packet. Inputs are
// the text fields copied by KernelPage and the desired key; output is empty when
// the current row does not expose the requested column.


// FirstNonEmpty returns the first non-empty string from a short candidate list.
// Inputs are already-normalized display strings; output is the preferred value
// used to resolve object paths from heterogeneous KernelResultRow layouts.


// NativePathFromAction resolves a native object path from the selected row. The
// input may be a generic object row, symbolic-link row, named-pipe row, or
// fallback filter text; output is empty only when no usable path is available.


// ObjectTypeNameFromAction resolves a type name from ObjectTypeMatrix and other
// object-result rows. Inputs are selected-row fields copied by KernelPage; the
// return value is empty only when no type-like cell exists.


// AppendObjectTypeDetailRow renders an ObjectTypeMatrix row as a first-class
// detail result. Inputs are the selected action request, resolved type name and
// packet; processing copies count/access-mask fields without opening an object;
// no value is returned because the row is appended to the packet.


// MakeNativeActionResult creates the common result packet for R3 Native row
// actions. Inputs are the action request, success flag, operation text, and
// accumulated rows/warnings; output is the same grid model used by queries.


// AppendObjectBasicInfoRow queries NtQueryObject(ObjectBasicInformation) for an
// opened object handle. Inputs are runtime, object path, handle and open status;
// processing appends a row even when the open failed so the UI shows the exact
// status rather than silently doing nothing.


// AppendQueriedObjectText asks NtQueryObject for name/type information. Inputs
// are an opened object handle and info class; processing uses the growable query
// helper shape manually because this file keeps Native actions local; output is
// one detail row when the query is available.


// Runtime loads ntdll exports lazily. Inputs are none; processing resolves each
// symbol by name; return is a cached function table.


// OpenDirectory opens an object-manager directory. Input is a native path such
// as \Device; processing calls NtOpenDirectoryObject; return is a handle that
// the caller must close or null on failure.


// OpenSymbolicLink opens one object-manager symbolic link. Input is a native
// link path; processing calls NtOpenSymbolicLinkObject; return is a closeable
// handle or null on failure.


// QuerySymbolicLinkTarget reads a symbolic-link target. Input is an opened link
// handle; processing calls NtQuerySymbolicLinkObject; return is empty on error.


// QueryBasicObjectCounts reads handle and pointer counts from any object handle.
// Inputs are runtime and object handle; processing calls NtQueryObject; output
// strings stay empty when the object does not allow the query.


// OpenNamedPipeReadOnly opens a named pipe namespace entry without reading or
// writing payload data. Inputs are runtime and native pipe path; processing uses
// NtOpenFile with FILE_READ_ATTRIBUTES|SYNCHRONIZE; return is a closeable handle
// or null while statusOut/ioStatusOut carry the exact native result.


// AppendDirectoryPreviewRows adds a small, live child preview for an opened
// object directory. Inputs are a native path and row limit; processing reuses the
// one-level directory enumerator; output rows make the right-click details page
// actionable without forcing the full recursive tab.


// DirectoryStatusText explains one object-manager row. Inputs are type and
// query state; return is compact display text for the status/details column.


// EnumerateDirectoryFlat returns one level of object-manager children. Inputs
// are runtime, directory path and warning sink; processing loops
// NtQueryDirectoryObject; return is a vector of copied entries.


// AppendDirectoryEntryRow converts one object-manager entry into a generic row.
// Inputs are a source label, depth, object entry, and enumApi text; processing
// formats the original KernelDock tree metadata plus copyable enumeration API
// text; output is appended to the query packet with no return value.


// MakeResult finalizes a worker packet. Inputs are feature id, success state,
// operation message and packet data; output is the facade result consumed by UI.


// AppendDirectoryRoot appends all direct children under one root. Inputs are a
// root path and source label; processing calls EnumerateDirectoryFlat; no value
// is returned because rows/warnings are accumulated in packet.


// CommonNamespaceRoots returns object-manager roots used by multiple pages.
// Input is none; return is an ordered list of readable high-value directories.




// QueryObjectNamespaceOverview implements the first object namespace page.
// Input is the request; processing enumerates key object directories one level;
// return contains live R3 namespace rows.


// QueryObjectDirectoryRecursive implements bounded recursive namespace walking.
// Input is the request filter as optional start path; processing BFS-enumerates
// directories with caps to keep the UI responsive; return contains tree rows.


// QuerySymbolicLinks enumerates common directories and resolves link targets.
// Input is the request; processing filters object rows by SymbolicLink type;
// return contains source path and target text.


// QueryDeviceDriverObjects enumerates object-manager device/driver roots. Input
// is the request; processing is R3-only and does not call DeviceIoControl;
// return contains Device/Driver/FileSystem object rows.


// QueryBaseNamedObjects enumerates per-session and global BaseNamedObjects.
// Input is the request; processing reads object-manager directories; return
// contains mutex/event/section/semaphore style user-visible objects.


// IsCommunicationType reports whether an object type is relevant to IPC or
// synchronization. Input is an object-manager type string; return drives the
// communication endpoint page filter.


// AppendCommunicationEndpointsRecursive walks object-manager directories with a
// small depth cap and records IPC/synchronization objects. Inputs are a root
// path, source label and filter; processing avoids revisiting directories and
// stops at the global row cap; no value is returned because rows accumulate in
// the QueryPacket.


// QueryCommunicationEndpoint enumerates user/kernel-visible communication and
// synchronization objects. Input is the request; processing filters common
// namespace roots by type; return contains endpoint rows.


// AlignPointer rounds an address up to the native pointer alignment. Input is a
// byte pointer represented as uintptr_t; return points at the next entry block.


// QueryObjectTypeMatrix calls NtQueryObject(ObjectTypesInformation). Input is
// the request; processing parses the variable-length type array; return contains
// object counts, handle counts and access masks.
void AppendObjectTypeR0Evidence(QueryPacket& packet) {
    const auto result = ksword::ark::DriverClient().enumObjectTypeTable(
        KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL,
        KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS);
    if (!result.io.ok) {
        packet.warnings.push_back(result.unsupported
            ? L"当前驱动不支持 R0 对象类型表；保留 R3 统计。"
            : L"R0 对象类型表读取失败，Win32=" + std::to_wstring(result.io.win32Error));
    }

    std::unordered_map<std::uint32_t, std::size_t> rowByIndex;
    for (std::size_t rowIndex = 0; rowIndex < packet.rows.size(); ++rowIndex) {
        KernelResultRow& row = packet.rows[rowIndex];
        for (const auto& column : row.columns) {
            if (column.first == L"TypeIndex") {
                try {
                    rowByIndex[static_cast<std::uint32_t>(std::stoul(column.second))] = rowIndex;
                } catch (...) {
                    // Preserve the R3 row even if this build returned an invalid index.
                }
                break;
            }
        }
        row.columns.emplace_back(L"R0Address", L"—");
        row.columns.emplace_back(L"R0Validation", result.io.ok ? L"R0 未返回该槽" : L"R0 不可用");
        row.columns.emplace_back(L"R0Status", L"—");
        row.columns.emplace_back(L"R0IdentityHash", L"—");
    }

    for (const auto& entry : result.entries) {
        std::size_t nameLength = 0;
        while (nameLength < KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS &&
            entry.typeName[nameLength] != L'\0') ++nameLength;
        const std::wstring r0Name(entry.typeName, nameLength);
        const auto found = rowByIndex.find(entry.typeIndex);
        const bool r3Present = found != rowByIndex.end();
        if (!r3Present) {
            KernelResultRow row = Row({
                { L"Index", std::to_wstring(entry.typeIndex) },
                { L"TypeIndex", std::to_wstring(entry.typeIndex) },
                { L"Type", r0Name.empty() ? L"<R0 名称不可用>" : r0Name },
                { L"Objects", L"—" },
                { L"Handles", L"—" },
                { L"ValidAccess", L"—" },
                { L"R0Address", L"—" },
                { L"R0Validation", L"—" },
                { L"R0Status", L"—" },
                { L"R0IdentityHash", L"—" }
            });
            packet.rows.push_back(std::move(row));
            rowByIndex[entry.typeIndex] = packet.rows.size() - 1;
        }
        KernelResultRow& target = packet.rows[rowByIndex[entry.typeIndex]];
        std::wstring r3Name;
        for (const auto& column : target.columns) {
            if (column.first == L"Type") {
                r3Name = column.second;
                break;
            }
        }
        const bool indexMatched =
            (entry.fieldFlags & KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX_MATCH) != 0;
        const bool nameMatched = !r3Present || r0Name.empty() || r3Name.empty() ||
            _wcsicmp(r0Name.c_str(), r3Name.c_str()) == 0;
        const std::wstring validation =
            entry.status == KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_INDEX_MISMATCH
                ? L"索引不一致"
                : (entry.status == KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_READ_FAILED
                    ? L"结构读取失败"
                    : (entry.objectTypeAddress == 0
                        ? L"R0 槽为空"
                        : (!r3Present
                            ? L"仅 R0 可见"
                            : (indexMatched && nameMatched ? L"槽/索引/名称一致" : L"索引或名称不一致"))));
        for (auto& column : target.columns) {
            if (column.first == L"R0Address") column.second = HexText(entry.objectTypeAddress);
            else if (column.first == L"R0Validation") column.second = validation;
            else if (column.first == L"R0Status") column.second = std::to_wstring(entry.status);
            else if (column.first == L"R0IdentityHash") column.second = HexText(entry.identityHash);
        }
    }
    if (result.io.ok && result.status != KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK) {
        packet.warnings.push_back(L"R0 对象类型表为降级结果，状态=" + std::to_wstring(result.status));
    }
}

KernelOperationResult QueryObjectTypeMatrix(const KernelRequest& request) {
    return ks::r3::kernel::QueryObjectTypeMatrixR3(request, [](QueryPacket& packet) { AppendObjectTypeR0Evidence(packet); });
}



// FileTimeText converts a native LARGE_INTEGER timestamp into local time. Input
// is a FILETIME-compatible large integer; return is compact date/time text or
// empty when the timestamp is zero.


// QueryNamedPipeDirectory enumerates one native named-pipe directory. Inputs are
// the runtime, path and packet; processing uses NtOpenFile/NtQueryDirectoryFile;
// no value is returned because rows are appended to packet.


// QueryNamedPipes enumerates native named-pipe namespaces. Input is the request;
// processing uses only Windows/Native file APIs; return lists live pipes.


// QueryAtomTable probes global atoms and registered clipboard formats. Input is
// the request; processing uses documented Win32 getters only; return contains a
// best-effort visible atom/format list.


// QueryGrowable invokes one NtQuery* function that follows the common
// buffer-size contract. Inputs are a callable and initial size; processing grows
// the buffer on size-related statuses; output is status and owned bytes.
std::pair<LONG, std::vector<std::byte>> QueryGrowable(const std::function<LONG(PVOID, ULONG, PULONG)>& query, ULONG initialSize) {
    std::vector<std::byte> buffer;
    LONG status = kStatusInfoLengthMismatch;
    ULONG bufferSize = initialSize;
    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returned = 0;
        status = query(buffer.data(), bufferSize, &returned);
        if (IsSuccessStatus(status)) {
            return { status, std::move(buffer) };
        }
        if (!IsRetryStatus(status)) {
            break;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2, returned + 0x1000);
    }
    return { status, std::move(buffer) };
}

// AppendNtQueryRow writes a safe NtQuery probe result. Inputs identify the API,
// class number, status and returned byte count; output is appended to packet.
void AppendNtQueryRow(QueryPacket& packet, const std::wstring& filter, const std::wstring& category, const std::wstring& functionName, ULONG infoClass, LONG status, std::size_t bytes, const std::wstring& detail) {
    KernelResultRow row = Row({
        { L"Category", category },
        { L"Function", functionName },
        { L"Class", std::to_wstring(infoClass) },
        { L"Status", StatusText(status) },
        { L"Success", IsSuccessStatus(status) ? L"true" : L"false" },
        { L"Bytes", std::to_wstring(bytes) },
        { L"Detail", detail },
    }, detail);
    if (MatchesColumnsFilter(row, filter)) {
        packet.rows.push_back(std::move(row));
    }
}

// AppendNtdllExportRows lists NtQuery* exports from ntdll. Input is packet;
// processing parses the PE export directory in memory; no value is returned.
void AppendNtdllExportRows(QueryPacket& packet, const std::wstring& filter) {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        packet.warnings.push_back(L"ntdll.dll 未加载，无法枚举 NtQuery* 导出。");
        return;
    }

    const auto* base = reinterpret_cast<const std::byte*>(ntdll);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        packet.warnings.push_back(L"ntdll DOS 头无效。");
        return;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        packet.warnings.push_back(L"ntdll NT 头无效。");
        return;
    }
    const IMAGE_DATA_DIRECTORY& exportData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportData.VirtualAddress == 0 || exportData.Size == 0) {
        packet.warnings.push_back(L"ntdll 无导出目录。");
        return;
    }

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exportData.VirtualAddress);
    const auto* names = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
    const auto* ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
    const auto* functions = reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);
    std::size_t added = 0;
    for (DWORD index = 0; index < exports->NumberOfNames && added < kMaxExportRows; ++index) {
        const char* exportName = reinterpret_cast<const char*>(base + names[index]);
        if (!exportName || std::strncmp(exportName, "NtQuery", 7) != 0) {
            continue;
        }
        const WORD ordinalIndex = ordinals[index];
        const DWORD rva = ordinalIndex < exports->NumberOfFunctions ? functions[ordinalIndex] : 0;
        const int wideLength = ::MultiByteToWideChar(CP_ACP, 0, exportName, -1, nullptr, 0);
        std::wstring wideName;
        if (wideLength > 0) {
            wideName.assign(static_cast<std::size_t>(wideLength - 1), L'\0');
            ::MultiByteToWideChar(CP_ACP, 0, exportName, -1, wideName.data(), wideLength);
        }
        KernelResultRow row = Row({
            { L"Category", L"Export" },
            { L"Function", wideName.empty() ? L"NtQuery*" : wideName },
            { L"Ordinal", std::to_wstring(exports->Base + ordinalIndex) },
            { L"RVA", HexText(rva) },
            { L"Status", L"Exported" },
        });
        if (MatchesColumnsFilter(row, filter)) {
            packet.rows.push_back(std::move(row));
            ++added;
        }
    }
}

// QueryNtQueryLegacy executes safe NtQuery probes against current process,
// thread and token handles, plus lists NtQuery* exports. Input is the request;
// output is a live status matrix rather than static text.
KernelOperationResult QueryNtQueryLegacy(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    AppendNtdllExportRows(packet, request.filterText);

    if (runtime.querySystemInformation) {
        const std::array<ULONG, 6> classes{ 0, 2, 3, 5, 11, 16 };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.querySystemInformation(infoClass, data, size, returned);
            }, infoClass == 11 ? 1024 * 1024 : 128 * 1024);
            AppendNtQueryRow(packet, request.filterText, L"System", L"NtQuerySystemInformation", infoClass, status, buffer.size(), L"安全枚举类探测");
        }
    } else {
        packet.warnings.push_back(L"NtQuerySystemInformation 不可用。");
    }

    if (runtime.queryInformationProcess) {
        const std::array<ULONG, 4> classes{ 0, 7, 20, 27 };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryInformationProcess(::GetCurrentProcess(), infoClass, data, size, returned);
            }, 4096);
            AppendNtQueryRow(packet, request.filterText, L"Process", L"NtQueryInformationProcess", infoClass, status, buffer.size(), L"当前进程句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationProcess 不可用。");
    }

    if (runtime.queryInformationThread) {
        const std::array<ULONG, 2> classes{ 0, 1 };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryInformationThread(::GetCurrentThread(), infoClass, data, size, returned);
            }, 4096);
            AppendNtQueryRow(packet, request.filterText, L"Thread", L"NtQueryInformationThread", infoClass, status, buffer.size(), L"当前线程句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationThread 不可用。");
    }

    if (runtime.queryInformationToken) {
        HANDLE token = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
            const std::array<ULONG, 3> classes{ 1, 25, 10 };
            for (const ULONG infoClass : classes) {
                auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                    return runtime.queryInformationToken(token, infoClass, data, size, returned);
                }, 4096);
                AppendNtQueryRow(packet, request.filterText, L"Token", L"NtQueryInformationToken", infoClass, status, buffer.size(), L"当前进程令牌");
            }
            ::CloseHandle(token);
        } else {
            packet.warnings.push_back(std::wstring(L"OpenProcessToken 失败，Win32=") + std::to_wstring(::GetLastError()));
        }
    } else {
        packet.warnings.push_back(L"NtQueryInformationToken 不可用。");
    }

    if (runtime.queryObject) {
        const std::array<ULONG, 3> classes{ kObjectBasicInformation, kObjectNameInformation, kObjectTypeInformation };
        for (const ULONG infoClass : classes) {
            auto [status, buffer] = QueryGrowable([&](PVOID data, ULONG size, PULONG returned) {
                return runtime.queryObject(::GetCurrentProcess(), infoClass, data, size, returned);
            }, 4096);
            AppendNtQueryRow(packet, request.filterText, L"Object", L"NtQueryObject", infoClass, status, buffer.size(), L"当前进程伪句柄");
        }
    } else {
        packet.warnings.push_back(L"NtQueryObject 不可用。");
    }

    return MakeResult(request.featureId, !packet.rows.empty(), L"历史 NtQuery 探测", std::move(packet));
}

// ExecuteNativeObjectDetail opens the selected object-manager path when the
// type has a safe read-only opener in this lightweight project. Inputs are the
// selected row fields; processing never guesses destructive access and records
// unsupported object types as explicit rows; output is a detailed result table.


// ExecuteNativeSymbolicLinkResolve resolves the selected symbolic link again on
// demand. Inputs are row fields or the filter edit as fallback; processing calls
// NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject only; output shows target,
// DOS candidates and object count fields so the right-click operation is useful.


// ExecuteNativeNamedPipeProbe validates whether the selected named-pipe entry
// can be opened as a native file object. Inputs are the selected Pipe/NtPath
// fields; processing uses NtOpenFile with read-only/synchronize access; output
// reports NTSTATUS and basic object metadata without reading or writing pipe
// payloads.


} // namespace

bool IsNativeKernelFeature(const KernelFeatureId id) {
    switch (id) {
    case KernelFeatureId::ObjectNamespaceOverview:
    case KernelFeatureId::ObjectDirectoryRecursive:
    case KernelFeatureId::NamedPipe:
    case KernelFeatureId::BaseNamedObjects:
    case KernelFeatureId::SymbolicLink:
    case KernelFeatureId::DeviceDriverObjects:
    case KernelFeatureId::ObjectTypeMatrix:
    case KernelFeatureId::CommunicationEndpoint:
    case KernelFeatureId::AtomTable:
    case KernelFeatureId::NtQueryLegacy:
        return true;
    default:
        return false;
    }
}

KernelOperationResult QueryNativeKernelFeature(const KernelRequest& request) {
    switch (request.featureId) {
    case KernelFeatureId::ObjectNamespaceOverview:
        return QueryObjectNamespaceOverview(request);
    case KernelFeatureId::ObjectDirectoryRecursive:
        return QueryObjectDirectoryRecursive(request);
    case KernelFeatureId::NamedPipe:
        return QueryNamedPipes(request);
    case KernelFeatureId::BaseNamedObjects:
        return QueryBaseNamedObjects(request);
    case KernelFeatureId::SymbolicLink:
        return QuerySymbolicLinks(request);
    case KernelFeatureId::DeviceDriverObjects:
        return QueryDeviceDriverObjects(request);
    case KernelFeatureId::ObjectTypeMatrix:
        return QueryObjectTypeMatrix(request);
    case KernelFeatureId::CommunicationEndpoint:
        return QueryCommunicationEndpoint(request);
    case KernelFeatureId::AtomTable:
        return QueryAtomTable(request);
    case KernelFeatureId::NtQueryLegacy:
        return QueryNtQueryLegacy(request);
    default: {
        KernelOperationResult result;
        result.supported = false;
        result.success = false;
        result.message = L"该内核条目不是 R3 Native 查询项。";
        result.rows.push_back(Row({
            { L"功能", ToDisplayName(request.featureId) },
            { L"状态", L"Unsupported native route" },
        }, result.message));
        return result;
    }
    }
}

KernelOperationResult ExecuteNativeKernelAction(const KernelActionRequest& request) {
    switch (request.actionId) {
    case KernelActionId::NativeObjectQueryDetail:
        return ExecuteNativeObjectDetail(request);
    case KernelActionId::NativeSymbolicLinkResolve:
        return ExecuteNativeSymbolicLinkResolve(request);
    case KernelActionId::NativeNamedPipeProbe:
        return ExecuteNativeNamedPipeProbe(request);
    default: {
        QueryPacket packet;
        packet.rows.push_back(Row({
            { L"功能", ToDisplayName(request.featureId) },
            { L"Action", std::to_wstring(static_cast<std::uint32_t>(request.actionId)) },
            { L"状态", L"Unsupported native action" },
        }, L"该 R3 Native 动作没有注册执行路径。"));
        return MakeNativeActionResult(request, false, L"R3 Native 动作", std::move(packet));
    }
    }
}

} // namespace Ksword::Features::Kernel
