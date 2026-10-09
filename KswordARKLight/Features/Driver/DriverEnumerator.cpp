#include "../../../shared/usermode/backend/driver/DriverQueries.h"
#include "DriverEnumerator.h"

#include "../../Core/NtApi.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Psapi.h>
#include <Softpub.h>
#include <wintrust.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cwchar>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <sstream>
#include <string>
#include <vector>

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

namespace Ksword::Features::Driver {
namespace {
using namespace ks::r3::driver;







constexpr std::size_t kMaxR0DriverObjectQueries = 64U;
constexpr std::size_t kMaxIntegrityRows = 2048U;







// KRTL_PROCESS_MODULE_INFORMATION mirrors the public structure layout used by
// NtQuerySystemInformation(SystemModuleInformation). Inputs are kernel-returned
// bytes; processing only reads the fields needed for a read-only driver view.


// KRTL_PROCESS_MODULES stores the module count followed by the first entry. The
// buffer returned by NtQuerySystemInformation is contiguous, so the caller can
// walk the array in place.


// KOBJECT_DIRECTORY_INFORMATION mirrors the structure returned by
// NtQueryDirectoryObject. Inputs are the raw directory enumeration bytes; the
// code converts them into friendly rows without any write-back.


// KOBJECT_BASIC_INFORMATION captures the counts needed for the read-only
// object-info grid. Inputs are NtQueryObject bytes; processing reads only the
// stable count fields and ignores the rest.




// NtLibraryHandle resolves the small ntdll API set once and caches the function
// pointers in a tiny value type. Inputs are none; processing uses GetProcAddress;
// output is a best-effort function table for the R3 directory/object queries.
NtLibrary NtLibraryHandle() {
    NtLibrary library{};
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    if (!ntdll) {
        return library;
    }

    library.openDirectoryObject = reinterpret_cast<NtOpenDirectoryObjectFn>(::GetProcAddress(ntdll, "NtOpenDirectoryObject"));
    library.queryDirectoryObject = reinterpret_cast<NtQueryDirectoryObjectFn>(::GetProcAddress(ntdll, "NtQueryDirectoryObject"));
    library.openSymbolicLinkObject = reinterpret_cast<NtOpenSymbolicLinkObjectFn>(::GetProcAddress(ntdll, "NtOpenSymbolicLinkObject"));
    library.querySymbolicLinkObject = reinterpret_cast<NtQuerySymbolicLinkObjectFn>(::GetProcAddress(ntdll, "NtQuerySymbolicLinkObject"));
    library.queryObject = reinterpret_cast<NtQueryObjectFn>(::GetProcAddress(ntdll, "NtQueryObject"));
    return library;
}

// IsRetryStatus identifies the common NtQuerySystemInformation growth statuses.
// Input is an NTSTATUS-compatible value; output is true when the buffer should
// be enlarged and queried again.


// WideText converts a counted UNICODE_STRING into std::wstring. Input is an
// optional string from ntdll; output is empty when the buffer is missing.


// AnsiTextToWide converts the module path returned by NtQuerySystemInformation
// into displayable UTF-16 text. Input is a narrow ANSI/OEM string view; output
// preserves ASCII-safe paths and falls back to an empty string on conversion
// failure.


// AnsiPathFromModule converts a kernel module path to UTF-16. Input is the raw
// 256-byte ANSI path from the module entry; output is the best-effort readable
// driver path for the overview grid.


// Utf8ToWide converts ArkDriverClient diagnostic text to the Win32 UI encoding.
// Input is the narrow message returned by the shared client; processing uses
// strict UTF-8 first and a byte-wise fallback; output is safe for list rows.
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

// CompactHex formats driver protocol integer fields. Input is a numeric value;
// output is uppercase hexadecimal text without assuming it is a valid pointer.


// ParseCompactHex converts a display address produced by CompactHex or
// FormatHexAddress back into an integer key. Input is UI text; processing
// accepts optional 0x prefix; output is zero when the text is not parseable.
std::uint64_t ParseCompactHex(const std::wstring& text) {
    const wchar_t* begin = text.c_str();
    while (*begin == L' ' || *begin == L'\t') {
        ++begin;
    }
    if (begin[0] == L'0' && (begin[1] == L'x' || begin[1] == L'X')) {
        begin += 2;
    }
    wchar_t* end = nullptr;
    const unsigned long long value = ::wcstoull(begin, &end, 16);
    return end != begin ? static_cast<std::uint64_t>(value) : 0;
}

// NtStatusText formats NTSTATUS-style values returned by R0. Input is a signed
// NTSTATUS; output keeps the exact 32-bit diagnostic representation.


// ResolveKernelImagePathForTrust maps common kernel image paths into local
// Win32 paths for signature checks. Input may be \SystemRoot\... or \??\...;
// processing never opens kernel objects or rewrites the original path; output
// is empty when the path cannot be safely resolved to a local file.


// VerifyDriverImageSignature performs a quiet Authenticode check for a local
// driver image. Input is the display path from module enumeration; processing
// uses WinVerifyTrust with UI disabled and a path-resolution guard; output is a
// compact trust label for the overview grid.


// ApplyOverviewAnomalies copies R0 integrity evidence labels into the module
// overview rows. Inputs are overview rows and a module-base keyed anomaly map;
// processing only updates display text; no value is returned.
void ApplyOverviewAnomalies(
    std::vector<DriverOverviewRow>& rows,
    const std::unordered_map<std::uint64_t, std::wstring>& anomalies) {
    for (DriverOverviewRow& row : rows) {
        const std::uint64_t base = ParseCompactHex(row.baseAddressText);
        const auto found = anomalies.find(base);
        if (found != anomalies.end() && !found->second.empty()) {
            row.anomalyText = found->second;
        } else {
            row.anomalyText = L"未发现 R0 完整性异常";
        }
    }
}

// ApplyOverviewIntegrityStatus writes one aggregate integrity status to every
// module row when R0 evidence cannot prove a per-module clean/risk state. Inputs
// are overview rows and status text; processing updates display text only; no
// value is returned.
void ApplyOverviewIntegrityStatus(std::vector<DriverOverviewRow>& rows, const std::wstring& statusText) {
    for (DriverOverviewRow& row : rows) {
        row.anomalyText = statusText;
    }
}

// DriverObjectQueryStatusText maps shared protocol status values to concise UI
// labels. Input is KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_*; output is text only.
const wchar_t* DriverObjectQueryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NAME_INVALID: return L"Name invalid";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_NOT_FOUND: return L"Not found";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_REFERENCE_FAILED: return L"Reference failed";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_UNAVAILABLE:
    default:
        return L"Unavailable";
    }
}

// MajorFunctionName returns the conventional IRP_MJ_* name for one dispatch
// slot. Input is a MajorFunction index; output falls back to a numbered label.
std::wstring MajorFunctionName(const std::uint32_t majorFunction) {
    switch (majorFunction) {
    case 0x00: return L"IRP_MJ_CREATE";
    case 0x01: return L"IRP_MJ_CREATE_NAMED_PIPE";
    case 0x02: return L"IRP_MJ_CLOSE";
    case 0x03: return L"IRP_MJ_READ";
    case 0x04: return L"IRP_MJ_WRITE";
    case 0x05: return L"IRP_MJ_QUERY_INFORMATION";
    case 0x06: return L"IRP_MJ_SET_INFORMATION";
    case 0x07: return L"IRP_MJ_QUERY_EA";
    case 0x08: return L"IRP_MJ_SET_EA";
    case 0x09: return L"IRP_MJ_FLUSH_BUFFERS";
    case 0x0A: return L"IRP_MJ_QUERY_VOLUME_INFORMATION";
    case 0x0B: return L"IRP_MJ_SET_VOLUME_INFORMATION";
    case 0x0C: return L"IRP_MJ_DIRECTORY_CONTROL";
    case 0x0D: return L"IRP_MJ_FILE_SYSTEM_CONTROL";
    case 0x0E: return L"IRP_MJ_DEVICE_CONTROL";
    case 0x0F: return L"IRP_MJ_INTERNAL_DEVICE_CONTROL";
    case 0x10: return L"IRP_MJ_SHUTDOWN";
    case 0x11: return L"IRP_MJ_LOCK_CONTROL";
    case 0x12: return L"IRP_MJ_CLEANUP";
    case 0x13: return L"IRP_MJ_CREATE_MAILSLOT";
    case 0x14: return L"IRP_MJ_QUERY_SECURITY";
    case 0x15: return L"IRP_MJ_SET_SECURITY";
    case 0x16: return L"IRP_MJ_POWER";
    case 0x17: return L"IRP_MJ_SYSTEM_CONTROL";
    case 0x18: return L"IRP_MJ_DEVICE_CHANGE";
    case 0x19: return L"IRP_MJ_QUERY_QUOTA";
    case 0x1A: return L"IRP_MJ_SET_QUOTA";
    case 0x1B: return L"IRP_MJ_PNP";
    default:
        return std::wstring(L"IRP_MJ_") + std::to_wstring(majorFunction);
    }
}

// LeafName extracts the last path segment. Input is a readable path; output is
// the object or file name used when the native API does not provide a separate
// basename.


// JoinObjectPath combines a root directory and child name into one object path.
// Inputs are the namespace root and child name; processing avoids duplicate
// separators; output is a valid object-manager path string.


// StatusForObjectType returns a concise Chinese diagnosis for one object row.
// Inputs are the object type and whether native information was successfully
// queried; output is a stable display string for the status column.


// CapabilityForObjectType provides the Chinese next-step hint required by the
// object view. Inputs are the object type and whether a symlink target was read;
// output tells the user what the row can support next.


// OpenNtDirectory returns an R3 handle for one object directory path. Input is
// a namespace path such as \Device; output is null when the object is missing
// or the export cannot be resolved.


// QueryBasicCounts reads handle and reference counts for a live object handle.
// Input is a native handle and the NtQueryObject export; output is true only
// when the counts were successfully copied into the output integers.


// QuerySymbolicLinkTarget reads the target path for a symbolic link object.
// Input is an opened symbolic-link handle; output is empty when the target is
// unavailable or the target buffer is too small.


// AppendDirectoryRow converts one directory entry into a DriverObjectRow. Inputs
// are the source directory path, entry name and type; processing optionally
// opens the target object for count/target diagnostics; output is the completed
// row ready for the model snapshot.


// IsDriverDirectoryRow identifies one \Driver directory entry suitable for the
// shared DriverObject query. Input is an object-manager row; output is true only
// for concrete Driver objects, not directories or symbolic links.
bool IsDriverDirectoryRow(const DriverObjectRow& row) {
    return row.directoryPathText == L"\\Driver"
        && !row.fullPathText.empty()
        && !row.objectNameText.empty()
        && row.objectTypeText == L"Driver";
}

// AppendUniqueDriverQueryName appends one DriverObject name if it has not been
// queued already. Inputs are the queue and candidate name; processing preserves
// order while avoiding duplicate R0 queries; no value is returned.
void AppendUniqueDriverQueryName(std::vector<std::wstring>& names, const std::wstring& candidate) {
    if (candidate.empty()) {
        return;
    }
    const auto exists = std::find_if(names.begin(), names.end(), [&](const std::wstring& value) {
        return _wcsicmp(value.c_str(), candidate.c_str()) == 0;
    });
    if (exists == names.end()) {
        names.push_back(candidate);
    }
}

// BuildDriverObjectQueryNames builds the R0 query list from native \Driver rows.
// Input is the object-manager snapshot; output is an ordered list of
// \Driver\Name values capped later by the caller for UI responsiveness.
std::vector<std::wstring> BuildDriverObjectQueryNames(const std::vector<DriverObjectRow>& rows) {
    std::vector<std::wstring> names;
    names.reserve(rows.size());
    for (const DriverObjectRow& row : rows) {
        if (IsDriverDirectoryRow(row)) {
            AppendUniqueDriverQueryName(names, row.fullPathText);
        }
    }
    return names;
}

// AppendDriverObjectSummaryRow writes the fixed DriverObject response header as
// one object table row. Inputs are the queried name and parsed ArkDriverClient
// result; output is appended to the model row list.
void AppendDriverObjectSummaryRow(
    const std::wstring& requestedName,
    const ksword::ark::DriverObjectQueryResult& query,
    std::vector<DriverObjectRow>& rows) {
    DriverObjectRow row;
    row.directoryPathText = L"R0 DriverObject";
    row.objectNameText = query.driverName.empty() ? requestedName : query.driverName;
    row.objectTypeText = L"DriverObject";
    row.fullPathText = requestedName;
    row.targetPathText = query.imagePath.empty() ? query.serviceKeyName : query.imagePath;
    row.referenceCountText = CompactHex(query.driverObjectAddress);
    row.handleCountText = std::to_wstring(query.totalDeviceCount);
    row.statusText = std::wstring(DriverObjectQueryStatusText(query.queryStatus)) +
        std::wstring(L"; io=") + (query.io.ok ? std::wstring(L"OK") : std::wstring(L"FAIL")) +
        std::wstring(L"; nt=") + NtStatusText(query.lastStatus);
    row.capabilityHint = std::wstring(L"ArkDriverClient::queryDriverObject; DriverStart=") +
        CompactHex(query.driverStart) + std::wstring(L"; DriverUnload=") + CompactHex(query.driverUnload) +
        std::wstring(L"; Major=") + std::to_wstring(query.majorFunctionCount) +
        std::wstring(L"; Devices=") + std::to_wstring(query.returnedDeviceCount) + std::wstring(L"/") + std::to_wstring(query.totalDeviceCount);
    row.querySucceeded = query.io.ok &&
        (query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
            query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL);
    rows.push_back(std::move(row));
}

// AppendDriverObjectMajorRows writes MajorFunction entries from the R0 response.
// Inputs are the parent query name and parsed entries; processing creates flat
// rows so the existing list view can show them without a new child table.
void AppendDriverObjectMajorRows(
    const std::wstring& requestedName,
    const ksword::ark::DriverObjectQueryResult& query,
    std::vector<DriverObjectRow>& rows) {
    for (const ksword::ark::DriverMajorFunctionEntry& entry : query.majorFunctions) {
        DriverObjectRow row;
        row.directoryPathText = L"R0 MajorFunction";
        row.objectNameText = MajorFunctionName(entry.majorFunction);
        row.objectTypeText = L"MajorFunction";
        row.fullPathText = requestedName;
        row.targetPathText = entry.moduleName;
        row.referenceCountText = CompactHex(entry.moduleBase);
        row.handleCountText = CompactHex(entry.dispatchAddress);
        row.statusText = std::wstring(L"flags=") + CompactHex(entry.flags);
        row.capabilityHint = std::wstring(L"Dispatch=") + CompactHex(entry.dispatchAddress) +
            std::wstring(L"; ModuleBase=") + CompactHex(entry.moduleBase);
        row.querySucceeded = query.io.ok;
        rows.push_back(std::move(row));
    }
    // DriverStartIo is one row next to the dispatch rows. NULL is the common,
    // healthy case, so the state travels with the row instead of a bare zero.
    if (query.startIo.state != KSWORD_ARK_DRIVER_START_IO_STATE_NOT_QUERIED) {
        const ksword::ark::DriverStartIoEntry& startIo = query.startIo;
        const bool present = startIo.state == KSWORD_ARK_DRIVER_START_IO_STATE_PRESENT;
        DriverObjectRow row;
        row.directoryPathText = L"R0 DriverStartIo";
        row.objectNameText = L"DriverStartIo";
        row.objectTypeText = L"DriverStartIo";
        row.fullPathText = requestedName;
        row.targetPathText = startIo.moduleName;
        row.referenceCountText = present ? CompactHex(startIo.moduleBase) : std::wstring(L"-");
        row.handleCountText = present ? CompactHex(startIo.address) : std::wstring(L"-");
        row.statusText = present
            ? std::wstring(L"present; flags=") + CompactHex(startIo.flags)
            : (startIo.state == KSWORD_ARK_DRIVER_START_IO_STATE_NULL
                ? std::wstring(L"null")
                : std::wstring(L"read-failed"));
        row.capabilityHint = std::wstring(L"DriverObject->DriverStartIo");
        row.querySucceeded = query.io.ok;
        rows.push_back(std::move(row));
    }
}

// AppendDriverObjectDeviceRows writes DeviceObject/AttachedDevice entries from
// the R0 response. Inputs are the parent query and parsed device chain; output
// is appended rows that preserve all address diagnostics as display text.
void AppendDriverObjectDeviceRows(
    const std::wstring& requestedName,
    const ksword::ark::DriverObjectQueryResult& query,
    std::vector<DriverObjectRow>& rows) {
    for (const ksword::ark::DriverDeviceEntry& entry : query.devices) {
        DriverObjectRow row;
        row.directoryPathText = L"R0 DeviceObject";
        row.objectNameText = entry.deviceName.empty() ? CompactHex(entry.deviceObjectAddress) : entry.deviceName;
        row.objectTypeText = entry.relationDepth == 0 ? L"DeviceObject" : L"AttachedDevice";
        row.fullPathText = requestedName;
        row.targetPathText = entry.deviceName;
        row.referenceCountText = CompactHex(entry.deviceObjectAddress);
        row.handleCountText = CompactHex(entry.attachedDeviceObjectAddress);
        row.statusText = std::wstring(L"nameStatus=") + NtStatusText(entry.nameStatus) +
            std::wstring(L"; depth=") + std::to_wstring(entry.relationDepth);
        row.capabilityHint = std::wstring(L"Type=") + CompactHex(entry.deviceType) +
            std::wstring(L"; Flags=") + CompactHex(entry.flags) +
            std::wstring(L"; Next=") + CompactHex(entry.nextDeviceObjectAddress) +
            std::wstring(L"; DriverObject=") + CompactHex(entry.driverObjectAddress);
        row.querySucceeded = query.io.ok;
        rows.push_back(std::move(row));
    }
}

// DriverIntegrityStatusText maps aggregate R0 integrity status codes into
// compact labels. Input is KSWORD_ARK_DRIVER_INTEGRITY_STATUS_*; output is
// display-only text for the object table and diagnostics.
const wchar_t* DriverIntegrityStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK: return L"OK";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND: return L"Not found";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE:
    default:
        return L"Unavailable";
    }
}

// DriverIntegrityClassText gives a stable evidence bucket name. Input is one
// R0 evidenceClass value; output names DriverObject, DeviceObject, FastIo,
// optional globals such as MmUnloadedDrivers/PiDDB, or a numbered fallback.
std::wstring DriverIntegrityClassText(const std::uint32_t evidenceClass) {
    switch (evidenceClass) {
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return L"ModuleView";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return L"PsLoadedModules";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return L"DriverObject";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return L"DriverSection";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return L"MajorFunction";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return L"FastIo";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_START_IO: return L"StartIo";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return L"DeviceObject";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return L"Service";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return L"MmUnloaded/PiDDB";
    default:
        return L"IntegrityClass" + std::to_wstring(evidenceClass);
    }
}

// AppendRiskName appends a risk label if its bit is set. Inputs are a vector,
// the raw risk mask, the bit and label; processing only mutates the vector; no
// value is returned.
void AppendRiskName(std::vector<std::wstring>& names, const std::uint32_t flags, const std::uint32_t bit, const wchar_t* label) {
    if ((flags & bit) != 0) {
        names.push_back(label);
    }
}

// JoinText joins small display labels with a separator. Input is a vector of
// labels and a fallback; output is a compact string for status/capability cells.
std::wstring JoinText(const std::vector<std::wstring>& values, const wchar_t* fallback) {
    if (values.empty()) {
        return fallback;
    }
    std::wstring text;
    for (const std::wstring& value : values) {
        if (!text.empty()) {
            text += L"|";
        }
        text += value;
    }
    return text;
}

// DriverIntegrityRiskText expands R0 risk bits into UI labels. Input is the
// raw KSWORD_ARK_DRIVER_INTEGRITY_RISK_* mask; output is "None" or a pipe-
// separated list that preserves unknown bits as hexadecimal evidence.
std::wstring DriverIntegrityRiskText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE, L"Unavailable");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, L"QueryFailed");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED, L"ModuleUnresolved");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH, L"OwnerMismatch");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE, L"OutsideImage");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH, L"SectionMismatch");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING, L"ServiceMissing");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD, L"EmptyUnload");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP, L"DeviceLoop");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP, L"AttachedLoop");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH, L"CrossDriverAttach");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER, L"NullPointer");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE, L"DynDataUnavailable");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED, L"Truncated");
    if (flags != 0) {
        names.push_back(L"raw=" + CompactHex(flags));
    }
    return JoinText(names, L"None");
}

// DriverIntegritySourceText expands the R0 source mask into compact labels.
// Input is KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_* bits; output is "None" or a
// pipe-separated source list for the capability hint.
std::wstring DriverIntegritySourceText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, L"SystemModule");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, L"AuxKlib");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES, L"PsLoadedModules");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, L"DriverObject");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION, L"DriverSection");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, L"ServiceRegistry");
    AppendRiskName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA, L"DynData");
    return JoinText(names, L"None");
}

// AppendOverviewAnomaly records the first non-empty anomaly string for a module
// base. Inputs are the anomaly map, base address and text; processing preserves
// existing higher-context messages; no value is returned.
void AppendOverviewAnomaly(std::unordered_map<std::uint64_t, std::wstring>& anomalies, const std::uint64_t moduleBase, const std::wstring& text) {
    if (moduleBase == 0 || text.empty()) {
        return;
    }
    auto& slot = anomalies[moduleBase];
    if (slot.empty()) {
        slot = text;
    } else if (slot.find(text) == std::wstring::npos) {
        slot += L"; ";
        slot += text;
    }
}

// AppendDriverIntegrityEvidenceRows converts the read-only DriverIntegrity
// response into object-grid rows. Inputs are the parsed ArkDriverClient result
// and anomaly map; processing appends local UI rows only; no R0 mutation is
// performed or exposed.
void AppendDriverIntegrityEvidenceRows(
    const ksword::ark::DriverIntegrityResult& query,
    std::vector<DriverObjectRow>& rows,
    std::unordered_map<std::uint64_t, std::wstring>& anomalies) {
    DriverObjectRow summary;
    summary.directoryPathText = L"R0 DriverIntegrity";
    summary.objectNameText = L"Summary";
    summary.objectTypeText = L"DriverIntegrity";
    summary.fullPathText = L"ArkDriverClient::queryDriverIntegrity";
    summary.targetPathText = Utf8ToWide(query.io.message);
    summary.referenceCountText = std::to_wstring(query.returnedCount);
    summary.handleCountText = std::to_wstring(query.totalCount);
    summary.statusText = std::wstring(DriverIntegrityStatusText(query.queryStatus)) +
        L"; io=" + (query.io.ok ? std::wstring(L"OK") : std::wstring(L"FAIL")) +
        L"; nt=" + NtStatusText(query.lastStatus) +
        L"; statusFlags=" + CompactHex(query.statusFlags);
    summary.capabilityHint = L"Source=" + DriverIntegritySourceText(query.sourceMask) +
        L"; Modules=" + std::to_wstring(query.moduleCount) +
        L"; FieldFlags=" + CompactHex(query.fieldFlags) +
        L"; Read-only DriverObject/DeviceObject/MajorFunction/FastIo/MmUnloadedDrivers/PiDDB evidence";
    summary.querySucceeded = query.io.ok;
    rows.push_back(std::move(summary));

    for (const ksword::ark::DriverIntegrityEvidenceEntry& entry : query.entries) {
        DriverObjectRow row;
        const std::wstring classText = DriverIntegrityClassText(entry.evidenceClass);
        const std::wstring riskText = DriverIntegrityRiskText(entry.riskFlags);
        row.directoryPathText = L"R0 DriverIntegrity";
        row.objectNameText = entry.ownerModule.empty() ? classText : entry.ownerModule;
        row.objectTypeText = classText;
        row.fullPathText = entry.detail;
        row.targetPathText = entry.ownerModule;
        row.referenceCountText = CompactHex(entry.objectAddress);
        row.handleCountText = CompactHex(entry.targetAddress);
        row.statusText = L"risk=" + riskText +
            L"; entryStatus=" + std::to_wstring(entry.entryStatus) +
            L"; statusFlags=" + CompactHex(entry.statusFlags) +
            L"; score=" + std::to_wstring(entry.riskScore) +
            L"; confidence=" + std::to_wstring(entry.confidence);
        row.capabilityHint = L"source=" + DriverIntegritySourceText(entry.sourceMask) +
            L"; ownerBase=" + CompactHex(entry.ownerModuleBase) +
            L"; ownerSize=" + CompactHex(entry.ownerModuleSize) +
            L"; fieldMask=" + CompactHex(entry.fieldMask) +
            L"; driverObject=" + CompactHex(entry.driverObjectAddress) +
            L"; kldr=" + CompactHex(entry.kldrEntryAddress);
        row.querySucceeded = query.io.ok;
        rows.push_back(std::move(row));

        if (entry.riskFlags != KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE) {
            AppendOverviewAnomaly(anomalies, entry.ownerModuleBase, classText + L":" + riskText);
        }
    }
}

// EnrichDriverIntegrityWithR0 queries read-only driver integrity evidence once
// and appends it to the object table while also returning module-base anomaly
// labels for the overview grid. Inputs are mutable rows/warnings/anomalies;
// processing uses ArkDriverClient only; no value is returned.
bool EnrichDriverIntegrityWithR0(
    std::vector<DriverObjectRow>& rows,
    std::vector<std::wstring>& warnings,
    std::unordered_map<std::uint64_t, std::wstring>& anomalies) {
    const ksword::ark::DriverClient client;
    const ksword::ark::DriverIntegrityResult query = client.queryDriverIntegrity(
        std::wstring(),
        0,
        KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DRIVER_OBJECT |
            KSWORD_ARK_DRIVER_INTEGRITY_FLAG_SERVICE |
            KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS,
        static_cast<unsigned long>(kMaxIntegrityRows),
        0);

    if (!query.io.ok) {
        warnings.push_back(std::wstring(L"R0 DriverIntegrity 查询跳过：") + Utf8ToWide(query.io.message));
        return false;
    }

    AppendDriverIntegrityEvidenceRows(query, rows, anomalies);
    warnings.push_back(std::wstring(L"R0 DriverIntegrity 只读证据完成：") +
        DriverIntegrityStatusText(query.queryStatus) +
        L"，Rows=" + std::to_wstring(query.entries.size()) +
        L"/" + std::to_wstring(query.totalCount) + L"。");
    return query.queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK ||
        query.queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL;
}

// EnrichDriverObjectsWithR0 appends real KswordARK DriverObject evidence to the
// object table. Inputs are existing rows and warnings; processing uses
// ArkDriverClient only, never direct transport calls; no value is returned.
void EnrichDriverObjectsWithR0(std::vector<DriverObjectRow>& rows, std::vector<std::wstring>& warnings) {
    const std::vector<std::wstring> queryNames = BuildDriverObjectQueryNames(rows);
    if (queryNames.empty()) {
        warnings.push_back(L"未发现可用于 R0 DriverObject 查询的 \\Driver 条目。");
        return;
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::DriverCapabilitiesQueryResult capability = client.queryDriverCapabilities();
    if (!capability.io.ok) {
        warnings.push_back(std::wstring(L"R0 DriverObject 查询跳过：KswordARK 驱动不可用或能力查询失败，Win32=") +
            std::to_wstring(capability.io.win32Error) + std::wstring(L"，") + Utf8ToWide(capability.io.message));
        return;
    }

    const std::size_t queryLimit = std::min<std::size_t>(queryNames.size(), kMaxR0DriverObjectQueries);
    std::size_t okCount = 0;
    std::size_t partialCount = 0;
    std::size_t failCount = 0;
    for (std::size_t index = 0; index < queryLimit; ++index) {
        const std::wstring& driverName = queryNames[index];
        const ksword::ark::DriverObjectQueryResult query = client.queryDriverObject(
            driverName,
            KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
            KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
            KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
        AppendDriverObjectSummaryRow(driverName, query, rows);
        if (query.io.ok &&
            (query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
                query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL)) {
            AppendDriverObjectMajorRows(driverName, query, rows);
            AppendDriverObjectDeviceRows(driverName, query, rows);
            if (query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL) {
                ++partialCount;
            } else {
                ++okCount;
            }
        } else {
            ++failCount;
        }
    }

    std::wstring summary = std::wstring(L"R0 DriverObject 查询完成：OK=") + std::to_wstring(okCount) +
        std::wstring(L"，Partial=") + std::to_wstring(partialCount) +
        std::wstring(L"，Failed=") + std::to_wstring(failCount) +
        std::wstring(L"，Queued=") + std::to_wstring(queryNames.size()) + std::wstring(L"。");
    if (queryNames.size() > queryLimit) {
        summary += std::wstring(L"为避免刷新阻塞，本次只查询前 ") + std::to_wstring(queryLimit) + std::wstring(L" 项。");
    }
    warnings.push_back(std::move(summary));
}

// QueryModuleInformation collects loaded kernel modules through NtQuerySystemInformation.
// Inputs are none; processing uses a growable buffer; output rows are used for
// the overview page when the native module contract is available.


// QueryPsapiModules collects loaded drivers through Psapi as a degraded path.
// Inputs are none; processing keeps the page usable when ntdll module queries
// are unavailable; output rows contain base/path text and an unknown-size mark.


// QueryObjectDirectory enumerates one root namespace directory without any
// recursive descent. Inputs are a directory path and output row vector; the
// processing keeps directory children flat so the view can show only one level.


} // namespace

DriverEnumerationResult EnumerateDriverSnapshot() {
    DriverEnumerationResult result;
    std::wstring moduleDiagnostic;
    if (!QueryModuleInformation(result.overviewRows, moduleDiagnostic)) {
        result.overviewRows.clear();
        if (!QueryPsapiModules(result.overviewRows, moduleDiagnostic)) {
            result.success = false;
            result.win32Error = ::GetLastError();
            result.diagnosticText = moduleDiagnostic;
            return result;
        }
    }

    const NtLibrary library = NtLibraryHandle();
    if (!library.openDirectoryObject || !library.queryDirectoryObject) {
        result.success = !result.overviewRows.empty();
        result.diagnosticText = moduleDiagnostic + L" 对象目录导出不可用。";
        std::vector<std::wstring> warnings;
        std::unordered_map<std::uint64_t, std::wstring> integrityAnomalies;
        if (EnrichDriverIntegrityWithR0(result.objectRows, warnings, integrityAnomalies)) {
            ApplyOverviewAnomalies(result.overviewRows, integrityAnomalies);
        } else {
            ApplyOverviewIntegrityStatus(result.overviewRows, L"R0 DriverIntegrity 不可用或未完成");
        }
        for (const std::wstring& warning : warnings) {
            result.diagnosticText += L" ";
            result.diagnosticText += warning;
        }
        return result;
    }

    std::vector<std::wstring> warnings;
    const std::array<std::wstring, 4> roots{
        L"\\Device",
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters"
    };

    for (const std::wstring& root : roots) {
        QueryObjectDirectory(library, root, result.objectRows, warnings);
    }
    EnrichDriverObjectsWithR0(result.objectRows, warnings);
    std::unordered_map<std::uint64_t, std::wstring> integrityAnomalies;
    if (EnrichDriverIntegrityWithR0(result.objectRows, warnings, integrityAnomalies)) {
        ApplyOverviewAnomalies(result.overviewRows, integrityAnomalies);
    } else {
        ApplyOverviewIntegrityStatus(result.overviewRows, L"R0 DriverIntegrity 不可用或未完成");
    }

    if (!warnings.empty()) {
        result.diagnosticText = moduleDiagnostic;
        for (const std::wstring& warning : warnings) {
            if (!result.diagnosticText.empty()) {
                result.diagnosticText += L" ";
            }
            result.diagnosticText += warning;
        }
    } else {
        result.diagnosticText = moduleDiagnostic + L" 对象目录已枚举。";
    }

    result.success = !result.overviewRows.empty() || !result.objectRows.empty();
    result.win32Error = ERROR_SUCCESS;
    if (result.diagnosticText.empty()) {
        result.diagnosticText = L"已完成驱动概览和对象信息枚举。";
    }
    return result;
}

} // namespace Ksword::Features::Driver
