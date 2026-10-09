#include "ProcessDetailCollector.h"
#include "../../../shared/usermode/backend/process/ProcessThreadsSupport.h"
#include "../../../shared/usermode/backend/process/ProcessBasicInfo.h"
#include "../../../shared/usermode/backend/process/ProcessBasicInfoSupport.h"

#include "../../Core/Common.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <psapi.h>
#include <sstream>
#include <tlhelp32.h>
#include <utility>
#include <winternl.h>

namespace Ksword::Features::ProcessDetail {
namespace {
using namespace ks::r3::process_detail::detail;
using ks::r3::process_detail::CollectBasicInfo;
using namespace ks::r3::process_detail::detail;











using EnumProcessModulesExFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
using GetModuleInformationFn = BOOL(WINAPI*)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
using GetModuleFileNameExWFn = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);

// NativeProcessBasicInformation is the stable native layout for class 0.
// Inputs come from NtQueryInformationProcess; processing reads only the PEB
// address and inherited PID; output avoids SDK field-name differences.


// RemotePeb mirrors only the early PEB fields needed to reach ProcessParameters.
// Input is target memory copied by ReadProcessMemory; processing uses the
// processParameters pointer only; output is not written back to the target.


// ModuleApi stores dynamically resolved PSAPI/K32 module enumeration exports.
// Inputs are loader module handles from LoadModuleApi; processing never requires
// adding a PSAPI import library to the project; callers check available() first.
struct ModuleApi {
    HMODULE library = nullptr;
    EnumProcessModulesExFn enumProcessModulesEx = nullptr;
    GetModuleInformationFn getModuleInformation = nullptr;
    GetModuleFileNameExWFn getModuleFileNameExW = nullptr;

    // available reports whether every module enumeration export was resolved.
    // There is no input; processing checks stored function pointers; output is
    // true only when CollectModules can call the API set safely.
    bool available() const {
        return enumProcessModulesEx && getModuleInformation && getModuleFileNameExW;
    }
};

// NtThreadApi stores optional ntdll thread metadata exports. Inputs are dynamic
// loader results; processing is read-only and optional; callers may continue
// with Toolhelp-only rows when the export is unavailable.


// RemoteProcessParameters mirrors only the offsets needed for same-bitness
// command-line reading. The structure is deliberately partial because the page
// does not mutate remote memory and only reads ImagePathName/CommandLine.


// FormatHexPointer formats an address for list-view display. Input is an
// integer pointer value; processing emits fixed-width hexadecimal text; output
// is a string such as 0x00007FF612340000.
std::wstring FormatHexPointer(std::uintptr_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase;
    if (sizeof(void*) == 8) {
        stream.width(16);
    } else {
        stream.width(8);
    }
    stream.fill(L'0');
    stream << value;
    return stream.str();
}

// NarrowToWide converts ArkDriverClient diagnostics and row details to UI text.
// Input is UTF-8/ASCII from the shared client; output is best-effort UTF-16.
std::wstring NarrowToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    int chars = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    UINT codePage = CP_UTF8;
    if (chars <= 0) {
        codePage = CP_ACP;
        chars = ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    }
    if (chars <= 0) {
        return L"<decode failed>";
    }

    std::wstring wide(static_cast<std::size_t>(chars), L'\0');
    ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), wide.data(), chars);
    return wide;
}

// HexMaskText formats raw source/anomaly masks for diagnostics. Input is a
// protocol mask; output remains stable when future bits are added.
std::wstring HexMaskText(ULONG value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// CrossViewSourceText renders shared process/thread source bits. Input is the
// R0 sourceMask; output uses protocol source names shown by the GUI pages.
std::wstring CrossViewSourceText(ULONG sourceMask) {
    std::vector<std::wstring> parts;
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0) {
        parts.push_back(L"Public");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0) {
        parts.push_back(L"ActiveProcessLinks");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0) {
        parts.push_back(L"CID");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0) {
        parts.push_back(L"ThreadListHead");
    }
    if (parts.empty()) {
        return L"无来源";
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"+";
        }
        text += part;
    }
    return text;
}

// CrossViewAnomalyText maps known anomaly flags to readable labels. Input is
// the raw protocol mask; output keeps unknown bits visible for audit export.
std::wstring CrossViewAnomalyText(ULONG anomalyFlags) {
    if (anomalyFlags == 0) {
        return L"未见异常";
    }

    std::vector<std::wstring> parts;
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) != 0) {
        parts.push_back(L"CID-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) != 0) {
        parts.push_back(L"Active-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) != 0) {
        parts.push_back(L"缺ActiveProcessLinks");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) != 0) {
        parts.push_back(L"缺CID");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) != 0) {
        parts.push_back(L"孤儿线程");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) != 0) {
        parts.push_back(L"缺ThreadListHead");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) != 0) {
        parts.push_back(L"入口不在模块");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0) {
        parts.push_back(L"PID不一致");
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"; ";
        }
        text += part;
    }
    if (text.empty()) {
        text = L"未知异常位 " + HexMaskText(anomalyFlags);
    }
    return text;
}

// Win32ErrorText returns a compact Win32 failure string. Input is an operation
// label and error code; processing appends the formatted system message; output
// is suitable for per-row or per-section status text.


// ResolveProc resolves one function by exact export name. Inputs are a module
// handle and ASCII export name; processing calls GetProcAddress; output is a
// typed function pointer or nullptr.


// LoadModuleApi resolves module enumeration APIs from kernel32 K32* exports or
// psapi.dll fallback exports. There is no input; processing may load psapi.dll;
// output reports function pointers and keeps the library loaded for process
// lifetime so pointers remain valid.
ModuleApi LoadModuleApi() {
    ModuleApi api{};

    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    api.library = kernel32;
    api.enumProcessModulesEx = ResolveProc<EnumProcessModulesExFn>(kernel32, "K32EnumProcessModulesEx");
    api.getModuleInformation = ResolveProc<GetModuleInformationFn>(kernel32, "K32GetModuleInformation");
    api.getModuleFileNameExW = ResolveProc<GetModuleFileNameExWFn>(kernel32, "K32GetModuleFileNameExW");
    if (api.available()) {
        return api;
    }

    HMODULE psapi = ::GetModuleHandleW(L"psapi.dll");
    if (!psapi) {
        psapi = ::LoadLibraryW(L"psapi.dll");
    }
    api.library = psapi;
    api.enumProcessModulesEx = ResolveProc<EnumProcessModulesExFn>(psapi, "EnumProcessModulesEx");
    api.getModuleInformation = ResolveProc<GetModuleInformationFn>(psapi, "GetModuleInformation");
    api.getModuleFileNameExW = ResolveProc<GetModuleFileNameExWFn>(psapi, "GetModuleFileNameExW");
    return api;
}

// LoadNtThreadApi resolves NtQueryInformationThread. There is no input;
// processing reads ntdll from the current process; output may be unavailable on
// unusual systems but does not fail the thread snapshot.


// QueryProcessImagePath reads the target image path through QueryFullProcess-
// ImageNameW. Input is an opened process handle; processing grows a local fixed
// buffer; output is the path or a diagnostic string.


// LeafNameFromPath returns the final path component. Input may be a full DOS
// path or a bare image name; output is empty only when the input is empty.


// QuerySnapshotIdentity uses the public Toolhelp process snapshot to fill the
// target/parent names and the target's snapshot thread count. Inputs are the
// target and parent PIDs; output fields remain unchanged when rows disappeared.


// FormatProcessStartTime converts a creation FILETIME into local wall-clock
// text. Input is UTC FILETIME; output is YYYY-MM-DD HH:MM:SS or unavailable.


// PriorityClassText maps GetPriorityClass values to stable user-facing text.
// Input is zero on query failure; output preserves failure as unavailable.


// SaturatingAdd64 aggregates monotonically increasing I/O counters without
// wrapping when a long-lived process approaches the unsigned 64-bit limit.


// QueryProcessSession reads the Terminal Services session for one PID. Input is
// processId; processing calls ProcessIdToSessionId; output is zero on failure
// and the caller records a status message separately.


// QueryTokenText opens the process token for user and integrity strings. Inputs
// are a process handle and output references; processing uses read-only token
// queries; output strings are diagnostic-safe even when access is denied.


// QueryBitnessText determines process architecture without injecting or
// executing target code. Input is process handle; processing prefers
// IsWow64Process2 then falls back to IsWow64Process; output is UI text.


// QueryNativeProcessBasicInformation reads stable class-zero process metadata.
// Input is an opened process handle; output carries PPID, PEB and affinity.


// QueryParentProcessId uses ProcessBasicInformation when available. Input is an
// opened process handle; output is zero when unavailable.


// ReadRemoteUnicodeString copies a UNICODE_STRING value from the target process.
// Inputs are a process handle and a remote string descriptor; processing caps
// the read size and calls ReadProcessMemory once; output is text or a diagnostic.


// QueryCommandLineText reads the target process command line from the PEB when
// readable. Input is a process handle; processing uses NtQueryInformationProcess
// for the PEB address and ReadProcessMemory for ProcessParameters; output is the
// command line or a failure reason without blocking the rest of the page.


// CollectBasicInfo reads the basic tab fields. Input is a PID; processing opens
// the process with limited read access and tolerates partial failure; output is
// a filled ProcessBasicInfo plus a success bit.


// CollectThreads enumerates threads owned by the target PID. Input is processId;
// processing uses CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD), then revalidates
// each opened thread's owner and creation time before retaining it in the snapshot.


// BaseNameFromPath extracts the final path component. Input is a full path;
// processing searches slash and backslash separators; output is never longer
// than the input and may equal the input for bare names.
std::wstring BaseNameFromPath(const std::wstring& path) {
    const std::size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos + 1 >= path.size()) {
        return path;
    }
    return path.substr(pos + 1);
}

// CollectModules enumerates modules loaded in the process. Input is processId;
// processing uses EnumProcessModulesEx and GetModuleInformation/GetModuleFile-
// NameExW; output is sorted by base address with per-row status.
std::vector<ProcessModuleInfo> CollectModules(DWORD processId, bool& succeededOut, std::wstring& statusOut) {
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessModuleInfo> rows;

    const ModuleApi moduleApi = LoadModuleApi();
    if (!moduleApi.available()) {
        statusOut = L"Module enumeration API unavailable.";
        return rows;
    }

    Ksword::Core::UniqueHandle process(::OpenProcess(kProcessReadAccess, FALSE, processId));
    if (!process.valid()) {
        statusOut = Win32ErrorText(L"OpenProcess", ::GetLastError());
        return rows;
    }

    DWORD neededBytes = 0;
    std::vector<HMODULE> modules(256);
    if (!moduleApi.enumProcessModulesEx(process.get(), modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &neededBytes, LIST_MODULES_ALL)) {
        statusOut = Win32ErrorText(L"EnumProcessModulesEx", ::GetLastError());
        return rows;
    }
    if (neededBytes > modules.size() * sizeof(HMODULE)) {
        modules.resize(neededBytes / sizeof(HMODULE));
        if (!moduleApi.enumProcessModulesEx(process.get(), modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &neededBytes, LIST_MODULES_ALL)) {
            statusOut = Win32ErrorText(L"EnumProcessModulesEx retry", ::GetLastError());
            return rows;
        }
    }
    modules.resize(neededBytes / sizeof(HMODULE));

    for (HMODULE module : modules) {
        ProcessModuleInfo row{};
        MODULEINFO moduleInfo{};
        if (moduleApi.getModuleInformation(process.get(), module, &moduleInfo, sizeof(moduleInfo))) {
            row.baseAddress = reinterpret_cast<std::uintptr_t>(moduleInfo.lpBaseOfDll);
            row.imageSize = moduleInfo.SizeOfImage;
        }

        std::wstring path(MAX_PATH, L'\0');
        DWORD copied = moduleApi.getModuleFileNameExW(process.get(), module, path.data(), static_cast<DWORD>(path.size()));
        if (copied >= path.size() - 1) {
            path.resize(kMaxPathBufferChars, L'\0');
            copied = moduleApi.getModuleFileNameExW(process.get(), module, path.data(), static_cast<DWORD>(path.size()));
        }
        if (copied > 0) {
            path.resize(copied);
            row.modulePath = path;
            row.moduleName = BaseNameFromPath(path);
            row.statusText = L"OK";
        } else {
            row.moduleName = FormatHexPointer(reinterpret_cast<std::uintptr_t>(module));
            row.modulePath = L"<module path unavailable>";
            row.statusText = Win32ErrorText(L"GetModuleFileNameExW", ::GetLastError());
        }
        rows.push_back(std::move(row));
    }

    succeededOut = true;
    statusOut = L"OK";
    std::sort(rows.begin(), rows.end(), [](const ProcessModuleInfo& left, const ProcessModuleInfo& right) {
        return left.baseAddress < right.baseAddress;
    });
    return rows;
}

// AttachRepresentativeThreads maps already-collected thread start addresses to
// loaded module address ranges. Inputs are the module rows and thread rows from
// the same PID snapshot; processing chooses the first thread whose Win32 start
// address lies inside each module; no value is returned because modules are
// updated in place for the Modules tab context menu.
void AttachRepresentativeThreads(
    std::vector<ProcessModuleInfo>& modules,
    const std::vector<ProcessThreadInfo>& threads) {
    if (modules.empty() || threads.empty()) {
        return;
    }

    for (ProcessModuleInfo& module : modules) {
        const std::uintptr_t moduleStart = module.baseAddress;
        const std::uintptr_t moduleEnd = moduleStart + static_cast<std::uintptr_t>(module.imageSize);
        if (moduleStart == 0 || moduleEnd <= moduleStart) {
            continue;
        }

        for (const ProcessThreadInfo& thread : threads) {
            if (thread.creationTime100ns != 0U &&
                thread.startAddress >= moduleStart && thread.startAddress < moduleEnd) {
                module.representativeThreadId = thread.threadId;
                module.representativeThreadCreationTime100ns = thread.creationTime100ns;
                break;
            }
        }
    }
}

// AddR0AuditRow appends one read-only driver evidence row to the ProcessDetail
// R0 tab. Inputs are the target vector and display-ready scalar fields;
// processing preserves object addresses only for display and never feeds them
// into write operations; there is no return value.
void AddR0AuditRow(
    std::vector<ProcessR0AuditInfo>& rows,
    const std::wstring& scope,
    DWORD processId,
    DWORD threadId,
    std::uint64_t objectAddress,
    std::uint64_t relatedObjectAddress,
    std::uint64_t startAddress,
    const std::wstring& sourceText,
    const std::wstring& statusText,
    ULONG confidence,
    const std::wstring& detailText) {
    ProcessR0AuditInfo row{};
    row.scope = scope;
    row.processId = processId;
    row.threadId = threadId;
    row.objectAddress = static_cast<std::uintptr_t>(objectAddress);
    row.relatedObjectAddress = static_cast<std::uintptr_t>(relatedObjectAddress);
    row.startAddress = static_cast<std::uintptr_t>(startAddress);
    row.confidence = confidence;
    row.sourceText = sourceText;
    row.anomalyText = statusText;
    row.detailText = detailText;
    rows.push_back(std::move(row));
}

// StatusHexText renders an NTSTATUS/LONG as fixed hexadecimal text. Input is a
// signed status value from the driver protocol; output is a UI diagnostic token.
std::wstring StatusHexText(long status) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << static_cast<unsigned long>(status);
    return stream.str();
}

// BuildProcessRuntimeSampleItems derives safe field-sample requests from the
// fixed process detail response. Inputs are offsets already returned by R0;
// processing keeps only known, bounded EPROCESS fields; output is suitable for
// ArkDriverClient::queryProcessRuntimeFieldSamples.
std::vector<ksword::ark::RuntimeFieldSampleRequestItem> BuildProcessRuntimeSampleItems(
    const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& detail) {
    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> items;
    const auto add = [&](std::uint32_t id, std::uint32_t offset, std::uint32_t size, const char* name, const char* type) {
        if (offset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE || size == 0 || size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES) {
            return;
        }
        ksword::ark::RuntimeFieldSampleRequestItem item{};
        item.runtimeItemId = id;
        item.offset = offset;
        item.size = size;
        item.name = name;
        item.type = type;
        items.push_back(std::move(item));
    };
    add(KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID, detail.offsets.epUniqueProcessId, sizeof(std::uint64_t), "EP.UniqueProcessId", "HANDLE");
    add(KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS, detail.offsets.epActiveProcessLinks, sizeof(std::uint64_t), "EP.ActiveProcessLinks", "LIST_ENTRY.Flink");
    add(KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD, detail.offsets.epThreadListHead, sizeof(std::uint64_t), "EP.ThreadListHead", "LIST_ENTRY.Flink");
    add(KSW_DYN_FIELD_ID_EP_TOKEN, detail.offsets.epToken, sizeof(std::uint64_t), "EP.Token", "EX_FAST_REF");
    add(KSW_DYN_FIELD_ID_EP_OBJECT_TABLE, detail.offsets.epObjectTable, sizeof(std::uint64_t), "EP.ObjectTable", "EXHANDLE_TABLE*");
    add(KSW_DYN_FIELD_ID_EP_SECTION_OBJECT, detail.offsets.epSectionObject, sizeof(std::uint64_t), "EP.SectionObject", "SECTION_OBJECT*");
    add(KSW_DYN_FIELD_ID_EP_PROTECTION, detail.offsets.epProtection, sizeof(std::uint8_t), "EP.Protection", "PS_PROTECTION");
    add(KSW_DYN_FIELD_ID_EP_SIGNATURE_LEVEL, detail.offsets.epSignatureLevel, sizeof(std::uint8_t), "EP.SignatureLevel", "UCHAR");
    add(KSW_DYN_FIELD_ID_EP_SECTION_SIGNATURE_LEVEL, detail.offsets.epSectionSignatureLevel, sizeof(std::uint8_t), "EP.SectionSignatureLevel", "UCHAR");
    return items;
}

// BuildThreadRuntimeSampleItems derives safe field-sample requests from the
// fixed thread detail response. Inputs are R0-provided ETHREAD/KTHREAD offsets;
// processing keeps known field sizes under the protocol cap; output is suitable
// for ArkDriverClient::queryThreadRuntimeFieldSamples.
std::vector<ksword::ark::RuntimeFieldSampleRequestItem> BuildThreadRuntimeSampleItems(
    const KSWORD_ARK_THREAD_DETAIL_RESPONSE& detail) {
    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> items;
    const auto add = [&](std::uint32_t id, std::uint32_t offset, std::uint32_t size, const char* name, const char* type) {
        if (offset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE || size == 0 || size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES) {
            return;
        }
        ksword::ark::RuntimeFieldSampleRequestItem item{};
        item.runtimeItemId = id;
        item.offset = offset;
        item.size = size;
        item.name = name;
        item.type = type;
        items.push_back(std::move(item));
    };
    add(KSW_DYN_FIELD_ID_ET_CID, detail.offsets.etCid, sizeof(std::uint64_t) * 2U, "ET.Cid", "CLIENT_ID");
    add(KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY, detail.offsets.etThreadListEntry, sizeof(std::uint64_t), "ET.ThreadListEntry", "LIST_ENTRY.Flink");
    add(KSW_DYN_FIELD_ID_ET_START_ADDRESS, detail.offsets.etStartAddress, sizeof(std::uint64_t), "ET.StartAddress", "PVOID");
    add(KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS, detail.offsets.etWin32StartAddress, sizeof(std::uint64_t), "ET.Win32StartAddress", "PVOID");
    add(KSW_DYN_FIELD_ID_KT_PROCESS, detail.offsets.ktProcess, sizeof(std::uint64_t), "KT.Process", "KPROCESS*");
    add(KSW_DYN_FIELD_ID_KT_INITIAL_STACK, detail.offsets.ktInitialStack, sizeof(std::uint64_t), "KT.InitialStack", "PVOID");
    add(KSW_DYN_FIELD_ID_KT_STACK_LIMIT, detail.offsets.ktStackLimit, sizeof(std::uint64_t), "KT.StackLimit", "PVOID");
    add(KSW_DYN_FIELD_ID_KT_STACK_BASE, detail.offsets.ktStackBase, sizeof(std::uint64_t), "KT.StackBase", "PVOID");
    add(KSW_DYN_FIELD_ID_KT_KERNEL_STACK, detail.offsets.ktKernelStack, sizeof(std::uint64_t), "KT.KernelStack", "PVOID");
    add(KSW_DYN_FIELD_ID_KT_READ_OPERATION_COUNT, detail.offsets.ktReadOperationCount, sizeof(std::uint64_t), "KT.ReadOperationCount", "ULONGLONG");
    add(KSW_DYN_FIELD_ID_KT_WRITE_OPERATION_COUNT, detail.offsets.ktWriteOperationCount, sizeof(std::uint64_t), "KT.WriteOperationCount", "ULONGLONG");
    add(KSW_DYN_FIELD_ID_KT_OTHER_OPERATION_COUNT, detail.offsets.ktOtherOperationCount, sizeof(std::uint64_t), "KT.OtherOperationCount", "ULONGLONG");
    return items;
}

// CollectR0AuditRows queries process/thread cross-view through ArkDriverClient.
// Inputs are a PID and status outputs; processing is read-only and bounded by
// the shared cross-view max-node defaults; output rows are UI evidence only.
std::vector<ProcessR0AuditInfo> CollectR0AuditRows(DWORD processId, bool& succeededOut, std::wstring& statusOut) {
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessR0AuditInfo> rows;

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::ThreadEnumResult threadEnumeration = driverClient.enumerateThreads(
        KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL | KSWORD_ARK_ENUM_THREAD_FLAG_SCAN_CID_TABLE,
        processId);
    if (!threadEnumeration.io.ok) {
        AddR0AuditRow(
            rows,
            L"ThreadEnumeration",
            processId,
            0,
            0,
            0,
            0,
            L"ArkDriverClient::enumerateThreads",
            L"Unavailable",
            0,
            NarrowToWide(threadEnumeration.io.message));
    } else {
        AddR0AuditRow(
            rows,
            L"ThreadEnumeration",
            processId,
            0,
            0,
            0,
            0,
            L"ArkDriverClient::enumerateThreads",
            L"OK",
            100,
            L"returned=" + std::to_wstring(threadEnumeration.returnedCount) +
                L"/" + std::to_wstring(threadEnumeration.totalCount) +
                L"; version=" + std::to_wstring(threadEnumeration.version));
        constexpr std::size_t kMaxThreadEnumerationRows = 512U;
        const std::size_t entryCount = (std::min)(threadEnumeration.entries.size(), kMaxThreadEnumerationRows);
        for (std::size_t index = 0; index < entryCount; ++index) {
            const ksword::ark::ThreadEntry& entry = threadEnumeration.entries[index];
            std::wostringstream detail;
            detail << L"flags=" << HexMaskText(entry.flags)
                   << L"; fieldFlags=" << HexMaskText(entry.fieldFlags)
                   << L"; r0Status=" << entry.r0Status
                   << L"; initialStack=" << FormatHexPointer(static_cast<std::uintptr_t>(entry.initialStack))
                   << L"; stack=" << FormatHexPointer(static_cast<std::uintptr_t>(entry.stackLimit))
                   << L"-" << FormatHexPointer(static_cast<std::uintptr_t>(entry.stackBase))
                   << L"; kernelStack=" << FormatHexPointer(static_cast<std::uintptr_t>(entry.kernelStack))
                   << L"; io=R" << entry.readOperationCount
                   << L"/W" << entry.writeOperationCount
                   << L"/O" << entry.otherOperationCount
                   << L"; transfer=R" << entry.readTransferCount
                   << L"/W" << entry.writeTransferCount
                   << L"/O" << entry.otherTransferCount
                   << L"; capability=" << FormatHexPointer(static_cast<std::uintptr_t>(entry.dynDataCapabilityMask));
            AddR0AuditRow(
                rows,
                L"ThreadEnumeration",
                static_cast<DWORD>(entry.processId),
                static_cast<DWORD>(entry.threadId),
                entry.kernelStack,
                entry.initialStack,
                entry.stackBase,
                L"R0 KTHREAD",
                entry.r0Status == KSWORD_ARK_THREAD_R0_STATUS_OK ? L"OK" : L"Partial",
                entry.r0Status == KSWORD_ARK_THREAD_R0_STATUS_OK ? 100UL : 50UL,
                detail.str());
        }
        if (threadEnumeration.entries.size() > entryCount) {
            AddR0AuditRow(
                rows,
                L"ThreadEnumeration",
                processId,
                0,
                0,
                0,
                0,
                L"R0 KTHREAD",
                L"Truncated",
                0,
                L"Light limits visible R0 thread enumeration evidence to " + std::to_wstring(kMaxThreadEnumerationRows) + L" rows per refresh.");
        }
    }

    const ksword::ark::ProcessSectionQueryResult sectionQuery = driverClient.queryProcessSection(processId);
    if (!sectionQuery.io.ok) {
        AddR0AuditRow(
            rows,
            L"ProcessSection",
            processId,
            0,
            sectionQuery.sectionObjectAddress,
            sectionQuery.controlAreaAddress,
            0,
            L"ArkDriverClient::queryProcessSection",
            L"Unavailable",
            0,
            NarrowToWide(sectionQuery.io.message));
    } else {
        AddR0AuditRow(
            rows,
            L"ProcessSection",
            processId,
            0,
            sectionQuery.sectionObjectAddress,
            sectionQuery.controlAreaAddress,
            0,
            L"ArkDriverClient::queryProcessSection",
            L"OK",
            100,
            L"returned=" + std::to_wstring(sectionQuery.returnedCount) +
                L"/" + std::to_wstring(sectionQuery.totalCount) +
                L"; queryStatus=" + std::to_wstring(sectionQuery.queryStatus) +
                L"; fieldFlags=" + HexMaskText(sectionQuery.fieldFlags) +
                L"; lastStatus=" + StatusHexText(sectionQuery.lastStatus));
        for (const ksword::ark::SectionMappingEntry& mapping : sectionQuery.mappings) {
            AddR0AuditRow(
                rows,
                L"ProcessSectionMapping",
                static_cast<DWORD>(mapping.processId),
                0,
                sectionQuery.sectionObjectAddress,
                sectionQuery.controlAreaAddress,
                mapping.startVa,
                L"ControlArea mapping",
                L"type=" + std::to_wstring(mapping.viewMapType),
                100,
                L"start=" + FormatHexPointer(static_cast<std::uintptr_t>(mapping.startVa)) +
                    L"; end=" + FormatHexPointer(static_cast<std::uintptr_t>(mapping.endVa)) +
                    L"; mapType=" + std::to_wstring(mapping.viewMapType));
        }
    }

    const ksword::ark::ProcessCrossViewResult processAudit = driverClient.queryProcessCrossView(
        KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
        processId,
        processId,
        KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
    if (!processAudit.io.ok) {
        statusOut = L"Process cross-view failed: " + NarrowToWide(processAudit.io.message);
    } else {
        for (const ksword::ark::ProcessCrossViewEntry& entry : processAudit.entries) {
            if (entry.processId != processId) {
                continue;
            }
            ProcessR0AuditInfo row{};
            row.scope = L"Process";
            row.processId = static_cast<DWORD>(entry.processId);
            row.objectAddress = static_cast<std::uintptr_t>(entry.objectAddress);
            row.startAddress = static_cast<std::uintptr_t>(entry.startAddress);
            row.sourceMask = entry.sourceMask;
            row.anomalyFlags = entry.anomalyFlags;
            row.confidence = entry.confidence;
            row.sourceText = CrossViewSourceText(row.sourceMask);
            row.anomalyText = CrossViewAnomalyText(row.anomalyFlags);
            row.detailText = NarrowToWide(entry.detail);
            rows.push_back(std::move(row));
        }
    }

    const ksword::ark::ThreadCrossViewResult threadAudit = driverClient.queryThreadCrossView(
        KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL,
        processId,
        0,
        0,
        KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
    if (!threadAudit.io.ok) {
        if (!statusOut.empty()) {
            statusOut += L"; ";
        }
        statusOut += L"Thread cross-view failed: " + NarrowToWide(threadAudit.io.message);
    } else {
        for (const ksword::ark::ThreadCrossViewEntry& entry : threadAudit.entries) {
            if (entry.processId != processId) {
                continue;
            }
            ProcessR0AuditInfo row{};
            row.scope = L"Thread";
            row.processId = static_cast<DWORD>(entry.processId);
            row.threadId = static_cast<DWORD>(entry.threadId);
            row.objectAddress = static_cast<std::uintptr_t>(entry.objectAddress);
            row.relatedObjectAddress = static_cast<std::uintptr_t>(entry.processObjectAddress);
            row.startAddress = static_cast<std::uintptr_t>(entry.startAddress);
            row.sourceMask = entry.sourceMask;
            row.anomalyFlags = entry.anomalyFlags;
            row.confidence = entry.confidence;
            row.sourceText = CrossViewSourceText(row.sourceMask);
            row.anomalyText = CrossViewAnomalyText(row.anomalyFlags);
            row.detailText = NarrowToWide(entry.detail);
            rows.push_back(std::move(row));
        }
    }

    const ksword::ark::ProcessRuntimeDetailResult processDetail =
        driverClient.queryProcessRuntimeDetail(processId);
    if (!processDetail.io.ok) {
        AddR0AuditRow(
            rows,
            L"ProcessDetail",
            processId,
            0,
            0,
            0,
            0,
            L"ArkDriverClient::queryProcessRuntimeDetail",
            processDetail.unsupported ? L"Unsupported" : L"Unavailable",
            0,
            NarrowToWide(processDetail.io.message));
    } else {
        const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& detail = processDetail.response;
        std::wostringstream text;
        text << L"fields=" << HexMaskText(detail.fieldFlags)
             << L"; requested=" << HexMaskText(detail.requestedFlags)
             << L"; dyn=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.dynDataCapabilityMask))
             << L"; missing=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.missingCapabilityMask))
             << L"; token=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.tokenObjectAddress))
             << L"; objectTable=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.objectTableAddress))
             << L"; section=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.sectionObjectAddress))
             << L"; detail=" << std::wstring(detail.detail);
        AddR0AuditRow(
            rows,
            L"ProcessDetail",
            processId,
            0,
            detail.processObjectAddress,
            detail.tokenObjectAddress,
            0,
            L"IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL",
            L"status=" + std::to_wstring(detail.status) + L", last=" + StatusHexText(detail.lastStatus),
            100,
            text.str());

        const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> sampleItems =
            BuildProcessRuntimeSampleItems(detail);
        if (!sampleItems.empty()) {
            const ksword::ark::RuntimeFieldSampleResult samples =
                driverClient.queryProcessRuntimeFieldSamples(processId, sampleItems);
            AddR0AuditRow(
                rows,
                L"ProcessRuntimeFields",
                processId,
                0,
                samples.objectAddress,
                0,
                0,
                L"IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS",
                samples.io.ok ? L"OK" : (samples.unsupported ? L"Unsupported" : L"Unavailable"),
                samples.io.ok ? 100UL : 0UL,
                L"returned=" + std::to_wstring(samples.returnedCount) +
                    L"/" + std::to_wstring(samples.totalCount) +
                    L"; status=" + std::to_wstring(samples.status) +
                    L"; " + NarrowToWide(samples.io.message));
            for (const ksword::ark::RuntimeFieldSampleEntry& entry : samples.entries) {
                AddR0AuditRow(
                    rows,
                    L"ProcessField",
                    processId,
                    0,
                    samples.objectAddress,
                    0,
                    0,
                    NarrowToWide(entry.name.empty() ? std::string("runtime-field") : entry.name),
                    L"rowStatus=" + std::to_wstring(entry.status),
                    entry.status == KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK ? 100UL : 50UL,
                    L"id=" + std::to_wstring(entry.runtimeItemId) +
                        L"; offset=" + HexMaskText(entry.offset) +
                        L"; size=" + std::to_wstring(entry.size) +
                        L"; bytesRead=" + std::to_wstring(entry.bytesRead) +
                        L"; value=" + FormatHexPointer(static_cast<std::uintptr_t>(entry.valueU64)) +
                        L"; last=" + StatusHexText(entry.lastStatus));
            }
        }
    }

    std::size_t threadDetailCount = 0U;
    for (const ksword::ark::ThreadCrossViewEntry& entry : threadAudit.entries) {
        if (entry.processId != processId || entry.threadId == 0U) {
            continue;
        }
        if (threadDetailCount >= 128U) {
            AddR0AuditRow(
                rows,
                L"ThreadDetail",
                processId,
                0,
                0,
                0,
                0,
                L"ArkDriverClient::queryThreadRuntimeDetail",
                L"Truncated",
                0,
                L"Thread runtime detail rows are capped at 128 per refresh to keep the Light GUI responsive.");
            break;
        }
        ++threadDetailCount;
        const ksword::ark::ThreadRuntimeDetailResult threadDetail =
            driverClient.queryThreadRuntimeDetail(entry.threadId, processId);
        if (!threadDetail.io.ok) {
            AddR0AuditRow(
                rows,
                L"ThreadDetail",
                processId,
                entry.threadId,
                entry.objectAddress,
                entry.processObjectAddress,
                entry.startAddress,
                L"ArkDriverClient::queryThreadRuntimeDetail",
                threadDetail.unsupported ? L"Unsupported" : L"Unavailable",
                0,
                NarrowToWide(threadDetail.io.message));
            continue;
        }

        const KSWORD_ARK_THREAD_DETAIL_RESPONSE& detail = threadDetail.response;
        std::wostringstream text;
        text << L"fields=" << HexMaskText(detail.fieldFlags)
             << L"; requested=" << HexMaskText(detail.requestedFlags)
             << L"; cidPid=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.cidUniqueProcess))
             << L"; cidTid=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.cidUniqueThread))
             << L"; start=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.startAddress))
             << L"; win32Start=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.win32StartAddress))
             << L"; stack=" << FormatHexPointer(static_cast<std::uintptr_t>(detail.stackLimit))
             << L"-" << FormatHexPointer(static_cast<std::uintptr_t>(detail.stackBase))
             << L"; detail=" << std::wstring(detail.detail);
        AddR0AuditRow(
            rows,
            L"ThreadDetail",
            processId,
            detail.threadId,
            detail.threadObjectAddress,
            detail.processObjectAddress,
            detail.startAddress,
            L"IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL",
            L"status=" + std::to_wstring(detail.status) + L", last=" + StatusHexText(detail.lastStatus),
            100,
            text.str());

        const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> sampleItems =
            BuildThreadRuntimeSampleItems(detail);
        if (!sampleItems.empty()) {
            const ksword::ark::RuntimeFieldSampleResult samples =
                driverClient.queryThreadRuntimeFieldSamples(detail.threadId, processId, sampleItems);
            AddR0AuditRow(
                rows,
                L"ThreadRuntimeFields",
                processId,
                detail.threadId,
                samples.objectAddress,
                detail.processObjectAddress,
                detail.startAddress,
                L"IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS",
                samples.io.ok ? L"OK" : (samples.unsupported ? L"Unsupported" : L"Unavailable"),
                samples.io.ok ? 100UL : 0UL,
                L"returned=" + std::to_wstring(samples.returnedCount) +
                    L"/" + std::to_wstring(samples.totalCount) +
                    L"; status=" + std::to_wstring(samples.status) +
                    L"; " + NarrowToWide(samples.io.message));
            for (const ksword::ark::RuntimeFieldSampleEntry& sample : samples.entries) {
                AddR0AuditRow(
                    rows,
                    L"ThreadField",
                    processId,
                    detail.threadId,
                    samples.objectAddress,
                    detail.processObjectAddress,
                    detail.startAddress,
                    NarrowToWide(sample.name.empty() ? std::string("runtime-field") : sample.name),
                    L"rowStatus=" + std::to_wstring(sample.status),
                    sample.status == KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK ? 100UL : 50UL,
                    L"id=" + std::to_wstring(sample.runtimeItemId) +
                        L"; offset=" + HexMaskText(sample.offset) +
                        L"; size=" + std::to_wstring(sample.size) +
                        L"; bytesRead=" + std::to_wstring(sample.bytesRead) +
                        L"; value=" + FormatHexPointer(static_cast<std::uintptr_t>(sample.valueU64)) +
                        L"; last=" + StatusHexText(sample.lastStatus));
            }
        }
    }

    succeededOut = statusOut.empty();
    if (statusOut.empty()) {
        statusOut = L"OK";
    }
    return rows;
}

} // namespace

ProcessDetailSnapshot ProcessDetailCollector::Collect(
    DWORD processId,
    ULONGLONG expectedCreationTime100ns) const {
    ProcessDetailSnapshot snapshot{};
    snapshot.basic.processId = processId;
    if (processId == 0 || expectedCreationTime100ns == 0U) {
        snapshot.basic.statusText = L"Process identity is unavailable; detail refresh skipped.";
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText;
        return snapshot;
    }

    const HANDLE rawIdentityProcess = ::OpenProcess(kProcessBasicAccess, FALSE, processId);
    const DWORD identityOpenError = rawIdentityProcess ? ERROR_SUCCESS : ::GetLastError();
    Ksword::Core::UniqueHandle identityProcess(rawIdentityProcess);
    if (!identityProcess.valid()) {
        snapshot.basic.statusText = Win32ErrorText(L"OpenProcess(identity)", identityOpenError);
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText;
        return snapshot;
    }

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    const BOOL identityTimeOk = ::GetProcessTimes(
        identityProcess.get(),
        &creationTime,
        &exitTime,
        &kernelTime,
        &userTime);
    const DWORD identityTimeError = identityTimeOk ? ERROR_SUCCESS : ::GetLastError();
    const ULONGLONG actualCreationTime100ns = identityTimeOk
        ? (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
            static_cast<ULONGLONG>(creationTime.dwLowDateTime)
        : 0U;
    if (!identityTimeOk || actualCreationTime100ns == 0U ||
        actualCreationTime100ns != expectedCreationTime100ns) {
        snapshot.basic.statusText = !identityTimeOk
            ? Win32ErrorText(L"GetProcessTimes(identity)", identityTimeError)
            : L"Process identity changed (PID was reused); detail refresh skipped.";
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText;
        return snapshot;
    }

    snapshot.basic = CollectBasicInfo(processId, snapshot.basicSucceeded);

    std::wstring threadStatus;
    snapshot.threads = CollectThreads(processId, snapshot.threadsSucceeded, threadStatus);
    if (snapshot.threadsSucceeded) {
        const std::size_t boundedThreadCount = (std::min)(
            snapshot.threads.size(),
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()));
        snapshot.basic.threadCount = static_cast<DWORD>(boundedThreadCount);
    }
    if (!snapshot.threadsSucceeded && !threadStatus.empty()) {
        snapshot.errorText += L"Threads: " + threadStatus + L"\r\n";
    }

    std::wstring moduleStatus;
    snapshot.modules = CollectModules(processId, snapshot.modulesSucceeded, moduleStatus);
    if (!snapshot.modulesSucceeded && !moduleStatus.empty()) {
        snapshot.errorText += L"Modules: " + moduleStatus + L"\r\n";
    }
    AttachRepresentativeThreads(snapshot.modules, snapshot.threads);

    std::wstring r0AuditStatus;
    snapshot.r0AuditRows = CollectR0AuditRows(processId, snapshot.r0AuditSucceeded, r0AuditStatus);
    if (!snapshot.r0AuditSucceeded && !r0AuditStatus.empty()) {
        snapshot.errorText += L"R0Audit: " + r0AuditStatus + L"\r\n";
    }

    if (!snapshot.basicSucceeded && !snapshot.basic.statusText.empty()) {
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText + L"\r\n" + snapshot.errorText;
    }
    if (snapshot.errorText.empty()) {
        snapshot.errorText = L"OK";
    }
    return snapshot;
}

} // namespace Ksword::Features::ProcessDetail
