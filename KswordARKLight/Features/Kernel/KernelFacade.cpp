#include "KernelFacade.h"

#include "KernelDynDataProfiles.h"
#include "KernelNativeQueries.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../../shared/driver/KswordArkKernelObjectIoctl.h"

#include <algorithm>
#include <memory>
#include <psapi.h>
#include <unordered_map>
#include <cstdint>
#include <cwctype>
#include <cstdlib>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::Kernel {
namespace {

// Utf8ToWide converts ArkDriverClient's narrow diagnostic strings to UTF-16.
// Input is a UTF-8/narrow string; processing uses strict UTF-8 first and then a
// byte-wise fallback; output is safe for Win32 controls.
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

// HexText formats unsigned diagnostic values from shared driver protocols.
// Input is a 64-bit integer; output is uppercase hexadecimal UI text.
std::wstring HexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// NtStatusText formats NTSTATUS values in the same diagnostic style as the full
// KernelDock reports. Input is a signed NTSTATUS-sized value; output is an
// uppercase eight-digit hexadecimal string.
std::wstring NtStatusText(const long status) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<std::uint32_t>(status);
    return stream.str();
}

// DynDataFieldPresent mirrors the original KernelDock field validity test.
// Inputs are the R0 field flags and raw offset; processing rejects both the
// absent PRESENT bit and DynData sentinel offsets; output is true for usable
// offsets that should be displayed as available.
bool DynDataFieldPresent(const std::uint32_t flags, const std::uint32_t offset) {
    return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
        offset != 0xFFFFFFFFU &&
        offset != 0x0000FFFFU;
}

// DynDataFieldStatusText converts one DynData field row into the original
// "可用/缺失" status text. Inputs are the R0 flags and offset; output is a
// compact Chinese label consumed by the Win32 ListView status column.
const wchar_t* DynDataFieldStatusText(const std::uint32_t flags, const std::uint32_t offset) {
    if (DynDataFieldPresent(flags, offset)) {
        return L"可用";
    }
    return (flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U ? L"缺失(必需)" : L"缺失(可选)";
}

// ModuleIdentityText mirrors the original DriverStatus/DynData single-line
// identity summary. Input is the ArkDriverClient module identity; output is a
// compact text containing class, machine, timestamp, size and base address.
std::wstring ModuleIdentityText(const ksword::ark::ArkDynModuleIdentity& identity) {
    if (!identity.present) {
        return L"<未识别>";
    }
    std::wostringstream stream;
    stream << (identity.moduleName.empty() ? L"<unnamed>" : identity.moduleName)
           << L"，Class=" << identity.classId
           << L"，Machine=" << HexText(identity.machine)
           << L"，TimeDateStamp=" << HexText(identity.timeDateStamp)
           << L"，SizeOfImage=" << HexText(identity.sizeOfImage)
           << L"，Base=" << HexText(identity.imageBase);
    return stream.str();
}

// FixedAnsiText converts NUL-terminated protocol char arrays into UTF-16 text.
// Inputs are a bounded ANSI/UTF-8-ish buffer and its capacity; processing stops
// at the first NUL and uses the same UTF-8 fallback as ArkDriverClient messages;
// output is safe display text for profile, capability, and missing-item rows.
std::wstring FixedAnsiText(const char* text, const std::size_t maxBytes) {
    if (text == nullptr || maxBytes == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < maxBytes && text[length] != '\0') {
        ++length;
    }
    if (length == 0U) {
        return {};
    }
    return Utf8ToWide(std::string(text, text + length));
}

// FixedWideText converts bounded UTF-16 protocol arrays into std::wstring.
// Inputs are a wchar_t array and its maximum element count; processing stops at
// the first NUL to avoid over-reading non-terminated driver packets; output is a
// normal string usable by ListView rows and detail panels.
std::wstring FixedWideText(const wchar_t* text, const std::size_t maxChars) {
    if (text == nullptr || maxChars == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < maxChars && text[length] != L'\0') {
        ++length;
    }
    return std::wstring(text, text + length);
}

// DynDataSourceName keeps DriverStatus field-source summaries aligned with the
// original sourceText helper. Input is KSW_DYN_FIELD_SOURCE_*; output is a UI
// label only.
const wchar_t* DynDataSourceName(const std::uint32_t source) {
    switch (source) {
    case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER: return L"System Informer";
    case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN: return L"Ksword runtime pattern";
    case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE: return L"Ksword extra table";
    case KSW_DYN_FIELD_SOURCE_PDB_PROFILE: return L"PDB profile";
    default: return L"Unavailable";
    }
}

// DynDataFieldsSummary is the R3-side aggregate used by the Win32 DriverStatus
// page. Inputs are queryDynDataFields entries; processing counts availability,
// required gaps and source classes; output is rendered as hidden summary fields.
struct DynDataFieldsSummary {
    std::uint32_t present = 0;
    std::uint32_t returned = 0;
    std::uint32_t declared = 0;
    std::uint32_t requiredMissing = 0;
    std::uint32_t pdb = 0;
    std::uint32_t runtime = 0;
    std::uint32_t systemInformer = 0;
    std::uint32_t extra = 0;
    std::uint32_t unavailable = 0;
    bool activeProcessLinksPresent = false;
    std::uint32_t activeProcessLinksOffset = 0xFFFFFFFFU;
    std::uint32_t activeProcessLinksSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
};

// SummarizeDynDataFields computes the same coverage/source counters shown by
// the original DriverStatus page. Inputs are fields query results; output is a
// value object with no ownership of the source query.
DynDataFieldsSummary SummarizeDynDataFields(const ksword::ark::DynDataFieldsResult& fields) {
    DynDataFieldsSummary summary;
    summary.returned = fields.returnedCount;
    summary.declared = fields.totalCount;
    for (const ksword::ark::DynDataFieldEntry& entry : fields.entries) {
        const bool present = DynDataFieldPresent(entry.flags, entry.offset);
        if (present) {
            ++summary.present;
        }
        if (!present && (entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U) {
            ++summary.requiredMissing;
        }
        switch (entry.source) {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            ++summary.systemInformer;
            break;
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            ++summary.runtime;
            break;
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            ++summary.extra;
            break;
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            ++summary.pdb;
            break;
        default:
            ++summary.unavailable;
            break;
        }
        if (entry.fieldName == "EpActiveProcessLinks" || entry.fieldName == "_EPROCESS.ActiveProcessLinks") {
            summary.activeProcessLinksPresent = present;
            summary.activeProcessLinksOffset = entry.offset;
            summary.activeProcessLinksSource = entry.source;
        }
    }
    return summary;
}

// FieldCoverageText mirrors fieldCoverageText from the original dock. Input
// is a DynDataFieldsSummary plus optional pack coverage; output is a one-line
// coverage sentence.
std::wstring FieldCoverageText(const DynDataFieldsSummary& summary, const double coveragePercent) {
    std::wostringstream stream;
    stream << L"可用 " << summary.present
           << L" / 返回 " << summary.returned
           << L" / R0声明 " << summary.declared
           << L"，必需缺失 " << summary.requiredMissing;
    if (coveragePercent >= 0.0) {
        stream << L"，pack覆盖率 " << std::fixed << std::setprecision(1) << coveragePercent << L"%";
    }
    return stream.str();
}

// FieldSourcesText mirrors fieldSourceSummaryText from the original dock. Input is a
// field aggregate; output lists counts by source class.
std::wstring FieldSourcesText(const DynDataFieldsSummary& summary) {
    std::wostringstream stream;
    stream << L"PDB=" << summary.pdb
           << L"，RuntimePattern=" << summary.runtime
           << L"，SystemInformer=" << summary.systemInformer
           << L"，Extra=" << summary.extra
           << L"，不可用=" << summary.unavailable;
    return stream.str();
}

// LocalPdbProfileText mirrors localPdbProfileText in a compact form. Inputs are
// the local pack match result and field aggregate; output is used by DriverStatus
// summary/detail rows without applying the profile.
std::wstring LocalPdbProfileText(const DynDataProfileMatch& match) {
    if (match.matched) {
        std::wostringstream stream;
        stream << L"命中：" << Utf8ToWide(match.profile.profileName)
               << L"，来源=" << match.source
               << L"，字段=" << match.fieldCount
               << L"，typedItems=" << match.typedItemCount
               << L"，callbackItems=" << match.callbackItemCount
               << L"，coverage=";
        if (match.coveragePercent >= 0.0) {
            stream << std::fixed << std::setprecision(1) << match.coveragePercent << L"%";
        } else {
            stream << L"<未知>";
        }
        stream << L"，packProfiles=" << match.profileCount
               << L"，路径=" << match.path;
        return stream.str();
    }
    return match.message.empty() ? L"未命中或未扫描。" : match.message;
}

// ActiveProcessLinksText mirrors activeProcessLinksOffsetText. Inputs are the
// local match and current R0 field aggregate; output highlights whether R0 has a
// usable offset and its source.
std::wstring ActiveProcessLinksText(const DynDataFieldsSummary& fields) {
    std::wostringstream stream;
    stream << L"LocalPack=<见本地 PDB profile>；R0="
           << (fields.activeProcessLinksPresent ? HexText(fields.activeProcessLinksOffset) : L"<未应用>")
           << L"；R0Source=" << DynDataSourceName(fields.activeProcessLinksSource);
    return stream.str();
}

// TrustedOffsetText mirrors trustedOffsetText from the original driver status
// page. Inputs are status flags, local pack match and field aggregate; output is
// a human-readable trusted-offset state.
std::wstring TrustedOffsetText(
    const std::uint32_t dynDataStatusFlags,
    const DynDataProfileMatch& match,
    const DynDataFieldsSummary& fields) {
    const bool pdbActive = (dynDataStatusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) != 0U;
    const bool callbackActive = (dynDataStatusFlags & KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE) != 0U;
    if (pdbActive) {
        std::wostringstream stream;
        stream << L"已启用可信 PDB 偏移；PDB字段 " << fields.pdb
               << L" / 可用字段 " << fields.present
               << L"，pack=" << (match.matched ? L"命中" : L"未确认")
               << L"，callback=" << (callbackActive ? L"Active" : L"Inactive") << L"。";
        return stream.str();
    }
    if (match.matched) {
        return L"本地 pack 已匹配当前内核，但 R0 当前字段来源尚未切换到 PDB profile。";
    }
    if (fields.present != 0U) {
        return L"当前有可用 DynData 字段，但未发现 PDB profile 字段；来源=" + FieldSourcesText(fields) + L"。";
    }
    return L"暂无可用可信偏移。";
}

// BoolText converts protocol booleans into compact Chinese text. Input is a
// boolean-like value; output is display text only.
const wchar_t* BoolText(const bool value) {
    return value ? L"是" : L"否";
}

// YesNoText is the std::wstring form used when composing result rows. Input is a
// boolean; output intentionally matches BoolText so UI summary rows can compare
// against one stable Chinese value.
std::wstring YesNoText(const bool value) {
    return value ? L"是" : L"否";
}

// SizeText formats byte counts the same way the original MemoryDock pages did.
// Inputs are raw byte counts from ArkDriverClient; processing selects GB/MB/KB/B
// units without changing the numeric source value; output is display-only text.
std::wstring SizeText(const std::uint64_t bytes) {
    std::wostringstream stream;
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
        stream << std::fixed << std::setprecision(2)
               << (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0))
               << L" GB";
    } else if (bytes >= 1024ULL * 1024ULL) {
        stream << std::fixed << std::setprecision(2)
               << (static_cast<double>(bytes) / (1024.0 * 1024.0))
               << L" MB";
    } else if (bytes >= 1024ULL) {
        stream << std::fixed << std::setprecision(2)
               << (static_cast<double>(bytes) / 1024.0)
               << L" KB";
    } else {
        stream << bytes << L" B";
    }
    return stream.str();
}

// ProcessDisplayName resolves a PID to a compact executable name using only
// Win32 APIs. Input is a process id from R0 event data; processing tries
// QueryFullProcessImageNameW and falls back to System/Idle labels; output is
// display-only and does not fail the kernel query when access is denied.
std::wstring ProcessDisplayName(const std::uint32_t processId) {
    if (processId == 0) {
        return L"Idle/System";
    }
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return L"PID " + std::to_wstring(processId);
    }
    std::wstring path(MAX_PATH * 4, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    std::wstring name = L"PID " + std::to_wstring(processId);
    if (::QueryFullProcessImageNameW(process, 0, path.data(), &length) && length > 0) {
        path.resize(length);
        const std::size_t slash = path.find_last_of(L"\\/");
        name = slash == std::wstring::npos ? path : path.substr(slash + 1);
    }
    ::CloseHandle(process);
    return name;
}

// BytesHex formats a bounded byte vector for list/detail display. Input is a
// byte buffer and max output count; processing avoids huge UI strings; output is
// uppercase hex bytes separated by spaces.
std::wstring BytesHex(const std::vector<std::uint8_t>& bytes, const std::size_t maxBytes = 32) {
    std::wostringstream stream;
    const std::size_t limit = std::min<std::size_t>(bytes.size(), maxBytes);
    for (std::size_t i = 0; i < limit; ++i) {
        if (i > 0) {
            stream << L' ';
        }
        stream << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned int>(bytes[i]);
    }
    if (bytes.size() > limit) {
        stream << L" ...";
    }
    return stream.str();
}


struct KernelModuleDiskInfo {
    std::uint64_t base = 0;
    std::wstring ntPath;
    std::wstring win32Path;
};

struct InlineDiskBaseline {
    bool available = false;
    bool differs = false;
    std::uint64_t rva = 0;
    std::uint32_t byteCount = 0;
    std::vector<std::uint8_t> bytes;
    std::wstring statusText = L"磁盘基线：未校验";
    std::wstring filePath;
};

std::wstring NormalizeKernelModulePath(const std::wstring& path) {
    std::wstring result = path;
    constexpr wchar_t ntPrefix[] = L"\\??\\";
    if (_wcsnicmp(result.c_str(), ntPrefix, 4) == 0) {
        result.erase(0, 4);
    }
    constexpr wchar_t systemRootPrefix[] = L"\\SystemRoot\\";
    if (_wcsnicmp(result.c_str(), systemRootPrefix, 12) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        if (::GetWindowsDirectoryW(windowsDir, MAX_PATH) != 0) {
            result = std::wstring(windowsDir) + result.substr(11);
        }
    }
    constexpr wchar_t sysrootPrefix[] = L"SystemRoot\\";
    if (_wcsnicmp(result.c_str(), sysrootPrefix, 11) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        if (::GetWindowsDirectoryW(windowsDir, MAX_PATH) != 0) {
            result = std::wstring(windowsDir) + L"\\" + result.substr(11);
        }
    }
    return result;
}

std::unordered_map<std::uint64_t, KernelModuleDiskInfo> QueryLoadedKernelModuleMap() {
    std::unordered_map<std::uint64_t, KernelModuleDiskInfo> modules;
    DWORD bytesNeeded = 0;
    ::EnumDeviceDrivers(nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0) {
        return modules;
    }
    std::vector<LPVOID> bases(bytesNeeded / sizeof(LPVOID));
    if (!::EnumDeviceDrivers(bases.data(), bytesNeeded, &bytesNeeded)) {
        return modules;
    }
    const DWORD count = bytesNeeded / sizeof(LPVOID);
    for (DWORD index = 0; index < count; ++index) {
        wchar_t path[MAX_PATH * 4]{};
        if (!::GetDeviceDriverFileNameW(bases[index], path, static_cast<DWORD>(std::size(path)))) {
            continue;
        }
        KernelModuleDiskInfo info;
        info.base = reinterpret_cast<std::uint64_t>(bases[index]);
        info.ntPath = path;
        info.win32Path = NormalizeKernelModulePath(info.ntPath);
        modules[info.base] = std::move(info);
    }
    return modules;
}

bool ReadWholeBinaryFile(const std::wstring& path, std::vector<std::uint8_t>& bytesOut) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 128LL * 1024LL * 1024LL) {
        ::CloseHandle(file);
        return false;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = ::ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    ::CloseHandle(file);
    if (!ok || read != bytes.size()) {
        return false;
    }
    bytesOut = std::move(bytes);
    return true;
}

bool RvaToFileOffset(const std::vector<std::uint8_t>& fileBytes, const std::uint32_t rva, const std::uint32_t bytesToRead, std::uint64_t& offsetOut) {
    if (fileBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return false;
    }
    const std::uint64_t ntOffset = static_cast<std::uint64_t>(dos->e_lfanew);
    if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > fileBytes.size()) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(fileBytes.data() + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.NumberOfSections > 96) {
        return false;
    }
    const std::uint64_t optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const std::uint64_t sectionOffset = optionalOffset + nt->FileHeader.SizeOfOptionalHeader;
    const std::uint64_t sectionBytes = static_cast<std::uint64_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionOffset + sectionBytes > fileBytes.size()) {
        return false;
    }
    if (rva + bytesToRead <= nt->OptionalHeader.SizeOfHeaders && rva + bytesToRead <= fileBytes.size()) {
        offsetOut = rva;
        return true;
    }
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(fileBytes.data() + sectionOffset);
    for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& section = sections[i];
        const std::uint32_t mappedSize = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (mappedSize == 0 || rva < section.VirtualAddress || rva >= section.VirtualAddress + mappedSize) {
            continue;
        }
        const std::uint32_t delta = rva - section.VirtualAddress;
        if (delta + bytesToRead > section.SizeOfRawData) {
            return false;
        }
        const std::uint64_t fileOffset = static_cast<std::uint64_t>(section.PointerToRawData) + delta;
        if (fileOffset + bytesToRead > fileBytes.size()) {
            return false;
        }
        offsetOut = fileOffset;
        return true;
    }
    return false;
}

InlineDiskBaseline ReadInlineDiskBaseline(
    const ksword::ark::KernelInlineHookEntry& entry,
    const std::unordered_map<std::uint64_t, KernelModuleDiskInfo>& modules,
    std::unordered_map<std::wstring, std::vector<std::uint8_t>>& fileCache) {
    InlineDiskBaseline baseline;
    const std::uint32_t byteCount = static_cast<std::uint32_t>(std::min<std::size_t>(
        std::min<std::size_t>(entry.currentBytes.size(), entry.currentByteCount),
        KSWORD_ARK_KERNEL_HOOK_BYTES));
    baseline.byteCount = byteCount;
    if (byteCount == 0) {
        baseline.statusText = L"不可用：R0 未返回内存字节。";
        return baseline;
    }
    if (entry.moduleBase == 0 || entry.functionAddress < entry.moduleBase) {
        baseline.statusText = L"不可用：函数地址或模块基址无效。";
        return baseline;
    }
    const std::uint64_t rva64 = entry.functionAddress - entry.moduleBase;
    baseline.rva = rva64;
    if (rva64 > 0xFFFFFFFFULL) {
        baseline.statusText = L"不可用：函数 RVA 超出 32 位 PE 范围。";
        return baseline;
    }
    const auto module = modules.find(entry.moduleBase);
    if (module == modules.end()) {
        baseline.statusText = L"不可用：R3 未能反查模块磁盘路径。";
        return baseline;
    }
    baseline.filePath = module->second.win32Path;
    if (baseline.filePath.empty() || ::GetFileAttributesW(baseline.filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        baseline.statusText = L"不可用：磁盘模块文件不存在或路径不可转换（" + module->second.ntPath + L"）。";
        return baseline;
    }
    auto cache = fileCache.find(baseline.filePath);
    if (cache == fileCache.end()) {
        std::vector<std::uint8_t> fileBytes;
        if (!ReadWholeBinaryFile(baseline.filePath, fileBytes)) {
            baseline.statusText = L"不可用：磁盘模块文件读取失败。";
            return baseline;
        }
        cache = fileCache.emplace(baseline.filePath, std::move(fileBytes)).first;
    }
    std::uint64_t fileOffset = 0;
    if (!RvaToFileOffset(cache->second, static_cast<std::uint32_t>(rva64), byteCount, fileOffset)) {
        baseline.statusText = L"不可用：未找到覆盖目标 RVA 的 PE 区段。";
        return baseline;
    }
    baseline.bytes.assign(cache->second.begin() + static_cast<std::ptrdiff_t>(fileOffset),
        cache->second.begin() + static_cast<std::ptrdiff_t>(fileOffset + byteCount));
    baseline.available = true;
    baseline.differs = !std::equal(baseline.bytes.begin(), baseline.bytes.end(), entry.currentBytes.begin());
    baseline.statusText = baseline.differs ? L"不同：内存字节与磁盘基线不一致" : L"一致：内存字节与磁盘基线相同";
    return baseline;
}

// Row builds one generic result row. Inputs are any number of key/value pairs;
// processing copies them into KernelResultRow; output is display-neutral data.
KernelResultRow Row(std::initializer_list<std::pair<std::wstring, std::wstring>> columns, const std::wstring& detail = {}) {
    KernelResultRow row;
    row.columns.assign(columns.begin(), columns.end());
    row.detailText = detail;
    return row;
}

// ContainsI checks whether text contains a fragment ignoring case. Inputs are
// display strings; output is true for empty filters or substring matches.
bool ContainsI(std::wstring text, std::wstring fragment) {
    if (fragment.empty()) {
        return true;
    }
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    std::transform(fragment.begin(), fragment.end(), fragment.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return text.find(fragment) != std::wstring::npos;
}

// RowMatchesFilter checks a generic row against user filter text. Inputs are one
// result row and filter; output controls whether ArkDriverClient rows are shown.
bool RowMatchesFilter(const KernelResultRow& row, const std::wstring& filter) {
    if (filter.empty() || ContainsI(row.detailText, filter)) {
        return true;
    }
    for (const auto& column : row.columns) {
        if (ContainsI(column.first, filter) || ContainsI(column.second, filter)) {
            return true;
        }
    }
    return false;
}

// PushFilteredRow appends a row only when it matches the generic UI filter.
// Inputs are destination, row and filter; no value is returned.
void PushFilteredRow(KernelOperationResult& result, KernelResultRow row, const std::wstring& filter) {
    if (RowMatchesFilter(row, filter)) {
        result.rows.push_back(std::move(row));
    }
}

// FieldValue extracts one selected-row field from a KernelActionRequest. Inputs
// are row key/value pairs and the requested key; output is an empty string when
// the selected result row does not carry that field.
std::wstring FieldValue(const KernelActionRequest& request, const std::wstring& key) {
    for (const auto& field : request.rowFields) {
        if (_wcsicmp(field.first.c_str(), key.c_str()) == 0) {
            return field.second;
        }
    }
    return {};
}

// ParseUnsigned64 accepts decimal or 0x-prefixed hexadecimal UI text. Input is a
// ListView cell value; processing rejects empty/invalid text; output is whether
// parsing consumed the complete value.
bool ParseUnsigned64(const std::wstring& text, std::uint64_t& valueOut) {
    if (text.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    const int base = (text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) ? 16 : 10;
    const unsigned long long parsed = std::wcstoull(text.c_str(), &end, base);
    if (end == text.c_str()) {
        return false;
    }
    while (end != nullptr && *end != L'\0') {
        if (!std::iswspace(*end)) {
            return false;
        }
        ++end;
    }
    valueOut = static_cast<std::uint64_t>(parsed);
    return true;
}

// FirstFieldValue returns the first non-empty selected-row field from a preferred
// key list. Inputs are the action request and likely column names; output is
// empty only when the current row cannot provide any requested field.
std::wstring FirstFieldValue(const KernelActionRequest& request, std::initializer_list<const wchar_t*> keys) {
    for (const wchar_t* key : keys) {
        const std::wstring value = FieldValue(request, key);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

// MutationOperationText maps the shared mutation operation enum to readable
// labels. Input is KSWORD_ARK_MUTATION_OPERATION_*; output is static display
// text with numeric fallback handled by callers.
const wchar_t* MutationOperationText(const std::uint32_t operation) {
    switch (operation) {
    case KSWORD_ARK_MUTATION_OPERATION_PREPARE: return L"Prepare";
    case KSWORD_ARK_MUTATION_OPERATION_COMMIT: return L"Commit";
    case KSWORD_ARK_MUTATION_OPERATION_ROLLBACK: return L"Rollback";
    case KSWORD_ARK_MUTATION_OPERATION_QUERY_AUDIT: return L"QueryAudit";
    case KSWORD_ARK_MUTATION_OPERATION_UNKNOWN:
    default:
        return L"Unknown";
    }
}

// MutationStatusText maps transaction status values into user-facing labels.
// Input is KSWORD_ARK_MUTATION_STATUS_*; output is static text used by audit and
// action result rows.
const wchar_t* MutationStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_MUTATION_STATUS_PREPARED: return L"Prepared";
    case KSWORD_ARK_MUTATION_STATUS_DRY_RUN: return L"Dry-run";
    case KSWORD_ARK_MUTATION_STATUS_COMMITTED: return L"Committed";
    case KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK: return L"Rolled back";
    case KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE: return L"Already at before";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_INVALID_REQUEST: return L"Rejected: invalid request";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_UNKNOWN_TARGET: return L"Rejected: unknown target";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_SIZE_LIMIT: return L"Rejected: size limit";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_SAFETY_POLICY: return L"Rejected: safety policy";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_BEFORE_MISMATCH: return L"Rejected: before mismatch";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_UNSUPPORTED_TARGET: return L"Rejected: unsupported target";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_PLAN_ONLY: return L"Rejected: plan only";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_NOT_FOUND: return L"Rejected: not found";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_BUSY: return L"Rejected: busy";
    case KSWORD_ARK_MUTATION_STATUS_REJECTED_TARGET_CHANGED: return L"Rejected: target changed";
    case KSWORD_ARK_MUTATION_STATUS_READ_FAILED: return L"Read failed";
    case KSWORD_ARK_MUTATION_STATUS_WRITE_FAILED: return L"Write failed";
    case KSWORD_ARK_MUTATION_STATUS_UNKNOWN:
    default:
        return L"Unknown";
    }
}

// MutationTargetText maps target-kind protocol values to readable labels. Input
// is KSWORD_ARK_MUTATION_TARGET_*; output is static display text.
const wchar_t* MutationTargetText(const std::uint32_t targetKind) {
    switch (targetKind) {
    case KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL: return L"Kernel virtual bytes";
    case KSWORD_ARK_MUTATION_TARGET_PROCESS_PROTECTION_BYTES: return L"Process protection bytes";
    case KSWORD_ARK_MUTATION_TARGET_CALLBACK_ENTRY_UNLINK_PLAN: return L"Callback unlink plan";
    case KSWORD_ARK_MUTATION_TARGET_UNKNOWN:
    default:
        return L"Unknown";
    }
}

// AppendFlagName appends one readable flag when the bit is present. Inputs are
// the output vector, mask, bit, and label; processing is local string assembly;
// no value is returned.
void AppendFlagName(std::vector<std::wstring>& names, const std::uint32_t mask, const std::uint32_t bit, const wchar_t* label) {
    if ((mask & bit) != 0U) {
        names.push_back(label);
    }
}

// AppendFlagName64 appends one readable flag from a 64-bit protocol mask. Inputs
// mirror AppendFlagName but are used by CPUID feature masks; no value is returned.
void AppendFlagName64(std::vector<std::wstring>& names, const std::uint64_t mask, const std::uint64_t bit, const wchar_t* label) {
    if ((mask & bit) != 0ULL) {
        names.push_back(label);
    }
}

// JoinNames joins flag labels into a compact string. Input is a vector of labels;
// output is "None" for no flags or a comma-separated string otherwise.
std::wstring JoinNames(const std::vector<std::wstring>& names) {
    if (names.empty()) {
        return L"None";
    }
    std::wstring result;
    for (const std::wstring& name : names) {
        if (!result.empty()) {
            result += L", ";
        }
        result += name;
    }
    return result;
}

// JoinNamesOrNormal joins flag labels but uses the original KswordARK wording
// for a clean row. Input is a vector of risk/anomaly labels; output is "正常"
// when no labels are present, otherwise a compact pipe-separated list.
std::wstring JoinNamesOrNormal(const std::vector<std::wstring>& names) {
    if (names.empty()) {
        return L"正常";
    }
    std::wstring result;
    for (const std::wstring& name : names) {
        if (!result.empty()) {
            result += L" | ";
        }
        result += name;
    }
    return result;
}

// SourceYesNo renders one source-matrix bit in the same compact style as the
// original ProcessDock Cross-View tables. Inputs are the source mask and target
// bit; output is "是" when present or "-" when absent.
std::wstring SourceYesNo(const std::uint32_t sourceMask, const std::uint32_t bit) {
    return (sourceMask & bit) != 0U ? L"是" : L"-";
}

// CpuVectorText formats driver-integrity CPU coordinates. Inputs are processor
// group, CPU number, and optional vector; output mirrors "Gx CPUy Vz" while
// hiding the vector when the protocol uses all-bits-set as "not applicable".
std::wstring CpuVectorText(const std::uint32_t group, const std::uint32_t cpu, const std::uint32_t vector) {
    std::wostringstream stream;
    stream << L"G" << group << L" CPU" << cpu;
    if (vector != 0xFFFFFFFFUL) {
        stream << L" V" << vector;
    }
    return stream.str();
}

// HotkeyDisplayText formats the R0 hotkey tuple for table display. Inputs are
// modifier flags, VK, and hotkey id; output keeps both hex flags and identifier
// so the compact Win32 table still has enough information for diagnostics.
std::wstring HotkeyDisplayText(const std::uint32_t modifiers, const std::uint32_t virtualKey, const std::uint32_t hotkeyId) {
    std::wostringstream stream;
    stream << L"VK " << HexText(virtualKey)
           << L" Mod " << HexText(modifiers)
           << L" Id " << HexText(hotkeyId);
    return stream.str();
}

// MutationRiskText expands the mutation risk mask. Input is a bitmask returned
// by R0; output is a stable, readable summary for audit/action rows.
std::wstring MutationRiskText(const std::uint32_t riskFlags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_FORCE_REQUIRED, L"Force required");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_FORCE_USED, L"Force used");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_DRY_RUN, L"Dry-run");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_POLICY_REQUIRED, L"Policy required");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_POLICY_DENIED, L"Policy denied");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_BEFORE_MISMATCH, L"Before mismatch");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_WRITE_BLOCKED_BY_DESIGN, L"Write blocked");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_PLAN_ONLY, L"Plan only");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_DYNDATA_REQUIRED, L"DynData required");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_DYNDATA_CONFIRMED, L"DynData confirmed");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_CANONICAL_REQUIRED, L"Canonical required");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_NONPAGED_REQUIRED, L"Nonpaged required");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_READ_SNAPSHOT_TAKEN, L"Read snapshot");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_ROLLBACK_IDEMPOTENT, L"Rollback idempotent");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_KERNEL_PATCH_SURFACE, L"Kernel patch surface");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_PROCESS_PROTECTION_SURFACE, L"Process protection surface");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_CALLBACK_UNLINK_SURFACE, L"Callback unlink surface");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_SIZE_LIMITED, L"Size limited");
    AppendFlagName(names, riskFlags, KSWORD_ARK_MUTATION_RISK_TARGET_CHANGED, L"Target changed");
    return JoinNames(names);
}

// MutationFlagsText expands user/action flags. Input is KSWORD_ARK_MUTATION_FLAG
// bitmask; output is a compact display string.
std::wstring MutationFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_FORCE, L"Force");
    AppendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED, L"UI confirmed");
    AppendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_DRY_RUN, L"Dry-run");
    AppendFlagName(names, flags, KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT, L"Expected-before");
    return JoinNames(names);
}

// ParseUnsigned32 is a bounds-checked wrapper around ParseUnsigned64. Input is a
// UI cell value; output is true only when the value fits an unsigned 32-bit field.
bool ParseUnsigned32(const std::wstring& text, std::uint32_t& valueOut) {
    std::uint64_t parsed = 0;
    if (!ParseUnsigned64(text, parsed) || parsed > 0xFFFFFFFFULL) {
        return false;
    }
    valueOut = static_cast<std::uint32_t>(parsed);
    return true;
}

// ParseHexByteList parses strings produced by BytesHex, such as "48 8B ..."
// into a byte vector. Inputs are display text from the selected row; output is a
// bounded byte vector suitable for ArkDriverClient's expected-current snapshot.
std::vector<std::uint8_t> ParseHexByteList(const std::wstring& text) {
    std::vector<std::uint8_t> bytes;
    std::wstring token;
    auto flushToken = [&]() {
        if (token.empty() || token == L"...") {
            token.clear();
            return;
        }
        std::uint64_t value = 0;
        if (ParseUnsigned64(L"0x" + token, value) && value <= 0xFF &&
            bytes.size() < KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) {
            bytes.push_back(static_cast<std::uint8_t>(value));
        }
        token.clear();
    };
    for (const wchar_t ch : text) {
        if (std::iswspace(ch) || ch == L',' || ch == L';') {
            flushToken();
        } else {
            token.push_back(ch);
        }
    }
    flushToken();
    return bytes;
}

// ParsePidList accepts comma/space/semicolon separated process ids for the
// minifilter bypass action. Input is the generic filter edit; output is a unique,
// bounded PID vector accepted by ArkDriverClient.
std::vector<std::uint32_t> ParsePidList(const std::wstring& text) {
    std::vector<std::uint32_t> pids;
    std::wstring token;
    auto flushToken = [&]() {
        if (token.empty()) {
            return;
        }
        std::uint32_t pid = 0;
        if (ParseUnsigned32(token, pid) && pid != 0 &&
            std::find(pids.begin(), pids.end(), pid) == pids.end() &&
            pids.size() < KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT) {
            pids.push_back(pid);
        }
        token.clear();
    };
    for (const wchar_t ch : text) {
        if (ch == L',' || ch == L';' || std::iswspace(ch)) {
            flushToken();
        } else {
            token.push_back(ch);
        }
    }
    flushToken();
    return pids;
}

// ParseFirstUnsigned64FromText extracts the first decimal or hexadecimal number
// from a free-form filter string. Inputs may be a plain "1234", "0xFFFF", or a
// copied row such as "PID: 1234"; output is false when no complete numeric token
// is found.
bool ParseFirstUnsigned64FromText(const std::wstring& text, std::uint64_t& valueOut) {
    std::wstring token;
    auto flush = [&]() -> bool {
        if (token.empty()) {
            return false;
        }
        std::uint64_t parsed = 0;
        const bool ok = ParseUnsigned64(token, parsed);
        token.clear();
        if (ok) {
            valueOut = parsed;
            return true;
        }
        return false;
    };
    for (const wchar_t ch : text) {
        const bool numeric = std::iswxdigit(ch) || ch == L'x' || ch == L'X';
        if (numeric) {
            token.push_back(ch);
        } else if (flush()) {
            return true;
        }
    }
    return flush();
}

// ParseFirstPidFromText extracts a PID from the generic filter box. Input is a
// free-form string; output is 0 when no usable 32-bit PID is present.
std::uint32_t ParseFirstPidFromText(const std::wstring& text) {
    std::uint64_t parsed = 0;
    if (!ParseFirstUnsigned64FromText(text, parsed) || parsed > 0xFFFFFFFFULL) {
        return 0;
    }
    return static_cast<std::uint32_t>(parsed);
}

// StartsWithI reports whether text starts with prefix ignoring case. Inputs are
// UI/path strings; processing compares one character at a time; output is true
// only when prefix is fully present.
bool StartsWithI(const std::wstring& text, const std::wstring& prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (::towlower(text[i]) != ::towlower(prefix[i])) {
            return false;
        }
    }
    return true;
}

// IsDriverObjectQuerySuccess maps the shared query status into a table success
// decision. Input is one DriverObject query response; output is true for full or
// partial DriverObject evidence so callers still display partial rows.
bool IsDriverObjectQuerySuccess(const ksword::ark::DriverObjectQueryResult& query) {
    return query.io.ok &&
        (query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
            query.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL);
}

// DriverObjectQueryStatusText maps the R0 query status enum to compact display
// text. Input is KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_*; output is static text.
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

// DriverUnloadStatusText maps the force-unload response enum into a concise
// label. Input is KSWORD_ARK_DRIVER_UNLOAD_STATUS_*; output is static text.
const wchar_t* DriverUnloadStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED: return L"Unloaded";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_MISSING: return L"Unload routine missing";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_REFERENCE_FAILED: return L"Reference failed";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_THREAD_FAILED: return L"Thread failed";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_WAIT_TIMEOUT: return L"Wait timeout";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED: return L"Operation failed";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP: return L"Forced cleanup";
    case KSWORD_ARK_DRIVER_UNLOAD_STATUS_CLEANUP_FAILED: return L"Cleanup failed";
    default: return L"Unknown";
    }
}

// DriverUnloadSucceeded reports whether the aggregate R0 unload status should
// be considered successful. Input is the status field; output drives result UI.
bool DriverUnloadSucceeded(const std::uint32_t status) {
    return status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED ||
        status == KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP;
}

// MajorFunctionName returns the conventional IRP_MJ_* label. Input is a major
// function index; output falls back to a numeric IRP_MJ_N label.
std::wstring MajorFunctionName(const std::uint32_t value) {
    switch (value) {
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
    default: return std::wstring(L"IRP_MJ_") + std::to_wstring(value);
    }
}

// NormalizeDriverObjectName converts a selected row path/name into the canonical
// \Driver\Name form required by ArkDriverClient. Input is user-visible text;
// output is empty for strings that cannot identify a DriverObject.
std::wstring NormalizeDriverObjectName(std::wstring value, const bool allowBareName) {
    while (!value.empty() && std::iswspace(value.front())) {
        value.erase(value.begin());
    }
    while (!value.empty() && std::iswspace(value.back())) {
        value.pop_back();
    }
    if (value.empty()) {
        return {};
    }
    if (StartsWithI(value, L"\\Driver\\")) {
        return value;
    }
    if (StartsWithI(value, L"Driver\\")) {
        return L"\\" + value;
    }
    if (allowBareName && value.find(L'\\') == std::wstring::npos) {
        return L"\\Driver\\" + value;
    }
    return {};
}

// AppendUniqueDriverObjectName adds one canonical name if it is not already in
// the vector. Inputs are the destination list and candidate; no value is
// returned because the list is mutated in place.
void AppendUniqueDriverObjectName(std::vector<std::wstring>& names, const std::wstring& candidate) {
    if (candidate.empty()) {
        return;
    }
    const auto exists = std::find_if(names.begin(), names.end(), [&](const std::wstring& item) {
        return _wcsicmp(item.c_str(), candidate.c_str()) == 0;
    });
    if (exists == names.end()) {
        names.push_back(candidate);
    }
}

// RowField extracts one field from a generic result row. Inputs are row and key;
// output is an empty string when the key is not present.
std::wstring RowField(const KernelResultRow& row, const std::wstring& key) {
    for (const auto& column : row.columns) {
        if (_wcsicmp(column.first.c_str(), key.c_str()) == 0) {
            return column.second;
        }
    }
    return {};
}

// DriverObjectNameFromRow resolves a DriverObject name from native or R0 rows.
// Inputs are one generic result row; processing checks explicit Path/DriverName
// first and then \Driver parent rows; output is canonical or empty.
std::wstring DriverObjectNameFromRow(const KernelResultRow& row) {
    const auto firstRowField = [&](std::initializer_list<const wchar_t*> keys) {
        for (const wchar_t* key : keys) {
            const std::wstring value = RowField(row, key);
            if (!value.empty()) {
                return value;
            }
        }
        return std::wstring{};
    };
    const std::wstring direct = NormalizeDriverObjectName(firstRowField({ L"DriverName", L"objectName", L"对象名称", L"Name" }), false);
    if (!direct.empty()) {
        return direct;
    }
    const std::wstring path = NormalizeDriverObjectName(firstRowField({ L"Path", L"fullPath", L"FullPath", L"完整路径", L"NtPath" }), false);
    if (!path.empty()) {
        return path;
    }
    const std::wstring parent = firstRowField({ L"Parent", L"Directory", L"directoryPath", L"目录路径" });
    const std::wstring source = firstRowField({ L"Source", L"来源目录" });
    const std::wstring type = firstRowField({ L"Type", L"objectType", L"对象类型", L"类型" });
    const bool allowName =
        _wcsicmp(parent.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(source.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(type.c_str(), L"DriverObject") == 0;
    return NormalizeDriverObjectName(firstRowField({ L"Name", L"objectName", L"对象名称", L"名称" }), allowName);
}

// DriverObjectNameFromActionRequest resolves the selected row snapshot carried
// by KernelPage into a canonical \Driver\Name string. Inputs are value-only
// row fields copied from the ListView; processing checks R0 DriverName/Path
// columns first and then native \Driver parent/name columns; output is empty
// when the selected row is not a DriverObject-related row.
std::wstring DriverObjectNameFromActionRequest(const KernelActionRequest& request) {
    const std::wstring direct = NormalizeDriverObjectName(FieldValue(request, L"DriverName"), false);
    if (!direct.empty()) {
        return direct;
    }
    const std::wstring path = NormalizeDriverObjectName(FirstFieldValue(request, {
        L"Path",
        L"fullPath",
        L"FullPath",
        L"完整路径",
        L"NtPath",
        L"NT Path",
    }), false);
    if (!path.empty()) {
        return path;
    }
    const std::wstring parent = FirstFieldValue(request, {
        L"Parent",
        L"Directory",
        L"directoryPath",
        L"目录路径",
    });
    const std::wstring source = FirstFieldValue(request, {
        L"Source",
        L"来源目录",
    });
    const std::wstring type = FirstFieldValue(request, {
        L"Type",
        L"objectType",
        L"对象类型",
        L"类型",
    });
    const bool allowName =
        _wcsicmp(parent.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(source.c_str(), L"\\Driver") == 0 ||
        _wcsicmp(type.c_str(), L"DriverObject") == 0 ||
        _wcsicmp(source.c_str(), L"R0 DriverObject") == 0 ||
        _wcsicmp(source.c_str(), L"R0 MajorFunction") == 0 ||
        _wcsicmp(source.c_str(), L"R0 DeviceObject") == 0;
    return NormalizeDriverObjectName(FirstFieldValue(request, {
        L"Name",
        L"objectName",
        L"对象名称",
        L"名称",
    }), allowName);
}

// DriverModuleBaseFromActionRequest extracts a loaded-driver image base from the
// immutable row snapshot. It accepts the detail query's DriverStart first and
// falls back to the module-base fields used by integrity and dispatch rows.
std::uint64_t DriverModuleBaseFromActionRequest(const KernelActionRequest& request) {
    const std::wstring value = FirstFieldValue(request, {
        L"DriverStart",
        L"ModuleBase",
        L"OwnerModuleBase",
        L"OwnerBase",
    });
    std::uint64_t moduleBase = 0;
    return ParseFirstUnsigned64FromText(value, moduleBase) ? moduleBase : 0ULL;
}

// InlinePatchLength mirrors the original KernelDock conservative NOP length
// selection. Inputs are hook type and available bytes; output is zero when the
// selected row is not safe for automatic NOP patching.
std::uint32_t InlinePatchLength(const std::uint32_t hookType, const std::uint32_t availableBytes) {
    std::uint32_t desired = 0;
    switch (hookType) {
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32:
        desired = 5;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8:
        desired = 2;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT:
        desired = 6;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX:
        desired = 12;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11:
        desired = 13;
        break;
    case KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH:
    case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH:
        desired = 1;
        break;
    default:
        desired = 0;
        break;
    }
    return std::min<std::uint32_t>(desired, availableBytes);
}

// CallbackRemoveTypeForClass converts callback enumeration classes into the
// removeExternalCallbackEx request class expected by the driver protocol.
// Inputs are enum rows from ArkDriverClient; output is zero when no safe public
// removal path exists.
std::uint32_t CallbackRemoveTypeForClass(const std::uint32_t callbackClass) {
    switch (callbackClass) {
    case KSWORD_ARK_CALLBACK_TYPE_REGISTRY:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
    case KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    case KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
    case KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
    case KSWORD_ARK_CALLBACK_TYPE_OBJECT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
    case KSWORD_ARK_CALLBACK_TYPE_MINIFILTER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
    default:
        return 0;
    }
}

// Crc32Step advances the same reflected CRC32 algorithm used by the callback
// rule validator in R0. Inputs are a byte span and a running CRC value; output
// is the updated running value before final bit inversion.
std::uint32_t Crc32Step(const std::uint8_t* const data, const std::size_t length, const std::uint32_t currentCrc) {
    std::uint32_t crc = currentCrc;
    if (data == nullptr || length == 0) {
        return crc;
    }
    for (std::size_t byteIndex = 0; byteIndex < length; ++byteIndex) {
        crc ^= static_cast<std::uint32_t>(data[byteIndex]);
        for (int bitIndex = 0; bitIndex < 8; ++bitIndex) {
            crc = (crc & 1U) != 0U ? ((crc >> 1U) ^ 0xEDB88320U) : (crc >> 1U);
        }
    }
    return crc;
}

// Crc32 computes the finalized reflected CRC32 for callback rule blobs. Input
// is the serialized blob with header.crc32 still zero; output is the value that
// must be copied into KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER::crc32.
std::uint32_t Crc32(const std::vector<std::uint8_t>& bytes) {
    return ~Crc32Step(bytes.data(), bytes.size(), 0xFFFFFFFFU);
}

// BuildDisabledCallbackRuleBlob creates a valid empty callback-rule snapshot.
// Inputs are a monotonically increasing rule version; processing writes the
// shared header, uses no groups/rules/string pool, and fills the required CRC;
// output is ready for ArkDriverClient::setCallbackRules.
std::vector<std::uint8_t> BuildDisabledCallbackRuleBlob(const std::uint64_t ruleVersion) {
    KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER header{};
    header.size = static_cast<unsigned long>(sizeof(header));
    header.magic = KSWORD_ARK_CALLBACK_RULE_BLOB_MAGIC;
    header.protocolVersion = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    header.schemaVersion = KSWORD_ARK_CALLBACK_RULE_SCHEMA_VERSION;
    header.globalFlags = 0;
    header.groupCount = 0;
    header.ruleCount = 0;
    header.groupOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.ruleOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.stringOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.stringBytes = 0;
    header.crc32 = 0;
    header.reserved = 0;
    header.ruleVersion = ruleVersion;

    std::vector<std::uint8_t> blob(sizeof(header), 0);
    std::memcpy(blob.data(), &header, sizeof(header));
    header.crc32 = Crc32(blob);
    std::memcpy(blob.data(), &header, sizeof(header));
    return blob;
}

struct LocalCallbackRuleGroup {
    std::uint32_t id = 0;
    bool enabled = true;
    std::uint32_t priority = 10;
    std::wstring name;
    std::wstring comment;
};

struct LocalCallbackRule {
    std::uint32_t id = 0;
    std::uint32_t groupId = 0;
    std::uint32_t typeIndex = 0;
    bool enabled = true;
    std::uint32_t priority = 10;
    std::uint32_t timeoutMs = 0;
    std::wstring name;
    std::wstring operation;
    std::wstring matchMode;
    std::wstring action;
    std::wstring timeoutDefault;
    std::wstring initiatorPattern;
    std::wstring targetPattern;
    std::wstring comment;
};

struct LocalCallbackRuleDocument {
    bool globalEnabled = true;
    std::vector<LocalCallbackRuleGroup> groups;
    std::vector<LocalCallbackRule> rules;
};

// SplitTabs keeps empty fields while parsing the lightweight Win32 rule export.
// Input is one serialized line; output is an ordered list of tab fields.
std::vector<std::wstring> SplitTabs(const std::wstring& line) {
    std::vector<std::wstring> fields;
    std::wstring current;
    for (const wchar_t ch : line) {
        if (ch == L'\t') {
            fields.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    fields.push_back(current);
    return fields;
}

// UnescapeLocalRuleField reverses the UI serializer for local callback rule
// text. Input is one field; output is plain Unicode text for blob string pool.
std::wstring UnescapeLocalRuleField(const std::wstring& text) {
    std::wstring value;
    value.reserve(text.size());
    bool escaping = false;
    for (const wchar_t ch : text) {
        if (escaping) {
            switch (ch) {
            case L't': value.push_back(L'\t'); break;
            case L'r': value.push_back(L'\r'); break;
            case L'n': value.push_back(L'\n'); break;
            case L'\\': value.push_back(L'\\'); break;
            default: value.push_back(ch); break;
            }
            escaping = false;
            continue;
        }
        if (ch == L'\\') {
            escaping = true;
        } else {
            value.push_back(ch);
        }
    }
    if (escaping) {
        value.push_back(L'\\');
    }
    return value;
}

std::uint32_t ParseLocalUInt(const std::wstring& text, const std::uint32_t fallback) {
    if (text.empty()) {
        return fallback;
    }
    wchar_t* end = nullptr;
    const unsigned long value = std::wcstoul(text.c_str(), &end, 10);
    return end != text.c_str() ? static_cast<std::uint32_t>(value) : fallback;
}

// ParseLocalCallbackRuleDocument parses the UI-exported .kswrules text. Inputs
// are the serialized local editor state and an error sink; output is a document
// used only to build the shared R0 rule blob.
bool ParseLocalCallbackRuleDocument(const std::wstring& text, LocalCallbackRuleDocument& document, std::wstring& errorText) {
    std::wistringstream input(text);
    std::wstring line;
    bool sawHeader = false;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if (!sawHeader) {
            if (line != L"KSWORD_ARKLIGHT_CALLBACK_RULES_V1") {
                errorText = L"本地规则配置头不匹配。";
                return false;
            }
            sawHeader = true;
            continue;
        }
        const std::vector<std::wstring> fields = SplitTabs(line);
        if (fields.empty()) {
            continue;
        }
        if (fields[0] == L"GLOBAL") {
            if (fields.size() >= 2) {
                document.globalEnabled = ParseLocalUInt(fields[1], 1) != 0;
            }
        } else if (fields[0] == L"GROUP") {
            if (fields.size() < 6) {
                errorText = L"GROUP 字段不足。";
                return false;
            }
            LocalCallbackRuleGroup group;
            group.id = ParseLocalUInt(fields[1], 0);
            group.enabled = ParseLocalUInt(fields[2], 0) != 0;
            group.priority = ParseLocalUInt(fields[3], 10);
            group.name = UnescapeLocalRuleField(fields[4]);
            group.comment = UnescapeLocalRuleField(fields[5]);
            if (group.id == 0) {
                errorText = L"GROUP id 非法。";
                return false;
            }
            document.groups.push_back(std::move(group));
        } else if (fields[0] == L"RULE") {
            if (fields.size() < 13) {
                errorText = L"RULE 字段不足。";
                return false;
            }
            LocalCallbackRule rule;
            rule.id = ParseLocalUInt(fields[1], 0);
            rule.groupId = ParseLocalUInt(fields[2], 0);
            rule.typeIndex = ParseLocalUInt(fields[3], 0);
            rule.enabled = ParseLocalUInt(fields[4], 0) != 0;
            rule.priority = ParseLocalUInt(fields[5], 10);
            rule.timeoutMs = ParseLocalUInt(fields[6], 0);
            rule.name = UnescapeLocalRuleField(fields[7]);
            rule.operation = UnescapeLocalRuleField(fields[8]);
            rule.matchMode = UnescapeLocalRuleField(fields[9]);
            rule.action = UnescapeLocalRuleField(fields[10]);
            rule.timeoutDefault = UnescapeLocalRuleField(fields[11]);
            if (fields.size() >= 15) {
                rule.initiatorPattern = UnescapeLocalRuleField(fields[12]);
                rule.targetPattern = UnescapeLocalRuleField(fields[13]);
                rule.comment = UnescapeLocalRuleField(fields[14]);
            } else {
                rule.initiatorPattern = L"*";
                rule.targetPattern = L"*";
                rule.comment = UnescapeLocalRuleField(fields[12]);
            }
            if (rule.id == 0 || rule.groupId == 0 || rule.typeIndex > 5) {
                errorText = L"RULE id/group/type 非法。";
                return false;
            }
            document.rules.push_back(std::move(rule));
        }
    }
    if (!sawHeader) {
        errorText = L"本地规则配置为空或缺少头。";
        return false;
    }
    if (document.groups.size() > KSWORD_ARK_CALLBACK_MAX_GROUP_COUNT ||
        document.rules.size() > KSWORD_ARK_CALLBACK_MAX_RULE_COUNT) {
        errorText = L"本地规则数量超过驱动协议限制。";
        return false;
    }
    return true;
}

std::uint32_t LocalCallbackTypeFromIndex(const std::uint32_t typeIndex) {
    switch (typeIndex) {
    case 0: return KSWORD_ARK_CALLBACK_TYPE_REGISTRY;
    case 1: return KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE;
    case 2: return KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE;
    case 3: return KSWORD_ARK_CALLBACK_TYPE_IMAGE_LOAD;
    case 4: return KSWORD_ARK_CALLBACK_TYPE_OBJECT;
    case 5: return KSWORD_ARK_CALLBACK_TYPE_MINIFILTER;
    default: return KSWORD_ARK_CALLBACK_TYPE_NONE;
    }
}

std::uint32_t LocalOperationMaskFromRule(const LocalCallbackRule& rule) {
    switch (rule.typeIndex) {
    case 0: return KSWORD_ARK_REG_OP_ALL;
    case 1: return KSWORD_ARK_PROCESS_OP_CREATE;
    case 2: return KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT;
    case 3: return KSWORD_ARK_IMAGE_OP_LOAD;
    case 4: return KSWORD_ARK_OBJECT_OP_HANDLE_CREATE | KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE | KSWORD_ARK_OBJECT_OP_TYPE_PROCESS | KSWORD_ARK_OBJECT_OP_TYPE_THREAD;
    case 5: return KSWORD_ARK_MINIFILTER_OP_ALL;
    default: return 0;
    }
}

std::uint32_t LocalMatchModeFromText(const std::wstring& text) {
    if (text.find(L"正则") != std::wstring::npos || text.find(L"Regex") != std::wstring::npos || text.find(L"regex") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_REGEX;
    }
    if (text.find(L"通配") != std::wstring::npos || text.find(L"Wildcard") != std::wstring::npos || text.find(L"*") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_WILDCARD;
    }
    if (text.find(L"前缀") != std::wstring::npos || text.find(L"Prefix") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_PREFIX;
    }
    if (text.find(L"精确") != std::wstring::npos || text.find(L"Exact") != std::wstring::npos) {
        return KSWORD_ARK_MATCH_MODE_EXACT;
    }
    return KSWORD_ARK_MATCH_MODE_WILDCARD;
}

std::uint32_t LocalActionFromText(const std::wstring& text) {
    if (text.find(L"拒绝") != std::wstring::npos || text.find(L"Deny") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_DENY;
    }
    if (text.find(L"允许") != std::wstring::npos || text.find(L"Allow") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_ALLOW;
    }
    if (text.find(L"询问") != std::wstring::npos || text.find(L"Ask") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_ASK_USER;
    }
    if (text.find(L"降权") != std::wstring::npos || text.find(L"Strip") != std::wstring::npos) {
        return KSWORD_ARK_RULE_ACTION_STRIP_ACCESS;
    }
    return KSWORD_ARK_RULE_ACTION_LOG_ONLY;
}

std::uint32_t LocalDecisionFromText(const std::wstring& text) {
    if (text.find(L"拒绝") != std::wstring::npos || text.find(L"Deny") != std::wstring::npos) {
        return KSWORD_ARK_DECISION_DENY;
    }
    if (text.find(L"允许") != std::wstring::npos || text.find(L"Allow") != std::wstring::npos) {
        return KSWORD_ARK_DECISION_ALLOW;
    }
    return KSWORD_ARK_DECISION_ALLOW;
}

// BuildCallbackRuleBlob converts local Win32 rule editor data into the shared
// R0 KSWORD_ARK_CALLBACK_RULE_BLOB format. Inputs are parsed groups/rules and
// a ruleVersion; output is a CRC-filled byte vector accepted by ArkDriverClient.
std::vector<std::uint8_t> BuildCallbackRuleBlob(const LocalCallbackRuleDocument& document, const std::uint64_t ruleVersion) {
    struct StringRef {
        std::uint32_t offset = 0;
        std::uint16_t chars = 0;
    };
    std::vector<std::uint8_t> stringBytes;
    const auto addString = [&](const std::wstring& value) -> StringRef {
        StringRef ref{};
        if (value.empty()) {
            return ref;
        }
        ref.offset = static_cast<std::uint32_t>(stringBytes.size());
        ref.chars = static_cast<std::uint16_t>(std::min<std::size_t>(value.size(), 0xFFFFU));
        const std::size_t byteCount = static_cast<std::size_t>(ref.chars) * sizeof(wchar_t);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
        stringBytes.insert(stringBytes.end(), bytes, bytes + byteCount);
        stringBytes.push_back(0);
        stringBytes.push_back(0);
        return ref;
    };

    std::vector<KSWORD_ARK_CALLBACK_GROUP_BLOB> groups(document.groups.size());
    for (std::size_t index = 0; index < document.groups.size(); ++index) {
        const LocalCallbackRuleGroup& source = document.groups[index];
        KSWORD_ARK_CALLBACK_GROUP_BLOB& target = groups[index];
        const StringRef name = addString(source.name);
        const StringRef comment = addString(source.comment);
        target.groupId = source.id;
        target.flags = source.enabled ? KSWORD_ARK_CALLBACK_GROUP_FLAG_ENABLED : 0;
        target.priority = source.priority;
        target.nameOffsetBytes = name.offset;
        target.nameLengthChars = name.chars;
        target.commentOffsetBytes = comment.offset;
        target.commentLengthChars = comment.chars;
    }

    std::vector<KSWORD_ARK_CALLBACK_RULE_BLOB> rules(document.rules.size());
    for (std::size_t index = 0; index < document.rules.size(); ++index) {
        const LocalCallbackRule& source = document.rules[index];
        KSWORD_ARK_CALLBACK_RULE_BLOB& target = rules[index];
        const StringRef name = addString(source.name);
        const StringRef comment = addString(source.comment);
        const StringRef initiator = addString(source.initiatorPattern.empty() ? L"*" : source.initiatorPattern);
        const StringRef targetPattern = addString(source.targetPattern.empty() ? L"*" : source.targetPattern);
        target.ruleId = source.id;
        target.groupId = source.groupId;
        target.flags = source.enabled ? KSWORD_ARK_CALLBACK_RULE_FLAG_ENABLED : 0;
        target.callbackType = LocalCallbackTypeFromIndex(source.typeIndex);
        target.operationMask = LocalOperationMaskFromRule(source);
        target.action = LocalActionFromText(source.action);
        target.matchMode = LocalMatchModeFromText(source.matchMode);
        target.priority = source.priority;
        target.initiatorOffsetBytes = initiator.offset;
        target.initiatorLengthChars = initiator.chars;
        target.targetOffsetBytes = targetPattern.offset;
        target.targetLengthChars = targetPattern.chars;
        target.askTimeoutMs = source.timeoutMs;
        target.askDefaultDecision = LocalDecisionFromText(source.timeoutDefault);
        target.ruleNameOffsetBytes = name.offset;
        target.ruleNameLengthChars = name.chars;
        target.commentOffsetBytes = comment.offset;
        target.commentLengthChars = comment.chars;
    }

    KSWORD_ARK_CALLBACK_RULE_BLOB_HEADER header{};
    header.size = static_cast<unsigned long>(
        sizeof(header) +
        groups.size() * sizeof(KSWORD_ARK_CALLBACK_GROUP_BLOB) +
        rules.size() * sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB) +
        stringBytes.size());
    header.magic = KSWORD_ARK_CALLBACK_RULE_BLOB_MAGIC;
    header.protocolVersion = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    header.schemaVersion = KSWORD_ARK_CALLBACK_RULE_SCHEMA_VERSION;
    header.globalFlags = document.globalEnabled ? KSWORD_ARK_CALLBACK_GLOBAL_FLAG_ENABLED : 0;
    header.groupCount = static_cast<unsigned long>(groups.size());
    header.ruleCount = static_cast<unsigned long>(rules.size());
    header.groupOffsetBytes = static_cast<unsigned long>(sizeof(header));
    header.ruleOffsetBytes = header.groupOffsetBytes + static_cast<unsigned long>(groups.size() * sizeof(KSWORD_ARK_CALLBACK_GROUP_BLOB));
    header.stringOffsetBytes = header.ruleOffsetBytes + static_cast<unsigned long>(rules.size() * sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB));
    header.stringBytes = static_cast<unsigned long>(stringBytes.size());
    header.ruleVersion = ruleVersion;

    std::vector<std::uint8_t> blob(header.size, 0);
    std::memcpy(blob.data(), &header, sizeof(header));
    if (!groups.empty()) {
        std::memcpy(blob.data() + header.groupOffsetBytes, groups.data(), groups.size() * sizeof(KSWORD_ARK_CALLBACK_GROUP_BLOB));
    }
    if (!rules.empty()) {
        std::memcpy(blob.data() + header.ruleOffsetBytes, rules.data(), rules.size() * sizeof(KSWORD_ARK_CALLBACK_RULE_BLOB));
    }
    if (!stringBytes.empty()) {
        std::memcpy(blob.data() + header.stringOffsetBytes, stringBytes.data(), stringBytes.size());
    }
    header.crc32 = Crc32(blob);
    std::memcpy(blob.data(), &header, sizeof(header));
    return blob;
}

// CurrentUtc100ns returns the Win32 FILETIME timestamp used by the callback
// protocol. Input is none; processing asks the OS for UTC system time; output is
// a 100ns timestamp suitable for ruleVersion display fallback.
std::uint64_t CurrentUtc100ns() {
    FILETIME fileTime{};
    ::GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

// Utc100nsToLocalText formats FILETIME-style timestamps returned by R0. Input
// is a UTC 100ns value; processing converts to local SYSTEMTIME when possible;
// output keeps the raw hexadecimal value in separate columns and returns a
// compact wall-clock string for operators.
std::wstring Utc100nsToLocalText(const std::uint64_t utc100ns) {
    if (utc100ns == 0) {
        return L"N/A";
    }

    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(utc100ns & 0xFFFFFFFFULL);
    utc.dwHighDateTime = static_cast<DWORD>(utc100ns >> 32U);
    FILETIME local{};
    SYSTEMTIME systemTime{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &systemTime)) {
        return L"Invalid";
    }

    std::wostringstream stream;
    stream << std::setfill(L'0')
           << std::setw(4) << systemTime.wYear << L'-'
           << std::setw(2) << systemTime.wMonth << L'-'
           << std::setw(2) << systemTime.wDay << L' '
           << std::setw(2) << systemTime.wHour << L':'
           << std::setw(2) << systemTime.wMinute << L':'
           << std::setw(2) << systemTime.wSecond;
    return stream.str();
}

// CallbackRegisteredMaskText expands the runtime registration mask. Input is
// the R0 mask; processing uses the driver-defined bit layout mirrored here for
// display only; output is a comma-separated summary.
std::wstring CallbackRegisteredMaskText(const std::uint32_t mask) {
    std::vector<std::wstring> names;
    AppendFlagName(names, mask, 0x00000001UL, L"Registry");
    AppendFlagName(names, mask, 0x00000002UL, L"Process");
    AppendFlagName(names, mask, 0x00000004UL, L"Thread");
    AppendFlagName(names, mask, 0x00000008UL, L"Image");
    AppendFlagName(names, mask, 0x00000010UL, L"Object");
    AppendFlagName(names, mask, 0x00000020UL, L"Minifilter");
    return JoinNames(names);
}

// CallbackEnumClassText mirrors KswordARK's callbackEnumClassText mapping.
// Input is a shared callback enum class; output is the operator-facing class
// label used in the lightweight table.
std::wstring CallbackEnumClassText(const std::uint32_t callbackClass) {
    switch (callbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY: return L"注册表 CmCallback";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS: return L"进程 Notify";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD: return L"线程 Notify";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE: return L"镜像加载 Notify";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT: return L"Object Callback";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER: return L"Minifilter";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT: return L"WFP Callout";
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER: return L"ETW Provider/Consumer";
    default: return std::wstring(L"未知(") + std::to_wstring(callbackClass) + L")";
    }
}

// CallbackEnumSourceText mirrors KswordARK's source-name mapping. Input is the
// callback source id; output explains whether evidence came from public APIs,
// private structure walks, PDB profiles, or Ksword itself.
std::wstring CallbackEnumSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF: return L"Ksword 自身注册";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION: return L"FltMgr 公开枚举";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED: return L"私有结构诊断";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN: return L"私有特征定位";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY: return L"Psp Notify 数组";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST: return L"Cm 回调链表";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST: return L"Ob 对象类型链表";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API: return L"WFP 管理 API";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA: return L"ETW DynData";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE: return L"PDB 可信 profile";
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API: return L"公开 API";
    default: return std::wstring(L"未知(") + std::to_wstring(source) + L")";
    }
}

// CallbackEnumStatusText maps R0 callback-row statuses to readable text. Input
// is KSWORD_ARK_CALLBACK_ENUM_STATUS_*; output keeps the numeric value separate.
std::wstring CallbackEnumStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED: return L"Not registered";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_CALLBACK_ENUM_STATUS_BUFFER_TRUNCATED: return L"Buffer truncated";
    default: return L"Unknown";
    }
}

// CallbackEnumFieldFlagsText expands KSWORD_ARK_CALLBACK_ENUM_FIELD_* bits.
// Input is a bitmask from ArkDriverClient; output follows the original Dock's
// evidence-focused display while preserving unknown bits by hex fallback.
std::wstring CallbackEnumFieldFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS, L"callback");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS, L"context");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS, L"registration");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE, L"module");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME, L"name");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE, L"altitude");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD, L"owned");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE, L"removable candidate");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK, L"operation mask");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK, L"object type mask");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER, L"identifier");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE, L"handle");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED, L"trusted");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE, L"verified remove");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE, L"experimental remove");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE, L"raw storage");
    const std::uint32_t knownFlags =
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// CallbackEnumTrustFlagsText expands trust provenance bits. Input is R0 trust
// flags; output matches the original Dock's PDB/public/fallback/revalidated
// diagnostic wording.
std::wstring CallbackEnumTrustFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE, L"pdb profile");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API, L"public api");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN, L"fallback pattern");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_TRUST_REVALIDATED, L"revalidated");
    const std::uint32_t knownFlags =
        KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API |
        KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN |
        KSWORD_ARK_CALLBACK_TRUST_REVALIDATED;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// CallbackEnumRemoveBehaviorText expands removal behavior bits. Input is the
// behavior mask returned by R0; output explains whether public API removal or
// experimental unlink is involved.
std::wstring CallbackEnumRemoveBehaviorText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API, L"public api");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK, L"experimental unlink");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION, L"require revalidation");
    AppendFlagName(names, flags, KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_FORCE_AFTER_PUBLIC_FAILURE, L"force after public failure");
    const std::uint32_t knownFlags =
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_FORCE_AFTER_PUBLIC_FAILURE;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// CallbackEnumMappingText mirrors the original remove-result mapping display.
// Input is KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_*; output names all known
// evidence channels and keeps future bits visible.
std::wstring CallbackEnumMappingText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE, L"module");
    AppendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED, L"enumerated");
    AppendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API, L"public api");
    AppendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED, L"pdb trusted");
    AppendFlagName(names, flags, KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL, L"experimental");
    const std::uint32_t knownFlags =
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// CallbackEnumIsPublicApiSource returns whether the row came from documented
// enumeration paths. Input is a source id; output follows the original Dock's
// public API bucket.
bool CallbackEnumIsPublicApiSource(const std::uint32_t source) {
    return source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API;
}

// CallbackEnumIsFallbackSource returns whether the row is private/fallback
// evidence. Input is a source id; output guides trust and removal labels.
bool CallbackEnumIsFallbackSource(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST:
    case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA:
        return true;
    default:
        return false;
    }
}

// CallbackEnumTrustBucket mirrors the original Dock's trust summary. Input is
// one callback row; output is a compact risk/trust bucket for the result table.
std::wstring CallbackEnumTrustBucket(const ksword::ark::CallbackEnumEntry& entry) {
    if (entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED ||
        entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED) {
        return L"unsupported（当前协议/平台未支持）";
    }
    if (entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF ||
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD) != 0U ||
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED) != 0U ||
        (entry.trustFlags & (KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE | KSWORD_ARK_CALLBACK_TRUST_REVALIDATED)) != 0U) {
        return L"trusted（可信/自有或预留 PDB）";
    }
    if (CallbackEnumIsPublicApiSource(entry.source) ||
        (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API) != 0U ||
        (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0U) {
        return L"public api（公开 API）";
    }
    if (CallbackEnumIsFallbackSource(entry.source) ||
        (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) != 0U) {
        return L"fallback/pattern（私有结构诊断）";
    }
    return L"fallback（未知来源保守展示）";
}

// CallbackEnumRemovePolicyText mirrors the original Dock's conservative remove
// policy. Input is one callback row; output states whether safe removal is
// verified, merely candidate, experimental-only, or not allowed.
std::wstring CallbackEnumRemovePolicyText(const ksword::ark::CallbackEnumEntry& entry) {
    if (entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED ||
        entry.status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK ||
        CallbackRemoveTypeForClass(entry.callbackClass) == 0U) {
        return L"not removable（不可移除）";
    }

    const bool removableCandidate = (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0U;
    const bool verifiedRemove =
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE) != 0U ||
        (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0U;
    const bool experimentalRemove =
        (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE) != 0U ||
        (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK) != 0U;
    const bool hasRequestValue = entry.callbackAddress != 0 || entry.registrationAddress != 0 || entry.rawStorageValue != 0;

    if (hasRequestValue && (verifiedRemove || (removableCandidate && CallbackEnumIsPublicApiSource(entry.source)))) {
        return L"removable verified（公开 API 可验证）";
    }
    if (removableCandidate && hasRequestValue) {
        return L"removable candidate（旧协议候选）";
    }
    if ((experimentalRemove || CallbackEnumIsFallbackSource(entry.source)) && hasRequestValue) {
        return L"experimental only（仅预留 unlink）";
    }
    return L"not removable（不可移除）";
}

// KernelHookStatusText mirrors KswordARK's kernelHookStatusText. Input is a
// shared hook status; output is the Chinese status shown by the original Dock.
std::wstring KernelHookStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN: return L"干净";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS: return L"可疑外跳";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH: return L"模块内跳转";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED: return L"读取失败";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED: return L"解析失败";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED: return L"需要强制确认";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED: return L"已修复/摘除";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED: return L"修复失败";
    case KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN:
    default:
        return std::wstring(L"未知(") + std::to_wstring(status) + L")";
    }
}

// InlineHookTypeText mirrors KswordARK's inlineHookTypeText. Input is the R0
// inline patch type; output is a readable instruction-pattern label.
std::wstring InlineHookTypeText(const std::uint32_t hookType) {
    switch (hookType) {
    case KSWORD_ARK_INLINE_HOOK_TYPE_NONE: return L"无明显补丁";
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32: return L"JMP rel32";
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8: return L"JMP rel8";
    case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT: return L"JMP [RIP+rel32]";
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX: return L"MOV RAX; JMP RAX";
    case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11: return L"MOV R11; JMP R11";
    case KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH: return L"RET 补丁";
    case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH: return L"INT3 补丁";
    case KSWORD_ARK_INLINE_HOOK_TYPE_UNKNOWN_PATCH: return L"未知补丁";
    default:
        return std::wstring(L"未知(") + std::to_wstring(hookType) + L")";
    }
}

// IatEatClassText mirrors KswordARK's iatEatClassText. Input is the hook class;
// output is IAT/EAT text with a numeric fallback.
std::wstring IatEatClassText(const std::uint32_t hookClass) {
    switch (hookClass) {
    case KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT: return L"IAT";
    case KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT: return L"EAT";
    default:
        return std::wstring(L"未知(") + std::to_wstring(hookClass) + L")";
    }
}

// BuildInlineHookDetailText reproduces the original KernelDock detail editor
// for one Inline Hook row. Inputs are one ArkDriverClient row and its optional
// R3 disk baseline; output is a complete multiline detail string.
std::wstring BuildInlineHookDetailText(
    const ksword::ark::KernelInlineHookEntry& entry,
    const InlineDiskBaseline& disk) {
    const std::wstring moduleText = entry.moduleName.empty() ? L"<空>" : entry.moduleName;
    const std::wstring functionText = entry.functionName.empty() ? L"<空>" : Utf8ToWide(entry.functionName);
    const std::wstring targetModuleText = entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName;
    const std::wstring diskBytesText = disk.available ? BytesHex(disk.bytes, disk.byteCount) : L"<不可用>";
    const std::wstring diskByteCountText = disk.available ? std::to_wstring(disk.byteCount) : L"0";
    const std::wstring diskPathText = disk.filePath.empty() ? L"<不可用>" : disk.filePath;
    const std::wstring rvaText = entry.moduleBase != 0 && entry.functionAddress >= entry.moduleBase
        ? HexText(entry.functionAddress - entry.moduleBase)
        : L"<未解析>";

    std::wostringstream detail;
    detail << L"Inline Hook 检测详情\r\n"
           << L"模块: " << moduleText << L"\r\n"
           << L"函数: " << functionText << L"\r\n"
           << L"函数地址: " << HexText(entry.functionAddress) << L"\r\n"
           << L"Hook类型: " << InlineHookTypeText(entry.hookType) << L"\r\n"
           << L"目标地址: " << HexText(entry.targetAddress) << L"\r\n"
           << L"目标模块: " << targetModuleText << L"\r\n"
           << L"状态: " << KernelHookStatusText(entry.status) << L"\r\n"
           << L"模块基址: " << HexText(entry.moduleBase) << L"\r\n"
           << L"目标模块基址: " << HexText(entry.targetModuleBase) << L"\r\n"
           << L"当前内存字节(" << entry.currentByteCount << L"): " << BytesHex(entry.currentBytes, entry.currentByteCount) << L"\r\n"
           << L"R0 观察基线(" << entry.originalByteCount << L"): " << BytesHex(entry.expectedBytes, entry.originalByteCount) << L"\r\n"
           << L"磁盘基线字节(" << diskByteCountText << L"): " << diskBytesText << L"\r\n"
           << L"差异状态: " << disk.statusText << L"\r\n"
           << L"磁盘路径: " << diskPathText << L"\r\n"
           << L"RVA: " << rvaText << L"\r\n"
           << L"标志: " << HexText(entry.flags) << L"\r\n\r\n"
           << L"说明: 当前协议字段 expectedBytes 在 R0 中来自内存观察，通常是 currentBytes 的同源快照，不代表磁盘原始字节。"
           << L"本页额外由 R3 按模块基址和 RVA 从磁盘模块文件读取基线字节并与当前内存字节比较；"
           << L"如果磁盘基线不可用，请只把 R0 观察基线当作诊断快照，不要把它理解为干净基线。"
           << L"磁盘基线是文件同 RVA 的 raw 字节，未应用重定位、热补丁或厂商运行时改写校正，差异仍需结合 Hook 类型和目标地址判断。"
           << L"摘除操作保持原有 NOP 流程，不新增自动修复能力。";
    return detail.str();
}

// BuildIatEatHookDetailText reproduces the original KernelDock detail editor
// for one IAT/EAT row. Input is one ArkDriverClient hook row; output is the
// complete multiline details shown by the Win32 detail edit.
std::wstring BuildIatEatHookDetailText(const ksword::ark::KernelIatEatHookEntry& entry) {
    const std::wstring functionText = !entry.functionName.empty()
        ? Utf8ToWide(entry.functionName)
        : std::wstring(L"#") + std::to_wstring(entry.ordinal);
    std::wostringstream detail;
    detail << L"IAT/EAT Hook 检测详情\r\n"
           << L"类别: " << IatEatClassText(entry.hookClass) << L"\r\n"
           << L"模块: " << (entry.moduleName.empty() ? L"<空>" : entry.moduleName) << L"\r\n"
           << L"导入模块: " << (entry.importModuleName.empty() ? L"<不适用>" : entry.importModuleName) << L"\r\n"
           << L"函数/序号: " << functionText << L"\r\n"
           << L"Thunk/EAT项: " << HexText(entry.thunkAddress) << L"\r\n"
           << L"当前目标: " << HexText(entry.currentTarget) << L"\r\n"
           << L"期望目标: " << HexText(entry.expectedTarget) << L"\r\n"
           << L"目标模块: " << (entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName) << L"\r\n"
           << L"所属模块基址: " << HexText(entry.moduleBase) << L"\r\n"
           << L"目标模块基址: " << HexText(entry.targetModuleBase) << L"\r\n"
           << L"状态: " << KernelHookStatusText(entry.status) << L"\r\n"
           << L"标志: " << HexText(entry.flags) << L"\r\n\r\n"
           << L"说明: IAT 检测比较 thunk 当前目标是否仍落在声明导入模块内；"
           << L"EAT 检测导出 RVA 是否落在自身映像或转发导出区域内。";
    return detail.str();
}

// SsdtFlagsText expands the SSDT/SSSDT row flags using the same concepts as
// the original Dock detail pane. Input is the R0 flags mask; output names the
// resolved index/table/shadow/stub evidence.
std::wstring SsdtFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED, L"索引已解析");
    AppendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID, L"服务表有效");
    AppendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE, L"Shadow/GUI表");
    AppendFlagName(names, flags, KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT, L"Stub导出");
    const std::uint32_t knownFlags =
        KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED |
        KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID |
        KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE |
        KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// SsdtStatusText builds the SSSDT-style status summary from the original Dock.
// Inputs are one SSDT row and whether this is a shadow table; output is a compact
// row-status sentence.
std::wstring SsdtStatusText(const ksword::ark::SsdtEntry& entry, const bool shadow) {
    std::vector<std::wstring> parts;
    if (shadow || (entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE) != 0U) {
        parts.push_back(L"Shadow/GUI表");
    }
    parts.push_back((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U ? L"索引已解析" : L"索引未解析");
    parts.push_back((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_STUB_EXPORT) != 0U ? L"Stub导出" : L"非Stub导出");
    parts.push_back(entry.serviceRoutineAddress != 0 ? L"表项已解析" : L"表项地址暂不可用");
    return JoinNames(parts);
}

// PagePermissionText expands page-table permission bits used by executable
// kernel-memory scan rows. Input is a permission mask from R0; output keeps the
// common R/W/X/NX/Large/Global signals readable while preserving raw hex columns.
std::wstring PagePermissionText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    std::wstring rwx;
    rwx += (flags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0U ? L'R' : L'-';
    rwx += (flags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0U ? L'W' : L'-';
    rwx += (flags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0U ? L'-' : L'X';
    names.push_back(rwx);
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_NX, L"NX");
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE, L"Large");
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_USER, L"User");
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL, L"Global");
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_WRITE_THROUGH, L"WriteThrough");
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_CACHE_DISABLE, L"CacheDisable");
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED, L"Accessed");
    AppendFlagName(names, flags, KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY, L"Dirty");
    const std::uint32_t knownFlags =
        KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT |
        KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE |
        KSWORD_ARK_PAGE_TABLE_FLAG_USER |
        KSWORD_ARK_PAGE_TABLE_FLAG_WRITE_THROUGH |
        KSWORD_ARK_PAGE_TABLE_FLAG_CACHE_DISABLE |
        KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED |
        KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY |
        KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE |
        KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL |
        KSWORD_ARK_PAGE_TABLE_FLAG_NX;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// KernelExecStatusText maps executable-memory aggregate/row statuses. Input is
// KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_*; output is a compact diagnostic label.
std::wstring KernelExecStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_CONSERVATIVE: return L"Conservative";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_PARTIAL_CONSERVATIVE: return L"Partial conservative";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_INVALID_RANGE: return L"Invalid range";
    case KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_IRQL_REJECTED: return L"IRQL rejected";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// KernelExecOwnerText names executable-memory owner classes. Input is the R0
// owner kind; output follows the module text / non-text / writable-exec buckets.
std::wstring KernelExecOwnerText(const std::uint32_t ownerKind) {
    switch (ownerKind) {
    case KSWORD_ARK_KERNEL_EXEC_OWNER_UNKNOWN: return L"未知";
    case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT: return L"模块 .text";
    case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_NON_TEXT: return L"模块非 .text";
    case KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_WRITABLE_EXECUTABLE: return L"模块 WX";
    default: return std::wstring(L"未知(") + std::to_wstring(ownerKind) + L")";
    }
}

// KernelExecRiskText expands executable-memory risk bits. Input is a risk mask;
// output names writable-executable, non-text executable, writable section, and
// large-page findings for quick triage.
std::wstring KernelExecRiskText(const std::uint32_t flags) {
    if (flags == 0U) {
        return L"正常";
    }
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE, L"WX");
    AppendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE, L"非.text可执行");
    AppendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE, L"节可写");
    AppendFlagName(names, flags, KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE, L"大页");
    const std::uint32_t knownFlags =
        KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE |
        KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE |
        KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE |
        KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// MemoryEvidenceHashText mirrors the original MemoryDock hash column. Inputs
// are one evidence row; processing combines algorithm, section and FNV/hash
// value; output is "无" when R0 did not provide a text-section hash.
std::wstring MemoryEvidenceHashText(const ksword::ark::KernelMemoryEvidenceEntry& entry) {
    if (entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE || entry.contentHash == 0ULL) {
        return L"无";
    }
    std::wstring algorithm = entry.hashAlgorithm == KSWORD_ARK_MEMORY_EVIDENCE_HASH_FNV1A64
        ? L"FNV1A64"
        : std::wstring(L"Hash(") + std::to_wstring(entry.hashAlgorithm) + L")";
    std::wstring section = Utf8ToWide(entry.sectionName);
    if (section.empty()) {
        section = L".text?";
    }
    return algorithm + L" " + section + L" " + HexText(entry.contentHash);
}

// MemoryEvidenceStatusText maps the memory-evidence response status. Input is
// KSWORD_ARK_MEMORY_EVIDENCE_STATUS_*; output is used by summary rows.
std::wstring MemoryEvidenceStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK: return L"OK";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_QUERY_FAILED: return L"Query failed";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_INVALID_REQUEST: return L"Invalid request";
    case KSWORD_ARK_MEMORY_EVIDENCE_STATUS_IRQL_REJECTED: return L"IRQL rejected";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// MemoryEvidenceKindText maps row kinds from the unified evidence scan. Input
// is KSWORD_ARK_MEMORY_EVIDENCE_KIND_*; output separates exec ranges, bigpool,
// and sampled text-section memory.
std::wstring MemoryEvidenceKindText(const std::uint32_t kind) {
    switch (kind) {
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_UNKNOWN: return L"未知";
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE: return L"执行页";
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL: return L"BigPool";
    case KSWORD_ARK_MEMORY_EVIDENCE_KIND_TEXT_SECTION_MEMORY: return L"text hash";
    default: return std::wstring(L"未知(") + std::to_wstring(kind) + L")";
    }
}

// MemoryEvidencePermissionText expands evidence-specific permission bits. Input
// is a permission mask from R0; output names present/read/write/execute/NX flags.
std::wstring MemoryEvidencePermissionText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    std::wstring rwx;
    rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ) != 0U ? L'R' : L'-';
    rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) != 0U ? L'W' : L'-';
    rwx += (flags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0U ? L'X' : L'-';
    names.push_back(rwx);
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT, L"Present");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX, L"NX");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE, L"Large");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL, L"Global");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER, L"User");
    const std::uint32_t knownFlags =
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL |
        KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// MemoryEvidenceOwnerText maps evidence owner classes. Input is a row owner id;
// output follows the R0 loaded-module/nonmodule/bigpool/system-PTE/MDL buckets.
std::wstring MemoryEvidenceOwnerText(const std::uint32_t ownerKind) {
    switch (ownerKind) {
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE: return L"LoadedModule";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NONMODULE: return L"Non-module";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL: return L"BigPool";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE: return L"SystemPte";
    case KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE: return L"MdlLike";
    default: return std::wstring(L"Unknown(") + std::to_wstring(ownerKind) + L")";
    }
}

// MemoryEvidenceRiskText expands memory evidence risk bits. Input is a R0 risk
// mask; output highlights RWX, non-module executable, executable pool and owner
// missing conditions.
std::wstring MemoryEvidenceRiskText(const std::uint32_t flags) {
    if (flags == 0U) {
        return L"正常";
    }
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX, L"RWX");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE, L"非模块执行");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE, L"模块非text执行");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL, L"执行池");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE, L"大页执行");
    AppendFlagName(names, flags, KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING, L"Owner缺失");
    const std::uint32_t knownFlags =
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// DriverIntegrityStatusText maps aggregate integrity query statuses. Input is
// KSWORD_ARK_DRIVER_INTEGRITY_STATUS_*; output is used for DriverIntegrity and
// CPU/IDT integrity pages.
std::wstring DriverIntegrityStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK: return L"OK";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND: return L"Not found";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_BUFFER_TOO_SMALL: return L"Buffer too small";
    case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED: return L"Query failed";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// DriverIntegrityClassText names the evidence-class buckets used by the original
// KswordARK integrity Dock. Input is one evidenceClass id; output identifies
// DriverObject, LDR, CPU, IDT, MSR, and optional global rows.
std::wstring DriverIntegrityClassText(const std::uint32_t evidenceClass) {
    switch (evidenceClass) {
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return L"ModuleView";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return L"PsLoadedModuleList";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return L"DriverObject";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return L"DriverSection";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return L"MajorFunction";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return L"FastIo";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return L"DeviceChain";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return L"Service";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return L"CPU";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return L"Descriptor";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return L"MSR";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return L"IDT";
    case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return L"OptionalGlobal";
    default: return std::wstring(L"Class(") + std::to_wstring(evidenceClass) + L")";
    }
}

// DriverIntegritySourceText expands evidence source bits. Input is a R0 source
// mask; output names module lists, DriverObject, service registry, CPU, IDT/GDT,
// MSR, and DynData sources.
std::wstring DriverIntegritySourceText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, L"SystemModule");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB, L"AuxKlib");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES, L"PsLoadedModules");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT, L"DriverObject");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION, L"DriverSection");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY, L"ServiceRegistry");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER, L"CPU");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT, L"IDT");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT, L"GDT");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR, L"MSR");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA, L"DynData");
    const std::uint32_t knownFlags =
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR |
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// DriverIntegrityRiskText expands integrity risk bits. Input is a R0 risk mask;
// output surfaces owner mismatch, code outside image, service gaps, CPU control
// risks, descriptor issues, DynData gaps and truncation.
std::wstring DriverIntegrityRiskText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE, L"不可用");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED, L"查询失败");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED, L"模块未解析");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH, L"Owner不匹配");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE, L"外跳");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH, L"Section不匹配");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING, L"服务缺失");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD, L"Unload为空");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP, L"Device环");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP, L"Attached环");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH, L"跨驱动挂接");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER, L"空指针");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER, L"IDT外部Owner");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED, L"WP关闭");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED, L"NXE关闭");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED, L"SMEP关闭");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED, L"SMAP关闭");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID, L"描述符异常");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE, L"DynData缺失");
    AppendFlagName(names, flags, KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED, L"截断");
    const std::uint32_t knownFlags =
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE |
        KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNamesOrNormal(names);
}

// CrossViewStatusText maps process/thread cross-view aggregate statuses. Input
// is KSWORD_ARK_CROSSVIEW_STATUS_*; output states whether evidence is complete,
// partial, capability-limited, or failed.
std::wstring CrossViewStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_CROSSVIEW_STATUS_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_CROSSVIEW_STATUS_OK: return L"OK";
    case KSWORD_ARK_CROSSVIEW_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_CROSSVIEW_STATUS_CAPABILITY_MISSING: return L"Capability missing";
    case KSWORD_ARK_CROSSVIEW_STATUS_READ_FAILED: return L"Read failed";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// CrossViewSourceText expands source evidence bits. Input is a process/thread
// cross-view source mask; output names public walk, active list, CID table, and
// thread-list sources.
std::wstring CrossViewSourceText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK, L"public walk");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST, L"active list");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE, L"cid table");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST, L"thread list");
    const std::uint32_t knownFlags =
        KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK |
        KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST |
        KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE |
        KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// CrossViewAnomalyText expands DKOM anomaly bits. Input is a row anomaly mask;
// output names CID-only, active-only, hidden/missing, orphan, start-address, and
// dangling-object evidence.
std::wstring CrossViewAnomalyText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY, L"CID-only");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY, L"Active-only");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST, L"缺 ActiveList");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE, L"缺 CID");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN, L"孤儿线程");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST, L"线程进程缺失");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE, L"入口出模块");
    AppendFlagName(names, flags, KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT, L"悬空对象");
    const std::uint32_t knownFlags =
        KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY |
        KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY |
        KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST |
        KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE |
        KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN |
        KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST |
        KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE |
        KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNamesOrNormal(names);
}

// DynV4StatusText expands per-module/profile status bits. Input is the v4
// statusFlags mask; output distinguishes exact identity match, applied profile,
// required completeness, optional degradation, rejected identity, and validation
// failure without guessing profile state in R3.
std::wstring DynV4StatusText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED, L"Identity matched");
    AppendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED, L"Profile applied");
    AppendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE, L"Required complete");
    AppendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_OPTIONAL_DEGRADED, L"Optional degraded");
    AppendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED, L"Identity rejected");
    AppendFlagName(names, flags, KSW_DYN_V4_STATUS_FLAG_VALIDATION_FAILED, L"Validation failed");
    const std::uint32_t knownFlags =
        KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED |
        KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED |
        KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE |
        KSW_DYN_V4_STATUS_FLAG_OPTIONAL_DEGRADED |
        KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED |
        KSW_DYN_V4_STATUS_FLAG_VALIDATION_FAILED;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// DynV4ItemKindText maps v4 item kinds to schema names. Input is the protocol
// itemKind value; output mirrors docs/pdb_r0_audit_prep item type labels.
const wchar_t* DynV4ItemKindText(const std::uint32_t itemKind) {
    switch (itemKind) {
    case KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET: return L"StructOffset";
    case KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA: return L"GlobalRva";
    case KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA: return L"FunctionRva";
    case KSW_DYN_V4_ITEM_KIND_ENUM_VALUE: return L"EnumValue";
    case KSW_DYN_V4_ITEM_KIND_TYPE_SIZE: return L"TypeSize";
    case KSW_DYN_V4_ITEM_KIND_BIT_FIELD: return L"BitField";
    case KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL: return L"ListHeadGlobal";
    default: return L"Unknown";
    }
}

// DynV4MissingKindText names required/optional missing item buckets. Input is a
// protocol missing kind; output is display-only and never changes gating logic.
const wchar_t* DynV4MissingKindText(const std::uint32_t missingKind) {
    switch (missingKind) {
    case KSW_DYN_V4_MISSING_KIND_REQUIRED: return L"Required";
    case KSW_DYN_V4_MISSING_KIND_OPTIONAL: return L"Optional";
    default: return L"Unknown";
    }
}

// DynV4ItemFlagsText expands v4 item flags into profile semantics. Input is a
// KSW_DYN_V4_ITEM_FLAG_* mask; processing names required/optional bits and
// preserves unknown bits as hexadecimal; output is display-only text.
std::wstring DynV4ItemFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSW_DYN_V4_ITEM_FLAG_REQUIRED, L"Required");
    AppendFlagName(names, flags, KSW_DYN_V4_ITEM_FLAG_OPTIONAL, L"Optional");
    const std::uint32_t knownFlags =
        KSW_DYN_V4_ITEM_FLAG_REQUIRED |
        KSW_DYN_V4_ITEM_FLAG_OPTIONAL;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// DynV4ItemValueText formats the 64-bit value carried by one accepted v4 item.
// Input is the shared item packet; processing combines valueHigh/valueLow and
// keeps aux values visible; output is a compact table/detail string.
std::wstring DynV4ItemValueText(const KSW_DYN_V4_ITEM_PACKET& item) {
    const std::uint64_t value =
        (static_cast<std::uint64_t>(item.valueHigh) << 32U) |
        static_cast<std::uint64_t>(item.valueLow);
    std::wostringstream stream;
    stream << HexText(value)
           << L" aux0=" << HexText(item.aux0)
           << L" aux1=" << HexText(item.aux1)
           << L" aux2=" << HexText(item.aux2)
           << L" aux3=" << HexText(item.aux3);
    return stream.str();
}

// CidObjectKindText names CID table object kinds. Input is R0 expectedObjectKind;
// output is a compact label used by the CID table summary page.
const wchar_t* CidObjectKindText(const std::uint32_t kind) {
    switch (kind) {
    case KSWORD_ARK_CID_OBJECT_KIND_PROCESS: return L"Process";
    case KSWORD_ARK_CID_OBJECT_KIND_THREAD: return L"Thread";
    case KSWORD_ARK_CID_OBJECT_KIND_UNKNOWN:
    default: return L"Unknown";
    }
}

// CidEnumStatusText names aggregate CID table enumeration statuses. Input is the
// protocol status; output explains capability/PDB degradation without implying
// a malicious object when R0 only returned partial evidence.
const wchar_t* CidEnumStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_CID_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_CID_ENUM_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_CID_ENUM_STATUS_DYNDATA_MISSING: return L"DynData missing";
    case KSWORD_ARK_CID_ENUM_STATUS_PSPCID_UNAVAILABLE: return L"PspCidTable unavailable";
    case KSWORD_ARK_CID_ENUM_STATUS_TYPE_UNAVAILABLE: return L"Type unavailable";
    case KSWORD_ARK_CID_ENUM_STATUS_BUFFER_TRUNCATED: return L"Buffer truncated";
    case KSWORD_ARK_CID_ENUM_STATUS_BUDGET_EXHAUSTED: return L"Budget exhausted";
    case KSWORD_ARK_CID_ENUM_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// ObjectSummaryStatusText names the single-object metadata query status. Input
// is KSWORD_ARK_OBJECT_SUMMARY_STATUS_*; output is used in the CID summary page
// and does not alter object lifetime or reference counts.
const wchar_t* ObjectSummaryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_OK: return L"OK";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNSUPPORTED_TARGET: return L"Unsupported target";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_LOOKUP_FAILED: return L"Lookup failed";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_TYPE_QUERY_FAILED: return L"Type query failed";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_COUNTERS_UNAVAILABLE: return L"Counters unavailable";
    case KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// ObjectHeaderStatusText names ObjectHeader profile readiness. Input is
// KSWORD_ARK_OBJECT_HEADER_STATUS_*; output explains whether type/counter
// fields are trustworthy for read-only display.
const wchar_t* ObjectHeaderStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_OBJECT_HEADER_STATUS_PROFILE_MISSING: return L"Profile missing";
    case KSWORD_ARK_OBJECT_HEADER_STATUS_PARTIAL_PROFILE: return L"Partial profile";
    case KSWORD_ARK_OBJECT_HEADER_STATUS_AVAILABLE: return L"Available";
    case KSWORD_ARK_OBJECT_HEADER_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// CidEntryFlagsText expands CID row anomaly flags. Input is one entry flag mask;
// output highlights dangling/type-mismatch/reference state for read-only audit.
std::wstring CidEntryFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName(names, flags, KSWORD_ARK_CID_ENTRY_FLAG_DANGLING, L"Dangling");
    AppendFlagName(names, flags, KSWORD_ARK_CID_ENTRY_FLAG_TYPE_MISMATCH, L"Type mismatch");
    AppendFlagName(names, flags, KSWORD_ARK_CID_ENTRY_FLAG_REFERENCED, L"Referenced");
    const std::uint32_t knownFlags =
        KSWORD_ARK_CID_ENTRY_FLAG_DANGLING |
        KSWORD_ARK_CID_ENTRY_FLAG_TYPE_MISMATCH |
        KSWORD_ARK_CID_ENTRY_FLAG_REFERENCED;
    if ((flags & ~knownFlags) != 0U) {
        names.push_back(std::wstring(L"unknown=") + HexText(flags & ~knownFlags));
    }
    return JoinNames(names);
}

// IpcSummaryStatusText names R0 IPC summary states. Input is one protocol status
// value; output is a human-readable downgrade reason for IPC/ALPC/pipe rows.
const wchar_t* IpcSummaryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_IPC_SUMMARY_STATUS_OK: return L"OK";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_STUB: return L"LegacyStub(旧驱动占位)";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED: return L"Failed";
    case KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE:
    default: return L"Unavailable";
    }
}

// CpuFeatureText renders KSWORD_ARK_CPU_FEATURE_* bits as compact badges. Input
// is the R0 CPUID feature mask; output is suitable for the CPU hardware page and
// falls back to "None" when no stable feature bits were returned.
std::wstring CpuFeatureText(const std::uint64_t flags) {
    std::vector<std::wstring> names;
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE3, L"SSE3");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PCLMULQDQ, L"PCLMULQDQ");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_VMX, L"VMX");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSSE3, L"SSSE3");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_FMA, L"FMA");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE41, L"SSE4.1");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE42, L"SSE4.2");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AES, L"AES");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_XSAVE, L"XSAVE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_OSXSAVE, L"OSXSAVE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AVX, L"AVX");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_HYPERVISOR, L"Hypervisor");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MSR, L"MSR");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PAE, L"PAE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MCE, L"MCE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CX8, L"CX8");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_APIC, L"APIC");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SEP, L"SEP");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MTRR, L"MTRR");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PGE, L"PGE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MCA, L"MCA");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CMOV, L"CMOV");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PAT, L"PAT");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PSE36, L"PSE36");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CLFSH, L"CLFSH");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_MMX, L"MMX");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_FXSR, L"FXSR");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE, L"SSE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SSE2, L"SSE2");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_FSGSBASE, L"FSGSBASE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_BMI1, L"BMI1");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_HLE, L"HLE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AVX2, L"AVX2");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SMEP, L"SMEP");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_BMI2, L"BMI2");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_ERMS, L"ERMS");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_INVPCID, L"INVPCID");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RTM, L"RTM");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_AVX512F, L"AVX512F");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RDSEED, L"RDSEED");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_ADX, L"ADX");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_SMAP, L"SMAP");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CLFLUSHOPT, L"CLFLUSHOPT");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_CLWB, L"CLWB");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_UMIP, L"UMIP");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_PKU, L"PKU");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_OSPKE, L"OSPKE");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RDRAND, L"RDRAND");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_RDTSCP, L"RDTSCP");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_NX, L"NX");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_LM, L"LM");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_INVARIANT_TSC, L"InvariantTSC");
    AppendFlagName64(names, flags, KSWORD_ARK_CPU_FEATURE_LAHF_LM, L"LAHF_LM");
    return JoinNames(names);
}

// KeyboardEnumStatusText maps win32k keyboard enumeration statuses. Input is a
// KSWORD_ARK_KEYBOARD_ENUM_STATUS_* value; output is used by hotkey/hook pages.
std::wstring KeyboardEnumStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK: return L"OK";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND: return L"win32k not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND: return L"pattern not found";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE: return L"session unavailable";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED: return L"buffer truncated";
    case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED: return L"read failed";
    default: return std::wstring(L"Unknown(") + std::to_wstring(status) + L")";
    }
}

// KeyboardSourceText names hotkey/hook source chains. Input is a source id from
// R0; output identifies hotkey table, thread hook chain, or global hook chain.
std::wstring KeyboardSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE: return L"win32k hotkey table";
    case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_THREAD_HOOK_CHAIN: return L"thread hook chain";
    case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN: return L"global hook chain";
    default: return std::wstring(L"Unknown(") + std::to_wstring(source) + L")";
    }
}

// KeyboardHookScopeText maps hook scope values. Input is a hook scope id; output
// distinguishes thread/global hooks.
std::wstring KeyboardHookScopeText(const std::uint32_t scope) {
    switch (scope) {
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_UNKNOWN: return L"Unknown";
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD: return L"Thread";
    case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL: return L"Global";
    default: return std::wstring(L"Unknown(") + std::to_wstring(scope) + L")";
    }
}

// KeyboardHookTypeText maps WH_KEYBOARD and WH_KEYBOARD_LL constants. Input is
// a hook type id; output keeps unknown types visible by number.
std::wstring KeyboardHookTypeText(const std::uint32_t type) {
    switch (type) {
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD: return L"WH_KEYBOARD";
    case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL: return L"WH_KEYBOARD_LL";
    default: return std::wstring(L"Hook(") + std::to_wstring(type) + L")";
    }
}

// AppendCallbackRuntimeRows expands KSWORD_ARK_CALLBACK_RUNTIME_STATE into
// operator-friendly rows. Inputs are one state snapshot, an optional source
// label, and a UI filter; processing appends status/rule/registration rows;
// output is written to the common KernelOperationResult table.
void AppendCallbackRuntimeRows(
    KernelOperationResult& result,
    const KSWORD_ARK_CALLBACK_RUNTIME_STATE& state,
    const std::wstring& filter,
    const std::wstring& source) {
    PushFilteredRow(result, Row({
        { L"Source", source },
        { L"Section", L"Runtime" },
        { L"Size", std::to_wstring(state.size) },
        { L"Version", std::to_wstring(state.version) },
        { L"DriverOnline", BoolText(state.driverOnline != 0) },
        { L"GlobalEnabled", BoolText(state.globalEnabled != 0) },
        { L"RulesApplied", BoolText(state.rulesApplied != 0) },
        { L"Health", state.driverOnline != 0 && state.globalEnabled != 0 ? L"Active" : L"Disabled/Offline" },
    }, L"驱动回调运行态总览。"), filter);

    PushFilteredRow(result, Row({
        { L"Source", source },
        { L"Section", L"Callbacks" },
        { L"RegisteredMask", HexText(state.callbacksRegisteredMask) },
        { L"RegisteredText", CallbackRegisteredMaskText(state.callbacksRegisteredMask) },
    }, L"已注册的 R0 回调类型。"), filter);

    // AskUser 队列不是内核回调，但它和五类回调一样可以在降级启动中缺席，
    // 因此单独给出原始状态，避免"规则设了询问用户却没弹窗"被误判为软件缺陷。
    PushFilteredRow(result, Row({
        { L"Source", source },
        { L"Section", L"AskUserQueue" },
        { L"Available", BoolText(state.waitQueueStatus == 0) },
        { L"Status", HexText(static_cast<std::uint32_t>(state.waitQueueStatus)) },
    }, L"用户询问队列不可用时，Ask 规则回落到规则自身的默认决策。"), filter);

    const struct {
        const wchar_t* name;
        std::uint32_t bit;
        long registerStatus;
        bool hasRegisterStatus;
    } callbackTypes[] = {
        { L"Registry", 0x00000001UL, state.registryCallbackStatus, true },
        { L"Process", 0x00000002UL, state.processCallbackStatus, true },
        { L"Thread", 0x00000004UL, state.threadCallbackStatus, true },
        { L"Image", 0x00000008UL, state.imageCallbackStatus, true },
        { L"Object", 0x00000010UL, state.objectCallbackStatus, true },
        // Minifilter 的注册状态走独立的 minifilter 查询接口，不在本结构中。
        { L"Minifilter", 0x00000020UL, 0L, false },
    };
    for (const auto& callbackType : callbackTypes) {
        PushFilteredRow(result, Row({
            { L"Source", source },
            { L"Section", L"CallbackType" },
            { L"Name", callbackType.name },
            { L"Mask", HexText(callbackType.bit) },
            { L"Registered", BoolText((state.callbacksRegisteredMask & callbackType.bit) != 0U) },
            // 注册失败时这里是内核返回的原始 NTSTATUS，例如 altitude 冲突或槽位耗尽。
            { L"Status", callbackType.hasRegisterStatus
                ? HexText(static_cast<std::uint32_t>(callbackType.registerStatus))
                : std::wstring(L"-") },
        }), filter);
    }

    PushFilteredRow(result, Row({
        { L"Source", source },
        { L"Section", L"Rules" },
        { L"Groups", std::to_wstring(state.groupCount) },
        { L"Rules", std::to_wstring(state.ruleCount) },
        { L"RuleVersion", std::to_wstring(state.appliedRuleVersion) },
        { L"AppliedAt", Utc100nsToLocalText(state.appliedAtUtc100ns) },
        { L"AppliedAtRaw", HexText(state.appliedAtUtc100ns) },
    }, L"当前已应用的回调规则快照。"), filter);

    PushFilteredRow(result, Row({
        { L"Source", source },
        { L"Section", L"PendingDecision" },
        { L"Pending", std::to_wstring(state.pendingDecisionCount) },
        { L"WaitingReceivers", std::to_wstring(state.waitingReceiverCount) },
        { L"Attention", state.pendingDecisionCount != 0U ? L"有等待用户决策的回调事件" : L"无等待决策" },
    }, L"右键可取消全部等待决策。"), filter);
}

// MakeActionError returns a structured failure packet for invalid UI action
// parameters. Inputs are action request and reason; output is rendered by the
// normal kernel result table.
KernelOperationResult MakeActionError(const KernelActionRequest& request, const std::wstring& reason) {
    KernelOperationResult result;
    result.supported = true;
    result.success = false;
    result.destructiveAction = request.actionId != KernelActionId::None;
    result.message = reason;
    result.rows.push_back(Row({
        { L"功能", ToDisplayName(request.featureId) },
        { L"动作", std::to_wstring(static_cast<std::uint32_t>(request.actionId)) },
        { L"状态", L"参数无效" },
    }, reason));
    return result;
}

// ApplyIoSummary fills common result metadata from ArkDriverClient IoResult.
// Inputs are the original request, operation label, IoResult and result object;
// processing writes success/message and an overview row; no value is returned.
void ApplyIoSummary(
    const KernelRequest& request,
    const std::wstring& operation,
    const ksword::ark::IoResult& io,
    KernelOperationResult& result) {
    result.supported = true;
    result.success = io.ok;
    result.message = operation + (io.ok ? L" 查询完成。" : L" 查询失败。") + L" " + Utf8ToWide(io.message);
    result.rows.push_back(Row({
        { L"功能", ToDisplayName(request.featureId) },
        { L"操作", operation },
        { L"IO", io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(io.win32Error) },
        { L"Bytes", std::to_wstring(io.bytesReturned) },
    }, Utf8ToWide(io.message)));
}

// MakeUnsupportedResult reports impossible facade routes accurately. Inputs are
// a request and a concrete message; output is a diagnostic row rather than fake
// kernel data.
KernelOperationResult MakeUnsupportedResult(const KernelRequest& request, const std::wstring& message) {
    KernelOperationResult result;
    result.supported = false;
    result.success = false;
    result.message = message;
    result.rows.push_back(Row({
        { L"功能", ToDisplayName(request.featureId) },
        { L"数据源", L"KernelFacade" },
        { L"状态", L"Unsupported route" },
    }, message));
    return result;
}

// IsArkDriverBacked reports whether a retained feature has a real
// ArkDriverClient read-only query in this light project. Input is a feature id;
// output controls facade routing only.
bool IsArkDriverBacked(const KernelFeatureId id) {
    switch (id) {
    case KernelFeatureId::Ssdt:
    case KernelFeatureId::ShadowSsdt:
    case KernelFeatureId::InlineHook:
    case KernelFeatureId::IatEatHook:
    case KernelFeatureId::DynData:
    case KernelFeatureId::DriverStatus:
    case KernelFeatureId::CallbackIntercept:
    case KernelFeatureId::CallbackEnumeration:
    case KernelFeatureId::KernelExecutableMemory:
    case KernelFeatureId::KernelMemoryEvidence:
    case KernelFeatureId::ProcessCrossView:
    case KernelFeatureId::ThreadCrossView:
    case KernelFeatureId::DriverIntegrity:
    case KernelFeatureId::KernelCpuIntegrity:
    case KernelFeatureId::CpuHardwareSnapshot:
    case KernelFeatureId::PhysicalMemoryLayout:
    case KernelFeatureId::MutationAudit:
    case KernelFeatureId::KeyboardHotkeys:
    case KernelFeatureId::KeyboardHooks:
    case KernelFeatureId::DynDataCapabilities:
    case KernelFeatureId::PdbProfileStatus:
    case KernelFeatureId::CidTableSummary:
    case KernelFeatureId::IpcSummary:
    case KernelFeatureId::HookAuditSummary:
    case KernelFeatureId::MinifilterBypassPids:
    case KernelFeatureId::KernelTimerDpc:
    case KernelFeatureId::IoctlRegistry:
    case KernelFeatureId::WorkQueueThreads:
    case KernelFeatureId::SlatIommuAudit:
    case KernelFeatureId::HvmStatus:
    case KernelFeatureId::HvmEvents:
    case KernelFeatureId::DriverDispatchTable:
    case KernelFeatureId::DriverImageFields:
    case KernelFeatureId::DriverCommunication:
    case KernelFeatureId::PlatformAudit:
    case KernelFeatureId::SystemTimeState:
    case KernelFeatureId::I8042Audit:
    case KernelFeatureId::PiDdbCache:
    case KernelFeatureId::RawDiskSectors:
    case KernelFeatureId::NetworkTrafficPackets:
        return true;
    default:
        return false;
    }
}

// AppendDriverObjectQueryRows expands one ArkDriverClient DriverObject query
// into summary, MajorFunction, and DeviceObject rows. Inputs are the requested
// object name, parsed client response, and result sink; processing formats every
// protocol address as text only; no value is returned because rows are appended.
void AppendDriverObjectQueryRows(
    const std::wstring& requestedName,
    const ksword::ark::DriverObjectQueryResult& query,
    KernelOperationResult& result) {
    const std::wstring driverName = query.driverName.empty() ? requestedName : query.driverName;
    const bool queryOk = IsDriverObjectQuerySuccess(query);

    result.rows.push_back(Row({
        { L"Source", L"R0 DriverObject" },
        { L"Name", driverName },
        { L"Type", L"DriverObject" },
        { L"Path", driverName },
        { L"DriverName", driverName },
        { L"DriverObject", HexText(query.driverObjectAddress) },
        { L"DriverStart", HexText(query.driverStart) },
        { L"DriverSection", HexText(query.driverSection) },
        { L"DriverUnload", HexText(query.driverUnload) },
        { L"DriverSize", HexText(query.driverSize) },
        { L"DriverFlags", HexText(query.driverFlags) },
        { L"ServiceKey", query.serviceKeyName },
        { L"ImagePath", query.imagePath },
        { L"MajorFunctions", std::to_wstring(query.majorFunctionCount) },
        { L"Devices", std::to_wstring(query.returnedDeviceCount) + L"/" + std::to_wstring(query.totalDeviceCount) },
        { L"QueryStatus", std::wstring(DriverObjectQueryStatusText(query.queryStatus)) + L" (" + std::to_wstring(query.queryStatus) + L")" },
        { L"IO", query.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(query.io.win32Error) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
        { L"FieldFlags", HexText(query.fieldFlags) },
    }, queryOk ? query.imagePath : Utf8ToWide(query.io.message)));

    if (!queryOk) {
        return;
    }

    for (const ksword::ark::DriverMajorFunctionEntry& entry : query.majorFunctions) {
        result.rows.push_back(Row({
            { L"Source", L"R0 MajorFunction" },
            { L"Name", MajorFunctionName(entry.majorFunction) },
            { L"Type", L"MajorFunction" },
            { L"Path", driverName },
            { L"DriverName", driverName },
            { L"Major", std::to_wstring(entry.majorFunction) },
            { L"Dispatch", HexText(entry.dispatchAddress) },
            { L"Module", entry.moduleName },
            { L"ModuleBase", HexText(entry.moduleBase) },
            { L"Flags", HexText(entry.flags) },
        }, entry.moduleName));
    }

    for (const ksword::ark::DriverDeviceEntry& entry : query.devices) {
        result.rows.push_back(Row({
            { L"Source", L"R0 DeviceObject" },
            { L"Name", entry.deviceName.empty() ? HexText(entry.deviceObjectAddress) : entry.deviceName },
            { L"Type", entry.relationDepth == 0 ? L"DeviceObject" : L"AttachedDevice" },
            { L"Path", entry.deviceName },
            { L"DriverName", driverName },
            { L"DeviceName", entry.deviceName },
            { L"DeviceObject", HexText(entry.deviceObjectAddress) },
            { L"RootDeviceObject", HexText(entry.rootDeviceObjectAddress) },
            { L"AttachedDevice", HexText(entry.attachedDeviceObjectAddress) },
            { L"NextDevice", HexText(entry.nextDeviceObjectAddress) },
            { L"DeviceDriverObject", HexText(entry.driverObjectAddress) },
            { L"DeviceType", HexText(entry.deviceType) },
            { L"Flags", HexText(entry.flags) },
            { L"Characteristics", HexText(entry.characteristics) },
            { L"StackSize", std::to_wstring(entry.stackSize) },
            { L"Alignment", std::to_wstring(entry.alignmentRequirement) },
            { L"Depth", std::to_wstring(entry.relationDepth) },
            { L"NameStatus", HexText(static_cast<std::uint32_t>(entry.nameStatus)) },
        }, entry.deviceName));
    }
}

// QueryDeviceDriverObjectsHybrid preserves the native object-manager directory
// view and augments selected \Driver rows with ArkDriverClient DriverObject
// evidence. Input is the UI request; processing queries R3 first, then caps R0
// DriverObject queries to avoid blocking refresh; output is one combined table.
KernelOperationResult QueryDeviceDriverObjectsHybrid(const KernelRequest& request) {
    KernelOperationResult result = QueryNativeKernelFeature(request);
    std::vector<std::wstring> driverNames;
    driverNames.reserve(64);

    for (const KernelResultRow& row : result.rows) {
        AppendUniqueDriverObjectName(driverNames, DriverObjectNameFromRow(row));
    }
    AppendUniqueDriverObjectName(driverNames, NormalizeDriverObjectName(request.filterText, false));

    if (driverNames.empty()) {
        result.rows.push_back(Row({
            { L"Source", L"R0 DriverObject" },
            { L"Status", L"Skipped" },
            { L"Reason", L"未发现可用于 R0 DriverObject 查询的 \\Driver 条目" },
        }));
        return result;
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::DriverCapabilitiesQueryResult capability = client.queryDriverCapabilities();
    result.rows.push_back(Row({
        { L"Source", L"R0 DriverObject" },
        { L"R0", capability.io.ok ? L"Online" : L"Unavailable" },
        { L"Protocol", std::to_wstring(capability.driverProtocolVersion) },
        { L"Win32", std::to_wstring(capability.io.win32Error) },
        { L"Queued", std::to_wstring(driverNames.size()) },
    }, capability.io.ok ? Utf8ToWide(capability.lastErrorSummary) : Utf8ToWide(capability.io.message)));
    if (!capability.io.ok) {
        result.message += L" R0 DriverObject 查询跳过：";
        result.message += Utf8ToWide(capability.io.message);
        return result;
    }

    constexpr std::size_t kMaxDriverObjectQueries = 64;
    const std::size_t queryLimit = std::min<std::size_t>(driverNames.size(), kMaxDriverObjectQueries);
    std::size_t okCount = 0;
    std::size_t failCount = 0;
    for (std::size_t index = 0; index < queryLimit; ++index) {
        const ksword::ark::DriverObjectQueryResult query = client.queryDriverObject(
            driverNames[index],
            KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
            KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
            KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
        if (IsDriverObjectQuerySuccess(query)) {
            ++okCount;
        } else {
            ++failCount;
        }
        AppendDriverObjectQueryRows(driverNames[index], query, result);
    }
    if (driverNames.size() > queryLimit) {
        result.rows.push_back(Row({
            { L"Source", L"R0 DriverObject" },
            { L"Status", L"Truncated" },
            { L"Shown", std::to_wstring(queryLimit) },
            { L"Total", std::to_wstring(driverNames.size()) },
        }));
    }
    result.message += L" R0 DriverObject 查询完成：OK=" + std::to_wstring(okCount) + L"，Failed=" + std::to_wstring(failCount) + L"。";
    return result;
}

// AppendTruncationRow records when a driver result is intentionally capped for
// UI responsiveness. Inputs are the source total, emitted count and result sink;
// processing appends one diagnostic row only when data was truncated.
void AppendTruncationRow(const std::wstring& tableName, const std::size_t total, const std::size_t shown, KernelOperationResult& result) {
    if (total <= shown) {
        return;
    }
    result.rows.push_back(Row({
        { L"Table", tableName },
        { L"Shown", std::to_wstring(shown) },
        { L"Total", std::to_wstring(total) },
        { L"Status", L"Truncated for UI responsiveness" },
    }));
}

// AppendSsdtRows converts an SSDT result into generic rows. Inputs are table
// label, query result and destination; processing caps rows to keep the edit box
// responsive; no return value is needed.
void AppendSsdtRows(const wchar_t* tableName, const ksword::ark::SsdtEnumResult& query, const KernelRequest& request, KernelOperationResult& result) {
    const bool shadow = std::wstring(tableName).find(L"Shadow") != std::wstring::npos;
    result.rows.push_back(Row({
        { L"表", tableName },
        { L"Version", std::to_wstring(query.version) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"ServiceTable", HexText(query.serviceTableBase) },
        { L"ServiceCount", std::to_wstring(query.serviceCountFromTable) },
    }));

    const std::size_t limit = std::min<std::size_t>(query.entries.size(), 256);
    for (std::size_t i = 0; i < limit; ++i) {
        const ksword::ark::SsdtEntry& entry = query.entries[i];
        PushFilteredRow(result, Row({
            { L"索引", ((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U) ? std::to_wstring(entry.serviceIndex) : L"<未知>" },
            { L"Index", std::to_wstring(entry.serviceIndex) },
            { L"IndexResolved", ((entry.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U) ? L"1" : L"0" },
            { L"服务名", Utf8ToWide(entry.serviceName) },
            { L"ServiceName", Utf8ToWide(entry.serviceName) },
            { L"Name", Utf8ToWide(entry.serviceName) },
            { L"Stub地址", HexText(entry.zwRoutineAddress) },
            { L"Zw导出地址", HexText(entry.zwRoutineAddress) },
            { L"Zw", HexText(entry.zwRoutineAddress) },
            { L"服务例程", HexText(entry.serviceRoutineAddress) },
            { L"表项地址", HexText(entry.serviceRoutineAddress) },
            { L"ServiceAddress", HexText(entry.serviceRoutineAddress) },
            { L"Service", HexText(entry.serviceRoutineAddress) },
            { L"模块", Utf8ToWide(entry.moduleName) },
            { L"Module", Utf8ToWide(entry.moduleName) },
            { L"ServiceTable", HexText(query.serviceTableBase) },
            { L"ServiceTableBase", HexText(query.serviceTableBase) },
            { L"Flags", HexText(entry.flags) },
            { L"FlagsText", SsdtFlagsText(entry.flags) },
            { L"Status", SsdtStatusText(entry, shadow) },
            { L"Detail", std::wstring(tableName) + L"\r\n"
                L"Version: " + std::to_wstring(query.version) + L"\r\n"
                L"ServiceTableBase: " + HexText(query.serviceTableBase) + L"\r\n"
                L"ServiceCountFromTable: " + std::to_wstring(query.serviceCountFromTable) + L"\r\n"
                L"Flags: " + HexText(entry.flags) + L" (" + SsdtFlagsText(entry.flags) + L")" },
        }), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    AppendTruncationRow(tableName, query.entries.size(), limit, result);
}

// QuerySsdt calls the shared SSDT IOCTL through ArkDriverClient. Inputs are the
// UI request and whether the shadow table is requested; output contains rows.
KernelOperationResult QuerySsdt(const KernelRequest& request, const bool shadow) {
    const ksword::ark::DriverClient client;
    const ksword::ark::SsdtEnumResult query = shadow
        ? client.enumerateShadowSsdt(KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED)
        : client.enumerateSsdt(KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);

    KernelOperationResult result;
    ApplyIoSummary(request, shadow ? L"Shadow SSDT" : L"SSDT", query.io, result);
    AppendSsdtRows(shadow ? L"Shadow SSDT" : L"SSDT", query, request, result);
    return result;
}

// QueryInlineHooks calls IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS through the original
// client. Inputs are module filter fields from KernelRequest; output is generic
// rows for the light UI.
KernelOperationResult QueryInlineHooks(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    unsigned long flags = 0;
    if ((request.flags & KernelRequestFlagIncludeInternal) != 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL;
    }
    if ((request.flags & KernelRequestFlagIncludeClean) != 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN;
    }
    if (!request.moduleFilterText.empty()) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER;
    }
    const ksword::ark::KernelInlineHookScanResult query = client.scanInlineHooks(flags, KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, request.moduleFilterText);

    KernelOperationResult result;
    ApplyIoSummary(request, L"Inline Hook", query.io, result);
    result.rows.push_back(Row({
        { L"Status", std::wstring(KernelHookStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Modules", std::to_wstring(query.moduleCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));

    const std::unordered_map<std::uint64_t, KernelModuleDiskInfo> moduleMap = QueryLoadedKernelModuleMap();
    std::unordered_map<std::wstring, std::vector<std::uint8_t>> diskFileCache;
    const std::size_t limit = std::min<std::size_t>(query.entries.size(), 128);
    for (std::size_t i = 0; i < limit; ++i) {
        const ksword::ark::KernelInlineHookEntry& entry = query.entries[i];
        const InlineDiskBaseline disk = ReadInlineDiskBaseline(entry, moduleMap, diskFileCache);
        const std::wstring detailText = BuildInlineHookDetailText(entry, disk);
        PushFilteredRow(result, Row({
            { L"函数", Utf8ToWide(entry.functionName) },
            { L"Function", Utf8ToWide(entry.functionName) },
            { L"函数地址", HexText(entry.functionAddress) },
            { L"Address", HexText(entry.functionAddress) },
            { L"目标地址", HexText(entry.targetAddress) },
            { L"Target", HexText(entry.targetAddress) },
            { L"模块", entry.moduleName },
            { L"Module", entry.moduleName },
            { L"目标模块", entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName },
            { L"TargetModule", entry.targetModuleName },
            { L"状态", std::wstring(KernelHookStatusText(entry.status)) },
            { L"Status", std::wstring(KernelHookStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"类型", InlineHookTypeText(entry.hookType) },
            { L"Type", std::to_wstring(entry.hookType) },
            { L"TypeText", InlineHookTypeText(entry.hookType) },
            { L"Flags", HexText(entry.flags) },
            { L"ModuleBase", HexText(entry.moduleBase) },
            { L"TargetModuleBase", HexText(entry.targetModuleBase) },
            { L"内存字节", BytesHex(entry.currentBytes, entry.currentByteCount) },
            { L"CurrentBytes", BytesHex(entry.currentBytes, entry.currentBytes.size()) },
            { L"CurrentByteCount", std::to_wstring(entry.currentByteCount) },
            { L"磁盘字节", disk.available ? BytesHex(disk.bytes, disk.byteCount) : L"<未获取>" },
            { L"DiskBytes", disk.available ? BytesHex(disk.bytes, disk.byteCount) : L"<未获取>" },
            { L"差异状态", disk.statusText },
            { L"DiskDiff", disk.statusText },
            { L"DiskPath", disk.filePath },
            { L"DiskRva", HexText(disk.rva) },
            { L"ExpectedBytes", BytesHex(entry.expectedBytes, entry.expectedBytes.size()) },
            { L"OriginalByteCount", std::to_wstring(entry.originalByteCount) },
            { L"Detail", detailText },
        }, detailText), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    AppendTruncationRow(L"Inline Hook", query.entries.size(), limit, result);
    return result;
}

// QueryIatEatHooks calls IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS through the shared
// client. Inputs are filters from KernelRequest; output is generic rows.
KernelOperationResult QueryIatEatHooks(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    unsigned long flags = 0;
    if ((request.flags & KernelRequestFlagIncludeIat) != 0U || (request.flags & (KernelRequestFlagIncludeIat | KernelRequestFlagIncludeEat)) == 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS;
    }
    if ((request.flags & KernelRequestFlagIncludeEat) != 0U || (request.flags & (KernelRequestFlagIncludeIat | KernelRequestFlagIncludeEat)) == 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS;
    }
    if ((request.flags & KernelRequestFlagIncludeClean) != 0U) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN;
    }
    if (!request.moduleFilterText.empty()) {
        flags |= KSWORD_ARK_KERNEL_SCAN_FLAG_MODULE_FILTER;
    }
    const ksword::ark::KernelIatEatHookScanResult query = client.enumerateIatEatHooks(flags, KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, request.moduleFilterText);

    KernelOperationResult result;
    ApplyIoSummary(request, L"IAT/EAT Hook", query.io, result);
    result.rows.push_back(Row({
        { L"Status", std::wstring(KernelHookStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Modules", std::to_wstring(query.moduleCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));

    const std::size_t limit = std::min<std::size_t>(query.entries.size(), 128);
    for (std::size_t i = 0; i < limit; ++i) {
        const ksword::ark::KernelIatEatHookEntry& entry = query.entries[i];
        const std::wstring detailText = BuildIatEatHookDetailText(entry);
        PushFilteredRow(result, Row({
            { L"类别", IatEatClassText(entry.hookClass) },
            { L"Class", std::to_wstring(entry.hookClass) },
            { L"ClassText", IatEatClassText(entry.hookClass) },
            { L"模块", entry.moduleName },
            { L"Module", entry.moduleName },
            { L"导入模块", entry.importModuleName.empty() ? L"<不适用>" : entry.importModuleName },
            { L"Import", entry.importModuleName },
            { L"函数/序号", !entry.functionName.empty() ? Utf8ToWide(entry.functionName) : (std::wstring(L"#") + std::to_wstring(entry.ordinal)) },
            { L"FunctionOrdinal", !entry.functionName.empty() ? Utf8ToWide(entry.functionName) : (std::wstring(L"#") + std::to_wstring(entry.ordinal)) },
            { L"Function", Utf8ToWide(entry.functionName) },
            { L"Thunk/EAT项", HexText(entry.thunkAddress) },
            { L"Thunk", HexText(entry.thunkAddress) },
            { L"当前目标", HexText(entry.currentTarget) },
            { L"Current", HexText(entry.currentTarget) },
            { L"期望目标", HexText(entry.expectedTarget) },
            { L"Expected", HexText(entry.expectedTarget) },
            { L"目标模块", entry.targetModuleName.empty() ? L"<未解析>" : entry.targetModuleName },
            { L"TargetModule", entry.targetModuleName },
            { L"状态", std::wstring(KernelHookStatusText(entry.status)) },
            { L"Status", std::wstring(KernelHookStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Flags", HexText(entry.flags) },
            { L"Ordinal", std::to_wstring(entry.ordinal) },
            { L"ModuleBase", HexText(entry.moduleBase) },
            { L"TargetModuleBase", HexText(entry.targetModuleBase) },
            { L"Detail", detailText },
        }, detailText), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    AppendTruncationRow(L"IAT/EAT Hook", query.entries.size(), limit, result);
    return result;
}

// QueryDynData collects DynData status and field rows through ArkDriverClient.
// Input is the kernel request; output includes both status and field metadata.
KernelOperationResult QueryDynData(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::DynDataStatusResult status = client.queryDynDataStatus();

    KernelOperationResult result;
    ApplyIoSummary(request, L"DynData Status", status.io, result);
    result.rows.push_back(Row({
        { L"StatusFlags", HexText(status.statusFlags) },
        { L"StatusQueryOk", YesNoText(status.io.ok) },
        { L"SI Version", std::to_wstring(status.systemInformerDataVersion) },
        { L"SI Length", std::to_wstring(status.systemInformerDataLength) },
        { L"LastStatus", NtStatusText(status.lastStatus) },
        { L"MatchedClass", std::to_wstring(status.matchedProfileClass) },
        { L"MatchedProfileOffset", HexText(status.matchedProfileOffset) },
        { L"MatchedFieldsId", std::to_wstring(status.matchedFieldsId) },
        { L"FieldCount", std::to_wstring(status.fieldCount) },
        { L"CapabilityMask", HexText(status.capabilityMask) },
        { L"Ntos", status.ntoskrnl.moduleName },
        { L"NtosIdentity", ModuleIdentityText(status.ntoskrnl) },
        { L"Lxcore", status.lxcore.moduleName },
        { L"LxcoreIdentity", ModuleIdentityText(status.lxcore) },
        { L"UnavailableReason", status.unavailableReason },
    }, status.unavailableReason));

    // DynData R0 features are often limited until a matching local PDB profile
    // is applied. The local pack scan is intentionally done during the read-only
    // query as a diagnostic row; applying the match remains a separate explicit
    // right-click action so the Dock does not mutate R0 state while refreshing.
    const DynDataProfileMatch profileMatch = FindMatchingDynDataProfile(status.ntoskrnl);
    result.rows.push_back(Row({
        { L"Source", L"Local PDB Profile Summary" },
        { L"PdbProfileScanAttempted", YesNoText(profileMatch.scanned) },
        { L"PdbProfileFound", YesNoText(profileMatch.matched) },
        { L"PdbProfileApplied", L"否" },
        { L"PdbProfileSource", profileMatch.matched ? profileMatch.source : L"None" },
        { L"PdbProfileName", Utf8ToWide(profileMatch.profile.profileName) },
        { L"PdbProfilePath", profileMatch.path },
        { L"PdbProfileStatus", profileMatch.valid ? L"OK" : L"NotApplied" },
        { L"PdbProfileAppliedFields", L"0" },
        { L"PdbProfileRejectedFields", L"0" },
        { L"PdbProfileUnknownFields", L"0" },
        { L"PdbProfileIgnoredJsonFields", L"0" },
        { L"PdbProfileMessage", profileMatch.message },
        { L"PdbProfileIo", profileMatch.source == L"Runtime Exact PDB" ? L"DbgHelp exact PDB" : L"Local scan only" },
    }, profileMatch.message));
    AppendDynDataProfileRows(result, profileMatch, request.filterText);

    const ksword::ark::DynDataFieldsResult fields = client.queryDynDataFields();
    result.rows.push_back(Row({
        { L"DynData Fields IO", fields.io.ok ? L"OK" : L"FAIL" },
        { L"FieldsQueryOk", YesNoText(fields.io.ok) },
        { L"FieldsTotal", std::to_wstring(fields.totalCount) },
        { L"FieldsReturned", std::to_wstring(fields.returnedCount) },
    }, Utf8ToWide(fields.io.message)));
    result.success = result.success && fields.io.ok;

    const std::size_t limit = std::min<std::size_t>(fields.entries.size(), 256);
    for (std::size_t i = 0; i < limit; ++i) {
        const ksword::ark::DynDataFieldEntry& entry = fields.entries[i];
        result.rows.push_back(Row({
            { L"Field", Utf8ToWide(entry.fieldName) },
            { L"Id", std::to_wstring(entry.fieldId) },
            { L"Offset", HexText(entry.offset) },
            { L"Status", DynDataFieldStatusText(entry.flags, entry.offset) },
            { L"Source", Utf8ToWide(entry.sourceName) },
            { L"Feature", Utf8ToWide(entry.featureName) },
            { L"Mask", HexText(entry.capabilityMask) },
            { L"Flags", HexText(entry.flags) },
        }));
    }
    AppendTruncationRow(L"DynData Fields", fields.entries.size(), limit, result);
    return result;
}

// QueryDriverStatus calls the driver capability matrix IOCTL. Input is a kernel
// request; output contains the runtime protocol and feature dependency rows.
KernelOperationResult QueryDriverStatus(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::DriverCapabilitiesQueryResult query = client.queryDriverCapabilities();
    const ksword::ark::DynDataStatusResult dynStatus = client.queryDynDataStatus();
    const ksword::ark::DynDataFieldsResult dynFields = client.queryDynDataFields();
    const DynDataFieldsSummary fieldSummary = SummarizeDynDataFields(dynFields);
    const DynDataProfileMatch profileMatch = FindMatchingDynDataProfile(dynStatus.ntoskrnl);
    const std::uint32_t effectiveDynStatusFlags = dynStatus.io.ok ? dynStatus.statusFlags : query.dynDataStatusFlags;
    const std::uint64_t effectiveDynCapabilityMask = dynStatus.io.ok ? dynStatus.capabilityMask : query.dynDataCapabilityMask;
    const bool driverLoaded = (query.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_DRIVER_LOADED) != 0U;
    const bool protocolOk = (query.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_PROTOCOL_OK) != 0U;
    const bool dynMissing = (query.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_DYNDATA_MISSING) != 0U;
    const bool limited = (query.statusFlags & KSWORD_ARK_DRIVER_STATUS_FLAG_LIMITED) != 0U;
    const bool pdbActive = (effectiveDynStatusFlags & KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) != 0U;
    const bool callbackActive = (effectiveDynStatusFlags & KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE) != 0U;

    std::wstring badges = driverLoaded ? L"Driver Loaded" : L"Driver Missing";
    if (!protocolOk) { badges += L", Protocol Mismatch"; }
    if (dynMissing) { badges += L", DynData Missing"; }
    if (pdbActive) { badges += L", PDB Profile Active"; }
    if (callbackActive) { badges += L", Callback Profile Active"; }
    if (profileMatch.matched) { badges += L", Pack Matched"; }
    if (pdbActive) { badges += L", Trusted Offsets"; }
    if (fieldSummary.requiredMissing != 0U) { badges += L", Required Offsets Missing"; }
    if (limited) { badges += L", Limited"; }

    KernelOperationResult result;
    ApplyIoSummary(request, L"Driver Capabilities", query.io, result);
    result.success = result.success && dynStatus.io.ok && dynFields.io.ok;
    result.rows.push_back(Row({
        { L"Version", std::to_wstring(query.version) },
        { L"Protocol", std::to_wstring(query.driverProtocolVersion) },
        { L"ExpectedProtocol", HexText(KSWORD_ARK_DRIVER_PROTOCOL_VERSION) },
        { L"StatusFlags", HexText(query.statusFlags) },
        { L"StatusBadges", badges },
        { L"SecurityPolicy", HexText(query.securityPolicyFlags) },
        { L"DynDataStatus", HexText(effectiveDynStatusFlags) },
        { L"DynDataCapability", HexText(effectiveDynCapabilityMask) },
        { L"FeatureTotal", std::to_wstring(query.totalFeatureCount) },
        { L"FeatureReturned", std::to_wstring(query.returnedFeatureCount) },
        { L"LastError", Utf8ToWide(query.lastErrorSource) },
        { L"LastErrorSummary", Utf8ToWide(query.lastErrorSummary) },
        { L"LastErrorStatus", HexText(static_cast<std::uint32_t>(query.lastErrorStatus)) },
        { L"DynDataStatusQueryOk", BoolText(dynStatus.io.ok) },
        { L"DynDataFieldsQueryOk", BoolText(dynFields.io.ok) },
        { L"DynDataStatusIo", Utf8ToWide(dynStatus.io.message) },
        { L"DynDataFieldsIo", Utf8ToWide(dynFields.io.message) },
        { L"FieldCoverage", FieldCoverageText(fieldSummary, profileMatch.coveragePercent) },
        { L"FieldSources", FieldSourcesText(fieldSummary) },
        { L"RequiredMissing", std::to_wstring(fieldSummary.requiredMissing) },
        { L"NtosIdentity", ModuleIdentityText(dynStatus.ntoskrnl) },
        { L"LxcoreIdentity", ModuleIdentityText(dynStatus.lxcore) },
        { L"LocalPdbProfileMatched", YesNoText(profileMatch.matched) },
        { L"LocalPdbProfile", LocalPdbProfileText(profileMatch) },
        { L"LocalPdbProfileName", Utf8ToWide(profileMatch.profile.profileName) },
        { L"LocalPdbProfilePath", profileMatch.path },
        { L"LocalPdbMessage", profileMatch.message },
        { L"LocalPdbVersion", Utf8ToWide(profileMatch.profile.profileName) },
        { L"ActiveProcessLinksOffset", ActiveProcessLinksText(fieldSummary) },
        { L"CallbackProfileCoverage", std::to_wstring(profileMatch.callbackItemCount) + L" callback items" },
        { L"PdbProfileActive", YesNoText(pdbActive) },
        { L"CallbackProfileActive", YesNoText(callbackActive) },
        { L"TrustedPdbOffsetsActive", YesNoText(pdbActive) },
        { L"TrustedOffset", TrustedOffsetText(effectiveDynStatusFlags, profileMatch, fieldSummary) },
        { L"SI Version", std::to_wstring(dynStatus.systemInformerDataVersion) },
        { L"SI Length", std::to_wstring(dynStatus.systemInformerDataLength) },
        { L"MatchedClass", std::to_wstring(dynStatus.matchedProfileClass) },
        { L"MatchedProfileOffset", HexText(dynStatus.matchedProfileOffset) },
        { L"MatchedFieldsId", std::to_wstring(dynStatus.matchedFieldsId) },
        { L"UnavailableReason", dynStatus.unavailableReason },
    }, Utf8ToWide(query.lastErrorSummary)));

    const std::size_t limit = std::min<std::size_t>(query.entries.size(), 256);
    for (std::size_t i = 0; i < limit; ++i) {
        const ksword::ark::DriverFeatureCapabilityEntry& entry = query.entries[i];
        result.rows.push_back(Row({
            { L"Feature", Utf8ToWide(entry.featureName) },
            { L"Id", std::to_wstring(entry.featureId) },
            { L"State", Utf8ToWide(entry.stateName) },
            { L"Status", Utf8ToWide(entry.stateName) },
            { L"StateId", std::to_wstring(entry.state) },
            { L"Flags", HexText(entry.flags) },
            { L"Policy", HexText(entry.requiredPolicyFlags) },
            { L"RequiredPolicy", HexText(entry.requiredPolicyFlags) },
            { L"DeniedPolicy", HexText(entry.deniedPolicyFlags) },
            { L"RequiredDyn", HexText(entry.requiredDynDataMask) },
            { L"PresentDyn", HexText(entry.presentDynDataMask) },
            { L"Dependency", Utf8ToWide(entry.dependencyText) },
            { L"Fields", Utf8ToWide(entry.dependencyText) },
            { L"Reason", Utf8ToWide(entry.reasonText) },
        }, Utf8ToWide(entry.dependencyText + " " + entry.reasonText)));
    }
    AppendTruncationRow(L"Driver Capabilities", query.entries.size(), limit, result);
    return result;
}

// QueryCallbackRuntime calls the callback-runtime state IOCTL. Input is a kernel
// request; output is a readable runtime table rather than one opaque mask row.
KernelOperationResult QueryCallbackRuntime(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::CallbackRuntimeResult query = client.queryCallbackRuntimeState();

    KernelOperationResult result;
    ApplyIoSummary(request, L"Callback Runtime", query.io, result);
    AppendCallbackRuntimeRows(result, query.state, request.filterText, L"Query");
    const ksword::ark::MinifilterBypassPidResult bypass = client.queryMinifilterBypassPids();
    result.rows.push_back(Row({
        { L"Section", L"MinifilterBypass" },
        { L"Status", bypass.io.ok ? L"OK" : L"FAIL" },
        { L"PidCount", std::to_wstring(bypass.response.pidCount) },
        { L"Flags", HexText(bypass.response.flags) },
        { L"Win32", std::to_wstring(bypass.io.win32Error) },
    }, Utf8ToWide(bypass.io.message)));
    const std::uint32_t bypassCount = std::min<std::uint32_t>(bypass.response.pidCount, KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT);
    for (std::uint32_t index = 0; index < bypassCount; ++index) {
        PushFilteredRow(result, Row({
            { L"Section", L"BypassPid" },
            { L"Index", std::to_wstring(index) },
            { L"PID", std::to_wstring(bypass.response.processIds[index]) },
            { L"Process", ProcessDisplayName(bypass.response.processIds[index]) },
        }), request.filterText);
    }
    return result;
}

// QueryCallbackEnumeration calls callback enumeration through ArkDriverClient.
// Input is a kernel request; output is callback rows with module/name/details.
KernelOperationResult QueryCallbackEnumeration(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::CallbackEnumResult query = client.enumerateCallbacks(KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL);

    KernelOperationResult result;
    ApplyIoSummary(request, L"Callback Enumeration", query.io, result);
    result.rows.push_back(Row({
        { L"Version", std::to_wstring(query.version) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Flags", HexText(query.flags) },
        { L"ResponseFlags", HexText(query.flags) },
        { L"CallbackEnumResponseFlags", HexText(query.flags) },
        { L"CallbackEnumTruncated", (query.flags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED) != 0U ? L"1" : L"0" },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, std::wstring(L"Callback Enumeration response: returned=") + std::to_wstring(query.returnedCount) +
        L" total=" + std::to_wstring(query.totalCount) +
        L" flags=" + HexText(query.flags)));

    const std::size_t limit = std::min<std::size_t>(query.entries.size(), 256);
    for (std::size_t i = 0; i < limit; ++i) {
        const ksword::ark::CallbackEnumEntry& entry = query.entries[i];
        PushFilteredRow(result, Row({
            { L"类别", CallbackEnumClassText(entry.callbackClass) },
            { L"Class", std::to_wstring(entry.callbackClass) },
            { L"ClassText", CallbackEnumClassText(entry.callbackClass) },
            { L"名称", entry.name },
            { L"Name", entry.name },
            { L"Altitude", entry.altitude },
            { L"回调/对象地址", HexText(entry.callbackAddress) },
            { L"Callback", HexText(entry.callbackAddress) },
            { L"Context", HexText(entry.contextAddress) },
            { L"Registration", HexText(entry.registrationAddress) },
            { L"来源", CallbackEnumSourceText(entry.source) },
            { L"Source", std::to_wstring(entry.source) },
            { L"SourceText", CallbackEnumSourceText(entry.source) },
            { L"可信状态", CallbackEnumTrustBucket(entry) },
            { L"SourceTrust", CallbackEnumTrustBucket(entry) },
            { L"状态", std::wstring(CallbackEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Status", std::wstring(CallbackEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"OperationMask", HexText(entry.operationMask) },
            { L"ObjectTypeMask", HexText(entry.objectTypeMask) },
            { L"Generation", HexText(entry.generation) },
            { L"IdentityHash", HexText(entry.identityHash) },
            { L"RawStorageValue", HexText(entry.rawStorageValue) },
            { L"模块", entry.modulePath },
            { L"ModuleBase", HexText(entry.moduleBase) },
            { L"ModuleSize", HexText(entry.moduleSize) },
            { L"ModulePath", entry.modulePath },
            { L"FieldFlags", HexText(entry.fieldFlags) },
            { L"FieldText", CallbackEnumFieldFlagsText(entry.fieldFlags) },
            { L"Trust", HexText(entry.trustFlags) },
            { L"TrustText", CallbackEnumTrustFlagsText(entry.trustFlags) },
            { L"Remove", HexText(entry.removeBehavior) },
            { L"RemoveText", CallbackEnumRemoveBehaviorText(entry.removeBehavior) },
            { L"移除策略", CallbackEnumRemovePolicyText(entry) },
            { L"RemovePolicy", CallbackEnumRemovePolicyText(entry) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.modulePath.empty() ? entry.detail : entry.modulePath + L" | " + entry.detail), request.filterText.empty() ? request.moduleFilterText : request.filterText);
    }
    AppendTruncationRow(L"Callback Enumeration", query.entries.size(), limit, result);
    return result;
}

// QueryKernelExecutableMemory calls the ArkDriverClient executable-page scanner.
// Inputs are optional module/path filter text from the UI; output is a readable
// row set with page range, owner, permission and risk data.
KernelOperationResult QueryKernelExecutableMemory(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::KernelExecutableMemoryScanResult query = client.scanKernelExecutableMemory(
        KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL,
        4096UL,
        request.moduleFilterText);

    KernelOperationResult result;
    ApplyIoSummary(request, L"Kernel Executable Memory", query.io, result);
    result.rows.push_back(Row({
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(KernelExecStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Modules", std::to_wstring(query.moduleCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));

    for (const ksword::ark::KernelExecutableMemoryPageEntry& entry : query.entries) {
        const std::wstring ownerText = KernelExecOwnerText(entry.ownerKind);
        const std::wstring ownerDisplay = entry.owner.empty() ? ownerText : ownerText + L" " + entry.owner;
        result.rows.push_back(Row({
            { L"VA", HexText(entry.virtualAddress) },
            { L"RegionSize", HexText(entry.regionSize) },
            { L"Pages", std::to_wstring(entry.pageCount) },
            { L"PageSize", std::to_wstring(entry.pageSize) },
            { L"Perm", HexText(entry.permissionFlags) },
            { L"PermText", PagePermissionText(entry.permissionFlags) },
            { L"Risk", HexText(entry.riskFlags) },
            { L"RiskText", KernelExecRiskText(entry.riskFlags) },
            { L"OwnerKind", std::to_wstring(entry.ownerKind) },
            { L"OwnerKindText", ownerText },
            { L"OwnerDisplay", ownerDisplay },
            { L"Owner", entry.owner },
            { L"OwnerAddress", HexText(entry.ownerAddress) },
            { L"ModuleBase", HexText(entry.moduleBase) },
            { L"ModuleSize", HexText(entry.moduleSize) },
            { L"Module", entry.modulePath },
            { L"ModulePath", entry.modulePath },
            { L"Status", std::wstring(KernelExecStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

// QueryKernelMemoryEvidence calls the unified memory-evidence IOCTL. Inputs are
// optional filter text; output contains risk, owner, hash and sample summaries.
KernelOperationResult QueryKernelMemoryEvidence(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const bool includeNonModuleRange = (request.flags & KernelRequestFlagIncludeNonModuleExecutableRanges) != 0;
    if (includeNonModuleRange && (request.startAddress == 0 || request.endAddress <= request.startAddress)) {
        KernelOperationResult invalid;
        invalid.supported = true;
        invalid.success = false;
        invalid.message = L"非模块执行范围需要有效的起始/结束 VA。";
        invalid.rows.push_back(Row({
            { L"Status", L"Invalid request" },
            { L"Detail", invalid.message },
        }, invalid.message));
        return invalid;
    }

    unsigned long flags =
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
    if (includeNonModuleRange) {
        flags |= KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES;
    }
    unsigned long maxRows = request.maxRows == 0 ? KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS : request.maxRows;
    maxRows = std::max<unsigned long>(16UL, std::min<unsigned long>(maxRows, KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS));
    const ksword::ark::KernelMemoryEvidenceResult query = client.queryKernelMemoryEvidence(
        flags,
        maxRows,
        includeNonModuleRange ? request.startAddress : 0ULL,
        includeNonModuleRange ? request.endAddress : 0ULL,
        KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES,
        KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS,
        KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES);

    KernelOperationResult result;
    ApplyIoSummary(request, L"Kernel Memory Evidence", query.io, result);
    result.rows.push_back(Row({
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(MemoryEvidenceStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalRows) },
        { L"Returned", std::to_wstring(query.returnedRows) },
        { L"ResponseFlags", HexText(query.responseFlags) },
        { L"SourceFlags", HexText(query.sourceFlags) },
        { L"MaxRows", std::to_wstring(query.maxRows) },
        { L"MaxBytes", HexText(query.maxBytes) },
        { L"BytesScanned", HexText(query.bytesScanned) },
        { L"AddressFilter", includeNonModuleRange ? HexText(request.startAddress) + L"-" + HexText(request.endAddress) : L"" },
        { L"Modules", std::to_wstring(query.moduleCount) },
        { L"BigPoolRows", std::to_wstring(query.bigPoolRowsSeen) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));

    for (const ksword::ark::KernelMemoryEvidenceEntry& entry : query.entries) {
        const std::wstring ownerKind = MemoryEvidenceOwnerText(entry.ownerKind);
        const std::wstring ownerDisplay = entry.ownerName.empty() ? ownerKind : ownerKind + L" " + entry.ownerName;
        const std::wstring hashText = MemoryEvidenceHashText(entry);
        result.rows.push_back(Row({
            { L"Kind", std::to_wstring(entry.evidenceKind) },
            { L"KindText", MemoryEvidenceKindText(entry.evidenceKind) },
            { L"VA", HexText(entry.virtualAddress) },
            { L"RegionSize", HexText(entry.regionSize) },
            { L"SizeText", SizeText(entry.regionSize) },
            { L"PageSize", std::to_wstring(entry.pageSize) },
            { L"Perm", HexText(entry.permissionFlags) },
            { L"PermText", MemoryEvidencePermissionText(entry.permissionFlags) },
            { L"Risk", HexText(entry.riskFlags) },
            { L"RiskText", MemoryEvidenceRiskText(entry.riskFlags) },
            { L"OwnerKind", std::to_wstring(entry.ownerKind) },
            { L"OwnerKindText", ownerKind },
            { L"OwnerDisplay", ownerDisplay },
            { L"Owner", entry.ownerName },
            { L"OwnerAddress", HexText(entry.ownerAddress) },
            { L"ModuleBase", HexText(entry.moduleBase) },
            { L"ModuleSize", HexText(entry.moduleSize) },
            { L"ModuleSizeText", SizeText(entry.moduleSize) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"BigPoolTag", HexText(entry.bigPoolTag) },
            { L"BigPoolFlags", HexText(entry.bigPoolFlags) },
            { L"SectionRva", HexText(entry.sectionRva) },
            { L"SectionSize", HexText(entry.sectionSize) },
            { L"SectionSizeText", SizeText(entry.sectionSize) },
            { L"Section", Utf8ToWide(entry.sectionName) },
            { L"HashAlgorithm", std::to_wstring(entry.hashAlgorithm) },
            { L"SampleSize", std::to_wstring(entry.sampleSize) },
            { L"Hash", HexText(entry.contentHash) },
            { L"HashText", hashText },
            { L"Sample", BytesHex(entry.sample) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

// QueryProcessCrossView calls the R0 process DKOM cross-view query. Input is an
// optional text filter; output lists source/anomaly masks and object addresses.
KernelOperationResult QueryProcessCrossView(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const std::uint32_t pidFilter = ParseFirstPidFromText(request.filterText);
    const ksword::ark::ProcessCrossViewResult query = client.queryProcessCrossView(
        KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
        pidFilter,
        pidFilter);

    KernelOperationResult result;
    ApplyIoSummary(request, L"Process CrossView", query.io, result);
    result.rows.push_back(Row({
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(CrossViewStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"DynData", HexText(query.dynDataCapabilityMask) },
        { L"MissingDyn", HexText(query.missingCapabilityMask) },
        { L"PidFilter", pidFilter == 0 ? L"" : std::to_wstring(pidFilter) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));
    result.rows.push_back(Row({
        { L"OffsetSet", L"ProcessCrossView" },
        { L"EP.UniqueProcessId", HexText(query.fieldOffsets.epUniqueProcessId) },
        { L"EP.ActiveProcessLinks", HexText(query.fieldOffsets.epActiveProcessLinks) },
        { L"EP.ThreadListHead", HexText(query.fieldOffsets.epThreadListHead) },
        { L"EP.ImageFileName", HexText(query.fieldOffsets.epImageFileName) },
        { L"ET.Cid", HexText(query.fieldOffsets.etCid) },
        { L"ET.ThreadListEntry", HexText(query.fieldOffsets.etThreadListEntry) },
        { L"ET.StartAddress", HexText(query.fieldOffsets.etStartAddress) },
        { L"ET.Win32StartAddress", HexText(query.fieldOffsets.etWin32StartAddress) },
        { L"KT.Process", HexText(query.fieldOffsets.ktProcess) },
        { L"HT.TableCode", HexText(query.fieldOffsets.htTableCode) },
        { L"HTE.LowValue", HexText(query.fieldOffsets.hteLowValue) },
        { L"PspCidTableRva", HexText(query.fieldOffsets.pspCidTableRva) },
        { L"PspCidTable", HexText(query.fieldOffsets.pspCidTableAddress) },
    }, L"DynData offsets used by R0 cross-view enumeration."));

    for (const ksword::ark::ProcessCrossViewEntry& entry : query.entries) {
        result.rows.push_back(Row({
            { L"ID", std::to_wstring(entry.processId) },
            { L"对象", HexText(entry.objectAddress) },
            { L"进程", Utf8ToWide(entry.imageName) },
            { L"PublicWalk", SourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) },
            { L"Active/ThreadList", SourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) },
            { L"CID", SourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) },
            { L"异常", CrossViewAnomalyText(entry.anomalyFlags) },
            { L"置信度", std::to_wstring(entry.confidence) },
            { L"PID", std::to_wstring(entry.processId) },
            { L"PPID", std::to_wstring(entry.parentProcessId) },
            { L"Image", Utf8ToWide(entry.imageName) },
            { L"Object", HexText(entry.objectAddress) },
            { L"ProcessObject", HexText(entry.objectAddress) },
            { L"Start", HexText(entry.startAddress) },
            { L"StartAddress", HexText(entry.startAddress) },
            { L"SourceMask", HexText(entry.sourceMask) },
            { L"SourceText", CrossViewSourceText(entry.sourceMask) },
            { L"Anomaly", HexText(entry.anomalyFlags) },
            { L"AnomalyText", CrossViewAnomalyText(entry.anomalyFlags) },
            { L"DynData", HexText(entry.dynDataCapabilityMask) },
            { L"DynDataCapabilityMask", HexText(entry.dynDataCapabilityMask) },
            { L"EP.UniqueProcessId", HexText(entry.fieldOffsets.epUniqueProcessId) },
            { L"EP.ActiveProcessLinks", HexText(entry.fieldOffsets.epActiveProcessLinks) },
            { L"EP.ThreadListHead", HexText(entry.fieldOffsets.epThreadListHead) },
            { L"EP.ImageFileName", HexText(entry.fieldOffsets.epImageFileName) },
            { L"ET.Cid", HexText(entry.fieldOffsets.etCid) },
            { L"ET.ThreadListEntry", HexText(entry.fieldOffsets.etThreadListEntry) },
            { L"ET.StartAddress", HexText(entry.fieldOffsets.etStartAddress) },
            { L"ET.Win32StartAddress", HexText(entry.fieldOffsets.etWin32StartAddress) },
            { L"KT.Process", HexText(entry.fieldOffsets.ktProcess) },
            { L"HT.TableCode", HexText(entry.fieldOffsets.htTableCode) },
            { L"HTE.LowValue", HexText(entry.fieldOffsets.hteLowValue) },
            { L"PspCidTableRva", HexText(entry.fieldOffsets.pspCidTableRva) },
            { L"PspCidTable", HexText(entry.fieldOffsets.pspCidTableAddress) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, Utf8ToWide(entry.detail)));
    }
    return result;
}

// QueryThreadCrossView calls the R0 thread DKOM cross-view query. Input is an
// optional text filter; output lists ETHREAD/KTHREAD source/anomaly evidence.
KernelOperationResult QueryThreadCrossView(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const std::uint32_t pidFilter = ParseFirstPidFromText(request.filterText);
    const ksword::ark::ThreadCrossViewResult query = client.queryThreadCrossView(
        KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL,
        pidFilter);

    KernelOperationResult result;
    ApplyIoSummary(request, L"Thread CrossView", query.io, result);
    result.rows.push_back(Row({
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(CrossViewStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"DynData", HexText(query.dynDataCapabilityMask) },
        { L"MissingDyn", HexText(query.missingCapabilityMask) },
        { L"PidFilter", pidFilter == 0 ? L"" : std::to_wstring(pidFilter) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));
    result.rows.push_back(Row({
        { L"OffsetSet", L"ThreadCrossView" },
        { L"EP.UniqueProcessId", HexText(query.fieldOffsets.epUniqueProcessId) },
        { L"EP.ActiveProcessLinks", HexText(query.fieldOffsets.epActiveProcessLinks) },
        { L"EP.ThreadListHead", HexText(query.fieldOffsets.epThreadListHead) },
        { L"EP.ImageFileName", HexText(query.fieldOffsets.epImageFileName) },
        { L"ET.Cid", HexText(query.fieldOffsets.etCid) },
        { L"ET.ThreadListEntry", HexText(query.fieldOffsets.etThreadListEntry) },
        { L"ET.StartAddress", HexText(query.fieldOffsets.etStartAddress) },
        { L"ET.Win32StartAddress", HexText(query.fieldOffsets.etWin32StartAddress) },
        { L"KT.Process", HexText(query.fieldOffsets.ktProcess) },
        { L"HT.TableCode", HexText(query.fieldOffsets.htTableCode) },
        { L"HTE.LowValue", HexText(query.fieldOffsets.hteLowValue) },
        { L"PspCidTableRva", HexText(query.fieldOffsets.pspCidTableRva) },
        { L"PspCidTable", HexText(query.fieldOffsets.pspCidTableAddress) },
    }, L"DynData offsets used by R0 thread cross-view enumeration."));

    for (const ksword::ark::ThreadCrossViewEntry& entry : query.entries) {
        const std::wstring imageName = Utf8ToWide(entry.imageName);
        const std::wstring processText = std::to_wstring(entry.processId) + L" " + imageName;
        result.rows.push_back(Row({
            { L"ID", std::to_wstring(entry.threadId) },
            { L"对象", HexText(entry.objectAddress) },
            { L"进程", processText },
            { L"PublicWalk", SourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) },
            { L"Active/ThreadList", SourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) },
            { L"CID", SourceYesNo(entry.sourceMask, KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) },
            { L"异常", CrossViewAnomalyText(entry.anomalyFlags) },
            { L"置信度", std::to_wstring(entry.confidence) },
            { L"PID", std::to_wstring(entry.processId) },
            { L"TID", std::to_wstring(entry.threadId) },
            { L"Image", imageName },
            { L"ThreadObject", HexText(entry.objectAddress) },
            { L"ProcessObject", HexText(entry.processObjectAddress) },
            { L"Start", HexText(entry.startAddress) },
            { L"StartAddress", HexText(entry.startAddress) },
            { L"SourceMask", HexText(entry.sourceMask) },
            { L"SourceText", CrossViewSourceText(entry.sourceMask) },
            { L"Anomaly", HexText(entry.anomalyFlags) },
            { L"AnomalyText", CrossViewAnomalyText(entry.anomalyFlags) },
            { L"DynData", HexText(entry.dynDataCapabilityMask) },
            { L"DynDataCapabilityMask", HexText(entry.dynDataCapabilityMask) },
            { L"EP.UniqueProcessId", HexText(entry.fieldOffsets.epUniqueProcessId) },
            { L"EP.ActiveProcessLinks", HexText(entry.fieldOffsets.epActiveProcessLinks) },
            { L"EP.ThreadListHead", HexText(entry.fieldOffsets.epThreadListHead) },
            { L"EP.ImageFileName", HexText(entry.fieldOffsets.epImageFileName) },
            { L"ET.Cid", HexText(entry.fieldOffsets.etCid) },
            { L"ET.ThreadListEntry", HexText(entry.fieldOffsets.etThreadListEntry) },
            { L"ET.StartAddress", HexText(entry.fieldOffsets.etStartAddress) },
            { L"ET.Win32StartAddress", HexText(entry.fieldOffsets.etWin32StartAddress) },
            { L"KT.Process", HexText(entry.fieldOffsets.ktProcess) },
            { L"HT.TableCode", HexText(entry.fieldOffsets.htTableCode) },
            { L"HTE.LowValue", HexText(entry.fieldOffsets.hteLowValue) },
            { L"PspCidTableRva", HexText(entry.fieldOffsets.pspCidTableRva) },
            { L"PspCidTable", HexText(entry.fieldOffsets.pspCidTableAddress) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, Utf8ToWide(entry.detail)));
    }
    return result;
}

// AppendDriverIntegrityRows converts DriverIntegrityResult entries into generic
// rows. Inputs are the raw R0 query result and the UI operation result; processing
// appends every evidence row so KernelPage can perform local filtering without
// losing rows during edit-box changes; no value is returned.
void AppendDriverIntegrityRows(const ksword::ark::DriverIntegrityResult& query, KernelOperationResult& result) {
    result.rows.push_back(Row({
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(DriverIntegrityStatusText(query.queryStatus)) + L" (" + std::to_wstring(query.queryStatus) + L")" },
        { L"Flags", HexText(query.flags) },
        { L"SourceMask", HexText(query.sourceMask) },
        { L"SourceText", DriverIntegritySourceText(query.sourceMask) },
        { L"FieldFlags", HexText(query.fieldFlags) },
        { L"StatusFlags", HexText(query.statusFlags) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"CpuCount", std::to_wstring(query.cpuCount) },
        { L"ModuleCount", std::to_wstring(query.moduleCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));

    for (const ksword::ark::DriverIntegrityEvidenceEntry& entry : query.entries) {
        const std::wstring ownerDisplay = entry.ownerModule.empty()
            ? HexText(entry.ownerModuleBase)
            : entry.ownerModule + L" " + HexText(entry.ownerModuleBase);
        const std::wstring cpuVector = CpuVectorText(entry.processorGroup, entry.processorNumber, entry.vector);
        result.rows.push_back(Row({
            { L"类别", DriverIntegrityClassText(entry.evidenceClass) },
            { L"对象", HexText(entry.objectAddress) },
            { L"目标", HexText(entry.targetAddress) },
            { L"Owner", ownerDisplay },
            { L"CPU/Vector", cpuVector },
            { L"风险", DriverIntegrityRiskText(entry.riskFlags) },
            { L"置信度", std::to_wstring(entry.confidence) },
            { L"Class", std::to_wstring(entry.evidenceClass) },
            { L"ClassText", DriverIntegrityClassText(entry.evidenceClass) },
            { L"Risk", HexText(entry.riskFlags) },
            { L"RiskText", DriverIntegrityRiskText(entry.riskFlags) },
            { L"EntryStatus", std::to_wstring(entry.entryStatus) },
            { L"StatusFlags", HexText(entry.statusFlags) },
            { L"FieldMask", HexText(entry.fieldMask) },
            { L"RiskScore", std::to_wstring(entry.riskScore) },
            { L"RangeState", std::to_wstring(entry.rangeState) },
            { L"Ordinal", std::to_wstring(entry.ordinal) },
            { L"Source", HexText(entry.sourceMask) },
            { L"SourceText", DriverIntegritySourceText(entry.sourceMask) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"Group", std::to_wstring(entry.processorGroup) },
            { L"CPU", std::to_wstring(entry.processorNumber) },
            { L"Vector", std::to_wstring(entry.vector) },
            { L"CpuVector", cpuVector },
            { L"Object", HexText(entry.objectAddress) },
            { L"ObjectAddress", HexText(entry.objectAddress) },
            { L"Target", HexText(entry.targetAddress) },
            { L"TargetAddress", HexText(entry.targetAddress) },
            { L"OwnerBase", HexText(entry.ownerModuleBase) },
            { L"OwnerModuleBase", HexText(entry.ownerModuleBase) },
            { L"OwnerSize", HexText(entry.ownerModuleSize) },
            { L"OwnerModuleSize", HexText(entry.ownerModuleSize) },
            { L"OwnerModuleSizeText", SizeText(entry.ownerModuleSize) },
            { L"OwnerModule", entry.ownerModule },
            { L"DriverObject", HexText(entry.driverObjectAddress) },
            { L"DriverStart", HexText(entry.driverStart) },
            { L"DriverSize", SizeText(entry.driverSize) },
            { L"DriverSection", HexText(entry.driverSection) },
            { L"DriverUnload", HexText(entry.driverUnload) },
            { L"DeviceObject", HexText(entry.deviceObjectAddress) },
            { L"AttachedDevice", HexText(entry.attachedDeviceObjectAddress) },
            { L"KldrEntry", HexText(entry.kldrEntryAddress) },
            { L"KldrListHead", HexText(entry.kldrListHeadAddress) },
            { L"KldrDllBase", HexText(entry.kldrDllBase) },
            { L"KldrSize", SizeText(entry.kldrSizeOfImage) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
        }, entry.detail));
    }
}

KernelOperationResult QueryDriverIntegrity(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    std::uint64_t targetModuleBase = 0;
    const bool hasModuleBaseFilter = ParseFirstUnsigned64FromText(request.filterText, targetModuleBase);
    const unsigned long maxRows = request.maxRows == 0 ? KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS : request.maxRows;
    const ksword::ark::DriverIntegrityResult query = client.queryDriverIntegrity(
        request.moduleFilterText,
        hasModuleBaseFilter ? targetModuleBase : 0ULL,
        KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS,
        maxRows,
        KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Driver Integrity", query.io, result);
    if (hasModuleBaseFilter) {
        result.rows.push_back(Row({
            { L"DriverIntegrityFilter", L"ModuleBase" },
            { L"ModuleBase", HexText(targetModuleBase) },
            { L"DriverName", request.moduleFilterText },
        }, L"R0 queryDriverIntegrity received targetModuleBase from the generic filter box."));
    }
    AppendDriverIntegrityRows(query, result);
    return result;
}

KernelOperationResult QueryKernelCpuIntegrity(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxRows = request.maxRows == 0 ? KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS : request.maxRows;
    const unsigned long idtVectors = request.idtVectorLimit == 0 ? 0UL : request.idtVectorLimit;
    const unsigned long flags = idtVectors == 0
        ? KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU
        : (KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES);
    const ksword::ark::DriverIntegrityResult query = client.queryKernelCpuIntegrity(
        flags,
        maxRows,
        idtVectors);
    KernelOperationResult result;
    ApplyIoSummary(request, L"CPU/IDT Integrity", query.io, result);
    AppendDriverIntegrityRows(query, result);
    return result;
}

KernelOperationResult QueryCpuHardwareSnapshot(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::CpuHardwareSnapshotResult query = client.queryCpuHardwareSnapshot();
    KernelOperationResult result;
    ApplyIoSummary(request, L"CPU Hardware Snapshot", query.io, result);
    const std::wstring vendor = Utf8ToWide(query.vendor);
    const std::wstring brand = Utf8ToWide(query.brand);
    const std::wstring features = CpuFeatureText(query.featureMask);
    const std::wstring leaves = L"basic=" + HexText(query.maxBasicLeaf) + L" ext=" + HexText(query.maxExtendedLeaf);
    result.rows.push_back(Row({
        { L"项目", L"R0 CPUID" },
        { L"值", brand.empty() ? vendor : brand },
        { L"摘要", vendor + L" F" + std::to_wstring(query.family) + L"/M" + std::to_wstring(query.model) + L"/S" + std::to_wstring(query.stepping) },
        { L"状态", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"FieldFlags", HexText(query.fieldFlags) },
        { L"Vendor", vendor },
        { L"Brand", brand },
        { L"Logical", std::to_wstring(query.logicalProcessorCount) },
        { L"Active", std::to_wstring(query.activeProcessorCount) },
        { L"Package", std::to_wstring(query.packageCount) },
        { L"Family", std::to_wstring(query.family) },
        { L"Model", std::to_wstring(query.model) },
        { L"Stepping", std::to_wstring(query.stepping) },
        { L"ProcessorType", std::to_wstring(query.processorType) },
        { L"BrandIndex", std::to_wstring(query.brandIndex) },
        { L"CLFlushLine", std::to_wstring(query.clflushLineSize) },
        { L"InitialApicId", std::to_wstring(query.initialApicId) },
        { L"MaxBasicLeaf", HexText(query.maxBasicLeaf) },
        { L"MaxExtendedLeaf", HexText(query.maxExtendedLeaf) },
        { L"Leaves", leaves },
        { L"FeatureMask", HexText(query.featureMask) },
        { L"Features", features },
        { L"Leaf1ECX", HexText(query.leaf1Ecx) },
        { L"Leaf1EDX", HexText(query.leaf1Edx) },
        { L"Leaf7EBX", HexText(query.leaf7Ebx) },
        { L"Leaf7ECX", HexText(query.leaf7Ecx) },
        { L"Leaf7EDX", HexText(query.leaf7Edx) },
        { L"Leaf80000001ECX", HexText(query.leaf80000001Ecx) },
        { L"Leaf80000001EDX", HexText(query.leaf80000001Edx) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));
    return result;
}

// QueryKernelTimerDpc returns the immutable R0 TimerTable snapshot. The caller
// executes this facade query on KernelPage's worker and only applies the value
// result when its request generation is still current.
KernelOperationResult QueryKernelTimerDpc(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxEntries = request.maxRows == 0
        ? KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES
        : request.maxRows;
    const ksword::ark::KernelTimerDpcEnumResult query = client.enumerateKernelTimerDpc(maxEntries);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Kernel Timer/DPC", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"QueryStatus", HexText(query.queryStatus) },
        { L"StatusFlags", HexText(query.statusFlags) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"ProcessorCount", std::to_wstring(query.processorCount) },
        { L"BucketCount", std::to_wstring(query.bucketCount) },
        { L"BucketsVisited", std::to_wstring(query.bucketsVisited) },
        { L"CorruptBuckets", std::to_wstring(query.corruptBucketCount) },
        { L"ReadFailures", std::to_wstring(query.readFailureCount) },
        { L"Duplicates", std::to_wstring(query.duplicateCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"KTIMER/KDPC snapshot uses the driver's bounded per-bucket traversal. Partial or corrupt diagnostics remain visible in the query summary."));

    for (const ksword::ark::KernelTimerDpcEntry& entry : query.entries) {
        const std::wstring cpu = std::to_wstring(entry.processorGroup) + L":" + std::to_wstring(entry.processorNumber);
        std::wostringstream detail;
        detail << L"CPU: " << cpu << L"\r\n"
               << L"Bucket: " << entry.bucketIndex << L"\r\n"
               << L"Timer: " << HexText(entry.timerAddress) << L"\r\n"
               << L"DueTime: " << entry.dueTime << L"\r\n"
               << L"Period: " << entry.period << L"\r\n"
               << L"TimerType: " << entry.timerType << L"\r\n"
               << L"DPC: " << HexText(entry.dpcAddress) << L"\r\n"
               << L"DeferredRoutine: " << HexText(entry.deferredRoutine) << L"\r\n"
               << L"DeferredContext: " << HexText(entry.deferredContext) << L"\r\n"
               << L"Flags: " << HexText(entry.flags);
        result.rows.push_back(Row({
            { L"CPU", cpu },
            { L"Processor", cpu },
            { L"Bucket", std::to_wstring(entry.bucketIndex) },
            { L"BucketIndex", std::to_wstring(entry.bucketIndex) },
            { L"Timer", HexText(entry.timerAddress) },
            { L"TimerAddress", HexText(entry.timerAddress) },
            { L"DueTime", std::to_wstring(entry.dueTime) },
            { L"Period", std::to_wstring(entry.period) },
            { L"类型", std::to_wstring(entry.timerType) },
            { L"TimerType", std::to_wstring(entry.timerType) },
            { L"DPC", HexText(entry.dpcAddress) },
            { L"Dpc", HexText(entry.dpcAddress) },
            { L"DpcAddress", HexText(entry.dpcAddress) },
            { L"例程", HexText(entry.deferredRoutine) },
            { L"DeferredRoutine", HexText(entry.deferredRoutine) },
            { L"上下文", HexText(entry.deferredContext) },
            { L"DeferredContext", HexText(entry.deferredContext) },
            { L"标志", HexText(entry.flags) },
            { L"Flags", HexText(entry.flags) },
            { L"状态", L"Captured" },
            { L"Status", L"Captured" },
        }, detail.str()));
    }
    return result;
}

// FixedWideField copies a fixed-size wide array out of a protocol row. The
// driver pads these to their full length, so a plain wstring(ptr) would read
// past the terminator when the field happens to be full.
std::wstring FixedWideField(const wchar_t* field, const std::size_t capacity) {
    if (field == nullptr || capacity == 0) {
        return {};
    }
    std::size_t length = 0;
    while (length < capacity && field[length] != L'\0') {
        ++length;
    }
    return std::wstring(field, length);
}

// FixedAnsiField is the same for the ANSI vendor strings the CPUID paths return.
std::wstring FixedAnsiField(const char* field, const std::size_t capacity) {
    if (field == nullptr || capacity == 0) {
        return {};
    }
    std::size_t length = 0;
    while (length < capacity && field[length] != '\0') {
        ++length;
    }
    std::wstring wide;
    wide.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
        wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(field[index])));
    }
    return wide;
}

// AppendZeroResponseWarning flags a response the driver never actually filled.
// These IOCTL handlers zero the output buffer before calling their worker and
// still report the full length, so a worker that bails out early leaves a
// response whose queryStatus reads as STATUS_SUCCESS. version/size are set by
// the worker itself, so both being zero is the reliable "nothing ran" signal.
void AppendZeroResponseWarning(
    const std::uint32_t version,
    const std::uint32_t size,
    std::vector<KernelResultRow>& rows) {
    if (version != 0 || size != 0) {
        return;
    }
    rows.push_back(Row({
        { L"Warning", L"R0 返回了全零响应" },
        { L"Meaning", L"驱动侧 worker 未写入任何字段，其中的 0 状态不代表成功" },
    }, L"IOCTL handler zeroes the output buffer before invoking its worker and still reports the full "
       L"response length. version/size are written by the worker, so both being zero means the worker "
       L"never ran and no field in this response should be trusted."));
}

// QueryWorkQueueThreads enumerates ExWorkerQueue work items and their hosting
// threads. A work item whose routine sits outside any loaded module is the
// interesting case, so the module columns stay visible even when empty.
KernelOperationResult QueryWorkQueueThreads(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxEntries = request.maxRows == 0
        ? KSWORD_ARK_WORK_QUEUE_DEFAULT_MAX_ENTRIES
        : request.maxRows;
    const ksword::ark::WorkQueueEnumResult query =
        client.enumerateWorkQueues(KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_ALL, maxEntries);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Kernel WorkQueue", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"QueryStatus", HexText(query.queryStatus) },
        { L"StatusFlags", HexText(query.statusFlags) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Nodes", std::to_wstring(query.nodeCount) },
        { L"QueuesVisited", std::to_wstring(query.queuesVisited) },
        { L"CorruptLists", std::to_wstring(query.corruptListCount) },
        { L"ReadFailures", std::to_wstring(query.readFailureCount) },
        { L"ReferenceFailures", std::to_wstring(query.referenceFailureCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"ExWorkerQueue traversal is bounded per queue by the driver. Corrupt-list and read-failure "
       L"counts stay visible so a partial walk is never mistaken for an empty one."));

    for (const ksword::ark::WorkQueueEntry& entry : query.entries) {
        const std::wstring moduleName = Utf8ToWide(entry.moduleName);
        const std::wstring modulePath = Utf8ToWide(entry.modulePath);
        std::wostringstream detail;
        detail << L"RowKind: " << entry.rowKind << L"\r\n"
               << L"QueueType: " << entry.queueType << L"\r\n"
               << L"Priority: " << entry.priorityIndex << L"\r\n"
               << L"Node: " << entry.nodeIndex << L"\r\n"
               << L"Queue: " << HexText(entry.queueAddress) << L"\r\n"
               << L"WorkItem: " << HexText(entry.workItemAddress) << L"\r\n"
               << L"Routine: " << HexText(entry.routineAddress) << L"\r\n"
               << L"Parameter: " << HexText(entry.parameterAddress) << L"\r\n"
               << L"Thread: " << HexText(entry.threadObject) << L" (TID " << entry.threadId << L")\r\n"
               << L"ModuleBase: " << HexText(entry.moduleBase) << L"\r\n"
               << L"ModuleSize: " << HexText(entry.moduleSize) << L"\r\n"
               << L"ModulePath: " << modulePath << L"\r\n"
               << L"Flags: " << HexText(entry.flags) << L"\r\n"
               << L"Status: " << HexText(entry.status);
        result.rows.push_back(Row({
            { L"QueueType", std::to_wstring(entry.queueType) },
            { L"Priority", std::to_wstring(entry.priorityIndex) },
            { L"Node", std::to_wstring(entry.nodeIndex) },
            { L"Queue", HexText(entry.queueAddress) },
            { L"WorkItem", HexText(entry.workItemAddress) },
            { L"Routine", HexText(entry.routineAddress) },
            { L"Module", moduleName.empty() ? L"(未归属模块)" : moduleName },
            { L"ThreadId", entry.threadId != 0 ? std::to_wstring(entry.threadId) : L"-" },
            { L"Thread", HexText(entry.threadObject) },
            { L"Flags", HexText(entry.flags) },
        }, detail.str()));
    }
    return result;
}

// QuerySlatIommuAudit reads the EPT/NPT cross-view probes plus DMAR/IVRS
// firmware evidence. A clean guest-visible result cannot prove an opaque outer
// SLAT is clean, which is why the probe mismatch counters are surfaced as their
// own row rather than folded into a verdict.
KernelOperationResult QuerySlatIommuAudit(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const bool includeMmio = (request.flags & KernelRequestFlagIncludeInternal) != 0;
    const ksword::ark::SlatIommuAuditResult query = client.querySlatIommuAudit(includeMmio);
    KernelOperationResult result;
    ApplyIoSummary(request, L"SLAT/IOMMU Audit", query.io, result);
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response = query.response;
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"QueryStatus", HexText(static_cast<std::uint32_t>(response.queryStatus)) },
        { L"RiskFlags", HexText(response.riskFlags) },
        { L"FieldFlags", HexText(response.fieldFlags) },
        { L"CpuVendor", FixedAnsiField(response.cpuVendor, KSWORD_ARK_SLAT_IOMMU_VENDOR_CHARS) },
        { L"HypervisorVendor", FixedAnsiField(response.hypervisorVendor, KSWORD_ARK_SLAT_IOMMU_VENDOR_CHARS) },
        { L"Probes", std::to_wstring(response.probeCount) },
        { L"Mismatches", std::to_wstring(response.mismatchCount) },
        { L"Unstable", std::to_wstring(response.unstableCount) },
        { L"IommuRows", std::to_wstring(response.iommuRowCount) },
        { L"ReservedMemory", std::to_wstring(response.reservedMemoryCount) },
        { L"MalformedRows", std::to_wstring(response.malformedRowCount) },
        { L"DmarStatus", HexText(static_cast<std::uint32_t>(response.dmarStatus)) },
        { L"IvrsStatus", HexText(static_cast<std::uint32_t>(response.ivrsStatus)) },
        { L"IommuInterface", HexText(static_cast<std::uint32_t>(response.iommuInterfaceStatus)) },
        { L"VmxFeatureControl", HexText(response.vmxFeatureControl) },
        { L"VmxEptVpidCaps", HexText(response.vmxEptVpidCapabilities) },
        { L"AmdVmCr", HexText(response.amdVmCr) },
        { L"CpuidCycles", std::to_wstring(response.cpuidCyclesMinimum) + L"/" +
            std::to_wstring(response.cpuidCyclesMedian) + L"/" + std::to_wstring(response.cpuidCyclesMaximum) },
    }, L"Probe mismatches and CPUID timing spread are reported as raw counts. A guest-visible view that "
       L"looks clean cannot prove an outer SLAT is clean, so no verdict is derived here. "
       L"DMAR/IVRS use STATUS_NOT_FOUND when the firmware table is simply absent."));
    AppendZeroResponseWarning(response.version, response.size, result.rows);
    return result;
}

// QueryHvmStatus reads virtualization capability and takeover state. It never
// prepares, tests or tears down anything -- those are control actions.
KernelOperationResult QueryHvmStatus(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::HvmStatusResult query = client.queryHvmStatus();
    KernelOperationResult result;
    ApplyIoSummary(request, L"HVM Status", query.io, result);
    const KSWORD_ARK_QUERY_HVM_RESPONSE& response = query.response;
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"QueryStatus", HexText(response.queryStatus) },
        { L"StateFlags", HexText(response.stateFlags) },
        { L"Generation", std::to_wstring(response.generation) },
        { L"Processors", std::to_wstring(response.processorCount) },
        { L"Prepared", std::to_wstring(response.preparedProcessorCount) },
        { L"SelfTestPassed", std::to_wstring(response.selfTestPassedProcessorCount) },
        { L"Resident", std::to_wstring(response.residentProcessorCount) },
        { L"ResidentImpl", std::to_wstring(response.residentImplementation) },
        { L"EptImpl", std::to_wstring(response.eptImplementation) },
        { L"NestedImpl", std::to_wstring(response.nestedImplementation) },
        { L"EvmcsImpl", std::to_wstring(response.evmcsImplementation) },
        { L"EptRules", std::to_wstring(response.eptRuleCount) },
        { L"EptPages", std::to_wstring(response.eptPageCount) },
        { L"Events", std::to_wstring(response.eventCount) },
        { L"DroppedEvents", std::to_wstring(response.droppedEventCount) },
        { L"NestedState", std::to_wstring(response.nestedState) },
        { L"EvmcsState", std::to_wstring(response.evmcsState) },
        { L"FeatureFlags", HexText(response.featureFlags) },
        { L"VmxBasic", HexText(response.vmxBasic) },
    }, L"Read-only virtualization state. preparedProcessorCount below processorCount means the takeover "
       L"is partial, which matters because a per-CPU view can differ from the machine-wide one."));
    AppendZeroResponseWarning(response.version, response.size, result.rows);
    return result;
}

// QueryHvmEvents drains the VM-exit event ring without clearing it. Clearing is
// deliberately not offered here: another reader would silently lose events.
KernelOperationResult QueryHvmEvents(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxRows = request.maxRows == 0
        ? KSWORD_ARK_HVM_MAX_EVENT_ROWS
        : request.maxRows;
    const ksword::ark::HvmEventResult query = client.queryHvmEvents(0, maxRows, false);
    KernelOperationResult result;
    ApplyIoSummary(request, L"HVM Events", query.io, result);
    const KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE& response = query.response;
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"Returned", std::to_wstring(response.returnedRows) },
        { L"Available", std::to_wstring(response.availableRows) },
        { L"Dropped", std::to_wstring(response.droppedRows) },
        { L"NewestSequence", std::to_wstring(response.newestSequence) },
    }, L"Nonblocking snapshot of the VM-exit ring, read without clearing it so a second reader does not "
       L"lose events. droppedRows counts entries overwritten before this read."));
    AppendZeroResponseWarning(response.version, response.size, result.rows);

    const unsigned long rowCount = response.returnedRows < KSWORD_ARK_HVM_MAX_EVENT_ROWS
        ? response.returnedRows
        : KSWORD_ARK_HVM_MAX_EVENT_ROWS;
    for (unsigned long index = 0; index < rowCount; ++index) {
        const KSWORD_ARK_HVM_EVENT_ROW& row = response.rows[index];
        std::wostringstream rowDetail;
        rowDetail << L"Sequence: " << row.sequence << L"\r\n"
                  << L"Timestamp: " << row.timestamp << L"\r\n"
                  << L"CPU: " << row.processorGroup << L":" << static_cast<unsigned>(row.processorNumber) << L"\r\n"
                  << L"Type: " << row.type << L"\r\n"
                  << L"ExitReason: " << HexText(row.exitReason) << L"\r\n"
                  << L"Qualification: " << HexText(row.qualification) << L"\r\n"
                  << L"GuestRip: " << HexText(row.guestRip) << L"\r\n"
                  << L"GuestPhysical: " << HexText(row.guestPhysicalAddress) << L"\r\n"
                  << L"GuestLinear: " << HexText(row.guestLinearAddress) << L"\r\n"
                  << L"Access: " << HexText(row.access) << L"\r\n"
                  << L"RuleId: " << row.ruleId << L"\r\n"
                  << L"Status: " << HexText(static_cast<std::uint32_t>(row.status));
        result.rows.push_back(Row({
            { L"Sequence", std::to_wstring(row.sequence) },
            { L"CPU", std::to_wstring(row.processorGroup) + L":" + std::to_wstring(static_cast<unsigned>(row.processorNumber)) },
            { L"Type", std::to_wstring(row.type) },
            { L"ExitReason", HexText(row.exitReason) },
            { L"Qualification", HexText(row.qualification) },
            { L"GuestRip", HexText(row.guestRip) },
            { L"GuestPhysical", HexText(row.guestPhysicalAddress) },
            { L"Access", HexText(row.access) },
            { L"RuleId", std::to_wstring(row.ruleId) },
        }, rowDetail.str()));
    }
    return result;
}

// BuildDriverTargetIdentity reads the target driver out of the shared filter
// box. These three queries address one driver rather than enumerating, because
// the underlying protocol is per-DriverObject.
struct DriverTargetIdentity {
    std::uint64_t moduleBase = 0;
    std::wstring driverName;
    bool valid = false;
};

DriverTargetIdentity BuildDriverTargetIdentity(const KernelRequest& request) {
    DriverTargetIdentity identity;
    identity.driverName = request.filterText;
    identity.moduleBase = request.startAddress;
    identity.valid = !identity.driverName.empty() || identity.moduleBase != 0;
    return identity;
}

KernelOperationResult MakeDriverTargetPrompt(const KernelRequest& request, const wchar_t* label) {
    KernelOperationResult result;
    result.supported = true;
    result.success = false;
    result.message = std::wstring(label) + L"：请先在过滤框输入驱动名（例如 disk.sys），或在起点地址填入模块基址。";
    result.rows.push_back(Row({
        { L"Hint", L"需要指定目标驱动" },
        { L"Filter", L"驱动名，例如 disk.sys" },
        { L"StartAddress", L"可选，模块基址" },
    }, L"This protocol addresses one DriverObject at a time rather than enumerating every driver, so a "
       L"target has to be named before the query can run."));
    static_cast<void>(request);
    return result;
}

// QueryDriverDispatchTable reads one driver's MajorFunction slot against the
// baseline the driver recorded. Read-only: no slot is written here.
KernelOperationResult QueryDriverDispatchTable(const KernelRequest& request) {
    const DriverTargetIdentity identity = BuildDriverTargetIdentity(request);
    if (!identity.valid) {
        return MakeDriverTargetPrompt(request, L"驱动派遣表");
    }
    const ksword::ark::DriverClient client;
    const unsigned long majorFunction = request.idtVectorLimit;
    const ksword::ark::DriverDispatchControlResult query =
        client.queryDriverDispatch(identity.moduleBase, identity.driverName, majorFunction);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Driver Dispatch", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Driver", identity.driverName.empty() ? HexText(identity.moduleBase) : identity.driverName },
        { L"MajorFunction", HexText(query.majorFunction) },
        { L"State", std::to_wstring(query.state) },
        { L"Generation", std::to_wstring(query.generation) },
        { L"ModuleBase", HexText(query.targetModuleBase) },
        { L"DriverObject", HexText(query.driverObjectAddress) },
        { L"Current", HexText(query.currentDispatchAddress) },
        { L"Original", HexText(query.originalDispatchAddress) },
        { L"Applied", HexText(query.appliedDispatchAddress) },
        { L"ResponseFlags", HexText(query.responseFlags) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"Current versus original dispatch address for one MajorFunction slot. Use the row limit box to "
       L"choose the major function index; 0 is IRP_MJ_CREATE."));
    return result;
}

// QueryDriverImageFields reads one LDR image entry's identity fields together
// with whatever restore record the driver still holds for them.
KernelOperationResult QueryDriverImageFields(const KernelRequest& request) {
    const DriverTargetIdentity identity = BuildDriverTargetIdentity(request);
    if (!identity.valid) {
        return MakeDriverTargetPrompt(request, L"驱动镜像字段");
    }
    const ksword::ark::DriverClient client;
    const ksword::ark::DriverImageControlResult query =
        client.queryDriverImage(identity.moduleBase, identity.driverName);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Driver Image", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Driver", identity.driverName.empty() ? HexText(identity.moduleBase) : identity.driverName },
        { L"State", std::to_wstring(query.state) },
        { L"Generation", std::to_wstring(query.generation) },
        { L"ModuleBase", HexText(query.targetModuleBase) },
        { L"ManagedFields", HexText(query.managedFieldMask) },
        { L"OwnedFields", HexText(query.ownedFieldMask) },
        { L"ConflictFields", HexText(query.conflictFieldMask) },
        { L"ChangedFields", HexText(query.changedFieldMask) },
        { L"LayoutFlags", HexText(query.layoutFlags) },
        { L"ResponseFlags", HexText(query.responseFlags) },
        { L"LoaderStatus", HexText(static_cast<std::uint32_t>(query.loaderStatus)) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"A non-zero conflictFieldMask means a third party rewrote a field this driver still holds a "
       L"restore record for, so the recorded original can no longer be assumed to be the live value."));
    return result;
}

// QueryDriverCommunication reads whether a driver's dispatch surface is
// currently pointed at the system reject entry, and who owns that state.
KernelOperationResult QueryDriverCommunication(const KernelRequest& request) {
    const DriverTargetIdentity identity = BuildDriverTargetIdentity(request);
    if (!identity.valid) {
        return MakeDriverTargetPrompt(request, L"驱动通信端点");
    }
    const ksword::ark::DriverClient client;
    const ksword::ark::DriverCommunicationControlResult query =
        client.queryDriverCommunication(identity.moduleBase, identity.driverName);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Driver Communication", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Version", std::to_wstring(query.version) },
        { L"Driver", identity.driverName.empty() ? HexText(identity.moduleBase) : identity.driverName },
        { L"State", std::to_wstring(query.state) },
        { L"Generation", std::to_wstring(query.generation) },
        { L"TargetedMask", HexText(query.targetedMask) },
        { L"ActiveMask", HexText(query.activeMask) },
        { L"OwnedMask", HexText(query.ownedMask) },
        { L"ConflictMask", HexText(query.conflictMask) },
        { L"ChangedMask", HexText(query.changedMask) },
        { L"DriverObject", HexText(query.driverObjectAddress) },
        { L"DriverStart", HexText(query.driverStart) },
        { L"RejectDispatch", HexText(query.rejectDispatchAddress) },
        { L"ResponseFlags", HexText(query.responseFlags) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"activeMask lists the MajorFunction slots currently pointing at the system reject entry. "
       L"ownedMask is the subset this driver may still restore; anything in conflictMask was rewritten "
       L"by someone else and is no longer safe to restore blindly."));
    return result;
}

// QueryPlatformAudit reads HAL table entries, WDF functions and WDF callbacks
// with the driver's own signature-verified evidence attached.
KernelOperationResult QueryPlatformAudit(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxRows = request.maxRows == 0
        ? KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS
        : request.maxRows;
    const ksword::ark::PlatformAuditResult query =
        client.queryPlatformAudit(KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL, maxRows);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Platform Audit", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"QueryStatus", HexText(query.status) },
        { L"ScopeMask", HexText(query.scopeMask) },
        { L"ResponseFlags", HexText(query.responseFlags) },
        { L"BuildNumber", std::to_wstring(query.buildNumber) },
        { L"SignaturePolicy", HexText(query.signaturePolicyFlags) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"HAL/WDF slot evidence. Rows carry the driver's own confidence and signature id rather than a "
       L"derived verdict, because an unrecognized prologue is not by itself evidence of a hook."));

    for (const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& entry : query.entries) {
        const std::wstring name = FixedWideField(entry.name, KSWORD_ARK_PLATFORM_NAME_CHARS);
        const std::wstring modulePath = FixedWideField(entry.modulePath, KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS);
        std::wostringstream detail;
        detail << L"Name: " << name << L"\r\n"
               << L"Scope: " << entry.scope << L"\r\n"
               << L"RowKind: " << entry.rowKind << L"\r\n"
               << L"EntryIndex: " << entry.entryIndex << L"\r\n"
               << L"Live: " << HexText(entry.liveAddress) << L"\r\n"
               << L"Original: " << HexText(entry.originalAddress) << L"\r\n"
               << L"Table: " << HexText(entry.tableAddress) << L"\r\n"
               << L"ModuleBase: " << HexText(entry.moduleBase) << L"\r\n"
               << L"ModuleSize: " << HexText(entry.moduleSize) << L"\r\n"
               << L"ModulePath: " << modulePath << L"\r\n"
               << L"HookStatus: " << HexText(entry.hookStatus) << L"\r\n"
               << L"Confidence: " << entry.confidence << L"\r\n"
               << L"SignatureId: " << entry.signatureId << L"\r\n"
               << L"LastStatus: " << HexText(static_cast<std::uint32_t>(entry.lastStatus));
        result.rows.push_back(Row({
            { L"Name", name.empty() ? L"(未命名槽)" : name },
            { L"Scope", std::to_wstring(entry.scope) },
            { L"Index", std::to_wstring(entry.entryIndex) },
            { L"Live", HexText(entry.liveAddress) },
            { L"Original", HexText(entry.originalAddress) },
            { L"HookStatus", HexText(entry.hookStatus) },
            { L"Confidence", std::to_wstring(entry.confidence) },
            { L"Module", modulePath },
        }, detail.str()));
    }
    return result;
}

// QuerySystemTimeState reads which performance-counter backend is in use and
// whether the multiplier is currently taken over. Read-only: the takeover
// itself is a control action and is not reachable from here.
KernelOperationResult QuerySystemTimeState(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::SystemTimeQueryResult query = client.querySystemTime();
    KernelOperationResult result;
    ApplyIoSummary(request, L"System Time", query.io, result);
    const KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE& response = query.response;
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(response.version) },
        { L"QueryStatus", HexText(response.status) },
        { L"StateFlags", HexText(response.stateFlags) },
        { L"Generation", std::to_wstring(response.generation) },
        { L"Factor", std::to_wstring(response.factor) },
        { L"Backend", std::to_wstring(response.backend) },
        { L"ResolutionMode", std::to_wstring(response.resolutionMode) },
        { L"OsBuild", std::to_wstring(response.osBuildNumber) },
        { L"CounterValue", HexText(response.counterValue) },
        { L"CounterSource", HexText(response.counterSourceAddress) },
        { L"PrimarySlot", HexText(response.primarySlotAddress) },
        { L"SecondarySlot", HexText(response.secondarySlotAddress) },
        { L"HvSharedPage", HexText(response.hypervisorSharedPageAddress) },
        { L"HvOrigMultiplier", HexText(response.hypervisorOriginalMultiplier) },
        { L"HvCurMultiplier", HexText(response.hypervisorCurrentMultiplier) },
        { L"HvOrigBias", HexText(response.hypervisorOriginalBias) },
        { L"HvCurBias", HexText(response.hypervisorCurrentBias) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(response.lastStatus)) },
    }, L"A current multiplier or bias that differs from the recorded original means the system clock "
       L"rate is being scaled by someone. Under a hypervisor the shared-page values are the ones that "
       L"matter, since the guest-visible counter is derived from them."));
    AppendZeroResponseWarning(response.version, response.size, result.rows);
    return result;
}

// QueryI8042Audit enumerates the keyboard/mouse filter callbacks on the i8042
// port stack. A callback whose owning module is not the expected class driver
// is the classic shape of a kernel keylogger, so the owner module is a column
// rather than a detail-only field.
KernelOperationResult QueryI8042Audit(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxRows = request.maxRows == 0
        ? KSWORD_ARK_I8042_DEFAULT_MAX_ROWS
        : request.maxRows;
    const ksword::ark::I8042AuditResult query = client.queryI8042Audit(maxRows);
    KernelOperationResult result;
    ApplyIoSummary(request, L"i8042 Audit", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"QueryStatus", HexText(query.status) },
        { L"ResponseFlags", HexText(query.responseFlags) },
        { L"DescriptorId", std::to_wstring(query.descriptorId) },
        { L"ImageBase", HexText(query.imageBase) },
        { L"ImageSize", HexText(query.imageSize) },
        { L"ImageTimeDateStamp", HexText(query.imageTimeDateStamp) },
        { L"PdbAge", std::to_wstring(query.pdbAge) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"Endpoint rows are resolved against an exact i8042prt build descriptor. A zero descriptorId "
       L"means the running build was not recognized and the offsets behind these rows are unverified."));

    for (const KSWORD_ARK_I8042_AUDIT_ENTRY& entry : query.entries) {
        const std::wstring pnpId = FixedWideField(entry.pnpId, KSWORD_ARK_I8042_PNP_ID_CHARS);
        const std::wstring ownerPath = FixedWideField(entry.ownerModulePath, KSWORD_ARK_I8042_MODULE_PATH_CHARS);
        std::wostringstream detail;
        detail << L"PnpId: " << pnpId << L"\r\n"
               << L"RowKind: " << entry.rowKind << L"\r\n"
               << L"DeviceKind: " << entry.deviceKind << L"\r\n"
               << L"EndpointKind: " << entry.endpointKind << L"\r\n"
               << L"Verdict: " << entry.verdict << L"\r\n"
               << L"DeviceObject: " << HexText(entry.deviceObject) << L"\r\n"
               << L"ClassDeviceObject: " << HexText(entry.classDeviceObject) << L"\r\n"
               << L"Callback: " << HexText(entry.callbackAddress) << L"\r\n"
               << L"Context: " << HexText(entry.contextAddress) << L"\r\n"
               << L"ModuleBase: " << HexText(entry.moduleBase) << L"\r\n"
               << L"ModuleSize: " << HexText(entry.moduleSize) << L"\r\n"
               << L"OwnerModule: " << ownerPath << L"\r\n"
               << L"DetailCode: " << HexText(entry.detailCode) << L"\r\n"
               << L"LastStatus: " << HexText(static_cast<std::uint32_t>(entry.lastStatus));
        result.rows.push_back(Row({
            { L"PnpId", pnpId },
            { L"DeviceKind", std::to_wstring(entry.deviceKind) },
            { L"EndpointKind", std::to_wstring(entry.endpointKind) },
            { L"Verdict", std::to_wstring(entry.verdict) },
            { L"Callback", HexText(entry.callbackAddress) },
            { L"OwnerModule", ownerPath.empty() ? L"(未归属模块)" : ownerPath },
            { L"DeviceObject", HexText(entry.deviceObject) },
            { L"Status", HexText(entry.status) },
        }, detail.str()));
    }
    return result;
}

// QueryPiDdbCache enumerates PiDDBCacheTable, which records every driver the
// loader has vetted. Its entries survive an unload, so a driver that is gone
// from the module list can still be named here.
KernelOperationResult QueryPiDdbCache(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxRows = request.maxRows == 0
        ? KSWORD_ARK_PIDDB_DEFAULT_ROWS
        : request.maxRows;
    const ksword::ark::PiDdbQueryResult query = client.queryPiDdb(maxRows);
    KernelOperationResult result;
    ApplyIoSummary(request, L"PiDDB Cache", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"QueryStatus", HexText(query.queryStatus) },
        { L"ResponseFlags", HexText(query.responseFlags) },
        { L"Total", std::to_wstring(query.totalRows) },
        { L"Returned", std::to_wstring(query.entries.size()) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"PiDDBCacheTable is walked read-only. Entries persist after a driver unloads, which is why this "
       L"table and the loaded-module list disagree by design."));

    for (const ksword::ark::PiDdbEntry& entry : query.entries) {
        std::wostringstream detail;
        detail << L"Driver: " << entry.driverName << L"\r\n"
               << L"Entry: " << HexText(entry.entryAddress) << L"\r\n"
               << L"TimeDateStamp: " << HexText(entry.timeDateStamp) << L"\r\n"
               << L"LoadStatus: " << HexText(static_cast<std::uint32_t>(entry.loadStatus));
        result.rows.push_back(Row({
            { L"Driver", entry.driverName },
            { L"TimeDateStamp", HexText(entry.timeDateStamp) },
            { L"LoadStatus", HexText(static_cast<std::uint32_t>(entry.loadStatus)) },
            { L"Entry", HexText(entry.entryAddress) },
        }, detail.str()));
    }
    return result;
}

// FormatIpAddress renders one 16-byte address slot. IPv4 rows leave the trailing
// 12 bytes zeroed, so the family decides how many of them mean anything.
std::wstring FormatIpAddress(const unsigned char* address, const unsigned long addressFamily) {
    if (address == nullptr) {
        return {};
    }
    std::wostringstream text;
    // AF_INET6 is 23 on Windows; anything else is rendered as IPv4 because the
    // driver only ever fills these two shapes.
    if (addressFamily == 23UL) {
        for (int group = 0; group < 8; ++group) {
            if (group != 0) {
                text << L':';
            }
            const unsigned value =
                (static_cast<unsigned>(address[group * 2]) << 8) | static_cast<unsigned>(address[group * 2 + 1]);
            text << std::hex << value;
        }
        return text.str();
    }
    text << static_cast<unsigned>(address[0]) << L'.' << static_cast<unsigned>(address[1]) << L'.'
         << static_cast<unsigned>(address[2]) << L'.' << static_cast<unsigned>(address[3]);
    return text.str();
}

// QueryRawDiskSectors reads sector-aligned bytes straight off a physical disk
// through the driver's storage backend. The disk number comes from the filter
// box and the byte offset from the start-address box; both are required because
// there is no sane default for "which disk to read".
KernelOperationResult QueryRawDiskSectors(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    unsigned long diskNumber = 0;
    bool diskNumberValid = false;
    if (!request.filterText.empty()) {
        try {
            diskNumber = static_cast<unsigned long>(std::stoul(request.filterText));
            diskNumberValid = true;
        } catch (const std::exception&) {
            diskNumberValid = false;
        }
    }
    if (!diskNumberValid) {
        KernelOperationResult prompt;
        prompt.supported = true;
        prompt.success = false;
        prompt.message = L"物理磁盘扇区：请在过滤框填写磁盘号（0 表示 PhysicalDrive0），起点地址填字节偏移。";
        prompt.rows.push_back(Row({
            { L"Hint", L"需要磁盘号" },
            { L"Filter", L"磁盘号，例如 0" },
            { L"StartAddress", L"字节偏移，会被向下对齐到扇区边界" },
            { L"MaxRows", L"读取字节数，默认一个扇区" },
        }, L"Reading a physical disk has no meaningful default target, so the disk number is required "
           L"rather than guessed."));
        return prompt;
    }

    KernelOperationResult result;
    const ksword::ark::RawDiskBackendResult backend = client.queryRawDiskBackend(diskNumber);
    ApplyIoSummary(request, L"Raw Disk", backend.io, result);
    const KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE& info = backend.response;
    const unsigned long sectorSize = info.logicalSectorSize != 0 ? info.logicalSectorSize : 512UL;
    result.rows.push_back(Row({
        { L"Status", backend.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(backend.unsupported) },
        { L"Disk", std::to_wstring(info.diskNumber) },
        { L"BackendStatus", HexText(info.status) },
        { L"Capabilities", HexText(info.capabilityFlags) },
        { L"AvailableBackends", HexText(info.availableBackendMask) },
        { L"LogicalSector", std::to_wstring(info.logicalSectorSize) },
        { L"PhysicalSector", std::to_wstring(info.physicalSectorSize) },
        { L"DiskSize", std::to_wstring(info.diskSizeBytes) },
        { L"BusType", std::to_wstring(info.busType) },
        { L"Model", FixedWideField(info.model, KSWORD_ARK_RAW_DISK_MODEL_CHARS) },
        { L"Serial", FixedWideField(info.serial, KSWORD_ARK_RAW_DISK_SERIAL_CHARS) },
        { L"DevicePath", FixedWideField(info.devicePath, KSWORD_ARK_RAW_DISK_PATH_CHARS) },
        { L"Detail", FixedWideField(info.detail, KSWORD_ARK_RAW_DISK_DETAIL_CHARS) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(info.lastStatus)) },
    }, L"Backend capability for this disk. availableBackendMask lists which of the three storage paths "
       L"the driver can actually use here."));
    if (!backend.io.ok) {
        return result;
    }

    // Both offset and length are snapped to the sector grid, because the storage
    // path rejects anything else and a silent partial read would be worse.
    const std::uint64_t alignedOffset = (request.startAddress / sectorSize) * sectorSize;
    unsigned long requestedLength = request.maxRows == 0 ? sectorSize : request.maxRows;
    requestedLength = ((requestedLength + sectorSize - 1) / sectorSize) * sectorSize;
    if (requestedLength > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES) {
        requestedLength = KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES;
    }

    const ksword::ark::RawDiskReadResult read =
        client.readRawDisk(diskNumber, 0UL, alignedOffset, requestedLength);
    result.rows.push_back(Row({
        { L"ReadStatus", HexText(read.status) },
        { L"BackendUsed", std::to_wstring(read.backendUsed) },
        { L"SectorSize", std::to_wstring(read.logicalSectorSize) },
        { L"Offset", HexText(alignedOffset) },
        { L"Requested", std::to_wstring(requestedLength) },
        { L"Returned", std::to_wstring(read.bytes.size()) },
        { L"Transport", read.io.ok ? L"OK" : L"Failed" },
    }, L"Offset and length are aligned down/up to the logical sector size before the request is sent; "
       L"the storage path rejects unaligned transfers outright."));

    // 16 bytes per row keeps each line readable next to the offset column.
    constexpr std::size_t kBytesPerRow = 16;
    for (std::size_t offset = 0; offset < read.bytes.size(); offset += kBytesPerRow) {
        const std::size_t chunk = (std::min)(kBytesPerRow, read.bytes.size() - offset);
        std::wostringstream hex;
        std::wostringstream ascii;
        for (std::size_t index = 0; index < chunk; ++index) {
            const unsigned char value = read.bytes[offset + index];
            if (index != 0) {
                hex << L' ';
            }
            hex << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned>(value);
            ascii << (value >= 0x20 && value < 0x7F ? static_cast<wchar_t>(value) : L'.');
        }
        result.rows.push_back(Row({
            { L"Offset", HexText(alignedOffset + offset) },
            { L"Hex", hex.str() },
            { L"Ascii", ascii.str() },
        }, L"Raw sector bytes."));
    }
    return result;
}

// QueryNetworkTrafficPackets drains the R0 WFP per-packet ring. The capture is
// off by default and its start/stop switch is a control action, so an empty
// result here usually means capture was never turned on rather than that no
// traffic occurred.
KernelOperationResult QueryNetworkTrafficPackets(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxRows = request.maxRows == 0
        ? KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS
        : request.maxRows;
    const ksword::ark::NetworkTrafficPacketResult query = client.queryNetworkTrafficPackets(0, maxRows);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Network Traffic", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"QueryStatus", HexText(query.status) },
        { L"Capacity", std::to_wstring(query.capacity) },
        { L"OldestSequence", std::to_wstring(query.oldestSequence) },
        { L"NewestSequence", std::to_wstring(query.newestSequence) },
        { L"NextCursor", std::to_wstring(query.nextSequence) },
        { L"DroppedPackets", std::to_wstring(query.droppedPacketCount) },
        { L"CursorGap", std::to_wstring(query.cursorGapCount) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.entries.size()) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"Packets come from the driver's own WFP capture ring, so no Npcap or raw-socket path is "
       L"involved. Capture is off until it is explicitly started, which is why an empty ring with a "
       L"zero newestSequence means it was never running rather than that the link was idle. "
       L"droppedPacketCount counts packets the ring overwrote before anyone read them."));

    for (const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& row : query.entries) {
        const std::wstring local =
            FormatIpAddress(row.localAddress, row.addressFamily) + L":" + std::to_wstring(row.localPort);
        const std::wstring remote =
            FormatIpAddress(row.remoteAddress, row.addressFamily) + L":" + std::to_wstring(row.remotePort);
        std::wostringstream detail;
        detail << L"Sequence: " << row.sequence << L"\r\n"
               << L"Timestamp: " << row.timestamp100ns << L"\r\n"
               << L"Family: " << row.addressFamily << L"\r\n"
               << L"Direction: " << row.direction << L"\r\n"
               << L"Protocol: " << row.protocol << L"\r\n"
               << L"ProcessId: " << row.processId << L"\r\n"
               << L"Local: " << local << L"\r\n"
               << L"Remote: " << remote << L"\r\n"
               << L"TotalLength: " << row.totalPacketLength << L"\r\n"
               << L"CapturedLength: " << row.capturedLength << L"\r\n"
               << L"PayloadOffset: " << row.payloadOffset << L"\r\n"
               << L"PayloadLength: " << row.payloadLength << L"\r\n"
               << L"Flags: " << HexText(row.flags);
        result.rows.push_back(Row({
            { L"Sequence", std::to_wstring(row.sequence) },
            { L"Direction", std::to_wstring(row.direction) },
            { L"Protocol", std::to_wstring(row.protocol) },
            { L"Local", local },
            { L"Remote", remote },
            { L"ProcessId", row.processId != 0 ? std::to_wstring(row.processId) : L"-" },
            { L"Length", std::to_wstring(row.totalPacketLength) },
            { L"Captured", std::to_wstring(row.capturedLength) },
        }, detail.str()));
    }
    return result;
}

// QueryIoctlRegistry exposes the driver's registered dispatch metadata without
// duplicating transport primitives in the UI. It is a read-only bounded query.
KernelOperationResult QueryIoctlRegistry(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const unsigned long maxEntries = request.maxRows == 0
        ? KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES
        : request.maxRows;
    const ksword::ark::IoctlRegistryQueryResult query = client.queryIoctlRegistry(
        KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER,
        maxEntries);
    KernelOperationResult result;
    ApplyIoSummary(request, L"IOCTL Dispatch Registry", query.io, result);
    result.rows.push_back(Row({
        { L"Status", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"RegistryStatus", HexText(query.status) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Duplicates", std::to_wstring(query.duplicateCount) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, L"The registry is a diagnostic snapshot of handlers registered by KswordARK's centralized IOCTL dispatcher."));

    for (const ksword::ark::IoctlRegistryEntry& entry : query.entries) {
        const std::wstring methodAccess = std::to_wstring(entry.method) + L" / " + std::to_wstring(entry.access);
        const std::wstring name = Utf8ToWide(entry.name);
        std::wostringstream detail;
        detail << L"IOCTL: " << HexText(entry.ioControlCode) << L"\r\n"
               << L"Function: " << entry.functionNumber << L"\r\n"
               << L"Method/Access: " << methodAccess << L"\r\n"
               << L"Required capability: " << HexText(entry.requiredCapability) << L"\r\n"
               << L"Handler: " << HexText(entry.handlerAddress) << L"\r\n"
               << L"Name: " << name << L"\r\n"
               << L"Flags: " << HexText(entry.flags);
        result.rows.push_back(Row({
            { L"IOCTL", HexText(entry.ioControlCode) },
            { L"IoControlCode", HexText(entry.ioControlCode) },
            { L"函数", std::to_wstring(entry.functionNumber) },
            { L"Function", std::to_wstring(entry.functionNumber) },
            { L"FunctionNumber", std::to_wstring(entry.functionNumber) },
            { L"Method/Access", methodAccess },
            { L"MethodAccess", methodAccess },
            { L"Capability", HexText(entry.requiredCapability) },
            { L"RequiredCapability", HexText(entry.requiredCapability) },
            { L"Handler", HexText(entry.handlerAddress) },
            { L"HandlerAddress", HexText(entry.handlerAddress) },
            { L"名称", name },
            { L"Name", name },
            { L"Flags", HexText(entry.flags) },
            { L"状态", L"Registered" },
            { L"Status", L"Registered" },
        }, detail.str()));
    }
    return result;
}

KernelOperationResult QueryPhysicalMemoryLayout(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::PhysicalMemoryLayoutResult query = client.queryPhysicalMemoryLayout();
    KernelOperationResult result;
    ApplyIoSummary(request, L"Physical Memory Layout", query.io, result);
    result.rows.push_back(Row({
        { L"范围", std::to_wstring(query.rangeCount) },
        { L"总物理内存", SizeText(query.totalPhysicalBytes) },
        { L"最高物理地址", HexText(query.highestPhysicalAddress) },
        { L"最大连续Range", SizeText(query.largestRangeBytes) },
        { L"状态", query.io.ok ? L"OK" : L"Failed" },
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"FieldFlags", HexText(query.fieldFlags) },
        { L"Ranges", std::to_wstring(query.rangeCount) },
        { L"ZeroRanges", std::to_wstring(query.zeroLengthRangeCount) },
        { L"Truncated", std::to_wstring(query.truncated) },
        { L"TotalBytes", HexText(query.totalPhysicalBytes) },
        { L"TotalText", SizeText(query.totalPhysicalBytes) },
        { L"HighestAddress", HexText(query.highestPhysicalAddress) },
        { L"LargestRange", HexText(query.largestRangeBytes) },
        { L"LargestRangeText", SizeText(query.largestRangeBytes) },
        { L"SmallestRange", HexText(query.smallestRangeBytes) },
        { L"SmallestRangeText", SizeText(query.smallestRangeBytes) },
        { L"FirstBase", HexText(query.firstBaseAddress) },
        { L"LastEnd", HexText(query.lastEndAddress) },
        { L"GapBytes", HexText(query.estimatedAddressSpaceGapBytes) },
        { L"GapText", SizeText(query.estimatedAddressSpaceGapBytes) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));
    return result;
}

KernelOperationResult QueryMutationAudit(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::MutationAuditResult query = client.queryMutationAudit(KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Mutation Audit", query.io, result);
    result.rows.push_back(Row({
        { L"Unsupported", BoolText(query.unsupported) },
        { L"Version", std::to_wstring(query.version) },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Lost", std::to_wstring(query.lostCount) },
        { L"OldestSeq", HexText(query.oldestSequence) },
        { L"NextSeq", HexText(query.nextSequence) },
    }));

    for (const ksword::ark::MutationAuditEntry& entry : query.entries) {
        result.rows.push_back(Row({
            { L"Seq", HexText(entry.sequence) },
            { L"Tx", HexText(entry.transactionId) },
            { L"TransactionId", std::to_wstring(entry.transactionId) },
            { L"TransactionIdHex", HexText(entry.transactionId) },
            { L"Operation", std::wstring(MutationOperationText(entry.operation)) + L" (" + std::to_wstring(entry.operation) + L")" },
            { L"OperationText", MutationOperationText(entry.operation) },
            { L"Status", std::wstring(MutationStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"StatusText", MutationStatusText(entry.status) },
            { L"TargetKind", std::wstring(MutationTargetText(entry.targetKind)) + L" (" + std::to_wstring(entry.targetKind) + L")" },
            { L"TargetKindText", MutationTargetText(entry.targetKind) },
            { L"Risk", HexText(entry.riskFlags) },
            { L"RiskText", MutationRiskText(entry.riskFlags) },
            { L"Flags", HexText(entry.flags) },
            { L"FlagsText", MutationFlagsText(entry.flags) },
            { L"PID", std::to_wstring(entry.processId) },
            { L"Address", HexText(entry.targetAddress) },
            { L"Context", HexText(entry.targetContext) },
            { L"Bytes", std::to_wstring(entry.bytes) },
            { L"BeforeHash", HexText(entry.beforeHash) },
            { L"AfterHash", HexText(entry.afterHash) },
            { L"Data", BytesHex(entry.byteData) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }));
    }
    return result;
}

KernelOperationResult QueryKeyboardHotkeys(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const std::uint32_t pidFilter = ParseFirstPidFromText(request.filterText);
    const ksword::ark::KeyboardHotkeyEnumResult query = client.enumerateKeyboardHotkeys(pidFilter);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Keyboard Hotkeys", query.io, result);
    result.rows.push_back(Row({
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(KeyboardEnumStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Flags", HexText(query.flags) },
        { L"Win32kBase", HexText(query.win32kBase) },
        { L"SessionGlobals", HexText(query.sessionGlobals) },
        { L"TableOffset", HexText(query.tableOffset) },
        { L"HotkeyNextOffset", HexText(query.hotkeyNextOffset) },
        { L"HotkeyModifiersOffset", HexText(query.hotkeyModifiersOffset) },
        { L"HotkeyVkOffset", HexText(query.hotkeyVkOffset) },
        { L"HotkeyIdOffset", HexText(query.hotkeyIdOffset) },
        { L"PidFilter", pidFilter == 0 ? L"" : std::to_wstring(pidFilter) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));
    for (const ksword::ark::KeyboardHotkeyEntry& entry : query.entries) {
        const std::wstring processName = ProcessDisplayName(entry.processId);
        const std::wstring hotkeyText = HotkeyDisplayText(entry.modifiers, entry.virtualKey, entry.hotkeyId);
        const std::wstring vkModText = L"VK=" + HexText(entry.virtualKey) + L" Mod=" + HexText(entry.modifiers);
        result.rows.push_back(Row({
            { L"对象", HexText(entry.hotkeyObject) },
            { L"热键ID", HexText(entry.hotkeyId) },
            { L"进程ID", std::to_wstring(entry.processId) },
            { L"线程ID", std::to_wstring(entry.threadId) },
            { L"进程名", processName },
            { L"VK/Mod", vkModText },
            { L"详情", entry.detail },
            { L"PID", std::to_wstring(entry.processId) },
            { L"TID", std::to_wstring(entry.threadId) },
            { L"Process", processName },
            { L"窗口", HexText(entry.windowObject) },
            { L"热键", hotkeyText },
            { L"来源", KeyboardSourceText(entry.source) },
            { L"VK", HexText(entry.virtualKey) },
            { L"Modifiers", HexText(entry.modifiers) },
            { L"ModifierFlags2", HexText(entry.modifierFlags2) },
            { L"Id", HexText(entry.hotkeyId) },
            { L"Object", HexText(entry.hotkeyObject) },
            { L"Next", HexText(entry.nextHotkeyObject) },
            { L"ThreadInfo", HexText(entry.threadInfo) },
            { L"ThreadObject", HexText(entry.threadObject) },
            { L"WindowObject", HexText(entry.windowObject) },
            { L"Source", HexText(entry.source) },
            { L"SourceText", KeyboardSourceText(entry.source) },
            { L"Status", std::wstring(KeyboardEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Flags", HexText(entry.flags) },
            { L"Bucket", std::to_wstring(entry.bucketIndex) },
            { L"Depth", std::to_wstring(entry.depth) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

KernelOperationResult QueryKeyboardHooks(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const std::uint32_t pidFilter = ParseFirstPidFromText(request.filterText);
    const ksword::ark::KeyboardHookEnumResult query = client.enumerateKeyboardHooks(pidFilter);
    KernelOperationResult result;
    ApplyIoSummary(request, L"Keyboard Hooks", query.io, result);
    result.rows.push_back(Row({
        { L"Version", std::to_wstring(query.version) },
        { L"Status", std::wstring(KeyboardEnumStatusText(query.status)) + L" (" + std::to_wstring(query.status) + L")" },
        { L"Total", std::to_wstring(query.totalCount) },
        { L"Returned", std::to_wstring(query.returnedCount) },
        { L"Flags", HexText(query.flags) },
        { L"Win32kBase", HexText(query.win32kBase) },
        { L"ThreadHookArrayOffset", HexText(query.threadHookArrayOffset) },
        { L"DesktopInfoOffset", HexText(query.desktopInfoOffset) },
        { L"DesktopHookArrayOffset", HexText(query.desktopHookArrayOffset) },
        { L"HookNextOffset", HexText(query.hookNextOffset) },
        { L"HookTypeOffset", HexText(query.hookTypeOffset) },
        { L"HookProcedureOffset", HexText(query.hookProcedureOffset) },
        { L"HookFlagsOffset", HexText(query.hookFlagsOffset) },
        { L"HookModuleIdOffset", HexText(query.hookModuleIdOffset) },
        { L"HookTargetThreadInfoOffset", HexText(query.hookTargetThreadInfoOffset) },
        { L"PidFilter", pidFilter == 0 ? L"" : std::to_wstring(pidFilter) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));
    for (const ksword::ark::KeyboardHookEntry& entry : query.entries) {
        const std::wstring processName = ProcessDisplayName(entry.processId);
        const std::wstring moduleDisplay = entry.moduleBase != 0
            ? HexText(entry.moduleBase)
            : std::wstring(L"ModuleId ") + std::to_wstring(entry.moduleId);
        const std::wstring procedureDisplay = HexText(entry.procedureAddress) + L" / " + HexText(entry.procedureOffset);
        result.rows.push_back(Row({
            { L"对象", HexText(entry.hookObject) },
            { L"类型", KeyboardHookTypeText(entry.hookType) },
            { L"范围", KeyboardHookScopeText(entry.hookScope) },
            { L"进程ID", std::to_wstring(entry.processId) },
            { L"线程ID", std::to_wstring(entry.threadId) },
            { L"函数/偏移", procedureDisplay },
            { L"详情", entry.detail },
            { L"PID", std::to_wstring(entry.processId) },
            { L"TID", std::to_wstring(entry.threadId) },
            { L"Process", processName },
            { L"Hook类型", KeyboardHookTypeText(entry.hookType) },
            { L"回调", HexText(entry.procedureAddress) },
            { L"模块", moduleDisplay },
            { L"来源", KeyboardSourceText(entry.source) },
            { L"Type", std::to_wstring(entry.hookType) },
            { L"TypeText", KeyboardHookTypeText(entry.hookType) },
            { L"Scope", std::to_wstring(entry.hookScope) },
            { L"ScopeText", KeyboardHookScopeText(entry.hookScope) },
            { L"Object", HexText(entry.hookObject) },
            { L"ChainHead", HexText(entry.chainHead) },
            { L"Next", HexText(entry.nextHookObject) },
            { L"ThreadInfo", HexText(entry.threadInfo) },
            { L"TargetThreadInfo", HexText(entry.targetThreadInfo) },
            { L"DesktopInfo", HexText(entry.desktopInfo) },
            { L"Procedure", HexText(entry.procedureAddress) },
            { L"ProcedureOffset", HexText(entry.procedureOffset) },
            { L"ModuleBase", HexText(entry.moduleBase) },
            { L"ModuleId", std::to_wstring(entry.moduleId) },
            { L"Source", HexText(entry.source) },
            { L"SourceText", KeyboardSourceText(entry.source) },
            { L"Status", std::wstring(KeyboardEnumStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"Flags", HexText(entry.flags) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }, entry.detail));
    }
    return result;
}

KernelOperationResult QueryDynDataCapabilities(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::DynDataCapabilitiesResult query = client.queryDynDataCapabilities();
    KernelOperationResult result;
    ApplyIoSummary(request, L"DynData Capabilities", query.io, result);
    result.rows.push_back(Row({
        { L"Capability", HexText(query.capabilityMask) },
        { L"状态", HexText(query.statusFlags) },
        { L"字段", L"DynData capability mask" },
        { L"原因", Utf8ToWide(query.io.message) },
        { L"StatusFlags", HexText(query.statusFlags) },
        { L"CapabilityMask", HexText(query.capabilityMask) },
    }, Utf8ToWide(query.io.message)));
    return result;
}

// QueryPdbProfileStatus summarizes DynData v3/v4 profile state through existing
// ArkDriverClient transport. Input is the current UI request; processing reads
// legacy status, fields, v4 module status, v4 capability groups, and missing
// items; output is read-only rows used by the PDB Profile status page.
KernelOperationResult QueryPdbProfileStatus(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::DynDataStatusResult status = client.queryDynDataStatus();
    const ksword::ark::DynDataFieldsResult fields = client.queryDynDataFields();
    const ksword::ark::DynDataCapabilitiesResult caps = client.queryDynDataCapabilities();
    const ksword::ark::DynDataV4ModulesResult v4Modules = client.queryDynDataV4Modules();
    const ksword::ark::DynDataV4CapabilityGroupsResult v4Groups = client.queryDynDataV4CapabilityGroups();
    const ksword::ark::DynDataV4MissingItemsResult v4Missing = client.queryDynDataV4MissingItems();
    const ksword::ark::DynDataV4ItemsResult v4Items = client.queryDynDataV4Items();
    const DynDataProfileMatch profileMatch = FindMatchingDynDataProfile(status.ntoskrnl);

    KernelOperationResult result;
    ApplyIoSummary(request, L"PDB Profile/DynData Status", status.io, result);
    result.success = status.io.ok && fields.io.ok && caps.io.ok;

    result.rows.push_back(Row({
        { L"模块", L"ntoskrnl" },
        { L"Module", status.ntoskrnl.moduleName },
        { L"Class", std::to_wstring(status.ntoskrnl.classId) },
        { L"Profile", Utf8ToWide(profileMatch.profile.profileName) },
        { L"状态", TrustedOffsetText(status.statusFlags, profileMatch, SummarizeDynDataFields(fields)) },
        { L"Status", HexText(status.statusFlags) },
        { L"Capability", HexText(status.capabilityMask) },
        { L"CapabilityMask", HexText(caps.capabilityMask) },
        { L"缺失", fields.io.ok ? FieldCoverageText(SummarizeDynDataFields(fields), profileMatch.coveragePercent) : L"字段查询失败" },
        { L"Identity", ModuleIdentityText(status.ntoskrnl) },
        { L"PdbProfileName", Utf8ToWide(profileMatch.profile.profileName) },
        { L"PdbProfilePath", profileMatch.path },
        { L"Reason", profileMatch.message },
    }, profileMatch.message));

    result.rows.push_back(Row({
        { L"模块", L"legacy-v3" },
        { L"Class", std::to_wstring(status.matchedProfileClass) },
        { L"Profile", Utf8ToWide(profileMatch.profile.profileName) },
        { L"状态", profileMatch.matched ? L"Local pack matched" : L"Local pack not matched" },
        { L"Capability", HexText(status.capabilityMask) },
        { L"缺失", L"RequiredMissing=" + std::to_wstring(SummarizeDynDataFields(fields).requiredMissing) },
        { L"Identity", ModuleIdentityText(status.ntoskrnl) },
        { L"Detail", L"v3 兼容路径保持不破坏；应用 profile 仍需显式动作，不在刷新时修改 R0 状态。" },
    }));

    result.rows.push_back(Row({
        { L"模块", L"v4-modules" },
        { L"Class", L"multi-module" },
        { L"Profile", L"profile-v4" },
        { L"状态", v4Modules.io.ok ? L"OK" : L"Unavailable" },
        { L"Capability", L"module status" },
        { L"缺失", v4Modules.io.ok ? L"" : Utf8ToWide(v4Modules.io.message) },
        { L"Identity", L"ArkDriverClient::queryDynDataV4Modules" },
        { L"Detail", Utf8ToWide(v4Modules.io.message) },
    }, Utf8ToWide(v4Modules.io.message)));
    result.rows.push_back(Row({
        { L"模块", L"v4-items" },
        { L"Class", L"accepted-items" },
        { L"Profile", L"profile-v4" },
        { L"状态", v4Items.io.ok ? L"OK" : (v4Items.unsupported ? L"Unsupported" : L"Unavailable") },
        { L"Capability", L"item status" },
        { L"缺失", v4Items.io.ok ? L"" : Utf8ToWide(v4Items.io.message) },
        { L"Identity", L"ArkDriverClient::queryDynDataV4Items" },
        { L"Detail", L"returned=" + std::to_wstring(v4Items.returnedCount) +
            L"/" + std::to_wstring(v4Items.totalCount) +
            L"; " + Utf8ToWide(v4Items.io.message) },
    }, Utf8ToWide(v4Items.io.message)));
    if (v4Modules.io.ok) {
        for (const KSW_DYN_V4_MODULE_STATUS_ENTRY& entry : v4Modules.entries) {
            const std::wstring moduleName = FixedWideText(entry.module.image.moduleName, KSW_DYN_MODULE_NAME_CHARS);
            const std::wstring profileName = FixedAnsiText(entry.module.profileName, KSW_DYN_V4_PROFILE_NAME_CHARS);
            const std::wstring pdbName = FixedAnsiText(entry.module.pdb.pdbName, KSW_DYN_PDB_NAME_CHARS);
            const std::wstring pdbGuid = FixedAnsiText(entry.module.pdb.pdbGuid, KSW_DYN_PDB_GUID_CHARS);
            std::wostringstream identity;
            identity << moduleName
                     << L" machine=" << HexText(entry.module.image.machine)
                     << L" timestamp=" << HexText(entry.module.image.timeDateStamp)
                     << L" size=" << HexText(entry.module.image.sizeOfImage)
                     << L" pdb=" << pdbName << L"/" << pdbGuid
                     << L"/age=" << entry.module.pdb.pdbAge;
            result.rows.push_back(Row({
                { L"模块", moduleName.empty() ? L"<unnamed>" : moduleName },
                { L"Module", moduleName },
                { L"ModuleName", moduleName },
                { L"Class", std::to_wstring(entry.module.image.classId) },
                { L"ModuleClassId", std::to_wstring(entry.module.image.classId) },
                { L"Profile", profileName },
                { L"ProfileName", profileName },
                { L"状态", DynV4StatusText(entry.statusFlags) },
                { L"Status", HexText(entry.statusFlags) },
                { L"StatusFlags", HexText(entry.statusFlags) },
                { L"Capability", std::to_wstring(entry.activeCapabilityGroupCount) + L"/" + std::to_wstring(entry.capabilityGroupCount) },
                { L"缺失", L"required=" + std::to_wstring(entry.missingRequiredItemCount) + L", optional=" + std::to_wstring(entry.missingOptionalItemCount) },
                { L"MissingSummary", L"required=" + std::to_wstring(entry.missingRequiredItemCount) + L", optional=" + std::to_wstring(entry.missingOptionalItemCount) },
                { L"Identity", identity.str() },
                { L"Detail", L"v4 module profile status row" },
            }, identity.str()));
        }
    }

    if (v4Items.io.ok) {
        for (const KSW_DYN_V4_ITEM_STATUS_ENTRY& entry : v4Items.entries) {
            const KSW_DYN_V4_ITEM_PACKET& item = entry.item;
            const std::wstring kindText = DynV4ItemKindText(item.itemKind);
            const std::wstring flagsText = DynV4ItemFlagsText(item.flags);
            result.rows.push_back(Row({
                { L"模块", L"v4-item" },
                { L"ModuleClassId", std::to_wstring(entry.moduleClassId) },
                { L"Class", std::to_wstring(entry.moduleClassId) },
                { L"Profile", L"ItemId=" + std::to_wstring(item.itemId) },
                { L"状态", flagsText },
                { L"Status", flagsText },
                { L"Capability", L"group=" + std::to_wstring(item.capabilityGroupId) },
                { L"Group", std::to_wstring(item.capabilityGroupId) },
                { L"缺失", kindText },
                { L"Identity", L"itemIndex=" + std::to_wstring(entry.itemIndex) },
                { L"ItemIndex", std::to_wstring(entry.itemIndex) },
                { L"ItemId", std::to_wstring(item.itemId) },
                { L"ItemKind", kindText },
                { L"Flags", HexText(item.flags) },
                { L"Value", DynV4ItemValueText(item) },
                { L"Detail", DynV4ItemValueText(item) },
            }, DynV4ItemValueText(item)));
        }
    }

    if (v4Groups.io.ok) {
        for (const KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY& entry : v4Groups.entries) {
            result.rows.push_back(Row({
                { L"模块", L"capability-group" },
                { L"Class", std::to_wstring(entry.moduleClassId) },
                { L"Profile", FixedAnsiText(entry.groupName, KSW_DYN_V4_CAPABILITY_NAME_CHARS) },
                { L"状态", DynV4StatusText(entry.statusFlags) },
                { L"Capability", L"group=" + std::to_wstring(entry.groupId) },
                { L"Group", std::to_wstring(entry.groupId) },
                { L"缺失", L"required " + std::to_wstring(entry.presentRequiredItemCount) + L"/" + std::to_wstring(entry.requiredItemCount) +
                    L", optional " + std::to_wstring(entry.presentOptionalItemCount) + L"/" + std::to_wstring(entry.optionalItemCount) },
                { L"Identity", L"ModuleClassId=" + std::to_wstring(entry.moduleClassId) },
                { L"Detail", L"v4 capability group status row" },
            }));
        }
    }

    if (v4Missing.io.ok) {
        for (const KSW_DYN_V4_MISSING_ITEM_ENTRY& entry : v4Missing.entries) {
            const std::wstring itemName = FixedAnsiText(entry.itemName, KSW_DYN_V4_ITEM_NAME_CHARS);
            const std::wstring reason = FixedAnsiText(entry.reason, KSW_DYN_V4_MISSING_REASON_CHARS);
            result.rows.push_back(Row({
                { L"模块", L"missing-item" },
                { L"Class", std::to_wstring(entry.moduleClassId) },
                { L"Profile", itemName },
                { L"状态", DynV4MissingKindText(entry.missingKind) },
                { L"Capability", L"group=" + std::to_wstring(entry.capabilityGroupId) },
                { L"缺失", std::wstring(DynV4ItemKindText(entry.itemKind)) + L" " + itemName },
                { L"Identity", L"ItemId=" + std::to_wstring(entry.itemId) },
                { L"Reason", reason },
                { L"Detail", reason },
            }, reason));
        }
    }
    return result;
}

// QueryCidTableSummary uses the ArkDriverClient high-level CID wrapper. Input
// may contain a PID/CID filter; processing never requests mutation and leaves
// protocol parsing inside ArkDriverClient; output preserves the existing Light
// table columns for source/dangling/type-mismatch evidence.
KernelOperationResult QueryCidTableSummary(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const std::uint32_t cidFilter = ParseFirstPidFromText(request.filterText);
    const ksword::ark::CidTableAuditResult query = client.enumCidTable(
        KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL,
        256,
        8192,
        cidFilter,
        cidFilter);

    KernelOperationResult result;
    ApplyIoSummary(request, L"CID Table Summary", query.io, result);
    if (!query.io.ok) {
        return result;
    }

    result.rows.push_back(Row({
        { L"CID", cidFilter == 0 ? L"<all>" : std::to_wstring(cidFilter) },
        { L"对象", HexText(query.pspCidTableAddress) },
        { L"类型", L"PspCidTable" },
        { L"状态", CidEnumStatusText(query.status) },
        { L"Flags", HexText(query.flags) },
        { L"引用", L"visited=" + std::to_wstring(query.visitedCount) + L"/" + std::to_wstring(query.maxVisitCount) },
        { L"Detail", L"total=" + std::to_wstring(query.totalCount) + L", returned=" + std::to_wstring(query.returnedCount) },
        { L"CapabilityMask", HexText(query.dynDataCapabilityMask) },
        { L"HT.TableCode", HexText(query.htTableCodeOffset) },
        { L"HTE.LowValue", HexText(query.hteLowValueOffset) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }));

    for (const KSWORD_ARK_CID_TABLE_ENTRY& entry : query.entries) {
        result.rows.push_back(Row({
            { L"CID", std::to_wstring(entry.cidValue) },
            { L"Cid", std::to_wstring(entry.cidValue) },
            { L"对象", HexText(entry.objectAddress) },
            { L"Object", HexText(entry.objectAddress) },
            { L"ObjectAddress", HexText(entry.objectAddress) },
            { L"类型", CidObjectKindText(entry.expectedObjectKind) },
            { L"Kind", CidObjectKindText(entry.expectedObjectKind) },
            { L"状态", HexText(static_cast<std::uint32_t>(entry.lookupStatus)) },
            { L"Status", HexText(static_cast<std::uint32_t>(entry.lookupStatus)) },
            { L"LookupStatus", HexText(static_cast<std::uint32_t>(entry.lookupStatus)) },
            { L"Flags", HexText(entry.flags) },
            { L"FlagText", CidEntryFlagsText(entry.flags) },
            { L"引用", HexText(static_cast<std::uint32_t>(entry.referenceStatus)) },
            { L"ReferenceStatus", HexText(static_cast<std::uint32_t>(entry.referenceStatus)) },
            { L"HandleIndex", std::to_wstring(entry.handleIndex) },
            { L"Detail", CidEntryFlagsText(entry.flags) },
        }));
    }

    const std::size_t objectSummaryLimit = cidFilter == 0U ? 16U : 64U;
    const std::size_t objectSummaryCount = std::min(query.entries.size(), objectSummaryLimit);
    for (std::size_t index = 0U; index < objectSummaryCount; ++index) {
        const KSWORD_ARK_CID_TABLE_ENTRY& entry = query.entries[index];
        if (entry.cidValue == 0U && entry.objectAddress == 0ULL) {
            continue;
        }
        const ksword::ark::KernelObjectSummaryAuditResult summary =
            client.queryKernelObjectSummary(entry.expectedObjectKind, entry.cidValue, entry.objectAddress);
        const KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE& response = summary.response;
        const std::wstring transportStatus = summary.io.ok
            ? ObjectSummaryStatusText(response.status)
            : (summary.unsupported ? L"Unsupported" : L"Unavailable");
        const std::wstring typeName = FixedWideText(response.typeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS);
        const std::wstring detailText = FixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS);
        result.rows.push_back(Row({
            { L"CID", std::to_wstring(entry.cidValue) },
            { L"Cid", std::to_wstring(entry.cidValue) },
            { L"对象", HexText(response.objectAddress != 0ULL ? response.objectAddress : entry.objectAddress) },
            { L"Object", HexText(response.objectAddress != 0ULL ? response.objectAddress : entry.objectAddress) },
            { L"ObjectAddress", HexText(response.objectAddress != 0ULL ? response.objectAddress : entry.objectAddress) },
            { L"类型", typeName.empty() ? CidObjectKindText(entry.expectedObjectKind) : typeName },
            { L"Kind", CidObjectKindText(response.targetKind != KSWORD_ARK_CID_OBJECT_KIND_UNKNOWN ? response.targetKind : entry.expectedObjectKind) },
            { L"状态", transportStatus },
            { L"Status", transportStatus },
            { L"LookupStatus", NtStatusText(response.lookupStatus) },
            { L"TypeStatus", NtStatusText(response.typeStatus) },
            { L"CounterStatus", NtStatusText(response.counterStatus) },
            { L"ObjectHeaderStatus", ObjectHeaderStatusText(response.objectHeaderStatus) },
            { L"Flags", HexText(response.fieldFlags) },
            { L"FieldFlags", HexText(response.fieldFlags) },
            { L"引用", L"ptr=" + std::to_wstring(response.pointerCount) + L", handle=" + std::to_wstring(response.handleCount) },
            { L"ReferenceStatus", L"ptr=" + std::to_wstring(response.pointerCount) + L", handle=" + std::to_wstring(response.handleCount) },
            { L"HandleIndex", std::to_wstring(entry.handleIndex) },
            { L"TypeIndex", std::to_wstring(response.typeIndex) },
            { L"ObjectType", HexText(response.objectTypeAddress) },
            { L"DynDataCapabilityMask", HexText(response.dynDataCapabilityMask) },
            { L"OT.NameOffset", HexText(response.otNameOffset) },
            { L"OT.IndexOffset", HexText(response.otIndexOffset) },
            { L"Source", L"ArkDriverClient::queryKernelObjectSummary" },
            { L"Detail", detailText.empty() ? Utf8ToWide(summary.io.message) : detailText },
        }, detailText.empty() ? Utf8ToWide(summary.io.message) : detailText));
    }
    if (query.entries.size() > objectSummaryCount) {
        result.rows.push_back(Row({
            { L"CID", L"<summary-limit>" },
            { L"对象", HexText(query.pspCidTableAddress) },
            { L"类型", L"KernelObjectSummary" },
            { L"状态", L"Truncated" },
            { L"引用", std::to_wstring(objectSummaryCount) + L"/" + std::to_wstring(query.entries.size()) },
            { L"Detail", L"未带筛选时仅查询前 16 条对象摘要；输入 PID/CID 筛选可扩大到 64 条，避免刷新页时过量 IOCTL。" },
        }));
    }
    return result;
}

// QueryIpcSummary reads the R0 IPC summary protocol and augments it with the
// KernelLight local NamedPipe/communication-endpoint entry points. Input is one
// UI request; processing remains read-only and does not enumerate or mutate pipe
// contents; output distinguishes ALPC, NamedPipe, Mailslot and SMB fallback.
KernelOperationResult QueryIpcSummary(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const std::uint32_t pidFilter = ParseFirstPidFromText(request.filterText);
    const ksword::ark::IpcSummaryAuditResult query = client.queryIpcSummary(
        pidFilter,
        0,
        KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL,
        128);
    const KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE& response = query.response;

    KernelOperationResult result;
    ApplyIoSummary(request, L"IPC Summary", query.io, result);
    result.rows.push_back(Row({
        { L"类别", L"ALPC" },
        { L"Class", L"ALPC" },
        { L"状态", query.io.ok ? IpcSummaryStatusText(response.alpcStatus) : L"Unavailable" },
        { L"Status", query.io.ok ? IpcSummaryStatusText(response.alpcStatus) : L"Unavailable" },
        { L"进程", pidFilter == 0 ? L"<all/current capability>" : std::to_wstring(pidFilter) },
        { L"PID", std::to_wstring(response.processId) },
        { L"Handle/Object", HexText(response.alpcObjectAddress) },
        { L"Object", HexText(response.alpcObjectAddress) },
        { L"Capability", HexText(response.dynDataCapabilityMask) },
        { L"CapabilityMask", HexText(response.dynDataCapabilityMask) },
        { L"来源", L"ArkDriverClient::queryIpcSummary" },
        { L"Source", L"R0 IPC summary" },
        { L"Detail", FixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS) },
        { L"TypeName", FixedWideText(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(response.lastStatus)) },
    }, FixedWideText(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS)));
    result.rows.push_back(Row({
        { L"类别", L"NamedPipe" },
        { L"状态", query.io.ok ? IpcSummaryStatusText(response.namedPipeStatus) : L"Use NamedPipe tab" },
        { L"进程", L"<namespace>" },
        { L"Handle/Object", L"\\Device\\NamedPipe" },
        { L"Capability", L"R3 Native + R0 summary" },
        { L"来源", L"命名管道页" },
        { L"Detail", L"切换到 IPC/命名管道子页可执行只读 NT object namespace 枚举。" },
    }));
    result.rows.push_back(Row({
        { L"类别", L"Mailslot" },
        { L"状态", query.io.ok ? IpcSummaryStatusText(response.mailslotStatus) : L"Unavailable" },
        { L"进程", L"<namespace>" },
        { L"Handle/Object", L"\\Device\\Mailslot" },
        { L"Capability", HexText(response.dynDataCapabilityMask) },
        { L"来源", L"R0 IPC summary" },
        { L"Detail", L"当前只读摘要；缺字段时显示 partial/unavailable，不猜测对象布局。" },
    }));
    result.rows.push_back(Row({
        { L"类别", L"SMB" },
        { L"状态", L"Fallback" },
        { L"进程", L"<system/network>" },
        { L"Handle/Object", L"Lanman/Redirector" },
        { L"Capability", L"network stack audit pending" },
        { L"来源", L"docs/pdb_r0_audit_prep/04_network_stack_audit.md" },
        { L"Detail", L"SMB 仅作为 IPC 风险入口提示；本轮不修改 Network 模块，也不新增网络 IOCTL 调用。" },
    }));
    return result;
}

// QueryHookAuditSummary aggregates existing read-only hook/callback audit entry
// points. Input is the UI request; processing queries lightweight capability and
// selected existing collectors; output is a compact routing/status table rather
// than a destructive repair panel.
KernelOperationResult QueryHookAuditSummary(const KernelRequest& request) {
    KernelOperationResult result;
    result.supported = true;
    result.success = true;
    result.message = L"Hook/callback 只读审计入口汇总完成。";

    const KernelRequest callbackRequest{ KernelFeatureId::CallbackEnumeration, request.filterText, request.moduleFilterText, request.flags, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelRequest inlineRequest{ KernelFeatureId::InlineHook, request.filterText, request.moduleFilterText, request.flags | KernelRequestFlagRiskOnly, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelRequest iatEatRequest{ KernelFeatureId::IatEatHook, request.filterText, request.moduleFilterText, request.flags | KernelRequestFlagRiskOnly, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelRequest ssdtRequest{ KernelFeatureId::Ssdt, request.filterText, request.moduleFilterText, request.flags, request.startAddress, request.endAddress, 128, request.idtVectorLimit };
    const KernelOperationResult callbacks = QueryCallbackEnumeration(callbackRequest);
    const KernelOperationResult inlineHooks = QueryInlineHooks(inlineRequest);
    const KernelOperationResult iatEatHooks = QueryIatEatHooks(iatEatRequest);
    const KernelOperationResult ssdt = QuerySsdt(ssdtRequest, false);

    const auto appendSummary = [&](const wchar_t* cls, const wchar_t* entry, const KernelOperationResult& source, const wchar_t* capability) {
        result.success = result.success && source.success;
        result.rows.push_back(Row({
            { L"类别", cls },
            { L"Class", cls },
            { L"入口", entry },
            { L"Entry", entry },
            { L"状态", source.success ? L"OK" : (source.supported ? L"Partial/Failed" : L"Unsupported") },
            { L"Status", source.message },
            { L"Capability", capability },
            { L"Rows", std::to_wstring(source.rows.size()) },
            { L"风险/降级", source.success ? L"只读审计可用" : source.message },
            { L"Detail", source.message },
        }, source.message));
    };

    appendSummary(L"Callback", L"回调遍历", callbacks, L"KSW_CAP_CALLBACK_*");
    appendSummary(L"InlineHook", L"Inline Hook", inlineHooks, L"kernel hook scan");
    appendSummary(L"IAT/EAT", L"IAT/EAT", iatEatHooks, L"import/export scan");
    appendSummary(L"SSDT", L"SSDT", ssdt, L"service table scan");
    result.rows.push_back(Row({
        { L"类别", L"ShadowSSDT" },
        { L"入口", L"ShadowSSDT 子页" },
        { L"状态", L"Available on dedicated tab" },
        { L"Capability", L"win32k/profile gated" },
        { L"Rows", L"-" },
        { L"风险/降级", L"请切换 Hook审计/ShadowSSDT 或原 SSSDT 解析页查看完整行。" },
        { L"Detail", L"摘要页避免一次刷新触发过多 win32k/ShadowSSDT 查询；专页仍保持只读审计。" },
    }));
    return result;
}

KernelOperationResult QueryMinifilterBypassPids(const KernelRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::MinifilterBypassPidResult query = client.queryMinifilterBypassPids();
    KernelOperationResult result;
    ApplyIoSummary(request, L"Minifilter Bypass PIDs", query.io, result);
    result.rows.push_back(Row({
        { L"Version", std::to_wstring(query.response.version) },
        { L"PidCount", std::to_wstring(query.response.pidCount) },
        { L"Flags", HexText(query.response.flags) },
    }));
    const std::uint32_t count = std::min<std::uint32_t>(query.response.pidCount, KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT);
    for (std::uint32_t index = 0; index < count; ++index) {
        const std::uint32_t pid = query.response.processIds[index];
        result.rows.push_back(Row({
            { L"Index", std::to_wstring(index) },
            { L"PID", std::to_wstring(pid) },
            { L"Process", ProcessDisplayName(pid) },
            { L"状态", L"放行" },
            { L"来源", L"R0 minifilter bypass whitelist" },
        }));
    }
    return result;
}

// ExecuteInlineHookNopPatch sends the selected Inline Hook row through
// ArkDriverClient::patchInlineHook. Inputs are row fields from the ListView and
// the force flag controlled by UI confirmation; output includes R0 before/after
// bytes and transport diagnostics.
KernelOperationResult ExecuteInlineHookNopPatch(const KernelActionRequest& request) {
    std::uint64_t functionAddress = 0;
    std::uint32_t hookType = 0;
    if (!ParseUnsigned64(FieldValue(request, L"Address"), functionAddress) ||
        !ParseUnsigned32(FieldValue(request, L"Type"), hookType) ||
        functionAddress == 0) {
        return MakeActionError(request, L"当前行缺少 Inline Hook Address/Type 字段。请先刷新 Inline Hook 页并选择一条真实 Hook 行。");
    }

    std::uint32_t currentByteCount = 0;
    ParseUnsigned32(FieldValue(request, L"CurrentByteCount"), currentByteCount);
    const std::uint32_t availableBytes = currentByteCount != 0 ? currentByteCount : KSWORD_ARK_KERNEL_HOOK_BYTES;
    const std::uint32_t patchBytes = InlinePatchLength(hookType, availableBytes);
    if (patchBytes == 0) {
        return MakeActionError(request, L"当前 Hook 类型不适合自动 NOP 摘除。");
    }

    const ksword::ark::DriverClient client;
    const unsigned long flags = request.force ? KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE : 0UL;
    const std::vector<std::uint8_t> currentBytes = ParseHexByteList(FieldValue(request, L"CurrentBytes"));
    const ksword::ark::KernelInlinePatchResult patch = client.patchInlineHook(
        functionAddress,
        KSWORD_ARK_INLINE_PATCH_MODE_NOP_BRANCH,
        patchBytes,
        currentBytes,
        {},
        flags);

    KernelOperationResult result;
    result.supported = true;
    result.success = patch.io.ok && patch.status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED;
    result.destructiveAction = true;
    result.message = std::wstring(L"Inline Hook NOP 摘除")
        + (request.force ? L"（强制）" : L"")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + Utf8ToWide(patch.io.message);
    result.rows.push_back(Row({
        { L"Action", L"InlineHookNopPatch" },
        { L"Forced", BoolText(request.force) },
        { L"IO", patch.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(patch.io.win32Error) },
        { L"BytesReturned", std::to_wstring(patch.io.bytesReturned) },
        { L"Version", std::to_wstring(patch.version) },
        { L"Status", std::to_wstring(patch.status) },
        { L"BytesPatched", std::to_wstring(patch.bytesPatched) },
        { L"FieldFlags", HexText(patch.fieldFlags) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(patch.lastStatus)) },
        { L"Address", HexText(patch.functionAddress != 0 ? patch.functionAddress : functionAddress) },
        { L"Before", BytesHex(patch.beforeBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) },
        { L"After", BytesHex(patch.afterBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES) },
    }, Utf8ToWide(patch.io.message)));
    return result;
}

// ExecuteCallbackSafeRemove removes one enumerated callback using only the public
// API behavior path. Inputs are selected callback row fields; output reports the
// EX response packet and never uses the experimental unlink behavior.
KernelOperationResult ExecuteCallbackSafeRemove(const KernelActionRequest& request) {
    std::uint32_t callbackClass = 0;
    std::uint64_t callbackAddress = 0;
    std::uint64_t registrationAddress = 0;
    std::uint64_t rawStorageValue = 0;
    std::uint64_t generation = 0;
    std::uint64_t identityHash = 0;
    std::uint32_t source = 0;
    std::uint32_t operationMask = 0;
    std::uint32_t objectTypeMask = 0;
    std::uint32_t trustFlags = 0;
    std::uint32_t removeBehavior = 0;
    if (!ParseUnsigned32(FieldValue(request, L"Class"), callbackClass) ||
        !ParseUnsigned64(FieldValue(request, L"Callback"), callbackAddress) ||
        callbackClass == 0 ||
        callbackAddress == 0) {
        return MakeActionError(request, L"当前行缺少 Callback Enumeration 的 Class/Callback 字段。");
    }
    ParseUnsigned64(FieldValue(request, L"Registration"), registrationAddress);
    ParseUnsigned64(FieldValue(request, L"RawStorageValue"), rawStorageValue);
    ParseUnsigned64(FieldValue(request, L"Generation"), generation);
    ParseUnsigned64(FieldValue(request, L"IdentityHash"), identityHash);
    ParseUnsigned32(FieldValue(request, L"Source"), source);
    ParseUnsigned32(FieldValue(request, L"OperationMask"), operationMask);
    ParseUnsigned32(FieldValue(request, L"ObjectTypeMask"), objectTypeMask);
    ParseUnsigned32(FieldValue(request, L"Trust"), trustFlags);
    ParseUnsigned32(FieldValue(request, L"Remove"), removeBehavior);

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST packet{};
    packet.size = sizeof(packet);
    packet.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    packet.callbackClass = CallbackRemoveTypeForClass(callbackClass);
    if (packet.callbackClass == 0) {
        return MakeActionError(request, L"当前回调类型没有安全公开 API 移除映射。");
    }
    packet.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION;
    packet.callbackAddress = callbackAddress;
    packet.registrationAddress = registrationAddress;
    packet.rawStorageValue = rawStorageValue;
    packet.enumerationGeneration = generation;
    packet.identityHash = identityHash;
    packet.source = source;
    packet.operationMask = operationMask;
    packet.objectTypeMask = objectTypeMask;
    packet.trustFlags = trustFlags;
    packet.removeBehavior = removeBehavior != 0
        ? removeBehavior
        : (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);

    const ksword::ark::DriverClient client;
    const ksword::ark::CallbackRemoveExResult removed = client.removeExternalCallbackEx(packet);
    const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE& response = removed.response;

    KernelOperationResult result;
    result.supported = true;
    result.success = removed.io.ok && response.ntstatus >= 0;
    result.destructiveAction = true;
    result.message = std::wstring(L"Callback 安全移除")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + Utf8ToWide(removed.io.message);
    result.rows.push_back(Row({
        { L"Action", L"CallbackSafeRemove" },
        { L"IO", removed.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(removed.io.win32Error) },
        { L"BytesReturned", std::to_wstring(removed.io.bytesReturned) },
        { L"RequestClass", std::to_wstring(packet.callbackClass) },
        { L"RequestCallback", HexText(packet.callbackAddress) },
        { L"RequestRegistration", HexText(packet.registrationAddress) },
        { L"RequestRawStorageValue", HexText(packet.rawStorageValue) },
        { L"RequestGeneration", HexText(packet.enumerationGeneration) },
        { L"RequestIdentityHash", HexText(packet.identityHash) },
        { L"RequestBehavior", HexText(packet.removeBehavior) },
        { L"RequestBehaviorText", CallbackEnumRemoveBehaviorText(packet.removeBehavior) },
        { L"ResponseClass", std::to_wstring(response.callbackClass) },
        { L"ResponseClassText", CallbackEnumClassText(response.callbackClass) },
        { L"ResponseSource", std::to_wstring(response.source) },
        { L"ResponseSourceText", CallbackEnumSourceText(response.source) },
        { L"Callback", HexText(response.callbackAddress) },
        { L"Registration", HexText(response.registrationAddress) },
        { L"RawStorageValue", HexText(response.rawStorageValue) },
        { L"Generation", HexText(response.enumerationGeneration) },
        { L"IdentityHash", HexText(response.identityHash) },
        { L"NTSTATUS", HexText(static_cast<std::uint32_t>(response.ntstatus)) },
        { L"Revalidation", HexText(static_cast<std::uint32_t>(response.revalidationStatus)) },
        { L"ResponseTrust", HexText(response.trustFlags) },
        { L"ResponseTrustText", CallbackEnumTrustFlagsText(response.trustFlags) },
        { L"ResponseBehavior", HexText(response.removeBehavior) },
        { L"ResponseBehaviorText", CallbackEnumRemoveBehaviorText(response.removeBehavior) },
        { L"Mapping", HexText(response.mappingFlags) },
        { L"MappingText", CallbackEnumMappingText(response.mappingFlags) },
        { L"ModuleBase", HexText(response.moduleBase) },
        { L"ModuleSize", HexText(response.moduleSize) },
        { L"ModulePath", response.modulePath },
        { L"Service", response.serviceName },
        { L"Message", response.message },
    }, Utf8ToWide(removed.io.message)));
    return result;
}


// ExecuteCallbackExperimentalUnlink sends the original KernelDock experimental
// unlink request through ArkDriverClient::removeExternalCallbackEx. Inputs are
// the selected CallbackEnum row fields; processing sets the protocol's explicit
// EXPERIMENTAL_UNLINK flag and behavior bits; output reports the R0 response.
KernelOperationResult ExecuteCallbackExperimentalUnlink(const KernelActionRequest& request) {
    std::uint32_t callbackClass = 0;
    std::uint64_t callbackAddress = 0;
    std::uint64_t registrationAddress = 0;
    std::uint64_t rawStorageValue = 0;
    std::uint64_t generation = 0;
    std::uint64_t identityHash = 0;
    std::uint32_t source = 0;
    std::uint32_t operationMask = 0;
    std::uint32_t objectTypeMask = 0;
    std::uint32_t trustFlags = 0;
    std::uint32_t removeBehavior = 0;
    if (!ParseUnsigned32(FieldValue(request, L"Class"), callbackClass) || callbackClass == 0) {
        return MakeActionError(request, L"当前行缺少 Callback Enumeration 的 Class 字段。");
    }
    ParseUnsigned64(FieldValue(request, L"Callback"), callbackAddress);
    ParseUnsigned64(FieldValue(request, L"Registration"), registrationAddress);
    ParseUnsigned64(FieldValue(request, L"RawStorageValue"), rawStorageValue);
    ParseUnsigned64(FieldValue(request, L"Generation"), generation);
    ParseUnsigned64(FieldValue(request, L"IdentityHash"), identityHash);
    ParseUnsigned32(FieldValue(request, L"Source"), source);
    ParseUnsigned32(FieldValue(request, L"OperationMask"), operationMask);
    ParseUnsigned32(FieldValue(request, L"ObjectTypeMask"), objectTypeMask);
    ParseUnsigned32(FieldValue(request, L"Trust"), trustFlags);
    ParseUnsigned32(FieldValue(request, L"Remove"), removeBehavior);

    const std::uint64_t primaryRemoveValue = rawStorageValue != 0 ? rawStorageValue :
        (registrationAddress != 0 ? registrationAddress : callbackAddress);
    if (primaryRemoveValue == 0) {
        return MakeActionError(request, L"当前行缺少 Callback/Registration/RawStorageValue，无法构造 experimental unlink 请求。");
    }

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST packet{};
    packet.size = sizeof(packet);
    packet.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    packet.callbackClass = CallbackRemoveTypeForClass(callbackClass);
    if (packet.callbackClass == 0) {
        return MakeActionError(request, L"当前回调类型没有 removeExternalCallbackEx 映射，不能发送 experimental unlink。");
    }
    packet.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_EXPERIMENTAL_UNLINK |
        KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION;
    packet.callbackAddress = callbackAddress;
    packet.registrationAddress = registrationAddress;
    packet.rawStorageValue = rawStorageValue;
    packet.enumerationGeneration = generation;
    packet.identityHash = identityHash;
    packet.source = source;
    packet.operationMask = operationMask;
    packet.objectTypeMask = objectTypeMask;
    packet.trustFlags = trustFlags;
    packet.removeBehavior = removeBehavior != 0
        ? (removeBehavior | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION)
        : (KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);

    const ksword::ark::DriverClient client;
    const ksword::ark::CallbackRemoveExResult removed = client.removeExternalCallbackEx(packet);
    const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE& response = removed.response;

    KernelOperationResult result;
    result.supported = true;
    result.success = removed.io.ok && response.ntstatus >= 0;
    result.destructiveAction = true;
    result.message = std::wstring(L"Callback experimental unlink ")
        + (result.success ? L"完成。" : L"未完成或被 R0 拒绝。")
        + L" "
        + Utf8ToWide(removed.io.message);
    result.rows.push_back(Row({
        { L"Action", L"CallbackExperimentalUnlink" },
        { L"IO", removed.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(removed.io.win32Error) },
        { L"BytesReturned", std::to_wstring(removed.io.bytesReturned) },
        { L"RequestClass", std::to_wstring(packet.callbackClass) },
        { L"RequestFlags", HexText(packet.flags) },
        { L"RequestCallback", HexText(packet.callbackAddress) },
        { L"RequestRegistration", HexText(packet.registrationAddress) },
        { L"RequestRawStorageValue", HexText(packet.rawStorageValue) },
        { L"RequestGeneration", HexText(packet.enumerationGeneration) },
        { L"RequestIdentityHash", HexText(packet.identityHash) },
        { L"RequestBehavior", HexText(packet.removeBehavior) },
        { L"RequestBehaviorText", CallbackEnumRemoveBehaviorText(packet.removeBehavior) },
        { L"ResponseClass", std::to_wstring(response.callbackClass) },
        { L"ResponseClassText", CallbackEnumClassText(response.callbackClass) },
        { L"ResponseSource", std::to_wstring(response.source) },
        { L"ResponseSourceText", CallbackEnumSourceText(response.source) },
        { L"Callback", HexText(response.callbackAddress) },
        { L"Registration", HexText(response.registrationAddress) },
        { L"RawStorageValue", HexText(response.rawStorageValue) },
        { L"Generation", HexText(response.enumerationGeneration) },
        { L"IdentityHash", HexText(response.identityHash) },
        { L"NTSTATUS", HexText(static_cast<std::uint32_t>(response.ntstatus)) },
        { L"Revalidation", HexText(static_cast<std::uint32_t>(response.revalidationStatus)) },
        { L"ResponseTrust", HexText(response.trustFlags) },
        { L"ResponseTrustText", CallbackEnumTrustFlagsText(response.trustFlags) },
        { L"ResponseBehavior", HexText(response.removeBehavior) },
        { L"ResponseBehaviorText", CallbackEnumRemoveBehaviorText(response.removeBehavior) },
        { L"Mapping", HexText(response.mappingFlags) },
        { L"MappingText", CallbackEnumMappingText(response.mappingFlags) },
        { L"ModuleBase", HexText(response.moduleBase) },
        { L"ModuleSize", HexText(response.moduleSize) },
        { L"ModulePath", response.modulePath },
        { L"Service", response.serviceName },
        { L"Message", response.message },
    }, Utf8ToWide(removed.io.message)));
    return result;
}

// ExecuteCallbackRuntimeControl performs page-level callback runtime operations.
// Inputs are action id and current filter text; processing goes only through
// ArkDriverClient callback APIs; output contains the action transport result and
// a fresh runtime snapshot so operators can verify the new state immediately.
KernelOperationResult ExecuteCallbackRuntimeControl(const KernelActionRequest& request) {
    const ksword::ark::DriverClient client;
    ksword::ark::IoResult io{};
    const wchar_t* actionName = L"CallbackUnknown";
    std::vector<std::uint8_t> blob;

    if (request.actionId == KernelActionId::CallbackCancelPendingDecisions) {
        actionName = L"CallbackCancelPendingDecisions";
        io = client.cancelAllPendingCallbackDecisions();
    } else if (request.actionId == KernelActionId::CallbackApplyDisabledEmptyRules) {
        actionName = L"CallbackApplyDisabledEmptyRules";
        const ksword::ark::CallbackRuntimeResult before = client.queryCallbackRuntimeState();
        const std::uint64_t nextRuleVersion = before.io.ok && before.state.appliedRuleVersion != 0
            ? before.state.appliedRuleVersion + 1ULL
            : CurrentUtc100ns();
        blob = BuildDisabledCallbackRuleBlob(nextRuleVersion);
        io = client.setCallbackRules(blob.data(), static_cast<unsigned long>(blob.size()));
    } else if (request.actionId == KernelActionId::CallbackApplyLocalRules) {
        actionName = L"CallbackApplyLocalRules";
        LocalCallbackRuleDocument document;
        std::wstring parseError;
        if (!ParseLocalCallbackRuleDocument(request.moduleFilterText, document, parseError)) {
            return MakeActionError(request, L"本地 Callback 规则解析失败：" + parseError);
        }
        const ksword::ark::CallbackRuntimeResult before = client.queryCallbackRuntimeState();
        const std::uint64_t nextRuleVersion = before.io.ok && before.state.appliedRuleVersion != 0
            ? before.state.appliedRuleVersion + 1ULL
            : CurrentUtc100ns();
        blob = BuildCallbackRuleBlob(document, nextRuleVersion);
        io = client.setCallbackRules(blob.data(), static_cast<unsigned long>(blob.size()));
    } else {
        return MakeActionError(request, L"未知 CallbackIntercept 动作。");
    }

    KernelOperationResult result;
    result.supported = true;
    result.success = io.ok;
    result.destructiveAction = true;
    result.message = std::wstring(actionName)
        + (io.ok ? L" 完成。" : L" 失败。")
        + L" "
        + Utf8ToWide(io.message);
    result.rows.push_back(Row({
        { L"Action", actionName },
        { L"IO", io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(io.win32Error) },
        { L"BytesReturned", std::to_wstring(io.bytesReturned) },
        { L"BlobBytes", std::to_wstring(blob.size()) },
        { L"Source", request.actionId == KernelActionId::CallbackApplyLocalRules ? L"LocalRules" : L"RuntimeControl" },
    }, Utf8ToWide(io.message)));

    const ksword::ark::CallbackRuntimeResult after = client.queryCallbackRuntimeState();
    result.rows.push_back(Row({
        { L"Action", L"CallbackRuntimeRefresh" },
        { L"IO", after.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(after.io.win32Error) },
        { L"BytesReturned", std::to_wstring(after.io.bytesReturned) },
    }, Utf8ToWide(after.io.message)));
    AppendCallbackRuntimeRows(result, after.state, request.filterText, L"AfterAction");
    return result;
}

// ParseCallbackEventGuid validates the compact hexadecimal GUID sent by the
// Win32 callback receiver. Input accepts only 32 hex digits so a UI row cannot
// inject an arbitrary binary answer packet into the driver call.
bool ParseCallbackEventGuid(const std::wstring& text, KSWORD_ARK_GUID128& guidOut) {
    std::wstring compact;
    compact.reserve(32);
    for (const wchar_t ch : text) {
        if (ch != L'-' && ch != L'{' && ch != L'}') {
            if (!std::iswxdigit(ch)) {
                return false;
            }
            compact.push_back(ch);
        }
    }
    if (compact.size() != 32U) {
        return false;
    }
    for (std::size_t index = 0; index < sizeof(guidOut.bytes); ++index) {
        const auto digit = [](const wchar_t ch) -> int {
            if (ch >= L'0' && ch <= L'9') return ch - L'0';
            if (ch >= L'a' && ch <= L'f') return 10 + ch - L'a';
            return 10 + ch - L'A';
        };
        guidOut.bytes[index] = static_cast<unsigned char>((digit(compact[index * 2U]) << 4U) | digit(compact[index * 2U + 1U]));
    }
    return true;
}

// ExecuteCallbackAnswerEvent sends one explicit allow/deny decision received by
// the background wait loop. The caller supplies the event GUID and session only
// after an operator confirmation; this function performs no implicit fallback.
KernelOperationResult ExecuteCallbackAnswerEvent(const KernelActionRequest& request) {
    KSWORD_ARK_CALLBACK_ANSWER_REQUEST answer{};
    if (!ParseCallbackEventGuid(FieldValue(request, L"EventGuid"), answer.eventGuid)) {
        return MakeActionError(request, L"待决策事件 GUID 无效，已拒绝向驱动发送应答。" );
    }
    std::uint32_t sourceSessionId = 0;
    if (!ParseUnsigned32(FieldValue(request, L"SourceSessionId"), sourceSessionId)) {
        return MakeActionError(request, L"待决策事件缺少有效 SourceSessionId。" );
    }
    const std::wstring decisionText = FieldValue(request, L"Decision");
    const bool deny = decisionText == L"Deny";
    if (!deny && decisionText != L"Allow") {
        return MakeActionError(request, L"待决策事件的允许/拒绝动作无效。" );
    }
    answer.size = sizeof(answer);
    answer.version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    answer.decision = deny ? KSWORD_ARK_DECISION_DENY : KSWORD_ARK_DECISION_ALLOW;
    answer.sourceSessionId = sourceSessionId;
    answer.answeredAtUtc100ns = CurrentUtc100ns();

    const ksword::ark::DriverClient client;
    const ksword::ark::IoResult io = client.answerCallbackEvent(answer);
    KernelOperationResult result;
    result.supported = true;
    result.success = io.ok;
    result.destructiveAction = true;
    result.message = std::wstring(L"Callback 待决策应答 ") + (deny ? L"拒绝" : L"允许") +
        (io.ok ? L"完成。" : L"失败。") + L" " + Utf8ToWide(io.message);
    result.rows.push_back(Row({
        { L"Action", L"CallbackAnswerEvent" },
        { L"Decision", deny ? L"Deny" : L"Allow" },
        { L"EventGuid", FieldValue(request, L"EventGuid") },
        { L"SourceSessionId", std::to_wstring(sourceSessionId) },
        { L"IO", io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(io.win32Error) },
        { L"BytesReturned", std::to_wstring(io.bytesReturned) },
    }, Utf8ToWide(io.message)));
    return result;
}

// ExecuteSetMinifilterBypassPids writes the minifilter bypass PID list through
// ArkDriverClient. Inputs are PIDs typed into the generic filter box; output
// includes the new R0 whitelist snapshot when the write succeeds.
KernelOperationResult ExecuteSetMinifilterBypassPids(const KernelActionRequest& request) {
    const std::vector<std::uint32_t> pids = request.actionId == KernelActionId::MinifilterClearBypassPids
        ? std::vector<std::uint32_t>{}
        : ParsePidList(request.filterText);
    if (request.actionId == KernelActionId::MinifilterSetBypassPids && pids.empty()) {
        return MakeActionError(request, L"请在“过滤/起点”输入 PID 列表，例如：1234,5678。");
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::IoResult io = client.setMinifilterBypassPids(pids);
    KernelOperationResult result;
    result.supported = true;
    result.success = io.ok;
    result.destructiveAction = true;
    result.message = std::wstring(L"Minifilter bypass PID 列表写入")
        + (io.ok ? L"完成。" : L"失败。")
        + L" "
        + Utf8ToWide(io.message);
    result.rows.push_back(Row({
        { L"Action", request.actionId == KernelActionId::MinifilterClearBypassPids ? L"MinifilterClearBypassPids" : L"MinifilterSetBypassPids" },
        { L"IO", io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(io.win32Error) },
        { L"BytesReturned", std::to_wstring(io.bytesReturned) },
        { L"PidCount", std::to_wstring(pids.size()) },
    }, Utf8ToWide(io.message)));
    for (std::size_t index = 0; index < pids.size(); ++index) {
        result.rows.push_back(Row({
            { L"Index", std::to_wstring(index) },
            { L"PID", std::to_wstring(pids[index]) },
        }));
    }
    return result;
}

// ExecuteFileMonitorControl mirrors the original CallbackIntercept file-monitor
// buttons. Inputs are the selected action; processing goes through
// ArkDriverClient and emits table rows for the Win32 panel; output is rendered
// by the normal result pipeline.
// ActionRowField reads one field out of the selected row snapshot. Inputs are the
// request and the candidate column names; output is empty when the row does not
// carry any of them.
std::wstring ActionRowField(const KernelActionRequest& request, const std::vector<std::wstring>& names) {
    for (const std::wstring& name : names) {
        for (const auto& field : request.rowFields) {
            if (field.first == name) {
                return field.second;
            }
        }
    }
    return {};
}

// ParseHexOrDecimal accepts both the "0x..." form the tables print and a plain
// decimal, because a user retyping a value by hand rarely reproduces the prefix.
std::uint64_t ParseHexOrDecimal(const std::wstring& text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::iswspace(text[begin]) != 0) {
        ++begin;
    }
    std::size_t end = text.size();
    while (end > begin && std::iswspace(text[end - 1]) != 0) {
        --end;
    }
    const std::wstring trimmed = text.substr(begin, end - begin);
    if (trimmed.empty()) {
        return 0;
    }
    try {
        if (trimmed.size() > 2 && trimmed[0] == L'0' && (trimmed[1] == L'x' || trimmed[1] == L'X')) {
            return std::stoull(trimmed.substr(2), nullptr, 16);
        }
        return std::stoull(trimmed, nullptr, 10);
    } catch (const std::exception&) {
        return 0;
    }
}

// ExecuteNetworkCaptureControl starts or stops the R0 per-packet capture ring.
// Starting it makes the driver copy packet headers into a fixed non-paged ring;
// that ring is bounded, so leaving capture on does not grow without limit, but it
// does keep the WFP callout doing work for every packet.
KernelOperationResult ExecuteNetworkCaptureControl(const KernelActionRequest& request) {
    const ksword::ark::DriverClient client;
    const bool enable = request.actionId == KernelActionId::NetworkCaptureStart;
    KernelOperationResult result;
    result.supported = true;
    // Stopping is not destructive: the ring keeps whatever it already holds and
    // stays readable, only new packets stop arriving.
    result.destructiveAction = false;

    const ksword::ark::NetworkTrafficCaptureControlResult control = client.controlNetworkTrafficCapture(enable);
    result.success = control.io.ok && !control.unsupported;
    if (control.unsupported) {
        result.message = L"当前 KswordARK 驱动未注册逐包捕获控制 IOCTL，无法" +
            std::wstring(enable ? L"启动" : L"停止") + L"。请勿据此认为 R0 已停止采集。";
    } else {
        result.message = std::wstring(enable ? L"逐包捕获启动" : L"逐包捕获停止") +
            (control.io.ok ? L"完成。" : L"失败。") + L" " + Utf8ToWide(control.io.message);
    }
    result.rows.push_back(Row({
        { L"Section", L"NetworkTraffic" },
        { L"Action", enable ? L"StartCapture" : L"StopCapture" },
        { L"Status", control.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", BoolText(control.unsupported) },
        { L"Win32", std::to_wstring(control.io.win32Error) },
    }, L"The capture ring is a fixed non-paged buffer, so an enabled capture cannot grow without bound; "
       L"what it does cost is per-packet work in the WFP callout. An unsupported result must not be read "
       L"as 'capture is off' -- the driver simply never answered the question."));
    return result;
}

// ExecutePiDdbDeleteEntry removes one PiDDBCacheTable record. This erases the
// loader's evidence that a driver was ever vetted on this machine, which is
// exactly why it is gated behind a confirmation and reports the matched entry
// back: an operator should be able to see what was removed after the fact.
KernelOperationResult ExecutePiDdbDeleteEntry(const KernelActionRequest& request) {
    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = true;

    ksword::ark::PiDdbEntry expected{};
    expected.driverName = ActionRowField(request, { L"Driver", L"驱动" });
    expected.entryAddress = ParseHexOrDecimal(ActionRowField(request, { L"Entry", L"条目地址" }));
    expected.timeDateStamp =
        static_cast<std::uint32_t>(ParseHexOrDecimal(ActionRowField(request, { L"TimeDateStamp", L"时间戳" })));
    expected.loadStatus =
        static_cast<long>(ParseHexOrDecimal(ActionRowField(request, { L"LoadStatus", L"加载状态" })));

    if (expected.entryAddress == 0 || expected.driverName.empty()) {
        result.success = false;
        result.message = L"未能从选中行还原 PiDDB 条目（需要驱动名与条目地址），已放弃删除。";
        return result;
    }

    const ksword::ark::DriverClient client;
    // The expected entry is passed through so R0 can verify the slot still holds
    // what the UI showed; force stays false, so a slot that changed underneath is
    // refused rather than overwritten blind.
    const ksword::ark::PiDdbDeleteResult remove = client.deletePiDdbEntry(expected, request.force, true);
    result.success = remove.io.ok && !remove.unsupported;
    if (remove.unsupported) {
        result.message = L"当前 KswordARK 驱动未注册 PiDDB 删除 IOCTL。";
    } else {
        result.message = std::wstring(L"PiDDB 条目删除") + (result.success ? L"完成。" : L"失败。") +
            L" " + Utf8ToWide(remove.io.message);
    }
    result.rows.push_back(Row({
        { L"Section", L"PiDDB" },
        { L"Action", L"DeleteEntry" },
        { L"Status", remove.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", BoolText(remove.unsupported) },
        { L"DeleteStatus", HexText(remove.status) },
        { L"RemainingRows", std::to_wstring(remove.remainingRows) },
        { L"RequestedDriver", expected.driverName },
        { L"RequestedEntry", HexText(expected.entryAddress) },
        { L"MatchedDriver", remove.matchedEntry.driverName },
        { L"MatchedEntry", HexText(remove.matchedEntry.entryAddress) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(remove.lastStatus)) },
    }, L"The entry the UI displayed is sent along so R0 can confirm the slot still matches before "
       L"removing it; without force a slot that changed in between is refused instead of overwritten. "
       L"Removing a record erases the loader's evidence that this driver was ever vetted here."));
    return result;
}

// DriverRecoveryIdentity is the target a restore/abandon addresses. Every field
// is read back out of the row the user selected rather than retyped, because
// these protocols verify identity and generation before touching anything: a
// hand-entered value that no longer matches is refused, which looks like a bug
// but is the protocol working.
struct DriverRecoveryIdentity {
    std::uint64_t moduleBase = 0;
    std::uint64_t driverObjectAddress = 0;
    std::uint32_t generation = 0;
    unsigned long majorFunction = 0;
    unsigned long fieldMask = 0;
    std::wstring driverName;
    bool valid = false;
};

DriverRecoveryIdentity BuildDriverRecoveryIdentity(const KernelActionRequest& request) {
    DriverRecoveryIdentity identity;
    identity.driverName = request.filterText;
    identity.moduleBase = ParseHexOrDecimal(ActionRowField(request, { L"ModuleBase", L"DriverStart" }));
    identity.driverObjectAddress = ParseHexOrDecimal(ActionRowField(request, { L"DriverObject" }));
    identity.generation = static_cast<std::uint32_t>(ParseHexOrDecimal(ActionRowField(request, { L"Generation" })));
    identity.majorFunction = static_cast<unsigned long>(ParseHexOrDecimal(ActionRowField(request, { L"MajorFunction" })));
    identity.fieldMask = static_cast<unsigned long>(ParseHexOrDecimal(ActionRowField(request, { L"ManagedFields" })));
    identity.valid = identity.moduleBase != 0 || !identity.driverName.empty();
    return identity;
}

KernelOperationResult MakeRecoveryPrompt(const wchar_t* label) {
    KernelOperationResult result;
    result.supported = true;
    result.success = false;
    result.message = std::wstring(label) + L"：请先查询目标驱动并选中结果行，动作需要行内的模块基址与代次。";
    return result;
}

// ExecuteDriverDispatchRecovery restores one MajorFunction slot to its recorded
// original, or abandons the restore record while leaving the current value in
// place. Abandon is the more dangerous of the two despite touching nothing: it
// throws away the only record of what the slot used to be.
KernelOperationResult ExecuteDriverDispatchRecovery(const KernelActionRequest& request) {
    const DriverRecoveryIdentity identity = BuildDriverRecoveryIdentity(request);
    const bool restore = request.actionId == KernelActionId::DriverDispatchRestore;
    if (!identity.valid) {
        return MakeRecoveryPrompt(restore ? L"恢复驱动派遣槽" : L"放弃派遣恢复记录");
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::DriverDispatchControlResult control = restore
        ? client.restoreDriverDispatch(
            identity.moduleBase, identity.driverName, identity.majorFunction,
            identity.driverObjectAddress, identity.generation)
        : client.abandonDriverDispatch(
            identity.moduleBase, identity.driverName, identity.majorFunction,
            identity.driverObjectAddress, identity.generation);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = !restore;
    result.success = control.io.ok && !control.unsupported;
    result.message = std::wstring(restore ? L"派遣槽恢复" : L"派遣恢复记录放弃") +
        (result.success ? L"完成。" : L"失败。") + L" " + Utf8ToWide(control.io.message);
    result.rows.push_back(Row({
        { L"Section", L"DriverDispatch" },
        { L"Action", restore ? L"Restore" : L"Abandon" },
        { L"Status", control.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", BoolText(control.unsupported) },
        { L"MajorFunction", HexText(control.majorFunction) },
        { L"State", std::to_wstring(control.state) },
        { L"Generation", std::to_wstring(control.generation) },
        { L"Current", HexText(control.currentDispatchAddress) },
        { L"Original", HexText(control.originalDispatchAddress) },
        { L"ResponseFlags", HexText(control.responseFlags) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(control.lastStatus)) },
    }, L"Restore writes the recorded original back into the slot. Abandon changes nothing in the kernel "
       L"but permanently drops the record of what the original was, so a later restore becomes "
       L"impossible. The generation is checked first: if someone else altered the slot in between, the "
       L"request is refused rather than applied on top."));
    return result;
}

// ExecuteDriverImageRecovery restores the LDR image fields this driver still
// holds records for, or drops those records. The field mask comes from the row's
// ManagedFields so a restore covers exactly what was actually changed.
KernelOperationResult ExecuteDriverImageRecovery(const KernelActionRequest& request) {
    const DriverRecoveryIdentity identity = BuildDriverRecoveryIdentity(request);
    const bool restore = request.actionId == KernelActionId::DriverImageRestore;
    if (!identity.valid) {
        return MakeRecoveryPrompt(restore ? L"恢复驱动镜像字段" : L"放弃镜像恢复记录");
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::DriverImageControlResult control = restore
        ? client.restoreDriverImage(
            identity.moduleBase, identity.driverName, identity.fieldMask, true,
            identity.driverObjectAddress, identity.generation)
        : client.abandonDriverImage(
            identity.moduleBase, identity.driverName,
            identity.driverObjectAddress, identity.generation);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = !restore;
    result.success = control.io.ok && !control.unsupported;
    result.message = std::wstring(restore ? L"镜像字段恢复" : L"镜像恢复记录放弃") +
        (result.success ? L"完成。" : L"失败。") + L" " + Utf8ToWide(control.io.message);
    result.rows.push_back(Row({
        { L"Section", L"DriverImage" },
        { L"Action", restore ? L"Restore" : L"Abandon" },
        { L"Status", control.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", BoolText(control.unsupported) },
        { L"RequestedMask", HexText(identity.fieldMask) },
        { L"ManagedFields", HexText(control.managedFieldMask) },
        { L"OwnedFields", HexText(control.ownedFieldMask) },
        { L"ConflictFields", HexText(control.conflictFieldMask) },
        { L"ChangedFields", HexText(control.changedFieldMask) },
        { L"State", std::to_wstring(control.state) },
        { L"Generation", std::to_wstring(control.generation) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(control.lastStatus)) },
    }, L"The restore mask comes from the row's ManagedFields, so it covers exactly the fields this "
       L"driver actually changed. A field listed in conflictFieldMask was rewritten by a third party "
       L"since — the recorded original is no longer what that field held before, and restoring it would "
       L"overwrite someone else's value."));
    return result;
}

// ExecuteDriverCommunicationRestore points a driver's dispatch surface back at
// its own handlers after it was aimed at the system reject entry.
KernelOperationResult ExecuteDriverCommunicationRestore(const KernelActionRequest& request) {
    const DriverRecoveryIdentity identity = BuildDriverRecoveryIdentity(request);
    if (!identity.valid) {
        return MakeRecoveryPrompt(L"恢复驱动通信");
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::DriverCommunicationControlResult control =
        client.restoreDriverCommunication(identity.moduleBase, identity.driverName);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = false;
    result.success = control.io.ok;
    result.message = std::wstring(L"驱动通信恢复") + (result.success ? L"完成。" : L"失败。") +
        L" " + Utf8ToWide(control.io.message);
    result.rows.push_back(Row({
        { L"Section", L"DriverCommunication" },
        { L"Action", L"Restore" },
        { L"Status", control.io.ok ? L"OK" : L"FAIL" },
        { L"State", std::to_wstring(control.state) },
        { L"TargetedMask", HexText(control.targetedMask) },
        { L"ActiveMask", HexText(control.activeMask) },
        { L"OwnedMask", HexText(control.ownedMask) },
        { L"ConflictMask", HexText(control.conflictMask) },
        { L"ChangedMask", HexText(control.changedMask) },
        { L"Generation", std::to_wstring(control.generation) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(control.lastStatus)) },
    }, L"Only the slots in ownedMask are restored — those are the ones this driver redirected and can "
       L"still account for. Slots in conflictMask were rewritten by someone else and are deliberately "
       L"left alone rather than reset to a value that is no longer theirs."));
    return result;
}

KernelOperationResult ExecuteFileMonitorControl(const KernelActionRequest& request) {
    const ksword::ark::DriverClient client;
    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = request.actionId == KernelActionId::FileMonitorClear;

    if (request.actionId == KernelActionId::FileMonitorStartFsctl) {
        const ksword::ark::FileMonitorStatusResult before = client.queryFileMonitorStatus();
        unsigned long requestedMask = KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL;
        if (before.io.ok) {
            requestedMask |= before.operationMask;
        }
        const ksword::ark::IoResult io = client.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_START, requestedMask, 0UL, 0UL);
        result.success = io.ok;
        result.message = std::wstring(L"FSCTL 文件监控启动") + (io.ok ? L"完成。" : L"失败。") + L" " + Utf8ToWide(io.message);
        result.rows.push_back(Row({
            { L"Section", L"FileMonitor" },
            { L"Action", L"StartFsctl" },
            { L"Status", io.ok ? L"OK" : L"FAIL" },
            { L"OperationMask", HexText(requestedMask) },
            { L"Win32", std::to_wstring(io.win32Error) },
        }, Utf8ToWide(io.message)));
    } else if (request.actionId == KernelActionId::FileMonitorClear) {
        const ksword::ark::IoResult io = client.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_CLEAR, KSWORD_ARK_FILE_MONITOR_OPERATION_ALL, 0UL, 0UL);
        result.success = io.ok;
        result.message = std::wstring(L"文件监控队列清空") + (io.ok ? L"完成。" : L"失败。") + L" " + Utf8ToWide(io.message);
        result.rows.push_back(Row({
            { L"Section", L"FileMonitor" },
            { L"Action", L"Clear" },
            { L"Status", io.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(io.win32Error) },
        }, Utf8ToWide(io.message)));
    }

    if (request.actionId == KernelActionId::FileMonitorDrain ||
        request.actionId == KernelActionId::FileMonitorStartFsctl ||
        request.actionId == KernelActionId::FileMonitorClear) {
        const ksword::ark::FileMonitorDrainResult drain = client.drainFileMonitor(128UL, 0UL);
        result.success = result.success || drain.io.ok;
        if (result.message.empty()) {
            result.message = std::wstring(L"文件监控事件拉取") + (drain.io.ok ? L"完成。" : L"失败。") + L" " + Utf8ToWide(drain.io.message);
        }
        result.rows.push_back(Row({
            { L"Section", L"FileMonitor" },
            { L"Action", L"Drain" },
            { L"Status", drain.io.ok ? L"OK" : L"FAIL" },
            { L"Returned", std::to_wstring(drain.returnedCount) },
            { L"Parsed", std::to_wstring(drain.events.size()) },
            { L"QueuedBefore", std::to_wstring(drain.totalQueuedBeforeDrain) },
            { L"Dropped", std::to_wstring(drain.droppedCount) },
            { L"Win32", std::to_wstring(drain.io.win32Error) },
        }, Utf8ToWide(drain.io.message)));
        for (const ksword::ark::FileMonitorEventRow& event : drain.events) {
            const bool fsctlEvent = (event.operationType & KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL) != 0U;
            const bool pathPresent = (event.fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_PATH_PRESENT) != 0U;
            const bool pathTruncated = (event.fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_PATH_TRUNCATED) != 0U;
            const std::wstring pathState = pathTruncated
                ? L"截断"
                : pathPresent
                    ? L"完整"
                    : L"未确认";
            PushFilteredRow(result, Row({
                { L"Section", L"FileEvent" },
                { L"Time", Utc100nsToLocalText(static_cast<std::uint64_t>(event.timeUtc100ns)) },
                { L"TimeRaw", HexText(static_cast<std::uint64_t>(event.timeUtc100ns)) },
                { L"PID", std::to_wstring(event.processId) },
                { L"Process", ProcessDisplayName(event.processId) },
                { L"Path", event.path },
                { L"PathState", pathState },
                { L"PathLength", std::to_wstring(event.pathLengthChars) },
                { L"FieldFlags", HexText(event.fieldFlags) },
                { L"FsctlName", fsctlEvent ? std::wstring(KswordARKFileMonitorFsctlCodeToText(event.fsControlCode)) : L"-" },
                { L"ControlCode", fsctlEvent ? HexText(event.fsControlCode) : L"-" },
                { L"Status", fsctlEvent ? HexText(static_cast<std::uint32_t>(event.resultStatus)) : L"-" },
                { L"FileObject", HexText(event.fileObjectAddress) },
                { L"InputLength", fsctlEvent ? std::to_wstring(event.fsInputBufferLength) : L"-" },
                { L"OutputLength", fsctlEvent ? std::to_wstring(event.fsOutputBufferLength) : L"-" },
                { L"Operation", HexText(event.operationType) },
                { L"Major", std::to_wstring(event.majorFunction) },
                { L"Minor", std::to_wstring(event.minorFunction) },
                { L"TID", std::to_wstring(event.threadId) },
            }), request.filterText);
        }
    }
    return result;
}

// ExecuteDriverObjectQueryDetail resolves the selected Device/DriverObjects row
// to a canonical DriverObject name and performs a focused R0 query. Inputs are
// selected row text fields; processing goes through ArkDriverClient only; output
// is the same generic row model used by normal refresh results.
KernelOperationResult ExecuteDriverObjectQueryDetail(const KernelActionRequest& request) {
    const std::wstring driverName = DriverObjectNameFromActionRequest(request);
    if (driverName.empty()) {
        return MakeActionError(request, L"当前行不是可解析的 \\Driver\\Name 或 R0 DriverObject 行。");
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::DriverObjectQueryResult query = client.queryDriverObject(
        driverName,
        KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
        KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
        KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);

    KernelOperationResult result;
    result.supported = true;
    result.success = IsDriverObjectQuerySuccess(query);
    result.destructiveAction = false;
    result.message = std::wstring(L"DriverObject 详情查询")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + Utf8ToWide(query.io.message);
    result.rows.push_back(Row({
        { L"Action", L"DriverObjectQueryDetail" },
        { L"Request", driverName },
        { L"IO", query.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(query.io.win32Error) },
        { L"BytesReturned", std::to_wstring(query.io.bytesReturned) },
        { L"QueryStatus", std::wstring(DriverObjectQueryStatusText(query.queryStatus)) + L" (" + std::to_wstring(query.queryStatus) + L")" },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(query.lastStatus)) },
    }, Utf8ToWide(query.io.message)));
    AppendDriverObjectQueryRows(driverName, query, result);
    return result;
}

// ExecuteDriverObjectForceUnload requests the R0 DriverObject force-unload path
// for the selected driver row. Inputs are selected row text fields; processing
// asks ArkDriverClient to call the shared IOCTL; output reports every returned
// status field so the UI does not hide partial cleanup/failure details.
KernelOperationResult ExecuteDriverObjectForceUnload(const KernelActionRequest& request) {
    const std::wstring driverName = DriverObjectNameFromActionRequest(request);
    const std::uint64_t moduleBase = DriverModuleBaseFromActionRequest(request);
    if (driverName.empty() && moduleBase == 0ULL) {
        return MakeActionError(request, L"当前行没有可卸载的 \\Driver\\Name 或模块基址。请先查询 R0 DriverObject 详情。 ");
    }

    const ksword::ark::DriverClient client;
    const ksword::ark::DriverForceUnloadResult unload = moduleBase != 0ULL
        ? client.forceUnloadDriverByModuleBase(moduleBase, driverName, 0UL, 3000UL)
        : client.forceUnloadDriver(driverName, 0UL, 3000UL);

    KernelOperationResult result;
    result.supported = true;
    result.success = unload.io.ok && DriverUnloadSucceeded(unload.status);
    result.destructiveAction = true;
    result.message = std::wstring(L"DriverObject 强制卸载")
        + (result.success ? L"完成。" : L"未完成。")
        + L" "
        + Utf8ToWide(unload.io.message);
    result.rows.push_back(Row({
        { L"Action", L"DriverObjectForceUnload" },
        { L"Request", driverName },
        { L"ModuleBase", HexText(moduleBase) },
        { L"Resolution", moduleBase != 0ULL ? L"ModuleBase" : L"DriverName" },
        { L"IO", unload.io.ok ? L"OK" : L"FAIL" },
        { L"Win32", std::to_wstring(unload.io.win32Error) },
        { L"BytesReturned", std::to_wstring(unload.io.bytesReturned) },
        { L"Version", std::to_wstring(unload.version) },
        { L"Status", std::wstring(DriverUnloadStatusText(unload.status)) + L" (" + std::to_wstring(unload.status) + L")" },
        { L"Flags", HexText(unload.flags) },
        { L"DriverName", unload.driverName.empty() ? driverName : unload.driverName },
        { L"DriverObject", HexText(unload.driverObjectAddress) },
        { L"DriverUnload", HexText(unload.driverUnloadAddress) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(unload.lastStatus)) },
        { L"WaitStatus", HexText(static_cast<std::uint32_t>(unload.waitStatus)) },
        { L"CleanupFlagsApplied", HexText(unload.cleanupFlagsApplied) },
        { L"DeletedDeviceCount", std::to_wstring(unload.deletedDeviceCount) },
        { L"CallbackCandidates", std::to_wstring(unload.callbackCandidates) },
        { L"CallbacksRemoved", std::to_wstring(unload.callbacksRemoved) },
        { L"CallbackFailures", std::to_wstring(unload.callbackFailures) },
        { L"CallbackLastStatus", HexText(static_cast<std::uint32_t>(unload.callbackLastStatus)) },
    }, Utf8ToWide(unload.io.message)));
    return result;
}

// ExecuteDynDataApplyMatchedProfile finds the current ntoskrnl PDB profile and
// sends it to R0 through ArkDriverClient. Inputs are the action request and
// current driver identity read from DynData status; processing never opens the
// KswordARK device directly; output reports match metadata plus the driver apply
// response so the UI can diagnose rejected/unknown fields precisely.
KernelOperationResult ExecuteDynDataApplyMatchedProfile(const KernelActionRequest& request) {
    const ksword::ark::DriverClient client;
    const ksword::ark::DynDataStatusResult status = client.queryDynDataStatus();
    if (!status.io.ok) {
        KernelOperationResult result;
        result.supported = true;
        result.success = false;
        result.destructiveAction = true;
        result.message = L"DynData status 查询失败，无法匹配并应用本地 profile。 " + Utf8ToWide(status.io.message);
        result.rows.push_back(Row({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Stage", L"QueryDynDataStatus" },
            { L"IO", status.io.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(status.io.win32Error) },
            { L"BytesReturned", std::to_wstring(status.io.bytesReturned) },
        }, Utf8ToWide(status.io.message)));
        return result;
    }

    const DynDataProfileMatch match = FindMatchingDynDataProfile(status.ntoskrnl);
    if (!match.valid) {
        KernelOperationResult result;
        result.supported = true;
        result.success = false;
        result.destructiveAction = true;
        result.message = L"没有可应用的匹配 DynData profile。 " + match.message;
        result.rows.push_back(Row({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Stage", L"MatchLocalProfile" },
            { L"Matched", match.matched ? L"是" : L"否" },
            { L"Valid", match.valid ? L"是" : L"否" },
            { L"ProfilePath", match.path },
            { L"ExistingPacks", std::to_wstring(match.existingPackCount) },
            { L"ScannedProfiles", std::to_wstring(match.scannedProfileCount) },
        }, match.message));
        AppendDynDataProfileRows(result, match, request.filterText);
        return result;
    }

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = true;
    result.success = true;
    bool appliedAnyLayer = false;
    const auto appendLayerMessage = [&result](const std::wstring& message) {
        if (!result.message.empty()) {
            result.message += L" | ";
        }
        result.message += message;
    };

    if (!match.profile.fields.empty()) {
        appliedAnyLayer = true;
        const ksword::ark::DynDataProfileApplyResult applied = client.applyDynDataProfile(match.profile);
        const bool layerSucceeded =
            applied.io.ok &&
            applied.status >= 0 &&
            applied.rejectedFieldCount == 0 &&
            applied.unknownFieldCount == 0;
        result.success = result.success && layerSucceeded;
        appendLayerMessage(
            std::wstring(L"DynData legacy profile 应用")
            + (layerSucceeded ? L"完成。" : L"失败或部分拒绝。")
            + L" "
            + applied.message
            + L" "
            + Utf8ToWide(applied.io.message));
        result.rows.push_back(Row({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Mode", L"Legacy" },
            { L"IO", applied.io.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(applied.io.win32Error) },
            { L"BytesReturned", std::to_wstring(applied.io.bytesReturned) },
            { L"NTSTATUS", HexText(static_cast<std::uint32_t>(applied.status)) },
            { L"AppliedFields", std::to_wstring(applied.appliedFieldCount) },
            { L"RejectedFields", std::to_wstring(applied.rejectedFieldCount) },
            { L"UnknownFields", std::to_wstring(applied.unknownFieldCount) },
            { L"StatusFlags", HexText(applied.statusFlags) },
            { L"CapabilityMask", HexText(applied.capabilityMask) },
            { L"Profile", Utf8ToWide(match.profile.profileName) },
            { L"PdbName", Utf8ToWide(match.profile.pdbName) },
            { L"PdbGuid", Utf8ToWide(match.profile.pdbGuid) },
            { L"PdbAge", std::to_wstring(match.profile.pdbAge) },
            { L"ProfilePath", match.path },
        }, applied.message.empty() ? Utf8ToWide(applied.io.message) : applied.message));
    }

    if (!match.profileEx.items.empty()) {
        appliedAnyLayer = true;
        const ksword::ark::DynDataProfileApplyExResult applied = client.applyDynDataProfileEx(match.profileEx);
        const bool layerSucceeded =
            applied.io.ok &&
            applied.status >= 0 &&
            applied.rejectedItemCount == 0 &&
            applied.unknownItemCount == 0;
        result.success = result.success && layerSucceeded;
        appendLayerMessage(
            std::wstring(L"DynData EX profile 应用")
            + (layerSucceeded ? L"完成。" : L"失败或部分拒绝。")
            + L" "
            + applied.message
            + L" "
            + Utf8ToWide(applied.io.message));
        result.rows.push_back(Row({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Mode", L"EX" },
            { L"IO", applied.io.ok ? L"OK" : L"FAIL" },
            { L"Win32", std::to_wstring(applied.io.win32Error) },
            { L"BytesReturned", std::to_wstring(applied.io.bytesReturned) },
            { L"NTSTATUS", HexText(static_cast<std::uint32_t>(applied.status)) },
            { L"AppliedItems", std::to_wstring(applied.appliedItemCount) },
            { L"RejectedItems", std::to_wstring(applied.rejectedItemCount) },
            { L"UnknownItems", std::to_wstring(applied.unknownItemCount) },
            { L"StatusFlags", HexText(applied.statusFlags) },
            { L"CapabilityMask", HexText(applied.capabilityMask) },
            { L"Profile", Utf8ToWide(match.profileEx.profileName) },
            { L"PdbName", Utf8ToWide(match.profileEx.pdbName) },
            { L"PdbGuid", Utf8ToWide(match.profileEx.pdbGuid) },
            { L"PdbAge", std::to_wstring(match.profileEx.pdbAge) },
            { L"ProfilePath", match.path },
        }, applied.message.empty() ? Utf8ToWide(applied.io.message) : applied.message));
    }

    if (!match.profileV4.items.empty()) {
        appliedAnyLayer = true;
        const ksword::ark::DynDataV4ApplyResult applied = client.applyDynDataProfileV4(match.profileV4);
        const KSW_APPLY_DYN_PROFILE_V4_RESPONSE& response = applied.response;
        const bool layerSucceeded = applied.io.ok && !applied.unsupported && response.status >= 0 &&
            response.rejectedItemCount == 0 && response.missingRequiredItemCount == 0;
        result.success = result.success && layerSucceeded;
        appendLayerMessage(
            std::wstring(L"DynData V4 profile 应用")
            + (layerSucceeded ? L"完成。" : L"失败、旧驱动不支持或存在必需项缺失。")
            + L" "
            + response.message
            + L" "
            + Utf8ToWide(applied.io.message));
        result.rows.push_back(Row({
            { L"Action", L"DynDataApplyMatchedProfile" },
            { L"Mode", L"V4" },
            { L"IO", applied.io.ok ? L"OK" : L"FAIL" },
            { L"Unsupported", BoolText(applied.unsupported) },
            { L"Win32", std::to_wstring(applied.io.win32Error) },
            { L"BytesReturned", std::to_wstring(applied.io.bytesReturned) },
            { L"NTSTATUS", HexText(static_cast<std::uint32_t>(response.status)) },
            { L"StatusFlags", HexText(response.statusFlags) },
            { L"AppliedItems", std::to_wstring(response.appliedItemCount) },
            { L"RejectedItems", std::to_wstring(response.rejectedItemCount) },
            { L"RequiredItems", std::to_wstring(response.requiredItemCount) },
            { L"PresentRequiredItems", std::to_wstring(response.presentRequiredItemCount) },
            { L"OptionalItems", std::to_wstring(response.optionalItemCount) },
            { L"PresentOptionalItems", std::to_wstring(response.presentOptionalItemCount) },
            { L"ActiveCapabilityGroups", std::to_wstring(response.activeCapabilityGroupCount) },
            { L"MissingRequiredItems", std::to_wstring(response.missingRequiredItemCount) },
            { L"MissingOptionalItems", std::to_wstring(response.missingOptionalItemCount) },
            { L"Profile", Utf8ToWide(match.profile.profileName) },
            { L"PdbName", Utf8ToWide(match.profile.pdbName) },
            { L"PdbGuid", Utf8ToWide(match.profile.pdbGuid) },
            { L"PdbAge", std::to_wstring(match.profile.pdbAge) },
            { L"ItemCount", std::to_wstring(match.profileV4.items.size()) },
            { L"CapabilityGroupCount", std::to_wstring(match.profileV4.capabilityGroups.size()) },
            { L"ProfilePath", match.path },
        }, response.message[0] == L'\0' ? Utf8ToWide(applied.io.message) : std::wstring(response.message)));
    }

    if (!appliedAnyLayer) {
        result.success = false;
        result.message = L"匹配的 DynData profile 没有可下发的 Legacy、EX 或 V4 数据层。";
    }

    AppendDynDataProfileRows(result, match, request.filterText);
    return result;
}

// MutationActionName maps action ids to display names. Input is a mutation action
// enum; output is a stable label for result rows and messages.
const wchar_t* MutationActionName(const KernelActionId actionId) {
    switch (actionId) {
    case KernelActionId::MutationCommitDryRun: return L"MutationCommitDryRun";
    case KernelActionId::MutationRollbackDryRun: return L"MutationRollbackDryRun";
    case KernelActionId::MutationRollbackConfirmed: return L"MutationRollbackConfirmed";
    default: return L"MutationUnknown";
    }
}

// MutationActionSucceeded classifies the response status for user feedback. Input
// is a response packet and whether the request was dry-run; output is true when
// the operation reached the expected dry-run/rollback/commit outcome.
bool MutationActionSucceeded(const ksword::ark::MutationResponseResult& response, const bool dryRun, const bool rollback) {
    if (!response.io.ok) {
        return false;
    }
    if (dryRun) {
        return response.status == KSWORD_ARK_MUTATION_STATUS_DRY_RUN ||
            response.status == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE;
    }
    if (rollback) {
        return response.status == KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK ||
            response.status == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE;
    }
    return response.status == KSWORD_ARK_MUTATION_STATUS_COMMITTED;
}

// ExecuteMutationTransaction runs commit/rollback actions for a selected audit
// transaction. Inputs are the current action request and selected Tx field;
// processing only calls ArkDriverClient transaction APIs and never accepts
// arbitrary write bytes from UI; output contains full response metadata and a
// refreshed audit snapshot so the user can see the resulting event.
KernelOperationResult ExecuteMutationTransaction(const KernelActionRequest& request) {
    const std::wstring txText = FirstFieldValue(request, { L"Tx", L"TransactionId" });
    std::uint64_t transactionId = 0;
    if (!ParseUnsigned64(txText, transactionId) || transactionId == 0) {
        return MakeActionError(request, L"当前 Mutation Audit 行缺少有效 TransactionId/Tx 字段。");
    }

    const bool rollback = request.actionId != KernelActionId::MutationCommitDryRun;
    const bool dryRun = request.actionId != KernelActionId::MutationRollbackConfirmed;
    const unsigned long flags = dryRun
        ? KSWORD_ARK_MUTATION_FLAG_DRY_RUN
        : (KSWORD_ARK_MUTATION_FLAG_FORCE | KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);

    const ksword::ark::DriverClient client;
    const ksword::ark::MutationResponseResult response = rollback
        ? client.rollbackMutation(transactionId, flags)
        : client.commitMutation(transactionId, flags);

    KernelOperationResult result;
    result.supported = true;
    result.destructiveAction = !dryRun;
    result.success = MutationActionSucceeded(response, dryRun, rollback);
    result.message = std::wstring(MutationActionName(request.actionId))
        + (result.success ? L" 完成。" : L" 未完成。")
        + L" "
        + Utf8ToWide(response.io.message);
    result.rows.push_back(Row({
        { L"Action", MutationActionName(request.actionId) },
        { L"RequestTx", HexText(transactionId) },
        { L"RequestFlags", HexText(flags) },
        { L"RequestFlagsText", MutationFlagsText(flags) },
        { L"IO", response.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", BoolText(response.unsupported) },
        { L"Win32", std::to_wstring(response.io.win32Error) },
        { L"BytesReturned", std::to_wstring(response.io.bytesReturned) },
        { L"Version", std::to_wstring(response.version) },
        { L"Status", std::wstring(MutationStatusText(response.status)) + L" (" + std::to_wstring(response.status) + L")" },
        { L"TargetKind", std::wstring(MutationTargetText(response.targetKind)) + L" (" + std::to_wstring(response.targetKind) + L")" },
        { L"PID", std::to_wstring(response.processId) },
        { L"Tx", HexText(response.transactionId) },
        { L"Address", HexText(response.targetAddress) },
        { L"Context", HexText(response.targetContext) },
        { L"Bytes", std::to_wstring(response.bytes) },
        { L"Risk", HexText(response.riskFlags) },
        { L"RiskText", MutationRiskText(response.riskFlags) },
        { L"BeforeHash", HexText(response.beforeHash) },
        { L"AfterHash", HexText(response.afterHash) },
        { L"BeforeBytes", BytesHex(response.beforeBytes) },
        { L"AfterBytes", BytesHex(response.afterBytes) },
        { L"LastStatus", HexText(static_cast<std::uint32_t>(response.lastStatus)) },
    }, Utf8ToWide(response.io.message)));

    const ksword::ark::MutationAuditResult audit = client.queryMutationAudit(
        KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES,
        KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY,
        0);
    result.rows.push_back(Row({
        { L"Action", L"MutationAuditRefresh" },
        { L"IO", audit.io.ok ? L"OK" : L"FAIL" },
        { L"Unsupported", BoolText(audit.unsupported) },
        { L"Returned", std::to_wstring(audit.returnedCount) },
        { L"Lost", std::to_wstring(audit.lostCount) },
        { L"OldestSeq", HexText(audit.oldestSequence) },
        { L"NextSeq", HexText(audit.nextSequence) },
    }, Utf8ToWide(audit.io.message)));
    for (const ksword::ark::MutationAuditEntry& entry : audit.entries) {
        if (entry.transactionId != transactionId) {
            continue;
        }
        result.rows.push_back(Row({
            { L"Source", L"AuditAfterAction" },
            { L"Seq", HexText(entry.sequence) },
            { L"Tx", HexText(entry.transactionId) },
            { L"Operation", std::wstring(MutationOperationText(entry.operation)) + L" (" + std::to_wstring(entry.operation) + L")" },
            { L"Status", std::wstring(MutationStatusText(entry.status)) + L" (" + std::to_wstring(entry.status) + L")" },
            { L"TargetKind", std::wstring(MutationTargetText(entry.targetKind)) + L" (" + std::to_wstring(entry.targetKind) + L")" },
            { L"Risk", HexText(entry.riskFlags) },
            { L"RiskText", MutationRiskText(entry.riskFlags) },
            { L"Flags", HexText(entry.flags) },
            { L"FlagsText", MutationFlagsText(entry.flags) },
            { L"Data", BytesHex(entry.byteData) },
            { L"LastStatus", HexText(static_cast<std::uint32_t>(entry.lastStatus)) },
        }));
    }
    return result;
}

} // namespace

KernelOperationResult KernelFacade::QueryFeature(const KernelRequest& request) const {
    if (request.featureId == KernelFeatureId::DeviceDriverObjects) {
        return QueryDeviceDriverObjectsHybrid(request);
    }
    if (IsNativeKernelFeature(request.featureId)) {
        return QueryNativeKernelFeature(request);
    }
    if (IsArkDriverBacked(request.featureId)) {
        return QueryArkDriverFeature(request);
    }
    return MakeUnsupportedResult(request, L"该内核条目没有注册 R3 Native 或 ArkDriverClient 查询路径。");
}

KernelOperationResult KernelFacade::ExecuteAction(const KernelActionRequest& request) const {
    switch (request.actionId) {
    case KernelActionId::InlineHookNopPatch:
        return ExecuteInlineHookNopPatch(request);
    case KernelActionId::CallbackCancelPendingDecisions:
    case KernelActionId::CallbackApplyDisabledEmptyRules:
    case KernelActionId::CallbackApplyLocalRules:
        return ExecuteCallbackRuntimeControl(request);
    case KernelActionId::CallbackAnswerEvent:
        return ExecuteCallbackAnswerEvent(request);
    case KernelActionId::CallbackSafeRemove:
        return ExecuteCallbackSafeRemove(request);
    case KernelActionId::CallbackExperimentalUnlink:
        return ExecuteCallbackExperimentalUnlink(request);
    case KernelActionId::MinifilterSetBypassPids:
    case KernelActionId::MinifilterClearBypassPids:
        return ExecuteSetMinifilterBypassPids(request);
    case KernelActionId::NetworkCaptureStart:
    case KernelActionId::NetworkCaptureStop:
        return ExecuteNetworkCaptureControl(request);
    case KernelActionId::PiDdbDeleteEntry:
        return ExecutePiDdbDeleteEntry(request);
    case KernelActionId::DriverDispatchRestore:
    case KernelActionId::DriverDispatchAbandon:
        return ExecuteDriverDispatchRecovery(request);
    case KernelActionId::DriverImageRestore:
    case KernelActionId::DriverImageAbandon:
        return ExecuteDriverImageRecovery(request);
    case KernelActionId::DriverCommunicationRestore:
        return ExecuteDriverCommunicationRestore(request);
    case KernelActionId::FileMonitorStartFsctl:
    case KernelActionId::FileMonitorDrain:
    case KernelActionId::FileMonitorClear:
        return ExecuteFileMonitorControl(request);
    case KernelActionId::DriverObjectQueryDetail:
        return ExecuteDriverObjectQueryDetail(request);
    case KernelActionId::DriverObjectForceUnload:
        return ExecuteDriverObjectForceUnload(request);
    case KernelActionId::NativeObjectQueryDetail:
    case KernelActionId::NativeSymbolicLinkResolve:
    case KernelActionId::NativeNamedPipeProbe:
        return ExecuteNativeKernelAction(request);
    case KernelActionId::DynDataApplyMatchedProfile:
        return ExecuteDynDataApplyMatchedProfile(request);
    case KernelActionId::MutationCommitDryRun:
    case KernelActionId::MutationRollbackDryRun:
    case KernelActionId::MutationRollbackConfirmed:
        return ExecuteMutationTransaction(request);
    case KernelActionId::None:
    default:
        return MakeActionError(request, L"未选择可执行的内核动作。");
    }
}

KernelOperationResult KernelFacade::QueryArkDriverFeature(const KernelRequest& request) const {
    const ksword::ark::DriverClient client;
    const ksword::ark::DriverCapabilitiesQueryResult capability = client.queryDriverCapabilities();
    auto attachCapability = [&](KernelOperationResult result) {
        result.rows.insert(result.rows.begin(), Row({
            { L"R0", capability.io.ok ? L"Online" : L"Unavailable" },
            { L"Protocol", std::to_wstring(capability.driverProtocolVersion) },
            { L"StatusFlags", HexText(capability.statusFlags) },
            { L"DynDataStatus", HexText(capability.dynDataStatusFlags) },
            { L"Win32", std::to_wstring(capability.io.win32Error) },
            { L"CapabilityBytes", std::to_wstring(capability.io.bytesReturned) },
        }, capability.io.ok ? Utf8ToWide(capability.lastErrorSummary) : Utf8ToWide(capability.io.message)));
        if (!capability.io.ok && result.message.find(L"R0") == std::wstring::npos) {
            result.message = std::wstring(L"R0 驱动能力查询失败：") + Utf8ToWide(capability.io.message) + L" " + result.message;
        }
        return result;
    };

    switch (request.featureId) {
    case KernelFeatureId::Ssdt:
        return attachCapability(QuerySsdt(request, false));
    case KernelFeatureId::ShadowSsdt:
        return attachCapability(QuerySsdt(request, true));
    case KernelFeatureId::InlineHook:
        return attachCapability(QueryInlineHooks(request));
    case KernelFeatureId::IatEatHook:
        return attachCapability(QueryIatEatHooks(request));
    case KernelFeatureId::DynData:
        return attachCapability(QueryDynData(request));
    case KernelFeatureId::DriverStatus:
        return attachCapability(QueryDriverStatus(request));
    case KernelFeatureId::CallbackIntercept:
        return attachCapability(QueryCallbackRuntime(request));
    case KernelFeatureId::CallbackEnumeration:
        return attachCapability(QueryCallbackEnumeration(request));
    case KernelFeatureId::KernelExecutableMemory:
        return attachCapability(QueryKernelExecutableMemory(request));
    case KernelFeatureId::KernelMemoryEvidence:
        return attachCapability(QueryKernelMemoryEvidence(request));
    case KernelFeatureId::ProcessCrossView:
        return attachCapability(QueryProcessCrossView(request));
    case KernelFeatureId::ThreadCrossView:
        return attachCapability(QueryThreadCrossView(request));
    case KernelFeatureId::DriverIntegrity:
        return attachCapability(QueryDriverIntegrity(request));
    case KernelFeatureId::KernelCpuIntegrity:
        return attachCapability(QueryKernelCpuIntegrity(request));
    case KernelFeatureId::CpuHardwareSnapshot:
        return attachCapability(QueryCpuHardwareSnapshot(request));
    case KernelFeatureId::PhysicalMemoryLayout:
        return attachCapability(QueryPhysicalMemoryLayout(request));
    case KernelFeatureId::MutationAudit:
        return attachCapability(QueryMutationAudit(request));
    case KernelFeatureId::KeyboardHotkeys:
        return attachCapability(QueryKeyboardHotkeys(request));
    case KernelFeatureId::KeyboardHooks:
        return attachCapability(QueryKeyboardHooks(request));
    case KernelFeatureId::DynDataCapabilities:
        return attachCapability(QueryDynDataCapabilities(request));
    case KernelFeatureId::PdbProfileStatus:
        return attachCapability(QueryPdbProfileStatus(request));
    case KernelFeatureId::CidTableSummary:
        return attachCapability(QueryCidTableSummary(request));
    case KernelFeatureId::IpcSummary:
        return attachCapability(QueryIpcSummary(request));
    case KernelFeatureId::HookAuditSummary:
        return attachCapability(QueryHookAuditSummary(request));
    case KernelFeatureId::MinifilterBypassPids:
        return attachCapability(QueryMinifilterBypassPids(request));
    case KernelFeatureId::KernelTimerDpc:
        return attachCapability(QueryKernelTimerDpc(request));
    case KernelFeatureId::IoctlRegistry:
        return attachCapability(QueryIoctlRegistry(request));
    case KernelFeatureId::WorkQueueThreads:
        return attachCapability(QueryWorkQueueThreads(request));
    case KernelFeatureId::SlatIommuAudit:
        return attachCapability(QuerySlatIommuAudit(request));
    case KernelFeatureId::HvmStatus:
        return attachCapability(QueryHvmStatus(request));
    case KernelFeatureId::HvmEvents:
        return attachCapability(QueryHvmEvents(request));
    case KernelFeatureId::DriverDispatchTable:
        return attachCapability(QueryDriverDispatchTable(request));
    case KernelFeatureId::DriverImageFields:
        return attachCapability(QueryDriverImageFields(request));
    case KernelFeatureId::DriverCommunication:
        return attachCapability(QueryDriverCommunication(request));
    case KernelFeatureId::PlatformAudit:
        return attachCapability(QueryPlatformAudit(request));
    case KernelFeatureId::SystemTimeState:
        return attachCapability(QuerySystemTimeState(request));
    case KernelFeatureId::I8042Audit:
        return attachCapability(QueryI8042Audit(request));
    case KernelFeatureId::PiDdbCache:
        return attachCapability(QueryPiDdbCache(request));
    case KernelFeatureId::RawDiskSectors:
        return attachCapability(QueryRawDiskSectors(request));
    case KernelFeatureId::NetworkTrafficPackets:
        return attachCapability(QueryNetworkTrafficPackets(request));
    default:
        return MakeUnsupportedResult(request, L"该内核条目没有对应的 ArkDriverClient 只读 IOCTL。 ");
    }
}

} // namespace Ksword::Features::Kernel
