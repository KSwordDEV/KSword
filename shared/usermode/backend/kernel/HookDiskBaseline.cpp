#include "HookDiskBaseline.h"
#include <algorithm>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <sstream>
#pragma comment(lib,"Psapi.lib")
namespace ks::r3::kernel::disk {
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
}
