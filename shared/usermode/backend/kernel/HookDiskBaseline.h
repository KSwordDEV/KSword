#pragma once
#include "../Common.h"
#include "KernelTypes.h"
#include "../../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <psapi.h>
#include <array>
#include <unordered_map>
namespace ks::r3::kernel::disk {
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
std::wstring NormalizeKernelModulePath(const std::wstring& path);
std::unordered_map<std::uint64_t, KernelModuleDiskInfo> QueryLoadedKernelModuleMap();
bool ReadWholeBinaryFile(const std::wstring& path, std::vector<std::uint8_t>& bytesOut);
bool RvaToFileOffset(const std::vector<std::uint8_t>& fileBytes, const std::uint32_t rva, const std::uint32_t bytesToRead, std::uint64_t& offsetOut);
InlineDiskBaseline ReadInlineDiskBaseline(
    const ksword::ark::KernelInlineHookEntry& entry,
    const std::unordered_map<std::uint64_t, KernelModuleDiskInfo>& modules,
    std::unordered_map<std::wstring, std::vector<std::uint8_t>>& fileCache);
}
