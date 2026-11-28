#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "NativePrivateExecutionSite.h"

#include <limits>

namespace ks::cli::action_analyze::control {
namespace {

DWORD NativeError() noexcept {
    const auto error = GetLastError();
    return error ? error : ERROR_GEN_FAILURE;
}

bool Contains(const MEMORY_BASIC_INFORMATION& memory, std::uintptr_t address, std::size_t bytes) noexcept {
    const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
    return base <= address && bytes <= memory.RegionSize && address - base <= memory.RegionSize - bytes;
}

DWORD ReadSelector(HANDLE process, const NativeImageSite& site, MEMORY_BASIC_INFORMATION& memory,
    std::uintptr_t& destination) {
    const auto selector = site.pointerExportAddress;
    if (!site.base || !selector || selector % sizeof(std::uint64_t) ||
        !site.rva || selector < site.base || selector - site.base != site.rva) return ERROR_INVALID_ADDRESS;
    if (VirtualQueryEx(process, reinterpret_cast<const void*>(selector), &memory, sizeof(memory)) != sizeof(memory))
        return NativeError();
    const auto protection = memory.Protect & 0xff;
    if (memory.Type != MEM_IMAGE || memory.State != MEM_COMMIT ||
        reinterpret_cast<std::uintptr_t>(memory.AllocationBase) != site.base || (memory.Protect & PAGE_GUARD) ||
        (protection != PAGE_READONLY && protection != PAGE_READWRITE && protection != PAGE_WRITECOPY) ||
        !Contains(memory, selector, sizeof(std::uint64_t))) return ERROR_INVALID_ADDRESS;
    std::uint64_t pointer = 0;
    SIZE_T count = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(selector), &pointer, sizeof(pointer), &count))
        return NativeError();
    if (count != sizeof(pointer)) return ERROR_PARTIAL_COPY;
    if (!pointer || pointer > std::numeric_limits<std::uintptr_t>::max()) return ERROR_INVALID_ADDRESS;
    destination = static_cast<std::uintptr_t>(pointer);
    return ERROR_SUCCESS;
}

DWORD ReadExecutionRegion(HANDLE process, std::uintptr_t address, MEMORY_BASIC_INFORMATION& memory) {
    if (!address) return ERROR_INVALID_ADDRESS;
    if (VirtualQueryEx(process, reinterpret_cast<const void*>(address), &memory, sizeof(memory)) != sizeof(memory))
        return NativeError();
    const auto protection = memory.Protect & 0xff;
    if (memory.Type != MEM_PRIVATE || memory.State != MEM_COMMIT || !memory.AllocationBase ||
        (memory.Protect & PAGE_GUARD) || (protection != PAGE_EXECUTE && protection != PAGE_EXECUTE_READ &&
            protection != PAGE_EXECUTE_READWRITE) || !Contains(memory, address, 1)) return ERROR_INVALID_ADDRESS;
    return ERROR_SUCCESS;
}

} // namespace

DWORD ResolveNativePrivateExecutionSite(HANDLE process, DWORD pid, std::wstring_view modulePath,
    std::string_view exportName, NativePrivateExecutionSite& result, std::uintptr_t eventImageBase) {
    if (!process || GetProcessId(process) != pid || exportName.empty() || exportName.size() > 255 ||
        exportName.find('\0') != std::string_view::npos) return ERROR_INVALID_PARAMETER;
    NativePrivateExecutionSite candidate;
    // Reuse the same validated AMD64 PE/export parser. Existing write sites keep
    // their default writable-only selection; this explicitly requests image data.
    if (const auto error = ResolveNativeImageSite(process, pid, modulePath, std::nullopt, exportName,
        candidate.site, 8, true, eventImageBase)) return error;
    candidate.site.pointerExportAddress = candidate.site.address;
    MEMORY_BASIC_INFORMATION selector{};
    std::uintptr_t destination = 0;
    if (const auto error = ReadSelector(process, candidate.site, selector, destination)) return error;
    MEMORY_BASIC_INFORMATION region{};
    if (const auto error = ReadExecutionRegion(process, destination, region)) return error;
    candidate.site.address = destination;
    candidate.site.allocationBase = reinterpret_cast<std::uintptr_t>(region.AllocationBase);
    candidate.site.regionBase = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
    candidate.site.regionBytes = region.RegionSize;
    candidate.site.regionProtection = region.Protect;
    candidate.allocationProtection = region.AllocationProtect;
    candidate.selectorRegionBase = reinterpret_cast<std::uintptr_t>(selector.BaseAddress);
    candidate.selectorRegionBytes = selector.RegionSize;
    candidate.selectorProtection = selector.Protect;
    if (const auto error = VerifyNativePrivateExecutionSite(process, candidate)) return error;
    result = candidate; // publish only a complete and verified immutable binding
    return ERROR_SUCCESS;
}

DWORD VerifyNativePrivateExecutionSite(HANDLE process, const NativePrivateExecutionSite& frozen) {
    const auto& site = frozen.site;
    MEMORY_BASIC_INFORMATION selector{};
    std::uintptr_t destination = 0;
    if (const auto error = ReadSelector(process, site, selector, destination)) return error;
    if (destination != site.address || reinterpret_cast<std::uintptr_t>(selector.BaseAddress) != frozen.selectorRegionBase ||
        selector.RegionSize != frozen.selectorRegionBytes || selector.Protect != frozen.selectorProtection)
        return ERROR_INVALID_ADDRESS;
    MEMORY_BASIC_INFORMATION region{};
    if (const auto error = ReadExecutionRegion(process, destination, region)) return error;
    return reinterpret_cast<std::uintptr_t>(region.AllocationBase) == site.allocationBase &&
        reinterpret_cast<std::uintptr_t>(region.BaseAddress) == site.regionBase && region.RegionSize == site.regionBytes &&
        region.Protect == site.regionProtection && region.AllocationProtect == frozen.allocationProtection ?
        ERROR_SUCCESS : ERROR_INVALID_ADDRESS;
}

} // namespace ks::cli::action_analyze::control
