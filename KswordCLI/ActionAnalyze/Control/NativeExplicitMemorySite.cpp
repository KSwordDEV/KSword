#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "NativeExplicitMemorySite.h"

#include <limits>

namespace ks::cli::action_analyze::control {
namespace {

DWORD ReadRegion(HANDLE process, std::uint64_t address, std::uint32_t writeBytes,
    MEMORY_BASIC_INFORMATION& region)
{
    if (!process || !address || address > (std::numeric_limits<std::uintptr_t>::max)() ||
        (writeBytes != 0 && writeBytes != 1 && writeBytes != 2 && writeBytes != 4 && writeBytes != 8))
        return ERROR_INVALID_PARAMETER;
    const auto bytes = writeBytes ? writeBytes : 1;
    if (writeBytes && address % writeBytes) return ERROR_DATATYPE_MISMATCH;
    if (VirtualQueryEx(process, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
        &region, sizeof(region)) != sizeof(region)) {
        const auto error = GetLastError();
        return error ? error : ERROR_INVALID_ADDRESS;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
    if (region.State != MEM_COMMIT || region.Type != MEM_PRIVATE || !region.AllocationBase ||
        (region.Protect & PAGE_GUARD) || address < base || bytes > region.RegionSize ||
        address - base > region.RegionSize - bytes) return ERROR_INVALID_ADDRESS;
    const auto protection = region.Protect & 0xff;
    if (writeBytes) {
        if (protection != PAGE_READWRITE && protection != PAGE_EXECUTE_READWRITE) return ERROR_NOACCESS;
    } else if (protection != PAGE_EXECUTE && protection != PAGE_EXECUTE_READ &&
        protection != PAGE_EXECUTE_READWRITE) return ERROR_NOACCESS;
    return ERROR_SUCCESS;
}

} // namespace

DWORD ResolveNativeExplicitMemorySite(HANDLE process, DWORD pid, std::uint64_t address,
    std::uint32_t writeBytes, NativeExplicitMemorySite& result)
{
    result = {};
    if (!pid || GetProcessId(process) != pid) return ERROR_INVALID_PARAMETER;
    MEMORY_BASIC_INFORMATION region{};
    if (const auto error = ReadRegion(process, address, writeBytes, region)) return error;
    NativeExplicitMemorySite selected;
    selected.site.address = static_cast<std::uintptr_t>(address);
    selected.site.allocationBase = reinterpret_cast<std::uintptr_t>(region.AllocationBase);
    selected.site.regionBase = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
    selected.site.regionBytes = region.RegionSize;
    selected.site.regionProtection = region.Protect;
    selected.allocationProtection = region.AllocationProtect;
    result = selected;
    return ERROR_SUCCESS;
}

DWORD VerifyNativeExplicitMemorySite(HANDLE process, const NativeExplicitMemorySite& frozen,
    std::uint32_t writeBytes)
{
    MEMORY_BASIC_INFORMATION region{};
    if (const auto error = ReadRegion(process, frozen.site.address, writeBytes, region)) return error;
    return reinterpret_cast<std::uintptr_t>(region.AllocationBase) == frozen.site.allocationBase &&
        reinterpret_cast<std::uintptr_t>(region.BaseAddress) == frozen.site.regionBase &&
        region.RegionSize == frozen.site.regionBytes && region.Protect == frozen.site.regionProtection &&
        region.AllocationProtect == frozen.allocationProtection ? ERROR_SUCCESS : ERROR_INVALID_ADDRESS;
}

} // namespace ks::cli::action_analyze::control
