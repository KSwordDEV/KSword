#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include "../core/MonitorDiagnostics.h"

namespace apimon::detail {
using StopCheck = bool(*)();

// Walk VAD regions, not every 64KiB address inside an occupied region. Query
// and Allocate are parameters so boundary/race behavior is tested without hooks.
template<class Query, class Allocate>
unsigned char* FindNearFreeRegion(std::uintptr_t target, std::uintptr_t minimum,
    std::uintptr_t maximum, std::uintptr_t granularity, Query query, Allocate allocate, StopCheck stop) {
    constexpr std::uintptr_t radius = 0x7fff0000;
    constexpr std::uintptr_t page = 4096;
    const auto center = target & ~(granularity - 1);
    const auto lower = center > radius ? (std::max)(minimum, center - radius) : minimum;
    const auto upper = radius > maximum - center ? maximum : center + radius;
    std::uintptr_t up = center + granularity, down = center >= granularity ? center - granularity : 0;
    bool upValid = up > center && up <= upper && up <= maximum - page;
    bool downValid = down >= lower && down < center;
    while (upValid || downValid) {
        if (stop && stop()) return nullptr;
        const bool forward = upValid && (!downValid || up - center <= center - down);
        auto& cursor = forward ? up : down;
        MEMORY_BASIC_INFORMATION region{};
        if (!query(reinterpret_cast<void*>(cursor), &region)) {
            if (forward) upValid = false; else downValid = false;
            continue;
        }
        if (region.State == MEM_FREE) {
            if (auto* result = allocate(reinterpret_cast<void*>(cursor))) return result;
            // A concurrent reservation can invalidate this one candidate. Keep
            // searching the remaining free interval rather than skipping it.
            if (forward) {
                if (cursor > upper - (std::min)(upper, granularity)) upValid = false;
                else cursor += granularity;
            } else {
                if (cursor < granularity || cursor - granularity < lower) downValid = false;
                else cursor -= granularity;
            }
        } else if (forward) {
            const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            if (!region.RegionSize || base > maximum || region.RegionSize > maximum - base) { upValid = false; continue; }
            const auto end = base + region.RegionSize;
            if (end > maximum - (granularity - 1)) { upValid = false; continue; }
            const auto next = (end + granularity - 1) & ~(granularity - 1);
            if (next <= cursor) { upValid = false; continue; }
            cursor = next;
        } else {
            const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            if (base < granularity) { downValid = false; continue; }
            const auto next = (base - 1) & ~(granularity - 1);
            if (next >= cursor) { downValid = false; continue; }
            cursor = next;
        }
        upValid = upValid && up >= lower && up <= upper && up <= maximum - page;
        downValid = downValid && down >= lower && down <= upper && down <= maximum - page;
    }
    return nullptr;
}

inline unsigned char* AllocateNearAddress(const void* address, StopCheck stop) {
    if (stop && stop()) return nullptr;
    SYSTEM_INFO info{}; ::GetSystemInfo(&info);
    const auto target = reinterpret_cast<std::uintptr_t>(address);
    const auto minimum = reinterpret_cast<std::uintptr_t>(info.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(info.lpMaximumApplicationAddress);
    if (target < minimum || target > maximum || maximum < 4096) return nullptr;
    const auto granularity = static_cast<std::uintptr_t>(info.dwAllocationGranularity);
    using Allocate2 = PVOID(WINAPI*)(HANDLE,PVOID,SIZE_T,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
    static const Allocate2 systemAllocate = [] {
        const auto module = ::GetModuleHandleW(L"KernelBase.dll");
        const auto symbol = module ? ::GetProcAddress(module,"VirtualAlloc2") : nullptr;
        Allocate2 function = nullptr;
        static_assert(sizeof(function) == sizeof(symbol));
        std::memcpy(&function,&symbol,sizeof(function)); return function;
    }();
    if (systemAllocate) {
        constexpr std::uintptr_t radius = 0x7fff0000;
        const auto center = target & ~(granularity - 1);
        MEM_ADDRESS_REQUIREMENTS requirements{};
        requirements.LowestStartingAddress = reinterpret_cast<void*>(center > radius ? (std::max)(minimum,center-radius) : minimum);
        // HighestEndingAddress is inclusive and must be one LESS than an
        // allocation-granularity boundary. An aligned upper bound is rejected
        // with ERROR_INVALID_PARAMETER on Win10, silently forcing the walker.
        const auto upper = radius > maximum-center ? maximum : center+radius;
        requirements.HighestEndingAddress = reinterpret_cast<void*>((upper & ~(granularity-1))-1);
        requirements.Alignment = granularity;
        MEM_EXTENDED_PARAMETER parameter{};parameter.Type=MemExtendedParameterAddressRequirements;parameter.Pointer=&requirements;
        if (auto* memory=systemAllocate(nullptr,nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE,&parameter,1))
            return static_cast<unsigned char*>(memory);
        const auto error=::GetLastError();
        // The OS already searched this range. Only an unsupported interface
        // needs the compatibility walker; do not rescan on ordinary exhaustion.
        if (error!=ERROR_INVALID_PARAMETER && error!=ERROR_NOT_SUPPORTED && error!=ERROR_CALL_NOT_IMPLEMENTED) return nullptr;
    }
    return FindNearFreeRegion(target,minimum,maximum,granularity,
        [](const void* location,MEMORY_BASIC_INFORMATION* region) { APIMON_DIAG_ADD(NearQueries,1);return ::VirtualQuery(location,region,sizeof(*region))!=0; },
        [](void* location) { return static_cast<unsigned char*>(::VirtualAlloc(location,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE)); },stop);
}
}
