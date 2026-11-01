#pragma once
#include <Windows.h>
#include <cstdint>
#include <mutex>
#include <vector>

namespace apimon::detail {
constexpr std::size_t kCodePageBytes = 4096;
#ifdef _M_IX86
// A separate VirtualAlloc reservation for every 4KiB stub leaves a 60KiB
// unusable gap at each allocation-granularity boundary. Two large Raw sessions
// can fragment the entire 2GiB address space. Reserve an arena, commit each
// page separately, and never change protection of already published siblings.
struct CodePageBlock { unsigned char* base; std::uint64_t free; };
struct CodePagePool {
    std::mutex mutex;
    std::vector<CodePageBlock> blocks;
    std::size_t next = 0;
    std::size_t arenaBytes = 0;
    std::uint64_t mask = 0;
    CodePagePool() {
        SYSTEM_INFO info{}; ::GetSystemInfo(&info);
        arenaBytes = info.dwAllocationGranularity;
        const auto count = arenaBytes / kCodePageBytes;
        if (info.dwPageSize != kCodePageBytes || !count || count > 64) arenaBytes = 0;
        else mask = count == 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << count) - 1;
    }
};
inline CodePagePool& codePagePool() {
    static auto* const pool = new CodePagePool; // published pages outlive sessions
    return *pool;
}
#endif

inline unsigned char* AllocateCodePage() noexcept {
#ifdef _M_IX86
    try {
        auto& pool = codePagePool();
        const std::lock_guard<std::mutex> lock(pool.mutex);
        if (pool.arenaBytes) {
            while (pool.next < pool.blocks.size() && !pool.blocks[pool.next].free) ++pool.next;
            if (pool.next == pool.blocks.size()) {
                // Allocate bookkeeping before reserving target address space.
                if (pool.blocks.size() == pool.blocks.capacity())
                    pool.blocks.reserve(pool.blocks.size() + 64);
                auto* base = static_cast<unsigned char*>(::VirtualAlloc(nullptr, pool.arenaBytes, MEM_RESERVE, PAGE_NOACCESS));
                if (!base) return nullptr;
                pool.blocks.push_back({base, pool.mask});
            }
            auto& block = pool.blocks[pool.next];
            unsigned slot = 0;
            while (!(block.free & (std::uint64_t{1} << slot))) ++slot;
            auto* page = block.base + slot * kCodePageBytes;
            if (!::VirtualAlloc(page, kCodePageBytes, MEM_COMMIT, PAGE_READWRITE)) return nullptr;
            block.free &= ~(std::uint64_t{1} << slot);
            return page;
        }
    } catch (...) { return nullptr; }
#endif
    return static_cast<unsigned char*>(::VirtualAlloc(nullptr, kCodePageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
}

// Only unpublished/failed preparations may be released. Published code retains
// its existing lifetime through process exit, including retired sessions.
inline bool ReleaseCodePage(void* allocation) noexcept {
    if (!allocation) return true;
#ifdef _M_IX86
    try {
        auto& pool = codePagePool();
        const std::lock_guard<std::mutex> lock(pool.mutex);
        const auto address = reinterpret_cast<std::uintptr_t>(allocation);
        for (std::size_t i = 0; i < pool.blocks.size(); ++i) {
            auto& block = pool.blocks[i];
            const auto base = reinterpret_cast<std::uintptr_t>(block.base);
            if (address < base || address - base >= pool.arenaBytes) continue;
            const auto offset = address - base;
            if (offset % kCodePageBytes) return false;
            const auto bit = std::uint64_t{1} << (offset / kCodePageBytes);
            if (block.free & bit) return false;
            if (!::VirtualFree(allocation, kCodePageBytes, MEM_DECOMMIT)) return false;
            block.free |= bit;
            if (i < pool.next) pool.next = i;
            return true;
        }
    } catch (...) { return false; }
#endif
    return ::VirtualFree(allocation, 0, MEM_RELEASE) != FALSE;
}
}
