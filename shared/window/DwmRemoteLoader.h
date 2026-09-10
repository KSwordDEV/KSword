#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace ks::dwm_order::transport
{
    struct LoadResult
    {
        std::uint32_t error = 0;
        std::uint32_t threadExitCode = 0;
        std::uint64_t module = 0;
        bool loaderCompleted = false;
    };

    // Uses the target process identity. Keep deployment handles until loading ends,
    // including when the initiating call times out.
    LoadResult LoadAgent(void* process, std::uint32_t processId, const std::wstring& path,
        std::shared_ptr<void> lease = {});

    // Private x64 ABI shared with OtherDock/DwmRemoteLoader.asm.
    struct alignas(8) LoaderPacket
    {
        std::uint64_t loadLibraryEx = 0;
        std::uint64_t getLastError = 0;
        std::uint64_t addFunctionTable = 0;
        std::uint64_t deleteFunctionTable = 0;
        std::uint64_t codeBase = 0;
        std::uint64_t path = 0;
        std::uint64_t module = 0;
        std::uint32_t error = 0;
        std::uint32_t phase = 0;
        std::uint32_t unwindRegistered = 0;
        std::uint32_t reserved = 0;
        std::uint32_t functionBegin = 0;
        std::uint32_t functionEnd = 0;
        std::uint32_t unwindRva = 0;
        std::uint32_t padding = 0;
    };
    static_assert(offsetof(LoaderPacket, codeBase) == 32);
    static_assert(offsetof(LoaderPacket, path) == 40);
    static_assert(offsetof(LoaderPacket, module) == 48);
    static_assert(offsetof(LoaderPacket, error) == 56);
    static_assert(offsetof(LoaderPacket, phase) == 60);
    static_assert(offsetof(LoaderPacket, unwindRegistered) == 64);
    static_assert(offsetof(LoaderPacket, functionBegin) == 72);
    static_assert(sizeof(LoaderPacket) == 88);
}
