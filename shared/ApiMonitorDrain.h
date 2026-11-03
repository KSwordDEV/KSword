#pragma once

#include "WinApiMonitorProtocol.h"
#include <atomic>

namespace ks::winapi_monitor
{
    enum class DrainReadResult { Packet, EndOfStream, Truncated, Aborted };

    // Read an entire byte-pipe packet through graceful stop, but allow a
    // separate bounded abort. Preserve the fact that EOF cut a packet short.
    inline DrainReadResult readDrainPacket(HANDLE pipe, ApiMonitorEventPacket& packet,
        const std::atomic_bool& abort)
    {
        DWORD offset = 0;
        while (offset < sizeof(packet)) {
            if (abort.load()) return offset ? DrainReadResult::Truncated : DrainReadResult::Aborted;
            DWORD available = 0;
            if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
                return offset ? DrainReadResult::Truncated : DrainReadResult::EndOfStream;
            if (!available) { ::Sleep(10); continue; }
            const DWORD remaining = static_cast<DWORD>(sizeof(packet)) - offset;
            const DWORD requested = available < remaining ? available : remaining;
            DWORD received = 0;
            if (!::ReadFile(pipe, reinterpret_cast<unsigned char*>(&packet) + offset, requested, &received, nullptr)
                || !received)
                return offset ? DrainReadResult::Truncated : DrainReadResult::EndOfStream;
            offset += received;
        }
        return DrainReadResult::Packet;
    }
}
