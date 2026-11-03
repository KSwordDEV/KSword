#pragma once

#include "WinApiMonitorProtocol.h"
#include <array>
#include <cstring>

namespace ks::winapi_monitor
{
    // Optional trailer in otherwise unused bytes after detailText's NUL.  Old
    // readers see the unchanged string; the original packet is archived.
    // Never reduce the original detail text to make space for a stack.
    inline constexpr std::size_t kCallStackFrameLimit = 8;
    struct CallStackTrailer {
        std::uint32_t magic = 0x3154534bu; // KST1, little endian
        std::uint16_t version = 1;
        std::uint16_t count = 0;
        std::uint64_t frames[kCallStackFrameLimit]{};
    };
    static_assert(sizeof(CallStackTrailer) == 72);
    static_assert(sizeof(wchar_t) == 2);
    inline constexpr std::size_t kStackTrailerStart =
        (sizeof(ApiMonitorEventPacket::detailText) - sizeof(CallStackTrailer)) / sizeof(wchar_t);

    inline bool WriteCallStackTrailer(ApiMonitorEventPacket& packet, const CallStackTrailer& trailer) noexcept
    {
        if (packet.eventKind != static_cast<std::uint32_t>(EventKind::ApiCall)
            || packet.category == static_cast<std::uint32_t>(EventCategory::Internal)
            || trailer.magic != 0x3154534bu || trailer.version != 1
            || trailer.count == 0 || trailer.count > kCallStackFrameLimit) return false;
        std::size_t length = 0;
        while (length < kStackTrailerStart && packet.detailText[length]) ++length;
        if (length == kStackTrailerStart) return false;
        std::memcpy(reinterpret_cast<unsigned char*>(packet.detailText) + kStackTrailerStart * sizeof(wchar_t),
                    &trailer, sizeof(trailer));
        return true;
    }

    inline bool ReadCallStackTrailer(const ApiMonitorEventPacket& packet, CallStackTrailer& result) noexcept
    {
        if (packet.eventKind != static_cast<std::uint32_t>(EventKind::ApiCall)
            || packet.category == static_cast<std::uint32_t>(EventCategory::Internal)) return false;
        std::size_t length = 0;
        while (length < kStackTrailerStart && packet.detailText[length]) ++length;
        if (length == kStackTrailerStart) return false;
        CallStackTrailer value{};
        std::memcpy(&value, reinterpret_cast<const unsigned char*>(packet.detailText)
                    + kStackTrailerStart * sizeof(wchar_t), sizeof(value));
        if (value.magic != 0x3154534bu || value.version != 1 || !value.count
            || value.count > kCallStackFrameLimit) return false;
        for (std::size_t i = 0; i < value.count; ++i) if (!value.frames[i]) return false;
        result = value;
        return true;
    }
}
