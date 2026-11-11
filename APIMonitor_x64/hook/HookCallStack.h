#pragma once

#include "../../shared/ApiMonitorCallStack.h"

namespace apimon
{
    inline thread_local ks::winapi_monitor::CallStackTrailer g_currentHookStack{};

    // Called only after the re-entry guard is set. CaptureStackBackTrace may
    // include internal hook frames; consumers must not call them the caller.
    inline void CaptureHookCallStack() noexcept
    {
        g_currentHookStack.count = 0;
        const DWORD lastError = ::GetLastError();
        void* addresses[ks::winapi_monitor::kCallStackFrameLimit]{};
        USHORT count = 0;
        __try { count = ::CaptureStackBackTrace(0, static_cast<DWORD>(std::size(addresses)), addresses, nullptr); }
        __except (EXCEPTION_EXECUTE_HANDLER) { count = 0; }
        for (USHORT i = 0; i < count; ++i)
            g_currentHookStack.frames[i] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(addresses[i]));
        g_currentHookStack.count = count;
        ::SetLastError(lastError);
    }
    inline void ClearHookCallStack() noexcept { g_currentHookStack.count = 0; }
    inline void StoreHookCallStack(ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
    { (void)ks::winapi_monitor::WriteCallStackTrailer(packet, g_currentHookStack); }
}
