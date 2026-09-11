#pragma once

#include "DwmZOrderClient.h"

namespace ks::window_input
{
    enum class Mode { Unchanged, Disabled, ClickThrough, Covered, UiAccessFront, UiAccessBack, UiAccessCovered };
    enum class Status
    {
        Ok, InvalidWindow, SelfWindow, UnsupportedWindow, NativeFailure,
        DwmFailure, OrderInUse, RestoreFailed, LimitReached, OrderChanged, KernelFailure
    };
    struct Result
    {
        Status status = Status::Ok;
        std::uint32_t error = 0;
        bool enabled = false;
        bool clickThrough = false;
        bool topmost = false;
        bool managed = false;
        bool restored = false;
        bool dwmAttempted = false;
        bool kernelAttempted = false;
        std::int32_t kernelStatus = 0;
        std::uint32_t band = 0;
        Mode mode = Mode::Unchanged;
        dwm_order::Reply dwm;
    };

    // Supports child windows as well as top-level windows. Read-only.
    bool Capture(std::uint64_t hwnd, dwm_order::WindowIdentity& identity, std::uint32_t& error);
    Result Query(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath = {});
    Result Apply(const dwm_order::WindowIdentity& identity, Mode mode, const std::wstring& agentPath);
    Result Restore(const dwm_order::WindowIdentity& identity, const std::wstring& agentPath);
    Result RestoreAll(const std::wstring& agentPath);
    bool HasCoveredWindow();
    Result QueryBandSupport();
}
