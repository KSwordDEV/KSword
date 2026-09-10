#pragma once

#include "../../../shared/window/DwmZOrderProtocol.h"
#include <string>

namespace ks::dwm_order
{
    enum class Stage { Window, AgentFile, DwmProcess, PrepareAgent, LoadAgent, Request, Receipt };
    struct Reply
    {
        Response response;
        Stage stage = Stage::Window;
        std::uint32_t error = 0;
        std::uint32_t loaderThreadExitCode = 0;
        std::uint32_t requestThreadExitCode = 0;
        bool loaderCompleted = false;
    };

    bool CaptureWindow(std::uint64_t hwnd, WindowIdentity& identity, std::uint32_t& error);
    Reply ExecuteRequest(const Request& request, const std::wstring& agentPath);
}
