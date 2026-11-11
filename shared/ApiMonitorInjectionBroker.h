#pragma once
#include "ApiMonitorInjectionProtocol.h"
#include <functional>
#include <memory>
#include <vector>

namespace ks::winapi_monitor
{
    struct InjectionParticipant { DWORD pid = 0; std::uint64_t creation = 0; };
    // Hosted by the x64 main program, independent of Qt and the event queue.
    class InjectionBroker {
    public:
        using Injector = std::function<bool(DWORD, const std::wstring&, std::wstring*, std::uint64_t, HANDLE)>;
        InjectionBroker();
        ~InjectionBroker();
        InjectionBroker(const InjectionBroker&) = delete;
        InjectionBroker& operator=(const InjectionBroker&) = delete;
        bool start(DWORD rootPid, const std::wstring& agentPath, const std::wstring& session,
            const std::wstring& rootStopPath, std::wstring* error, Injector injector = {});
        void stop();
        // Stops and joins first, then transfers every accepted load identity,
        // including a canceled load whose remote thread may still finish.
        std::vector<InjectionParticipant> stopAndTakeParticipants();
        InjectionEndpoint endpoint() const;
    private:
        struct State;
        std::unique_ptr<State> m_state;
    };
}
