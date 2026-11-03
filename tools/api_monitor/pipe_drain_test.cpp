#include "shared/ApiMonitorDrain.h"
#include <thread>
#include <cstdio>

using namespace ks::winapi_monitor;

static bool run(bool truncated)
{
    const auto name = L"\\\\.\\pipe\\KswordDrainTest_" + std::to_wstring(::GetCurrentProcessId());
    HANDLE server = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 0, nullptr);
    if (server == INVALID_HANDLE_VALUE) return false;
    HANDLE client = ::CreateFileW(name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (client == INVALID_HANDLE_VALUE) { ::CloseHandle(server); return false; }
    if (!::ConnectNamedPipe(server, nullptr) && ::GetLastError() != ERROR_PIPE_CONNECTED) return false;
    std::atomic_bool abort{false}, stopRequested{true};
    std::thread sender([&] {
        ::Sleep(30); // Tail arrives after the controller has requested Stop.
        ApiMonitorEventPacket packet{}; packet.pid = ::GetCurrentProcessId();
        DWORD written = 0;
        ::WriteFile(server, &packet, static_cast<DWORD>(sizeof(packet)), &written, nullptr);
        if (truncated) ::WriteFile(server, &packet, 17, &written, nullptr);
        ::CloseHandle(server);
    });
    ApiMonitorEventPacket packet{};
    const auto first = readDrainPacket(client, packet, abort);
    const auto last = readDrainPacket(client, packet, abort);
    sender.join(); ::CloseHandle(client);
    return stopRequested.load() && first == DrainReadResult::Packet
        && last == (truncated ? DrainReadResult::Truncated : DrainReadResult::EndOfStream);
}

static bool runBurst()
{
    const auto name = L"\\\\.\\pipe\\KswordDrainBurst_" + std::to_wstring(::GetCurrentProcessId());
    HANDLE server = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 0, nullptr);
    if (server == INVALID_HANDLE_VALUE) return false;
    HANDLE client = ::CreateFileW(name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (client == INVALID_HANDLE_VALUE) { ::CloseHandle(server); return false; }
    if (!::ConnectNamedPipe(server, nullptr) && ::GetLastError() != ERROR_PIPE_CONNECTED) return false;
    std::atomic_bool abort{false}, writeFailed{false};
    constexpr unsigned count = 5000;
    std::thread sender([&] {
        for (unsigned index = 0; index < count; ++index) {
            ApiMonitorEventPacket packet{}; packet.apiId = index;
            DWORD written = 0;
            if (!::WriteFile(server, &packet, static_cast<DWORD>(sizeof(packet)), &written, nullptr)
                || written != sizeof(packet)) { writeFailed.store(true); break; }
        }
        ::CloseHandle(server);
    });
    unsigned received = 0;
    ApiMonitorEventPacket packet{};
    while (readDrainPacket(client, packet, abort) == DrainReadResult::Packet) {
        if (packet.apiId != received) { abort.store(true); break; }
        ++received;
    }
    ::CloseHandle(client); sender.join();
    return !writeFailed.load() && received == count;
}

int main()
{
    if (!run(false) || !run(true) || !runBurst()) return 1;
    std::puts("PASS: tail packet drained after stop; truncated EOF detected; 5000 burst packets preserved");
    return 0;
}
