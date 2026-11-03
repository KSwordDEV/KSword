#include "APIMonitor_x64/hook/HookCallStack.h"
#include <cassert>
#include <cstring>

void storeFromOtherTranslationUnit(ks::winapi_monitor::ApiMonitorEventPacket& packet);

__declspec(noinline) static void captureHere()
{
    ::SetLastError(0x5a5a);
    apimon::CaptureHookCallStack();
    assert(::GetLastError() == 0x5a5a);
}

int main()
{
    using namespace ks::winapi_monitor;
    ApiMonitorEventPacket packet{};
    packet.category = static_cast<std::uint32_t>(EventCategory::File);
    std::memcpy(packet.detailText, L"path=example", sizeof(L"path=example"));
    const auto before = packet;
    CallStackTrailer decoded{};
    assert(!ReadCallStackTrailer(packet, decoded));
    captureHere();
    assert(apimon::g_currentHookStack.count > 0);
    storeFromOtherTranslationUnit(packet);
    assert(ReadCallStackTrailer(packet, decoded));
    assert(decoded.count == apimon::g_currentHookStack.count);
    assert(!std::wcscmp(packet.detailText, before.detailText));
    assert(decoded.frames[0] != 0);
    apimon::ClearHookCallStack();
    assert(apimon::g_currentHookStack.count == 0);

    ApiMonitorEventPacket full{};
    full.category = static_cast<std::uint32_t>(EventCategory::File);
    for (std::size_t i = 0; i < kStackTrailerStart; ++i) full.detailText[i] = L'x';
    const auto unchanged = full;
    assert(!WriteCallStackTrailer(full, decoded));
    assert(std::memcmp(&full, &unchanged, sizeof(full)) == 0);
    assert(!ReadCallStackTrailer(full, decoded));
    packet.eventKind = static_cast<std::uint32_t>(EventKind::IoComplete);
    assert(!ReadCallStackTrailer(packet, decoded));
    packet.eventKind = static_cast<std::uint32_t>(EventKind::ApiCall);
    packet.category = static_cast<std::uint32_t>(EventCategory::Internal);
    assert(!ReadCallStackTrailer(packet, decoded));
}
