#include "shared/ApiMonitorExportSnapshot.h"
#include <array>
#include <iostream>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (false)
extern "C" __declspec(dllexport) __declspec(noinline) int StackExportFixture(int n) { return n + 123; }

template<class T> void put(std::vector<std::uint8_t>& blob, std::size_t at, T value)
{ std::memcpy(blob.data() + at, &value, sizeof(value)); }

int main()
{
    using namespace ks::winapi_monitor;
    using namespace export_detail;
    std::vector<std::uint8_t> blob(256);
    IMAGE_EXPORT_DIRECTORY dir{}; dir.NumberOfFunctions = 3; dir.NumberOfNames = 3;
    dir.AddressOfFunctions = 0x3040; dir.AddressOfNames = 0x3050; dir.AddressOfNameOrdinals = 0x3060;
    put(blob, 0, dir);
    put<DWORD>(blob, 0x40, 0x1010); put<DWORD>(blob, 0x44, 0x3090); put<DWORD>(blob, 0x48, 0x1080);
    put<DWORD>(blob, 0x50, 0x3070); put<DWORD>(blob, 0x54, 0x3076); put<DWORD>(blob, 0x58, 0x307e);
    put<WORD>(blob, 0x60, 0); put<WORD>(blob, 0x62, 1); put<WORD>(blob, 0x64, 2);
    std::memcpy(blob.data() + 0x70, "First\0Forward\0Nearest\0", 22);
    auto result = find(blob, 0x3000, 0x5000, 0x1000, 0x2000, 0x1090);
    CHECK(result.available && result.name == "Nearest" && result.displacement == 0x10);
    result = find(blob, 0x3000, 0x5000, 0x1000, 0x2000, 0x3020);
    CHECK(!result.available); // Target must be in the executable section.
    auto broken = blob; put<WORD>(broken, 0x64, 3);
    CHECK(!find(broken, 0x3000, 0x5000, 0x1000, 0x2000, 0x1090).available);
    broken = blob; put<DWORD>(broken, 0x40, 0x3090); put<DWORD>(broken, 0x48, 0x3090);
    CHECK(!find(broken, 0x3000, 0x5000, 0x1000, 0x2000, 0x1090).available); // all forwarders
    broken = blob; put<DWORD>(broken, 0x58, 0x30ff); broken[0xff] = 'x';
    CHECK(!find(broken, 0x3000, 0x5000, 0x1000, 0x2000, 0x1090).available);
    broken = blob; dir.AddressOfNames = 0xfffffff0; put(broken, 0, dir);
    CHECK(!find(broken, 0x3000, 0x5000, 0x1000, 0x2000, 0x1090).available);
    FILETIME created{}, exited{}, kernel{}, user{};
    CHECK(::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user));
    const auto creation = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    const auto address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&StackExportFixture));
    const std::array<std::uint64_t, 1> addresses{address};
    CallerSnapshotResolver resolver; StackSnapshotBatch batch(resolver);
    CHECK(batch.start(1, 1, ::GetCurrentProcessId(), creation, addresses));
    for (int i = 0; batch.pending() && i < 5000; ++i) { batch.poll(); ::Sleep(1); }
    CHECK(batch.pending() == 0 && batch.frames()[0].imageOffsetAvailable);
    result = QueryNearestExport(::GetCurrentProcessId(), creation, batch.frames()[0]);
    CHECK(result.available && result.name == "StackExportFixture" && result.displacement == 0);
    CHECK(!QueryNearestExport(::GetCurrentProcessId(), creation + 1, batch.frames()[0]).available);
    auto stale = batch.frames()[0]; stale.mappedPath += L"changed";
    CHECK(!QueryNearestExport(::GetCurrentProcessId(), creation, stale).available);
    resolver.stop();
    std::cout << "PASS: bounded in-memory exports, forwarding, corruption, identity and live image\n";
}
