#include "shared/ApiMonitorStackSnapshot.h"
#include <iostream>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (false)

static void wait(ks::winapi_monitor::StackSnapshotBatch& batch)
{
    for (int i = 0; batch.pending() && i < 5000; ++i) { batch.poll(); ::Sleep(1); }
}

int main()
{
    using namespace ks::winapi_monitor;
    FILETIME created{}, exited{}, kernel{}, user{};
    CHECK(::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user));
    const auto creation = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    const auto address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&wait));
    const auto pid = ::GetCurrentProcessId();
    CallerSnapshotResolver resolver;
    StackSnapshotBatch batch(resolver);
    const std::array<std::uint64_t, 2> addresses{address, address};
    const std::array<std::uint64_t, 9> tooMany{};
    CHECK(!batch.start(1, 2, pid, creation, tooMany));
    CHECK(batch.start(1, 1, pid, creation, addresses));
    // A new selection before the old completes must never accept stale results.
    CHECK(batch.start(1, 2, pid, creation, addresses));
    wait(batch);
    CHECK(batch.pending() == 0 && batch.frames().size() == 2);
    for (const auto& frame : batch.frames()) {
        CHECK(frame.address == address && frame.state == StackSnapshotState::Available);
        CHECK(frame.imageOffsetAvailable && !frame.mappedPath.empty() && frame.observedTime100ns >= creation);
        CHECK(frame.imageOffset == address - reinterpret_cast<std::uintptr_t>(::GetModuleHandleW(nullptr)));
    }
    CHECK(batch.start(1, 3, pid, creation + 1, addresses));
    wait(batch);
    CHECK(batch.pending() == 0);
    for (const auto& frame : batch.frames()) {
        CHECK(frame.state == StackSnapshotState::Unavailable);
        CHECK(frame.failure == CallerSnapshotStatus::IdentityMismatch);
        CHECK(!frame.imageOffsetAvailable && frame.mappedPath.empty());
    }
    const std::array<std::uint64_t, 1> zero{0};
    CHECK(batch.start(1, 4, pid, creation, zero));
    CHECK(batch.pending() == 0 && batch.frames()[0].state == StackSnapshotState::Unavailable);
    resolver.stop();
    std::cout << "PASS: bounded stack query, stale results, identity and image offsets\n";
}
