#include "shared/ApiMonitorCallerSnapshot.h"
#include <chrono>
#include <iostream>
#include <thread>
using namespace ks::winapi_monitor;
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << " " #x "\n"; return 1; } } while (false)
static std::vector<CallerSnapshot> waitResults(CallerSnapshotResolver& resolver, std::size_t n)
{
    std::vector<CallerSnapshot> all;
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (all.size() < n && std::chrono::steady_clock::now() < end) {
        auto part = resolver.drain();
        for (auto& value : part) all.push_back(std::move(value));
        if (all.size() < n) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return all;
}
int main()
{
    FILETIME created{}, exited{}, kernel{}, user{};
    CHECK(::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user));
    const std::uint64_t identity = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    // Both ends belong to this fixture process; no external process is touched.
    const auto pipeName = std::wstring(L"\\\\.\\pipe\\KSword-caller-test-")
        + std::to_wstring(::GetCurrentProcessId()) + L"-" + std::to_wstring(::GetTickCount64());
    const HANDLE server = ::CreateNamedPipeW(pipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, nullptr);
    CHECK(server != INVALID_HANDLE_VALUE);
    const HANDLE client = ::CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    CHECK(client != INVALID_HANDLE_VALUE);
    CHECK(::ConnectNamedPipe(server, nullptr) || ::GetLastError() == ERROR_PIPE_CONNECTED);
    const auto verified = VerifyCallerConnection(client, ::GetCurrentProcessId(), identity);
    CHECK(verified.verified && !verified.processName.empty());
    CHECK(!VerifyCallerConnection(client, ::GetCurrentProcessId(), identity + 1).verified);
    CHECK(!VerifyCallerConnection(client, ::GetCurrentProcessId() + 1, identity).verified);
    CHECK(!VerifyCallerConnection(client, ::GetCurrentProcessId(), 0).verified);
    ::CloseHandle(client); ::CloseHandle(server);
    void* memory = ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(memory != nullptr);
    const auto address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(memory));
    CallerSnapshotResolver resolver;
    CallerSnapshotRequest request{1, 2, ::GetCurrentProcessId(), identity, address};
    CHECK(resolver.submit({}) == CallerSnapshotResolver::SubmitStatus::Invalid);
    CHECK(resolver.submit(request) == CallerSnapshotResolver::SubmitStatus::Accepted);
    auto results = waitResults(resolver, 1);
    CHECK(results.size() == 1 && results[0].status == CallerSnapshotStatus::Available);
    CHECK(results[0].request.generation == 1 && results[0].request.sequence == 2);
    CHECK(results[0].observedTime100ns >= identity && results[0].state == MEM_COMMIT);
    CHECK(results[0].type == MEM_PRIVATE && results[0].regionBase <= address);
    CHECK(address - results[0].regionBase < results[0].regionSize);
    CHECK((results[0].protect & 0xff) == PAGE_READWRITE && results[0].mappedPath.empty());
    const auto firstObserved = results[0].observedTime100ns;
    CHECK(::VirtualFree(memory, 0, MEM_RELEASE));
    request.sequence = 3;
    CHECK(resolver.submit(request) == CallerSnapshotResolver::SubmitStatus::Accepted);
    results = waitResults(resolver, 1);
    CHECK(results.size() == 1 && results[0].request.sequence == 3);
    CHECK(results[0].status == CallerSnapshotStatus::Available && results[0].observedTime100ns == firstObserved);
    // Exact identity gates caches as well as process queries.
    request.sequence = 4; ++request.creationTime100ns;
    CHECK(resolver.submit(request) == CallerSnapshotResolver::SubmitStatus::Accepted);
    results = waitResults(resolver, 1);
    CHECK(results.size() == 1 && results[0].status == CallerSnapshotStatus::IdentityMismatch);
    request.creationTime100ns = identity;
    request.sequence = 5;
    request.address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(::GetModuleHandleW(nullptr)));
    CHECK(resolver.submit(request) == CallerSnapshotResolver::SubmitStatus::Accepted);
    results = waitResults(resolver, 1);
    CHECK(results.size() == 1 && results[0].status == CallerSnapshotStatus::Available);
    CHECK(results[0].type == MEM_IMAGE && results[0].observedTime100ns >= identity);
    CHECK(resolver.droppedResults() == 0);
    resolver.stop();
    CHECK(resolver.submit(request) == CallerSnapshotResolver::SubmitStatus::Stopped);
    {
        CallerSnapshotResolver saturated;
        int accepted = 0;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (accepted < 600 && std::chrono::steady_clock::now() < deadline) {
            request.sequence = static_cast<std::uint64_t>(accepted + 10);
            const auto status = saturated.submit(request);
            if (status == CallerSnapshotResolver::SubmitStatus::Accepted) ++accepted;
            else if (status == CallerSnapshotResolver::SubmitStatus::Full) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            else CHECK(false);
        }
        CHECK(accepted == 600);
        while (saturated.droppedResults() == 0 && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        CHECK(saturated.droppedResults() > 0);
        CHECK(saturated.drain().size() == CallerSnapshotResolver::ResultCapacity);
        saturated.stop();
    }
    std::cout << "PASS: bounded caller snapshots, process identity, cache timestamps, image/private and shutdown\n";
}
