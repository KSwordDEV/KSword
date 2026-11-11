// Deterministic, owned target for live API timing/return/loss tests. It creates
// threads only inside this process and writes actual observed results to CSV.
#define NOMINMAX
#include <Windows.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

namespace {
struct Observation {
    DWORD tid;
    unsigned sequence;
    bool expectedSuccess;
    std::uintptr_t returned;
    DWORD lastError;
    std::uint64_t elapsed100ns;
};
bool touch(const std::filesystem::path& path) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    return !!output;
}
bool markerExists(const std::filesystem::path& path) {
    return ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 1;
    const std::filesystem::path root(argv[1]);
    const auto present = root / L"metrics-present.dat";
    const auto missing = root / L"metrics-absent.dat";
    if (!std::filesystem::is_directory(root) || !touch(present) || markerExists(missing)) return 2;
    LARGE_INTEGER frequency{};
    if (!::QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) return 3;
    if (!touch(root / L"ready")) return 4;
    const auto deadline = ::GetTickCount64() + 180000;
    constexpr unsigned threads = 4;
    constexpr unsigned iterations = 400;
    for (unsigned round = 1; round <= 3; ++round) {
        const auto number = std::to_wstring(round);
        while (!markerExists(root / (L"start-" + number))) {
            if (markerExists(root / L"stop") || ::GetTickCount64() >= deadline) return 5;
            ::Sleep(10);
        }
        std::vector<std::vector<Observation>> records(threads);
        std::vector<std::thread> workers;
        for (unsigned worker = 0; worker < threads; ++worker) {
            workers.emplace_back([&, worker] {
                auto& values = records[worker]; values.reserve(iterations);
                const DWORD tid = ::GetCurrentThreadId();
                for (unsigned i = 0; i < iterations; ++i) {
                    const bool shouldSucceed = (i % 2) == 0;
                    LARGE_INTEGER begin{}, end{};
                    ::QueryPerformanceCounter(&begin);
                    const HANDLE handle = ::CreateFileW(shouldSucceed ? present.c_str() : missing.c_str(),
                        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    const DWORD error = ::GetLastError();
                    ::QueryPerformanceCounter(&end);
                    const auto elapsed = static_cast<std::uint64_t>(
                        static_cast<double>(end.QuadPart - begin.QuadPart) * 10000000.0
                        / static_cast<double>(frequency.QuadPart));
                    values.push_back({tid, i, shouldSucceed, reinterpret_cast<std::uintptr_t>(handle), error, elapsed});
                    if (handle != INVALID_HANDLE_VALUE) ::CloseHandle(handle);
                }
            });
        }
        for (auto& worker : workers) worker.join();
        std::ofstream output(root / (L"observed-" + number + L".csv"), std::ios::binary | std::ios::trunc);
        if (!output) return 6;
        output << "tid,sequence,expectedSuccess,returnValue,lastError,elapsed100ns\n";
        for (const auto& values : records) for (const auto& value : values) {
            output << value.tid << ',' << value.sequence << ',' << value.expectedSuccess << ','
                   << value.returned << ',' << value.lastError << ',' << value.elapsed100ns << '\n';
        }
        output.close();
        if (!output || !touch(root / (L"done-" + number))) return 7;
    }
    while (!markerExists(root / L"stop")) {
        if (::GetTickCount64() >= deadline) return 8;
        ::Sleep(10);
    }
    return 0;
}
