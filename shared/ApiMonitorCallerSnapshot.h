#pragma once

// Bounded, read-only *current* snapshots for recorded caller addresses.
// A snapshot is observed after the call: it must never be presented as proof of
// what occupied that address when a historic event occurred.
#include <windows.h>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <iterator>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ks::winapi_monitor
{
    struct CallerConnectionIdentity
    {
        bool verified = false;
        std::wstring processName;
    };
    // Resolve an identity only once per newly-connected pipe. This never opens
    // arbitrary processes: expectedPid must equal the actual pipe server PID.
    inline CallerConnectionIdentity VerifyCallerConnection(HANDLE pipe, std::uint32_t expectedPid,
        std::uint64_t expectedCreation)
    {
        CallerConnectionIdentity result;
        ULONG serverPid = 0;
        if (!expectedPid || !expectedCreation || !::GetNamedPipeServerProcessId(pipe, &serverPid)
            || serverPid != expectedPid) return result;
        HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, expectedPid);
        if (!process) return result;
        struct Closer { HANDLE value; ~Closer() { ::CloseHandle(value); } } closer{process};
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (!::GetProcessTimes(process, &creation, &exit, &kernel, &user)) return result;
        const auto observed = (std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        if (observed != expectedCreation || ::WaitForSingleObject(process, 0) != WAIT_TIMEOUT) return result;
        result.verified = true;
        wchar_t path[4096]{}; DWORD length = static_cast<DWORD>(std::size(path));
        if (::QueryFullProcessImageNameW(process, 0, path, &length) && length > 0) {
            std::wstring name(path, length);
            const auto separator = name.find_last_of(L"\\/");
            result.processName = separator == std::wstring::npos ? std::move(name) : name.substr(separator + 1);
        }
        return result;
    }

    struct CallerSnapshotRequest
    {
        std::uint64_t generation = 0, sequence = 0;
        std::uint32_t pid = 0;
        std::uint64_t creationTime100ns = 0, address = 0;
        std::uint64_t requestId = 0;
    };

    enum class CallerSnapshotStatus { Available, OpenFailed, IdentityMismatch, ProcessExited, QueryFailed };
    struct CallerSnapshot
    {
        CallerSnapshotRequest request;
        CallerSnapshotStatus status = CallerSnapshotStatus::QueryFailed;
        std::uint64_t observedTime100ns = 0, regionBase = 0, regionSize = 0, allocationBase = 0;
        std::uint32_t state = 0, type = 0, protect = 0, win32Error = 0;
        // Optional device path, only when Windows returns a complete path.
        std::wstring mappedPath;
    };

    class CallerSnapshotResolver final
    {
    public:
        enum class SubmitStatus { Accepted, Invalid, Full, Stopped, ResourceFailure };
        static constexpr std::size_t QueueCapacity = 256;
        static constexpr std::size_t ResultCapacity = 256;
        static constexpr std::size_t CacheCapacity = 512;

        CallerSnapshotResolver() : m_thread([this] { run(); }) {}
        CallerSnapshotResolver(const CallerSnapshotResolver&) = delete;
        CallerSnapshotResolver& operator=(const CallerSnapshotResolver&) = delete;
        ~CallerSnapshotResolver() { stop(); }

        SubmitStatus submit(const CallerSnapshotRequest& request)
        {
            if (!request.pid || !request.creationTime100ns || !request.address
                || request.address > static_cast<std::uint64_t>(UINTPTR_MAX)) return SubmitStatus::Invalid;
            std::lock_guard lock(m_mutex);
            if (m_stopping) return SubmitStatus::Stopped;
            if (m_requests.size() >= QueueCapacity) return SubmitStatus::Full;
            try { m_requests.push_back(request); } catch (...) { return SubmitStatus::ResourceFailure; }
            m_wake.notify_one();
            return SubmitStatus::Accepted;
        }
        // No callbacks: callers drain from their owning thread and validate
        // generation/sequence against their still-live event before applying.
        std::vector<CallerSnapshot> drain(std::size_t maximum = ResultCapacity)
        {
            std::vector<CallerSnapshot> output;
            std::lock_guard lock(m_mutex);
            if (maximum > m_results.size()) maximum = m_results.size();
            output.reserve(maximum);
            while (maximum--) { output.push_back(std::move(m_results.front())); m_results.pop_front(); }
            return output;
        }
        std::uint64_t droppedResults() const
        { std::lock_guard lock(m_mutex); return m_droppedResults; }
        bool isStopping() const
        { std::lock_guard lock(m_mutex); return m_stopping; }
        // requestStop never joins; use from UI/shutdown callbacks.
        void requestStop()
        {
            std::lock_guard lock(m_mutex);
            if (m_stopping) return;
            m_stopping = true; m_requests.clear(); m_wake.notify_one();
        }
        // Only one owner may join. Call on a cleanup worker, not the UI thread.
        void stop()
        {
            requestStop();
            if (m_thread.joinable()) m_thread.join();
        }

    private:
        struct Key
        {
            std::uint32_t pid;
            std::uint64_t creation, address;
            bool operator==(const Key&) const = default;
        };
        struct Hash
        {
            std::size_t operator()(const Key& key) const noexcept
            {
                auto value = std::hash<std::uint64_t>{}(key.creation);
                value ^= std::hash<std::uint64_t>{}(key.address) + 0x9e3779b9U + (value << 6) + (value >> 2);
                value ^= std::hash<std::uint32_t>{}(key.pid) + 0x9e3779b9U + (value << 6) + (value >> 2);
                return value;
            }
        };
        struct CacheEntry { CallerSnapshot value; std::chrono::steady_clock::time_point time; };
        struct Handle
        {
            HANDLE value = nullptr;
            ~Handle() { if (value) ::CloseHandle(value); }
        };
        static std::uint64_t fileTime(const FILETIME& time) noexcept
        { return (std::uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime; }
        static CallerSnapshot query(const CallerSnapshotRequest& request)
        {
            CallerSnapshot result; result.request = request;
            Handle process{::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, request.pid)};
            if (!process.value) process.value = ::OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, request.pid);
            if (!process.value) { result.status = CallerSnapshotStatus::OpenFailed; result.win32Error = ::GetLastError(); return result; }
            FILETIME creation{}, exit{}, kernel{}, user{};
            if (!::GetProcessTimes(process.value, &creation, &exit, &kernel, &user)) {
                result.status = CallerSnapshotStatus::OpenFailed; result.win32Error = ::GetLastError(); return result;
            }
            if (fileTime(creation) != request.creationTime100ns) { result.status = CallerSnapshotStatus::IdentityMismatch; return result; }
            const DWORD before = ::WaitForSingleObject(process.value, 0);
            if (before == WAIT_OBJECT_0) { result.status = CallerSnapshotStatus::ProcessExited; return result; }
            if (before != WAIT_TIMEOUT) { result.status = CallerSnapshotStatus::QueryFailed; result.win32Error = ::GetLastError(); return result; }
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQueryEx(process.value, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(request.address)), &info, sizeof(info)) != sizeof(info)) {
                result.status = CallerSnapshotStatus::QueryFailed; result.win32Error = ::GetLastError(); return result;
            }
            result.regionBase = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
            result.regionSize = info.RegionSize;
            result.allocationBase = reinterpret_cast<std::uintptr_t>(info.AllocationBase);
            result.state = info.State; result.type = info.Type; result.protect = info.Protect;
            if (info.State == MEM_COMMIT && info.Type == MEM_IMAGE) {
                using GetMappedFileNameFunction = DWORD (WINAPI*)(HANDLE, LPVOID, LPWSTR, DWORD);
                const auto kernelModule = ::GetModuleHandleW(L"kernel32.dll");
                const auto function = kernelModule ? std::bit_cast<GetMappedFileNameFunction>(::GetProcAddress(kernelModule, "K32GetMappedFileNameW")) : nullptr;
                if (function) {
                    wchar_t path[4096]{};
                    const auto length = function(process.value, info.BaseAddress, path, static_cast<DWORD>(std::size(path)));
                    if (length && length < std::size(path) - 1) result.mappedPath.assign(path, length);
                }
            }
            const DWORD after = ::WaitForSingleObject(process.value, 0);
            if (after == WAIT_OBJECT_0) { result.status = CallerSnapshotStatus::ProcessExited; result.mappedPath.clear(); return result; }
            if (after != WAIT_TIMEOUT) { result.status = CallerSnapshotStatus::QueryFailed; result.win32Error = ::GetLastError(); result.mappedPath.clear(); return result; }
            FILETIME observed{}; ::GetSystemTimeAsFileTime(&observed);
            result.observedTime100ns = fileTime(observed);
            result.status = CallerSnapshotStatus::Available;
            return result;
        }
        void run()
        {
            for (;;) {
                CallerSnapshotRequest request;
                {
                    std::unique_lock lock(m_mutex);
                    m_wake.wait(lock, [this] { return m_stopping || !m_requests.empty(); });
                    if (m_stopping) return;
                    request = m_requests.front(); m_requests.pop_front();
                }
                try {
                const Key key{request.pid, request.creationTime100ns, request.address};
                const auto now = std::chrono::steady_clock::now();
                CallerSnapshot result;
                const auto cached = m_cache.find(key);
                if (cached != m_cache.end() && now - cached->second.time < std::chrono::seconds(1)) {
                    result = cached->second.value; result.request = request;
                } else {
                    result = query(request);
                    if (result.status == CallerSnapshotStatus::Available) {
                        if (m_cache.size() >= CacheCapacity) m_cache.clear();
                        m_cache[key] = CacheEntry{result, now};
                    }
                }
                {
                    std::lock_guard lock(m_mutex);
                    if (m_stopping) return;
                    if (m_results.size() == ResultCapacity) { ++m_droppedResults; continue; }
                    m_results.push_back(std::move(result));
                }
                } catch (...) {
                    std::lock_guard lock(m_mutex); ++m_droppedResults;
                }
            }
        }
        mutable std::mutex m_mutex;
        std::condition_variable m_wake;
        std::deque<CallerSnapshotRequest> m_requests;
        std::deque<CallerSnapshot> m_results;
        std::unordered_map<Key, CacheEntry, Hash> m_cache; // worker only
        std::uint64_t m_droppedResults = 0;
        bool m_stopping = false;
        std::thread m_thread; // started only after all other members are initialized
    };
}
