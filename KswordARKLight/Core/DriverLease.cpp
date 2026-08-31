#include "DriverLease.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace Ksword::Core {
namespace {

constexpr wchar_t kLeaseMutexName[] = L"Local\\KswordARKLight.DriverLease.Mutex.v1";
constexpr wchar_t kLeaseMappingName[] = L"Local\\KswordARKLight.DriverLease.Mapping.v1";
constexpr std::uint32_t kLeaseMagic = 0x4C534B41U; // AKSL
constexpr std::uint32_t kLeaseVersion = 1U;
constexpr std::size_t kMaximumLeases = 32U;

struct LeaseEntry final {
    DWORD processId = 0;
    std::uint64_t creationTime100ns = 0;
};

struct SharedLeaseState final {
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::uint32_t driverOwnedByLight = 0;
    std::uint32_t reserved = 0;
    std::array<LeaseEntry, kMaximumLeases> leases{};
};

class MutexGuard final {
public:
    explicit MutexGuard(HANDLE mutex) : mutex_(mutex) {
        if (mutex_) {
            const DWORD wait = ::WaitForSingleObject(mutex_, 5000);
            locked_ = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
        }
    }
    ~MutexGuard() {
        if (locked_) {
            ::ReleaseMutex(mutex_);
        }
    }
    bool locked() const noexcept { return locked_; }
private:
    HANDLE mutex_ = nullptr;
    bool locked_ = false;
};

std::uint64_t FileTimeValue(const FILETIME& value) noexcept {
    ULARGE_INTEGER integer{};
    integer.LowPart = value.dwLowDateTime;
    integer.HighPart = value.dwHighDateTime;
    return integer.QuadPart;
}

std::uint64_t ProcessCreationTime(HANDLE process) noexcept {
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    return process && ::GetProcessTimes(process, &creation, &exit, &kernel, &user)
        ? FileTimeValue(creation)
        : 0U;
}

bool IsEntryAlive(const LeaseEntry& entry) noexcept {
    if (entry.processId == 0 || entry.creationTime100ns == 0) {
        return false;
    }
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.processId);
    if (!process) {
        return false;
    }
    const DWORD wait = ::WaitForSingleObject(process, 0);
    const std::uint64_t creation = ProcessCreationTime(process);
    ::CloseHandle(process);
    return wait == WAIT_TIMEOUT && creation == entry.creationTime100ns;
}

void InitializeIfNeeded(SharedLeaseState& state) noexcept {
    if (state.magic == kLeaseMagic && state.version == kLeaseVersion) {
        return;
    }
    std::memset(&state, 0, sizeof(state));
    state.magic = kLeaseMagic;
    state.version = kLeaseVersion;
}

std::size_t CompactLiveLeases(SharedLeaseState& state) noexcept {
    std::array<LeaseEntry, kMaximumLeases> live{};
    std::size_t count = 0;
    for (const LeaseEntry& entry : state.leases) {
        if (IsEntryAlive(entry) && count < live.size()) {
            live[count++] = entry;
        }
    }
    state.leases = live;
    return count;
}

SharedLeaseState* State(void* shared) noexcept {
    return static_cast<SharedLeaseState*>(shared);
}

} // namespace

DriverLease::~DriverLease() {
    if (!released_) {
        (void)releaseRequestsStop();
    }
    closeHandles();
}

bool DriverLease::acquire() {
    if (registered_) {
        return true;
    }
    released_ = false;
    processId_ = ::GetCurrentProcessId();
    processCreationTime100ns_ = ProcessCreationTime(::GetCurrentProcess());
    if (processCreationTime100ns_ == 0) {
        return false;
    }

    mutex_ = ::CreateMutexW(nullptr, FALSE, kLeaseMutexName);
    if (!mutex_) {
        closeHandles();
        return false;
    }
    mapping_ = ::CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        static_cast<DWORD>(sizeof(SharedLeaseState)),
        kLeaseMappingName);
    if (!mapping_) {
        closeHandles();
        return false;
    }
    shared_ = ::MapViewOfFile(mapping_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedLeaseState));
    if (!shared_) {
        closeHandles();
        return false;
    }

    bool acquired = false;
    {
        MutexGuard guard(mutex_);
        if (guard.locked()) {
            SharedLeaseState& state = *State(shared_);
            InitializeIfNeeded(state);
            const std::size_t count = CompactLiveLeases(state);
            for (std::size_t index = 0; index < count; ++index) {
                if (state.leases[index].processId == processId_ &&
                    state.leases[index].creationTime100ns == processCreationTime100ns_) {
                    acquired = true;
                    break;
                }
            }
            if (!acquired && count < state.leases.size()) {
                state.leases[count] = { processId_, processCreationTime100ns_ };
                acquired = true;
            }
        }
    }
    if (!acquired) {
        closeHandles();
        return false;
    }
    registered_ = true;
    return true;
}

void DriverLease::observeStartTransition(const bool runningBefore, const bool runningAfter) {
    if (!registered_ || !DriverLeasePolicy::OwnsStartTransition(runningBefore, runningAfter)) {
        return;
    }
    MutexGuard guard(mutex_);
    if (guard.locked() && shared_) {
        SharedLeaseState& state = *State(shared_);
        InitializeIfNeeded(state);
        state.driverOwnedByLight = 1U;
    }
}

void DriverLease::observeExplicitStop() {
    if (!registered_) {
        return;
    }
    MutexGuard guard(mutex_);
    if (guard.locked() && shared_) {
        SharedLeaseState& state = *State(shared_);
        InitializeIfNeeded(state);
        state.driverOwnedByLight = 0U;
    }
}

bool DriverLease::releaseRequestsStop() {
    if (released_) {
        return false;
    }
    released_ = true;
    if (!registered_ || !shared_) {
        registered_ = false;
        return false;
    }

    bool shouldStop = false;
    {
        MutexGuard guard(mutex_);
        if (guard.locked()) {
            SharedLeaseState& state = *State(shared_);
            InitializeIfNeeded(state);
            for (LeaseEntry& entry : state.leases) {
                if (entry.processId == processId_ && entry.creationTime100ns == processCreationTime100ns_) {
                    entry = {};
                }
            }
            const std::size_t remaining = CompactLiveLeases(state);
            shouldStop = DriverLeasePolicy::ShouldStopOnLastRelease(state.driverOwnedByLight != 0U, remaining);
            if (shouldStop) {
                state.driverOwnedByLight = 0U;
            }
        }
    }
    registered_ = false;
    return shouldStop;
}

void DriverLease::closeHandles() noexcept {
    if (shared_) {
        ::UnmapViewOfFile(shared_);
        shared_ = nullptr;
    }
    if (mapping_) {
        ::CloseHandle(mapping_);
        mapping_ = nullptr;
    }
    if (mutex_) {
        ::CloseHandle(mutex_);
        mutex_ = nullptr;
    }
}

} // namespace Ksword::Core
