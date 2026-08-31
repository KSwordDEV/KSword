#pragma once

#include "DriverLeasePolicy.h"
#include "Win32Lean.h"

#include <cstdint>

namespace Ksword::Core {

// DriverLease coordinates KswordARK ownership across concurrently running
// KswordARKLight processes. acquire registers the current process identity;
// observeStartTransition records only a stopped-to-running transition; release
// returns true only for the last live lease of a driver started by Light.
class DriverLease final {
public:
    DriverLease() = default;
    ~DriverLease();

    DriverLease(const DriverLease&) = delete;
    DriverLease& operator=(const DriverLease&) = delete;

    bool acquire();
    void observeStartTransition(bool runningBefore, bool runningAfter);
    void observeExplicitStop();
    bool releaseRequestsStop();
    bool registered() const noexcept { return registered_; }

private:
    void closeHandles() noexcept;

    HANDLE mutex_ = nullptr;
    HANDLE mapping_ = nullptr;
    void* shared_ = nullptr;
    DWORD processId_ = 0;
    std::uint64_t processCreationTime100ns_ = 0;
    bool registered_ = false;
    bool released_ = false;
};

} // namespace Ksword::Core
