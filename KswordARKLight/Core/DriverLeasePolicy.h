#pragma once

#include <cstddef>

namespace Ksword::Core {

// DriverLeasePolicy is the pure decision surface shared by the production
// cross-process lease and the headless test adapter. It never touches SCM or
// process state; callers supply observed transitions and live lease counts.
class DriverLeasePolicy final {
public:
    static constexpr bool OwnsStartTransition(bool runningBefore, bool runningAfter) noexcept {
        return !runningBefore && runningAfter;
    }

    static constexpr bool ShouldStopOnLastRelease(bool driverOwnedByLight, std::size_t remainingLeases) noexcept {
        return driverOwnedByLight && remainingLeases == 0U;
    }
};

} // namespace Ksword::Core
