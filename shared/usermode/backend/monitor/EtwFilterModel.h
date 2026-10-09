#pragma once

#include "../Win32.h"

#include <evntrace.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ks::r3::monitor {

// EtwProviderPreset describes one ETW provider option shown in the filter
// dialog. Inputs are static GUID/name pairs; EtwSessionController consumes the
// enabled presets when starting a trace session.
struct EtwProviderPreset {
    std::wstring name;
    GUID providerGuid{};
    bool enabled = true;
    UCHAR level = TRACE_LEVEL_INFORMATION;
    std::uint64_t matchAnyKeyword = 0;
};

// EtwFilterState stores the whole configurable ETW filter state. The main page
// does not keep these controls visible; EtwFilterDialog edits this model in a
// modal Win32 dialog, then EtwSessionController reads the accepted state.
struct EtwFilterState {
    std::vector<EtwProviderPreset> providers;
    std::uint32_t processId = 0;
    std::uint8_t minimumLevel = TRACE_LEVEL_VERBOSE;
    bool onlyCurrentProcess = false;
};

// EtwFilterModel owns default and current filter state. Inputs are user edits
// from EtwFilterDialog; output is a copy consumed by EtwSessionController.
class EtwFilterModel final {
public:
    EtwFilterModel();

    // state returns the current filter settings by value. There are no inputs.
    EtwFilterState state() const;

    // setState replaces the model. Input is a complete state; no value returns.
    void setState(const EtwFilterState& state);

    // resetDefaults restores built-in providers and broad filtering.
    // There are no inputs and no return value.
    void resetDefaults();

private:
    EtwFilterState state_;
};

// EventMatchesFilter evaluates a captured event against user filters. Inputs
// are event metadata and filter state; output is true when the row should be
// retained by the model.
bool EventMatchesFilter(
    std::uint32_t processId,
    std::uint8_t level,
    const EtwFilterState& state);

} // namespace ks::r3::monitor
