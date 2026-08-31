#pragma once

#include "../../Core/Win32Lean.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace Ksword::Features::Monitor {

// EtwEvent describes one compact ETW event row for the monitor page.
// Inputs come from EVENT_RECORD metadata; processing is performed by
// EtwSessionController; rows are later consumed by EtwMonitorView.
struct EtwEvent {
    std::wstring timeText;
    std::wstring providerText;
    std::uint16_t eventId = 0;
    std::uint8_t version = 0;
    std::uint8_t level = 0;
    std::uint8_t opcode = 0;
    std::uint16_t task = 0;
    std::uint32_t processId = 0;
    std::uint32_t threadId = 0;
    std::uint64_t keyword = 0;
    std::wstring summary;
};

// EtwEventModel owns the in-memory event list displayed by the ETW page.
// Inputs are appended EtwEvent rows; processing trims the list to a bounded
// capacity; callers receive snapshots so worker/UI threads do not share iterators.
class EtwEventModel final {
public:
    explicit EtwEventModel(std::size_t maxRows = 5000);

    // append adds one row and trims the oldest rows when the limit is exceeded.
    // Input is an event row; processing is protected by a mutex; no value returns.
    void append(const EtwEvent& eventRow);

    // clear removes all rows. There are no inputs and no return value.
    void clear();

    // snapshot returns a stable copy for UI rebuilds. There are no inputs.
    std::vector<EtwEvent> snapshot() const;

    // rowCount returns the current number of buffered rows. There are no inputs.
    std::size_t rowCount() const;

private:
    mutable std::mutex mutex_;
    std::vector<EtwEvent> rows_;
    std::size_t maxRows_;
};

// GuidToString converts a GUID to canonical text. Input is a GUID; output is a
// brace-wrapped uppercase GUID string suitable for list display and filtering.
std::wstring GuidToString(const GUID& value);

// FileTimeToLocalText converts an ETW timestamp into local display text. Input
// is a FILETIME-compatible value; output is a short local timestamp string.
std::wstring FileTimeToLocalText(const LARGE_INTEGER& timestamp);

// BuildVisibleEtwEventsTsv serializes a stable ETW view snapshot in its
// displayed order. Inputs are the immutable UI-owned event rows and filtered
// source indexes; output is an empty string when no valid visible row exists.
// The helper never touches a live ETW session or any UI handle.
std::wstring BuildVisibleEtwEventsTsv(
    const std::vector<EtwEvent>& rows,
    const std::vector<std::size_t>& visibleIndexes);

} // namespace Ksword::Features::Monitor
