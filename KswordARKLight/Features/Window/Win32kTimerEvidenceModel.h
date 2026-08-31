#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::ark {
struct Win32kTimersResult;
}

namespace Ksword::Features::Window {

// Win32kTimerEvidenceRow is one immutable, display-ready tagTIMER evidence
// record. relatedProcessId is populated only when the driver marked the owner
// thread fields present, so callers can route a process investigation without
// treating an absent packet field as a valid PID.
struct Win32kTimerEvidenceRow {
    std::wstring category;
    std::wstring source;
    std::wstring item;
    std::wstring status;
    std::wstring detail;
    std::uint32_t relatedProcessId = 0;
};

// Win32kTimerEvidenceStatusText formats a protocol status code without making
// a driver call. Unknown future values remain explicit instead of being
// interpreted as success.
std::wstring Win32kTimerEvidenceStatusText(std::uint32_t status);

// BuildWin32kTimerEvidenceRows projects one already-collected driver snapshot
// into generic audit rows. It performs no driver, process, or window query and
// never changes timer state.
std::vector<Win32kTimerEvidenceRow> BuildWin32kTimerEvidenceRows(
    const ksword::ark::Win32kTimersResult& result);

} // namespace Ksword::Features::Window
