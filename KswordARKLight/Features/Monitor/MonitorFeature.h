#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Monitor {

// CreateMonitorFeaturePage creates the ETW-only monitor page. Inputs are parent
// HWND and bounds; processing delegates to EtwMonitorView; output is the page
// HWND or nullptr. Integration session should wire this facade into docks.
HWND CreateMonitorFeaturePage(HWND parent, const RECT& bounds);

bool RequestMonitorFeatureProcess(HWND page, DWORD processId);

} // namespace Ksword::Features::Monitor
