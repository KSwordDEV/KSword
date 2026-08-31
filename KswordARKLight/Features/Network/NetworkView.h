#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Network {

// CreateNetworkFeatureView creates the unified Network workspace. Inputs are
// the parent HWND and parent-relative bounds; processing creates one tab host
// for connection management, diagnostics, firewall rules and the five R0/R3
// audit pages; output is the created child HWND or nullptr on failure.
HWND CreateNetworkFeatureView(HWND parent, const RECT& bounds);

// ResizeNetworkFeatureView moves an existing Network audit page. Inputs are the
// child HWND and new bounds; processing delegates layout to WM_SIZE; no value is
// returned.
void ResizeNetworkFeatureView(HWND view, const RECT& bounds);

bool RequestNetworkFeatureViewProcess(HWND view, DWORD processId);

} // namespace Ksword::Features::Network
