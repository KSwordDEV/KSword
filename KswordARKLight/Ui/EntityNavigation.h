#pragma once

#include "../Core/EntityRef.h"
#include "../Core/Win32Lean.h"

namespace Ksword::Ui {

constexpr UINT kEntityNavigationMessage = WM_APP + 104;

// RequestEntityNavigation synchronously sends an immutable request to the root
// Lite shell. Synchronous delivery keeps the stack-owned request valid and
// returns whether a route accepted it.
bool RequestEntityNavigation(HWND source, const Ksword::Core::NavigationRequest& request);

} // namespace Ksword::Ui
