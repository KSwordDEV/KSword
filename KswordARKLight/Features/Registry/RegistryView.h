#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::Registry {

// CreateRegistryView creates the Win32 registry dock surface. Inputs are parent
// HWND and initial bounds; processing creates a persistent toolbar/list/editor
// page; output is the child HWND or nullptr on failure.
HWND CreateRegistryView(HWND parent, const RECT& bounds);

bool RequestRegistryViewNavigate(HWND page, const std::wstring& path);

} // namespace Ksword::Features::Registry
