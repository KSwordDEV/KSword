#pragma once

#include "WindowTypes.h"

namespace ks::r3::window {

// EnumerateTopLevelWindows returns all retained non-desktop window rows. There
// is no input; processing uses EnumWindows plus GetWindowInfo, GetClassName and
// GetWindowText; output is a snapshot without any desktop-management behavior.
WindowEnumerationResult EnumerateTopLevelWindows();

// QueryWindowDetails returns live details for one HWND. Input is a transient HWND
// from the current snapshot; processing calls IsWindow before querying Win32
// properties; output has found=false when the window no longer exists.
WindowDetail QueryWindowDetails(HWND hwnd);

} // namespace ks::r3::window
