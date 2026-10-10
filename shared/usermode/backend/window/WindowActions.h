#pragma once

#include "../Win32.h"

#include <string>

namespace ks::r3::window {

// WindowActionResult reports the outcome of a user-triggered window operation.
// Inputs are produced by WindowActions functions; consumers show message text in
// status panes without throwing exceptions across the Win32 callback boundary.
struct WindowActionResult {
    bool success = false;
    std::wstring message;
    bool attempted = false,requestAccepted = false,requestAcceptedKnown = false,errorKnown = false;
    bool restoreAttempted = false,restoreAccepted = false;
    DWORD win32Error = ERROR_SUCCESS,restoreError = ERROR_SUCCESS;
    LONG_PTR nativeReturn = 0;
};

// BringWindowToFront validates and foregrounds a top-level HWND. Input is a
// transient HWND from EnumWindows; processing restores minimized windows and uses
// SetForegroundWindow; output describes success or the Win32 failure.
WindowActionResult BringWindowToFront(HWND hwnd,bool asynchronous = false);

// MinimizeWindow validates and minimizes a top-level HWND. Input is a transient
// HWND; processing calls ShowWindow(SW_MINIMIZE); output reports whether the HWND
// still exists and the command was issued.
WindowActionResult MinimizeWindow(HWND hwnd,bool asynchronous = false);

// MaximizeWindow validates and maximizes a top-level HWND. Input is a transient
// HWND; processing calls ShowWindow(SW_MAXIMIZE); output reports command status.
WindowActionResult MaximizeWindow(HWND hwnd,bool asynchronous = false);

// RestoreWindow validates and restores a top-level HWND. Input is a transient
// HWND; processing calls ShowWindow(SW_RESTORE); output reports command status.
WindowActionResult RestoreWindow(HWND hwnd,bool asynchronous = false);

// CloseWindowGracefully posts WM_CLOSE to a top-level HWND. Input is a transient
// HWND; processing does not terminate processes or duplicate handles; output
// reports whether the close request was posted.
WindowActionResult CloseWindowGracefully(HWND hwnd);

} // namespace ks::r3::window
