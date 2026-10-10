#include "WindowActions.h"

#include "../Common.h"
#include "WindowTypes.h"

namespace ks::r3::window {
namespace {

// ValidateWindowForAction checks that an HWND still maps to a live window. Input
// is the transient HWND selected in the view; output is an error result when the
// window disappeared, otherwise a successful no-op result used by callers.
WindowActionResult ValidateWindowForAction(HWND hwnd) {
    if (!hwnd || !::IsWindow(hwnd)) {
        WindowActionResult r{false,L"Window no longer exists."};r.errorKnown = true;r.win32Error = ERROR_INVALID_WINDOW_HANDLE;return r;
    }
    return { true, L"OK" };
}

} // namespace

WindowActionResult BringWindowToFront(HWND hwnd,bool asynchronous) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    WindowActionResult result;result.attempted = true;
    if (::IsIconic(hwnd)) {
        result.restoreAttempted = true;
        if (asynchronous) {::SetLastError(ERROR_SUCCESS);result.restoreAccepted = ::ShowWindowAsync(hwnd,SW_RESTORE) != FALSE;if (!result.restoreAccepted) result.restoreError = ::GetLastError();}
        else ::ShowWindow(hwnd,SW_RESTORE);
    }
    ::SetLastError(ERROR_SUCCESS);const BOOL ok = ::SetForegroundWindow(hwnd);const auto error = ok ? ERROR_SUCCESS : ::GetLastError();
    result.success = ok != FALSE;result.requestAcceptedKnown = true;result.requestAccepted = result.success;result.nativeReturn = ok;result.errorKnown = !ok && error != ERROR_SUCCESS;result.win32Error = error;
    result.message = !ok ? L"SetForegroundWindow failed for " + HwndToText(hwnd) + L": " + ks::r3::common::LastErrorMessage(error) : L"Brought window to front: " + HwndToText(hwnd);
    return result;
}

WindowActionResult MinimizeWindow(HWND hwnd,bool asynchronous) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    WindowActionResult result{true,L"Minimize requested: " + HwndToText(hwnd)};result.attempted = true;
    ::SetLastError(ERROR_SUCCESS);const auto value = asynchronous ? ::ShowWindowAsync(hwnd,SW_MINIMIZE) : ::ShowWindow(hwnd,SW_MINIMIZE);
    result.nativeReturn = value;result.requestAcceptedKnown = asynchronous;result.requestAccepted = asynchronous && value != FALSE;
    if (asynchronous && !value) {result.success = false;result.win32Error = ::GetLastError();result.errorKnown = result.win32Error != ERROR_SUCCESS;}
    return result;
}

WindowActionResult MaximizeWindow(HWND hwnd,bool asynchronous) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    WindowActionResult result{true,L"Maximize requested: " + HwndToText(hwnd)};result.attempted = true;
    ::SetLastError(ERROR_SUCCESS);const auto value = asynchronous ? ::ShowWindowAsync(hwnd,SW_MAXIMIZE) : ::ShowWindow(hwnd,SW_MAXIMIZE);
    result.nativeReturn = value;result.requestAcceptedKnown = asynchronous;result.requestAccepted = asynchronous && value != FALSE;
    if (asynchronous && !value) {result.success = false;result.win32Error = ::GetLastError();result.errorKnown = result.win32Error != ERROR_SUCCESS;}
    return result;
}

WindowActionResult RestoreWindow(HWND hwnd,bool asynchronous) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    WindowActionResult result{true,L"Restore requested: " + HwndToText(hwnd)};result.attempted = true;
    ::SetLastError(ERROR_SUCCESS);const auto value = asynchronous ? ::ShowWindowAsync(hwnd,SW_RESTORE) : ::ShowWindow(hwnd,SW_RESTORE);
    result.nativeReturn = value;result.requestAcceptedKnown = asynchronous;result.requestAccepted = asynchronous && value != FALSE;
    if (asynchronous && !value) {result.success = false;result.win32Error = ::GetLastError();result.errorKnown = result.win32Error != ERROR_SUCCESS;}
    return result;
}

WindowActionResult CloseWindowGracefully(HWND hwnd) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    ::SetLastError(ERROR_SUCCESS);const BOOL ok = ::PostMessageW(hwnd,WM_CLOSE,0,0);const auto error = ok ? ERROR_SUCCESS : ::GetLastError();
    WindowActionResult result{ok != FALSE,!ok ? L"WM_CLOSE post failed for " + HwndToText(hwnd) + L": " + ks::r3::common::LastErrorMessage(error) : L"Close requested: " + HwndToText(hwnd)};
    result.attempted = true;result.requestAcceptedKnown = true;result.requestAccepted = ok != FALSE;result.nativeReturn = ok;result.win32Error = error;result.errorKnown = !ok && error != ERROR_SUCCESS;return result;
}

} // namespace ks::r3::window
