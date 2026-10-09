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
        return { false, L"Window no longer exists." };
    }
    return { true, L"OK" };
}

} // namespace

WindowActionResult BringWindowToFront(HWND hwnd) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    if (::IsIconic(hwnd)) {
        ::ShowWindow(hwnd, SW_RESTORE);
    }
    if (!::SetForegroundWindow(hwnd)) {
        return { false, L"SetForegroundWindow failed for " + HwndToText(hwnd) + L": " + ks::r3::common::LastErrorMessage() };
    }
    return { true, L"Brought window to front: " + HwndToText(hwnd) };
}

WindowActionResult MinimizeWindow(HWND hwnd) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    ::ShowWindow(hwnd, SW_MINIMIZE);
    return { true, L"Minimize requested: " + HwndToText(hwnd) };
}

WindowActionResult MaximizeWindow(HWND hwnd) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    ::ShowWindow(hwnd, SW_MAXIMIZE);
    return { true, L"Maximize requested: " + HwndToText(hwnd) };
}

WindowActionResult RestoreWindow(HWND hwnd) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    ::ShowWindow(hwnd, SW_RESTORE);
    return { true, L"Restore requested: " + HwndToText(hwnd) };
}

WindowActionResult CloseWindowGracefully(HWND hwnd) {
    WindowActionResult valid = ValidateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    if (!::PostMessageW(hwnd, WM_CLOSE, 0, 0)) {
        return { false, L"WM_CLOSE post failed for " + HwndToText(hwnd) + L": " + ks::r3::common::LastErrorMessage() };
    }
    return { true, L"Close requested: " + HwndToText(hwnd) };
}

} // namespace ks::r3::window
