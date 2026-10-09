#include "ClipboardControl.h"

namespace ks::r3::window_tools {
DWORD CurrentClipboardOwnerProcessId() {
    const HWND owner = ::GetClipboardOwner();
    if (!owner || !::IsWindow(owner)) {
        return 0;
    }
    DWORD processId = 0;
    if (::GetWindowThreadProcessId(owner, &processId) == 0U || processId == 0U) {
        return 0;
    }
    return ::GetClipboardOwner() == owner ? processId : 0U;
}
DWORD CurrentClipboardOpenProcessId() {
    const HWND opener = ::GetOpenClipboardWindow();
    if (!opener || !::IsWindow(opener)) {
        return 0;
    }
    DWORD processId = 0;
    if (::GetWindowThreadProcessId(opener, &processId) == 0U || processId == 0U) {
        return 0;
    }
    return ::GetOpenClipboardWindow() == opener ? processId : 0U;
}
ClipboardClearResult ClearClipboard(HWND owner) {
    bool emptied = false;
    DWORD error = 0;
    {
        ScopedClipboard clipboard(owner);
        if (clipboard.opened()) {
            emptied = ::EmptyClipboard() != FALSE;
            error = emptied ? 0 : ::GetLastError();
        } else {
            error = clipboard.lastError();
        }
    }


    return {emptied, error};
}
}
