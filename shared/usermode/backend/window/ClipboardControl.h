#pragma once
#include "../Common.h"
#include "Clipboard.h"
namespace ks::r3::window_tools {
DWORD CurrentClipboardOwnerProcessId();
DWORD CurrentClipboardOpenProcessId();
struct ClipboardClearResult { bool emptied = false; DWORD error = 0; };
ClipboardClearResult ClearClipboard(HWND owner);
}
