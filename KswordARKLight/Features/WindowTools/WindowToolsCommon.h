#pragma once
#include "../../../shared/usermode/backend/window/WindowQueries.h"
#include "../../../shared/usermode/backend/window/WindowToolsTypes.h"

#include "../../Core/Win32Lean.h"
#include "../../Ui/VirtualListView.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::WindowTools {
using ks::r3::window_tools::TopLevelWindowInfo;


// WDA_EXCLUDEFROMCAPTURE only appeared in the Windows 10 2004 SDK. The value is
// pinned here so this module still builds against an older SDK, and so the tab
// can always offer the option: whether the running system honors it is reported
// from the SetWindowDisplayAffinity result rather than assumed at compile time.
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

// TopLevelWindowInfo is one EnumWindows row shared by the capture-protection and
// hierarchy tabs. Every field is a value copy taken during enumeration; hwnd is
// kept only as an identity token and must be revalidated with IsWindow before
// any operation, because a window can close between the snapshot and the click
// that acts on it.


// EnumerateTopLevelWindowInfo captures every top-level window in one pass. There
// is no input; output is the snapshot in raw EnumWindows order, which is also
// the current Z order.
//
// This is safe to call from an AsyncSnapshotTask worker. EnumWindows, and the
// per-window queries used here, are read-only calls into win32k that do not
// require the caller to own the window or its thread. That is not true of the
// mutating half of this module: SetWindowDisplayAffinity and every clipboard API
// stay on the UI thread, in their own tabs.
using ks::r3::window_tools::EnumerateTopLevelWindowInfo;

// HwndText formats a window handle as fixed-width hexadecimal. Input is any
// HWND including nullptr; output is display text that never implies the handle
// is still valid.
using ks::r3::window_tools::HwndText;

// PointerText formats a code or object address. Input is any pointer-sized
// value; output is fixed-width hexadecimal for column alignment.
std::wstring PointerText(std::uint64_t value);

// HexText formats an integer with a fixed digit count. Inputs are the value and
// the number of digits to pad to; output carries the 0x prefix.
using ks::r3::window_tools::HexText;

// RectText formats a RECT as edges plus derived size. Input is a RECT; output is
// compact display text used by the detail panes.
std::wstring RectText(const RECT& rect);

// WindowTitleText reads one window's caption. Input is a live HWND; output is
// empty for untitled, inaccessible, or disappearing windows.
using ks::r3::window_tools::WindowTitleText;

// WindowClassText reads one window's class name. Input is a live HWND; output is
// empty when the call fails.
using ks::r3::window_tools::WindowClassText;

// ProcessNameFromId resolves a PID to its image file name. Input is a process id
// from GetWindowThreadProcessId; output is a stable placeholder when the process
// cannot be opened, which is the normal case for higher-integrity processes.
using ks::r3::window_tools::ProcessNameFromId;

// DisplayAffinityText renders a GetWindowDisplayAffinity value. Inputs are the
// raw affinity and whether the query succeeded; output names the constant and
// explains what it does to a screen capture.
using ks::r3::window_tools::DisplayAffinityText;

// DescribeWindowBrief formats a one-line identity for a related window. Input is
// any HWND including nullptr; output is handle, class and truncated title, used
// for ancestor and Z-order neighbours where a full block would drown the report.
std::wstring DescribeWindowBrief(HWND hwnd);

// DecodeWindowStyleBits names every set bit of GWL_STYLE. Inputs are the style
// value and whether the window is a child; output is one entry per recognized
// bit plus a trailing note for the class-specific low word.
//
// isChild is not cosmetic. Bits 16 and 17 are WS_TABSTOP/WS_GROUP on a child
// control and WS_MAXIMIZEBOX/WS_MINIMIZEBOX on a top-level window -- the same
// bits with different meanings -- so a decoder that ignores WS_CHILD reports the
// wrong flag for half the windows on the system.
std::vector<std::wstring> DecodeWindowStyleBits(DWORD style, bool isChild);

// DecodeWindowExStyleBits names every set bit of GWL_EXSTYLE. Input is the
// extended style; output is one entry per recognized bit plus any leftover bits
// as raw hexadecimal so nothing is silently dropped.
std::vector<std::wstring> DecodeWindowExStyleBits(DWORD exStyle);

// DecodeClassStyleBits names every set bit of a CS_* class style. Input is the
// value from GetClassLongPtr(GCL_STYLE); output follows the same rules as the
// window style decoders.
std::vector<std::wstring> DecodeClassStyleBits(DWORD classStyle);

// CopyTextToClipboard places text on the clipboard. Inputs are an owner window
// belonging to the calling thread and the text; output is false when the
// clipboard is held by another process.
//
// This must be called on the UI thread: OpenClipboard binds the clipboard to the
// calling thread and to a window that thread owns.
bool CopyTextToClipboard(HWND owner, const std::wstring& text);

// RowsAsTsv renders list rows as tab-separated text. Inputs are the list, a flag
// selecting all visible rows instead of only the selected ones, and how many
// leading cells are real columns; output ends every row with CRLF so it pastes
// into a spreadsheet unchanged.
std::wstring RowsAsTsv(const Ksword::Ui::VirtualListView& list, bool visibleRows, int columnCount);

} // namespace Ksword::Features::WindowTools
