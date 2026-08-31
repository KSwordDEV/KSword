#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Process {

// CreateProcessView creates the Win32 child page for the process list feature.
// Inputs are the parent HWND and initial bounds. Processing registers a private
// window class, creates toolbar/status/list controls, and starts a first process
// snapshot refresh. Return value is the page HWND, or null when registration or
// child-window creation fails.
HWND CreateProcessView(HWND parent, const RECT& bounds);

// ResizeProcessView moves the already-created process page. Inputs are the page
// HWND and new bounds in parent-client coordinates. Processing calls MoveWindow;
// there is no return value because invalid HWNDs are ignored by Win32.
void ResizeProcessView(HWND view, const RECT& bounds);

// RequestProcessViewRefresh 用途：向已有进程页投递轻量刷新请求。
// 参数 view 是进程页 HWND；处理会复用普通刷新路径，并默认执行 R0 查隐藏。
void RequestProcessViewRefresh(HWND view);

// RequestProcessViewOpenDetails resolves the current process instance before
// opening details. A zero creation time is replaced from the latest snapshot or
// a verified Win32 process handle; a mismatched nonzero identity is rejected.
bool RequestProcessViewOpenDetails(HWND view, DWORD processId, ULONGLONG expectedCreationTime100ns = 0);

} // namespace Ksword::Features::Process
