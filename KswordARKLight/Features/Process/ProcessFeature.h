#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Process {

// CreateProcessFeaturePage is the module facade for the lightweight Win32
// process list page. Inputs are the parent HWND and initial parent-client
// bounds. Processing delegates to ProcessView so this module only
// needs this stable module-level entry point. Return value is the created child
// HWND or null on failure.
HWND CreateProcessFeaturePage(HWND parent, const RECT& bounds);

// ResizeProcessFeaturePage is the module facade for host-driven layout changes.
// Inputs are an existing process page HWND and new bounds. Processing delegates
// to ProcessView and returns no value.
void ResizeProcessFeaturePage(HWND page, const RECT& bounds);

// RequestProcessFeatureRefresh 用途：向已物化的进程功能页投递刷新请求。
// 调用场景：R0 驱动变为可用后，让查隐藏进程逻辑立刻跑一次。
void RequestProcessFeatureRefresh(HWND page);

bool RequestProcessFeatureOpenDetails(HWND page, DWORD processId, ULONGLONG expectedCreationTime100ns = 0);

} // namespace Ksword::Features::Process
