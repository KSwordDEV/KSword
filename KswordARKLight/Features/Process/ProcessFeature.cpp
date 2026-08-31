#include "ProcessFeature.h"

#include "ProcessView.h"

namespace Ksword::Features::Process {

HWND CreateProcessFeaturePage(HWND parent, const RECT& bounds) {
    // Input is the host HWND and desired child bounds. Processing is intentionally
    // thin: this facade preserves a stable integration symbol while ProcessView
    // owns child controls, enumeration, model binding, and menu interactions.
    // Return value is the child page HWND or null if the view cannot be created.
    return CreateProcessView(parent, bounds);
}

void ResizeProcessFeaturePage(HWND page, const RECT& bounds) {
    // Input is an existing process feature page and a new host layout rectangle.
    // Processing delegates to ProcessView, which uses MoveWindow only; there is
    // no return value because invalid HWNDs are safely ignored.
    ResizeProcessView(page, bounds);
}

void RequestProcessFeatureRefresh(HWND page) {
    // page 用途：MainWindow 保存的进程页 HWND；调用方式为驱动状态变化后异步刷新。
    // 处理过程：转发给 ProcessView，避免 MainWindow 直接依赖页面内部消息号。
    RequestProcessViewRefresh(page);
}

bool RequestProcessFeatureOpenDetails(HWND page, DWORD processId, ULONGLONG expectedCreationTime100ns) {
    return RequestProcessViewOpenDetails(page, processId, expectedCreationTime100ns);
}

} // namespace Ksword::Features::Process
