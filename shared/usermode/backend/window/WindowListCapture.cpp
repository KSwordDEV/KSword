#include "WindowListCapture.h"

namespace ks::r3::window {
std::wstring CaptureAffinityText(const DWORD affinity) {
    switch (affinity) {
    case WDA_NONE:
        return L"允许窗口被捕获（WDA_NONE）";
    case WDA_MONITOR:
        return L"阻止屏幕捕获（WDA_MONITOR）";
    case WDA_EXCLUDEFROMCAPTURE:
        return L"从捕获中排除（WDA_EXCLUDEFROMCAPTURE）";
    default:
        return L"未知捕获保护值";
    }
}
std::wstring ApplyWindowListCaptureAffinity(HWND window, DWORD affinity,window_tools::DisplayAffinityWriteEvidence* output) {
    window_tools::DisplayAffinityWriteEvidence local;auto& evidence=output?*output:local;evidence={};evidence.attempted=true;evidence.requested=affinity;::SetLastError(ERROR_SUCCESS);
    std::wstring message;
    const bool applied = ::SetWindowDisplayAffinity(window, affinity) != FALSE;
    const DWORD error = applied ? ERROR_SUCCESS : ::GetLastError();
    evidence.accepted=applied;evidence.error=error;
    if (applied) {
        evidence.after=window_tools::QueryDisplayAffinity(window);
        message = evidence.after.available
            ? L"已设置为 " + CaptureAffinityText(evidence.after.affinity) + L"。"
            : L"设置调用成功，但回读属性失败。";
    } else {
        message = L"设置窗口捕获保护失败（错误码 " + std::to_wstring(error) + L"）。";
        if (error == ERROR_ACCESS_DENIED) {
            message += L" 该 API 主要用于进程保护自身窗口，跨进程设置通常被拒绝。";
        }
    }

    return message;
}
}
