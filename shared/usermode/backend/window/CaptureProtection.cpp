#include "CaptureProtection.h"

namespace ks::r3::window_tools {
DisplayAffinityEvidence QueryDisplayAffinity(HWND window) {
    DisplayAffinityEvidence e;e.attempted = true;::SetLastError(ERROR_SUCCESS);
    e.available = ::GetWindowDisplayAffinity(window,&e.affinity) != FALSE;if (!e.available) e.error = ::GetLastError();return e;
}
std::wstring ApplyDisplayAffinity(HWND window, DWORD affinity,DisplayAffinityWriteEvidence* output) {
    DisplayAffinityWriteEvidence local;auto& e = output ? *output : local;e = {};e.attempted = true;e.requested = affinity;::SetLastError(ERROR_SUCCESS);
    const bool applied = ::SetWindowDisplayAffinity(window, affinity) != FALSE;
    const DWORD error = applied ? 0 : ::GetLastError();
    e.accepted = applied;e.error = error;
    std::wstring message;
    if (applied) {
        // Read the value back instead of trusting the return code: the system
        // may downgrade an unsupported request, and only a re-query shows it.
        e.after = QueryDisplayAffinity(window);
        if (e.after.available) {
            message = L"已设置为 " + DisplayAffinityText(e.after.affinity, true) + L"。";
        } else {
            message = L"设置调用成功，但回读属性失败。";
        }
    } else {
        message = L"设置失败（错误码 " + std::to_wstring(error) + L"）：" +
            ks::r3::common::LastErrorMessage(error);
        if (error == ERROR_ACCESS_DENIED) {
            message += L" 该 API 主要用于进程保护自身窗口，跨进程设置通常被拒绝。";
        }
    }

    return message;
}
}
