#include "CaptureProtection.h"

namespace ks::r3::window_tools {
std::wstring ApplyDisplayAffinity(HWND window, DWORD affinity) {
    const bool applied = ::SetWindowDisplayAffinity(window, affinity) != FALSE;
    const DWORD error = applied ? 0 : ::GetLastError();
    std::wstring message;
    if (applied) {
        // Read the value back instead of trusting the return code: the system
        // may downgrade an unsupported request, and only a re-query shows it.
        DWORD current = 0;
        if (::GetWindowDisplayAffinity(window, &current)) {
            message = L"已设置为 " + DisplayAffinityText(current, true) + L"。";
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
