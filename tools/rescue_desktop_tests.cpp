#include "../shared/rescue/RescueDesktopWin32.h"

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <string>
#include <vector>

namespace
{
    int failures = 0; // 本进程失败断言数量。
    int checks = 0; // 本进程总断言数量。
    int rejectedMessages = 0; // 隐藏测试窗口拒绝的伪造鼠标/键盘消息数量。

    // 输入条件与说明，记录断言并打印失败；不改变桌面或其他进程。
    void Check(const bool condition, const char* description)
    {
        ++checks;
        if (!condition)
        {
            ++failures;
            std::printf("FAIL: %s (Win32=%lu)\n", description, ::GetLastError());
        }
    }

    // 在实际窗口过程内使用正式输入来源策略，验证 SendMessage/PostMessage 被拒绝。
    LRESULT CALLBACK ProbeWindow(const HWND window, const UINT message, const WPARAM value, const LPARAM detail)
    {
        if (ks::rescue::IsMouseMessage(message) || ks::rescue::IsKeyboardMessage(message))
        {
            INPUT_MESSAGE_SOURCE source{}; // 实际派发时 Windows 报告的消息来源。
            if (!::GetCurrentInputMessageSource(&source)
                || !ks::rescue::AcceptInputSource(message, source))
            {
                ++rejectedMessages;
                return 0;
            }
        }
        return ::DefWindowProcW(window, message, value, detail);
    }

    // 在白名单继承的私有桌面创建不显示的窗口；整个测试绝不调用 SwitchDesktop。
    int ChildProbe(const int count, wchar_t** arguments)
    {
        Check(count == 8, "client argument count");
        if (count != 8)
        {
            return 1;
        }
        const std::wstring expected = arguments[2]; // 父进程新建的唯一桌面名。
        const HDESK inherited = reinterpret_cast<HDESK>(std::wcstoull(arguments[3], nullptr, 10));
        const HANDLE ready = reinterpret_cast<HANDLE>(std::wcstoull(arguments[4], nullptr, 10));
        Check(ks::rescue::DesktopName(inherited) == expected, "inherited desktop is usable");
        // 创建客户端时显式绑定继承句柄，不能假定 HANDLE_LIST 使 USER32 自动选中它。
        Check(::SetThreadDesktop(inherited) != FALSE, "explicitly bind the inherited private desktop before windows");
        Check(ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId())) == expected,
            "client thread is on the intended private desktop");

        // 创建者同一账号也不能凭名称拿到写对象、装 Hook 或修改 DACL 的权限。
        for (const ACCESS_MASK access : { DESKTOP_CREATEWINDOW, DESKTOP_HOOKCONTROL, WRITE_DAC, READ_CONTROL })
        {
            const HDESK reopened = ::OpenDesktopW(expected.c_str(), 0, FALSE, access);
            Check(reopened == nullptr && ::GetLastError() == ERROR_ACCESS_DENIED, "private desktop rejects reopen");
            if (reopened)
            {
                ::CloseDesktop(reopened);
            }
        }

        WNDCLASSW type{}; // 隐藏测试窗口类，使用真实 Win32 派发，不接触用户窗口。
        type.hInstance = ::GetModuleHandleW(nullptr);
        type.lpfnWndProc = ProbeWindow;
        type.lpszClassName = L"KSword.Rescue.TestWindow";
        Check(::RegisterClassW(&type) != 0, "register hidden probe class");
        const HWND window = ::CreateWindowExW(0, type.lpszClassName, L"", WS_POPUP,
            -32000, -32000, 1, 1, nullptr, nullptr, type.hInstance, nullptr);
        Check(window != nullptr, "create hidden window with inherited private desktop handle");
        if (window)
        {
            const HDESK original = ::OpenDesktopW(arguments[7], 0, FALSE,
                DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
            Check(original != nullptr, "open original desktop for migration probe");
            if (original)
            {
                // 正式 Windows 行为：已拥有窗口的线程不能平移到另一个桌面。
                const BOOL moved = ::SetThreadDesktop(original);
                Check(!moved && ::GetLastError() == ERROR_BUSY, "live window migration returns ERROR_BUSY");
                ::CloseDesktop(original);
            }
            ::SendMessageW(window, WM_CHAR, L'A', 0);
            ::SendMessageW(window, WM_LBUTTONDOWN, MK_LBUTTON, 0);
            Check(rejectedMessages == 2, "SendMessage mouse and character input rejected");
            ::PostMessageW(window, WM_KEYDOWN, 'A', 0);
            ::PostMessageW(window, WM_LBUTTONUP, 0, 0);
            MSG message{}; // 泵送本测试线程消息，观察 PostMessage 的来源判定。
            while (::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
            {
                ::TranslateMessage(&message);
                ::DispatchMessageW(&message);
            }
            Check(rejectedMessages >= 4, "PostMessage mouse and keyboard input rejected");
            ::DestroyWindow(window);
        }
        Check(::SetEvent(ready) != FALSE, "inherited ready event is usable");
        return failures == 0 ? 0 : 1;
    }

    // 输入实际 Taskbar/KSword 路径，只在未提升令牌下探测伪造标记；不请求 UAC 或切换桌面。
    int ElevationGateProbe(const std::wstring& host, const std::wstring& client)
    {
        HANDLE token = nullptr; // 先核验测试进程真实令牌，提升态下必须跳过以免进入救援桌面。
        const BOOL opened = ::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token);
        Check(opened != FALSE, "query elevation probe token");
        if (!opened)
        {
            return 1;
        }
        TOKEN_ELEVATION elevation{}; // 子进程通过 CreateProcess 继承本测试进程的同一令牌。
        DWORD bytes = 0; // Windows 返回的提升信息大小。
        const BOOL queried = ::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes);
        ::CloseHandle(token);
        Check(queried != FALSE, "read elevation probe token");
        if (!queried)
        {
            return 1;
        }
        if (elevation.TokenIsElevated != 0)
        {
            std::printf("RESCUE_ELEVATION_GATE=SKIP already_elevated\n");
            return 0;
        }

        // 内部标记不是提权证据：未提升的真实 Taskbar 应立即拒绝，不能再次弹 UAC。
        const std::wstring command = L"\"" + host + L"\" " + ks::rescue::kHostArgument
            + L" \"" + client + L"\" --ksword-rescue-elevation-attempted";
        std::vector<wchar_t> writable(command.begin(), command.end()); // CreateProcess 需要可写参数。
        writable.push_back(L'\0');
        STARTUPINFOW startup{}; // 该测试分支不创建窗口，且只启动自己的探测子进程。
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION child{}; // 精确等待本次探测子进程，不接触常驻 Taskbar。
        const BOOL launched = ::CreateProcessW(host.c_str(), writable.data(), nullptr, nullptr,
            FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child);
        Check(launched != FALSE, "launch actual Taskbar with spoofed elevation marker");
        if (!launched)
        {
            return 1;
        }
        const DWORD waited = ::WaitForSingleObject(child.hProcess, 10000);
        Check(waited == WAIT_OBJECT_0, "spoofed elevation marker exits without UAC or readiness wait");
        if (waited != WAIT_OBJECT_0)
        {
            ::TerminateProcess(child.hProcess, 1);
            ::WaitForSingleObject(child.hProcess, 5000);
        }
        DWORD exitCode = 0; // 未提升的内部入口必须返回明确失败，不能进入普通或救援 GUI。
        Check(::GetExitCodeProcess(child.hProcess, &exitCode) && exitCode == 2,
            "unelevated actual Taskbar rejects claimed elevation");
        ::CloseHandle(child.hThread);
        ::CloseHandle(child.hProcess);
        std::printf("RESCUE_ELEVATION_GATE=%s checks=%d failures=%d\n",
            failures == 0 ? "PASS" : "FAIL", checks, failures);
        return failures == 0 ? 0 : 1;
    }

    // 已有会话时实际监护入口必须直接结束，不弹 UAC、不创建或切换桌面。
    int SessionGuardProbe(const std::wstring& host, const std::wstring& client)
    {
        const HANDLE guard = ::CreateMutexW(nullptr, FALSE, ks::rescue::kSessionGuardName);
        Check(guard != nullptr, "hold a rescue session guard");
        if (!guard) return 1;
        std::wstring command = L"\"" + host + L"\" " + ks::rescue::kHostArgument + L" \"" + client + L"\"";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION child{};
        const BOOL launched = ::CreateProcessW(host.c_str(), command.data(), nullptr, nullptr,
            FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child);
        Check(launched != FALSE, "launch actual host while a rescue session is active");
        if (launched)
        {
            const DWORD waited = ::WaitForSingleObject(child.hProcess, 10000);
            Check(waited == WAIT_OBJECT_0, "duplicate host exits before UAC or desktop creation");
            if (waited != WAIT_OBJECT_0)
            {
                ::TerminateProcess(child.hProcess, 1);
                ::WaitForSingleObject(child.hProcess, 5000);
            }
            DWORD exitCode = 1;
            Check(::GetExitCodeProcess(child.hProcess, &exitCode) && exitCode == 0,
                "duplicate host reports an existing session");
            ::CloseHandle(child.hThread);
            ::CloseHandle(child.hProcess);
        }
        ::CloseHandle(guard);
        std::printf("RESCUE_SESSION_GUARD=%s checks=%d failures=%d\n",
            failures == 0 ? "PASS" : "FAIL", checks, failures);
        return failures == 0 ? 0 : 1;
    }

    void InputPolicyTests()
    {
        const INPUT_MESSAGE_SOURCE mouse{ IMDT_MOUSE, IMO_HARDWARE }; // 物理鼠标来源。
        const INPUT_MESSAGE_SOURCE keyboard{ IMDT_KEYBOARD, IMO_HARDWARE }; // 物理键盘来源。
        Check(ks::rescue::AcceptInputSource(WM_LBUTTONDOWN, mouse), "hardware mouse accepted");
        Check(ks::rescue::AcceptInputSource(WM_NCLBUTTONDOWN, mouse), "hardware title bar click accepted");
        Check(ks::rescue::AcceptInputSource(WM_KEYDOWN, keyboard), "hardware keyboard accepted");
        Check(!ks::rescue::AcceptInputSource(WM_KEYDOWN, mouse), "wrong device type rejected");
        Check(!ks::rescue::AcceptInputSource(WM_LBUTTONDOWN, keyboard), "keyboard cannot authenticate mouse");
        for (const auto origin : { IMO_UNAVAILABLE, IMO_SYSTEM, IMO_INJECTED })
        {
            Check(!ks::rescue::AcceptInputSource(WM_LBUTTONDOWN, { IMDT_MOUSE, origin }), "nonhardware mouse rejected");
            Check(!ks::rescue::AcceptInputSource(WM_CHAR, { IMDT_KEYBOARD, origin }), "nonhardware character rejected");
        }
        Check(!ks::rescue::RejectInjectedMouse(0), "unmarked physical mouse Hook passed");
        Check(ks::rescue::RejectInjectedMouse(LLMHF_INJECTED), "same integrity mouse injection rejected");
        Check(ks::rescue::RejectInjectedMouse(LLMHF_LOWER_IL_INJECTED), "lower integrity mouse injection rejected");
        Check(!ks::rescue::RejectInjectedKeyboard(LLKHF_ALTDOWN | LLKHF_UP), "physical system key Hook passed");
        Check(ks::rescue::RejectInjectedKeyboard(LLKHF_INJECTED), "same integrity keyboard injection rejected");
        Check(ks::rescue::RejectInjectedKeyboard(LLKHF_LOWER_IL_INJECTED), "lower integrity keyboard injection rejected");
        Check(ks::rescue::IsMouseMessage(WM_NCXBUTTONDOWN), "nonclient extra mouse button covered");
        Check(!ks::rescue::IsMouseMessage(WM_PAINT), "paint unaffected by mouse policy");
    }
}

int wmain(const int count, wchar_t** arguments)
{
    if (count == 4 && std::wstring(arguments[1]) == L"--session-guard-probe")
    {
        return SessionGuardProbe(arguments[2], arguments[3]);
    }
    if (count == 4 && std::wstring(arguments[1]) == L"--elevation-gate-probe")
    {
        return ElevationGateProbe(arguments[2], arguments[3]);
    }
    if (count > 1 && std::wstring(arguments[1]) == ks::rescue::kClientArgument)
    {
        return ChildProbe(count, arguments);
    }
    InputPolicyTests();
    const std::wstring original = ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId()));
    const std::wstring name = std::wstring(ks::rescue::kDesktopPrefix) + L"Tests."
        + std::to_wstring(::GetCurrentProcessId()) + L"." + std::to_wstring(::GetTickCount64());
    ks::rescue::ClientHandles handles; // 正式启动函数需要的最小继承集合。
    handles.desktop = ks::rescue::CreatePrivateDesktop(name);
    Check(handles.desktop != nullptr, "create owner-rights protected private desktop");
    if (handles.desktop)
    {
        Check(!ks::rescue::IsInputDesktop(handles.desktop), "private test desktop never becomes input desktop");
        SECURITY_ATTRIBUTES security{}; // 未命名测试事件的继承属性。
        security.nLength = sizeof(security);
        security.bInheritHandle = TRUE;
        handles.ready = ::CreateEventW(&security, TRUE, FALSE, nullptr);
        handles.leave = ::CreateEventW(&security, TRUE, FALSE, nullptr);
        ::DuplicateHandle(::GetCurrentProcess(), ::GetCurrentProcess(), ::GetCurrentProcess(),
            &handles.host, SYNCHRONIZE, TRUE, 0);
        wchar_t path[32768]{}; // 当前测试 exe 路径，正式 LaunchClient 将启动其探测入口。
        ::GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        PROCESS_INFORMATION child{}; // 只等待自己创建的无界面测试进程。
        DWORD error = 0; // 正式启动实现返回的错误码。
        const bool launched = ks::rescue::LaunchClient(path, original, handles, child, error);
        ::SetLastError(error);
        Check(launched, "launch with desktop/event/process handle whitelist");
        if (launched)
        {
            const DWORD waited = ::WaitForSingleObject(child.hProcess, 10000);
            Check(waited == WAIT_OBJECT_0, "probe process exits within deadline");
            if (waited != WAIT_OBJECT_0)
            {
                // 只清理本次创建的测试子进程，永远不按名称扫描/终止用户程序。
                ::TerminateProcess(child.hProcess, 1);
            }
            DWORD exitCode = 1; // 子进程全部真实 Win32 行为断言的汇总。
            ::GetExitCodeProcess(child.hProcess, &exitCode);
            Check(exitCode == 0, "real desktop/inheritance/migration/input probes pass");
            Check(::WaitForSingleObject(handles.ready, 0) == WAIT_OBJECT_0, "client readiness received");
            ::CloseHandle(child.hThread);
            ::CloseHandle(child.hProcess);
        }
        ::CloseHandle(handles.ready);
        ::CloseHandle(handles.leave);
        ::CloseHandle(handles.host);
        ::CloseDesktop(handles.desktop);
    }
    Check(ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId())) == original,
        "test leaves the calling thread on its original desktop");
    std::printf("RESCUE_DESKTOP_TESTS=%s checks=%d failures=%d\n", failures == 0 ? "PASS" : "FAIL", checks, failures);
    return failures == 0 ? 0 : 1;
}
