#include "../shared/rescue/RescueDesktopHost.h"
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
        // 在显式绑定前使用 USER32，模拟运行库提前访问桌面的情况。
        Check(ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId())) == expected,
            "client starts on the private desktop before explicit binding");
        Check(ks::rescue::DesktopName(inherited) == expected, "inherited desktop is usable");
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
            // 模拟运行库已创建窗口。正式绑定函数应复用已连接的目标桌面。
            Check(ks::rescue::BindClientDesktop(inherited, expected) == ERROR_SUCCESS,
                "accept an already bound client that owns an early window");
            Check(ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId())) == expected,
                "client thread stays on the intended private desktop");
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

    // 启动实际监护 exe 的拒绝分支，检查它在指定时间内以预期错误退出。
    int RejectedStartupProbe(const std::wstring& executable, const std::wstring& arguments,
        DWORD expectedError, const char* resultName)
    {
        std::wstring command = L"\"" + executable + L"\" " + arguments;
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION child{}; // 只等待或结束本次启动的探测子进程。
        const BOOL launched = ::CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr,
            FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child);
        Check(launched != FALSE, "launch actual KSword for startup rejection probe");
        if (!launched)
        {
            return 1;
        }
        const DWORD waited = ::WaitForSingleObject(child.hProcess, 10000);
        Check(waited == WAIT_OBJECT_0, "startup rejects the request before UI or UAC");
        if (waited != WAIT_OBJECT_0)
        {
            ::TerminateProcess(child.hProcess, 1);
            ::WaitForSingleObject(child.hProcess, 5000);
        }
        DWORD exitCode = 0;
        Check(::GetExitCodeProcess(child.hProcess, &exitCode) && exitCode == expectedError,
            "startup returns the expected rejection code");
        ::CloseHandle(child.hThread);
        ::CloseHandle(child.hProcess);
        std::printf("%s=%s checks=%d failures=%d\n", resultName,
            failures == 0 ? "PASS" : "FAIL", checks, failures);
        return failures == 0 ? 0 : 1;
    }

    // 输入实际 KSword 路径，在未提升令牌下验证监护入口要求真实管理员权限。
    int ElevationGateProbe(const std::wstring& host)
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

        // 用合法的接替格式进入实际监护入口，验证参数不能代替令牌检查。
        const std::wstring original = ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId()));
        Check(!original.empty(), "read origin desktop for elevation probe");
        if (original.empty())
        {
            return 1;
        }
        const std::wstring arguments = std::wstring(ks::rescue::kHostArgument) + L" "
            + ks::rescue::kElevationAttemptArgument + L" "
            + ks::rescue::kOriginalDesktopArgument + L" \"" + original + L"\"";
        return RejectedStartupProbe(host, arguments, ERROR_ELEVATION_REQUIRED, "RESCUE_ELEVATION_GATE");
    }

    // 已有会话时实际监护入口必须直接结束，不弹 UAC、不创建或切换桌面。
    int SessionGuardProbe(const std::wstring& host, bool ordinaryTaskbar)
    {
        const HANDLE guard = ::CreateMutexExW(nullptr,
            ordinaryTaskbar ? L"Local\\KSword.Taskbar.Instance" : ks::rescue::kSessionGuardName, 0, SYNCHRONIZE);
        Check(guard != nullptr, "hold a rescue session guard");
        if (!guard) return 1;
        std::wstring command = L"\"" + host + L"\"";
        if (!ordinaryTaskbar)
        {
            command += L" " + std::wstring(ks::rescue::kHostArgument);
        }
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
        std::printf("%s=%s checks=%d failures=%d\n", ordinaryTaskbar ? "TASKBAR_SINGLE_INSTANCE" : "RESCUE_SESSION_GUARD",
            failures == 0 ? "PASS" : "FAIL", checks, failures);
        return failures == 0 ? 0 : 1;
    }

    void BusyEntryThreadProbe()
    {
        const auto entryId = ::GetCurrentThreadId();
        const auto original = ks::rescue::DesktopName(::GetThreadDesktop(entryId));
        WNDCLASSW type{};
        type.hInstance = ::GetModuleHandleW(nullptr);
        type.lpfnWndProc = ::DefWindowProcW;
        type.lpszClassName = L"KSword.Rescue.BusyEntryProbe";
        Check(::RegisterClassW(&type) != 0, "register entry-thread window class");
        HWND window = ::CreateWindowExW(0, type.lpszClassName, L"", WS_POPUP,
            -32000, -32000, 1, 1, nullptr, nullptr, type.hInstance, nullptr);
        Check(window != nullptr, "entry thread already owns a hidden window");
        HDESK desktop = ks::rescue::CreatePrivateDesktop();
        Check(desktop != nullptr, "create test desktop without switching input");
        if (window && desktop)
        {
            const auto name = ks::rescue::DesktopName(desktop);
            const BOOL bound = ::SetThreadDesktop(desktop);
            const DWORD error = ::GetLastError();
            Check(!bound && error == ERROR_BUSY, "old entry-thread binding reproduces ERROR_BUSY");
            const DWORD result = ks::rescue::RunDesktopSessionOnFreshThread([&]() -> DWORD {
                if (::GetCurrentThreadId() == entryId) return ERROR_INVALID_THREAD_ID;
                HDESK previous = ::GetThreadDesktop(::GetCurrentThreadId());
                if (!::SetThreadDesktop(desktop)) return ::GetLastError();
                const bool correct = ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId())) == name;
                if (!::SetThreadDesktop(previous)) return ::GetLastError();
                return correct ? ERROR_SUCCESS : ERROR_INVALID_DATA;
            });
            Check(result == ERROR_SUCCESS, "production fresh-thread adapter binds despite a busy entry thread");
            Check(ks::rescue::DesktopName(::GetThreadDesktop(entryId)) == original, "entry thread remains on original desktop");
            Check(!ks::rescue::IsInputDesktop(desktop), "probe never switches the input desktop");
        }
        if (window) ::DestroyWindow(window);
        if (desktop) ::CloseDesktop(desktop);
        ::UnregisterClassW(type.lpszClassName, type.hInstance);
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
    if (count == 3 && std::wstring(arguments[1]) == L"--client-init-rejection-probe")
    {
        // 真实客户端收到格式完整但无有效等待句柄的请求时应返回 ERROR_INVALID_HANDLE。
        const std::wstring request = std::wstring(ks::rescue::kClientArgument)
            + L" KSword.Rescue.Probe 0 0 0 0 Default";
        return RejectedStartupProbe(arguments[2], request, ERROR_INVALID_HANDLE, "RESCUE_CLIENT_INIT_REJECTION");
    }
    if (count == 3 && std::wstring(arguments[1]) == L"--taskbar-single-instance-probe")
        return SessionGuardProbe(arguments[2], true);
    if (count == 3 && std::wstring(arguments[1]) == L"--session-guard-probe")
    {
        return SessionGuardProbe(arguments[2], false);
    }
    if (count == 3 && std::wstring(arguments[1]) == L"--elevation-gate-probe")
    {
        return ElevationGateProbe(arguments[2]);
    }
    if (count == 3 && std::wstring(arguments[1]) == L"--client-path-rejection-probe")
    {
        // 旧监护协议允许指定客户端路径，新入口只允许启动自身模块。
        const std::wstring request = std::wstring(ks::rescue::kHostArgument) + L" \"" + arguments[2] + L"\"";
        return RejectedStartupProbe(arguments[2], request,
            ERROR_INVALID_PARAMETER, "RESCUE_CLIENT_PATH_REJECTION");
    }
    if (count > 1 && std::wstring(arguments[1]) == ks::rescue::kClientArgument)
    {
        return ChildProbe(count, arguments);
    }
    InputPolicyTests();
    BusyEntryThreadProbe();
    const std::wstring original = ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId()));
    ks::rescue::ClientHandles handles; // 正式启动函数需要的最小继承集合。
    handles.desktop = ks::rescue::CreatePrivateDesktop();
    Check(handles.desktop != nullptr, "create owner-rights protected private desktop");
    if (handles.desktop)
    {
        const auto name = ks::rescue::DesktopName(handles.desktop);
        const std::wstring prefix = ks::rescue::kDesktopPrefix;
        Check(name.rfind(prefix, 0) == 0 && name.size() == prefix.size() + 32
            && name.find_first_not_of(L"0123456789abcdef", prefix.size()) == std::wstring::npos,
            "production desktop name contains a 128-bit random suffix");
        HDESK second = ks::rescue::CreatePrivateDesktop();
        Check(second && ks::rescue::DesktopName(second) != name,
            "two concurrent private desktops have different names");
        if (second) ::CloseDesktop(second);
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
