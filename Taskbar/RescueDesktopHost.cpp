#include "RescueDesktopHost.h"
#include "../shared/rescue/RescueDesktopWin32.h"

#include <shellapi.h>
#include <objbase.h>
#include <array>
#include <string>
#include <vector>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

namespace
{
    constexpr wchar_t kElevationAttemptArgument[] = L"--ksword-rescue-elevation-attempted";
    constexpr wchar_t kOriginalDesktopArgument[] = L"--ksword-rescue-origin-desktop";
    ULONGLONG physicalReturnTick = 0; // 本监护线程最近一次真实返回组合键的时间，不接受消息伪造。

    // 输入阶段、Win32 错误和值，追加到 exe 同目录 logs；不在输入 Hook 内调用，保留 LastError。
    void LogStage(const wchar_t* stage, const DWORD error = ERROR_SUCCESS,
        const DWORD value = 0, const std::wstring& detail = {})
    {
        const DWORD savedError = ::GetLastError(); // 诊断不能覆盖调用方正在处理的 API 错误。
        std::array<wchar_t, 32768> path{}; // 当前 exe 路径，用于定位发行目录中的日志。
        const DWORD length = ::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length != 0 && length < path.size())
        {
            const std::wstring executable(path.data(), length); // 避免使用不可控的当前工作目录。
            const std::wstring directory = executable.substr(0, executable.find_last_of(L"\\/")) + L"\\logs";
            ::CreateDirectoryW(directory.c_str(), nullptr);
            const std::wstring filename = directory + L"\\sos-rescue-"
                + std::to_wstring(::GetCurrentProcessId()) + L".log";
            const HANDLE file = ::CreateFileW(filename.c_str(), FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE)
            {
                // 只记录启动状态、错误和桌面名称，不保存键盘输入或继承句柄值。
                const std::wstring line = std::to_wstring(::GetTickCount64()) + L" " + stage
                    + L" error=" + std::to_wstring(error) + L" value=" + std::to_wstring(value)
                    + (detail.empty() ? L"" : L" detail=" + detail) + L"\r\n";
                const int bytes = ::WideCharToMultiByte(CP_UTF8, 0, line.data(),
                    static_cast<int>(line.size()), nullptr, 0, nullptr, nullptr);
                if (bytes > 0)
                {
                    std::vector<char> utf8(static_cast<size_t>(bytes)); // 跨语言系统也能读取桌面名。
                    ::WideCharToMultiByte(CP_UTF8, 0, line.data(), static_cast<int>(line.size()),
                        utf8.data(), bytes, nullptr, nullptr);
                    DWORD written = 0; // WriteFile 的实际追加长度。
                    ::WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
                }
                ::CloseHandle(file);
            }
        }
        ::SetLastError(savedError);
    }

    // 查询当前监护进程的真实令牌；返回查询是否成功，输出是否已获管理员提升。
    bool QueryCurrentElevation(bool& elevated)
    {
        elevated = false;
        HANDLE token = nullptr; // 只查询令牌，不改变当前 Taskbar 或其他进程的权限。
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            return false;
        }
        TOKEN_ELEVATION elevation{}; // UAC 提升状态由 Windows 令牌决定，不信任命令行标记。
        DWORD byteCount = 0; // Windows 返回的令牌信息长度。
        const BOOL queried = ::GetTokenInformation(token, TokenElevation,
            &elevation, sizeof(elevation), &byteCount);
        const DWORD error = queried ? ERROR_SUCCESS : ::GetLastError(); // 保留真实令牌查询错误。
        ::CloseHandle(token);
        ::SetLastError(error);
        elevated = queried && elevation.TokenIsElevated != 0;
        return queried != FALSE;
    }

    // 在原桌面请求 UAC 后等待高权限监护进程；取消/失败返回 2，不创建低权限救援桌面。
    int LaunchElevatedHostAndWait(const std::wstring& executable, const std::wstring& originalName)
    {
        if (executable.empty() || executable.find(L'"') != std::wstring::npos)
        {
            return 2;
        }
        std::array<wchar_t, 32768> selfPath{}; // 精确启动当前 Taskbar，避免 PATH 或工作目录替换。
        const DWORD length = ::GetModuleFileNameW(nullptr, selfPath.data(),
            static_cast<DWORD>(selfPath.size()));
        if (length == 0 || length >= selfPath.size())
        {
            return 2;
        }
        const std::wstring parameters = std::wstring(ks::rescue::kHostArgument)
            + L" \"" + executable + L"\" " + kElevationAttemptArgument
            + L" " + kOriginalDesktopArgument + L" \"" + originalName + L"\"";
        const std::wstring directory(selfPath.data(), length); // 高权限监护入口的 exe 同目录。
        const std::wstring workingDirectory = directory.substr(0, directory.find_last_of(L"\\/"));

        // ShellExecuteEx 使用 COM；本入口还没有 Qt、Hook 或桌面句柄，UAC 不阻塞 SOS Hook 线程。
        const HRESULT initialized = ::CoInitializeEx(nullptr,
            COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if (FAILED(initialized))
        {
            LogStage(L"uac.com_init", static_cast<DWORD>(initialized));
            return 2;
        }
        SHELLEXECUTEINFOW request{}; // 只提权独立监护进程，常驻 Taskbar 保持原身份。
        request.cbSize = sizeof(request);
        request.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        request.lpVerb = L"runas";
        request.lpFile = selfPath.data();
        request.lpParameters = parameters.c_str();
        request.lpDirectory = workingDirectory.c_str();
        request.nShow = SW_HIDE;
        LogStage(L"uac.request", ERROR_SUCCESS, 0, originalName);
        const BOOL launched = ::ShellExecuteExW(&request);
        if (!launched || !request.hProcess)
        {
            LogStage(L"uac.launch_failed", launched ? ERROR_INVALID_HANDLE : ::GetLastError());
            if (request.hProcess)
            {
                ::CloseHandle(request.hProcess);
            }
            ::CoUninitialize();
            ::OutputDebugStringW(L"[Taskbar][SOS] UAC was canceled or elevation failed.\n");
            return 2;
        }

        LogStage(L"uac.host_started", ERROR_SUCCESS, ::GetProcessId(request.hProcess));

        // 保留引导进程到整个救援会话结束，普通 Taskbar 可继续用该进程句柄防止并发 SOS。
        const DWORD waited = ::WaitForSingleObject(request.hProcess, INFINITE);
        DWORD exitCode = 2; // 保留高权限监护会话的最终退出状态。
        const BOOL readExit = waited == WAIT_OBJECT_0
            && ::GetExitCodeProcess(request.hProcess, &exitCode);
        LogStage(L"uac.host_exit", readExit ? ERROR_SUCCESS : ::GetLastError(), exitCode);
        ::CloseHandle(request.hProcess);
        ::CoUninitialize();
        return readExit ? static_cast<int>(exitCode) : 2;
    }

    // 低级 Hook 只判断注入标志并立即返回，不执行磁盘、Qt 或进程启动工作。
    LRESULT CALLBACK MouseGuard(const int code, const WPARAM message, const LPARAM data)
    {
        if (code == HC_ACTION && data != 0)
        {
            const auto* input = reinterpret_cast<const MSLLHOOKSTRUCT*>(data); // Windows 输入记录。
            if (ks::rescue::RejectInjectedMouse(input->flags))
            {
                return 1;
            }
        }
        return ::CallNextHookEx(nullptr, code, message, data);
    }

    LRESULT CALLBACK KeyboardGuard(const int code, const WPARAM message, const LPARAM data)
    {
        if (code == HC_ACTION && data != 0)
        {
            const auto* input = reinterpret_cast<const KBDLLHOOKSTRUCT*>(data); // Windows 输入记录。
            if (ks::rescue::RejectInjectedKeyboard(input->flags))
            {
                return 1;
            }
            // WM_HOTKEY 本身可以被消息伪造；必须与本线程收到的物理组合键回调关联。
            if (input->vkCode == VK_F10 && (message == WM_KEYDOWN || message == WM_SYSKEYDOWN)
                && (::GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0
                && (::GetAsyncKeyState(VK_MENU) & 0x8000) != 0
                && (::GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0)
            {
                physicalReturnTick = ::GetTickCount64();
            }
        }
        return ::CallNextHookEx(nullptr, code, message, data);
    }

    // HostSession：所有句柄/Hook 由同一无 Qt 线程管理，析构先恢复桌面再拆除防护。
    class HostSession final
    {
    public:
        ~HostSession()
        {
            restore();
            if (hotkey_)
            {
                ::UnregisterHotKey(nullptr, ks::rescue::kReturnHotkeyId);
            }
            if (mouse_)
            {
                ::UnhookWindowsHookEx(mouse_);
            }
            if (keyboard_)
            {
                ::UnhookWindowsHookEx(keyboard_);
            }
            // 桌面无窗口/Hook 后才可换回，随后再释放本会话持有的桌面引用。
            if (threadDesktop_)
            {
                ::SetThreadDesktop(threadDesktop_);
            }
            if (process_.hProcess)
            {
                ::CloseHandle(process_.hProcess);
            }
            if (handles_.ready)
            {
                ::CloseHandle(handles_.ready);
            }
            if (handles_.leave)
            {
                ::CloseHandle(handles_.leave);
            }
            if (handles_.host)
            {
                ::CloseHandle(handles_.host);
            }
            if (handles_.desktop)
            {
                ::CloseDesktop(handles_.desktop);
            }
            if (original_)
            {
                ::CloseDesktop(original_);
            }
        }

        // 输入目标 exe，建立继承白名单/输入守卫并启动子进程；失败不切换用户桌面。
        bool start(const std::wstring& executable, const std::wstring& expectedOriginalName)
        {
            threadDesktop_ = ::GetThreadDesktop(::GetCurrentThreadId());
            // UAC 刚批准时输入桌面可能仍是安全桌面；按提权前固定的名字打开原桌面。
            original_ = expectedOriginalName.empty()
                ? ::OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS)
                : ::OpenDesktopW(expectedOriginalName.c_str(), 0, FALSE,
                    DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS);
            if (!original_)
            {
                LogStage(L"original.open_failed", ::GetLastError(), 0, expectedOriginalName);
                return false;
            }
            const std::wstring originalName = ks::rescue::DesktopName(original_); // 返回时的目标。
            LogStage(L"original.opened", ERROR_SUCCESS, 0, originalName);
            const std::wstring name = std::wstring(ks::rescue::kDesktopPrefix)
                + std::to_wstring(::GetCurrentProcessId()) + L"." + std::to_wstring(::GetTickCount64());
            handles_.desktop = ks::rescue::CreatePrivateDesktop(name);
            if (!handles_.desktop)
            {
                LogStage(L"private.create_failed", ::GetLastError());
                return false;
            }
            LogStage(L"private.created", ERROR_SUCCESS, 0, name);
            if (!::SetThreadDesktop(handles_.desktop))
            {
                LogStage(L"private.bind_failed", ::GetLastError());
                return false;
            }
            LogStage(L"private.bound");

            // 事件不命名，其他进程不能靠猜名称提前宣布就绪或要求退出。
            SECURITY_ATTRIBUTES security{}; // 只有白名单中的事件允许继承。
            security.nLength = sizeof(security);
            security.bInheritHandle = TRUE;
            handles_.ready = ::CreateEventW(&security, TRUE, FALSE, nullptr);
            if (!handles_.ready)
            {
                LogStage(L"event.ready_failed", ::GetLastError());
                return false;
            }
            handles_.leave = ::CreateEventW(&security, TRUE, FALSE, nullptr);
            if (!handles_.leave)
            {
                LogStage(L"event.leave_failed", ::GetLastError());
                return false;
            }
            const BOOL duplicated = ::DuplicateHandle(::GetCurrentProcess(), ::GetCurrentProcess(),
                ::GetCurrentProcess(), &handles_.host, SYNCHRONIZE, TRUE, 0);
            if (!duplicated)
            {
                LogStage(L"host.duplicate_failed", ::GetLastError());
                return false;
            }

            // 退出快捷键由监护循环处理，即使 KSword 的 Qt 线程阻塞也能返回原桌面。
            hotkey_ = ::RegisterHotKey(nullptr, ks::rescue::kReturnHotkeyId,
                MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, VK_F10) != FALSE;
            if (!hotkey_)
            {
                LogStage(L"input.hotkey_failed", ::GetLastError());
                return false;
            }
            mouse_ = ::SetWindowsHookExW(WH_MOUSE_LL, MouseGuard, ::GetModuleHandleW(nullptr), 0);
            if (!mouse_)
            {
                LogStage(L"input.mouse_hook_failed", ::GetLastError());
                return false;
            }
            keyboard_ = ::SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardGuard, ::GetModuleHandleW(nullptr), 0);
            if (!keyboard_)
            {
                LogStage(L"input.keyboard_hook_failed", ::GetLastError());
                return false;
            }
            LogStage(L"input.guards_ready");
            DWORD error = ERROR_SUCCESS; // 记录启动失败原因，供独立监护进程的退出码报告。
            if (!ks::rescue::LaunchClient(executable, originalName, handles_, process_, error))
            {
                LogStage(L"client.launch_failed", error);
                ::SetLastError(error);
                return false;
            }
            ::CloseHandle(process_.hThread);
            process_.hThread = nullptr;
            LogStage(L"client.started", ERROR_SUCCESS, process_.dwProcessId);
            return true;
        }

        // 等待就绪/退出同时泵送 Hook 消息，确保启动耗时不会导致低级 Hook 超时。
        int run()
        {
            const ULONGLONG deadline = ::GetTickCount64() + 60000; // 首次窗口就绪最多等待一分钟。
            bool entered = false; // 已完成首次桌面切换。
            bool leaving = false; // 已请求退出，禁止再次切入救援桌面。
            while (true)
            {
                std::array<HANDLE, 3> waiting{ process_.hProcess, handles_.leave, handles_.ready };
                const DWORD count = leaving ? 1 : (entered ? 2 : 3); // 避免手动复位事件造成忙轮询。
                const DWORD result = ::MsgWaitForMultipleObjects(count, waiting.data(), FALSE, 200, QS_ALLINPUT);
                if (result == WAIT_OBJECT_0)
                {
                    DWORD exitCode = 0; // 子进程的最终状态。
                    ::GetExitCodeProcess(process_.hProcess, &exitCode);
                    LogStage(L"client.exit", ERROR_SUCCESS, exitCode);
                    return static_cast<int>(exitCode);
                }
                if (!leaving && result == WAIT_OBJECT_0 + 1)
                {
                    restore();
                    leaving = true;
                }
                if (!entered && !leaving && result == WAIT_OBJECT_0 + 2)
                {
                    LogStage(L"client.ready");
                    // 如果用户已经锁屏/进入 UAC，等待原桌面重新活动，绝不强制覆盖安全屏幕。
                    if (ks::rescue::IsInputDesktop(original_))
                    {
                        if (!::SwitchDesktop(handles_.desktop))
                        {
                            LogStage(L"private.switch_failed", ::GetLastError());
                            ::SetEvent(handles_.leave);
                            return 3;
                        }
                        entered = true;
                        LogStage(L"private.entered");
                    }
                    else
                    {
                        // ready 为手动复位事件；让后续等待真正阻塞，避免锁屏期间持续占用 CPU。
                        ::ResetEvent(handles_.ready);
                        readyPending_ = true;
                        LogStage(L"original.wait_until_active");
                    }
                }
                if (readyPending_ && !entered && !leaving && ks::rescue::IsInputDesktop(original_))
                {
                    ::SetEvent(handles_.ready);
                    readyPending_ = false;
                }

                MSG message{}; // 只泵送监护线程自己的消息，不借用 KSword UI 线程。
                while (::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
                {
                    if (message.message == WM_HOTKEY && message.wParam == ks::rescue::kReturnHotkeyId
                        && physicalReturnTick != 0 && ::GetTickCount64() - physicalReturnTick <= 1000)
                    {
                        physicalReturnTick = 0;
                        restore();
                        ::SetEvent(handles_.leave);
                        leaving = true;
                    }
                    ::TranslateMessage(&message);
                    ::DispatchMessageW(&message);
                }
                if (result == WAIT_FAILED)
                {
                    LogStage(L"monitor.wait_failed", ::GetLastError());
                    ::SetEvent(handles_.leave);
                    return 4;
                }
                if (leaving)
                {
                    // 返回请求发出后继续重试恢复，瞬时 SwitchDesktop 失败不能留下空桌面。
                    restore();
                }
                if (!entered && !leaving && ::GetTickCount64() >= deadline)
                {
                    LogStage(L"client.ready_timeout", WAIT_TIMEOUT);
                    // 超时仅要求本次新实例退出，保持当前用户桌面，不退回普通启动模式。
                    ::SetEvent(handles_.leave);
                    return 5;
                }
            }
        }

    private:
        // 只在自己的桌面正在接收输入时恢复，避免退出事件抢走 Winlogon/UAC 或其他桌面。
        void restore()
        {
            if (original_ && handles_.desktop && ks::rescue::IsInputDesktop(handles_.desktop))
            {
                if (::SwitchDesktop(original_))
                {
                    LogStage(L"original.restored");
                }
                else
                {
                    LogStage(L"original.restore_failed", ::GetLastError());
                }
            }
        }

        HDESK original_ = nullptr; // 操作开始前的输入桌面，保持到客户端退出。
        HDESK threadDesktop_ = nullptr; // Windows 管理的原线程桌面，不手动 CloseDesktop。
        ks::rescue::ClientHandles handles_; // 客户端可继承的最小句柄集。
        PROCESS_INFORMATION process_{}; // 本会话唯一的 KSword 客户端。
        HHOOK mouse_ = nullptr; // 救援桌面低级鼠标 Hook。
        HHOOK keyboard_ = nullptr; // 救援桌面低级键盘 Hook。
        bool hotkey_ = false; // 独立的物理应急返回快捷键是否注册成功。
        bool readyPending_ = false; // 就绪时原桌面暂时不活动，等待恢复后切换。
    };
}

int RunRescueDesktopHostIfRequested()
{
    int count = 0; // CommandLineToArgvW 返回的参数数量。
    wchar_t** arguments = ::CommandLineToArgvW(::GetCommandLineW(), &count);
    if (!arguments)
    {
        LogStage(L"entry.arguments_failed", ::GetLastError());
        return 2;
    }
    const bool requested = count >= 2 && std::wstring(arguments[1]) == ks::rescue::kHostArgument;
    const bool elevationAttempted = requested && (count == 4 || count == 6)
        && std::wstring(arguments[3]) == kElevationAttemptArgument;
    const bool originHandoff = elevationAttempted && count == 6
        && std::wstring(arguments[4]) == kOriginalDesktopArgument;
    const std::wstring executable = requested && (count == 3 || (count == 4 && elevationAttempted)
        || originHandoff) ? arguments[2] : L"";
    const std::wstring originalName = originHandoff ? arguments[5] : L"";
    ::LocalFree(arguments);
    if (!requested)
    {
        return -1;
    }
    LogStage(L"entry", ERROR_SUCCESS, static_cast<DWORD>(count),
        ks::rescue::DesktopName(::GetThreadDesktop(::GetCurrentThreadId())));
    if (executable.empty() || (originHandoff
        && (originalName.empty() || originalName.find_first_of(L"\\/\"") != std::wstring::npos)))
    {
        LogStage(L"entry.invalid_arguments", ERROR_INVALID_PARAMETER);
        return 2;
    }

    // 普通主程序和 Taskbar 都监听 SOS；只有首个引导进程持有会话名，避免一次按键启动两份。
    // UAC 接替进程借用仍存活的引导进程所持门闩，不重复获取。
    struct LaunchGuard
    {
        HANDLE handle = nullptr;
        ~LaunchGuard() { if (handle) ::CloseHandle(handle); }
    } launchGuard;
    if (!elevationAttempted)
    {
        launchGuard.handle = ::CreateMutexW(nullptr, FALSE, ks::rescue::kSessionGuardName);
        const DWORD error = ::GetLastError();
        if (!launchGuard.handle)
        {
            LogStage(L"entry.session_guard_failed", error);
            return 2;
        }
        if (error == ERROR_ALREADY_EXISTS)
        {
            LogStage(L"entry.session_already_active");
            return 0;
        }
    }

    // 先提升监护进程，再建立私有桌面和句柄；客户端直接继承管理员令牌，不在救援桌面内重启。
    bool elevated = false; // 当前 Windows 令牌是否已经提升。
    if (!QueryCurrentElevation(elevated))
    {
        LogStage(L"elevation.query_failed", ::GetLastError());
        ::OutputDebugStringW(L"[Taskbar][SOS] Cannot verify the rescue host elevation token.\n");
        return 2;
    }
    LogStage(L"elevation.state", ERROR_SUCCESS, elevated ? 1 : 0);
    if (!elevated)
    {
        if (elevationAttempted)
        {
            LogStage(L"elevation.still_unelevated", ERROR_ELEVATION_REQUIRED);
            // 即使命令行声称已提权，也必须核验真实令牌；失败只结束，不循环弹 UAC。
            ::OutputDebugStringW(L"[Taskbar][SOS] Rescue host is still not elevated after UAC.\n");
            return 2;
        }
        // UAC 前记录输入桌面，避免批准后把尚在活动的安全桌面当成返回目标。
        const HDESK beforeUac = ::OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
        if (!beforeUac)
        {
            LogStage(L"original.capture_failed", ::GetLastError());
            return 2;
        }
        const std::wstring sourceName = ks::rescue::DesktopName(beforeUac); // 跨 UAC 只传名称，不传句柄。
        ::CloseDesktop(beforeUac);
        if (sourceName.empty() || sourceName.find_first_of(L"\\/\"") != std::wstring::npos)
        {
            LogStage(L"original.invalid_name", ERROR_INVALID_NAME);
            return 2;
        }
        LogStage(L"original.captured", ERROR_SUCCESS, 0, sourceName);
        return LaunchElevatedHostAndWait(executable, sourceName);
    }

    HostSession session; // 独立进程在所有退出分支都自动清理并尝试恢复原桌面。
    if (!session.start(executable, originalName))
    {
        ::OutputDebugStringW(L"[Taskbar][SOS] Rescue desktop initialization failed.\n");
        return 2;
    }
    return session.run();
}
