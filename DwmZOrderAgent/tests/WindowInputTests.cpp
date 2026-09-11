#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "../../Ksword5.1/Ksword5.1/OtherDock/WindowInputClient.h"
#include <cstdio>
#include <cstdlib>
#include <string>

namespace
{
    using namespace ks::window_input;
    using ks::dwm_order::WindowIdentity;
    enum class DwmBehavior { Ready, Missing, ApplyFailure, RestoreFailure, Busy };
    DwmBehavior behavior = DwmBehavior::Ready;
    std::uint64_t maintained = 0;
    int dwmCalls = 0;
    int failures = 0;

    void Check(bool ok, const char* name)
    {
        if (!ok) { std::printf("FAIL: %s (Win32 %lu)\n", name, GetLastError()); ++failures; }
    }

    struct HostWindows { HWND normal, child, layered, ownDc; };

    int Host()
    {
        WNDCLASSW cls{};
        cls.hInstance = GetModuleHandleW(nullptr);
        cls.lpfnWndProc = DefWindowProcW;
        cls.lpszClassName = L"WindowInputTestHost";
        if (!RegisterClassW(&cls)) return 2;
        HostWindows windows{};
        // Off-screen fixtures never overlap the user's windows.
        windows.normal = CreateWindowExW(0, cls.lpszClassName, L"Input fixture", WS_POPUP | WS_VISIBLE,
            -30000, -30000, 32, 32, nullptr, nullptr, cls.hInstance, nullptr);
        windows.child = CreateWindowExW(0, cls.lpszClassName, L"Child fixture", WS_CHILD,
            0, 0, 8, 8, windows.normal, nullptr, cls.hInstance, nullptr);
        windows.layered = CreateWindowExW(WS_EX_LAYERED, cls.lpszClassName, L"Layered fixture", WS_POPUP,
            -30000, -30000, 32, 32, nullptr, nullptr, cls.hInstance, nullptr);
        SetLayeredWindowAttributes(windows.layered, RGB(1, 2, 3), 123, LWA_ALPHA | LWA_COLORKEY);
        cls.style = CS_OWNDC;
        cls.lpszClassName = L"WindowInputTestOwnDC";
        if (!RegisterClassW(&cls)) return 3;
        windows.ownDc = CreateWindowExW(0, cls.lpszClassName, L"DC fixture", WS_POPUP,
            -30000, -30000, 32, 32, nullptr, nullptr, cls.hInstance, nullptr);
        if (!windows.normal || !windows.child || !windows.layered || !windows.ownDc) return 4;
        DWORD written = 0;
        if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &windows, sizeof(windows), &written, nullptr)
            || written != sizeof(windows)) return 5;
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        { TranslateMessage(&message); DispatchMessageW(&message); }
        for (HWND hwnd : {windows.child, windows.normal, windows.layered, windows.ownDc}) DestroyWindow(hwnd);
        return 0;
    }

    WindowIdentity Identity(HWND hwnd)
    {
        WindowIdentity identity;
        std::uint32_t error = 0;
        Check(Capture(reinterpret_cast<std::uint64_t>(hwnd), identity, error), "capture fixture identity");
        return identity;
    }

    int CALLBACK RemoveInputMarker(HWND hwnd, LPWSTR name, HANDLE, ULONG_PTR)
    {
        if (IS_INTRESOURCE(name)) return 1;
        if (std::wstring(name).find(L"KSword.WindowInput.") == 0) RemovePropW(hwnd, name);
        return 1;
    }
}

// This test binary never opens or injects into DWM. These receipts exercise
// native-input rollback and ownership without running the compositor agent.
namespace ks::dwm_order
{
    std::recursive_mutex& OperationMutex() { static std::recursive_mutex lock; return lock; }
    Reply ExecuteRequest(const Request& request, const std::wstring&, bool allowLoad)
    {
        ++dwmCalls;
        Check(!allowLoad, "window settings must not inject DWM");
        Reply reply;
        reply.response.status = Status::Ok;
        reply.response.flags = Verified;
        if (behavior == DwmBehavior::Missing) reply.response.status = Status::NotRunning;
        else if (request.action == Action::Apply)
        {
            if (behavior == DwmBehavior::ApplyFailure) reply.response.status = Status::NativeFailure;
            else maintained = request.target.hwnd;
        }
        else if (request.action == Action::Restore)
        {
            if (behavior == DwmBehavior::RestoreFailure) reply.response.status = Status::Timeout;
            else maintained = 0;
        }
        if (maintained || behavior == DwmBehavior::Busy)
        { reply.response.flags |= Maintaining; reply.response.maintainedWindow = maintained ? maintained : 123; }
        return reply;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"--host") return Host();
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &security, 0)) return 2;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    wchar_t exe[32768]{};
    GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(std::size(exe)));
    std::wstring command = L"\"" + std::wstring(exe) + L"\" --host";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writePipe;
    startup.hStdError = writePipe;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(exe, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process)) return 3;
    CloseHandle(writePipe);
    HostWindows windows{};
    DWORD read = 0;
    const bool hostReady = ReadFile(readPipe, &windows, sizeof(windows), &read, nullptr) && read == sizeof(windows);
    CloseHandle(readPipe);
    Check(hostReady, "fixture startup");
    if (hostReady)
    {
        const auto normal = Identity(windows.normal), child = Identity(windows.child);
        const auto layered = Identity(windows.layered), ownDc = Identity(windows.ownDc);
        Check(Apply(normal, Mode::Disabled, L"").status == Status::Ok, "disable normal window");
        Check(!IsWindowEnabled(windows.normal), "disabled readback");
        EnableWindow(windows.normal, TRUE);
        Check(Apply(normal, Mode::Disabled, L"").status == Status::Ok
            && !IsWindowEnabled(windows.normal), "repeat apply repairs externally changed state");
        auto wrong = normal;
        ++wrong.processCreated;
        Check(Restore(wrong, L"").status == Status::InvalidWindow, "reject stale restore identity");
        Check(!IsWindowEnabled(windows.normal), "stale restore made no change");
        Check(Restore(normal, L"").status == Status::Ok && IsWindowEnabled(windows.normal), "restore enabled state");

        Check(Apply(child, Mode::Disabled, L"").status == Status::Ok && !IsWindowEnabled(windows.child), "disable child window");
        Check(Restore(child, L"").status == Status::Ok && IsWindowEnabled(windows.child), "restore child window");

        const auto originalEx = GetWindowLongPtrW(windows.normal, GWL_EXSTYLE);
        Check(Apply(normal, Mode::ClickThrough, L"").status == Status::Ok, "apply layered pass-through");
        Check(Query(normal).clickThrough, "pass-through readback");
        SetWindowLongPtrW(windows.normal, GWL_EXSTYLE, GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
        Check(Restore(normal, L"").status == Status::Ok, "restore pass-through");
        Check(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) == (originalEx | WS_EX_TOOLWINDOW), "preserve unrelated style changes");

        Check(Apply(layered, Mode::ClickThrough, L"").status == Status::Ok, "pass-through on existing layered window");
        Check(Restore(layered, L"").status == Status::Ok, "restore existing layered window");
        COLORREF color = 0;
        BYTE alpha = 0;
        DWORD flags = 0;
        Check(GetLayeredWindowAttributes(windows.layered, &color, &alpha, &flags)
            && color == RGB(1, 2, 3) && alpha == 123 && flags == (LWA_ALPHA | LWA_COLORKEY), "preserve original alpha and color key");
        Check(Apply(ownDc, Mode::ClickThrough, L"").status == Status::UnsupportedWindow, "reject unsupported layered class");
        Check(dwmCalls == 0, "basic input modes do not access DWM");

        behavior = DwmBehavior::Missing;
        Check(Apply(normal, Mode::Covered, L"").status == Status::DwmFailure, "covered mode requires preloaded agent");
        Check(!(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) & WS_EX_TOPMOST), "missing agent leaves native order alone");
        behavior = DwmBehavior::Busy;
        Check(Apply(normal, Mode::Covered, L"").status == Status::OrderInUse, "do not replace another maintained window");
        behavior = DwmBehavior::ApplyFailure;
        Check(Apply(normal, Mode::Covered, L"").status == Status::DwmFailure, "failed DWM apply is reported");
        Check(!(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) & WS_EX_TOPMOST), "failed DWM apply rolls back native topmost");
        Check(!Query(normal).managed, "successful rollback removes saved record");
        behavior = DwmBehavior::Ready;
        Check(Apply(normal, Mode::Covered, L"").status == Status::Ok && HasCoveredWindow(), "covered mode transaction");
        Check(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) & WS_EX_TOPMOST, "covered mode uses real native topmost");
        maintained = 0;
        Check(Query(normal).status == Status::OrderChanged, "query detects lost DWM maintenance");
        maintained = normal.hwnd;
        behavior = DwmBehavior::RestoreFailure;
        Check(Restore(normal, L"").status == Status::RestoreFailed && HasCoveredWindow(), "retain incomplete restoration");
        behavior = DwmBehavior::Ready;
        Check(Restore(normal, L"").status == Status::Ok && !HasCoveredWindow(), "retry incomplete restoration");
        Check(!Restore(normal, L"").restored, "no saved record is not reported as restored");

        Check(Apply(normal, Mode::Disabled, L"").status == Status::Ok, "prepare lifetime marker case");
        EnumPropsExW(windows.normal, RemoveInputMarker, 0);
        RestoreAll(L"");
        Check(!IsWindowEnabled(windows.normal), "lost lifetime marker prevents stale restoration");
        EnableWindow(windows.normal, TRUE);
        Check(Apply(normal, Mode::ClickThrough, L"").status == Status::Ok, "prepare restore all pass-through");
        Check(Apply(child, Mode::Disabled, L"").status == Status::Ok, "prepare restore all disabled child");
        Check(RestoreAll(L"").status == Status::Ok, "restore all input settings");
        Check(IsWindowEnabled(windows.child) && !Query(normal).clickThrough, "restore all readback");
    }
    PostThreadMessageW(process.dwThreadId, WM_QUIT, 0, 0);
    if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 4);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    std::printf("Window input tests: %s\n", failures ? "FAILED" : "PASS");
    return failures ? 1 : 0;
}
