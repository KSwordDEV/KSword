#include "Launcher.h"

#include <commctrl.h>
#include <strsafe.h>

#pragma comment(lib, "comctl32.lib")

namespace launcher {

namespace {
#ifndef TDCBF_OK
#define TDCBF_OK 0x0001
#endif
constexpr int kMainButton = 1001;
constexpr int kLightButton = 1002;
constexpr int kIgnoreButton = 1003;
constexpr int kUploadButton = 1004;
constexpr int kRetryButton = 1005;
constexpr int kCancelButton = 1006;

std::wstring Text(bool chinese, const wchar_t* zh, const wchar_t* en) { return chinese ? zh : en; }

int TaskDialog(const std::wstring& title, const std::wstring& body, const std::wstring& instruction, DWORD buttons, bool chinese, bool allowCancel = true) {
    (void)chinese;
    (void)allowCancel;
    TASKDIALOGCONFIG config = { sizeof(config) };
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    config.pszWindowTitle = title.c_str();
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = body.c_str();
    config.dwCommonButtons = buttons;
    config.pszMainIcon = TD_INFORMATION_ICON;
    int result = 0;
    if (FAILED(TaskDialogIndirect(&config, &result, nullptr, nullptr))) {
        MessageBoxW(nullptr, body.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
        result = IDOK;
    }
    return result;
}

LRESULT CALLBACK CheckingWndProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams));
    }
    if (message == WM_CLOSE) { DestroyWindow(window); return 0; }
    if (message == WM_DESTROY) return 0;
    return DefWindowProcW(window, message, wParam, lParam);
}

}

void ShowSimpleMessage(const std::wstring& title, const std::wstring& body, bool chinese) {
    TaskDialog(title, body, title, TDCBF_OK, chinese);
}

int ShowUnsupportedOsDialog(const OsInfo& os, bool chinese) {
    const std::wstring version = L"Windows " + std::to_wstring(os.major) + L"." + std::to_wstring(os.minor) + L" (Build " + std::to_wstring(os.build) + L")";
    std::wstring body = chinese ? L"此系统早于 Windows 10，Ksword 不支持该系统。\n检测到版本：" + version : L"This system is older than Windows 10 and is not supported by Ksword.\nDetected version: " + version;
    return TaskDialog(Text(chinese, L"Ksword 兼容性检查", L"Ksword compatibility check"), body, Text(chinese, L"系统版本不受支持", L"Unsupported Windows version"), TDCBF_OK, chinese);
}

int ShowUnsupportedBuildDialog(const OsInfo& os, DWORD maximumBuild, bool chinese) {
    const std::wstring version = L"Windows " + std::to_wstring(os.major) + L"." + std::to_wstring(os.minor) + L" (Build " + std::to_wstring(os.build) + L")";
    const std::wstring limit = std::to_wstring(maximumBuild);
    const std::wstring body = chinese
        ? L"此 Windows build 超出 Ksword 已验证的最高版本（Build " + limit + L"）。主程序不会启动需要内核偏移的功能；可以使用诊断模式收集上报信息。\n检测到版本：" + version
        : L"This Windows build is newer than the highest Ksword-validated build (" + limit + L"). The main program will not start offset-dependent kernel features; diagnostic collection remains available.\nDetected version: " + version;
    return TaskDialog(Text(chinese, L"Ksword 兼容性检查", L"Ksword compatibility check"), body, Text(chinese, L"Windows build 暂不受支持", L"Windows build is not supported"), TDCBF_OK, chinese);
}

int ShowEarlyWindowsChoiceDialog(bool chinese) {
    const std::wstring title = Text(chinese, L"Ksword 兼容性检查", L"Ksword compatibility check");
    const std::wstring instruction = Text(chinese, L"当前 Windows 版本早于主程序的 Qt 6.9.3 要求", L"This Windows version predates the main program's Qt 6.9.3 requirement");
    const std::wstring content = Text(chinese, L"主程序可能无法良好运行，但 Light 版本仍支持早期 Windows 10。请选择启动目标。", L"The main program may not run well, while the Light edition supports early Windows 10. Choose a launch target.");
    const std::wstring mainButton = Text(chinese, L"强制运行主程序", L"Force main program");
    const std::wstring lightButton = Text(chinese, L"运行 Light 版本", L"Run Light version");
    TASKDIALOG_BUTTON buttons[] = {
        { kMainButton, mainButton.c_str() },
        { kLightButton, lightButton.c_str() },
    };
    TASKDIALOGCONFIG config = { sizeof(config) };
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    config.pszWindowTitle = title.c_str();
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = content.c_str();
    config.cButtons = ARRAYSIZE(buttons);
    config.pButtons = buttons;
    config.nDefaultButton = kLightButton;
    config.pszMainIcon = TD_WARNING_ICON;
    int result = 0;
    TaskDialogIndirect(&config, &result, nullptr, nullptr);
    return result;
}

int ShowMissingDataDialog(bool chinese) {
    const std::wstring title = Text(chinese, L"Ksword 兼容性检查", L"Ksword compatibility check");
    const std::wstring instruction = Text(chinese, L"发现不支持的部分", L"Some system data is not supported");
    const std::wstring content = Text(chinese,
        L"开发者目前没有你的系统的一部分或全部偏移信息。忽略后仍可启动并使用大多数功能，但部分高级功能会缺少适配。上传收集包后，大概率可在下个版本得到支持。\n\n点击“上传”后，请将打开文件夹中的内容压缩并发送给开发者。",
        L"The developer does not yet have all offsets for this system. You can still use most features, but some advanced features may lack adaptation. Preparing this bundle gives the next version a good chance to support your system.\n\nAfter choosing Prepare upload, compress the opened folder and send it to the developer.");
    const std::wstring ignoreButton = Text(chinese, L"忽略", L"Ignore");
    const std::wstring uploadButton = Text(chinese, L"上传", L"Prepare upload");
    TASKDIALOG_BUTTON buttons[] = {
        { kIgnoreButton, ignoreButton.c_str() },
        { kUploadButton, uploadButton.c_str() },
    };
    TASKDIALOGCONFIG config = { sizeof(config) };
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    config.pszWindowTitle = title.c_str();
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = content.c_str();
    config.cButtons = ARRAYSIZE(buttons);
    config.pButtons = buttons;
    config.nDefaultButton = kIgnoreButton;
    config.pszMainIcon = TD_WARNING_ICON;
    int result = 0;
    TaskDialogIndirect(&config, &result, nullptr, nullptr);
    return result == kUploadButton ? kUploadButton : kIgnoreButton;
}

int ShowUploadElevationFailureDialog(bool chinese) {
    const std::wstring title = Text(chinese, L"需要管理员权限", L"Administrator permission required");
    const std::wstring instruction = Text(chinese, L"采集数据需要管理员权限", L"Administrator permission is required to collect data");
    const std::wstring content = Text(chinese, L"Windows 未接受提权请求。可以重试，或取消上传并继续启动。", L"Windows did not accept the elevation request. Retry, or cancel upload and continue launching.");
    const std::wstring retryButton = Text(chinese, L"重试", L"Retry");
    const std::wstring cancelButton = Text(chinese, L"取消上传", L"Cancel upload");
    TASKDIALOG_BUTTON buttons[] = {
        { kRetryButton, retryButton.c_str() },
        { kCancelButton, cancelButton.c_str() },
    };
    TASKDIALOGCONFIG config = { sizeof(config) };
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    config.pszWindowTitle = title.c_str();
    config.pszMainInstruction = instruction.c_str();
    config.pszContent = content.c_str();
    config.cButtons = ARRAYSIZE(buttons);
    config.pButtons = buttons;
    config.nDefaultButton = kRetryButton;
    config.pszMainIcon = TD_WARNING_ICON;
    int result = 0;
    TaskDialogIndirect(&config, &result, nullptr, nullptr);
    return result == kRetryButton ? kRetryButton : kCancelButton;
}

void ShowCheckingWindow(const std::wstring& text, HWND* output) {
    if (!output) return;
    *output = nullptr;
    static const wchar_t kClassName[] = L"KswordLauncherCheckingWindow";
    static bool registered = false;
    if (!registered) {
        WNDCLASSW klass = {};
        klass.lpfnWndProc = CheckingWndProc;
        klass.hInstance = GetModuleHandleW(nullptr);
        klass.hCursor = LoadCursorW(nullptr, IDC_WAIT);
        klass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        klass.lpszClassName = kClassName;
        registered = RegisterClassW(&klass) != 0;
    }
    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME, kClassName, L"Ksword Launcher", WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 520, 150, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!window) return;
    HWND label = CreateWindowW(L"STATIC", text.c_str(), WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 45, 480, 35, window, nullptr, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
    RECT work = {}; SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    SetWindowPos(window, HWND_TOP, work.left + (work.right - work.left - 520) / 2, work.top + (work.bottom - work.top - 150) / 2, 520, 150, SWP_SHOWWINDOW);
    UpdateWindow(window);
    *output = window;
}

void CloseCheckingWindow(HWND window) {
    if (window) DestroyWindow(window);
    MSG message = {};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&message); DispatchMessageW(&message); }
}

void ShowCollectionProgress(bool chinese, CollectionProgress* progress) {
    if (!progress) return;
    *progress = {};
    INITCOMMONCONTROLSEX init = { sizeof(init), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&init);
    static const wchar_t kClassName[] = L"KswordLauncherCheckingWindow";
    static bool registered = false;
    if (!registered) {
        WNDCLASSW klass = {};
        klass.lpfnWndProc = CheckingWndProc;
        klass.hInstance = GetModuleHandleW(nullptr);
        klass.hCursor = LoadCursorW(nullptr, IDC_WAIT);
        klass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        klass.lpszClassName = kClassName;
        registered = RegisterClassW(&klass) != 0;
    }
    const int width = 520;
    const int height = 180;
    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME, kClassName,
        chinese ? L"Ksword 启动器" : L"Ksword Launcher",
        WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, width, height,
        nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!window) return;
    HWND label = CreateWindowW(L"STATIC", chinese ? L"准备采集…" : L"Preparing collection...",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 35, 480, 30, window, nullptr,
        GetModuleHandleW(nullptr), nullptr);
    HWND bar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | WS_VISIBLE, 20, 85, 480, 24, window, nullptr,
        GetModuleHandleW(nullptr), nullptr);
    SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
    SendMessageW(bar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessageW(bar, PBM_SETPOS, 0, 0);
    RECT work = {}; SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    SetWindowPos(window, HWND_TOP, work.left + (work.right - work.left - width) / 2,
        work.top + (work.bottom - work.top - height) / 2, width, height, SWP_SHOWWINDOW);
    UpdateWindow(window);
    progress->window = window;
    progress->label = label;
    progress->bar = bar;
}

void UpdateCollectionProgress(CollectionProgress* progress, int percent, const std::wstring& text) {
    if (!progress || !progress->window) return;
    if (progress->label) SetWindowTextW(progress->label, text.c_str());
    const int position = percent < 0 ? 0 : (percent > 100 ? 100 : percent);
    if (progress->bar) SendMessageW(progress->bar, PBM_SETPOS, static_cast<WPARAM>(position), 0);
    UpdateWindow(progress->window);
    MSG message = {};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

void CloseCollectionProgress(CollectionProgress* progress) {
    if (!progress) return;
    if (progress->window) DestroyWindow(progress->window);
    *progress = {};
    MSG message = {};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

}
