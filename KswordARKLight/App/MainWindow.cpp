#include "MainWindow.h"

#include "../Core/Common.h"
#include "../Core/DriverService.h"
#include "../Core/Privilege.h"
#include "../Core/WorkspaceConfig.h"
#include "../Features/FeatureRegistry.h"
#include "../Features/File/FileFeature.h"
#include "../Features/Handle/HandleFeature.h"
#include "../Features/Memory/MemoryFeature.h"
#include "../Features/Monitor/MonitorFeature.h"
#include "../Features/Network/NetworkFeature.h"
#include "../Features/Process/ProcessFeature.h"
#include "../Features/Registry/RegistryFeature.h"
#include "../Features/Window/WindowFeature.h"
#include "../Ui/Controls.h"
#include "../Ui/EntityNavigation.h"
#include "../Ui/EvidenceSession.h"
#include "../Ui/EvidenceSessionView.h"
#include "../Ui/ExportUtil.h"
#include "../Ui/Theme.h"
#include "../resource.h"

#include <algorithm>
#include <commctrl.h>
#include <cstdint>
#include <tlhelp32.h>
#include <cwctype>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace Ksword::App {
namespace {
constexpr wchar_t kMainWindowClass[] = L"KswordARKLight.MainWindow";
constexpr int kTopmostMenuId = 1000;
constexpr int kPrivilegeMenuId = 1001;
constexpr int kDriverMenuId = 1002;
constexpr int kCommandEditId = 1003;
constexpr int kStatusTextId = 1004;
constexpr int kNavigationPaletteMenuId = 1005;
constexpr int kEvidenceInspectorMenuId = 1099;
constexpr int kEvidenceJsonPrivacyMenuId = 1100;
constexpr int kEvidenceJsonRawMenuId = 1101;
constexpr int kEvidenceTsvPrivacyMenuId = 1102;
constexpr int kEvidenceDiffMenuId = 1103;
constexpr int kEvidenceClearMenuId = 1104;
constexpr int kCommandEditWidth = 320;
constexpr int kCommandEditHeight = 22;
constexpr int kCommandEditMenuGap = 8;
constexpr int kNavigationPaletteWidth = 560;
constexpr int kNavigationPaletteHeight = 440;
constexpr int kStatusHeight = 18;
constexpr int kWindowMenuDockBaseId = 42000;
constexpr int kProcessModuleCommandId = 40001;
constexpr int kMemoryModuleCommandId = 40002;
constexpr int kFileModuleCommandId = 40003;
constexpr int kMonitorModuleCommandId = 40006;
constexpr int kWindowModuleCommandId = 40008;
constexpr int kRegistryModuleCommandId = 40010;
constexpr int kNetworkModuleCommandId = 40011;
constexpr int kHandleModuleCommandId = 40012;
constexpr UINT kMsgQueryDriverStatus = WM_APP + 101;
constexpr UINT kMsgDockActivated = WM_APP + 102;
constexpr UINT kMsgMaterializeDock = WM_APP + 103;
constexpr wchar_t kWorkspaceRegistryPath[] = L"Software\\KSwordDEV\\KswordARKLight\\Workspace";
constexpr wchar_t kWorkspaceRegistryValue[] = L"State";

// RegisterMainWindowClass registers the top-level shell class. Input is the
// module instance; processing installs icon/cursor/background metadata; output
// is true after RegisterClassW succeeds or the class already exists.
bool RegisterMainWindowClass(HINSTANCE instance) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = MainWindow::WndProc;
    wc.hInstance = instance;
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.hIcon = ::LoadIconW(instance, MAKEINTRESOURCEW(IDI_KSWORDARKLIGHT_APP));
    wc.lpszClassName = kMainWindowClass;
    if (::RegisterClassW(&wc)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

// CenterWindowRect returns a centered rectangle in the primary work area. Inputs
// are requested dimensions; output is the rectangle used for CreateWindowExW.
RECT CenterWindowRect(int width, int height) {
    RECT work{};
    ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int x = work.left + ((work.right - work.left) - width) / 2;
    const int y = work.top + ((work.bottom - work.top) - height) / 2;
    return { x, y, x + width, y + height };
}

// TrimWhitespace removes leading/trailing Unicode whitespace from one command.
// Input is raw edit text; processing keeps interior spacing intact; output is
// used only to decide whether Enter should launch cmd.exe.
std::wstring TrimWhitespace(const std::wstring& value) {
    std::size_t first = 0;
    while (first < value.size() && std::iswspace(value[first])) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first && std::iswspace(value[last - 1])) {
        --last;
    }
    return value.substr(first, last - first);
}

std::wstring LowerText(std::wstring value) {
    for (wchar_t& character : value) {
        character = static_cast<wchar_t>(std::towlower(character));
    }
    return value;
}

// ClampWorkspaceNormalRect keeps a persisted outer screen rectangle on an
// available monitor. It deliberately operates on GetWindowRect coordinates,
// never WINDOWPLACEMENT::rcNormalPosition work-area coordinates.
bool ClampWorkspaceNormalRect(const Ksword::Core::WorkspaceNormalRect& saved, RECT* rectOut) {
    if (!rectOut || !Ksword::Core::IsWorkspaceNormalRectValid(saved)) {
        return false;
    }

    RECT candidate{
        static_cast<LONG>(saved.left),
        static_cast<LONG>(saved.top),
        static_cast<LONG>(saved.right),
        static_cast<LONG>(saved.bottom)
    };
    const HMONITOR monitor = ::MonitorFromRect(&candidate, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!monitor || !::GetMonitorInfoW(monitor, &monitorInfo)) {
        return false;
    }

    const std::int64_t workWidth = static_cast<std::int64_t>(monitorInfo.rcWork.right) - monitorInfo.rcWork.left;
    const std::int64_t workHeight = static_cast<std::int64_t>(monitorInfo.rcWork.bottom) - monitorInfo.rcWork.top;
    const std::int64_t savedWidth = static_cast<std::int64_t>(saved.right) - saved.left;
    const std::int64_t savedHeight = static_cast<std::int64_t>(saved.bottom) - saved.top;
    if (workWidth <= 0 || workHeight <= 0 || savedWidth <= 0 || savedHeight <= 0) {
        return false;
    }

    const std::int64_t width = (std::min)(savedWidth, workWidth);
    const std::int64_t height = (std::min)(savedHeight, workHeight);
    const std::int64_t left = (std::clamp)(
        static_cast<std::int64_t>(saved.left),
        static_cast<std::int64_t>(monitorInfo.rcWork.left),
        static_cast<std::int64_t>(monitorInfo.rcWork.right) - width);
    const std::int64_t top = (std::clamp)(
        static_cast<std::int64_t>(saved.top),
        static_cast<std::int64_t>(monitorInfo.rcWork.top),
        static_cast<std::int64_t>(monitorInfo.rcWork.bottom) - height);
    *rectOut = {
        static_cast<LONG>(left),
        static_cast<LONG>(top),
        static_cast<LONG>(left + width),
        static_cast<LONG>(top + height)
    };
    return rectOut->right > rectOut->left && rectOut->bottom > rectOut->top;
}

Ksword::Core::WorkspaceConfig LoadWorkspaceConfig() {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, kWorkspaceRegistryPath, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return {};
    }

    DWORD type = 0;
    DWORD byteCount = 0;
    LONG status = ::RegQueryValueExW(key, kWorkspaceRegistryValue, nullptr, &type, nullptr, &byteCount);
    if (status != ERROR_SUCCESS || type != REG_BINARY || byteCount != Ksword::Core::kWorkspaceConfigBinarySize) {
        ::RegCloseKey(key);
        return {};
    }

    Ksword::Core::WorkspaceConfigBinary bytes{};
    byteCount = static_cast<DWORD>(bytes.size());
    status = ::RegQueryValueExW(key, kWorkspaceRegistryValue, nullptr, &type, bytes.data(), &byteCount);
    ::RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_BINARY || byteCount != bytes.size()) {
        return {};
    }

    const Ksword::Core::WorkspaceConfigDecodeResult decoded = Ksword::Core::DeserializeWorkspaceConfig(bytes);
    return decoded.valid() ? decoded.config : Ksword::Core::WorkspaceConfig{};
}

void StoreWorkspaceConfig(const Ksword::Core::WorkspaceConfig& config) {
    HKEY key = nullptr;
    if (::RegCreateKeyExW(HKEY_CURRENT_USER, kWorkspaceRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return;
    }

    const Ksword::Core::WorkspaceConfigBinary bytes = Ksword::Core::SerializeWorkspaceConfig(config);
    ::RegSetValueExW(key, kWorkspaceRegistryValue, 0, REG_BINARY, bytes.data(), static_cast<DWORD>(bytes.size()));
    ::RegCloseKey(key);
}

bool AllowsPersistedMaximize(const int showCommand) noexcept {
    return showCommand == SW_SHOWNORMAL || showCommand == SW_SHOW || showCommand == SW_SHOWDEFAULT;
}

bool IsEditableTextControl(const HWND hwnd) {
    if (!hwnd) {
        return false;
    }
    wchar_t className[32]{};
    if (::GetClassNameW(hwnd, className, static_cast<int>(sizeof(className) / sizeof(className[0]))) <= 0) {
        return false;
    }
    return ::lstrcmpiW(className, L"EDIT") == 0 ||
        ::lstrcmpiW(className, L"RICHEDIT20W") == 0 ||
        ::lstrcmpiW(className, L"RICHEDIT50W") == 0;
}

bool IsMainWindowDescendant(const HWND root, const HWND hwnd) {
    return root && hwnd && (root == hwnd || ::IsChild(root, hwnd));
}

DWORD ProcessIdForThread(const DWORD threadId) {
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    DWORD processId = 0;
    if (::Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32ThreadID == threadId) {
                processId = entry.th32OwnerProcessID;
                break;
            }
        } while (::Thread32Next(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return processId;
}

std::wstring HexIdentifier(const std::uint64_t value) {
    std::wostringstream output;
    output << L"0x" << std::hex << std::uppercase << value;
    return output.str();
}
} // namespace

MainWindow::MainWindow()
    : instance_(nullptr), hwnd_(nullptr), commandEdit_(nullptr), navigationPalette_(nullptr), statusText_(nullptr),
      mainMenu_(nullptr), windowMenu_(nullptr), evidenceMenu_(nullptr),
      commandEditProc_(nullptr), navigationPaletteProc_(nullptr),
      dockManager_(std::make_unique<Ksword::Docking::DockManager>()) {}

MainWindow::~MainWindow() = default;

bool MainWindow::create(HINSTANCE instance, int showCommand) {
    instance_ = instance;
    Ksword::Ui::AppTheme().ensure();
    Ksword::Ui::RegisterControlClasses(instance);
    Ksword::Docking::RegisterDockingClasses(instance);
    if (!RegisterMainWindowClass(instance)) {
        return false;
    }

    const Ksword::Core::WorkspaceConfig restoredWorkspace = LoadWorkspaceConfig();
    RECT rect = CenterWindowRect(1240, 780);
    if (restoredWorkspace.hasNormalRect) {
        RECT restoredRect{};
        if (ClampWorkspaceNormalRect(restoredWorkspace.normalRect, &restoredRect)) {
            rect = restoredRect;
        }
    }
    lastNormalScreenRect_ = rect;
    hasLastNormalScreenRect_ = true;
    restoredModuleCommandId_ = restoredWorkspace.activeCommandId;
    restoreMaximized_ = restoredWorkspace.maximized;
    wasMaximized_ = restoreMaximized_;
    hwnd_ = ::CreateWindowExW(0, kMainWindowClass, L"KswordARKLight", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
        nullptr, nullptr, instance, this);
    if (!hwnd_) {
        return false;
    }

    const int effectiveShowCommand = restoreMaximized_ && AllowsPersistedMaximize(showCommand)
        ? SW_SHOWMAXIMIZED
        : showCommand;
    ::ShowWindow(hwnd_, effectiveShowCommand);
    ::UpdateWindow(hwnd_);
    return true;
}

int MainWindow::run() {
    MSG msg{};
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == static_cast<WPARAM>(L'K') &&
            (::GetKeyState(VK_CONTROL) & 0x8000) != 0) {
            const HWND focus = ::GetFocus();
            if (IsMainWindowDescendant(hwnd_, focus) && !IsEditableTextControl(focus)) {
                showNavigationPalette();
                continue;
            }
        }
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        window = cs ? static_cast<MainWindow*>(cs->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        if (window) {
            // CreateWindowExW sends WM_NCCREATE/WM_CREATE before it returns to
            // MainWindow::create(). Store the real HWND immediately so all
            // child controls and dock hosts created during WM_CREATE receive a
            // valid parent window and become visible.
            window->hwnd_ = hwnd;
        }
    }
    if (window) {
        return window->handleMessage(hwnd, msg, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWindow::CommandEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    WNDPROC originalProc = window ? window->commandEditProc_ : nullptr;
    switch (msg) {
    case WM_GETDLGCODE:
        return DLGC_WANTALLKEYS;
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            if (window) {
                window->executeCommandInput();
            }
            return 0;
        }
        break;
    case WM_CHAR:
        if (wParam == VK_RETURN || wParam == L'\r') {
            return 0;
        }
        break;
    case WM_NCDESTROY:
        if (window && window->commandEditProc_) {
            ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(window->commandEditProc_));
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            originalProc = window->commandEditProc_;
            window->commandEditProc_ = nullptr;
            window->commandEdit_ = nullptr;
        }
        break;
    default:
        break;
    }
    return originalProc ? ::CallWindowProcW(originalProc, hwnd, msg, wParam, lParam) : ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWindow::NavigationPaletteProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    WNDPROC originalProc = window ? window->navigationPaletteProc_ : nullptr;
    switch (msg) {
    case WM_GETDLGCODE:
        return DLGC_WANTALLKEYS;
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            if (window) {
                window->activateNavigationPaletteSelection();
            }
            return 0;
        }
        if (wParam == VK_ESCAPE) {
            if (window) {
                window->hideNavigationPalette(true);
            }
            return 0;
        }
        break;
    case WM_LBUTTONDBLCLK: {
        const LRESULT result = originalProc
            ? ::CallWindowProcW(originalProc, hwnd, msg, wParam, lParam)
            : ::DefWindowProcW(hwnd, msg, wParam, lParam);
        if (window) {
            window->activateNavigationPaletteSelection();
        }
        return result;
    }
    case WM_KILLFOCUS:
        if (window) {
            window->hideNavigationPalette(false);
        }
        break;
    case WM_NCDESTROY:
        if (window && window->navigationPalette_ == hwnd && window->navigationPaletteProc_) {
            ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(window->navigationPaletteProc_));
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            originalProc = window->navigationPaletteProc_;
            window->navigationPaletteProc_ = nullptr;
            window->navigationPalette_ = nullptr;
        }
        break;
    default:
        break;
    }
    return originalProc ? ::CallWindowProcW(originalProc, hwnd, msg, wParam, lParam) : ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        if (!driverLease_.acquire()) {
            ::OutputDebugStringW(L"[KswordARKLight] Driver lease registration unavailable; automatic driver stop is disabled for safety.\r\n");
        }
        createMenuBar();
        createCommandInput();
        createChildControls();
        createModuleDocks();
        refreshPrivilegeText();
        refreshDriverText(driverStatus_);
        enableStartupPrivileges();
        refreshPrivilegeText();
        ::PostMessageW(hwnd_, kMsgQueryDriverStatus, 0, 0);
        layout();
        return 0;
    case kMsgQueryDriverStatus:
        queryDriverStatusDeferred();
        return 0;
    case kMsgDockActivated:
        queueDockMaterialization(static_cast<int>(wParam));
        return 0;
    case kMsgMaterializeDock:
        materializeDockForDockIndex(static_cast<int>(wParam));
        return 0;
    case Ksword::Ui::kEntityNavigationMessage:
        if (lParam != 0) {
            return routeNavigation(*reinterpret_cast<const Ksword::Core::NavigationRequest*>(lParam)) ? 1 : 0;
        }
        return 0;
    case WM_SIZE:
        if (wParam == SIZE_MAXIMIZED) {
            wasMaximized_ = true;
        } else if (wParam == SIZE_RESTORED) {
            wasMaximized_ = false;
            captureNormalWindowRect();
        }
        positionCommandInput();
        layout();
        return 0;
    case WM_MOVE:
        captureNormalWindowRect();
        positionCommandInput();
        return 0;
    case WM_SETTINGCHANGE:
        Ksword::Ui::RefreshSystemUIFont();
        Ksword::Ui::SetWindowFontRecursive(hwnd_);
        if (navigationPalette_) {
            ::SendMessageW(navigationPalette_, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
            ::InvalidateRect(navigationPalette_, nullptr, TRUE);
        }
        refreshTopmostMenuText();
        positionCommandInput();
        layout();
        ::InvalidateRect(hwnd_, nullptr, TRUE);
        return 0;
    case WM_COMMAND: {
        const int id = LOWORD(wParam);
        if (id >= kWindowMenuDockBaseId && id < kWindowMenuDockBaseId + static_cast<int>(modules_.size())) {
            toggleModuleDock(id - kWindowMenuDockBaseId);
            return 0;
        }
        if (id == kTopmostMenuId) {
            toggleTopmost();
            return 0;
        }
        if (id == kPrivilegeMenuId) {
            handleUiAccessButtonClicked();
            return 0;
        }
        if (id == kDriverMenuId) {
            installDriverFromButton();
            return 0;
        }
        if (id == kNavigationPaletteMenuId) {
            showNavigationPalette();
            return 0;
        }
        if (id == kEvidenceInspectorMenuId) {
            if (!Ksword::Ui::ShowEvidenceSessionInspector(hwnd_) && statusText_) {
                ::SetWindowTextW(statusText_, L"证据会话检查器无法创建。");
            }
            return 0;
        }
        if (id >= kEvidenceJsonPrivacyMenuId && id <= kEvidenceClearMenuId) {
            exportEvidence(id);
            return 0;
        }
        break;
    }
    case WM_INITMENU:
        if (reinterpret_cast<HMENU>(wParam) == mainMenu_) {
            refreshTopmostMenuText();
            positionCommandInput();
            return 0;
        }
        break;
    case WM_INITMENUPOPUP:
        if (reinterpret_cast<HMENU>(wParam) == windowMenu_) {
            rebuildWindowMenuChecks();
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    case WM_CTLCOLORLISTBOX:
        if (reinterpret_cast<HWND>(lParam) == navigationPalette_) {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, OPAQUE);
            ::SetBkColor(dc, Ksword::Ui::AppTheme().panelColor);
            ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
            return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().panelBrush());
        }
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        paint(dc);
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        persistWorkspaceState();
        stopDriverOnExit();
        if (navigationPalette_) {
            ::DestroyWindow(navigationPalette_);
            navigationPalette_ = nullptr;
        }
        if (commandEdit_) {
            ::DestroyWindow(commandEdit_);
            commandEdit_ = nullptr;
        }
        ::PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void MainWindow::createMenuBar() {
    modules_ = Ksword::Features::GetModuleDescriptors();
    mainMenu_ = ::CreateMenu();
    windowMenu_ = ::CreatePopupMenu();
    evidenceMenu_ = ::CreatePopupMenu();
    if (!mainMenu_ || !windowMenu_ || !evidenceMenu_) {
        return;
    }

    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        ::AppendMenuW(windowMenu_, MF_STRING | MF_CHECKED, kWindowMenuDockBaseId + index, modules_[index].title.c_str());
    }
    ::AppendMenuW(mainMenu_, MF_POPUP, reinterpret_cast<UINT_PTR>(windowMenu_), L"窗口");
    ::AppendMenuW(mainMenu_, MF_STRING, kNavigationPaletteMenuId, L"导航");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceInspectorMenuId, L"查看证据会话...");
    ::AppendMenuW(evidenceMenu_, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceJsonPrivacyMenuId, L"导出 JSON（隐私脱敏）...");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceJsonRawMenuId, L"导出 JSON（完整）...");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceTsvPrivacyMenuId, L"导出 TSV（隐私脱敏）...");
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceDiffMenuId, L"导出最近两次差异...");
    ::AppendMenuW(evidenceMenu_, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(evidenceMenu_, MF_STRING, kEvidenceClearMenuId, L"清空证据会话");
    ::AppendMenuW(mainMenu_, MF_POPUP, reinterpret_cast<UINT_PTR>(evidenceMenu_), L"证据");
    MENUITEMINFOW topmostItem{};
    topmostItem.cbSize = sizeof(topmostItem);
    topmostItem.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING;
    topmostItem.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
    topmostItem.wID = kTopmostMenuId;
    topmostItem.dwTypeData = const_cast<LPWSTR>(L"置顶");
    ::InsertMenuItemW(mainMenu_, ::GetMenuItemCount(mainMenu_), TRUE, &topmostItem);
    ::AppendMenuW(mainMenu_, MF_STRING, kPrivilegeMenuId, L"UIAccess");
    ::AppendMenuW(mainMenu_, MF_STRING, kDriverMenuId, L"R0");
    ::SetMenu(hwnd_, mainMenu_);
    refreshTopmostMenuText();
    ::DrawMenuBar(hwnd_);
}

void MainWindow::createCommandInput() {
    // The native menu bar is not a child-window container. Use an owned popup
    // edit instead so the command box can sit visually on the menu row without
    // replacing the existing HMENU-based shell.
    commandEdit_ = ::CreateWindowExW(WS_EX_TOOLWINDOW, L"EDIT", L"",
        WS_POPUP | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        0, 0, kCommandEditWidth, kCommandEditHeight,
        hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kCommandEditId)), instance_, nullptr);
    if (!commandEdit_) {
        return;
    }

    ::SendMessageW(commandEdit_, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ::SendMessageW(commandEdit_, EM_SETCUEBANNER, FALSE,
        reinterpret_cast<LPARAM>(L"模块 / pid 1234 / !命令"));
    ::SetWindowLongPtrW(commandEdit_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    commandEditProc_ = reinterpret_cast<WNDPROC>(
        ::SetWindowLongPtrW(commandEdit_, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&MainWindow::CommandEditProc)));
    positionCommandInput();
}

void MainWindow::rebuildNavigationPalette() {
    navigationPaletteEntries_.clear();
    navigationPaletteEntries_.reserve(modules_.size() + 9U);
    for (int moduleIndex = 0; moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        const Ksword::Ui::ModuleDescriptor& module = modules_[moduleIndex];
        NavigationPaletteEntry entry;
        entry.action = NavigationPaletteAction::Module;
        entry.moduleIndex = moduleIndex;
        entry.displayText = L"模块： " + module.title + L"  —  " + module.summary;
        navigationPaletteEntries_.push_back(std::move(entry));
    }

    const struct TemplateDescriptor {
        const wchar_t* command;
        const wchar_t* description;
    } templates[] = {
        { L"pid <PID>", L"打开当前进程详细信息" },
        { L"tid <TID>", L"按线程 ID 打开所属进程详细信息" },
        { L"mem <PID>", L"定位到该进程的内存操作" },
        { L"hwnd <HWND>", L"在窗口模块查询窗口句柄" },
        { L"net <PID>", L"筛选该进程的网络连接" },
        { L"handle <PID>", L"筛选该进程的句柄表" },
        { L"etw <PID>", L"定位到该进程的 ETW 监控" },
        { L"file <路径>", L"在文件模块导航到路径" },
        { L"reg <注册表路径>", L"在注册表模块导航到键" },
    };
    for (const TemplateDescriptor& descriptor : templates) {
        NavigationPaletteEntry entry;
        entry.action = NavigationPaletteAction::Template;
        entry.commandTemplate = descriptor.command;
        entry.displayText = L"命令模板： " + entry.commandTemplate + L"  —  " + descriptor.description;
        navigationPaletteEntries_.push_back(std::move(entry));
    }

    if (!navigationPalette_ || !::IsWindow(navigationPalette_)) {
        return;
    }
    ::SendMessageW(navigationPalette_, LB_RESETCONTENT, 0, 0);
    for (std::size_t index = 0; index < navigationPaletteEntries_.size(); ++index) {
        const LRESULT listIndex = ::SendMessageW(navigationPalette_, LB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(navigationPaletteEntries_[index].displayText.c_str()));
        if (listIndex != LB_ERR && listIndex != LB_ERRSPACE) {
            ::SendMessageW(navigationPalette_, LB_SETITEMDATA, static_cast<WPARAM>(listIndex),
                static_cast<LPARAM>(index));
        }
    }
}

void MainWindow::showNavigationPalette() {
    if (!hwnd_) {
        return;
    }
    if (!navigationPalette_ || !::IsWindow(navigationPalette_)) {
        HWND palette = ::CreateWindowExW(WS_EX_TOOLWINDOW, WC_LISTBOXW, L"",
            WS_POPUP | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            0, 0, kNavigationPaletteWidth, kNavigationPaletteHeight,
            hwnd_, nullptr, instance_, nullptr);
        if (!palette) {
            if (statusText_) {
                ::SetWindowTextW(statusText_, L"导航面板无法创建。");
            }
            return;
        }
        navigationPalette_ = palette;
        ::SendMessageW(navigationPalette_, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
        ::SetWindowLongPtrW(navigationPalette_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        navigationPaletteProc_ = reinterpret_cast<WNDPROC>(
            ::SetWindowLongPtrW(navigationPalette_, GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(&MainWindow::NavigationPaletteProc)));
    }

    rebuildNavigationPalette();
    if (navigationPaletteEntries_.empty()) {
        return;
    }
    ::SendMessageW(navigationPalette_, LB_SETCURSEL, 0, 0);

    RECT anchor{};
    if (!commandEdit_ || !::GetWindowRect(commandEdit_, &anchor)) {
        ::GetWindowRect(hwnd_, &anchor);
    }
    HMONITOR monitor = ::MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!::GetMonitorInfoW(monitor, &monitorInfo)) {
        ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &monitorInfo.rcWork, 0);
    }
    const RECT work = monitorInfo.rcWork;
    const int workLeft = static_cast<int>(work.left);
    const int workTop = static_cast<int>(work.top);
    const int workRight = static_cast<int>(work.right);
    const int workBottom = static_cast<int>(work.bottom);
    const int width = (std::min)(kNavigationPaletteWidth, (std::max)(1, workRight - workLeft - 16));
    const int height = (std::min)(kNavigationPaletteHeight, (std::max)(1, workBottom - workTop - 16));
    int x = static_cast<int>(anchor.left);
    int y = static_cast<int>(anchor.bottom) + 3;
    if (x + width > workRight) {
        x = workRight - width;
    }
    if (x < workLeft) {
        x = workLeft;
    }
    if (y + height > workBottom) {
        y = (std::max)(workTop, static_cast<int>(anchor.top) - height - 3);
    }
    ::SetWindowPos(navigationPalette_, HWND_TOP, x, y, width, height, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    ::SetFocus(navigationPalette_);
}

void MainWindow::hideNavigationPalette(const bool focusCommandInput) {
    if (navigationPalette_ && ::IsWindow(navigationPalette_)) {
        ::ShowWindow(navigationPalette_, SW_HIDE);
    }
    if (focusCommandInput && commandEdit_ && ::IsWindow(commandEdit_)) {
        positionCommandInput();
        ::SetFocus(commandEdit_);
    }
}

void MainWindow::activateNavigationPaletteSelection() {
    if (!navigationPalette_ || !::IsWindow(navigationPalette_)) {
        return;
    }
    const LRESULT selected = ::SendMessageW(navigationPalette_, LB_GETCURSEL, 0, 0);
    if (selected == LB_ERR) {
        return;
    }
    const LRESULT entryIndex = ::SendMessageW(navigationPalette_, LB_GETITEMDATA,
        static_cast<WPARAM>(selected), 0);
    if (entryIndex == LB_ERR || entryIndex < 0 ||
        static_cast<std::size_t>(entryIndex) >= navigationPaletteEntries_.size()) {
        return;
    }
    const NavigationPaletteEntry entry = navigationPaletteEntries_[static_cast<std::size_t>(entryIndex)];
    hideNavigationPalette(false);

    if (entry.action == NavigationPaletteAction::Module) {
        if (entry.moduleIndex < 0 || entry.moduleIndex >= static_cast<int>(modules_.size())) {
            return;
        }
        Ksword::Core::NavigationRequest request{};
        request.target = Ksword::Core::NavigationTarget::Default;
        request.entity.kind = Ksword::Core::EntityKind::Module;
        request.entity.text = modules_[entry.moduleIndex].title;
        if (!routeNavigation(request) && statusText_) {
            ::SetWindowTextW(statusText_, L"导航面板无法打开所选模块。");
        }
        return;
    }

    if (!commandEdit_ || !::IsWindow(commandEdit_)) {
        return;
    }
    ::SetWindowTextW(commandEdit_, entry.commandTemplate.c_str());
    positionCommandInput();
    ::SetFocus(commandEdit_);
    const std::size_t placeholderBegin = entry.commandTemplate.find(L'<');
    const std::size_t placeholderEnd = entry.commandTemplate.find(L'>', placeholderBegin);
    if (placeholderBegin != std::wstring::npos && placeholderEnd != std::wstring::npos &&
        placeholderEnd >= placeholderBegin) {
        ::SendMessageW(commandEdit_, EM_SETSEL, static_cast<WPARAM>(placeholderBegin),
            static_cast<LPARAM>(placeholderEnd + 1U));
        ::SendMessageW(commandEdit_, EM_SCROLLCARET, 0, 0);
    }
    if (statusText_) {
        ::SetWindowTextW(statusText_, L"已填入导航模板；替换尖括号中的参数后按 Enter。");
    }
}

void MainWindow::createChildControls() {
    statusText_ = Ksword::Ui::CreateText(hwnd_, kStatusTextId, L"Ready", 0, 0, 900, kStatusHeight);

    RECT dockBounds{ 0, 0, 900, 700 };
    dockManager_->create(hwnd_, dockBounds);
    dockManager_->setActivationChangedMessage(kMsgDockActivated);
}

void MainWindow::createModuleDocks() {
    if (modules_.empty()) {
        modules_ = Ksword::Features::GetModuleDescriptors();
    }
    dockSlots_.clear();
    dockSlots_.resize(modules_.size());
    pendingNavigation_.clear();
    pendingNavigation_.resize(modules_.size());
    RECT pageBounds{ 0, 0, 600, 400 };
    for (int moduleIndex = 0; moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        const auto& module = modules_[moduleIndex];
        HWND page = createModulePlaceholderPage(module, pageBounds);
        const int index = dockManager_->addDock(Ksword::Docking::DockPosition::Center, module.title, page);
        dockSlots_[moduleIndex].dockIndex = index;
        dockSlots_[moduleIndex].page = page;
        dockSlots_[moduleIndex].materialized = false;
        dockSlots_[moduleIndex].materializing = false;
    }
    if (!dockSlots_.empty()) {
        int initialModuleIndex = moduleIndexForCommandId(restoredModuleCommandId_);
        if (initialModuleIndex < 0) {
            initialModuleIndex = 0;
        }
        dockManager_->activateDock(dockSlots_[initialModuleIndex].dockIndex);
    }
    rebuildWindowMenuChecks();
}

void MainWindow::captureNormalWindowRect() {
    if (!hwnd_ || ::IsIconic(hwnd_) || ::IsZoomed(hwnd_)) {
        return;
    }
    RECT rect{};
    if (::GetWindowRect(hwnd_, &rect) && rect.right > rect.left && rect.bottom > rect.top) {
        lastNormalScreenRect_ = rect;
        hasLastNormalScreenRect_ = true;
    }
}

int MainWindow::activeModuleCommandId() const {
    if (!dockManager_) {
        return 0;
    }
    const int activeDockIndex = dockManager_->activeDockIndex();
    for (int moduleIndex = 0; moduleIndex < static_cast<int>(dockSlots_.size()) && moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        if (dockSlots_[moduleIndex].dockIndex == activeDockIndex) {
            return modules_[moduleIndex].commandId;
        }
    }
    return 0;
}

void MainWindow::persistWorkspaceState() {
    Ksword::Core::WorkspaceConfig config{};
    config.maximized = wasMaximized_;
    config.activeCommandId = activeModuleCommandId();
    if (hasLastNormalScreenRect_ && lastNormalScreenRect_.right > lastNormalScreenRect_.left &&
        lastNormalScreenRect_.bottom > lastNormalScreenRect_.top) {
        config.hasNormalRect = true;
        config.normalRect = {
            static_cast<std::int32_t>(lastNormalScreenRect_.left),
            static_cast<std::int32_t>(lastNormalScreenRect_.top),
            static_cast<std::int32_t>(lastNormalScreenRect_.right),
            static_cast<std::int32_t>(lastNormalScreenRect_.bottom)
        };
    }
    StoreWorkspaceConfig(config);
}

HWND MainWindow::createModulePlaceholderPage(const Ksword::Ui::ModuleDescriptor& module, const RECT& bounds) const {
    // This intentionally avoids module.createPage so startup only creates cheap
    // Win32 placeholders and dock labels. The real module page is built by
    // materializeDockForDockIndex after the shell is already visible.
    return Ksword::Ui::CreatePlaceholderPage(dockManager_->hwnd(), module, bounds);
}

HWND MainWindow::createModulePage(const Ksword::Ui::ModuleDescriptor& module, const RECT& bounds) const {
    // Input is one registry descriptor plus initial dock bounds. Processing uses
    // the module's factory when present, then falls back to a simple page so a
    // failed module cannot break the whole shell. Return value is a child HWND.
    HWND page = nullptr;
    if (module.createPage) {
        page = module.createPage(dockManager_->hwnd(), bounds);
    }
    if (!page) {
        page = Ksword::Ui::CreatePlaceholderPage(dockManager_->hwnd(), module, bounds);
    }
    return page;
}

void MainWindow::queueDockMaterialization(const int dockIndex) {
    if (!dockManager_ || dockIndex < 0) {
        return;
    }

    for (int moduleIndex = 0; moduleIndex < static_cast<int>(dockSlots_.size()); ++moduleIndex) {
        DockSlot& slot = dockSlots_[moduleIndex];
        if (slot.dockIndex != dockIndex || slot.materialized || slot.materializing) {
            continue;
        }
        slot.materializing = true;
        const std::wstring status = L"准备加载“" + modules_[moduleIndex].title + L"”页面…";
        Ksword::Ui::SetPlaceholderPageProgress(slot.page, status, 8);
        if (statusText_) {
            ::SetWindowTextW(statusText_, status.c_str());
        }
        ::PostMessageW(hwnd_, kMsgMaterializeDock, static_cast<WPARAM>(dockIndex), 0);
        return;
    }
}

void MainWindow::materializeDockForDockIndex(const int dockIndex) {
    if (!dockManager_ || dockIndex < 0) {
        return;
    }

    for (int moduleIndex = 0; moduleIndex < static_cast<int>(dockSlots_.size()); ++moduleIndex) {
        DockSlot& slot = dockSlots_[moduleIndex];
        if (slot.dockIndex != dockIndex || slot.materialized || !slot.materializing) {
            continue;
        }

        RECT pageBounds{ 0, 0, 600, 400 };
        if (slot.page) {
            RECT existing{};
            ::GetWindowRect(slot.page, &existing);
            POINT topLeft{ existing.left, existing.top };
            POINT bottomRight{ existing.right, existing.bottom };
            ::ScreenToClient(dockManager_->hwnd(), &topLeft);
            ::ScreenToClient(dockManager_->hwnd(), &bottomRight);
            pageBounds = { topLeft.x, topLeft.y, bottomRight.x, bottomRight.y };
        }

        // This is the frame the user actually stares at: the module factory on
        // the next line owns the UI thread until it returns, so the bar stands
        // still at this value for the whole construction. That is the honest
        // picture and it is left alone -- a fake animation here would only hide
        // which page is slow to build.
        Ksword::Ui::SetPlaceholderPageProgress(
            slot.page,
            L"正在创建“" + modules_[moduleIndex].title + L"”页面内容…",
            30);

        HWND realPage = createModulePage(modules_[moduleIndex], pageBounds);
        if (!realPage) {
            slot.materializing = false;
            Ksword::Ui::SetPlaceholderPageLoading(slot.page, false, L"页面创建失败，切换到此页面可重试。" );
            return;
        }

        // Last refresh the placeholder ever gets: mounting the real content
        // takes this HWND out of the dock, so a 100% frame would never be seen.
        Ksword::Ui::SetPlaceholderPageProgress(
            slot.page,
            L"正在挂载“" + modules_[moduleIndex].title + L"”页面…",
            80);

        HWND oldPage = slot.page;
        if (dockManager_->replaceDockContent(slot.dockIndex, realPage, true)) {
            slot.page = realPage;
            slot.materialized = true;
            slot.materializing = false;
            if (statusText_) {
                const std::wstring message = L"已加载模块：" + modules_[moduleIndex].title;
                ::SetWindowTextW(statusText_, message.c_str());
            }
            if (moduleIndex < static_cast<int>(pendingNavigation_.size()) && pendingNavigation_[moduleIndex]) {
                const bool routed = applyNavigationToModule(moduleIndex, *pendingNavigation_[moduleIndex]);
                pendingNavigation_[moduleIndex].reset();
                if (statusText_) {
                    ::SetWindowTextW(statusText_, routed ? L"已完成实体导航。" : L"模块已加载，但无法应用导航目标。");
                }
            }
        } else {
            ::DestroyWindow(realPage);
            slot.page = oldPage;
            slot.materializing = false;
            Ksword::Ui::SetPlaceholderPageLoading(slot.page, false, L"页面替换失败，切换到此页面可重试。" );
        }
        return;
    }
}

void MainWindow::rebuildWindowMenuChecks() {
    if (!windowMenu_) {
        return;
    }
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        const UINT state = moduleDockVisible(index) ? MF_CHECKED : MF_UNCHECKED;
        ::CheckMenuItem(windowMenu_, kWindowMenuDockBaseId + index, MF_BYCOMMAND | state);
    }
    ::DrawMenuBar(hwnd_);
}

bool MainWindow::moduleDockVisible(int moduleIndex) const {
    if (moduleIndex < 0 || moduleIndex >= static_cast<int>(dockSlots_.size())) {
        return false;
    }
    const DockSlot& slot = dockSlots_[moduleIndex];
    return slot.page && slot.dockIndex >= 0 && dockManager_ && dockManager_->dockVisible(slot.dockIndex);
}

bool MainWindow::isTopmost() const {
    if (!hwnd_) {
        return false;
    }
    const LONG_PTR exStyle = ::GetWindowLongPtrW(hwnd_, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOPMOST) != 0;
}

void MainWindow::toggleTopmost() {
    if (!hwnd_) {
        return;
    }
    const bool enableTopmost = !isTopmost();
    const HWND insertAfter = enableTopmost ? HWND_TOPMOST : HWND_NOTOPMOST;
    if (::SetWindowPos(hwnd_, insertAfter, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)) {
        refreshTopmostMenuText();
        if (statusText_) {
            ::SetWindowTextW(statusText_, enableTopmost ? L"Window is topmost." : L"Window is no longer topmost.");
        }
    }
}

void MainWindow::refreshTopmostMenuText() {
    if (!mainMenu_) {
        return;
    }
    const wchar_t* text = isTopmost() ? L"取消置顶" : L"置顶";
    MENUITEMINFOW item{};
    item.cbSize = sizeof(item);
    item.fMask = MIIM_FTYPE | MIIM_STRING;
    item.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
    item.dwTypeData = const_cast<LPWSTR>(text);
    ::SetMenuItemInfoW(mainMenu_, kTopmostMenuId, FALSE, &item);
    ::DrawMenuBar(hwnd_);
    positionCommandInput();
}

void MainWindow::positionCommandInput() {
    if (!hwnd_ || !mainMenu_ || !commandEdit_) {
        return;
    }

    if (::IsIconic(hwnd_)) {
        ::ShowWindow(commandEdit_, SW_HIDE);
        return;
    }

    const int menuCount = ::GetMenuItemCount(mainMenu_);
    int topmostIndex = -1;
    for (int index = 0; index < menuCount; ++index) {
        if (::GetMenuItemID(mainMenu_, index) == kTopmostMenuId) {
            topmostIndex = index;
            break;
        }
    }
    if (topmostIndex < 0) {
        ::ShowWindow(commandEdit_, SW_HIDE);
        return;
    }

    RECT topmostRect{};
    RECT windowRect{};
    if (!::GetMenuItemRect(hwnd_, mainMenu_, topmostIndex, &topmostRect) || !::GetWindowRect(hwnd_, &windowRect)) {
        ::ShowWindow(commandEdit_, SW_HIDE);
        return;
    }

    const int menuHeight = topmostRect.bottom - topmostRect.top;
    const int editHeight = (menuHeight > 6) ? (menuHeight - 4) : kCommandEditHeight;
    int x = topmostRect.left - kCommandEditMenuGap - kCommandEditWidth;
    const int minX = windowRect.left + 160;
    if (x < minX) {
        x = minX;
    }
    const int y = topmostRect.top + ((menuHeight - editHeight) / 2);
    ::SetWindowPos(commandEdit_, HWND_TOP, x, y, kCommandEditWidth, editHeight,
        SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

void MainWindow::enableStartupPrivileges() {
    startupPrivilegeResults_ = Ksword::Core::EnableStartupPrivileges();
    startupPrivilegeSummary_ = Ksword::Core::SummarizePrivilegeEnableResults(startupPrivilegeResults_);
    if (!startupPrivilegeSummary_.empty()) {
        ::OutputDebugStringW((L"[KswordARKLight] " + startupPrivilegeSummary_ + L"\r\n").c_str());
    }

    for (const Ksword::Core::PrivilegeEnableResult& result : startupPrivilegeResults_) {
        if (result.enabled) {
            continue;
        }
        std::wstring line = L"[KswordARKLight] Startup privilege failed: " + result.name +
            L", error=" + std::to_wstring(result.errorCode) + L", " + result.message + L"\r\n";
        ::OutputDebugStringW(line.c_str());
    }

    if (statusText_ && !startupPrivilegeSummary_.empty()) {
        ::SetWindowTextW(statusText_, startupPrivilegeSummary_.c_str());
    }
}

void MainWindow::executeCommandInput() {
    if (!commandEdit_) {
        return;
    }

    const int textLength = ::GetWindowTextLengthW(commandEdit_);
    if (textLength <= 0) {
        return;
    }

    std::vector<wchar_t> textBuffer(static_cast<std::size_t>(textLength) + 1, L'\0');
    ::GetWindowTextW(commandEdit_, textBuffer.data(), static_cast<int>(textBuffer.size()));
    const std::wstring commandText = TrimWhitespace(textBuffer.data());
    if (commandText.empty()) {
        return;
    }

    const Ksword::Core::CommandInputResult parsed = Ksword::Core::ParseCommandInput(commandText);
    if (parsed.kind == Ksword::Core::CommandInputKind::Invalid) {
        if (statusText_) {
            ::SetWindowTextW(statusText_, parsed.error.c_str());
        }
        return;
    }
    if (parsed.kind == Ksword::Core::CommandInputKind::Navigation) {
        const bool routed = routeNavigation(parsed.navigation);
        if (routed) {
            ::SetWindowTextW(commandEdit_, L"");
        } else if (statusText_) {
            ::SetWindowTextW(statusText_, L"没有找到可接收该命令的模块。");
        }
        return;
    }

    std::wstring commandLine = L"cmd.exe /k " + parsed.shellCommand;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL created = ::CreateProcessW(nullptr, commandLine.data(),
        nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        nullptr, nullptr, &startup, &process);
    if (!created) {
        const DWORD error = ::GetLastError();
        if (statusText_) {
            const std::wstring message = L"Command launch failed: " + std::to_wstring(error) +
                L", " + Ksword::Core::LastErrorMessage(error);
            ::SetWindowTextW(statusText_, message.c_str());
        }
        return;
    }

    if (process.hThread) {
        ::CloseHandle(process.hThread);
    }
    if (process.hProcess) {
        ::CloseHandle(process.hProcess);
    }
    ::SetWindowTextW(commandEdit_, L"");
    if (statusText_) {
        ::SetWindowTextW(statusText_, L"Command launched in a new console.");
    }
}

int MainWindow::moduleIndexForCommandId(const int commandId) const {
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        if (modules_[index].commandId == commandId) {
            return index;
        }
    }
    return -1;
}

int MainWindow::moduleIndexForTitle(const std::wstring& query) const {
    const std::wstring loweredQuery = LowerText(TrimWhitespace(query));
    if (loweredQuery.empty()) {
        return -1;
    }
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        if (LowerText(modules_[index].title) == loweredQuery) {
            return index;
        }
    }
    for (int index = 0; index < static_cast<int>(modules_.size()); ++index) {
        const std::wstring title = LowerText(modules_[index].title);
        if (title.find(loweredQuery) != std::wstring::npos || loweredQuery.find(title) != std::wstring::npos) {
            return index;
        }
    }
    return -1;
}

bool MainWindow::activateModule(const int moduleIndex) {
    if (!dockManager_ || moduleIndex < 0 || moduleIndex >= static_cast<int>(modules_.size())) {
        return false;
    }
    if (dockSlots_.size() < modules_.size()) {
        dockSlots_.resize(modules_.size());
    }
    if (pendingNavigation_.size() < modules_.size()) {
        pendingNavigation_.resize(modules_.size());
    }
    DockSlot& slot = dockSlots_[moduleIndex];
    if (!moduleDockVisible(moduleIndex)) {
        RECT pageBounds{ 0, 0, 600, 400 };
        slot.page = createModulePlaceholderPage(modules_[moduleIndex], pageBounds);
        slot.dockIndex = dockManager_->addDock(
            Ksword::Docking::DockPosition::Center, modules_[moduleIndex].title, slot.page);
        slot.materialized = false;
        slot.materializing = false;
        rebuildWindowMenuChecks();
    }
    if (slot.dockIndex < 0) {
        return false;
    }
    dockManager_->activateDock(slot.dockIndex);
    if (!slot.materialized) {
        queueDockMaterialization(slot.dockIndex);
    }
    return true;
}

bool MainWindow::routeNavigation(const Ksword::Core::NavigationRequest& request) {
    int commandId = 0;
    switch (request.target) {
    case Ksword::Core::NavigationTarget::Default:
        if (request.entity.kind == Ksword::Core::EntityKind::Module) {
            const int moduleIndex = moduleIndexForTitle(request.entity.text);
            if (moduleIndex < 0) {
                return false;
            }
            const bool activated = activateModule(moduleIndex);
            if (activated && statusText_) {
                ::SetWindowTextW(statusText_, (L"已切换到模块：" + modules_[moduleIndex].title).c_str());
            }
            return activated;
        }
        return false;
    case Ksword::Core::NavigationTarget::ProcessDetails: commandId = kProcessModuleCommandId; break;
    case Ksword::Core::NavigationTarget::MemoryOperations: commandId = kMemoryModuleCommandId; break;
    case Ksword::Core::NavigationTarget::FileBrowser: commandId = kFileModuleCommandId; break;
    case Ksword::Core::NavigationTarget::RegistryBrowser: commandId = kRegistryModuleCommandId; break;
    case Ksword::Core::NavigationTarget::NetworkConnections: commandId = kNetworkModuleCommandId; break;
    case Ksword::Core::NavigationTarget::HandleTable: commandId = kHandleModuleCommandId; break;
    case Ksword::Core::NavigationTarget::WindowManager: commandId = kWindowModuleCommandId; break;
    case Ksword::Core::NavigationTarget::EtwMonitor: commandId = kMonitorModuleCommandId; break;
    }
    const int moduleIndex = moduleIndexForCommandId(commandId);
    if (moduleIndex < 0) {
        return false;
    }
    if (pendingNavigation_.size() < modules_.size()) {
        pendingNavigation_.resize(modules_.size());
    }
    pendingNavigation_[moduleIndex] = request;
    if (!activateModule(moduleIndex)) {
        pendingNavigation_[moduleIndex].reset();
        return false;
    }
    DockSlot& slot = dockSlots_[moduleIndex];
    if (!slot.materialized) {
        if (statusText_) {
            ::SetWindowTextW(statusText_, (L"正在加载并导航到“" + modules_[moduleIndex].title + L"”…").c_str());
        }
        return true;
    }
    const bool routed = applyNavigationToModule(moduleIndex, request);
    pendingNavigation_[moduleIndex].reset();
    return routed;
}

bool MainWindow::applyNavigationToModule(
    const int moduleIndex,
    const Ksword::Core::NavigationRequest& request) {
    if (moduleIndex < 0 || moduleIndex >= static_cast<int>(dockSlots_.size()) || !dockSlots_[moduleIndex].page) {
        return false;
    }
    HWND page = dockSlots_[moduleIndex].page;
    switch (request.target) {
    case Ksword::Core::NavigationTarget::ProcessDetails: {
        DWORD processId = static_cast<DWORD>(request.entity.id);
        if (request.entity.kind == Ksword::Core::EntityKind::Thread) {
            processId = ProcessIdForThread(processId);
        }
        return processId != 0 && Ksword::Features::Process::RequestProcessFeatureOpenDetails(
            page, processId, request.entity.creationTime100ns);
    }
    case Ksword::Core::NavigationTarget::MemoryOperations:
        return request.entity.kind == Ksword::Core::EntityKind::Process && request.entity.id != 0U &&
            request.entity.id <= static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)()) &&
            Ksword::Features::Memory::RequestMemoryFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case Ksword::Core::NavigationTarget::FileBrowser:
        return Ksword::Features::File::RequestFileFeatureNavigate(page, request.entity.text);
    case Ksword::Core::NavigationTarget::RegistryBrowser:
        return Ksword::Features::Registry::RequestRegistryFeatureNavigate(page, request.entity.text);
    case Ksword::Core::NavigationTarget::NetworkConnections:
        return Ksword::Features::Network::RequestNetworkFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case Ksword::Core::NavigationTarget::HandleTable:
        return Ksword::Features::Handle::RequestHandleFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case Ksword::Core::NavigationTarget::WindowManager:
        return Ksword::Features::Window::RequestWindowFeatureQuery(
            page,
            request.entity.kind == Ksword::Core::EntityKind::Window
                ? HexIdentifier(request.entity.id)
                : std::to_wstring(request.entity.id));
    case Ksword::Core::NavigationTarget::EtwMonitor:
        return Ksword::Features::Monitor::RequestMonitorFeatureProcess(page, static_cast<DWORD>(request.entity.id));
    case Ksword::Core::NavigationTarget::Default:
        return true;
    }
    return false;
}

void MainWindow::exportEvidence(const int commandId) {
    Ksword::Ui::EvidenceSession& session = Ksword::Ui::GlobalEvidenceSession();
    if (commandId == kEvidenceClearMenuId) {
        session.clear();
        if (statusText_) {
            ::SetWindowTextW(statusText_, L"证据会话已清空。");
        }
        return;
    }
    if (session.size() == 0U) {
        if (statusText_) {
            ::SetWindowTextW(statusText_, L"证据会话为空；复制或导出模块结果后再试。");
        }
        return;
    }

    std::wstring text;
    const wchar_t* name = L"ksword-arklight-evidence.json";
    const wchar_t* title = L"导出证据会话";
    const wchar_t* filter = L"JSON (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    const wchar_t* extension = L"json";
    if (commandId == kEvidenceTsvPrivacyMenuId) {
        text = session.exportTsv(Ksword::Ui::EvidenceRedaction::Privacy);
        name = L"ksword-arklight-evidence.tsv";
        filter = L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0";
        extension = L"tsv";
    } else if (commandId == kEvidenceDiffMenuId) {
        if (session.size() < 2U) {
            if (statusText_) {
                ::SetWindowTextW(statusText_, L"至少需要两次证据采集才能生成差异。");
            }
            return;
        }
        text = Ksword::Ui::RenderEvidenceDiff(session.latestDiff());
        name = L"ksword-arklight-evidence-diff.txt";
        filter = L"Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
        extension = L"txt";
    } else {
        text = session.exportJson(commandId == kEvidenceJsonRawMenuId
            ? Ksword::Ui::EvidenceRedaction::None
            : Ksword::Ui::EvidenceRedaction::Privacy);
    }
    std::wstring error;
    const Ksword::Ui::SaveTextFileResult result = Ksword::Ui::SaveUtf8TextFileWithDialog(
        hwnd_, name, title, filter, extension, text, &error);
    if (statusText_) {
        if (result == Ksword::Ui::SaveTextFileResult::Saved) {
            ::SetWindowTextW(statusText_, L"证据会话已导出。");
        } else if (result == Ksword::Ui::SaveTextFileResult::Failed) {
            ::SetWindowTextW(statusText_, error.c_str());
        }
    }
}

void MainWindow::toggleModuleDock(int moduleIndex) {
    if (moduleIndex < 0 || moduleIndex >= static_cast<int>(modules_.size()) || !dockManager_) {
        return;
    }
    if (dockSlots_.size() < modules_.size()) {
        dockSlots_.resize(modules_.size());
    }

    DockSlot& slot = dockSlots_[moduleIndex];
    if (moduleDockVisible(moduleIndex)) {
        dockManager_->closeDock(slot.dockIndex);
        if (slot.page) {
            ::DestroyWindow(slot.page);
        }
        slot.page = nullptr;
        slot.dockIndex = -1;
        slot.materialized = false;
        slot.materializing = false;
        if (moduleIndex < static_cast<int>(pendingNavigation_.size())) {
            pendingNavigation_[moduleIndex].reset();
        }
        rebuildWindowMenuChecks();
        layout();
        return;
    }

    RECT pageBounds{ 0, 0, 600, 400 };
    slot.page = createModulePlaceholderPage(modules_[moduleIndex], pageBounds);
    slot.dockIndex = dockManager_->addDock(Ksword::Docking::DockPosition::Center, modules_[moduleIndex].title, slot.page);
    slot.materialized = false;
    slot.materializing = false;
    dockManager_->activateDock(slot.dockIndex);
    rebuildWindowMenuChecks();
    layout();
}

void MainWindow::layout() {
    if (!hwnd_) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int width = rc.right - rc.left;
    const int height = rc.bottom - rc.top;

    ::MoveWindow(statusText_, 0, height - kStatusHeight, width, kStatusHeight, TRUE);

    RECT dockBounds{
        0,
        0,
        width,
        height - kStatusHeight
    };
    dockManager_->layout(dockBounds);
    if (dockManager_->hwnd()) {
        ::ShowWindow(dockManager_->hwnd(), SW_SHOW);
        ::InvalidateRect(dockManager_->hwnd(), nullptr, TRUE);
    }
}

void MainWindow::refreshPrivilegeText() {
    if (!mainMenu_) {
        return;
    }
    std::wstring text = L"UIAccess";
    if (!startupPrivilegeResults_.empty()) {
        int enabledCount = 0;
        for (const Ksword::Core::PrivilegeEnableResult& result : startupPrivilegeResults_) {
            if (result.enabled) {
                ++enabledCount;
            }
        }
        text += L" 权限 " + std::to_wstring(enabledCount) + L"/" +
            std::to_wstring(startupPrivilegeResults_.size());
    }
    ::ModifyMenuW(mainMenu_, kPrivilegeMenuId, MF_BYCOMMAND | MF_STRING, kPrivilegeMenuId, text.c_str());
    ::DrawMenuBar(hwnd_);
    positionCommandInput();
}

void MainWindow::refreshDriverText(const Ksword::Core::DriverRuntimeStatus& status) {
    if (mainMenu_) {
        const wchar_t* text = status.serviceRunning || status.controlDeviceOpen ? L"卸载驱动" : L"装载驱动";
        ::ModifyMenuW(mainMenu_, kDriverMenuId, MF_BYCOMMAND | MF_STRING, kDriverMenuId, text);
        ::DrawMenuBar(hwnd_);
        positionCommandInput();
    }
    if (statusText_ && !status.message.empty()) {
        ::SetWindowTextW(statusText_, status.message.c_str());
    } else if (statusText_ && !driverStatusKnown_) {
        ::SetWindowTextW(statusText_, L"R0 driver status will be queried after startup.");
    }
}

void MainWindow::queryDriverStatusDeferred() {
    driverStatus_ = Ksword::Core::QueryDriverStatus();
    driverStatusKnown_ = true;
    refreshDriverText(driverStatus_);
    if (driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen) {
        requestProcessDockRefreshIfLoaded();
    }
}

void MainWindow::requestProcessDockRefreshIfLoaded() {
    if (dockSlots_.empty() || modules_.empty()) {
        return;
    }

    for (int moduleIndex = 0; moduleIndex < static_cast<int>(modules_.size()); ++moduleIndex) {
        if (modules_[moduleIndex].commandId != kProcessModuleCommandId) {
            continue;
        }
        if (moduleIndex >= static_cast<int>(dockSlots_.size())) {
            return;
        }

        const DockSlot& slot = dockSlots_[moduleIndex];
        if (!slot.materialized || !slot.page) {
            return;
        }

        // slot.page 用途：已物化的进程页 HWND；驱动装载后立即触发一次默认 R0 查隐藏刷新。
        Ksword::Features::Process::RequestProcessFeatureRefresh(slot.page);
        return;
    }
}

void MainWindow::handleUiAccessButtonClicked() {
    if (Ksword::Core::IsUiAccessEnabled()) {
        ::SetWindowTextW(statusText_, L"UIAccess is already enabled.");
        return;
    }

    if (!Ksword::Core::IsRunningAsAdmin()) {
        ::SetWindowTextW(statusText_, L"UIAccess needs Admin first; requesting elevation.");
        if (Ksword::Core::RelaunchElevated()) {
            ::PostMessageW(hwnd_, WM_CLOSE, 0, 0);
        } else {
            ::MessageBoxW(hwnd_, L"Admin elevation launch failed or was canceled.", L"UIAccess", MB_ICONWARNING | MB_OK);
        }
        return;
    }

    std::wstring detail;
    if (!Ksword::Core::LaunchSelfWithSystemUiAccessToken(&detail)) {
        ::MessageBoxW(hwnd_, detail.c_str(), L"UIAccess fallback failed", MB_ICONWARNING | MB_OK);
        refreshPrivilegeText();
        return;
    }

    ::SetWindowTextW(statusText_, L"UIAccess instance started; exiting current process.");
    ::PostMessageW(hwnd_, WM_CLOSE, 0, 0);
}

void MainWindow::installDriverFromButton() {
    Ksword::Core::DriverRuntimeStatus current = driverStatusKnown_ ? driverStatus_ : Ksword::Core::QueryDriverStatus();
    driverStatusKnown_ = true;
    driverStatus_ = current;
    if (current.serviceRunning || current.controlDeviceOpen) {
        driverStatus_ = Ksword::Core::StopDriverService();
        if (!driverStatus_.serviceRunning && !driverStatus_.controlDeviceOpen) {
            driverLease_.observeExplicitStop();
        }
        refreshDriverText(driverStatus_);
        if (driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen) {
            ::MessageBoxW(hwnd_, driverStatus_.message.c_str(), L"KswordARKLight R0 Driver", MB_ICONWARNING | MB_OK);
        }
        return;
    }

    driverStatus_ = Ksword::Core::InstallAndStartDriver();
    driverLease_.observeStartTransition(
        current.serviceRunning || current.controlDeviceOpen,
        driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen);
    refreshDriverText(driverStatus_);
    if (driverStatus_.serviceRunning || driverStatus_.controlDeviceOpen) {
        requestProcessDockRefreshIfLoaded();
    }
    if (!driverStatus_.serviceRunning && !driverStatus_.controlDeviceOpen) {
        ::MessageBoxW(hwnd_, driverStatus_.message.c_str(), L"KswordARKLight R0 Driver", MB_ICONWARNING | MB_OK);
    }
}

void MainWindow::stopDriverOnExit() {
    if (!driverLease_.releaseRequestsStop()) {
        ::OutputDebugStringW(L"[KswordARKLight] Driver remains running: it was pre-existing or another Light lease is active.\r\n");
        return;
    }
    const Ksword::Core::DriverRuntimeStatus current = Ksword::Core::QueryDriverStatus();
    if (!current.serviceRunning && !current.controlDeviceOpen) {
        return;
    }

    driverStatus_ = Ksword::Core::StopDriverService();
    driverStatusKnown_ = true;
    ::OutputDebugStringW((L"[KswordARKLight] Exit driver stop: " + driverStatus_.message + L"\r\n").c_str());
}

void MainWindow::paint(HDC dc) {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    ::FillRect(dc, &rc, Ksword::Ui::AppTheme().windowBrush());

    HPEN border = ::CreatePen(PS_SOLID, 1, Ksword::Ui::AppTheme().borderColor);
    HGDIOBJ oldPen = ::SelectObject(dc, border);
    ::MoveToEx(dc, 0, rc.bottom - kStatusHeight, nullptr);
    ::LineTo(dc, rc.right, rc.bottom - kStatusHeight);
    ::SelectObject(dc, oldPen);
    ::DeleteObject(border);
}

} // namespace Ksword::App
