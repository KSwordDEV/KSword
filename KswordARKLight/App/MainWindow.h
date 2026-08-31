#pragma once

#include "../Core/DriverLease.h"
#include "../Core/DriverService.h"
#include "../Core/EntityRef.h"
#include "../Core/Privilege.h"
#include "../Docking/DockManager.h"
#include "../Ui/PlaceholderPage.h"

#include "../Core/Win32Lean.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Ksword::App {

// MainWindow owns the top-level Win32 shell. Inputs are provided through create;
// processing creates toolbar controls and the full-width docking host; run()
// returns the process message-loop exit code.
class MainWindow final {
public:
    MainWindow();
    ~MainWindow();

    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    bool create(HINSTANCE instance, int showCommand);
    int run();

    // WndProc is public only so the Win32 class registration helper can bind it.
    // Inputs are normal Win32 window-procedure values; processing dispatches to
    // the owning MainWindow; output is a Win32 LRESULT.
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
private:
    struct DockSlot {
        int dockIndex = -1;
        HWND page = nullptr;
        bool materialized = false;
        bool materializing = false;
    };

    enum class NavigationPaletteAction {
        Module,
        Template
    };

    struct NavigationPaletteEntry {
        NavigationPaletteAction action = NavigationPaletteAction::Module;
        int moduleIndex = -1;
        std::wstring displayText;
        std::wstring commandTemplate;
    };

    LRESULT handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    // CommandEditProc subclasses the compact command input. Inputs are normal
    // edit-control window-procedure values; processing intercepts Enter and
    // forwards to executeCommandInput; output is a Win32 LRESULT.
    static LRESULT CALLBACK CommandEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    // NavigationPaletteProc subclasses the native list-box popup. Inputs are
    // list-box messages; processing accepts Enter/Escape and activation without
    // materializing or probing any feature module.
    static LRESULT CALLBACK NavigationPaletteProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void createMenuBar();
    void createChildControls();
    // createCommandInput creates the compact owned edit window used for typed
    // navigation and explicit ! shell commands.
    void createCommandInput();
    void showNavigationPalette();
    void hideNavigationPalette(bool focusCommandInput);
    void rebuildNavigationPalette();
    void activateNavigationPaletteSelection();
    void createModuleDocks();
    // captureNormalWindowRect records the top-level outer rectangle only while
    // the shell is neither minimized nor maximized, so workspace persistence
    // never treats an iconified/maximized rectangle as normal placement.
    void captureNormalWindowRect();
    // persistWorkspaceState saves only the validated normal outer rectangle,
    // maximized state, and stable active module command id. Dock visibility and
    // layout remain intentionally transient.
    void persistWorkspaceState();
    int activeModuleCommandId() const;
    // createModulePlaceholderPage creates a lightweight tab body used during
    // startup. Inputs are a module descriptor and initial bounds; processing
    // avoids touching feature code/enumerators; output is a child HWND.
    HWND createModulePlaceholderPage(const Ksword::Ui::ModuleDescriptor& module, const RECT& bounds) const;
    // createModulePage creates the real feature page registered in
    // FeatureRegistry. Inputs are the module descriptor and initial bounds;
    // processing calls the descriptor factory and falls back to a diagnostic
    // fallback page if the module cannot create a child HWND; output is HWND.
    HWND createModulePage(const Ksword::Ui::ModuleDescriptor& module, const RECT& bounds) const;
    // materializeDockForDockIndex replaces a startup placeholder with the real
    // feature page the first time a dock is activated. Input is the dock index
    // posted by DockManager; processing keeps the tab/split/floating location
    // intact; no value is returned.
    void materializeDockForDockIndex(int dockIndex);
    // queueDockMaterialization paints a lightweight loading state before
    // scheduling the real page factory on the next message turn.
    void queueDockMaterialization(int dockIndex);
    void rebuildWindowMenuChecks();
    void toggleModuleDock(int moduleIndex);
    bool moduleDockVisible(int moduleIndex) const;
    // isTopmost reads the current extended window style. There is no input;
    // processing checks WS_EX_TOPMOST on the native top-level HWND; output is
    // true only when the shell window is currently topmost.
    bool isTopmost() const;
    // toggleTopmost switches the native topmost state. There is no input;
    // processing calls SetWindowPos with HWND_TOPMOST/HWND_NOTOPMOST, refreshes
    // the menu text, and writes a compact status line; no value is returned.
    void toggleTopmost();
    // refreshTopmostMenuText keeps the menu command text synchronized with the
    // window state. There is no input; processing rewrites the top-level menu
    // item to either "置顶" or "取消置顶"; no value is returned.
    void refreshTopmostMenuText();
    // positionCommandInput keeps the command edit visually on the menu bar.
    // There is no input; processing uses GetMenuItemRect on the topmost item and
    // moves the edit to its left; no value is returned.
    void positionCommandInput();
    // enableStartupPrivileges applies common token privileges at startup. There
    // is no input; processing stores per-privilege results and updates status
    // text/tooltips without modal dialogs; no value is returned.
    void enableStartupPrivileges();
    // executeCommandInput parses navigation by default. Only a leading ! starts
    // cmd.exe /k in a new console; the shell never executes ordinary search text.
    void executeCommandInput();
    bool routeNavigation(const Ksword::Core::NavigationRequest& request);
    bool applyNavigationToModule(int moduleIndex, const Ksword::Core::NavigationRequest& request);
    int moduleIndexForCommandId(int commandId) const;
    int moduleIndexForTitle(const std::wstring& query) const;
    bool activateModule(int moduleIndex);
    void exportEvidence(int commandId);
    void layout();
    void refreshPrivilegeText();
    void refreshDriverText(const Ksword::Core::DriverRuntimeStatus& status);
    // queryDriverStatusDeferred performs the first SCM/control-device probe
    // after the window has already been created and painted. There is no input;
    // processing updates cached driver state and menu text; no value is
    // returned.
    void queryDriverStatusDeferred();
    void handleUiAccessButtonClicked();
    void installDriverFromButton();
    // stopDriverOnExit unloads only a driver started by Light and only after the
    // last live Light lease is released. Pre-existing drivers remain running.
    void stopDriverOnExit();
    // requestProcessDockRefreshIfLoaded 用途：R0 驱动可用后通知已物化进程页重新枚举。
    // 处理过程：只投递刷新消息，不直接访问进程页内部控件或 R0 IOCTL。
    void requestProcessDockRefreshIfLoaded();
    void paint(HDC dc);

private:
    HINSTANCE instance_;
    HWND hwnd_;
    HWND commandEdit_;
    HWND navigationPalette_;
    HWND statusText_;
    HMENU mainMenu_;
    HMENU windowMenu_;
    HMENU evidenceMenu_;
    WNDPROC commandEditProc_;
    WNDPROC navigationPaletteProc_;
    std::unique_ptr<Ksword::Docking::DockManager> dockManager_;
    std::vector<Ksword::Ui::ModuleDescriptor> modules_;
    std::vector<DockSlot> dockSlots_;
    std::vector<std::optional<Ksword::Core::NavigationRequest>> pendingNavigation_;
    std::vector<NavigationPaletteEntry> navigationPaletteEntries_;
    std::vector<Ksword::Core::PrivilegeEnableResult> startupPrivilegeResults_;
    std::wstring startupPrivilegeSummary_;
    Ksword::Core::DriverLease driverLease_;
    Ksword::Core::DriverRuntimeStatus driverStatus_;
    RECT lastNormalScreenRect_{};
    int restoredModuleCommandId_ = 0;
    bool hasLastNormalScreenRect_ = false;
    bool wasMaximized_ = false;
    bool restoreMaximized_ = false;
    bool driverStatusKnown_ = false;
};

} // namespace Ksword::App
