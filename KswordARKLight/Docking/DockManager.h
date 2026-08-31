#pragma once

#include "../Core/Win32Lean.h"

#include <memory>
#include <string>
#include <vector>

namespace Ksword::Docking {

// DockPosition identifies where a newly registered page should be placed. The
// docking manager converts these values into tab merges or split insertions.
enum class DockPosition {
    Left,
    Right,
    Top,
    Bottom,
    Center
};

// DockWidget stores one titled Win32 content window. Inputs are a stable title
// and content HWND; processing reparents the content between host/floating
// windows; accessors expose state for layout, hit testing, and painting.
class DockWidget final {
public:
    DockWidget(std::wstring title, HWND content);

    const std::wstring& title() const;
    HWND content() const;
    void setContent(HWND content);
    bool visible() const;
    void setVisible(bool visible);
    bool floating() const;
    HWND floatingHost() const;
    void setFloatingHost(HWND host);

private:
    std::wstring title_;
    HWND content_;
    bool visible_;
    HWND floatingHost_;
};

// DockManager is a handwritten Win32 docking system. It supports tabbed leaves,
// split panes, floating windows, drag previews, root-edge docking, selected-pane
// edge docking, and center tab merging.
class DockManager final {
public:
    enum class DropKind {
        None,
        Tab,
        PaneLeft,
        PaneRight,
        PaneTop,
        PaneBottom,
        RootLeft,
        RootRight,
        RootTop,
        RootBottom
    };

    DockManager();
    ~DockManager();

    DockManager(const DockManager&) = delete;
    DockManager& operator=(const DockManager&) = delete;

    // create initializes the host child window. Inputs are parent HWND and host
    // bounds; output is true when the host window is created.
    bool create(HWND parent, const RECT& bounds);

    // hwnd returns the host HWND. There is no input; output may be null before
    // create() succeeds.
    HWND hwnd() const;

    // addDock registers a dock page. Inputs are placement, title, and content
    // child HWND; processing reparents and inserts the page; output is index.
    int addDock(DockPosition position, const std::wstring& title, HWND content);

    // replaceDockContent swaps the child HWND owned by an existing dock. Inputs
    // are a dock index, the replacement child and whether the old child should
    // be destroyed; processing preserves tab/split/floating state and reparents
    // the new child to the current host; output reports whether the swap worked.
    bool replaceDockContent(int index, HWND content, bool destroyOldContent);

    // activateDock selects one page by index. Input is a dock index; processing
    // activates its leaf tab or foregrounds its floating window; no return.
    void activateDock(int index);

    // setActivationChangedMessage configures a parent notification. Input is a
    // message id or zero to disable; processing posts the active dock index in
    // WPARAM whenever user/code activation changes; no value is returned.
    void setActivationChangedMessage(UINT message);

    // closeDock hides one dock page. Input is a dock index; processing removes it
    // from host/floating layout and hides content; no return value.
    void closeDock(int index);

    // dockVisible reports whether a dock index is currently open. Input is a
    // dock index; processing checks bounds and visibility; output is true only
    // for visible dock widgets.
    bool dockVisible(int index) const;

    // activeDockIndex returns the active dock identity after all tab, close, and
    // floating-window transitions. It is read-only and returns -1 when no dock
    // is currently active.
    int activeDockIndex() const noexcept;

    // layout resizes the host and all docked children. Input is parent-relative
    // bounds; processing recomputes split/leaf rectangles; no return.
    void layout(const RECT& bounds);

    // saveLayout returns a diagnostic text dump of current dock/floating state.
    std::wstring saveLayout() const;

    // HostProc dispatches messages for the dock host custom class.
    static LRESULT CALLBACK HostProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // FloatingProc dispatches messages for detached dock windows.
    static LRESULT CALLBACK FloatingProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // OverlayProc dispatches messages for the topmost transparent docking-guide
    // overlay. Inputs are normal Win32 window-procedure values; output is a
    // Win32 LRESULT.
    static LRESULT CALLBACK OverlayProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    struct DockNode;
    struct FloatingDock;
    struct TabHit;
    struct DropTarget;

    LRESULT handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT handleFloatingMessage(FloatingDock* floating, HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void paint(HDC dc);
    void paintNode(HDC dc, const DockNode* node) const;
    void paintLeaf(HDC dc, const DockNode* leaf) const;
    void paintDropGuides(HDC dc) const;
    void paintDropGuidesOnOverlay(HDC dc) const;
    void showDropOverlay();
    void hideDropOverlay();
    void updateDropOverlay();

    void layoutChildren();
    void layoutNode(DockNode* node, const RECT& rect);
    void layoutLeafChildren(const DockNode* node);

    std::unique_ptr<DockNode> makeLeaf(int dockIndex);
    DockNode* firstLeaf() const;
    DockNode* findLeafById(DockNode* node, int leafId) const;
    const DockNode* findLeafById(const DockNode* node, int leafId) const;
    DockNode* findLeafContaining(DockNode* node, int dockIndex) const;
    const DockNode* findLeafContaining(const DockNode* node, int dockIndex) const;
    DockNode* findLeafAtPoint(DockNode* node, POINT pt) const;
    bool removeDockFromNode(DockNode* node, int dockIndex);
    bool nodeEmpty(const DockNode* node) const;
    void collapseEmptySplits(std::unique_ptr<DockNode>& node);

    TabHit hitTestTab(int x, int y) const;
    DropTarget dropTargetFromScreen(POINT screenPoint) const;
    RECT previewRectForTarget(const DropTarget& target) const;

    void beginTabDrag(const TabHit& hit, POINT screenPoint);
    void updateTabDrag(POINT screenPoint);
    void finishTabDrag(POINT screenPoint);
    void cancelTabDrag();

    void floatDock(int dockIndex, POINT screenPoint, bool noActivate = false);
    void moveDraggedFloatingDock(POINT screenPoint);
    bool setHoverTarget(const DropTarget& target);
    void beginFloatingMove(FloatingDock* floating);
    void updateFloatingMove(FloatingDock* floating, POINT screenPoint);
    void finishFloatingMove(FloatingDock* floating, POINT screenPoint);
    void destroyFloatingHost(int dockIndex, bool hideContent);

    bool moveDockToTarget(int dockIndex, const DropTarget& target);
    bool insertDockAsTab(int dockIndex, int leafId);
    bool splitLeafWithDock(int dockIndex, int leafId, DropKind kind);
    bool splitRootWithDock(int dockIndex, DropKind kind);
    void appendDockToLeaf(DockNode* leaf, int dockIndex);
    void setDockParentToHost(int dockIndex);
    void notifyActiveDockChanged() const;

private:
    HWND hwnd_;
    HWND parent_;
    HWND overlayHwnd_;
    std::unique_ptr<DockNode> root_;
    std::vector<std::unique_ptr<DockWidget>> docks_;
    std::vector<std::unique_ptr<FloatingDock>> floatingDocks_;
    int activeIndex_;
    UINT activationChangedMessage_;
    int hotTabDock_;
    int nextLeafId_;
    bool capturedTab_;
    bool draggingTab_;
    bool ignoreCaptureLoss_;
    POINT dragStartScreen_;
    POINT dragWindowOffset_;
    int dragDockIndex_;
    std::unique_ptr<TabHit> pressedTab_;
    std::unique_ptr<DropTarget> hoverTarget_;
};

// RegisterDockingClasses registers the custom host and floating classes. Input
// is module instance; output is true when both classes are available.
bool RegisterDockingClasses(HINSTANCE instance);

} // namespace Ksword::Docking
