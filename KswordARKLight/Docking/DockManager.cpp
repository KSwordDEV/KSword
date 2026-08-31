#include "DockManager.h"

#include "../Ui/Controls.h"
#include "../Ui/Theme.h"

#include <sstream>
#include <utility>
#include <windowsx.h>

namespace Ksword::Docking {
namespace {
constexpr wchar_t kDockManagerClass[] = L"KswordARKLight.DockManager";
constexpr wchar_t kFloatingClass[] = L"KswordARKLight.DockFloating";
constexpr wchar_t kOverlayClass[] = L"KswordARKLight.DockOverlay";
constexpr COLORREF kOverlayTransparentColor = RGB(255, 0, 255);
constexpr int kTabHeight = 22;
constexpr int kTabMinWidth = 52;
constexpr int kTabMaxWidth = 140;
constexpr int kSplitterSize = 4;
constexpr int kDragThreshold = 6;
constexpr int kFloatingWidth = 540;
constexpr int kFloatingHeight = 380;
constexpr UINT_PTR kTabDragTimerId = 1;
constexpr UINT kTabDragTimerMs = 16;

// MaxInt avoids std::max overload and Windows macro friction. Inputs are two
// integers; processing compares them directly; output is the larger value.
int MaxInt(int left, int right) { return left > right ? left : right; }

// MinInt avoids std::min overload and Windows macro friction. Inputs are two
// integers; processing compares them directly; output is the smaller value.
int MinInt(int left, int right) { return left < right ? left : right; }

// Width returns non-negative rectangle width. Input is a RECT; output is pixels.
int Width(const RECT& rc) { return MaxInt(0, rc.right - rc.left); }

// Height returns non-negative rectangle height. Input is a RECT; output is pixels.
int Height(const RECT& rc) { return MaxInt(0, rc.bottom - rc.top); }

// Contains reports whether a point lies inside a rectangle. Inputs must use the
// same coordinate space; output is true when the point is inside.
bool Contains(const RECT& rc, POINT pt) {
    return pt.x >= rc.left && pt.x < rc.right && pt.y >= rc.top && pt.y < rc.bottom;
}

// CenterTabGuide returns the target-pane TAB docking button. Input is the pane
// bounds; output is the button rectangle used for both painting and hit tests.
RECT CenterTabGuide(const RECT& rc) {
    RECT center{ (rc.left + rc.right) / 2 - 52, (rc.top + rc.bottom) / 2 - 52,
        (rc.left + rc.right) / 2 + 52, (rc.top + rc.bottom) / 2 + 52 };
    return { center.left + 32, center.top + 32, center.right - 32, center.bottom - 32 };
}

// CenterLeftGuide returns the selected-pane left docking button. Input is pane
// bounds; output is the button rectangle used for painting and hit tests.
RECT CenterLeftGuide(const RECT& rc) {
    RECT center{ (rc.left + rc.right) / 2 - 52, (rc.top + rc.bottom) / 2 - 52,
        (rc.left + rc.right) / 2 + 52, (rc.top + rc.bottom) / 2 + 52 };
    return { center.left, center.top + 32, center.left + 28, center.bottom - 32 };
}

// CenterRightGuide returns the selected-pane right docking button. Input is pane
// bounds; output is the button rectangle used for painting and hit tests.
RECT CenterRightGuide(const RECT& rc) {
    RECT center{ (rc.left + rc.right) / 2 - 52, (rc.top + rc.bottom) / 2 - 52,
        (rc.left + rc.right) / 2 + 52, (rc.top + rc.bottom) / 2 + 52 };
    return { center.right - 28, center.top + 32, center.right, center.bottom - 32 };
}

// CenterTopGuide returns the selected-pane top docking button. Input is pane
// bounds; output is the button rectangle used for painting and hit tests.
RECT CenterTopGuide(const RECT& rc) {
    RECT center{ (rc.left + rc.right) / 2 - 52, (rc.top + rc.bottom) / 2 - 52,
        (rc.left + rc.right) / 2 + 52, (rc.top + rc.bottom) / 2 + 52 };
    return { center.left + 32, center.top, center.right - 32, center.top + 28 };
}

// CenterBottomGuide returns the selected-pane bottom docking button. Input is
// pane bounds; output is the button rectangle used for painting/hit tests.
RECT CenterBottomGuide(const RECT& rc) {
    RECT center{ (rc.left + rc.right) / 2 - 52, (rc.top + rc.bottom) / 2 - 52,
        (rc.left + rc.right) / 2 + 52, (rc.top + rc.bottom) / 2 + 52 };
    return { center.left + 32, center.bottom - 28, center.right - 32, center.bottom };
}

// RootLeftGuide returns the whole-host left docking button. Input is host client
// bounds; output is the button rectangle used for painting and hit tests.
RECT RootLeftGuide(const RECT& rc) {
    return { rc.left, (rc.top + rc.bottom) / 2 - 24, rc.left + 48, (rc.top + rc.bottom) / 2 + 24 };
}

// RootRightGuide returns the whole-host right docking button. Input is host
// client bounds; output is the button rectangle used for painting and hit tests.
RECT RootRightGuide(const RECT& rc) {
    return { rc.right - 48, (rc.top + rc.bottom) / 2 - 24, rc.right, (rc.top + rc.bottom) / 2 + 24 };
}

// RootTopGuide returns the whole-host top docking button. Input is host client
// bounds; output is the button rectangle used for painting and hit tests.
RECT RootTopGuide(const RECT& rc) {
    return { (rc.left + rc.right) / 2 - 24, rc.top, (rc.left + rc.right) / 2 + 24, rc.top + 48 };
}

// RootBottomGuide returns the whole-host bottom docking button. Input is host
// client bounds; output is the button rectangle used for painting and hit tests.
RECT RootBottomGuide(const RECT& rc) {
    return { (rc.left + rc.right) / 2 - 24, rc.bottom - 48, (rc.left + rc.right) / 2 + 24, rc.bottom };
}

// DeflateCopy returns a deflated copy of a RECT. Inputs are original geometry and
// deltas; output is the adjusted rectangle.
RECT DeflateCopy(RECT rc, int dx, int dy) {
    ::InflateRect(&rc, -dx, -dy);
    return rc;
}

// SplitPreview calculates the highlighted destination rectangle. Inputs are the
// target area and drop kind; output is the preview sub-rectangle.
RECT SplitPreview(RECT rc, DockManager::DropKind kind) {
    switch (kind) {
    case DockManager::DropKind::PaneLeft:
    case DockManager::DropKind::RootLeft:
        rc.right = rc.left + MaxInt(1, Width(rc) / 3);
        break;
    case DockManager::DropKind::PaneRight:
    case DockManager::DropKind::RootRight:
        rc.left = rc.right - MaxInt(1, Width(rc) / 3);
        break;
    case DockManager::DropKind::PaneTop:
    case DockManager::DropKind::RootTop:
        rc.bottom = rc.top + MaxInt(1, Height(rc) / 3);
        break;
    case DockManager::DropKind::PaneBottom:
    case DockManager::DropKind::RootBottom:
        rc.top = rc.bottom - MaxInt(1, Height(rc) / 3);
        break;
    case DockManager::DropKind::Tab:
        rc = DeflateCopy(rc, 8, 8);
        break;
    default:
        ::SetRectEmpty(&rc);
        break;
    }
    return rc;
}

// HorizontalSplit reports the split axis required by a drop kind. Input is a
// drop kind; output is true for left/right splits.
bool HorizontalSplit(DockManager::DropKind kind) {
    return kind == DockManager::DropKind::PaneLeft || kind == DockManager::DropKind::PaneRight ||
        kind == DockManager::DropKind::RootLeft || kind == DockManager::DropKind::RootRight;
}

// IncomingFirst reports whether the newly inserted dock should be first child.
// Input is drop kind; output is true for left/top insertions.
bool IncomingFirst(DockManager::DropKind kind) {
    return kind == DockManager::DropKind::PaneLeft || kind == DockManager::DropKind::PaneTop ||
        kind == DockManager::DropKind::RootLeft || kind == DockManager::DropKind::RootTop;
}

// TabWidthForTitle measures and clamps one tab. Inputs are a DC and title; output
// is width in pixels.
int TabWidthForTitle(HDC dc, const std::wstring& title) {
    SIZE size{};
    ::GetTextExtentPoint32W(dc, title.c_str(), static_cast<int>(title.size()), &size);
    return MinInt(kTabMaxWidth, MaxInt(kTabMinWidth, static_cast<int>(size.cx) + 12));
}

// DrawFrame draws a one-pixel rectangle frame. Inputs are DC, rect and color; no
// value is returned.
void DrawFrame(HDC dc, const RECT& rc, COLORREF color) {
    HPEN pen = ::CreatePen(PS_SOLID, 1, color);
    HGDIOBJ oldPen = ::SelectObject(dc, pen);
    HGDIOBJ oldBrush = ::SelectObject(dc, ::GetStockObject(HOLLOW_BRUSH));
    ::Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
    ::SelectObject(dc, oldBrush);
    ::SelectObject(dc, oldPen);
    ::DeleteObject(pen);
}

// DrawDropBox paints one docking guide button. Inputs are DC, rect, label and
// active state; no value is returned.
void DrawDropBox(HDC dc, const RECT& rc, const wchar_t* label, bool active) {
    HBRUSH brush = ::CreateSolidBrush(active ? RGB(0, 100, 251) : RGB(255, 255, 255));
    ::FillRect(dc, &rc, brush);
    ::DeleteObject(brush);
    DrawFrame(dc, rc, active ? RGB(0, 76, 190) : RGB(120, 132, 150));
    Ksword::Ui::DrawTextLine(dc, label, rc, active ? RGB(255, 255, 255) : RGB(31, 35, 40),
        Ksword::Ui::SystemUIFont(), DT_SINGLELINE | DT_CENTER | DT_VCENTER);
}
} // namespace

// DockNode is one node in the recursive docking layout tree. Leaf nodes contain
// tabs; split nodes contain two child nodes and an orientation.
struct DockManager::DockNode {
    bool leaf = true;
    bool horizontal = true;
    float ratio = 0.5f;
    RECT rect{};
    RECT tabRect{};
    int leafId = 0;
    int activeDock = -1;
    std::vector<int> docks;
    std::unique_ptr<DockNode> first;
    std::unique_ptr<DockNode> second;
};

// FloatingDock represents one detached top-level window carrying one dock page.
// It stores owner and movement state so dragging back can show drop guides.
struct DockManager::FloatingDock {
    DockManager* owner = nullptr;
    HWND hwnd = nullptr;
    int dockIndex = -1;
    bool moving = false;
};

// TabHit identifies a clicked tab. It records leaf, dock index, ordinal and tab
// geometry in host client coordinates.
struct DockManager::TabHit {
    bool valid = false;
    int leafId = 0;
    int dockIndex = -1;
    int ordinal = -1;
    RECT rect{};
};

// DropTarget describes the active drag target. It records target kind, target
// leaf id and preview rectangle in host client coordinates.
struct DockManager::DropTarget {
    bool valid = false;
    DropKind kind = DropKind::None;
    int leafId = 0;
    RECT preview{};
};

DockWidget::DockWidget(std::wstring title, HWND content)
    : title_(std::move(title)), content_(content), visible_(true), floatingHost_(nullptr) {}

const std::wstring& DockWidget::title() const { return title_; }
HWND DockWidget::content() const { return content_; }
void DockWidget::setContent(HWND content) { content_ = content; }
bool DockWidget::visible() const { return visible_; }
void DockWidget::setVisible(bool visible) { visible_ = visible; }
bool DockWidget::floating() const { return floatingHost_ != nullptr; }
HWND DockWidget::floatingHost() const { return floatingHost_; }
void DockWidget::setFloatingHost(HWND host) { floatingHost_ = host; }

DockManager::DockManager()
    : hwnd_(nullptr), parent_(nullptr), overlayHwnd_(nullptr), activeIndex_(-1), hotTabDock_(-1), nextLeafId_(1),
      activationChangedMessage_(0),
      capturedTab_(false), draggingTab_(false), ignoreCaptureLoss_(false), dragStartScreen_{}, dragWindowOffset_{},
      dragDockIndex_(-1) {}

DockManager::~DockManager() {
    if (overlayHwnd_) {
        ::DestroyWindow(overlayHwnd_);
        overlayHwnd_ = nullptr;
    }
    for (auto& floating : floatingDocks_) {
        if (floating && floating->hwnd) {
            ::DestroyWindow(floating->hwnd);
        }
    }
    if (hwnd_) {
        ::DestroyWindow(hwnd_);
    }
}

bool DockManager::create(HWND parent, const RECT& bounds) {
    parent_ = parent;
    root_ = makeLeaf(-1);
    hwnd_ = ::CreateWindowExW(0, kDockManagerClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, Width(bounds), Height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), this);
    overlayHwnd_ = ::CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        kOverlayClass, L"", WS_POPUP, 0, 0, 1, 1, parent, nullptr, ::GetModuleHandleW(nullptr), this);
    if (overlayHwnd_) {
        ::SetLayeredWindowAttributes(overlayHwnd_, kOverlayTransparentColor, 255, LWA_COLORKEY);
        ::ShowWindow(overlayHwnd_, SW_HIDE);
    }
    return hwnd_ != nullptr;
}

HWND DockManager::hwnd() const { return hwnd_; }

int DockManager::addDock(DockPosition position, const std::wstring& title, HWND content) {
    if (!hwnd_ || !content) {
        return -1;
    }
    docks_.push_back(std::make_unique<DockWidget>(title, content));
    const int index = static_cast<int>(docks_.size()) - 1;
    setDockParentToHost(index);
    if (!root_ || nodeEmpty(root_.get())) {
        root_ = makeLeaf(index);
    } else if (position == DockPosition::Left) {
        splitRootWithDock(index, DropKind::RootLeft);
    } else if (position == DockPosition::Right) {
        splitRootWithDock(index, DropKind::RootRight);
    } else if (position == DockPosition::Top) {
        splitRootWithDock(index, DropKind::RootTop);
    } else if (position == DockPosition::Bottom) {
        splitRootWithDock(index, DropKind::RootBottom);
    } else {
        appendDockToLeaf(firstLeaf(), index);
    }
    activeIndex_ = index;
    layoutChildren();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
    return index;
}

bool DockManager::replaceDockContent(const int index, HWND content, const bool destroyOldContent) {
    // replaceDockContent is used by the shell's lazy module loader. Inputs are
    // an existing dock index and a replacement child HWND; processing keeps the
    // dock node, tab order, active dock and floating state intact while swapping
    // only the hosted content; output reports whether the index/content was
    // valid enough to perform the replacement.
    if (index < 0 || index >= static_cast<int>(docks_.size()) || !content) {
        return false;
    }

    HWND oldContent = docks_[index]->content();
    docks_[index]->setContent(content);

    HWND targetParent = hwnd_;
    if (docks_[index]->floating() && docks_[index]->floatingHost()) {
        targetParent = docks_[index]->floatingHost();
    }

    ::SetParent(content, targetParent);
    ::SetWindowLongPtrW(content, GWL_STYLE, (::GetWindowLongPtrW(content, GWL_STYLE) | WS_CHILD) & ~WS_POPUP);
    ::ShowWindow(content, SW_HIDE);

    if (oldContent && oldContent != content) {
        ::ShowWindow(oldContent, SW_HIDE);
        ::SetParent(oldContent, hwnd_);
        if (destroyOldContent) {
            ::DestroyWindow(oldContent);
        }
    }

    if (docks_[index]->floating() && docks_[index]->floatingHost()) {
        RECT client{};
        ::GetClientRect(docks_[index]->floatingHost(), &client);
        ::MoveWindow(content, 0, 0, Width(client), Height(client), TRUE);
        ::ShowWindow(content, SW_SHOW);
    }

    layoutChildren();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
    return true;
}

void DockManager::activateDock(int index) {
    if (index < 0 || index >= static_cast<int>(docks_.size()) || !docks_[index]->visible()) {
        return;
    }
    activeIndex_ = index;
    if (docks_[index]->floating()) {
        ::SetForegroundWindow(docks_[index]->floatingHost());
    } else if (DockNode* leaf = findLeafContaining(root_.get(), index)) {
        leaf->activeDock = index;
    }
    layoutChildren();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
    notifyActiveDockChanged();
}

void DockManager::setActivationChangedMessage(const UINT message) {
    activationChangedMessage_ = message;
}

void DockManager::closeDock(int index) {
    if (index < 0 || index >= static_cast<int>(docks_.size())) {
        return;
    }
    const bool closedWasActive = activeIndex_ == index;
    if (docks_[index]->floating()) {
        destroyFloatingHost(index, true);
    }
    removeDockFromNode(root_.get(), index);
    collapseEmptySplits(root_);
    docks_[index]->setVisible(false);
    if (HWND child = docks_[index]->content()) {
        ::ShowWindow(child, SW_HIDE);
    }
    const bool activeStillVisible = activeIndex_ >= 0 && activeIndex_ < static_cast<int>(docks_.size()) &&
        docks_[activeIndex_] && docks_[activeIndex_]->visible();
    if (closedWasActive || !activeStillVisible) {
        activeIndex_ = -1;
        for (int i = 0; i < static_cast<int>(docks_.size()); ++i) {
            if (docks_[i]->visible()) {
                activeIndex_ = i;
                break;
            }
        }
    }
    layoutChildren();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
}

bool DockManager::dockVisible(int index) const {
    return index >= 0 && index < static_cast<int>(docks_.size()) && docks_[index] && docks_[index]->visible();
}

int DockManager::activeDockIndex() const noexcept {
    return activeIndex_;
}

void DockManager::layout(const RECT& bounds) {
    if (!hwnd_) {
        return;
    }
    ::MoveWindow(hwnd_, bounds.left, bounds.top, Width(bounds), Height(bounds), TRUE);
    layoutChildren();
}

std::wstring DockManager::saveLayout() const {
    std::wostringstream out;
    out << L"active=" << activeIndex_ << L"\n";
    for (int i = 0; i < static_cast<int>(docks_.size()); ++i) {
        out << (docks_[i]->floating() ? L"FLOAT|" : L"DOCK|") << docks_[i]->title() << L"\n";
    }
    return out.str();
}

LRESULT CALLBACK DockManager::HostProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    DockManager* manager = reinterpret_cast<DockManager*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        manager = cs ? static_cast<DockManager*>(cs->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(manager));
    }
    if (manager) {
        return manager->handleMessage(hwnd, msg, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK DockManager::FloatingProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    FloatingDock* floating = reinterpret_cast<FloatingDock*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        floating = cs ? static_cast<FloatingDock*>(cs->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(floating));
    }
    if (floating && floating->owner) {
        return floating->owner->handleFloatingMessage(floating, hwnd, msg, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK DockManager::OverlayProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    DockManager* manager = reinterpret_cast<DockManager*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        manager = cs ? static_cast<DockManager*>(cs->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(manager));
    }
    if (!manager) {
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    switch (msg) {
    case WM_NCHITTEST:
        return HTTRANSPARENT;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        manager->paintDropGuidesOnOverlay(dc);
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT DockManager::handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_SIZE:
        layoutChildren();
        return 0;
    case WM_LBUTTONDOWN: {
        TabHit hit = hitTestTab(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        if (hit.valid) {
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ::ClientToScreen(hwnd, &pt);
            beginTabDrag(hit, pt);
            return 0;
        }
        break;
    }
    case WM_MOUSEMOVE: {
        POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        ::ClientToScreen(hwnd, &pt);
        if (capturedTab_) {
            updateTabDrag(pt);
            return 0;
        }
        TabHit hit = hitTestTab(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        const int nextHot = hit.valid ? hit.dockIndex : -1;
        if (nextHot != hotTabDock_) {
            hotTabDock_ = nextHot;
            ::InvalidateRect(hwnd_, nullptr, FALSE);
        }
        return 0;
    }
    case WM_TIMER:
        if (wParam == kTabDragTimerId && capturedTab_) {
            POINT pt{};
            ::GetCursorPos(&pt);
            updateTabDrag(pt);
            return 0;
        }
        break;
    case WM_LBUTTONUP: {
        POINT pt{};
        ::GetCursorPos(&pt);
        finishTabDrag(pt);
        return 0;
    }
    case WM_CAPTURECHANGED:
        if (capturedTab_ && !ignoreCaptureLoss_) {
            cancelTabDrag();
        }
        return 0;
    case WM_RBUTTONUP: {
        TabHit hit = hitTestTab(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        if (hit.valid) {
            HMENU menu = ::CreatePopupMenu();
            ::AppendMenuW(menu, MF_STRING, 1, L"浮动");
            ::AppendMenuW(menu, MF_STRING, 2, L"关闭");
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ::ClientToScreen(hwnd, &pt);
            const int cmd = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
            ::DestroyMenu(menu);
            if (cmd == 1) {
                floatDock(hit.dockIndex, pt);
            } else if (cmd == 2) {
                closeDock(hit.dockIndex);
            }
            return 0;
        }
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        RECT rc{};
        ::GetClientRect(hwnd, &rc);
        HDC memoryDc = ::CreateCompatibleDC(dc);
        HBITMAP memoryBitmap = ::CreateCompatibleBitmap(dc, Width(rc), Height(rc));
        HGDIOBJ oldBitmap = memoryDc && memoryBitmap ? ::SelectObject(memoryDc, memoryBitmap) : nullptr;
        if (memoryDc && memoryBitmap) {
            paint(memoryDc);
            ::BitBlt(dc, 0, 0, Width(rc), Height(rc), memoryDc, 0, 0, SRCCOPY);
        } else {
            paint(dc);
        }
        if (oldBitmap) {
            ::SelectObject(memoryDc, oldBitmap);
        }
        if (memoryBitmap) {
            ::DeleteObject(memoryBitmap);
        }
        if (memoryDc) {
            ::DeleteDC(memoryDc);
        }
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT DockManager::handleFloatingMessage(FloatingDock* floating, HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_ENTERSIZEMOVE:
        beginFloatingMove(floating);
        return 0;
    case WM_MOVING: {
        RECT* rc = reinterpret_cast<RECT*>(lParam);
        POINT pt{ rc ? rc->left + 90 : 0, rc ? rc->top + 16 : 0 };
        updateFloatingMove(floating, pt);
        break;
    }
    case WM_EXITSIZEMOVE: {
        RECT rc{};
        ::GetWindowRect(hwnd, &rc);
        POINT pt{ rc.left + 90, rc.top + 16 };
        finishFloatingMove(floating, pt);
        return 0;
    }
    case WM_SIZE: {
        if (floating->dockIndex >= 0 && floating->dockIndex < static_cast<int>(docks_.size())) {
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            HWND child = docks_[floating->dockIndex]->content();
            ::MoveWindow(child, 0, 0, Width(rc), Height(rc), FALSE);
        }
        return 0;
    }
    case WM_CLOSE:
        closeDock(floating->dockIndex);
        return 0;
    case WM_NCDESTROY:
        if (floating->dockIndex >= 0 && floating->dockIndex < static_cast<int>(docks_.size()) &&
            docks_[floating->dockIndex]->floatingHost() == hwnd) {
            docks_[floating->dockIndex]->setFloatingHost(nullptr);
        }
        floating->hwnd = nullptr;
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void DockManager::paint(HDC dc) {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    ::FillRect(dc, &rc, Ksword::Ui::AppTheme().windowBrush());
    paintNode(dc, root_.get());
}

void DockManager::paintNode(HDC dc, const DockNode* node) const {
    if (!node) {
        return;
    }
    if (!node->leaf) {
        paintNode(dc, node->first.get());
        paintNode(dc, node->second.get());
        return;
    }
    paintLeaf(dc, node);
}

void DockManager::paintLeaf(HDC dc, const DockNode* leaf) const {
    if (!leaf) {
        return;
    }
    Ksword::Ui::PaintPanel(dc, leaf->rect);
    RECT tabs = leaf->tabRect;
    ::FillRect(dc, &tabs, Ksword::Ui::AppTheme().panelBrush());
    HGDIOBJ oldFont = ::SelectObject(dc, Ksword::Ui::SystemUIFont());
    int x = tabs.left;
    for (int ordinal = 0; ordinal < static_cast<int>(leaf->docks.size()); ++ordinal) {
        const int dockIndex = leaf->docks[ordinal];
        if (dockIndex < 0 || dockIndex >= static_cast<int>(docks_.size()) || !docks_[dockIndex]->visible()) {
            continue;
        }
        int tabWidth = TabWidthForTitle(dc, docks_[dockIndex]->title());
        tabWidth = MinInt(tabWidth, MaxInt(kTabMinWidth, tabs.right - x));
        RECT tab{ x, tabs.top, x + tabWidth, tabs.bottom };
        const bool active = dockIndex == leaf->activeDock;
        const bool hot = dockIndex == hotTabDock_;
        HBRUSH brush = active ? Ksword::Ui::AppTheme().accentBrush() : Ksword::Ui::AppTheme().panelBrush();
        ::FillRect(dc, &tab, brush);
        if (hot && !active) {
            HBRUSH hover = ::CreateSolidBrush(RGB(235, 240, 248));
            ::FillRect(dc, &tab, hover);
            ::DeleteObject(hover);
        }
        Ksword::Ui::DrawTextLine(dc, docks_[dockIndex]->title(), tab,
            active ? RGB(255, 255, 255) : Ksword::Ui::AppTheme().textColor,
            Ksword::Ui::SystemUIFont(),
            DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        DrawFrame(dc, tab, Ksword::Ui::AppTheme().borderColor);
        x += tabWidth;
        if (x >= tabs.right) {
            break;
        }
    }
    ::SelectObject(dc, oldFont);
    DrawFrame(dc, leaf->rect, Ksword::Ui::AppTheme().borderColor);
}

void DockManager::paintDropGuides(HDC dc) const {
    if (!capturedTab_ && !hoverTarget_) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const bool hasHover = hoverTarget_ && hoverTarget_->valid;
    if (hasHover) {
        RECT preview = hoverTarget_->preview;
        HBRUSH previewBrush = ::CreateSolidBrush(RGB(191, 222, 255));
        ::FillRect(dc, &preview, previewBrush);
        ::DeleteObject(previewBrush);
        DrawFrame(dc, preview, RGB(0, 100, 251));
    }

    const DockNode* guideLeaf = nullptr;
    if (hoverTarget_ && hoverTarget_->leafId != 0) {
        guideLeaf = findLeafById(root_.get(), hoverTarget_->leafId);
    }
    if (!guideLeaf) {
        guideLeaf = findLeafContaining(root_.get(), activeIndex_);
    }
    const RECT guidePane = guideLeaf ? guideLeaf->rect : rc;
    RECT tab = CenterTabGuide(guidePane);
    RECT left = CenterLeftGuide(guidePane);
    RECT right = CenterRightGuide(guidePane);
    RECT top = CenterTopGuide(guidePane);
    RECT bottom = CenterBottomGuide(guidePane);
    DrawDropBox(dc, tab, L"TAB", hasHover && hoverTarget_->kind == DropKind::Tab);
    DrawDropBox(dc, left, L"L", hasHover && hoverTarget_->kind == DropKind::PaneLeft);
    DrawDropBox(dc, right, L"R", hasHover && hoverTarget_->kind == DropKind::PaneRight);
    DrawDropBox(dc, top, L"T", hasHover && hoverTarget_->kind == DropKind::PaneTop);
    DrawDropBox(dc, bottom, L"B", hasHover && hoverTarget_->kind == DropKind::PaneBottom);

    RECT rootLeft = RootLeftGuide(rc);
    RECT rootRight = RootRightGuide(rc);
    RECT rootTop = RootTopGuide(rc);
    RECT rootBottom = RootBottomGuide(rc);
    DrawDropBox(dc, rootLeft, L"ROOT L", hasHover && hoverTarget_->kind == DropKind::RootLeft);
    DrawDropBox(dc, rootRight, L"ROOT R", hasHover && hoverTarget_->kind == DropKind::RootRight);
    DrawDropBox(dc, rootTop, L"ROOT T", hasHover && hoverTarget_->kind == DropKind::RootTop);
    DrawDropBox(dc, rootBottom, L"ROOT B", hasHover && hoverTarget_->kind == DropKind::RootBottom);
}

void DockManager::paintDropGuidesOnOverlay(HDC dc) const {
    if (!overlayHwnd_) {
        return;
    }
    RECT overlayRc{};
    ::GetClientRect(overlayHwnd_, &overlayRc);
    HBRUSH transparentBrush = ::CreateSolidBrush(kOverlayTransparentColor);
    ::FillRect(dc, &overlayRc, transparentBrush);
    ::DeleteObject(transparentBrush);

    paintDropGuides(dc);
}

void DockManager::showDropOverlay() {
    if (!overlayHwnd_ || !hwnd_) {
        return;
    }
    RECT hostScreen{};
    ::GetWindowRect(hwnd_, &hostScreen);
    ::SetWindowPos(overlayHwnd_, HWND_TOPMOST, hostScreen.left, hostScreen.top,
        Width(hostScreen), Height(hostScreen), SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_SHOWWINDOW);
}

void DockManager::hideDropOverlay() {
    if (!overlayHwnd_) {
        return;
    }
    ::ShowWindow(overlayHwnd_, SW_HIDE);
}

void DockManager::updateDropOverlay() {
    if (!overlayHwnd_) {
        return;
    }
    showDropOverlay();
    ::InvalidateRect(overlayHwnd_, nullptr, FALSE);
}

void DockManager::layoutChildren() {
    if (!hwnd_) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    layoutNode(root_.get(), rc);
    for (int i = 0; i < static_cast<int>(docks_.size()); ++i) {
        if (docks_[i] && docks_[i]->visible() && !docks_[i]->floating() && docks_[i]->content()) {
            ::ShowWindow(docks_[i]->content(), SW_HIDE);
        }
    }
    layoutLeafChildren(root_.get());
}

void DockManager::layoutNode(DockNode* node, const RECT& rect) {
    if (!node) {
        return;
    }
    node->rect = rect;
    if (node->leaf) {
        node->tabRect = { rect.left, rect.top, rect.right, MinInt(rect.bottom, rect.top + kTabHeight) };
        return;
    }
    if (node->horizontal) {
        const int splitX = rect.left + static_cast<int>(Width(rect) * node->ratio);
        RECT first{ rect.left, rect.top, splitX - kSplitterSize / 2, rect.bottom };
        RECT second{ splitX + kSplitterSize / 2, rect.top, rect.right, rect.bottom };
        layoutNode(node->first.get(), first);
        layoutNode(node->second.get(), second);
    } else {
        const int splitY = rect.top + static_cast<int>(Height(rect) * node->ratio);
        RECT first{ rect.left, rect.top, rect.right, splitY - kSplitterSize / 2 };
        RECT second{ rect.left, splitY + kSplitterSize / 2, rect.right, rect.bottom };
        layoutNode(node->first.get(), first);
        layoutNode(node->second.get(), second);
    }
}

void DockManager::layoutLeafChildren(const DockNode* node) {
    if (!node) {
        return;
    }
    if (!node->leaf) {
        layoutLeafChildren(node->first.get());
        layoutLeafChildren(node->second.get());
        return;
    }
    RECT content{ node->rect.left, node->rect.top + kTabHeight, node->rect.right, node->rect.bottom };
    for (int dockIndex : node->docks) {
        if (dockIndex < 0 || dockIndex >= static_cast<int>(docks_.size())) {
            continue;
        }
        HWND child = docks_[dockIndex]->content();
        if (!child || docks_[dockIndex]->floating()) {
            continue;
        }
        ::MoveWindow(child, content.left, content.top, Width(content), Height(content), TRUE);
        ::ShowWindow(child, dockIndex == node->activeDock && docks_[dockIndex]->visible() ? SW_SHOW : SW_HIDE);
    }
}

std::unique_ptr<DockManager::DockNode> DockManager::makeLeaf(int dockIndex) {
    auto leaf = std::make_unique<DockNode>();
    leaf->leaf = true;
    leaf->leafId = nextLeafId_++;
    if (dockIndex >= 0) {
        leaf->docks.push_back(dockIndex);
        leaf->activeDock = dockIndex;
    }
    return leaf;
}

DockManager::DockNode* DockManager::firstLeaf() const {
    DockNode* node = root_.get();
    while (node && !node->leaf) {
        node = node->first ? node->first.get() : node->second.get();
    }
    return node;
}

DockManager::DockNode* DockManager::findLeafById(DockNode* node, int leafId) const {
    if (!node) {
        return nullptr;
    }
    if (node->leaf) {
        return node->leafId == leafId ? node : nullptr;
    }
    if (DockNode* found = findLeafById(node->first.get(), leafId)) {
        return found;
    }
    return findLeafById(node->second.get(), leafId);
}

const DockManager::DockNode* DockManager::findLeafById(const DockNode* node, int leafId) const {
    if (!node) {
        return nullptr;
    }
    if (node->leaf) {
        return node->leafId == leafId ? node : nullptr;
    }
    if (const DockNode* found = findLeafById(node->first.get(), leafId)) {
        return found;
    }
    return findLeafById(node->second.get(), leafId);
}

DockManager::DockNode* DockManager::findLeafContaining(DockNode* node, int dockIndex) const {
    if (!node) {
        return nullptr;
    }
    if (node->leaf) {
        for (int value : node->docks) {
            if (value == dockIndex) {
                return node;
            }
        }
        return nullptr;
    }
    if (DockNode* found = findLeafContaining(node->first.get(), dockIndex)) {
        return found;
    }
    return findLeafContaining(node->second.get(), dockIndex);
}

const DockManager::DockNode* DockManager::findLeafContaining(const DockNode* node, int dockIndex) const {
    if (!node) {
        return nullptr;
    }
    if (node->leaf) {
        for (int value : node->docks) {
            if (value == dockIndex) {
                return node;
            }
        }
        return nullptr;
    }
    if (const DockNode* found = findLeafContaining(node->first.get(), dockIndex)) {
        return found;
    }
    return findLeafContaining(node->second.get(), dockIndex);
}

DockManager::DockNode* DockManager::findLeafAtPoint(DockNode* node, POINT pt) const {
    if (!node || !Contains(node->rect, pt)) {
        return nullptr;
    }
    if (node->leaf) {
        return node;
    }
    if (DockNode* found = findLeafAtPoint(node->first.get(), pt)) {
        return found;
    }
    return findLeafAtPoint(node->second.get(), pt);
}

bool DockManager::removeDockFromNode(DockNode* node, int dockIndex) {
    if (!node) {
        return false;
    }
    if (node->leaf) {
        for (auto it = node->docks.begin(); it != node->docks.end(); ++it) {
            if (*it == dockIndex) {
                node->docks.erase(it);
                if (node->activeDock == dockIndex) {
                    node->activeDock = node->docks.empty() ? -1 : node->docks.front();
                }
                return true;
            }
        }
        return false;
    }
    return removeDockFromNode(node->first.get(), dockIndex) || removeDockFromNode(node->second.get(), dockIndex);
}

bool DockManager::nodeEmpty(const DockNode* node) const {
    if (!node) {
        return true;
    }
    if (node->leaf) {
        return node->docks.empty();
    }
    return nodeEmpty(node->first.get()) && nodeEmpty(node->second.get());
}

void DockManager::collapseEmptySplits(std::unique_ptr<DockNode>& node) {
    if (!node || node->leaf) {
        return;
    }
    collapseEmptySplits(node->first);
    collapseEmptySplits(node->second);
    const bool firstEmpty = nodeEmpty(node->first.get());
    const bool secondEmpty = nodeEmpty(node->second.get());
    if (firstEmpty && !secondEmpty) {
        node = std::move(node->second);
    } else if (!firstEmpty && secondEmpty) {
        node = std::move(node->first);
    } else if (firstEmpty && secondEmpty) {
        node = makeLeaf(-1);
    }
}

DockManager::TabHit DockManager::hitTestTab(int x, int y) const {
    TabHit result{};
    POINT pt{ x, y };
    DockNode* leaf = findLeafAtPoint(root_.get(), pt);
    if (!leaf || !leaf->leaf || !Contains(leaf->tabRect, pt)) {
        return result;
    }
    HDC dc = ::GetDC(hwnd_);
    HGDIOBJ oldFont = ::SelectObject(dc, Ksword::Ui::SystemUIFont());
    int left = leaf->tabRect.left;
    for (int ordinal = 0; ordinal < static_cast<int>(leaf->docks.size()); ++ordinal) {
        const int dockIndex = leaf->docks[ordinal];
        if (dockIndex < 0 || dockIndex >= static_cast<int>(docks_.size())) {
            continue;
        }
        int tabWidth = TabWidthForTitle(dc, docks_[dockIndex]->title());
        tabWidth = MinInt(tabWidth, MaxInt(kTabMinWidth, leaf->tabRect.right - left));
        RECT tab{ left, leaf->tabRect.top, left + tabWidth, leaf->tabRect.bottom };
        if (Contains(tab, pt)) {
            result.valid = true;
            result.leafId = leaf->leafId;
            result.dockIndex = dockIndex;
            result.ordinal = ordinal;
            result.rect = tab;
            break;
        }
        left += tabWidth;
        if (left >= leaf->tabRect.right) {
            break;
        }
    }
    ::SelectObject(dc, oldFont);
    ::ReleaseDC(hwnd_, dc);
    return result;
}

DockManager::DropTarget DockManager::dropTargetFromScreen(POINT screenPoint) const {
    DropTarget result{};
    RECT hostScreen{};
    ::GetWindowRect(hwnd_, &hostScreen);
    if (!Contains(hostScreen, screenPoint)) {
        return result;
    }
    POINT client = screenPoint;
    ::ScreenToClient(hwnd_, &client);
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    result.valid = true;

    // The visible docking guide buttons are the primary hit targets. This makes
    // redocking explicit: center guide buttons target the selected pane, and
    // root guide buttons target the whole dock host.
    DockNode* leaf = findLeafAtPoint(root_.get(), client);
    if (!leaf) {
        leaf = findLeafContaining(root_.get(), activeIndex_);
    }
    if (!leaf) {
        leaf = firstLeaf();
    }
    if (Contains(RootLeftGuide(rc), client)) {
        result.kind = DropKind::RootLeft;
        result.preview = SplitPreview(rc, result.kind);
        return result;
    }
    if (Contains(RootRightGuide(rc), client)) {
        result.kind = DropKind::RootRight;
        result.preview = SplitPreview(rc, result.kind);
        return result;
    }
    if (Contains(RootTopGuide(rc), client)) {
        result.kind = DropKind::RootTop;
        result.preview = SplitPreview(rc, result.kind);
        return result;
    }
    if (Contains(RootBottomGuide(rc), client)) {
        result.kind = DropKind::RootBottom;
        result.preview = SplitPreview(rc, result.kind);
        return result;
    }
    if (leaf) {
        result.leafId = leaf->leafId;
        if (Contains(CenterTabGuide(leaf->rect), client)) {
            result.kind = DropKind::Tab;
            result.preview = SplitPreview(leaf->rect, result.kind);
            return result;
        }
        if (Contains(CenterLeftGuide(leaf->rect), client)) {
            result.kind = DropKind::PaneLeft;
            result.preview = SplitPreview(leaf->rect, result.kind);
            return result;
        }
        if (Contains(CenterRightGuide(leaf->rect), client)) {
            result.kind = DropKind::PaneRight;
            result.preview = SplitPreview(leaf->rect, result.kind);
            return result;
        }
        if (Contains(CenterTopGuide(leaf->rect), client)) {
            result.kind = DropKind::PaneTop;
            result.preview = SplitPreview(leaf->rect, result.kind);
            return result;
        }
        if (Contains(CenterBottomGuide(leaf->rect), client)) {
            result.kind = DropKind::PaneBottom;
            result.preview = SplitPreview(leaf->rect, result.kind);
            return result;
        }
    }

    if (!leaf) {
        result.valid = false;
        return result;
    }
    result.valid = false;
    result.kind = DropKind::None;
    ::SetRectEmpty(&result.preview);
    return result;
}

RECT DockManager::previewRectForTarget(const DropTarget& target) const {
    return target.valid ? target.preview : RECT{};
}

void DockManager::beginTabDrag(const TabHit& hit, POINT screenPoint) {
    pressedTab_ = std::make_unique<TabHit>(hit);
    capturedTab_ = true;
    draggingTab_ = false;
    ignoreCaptureLoss_ = false;
    dragStartScreen_ = screenPoint;
    dragWindowOffset_ = { 96, 18 };
    dragDockIndex_ = hit.dockIndex;
    activeIndex_ = hit.dockIndex;
    if (DockNode* leaf = findLeafById(root_.get(), hit.leafId)) {
        leaf->activeDock = hit.dockIndex;
    }
    ::SetCapture(hwnd_);
    ::SetTimer(hwnd_, kTabDragTimerId, kTabDragTimerMs, nullptr);
    showDropOverlay();
}

void DockManager::updateTabDrag(POINT screenPoint) {
    if (!capturedTab_) {
        return;
    }
    const int dx = screenPoint.x - dragStartScreen_.x;
    const int dy = screenPoint.y - dragStartScreen_.y;
    if (!draggingTab_ && (dx * dx + dy * dy) >= kDragThreshold * kDragThreshold) {
        draggingTab_ = true;
        ignoreCaptureLoss_ = true;
        floatDock(dragDockIndex_, screenPoint, true);
        ::SetCapture(hwnd_);
        ignoreCaptureLoss_ = false;
    }
    if (draggingTab_) {
        moveDraggedFloatingDock(screenPoint);
        setHoverTarget(dropTargetFromScreen(screenPoint));
    }
}

void DockManager::finishTabDrag(POINT screenPoint) {
    if (!capturedTab_) {
        return;
    }
    const bool wasDragging = draggingTab_;
    const int dockIndex = dragDockIndex_;
    if (::GetCapture() == hwnd_) {
        capturedTab_ = false;
        ::ReleaseCapture();
    } else {
        capturedTab_ = false;
    }
    ::KillTimer(hwnd_, kTabDragTimerId);
    const DropTarget target = dropTargetFromScreen(screenPoint);
    const bool docked = wasDragging && moveDockToTarget(dockIndex, target);
    if (!wasDragging) {
        activateDock(dockIndex);
    }
    if (wasDragging && !docked && dockIndex >= 0 && dockIndex < static_cast<int>(docks_.size()) &&
        docks_[dockIndex]->floating()) {
        ::SetWindowPos(docks_[dockIndex]->floatingHost(), HWND_NOTOPMOST, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOOWNERZORDER | SWP_NOACTIVATE);
    }
    draggingTab_ = false;
    ignoreCaptureLoss_ = false;
    dragDockIndex_ = -1;
    pressedTab_.reset();
    hoverTarget_.reset();
    hideDropOverlay();
    if (docked || !wasDragging) {
        layoutChildren();
        ::InvalidateRect(hwnd_, nullptr, TRUE);
    } else {
        ::InvalidateRect(hwnd_, nullptr, FALSE);
    }
    if (docked || !wasDragging) {
        notifyActiveDockChanged();
    }
}

void DockManager::cancelTabDrag() {
    ::KillTimer(hwnd_, kTabDragTimerId);
    capturedTab_ = false;
    draggingTab_ = false;
    ignoreCaptureLoss_ = false;
    dragDockIndex_ = -1;
    pressedTab_.reset();
    hoverTarget_.reset();
    hideDropOverlay();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
}

void DockManager::floatDock(int dockIndex, POINT screenPoint, bool noActivate) {
    if (dockIndex < 0 || dockIndex >= static_cast<int>(docks_.size()) || docks_[dockIndex]->floating()) {
        return;
    }
    const POINT offset = noActivate ? dragWindowOffset_ : POINT{ 96, 18 };
    removeDockFromNode(root_.get(), dockIndex);
    collapseEmptySplits(root_);
    auto floating = std::make_unique<FloatingDock>();
    floating->owner = this;
    floating->dockIndex = dockIndex;
    HWND host = ::CreateWindowExW(WS_EX_TOOLWINDOW, kFloatingClass, docks_[dockIndex]->title().c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        screenPoint.x - offset.x, screenPoint.y - offset.y, kFloatingWidth, kFloatingHeight,
        parent_, nullptr, ::GetModuleHandleW(nullptr), floating.get());
    if (!host) {
        appendDockToLeaf(firstLeaf(), dockIndex);
        return;
    }
    floating->hwnd = host;
    docks_[dockIndex]->setFloatingHost(host);
    HWND child = docks_[dockIndex]->content();
    ::SetParent(child, host);
    ::SetWindowLongPtrW(child, GWL_STYLE, (::GetWindowLongPtrW(child, GWL_STYLE) | WS_CHILD) & ~WS_POPUP);
    RECT rc{};
    ::GetClientRect(host, &rc);
    ::MoveWindow(child, 0, 0, Width(rc), Height(rc), TRUE);
    ::ShowWindow(child, SW_SHOW);
    floatingDocks_.push_back(std::move(floating));
    ::ShowWindow(host, noActivate ? SW_SHOWNOACTIVATE : SW_SHOW);
    ::SetWindowPos(host, noActivate ? HWND_TOPMOST : HWND_TOP, screenPoint.x - offset.x,
        screenPoint.y - offset.y, kFloatingWidth, kFloatingHeight,
        SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    layoutChildren();
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

void DockManager::moveDraggedFloatingDock(POINT screenPoint) {
    if (dragDockIndex_ < 0 || dragDockIndex_ >= static_cast<int>(docks_.size()) || !docks_[dragDockIndex_]->floating()) {
        return;
    }
    HWND host = docks_[dragDockIndex_]->floatingHost();
    if (!host) {
        return;
    }
    ::SetWindowPos(host, nullptr, screenPoint.x - dragWindowOffset_.x, screenPoint.y - dragWindowOffset_.y,
        0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_ASYNCWINDOWPOS);
    showDropOverlay();
}

bool DockManager::setHoverTarget(const DropTarget& target) {
    if (hoverTarget_ && hoverTarget_->valid == target.valid && hoverTarget_->kind == target.kind &&
        hoverTarget_->leafId == target.leafId && ::EqualRect(&hoverTarget_->preview, &target.preview)) {
        return false;
    }
    hoverTarget_ = std::make_unique<DropTarget>(target);
    updateDropOverlay();
    return true;
}

void DockManager::beginFloatingMove(FloatingDock* floating) {
    if (!floating) {
        return;
    }
    floating->moving = true;
    hoverTarget_.reset();
    showDropOverlay();
}

void DockManager::updateFloatingMove(FloatingDock* floating, POINT screenPoint) {
    if (!floating || !floating->moving) {
        return;
    }
    setHoverTarget(dropTargetFromScreen(screenPoint));
}

void DockManager::finishFloatingMove(FloatingDock* floating, POINT screenPoint) {
    if (!floating) {
        return;
    }
    floating->moving = false;
    const DropTarget target = dropTargetFromScreen(screenPoint);
    if (target.valid) {
        moveDockToTarget(floating->dockIndex, target);
    }
    hoverTarget_.reset();
    hideDropOverlay();
    layoutChildren();
    ::InvalidateRect(hwnd_, nullptr, TRUE);
}

void DockManager::destroyFloatingHost(int dockIndex, bool hideContent) {
    if (dockIndex < 0 || dockIndex >= static_cast<int>(docks_.size())) {
        return;
    }
    HWND host = docks_[dockIndex]->floatingHost();
    docks_[dockIndex]->setFloatingHost(nullptr);
    if (HWND child = docks_[dockIndex]->content()) {
        if (hideContent) {
            ::ShowWindow(child, SW_HIDE);
        }
        ::SetParent(child, hwnd_);
        ::SetWindowLongPtrW(child, GWL_STYLE, (::GetWindowLongPtrW(child, GWL_STYLE) | WS_CHILD) & ~WS_POPUP);
    }
    if (host) {
        ::SetWindowLongPtrW(host, GWLP_USERDATA, 0);
        ::DestroyWindow(host);
    }
    for (auto it = floatingDocks_.begin(); it != floatingDocks_.end(); ++it) {
        if ((*it)->dockIndex == dockIndex) {
            floatingDocks_.erase(it);
            break;
        }
    }
}

bool DockManager::moveDockToTarget(int dockIndex, const DropTarget& target) {
    if (!target.valid || dockIndex < 0 || dockIndex >= static_cast<int>(docks_.size())) {
        return false;
    }
    if (docks_[dockIndex]->floating()) {
        destroyFloatingHost(dockIndex, false);
    } else {
        removeDockFromNode(root_.get(), dockIndex);
        collapseEmptySplits(root_);
    }
    bool ok = false;
    if (target.kind == DropKind::Tab) {
        ok = insertDockAsTab(dockIndex, target.leafId);
    } else if (target.kind == DropKind::PaneLeft || target.kind == DropKind::PaneRight ||
        target.kind == DropKind::PaneTop || target.kind == DropKind::PaneBottom) {
        ok = splitLeafWithDock(dockIndex, target.leafId, target.kind);
    } else {
        ok = splitRootWithDock(dockIndex, target.kind);
    }
    if (!ok) {
        appendDockToLeaf(firstLeaf(), dockIndex);
    }
    activeIndex_ = dockIndex;
    notifyActiveDockChanged();
    return true;
}

bool DockManager::insertDockAsTab(int dockIndex, int leafId) {
    DockNode* leaf = findLeafById(root_.get(), leafId);
    if (!leaf) {
        leaf = firstLeaf();
    }
    appendDockToLeaf(leaf, dockIndex);
    return leaf != nullptr;
}

bool DockManager::splitLeafWithDock(int dockIndex, int leafId, DropKind kind) {
    DockNode* leaf = findLeafById(root_.get(), leafId);
    if (!leaf || !leaf->leaf) {
        return false;
    }
    auto oldLeaf = std::make_unique<DockNode>();
    oldLeaf->leaf = true;
    oldLeaf->horizontal = leaf->horizontal;
    oldLeaf->ratio = leaf->ratio;
    oldLeaf->rect = leaf->rect;
    oldLeaf->tabRect = leaf->tabRect;
    oldLeaf->leafId = leaf->leafId;
    oldLeaf->activeDock = leaf->activeDock;
    oldLeaf->docks = leaf->docks;
    auto newLeaf = makeLeaf(dockIndex);
    leaf->leaf = false;
    leaf->horizontal = HorizontalSplit(kind);
    leaf->ratio = 0.5f;
    leaf->leafId = 0;
    leaf->activeDock = -1;
    leaf->docks.clear();
    if (IncomingFirst(kind)) {
        leaf->first = std::move(newLeaf);
        leaf->second = std::move(oldLeaf);
    } else {
        leaf->first = std::move(oldLeaf);
        leaf->second = std::move(newLeaf);
    }
    return true;
}

bool DockManager::splitRootWithDock(int dockIndex, DropKind kind) {
    if (!root_ || nodeEmpty(root_.get())) {
        root_ = makeLeaf(dockIndex);
        return true;
    }
    auto oldRoot = std::move(root_);
    auto newLeaf = makeLeaf(dockIndex);
    auto split = std::make_unique<DockNode>();
    split->leaf = false;
    split->horizontal = HorizontalSplit(kind);
    split->ratio = 0.5f;
    if (IncomingFirst(kind)) {
        split->first = std::move(newLeaf);
        split->second = std::move(oldRoot);
    } else {
        split->first = std::move(oldRoot);
        split->second = std::move(newLeaf);
    }
    root_ = std::move(split);
    return true;
}

void DockManager::appendDockToLeaf(DockNode* leaf, int dockIndex) {
    if (!leaf) {
        root_ = makeLeaf(dockIndex);
        return;
    }
    for (int value : leaf->docks) {
        if (value == dockIndex) {
            leaf->activeDock = dockIndex;
            return;
        }
    }
    leaf->docks.push_back(dockIndex);
    leaf->activeDock = dockIndex;
}

void DockManager::notifyActiveDockChanged() const {
    // notifyActiveDockChanged posts, rather than sends, to keep tab activation
    // cheap and to let lazy module creation happen after the current paint/input
    // message has unwound. Input is the current activeIndex_; there is no
    // synchronous return value.
    if (parent_ && activationChangedMessage_ != 0 && activeIndex_ >= 0) {
        ::PostMessageW(parent_, activationChangedMessage_, static_cast<WPARAM>(activeIndex_), 0);
    }
}

void DockManager::setDockParentToHost(int dockIndex) {
    if (dockIndex < 0 || dockIndex >= static_cast<int>(docks_.size())) {
        return;
    }
    HWND child = docks_[dockIndex]->content();
    if (!child) {
        return;
    }
    docks_[dockIndex]->setFloatingHost(nullptr);
    ::SetParent(child, hwnd_);
    ::SetWindowLongPtrW(child, GWL_STYLE, (::GetWindowLongPtrW(child, GWL_STYLE) | WS_CHILD) & ~WS_POPUP);
}

bool RegisterDockingClasses(HINSTANCE instance) {
    WNDCLASSW host{};
    host.lpfnWndProc = DockManager::HostProc;
    host.hInstance = instance;
    host.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    host.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    host.lpszClassName = kDockManagerClass;
    if (!::RegisterClassW(&host) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW floating{};
    floating.lpfnWndProc = DockManager::FloatingProc;
    floating.hInstance = instance;
    floating.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    floating.hbrBackground = Ksword::Ui::AppTheme().panelBrush();
    floating.lpszClassName = kFloatingClass;
    if (!::RegisterClassW(&floating) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    WNDCLASSW overlay{};
    overlay.lpfnWndProc = DockManager::OverlayProc;
    overlay.hInstance = instance;
    overlay.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    overlay.hbrBackground = reinterpret_cast<HBRUSH>(::GetStockObject(NULL_BRUSH));
    overlay.lpszClassName = kOverlayClass;
    if (!::RegisterClassW(&overlay) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    return true;
}

} // namespace Ksword::Docking
