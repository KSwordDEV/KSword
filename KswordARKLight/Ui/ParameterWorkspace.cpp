#include "ParameterWorkspace.h"
#include "Dpi.h"
#include "Theme.h"
#include <algorithm>
#include <memory>

namespace Ksword::Ui {
namespace {
constexpr wchar_t kViewport[] = L"KswordLight.ParameterViewport"; // 共享参数滚动宿主类。
constexpr wchar_t kBody[] = L"KswordLight.ParameterBody"; // 只转发参数命令的自然高度画布。

struct ScrollState {
    HWND body = nullptr; // 参数正文窗口，跟随滚动偏移。
    int content = 0; // 以当前DPI像素计算的自然高度。
    int position = 0; // 当前垂直位置，最大为content减视口高度。
};

// 更新滚动条及正文几何；输入自然高度来自页面，输出始终不越过有效范围。
void Reflow(HWND viewport, ScrollState& state)
{
    RECT bounds{}; // 去掉滚动条后的可用客户区。
    ::GetClientRect(viewport, &bounds);
    state.position = std::clamp(state.position, 0, (std::max)(0, state.content - static_cast<int>(bounds.bottom)));
    SCROLLINFO info{sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL}; // 固定滚动条宽度避免首帧横向跳动。
    info.nMax = (std::max)(0, state.content - 1);
    info.nPage = static_cast<UINT>((std::max)(0L, bounds.bottom));
    info.nPos = state.position;
    ::SetScrollInfo(viewport, SB_VERT, &info, TRUE);
    ::GetClientRect(viewport, &bounds); // 滚动条出现后重新读取正文宽度。
    ::MoveWindow(state.body, 0, -state.position, bounds.right,
        (std::max)(static_cast<int>(bounds.bottom), state.content), TRUE);
}

// 参数画布只转发真实子控件命令/颜色请求，不接管页面业务与原生输入语义。
LRESULT CALLBACK BodyProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp)
{
    if (message == WM_COMMAND || message == WM_NOTIFY || message == WM_DRAWITEM ||
        message == WM_CTLCOLORSTATIC || message == WM_CTLCOLOREDIT || message == WM_CTLCOLORLISTBOX) {
        return ::SendMessageW(::GetParent(::GetParent(hwnd)), message, wp, lp);
    }
    if (message == WM_MOUSEWHEEL) {
        return ::SendMessageW(::GetParent(hwnd), message, wp, lp);
    }
    if (message == WM_ERASEBKGND) {
        RECT area{}; // 参数画布热换肤直接使用当前主题底色。
        ::GetClientRect(hwnd, &area);
        ::FillRect(reinterpret_cast<HDC>(wp), &area, AppTheme().windowBrush());
        return 1;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}

// 共享视口管理滚动状态；窗口销毁时释放其状态，不访问业务页面对象。
LRESULT CALLBACK ViewportProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp)
{
    auto* state = reinterpret_cast<ScrollState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto next = std::make_unique<ScrollState>(); // 生命周期绑定原生视口。
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(next.release()));
        return TRUE;
    }
    if (!state) {
        return ::DefWindowProcW(hwnd, message, wp, lp);
    }
    switch (message) {
    case WM_SIZE:
        if (state->body) {
            Reflow(hwnd, *state);
        }
        return 0;
    case WM_VSCROLL: {
        SCROLLINFO info{sizeof(info), SIF_ALL}; // 使用32位拖动位置，避免HIWORD截断。
        ::GetScrollInfo(hwnd, SB_VERT, &info);
        switch (LOWORD(wp)) {
        case SB_LINEUP: state->position -= Scale(28); break;
        case SB_LINEDOWN: state->position += Scale(28); break;
        case SB_PAGEUP: state->position -= static_cast<int>(info.nPage); break;
        case SB_PAGEDOWN: state->position += static_cast<int>(info.nPage); break;
        case SB_THUMBTRACK: state->position = info.nTrackPos; break;
        default: break;
        }
        Reflow(hwnd, *state);
        return 0;
    }
    case WM_MOUSEWHEEL:
        state->position -= GET_WHEEL_DELTA_WPARAM(wp) * Scale(84) / WHEEL_DELTA;
        Reflow(hwnd, *state);
        return 0;
    case WM_ERASEBKGND: {
        RECT area{}; // 明确不透明主题底色，不能继承透明画布。
        ::GetClientRect(hwnd, &area);
        ::FillRect(reinterpret_cast<HDC>(wp), &area, AppTheme().windowBrush());
        return 1;
    }
    case WM_NCDESTROY:
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete state;
        break;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}
}

int LayoutParameterActions(std::span<const HWND> controls, int x, int y, int width,
    int preferredWidth, int rowHeight, int gap, bool arrange)
{
    if (controls.empty()) {
        return 0;
    }
    const int available = (std::max)(1, width); // 不通过负宽度把按钮移到视口之外。
    const int count = static_cast<int>(controls.size()); // 当前固定动作数量，不枚举窗口树。
    const int columns = (std::min)(count, (std::max)(1, (available + gap) / (preferredWidth + gap)));
    const int buttonWidth = (std::min)(preferredWidth, (std::max)(1, (available - (columns - 1) * gap) / columns));
    if (arrange) {
        for (int index = 0; index < count; ++index) {
            ::MoveWindow(controls[static_cast<std::size_t>(index)], x + (index % columns) * (buttonWidth + gap),
                y + (index / columns) * (rowHeight + gap), buttonWidth, rowHeight, TRUE);
        }
    }
    const int rows = (count + columns - 1) / columns; // 自然高度只由实际行数决定。
    return rows * rowHeight + (rows - 1) * gap;
}

bool ParameterWorkspace::Create(HWND page)
{
    WNDCLASSW type{}; // 两个共享窗口类型只注册一次。
    type.hInstance = ::GetModuleHandleW(nullptr);
    type.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = AppTheme().windowBrush();
    type.lpszClassName = kViewport;
    type.lpfnWndProc = ViewportProc;
    if (!::RegisterClassW(&type) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    type.lpszClassName = kBody;
    type.lpfnWndProc = BodyProc;
    if (!::RegisterClassW(&type) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    viewport_ = ::CreateWindowExW(WS_EX_CONTROLPARENT, kViewport, L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPCHILDREN,
        0, 0, 1, 1, page, nullptr, type.hInstance, nullptr);
    if (!viewport_) {
        return false; // 视口创建失败时不以空父窗口误建独立参数窗口。
    }
    body_ = ::CreateWindowExW(WS_EX_CONTROLPARENT, kBody, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        0, 0, 1, 1, viewport_, nullptr, type.hInstance, nullptr);
    if (!body_) {
        ::DestroyWindow(viewport_); // 尚无业务控件，仅撤回本次创建的共享宿主。
        viewport_ = nullptr;
        return false;
    }
    auto* state = reinterpret_cast<ScrollState*>(::GetWindowLongPtrW(viewport_, GWLP_USERDATA));
    state->body = body_;
    return true;
}

HWND ParameterWorkspace::Body() const
{
    return body_;
}

void ParameterWorkspace::Layout(int x, int y, int width, int height, int contentHeight) const
{
    auto* state = reinterpret_cast<ScrollState*>(::GetWindowLongPtrW(viewport_, GWLP_USERDATA));
    if (!state || !body_) {
        return; // 创建失败时不访问空视口；页面继续显示已有错误状态。
    }
    state->content = contentHeight; // 自然高度只由参数布局计算，剩余高度交结果。
    ::MoveWindow(viewport_, x, y, (std::max)(1, width), (std::max)(1, height), TRUE);
    Reflow(viewport_, *state);
}

void ParameterWorkspace::Reveal(HWND control) const
{
    if (!::IsChild(body_, control)) {
        return; // 固定动作与结果不属于参数滚动范围。
    }
    RECT field{}, viewport{}; // 把焦点参数的真实窗口范围映射到视口。
    ::GetWindowRect(control, &field);
    ::MapWindowPoints(nullptr, viewport_, reinterpret_cast<POINT*>(&field), 2);
    ::GetClientRect(viewport_, &viewport);
    auto* state = reinterpret_cast<ScrollState*>(::GetWindowLongPtrW(viewport_, GWLP_USERDATA));
    if (!state) {
        return;
    }
    if (field.top < 0) {
        state->position += field.top;
    } else if (field.bottom > viewport.bottom) {
        state->position += field.bottom - viewport.bottom;
    }
    Reflow(viewport_, *state);
}
}
