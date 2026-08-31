#include "MemoryFeature.h"

#include "DriverMemoryView.h"
#include "../../Ui/Theme.h"

namespace Ksword::Features::Memory {
namespace {

constexpr wchar_t kMemoryHostClass[] = L"KswordARKLight.MemoryFeaturePage";

struct MemoryFeaturePageState {
    HWND hwnd = nullptr;
    HWND driverMemoryView = nullptr;
};

MemoryFeaturePageState* StateFromWindow(HWND hwnd) {
    return reinterpret_cast<MemoryFeaturePageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int Width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

void LayoutChildren(MemoryFeaturePageState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    if (state.driverMemoryView) {
        ::MoveWindow(state.driverMemoryView, 0, 0, Width(rc), Height(rc), TRUE);
    }
}

bool RegisterMemoryFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) -> LRESULT {
        MemoryFeaturePageState* state = StateFromWindow(hwnd);
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            state = create ? static_cast<MemoryFeaturePageState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }
        switch (message) {
        case WM_CREATE: {
            if (!state) {
                return -1;
            }
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            state->driverMemoryView = CreateDriverMemoryView(hwnd, rc);
            if (!state->driverMemoryView) {
                return -1;
            }
            LayoutChildren(*state);
            return 0;
        }
        case WM_SIZE:
            if (state) {
                LayoutChildren(*state);
            }
            return 0;
        case WM_NCDESTROY:
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, message, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.lpszClassName = kMemoryHostClass;
    registered = ::RegisterClassW(&wc) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateMemoryFeaturePage(HWND parent, const RECT& bounds) {
    if (!parent || !RegisterMemoryFeatureClass()) {
        return nullptr;
    }
    auto* state = new MemoryFeaturePageState();
    HWND hwnd = ::CreateWindowExW(0, kMemoryHostClass, L"内存",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, Width(bounds), Height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

bool RequestMemoryFeatureProcess(HWND page, const DWORD processId) {
    if (!page || processId == 0U) {
        return false;
    }
    MemoryFeaturePageState* state = StateFromWindow(page);
    return state != nullptr && state->driverMemoryView != nullptr &&
        RequestDriverMemoryViewProcess(state->driverMemoryView, processId);
}

} // namespace Ksword::Features::Memory
