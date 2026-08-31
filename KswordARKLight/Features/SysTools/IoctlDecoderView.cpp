#include "IoctlDecoderView.h"

#include "IoctlDecoder.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"

#include <algorithm>
#include <memory>
#include <string>

namespace Ksword::Features::SysTools {
namespace {

constexpr wchar_t kIoctlDecoderViewClass[] = L"KswordARKLight.SysTools.IoctlDecoderView";
constexpr int kInputEditId = 67501;
constexpr int kCopyButtonId = 67502;
constexpr int kClearButtonId = 67503;
constexpr int kReportEditId = 67504;
constexpr int kGap = 8;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = 76;
constexpr int kStatusHeight = 22;

struct IoctlDecoderViewState final {
    HWND hwnd = nullptr;
    HWND inputEdit = nullptr;
    HWND copyButton = nullptr;
    HWND clearButton = nullptr;
    HWND reportEdit = nullptr;
    std::wstring reportText;
    std::wstring statusText = L"请输入一个 32 位十六进制 IOCTL 控制码。";
};

int Width(const RECT& rect) {
    return rect.right > rect.left ? static_cast<int>(rect.right - rect.left) : 0;
}

int Height(const RECT& rect) {
    return rect.bottom > rect.top ? static_cast<int>(rect.bottom - rect.top) : 0;
}

std::wstring WindowText(const HWND control) {
    if (!control) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(control);
    if (length <= 0) {
        return {};
    }
    std::wstring value(static_cast<std::size_t>(length) + 1U, L'\0');
    ::GetWindowTextW(control, value.data(), length + 1);
    value.resize(static_cast<std::size_t>(length));
    return value;
}

void ApplyDecode(IoctlDecoderViewState& state) {
    const IoctlDecodedFields decoded = DecodeIoctlCode(WindowText(state.inputEdit));
    switch (decoded.state) {
    case IoctlDecodeState::Empty:
        state.reportText = L"请输入十六进制 IOCTL 控制码。\r\n\r\n例如：0x222004";
        state.statusText = L"请输入一个 32 位十六进制 IOCTL 控制码。";
        break;
    case IoctlDecodeState::Invalid:
        state.reportText = L"输入无效：请输入 1 至 8 位十六进制控制码，可带 0x 前缀。";
        state.statusText = L"输入无效，尚未读取驱动或设备。";
        break;
    case IoctlDecodeState::Valid:
        state.reportText = BuildIoctlDecodedReport(decoded);
        state.statusText = L"已离线解析 " + FormatIoctlCode(decoded.code) + L"；未读取驱动或设备。";
        break;
    default:
        break;
    }
    if (state.reportEdit) {
        ::SetWindowTextW(state.reportEdit, state.reportText.c_str());
    }
    if (state.copyButton) {
        ::EnableWindow(state.copyButton, decoded.state == IoctlDecodeState::Valid ? TRUE : FALSE);
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void LayoutView(IoctlDecoderViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);
    const int inputLeft = kGap + 108;
    const int buttonWidth = 76;
    const int clearLeft = (std::max)(kGap, width - kGap - buttonWidth);
    const int copyLeft = (std::max)(kGap, clearLeft - kGap - buttonWidth);
    const int inputWidth = (std::max)(80, copyLeft - inputLeft - kGap);

    if (state.inputEdit) {
        ::MoveWindow(state.inputEdit, inputLeft, kGap + kRowHeight, inputWidth, kRowHeight, TRUE);
    }
    if (state.copyButton) {
        ::MoveWindow(state.copyButton, copyLeft, kGap + kRowHeight, buttonWidth, kRowHeight, TRUE);
    }
    if (state.clearButton) {
        ::MoveWindow(state.clearButton, clearLeft, kGap + kRowHeight, buttonWidth, kRowHeight, TRUE);
    }
    const int reportTop = kHeaderHeight;
    const int reportHeight = (std::max)(0, height - reportTop - kStatusHeight - kGap);
    if (state.reportEdit) {
        ::MoveWindow(state.reportEdit, kGap, reportTop, (std::max)(0, width - kGap * 2), reportHeight, TRUE);
    }
}

bool CreateChildControls(IoctlDecoderViewState& state) {
    state.inputEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kInputEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.copyButton = Ksword::Ui::CreateButton(state.hwnd, kCopyButtonId, L"复制结果", 0, 0, 0, 0);
    state.clearButton = Ksword::Ui::CreateButton(state.hwnd, kClearButtonId, L"清空", 0, 0, 0, 0);
    state.reportEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kReportEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.inputEdit || !state.copyButton || !state.clearButton || !state.reportEdit) {
        return false;
    }
    ::SendMessageW(state.inputEdit, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    ::SendMessageW(state.reportEdit, WM_SETFONT, reinterpret_cast<WPARAM>(Ksword::Ui::SystemUIFont()), TRUE);
    Ksword::Ui::AttachTextFindSupport(state.reportEdit);
    Ksword::Ui::SetWindowFontRecursive(state.hwnd);
    ApplyDecode(state);
    return true;
}

LRESULT CALLBACK IoctlDecoderViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<IoctlDecoderViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<IoctlDecoderViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state && !CreateChildControls(*state)) {
            return -1;
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        if (LOWORD(wParam) == kInputEditId && HIWORD(wParam) == EN_CHANGE) {
            ApplyDecode(*state);
            return 0;
        }
        if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kCopyButtonId) {
            state->statusText = Ksword::Ui::CopyTextToClipboard(hwnd, state->reportText, L"IOCTL 解码结果")
                ? L"已复制 IOCTL 解码结果，并已记录到证据会话。"
                : L"复制 IOCTL 解码结果失败。";
            ::InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
        }
        if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kClearButtonId) {
            ::SetWindowTextW(state->inputEdit, L"");
            ::SetFocus(state->inputEdit);
            return 0;
        }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, Ksword::Ui::AppTheme().windowBrush());
            RECT descriptionRect{ kGap, kGap, client.right - kGap, kGap + kRowHeight };
            Ksword::Ui::DrawTextLine(dc,
                L"输入 32 位 IOCTL 控制码，离线解析 CTL_CODE 字段与位布局。",
                descriptionRect,
                Ksword::Ui::AppTheme().textColor,
                Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            RECT inputLabelRect{ kGap, kGap + kRowHeight, kGap + 102, kGap + kRowHeight * 2 };
            Ksword::Ui::DrawTextLine(dc,
                L"IOCTL（十六进制）：",
                inputLabelRect,
                Ksword::Ui::AppTheme().textColor,
                Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            Ksword::Ui::DrawTextLine(dc,
                state->statusText,
                statusRect,
                Ksword::Ui::AppTheme().mutedTextColor,
                Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        break;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureIoctlDecoderViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = IoctlDecoderViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kIoctlDecoderViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateIoctlDecoderView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureIoctlDecoderViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(0,
        kIoctlDecoderViewClass,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
}

} // namespace Ksword::Features::SysTools
