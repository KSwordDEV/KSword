#include "LightNativeControlToolbar.h"

#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/ParameterWorkspace.h"
#include "../../Ui/Theme.h"
#include "../../Ui/AsyncTask.h"

#include <algorithm>
#include <commctrl.h>
#include <shellapi.h>
#include <string_view>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {
using Action = LightNativeControlAction;
using Ui::Scale;
constexpr std::size_t kGroupBegin = static_cast<std::size_t>(Action::PauseAll);
constexpr std::size_t kGroupEnd = static_cast<std::size_t>(Action::CloseGroup);
constexpr std::size_t kPause = static_cast<std::size_t>(Action::Pause);
constexpr std::array kWatchOrder{Action::Pause, Action::Continue, Action::StepInto, Action::StepOverCall,
    Action::StepOut, Action::CancelStep, Action::Detach, Action::DumpMemory}; // 视觉/键盘顺序，枚举ID不迁移。
constexpr wchar_t kToolbarClass[] = L"KswordLight.ActionAnalyzeNativeToolbar";
constexpr wchar_t kFloatClass[] = L"KswordLight.ActionAnalyzeNativeToolbarFloat";
constexpr int kFirstAction = 58600, kFloat = 58620, kReturn = 58621;
constexpr std::array<const wchar_t*, kLightNativeControlActions> kLabels{
    L"继续停点", L"步入 Into", L"步过 OverCall", L"跳出 Out", L"取消步进", L"脱离监控",
    L"暂停本集合", L"暂停集合所选", L"继续本集合", L"继续集合所选", L"恢复原继续票据", L"关闭本集合", L"内存转储", L"主动暂停"};
constexpr std::array<const wchar_t*, kLightNativeControlActions> kDescriptions{
    L"继续写入停点页当前完整停点。", L"对当前停点线程步入一条机器指令。",
    L"对当前停点线程越过调用。", L"从当前停点线程的可信调用帧跳出。",
    L"取消写入停点页当前正在运行的原生步进。", L"关闭写入或执行监控，由原所有者清退并脱离。",
    L"暂停本集合全部冻结成员，不作用于整系统。", L"暂停原集合页成员表中全部所选实例。",
    L"使用各成员当前完整停点令牌继续本集合。", L"仅继续原集合页成员表所选且持有完整停点令牌的实例。",
    L"按原集合页当前选择的原Continue票据恢复，不产生新继续票据。", L"由原集合所有者清退本集合。",
    L"相机：按原写入/执行页的内存起点及范围读取当前完整停点，并在同一worker保存本次完整capture到本会话项目raw-memory；缺页保留部分结果，失败不保存旧快照。",
    L"主动暂停原执行owner已经附加且Armed的实例，使用独立pause/N；Pending不等于已停，Preempted保留实际事件。本批ManualPause只提供继续、完整Held内存转储及关闭，不提供步进或执行观测保存。"};
bool GroupAction(Action action) {
    const auto index = static_cast<std::size_t>(action);
    return index >= kGroupBegin && index <= kGroupEnd;
}
}

void LightNativeControlPort::Bind(bool group, const std::shared_ptr<LightNativeControlSource>& source) {
    (group ? group_ : dataWatch_) = source;
    Notify();
}

void LightNativeControlPort::Unbind(bool group, const std::shared_ptr<LightNativeControlSource>& source) {
    auto& slot = group ? group_ : dataWatch_;
    if (slot.lock() == source) slot.reset(); // 旧页迟到销毁不能清除后来绑定的页面。
    Notify();
}

void LightNativeControlPort::Publish(const std::shared_ptr<LightNativeControlSource>& source, LightNativeControlState state) {
    if (!source || source->state == state) return;
    source->state = std::move(state);
    if (dataWatch_.lock() == source || group_.lock() == source) Notify();
}

LightNativeControlState LightNativeControlPort::Read(bool group) const {
    const auto source = (group ? group_ : dataWatch_).lock();
    return source && source->submit ? source->state : LightNativeControlState{};
}

void LightNativeControlPort::Submit(Action action) {
    // 原总览暂停入口优先交给实际附加的执行owner；忙/拒绝都不能再向集合重复派发。
    if (action == Action::PauseAll) {
        const auto execution = dataWatch_.lock();
        if (execution && execution->state.attached) {
            if (!execution->state.canPause || !execution->state.enabled[kPause] || !execution->submit) return;
            const auto submit = execution->submit;
            submit(Action::Pause);
            return;
        }
    }
    const auto index = static_cast<std::size_t>(action);
    if (index >= kLightNativeControlActions) return;
    const auto source = (GroupAction(action) ? group_ : dataWatch_).lock();
    if (!source || !source->state.enabled[index] || !source->submit ||
        (action == Action::DumpMemory && !source->state.canDump) ||
        (action == Action::Pause && !source->state.canPause)) return;
    const auto submit = source->submit; // 同步调用前保留回调值，原页仍须重新核验最新资格。
    submit(action);
}

void LightNativeControlPort::Observe(const std::shared_ptr<std::function<void()>>& observer) {
    observers_.push_back(observer);
}

void LightNativeControlPort::Notify() {
    std::erase_if(observers_, [](const auto& item) { return item.expired(); });
    const auto observers = observers_; // 回调期间允许观察者撤回或页面发布新值。
    for (const auto& item : observers) if (const auto callback = item.lock()) (*callback)();
}

struct LightNativeControlToolbar::Impl {
    HWND overview = nullptr, body = nullptr, floating = nullptr, returnButton = nullptr;
    HWND watchScope = nullptr, groupScope = nullptr, floatButton = nullptr, tooltip = nullptr;
    std::array<HWND, kLightNativeControlActions> buttons{};
    std::array<std::wstring, kLightNativeControlActions> tips;
    HIMAGELIST dumpImages = nullptr; // 相机按钮的系统图标图集，与原工具条宿主一起释放。
    std::wstring watchText, groupText;
    std::shared_ptr<LightNativeControlPort> port;
    std::shared_ptr<std::function<void()>> observer;
    Ui::ParameterWorkspace controls; // 工具条单独承担动作滚动，不包总览结果或API参数。
    int width = 1;
    bool retiring = false, destroying = false;

    std::array<HWND, kLightNativeControlActions + 1> NavigationOrder() const {
        std::array<HWND, kLightNativeControlActions + 1> order{};
        std::size_t at = 0;
        for (const auto action : kWatchOrder) order[at++] = buttons[static_cast<std::size_t>(action)];
        for (std::size_t index = kGroupBegin; index <= kGroupEnd; ++index) order[at++] = buttons[index];
        order.back() = floatButton;
        return order;
    }

    static LRESULT CALLBACK Proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
        auto* self = reinterpret_cast<Impl*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Impl*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return ::DefWindowProcW(hwnd, message, wp, lp);
        switch (message) {
        case WM_COMMAND:
            if (HIWORD(wp) == BN_CLICKED) {
                const int id = LOWORD(wp);
                if (id == kFloat || id == kReturn) self->Toggle();
                else if (!self->retiring && id >= kFirstAction && id < kFirstAction + static_cast<int>(kLightNativeControlActions)) {
                    self->port->Submit(static_cast<Action>(id - kFirstAction));
                    self->Refresh();
                }
                return 0;
            }
            break;
        case WM_SIZE:
            if (hwnd == self->floating && self->body) {
                RECT area{};
                ::GetClientRect(hwnd, &area);
                ::MoveWindow(self->body, 0, 0, area.right, area.bottom, TRUE);
                self->Arrange((std::max)(1L, area.right), (std::max)(1L, area.bottom));
            }
            return 0;
        case WM_CLOSE:
            if (hwnd == self->floating) { self->Dock(); return 0; }
            break;
        case WM_CTLCOLORSTATIC:
            return Ui::PaintLabelBackground(reinterpret_cast<HDC>(wp), reinterpret_cast<HWND>(lp),
                Ui::AppTheme().windowBrush(), Ui::AppTheme().textColor);
        case WM_ERASEBKGND: {
            RECT area{};
            ::GetClientRect(hwnd, &area);
            ::FillRect(reinterpret_cast<HDC>(wp), &area, Ui::AppTheme().windowBrush());
            return 1;
        }
        case WM_NCDESTROY:
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            if (hwnd == self->floating) self->floating = nullptr;
            if (hwnd == self->body) self->body = nullptr;
            break;
        }
        return ::DefWindowProcW(hwnd, message, wp, lp);
    }

    static LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data) {
        auto& self = *reinterpret_cast<Impl*>(data);
        if (message == WM_KEYDOWN && wp == VK_RETURN) {
            if (!(lp & (1LL << 30)) && ::IsWindowEnabled(hwnd)) ::SendMessageW(hwnd, BM_CLICK, 0, 0);
            return 0;
        }
        if (message == WM_KEYDOWN && wp == VK_TAB) {
            if (hwnd == self.returnButton) {
                ::SendMessageW(self.overview, WM_NEXTDLGCTL, (::GetKeyState(VK_SHIFT) & 0x8000) != 0, FALSE);
                return 0;
            }
            const auto order = self.NavigationOrder();
            const int direction = (::GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
            int index = static_cast<int>(std::find(order.begin(), order.end(), hwnd) - order.begin());
            while ((index += direction) >= 0 && index < static_cast<int>(order.size())) {
                if (::IsWindowEnabled(order[static_cast<std::size_t>(index)])) {
                    self.controls.Reveal(order[static_cast<std::size_t>(index)]);
                    ::SetFocus(order[static_cast<std::size_t>(index)]);
                    return 0;
                }
            }
            if (self.floating) {
                HWND first = self.floatButton;
                for (const HWND button : order) if (::IsWindowEnabled(button)) { first = button; break; }
                const HWND next = direction > 0 ? first : self.floatButton;
                self.controls.Reveal(next);
                ::SetFocus(next);
            } else {
                // 将边界Tab交回总览的原导航链，不接管API或结果控件的键盘语义。
                ::SendMessageW(self.overview, WM_NEXTDLGCTL, direction < 0, FALSE);
            }
            return 0;
        }
        if (message == WM_CHAR && (wp == L'\t' || wp == L'\r')) return 0;
        return ::DefSubclassProc(hwnd, message, wp, lp);
    }

    HWND Entry(bool reverse = false) const {
        if (floating) return returnButton;
        if (reverse) return floatButton;
        for (const HWND button : NavigationOrder()) if (::IsWindowEnabled(button)) return button;
        return floatButton;
    }

    // 窄窗动作沿用共享换行，正文状态独立自然高度，表格仍由总览持有滚动。
    int Arrange(int available, int maximumHeight = 0) {
        const int edge = Scale(6), gap = Scale(8), row = Scale(28);
        available = (std::max)(1, available - ::GetSystemMetrics(SM_CXVSCROLL));
        const int inner = (std::max)(1, available - 2 * edge);
        const int toggleWidth = (std::min)(Scale(108), inner);
        const bool narrow = inner < Scale(390);
        ::MoveWindow(watchScope, edge, edge, narrow ? inner : (std::max)(1, inner - toggleWidth - gap), row, TRUE);
        ::MoveWindow(floatButton, narrow ? edge : available - edge - toggleWidth, narrow ? edge + row + gap : edge,
            toggleWidth, row, TRUE);
        const int watchY = edge + (narrow ? 2 : 1) * (row + gap);
        std::array<HWND, kWatchOrder.size()> watchActions{};
        std::transform(kWatchOrder.begin(), kWatchOrder.end(), watchActions.begin(),
            [&](Action action) { return buttons[static_cast<std::size_t>(action)]; });
        const int watchHeight = Ui::LayoutParameterActions(watchActions,
            edge, watchY, inner, Scale(126), row, gap);
        const int groupY = watchY + watchHeight + gap;
        ::MoveWindow(groupScope, edge, groupY, inner, row, TRUE);
        const int groupHeight = Ui::LayoutParameterActions(std::span<const HWND>(buttons.data() + kGroupBegin,
            kGroupEnd - kGroupBegin + 1), edge, groupY + row + gap, inner, Scale(126), row, gap);
        if (tooltip) {
            for (std::size_t index = 0; index < buttons.size(); ++index) {
                TOOLINFOW tool{sizeof(tool)};
                tool.hwnd = controls.Body();
                tool.uId = index + 1; // 禁用按钮的画布提示，与启用按钮的HWND提示分开登记。
                ::GetWindowRect(buttons[index], &tool.rect);
                ::MapWindowPoints(nullptr, controls.Body(), reinterpret_cast<POINT*>(&tool.rect), 2);
                ::SendMessageW(tooltip, TTM_NEWTOOLRECTW, 0, reinterpret_cast<LPARAM>(&tool));
            }
        }
        const int naturalHeight = groupY + row + gap + groupHeight + edge;
        controls.Layout(0, 0, available + ::GetSystemMetrics(SM_CXVSCROLL),
            maximumHeight > 0 ? (std::min)(naturalHeight, maximumHeight) : naturalHeight, naturalHeight);
        return naturalHeight;
    }

    void SetTip(HWND control, std::wstring& storage, std::wstring value, bool add) {
        storage = std::move(value);
        TOOLINFOW tool{sizeof(tool)};
        tool.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
        tool.hwnd = controls.Body();
        tool.uId = reinterpret_cast<UINT_PTR>(control);
        ::GetWindowRect(control, &tool.rect);
        ::MapWindowPoints(nullptr, controls.Body(), reinterpret_cast<POINT*>(&tool.rect), 2);
        tool.lpszText = storage.data();
        ::SendMessageW(tooltip, add ? TTM_ADDTOOLW : TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>(&tool));
        // 启用按钮接收自己的鼠标消息；禁用按钮由画布接收，二者都显示同一份完整范围。
        tool.uFlags = TTF_SUBCLASS;
        tool.uId = static_cast<UINT_PTR>(std::find(buttons.begin(), buttons.end(), control) - buttons.begin()) + 1;
        ::SendMessageW(tooltip, add ? TTM_ADDTOOLW : TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>(&tool));
    }

    void Refresh() {
        if (!body || !port) return;
        const auto watch = port->Read(false), group = port->Read(true);
        const std::wstring nextWatch = watch.scope.empty() ? L"写入停点页：尚未创建或无当前会话" : watch.scope;
        const std::wstring nextGroup = group.scope.empty() ? L"本集合：请先在集合页配置实例" : group.scope;
        if (watchText != nextWatch) { watchText = nextWatch; ::SetWindowTextW(watchScope, watchText.substr(0, watchText.find(L'\r')).c_str()); }
        if (groupText != nextGroup) { groupText = nextGroup; ::SetWindowTextW(groupScope, groupText.substr(0, groupText.find(L'\r')).c_str()); }
        for (std::size_t index = 0; index < buttons.size(); ++index) {
            const bool preferExecution = static_cast<Action>(index) == Action::PauseAll && watch.attached;
            const bool isGroup = GroupAction(static_cast<Action>(index)) && !preferExecution;
            const auto& state = isGroup ? group : watch;
            const bool dump = static_cast<Action>(index) == Action::DumpMemory;
            const bool pause = static_cast<Action>(index) == Action::Pause || preferExecution;
            const bool enabled = !retiring && state.enabled[preferExecution ? kPause : index] &&
                (!dump || state.canDump) && (!pause || state.canPause);
            if (::IsWindowEnabled(buttons[index]) != static_cast<BOOL>(enabled)) ::EnableWindow(buttons[index], enabled);
            if (static_cast<Action>(index) == Action::PauseAll) {
                const auto label = preferExecution ? L"暂停本端会话" : kLabels[index];
                wchar_t current[64]{};
                ::GetWindowTextW(buttons[index], current, static_cast<int>(std::size(current)));
                if (std::wstring_view(current) != label) ::SetWindowTextW(buttons[index], label);
            }
            std::wstring tip = kDescriptions[preferExecution ? kPause : index];
            tip += L"\r\n" + (isGroup ? nextGroup : nextWatch);
            if (dump) tip += L"\r\n" + (watch.dumpHint.empty() ? L"需要原写入/执行页本会话项目、完整停点及有效内存范围。" : watch.dumpHint);
            if (pause) tip += L"\r\n" + (watch.pauseHint.empty() ? L"需要已实际附加的原Armed绑定，无Held、运行中步进或恢复责任。" : watch.pauseHint);
            if (static_cast<Action>(index) == Action::PauseAll) tip += preferExecution
                ? L"\r\n原执行owner实际attached，本入口只交原owner；不可执行时不回退集合。"
                : L"\r\n无实际附加的执行owner，本入口沿用原ProcessGroup全部成员暂停。";
            tip += isGroup ? L"\r\n范围来自原集合页，不随总览历史选区改变；所选来自原成员表。" :
                L"\r\n仅作用于写入停点页本端会话，不随总览历史选区改变。";
            if (!enabled) tip += L"\r\n当前不可执行：请核对原页会话、完整停点或在途操作；点击时仍由原页再次核验。";
            if (tips[index] != tip) SetTip(buttons[index], tips[index], std::move(tip), tips[index].empty());
        }
    }

    void RelayoutOverview() { ::SendMessageW(overview, WM_SIZE, 0, 0); }

    void Dock() {
        if (!floating || destroying) return;
        const HWND old = floating;
        const bool returnFocus = ::GetFocus() == returnButton || ::IsChild(body, ::GetFocus());
        ::SetParent(body, overview); // 移回原控件宿主，按钮与Proc不变。
        ::SetWindowTextW(floatButton, L"浮出工具条");
        ::ShowWindow(returnButton, SW_HIDE);
        ::DestroyWindow(old);
        floating = nullptr;
        RelayoutOverview();
        if (returnFocus) { controls.Reveal(floatButton); ::SetFocus(floatButton); }
    }

    void Toggle() {
        if (retiring) return;
        if (floating) { Dock(); return; }
        RECT origin{};
        ::GetWindowRect(body, &origin);
        MONITORINFO monitor{sizeof(monitor)};
        if (!::GetMonitorInfoW(::MonitorFromWindow(overview, MONITOR_DEFAULTTONEAREST), &monitor)) return;
        const int workWidth = monitor.rcWork.right - monitor.rcWork.left;
        const int workHeight = monitor.rcWork.bottom - monitor.rcWork.top;
        const int floatWidth = (std::max)(1, (std::min)(Scale(850), workWidth - Scale(32)));
        const int floatHeight = Arrange(floatWidth);
        RECT bounds{0, 0, floatWidth, floatHeight};
        constexpr DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME;
        ::AdjustWindowRectEx(&bounds, style, FALSE, WS_EX_TOOLWINDOW);
        const int windowWidth = (std::min)(static_cast<int>(bounds.right - bounds.left), workWidth);
        const int windowHeight = (std::min)(static_cast<int>(bounds.bottom - bounds.top), workHeight);
        const int left = std::clamp(static_cast<int>(origin.left), static_cast<int>(monitor.rcWork.left),
            static_cast<int>(monitor.rcWork.right) - windowWidth);
        const int top = std::clamp(static_cast<int>(origin.top), static_cast<int>(monitor.rcWork.top),
            static_cast<int>(monitor.rcWork.bottom) - windowHeight);
        floating = ::CreateWindowExW(WS_EX_TOOLWINDOW, kFloatClass, L"行为分析 · 本端实时调试", style,
            left, top, windowWidth, windowHeight,
            ::GetAncestor(overview, GA_ROOT), nullptr, ::GetModuleHandleW(nullptr), this);
        if (!floating) { Arrange(width); return; }
        ::SetParent(body, floating);
        RECT area{};
        ::GetClientRect(floating, &area);
        ::MoveWindow(body, 0, 0, area.right, area.bottom, TRUE);
        Arrange(area.right, area.bottom);
        ::SetWindowTextW(floatButton, L"收回工具条");
        ::ShowWindow(returnButton, SW_SHOWNA);
        ::ShowWindow(floating, SW_SHOWNOACTIVATE);
        RelayoutOverview();
    }
};

LightNativeControlToolbar::LightNativeControlToolbar() : impl_(std::make_unique<Impl>()) {}
LightNativeControlToolbar::~LightNativeControlToolbar() { Destroy(); }

bool LightNativeControlToolbar::Create(HWND overview, std::shared_ptr<LightNativeControlPort> port) {
    auto& self = *impl_;
    self.overview = overview;
    self.port = std::move(port);
    if (!self.port) return false;
    WNDCLASSW type{};
    type.lpfnWndProc = Impl::Proc;
    type.hInstance = ::GetModuleHandleW(nullptr);
    type.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = Ui::AppTheme().windowBrush();
    for (const auto name : {kToolbarClass, kFloatClass}) {
        type.lpszClassName = name;
        if (!::RegisterClassW(&type) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
    }
    self.body = ::CreateWindowExW(WS_EX_CONTROLPARENT, kToolbarClass, L"本端实时调试", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        0, 0, 1, 1, overview, nullptr, type.hInstance, &self);
    if (!self.body) return false;
    if (!self.controls.Create(self.body)) return false;
    self.watchScope = Ui::CreateText(self.controls.Body(), 0, L"", 0, 0, 1, 1);
    self.groupScope = Ui::CreateText(self.controls.Body(), 0, L"", 0, 0, 1, 1);
    self.floatButton = Ui::CreateButton(self.controls.Body(), kFloat, L"浮出工具条", 0, 0, 1, 1);
    self.returnButton = Ui::CreateButton(overview, kReturn, L"收回调试工具条", 0, 0, 1, 1);
    if (!self.watchScope || !self.groupScope || !self.floatButton || !self.returnButton) return false;
    for (const HWND label : {self.watchScope, self.groupScope}) {
        const auto style = ::GetWindowLongPtrW(label, GWL_STYLE);
        ::SetWindowLongPtrW(label, GWL_STYLE, (style & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFTNOWORDWRAP | SS_ENDELLIPSIS);
    }
    ::ShowWindow(self.returnButton, SW_HIDE);
    for (std::size_t index = 0; index < self.buttons.size(); ++index) {
        self.buttons[index] = Ui::CreateButton(self.controls.Body(), kFirstAction + static_cast<int>(index), kLabels[index], 0, 0, 1, 1);
        if (!self.buttons[index] || !::SetWindowSubclass(self.buttons[index], Impl::Navigate, 1, reinterpret_cast<DWORD_PTR>(&self))) return false;
    }
    // 系统相机图形附于原按钮，文字及提示保留；不创建第二套动作宿主。
    SHSTOCKICONINFO camera{};
    camera.cbSize = sizeof(camera);
    if (SUCCEEDED(::SHGetStockIconInfo(SIID_DEVICECAMERA, SHGSI_ICON | SHGSI_SMALLICON, &camera))) {
        self.dumpImages = ::ImageList_Create(Scale(16), Scale(16), ILC_COLOR32 | ILC_MASK, 1, 0);
        if (self.dumpImages && ::ImageList_AddIcon(self.dumpImages, camera.hIcon) >= 0) {
            BUTTON_IMAGELIST images{};
            images.himl = self.dumpImages;
            images.margin = {Scale(6), 0, Scale(4), 0};
            images.uAlign = BUTTON_IMAGELIST_ALIGN_LEFT;
            ::SendMessageW(self.buttons[static_cast<std::size_t>(Action::DumpMemory)], BCM_SETIMAGELIST, 0,
                reinterpret_cast<LPARAM>(&images));
        }
        ::DestroyIcon(camera.hIcon);
    }
    if (!::SetWindowSubclass(self.floatButton, Impl::Navigate, 1, reinterpret_cast<DWORD_PTR>(&self))) return false;
    if (!::SetWindowSubclass(self.returnButton, Impl::Navigate, 1, reinterpret_cast<DWORD_PTR>(&self))) return false;
    self.tooltip = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, self.body, nullptr, type.hInstance, nullptr);
    if (!self.tooltip) return false;
    ::SendMessageW(self.tooltip, TTM_SETMAXTIPWIDTH, 0, Scale(560));
    self.observer = std::make_shared<std::function<void()>>([&self] { self.Refresh(); });
    self.port->Observe(self.observer);
    Ui::SetWindowFontRecursive(self.body);
    self.Refresh();
    return true;
}

int LightNativeControlToolbar::Layout(int x, int y, int width, int maximumHeight) {
    auto& self = *impl_;
    self.width = width;
    if (self.floating) {
        ::MoveWindow(self.returnButton, x, y, (std::min)(Scale(180), width), Scale(28), TRUE);
        return Scale(28);
    }
    const int height = (std::min)(self.Arrange(width, maximumHeight), (std::max)(1, maximumHeight));
    ::MoveWindow(self.body, x, y, width, height, TRUE);
    return height;
}

void LightNativeControlToolbar::Destroy() {
    auto& self = *impl_;
    self.destroying = true;
    self.observer.reset(); // 先断开UI回调，再销毁浮窗或页面，拒绝后续发布触及旧控件。
    if (self.tooltip) ::DestroyWindow(self.tooltip);
    if (self.floating) ::DestroyWindow(self.floating);
    if (::IsWindow(self.body)) ::DestroyWindow(self.body);
    if (::IsWindow(self.returnButton)) ::DestroyWindow(self.returnButton);
    if (self.dumpImages) ::ImageList_Destroy(self.dumpImages);
    self.dumpImages = nullptr;
    self.tooltip = self.floating = self.body = self.returnButton = nullptr;
    self.port.reset();
}

void LightNativeControlToolbar::SetRetiring(bool retiring) { impl_->retiring = retiring; impl_->Refresh(); }
HWND LightNativeControlToolbar::Entry(bool reverse) const {
    const HWND entry = impl_->Entry(reverse);
    impl_->controls.Reveal(entry);
    return entry;
}
bool LightNativeControlToolbar::HandleCommand(WPARAM command) {
    if (LOWORD(command) != kReturn || HIWORD(command) != BN_CLICKED) return false;
    impl_->Toggle();
    return true;
}

namespace {
constexpr wchar_t kOverviewClass[] = L"KswordLight.ActionAnalyzeControlOverview";
struct Overview {
    HWND hwnd = nullptr, content = nullptr;
    LightNativeControlToolbar toolbar;
    std::shared_ptr<LightNativeControlPort> port;
    std::function<HWND(HWND, const RECT&)> createContent;
};

void LayoutOverview(Overview& page) {
    RECT area{};
    ::GetClientRect(page.hwnd, &area);
    if (!page.content) return; // 创建阶段不访问尚未创建的工具条控件。
    const int edge = Scale(6), gap = Scale(8);
    const int budget = (std::max)(1L, (std::min)(static_cast<LONG>(Scale(180)), area.bottom / 3));
    const int height = page.toolbar.Layout(edge, edge, (std::max)(1L, area.right - 2 * edge), budget);
    ::MoveWindow(page.content, 0, edge + height + gap, (std::max)(1L, area.right),
        (std::max)(1L, area.bottom - edge - height - gap), TRUE);
}

LRESULT CALLBACK OverviewProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* page = reinterpret_cast<Overview*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* input = static_cast<Overview*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        auto owned = std::make_unique<Overview>();
        owned->hwnd = hwnd;
        owned->port = input->port;
        owned->createContent = input->createContent;
        page = owned.release();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
    }
    if (!page) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_CREATE: {
        if (!page->toolbar.Create(hwnd, page->port)) return -1;
        const RECT initial{0, 0, 1, 1};
        page->content = page->createContent(hwnd, initial);
        if (!page->content) return -1;
        ::ShowWindow(page->content, SW_SHOWNA);
        LayoutOverview(*page);
        return 0;
    }
    case WM_SIZE: LayoutOverview(*page); return 0;
    case WM_COMMAND: if (page->toolbar.HandleCommand(wp)) return 0; break;
    case kFocusLightNativeToolbar:
        if (const HWND entry = page->toolbar.Entry(wp != 0); entry && ::IsWindowEnabled(entry)) { ::SetFocus(entry); return 1; }
        return 0;
    case WM_NEXTDLGCTL:
        if (page->content) {
            const HWND next = ::GetNextDlgTabItem(page->content, nullptr, wp != 0);
            if (next) ::SetFocus(next);
        }
        return 0;
    case Ui::kBeginNativeRetirementMessage: page->toolbar.SetRetiring(true); return 0;
    case Ui::kCancelNativeRetirementMessage: page->toolbar.SetRetiring(false); return 0;
    case WM_ERASEBKGND: {
        RECT area{};
        ::GetClientRect(hwnd, &area);
        ::FillRect(reinterpret_cast<HDC>(wp), &area, Ui::AppTheme().windowBrush());
        return 1;
    }
    case WM_DESTROY: page->toolbar.Destroy(); return 0;
    case WM_NCDESTROY:
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete page;
        return 0;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}
}

HWND CreateLightNativeControlOverview(HWND parent, const RECT& bounds, std::shared_ptr<LightNativeControlPort> port,
    std::function<HWND(HWND, const RECT&)> createContent) {
    WNDCLASSW type{};
    type.lpfnWndProc = OverviewProc;
    type.hInstance = ::GetModuleHandleW(nullptr);
    type.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = Ui::AppTheme().windowBrush();
    type.lpszClassName = kOverviewClass;
    if (!::RegisterClassW(&type) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    Overview input;
    input.port = std::move(port);
    input.createContent = std::move(createContent);
    return ::CreateWindowExW(WS_EX_CONTROLPARENT, kOverviewClass, L"行为分析总览", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, parent, nullptr, type.hInstance, &input);
}

} // namespace Ksword::Features::ActionAnalyze
