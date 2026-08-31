#include "ProcessDetailPage.h"

#include "ProcessDetailCollector.h"

#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <limits>
#include <sstream>
#include <utility>

namespace Ksword::Features::ProcessDetail {
namespace {

constexpr wchar_t kProcessDetailPageClass[] = L"KswordARKLight.ProcessDetailPage.FullWin32";
constexpr int kRootMargin = 8;
constexpr UINT kCopyCellCommand = 64001;
constexpr UINT kCopyRowCommand = 64002;
constexpr UINT kCopyAllCommand = 64003;
constexpr UINT kMsgSnapshotCompleted = WM_APP + 610;
constexpr UINT kMsgThreadFilterCompleted = WM_APP + 611;
constexpr UINT kMsgModuleFilterCompleted = WM_APP + 612;
constexpr UINT kMsgActionCompleted = WM_APP + 613;
constexpr UINT kMsgTokenReportCompleted = WM_APP + 614;
constexpr UINT kMsgTokenSwitchCompleted = WM_APP + 615;
constexpr UINT kMsgEvidenceCompleted = WM_APP + 616;
constexpr UINT kMsgPebCompleted = WM_APP + 617;
constexpr UINT kMsgHotkeyCompleted = WM_APP + 618;
constexpr UINT kMsgKeyboardCompleted = WM_APP + 619;
constexpr int kSnapshotLoadingOverlayId = 1110;

constexpr std::array<const wchar_t*, 10> kTabTitles{
    L"详细信息",
    L"线程",
    L"操作",
    L"模块",
    L"令牌",
    L"令牌开关",
    L"Process Detail Evidence",
    L"进程热键",
    L"键盘",
    L"PEB"
};

int RectWidth(const RECT& rect) {
    return std::max(0L, rect.right - rect.left);
}

int RectHeight(const RECT& rect) {
    return std::max(0L, rect.bottom - rect.top);
}

bool RegisterPageClass() {
    WNDCLASSW wc{};
    wc.lpfnWndProc = ProcessDetailPage::WindowProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.lpszClassName = kProcessDetailPageClass;
    if (::RegisterClassW(&wc)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

HFONT CreateTitleFont() {
    LOGFONTW font{};
    HFONT base = Ksword::Ui::SystemUIFont();
    if (base) {
        ::GetObjectW(base, sizeof(font), &font);
    }
    if (font.lfHeight == 0) {
        font.lfHeight = -18;
        wcscpy_s(font.lfFaceName, L"Segoe UI");
    } else {
        font.lfHeight = static_cast<LONG>(font.lfHeight * 1.35);
    }
    font.lfWeight = FW_BOLD;
    return ::CreateFontIndirectW(&font);
}

void InsertTab(HWND tab, int index, const wchar_t* title) {
    TCITEMW item{};
    item.mask = TCIF_TEXT;
    item.pszText = const_cast<LPWSTR>(title);
    ::SendMessageW(tab, TCM_INSERTITEMW, static_cast<WPARAM>(index), reinterpret_cast<LPARAM>(&item));
}

} // namespace

ProcessDetailPage::ProcessDetailPage(
    DWORD processId,
    ULONGLONG expectedCreationTime100ns)
    : processId_(processId),
      expectedCreationTime100ns_(expectedCreationTime100ns) {}

ProcessDetailPage::~ProcessDetailPage() {
    if (snapshotTask_) {
        snapshotTask_->cancel();
    }
    if (actionTask_) {
        actionTask_->cancel();
    }
    if (tokenReportTask_) {
        tokenReportTask_->cancel();
    }
    if (tokenSwitchTask_) {
        tokenSwitchTask_->cancel();
    }
    if (evidenceTask_) {
        evidenceTask_->cancel();
    }
    if (pebTask_) {
        pebTask_->cancel();
    }
    if (hotkeyTask_) {
        hotkeyTask_->cancel();
    }
    if (keyboardTask_) {
        keyboardTask_->cancel();
    }
    if (threadFilterTask_) {
        threadFilterTask_->cancel();
    }
    if (moduleFilterTask_) {
        moduleFilterTask_->cancel();
    }
    if (titleFont_) {
        ::DeleteObject(titleFont_);
        titleFont_ = nullptr;
    }
}

HWND ProcessDetailPage::Create(
    HWND parent,
    DWORD processId,
    ULONGLONG expectedCreationTime100ns,
    const RECT& bounds) {
    if (!RegisterPageClass()) {
        return nullptr;
    }
    auto* page = new ProcessDetailPage(processId, expectedCreationTime100ns);
    HWND hwnd = ::CreateWindowExW(
        0,
        kProcessDetailPageClass,
        L"Process Detail",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        RectWidth(bounds),
        RectHeight(bounds),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        page);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

LRESULT CALLBACK ProcessDetailPage::WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* page = reinterpret_cast<ProcessDetailPage*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        page = create ? static_cast<ProcessDetailPage*>(create->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
        if (page) {
            page->hwnd_ = hwnd;
        }
    }
    return page ? page->HandleMessage(hwnd, message, wParam, lParam)
                : ::DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT ProcessDetailPage::HandleMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        return Initialize(hwnd) ? 0 : -1;
    case WM_SIZE:
        Layout();
        return 0;
    case kMsgSnapshotCompleted:
        if (snapshotTask_ && snapshotTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgActionCompleted:
        if (actionTask_ && actionTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgTokenReportCompleted:
        if (tokenReportTask_ && tokenReportTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgTokenSwitchCompleted:
        if (tokenSwitchTask_ && tokenSwitchTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgEvidenceCompleted:
        if (evidenceTask_ && evidenceTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgPebCompleted:
        if (pebTask_ && pebTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgHotkeyCompleted:
        if (hotkeyTask_ && hotkeyTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgKeyboardCompleted:
        if (keyboardTask_ && keyboardTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgThreadFilterCompleted:
        if (threadFilterTask_ && threadFilterTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgModuleFilterCompleted:
        if (moduleFilterTask_ && moduleFilterTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (auto* header = reinterpret_cast<NMHDR*>(lParam);
            header && header->hwndFrom == tab_ && header->code == TCN_SELCHANGE) {
            UpdateVisiblePage();
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    case WM_NCDESTROY:
        if (snapshotTask_) {
            snapshotTask_->cancel();
        }
        if (actionTask_) {
            actionTask_->cancel();
        }
        if (tokenReportTask_) {
            tokenReportTask_->cancel();
        }
        if (tokenSwitchTask_) {
            tokenSwitchTask_->cancel();
        }
        if (evidenceTask_) {
            evidenceTask_->cancel();
        }
        if (pebTask_) {
            pebTask_->cancel();
        }
        if (hotkeyTask_) {
            hotkeyTask_->cancel();
        }
        if (keyboardTask_) {
            keyboardTask_->cancel();
        }
        if (threadFilterTask_) {
            threadFilterTask_->cancel();
        }
        if (moduleFilterTask_) {
            moduleFilterTask_->cancel();
        }
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete this;
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool ProcessDetailPage::Initialize(HWND hwnd) {
    hwnd_ = hwnd;
    titleFont_ = CreateTitleFont();
    tab_ = ::CreateWindowExW(
        0,
        WC_TABCONTROLW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | WS_TABSTOP,
        kRootMargin,
        kRootMargin,
        400,
        300,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(TabControl)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ApplyFont(tab_);
    if (!tab_) {
        return false;
    }
    if (kTabTitles.size() != static_cast<std::size_t>(TabIndex::Count)) {
        return false;
    }
    for (int index = 0; index < static_cast<int>(kTabTitles.size()); ++index) {
        InsertTab(tab_, index, kTabTitles[static_cast<std::size_t>(index)]);
    }

    loadingOverlay_ = Ksword::Ui::CreateLoadingOverlay(hwnd_, kSnapshotLoadingOverlayId, { 0, 0, 1, 1 });
    snapshotTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessDetailSnapshot>>(hwnd_, kMsgSnapshotCompleted);
    actionTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessDetailActionResult>>(hwnd_, kMsgActionCompleted);
    tokenReportTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessTokenReportSnapshot>>(hwnd_, kMsgTokenReportCompleted);
    tokenSwitchTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessTokenSwitchSnapshot>>(hwnd_, kMsgTokenSwitchCompleted);
    evidenceTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessDetailSnapshot>>(hwnd_, kMsgEvidenceCompleted);
    pebTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessPebSnapshot>>(hwnd_, kMsgPebCompleted);
    hotkeyTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<ProcessHotkeySnapshot>>(hwnd_, kMsgHotkeyCompleted);
    keyboardTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<KeyboardSnapshot>>(hwnd_, kMsgKeyboardCompleted);
    threadFilterTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<DetailTableFilterResult>>(hwnd_, kMsgThreadFilterCompleted);
    moduleFilterTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<DetailTableFilterResult>>(hwnd_, kMsgModuleFilterCompleted);
    if (!loadingOverlay_ || !snapshotTask_ || !actionTask_ || !tokenReportTask_ || !tokenSwitchTask_ || !evidenceTask_ || !pebTask_ || !hotkeyTask_ || !keyboardTask_ || !threadFilterTask_ || !moduleFilterTask_) {
        return false;
    }
    ::SendMessageW(tab_, TCM_SETCURSEL, 0, 0);
    UpdateVisiblePage();
    BeginSnapshotRefresh();
    return true;
}

LRESULT CALLBACK ProcessDetailPage::PageSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    auto* page = reinterpret_cast<ProcessDetailPage*>(referenceData);
    if (!page || subclassId == 0 || subclassId > static_cast<UINT_PTR>(TabIndex::Count)) {
        return ::DefSubclassProc(hwnd, message, wParam, lParam);
    }
    const TabIndex tab = static_cast<TabIndex>(subclassId - 1);
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, PageSubclassProc, subclassId);
    }
    return page->HandlePageMessage(tab, hwnd, message, wParam, lParam);
}

LRESULT ProcessDetailPage::HandlePageMessage(
    TabIndex tab,
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam) {
    switch (message) {
    case WM_SIZE:
        LayoutPage(tab);
        return 0;
    case WM_COMMAND: {
        const int id = LOWORD(wParam);
        bool handled = false;
        switch (tab) {
        case TabIndex::Detail: handled = HandleDetailCommand(id); break;
        case TabIndex::Threads: handled = HandleThreadCommand(id); break;
        case TabIndex::Actions: handled = HandleActionCommand(id); break;
        case TabIndex::Modules: handled = HandleModuleCommand(id); break;
        case TabIndex::Token: handled = HandleTokenCommand(id); break;
        case TabIndex::TokenSwitch: handled = HandleTokenSwitchCommand(id); break;
        case TabIndex::Evidence: handled = HandleEvidenceCommand(id); break;
        case TabIndex::Hotkey: handled = HandleHotkeyCommand(id); break;
        case TabIndex::Keyboard: handled = HandleKeyboardCommand(id); break;
        case TabIndex::Peb: handled = HandlePebCommand(id); break;
        default: break;
        }
        if (handled) {
            return 0;
        }
        break;
    }
    case WM_NOTIFY: {
        LRESULT result = 0;
        if (HandlePageNotify(tab, reinterpret_cast<NMHDR*>(lParam), result)) {
            return result;
        }
        break;
    }
    case WM_CONTEXTMENU: {
        POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        HWND source = reinterpret_cast<HWND>(wParam);
        if (point.x == -1 && point.y == -1 && source) {
            RECT sourceRect{};
            ::GetWindowRect(source, &sourceRect);
            point = { sourceRect.left + 24, sourceRect.top + 24 };
        }
        if (HandleGenericContextMenu(source, point)) {
            return 0;
        }
        break;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    default:
        break;
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

void ProcessDetailPage::Layout() {
    if (!hwnd_ || !tab_) {
        return;
    }
    RECT client{};
    ::GetClientRect(hwnd_, &client);
    const int width = std::max(0, RectWidth(client) - kRootMargin * 2);
    const int height = std::max(0, RectHeight(client) - kRootMargin * 2);
    ::MoveWindow(tab_, kRootMargin, kRootMargin, width, height, TRUE);

    RECT pageRect{};
    ::GetClientRect(tab_, &pageRect);
    ::SendMessageW(tab_, TCM_ADJUSTRECT, FALSE, reinterpret_cast<LPARAM>(&pageRect));
    for (std::size_t index = 0; index < pages_.size(); ++index) {
        HWND page = pages_[index].hwnd;
        if (page) {
            ::MoveWindow(page, pageRect.left, pageRect.top, RectWidth(pageRect), RectHeight(pageRect), TRUE);
            LayoutPage(static_cast<TabIndex>(index));
        }
    }
    if (loadingOverlay_) {
        ::MoveWindow(loadingOverlay_, 0, 0, RectWidth(client), RectHeight(client), TRUE);
    }
}

void ProcessDetailPage::LayoutPage(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    if (!page.hwnd) {
        return;
    }
    RECT client{};
    ::GetClientRect(page.hwnd, &client);
    HDWP deferred = ::BeginDeferWindowPos(static_cast<int>(page.placements.size()));
    for (const Placement& placement : page.placements) {
        if (!placement.hwnd) {
            continue;
        }
        const int x = placement.x < 0 ? std::max(0, RectWidth(client) + placement.x) : placement.x;
        const int y = placement.y < 0 ? std::max(0, RectHeight(client) + placement.y) : placement.y;
        const int width = placement.width < 0
            ? std::max(0, RectWidth(client) - x + placement.width)
            : placement.width;
        const int height = placement.height < 0
            ? std::max(0, RectHeight(client) - y + placement.height)
            : placement.height;
        if (deferred) {
            deferred = ::DeferWindowPos(
                deferred,
                placement.hwnd,
                nullptr,
                x,
                y,
                width,
                height,
                SWP_NOZORDER | SWP_NOACTIVATE);
        } else {
            ::MoveWindow(placement.hwnd, x, y, width, height, TRUE);
        }
    }
    if (deferred) {
        ::EndDeferWindowPos(deferred);
    }
}

void ProcessDetailPage::UpdateVisiblePage() {
    int selected = static_cast<int>(::SendMessageW(tab_, TCM_GETCURSEL, 0, 0));
    if (selected < 0 || selected >= static_cast<int>(TabIndex::Count)) {
        selected = 0;
    }

    const TabIndex selectedTab = static_cast<TabIndex>(selected);
    if (currentTab_ != selectedTab && currentTab_ != TabIndex::Count) {
        DestroyPageHost(currentTab_);
    }
    currentTab_ = selectedTab;

    if (!EnsurePage(selectedTab)) {
        return;
    }

    if (HWND page = pages_[static_cast<std::size_t>(selectedTab)].hwnd) {
        ::ShowWindow(page, SW_SHOW);
    }
    Layout();
    PopulateTab(selectedTab);
    OnTabActivated(selectedTab);
    RedrawTabClient();
}

bool ProcessDetailPage::EnsurePage(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    if (page.hwnd) {
        return true;
    }
    ResetTabRuntimeState(tab);
    if (!CreatePageHost(tab)) {
        return false;
    }
    if (!CreateTabControls(tab)) {
        DestroyPageHost(tab);
        return false;
    }
    LayoutPage(tab);
    return true;
}

bool ProcessDetailPage::CreatePageHost(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    if (page.hwnd) {
        return true;
    }

    // TabCtrl_AdjustRect returns tab-client coordinates. The page host lives
    // inside the TabControl so the active tab owns all visible child HWNDs.
    HWND pageHwnd = ::CreateWindowExW(
        0,
        WC_STATICW,
        L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        0,
        0,
        100,
        100,
        tab_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    page.hwnd = pageHwnd;
    if (!pageHwnd || !::SetWindowSubclass(
            pageHwnd,
            PageSubclassProc,
            static_cast<UINT_PTR>(static_cast<std::size_t>(tab) + 1),
            reinterpret_cast<DWORD_PTR>(this))) {
        page.hwnd = nullptr;
        if (pageHwnd) {
            ::DestroyWindow(pageHwnd);
        }
        return false;
    }
    return true;
}

void ProcessDetailPage::DestroyPageHost(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    for (const Placement& placement : page.placements) {
        listColumnCounts_.erase(placement.hwnd);
        listContextColumns_.erase(placement.hwnd);
    }

    HWND oldPage = page.hwnd;
    if (tab == TabIndex::Threads) {
        threadVirtualList_.detach();
    } else if (tab == TabIndex::Modules) {
        moduleVirtualList_.detach();
    }
    page.hwnd = nullptr;
    page.placements.clear();
    ResetTabRuntimeState(tab);

    if (oldPage) {
        ::ShowWindow(oldPage, SW_HIDE);
        ::DestroyWindow(oldPage);
    }
    RedrawTabClient();
}

bool ProcessDetailPage::CreateTabControls(TabIndex tab) {
    switch (tab) {
    case TabIndex::Detail: return CreateDetailTab();
    case TabIndex::Threads: return CreateThreadTab();
    case TabIndex::Actions: return CreateActionTab();
    case TabIndex::Modules: return CreateModuleTab();
    case TabIndex::Token: return CreateTokenTab();
    case TabIndex::TokenSwitch: return CreateTokenSwitchTab();
    case TabIndex::Evidence: return CreateEvidenceTab();
    case TabIndex::Hotkey: return CreateHotkeyTab();
    case TabIndex::Keyboard: return CreateKeyboardTab();
    case TabIndex::Peb: return CreatePebTab();
    default: return false;
    }
}

void ProcessDetailPage::PopulateTab(TabIndex tab) {
    switch (tab) {
    case TabIndex::Detail: PopulateDetailTab(); break;
    case TabIndex::Threads: PopulateThreadTab(); break;
    case TabIndex::Modules: PopulateModuleTab(); break;
    case TabIndex::Token: PopulateTokenTab(); break;
    case TabIndex::TokenSwitch: PopulateTokenSwitchTab(); break;
    case TabIndex::Evidence: PopulateEvidenceTab(); break;
    case TabIndex::Hotkey: PopulateHotkeyTab(); break;
    case TabIndex::Keyboard: PopulateKeyboardTab(); break;
    case TabIndex::Peb: PopulatePebTab(); break;
    case TabIndex::Actions:
    default:
        break;
    }
}

void ProcessDetailPage::ResetTabRuntimeState(TabIndex tab) {
    switch (tab) {
    case TabIndex::Token:
        tokenLoaded_ = false;
        break;
    case TabIndex::TokenSwitch:
        tokenSwitchLoaded_ = false;
        break;
    case TabIndex::Evidence:
        sectionLoaded_ = false;
        break;
    case TabIndex::Hotkey:
        hotkeyLoaded_ = false;
        break;
    case TabIndex::Keyboard:
        keyboardLoaded_ = false;
        break;
    case TabIndex::Peb:
        pebLoaded_ = false;
        break;
    default:
        break;
    }
}

void ProcessDetailPage::RedrawTabClient() {
    if (!tab_) {
        return;
    }
    ::RedrawWindow(
        tab_,
        nullptr,
        nullptr,
        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

void ProcessDetailPage::OnTabActivated(TabIndex tab) {
    switch (tab) {
    case TabIndex::Token:
        if (!tokenLoaded_) { RefreshTokenReport(); }
        break;
    case TabIndex::TokenSwitch:
        if (!tokenSwitchLoaded_) { RefreshTokenSwitches(); }
        break;
    case TabIndex::Evidence:
        if (!sectionLoaded_) { RefreshSectionReport(); }
        break;
    case TabIndex::Hotkey:
        if (!hotkeyLoaded_) { RefreshHotkeys(); }
        break;
    case TabIndex::Keyboard:
        if (!keyboardLoaded_) { RefreshKeyboard(); }
        break;
    case TabIndex::Peb:
        if (!pebLoaded_) { RefreshPebReport(); }
        break;
    default:
        break;
    }
}

void ProcessDetailPage::RefreshAll() {
    BeginSnapshotRefresh();
}

// BeginSnapshotRefresh schedules the expensive process, thread, module and R0
// evidence queries off the UI thread. AsyncSnapshotTask coalesces repeated
// refreshes and discards out-of-date completions when the page closes.
void ProcessDetailPage::BeginSnapshotRefresh(const std::wstring& loadingMessage) {
    if (!snapshotTask_) {
        return;
    }
    Ksword::Ui::SetLoadingOverlay(loadingOverlay_, true, loadingMessage);
    SetSnapshotRefreshControlsEnabled(false);
    snapshotTask_->request(
        [processId = processId_, expectedCreationTime100ns = expectedCreationTime100ns_]() {
            ProcessDetailCollector collector;
            return collector.Collect(processId, expectedCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessDetailSnapshot>&& snapshot, std::exception_ptr error) {
            Ksword::Ui::SetLoadingOverlay(loadingOverlay_, false);
            SetSnapshotRefreshControlsEnabled(true);
            if (error || !snapshot.has_value()) {
                snapshot_ = {};
                snapshot_.errorText = L"进程详情后台刷新异常结束。请检查目标进程、权限和驱动状态。";
            } else {
                ApplySnapshot(std::move(*snapshot));
                return;
            }
            if (currentTab_ != TabIndex::Count && pages_[static_cast<std::size_t>(currentTab_)].hwnd) {
                PopulateTab(currentTab_);
            }
        });
}

// ApplySnapshot atomically replaces the UI-facing detail snapshot after the
// worker completed. Controls are populated only for the live tab, so hidden
// tabs never cause eager control creation or message storms.
void ProcessDetailPage::ApplySnapshot(ProcessDetailSnapshot snapshot) {
    snapshot_ = std::move(snapshot);
    pendingThreadEntries_ = std::make_shared<const std::vector<ProcessThreadInfo>>(std::move(snapshot_.threads));
    pendingModuleEntries_ = std::make_shared<const std::vector<ProcessModuleInfo>>(std::move(snapshot_.modules));
    ++threadSourceGeneration_;
    ++moduleSourceGeneration_;
    RequestThreadFilter(true);
    RequestModuleFilter(true);
    if (currentTab_ != TabIndex::Count && pages_[static_cast<std::size_t>(currentTab_)].hwnd) {
        PopulateTab(currentTab_);
    }
}

void ProcessDetailPage::SetSnapshotRefreshControlsEnabled(const bool enabled) {
    if (HWND threadRefresh = Control(TabIndex::Threads, ThreadRefresh)) {
        ::EnableWindow(threadRefresh, enabled);
    }
    if (HWND moduleRefresh = Control(TabIndex::Modules, ModuleRefresh)) {
        ::EnableWindow(moduleRefresh, enabled);
    }
}

// ExecuteBackgroundAction serializes process-detail mutations away from the UI
// thread. Confirmations and selection capture occur before this call; the
// worker receives only immutable IDs/snapshots and completion is discarded when
// the page is destroyed by AsyncSnapshotTask.
void ProcessDetailPage::ExecuteBackgroundAction(
    const TabIndex tab,
    const int statusControlId,
    const std::wstring& workingText,
    std::function<ProcessDetailActionResult()> work) {
    if (!actionTask_ || !work) {
        SetPageStatus(tab, statusControlId, L"● 操作任务不可用。");
        return;
    }
    if (actionTask_->running()) {
        SetPageStatus(tab, statusControlId, L"● 另一个进程操作正在后台执行。");
        return;
    }
    SetPageStatus(tab, statusControlId, workingText);
    SetBackgroundActionControlsEnabled(false);
    actionTask_->request(
        std::move(work),
        [this, tab, statusControlId](std::uint64_t, std::optional<ProcessDetailActionResult>&& result, std::exception_ptr error) {
            SetBackgroundActionControlsEnabled(true);
            if (error || !result.has_value()) {
                SetPageStatus(tab, statusControlId, L"● 后台操作异常结束。");
                return;
            }
            SetPageStatus(tab, statusControlId, result->statusText);
            if (!result->dialogText.empty()) {
                ::MessageBoxW(
                    hwnd_,
                    result->dialogText.c_str(),
                    result->dialogTitle.empty() ? L"进程操作" : result->dialogTitle.c_str(),
                    MB_OK | (result->dialogIcon == 0 ? MB_ICONINFORMATION : result->dialogIcon));
            }
            if (result->refreshTokenSwitches) {
                RefreshTokenSwitches();
            }
            if (result->refreshTokenReport) {
                RefreshTokenReport();
            }
            if (result->refreshPebReport) {
                RefreshPebReport();
            }
            if (result->refreshRequired) {
                RefreshAll();
            }
        });
}

// SetBackgroundActionControlsEnabled keeps the mutation surface idle while the
// shared action worker owns an operation. The status labels and tab navigation
// remain available, so the user can inspect prior data without starting a
// competing process/R0 request.
void ProcessDetailPage::SetBackgroundActionControlsEnabled(const bool enabled) {
    constexpr std::array<int, 50> controls{
        ActionTerminateMode,
        ActionTerminate,
        ActionSuspend,
        ActionResume,
        ActionSetCritical,
        ActionClearCritical,
        ActionPriority,
        ActionApplyPriority,
        ActionOpenFolder,
        ActionRefreshPpl,
        ActionEfficiencyOn,
        ActionEfficiencyOff,
        ActionR0Terminate,
        ActionR0Suspend,
        ActionR0Ppl,
        ActionR0Hide,
        ActionR0Danger,
        ActionInjectionMode,
        ActionDllPath,
        ActionBrowseDll,
        ActionInjectDll,
        ActionShellcodePath,
        ActionBrowseShellcode,
        ActionInjectShellcode,
        TokenSwitchApply,
        TokenRawInfoClass,
        TokenRawInputMode,
        TokenRawPayload,
        TokenRawApply,
        TokenSandboxInert,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenUiAccess,
        TokenMandatoryNoWriteUp,
        TokenMandatoryNewProcessMin,
        TokenHasRestrictions,
        TokenIsAppContainer,
        TokenIsRestricted,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        PebApply,
        PebCommandLine,
        PebImagePath,
        PebCurrentDirectory,
        PebEnvironmentName,
        PebEnvironmentValue,
        PebImageBase,
        PebAffinity,
        PebPriority
    };
    for (const int controlId : controls) {
        const TabIndex tab = controlId >= PebRefresh
            ? TabIndex::Peb
            : controlId >= TokenSwitchRefresh ? TabIndex::TokenSwitch : TabIndex::Actions;
        if (HWND control = Control(tab, controlId)) { ::EnableWindow(control, enabled); }
    }
}

HWND ProcessDetailPage::AddControl(
    TabIndex tab,
    DWORD exStyle,
    const wchar_t* className,
    const wchar_t* text,
    DWORD style,
    int controlId,
    int x,
    int y,
    int width,
    int height) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    const int initialWidth = width < 0 ? 100 : width;
    const int initialHeight = height < 0 ? 100 : height;
    HWND child = ::CreateWindowExW(
        exStyle,
        className,
        text ? text : L"",
        WS_CHILD | WS_VISIBLE | style,
        x,
        y,
        initialWidth,
        initialHeight,
        page.hwnd,
        controlId == 0 ? nullptr : reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ApplyFont(child);
    if (child) {
        page.placements.push_back(Placement{ child, x, y, width, height });
    }
    return child;
}

HWND ProcessDetailPage::AddLabel(
    TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height) {
    return AddControl(tab, 0, WC_STATICW, text, SS_LEFT | SS_CENTERIMAGE | SS_NOTIFY, controlId, x, y, width, height);
}

HWND ProcessDetailPage::AddButton(
    TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height) {
    return AddControl(tab, 0, WC_BUTTONW, text, BS_PUSHBUTTON | WS_TABSTOP, controlId, x, y, width, height);
}

HWND ProcessDetailPage::AddEdit(
    TabIndex tab,
    int controlId,
    const wchar_t* text,
    bool readOnly,
    bool multiline,
    int x,
    int y,
    int width,
    int height) {
    DWORD style = WS_TABSTOP | ES_LEFT;
    DWORD exStyle = WS_EX_CLIENTEDGE;
    if (readOnly) {
        style |= ES_READONLY;
    }
    if (multiline) {
        style |= ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL;
    } else {
        style |= ES_AUTOHSCROLL;
    }
    HWND edit = AddControl(tab, exStyle, WC_EDITW, text, style, controlId, x, y, width, height);
    // Every multi-line pane on this page routes through here, so attaching once
    // covers the detail, evidence, PEB and token dumps in a single place.
    if (multiline) {
        Ksword::Ui::AttachTextFindSupport(edit);
    }
    return edit;
}

HWND ProcessDetailPage::AddCombo(TabIndex tab, int controlId, int x, int y, int width, int height) {
    return AddControl(
        tab, 0, WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL | WS_TABSTOP,
        controlId, x, y, width, height);
}

HWND ProcessDetailPage::AddCheck(
    TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height) {
    return AddControl(tab, 0, WC_BUTTONW, text, BS_AUTOCHECKBOX | WS_TABSTOP, controlId, x, y, width, height);
}

HWND ProcessDetailPage::AddGroup(
    TabIndex tab, const wchar_t* text, int x, int y, int width, int height) {
    return AddControl(tab, 0, WC_BUTTONW, text, BS_GROUPBOX, 0, x, y, width, height);
}

HWND ProcessDetailPage::AddList(TabIndex tab, int controlId, int x, int y, int width, int height) {
    HWND list = AddControl(
        tab,
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP,
        controlId,
        x,
        y,
        width,
        height);
    if (list) {
        ListView_SetExtendedListViewStyle(
            list,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_INFOTIP);
    }
    return list;
}

HWND ProcessDetailPage::AddVirtualList(
    TabIndex tab,
    int controlId,
    int x,
    int y,
    int width,
    int height,
    Ksword::Ui::VirtualListView& virtualList) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    const int initialWidth = width < 0 ? 100 : width;
    const int initialHeight = height < 0 ? 100 : height;
    if (!virtualList.create(page.hwnd, controlId, x, y, initialWidth, initialHeight)) {
        return nullptr;
    }
    HWND list = virtualList.hwnd();
    page.placements.push_back(Placement{ list, x, y, width, height });
    ListView_SetExtendedListViewStyle(
        list,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_INFOTIP);
    return list;
}

HWND ProcessDetailPage::Control(TabIndex tab, int controlId) const {
    const HWND page = pages_[static_cast<std::size_t>(tab)].hwnd;
    return page ? ::GetDlgItem(page, controlId) : nullptr;
}

void ProcessDetailPage::SetControlText(TabIndex tab, int controlId, const std::wstring& text) {
    if (HWND control = Control(tab, controlId)) {
        ::SetWindowTextW(control, text.c_str());
    }
}

std::wstring ProcessDetailPage::ControlText(TabIndex tab, int controlId) const {
    return ReadWindowText(Control(tab, controlId));
}

void ProcessDetailPage::SetPageStatus(TabIndex tab, int controlId, const std::wstring& text) {
    SetControlText(tab, controlId, text.size() > 160 ? text.substr(0, 157) + L"..." : text);
}

void ProcessDetailPage::AddListColumn(HWND list, int index, const wchar_t* title, int width) {
    if (!list) {
        return;
    }
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

void ProcessDetailPage::ClearList(HWND list) {
    if (list) {
        ListView_DeleteAllItems(list);
    }
}

void ProcessDetailPage::AddListRow(
    HWND list,
    int row,
    const std::vector<std::wstring>& values,
    LPARAM data) {
    if (!list || values.empty()) {
        return;
    }
    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = row;
    item.pszText = const_cast<LPWSTR>(values[0].c_str());
    item.lParam = data;
    const int inserted = ListView_InsertItem(list, &item);
    if (inserted < 0) {
        return;
    }
    for (int column = 1; column < static_cast<int>(values.size()); ++column) {
        ListView_SetItemText(list, inserted, column, const_cast<LPWSTR>(values[column].c_str()));
    }
}

std::wstring ProcessDetailPage::ListCell(HWND list, int row, int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::vector<wchar_t> buffer(8192, L'\0');
    LVITEMW item{};
    item.iSubItem = column;
    item.pszText = buffer.data();
    item.cchTextMax = static_cast<int>(buffer.size());
    ListView_GetItem(list, &item);
    ListView_GetItemText(list, row, column, buffer.data(), static_cast<int>(buffer.size()));
    return buffer.data();
}

bool ProcessDetailPage::CopyText(HWND owner, const std::wstring& text) {
    // Keep all explicit detail-table copies in the common evidence path while
    // preserving the existing Unicode clipboard representation.
    return Ksword::Ui::CopyTextToClipboard(owner, text, L"进程详细信息");
}

std::wstring ProcessDetailPage::ReadWindowText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<std::size_t>(std::max(0, length)) + 1, L'\0');
    ::GetWindowTextW(hwnd, text.data(), static_cast<int>(text.size()));
    text.resize(std::wcslen(text.c_str()));
    return text;
}

void ProcessDetailPage::ApplyFont(HWND hwnd, HFONT font) {
    if (hwnd) {
        ::SendMessageW(
            hwnd,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(font ? font : Ksword::Ui::SystemUIFont()),
            TRUE);
    }
}

int ProcessDetailPage::SelectedListRow(HWND list) const {
    return list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
}

void ProcessDetailPage::CopyListCell(HWND list) {
    const int row = SelectedListRow(list);
    const int column = listContextColumns_.contains(list) ? listContextColumns_[list] : 0;
    CopyText(hwnd_, ListCell(list, row, column));
}

void ProcessDetailPage::CopyListRow(HWND list) {
    const int row = SelectedListRow(list);
    const int columns = listColumnCounts_.contains(list) ? listColumnCounts_[list] : 0;
    if (row < 0 || columns <= 0) {
        return;
    }
    std::wostringstream text;
    for (int column = 0; column < columns; ++column) {
        if (column) { text << L'\t'; }
        text << ListCell(list, row, column);
    }
    CopyText(hwnd_, text.str());
}

void ProcessDetailPage::CopyListAll(HWND list) {
    const int rows = list ? ListView_GetItemCount(list) : 0;
    const int columns = listColumnCounts_.contains(list) ? listColumnCounts_[list] : 0;
    if (rows <= 0 || columns <= 0) {
        return;
    }
    std::wostringstream text;
    wchar_t headerText[512]{};
    HWND header = ListView_GetHeader(list);
    for (int column = 0; column < columns; ++column) {
        HDITEMW item{};
        item.mask = HDI_TEXT;
        item.pszText = headerText;
        item.cchTextMax = static_cast<int>(std::size(headerText));
        Header_GetItem(header, column, &item);
        if (column) { text << L'\t'; }
        text << headerText;
    }
    text << L"\r\n";
    for (int row = 0; row < rows; ++row) {
        for (int column = 0; column < columns; ++column) {
            if (column) { text << L'\t'; }
            text << ListCell(list, row, column);
        }
        if (row + 1 < rows) { text << L"\r\n"; }
    }
    CopyText(hwnd_, text.str());
}

bool ProcessDetailPage::HandleGenericContextMenu(HWND source, POINT screenPoint) {
    if (!source || !listColumnCounts_.contains(source)) {
        return false;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(source, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int hitRow = ListView_SubItemHitTest(source, &hit);
    listContextColumns_[source] = hit.iSubItem >= 0 ? hit.iSubItem : 0;
    if (hitRow >= 0) {
        ListView_SetItemState(source, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(source, hitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (SelectedListRow(source) < 0) {
        return true;
    }

    if (source == Control(TabIndex::Threads, ThreadList)) {
        return HandleThreadContextMenu(screenPoint);
    }
    if (source == Control(TabIndex::Modules, ModuleList)) {
        return HandleModuleContextMenu(screenPoint);
    }

    HMENU menu = ::CreatePopupMenu();
    ::AppendMenuW(menu, MF_STRING, kCopyCellCommand, L"复制当前单元格");
    ::AppendMenuW(menu, MF_STRING, kCopyRowCommand, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING, kCopyAllCommand, L"复制全部");
    const UINT command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    if (command == kCopyCellCommand) { CopyListCell(source); }
    if (command == kCopyRowCommand) { CopyListRow(source); }
    if (command == kCopyAllCommand) { CopyListAll(source); }
    return true;
}

bool ProcessDetailPage::HandlePageNotify(TabIndex tab, NMHDR* header, LRESULT& result) {
    if (!header) {
        return false;
    }
    if (tab == TabIndex::Keyboard &&
        header->hwndFrom == Control(TabIndex::Keyboard, KeyboardInnerTab) &&
        header->code == TCN_SELCHANGE) {
        RebuildKeyboardList();
        result = 0;
        return true;
    }
    if (threadVirtualList_.handleNotify(*header, result) || moduleVirtualList_.handleNotify(*header, result)) {
        return true;
    }
    if (header->code == NM_RCLICK && listColumnCounts_.contains(header->hwndFrom)) {
        POINT point{};
        ::GetCursorPos(&point);
        result = HandleGenericContextMenu(header->hwndFrom, point) ? 0 : 1;
        return true;
    }
    if (tab == TabIndex::Threads && header->hwndFrom == Control(TabIndex::Threads, ThreadList) &&
        header->code == NM_DBLCLK) {
        ShowSelectedThreadSummary();
        result = 0;
        return true;
    }
    return false;
}

const std::vector<ProcessThreadInfo>& ProcessDetailPage::ThreadEntries() const noexcept {
    static const std::vector<ProcessThreadInfo> empty;
    return threadEntries_ ? *threadEntries_ : empty;
}

const std::vector<ProcessModuleInfo>& ProcessDetailPage::ModuleEntries() const noexcept {
    static const std::vector<ProcessModuleInfo> empty;
    return moduleEntries_ ? *moduleEntries_ : empty;
}

std::size_t ProcessDetailPage::LatestThreadCount() const noexcept {
    if (pendingThreadEntries_) {
        return pendingThreadEntries_->size();
    }
    return ThreadEntries().size();
}

} // namespace Ksword::Features::ProcessDetail
