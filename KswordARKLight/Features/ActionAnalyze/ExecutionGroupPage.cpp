#include "ExecutionGroupPage.h"
#include "ExecutionGroupPageState.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/Theme.h"
#include "../../Ui/WorkspaceHost.h"
#include <algorithm>
#include <memory>
#include <windowsx.h>

namespace Ksword::Features::ActionAnalyze {
namespace execution_group_page {
namespace {
constexpr wchar_t kClass[] = L"KswordARKLight.ExecutionGroup";
constexpr UINT_PTR kDisplayTimer = 1;
constexpr UINT kEvidenceDraft = WM_APP + 981; // 同UI线程同步传纯值，不保留发送方指针。

std::vector<HWND> Navigation(const Page& page)
{
    std::vector<HWND> controls(page.inputs.begin(), page.inputs.end());
    controls.insert(controls.begin() + 2, page.identify);
    controls.insert(controls.end(), page.apiInputs.begin(), page.apiInputs.end()); // 来源字段由原参数正文参与Tab遍历。
    controls.insert(controls.end(), page.memoryInputs.begin(), page.memoryInputs.end()); // 独立内存范围使用同一键盘导航。
    for (const auto control : {page.draft, page.add, page.remove, page.loadDraft, page.projectDirectory, page.openProject, page.holdPeersOnHit, page.autoSaveExecution, page.authorized,
        page.start, page.appendMembers, page.query, page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected,
        page.addRange, page.stepInto, page.stepOver, page.stepOut, page.cancelStep, page.saveExecution, page.captureApi,
        page.readMemory, page.saveMemory, page.close, page.preset,
        page.members, page.textMode, page.copy, page.exportText, page.text}) controls.push_back(control);
    return controls;
}

LRESULT CALLBACK Proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp)
{
    auto* page = reinterpret_cast<Page*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto state = std::make_unique<Page>();
        state->hwnd = hwnd;
        page = state.release();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
    }
    if (!page) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_CREATE: {
        if (!CreateControls(*page)) return -1;
        const auto error = page->session.StartWorker();
        if (error) page->error = L"执行集合后台会话未启动，Win32=" + std::to_wstring(error);
        if (!::SetTimer(hwnd, kDisplayTimer, 250, nullptr)) return -1;
        Refresh(*page);
        return 0;
    }
    case WM_SIZE:
        Layout(*page);
        return 0;
    case WM_TIMER:
        if (wp == kDisplayTimer && ::IsWindowVisible(hwnd)) {
            const auto snapshot = page->session.ReadStatus();
            if (snapshot.revision != page->shown.revision || snapshot.busy != page->shown.busy ||
                snapshot.closing != page->shown.closing || snapshot.active != page->shown.active ||
                snapshot.canStart != page->shown.canStart) Refresh(*page);
        }
        return 0;
    case Ui::kBeginNativeRetirementMessage:
        page->retiring = true;
        page->session.BeginRetirement();
        Refresh(*page);
        return page->session.Ready() ? TRUE : FALSE;
    case Ui::kPollNativeRetirementMessage:
        return page->session.Ready() ? TRUE : FALSE;
    case Ui::kCancelNativeRetirementMessage:
        page->retiring = false;
        page->session.CancelRetirement();
        Refresh(*page);
        return TRUE;
    case kEvidenceDraft: {
        const auto* draft = reinterpret_cast<const Ksword::Evidence::NativeExecutionSiteDraft*>(lp); // 当前同步调用的来源值。
        const auto state = page->session.ReadStatus(); // 读取原worker已公布状态，不发原生Query。
        if (!draft || page->retiring || !state.canStart || state.busy || state.active || state.closing ||
            page->sites.size() >= execution_native::kOwnedExecutionGroupLimit ||
            std::any_of(page->sites.begin(), page->sites.end(), [&](const auto& site) { return site.pid == draft->pid; }))
        {
            return FALSE;
        }
        execution_native::ExecutionGroupSite site; // 纯参数站点，不继承历史授权、停点或owner。
        site.pid = draft->pid;
        site.creationFileTime = draft->creationFileTime;
        site.address = draft->address;
        site.rangeBytes = draft->rangeBytes;
        std::erase_if(page->evidenceDrafts, [&](const auto& origin) // 删除已不在目录中的旧来源，保持常量上限。
        {
            return std::none_of(page->sites.begin(), page->sites.end(), [&](const auto& existing)
            {
                return existing.pid == origin.pid && existing.creationFileTime == origin.creationFileTime &&
                    existing.address == origin.address && existing.rangeBytes == origin.rangeBytes;
            });
        });
        page->sites.push_back(std::move(site)); // 不调用LoadDraft，保留原编辑表单全部未保存值。
        page->evidenceDrafts.push_back(*draft);
        RefreshDraft(*page);
        ::SendMessageW(page->draft, CB_SETCURSEL, page->sites.size() - 1, 0);
        page->error.clear();
        Refresh(*page);
        return TRUE;
    }
    case WM_COMMAND: {
        const int id = LOWORD(wp), code = HIWORD(wp);
        if (id == kPreset && code == CBN_SELCHANGE) {
            const auto preset = ::SendMessageW(page->preset, CB_GETCURSEL, 0, 0);
            if (preset == 0) page->visibleColumns = {true, true, true, true, true, false, false, false, false, false, true};
            else if (preset == 1) page->visibleColumns = {true, false, false, false, false, true, true, true, true, true, false};
            else return 0;
            RebuildColumns(*page);
            Refresh(*page);
        } else if ((id == kTextMode || id == kDraft) && code == CBN_SELCHANGE) RefreshText(*page);
        else if ((id == kAddress || id == kExport) && code == EN_CHANGE)
        {
            const bool image = InputText(page->inputs[Address]).empty(); // 仅在机制可见性改变时重新布局，逐字符编辑不重排页面。
            const bool shown = (::GetWindowLongPtrW(page->inputs[ImageSha256], GWL_STYLE) & WS_VISIBLE) != 0;
            const bool definition = image && InputText(page->inputs[Export]).empty(); // 精确导出不发送隐藏的RVA定义草稿。
            const bool definitionShown = (::GetWindowLongPtrW(page->inputs[DefinitionId], GWL_STYLE) & WS_VISIBLE) != 0;
            if (image != shown || definition != definitionShown)
            {
                Layout(*page); // 地址切到私有机制时隐藏散列行，保留其文本和原集合结果。
            }
        }
        else if (((id == kAuthorized || id == kAutoSaveExecution || id == kOpenProject) && code == BN_CLICKED) ||
            (id == kProjectDirectory && code == EN_CHANGE))
        {
            // 开始资格取当前参数草稿；路径/自动保存改变时立即更新，不等待后台状态修订。
            Refresh(*page);
        }
        else if (code == BN_CLICKED && (id == kIdentify || id == kAdd || id == kRemove || id == kLoadDraft ||
            id == kStart || id == kAppendMembers || id == kQuery || id == kPauseAll || id == kPauseSelected || id == kContinueAll ||
            id == kContinueSelected || id == kStepInto || id == kStepOver || id == kStepOut || id == kCancelStep ||
            id == kClose || id == kAddRange || id == kSaveExecution || id == kCaptureApi || id == kReadMemory ||
            id == kSaveMemory || id == kCopy || id == kExportText)) Command(*page, id);
        return 0;
    }
    case WM_NOTIFY: {
        const auto* notify = reinterpret_cast<NMHDR*>(lp);
        if (notify && notify->hwndFrom == page->members && notify->code == LVN_ITEMCHANGED && !page->publishing) Refresh(*page);
        return 0;
    }
    case WM_CONTEXTMENU: {
        const auto source = reinterpret_cast<HWND>(wp);
        if (source == ListView_GetHeader(page->members)) {
            POINT point{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(source, &rect);
                point = {rect.left, rect.bottom};
            }
            HeaderMenu(*page, point);
            return 0;
        }
        break;
    }
    case WM_DRAWITEM:
        if (lp) Ui::DrawThemedButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lp));
        return TRUE;
    case WM_CTLCOLORSTATIC: {
        const auto& theme = Ui::AppTheme();
        const auto brush = Ui::PaintLabelBackground(reinterpret_cast<HDC>(wp), reinterpret_cast<HWND>(lp), theme.windowBrush(), theme.textColor);
        if (brush) return brush;
        break;
    }
    case WM_ERASEBKGND: {
        RECT rect{};
        ::GetClientRect(hwnd, &rect);
        ::FillRect(reinterpret_cast<HDC>(wp), &rect, Ui::AppTheme().windowBrush());
        return 1;
    }
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kDisplayTimer);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete page; // 析构只移交清退责任；不在UI线程销毁原生集合。
        break;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}
}

LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data)
{
    auto& page = *reinterpret_cast<Page*>(data);
    if (message == WM_CONTEXTMENU && hwnd == ListView_GetHeader(page.members))
        return ::SendMessageW(page.hwnd, WM_CONTEXTMENU, reinterpret_cast<WPARAM>(hwnd), lp);
    if (message == WM_KEYDOWN && wp == VK_TAB && !(::GetKeyState(VK_CONTROL) & 0x8000)) {
        const auto controls = Navigation(page);
        const auto found = std::find(controls.begin(), controls.end(), hwnd);
        const int count = static_cast<int>(controls.size());
        const int step = (::GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
        int index = found == controls.end() ? 0 : static_cast<int>(found - controls.begin());
        for (int attempt = 0; attempt < count; ++attempt) {
            index = (index + step + count) % count;
            const auto next = controls[static_cast<std::size_t>(index)];
            if (::IsWindowVisible(next) && ::IsWindowEnabled(next)) {
                ::SetFocus(next);
                page.parameters.Reveal(next);
                break;
            }
        }
        return 0;
    }
    if (message == WM_KEYDOWN && wp == VK_RETURN && ::IsWindowEnabled(hwnd)) {
        wchar_t type[24]{};
        ::GetClassNameW(hwnd, type, 24);
        if (::lstrcmpiW(type, L"BUTTON") == 0 && !(lp & (1LL << 30))) {
            ::SendMessageW(hwnd, BM_CLICK, 0, 0);
            return 0;
        }
    }
    if (message == WM_CHAR && wp == L'\t') return 0;
    return ::DefSubclassProc(hwnd, message, wp, lp);
}

HWND CreateExecutionGroupWindow(HWND parent, const RECT& bounds)
{
    WNDCLASSW wc{};
    wc.lpfnWndProc = Proc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ui::AppTheme().windowBrush();
    wc.lpszClassName = kClass;
    if (!::RegisterClassW(&wc) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    return ::CreateWindowExW(WS_EX_CONTROLPARENT, kClass, L"执行断点集合", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, parent,
        nullptr, wc.hInstance, nullptr);
}
}

HWND CreateExecutionGroupPage(HWND parent, const RECT& bounds)
{
    return execution_group_page::CreateExecutionGroupWindow(parent, bounds);
}

// 来源页位于同一原生WorkspaceHost分支；按固定导航ID查找，不搜索其它窗口或进程。
bool PrepareExecutionGroupEvidenceDraft(HWND source, const Ksword::Evidence::NativeExecutionSiteDraft& draft)
{
    for (HWND host = source; host; host = ::GetParent(host)) // 只在当前宿主祖先链定位执行工作台。
    {
        if (!::GetDlgItem(host, 58790))
        {
            continue;
        }
        const HWND target = Ui::WorkspaceHostPage(host, 2, true); // 按原工厂惰性创建唯一集合页。
        if (!target || !::SendMessageW(target, execution_group_page::kEvidenceDraft, 0, reinterpret_cast<LPARAM>(&draft)))
        {
            return false;
        }
        return Ui::ActivateWorkspaceHostTab(host, 2); // 成功加入目录才导航，显式Start仍由用户执行。
    }
    return false;
}
}
