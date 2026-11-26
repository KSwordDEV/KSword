#include "LightPrivateExecutionCandidatesPane.h"
#include "../Memory/DriverMemoryModel.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/MenuUtil.h"
#include "../../Ui/ParameterWorkspace.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include <algorithm>
#include <array>
#include <commctrl.h>
#include <limits>
#include <utility>
#include <windowsx.h>

namespace Ksword::Features::ActionAnalyze {
namespace {
using Ui::Scale;
constexpr wchar_t kClass[] = L"KswordLight.PrivateExecutionCandidates";
enum : int { kThrough = 58800, kRead, kNext, kWhole, kBase, kPages, kPrepare, kColumns, kList, kCopy, kExport, kDetails, kColumnsB };
constexpr UINT_PTR kDisplayTimer = 1;
constexpr UINT kColumnMenu = 58900; // 原生表头逐列显隐的局部命令范围。
constexpr std::array<const wchar_t*, 9> kColumnNames{
    L"操作", L"目标PID / 创建FILETIME", L"实际起点", L"实际字节", L"原新保护",
    L"原API坐标", L"来源 / 代次", L"源序号", L"Free仅请求"};
constexpr std::array<int, 9> kColumnWidths{100, 180, 140, 90, 135, 130, 240, 100, 100};
struct Pane {
    HWND hwnd = nullptr, hint = nullptr, identity = nullptr, throughLabel = nullptr, through = nullptr;
    HWND baseLabel = nullptr, base = nullptr, pagesLabel = nullptr, pages = nullptr, whole = nullptr;
    HWND status = nullptr, read = nullptr, next = nullptr, prepare = nullptr, columns = nullptr, columnsB = nullptr, list = nullptr;
    HWND tooltip = nullptr; // 原生提示由Pane持有，不借用临时字符串。
    int columnPreset = 0; // 0=A实际范围、1=B来源、-1=用户逐列自定义。
    std::array<int, 9> columnWidths{}; // 隐藏前保存真实宽度，切换列组仍保留用户调整。
    HWND details = nullptr, copy = nullptr, exportText = nullptr;
    Ui::ParameterWorkspace parameters;
    LightPrivateExecutionCandidatesPort port;
    LightPrivateExecutionCandidatesContext context;
    std::shared_ptr<const private_execution::PrivateExecutionCandidatesPage> page;
    std::shared_ptr<const private_execution::PrivateExecutionCandidatesPage> draftPage;
    std::wstring pageDirectory, identityText, statusText, detailsText, error;
    int draftRow = -1;
    bool retiring = false, loading = false, preparing = false;
    bool rebuilding = false; // 列表同步通知不能重入刷新并改写尚在重建的行选择。
};
// 输入共享服务的ASCII标识，输出显示文本；不涉及文件编码或系统查询。
std::wstring Wide(std::string_view text) {
    return {text.begin(), text.end()};
}
// 输入本地控件，输出完整草稿文字；调用方随后冻结到纯值请求。
std::wstring Text(HWND control) {
    std::wstring text(static_cast<std::size_t>(::GetWindowTextLengthW(control)) + 1, L'\0');
    text.resize(static_cast<std::size_t>(::GetWindowTextW(control, text.data(), static_cast<int>(text.size()))));
    return text;
}
// 返回当前单选行；-1为未选择，不默认使用第一条调用。
int Selected(const Pane& pane) {
    return ListView_GetNextItem(pane.list, -1, LVNI_SELECTED);
}
// 输入Pane已成功页与选中索引，返回同一页行的只读借用。
const private_execution::PrivateExecutionCandidate* Row(const Pane& pane) {
    const int row = Selected(pane);
    return pane.page && row >= 0 && static_cast<std::size_t>(row) < pane.page->rows.size() ? &pane.page->rows[row] : nullptr;
}
// 核对显示页与原页最新发布身份；失败旧页仍可读，不能借到新会话。
bool SameSession(const Pane& pane) {
    return pane.page && pane.context.sessionIdentity && pane.context.projectId == pane.page->scope.projectId &&
        pane.context.sampleId == pane.page->scope.sampleId && pane.context.projectDirectory == pane.pageDirectory &&
        pane.context.view && pane.context.view->page == pane.page;
}
// 只判定原worker的读取入队资格，不执行查询或自动读取。
bool ReadReady(const Pane& pane) {
    return !pane.retiring && !pane.preparing && !pane.context.retiring && pane.context.active && !pane.context.busy &&
        !pane.context.projectId.empty() && !pane.context.sampleId.empty();
}
// 从纯值快照核对候选和native强目标；最终选段仍由共享Prepare及原owner复核。
bool SelectReady(const Pane& pane) {
    const auto* row = Row(pane);
    if (!ReadReady(pane) || !SameSession(pane) || !pane.context.target.attached || !pane.context.nxBinding || !row ||
        !row->rangeCandidate || !row->strongTarget || !row->origin.record.apiMemoryLifecycle) return false;
    const auto& fields = *row->origin.record.apiMemoryLifecycle;
    return fields.targetPid == pane.context.target.pid && fields.targetCreationFileTime == pane.context.target.creationFileTime;
}
// 使用当前系统字体测量自然折行高度，供窄窗参数滚动布局使用。
int Height(HWND label, int width) {
    const auto text = Text(label);
    const auto dc = ::GetDC(label);
    if (!dc) return Scale(48);
    const auto prior = ::SelectObject(dc, Ui::SystemUIFont());
    RECT bounds{0, 0, width, 0};
    ::DrawTextW(dc, text.c_str(), -1, &bounds, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    ::SelectObject(dc, prior);
    ::ReleaseDC(label, dc);
    return (std::max)(Scale(20), static_cast<int>(bounds.bottom));
}
// 输入页根尺寸，输出共享参数滚动区、固定动作和独立结果视口几何。
void Layout(Pane& pane) {
    if (!pane.details) return;
    RECT area{};
    ::GetClientRect(pane.hwnd, &area);
    const int edge = Scale(6), gap = Scale(8), row = Scale(28);
    const int width = (std::max)(1, static_cast<int>(area.right) - 2 * edge);
    const bool columns = width >= Scale(900);
    const int parameterWidth = columns ? (std::min)(Scale(370), width * 2 / 5) : width;
    const int bodyWidth = (std::max)(1, parameterWidth - ::GetSystemMetrics(SM_CXVSCROLL));
    const auto move = [](HWND child, int x, int y, int w, int h) { ::MoveWindow(child, x, y, (std::max)(1, w), (std::max)(1, h), TRUE); };
    int y = 0;
    for (const HWND label : {pane.hint, pane.identity}) {
        const int height = Height(label, bodyWidth);
        move(label, 0, y, bodyWidth, height);
        y += height + gap;
    }
    const auto field = [&](HWND label, HWND input, bool combo) {
        const int height = Height(label, bodyWidth);
        move(label, 0, y, bodyWidth, height);
        y += height;
        move(input, 0, y, bodyWidth, combo ? Scale(240) : row);
        y += row + gap;
    };
    field(pane.throughLabel, pane.through, true);
    field(pane.baseLabel, pane.base, false);
    field(pane.pagesLabel, pane.pages, true);
    move(pane.whole, 0, y, (std::min)(Scale(200), bodyWidth), row);
    y += row + gap;
    const int statusHeight = Height(pane.status, bodyWidth);
    move(pane.status, 0, y, bodyWidth, statusHeight);
    y += statusHeight + gap;
    const std::array actions{pane.read, pane.next, pane.prepare};
    const int actionsHeight = Ui::LayoutParameterActions(actions, 0, 0, parameterWidth, Scale(156), row, gap, false);
    const int available = (std::max)(1, static_cast<int>(area.bottom) - 2 * edge);
    const int parameterHeight = columns ? (std::max)(1, available - actionsHeight - gap) :
        (std::max)(1, (std::min)(y, available / 3));
    pane.parameters.Layout(edge, edge, parameterWidth, parameterHeight, y);
    Ui::LayoutParameterActions(actions, edge, edge + parameterHeight + gap, parameterWidth, Scale(156), row, gap);
    const int resultX = columns ? edge + parameterWidth + gap : edge;
    const int resultY = columns ? edge : edge + parameterHeight + actionsHeight + 2 * gap;
    const int resultWidth = columns ? (std::max)(1, width - parameterWidth - gap) : width;
    const int resultHeight = (std::max)(1, static_cast<int>(area.bottom) - resultY - edge);
    const int segmentWidth = (std::min)(Scale(36), resultWidth / 2);
    move(pane.columns, resultX, resultY, segmentWidth, row);
    move(pane.columnsB, resultX + segmentWidth, resultY, segmentWidth, row);
    const int flexible = (std::max)(2, resultHeight - 2 * row - 3 * gap);
    const int listHeight = flexible * 3 / 5;
    move(pane.list, resultX, resultY + row + gap, resultWidth, listHeight);
    const int toolsY = resultY + row + gap + listHeight + gap;
    move(pane.copy, resultX, toolsY, (std::min)(Scale(96), resultWidth / 2), row);
    move(pane.exportText, resultX + resultWidth / 2, toolsY, (std::min)(Scale(96), resultWidth / 2), row);
    move(pane.details, resultX, toolsY + row + gap, resultWidth, flexible - listHeight);
}
// 只切换同一冻结目录的互补列组；输入预设/列宽，输出真实ListView列宽和按钮强调。
void ApplyColumns(Pane& pane) {
    for (std::size_t index = 0; index < kColumnNames.size(); ++index) {
        if (pane.columnPreset >= 0) {
            const bool show = pane.columnPreset == 0 ? index < 5 : index >= 5;
            Ui::SetListViewColumnWidth(pane.list, static_cast<int>(index), show ? pane.columnWidths[index] : 0);
        }
    }
    for (const auto button : {pane.columns, pane.columnsB}) {
        const bool selected = (button == pane.columns && pane.columnPreset == 0) || (button == pane.columnsB && pane.columnPreset == 1);
        ::SetWindowLongPtrW(button, GWLP_USERDATA, static_cast<LONG_PTR>(selected ? Ui::ButtonRole::Primary : Ui::ButtonRole::Default));
        ::InvalidateRect(button, nullptr, TRUE);
    }
}

// 页快照更换时重建最多8行；列配置和选择由本Pane保存，不执行后台读取。
void Rebuild(Pane& pane) {
    pane.rebuilding = true;
    const int selected = Selected(pane);
    Ui::ScopedListViewRedrawLock redraw(pane.list);
    Ui::ClearListViewRows(pane.list);
    if (pane.page) {
        for (const auto& candidate : pane.page->rows) {
            auto cells = LightPrivateExecutionCandidateCells(candidate, false); // A的实际输出。
            const auto source = LightPrivateExecutionCandidateCells(candidate, true); // B的独立来源。
            cells.insert(cells.end(), source.begin(), source.end());
            Ui::InsertListViewTextRow(pane.list, cells);
        }
    }
    if (selected >= 0 && pane.page && static_cast<std::size_t>(selected) < pane.page->rows.size())
        ListView_SetItemState(pane.list, selected, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    pane.rebuilding = false;
}

// 表头菜单只改本地列显隐；选择自定义后两枚预设都取消强调，不冒充A/B。
void ColumnMenu(Pane& pane, POINT point) {
    std::vector<Ui::PopupMenuItem> items; // 所有真实列的并行菜单，最多9项。
    int visible = 0;
    for (int index = 0; index < static_cast<int>(kColumnNames.size()); ++index) {
        if (ListView_GetColumnWidth(pane.list, index) > 0) ++visible;
    }
    for (int index = 0; index < static_cast<int>(kColumnNames.size()); ++index) {
        const bool shown = ListView_GetColumnWidth(pane.list, index) > 0;
        items.push_back({kColumnMenu + static_cast<UINT>(index), kColumnNames[index], false, !shown || visible > 1, shown});
    }
    const HMENU menu = Ui::BuildPopupMenu(items); // 借用原生菜单创建与Track入口。
    if (!menu) return;
    MENUINFO surface{sizeof(surface)}; // 明确不透明主题底色，菜单文字状态由本Pane绘制。
    surface.fMask = MIM_BACKGROUND;
    surface.hbrBack = Ui::AppTheme().panelBrush();
    ::SetMenuInfo(menu, &surface);
    for (UINT index = 0; index < static_cast<UINT>(items.size()); ++index) {
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_FTYPE;
        item.fType = MFT_OWNERDRAW;
        ::SetMenuItemInfoW(menu, index, TRUE, &item);
    }
    const UINT command = Ui::TrackPopupMenuForCommand(pane.hwnd, menu, point);
    ::DestroyMenu(menu);
    if (command < kColumnMenu || command >= kColumnMenu + kColumnNames.size()) return;
    const int index = static_cast<int>(command - kColumnMenu);
    const int width = ListView_GetColumnWidth(pane.list, index);
    if (width > 0 && visible <= 1) return;
    if (width > 0) pane.columnWidths[index] = width;
    Ui::SetListViewColumnWidth(pane.list, index, width > 0 ? 0 : pane.columnWidths[index]);
    pane.columnPreset = -1;
    ApplyColumns(pane);
}

// 仅绘制本菜单的既有文字，正常、选中和禁用状态各自采用明确主题颜色。
void DrawColumnMenu(const DRAWITEMSTRUCT& item) {
    if (item.itemID < kColumnMenu || item.itemID >= kColumnMenu + kColumnNames.size()) return;
    const bool selected = (item.itemState & ODS_SELECTED) != 0;
    const bool disabled = (item.itemState & (ODS_DISABLED | ODS_GRAYED)) != 0;
    const auto& theme = Ui::AppTheme();
    ::FillRect(item.hDC, &item.rcItem, selected && !disabled ? theme.accentBrush() : theme.panelBrush());
    const auto color = disabled ? theme.mutedTextColor : selected ? theme.dangerTextColor : theme.textColor;
    const std::wstring label = std::wstring((item.itemState & ODS_CHECKED) ? L"✓  " : L"    ") + kColumnNames[item.itemID - kColumnMenu];
    Ui::DrawTextLine(item.hDC, label, item.rcItem, color, Ui::SystemUIFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}
// 消费原页发布值，只更新变化文字和资格；失败不替换成功目录。
void Refresh(Pane& pane) {
    if (pane.rebuilding || !pane.port.read || !pane.details) return;
    pane.context = pane.port.read(); // 原页已发布纯值，不读盘、不Query native。
    std::wstring identity = L"原会话目录：" + pane.context.projectDirectory + L"\r\n项目/采样：" +
        Wide(pane.context.projectId) + L" / " + Wide(pane.context.sampleId) + L"\r\n当前native PID/创建FILETIME：" +
        std::to_wstring(pane.context.target.pid) + L" / " + std::to_wstring(pane.context.target.creationFileTime);
    if (pane.context.view && pane.context.view->page && pane.page != pane.context.view->page) {
        pane.page = pane.context.view->page;
        pane.pageDirectory = pane.context.view->pageProjectDirectory;
        pane.draftPage.reset();
        pane.draftRow = -1;
        pane.rebuilding = true;
        Ui::ClearListViewRows(pane.list); // 页身份变化后不按旧行号自动选中新页对象。
        pane.rebuilding = false;
        Rebuild(pane); // 每次完整成功页才换表，不以失败空表替换旧结果。
    }
    std::wstring status = pane.context.diagnostic;
    if (const auto& view = pane.context.view) {
        status += L"\r\n最近请求：1.." + std::to_wstring(view->request.throughOrdinal) + L" · " + Wide(Ksword::ActionAnalyze::ProjectErrorName(view->result.error)) + L" · " + Wide(view->result.detail) +
            L" · Win32 " + std::to_wstring(view->result.nativeError);
        status += view->result ? L"\r\n本次读取成功" : L"\r\n本次读取失败，旧目录保留；重新读取或重试下一页。";
    } else status += L"\r\n尚未读取候选目录。";
    if (pane.page) {
        identity += L"\r\n显示目录：" + pane.pageDirectory + L"\r\n显示项目/采样：" + Wide(pane.page->scope.projectId) + L" / " + Wide(pane.page->scope.sampleId);
        status += L"\r\n显示截止段1.." + std::to_wstring(pane.page->throughOrdinal) + L" · 本页 " + std::to_wstring(pane.page->rows.size()) + L" / 8行";
        status += L"\r\n生命周期 " + std::to_wstring(pane.page->lifecycleCount) + L" · 范围候选 " + std::to_wstring(pane.page->rangeCandidateCount) +
            L" · Free仅请求 " + std::to_wstring(pane.page->freeRequestCount);
        status += L"\r\n坏AAIM1 " + std::to_wstring(pane.page->malformedLifecycleCount) + L" · 旧摘要 " + std::to_wstring(pane.page->legacyLifecycleCount);
        if (pane.page->rows.empty()) status += L"\r\n完整核验前缀成功，本页没有合法AAIM1调用。";
        if (!SameSession(pane)) status += L"\r\n显示目录属于旧会话或旧采样，只读，不能续页或载入。";
    }
    if (!SelectReady(pane)) status += L"\r\n载入需选中有效范围、强目标匹配原已附加NX会话及同项目/采样。";
    else if (pane.draftPage != pane.page || pane.draftRow != Selected(pane)) status += L"\r\n请采用所选整段，或显式编辑整页子范围以绑定当前行。";
    if (!pane.error.empty()) status += L"\r\n" + pane.error;
    bool relayout = false;
    if (identity != pane.identityText) {
        pane.identityText = std::move(identity);
        ::SetWindowTextW(pane.identity, pane.identityText.c_str());
        relayout = true;
    }
    if (status != pane.statusText) {
        pane.statusText = std::move(status);
        ::SetWindowTextW(pane.status, pane.statusText.c_str());
        relayout = true;
    }
    std::wstring details = pane.page ? L"显示目录：" + pane.pageDirectory + L"\r\n显示项目/采样：" + Wide(pane.page->scope.projectId) + L" / " + Wide(pane.page->scope.sampleId) +
        L"\r\n显示目录snapshot（完整token）：\r\n" + Wide(pane.page->snapshot) +
        L"\r\n下一页raw游标：" + (pane.page->nextAfter ? std::to_wstring(pane.page->nextAfter->segmentOrdinal) + L" / " +
        std::to_wstring(pane.page->nextAfter->sequence) : L"无（本前缀末页）") : L"尚未读取。";
    if (const auto* row = Row(pane)) details = FormatLightPrivateExecutionCandidate(*row) + L"\r\n\r\n" + details;
    else details += L"\r\n请选择目录行查看实际输出、执行保护和原API坐标。";
    if (details != pane.detailsText) {
        pane.detailsText = std::move(details);
        ::SetWindowTextW(pane.details, pane.detailsText.c_str());
    }
    ::EnableWindow(pane.read, ReadReady(pane));
    ::EnableWindow(pane.next, ReadReady(pane) && SameSession(pane) && pane.page->nextAfter.has_value());
    ::EnableWindow(pane.through, ReadReady(pane));
    const auto* selected = Row(pane);
    ::EnableWindow(pane.whole, SelectReady(pane) && selected && selected->wholeRangeDraft.has_value());
    ::EnableWindow(pane.base, !pane.preparing && !pane.retiring && selected && selected->rangeCandidate);
    ::EnableWindow(pane.pages, !pane.preparing && !pane.retiring && selected && selected->rangeCandidate);
    ::EnableWindow(pane.prepare, SelectReady(pane) && pane.draftPage == pane.page && pane.draftRow == Selected(pane));
    if (relayout) Layout(pane);
}
// 显式点击读取或续页时冻结原身份、截止段和token，提交原worker后立即返回。
void Read(Pane& pane, bool next) {
    const auto frozen = pane.context; // 用户所见代次与目录；刷新后不能换成后来会话再发请求。
    const auto page = pane.page;
    const auto ordinal = ::SendMessageW(pane.through, CB_GETCURSEL, 0, 0);
    if (!ReadReady(pane) || !pane.port.request) return;
    LightPrivateExecutionCandidatesRequest request;
    request.projectId = frozen.projectId;
    request.sampleId = frozen.sampleId;
    if (next) {
        if (!SameSession(pane) || !page->nextAfter) return;
        request.throughOrdinal = page->throughOrdinal; // 续页不读后来编辑的截止段。
        request.after = page->nextAfter;
        request.expectedSnapshot = page->snapshot;
    } else {
        if (ordinal < 0 || ordinal >= 128) return;
        request.throughOrdinal = static_cast<std::uint64_t>(ordinal) + 1;
    }
    pane.error = pane.port.request(frozen.sessionIdentity, request) ? L"" : L"原会话或目录已变化、正在忙或清退，未读取。请核对后重试。";
    Refresh(pane);
}
// 显式采用共享服务提供的合法整段；只填本页草稿，不写原AddRange或目标。
void Whole(Pane& pane) {
    const auto* row = Row(pane);
    if (!SelectReady(pane) || !row || !row->wholeRangeDraft) return;
    const auto& draft = *row->wholeRangeDraft;
    pane.loading = true;
    ::SetWindowTextW(pane.base, PrivateCandidateHex(draft.address).c_str());
    ::SendMessageW(pane.pages, CB_SETCURSEL, static_cast<WPARAM>(draft.bytes / 4096 - 1), 0);
    pane.loading = false;
    pane.draftPage = pane.page;
    pane.draftRow = Selected(pane);
    pane.error.clear();
    Refresh(pane);
}
// 用户明确载入时共享Prepare核验子范围，再交原页确认替换和二次身份复核。
void Prepare(Pane& pane) {
    const auto* row = Row(pane);
    if (!SelectReady(pane) || !row || pane.draftPage != pane.page || pane.draftRow != Selected(pane) || !pane.port.prepare) return;
    std::uint64_t base = 0;
    const auto pages = ::SendMessageW(pane.pages, CB_GETCURSEL, 0, 0);
    if (!Memory::ParseUnsignedInteger(Text(pane.base), (std::numeric_limits<std::uint64_t>::max)(), L"子范围起点", base, pane.error) || pages < 0 || pages >= 64) {
        if (pane.error.empty()) pane.error = L"请选择1..64个整页。";
        Refresh(pane);
        return;
    }
    const auto bytes = (static_cast<std::uint64_t>(pages) + 1) * 4096;
    private_execution::PrivateExecutionRangeDraft draft;
    const auto status = private_execution::PreparePrivateExecutionRangeDraft(*row, base, bytes, draft);
    if (!status) { pane.error = L"子范围不在成功实际输出内部，或未整页对齐：" + Wide(status.detail); Refresh(pane); return; }
    const LightPrivateExecutionCandidateSelection selection{pane.context.sessionIdentity, pane.page, static_cast<std::size_t>(Selected(pane)), base, bytes};
    pane.preparing = true;
    Refresh(pane);
    const bool accepted = pane.port.prepare(selection); // 原页负责替换确认和确认后的身份复核，不自动AddRange。
    pane.preparing = false;
    pane.error = accepted ? L"已载入原AddRange草稿；需当前完整NX Held，再显式点击原纳入按钮。" : L"未载入：用户取消替换、原目标/项目/采样已变化，或原页不可用。";
    Refresh(pane);
}
// 保留本页Tab遍历和按钮Enter语义，滚动参数区揭示真实焦点控件。
LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data) {
    auto& pane = *reinterpret_cast<Pane*>(data);
    if (message == WM_KEYDOWN && wp == VK_TAB) {
        const std::array order{pane.through, pane.base, pane.pages, pane.whole, pane.read, pane.next, pane.prepare, pane.columns, pane.columnsB, pane.list, pane.copy, pane.exportText, pane.details};
        const int count = static_cast<int>(order.size()), direction = (::GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
        int at = static_cast<int>(std::find(order.begin(), order.end(), hwnd) - order.begin());
        for (int i = 0; i < count; ++i) {
            at = (at + direction + count) % count;
            if (::IsWindowEnabled(order[at])) { pane.parameters.Reveal(order[at]); ::SetFocus(order[at]); break; }
        }
        return 0;
    }
    if (message == WM_KEYDOWN && wp == VK_RETURN && (hwnd == pane.read || hwnd == pane.next || hwnd == pane.prepare ||
        hwnd == pane.whole || hwnd == pane.copy || hwnd == pane.exportText || hwnd == pane.columns || hwnd == pane.columnsB)) {
        if (!(lp & (1LL << 30)) && ::IsWindowEnabled(hwnd)) ::SendMessageW(hwnd, BM_CLICK, 0, 0);
        return 0;
    }
    if (message == WM_CHAR && (wp == L'\t' || wp == L'\r')) return 0;
    return ::DefSubclassProc(hwnd, message, wp, lp);
}
// 创建共享布局及原生等价文本视口；纯Win32 Light不依赖Qt CodeEditorWidget。
bool Create(Pane& pane) {
    if (!pane.parameters.Create(pane.hwnd)) return false;
    const HWND body = pane.parameters.Body();
    pane.hint = Ui::CreateText(body, 0, L"AAIM1范围候选：成功Alloc实际输出、执行Protect实际输出。这里只读原项目同采样，不扫描未来段、不另建项目。选择不暂停、不继续、不纳入。", 0, 0, 1, 1);
    pane.identity = Ui::CreateText(body, 0, L"", 0, 0, 1, 1);
    pane.status = Ui::CreateText(body, 0, L"", 0, 0, 1, 1);
    pane.throughLabel = Ui::CreateText(body, 0, L"显式截止raw段（从1连续核验）", 0, 0, 1, 1);
    pane.baseLabel = Ui::CreateText(body, 0, L"所选调用的整页子范围起点（不取整）", 0, 0, 1, 1);
    pane.pagesLabel = Ui::CreateText(body, 0, L"子范围4 KiB页数（最多64页）", 0, 0, 1, 1);
    const auto combo = [&](int id) { return ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 1, 1, body, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr); };
    pane.through = combo(kThrough);
    pane.pages = combo(kPages);
    pane.base = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 1, 1, body, reinterpret_cast<HMENU>(kBase), ::GetModuleHandleW(nullptr), nullptr);
    pane.whole = Ui::CreateButton(body, kWhole, L"采用所选实际整段", 0, 0, 1, 1);
    pane.read = Ui::CreateButton(pane.hwnd, kRead, L"读取首8行 / 重试", 0, 0, 1, 1);
    pane.next = Ui::CreateButton(pane.hwnd, kNext, L"同snapshot下一页", 0, 0, 1, 1);
    pane.prepare = Ui::CreateButton(pane.hwnd, kPrepare, L"仅载入AddRange草稿", 0, 0, 1, 1);
    pane.columns = Ui::CreateButton(pane.hwnd, kColumns, L"A", 0, 0, 1, 1, Ui::ButtonRole::Primary);
    pane.columnsB = Ui::CreateButton(pane.hwnd, kColumnsB, L"B", 0, 0, 1, 1, Ui::ButtonRole::Primary);
    pane.list = Ui::CreateReportListView(pane.hwnd, kList, 0, 0, 1, 1, LVS_SINGLESEL);
    pane.copy = Ui::CreateButton(pane.hwnd, kCopy, L"复制详情", 0, 0, 1, 1);
    pane.exportText = Ui::CreateButton(pane.hwnd, kExport, L"导出详情", 0, 0, 1, 1);
    pane.details = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
        0, 0, 1, 1, pane.hwnd, reinterpret_cast<HMENU>(kDetails), ::GetModuleHandleW(nullptr), nullptr);
    for (const HWND control : {pane.hint, pane.identity, pane.status, pane.throughLabel, pane.baseLabel, pane.pagesLabel}) {
        if (!control) return false;
        const auto style = ::GetWindowLongPtrW(control, GWL_STYLE);
        ::SetWindowLongPtrW(control, GWL_STYLE, (style & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFT);
    }
    for (const HWND control : {pane.through, pane.pages, pane.base, pane.whole, pane.read, pane.next, pane.prepare,
        pane.columns, pane.columnsB, pane.list, pane.copy, pane.exportText, pane.details})
        if (!control || !::SetWindowSubclass(control, Navigate, 1, reinterpret_cast<DWORD_PTR>(&pane))) return false;
    for (unsigned i = 1; i <= 128; ++i) {
        const auto label = std::to_wstring(i);
        if (::SendMessageW(pane.through, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str())) < 0) return false;
        if (i <= 64 && ::SendMessageW(pane.pages, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str())) < 0) return false;
    }
    ::SendMessageW(pane.through, CB_SETCURSEL, 0, 0);
    ::SendMessageW(pane.pages, CB_SETCURSEL, 0, 0);
    // 所有列只创建一次，显示组各自精简；操作条None，业务动作在固定参数footer。
    for (int index = 0; index < static_cast<int>(kColumnNames.size()); ++index) {
        pane.columnWidths[index] = Scale(kColumnWidths[index]);
        if (!Ui::AddListViewColumn(pane.list, {index, pane.columnWidths[index], LVCFMT_LEFT, kColumnNames[index]})) return false;
    }
    ApplyColumns(pane);
    ListView_SetBkColor(pane.list, Ui::AppTheme().panelColor);
    ListView_SetTextBkColor(pane.list, Ui::AppTheme().panelColor);
    ListView_SetTextColor(pane.list, Ui::AppTheme().textColor);
    pane.tooltip = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, pane.hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (!pane.tooltip) return false;
    const auto tip = [&](HWND control, const wchar_t* text) {
        TOOLINFOW tool{sizeof(tool)};
        tool.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
        tool.hwnd = pane.hwnd;
        tool.uId = reinterpret_cast<UINT_PTR>(control);
        tool.lpszText = const_cast<wchar_t*>(text);
        ::SendMessageW(pane.tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&tool));
    };
    tip(pane.read, L"从raw段1到明确选择的截止段完整核验，读取首8行。失败保留旧目录和身份；不自动查找未来段。");
    tip(pane.next, L"冻结当前成功目录的截止段、完整snapshot及nextAfter续读8行；不采用后来编辑的截止段。失败可原位重试。");
    tip(pane.whole, L"仅在整个实际输出满足4 KiB对齐和1..64页时，将该范围填入本页子范围草稿；不纳入目标。");
    tip(pane.prepare, L"共享Prepare核验所选整页子范围，再匹配原native PID+创建时间及项目/sample，仅载入原AddRange草稿；旧草稿需确认替换。不会暂停、继续或自动纳入。");
    tip(pane.columns, L"A：精简实际范围视角，含目标强实例、成功实际输出及原执行保护。表头右键可逐列选择。");
    tip(pane.columnsB, L"B：精简原调用来源视角，含raw坐标、来源代次、源序号及Free仅请求计数。自定义列后A/B均不强调。");
    tip(pane.copy, L"复制同一完整详情正文，保留原API来源、实际输出、Free请求和冻结目录身份。");
    tip(pane.exportText, L"将同一完整详情正文导出为UTF-8文本；不重新读取项目或目标。");
    tip(pane.through, L"显式选择1..128段；只有点击读取才生效，修改不改变旧结果来源或续页游标。");
    tip(pane.base, L"显式输入非零4 KiB对齐起点，必须完整包含在所选成功实际输出中，不向外取整。");
    tip(pane.pages, L"选择1..64个4 KiB页。实际MEM_PRIVATE、allocation、重叠和总页预算由原Held owner最终核验。");
    ::SendMessageW(pane.tooltip, TTM_SETMAXTIPWIDTH, 0, Scale(460));
    ::SendMessageW(pane.details, EM_SETLIMITTEXT, 0, 0);
    ::SendMessageW(pane.base, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"非零4 KiB对齐，十进制或0x"));
    Ui::AttachTextFindSupport(pane.details);
    Ui::SetWindowFontRecursive(pane.hwnd);
    Rebuild(pane);
    Refresh(pane);
    Layout(pane);
    return true;
}
// 页窗口分派本地交互与显示刷新；销毁只回收Pane资源，native责任仍归原页。
LRESULT CALLBACK Proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* pane = reinterpret_cast<Pane*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto owned = std::make_unique<Pane>();
        owned->hwnd = hwnd;
        owned->port = *static_cast<LightPrivateExecutionCandidatesPort*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        pane = owned.release();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pane));
    }
    if (!pane) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_CREATE: return Create(*pane) ? 0 : -1;
    case WM_SIZE: Layout(*pane); return 0;
    case WM_SHOWWINDOW:
        if (wp) { Refresh(*pane); ::SetTimer(hwnd, kDisplayTimer, 200, nullptr); }
        else ::KillTimer(hwnd, kDisplayTimer);
        return 0;
    case WM_TIMER: if (wp == kDisplayTimer) { Refresh(*pane); return 0; } break;
    case WM_NOTIFY: {
        const auto* notice = reinterpret_cast<NMHDR*>(lp);
        if (notice->hwndFrom == pane->list && notice->code == LVN_ITEMCHANGED) { Refresh(*pane); return 0; }
        break;
    }
    case WM_CONTEXTMENU: {
        const auto source = reinterpret_cast<HWND>(wp);
        if (source != pane->list && source != ListView_GetHeader(pane->list)) break;
        POINT point{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        if (point.x == -1 && point.y == -1) {
            point = {0, Scale(28)};
            ::ClientToScreen(pane->list, &point);
        }
        ColumnMenu(*pane, point);
        return 0;
    }
    case WM_MEASUREITEM: {
        auto& item = *reinterpret_cast<MEASUREITEMSTRUCT*>(lp);
        if (item.CtlType == ODT_MENU) {
            item.itemWidth = Scale(250);
            item.itemHeight = Scale(28);
            return TRUE;
        }
        break;
    }
    case WM_DRAWITEM: {
        const auto& item = *reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if (item.CtlType == ODT_MENU) {
            DrawColumnMenu(item);
            return TRUE;
        }
        if (item.hwndItem == pane->columns || item.hwndItem == pane->columnsB) {
            Ui::DrawThemedButton(item);
            return TRUE;
        }
        break;
    }
    case WM_COMMAND:
        if (!pane->loading && ((LOWORD(wp) == kBase && HIWORD(wp) == EN_CHANGE) || (LOWORD(wp) == kPages && HIWORD(wp) == CBN_SELCHANGE))) {
            pane->draftPage = pane->page;
            pane->draftRow = Selected(*pane);
            pane->error.clear();
            Refresh(*pane);
            return 0;
        }
        if (HIWORD(wp) == BN_CLICKED && !pane->retiring) {
            switch (LOWORD(wp)) {
            case kColumns:
            case kColumnsB:
                for (int index = 0; index < static_cast<int>(kColumnNames.size()); ++index) {
                    const int width = ListView_GetColumnWidth(pane->list, index);
                    if (width > 0) pane->columnWidths[index] = width;
                }
                pane->columnPreset = LOWORD(wp) == kColumns ? 0 : 1;
                ApplyColumns(*pane);
                return 0;
            case kRead: Read(*pane, false); return 0;
            case kNext: Read(*pane, true); return 0;
            case kWhole: Whole(*pane); return 0;
            case kPrepare: Prepare(*pane); return 0;
            case kCopy:
                if (!Ui::CopyTextToClipboard(hwnd, pane->detailsText, L"范围候选完整来源")) pane->error = L"复制失败，请重试。";
                Refresh(*pane); return 0;
            case kExport: {
                std::wstring error;
                if (Ui::SaveUtf8TextFileWithDialog(hwnd, L"private-execution-candidate.txt", L"导出候选详情", L"文本文件 (*.txt)\0*.txt\0", L"txt", pane->detailsText, &error) == Ui::SaveTextFileResult::Failed)
                    pane->error = std::move(error);
                Refresh(*pane); return 0;
            }
            }
        }
        break;
    case Ui::kBeginNativeRetirementMessage: pane->retiring = true; Refresh(*pane); return 0;
    case Ui::kCancelNativeRetirementMessage: pane->retiring = false; Refresh(*pane); return 0;
    case WM_CTLCOLORSTATIC:
        if (const auto brush = Ui::PaintLabelBackground(reinterpret_cast<HDC>(wp), reinterpret_cast<HWND>(lp), Ui::AppTheme().windowBrush(), Ui::AppTheme().textColor)) return brush;
        [[fallthrough]];
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
        ::SetTextColor(reinterpret_cast<HDC>(wp), Ui::AppTheme().textColor);
        ::SetBkColor(reinterpret_cast<HDC>(wp), Ui::AppTheme().panelColor);
        return reinterpret_cast<LRESULT>(Ui::AppTheme().panelBrush());
    case WM_ERASEBKGND: {
        RECT area{};
        ::GetClientRect(hwnd, &area);
        ::FillRect(reinterpret_cast<HDC>(wp), &area, Ui::AppTheme().windowBrush());
        return 1;
    }
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kDisplayTimer);
        if (pane->tooltip) ::DestroyWindow(pane->tooltip);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete pane;
        return 0;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}
}
// WorkspaceHost惰性工厂入口：输入父窗、尺寸和纯UI端口，输出新Pane窗口。
HWND CreateLightPrivateExecutionCandidatesPane(HWND parent, const RECT& bounds, LightPrivateExecutionCandidatesPort port) {
    WNDCLASSW type{};
    type.lpfnWndProc = Proc;
    type.hInstance = ::GetModuleHandleW(nullptr);
    type.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = Ui::AppTheme().windowBrush();
    type.lpszClassName = kClass;
    if (!::RegisterClassW(&type) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    return ::CreateWindowExW(WS_EX_CONTROLPARENT, kClass, L"私有范围候选", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, parent, nullptr, type.hInstance, &port);
}
} // namespace Ksword::Features::ActionAnalyze
