#include "ExecutionGroupPageState.h"
#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/TextFindSupport.h"
#include <algorithm>

namespace Ksword::Features::ActionAnalyze::execution_group_page {
namespace {
using Ui::Scale;
HWND Edit(HWND parent, int id, DWORD style = ES_AUTOHSCROLL)
{
    return ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
        0, 0, 1, 1, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
}
HWND Combo(HWND parent, int id)
{
    return ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
        CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0, 1, 1, parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
}
void Wrap(HWND label)
{
    const auto style = ::GetWindowLongPtrW(label, GWL_STYLE);
    ::SetWindowLongPtrW(label, GWL_STYLE, (style & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFT);
}
int TextHeight(HWND control, int width)
{
    const auto text = InputText(control);
    RECT rect{0, 0, width, 0};
    const auto dc = ::GetDC(control);
    if (!dc) return Scale(48);
    const auto old = ::SelectObject(dc, Ui::SystemUIFont());
    ::DrawTextW(dc, text.c_str(), -1, &rect, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    ::SelectObject(dc, old);
    ::ReleaseDC(control, dc);
    return (std::max)(Scale(20), static_cast<int>(rect.bottom));
}
void Tip(const Page& page, HWND control, const wchar_t* text)
{
    TOOLINFOW tool{sizeof(tool)};
    tool.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    tool.hwnd = page.hwnd;
    tool.uId = reinterpret_cast<UINT_PTR>(control);
    tool.lpszText = const_cast<wchar_t*>(text);
    ::SendMessageW(page.tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&tool));
}
}

void Layout(Page& page)
{
    RECT rect{};
    ::GetClientRect(page.hwnd, &rect);
    const int edge = Scale(6), gap = Scale(8), row = Scale(28);
    const int width = (std::max)(1, static_cast<int>(rect.right) - 2 * edge);
    const bool wide = width >= Scale(1000);
    const int parametersWidth = wide ? Scale(340) : width;
    const int bodyWidth = (std::max)(1, parametersWidth - ::GetSystemMetrics(SM_CXVSCROLL));
    const auto move = [](HWND child, int x, int y, int w, int h) {
        ::MoveWindow(child, x, y, (std::max)(1, w), (std::max)(1, h), TRUE);
    };
    const std::array actions{page.start, page.query, page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected,
        page.stepInto, page.stepOver, page.stepOut, page.cancelStep, page.close};
    const int actionsHeight = Ui::LayoutParameterActions(actions, edge, 0, width, Scale(136), row, gap, false);
    const int contentHeight = (std::max)(1, static_cast<int>(rect.bottom) - 2 * edge - actionsHeight - gap);
    const int parameterHeight = wide ? contentHeight : (std::max)(1, contentHeight / 3);
    int y = 0;
    const int hintHeight = TextHeight(page.hint, bodyWidth);
    move(page.hint, 0, y, bodyWidth, hintHeight);
    y += hintHeight + gap;
    for (std::size_t i = 0; i < FieldCount; ++i) {
        const int labelHeight = TextHeight(page.labels[i], bodyWidth);
        move(page.labels[i], 0, y, bodyWidth, labelHeight);
        y += labelHeight;
        const int height = i == Condition ? 3 * row : row;
        move(page.inputs[i], 0, y, bodyWidth, height);
        y += height + gap;
        if (i == Creation) {
            move(page.identify, 0, y, (std::min)(bodyWidth, Scale(136)), row);
            y += row + gap;
            const int identityHeight = TextHeight(page.identity, bodyWidth);
            move(page.identity, 0, y, bodyWidth, identityHeight);
            y += identityHeight + gap;
        }
    }
    move(page.draft, 0, y, bodyWidth, Scale(240));
    y += row + gap;
    const std::array draftActions{page.add, page.remove, page.loadDraft};
    y += Ui::LayoutParameterActions(draftActions, 0, y, bodyWidth, Scale(104), row, gap) + gap;
    const int authorizationHeight = TextHeight(page.authorized, bodyWidth) + gap;
    move(page.authorized, 0, y, bodyWidth, authorizationHeight);
    y += authorizationHeight + gap;
    page.parameters.Layout(edge, edge, parametersWidth, parameterHeight, y);
    Ui::LayoutParameterActions(actions, edge, edge + contentHeight + gap, width, Scale(136), row, gap);

    const int x = wide ? edge + parametersWidth + gap : edge;
    const int top = wide ? edge : edge + parameterHeight + gap;
    const int resultWidth = wide ? width - parametersWidth - gap : width;
    const int resultHeight = wide ? contentHeight : contentHeight - parameterHeight - gap;
    const int statusHeight = (std::min)(Scale(60), (std::max)(1, resultHeight / 6));
    move(page.status, x, top, resultWidth, statusHeight);
    move(page.preset, x, top + statusHeight + gap, resultWidth, Scale(180));
    const std::array tools{page.textMode, page.copy, page.exportText};
    const int toolsHeight = Ui::LayoutParameterActions(tools, 0, 0, resultWidth, Scale(104), row, gap, false);
    const int listTop = top + statusHeight + row + 2 * gap;
    const int available = (std::max)(2, top + resultHeight - listTop - toolsHeight - 2 * gap);
    const int listHeight = (std::max)(1, available * 2 / 3);
    move(page.members, x, listTop, resultWidth, listHeight);
    const int toolsTop = listTop + listHeight + gap;
    Ui::LayoutParameterActions(tools, x, toolsTop, resultWidth, Scale(104), row, gap);
    const int textTop = toolsTop + toolsHeight + gap;
    move(page.text, x, textTop, resultWidth, top + resultHeight - textTop);
}

bool CreateControls(Page& page)
{
    if (!page.parameters.Create(page.hwnd)) return false;
    const auto body = page.parameters.Body();
    page.hint = Ui::CreateText(body, 0,
        L"显式执行站点：每进程一个，最多16个。填写模块路径及RVA或导出名，或填写私有地址及可选范围。加入草稿后显式启动；逐成员回读不证明同时冻结。", 0, 0, 1, 1);
    Wrap(page.hint);
    constexpr std::array<const wchar_t*, FieldCount> names{L"PID（十进制）", L"创建 FILETIME（十进制）",
        L"普通模块绝对路径（与私有地址互斥）", L"模块 RVA（十六进制，与导出二选一）", L"精确导出名（区分大小写）",
        L"私有执行地址（十六进制）", L"私有范围字节数（十进制，0为单地址）", L"命中条件（可空，启动时冻结）"};
    for (std::size_t i = 0; i < FieldCount; ++i) {
        page.labels[i] = Ui::CreateText(body, 0, names[i], 0, 0, 1, 1);
        Wrap(page.labels[i]);
        page.inputs[i] = Edit(body, kPid + static_cast<int>(i), i == Condition ?
            ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL : ES_AUTOHSCROLL);
        ::SendMessageW(page.inputs[i], EM_SETLIMITTEXT, i == Module ? 32767 : i == Condition ? 16384 : i == Export ? 4096 : 20, 0);
    }
    page.identify = Ui::CreateButton(body, kIdentify, L"读取 PID 身份", 0, 0, 1, 1);
    page.identity = Ui::CreateText(body, 0, L"尚未读取身份；读取后显式加入草稿。", 0, 0, 1, 1);
    Wrap(page.identity);
    page.draft = Combo(body, kDraft);
    page.add = Ui::CreateButton(body, kAdd, L"加入草稿", 0, 0, 1, 1);
    page.remove = Ui::CreateButton(body, kRemove, L"移除草稿项", 0, 0, 1, 1);
    page.loadDraft = Ui::CreateButton(body, kLoadDraft, L"载入草稿项", 0, 0, 1, 1);
    page.authorized = ::CreateWindowExW(0, L"BUTTON", L"我已获得对本次全部进程实例的明确授权",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE, 0, 0, 1, 1, body,
        reinterpret_cast<HMENU>(kAuthorized), ::GetModuleHandleW(nullptr), nullptr);
    page.start = Ui::CreateButton(page.hwnd, kStart, L"启动执行集合", 0, 0, 1, 1, Ui::ButtonRole::Primary);
    page.query = Ui::CreateButton(page.hwnd, kQuery, L"刷新原集合", 0, 0, 1, 1);
    page.pauseAll = Ui::CreateButton(page.hwnd, kPauseAll, L"暂停全部成员", 0, 0, 1, 1);
    page.pauseSelected = Ui::CreateButton(page.hwnd, kPauseSelected, L"暂停选中成员", 0, 0, 1, 1);
    page.continueAll = Ui::CreateButton(page.hwnd, kContinueAll, L"继续全部成员", 0, 0, 1, 1);
    page.continueSelected = Ui::CreateButton(page.hwnd, kContinueSelected, L"继续选中成员", 0, 0, 1, 1);
    page.stepInto = Ui::CreateButton(page.hwnd, kStepInto, L"选中成员步入", 0, 0, 1, 1);
    page.stepOver = Ui::CreateButton(page.hwnd, kStepOver, L"选中成员步过", 0, 0, 1, 1);
    page.stepOut = Ui::CreateButton(page.hwnd, kStepOut, L"选中成员跳出", 0, 0, 1, 1);
    page.cancelStep = Ui::CreateButton(page.hwnd, kCancelStep, L"中止选中步进", 0, 0, 1, 1);
    page.close = Ui::CreateButton(page.hwnd, kClose, L"关闭并清退集合", 0, 0, 1, 1, Ui::ButtonRole::Danger);
    // 本表操作条为None；业务控制在固定底栏，完整文档操作在正文工具行。
    page.members = Ui::CreateReportListView(page.hwnd, kMembers, 0, 0, 1, 1);
    ::SetWindowLongPtrW(page.members, GWL_STYLE, ::GetWindowLongPtrW(page.members, GWL_STYLE) & ~static_cast<LONG_PTR>(LVS_SINGLESEL));
    page.preset = Combo(page.hwnd, kPreset);
    for (const auto title : {L"A · 执行站点与当前状态", L"B · 原生身份与停点票据", L"自定义列（表头右键）"})
        ::SendMessageW(page.preset, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(title));
    ::SendMessageW(page.preset, CB_SETCURSEL, 0, 0);
    page.textMode = Combo(page.hwnd, kTextMode);
    for (const auto title : {L"字段 Fields", L"结果 Result"})
        ::SendMessageW(page.textMode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(title));
    ::SendMessageW(page.textMode, CB_SETCURSEL, 0, 0);
    page.copy = Ui::CreateButton(page.hwnd, kCopy, L"复制完整正文", 0, 0, 1, 1);
    page.exportText = Ui::CreateButton(page.hwnd, kExportText, L"导出完整正文", 0, 0, 1, 1);
    page.text = Edit(page.hwnd, kText, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL);
    page.status = Edit(page.hwnd, kStatus, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL);
    ::SendMessageW(page.text, EM_SETLIMITTEXT, 0, 0);
    Ui::AttachTextFindSupport(page.text);
    std::vector<HWND> controls(page.inputs.begin(), page.inputs.end());
    for (const auto control : {page.identify, page.draft, page.add, page.remove, page.loadDraft, page.authorized,
        page.start, page.query, page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected, page.stepInto, page.stepOver,
        page.stepOut, page.cancelStep, page.close, page.members, page.preset, page.textMode, page.copy,
        page.exportText, page.text, page.status}) controls.push_back(control);
    for (const auto control : controls)
        if (!control || !::SetWindowSubclass(control, Navigate, 1, reinterpret_cast<DWORD_PTR>(&page))) return false;
    if (!::SetWindowSubclass(ListView_GetHeader(page.members), Navigate, 1, reinterpret_cast<DWORD_PTR>(&page))) return false;
    for (const auto label : page.labels) if (!label) return false;
    if (!page.hint || !page.identity) return false;
    page.tooltip = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, page.hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (page.tooltip) {
        ::SendMessageW(page.tooltip, TTM_SETMAXTIPWIDTH, 0, Scale(440));
        Tip(page, page.start, L"须有1–16个草稿站点、全集授权及已结清的旧集合。启动按值冻结全部参数，部分失败保留成功成员。");
        Tip(page, page.pauseAll, L"全部成员须可暂停或已持有停点，且至少一个需要暂停。整批核对身份后只向运行成员请求暂停；已停成员单列already-held回执。不证明同时冻结。");
        Tip(page, page.pauseSelected, L"所选成员须可暂停或已持有停点，且至少一个需要暂停。提交整个选区的完整快照；已停成员不重复请求暂停。");
        Tip(page, page.continueAll, L"全部成员须可继续或已运行，且至少一个需要继续。只继续精确Held停点；运行成员单列already-running回执，不伪造释放。");
        Tip(page, page.continueSelected, L"所选成员须可继续或已运行，且至少一个需要继续。提交整个选区的完整快照；运行成员不生成释放请求。");
        for (const auto button : {page.stepInto, page.stepOver, page.stepOut})
            Tip(page, button, L"只选一个当前断点或步进停点，命中条件须允许操作。主动暂停停点不支持步进。");
        Tip(page, page.cancelStep, L"只选一个仍在原生步进中的成员；中止复用该成员的原步进请求。");
        Tip(page, page.close, L"原集合清退未结清时保持存活，可再次点击重试；确认clean后才允许启动下一轮草稿。");
        Tip(page, page.query, L"回读原集合及真实成员状态；后台会话首次创建失败时可在此重试。");
        Tip(page, page.identify, L"在集合的同一个后台会话读取PID创建时间，不附加、不暂停；已有创建时间草稿不被覆盖。");
        Tip(page, page.add, L"将当前参数编译并加入下一轮草稿；不改变正在运行的成员或旧结果。修改已有项须先移除原草稿项。");
        Tip(page, page.draft, L"这里选择待执行的草稿项；原集合操作仅取右侧成员表选择。");
    }
    Ui::SetWindowFontRecursive(page.hwnd);
    RebuildColumns(page);
    RefreshDraft(page);
    Layout(page);
    return true;
}
}
