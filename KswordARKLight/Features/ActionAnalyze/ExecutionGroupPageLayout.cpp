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
    const std::array actions{page.start, page.appendMembers, page.query, page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected,
        page.addRange, page.stepInto, page.stepOver, page.stepOut, page.cancelStep, page.saveExecution, page.captureApi,
        page.readMemory, page.saveMemory, page.close};
    const int actionsHeight = Ui::LayoutParameterActions(actions, edge, 0, width, Scale(136), row, gap, false);
    const int contentHeight = (std::max)(1, static_cast<int>(rect.bottom) - 2 * edge - actionsHeight - gap);
    const int parameterHeight = wide ? contentHeight : (std::max)(1, contentHeight / 3);
    int y = 0;
    const int hintHeight = TextHeight(page.hint, bodyWidth);
    move(page.hint, 0, y, bodyWidth, hintHeight);
    y += hintHeight + gap;
    for (std::size_t i = 0; i < FieldCount; ++i) {
        // 私有地址隐藏模块约束，导出隐藏RVA定义；切换时只改可见性，保留各自草稿。
        if (i == ImageSha256 || i == DefinitionId)
        {
            const bool image = InputText(page.inputs[Address]).empty(); // 现有页面用私有地址是否填写区分站点机制。
            const bool visible = image && (i != DefinitionId || InputText(page.inputs[Export]).empty()); // 定义只随RVA站点发送。
            ::ShowWindow(page.labels[i], visible ? SW_SHOW : SW_HIDE);
            ::ShowWindow(page.inputs[i], visible ? SW_SHOW : SW_HIDE);
            if (!visible)
            {
                continue;
            }
        }
        const int labelHeight = TextHeight(page.labels[i], bodyWidth);
        move(page.labels[i], 0, y, bodyWidth, labelHeight);
        y += labelHeight;
        const int height = i == Condition ? 3 * row : row;
        move(page.inputs[i], 0, y, bodyWidth, height);
        y += height + gap;
        if (i == Range) {
            const int rangeHintHeight = TextHeight(page.rangeHint, bodyWidth);
            move(page.rangeHint, 0, y, bodyWidth, rangeHintHeight);
            y += rangeHintHeight + gap;
        }
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
    // 归档路径属于下一轮Start草稿，与所选成员及保存动作分开；只用现有参数正文滚动。
    const int projectHeight = TextHeight(page.projectLabel, bodyWidth); // 长中文按实际宽度折行。
    move(page.projectLabel, 0, y, bodyWidth, projectHeight);
    y += projectHeight;
    move(page.projectDirectory, 0, y, bodyWidth, row);
    y += row + gap;
    const int openHeight = TextHeight(page.openProject, bodyWidth) + gap; // 复选框保留完整新采样语义。
    move(page.openProject, 0, y, bodyWidth, openHeight);
    y += openHeight + gap;
    const int peerHeight = TextHeight(page.holdPeersOnHit, bodyWidth) + gap; // 长文本复选框自然折行，复用原参数滚动。
    move(page.holdPeersOnHit, 0, y, bodyWidth, peerHeight);
    y += peerHeight + gap;
    for (std::size_t index = 0; index < page.apiInputs.size(); ++index)
    {
        const int labelHeight = TextHeight(page.apiLabels[index], bodyWidth); // 参数正文统一滚动，不把API字段挤到结果区。
        move(page.apiLabels[index], 0, y, bodyWidth, labelHeight);
        y += labelHeight;
        move(page.apiInputs[index], 0, y, bodyWidth, row);
        y += row + gap;
    }
    for (std::size_t index = 0; index < page.memoryInputs.size(); ++index)
    {
        const int labelHeight = TextHeight(page.memoryLabels[index], bodyWidth); // 范围标签与输入沿用唯一参数正文滚动。
        move(page.memoryLabels[index], 0, y, bodyWidth, labelHeight);
        y += labelHeight;
        move(page.memoryInputs[index], 0, y, bodyWidth, row);
        y += row + gap;
    }
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
        L"私有地址 / 追加NX起点（十六进制）", L"私有范围 / 追加字节数（十进制）", L"命中条件（可空，启动时冻结）",
        L"期望映像 SHA256（可选，仅模块导出/RVA）", L"冻结断点定义 ID（可选，仅模块RVA）"};
    for (std::size_t i = 0; i < FieldCount; ++i) {
        page.labels[i] = Ui::CreateText(body, 0, names[i], 0, 0, 1, 1);
        Wrap(page.labels[i]);
        const int id = i == DefinitionId ? kDefinitionId : i == ImageSha256 ? kImageSha256 : kPid + static_cast<int>(i); // 保留现有按钮和身份输入ID。
        page.inputs[i] = Edit(body, id, i == Condition ?
            ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL : ES_AUTOHSCROLL);
        const int limit = i == Module ? 32767 : i == Condition ? 16384 : i == Export ? 4096 :
            i == ImageSha256 || i == DefinitionId ? 128 : 20; // 超长身份保留为非法值，不截成有效输入。
        ::SendMessageW(page.inputs[i], EM_SETLIMITTEXT, limit, 0);
    }
    page.identify = Ui::CreateButton(body, kIdentify, L"读取 PID 身份", 0, 0, 1, 1);
    page.rangeHint = Ui::CreateText(body, 0,
        L"启动草稿：范围为0时使用单地址。追加范围：复用上方起点和字节数，点击底栏“追加选中NX范围”，仅追加到右侧单选的完整Held NX成员（允许主动暂停）。起点、长度须4KiB对齐，长度1–64页；不修改启动站点或条件，不继续目标。", 0, 0, 1, 1);
    Wrap(page.rangeHint);
    page.identity = Ui::CreateText(body, 0, L"尚未读取身份；读取后显式加入草稿。", 0, 0, 1, 1);
    Wrap(page.identity);
    page.draft = Combo(body, kDraft);
    page.add = Ui::CreateButton(body, kAdd, L"加入草稿", 0, 0, 1, 1);
    page.remove = Ui::CreateButton(body, kRemove, L"移除草稿项", 0, 0, 1, 1);
    page.loadDraft = Ui::CreateButton(body, kLoadDraft, L"载入草稿项", 0, 0, 1, 1);
    page.projectLabel = Ui::CreateText(body, 0, L"执行观察项目目录（可选；留空仅控制）", 0, 0, 1, 1);
    Wrap(page.projectLabel);
    page.projectDirectory = Edit(body, kProjectDirectory); // 支持粘贴完整路径，Start前不执行磁盘操作。
    ::SendMessageW(page.projectDirectory, EM_SETLIMITTEXT, 32767, 0);
    page.openProject = ::CreateWindowExW(0, L"BUTTON", L"打开已有项目，创建新采样",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE, 0, 0, 1, 1, body,
        reinterpret_cast<HMENU>(kOpenProject), ::GetModuleHandleW(nullptr), nullptr);
    page.holdPeersOnHit = ::CreateWindowExW(0, L"BUTTON", L"成员命中后暂停其他成员",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE, 0, 0, 1, 1, body,
        reinterpret_cast<HMENU>(kHoldPeersOnHit), ::GetModuleHandleW(nullptr), nullptr); // 默认未选，活集合中禁用编辑。
    const std::array<const wchar_t*, 3> apiTitles{L"同采样API来源PID（集合以外）", L"API来源创建FILETIME（十进制）", L"API采集时长（1000–10000毫秒）"}; // 自然高度标签保留单位。
    const std::array<int, 3> apiIds{kApiPid, kApiCreation, kApiDuration}; // 不改变已有站点字段ID。
    for (std::size_t index = 0; index < page.apiInputs.size(); ++index)
    {
        page.apiLabels[index] = Ui::CreateText(body, 0, apiTitles[index], 0, 0, 1, 1);
        Wrap(page.apiLabels[index]);
        page.apiInputs[index] = Edit(body, apiIds[index]);
        ::SendMessageW(page.apiInputs[index], EM_SETLIMITTEXT, index == 1 ? 20 : 10, 0); // 非法文本交原解析器拒绝。
    }
    ::SetWindowTextW(page.apiInputs[2], L"3000"); // 只设有限时长草稿，不默认选择来源PID。
    const std::array<const wchar_t*, 2> memoryTitles{L"停点内存起始地址（十六进制）", L"停点内存范围字节数（十进制，最多256KiB）"}; // 独立草稿不会修改已读取结果。
    const std::array<int, 2> memoryIds{kMemoryAddress, kMemoryBytes}; // 追加控件ID不改变既有导航。
    for (std::size_t index = 0; index < page.memoryInputs.size(); ++index)
    {
        page.memoryLabels[index] = Ui::CreateText(body, 0, memoryTitles[index], 0, 0, 1, 1);
        Wrap(page.memoryLabels[index]);
        page.memoryInputs[index] = Edit(body, memoryIds[index]);
        ::SendMessageW(page.memoryInputs[index], EM_SETLIMITTEXT, 20, 0);
    }
    page.authorized = ::CreateWindowExW(0, L"BUTTON", L"我已获得对本次全部进程实例的明确授权",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE, 0, 0, 1, 1, body,
        reinterpret_cast<HMENU>(kAuthorized), ::GetModuleHandleW(nullptr), nullptr);
    page.start = Ui::CreateButton(page.hwnd, kStart, L"启动执行集合", 0, 0, 1, 1, Ui::ButtonRole::Primary);
    page.appendMembers = Ui::CreateButton(page.hwnd, kAppendMembers, L"追加表单目标到本轮集合", 0, 0, 1, 1); // 复杂动作保留明确文字。
    page.query = Ui::CreateButton(page.hwnd, kQuery, L"刷新原集合", 0, 0, 1, 1);
    page.pauseAll = Ui::CreateButton(page.hwnd, kPauseAll, L"暂停全部成员", 0, 0, 1, 1);
    page.pauseSelected = Ui::CreateButton(page.hwnd, kPauseSelected, L"暂停选中成员", 0, 0, 1, 1);
    page.continueAll = Ui::CreateButton(page.hwnd, kContinueAll, L"继续全部成员", 0, 0, 1, 1);
    page.continueSelected = Ui::CreateButton(page.hwnd, kContinueSelected, L"继续选中成员", 0, 0, 1, 1);
    page.addRange = Ui::CreateButton(page.hwnd, kAddRange, L"追加选中NX范围", 0, 0, 1, 1);
    page.stepInto = Ui::CreateButton(page.hwnd, kStepInto, L"选中成员步入", 0, 0, 1, 1);
    page.stepOver = Ui::CreateButton(page.hwnd, kStepOver, L"选中成员步过", 0, 0, 1, 1);
    page.stepOut = Ui::CreateButton(page.hwnd, kStepOut, L"选中成员跳出", 0, 0, 1, 1);
    page.cancelStep = Ui::CreateButton(page.hwnd, kCancelStep, L"中止选中步进", 0, 0, 1, 1);
    page.saveExecution = Ui::CreateButton(page.hwnd, kSaveExecution, L"保存选中执行观察", 0, 0, 1, 1);
    page.captureApi = Ui::CreateButton(page.hwnd, kCaptureApi, L"采集同采样API", 0, 0, 1, 1); // 范围为单选原成员，来源另填。
    page.readMemory = Ui::CreateButton(page.hwnd, kReadMemory, L"读取选中停点内存", 0, 0, 1, 1); // 单成员明确范围读取。
    page.saveMemory = Ui::CreateButton(page.hwnd, kSaveMemory, L"保存本次内存快照", 0, 0, 1, 1); // 当前结果保存不受后来选区影响。
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
    controls.insert(controls.end(), page.apiInputs.begin(), page.apiInputs.end()); // 新来源字段参与原键盘导航，不另建窗口。
    controls.insert(controls.end(), page.memoryInputs.begin(), page.memoryInputs.end()); // 原键盘路由覆盖内存范围输入。
    for (const auto control : {page.identify, page.draft, page.add, page.remove, page.loadDraft, page.projectDirectory, page.openProject, page.holdPeersOnHit, page.authorized,
        page.start, page.appendMembers, page.query, page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected, page.addRange, page.stepInto, page.stepOver,
        page.stepOut, page.cancelStep, page.saveExecution, page.captureApi, page.readMemory, page.saveMemory, page.close, page.members, page.preset, page.textMode, page.copy,
        page.exportText, page.text, page.status}) controls.push_back(control);
    for (const auto control : controls)
        if (!control || !::SetWindowSubclass(control, Navigate, 1, reinterpret_cast<DWORD_PTR>(&page))) return false;
    if (!::SetWindowSubclass(ListView_GetHeader(page.members), Navigate, 1, reinterpret_cast<DWORD_PTR>(&page))) return false;
    for (const auto label : page.labels) if (!label) return false;
    for (const auto label : page.apiLabels) if (!label) return false; // 创建失败不能交付缺标签输入。
    for (const auto label : page.memoryLabels) if (!label) return false; // 内存范围必须有明确标签。
    if (!page.hint || !page.identity || !page.rangeHint || !page.projectLabel) return false;
    page.tooltip = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, page.hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (page.tooltip) {
        ::SendMessageW(page.tooltip, TTM_SETMAXTIPWIDTH, 0, Scale(440));
        Tip(page, page.start, L"须有1–16个草稿站点、全集授权及已结清的旧集合。启动按值冻结全部参数，部分失败保留成功成员。");
        Tip(page, page.appendMembers, L"明确授权后，冻结当前表单的新进程实例与条件，追加到本轮同一采样。已有成员和停点不替换、不继续。累计最多16个不同PID；失败保留原集合与恢复责任，可修改表单后重试。");
        Tip(page, page.pauseAll, L"全部成员须可暂停或已持有停点，且至少一个需要暂停。整批核对身份后只向运行成员请求暂停；已停成员单列already-held回执。不证明同时冻结。");
        Tip(page, page.pauseSelected, L"所选成员须可暂停或已持有停点，且至少一个需要暂停。提交整个选区的完整快照；已停成员不重复请求暂停。");
        Tip(page, page.continueAll, L"全部成员须可继续或已运行，且至少一个需要继续。只继续精确Held停点；运行成员单列already-running回执，不伪造释放。");
        Tip(page, page.continueSelected, L"所选成员须可继续或已运行，且至少一个需要继续。提交整个选区的完整快照；运行成员不生成释放请求。");
        Tip(page, page.addRange, L"须单选原集合的完整Held NX成员，允许主动暂停。只使用私有地址/范围字节草稿和点击时的完整停点，向原owner追加；不读取PID、模块或条件草稿，不修改启动站点，不继续。失败保留草稿、原集合和回执，可刷新后重试。");
        Tip(page, page.inputs[Address], L"加入草稿时作为启动私有地址；追加选中NX范围时作为新增范围起点。追加目标由右侧单选成员的原停点决定，不由PID草稿决定。");
        Tip(page, page.inputs[Range], L"启动时0表示单地址；追加时必须填写非零字节数，4KiB整数倍且不超过256KiB。编辑不会修改已保存草稿项或旧集合来源。");
        Tip(page, page.inputs[ImageSha256], L"只接受64位小写十六进制SHA256，留空不设约束。原生所有者核验实际调试装载文件后才武装DR0，不自动采集。私有地址时隐藏并保留草稿，不发送。");
        Tip(page, page.inputs[DefinitionId], L"仅模块RVA站点可填写规范UUID，并须配置项目。全部成员在附加前核对本轮采样冻结定义的启用状态、模块、RVA和映像散列；不解析PDB或激活系统所有实例。");
        for (const auto button : {page.stepInto, page.stepOver, page.stepOut})
            Tip(page, button, L"只选一个当前断点或步进停点，命中条件须允许操作。主动暂停停点不支持步进。");
        Tip(page, page.cancelStep, L"只选一个仍在原生步进中的成员；中止复用该成员的原步进请求。");
        Tip(page, page.saveExecution, L"启动前须配置项目。单选当前执行进入或单指令完成事件后显式保存，保留寄存器和事件时绑定；不继续本成员或同伴。相同事件返回原段坐标，追加失败不跳段。");
        Tip(page, page.captureApi, L"须配置本轮项目并单选仍附加的原成员。确认另一明确来源后采集1–10秒，写同一采样raw。集合全部成员不能作为来源；不Continue或自动保存执行事件，关闭时取消采集。");
        Tip(page, page.readMemory, L"冻结唯一选中成员的完整停点与下方内存范围，在原会话逐页读取；读前后回读原停点，不继续任何成员。主动暂停也可读取；失败不转实时读取。");
        Tip(page, page.saveMemory, L"将当前实际读取的范围和页状态写入本轮项目raw-memory；不按当前选择或参数重读，不补零。重复保存返回原段，写入失败后停止追加。");
        for (const auto input : page.memoryInputs)
        {
            Tip(page, input, L"只用于显式读取停点内存，与启动和追加NX范围分开。起点按十六进制、长度按十进制填写，最多256KiB；修改不改变已读结果来源。");
        }
        for (const auto input : page.apiInputs)
        {
            Tip(page, input, L"API来源与上方站点草稿分开。填写集合以外的明确PID、创建FILETIME及1000–10000毫秒；实际采集前显示确认。");
        }
        Tip(page, page.projectDirectory, L"默认新建项目；勾选打开已有项目时复用项目但创建新采样。项目或写租约失败会阻止本轮附加，不借用其它页面writer。");
        Tip(page, page.openProject, L"必须填写已有项目目录。每次Start均创建独立新采样，历史执行证据不恢复活控制权。");
        Tip(page, page.holdPeersOnHit, L"开始时冻结。新断点经条件处理仍持有时逐成员请求暂停；未知条件保留，假条件继续。主动暂停和步进不触发，同一事件只请求一次。");
        Tip(page, page.close, L"原集合清退未结清时保持存活，可再次点击重试；确认clean后才允许启动下一轮草稿。");
        Tip(page, page.query, L"回读原集合及真实成员状态；后台会话首次创建失败时可在此重试。");
        Tip(page, page.identify, L"在集合的同一个后台会话读取PID创建时间，不附加、不暂停；已有创建时间草稿不被覆盖。");
        Tip(page, page.add, L"将当前参数编译并加入下一轮草稿；不改变正在运行的成员或旧结果。修改已有项须先移除原草稿项。");
        Tip(page, page.draft, L"这里选择待执行的草稿项；原集合操作仅取右侧成员表选择。");
        Tip(page, page.loadDraft, L"显式载回选中草稿的全部参数及期望映像SHA256，不使用实际测量值覆盖期望约束，不改变原集合。");
    }
    Ui::SetWindowFontRecursive(page.hwnd);
    RebuildColumns(page);
    RefreshDraft(page);
    Layout(page);
    return true;
}
}
