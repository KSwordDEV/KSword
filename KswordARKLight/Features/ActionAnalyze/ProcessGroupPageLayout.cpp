#include "ProcessGroupPageState.h"
#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include <algorithm>
#include <array>

namespace Ksword::Features::ActionAnalyze::process_group_page {
namespace {
using Ui::Scale;

// 由CreateControls调用，输入父窗口、稳定ID和EDIT风格，返回新控件或空句柄。
// 参数父窗口只能是共享Body，结果父窗口为页面；本函数不创建业务会话。
HWND Edit(HWND parent, int id, DWORD style)
{
    return ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
        0, 0, 1, 1, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
}

// 由CreateControls传入页面、目标控件和静态说明，向本页tooltip登记，无返回值。
// 静态悬停说明与控件句柄绑定，提示文本不从临时字符串借用内存。
void Tip(const Page& page, HWND control, const wchar_t* text)
{
    if (!page.tooltip) {
        return;
    }
    TOOLINFOW tool{sizeof(tool)}; // HWND即本页内稳定提示ID。
    tool.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    tool.hwnd = page.hwnd;
    tool.uId = reinterpret_cast<UINT_PTR>(control);
    tool.lpszText = const_cast<wchar_t*>(text);
    ::SendMessageW(page.tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&tool));
}

// Layout传入文字控件和可用像素宽度，返回当前字体下的自然像素高度。
// 参数说明不靠固定单行高度裁切，函数不查询目标进程或改写控件文字。
int TextHeight(HWND control, int width)
{
    const int length = ::GetWindowTextLengthW(control); // 只量既有本地文本，不调用业务查询。
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    ::GetWindowTextW(control, text.data(), length + 1);
    RECT bounds{0, 0, width, 0}; // DT_CALCRECT输出所需自然高度。
    const HDC dc = ::GetDC(control);
    if (!dc) {
        return Scale(48);
    }
    const auto prior = ::SelectObject(dc, Ui::SystemUIFont());
    ::DrawTextW(dc, text.c_str(), -1, &bounds, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    ::SelectObject(dc, prior);
    ::ReleaseDC(control, dc);
    return (std::max)(Scale(20), static_cast<int>(bounds.bottom));
}
} // namespace

// 页根创建或尺寸变化时调用；输入本页控件，原位更新几何，无业务输出。
void Layout(Page& page)
{
    RECT area{}; // 页根四边6px仅此处负责。
    ::GetClientRect(page.hwnd, &area);
    const int edge = Scale(6); // 页根唯一外边距。
    const int gap = Scale(8); // 相邻控件自然间隔。
    const int row = Scale(28); // 固定动作及输入行高。
    const int width = (std::max)(1, static_cast<int>(area.right) - 2 * edge); // 页根可用宽度。
    const bool columns = width >= Scale(1000); // 宽窗同时观察参数和结果；窄窗上下分区。
    const int parameterWidth = columns ? Scale(400) : width; // 宽窗限制参数宽度，结果吸收剩余空间。
    const int bodyWidth = (std::max)(1, parameterWidth - ::GetSystemMetrics(SM_CXVSCROLL)); // 预留共享滚动条。
    const auto move = [](HWND child, int x, int y, int w, int h) {
        ::MoveWindow(child, x, y, (std::max)(1, w), (std::max)(1, h), TRUE);
    };
    const std::array actions{page.configureButton, page.pauseAll, page.pauseSelected, page.continueAll,
        page.continueSelected, page.refresh, page.recover, page.close, page.newCollection, page.readMemory, page.saveMemory};
    const int actionsHeight = Ui::LayoutParameterActions(actions, edge, 0, width, Scale(144), row, gap, false);
    const int contentHeight = (std::max)(1, static_cast<int>(area.bottom) - 2 * edge - actionsHeight - gap);
    const int parameterHeight = columns ? contentHeight : (std::max)(1, contentHeight * 2 / 5);

    int y = 0; // Body为独立自然高度画布，不给每行分配剩余高度。
    const int hintHeight = TextHeight(page.hint, bodyWidth);
    move(page.hint, 0, y, bodyWidth, hintHeight);
    y += hintHeight + gap;
    const auto field = [&](HWND label, HWND input) {
        const int labelHeight = TextHeight(label, bodyWidth); // 窄窗标签独占行，避免长中文挤压输入。
        move(label, 0, y, bodyWidth, labelHeight);
        y += labelHeight;
        move(input, 0, y, bodyWidth, row);
        y += row + gap;
    };
    field(page.pidLabel, page.pid);
    field(page.creationLabel, page.creation);
    move(page.identityButton, 0, y, (std::min)(bodyWidth, Scale(120)), row);
    y += row + gap;
    move(page.identityView, 0, y, bodyWidth, Scale(72));
    y += Scale(72) + gap;
    const int authorizationHeight = TextHeight(page.authorized, bodyWidth) + Scale(8);
    move(page.authorized, 0, y, bodyWidth, authorizationHeight);
    y += authorizationHeight + gap;
    const std::array draftActions{page.addButton, page.removeButton}; // 草稿编辑动作不混入控制footer。
    y += Ui::LayoutParameterActions(draftActions, 0, y, bodyWidth, Scale(120), row, gap) + gap;
    field(page.projectLabel, page.projectDirectory);
    field(page.memoryBaseLabel, page.memoryBase);
    field(page.memoryBytesLabel, page.memoryBytes);
    page.parameters.Layout(edge, edge, parameterWidth, parameterHeight, y);
    Ui::LayoutParameterActions(actions, edge, edge + contentHeight + gap, width, Scale(144), row, gap);

    const int resultX = columns ? edge + parameterWidth + gap : edge;
    const int resultY = columns ? edge : edge + parameterHeight + gap;
    const int resultWidth = columns ? width - parameterWidth - gap : width;
    const int resultHeight = columns ? contentHeight : contentHeight - parameterHeight - gap;
    const int statusHeight = (std::min)(Scale(56), (std::max)(1, resultHeight / 6)); // 状态保持紧凑，主空间留给清单。
    move(page.status, resultX, resultY, resultWidth, statusHeight);
    const std::array textActions{page.copyDetails, page.exportDetails}; // 详情自己的工具，不改变成员表操作条模式。
    const int toolsHeight = Ui::LayoutParameterActions(textActions, 0, 0, resultWidth, Scale(104), row, gap, false);
    const int listY = resultY + statusHeight + gap; // 状态下方主清单的顶部。
    const int flexibleHeight = (std::max)(2, resultHeight - statusHeight - row - toolsHeight - 4 * gap);
    const int listHeight = (std::max)(1, flexibleHeight * 3 / 5); // 扣掉固定工具后再分配清单和正文高度。
    move(page.members, resultX, listY, resultWidth, listHeight);
    const int historyY = listY + listHeight + gap;
    move(page.history, resultX, historyY, resultWidth, Scale(220)); // 下拉高度含popup，不扩大关闭态行高。
    const int toolsY = historyY + row + gap; // 历史票据与详情工具分别占自然行高。
    Ui::LayoutParameterActions(textActions, resultX, toolsY, resultWidth, Scale(104), row, gap);
    const int detailY = toolsY + toolsHeight + gap;
    move(page.details, resultX, detailY, resultWidth, resultY + resultHeight - detailY);
}

// WM_CREATE传入本页状态，创建共享参数/结果及提示；成功返回true，失败由宿主撤回本页。
bool CreateControls(Page& page)
{
    if (!page.parameters.Create(page.hwnd)) {
        return false;
    }
    const HWND body = page.parameters.Body(); // 所有参数均直接进入唯一共享滚动正文。
    page.hint = Ui::CreateText(body, 0, L"仅控制明确授权的进程实例。配置只核验，不暂停。Held范围逐页读取不是原子进程转储；失败不转实时，不补零。", 0, 0, 1, 1);
    page.pidLabel = Ui::CreateText(body, 0, L"目标 PID", 0, 0, 1, 1);
    page.pid = Edit(body, kPid, ES_AUTOHSCROLL | ES_NUMBER);
    page.creationLabel = Ui::CreateText(body, 0, L"创建 FILETIME", 0, 0, 1, 1);
    page.creation = Edit(body, kCreation, ES_AUTOHSCROLL | ES_NUMBER);
    page.identityButton = Ui::CreateButton(body, kIdentify, L"读取身份", 0, 0, 1, 1);
    page.identityView = Edit(body, 0, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL);
    page.authorized = ::CreateWindowExW(0, L"BUTTON", L"我已获得对这些进程实例的明确授权",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE,
        0, 0, 1, 1, body, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kAuthorized)), ::GetModuleHandleW(nullptr), nullptr);
    page.addButton = Ui::CreateButton(body, kAdd, L"加入集合", 0, 0, 1, 1);
    page.removeButton = Ui::CreateButton(body, kRemove, L"移除选中", 0, 0, 1, 1);
    page.projectLabel = Ui::CreateText(body, 0, L"新项目目录（可选）", 0, 0, 1, 1);
    page.projectDirectory = Edit(body, kProject, ES_AUTOHSCROLL);
    page.memoryBaseLabel = Ui::CreateText(body, 0, L"起始地址（0x或十进制）", 0, 0, 1, 1);
    page.memoryBase = Edit(body, kMemoryBase, ES_AUTOHSCROLL);
    page.memoryBytesLabel = Ui::CreateText(body, 0, L"范围字节数（十进制）", 0, 0, 1, 1);
    page.memoryBytes = Edit(body, kMemoryBytes, ES_AUTOHSCROLL);

    // 共享CreateText默认为单行；本页测量过的说明和字段标签必须允许真实折行。
    for (const auto label : {page.hint, page.pidLabel, page.creationLabel, page.projectLabel,
        page.memoryBaseLabel, page.memoryBytesLabel}) {
        if (label) {
            const LONG_PTR style = ::GetWindowLongPtrW(label, GWL_STYLE); // 仅替换静态控件类型，保留可见与父子关系。
            ::SetWindowLongPtrW(label, GWL_STYLE, (style & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFT);
        }
    }

    // 执行动作是页根固定控件，不嵌入参数滚动区或结果表操作条。
    page.configureButton = Ui::CreateButton(page.hwnd, kConfigure, L"冻结并配置集合", 0, 0, 1, 1, Ui::ButtonRole::Primary);
    page.pauseAll = Ui::CreateButton(page.hwnd, kPauseAll, L"暂停全部成员", 0, 0, 1, 1);
    page.pauseSelected = Ui::CreateButton(page.hwnd, kPauseSelected, L"暂停选中成员", 0, 0, 1, 1);
    page.continueAll = Ui::CreateButton(page.hwnd, kContinueAll, L"继续全部成员", 0, 0, 1, 1);
    page.continueSelected = Ui::CreateButton(page.hwnd, kContinueSelected, L"继续选中成员", 0, 0, 1, 1);
    page.refresh = Ui::CreateButton(page.hwnd, kRefresh, L"刷新状态", 0, 0, 1, 1);
    page.recover = Ui::CreateButton(page.hwnd, kRecover, L"恢复原继续票据", 0, 0, 1, 1);
    page.close = Ui::CreateButton(page.hwnd, kClose, L"关闭并清退集合", 0, 0, 1, 1, Ui::ButtonRole::Danger);
    page.newCollection = Ui::CreateButton(page.hwnd, kNewCollection, L"准备新集合", 0, 0, 1, 1);
    page.readMemory = Ui::CreateButton(page.hwnd, kReadMemory, L"读取选中停点内存", 0, 0, 1, 1);
    page.saveMemory = Ui::CreateButton(page.hwnd, kSaveMemory, L"保存本次内存快照", 0, 0, 1, 1);
    page.members = Ui::CreateReportListView(page.hwnd, kMembers, 0, 0, 1, 1);
    if (page.members) {
        const auto style = ::GetWindowLongPtrW(page.members, GWL_STYLE); // 保留共享列表主题与扩展样式，仅允许多选。
        ::SetWindowLongPtrW(page.members, GWL_STYLE, style & ~static_cast<LONG_PTR>(LVS_SINGLESEL));
        Ui::AddListViewColumns(page.members, {{0, Scale(88), LVCFMT_RIGHT, L"PID"},
            {1, Scale(170), LVCFMT_LEFT, L"成员状态"}, {2, Scale(100), LVCFMT_LEFT, L"清退确认"}});
    }
    page.history = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
        CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0, 1, 1, page.hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kHistory)), ::GetModuleHandleW(nullptr), nullptr);
    page.details = Edit(page.hwnd, kDetails, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL);
    page.status = Edit(page.hwnd, kStatus, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL);
    page.copyDetails = Ui::CreateButton(page.hwnd, kCopyDetails, L"复制完整详情", 0, 0, 1, 1);
    page.exportDetails = Ui::CreateButton(page.hwnd, kExportDetails, L"导出完整详情", 0, 0, 1, 1);

    const std::array controls{page.pid, page.creation, page.identityButton, page.identityView, page.authorized,
        page.addButton, page.removeButton, page.projectDirectory, page.memoryBase, page.memoryBytes,
        page.configureButton, page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected,
        page.refresh, page.recover, page.close, page.newCollection, page.readMemory, page.saveMemory,
        page.members, page.history, page.details, page.status, page.copyDetails, page.exportDetails}; // 完整键盘目标控件集合。
    for (const auto control : controls) {
        if (!control || !::SetWindowSubclass(control, Navigate, 1, reinterpret_cast<DWORD_PTR>(&page))) {
            return false;
        }
    }
    for (const auto label : {page.hint, page.pidLabel, page.creationLabel, page.projectLabel,
        page.memoryBaseLabel, page.memoryBytesLabel}) {
        if (!label) {
            return false;
        }
    }
    ::SendMessageW(page.pid, EM_SETLIMITTEXT, 10, 0);
    ::SendMessageW(page.details, EM_SETLIMITTEXT, 0, 0); // 完整详情不受EDIT默认32KiB输入预算截断。
    ::SendMessageW(page.projectDirectory, EM_SETLIMITTEXT, 32767, 0);
    for (const auto input : {page.creation, page.memoryBase, page.memoryBytes}) {
        ::SendMessageW(input, EM_SETLIMITTEXT, 20, 0); // 数值长度与解析器的uint64边界一致。
    }
    page.tooltip = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, page.hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    Tip(page, page.identityButton, L"只读回读PID的创建FILETIME和映像路径，不附加、不暂停。");
    Tip(page, page.pid, L"十进制进程号；加入集合后与真实创建FILETIME一起冻结。");
    Tip(page, page.creation, L"非零十进制创建FILETIME；留空时必须先读取同PID的真实身份。");
    Tip(page, page.authorized, L"只声明当前草稿实例的明确授权，勾选本身不配置、不暂停。");
    Tip(page, page.memoryBase, L"非零起始地址，0x前缀按十六进制，其余按十进制；修改不改写旧结果。");
    Tip(page, page.memoryBytes, L"非零十进制字节数；读取前复核完整停点，访问失败保留真实错误。");
    Tip(page, page.history, L"选择原票据仅切换详情，Recover只复用本集合的原Continue票据。");
    Tip(page, page.addButton, L"加入精确PID与创建时间草稿，同PID只保留一次。");
    Tip(page, page.removeButton, L"只移除未冻结草稿的选中实例，不影响旧结果。");
    Tip(page, page.configureButton, L"冻结全部实例、授权与新项目目录；先登记真实sample，再核对集合身份，不暂停。");
    Tip(page, page.pauseAll, L"按全部冻结成员请求暂停，不宣称原子同步停住。");
    Tip(page, page.pauseSelected, L"冻结当前全部选中实例后请求暂停，不从首行推断全组。");
    Tip(page, page.continueAll, L"每个冻结成员必须都有当前完整停点令牌才提交整组继续。");
    Tip(page, page.continueSelected, L"只继续点击时选中的实例，逐成员保留真实失败回执。");
    Tip(page, page.refresh, L"只回读原集合状态，不生成暂停或继续请求。");
    Tip(page, page.recover, L"复用所选原Continue票据请求恢复，不新增继续责任。");
    Tip(page, page.close, L"由原owner清退；未clean保活，确认clean后归还本端项目writer。");
    Tip(page, page.newCollection, L"只有原集合清退确认后才开放新草稿；旧结果保留至显式配置下一集合。");
    Tip(page, page.projectDirectory, L"可选尚不存在的新目录，不占其它页面writer；留空可读，不能保存。");
    Tip(page, page.readMemory, L"读取唯一选中完整Held成员的显式范围；同原worker前后Query，不自动Continue，不回退Live。");
    Tip(page, page.saveMemory, L"保存显示的原capture与readContext至原sample，只写真实成功页及失败元数据；坏尾禁止跳段。");
    Tip(page, page.copyDetails, L"复制当前完整详情，包括原成员身份、票据及内存归档来源，不从新参数重建。");
    Tip(page, page.exportDetails, L"将同一完整详情导出为UTF-8文本；内存原字节须通过保存快照归档。");
    if (page.tooltip) {
        ::SendMessageW(page.tooltip, TTM_SETMAXTIPWIDTH, 0, Scale(460));
    }
    Ui::AttachTextFindSupport(page.details); // 同一完整文本承载搜索与原生选择复制，不造隐藏副本。
    Ui::SetWindowFontRecursive(page.hwnd);
    Layout(page);
    Refresh(page);
    return true;
}
} // namespace Ksword::Features::ActionAnalyze::process_group_page
