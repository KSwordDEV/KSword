#include "NetworkTrafficPageState.h"
#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/TextFindSupport.h"

#include <algorithm>
#include <array>
#include <commctrl.h>

namespace Ksword::Features::ActionAnalyze::network_traffic_page {
namespace {
using Ui::Scale;

// 创建单行参数或原生多行正文；控件只属于页面，不携带后台对象。
HWND Edit(HWND parent, int id, DWORD style)
{
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
        0, 0, 1, 1, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
}

// 为当前本页动作登记静态tooltip，字符串生命周期覆盖窗口。
void Tip(const Page& page, HWND control, const wchar_t* text)
{
    TOOLINFOW tool{sizeof(tool)}; // 以目标HWND标识提示项。
    tool.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    tool.hwnd = page.hwnd;
    tool.uId = reinterpret_cast<UINT_PTR>(control);
    tool.lpszText = const_cast<wchar_t*>(text);
    SendMessageW(page.tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&tool));
}

// 使用真实字体测量折行说明，在窄窗不裁切前提文字。
int HintHeight(HWND control, int width)
{
    std::wstring text(static_cast<std::size_t>(GetWindowTextLengthW(control)) + 1, L'\0'); // 本地静态文字。
    GetWindowTextW(control, text.data(), static_cast<int>(text.size()));
    const HDC dc = GetDC(control); // 测量DC，返回前释放。
    if (!dc) {
        return Scale(80);
    }
    const auto prior = SelectObject(dc, Ui::SystemUIFont()); // 沿用本端字体。
    RECT bounds{0, 0, width, 0}; // 自然文字高度输出。
    DrawTextW(dc, text.c_str(), -1, &bounds, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    SelectObject(dc, prior);
    ReleaseDC(control, dc);
    return (std::max)(Scale(24), static_cast<int>(bounds.bottom));
}
} // namespace

// 本页不创建列表，文本详情沿用原生共享搜索与复制导出工具。
bool CreateControls(Page& page)
{
    if (!page.parameters.Create(page.hwnd)) {
        return false;
    }
    const auto body = page.parameters.Body(); // 参数唯一滚动责任者。
    page.hint = Ui::CreateText(body, 0,
        L"复用网络流量监控，向已有采样写入 IP 包。接口抓包后仅保留目标 PID 线索；不证明事件时强实例归属，覆盖率未知，HTTPS 解析后置。", 0, 0, 1, 1);
    page.projectLabel = Ui::CreateText(body, 0, L"项目路径", 0, 0, 1, 1);
    page.project = Edit(body, kProject, ES_AUTOHSCROLL);
    page.browse = Ui::CreateButton(body, kBrowse, L"选择已有项目…", 0, 0, 1, 1);
    page.sampleLabel = Ui::CreateText(body, 0, L"已有采样 UUID", 0, 0, 1, 1);
    page.sample = Edit(body, kSample, ES_AUTOHSCROLL);
    page.pidLabel = Ui::CreateText(body, 0, L"目标 PID", 0, 0, 1, 1);
    page.pid = Edit(body, kPid, ES_AUTOHSCROLL | ES_NUMBER);
    page.creationLabel = Ui::CreateText(body, 0, L"创建 FILETIME", 0, 0, 1, 1);
    page.creation = Edit(body, kCreation, ES_AUTOHSCROLL | ES_NUMBER);

    // 来源明确分列R3和既有WFP，不做失败后静默切换。
    page.sourceLabel = Ui::CreateText(body, 0, L"采集来源", 0, 0, 1, 1);
    page.source = CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 1, 1, body, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSource)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(page.source, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"raw-socket"));
    SendMessageW(page.source, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"existing-wfp"));
    SendMessageW(page.source, CB_SETCURSEL, 0, 0);
    page.durationLabel = Ui::CreateText(body, 0, L"采集时长（100..60000 ms）", 0, 0, 1, 1);
    page.duration = Edit(body, kDuration, ES_AUTOHSCROLL | ES_NUMBER);
    SetWindowTextW(page.duration, L"5000");
    page.ordinalLabel = Ui::CreateText(body, 0, L"网络段号（0 为最新）", 0, 0, 1, 1);
    page.ordinal = Edit(body, kOrdinal, ES_AUTOHSCROLL | ES_NUMBER);
    SetWindowTextW(page.ordinal, L"0");
    page.sequenceLabel = Ui::CreateText(body, 0, L"记录序号（可选）", 0, 0, 1, 1);
    page.sequence = Edit(body, kSequence, ES_AUTOHSCROLL | ES_NUMBER);

    // 固定动作明确区分写入与只读；正文工具始终作用于已经发布的原文本。
    page.capture = Ui::CreateButton(page.hwnd, kCapture, L"采集到原采样", 0, 0, 1, 1, Ui::ButtonRole::Primary);
    page.read = Ui::CreateButton(page.hwnd, kRead, L"读取网络段", 0, 0, 1, 1);
    page.cancel = Ui::CreateButton(page.hwnd, kCancel, L"停止采集", 0, 0, 1, 1);
    page.status = Ui::CreateText(page.hwnd, 0, L"尚未执行；请选择已有项目并填写采样 UUID。", 0, 0, 1, 1);
    page.receipt = Edit(page.hwnd, 0, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL);
    SendMessageW(page.receipt, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
    Ui::AttachTextFindSupport(page.receipt);
    page.copy = Ui::CreateButton(page.hwnd, kCopy, L"复制回执", 0, 0, 1, 1);
    page.exportText = Ui::CreateButton(page.hwnd, kExport, L"导出回执", 0, 0, 1, 1);
    page.find = Ui::CreateButton(page.hwnd, kFind, L"搜索回执", 0, 0, 1, 1);

    // 共享CreateText默认单行；本页说明与状态启用真实折行。
    for (const auto control : {page.hint, page.status}) {
        const auto style = GetWindowLongPtrW(control, GWL_STYLE); // 保留原可见性和父子身份。
        SetWindowLongPtrW(control, GWL_STYLE, (style & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFT);
    }
    page.tooltip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, page.hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
    Tip(page, page.browse, L"选择已有 project.ksaproj，仅修改待执行参数。");
    Tip(page, page.capture, L"冻结项目、采样、目标实例及来源，在正式项目写租约内采集并核验网络段。");
    Tip(page, page.read, L"只读核验原 raw-network，不要求目标进程仍在运行。");
    Tip(page, page.cancel, L"停止本次来源并排空归档，保留已提交的原采样数据。");
    Tip(page, page.source, L"raw-socket 复用接口抓包；existing-wfp 只读已启用的 WFP，不自动切换来源。");
    Tip(page, page.sequence, L"留空显示前 256 条、每包 64 字节；指定序号读取该记录全部归档字节。");
    Tip(page, page.copy, L"复制当前显示的完整回执和字节正文。");
    Tip(page, page.exportText, L"导出当前显示的完整回执和字节正文。");
    Tip(page, page.find, L"在当前回执中查找文字。");
    Ui::SetWindowFontRecursive(page.hwnd);
    UpdateActions(page);
    Layout(page);
    return page.project && page.sample && page.source && page.capture && page.receipt;
}

// 宽窗参数/结果并排，窄窗上下；参数自然高度只交给共享滚动视口。
void Layout(Page& page)
{
    RECT bounds{}; // 当前客户区，四边留白只由本函数计算一次。
    GetClientRect(page.hwnd, &bounds);
    const int edge = Scale(6); // 统一页根外边距。
    const int gap = Scale(8); // 普通控件行距。
    const int row = Scale(28); // 输入和动作自然行高。
    const int width = (std::max)(1, static_cast<int>(bounds.right) - edge * 2);
    const std::array actions{page.capture, page.read, page.cancel}; // 固定页底动作。
    const int actionsHeight = Ui::LayoutParameterActions(actions, 0, 0, width, Scale(132), row, gap, false);
    const int height = (std::max)(1, static_cast<int>(bounds.bottom) - edge * 2 - gap - actionsHeight);
    const bool columns = width >= Scale(820); // 宽窗参数有宽度上限。
    const int parameterWidth = columns ? Scale(360) : width;
    const int parameterHeight = columns ? height : (std::max)(1, height * 2 / 5);
    const int bodyWidth = (std::max)(1, parameterWidth - GetSystemMetrics(SM_CXVSCROLL));
    const auto move = [](HWND control, int x, int y, int w, int h) {
        MoveWindow(control, x, y, (std::max)(1, w), (std::max)(1, h), TRUE);
    };

    int y = HintHeight(page.hint, bodyWidth); // 自然说明之后逐行排列，不拉伸字段。
    move(page.hint, 0, 0, bodyWidth, y);
    y += gap;
    const auto field = [&](HWND label, HWND input, bool combo = false) {
        move(label, 0, y, bodyWidth, row - Scale(4));
        y += row - Scale(4);
        move(input, 0, y, bodyWidth, combo ? Scale(180) : row);
        y += row + gap;
    };
    field(page.projectLabel, page.project);
    move(page.browse, 0, y, (std::min)(bodyWidth, Scale(156)), row);
    y += row + gap;
    field(page.sampleLabel, page.sample);
    field(page.pidLabel, page.pid);
    field(page.creationLabel, page.creation);
    field(page.sourceLabel, page.source, true);
    field(page.durationLabel, page.duration);
    field(page.ordinalLabel, page.ordinal);
    field(page.sequenceLabel, page.sequence);
    page.parameters.Layout(edge, edge, parameterWidth, parameterHeight, y);
    Ui::LayoutParameterActions(actions, edge, edge + height + gap, width, Scale(132), row, gap);

    const int resultX = columns ? edge + parameterWidth + gap : edge; // 结果同屏可见。
    const int resultY = columns ? edge : edge + parameterHeight + gap;
    const int resultWidth = columns ? width - parameterWidth - gap : width;
    const int resultHeight = columns ? height : height - parameterHeight - gap;
    const int statusHeight = HintHeight(page.status, resultWidth);
    move(page.status, resultX, resultY, resultWidth, statusHeight);
    const std::array textActions{page.copy, page.exportText, page.find}; // 同一正文工具。
    const int toolsHeight = Ui::LayoutParameterActions(textActions, resultX, resultY + statusHeight + gap,
        resultWidth, Scale(100), row, gap);
    const int textY = resultY + statusHeight + toolsHeight + gap * 2;
    move(page.receipt, resultX, textY, resultWidth, resultY + resultHeight - textY);
}

} // namespace Ksword::Features::ActionAnalyze::network_traffic_page
