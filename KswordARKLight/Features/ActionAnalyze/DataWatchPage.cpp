#include "DataWatchPage.h"

#include "ActionAnalyzePage.h"
#include "LightDataWatchSession.h"
#include "LightNativeControlToolbar.h"
#include "ProjectBreakpointPane.h"
#include "LightPrivateExecutionCandidatesPane.h"
#include "NativeSessionApiFields.h"
#include "ApiTransferPresentation.h"
#include "ProcessGroupPage.h"
#include "../Memory/DriverMemoryModel.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/WorkspaceHost.h"
#include "../../Ui/ParameterWorkspace.h"
#include "../../Ui/ExportUtil.h"

#include <algorithm>
#include <array>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cwchar>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

constexpr wchar_t kPageClass[] = L"KswordARKLight.ActionAnalyzeDataWatch";
constexpr int kWorkspaceTabs = 58400;
enum : int { kPath = 58401, kBrowse, kExport, kBytes, kStart, kContinue, kClose, kReceipt, kCondition,
    kStepMode, kStep, kCancelStep, kSiteKind, kMemoryProject, kMemoryBase, kMemoryBytes,
    kReadMemory, kSaveMemory, kSaveExecution, kCopyReceipt, kExportReceipt, kFollowExecution,
    kTargetPid, kTargetCreation, kPrivateAddress, kPrivatePages, kRangeBase, kRangePages, kAddRange,
    kApiPid, kApiCreation, kApiDuration, kCaptureApi, kPause, kProjectMode };
constexpr UINT_PTR kDisplayTimer = 1;
constexpr UINT kDisplayIntervalMs = 200;
constexpr UINT kPrepareImageDraft = WM_APP + 973; // 同线程同步传纯值，未保存指针。
constexpr UINT kCandidateContext = WM_APP + 981, kReadCandidates = WM_APP + 982, kPrepareRangeDraft = WM_APP + 983;
struct CandidateReadCommand {
    std::shared_ptr<const std::uint8_t> sessionIdentity;
    LightPrivateExecutionCandidatesRequest request;
};
constexpr std::array<std::uint32_t, 4> kWatchWidths{1, 2, 4, 8};
constexpr LRESULT kPrivateWrite = 3, kPrivateExecution = 4, kPrivatePageExecution = 5; // 原模式0..5索引不变。
constexpr LRESULT kImageExportExecution = 6, kImageRvaExecution = 7; // 保留旧六种绑定，新增已有普通模块入口。
constexpr LRESULT kSuspendedImageLaunch = 8; // 普通EXE默认PE入口，初始挂起释放前取得真实owner。

bool DirectMode(LRESULT mode) { return mode >= kPrivateWrite && mode <= kPrivatePageExecution; }
bool ImageMode(LRESULT mode) { return mode == kImageExportExecution || mode == kImageRvaExecution; }
bool ExecutionMode(LRESULT mode) { return mode == 2 || mode == kPrivateExecution || mode == kPrivatePageExecution || ImageMode(mode) || mode == kSuspendedImageLaunch; }

using Ui::Scale;
namespace native = ks::cli::action_analyze::control;
namespace rules = Ksword::ActionAnalyze::Rules;

struct Page {
    HWND hwnd = nullptr;
    HWND hint = nullptr, pathLabel = nullptr, path = nullptr, browse = nullptr;
    HWND exportLabel = nullptr, exportName = nullptr, bytesLabel = nullptr, bytes = nullptr;
    HWND conditionLabel = nullptr, condition = nullptr; // 条件草稿和固定标签。
    HWND siteKindLabel = nullptr, siteKind = nullptr; // 映像或私有指针绑定的明确选择。
    HWND pidLabel = nullptr, targetPid = nullptr, creationLabel = nullptr, targetCreation = nullptr;
    HWND addressLabel = nullptr, privateAddress = nullptr; // 已有实例的身份和地址不借用路径字段。
    HWND pagesLabel = nullptr, privatePages = nullptr; // mode5输入正十进制页数，其它模式不采用此草稿。
    HWND rangeTitle = nullptr, rangeBaseLabel = nullptr, rangeBase = nullptr, rangePagesLabel = nullptr, rangePages = nullptr, addRange = nullptr;
    HWND rangeSource = nullptr;
    std::shared_ptr<const private_execution::PrivateExecutionRangeDraft> rangeOrigin;
    std::shared_ptr<const std::uint8_t> rangeOriginSession;
    bool preparingRange = false;
    std::wstring rangeSourceText;
    std::string definitionId; // 项目定义准备的来源，编辑位置后清除；PID/条件草稿独立保留。
    std::string definitionProjectId; // 载入定义时冻结来源项目，附加前由原worker核验。
    bool preparingDefinition = false;
    HWND apiTitle = nullptr, apiTarget = nullptr, apiPidLabel = nullptr, apiPid = nullptr;
    HWND apiCreationLabel = nullptr, apiCreation = nullptr, apiDurationLabel = nullptr, apiDuration = nullptr, captureApi = nullptr;
    bool apiConfirming = false;
    std::wstring apiTargetText;
    HWND stepLabel = nullptr, stepMode = nullptr, step = nullptr, cancelStep = nullptr; // 模式与显式原生控制入口。
    HWND tooltip = nullptr; // 由本页拥有的原生提示窗。
    HWND start = nullptr, pause = nullptr, resume = nullptr, close = nullptr, receipt = nullptr;
    Ui::ParameterWorkspace parameters; // 参数独立滚动，执行动作及结果固定可见。
    HWND projectLabel = nullptr, projectDirectory = nullptr; // Start前的新项目目录草稿。
    HWND projectModeLabel = nullptr, projectMode = nullptr; // 新建或打开模式只作用于下一次Start。
    HWND memoryBaseLabel = nullptr, memoryBase = nullptr, memoryBytesLabel = nullptr, memoryBytes = nullptr;
    HWND readMemory = nullptr, saveMemory = nullptr, saveExecution = nullptr; // 三个显式只读/归档动作。
    HWND copyReceipt = nullptr, exportReceipt = nullptr; // 同一完整回执文本的复制与导出。
    HWND followExecution = nullptr; // 同址私有写转执行入口，不触发Continue。
    HIMAGELIST followImages = nullptr; // 系统真实链接图标的按钮图集，由本页释放。
    HIMAGELIST rangeImages = nullptr;
    LightDataWatchSession session;
    std::shared_ptr<LightNativeControlPort> controlPort; // 工作台的纯UI端口，不持有第二后台会话。
    std::shared_ptr<LightNativeControlSource> controlSource; // 页根销毁时撤回，工具条只持弱引用。
    LightDataWatchSnapshot shown;
    std::wstring inputError;
    std::wstring shownText;
    bool retiring = false;
};

HWND MakeEdit(HWND parent, int id, DWORD style) {
    return ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
        0, 0, 1, 1, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
}

// 更新已有提示项；传入静态文字，避免tooltip借用局部字符串。
void UpdateDraftTip(const Page& page, HWND control, const wchar_t* description) {
    if (!page.tooltip) return;
    TOOLINFOW tool{};
    tool.cbSize = sizeof(tool);
    tool.hwnd = page.hwnd;
    tool.uId = reinterpret_cast<UINT_PTR>(control);
    tool.lpszText = const_cast<wchar_t*>(description);
    ::SendMessageW(page.tooltip, TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>(&tool));
}

// 模式选择只解释下一次操作，不读取目标或改变当前会话。
void DescribeDraftMode(const Page& page) {
    const auto kind = ::SendMessageW(page.siteKind, CB_GETCURSEL, 0, 0);
    const bool direct = DirectMode(kind);
    const bool image = ImageMode(kind);
    const bool launch = kind == kSuspendedImageLaunch; // 新启动不展示已有实例输入或合作导出要求。
    ::SetWindowTextW(page.hint, launch
        ? L"选择普通 AMD64 EXE，创建挂起并由原所有者先设置入口断点，再释放初始挂起。RVA留空使用PE入口；不覆盖此前TLS/loader，API Agent就绪单独报告。"
        : image
        ? kind == kImageRvaExecution
            ? L"附加已有 AMD64 实例的普通模块：选择已加载模块的绝对路径，输入非零32位RVA（十进制或0x）。使用DR0执行断点，不改变页保护。"
            : L"附加已有 AMD64 实例的普通模块：选择已加载模块的绝对路径及区分大小写的精确PE导出名。使用DR0执行断点，不依赖PDB。"
        : direct
        ? kind == kPrivatePageExecution
            ? L"关注已有私有执行范围：起点4 KiB对齐，页数为正十进制整数且须属同一allocation。逐页保留原保护，关闭时恢复。普通指令按真实BS推进；不支持POPF、SS、特权及需同时开放两页的跨页取指。"
            : L"附加已授权的 AMD64 实例。开始时冻结 PID、创建 FILETIME 与私有绝对地址。"
        : L"启动已授权且导出 KSwordActionAnalyzeDataWatchV1 的 AMD64 合作程序。");
    ::SetWindowTextW(page.start, launch ? L"启动并停在入口" : direct || image ? L"附加并监视" : L"启动并监视");
    ::SetWindowTextW(page.pathLabel, launch ? L"程序路径" : image ? L"已加载模块" : L"合作目标");
    ::SetWindowTextW(page.browse, image ? L"选择模块…" : L"选择 EXE…");
    ::SetWindowTextW(page.exportLabel, launch ? L"入口RVA（可选）" : kind == kImageRvaExecution ? L"模块RVA" : image ? L"精确PE导出" : L"数据导出");
    ::SendMessageW(page.exportName, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(
        launch ? L"留空使用PE AddressOfEntryPoint" : kind == kImageRvaExecution ? L"非零uint32：十进制或0x十六进制" : image ? L"区分大小写的PE导出名（ASCII）" : L"区分大小写的数据导出名（ASCII）"));
    ::SetWindowTextW(page.bytesLabel, ExecutionMode(kind) ? L"写入宽度：无" : L"写入字节数");
    ::SetWindowTextW(page.addressLabel, kind == kPrivatePageExecution ? L"私有范围起点" : L"私有绝对地址");
    UpdateDraftTip(page, page.browse, launch ? L"选择已授权的普通AMD64 EXE；不要求合作导出或PDB。" : image ? L"选择该精确进程实例中已加载模块的绝对路径，支持DLL和EXE；不加载或启动所选文件。"
        : L"选择已获明确授权的合作程序");
    UpdateDraftTip(page, page.exportName, launch ? L"留空使用PE入口；可输入非零32位RVA（十进制或0x），须为明确指令边界。"
        : kind == kImageRvaExecution
        ? L"模块内非零32位RVA，仅接受完整十进制或0x十六进制；不是绝对地址，不查询PDB。启动时与模块路径及实例一起冻结。"
        : image ? L"精确PE导出名，区分大小写且仅接受可打印ASCII；不作PDB或符号模糊搜索。启动时与模块路径及实例一起冻结。"
        : L"合作程序的数据导出名；指针模式沿用原Ready/Gate流程。");
}

// 使用本页现有字体测量折行说明，窄窗不靠固定高度裁切输入前提。
int HintHeight(HWND hint, int width) {
    std::wstring text(static_cast<std::size_t>(::GetWindowTextLengthW(hint)) + 1, L'\0');
    ::GetWindowTextW(hint, text.data(), static_cast<int>(text.size()));
    const HDC dc = ::GetDC(hint);
    if (!dc) return Scale(60);
    const auto prior = ::SelectObject(dc, Ui::SystemUIFont());
    RECT bounds{0, 0, width, 0};
    ::DrawTextW(dc, text.c_str(), -1, &bounds, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    ::SelectObject(dc, prior);
    ::ReleaseDC(hint, dc);
    return (std::max)(Scale(24), static_cast<int>(bounds.bottom));
}

void Layout(const Page& page) {
    RECT area{};
    ::GetClientRect(page.hwnd, &area);
    const int edge = Scale(6), gap = Scale(8), row = Scale(28);
    const int fullWidth = (std::max)(1, static_cast<int>(area.right) - 2 * edge);
    const bool columns = fullWidth >= Scale(840); // 宽窗参数在左，窄窗上下分区并保持正文滚动。
    const int panelWidth = columns ? (std::min)(Scale(460), fullWidth / 2) : fullWidth;
    const int width = (std::max)(1, panelWidth - ::GetSystemMetrics(SM_CXVSCROLL)); // 参数正文扣除原生滚动条。
    const auto move = [&](HWND child, int x, int y, int w, int h) {
        if (::GetParent(child) == page.parameters.Body()) {
            x -= edge; // 页根已计一次等边留白，参数子画布不重复添加。
        }
        ::MoveWindow(child, x, y, (std::max)(1, w), (std::max)(1, h), TRUE);
    };
    const bool narrow = width < Scale(440);
    const int label = Scale(110), browse = Scale(104);
    int y = 0; // 页根6px留白仅由外层负责，参数画布不重复累加。
    const int hintHeight = HintHeight(page.hint, width);
    move(page.hint, edge, y, width, hintHeight);
    y += hintHeight + gap;
    const bool stacked = width < Scale(360); // 长创建时间标签在窄窗单独一行，输入保留可用宽度。
    const auto field = [&](HWND caption, HWND input, bool combo = false) {
        move(caption, edge, y + (stacked ? 0 : Scale(5)), stacked ? width : label, row - Scale(5));
        if (stacked) y += row - Scale(5);
        move(input, edge + (stacked ? 0 : label), y, width - (stacked ? 0 : label), combo ? Scale(180) : row);
        y += row + gap;
    };
    field(page.siteKindLabel, page.siteKind, true); // 先选对象来源，再编辑该模式的范围草稿。
    const auto kind = ::SendMessageW(page.siteKind, CB_GETCURSEL, 0, 0);
    const bool direct = DirectMode(kind);
    const bool image = ImageMode(kind);
    for (const auto control : {page.pathLabel, page.path, page.browse, page.exportLabel, page.exportName}) {
        ::ShowWindow(control, direct ? SW_HIDE : SW_SHOWNA);
    }
    for (const auto control : {page.pidLabel, page.targetPid, page.creationLabel, page.targetCreation}) {
        ::ShowWindow(control, direct || image ? SW_SHOWNA : SW_HIDE);
    }
    for (const auto control : {page.addressLabel, page.privateAddress}) {
        ::ShowWindow(control, direct ? SW_SHOWNA : SW_HIDE);
    }
    for (const auto control : {page.pagesLabel, page.privatePages}) {
        ::ShowWindow(control, kind == kPrivatePageExecution ? SW_SHOWNA : SW_HIDE);
    }
    if (direct || image) {
        field(page.pidLabel, page.targetPid);
        field(page.creationLabel, page.targetCreation);
    }
    if (direct) {
        field(page.addressLabel, page.privateAddress);
        if (kind == kPrivatePageExecution) field(page.pagesLabel, page.privatePages);
    } else {
        if (narrow) {
            field(page.pathLabel, page.path);
            move(page.browse, edge, y, (std::min)(browse, width), row);
            y += row + gap;
        } else {
            move(page.pathLabel, edge, y + Scale(5), label, row - Scale(5));
            move(page.path, edge + label, y, width - label - gap - browse, row);
            move(page.browse, edge + width - browse, y, browse, row);
            y += row + gap;
        }
        field(page.exportLabel, page.exportName);
    }
    field(page.bytesLabel, page.bytes, true);
    field(page.conditionLabel, page.condition);
    field(page.stepLabel, page.stepMode, true);
    y += gap;
    const int rangeTitleHeight = HintHeight(page.rangeTitle, width);
    move(page.rangeTitle, edge, y, width, rangeTitleHeight);
    y += rangeTitleHeight + gap;
    field(page.rangeBaseLabel, page.rangeBase);
    field(page.rangePagesLabel, page.rangePages);
    const int sourceHeight = HintHeight(page.rangeSource, width);
    move(page.rangeSource, edge, y, width, sourceHeight);
    y += sourceHeight + gap;
    move(page.addRange, edge, y, (std::min)(Scale(220), width), row);
    y += row + gap;
    y += Scale(4);
    // 项目绑定在开始前冻结；范围草稿编辑不会重写上次结果来源。
    field(page.projectModeLabel, page.projectMode, true);
    field(page.projectLabel, page.projectDirectory);
    field(page.memoryBaseLabel, page.memoryBase);
    field(page.memoryBytesLabel, page.memoryBytes);
    y += gap;
    const int apiTitleHeight = HintHeight(page.apiTitle, width);
    move(page.apiTitle, edge, y, width, apiTitleHeight);
    y += apiTitleHeight + gap;
    const int targetHeight = HintHeight(page.apiTarget, width);
    move(page.apiTarget, edge, y, width, targetHeight);
    y += targetHeight + gap;
    field(page.apiPidLabel, page.apiPid);
    field(page.apiCreationLabel, page.apiCreation);
    field(page.apiDurationLabel, page.apiDuration);
    move(page.captureApi, edge, y, (std::min)(Scale(220), width), row);
    y += row + gap;
    const std::array actions{page.start, page.pause, page.followExecution, page.resume, page.close, page.step, page.cancelStep,
        page.saveExecution, page.readMemory, page.saveMemory}; // 完整动作集合按共享工具行换行。
    const int actionHeight = Ui::LayoutParameterActions(actions, edge, edge, panelWidth, Scale(144), row, gap, false);
    const int viewportHeight = columns ? (std::max)(Scale(80), static_cast<int>(area.bottom) - 2 * edge - gap - actionHeight)
        : (std::max)(Scale(64), (static_cast<int>(area.bottom) - actionHeight - 3 * edge) / 2);
    page.parameters.Layout(edge, edge, panelWidth, viewportHeight, y);
    y = edge + viewportHeight + gap;

    Ui::LayoutParameterActions(actions, edge, y, panelWidth, Scale(144), row, gap);
    y += actionHeight + gap;
    if (columns) {
        const int resultX = edge + panelWidth + gap; // 结果工具行与正文同宽，滚动互相独立。
        move(page.copyReceipt, resultX, edge, Scale(100), row);
        move(page.exportReceipt, resultX + Scale(108), edge, Scale(100), row);
        move(page.receipt, resultX, edge + row + gap, fullWidth - panelWidth - gap,
            static_cast<int>(area.bottom) - 2 * edge - row - gap);
    } else {
        move(page.copyReceipt, edge, y, Scale(100), row);
        move(page.exportReceipt, edge + Scale(108), y, Scale(100), row);
        y += row + gap;
        move(page.receipt, edge, y, fullWidth, static_cast<int>(area.bottom) - y - edge);
    }
}

std::wstring ReadText(HWND input) {
    std::wstring value(static_cast<std::size_t>(::GetWindowTextLengthW(input)) + 1, L'\0');
    value.resize(static_cast<std::size_t>(::GetWindowTextW(input, value.data(), static_cast<int>(value.size()))));
    return value;
}

// 从页数编辑框解析正十进制；只限制uint64字节转换不溢出，不另设产品页数上限。
bool ReadPageCount(HWND input, std::uint64_t& pages, std::wstring& error) {
    const auto text = ReadText(input); // 原草稿严格保留；空白、符号和十六进制不作隐式转换。
    if (text.empty() || !std::all_of(text.begin(), text.end(), [](wchar_t ch) { return ch >= L'0' && ch <= L'9'; }) ||
        !Memory::ParseUnsignedInteger(text, UINT64_MAX / 4096, L"4 KiB页数", pages, error) || !pages) {
        if (error.empty()) error = L"页数须为正十进制整数，且转换为4 KiB字节数不能溢出。";
        return false;
    }
    return true;
}

void Browse(Page& page) {
    std::wstring path(32768, L'\0');
    const bool image = ImageMode(::SendMessageW(page.siteKind, CB_GETCURSEL, 0, 0));
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = page.hwnd;
    const bool launch = ::SendMessageW(page.siteKind, CB_GETCURSEL, 0, 0) == kSuspendedImageLaunch;
    dialog.lpstrFilter = image ? L"已加载模块 (*.dll;*.exe)\0*.dll;*.exe\0所有文件 (*.*)\0*.*\0" : L"程序 (*.exe)\0*.exe\0";
    dialog.lpstrTitle = launch ? L"选择普通EXE启动目标" : image ? L"选择已有实例中已加载的模块" : L"选择合作写入停点目标";
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;
    if (::GetOpenFileNameW(&dialog)) {
        page.definitionId.clear(); // 另选模块后不沿用旧定义来源。
        ::SetWindowTextW(page.path, path.c_str());
        page.inputError.clear();
    }
}

const wchar_t* StateText(const LightDataWatchSnapshot& status) {
    const bool execution = status.binding ? status.binding->writeWatchBytes == 0
        : status.request.privateExecution || status.request.imageExecutionAttachment || status.request.suspendedImageLaunch;
    const bool image = status.request.imageExecutionAttachment || status.request.suspendedImageLaunch;
    const bool pageExecution = status.binding ? status.binding->rangeBytes != 0 : status.request.privateRangeBytes != 0;
    switch (status.state) {
    case LightDataWatchState::Idle: return L"尚未启动";
    case LightDataWatchState::Starting: return L"正在核验目标并设置停点";
    case LightDataWatchState::Armed:
        if (status.continuing) return L"正在提交本端控制操作";
        if (status.armedPause && status.armedPause->state == native::NativeArmedPauseState::Pending)
            return L"主动暂停已受理，等待原生停止事件（Pending）";
        return image ? L"已设模块执行断点，等待入口尝试" : pageExecution ? L"已设NX私有执行范围，等待范围内取指尝试" : execution
        ? L"已设私有执行停点，等待入口尝试" : L"已设写入停点，等待字节变化";
    case LightDataWatchState::Held: return status.continuing ? L"正在执行停点控制" :
        status.stopReason == native::NativeStopReason::ManualPause ? L"已主动暂停（ManualPause），可继续或读取完整停点内存" :
        status.displayedStop && native::IsDataWatchStepStop(*status.displayedStop) ? L"已停在原生步进事件" :
        execution && status.displayedStop && status.displayedStop->breakpointHit &&
            status.displayedStop->breakpointHit->dataChange ? L"已切换执行关注，原写入事件仍保持停止" :
        image ? L"已停在模块执行入口尝试" : pageExecution ? L"已停在NX私有范围内执行尝试" : execution ? L"已停在私有执行入口尝试" : L"写入停点已命中";
    case LightDataWatchState::Stepping: return L"正在执行原生步进";
    case LightDataWatchState::Closing: return image ? L"正在清退模块执行断点" : execution ? L"正在清退私有执行停点" : L"正在清退写入停点";
    case LightDataWatchState::Closed: return L"清退已确认 · 已脱离";
    case LightDataWatchState::Exited: return L"目标已退出 · 清退已确认";
    case LightDataWatchState::Failed: return image ? L"模块执行断点未完成" : execution ? L"私有执行停点未完成" : L"写入停点未完成";
    case LightDataWatchState::RecoveryRequired: return L"清退或恢复尚未确认";
    case LightDataWatchState::Cancelled: return L"启动已取消";
    }
    return L"状态不可用";
}

// 回执与全局控制工具条共用本轮冻结位置，不从后来编辑的导出/RVA框取值。
std::wstring ImageSiteText(const LightDataWatchRequest& request) {
    if (request.imageRva) {
        wchar_t rva[16]{};
        swprintf_s(rva, L"0x%08X", static_cast<unsigned int>(*request.imageRva));
        return L"模块RVA " + std::wstring(rva);
    }
    if (request.suspendedImageLaunch) return L"PE AddressOfEntryPoint"; // 未填写RVA时保留实际选择语义。
    return L"精确PE导出 " + std::wstring(request.exportName.begin(), request.exportName.end());
}

// 附加同一启动请求的冻结原文、计数和最近一笔判断，不读取当前编辑框。
void AppendConditionReceipt(std::wstring& text, const LightDataWatchSnapshot& result) {
    const auto& report = result.condition; // 原生工作线程发布的三值回执。
    text += L"\r\n本次停点条件：" + result.request.condition;
    if (result.displayedStop && result.stopReason == native::NativeStopReason::ManualPause)
        text += L"\r\n当前为主动暂停，不应用命中条件、不自动放行；以下条件计数和判断属于此前真实命中。";
    else if (result.displayedStop && result.displayedStop->pending &&
        (!report.last || report.last->event != result.displayedStop->pending->event))
        text += L"\r\n当前停点来自只读native回读，尚无本事件条件求值；下列历史条件判断不能代表当前事件。";
    text += L"\r\n数值/位运算按C#优先级；例如 (stop.thread.rax & 0xffu64)==0u64、stop.thread.rip>=stop.address。";
    text += L"\r\nv3三元条件 condition ? trueBranch : falseBranch：两分支须同为bool或u64，仅求值选中分支；未知条件返回未知。";
    text += L"\r\nv3的 &、^、| 支持两个bool谓词，始终从左到右求值两侧；混合bool/u64拒绝。";
    text += L"\r\nv3的 ==、!= 支持两个bool字段或谓词；任一未知即未知，不支持bool大小比较。";
    text += L"\r\n真／假／未知次数：" + std::to_wstring(report.trueCount) + L" / " +
        std::to_wstring(report.falseCount) + L" / " + std::to_wstring(report.unknownCount);
    if (!report.last) {
        return;
    }
    const auto& decision = *report.last; // 条件事件可晚于最近一次实际手动停点。
    const auto truth = decision.evaluation.truth;
    text += truth == rules::Truth::True ? L"\r\n条件为真，命中停点" :
        truth == rules::Truth::False ? L"\r\n条件为假" : L"\r\n条件未知";
    text += L" · 事件 " + std::to_wstring(decision.event.serial) + L" · 停止组 " +
        std::wstring(decision.groupId.begin(), decision.groupId.end()) + L" · 求值时修订 " +
        std::to_wstring(decision.stateRevision);
    if (decision.evaluation.fault != rules::EvaluationFault::None) {
        text += decision.evaluation.fault == rules::EvaluationFault::Budget ? L"\r\n超出求值预算" :
            decision.evaluation.fault == rules::EvaluationFault::DivisionByZero ? L"\r\n数值求值除零，结果为未知" : L"\r\n求值输入无效";
        const std::string_view fault(rules::EvaluationFaultId(decision.evaluation.fault));
        text += L" · " + std::wstring(fault.begin(), fault.end());
    }
    if (decision.failureStage) {
        // 清退结束后仍可检查原自动继续错误；正常清退不会改写条件回执。
        const std::string_view stage(decision.failureStage); // 共享控制层返回的静态诊断标识。
        text += L"\r\n自动继续未确认 · " + std::wstring(stage.begin(), stage.end()) + L" · Win32 " +
            std::to_wstring(decision.releaseError);
    } else if (decision.release == native::ReleaseResult::Continued) {
        text += L"\r\n已自动继续";
    }
}

// 只投影同一个冻结原生快照；历史停点仅供回查，不参与继续或步进资格判断。
void AppendStopRegisters(std::wstring& text, const LightDataWatchSnapshot& result) {
    const auto& snapshot = result.displayedStop ? result.displayedStop : result.lastDisplayedStop;
    if (!snapshot || !snapshot->responsibility || !snapshot->pending || !snapshot->group) return;
    const auto& stop = *snapshot->responsibility;
    text += result.displayedStop ? L"\r\n当前停点的冻结寄存器" : L"\r\n最近显示停点的冻结寄存器（历史只读）";
    text += L"\r\n寄存器来源停点：" + std::wstring(stop.stopId.begin(), stop.stopId.end()) +
        L" · 原生事件 " + std::to_wstring(stop.event.serial) + L" · 修订 " + std::to_wstring(snapshot->group->stateRevision);
    text += L"\r\n寄存器来源停止组：" + std::wstring(stop.groupId.begin(), stop.groupId.end());
    const auto thread = std::find_if(snapshot->frozenThreads.begin(), snapshot->frozenThreads.end(), [&](const auto& item) {
        return item.identity == stop.actualEventThread && item.tid == snapshot->pending->tid;
    });
    text += L"\r\n寄存器来源线程 TID " + std::to_wstring(snapshot->pending->tid) + L" · 创建 FILETIME " +
        (thread != snapshot->frozenThreads.end() && thread->creationTime ? std::to_wstring(thread->creationTime) : L"未核验");
    const auto& registers = snapshot->registers;
    if (!registers || thread == snapshot->frozenThreads.end() || registers->thread != thread->identity ||
        stop.event != snapshot->pending->event) {
        text += L"\r\nRIP：未知 · RAX：未知 · RSP：未知（未取得同一事件线程的冻结寄存器）";
        return;
    }
    wchar_t values[96]{}; // 零值也是有效采集结果；统一以完整64位十六进制呈现。
    swprintf_s(values, L"\r\nRIP：0x%016llX\r\nRAX：0x%016llX\r\nRSP：0x%016llX",
        static_cast<unsigned long long>(registers->rip), static_cast<unsigned long long>(registers->rax),
        static_cast<unsigned long long>(registers->rsp));
    text += values;
    // 其余通用寄存器与标志继续显示同一事件值，保留旧RIP/RAX/RSP的阅读顺序。
    for (const auto& field : native::NativeStopRegisterFields) {
        if (field.value == &native::NativeStopRegisters::rip || field.value == &native::NativeStopRegisters::rax ||
            field.value == &native::NativeStopRegisters::rsp) continue;
        std::wstring label(field.name, field.name + std::char_traits<char>::length(field.name));
        for (auto& character : label) {
            if (character >= L'a' && character <= L'z') character -= L'a' - L'A';
        }
        swprintf_s(values, L"\r\n%s：0x%016llX", label.c_str(),
            static_cast<unsigned long long>((*registers).*(field.value)));
        text += values;
    }
}

// 从原页面草稿和显示停点组装同一读取计划，供只读按钮及相机共用；不查询目标。
bool PrepareStopMemory(const std::shared_ptr<const native::NativeControlResult>& stop,
    const std::wstring& base, const std::wstring& bytes, native::ProcessMemorySnapshotRequest& request,
    LightMemoryInputRejection& rejection) {
    if (!stop || !stop->responsibility || !stop->group) return false;
    native::ProcessGroupResult view;
    native::ProcessGroupMember member;
    member.target = {stop->pid, stop->processCreationTime};
    member.control = *stop;
    member.stop = native::ProcessGroupStop{member.target, stop->responsibility->groupId,
        stop->responsibility->stopId, stop->responsibility->event, stop->group->stateRevision};
    view.members.push_back(member);
    return PrepareHeldMemoryRequest(view, member.target, stop->group->epoch, base, bytes, request, rejection);
}

bool CanPause(const Page& page, std::wstring& hint) {
    const auto& result = page.shown;
    hint = L"只请求原写入/执行owner暂停当前已附加实例；受理不代表已停止。";
    if (page.retiring || !result.active || result.state == LightDataWatchState::Closing) {
        hint += L"\r\n会话未运行或正在清退。";
    } else if (!result.nativeTarget.attached) {
        hint += L"\r\n原owner尚未实际附加目标。";
    } else if (result.continuing) {
        hint += L"\r\n已有在途控制、读取或API操作。";
    } else if (result.armedPause && result.armedPause->state == native::NativeArmedPauseState::Pending) {
        hint += L"\r\n原暂停请求Pending，等待实际回执，不重复暂停。";
    } else if (result.state != LightDataWatchState::Armed || !result.displayedSession ||
        !native::CanPauseDataWatchSession(*result.displayedSession)) {
        hint += L"\r\n需要原绑定Armed，且没有Held停点、运行中步进或恢复责任。";
    } else {
        hint += L"\r\n当前可请求pause/N；ManualPause可继续及转储，本批不提供步进或执行观测保存。";
        return true;
    }
    return false;
}

bool CanDumpMemory(const Page& page, std::wstring& hint) {
    const auto& result = page.shown;
    hint = L"范围来自原写入/执行页的内存起点及范围字节；相机冻结后读取并保存本次结果。";
    if (result.memoryProject.sampleId.empty()) {
        hint += L"\r\n需本会话项目：请在开始前选择新建或打开原项目，创建本轮新采样。";
        return false;
    }
    if (result.memoryProject.archiveBlocked) {
        hint += L"\r\n本会话内存归档已阻断，请核对原页归档回执。";
        return false;
    }
    if (page.retiring || !result.active || result.continuing || result.state == LightDataWatchState::Closing ||
        !result.displayedStop || !result.displayedStop->group || result.displayedStop->group->historical ||
        result.displayedStop->group->state != native::GroupState::HeldComplete || !native::DataWatchHeldStop(*result.displayedStop)) {
        hint += L"\r\n需原会话当前完整Held停点，且无在途控制或清退。";
        return false;
    }
    native::ProcessMemorySnapshotRequest request;
    LightMemoryInputRejection rejection;
    const auto base = ReadText(page.memoryBase), bytes = ReadText(page.memoryBytes);
    if (!PrepareStopMemory(result.displayedStop, base, bytes, request, rejection)) {
        const std::string_view reason(rejection.detail);
        hint += L"\r\n请在原页填写有效内存起点及范围字节数：" + std::wstring(reason.begin(), reason.end());
        return false;
    }
    hint += L"\r\n当前范围草稿：起点 " + base + L" · " + bytes + L" B；缺页保留部分结果。";
    return true;
}

void PublishToolbar(Page& page) {
    if (!page.controlPort || !page.controlSource) return;
    LightNativeControlState state;
    const auto enable = [&](LightNativeControlAction action, HWND button) {
        state.enabled[static_cast<std::size_t>(action)] = !page.retiring && ::IsWindowEnabled(button);
    };
    enable(LightNativeControlAction::Continue, page.resume);
    enable(LightNativeControlAction::StepInto, page.step);
    enable(LightNativeControlAction::StepOverCall, page.step);
    enable(LightNativeControlAction::StepOut, page.step);
    enable(LightNativeControlAction::CancelStep, page.cancelStep);
    enable(LightNativeControlAction::Detach, page.close);
    state.attached = page.shown.nativeTarget.attached; // 路由依据实际附加，不能以按钮可用性决定回退。
    state.canPause = CanPause(page, state.pauseHint);
    state.enabled[static_cast<std::size_t>(LightNativeControlAction::Pause)] = state.canPause;
    state.canDump = CanDumpMemory(page, state.dumpHint);
    state.enabled[static_cast<std::size_t>(LightNativeControlAction::DumpMemory)] = state.canDump;
    state.scope = L"写入停点页本端会话";
    if (page.shown.pid && page.shown.creation) {
        state.scope += L" · PID " + std::to_wstring(page.shown.pid) + L" · 创建 FILETIME " + std::to_wstring(page.shown.creation);
    } else {
        state.scope += L" · 尚无已回读实例";
    }
    if (!page.shown.active) state.scope += L" · 未运行";
    state.scope += L"\r\n" + std::wstring(StateText(page.shown));
    if (page.shown.request.imageExecutionAttachment || page.shown.request.suspendedImageLaunch) {
        state.scope += L" · 普通模块执行 · " + page.shown.request.executable + L" · " + ImageSiteText(page.shown.request);
    }
    if (page.shown.request.privateRangeBytes) {
        const auto range = page.shown.binding ? page.shown.binding->rangeBytes : page.shown.request.privateRangeBytes;
        state.scope += L" · NX初始范围 " + std::to_wstring(range) + L" B / " + std::to_wstring(range / 4096) + L"页";
        if (page.shown.binding && !page.shown.binding->executionRanges.empty()) {
            std::uint64_t total = 0;
            for (const auto& item : page.shown.binding->executionRanges) total += item.bytes;
            state.scope += L" · 已纳入合计 " + std::to_wstring(total / 4096) + L"页";
        }
        state.scope += L"\r\n推进结果以原页后端stage为准；POPF/SS/特权和需同时开放两页的跨页取指不支持。";
    }
    page.controlPort->Publish(page.controlSource, std::move(state));
}

void Refresh(Page& page) {
    page.shown = page.session.ReadStatus();
    const auto& result = page.shown;
    const auto focused = ::GetFocus();
    bool moveFocus = false;
    const auto enable = [&](HWND control, bool value) {
        if (static_cast<bool>(::IsWindowEnabled(control)) != value) {
            if (!value && focused == control) moveFocus = true;
            ::EnableWindow(control, value);
        }
    };
    for (const auto control : {page.siteKind, page.start, page.projectDirectory, page.projectMode}) {
        enable(control, !page.retiring && !result.active);
    }
    const auto kind = ::SendMessageW(page.siteKind, CB_GETCURSEL, 0, 0);
    const bool directDraft = DirectMode(kind);
    const bool imageDraft = ImageMode(kind);
    const bool executionDraft = ExecutionMode(kind); // 草稿不改变当前会话。
    for (const auto control : {page.path, page.browse, page.exportName}) {
        enable(control, !page.retiring && !result.active && !directDraft);
    }
    for (const auto control : {page.targetPid, page.targetCreation}) {
        enable(control, !page.retiring && !result.active && (directDraft || imageDraft));
    }
    enable(page.privateAddress, !page.retiring && !result.active && directDraft);
    enable(page.privatePages, !page.retiring && !result.active && kind == kPrivatePageExecution);
    const bool rangeReady = !page.retiring && !page.preparingRange && result.active && !result.continuing && result.state != LightDataWatchState::Closing &&
        result.displayedStop && result.displayedStop->group && !result.displayedStop->group->historical &&
        result.displayedStop->group->state == native::GroupState::HeldComplete && result.binding && result.binding->rangeBytes &&
        result.binding->state == native::NativeBreakpointState::Held && !result.binding->writeWatchBytes &&
        native::DataWatchHeldStop(*result.displayedStop);
    for (const auto control : {page.rangeBase, page.rangePages, page.addRange}) enable(control, rangeReady);
    std::wstring rangeSource = page.rangeOrigin ? L"待纳入草稿 · " + FormatLightPrivateExecutionOrigin(*page.rangeOrigin) : L"手工范围草稿；尚无AAIM1候选来源。";
    if (page.rangeOrigin && page.rangeOriginSession != result.sessionIdentity)
        rangeSource += L"\r\n此草稿属于旧会话，禁止提交；请从当前目录重新载入或明确编辑为手工草稿。";
    if (rangeSource != page.rangeSourceText) {
        page.rangeSourceText = std::move(rangeSource);
        ::SetWindowTextW(page.rangeSource, page.rangeSourceText.c_str());
        Layout(page);
    }
    enable(page.bytes, !page.retiring && !result.active && !executionDraft);
    enable(page.condition, !page.retiring); // 活会话中可编辑下一次的条件草稿。
    std::wstring pauseHint;
    enable(page.pause, CanPause(page, pauseHint));
    enable(page.resume, !page.retiring && result.displayedStop && !result.continuing);
    enable(page.followExecution, !page.retiring && result.displayedStop && !result.continuing &&
        native::CanFollowDataWatchPrivateExecution(*result.displayedStop));
    const bool manualPause = result.displayedStop && result.stopReason == native::NativeStopReason::ManualPause;
    enable(page.step, !page.retiring && result.displayedStop && !result.continuing && !manualPause);
    enable(page.stepMode, !page.retiring && !manualPause);
    enable(page.cancelStep, !page.retiring && result.step &&
        result.step->state == native::NativeStepState::Running && !result.continuing);
    enable(page.close, !page.retiring && result.active && result.state != LightDataWatchState::Closing);
    const bool canArchive = !page.retiring && result.active && !result.continuing &&
        result.state != LightDataWatchState::Closing; // 保存和控制共用唯一串行入队资格。
    enable(page.readMemory, canArchive && result.displayedStop && result.displayedStop->group &&
        result.displayedStop->group->state == native::GroupState::HeldComplete);
    enable(page.saveMemory, canArchive && !result.memoryProject.sampleId.empty() &&
        !result.memoryProject.archiveBlocked && result.memory && result.memory->snapshot &&
        result.memory->snapshot->round && !result.memory->snapshot->round->pages.empty());
    enable(page.saveExecution, canArchive && !result.memoryProject.sampleId.empty() && !result.execution.blocked &&
        result.displayedStop && !manualPause && native::NativeExecutionFromOwnedStop(*result.displayedStop).has_value());
    const bool apiReady = canArchive && !page.apiConfirming && result.nativeTarget.attached &&
        !result.memoryProject.projectDirectory.empty() && !result.memoryProject.sampleId.empty();
    for (const auto control : {page.apiPid, page.apiCreation, page.apiDuration, page.captureApi}) enable(control, apiReady);
    std::wstring apiTarget = L"当前native目标：PID " + std::to_wstring(result.nativeTarget.pid) + L" · 创建FILETIME " +
        std::to_wstring(result.nativeTarget.creationFileTime);
    apiTarget += result.nativeTarget.attached ? L" · 已附加" : L" · 未附加";
    apiTarget += L"\r\nAPI来源必须是另一明确实例。需本会话项目，确认后借用原采样采集1000–10000ms；关闭等待本轮API清退。";
    if (apiTarget != page.apiTargetText) {
        page.apiTargetText = std::move(apiTarget);
        ::SetWindowTextW(page.apiTarget, page.apiTargetText.c_str());
        Layout(page); // 状态说明自然高度随宽度/真实目标变化，不执行目标查询。
    }
    if (moveFocus && !page.retiring && ::IsWindowVisible(page.hwnd)) {
        ::SetFocus(::IsWindowEnabled(page.close) ? page.close : page.receipt);
    }

    std::wstring text = StateText(result);
    text += result.request.openExistingProject ? L"\r\n本轮项目模式：打开项目并新建采样" : L"\r\n本轮项目模式：新建项目（空路径为仅读取）";
    if (!result.projectId.empty()) text += L"\r\n本轮项目ID：" + std::wstring(result.projectId.begin(), result.projectId.end());
    if (manualPause)
        text += L"\r\n停止原因：ManualPause · 主动中断不是执行命中。本批仅允许恢复继续、完整Held读取/转储和原路径关闭。";
    if (result.armedPause) {
        const auto& pause = *result.armedPause;
        const auto state = [&]() -> const wchar_t* {
            switch (pause.state) {
            case native::NativeArmedPauseState::Pending: return L"Pending · 已受理，尚未确认停止";
            case native::NativeArmedPauseState::Held: return L"Held · 主动停止事件已到达，当前控制资格见本页状态";
            case native::NativeArmedPauseState::Preempted: return L"Preempted · 被其它真实事件抢先，不能视为主动暂停成功";
            case native::NativeArmedPauseState::Rejected: return L"Rejected · 请求被拒绝";
            case native::NativeArmedPauseState::Cancelled: return L"Cancelled · 请求已取消";
            case native::NativeArmedPauseState::Ended: return L"Ended · 目标结束";
            case native::NativeArmedPauseState::RecoveryRequired: return L"RecoveryRequired · 原owner仍有恢复责任";
            }
            return L"未知";
        }();
        text += L"\r\n独立主动暂停回执：" + std::wstring(state);
        text += L"\r\n暂停请求ID：" + std::wstring(pause.request.requestId.begin(), pause.request.requestId.end());
        text += L"\r\n暂停请求实例：PID " + std::to_wstring(pause.request.pid) + L" · 创建FILETIME " + std::to_wstring(pause.request.processCreationTime);
        text += L"\r\n暂停owner会话/代次：" + std::wstring(pause.owner.sessionId.begin(), pause.owner.sessionId.end()) + L" / " +
            std::wstring(pause.owner.epoch.begin(), pause.owner.epoch.end());
        const std::string_view stage(pause.stage);
        text += L"\r\n暂停stage：" + std::wstring(stage.begin(), stage.end()) + L" · Win32 " + std::to_wstring(pause.win32Error);
        if (pause.groupId) text += L"\r\n暂停回执停止组：" + std::wstring(pause.groupId->begin(), pause.groupId->end());
        if (pause.event) text += L"\r\n暂停回执事件：" + std::wstring(pause.event->backendInstanceId.begin(), pause.event->backendInstanceId.end()) +
            L" / " + std::to_wstring(pause.event->serial);
        text += L"\r\n暂停回执独立保留；真实命中、原生事件责任及清退结果分别显示。";
    }
    text += L"\r\n主动暂停入口：" + pauseHint;
    if (!result.nativeStage.empty()) {
        text += L"\r\n原native控制stage：" + std::wstring(result.nativeStage.begin(), result.nativeStage.end());
        text += result.nativeTarget.attached ? L"\r\n原native目标仍已附加" : L"\r\n原native目标未附加";
        text += result.nativeClean ? L" · 原native责任已清理：是" : L" · 原native责任已清理：否";
    }
    if (result.firstRecoveryFailure) {
        const auto& failure = *result.firstRecoveryFailure;
        const std::string_view stage(failure.stage);
        text += L"\r\n首次原native恢复失败（保留）：" + std::wstring(stage.begin(), stage.end()) + L" · Win32 " + std::to_wstring(failure.win32Error);
        if (failure.pendingEvent) text += L" · 原事件 " + std::to_wstring(failure.pendingEvent->serial);
        if (failure.releaseRequestId) text += L" · 原继续请求 " + std::wstring(failure.releaseRequestId->begin(), failure.releaseRequestId->end());
    }
    if (result.retirement) text += result.retirement->kind == native::NativeRetirementKind::Detached
        ? L"\r\n原native清退回执：Detached · 脱离已确认" : L"\r\n原native清退回执：ExitEventContinued · 退出事件已继续";
    if (result.request.suspendedImageLaunch) {
        // 与原native/API回执一起显示启动事实，不能把入口成功当成TLS或Agent已覆盖。
        text += L"\r\n本次绑定方式：普通EXE挂起启动\r\n目标 " + result.request.executable;
        text += L"\r\n本次位置：" + ImageSiteText(result.request);
        if (result.launch) {
            const auto& launch = *result.launch;
            text += launch.createdSuspended ? L"\r\n创建时挂起：是" : L"\r\n创建时挂起：否";
            text += launch.ownerAttachedBeforeResume ? L"\r\n首次恢复前所有者已附加：是" : L"\r\n首次恢复前所有者已附加：否";
            text += launch.breakpointArmedBeforeResume ? L"\r\n首次恢复前入口已武装：是" : L"\r\n首次恢复前入口已武装：否";
            text += launch.initialSuspendReleased ? L"\r\n初始挂起已释放：是" : L"\r\n初始挂起已释放：否";
            text += L"\r\n最早TLS/loader覆盖：未覆盖\r\nAPI Agent就绪：未知";
            const std::string_view stage(launch.stage); // 原始稳定诊断与原Win32值分别保留。
            text += L"\r\n启动阶段：" + std::wstring(stage.begin(), stage.end()) + L" · Win32 " + std::to_wstring(launch.win32Error);
        }
    } else if (result.request.imageExecutionAttachment) {
        text += L"\r\n本次绑定方式：已有普通模块执行断点";
        text += L"\r\n请求实例：PID " + std::to_wstring(result.request.targetPid) + L" · 创建 FILETIME " +
            std::to_wstring(result.request.targetCreationFileTime);
        text += L"\r\n请求模块绝对路径：" + result.request.executable;
        text += L"\r\n本次位置：" + ImageSiteText(result.request);
        if (!result.request.definitionId.empty()) text += L"\r\n来源断点定义ID：" + std::wstring(result.request.definitionId.begin(), result.request.definitionId.end());
        text += L"\r\n模块执行使用DR0，无写入宽度；不改变页保护，不启动目标，不依赖PDB。";
    } else if (result.request.privateAddress) {
        wchar_t address[24]{};
        swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(result.request.privateAddress));
        text += result.request.privateRangeBytes ? L"\r\n本次绑定方式：已有私有页执行关注" :
            result.request.privateExecution ? L"\r\n本次绑定方式：已有私有地址执行" : L"\r\n本次绑定方式：已有私有地址写入";
        text += L"\r\n请求实例：PID " + std::to_wstring(result.request.targetPid) + L" · 创建 FILETIME " +
            std::to_wstring(result.request.targetCreationFileTime);
        text += (result.request.privateRangeBytes ? L"\r\n请求私有页起点：" : L"\r\n请求私有绝对地址：") + std::wstring(address);
        text += result.request.privateRangeBytes ? L" · 执行关注页（无写入宽度）" :
            result.request.privateExecution ? L" · 执行入口（无写入宽度）" :
            L" · 范围 " + std::to_wstring(result.request.bytes) + L" B";
        if (result.request.privateRangeBytes) {
            text += L"\r\n请求页范围：" + std::to_wstring(result.request.privateRangeBytes) + L" B / " +
                std::to_wstring(result.request.privateRangeBytes / 4096) + L"页 · 4 KiB对齐";
            text += L"\r\n范围须属同一allocation，临时撤X并逐页保留原RX/RWX等保护，关闭时恢复；不占用DR0。";
            text += L"\r\n普通指令按真实BS推进；POPF/SS/特权和需同时开放两页的跨页取指不支持；运行能力未实测。";
        }
    } else if (!result.request.executable.empty()) {
        text += L"\r\n目标 " + result.request.executable + L"\r\n数据导出 " +
            std::wstring(result.request.exportName.begin(), result.request.exportName.end());
        text += result.request.privateExecution ? L" · 执行入口（无写入宽度）" :
            L" · 范围 " + std::to_wstring(result.request.bytes) + L" B";
        text += result.request.privateExecution ? L"\r\n数据绑定方式：指针导出的私有执行入口" :
            result.request.indirect ? L"\r\n数据绑定方式：指针导出的私有区间" : L"\r\n数据绑定方式：映像数据导出";
    }
    if (result.pid && result.creation) {
        text += L"\r\nPID " + std::to_wstring(result.pid) + L" · 创建 FILETIME " + std::to_wstring(result.creation);
    }
    if (result.enrolledThreads) text += L"\r\n已登记线程 " + std::to_wstring(*result.enrolledThreads);
    if (result.binding) {
        const auto& binding = *result.binding; // 回执的实际地址，不随参数草稿改变。
        wchar_t address[24]{}; // AMD64 地址的十六进制呈现。
        swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(binding.address));
        text += (binding.rangeBytes ? L"\r\n执行关注页起点：" : L"\r\n关注地址：") + std::wstring(address);
        if ((result.request.imageExecutionAttachment || result.request.suspendedImageLaunch) && binding.moduleBase) {
            // 只有后端已回读的映像基址才显示为实际绑定，不把输入RVA当成已成功设置。
            swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(binding.moduleBase));
            text += L"\r\n实际模块基址：" + std::wstring(address);
            swprintf_s(address, L"0x%08X", static_cast<unsigned int>(binding.rva));
            text += L"\r\n实际模块RVA：" + std::wstring(address);
            if (binding.imageSha256)
            {
                // 只展示原owner实际事件文件实测值，不把冻结定义中的请求散列当作核验通过。
                text += L"\r\n已核验装载文件SHA-256：" + std::wstring(binding.imageSha256->begin(), binding.imageSha256->end());
            }
        }
        text += binding.rangeBytes ? L"\r\nNX初始范围：" + std::to_wstring(binding.rangeBytes) + L" B / " + std::to_wstring(binding.rangeBytes / 4096) + L"页" :
            binding.writeWatchBytes == 0 ? L"\r\n当前实际关注：执行入口（无写入宽度）" :
            L"\r\n当前实际关注：写入 · 范围 " + std::to_wstring(binding.writeWatchBytes) + L" B";
        if (binding.pointerExportAddress) {
            swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(binding.pointerExportAddress));
            text += L"\r\n指针导出地址：" + std::wstring(address);
        }
        if (binding.explicitPrivateAddress || binding.pointerExportAddress) {
            swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(binding.allocationBase));
            text += L"\r\n私有分配基址：" + std::wstring(address) + L" · 区域字节数 " + std::to_wstring(binding.regionBytes);
            swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(binding.regionBase));
            wchar_t protection[24]{};
            swprintf_s(protection, L"0x%lX", static_cast<unsigned long>(binding.regionProtection));
            text += L"\r\n绑定区域基址：" + std::wstring(address) + L" · 保护 " + protection;
            text += L"\r\n分配代次：未知";
        }
        std::uint64_t total = 0;
        for (const auto& range : binding.executionRanges) {
            total += range.bytes;
            wchar_t rangeText[128]{};
            swprintf_s(rangeText, L"\r\n成功NX范围：0x%llX · %llu B / %llu页 · allocation 0x%llX",
                static_cast<unsigned long long>(range.base), static_cast<unsigned long long>(range.bytes),
                static_cast<unsigned long long>(range.bytes / 4096), static_cast<unsigned long long>(range.allocationBase));
            text += rangeText;
        }
        if (!binding.executionRanges.empty()) text += L"\r\n已纳入范围合计：" + std::to_wstring(total) + L" B / " + std::to_wstring(total / 4096) + L"页";
    }
    if (result.executionRange) {
        const auto& range = *result.executionRange;
        const std::string_view stage(range.stage);
        text += L"\r\n纳入执行范围回执：" + std::wstring(stage.begin(), stage.end()) + L" · Win32 " + std::to_wstring(range.win32Error);
        text += L"\r\n请求起点/字节：" + std::to_wstring(range.request.address) + L" / " + std::to_wstring(range.request.bytes);
        text += L"\r\n原范围事务票据：" + std::wstring(range.request.stop.requestId.begin(), range.request.stop.requestId.end());
        text += L"\r\n原停止组/停点：" + std::wstring(range.request.stop.groupId.begin(), range.request.stop.groupId.end()) + L" / " +
            std::wstring(range.request.stop.stopId.begin(), range.request.stop.stopId.end());
        text += L"\r\n原事件序号：" + std::to_wstring(range.request.stop.event.serial);
        text += range.added ? L"\r\n新增已确认：是" : L"\r\n新增已确认：否";
        text += range.rollbackComplete ? L"\r\n新增失败回滚已确认：是" : L"\r\n新增失败回滚已确认：否";
        text += L"\r\n操作后状态修订：" + std::to_wstring(range.stateRevision);
    }
    if (result.executionRangeOrigin) text += L"\r\n最近显式纳入请求的历史来源：\r\n" + FormatLightPrivateExecutionOrigin(*result.executionRangeOrigin);
    if (result.step) {
        const auto& step = *result.step; // 最近一笔请求身份与机器地址来自同一原生回执。
        const auto& requestId = step.request.release.requestId; // 与继续共享的内部序号。
        text += L"\r\n原生步进回执 · " + std::wstring(requestId.begin(), requestId.end());
        const std::string_view stage(step.stage); // 原生状态码不翻译为未得到证实的成功。
        text += L"\r\n诊断阶段：" + std::wstring(stage.begin(), stage.end()) + L" · Win32 " + std::to_wstring(step.win32Error);
        text += L"\r\n起始指令地址：" + std::to_wstring(step.startIp) + L" · 已观察指令地址：" +
            (step.observedIp ? std::to_wstring(*step.observedIp) : L"未知");
        text += step.resourcesRestored ? L"\r\n步进资源已恢复：是" : L"\r\n步进资源已恢复：否";
    }
    if (!result.request.condition.empty()) {
        AppendConditionReceipt(text, result);
    }
    if (const auto& follow = result.executionFollow) {
        const std::string_view id(follow->request.stop.requestId); // 原转换票据不等同继续回执。
        const std::string_view stage(follow->stage); // 稳定原生诊断，无需构造活控制令牌。
        text += L"\r\n同址写转执行回执 · " + std::wstring(id.begin(), id.end());
        text += follow->converted ? L"\r\n转换已确认：是" : L"\r\n转换已确认：否";
        text += follow->rollbackComplete ? L"\r\n失败回滚已确认：是" : L"\r\n失败回滚已确认：否";
        text += L"\r\n诊断阶段：" + std::wstring(stage.begin(), stage.end()) + L" · Win32 " +
            std::to_wstring(follow->win32Error);
        text += L"\r\n转换本身不是执行证据，原写入事件不会变成执行入口尝试。";
    }
    if (result.lastHit) {
        const auto& hit = *result.lastHit;
        wchar_t mask[12]{};
        swprintf_s(mask, L"0x%X", static_cast<unsigned int>(hit.changedByteMask));
        text += hit.execution ? L"\r\n最近执行入口尝试令牌 " :
            result.stopReason != native::NativeStopReason::ManualPause && result.displayedStop && result.displayedStop->breakpointHit
                ? L"\r\n当前写入停点令牌 " : L"\r\n最近写入停点令牌 ";
        text += hit.token + L"\r\n触发线程 TID " + std::to_wstring(hit.tid) + L" · 创建 FILETIME " +
            (hit.threadCreation ? std::to_wstring(hit.threadCreation) : L"未核验");
        if (hit.execution) {
            wchar_t address[24]{}; // 显示冻结入口，不从指针草稿重新解引用。
            swprintf_s(address, L"0x%llX", static_cast<unsigned long long>(hit.address));
            text += (result.request.privateRangeBytes ? L"\r\n真实页内命中RIP：" : L"\r\n执行入口尝试地址：") + std::wstring(address);
        } else {
            text += L"\r\n变化字节掩码 " + std::wstring(mask) + L" · 登记时最近停点序号 " +
                std::to_wstring(hit.enrolledAfterStop);
        }
    }
    AppendStopRegisters(text, result);
    if (!result.diagnostic.empty()) text += L"\r\n" + result.diagnostic;
    if (result.request.privateRangeBytes && !result.nativeStage.empty()) {
        text += L"\r\n页执行后端stage：" + std::wstring(result.nativeStage.begin(), result.nativeStage.end());
    }
    if (!result.memoryDumpDiagnostic.empty()) text += L"\r\n" + result.memoryDumpDiagnostic;
    text += L"\r\n" + FormatLightProcessGroupMemoryArchive(result.memoryProject);
    if (result.memory) {
        text += L"\r\n" + FormatLightProcessGroupMemory(*result.memory); // 只投影原capture，不从当前地址重新读取。
    }
    text += FormatLightNativeExecution(result.execution);
    if (result.api) text += FormatLightNativeSessionApi(*result.api);
    if (result.apiStartup)
    {
        text += FormatLightNativeSessionApiProgress(*result.apiStartup); // 复用原刷新与详情正文，不另建timer。
    }
    if (result.apiCheckpoint && result.apiRules)
    {
        text += FormatLightNativeSessionApiCheckpoint(*result.apiCheckpoint, *result.apiRules);
    }
    if (result.apiTransfers)
    {
        text += ApiTransferProgress(*result.apiTransfers); // 复用同一writer的累计计数和最近转移坐标。
    }
    if (!result.apiDiagnostic.empty()) text += L"\r\n" + result.apiDiagnostic;
    if (!page.inputError.empty()) text += L"\r\n" + page.inputError;
    if (text != page.shownText) {
        page.shownText = std::move(text);
        ::SetWindowTextW(page.receipt, page.shownText.c_str());
    }
    PublishToolbar(page);
    if (!result.active) ::KillTimer(page.hwnd, kDisplayTimer);
}

// 工具条只发纯UI动作；点击时重读本地已发布值并冻结原停点，不执行Query或借用总览选区。
void ReadStopMemory(Page& page, bool dump = false); // 相机仍由原页冻结范围，不从总览历史选区取值。

void SubmitControl(Page& page, LightNativeControlAction action) {
    const auto armed = page.shown.displayedSession;
    const auto stop = page.shown.displayedStop; // 先冻结用户当前看到的原停点，再检查新发布值。
    const auto step = page.shown.step;
    Refresh(page);
    if (page.retiring) return;
    const bool stoppedAction = action == LightNativeControlAction::Continue || action == LightNativeControlAction::StepInto ||
        action == LightNativeControlAction::StepOverCall || action == LightNativeControlAction::StepOut ||
        action == LightNativeControlAction::DumpMemory;
    if ((stoppedAction && (!stop || stop != page.shown.displayedStop)) ||
        (action == LightNativeControlAction::CancelStep && (!step || !page.shown.step || step->request != page.shown.step->request))) {
        page.inputError = L"显示中的停点或步进请求已更新，请核对原页回执后重新执行。";
        Refresh(page);
        return;
    }
    bool accepted = true;
    switch (action) {
    case LightNativeControlAction::Pause:
        if (!::IsWindowEnabled(page.pause)) return;
        accepted = page.session.Pause(armed); // 保留Refresh前用户所见原副本，不能换成后来会话。
        break;
    case LightNativeControlAction::DumpMemory:
        ReadStopMemory(page, true);
        return;
    case LightNativeControlAction::Continue:
        if (!::IsWindowEnabled(page.resume)) return;
        accepted = page.session.Continue(stop);
        break;
    case LightNativeControlAction::StepInto:
    case LightNativeControlAction::StepOverCall:
    case LightNativeControlAction::StepOut: {
        if (!::IsWindowEnabled(page.step)) return;
        const auto mode = action == LightNativeControlAction::StepInto ? native::NativeStepMode::Into :
            action == LightNativeControlAction::StepOverCall ? native::NativeStepMode::OverCall : native::NativeStepMode::Out;
        accepted = page.session.Step(stop, mode);
        break;
    }
    case LightNativeControlAction::CancelStep:
        if (!::IsWindowEnabled(page.cancelStep) || !page.shown.step) return;
        accepted = page.session.CancelStep(*step);
        break;
    case LightNativeControlAction::Detach:
        if (!::IsWindowEnabled(page.close)) return;
        page.session.Close();
        break;
    default: return;
    }
    page.inputError = accepted ? L"" : L"该会话、停点或步进请求已更新，请查看写入停点页的当前回执。";
    Refresh(page);
}

void Start(Page& page) {
    if (page.retiring || page.shown.active) return;
    const auto width = ::SendMessageW(page.bytes, CB_GETCURSEL, 0, 0);
    const auto siteKind = ::SendMessageW(page.siteKind, CB_GETCURSEL, 0, 0); // 点击时冻结绑定模式。
    const bool direct = DirectMode(siteKind);
    const bool image = ImageMode(siteKind);
    const bool execution = ExecutionMode(siteKind);
    const auto reject = [&](HWND control) {
        page.parameters.Reveal(control); // 校验失败时将对应参数滚入视口，再保留原位修正入口。
        ::SetFocus(control);
        Refresh(page);
    };
    if (siteKind < 0 || siteKind > kSuspendedImageLaunch) {
        page.inputError = L"请选择绑定方式。";
        reject(page.siteKind);
        return;
    }
    if (!execution && (width < 0 || static_cast<std::size_t>(width) >= kWatchWidths.size())) {
        page.inputError = L"请选择关注范围的字节数。";
        reject(page.bytes);
        return;
    }
    LightDataWatchRequest request; // 只冻结本模式的输入，隐藏的地址或导出草稿不混入其它模式。
    request.imageExecutionAttachment = image;
    request.suspendedImageLaunch = siteKind == kSuspendedImageLaunch;
    if (image) {
        request.definitionId = page.definitionId;
        request.definitionProjectId = page.definitionProjectId;
    }
    request.privateExecution = execution && !image && !request.suspendedImageLaunch;
    request.bytes = execution ? 0 : kWatchWidths[static_cast<std::size_t>(width)];
    if (siteKind == kPrivatePageExecution) {
        std::uint64_t pages = 0; // 启动时从可编辑页数冻结，乘法前验证不溢出。
        page.inputError.clear();
        if (!ReadPageCount(page.privatePages, pages, page.inputError)) {
            reject(page.privatePages);
            return;
        }
        request.privateRangeBytes = pages * 4096;
    }
    request.projectDirectory = ReadText(page.projectDirectory);
    const auto projectMode = ::SendMessageW(page.projectMode, CB_GETCURSEL, 0, 0);
    if (projectMode < 0 || projectMode > 1 || (projectMode == 1 && request.projectDirectory.empty())) {
        page.inputError = L"请选择项目模式；打开原项目必须填写项目目录或project.ksaproj路径。";
        reject(page.projectDirectory);
        return;
    }
    request.openExistingProject = projectMode == 1;
    // 模块与私有附加共用精确实例输入，模块模式始终不读取隐藏的私有地址。
    if (direct || image) {
        std::uint64_t pid = 0;
        const auto parse = [&](HWND input, const wchar_t* label, std::uint64_t maximum, std::uint64_t& value) {
            if (!Memory::ParseUnsignedInteger(ReadText(input), maximum, label, value, page.inputError)) {
                reject(input);
                return false;
            }
            if (!value) {
                page.inputError = std::wstring(label) + L"必须为非零无符号整数。";
                reject(input);
                return false;
            }
            return true;
        };
        if (!parse(page.targetPid, L"目标 PID", (std::numeric_limits<std::uint32_t>::max)(), pid) ||
            !parse(page.targetCreation, L"创建 FILETIME", (std::numeric_limits<std::uint64_t>::max)(), request.targetCreationFileTime) ||
            (direct && !parse(page.privateAddress, L"私有绝对地址", (std::numeric_limits<std::uint64_t>::max)(), request.privateAddress))) {
            return;
        }
        request.targetPid = static_cast<std::uint32_t>(pid); // 已通过32位上限检查，转换不截断。
        if (request.privateRangeBytes && request.privateAddress % 4096 != 0) {
            page.inputError = L"私有页起点必须按4 KiB（4096字节）对齐；不会自动取整或改写地址。";
            reject(page.privateAddress);
            return;
        }
    }
    if (!direct) {
        request.executable = ReadText(page.path);
        const auto name = ReadText(page.exportName);
        if (request.executable.empty()) {
            page.inputError = request.suspendedImageLaunch ? L"请选择已授权的普通AMD64 EXE。" : image ? L"请选择该已有实例中已加载模块的绝对路径（DLL或EXE）。" : L"请选择已明确授权的合作 EXE。";
            reject(page.browse);
            return;
        }
        if (siteKind == kImageRvaExecution || (request.suspendedImageLaunch && !name.empty())) {
            std::uint64_t rva = 0; // 先按32位上限解析，成功后才转换，不截断溢出或容忍尾随字符。
            if (!Memory::ParseUnsignedInteger(name, (std::numeric_limits<std::uint32_t>::max)(), L"模块RVA", rva, page.inputError) || !rva) {
                if (page.inputError.empty()) page.inputError = L"模块RVA必须为非零32位无符号整数（十进制或0x十六进制）。";
                reject(page.exportName);
                return;
            }
            request.imageRva = static_cast<std::uint32_t>(rva);
        } else if (!request.suspendedImageLaunch) {
            if (name.empty() || !std::all_of(name.begin(), name.end(), [](wchar_t ch) { return ch >= 33 && ch <= 126; })) {
                page.inputError = image ? L"请输入区分大小写的精确PE导出名，仅接受可打印ASCII。" : L"请输入区分大小写的数据导出名。";
                reject(page.exportName);
                return;
            }
            request.exportName.reserve(name.size());
            for (const wchar_t character : name) request.exportName.push_back(static_cast<char>(character)); // 已核对可打印ASCII。
        }
        request.indirect = !image && !request.suspendedImageLaunch && siteKind != 0;
    }
    request.condition = ReadText(page.condition);
    auto prepared = native::PrepareDataWatchCondition(request.condition);
    if (prepared.diagnostic) {
        const std::string_view diagnostic(prepared.diagnostic);
        page.inputError = L"停点条件无效：" + std::wstring(diagnostic.begin(), diagnostic.end());
        if (const auto& at = prepared.location) {
            page.inputError += L" · UTF-8 字节偏移 " + std::to_wstring(at->offset);
        }
        reject(page.condition);
        return;
    }
    if (!::SetTimer(page.hwnd, kDisplayTimer, kDisplayIntervalMs, nullptr)) {
        page.inputError = L"无法启动状态刷新，请重试。";
        Refresh(page);
        return;
    }
    page.inputError.clear();
    const DWORD error = page.session.Start(std::move(request), std::move(prepared.predicate));
    if (error) page.inputError = L"无法提交启动请求 · Win32 " + std::to_wstring(error);
    Refresh(page);
}

void CaptureSessionApi(Page& page) {
    if (page.apiConfirming || !::IsWindowEnabled(page.captureApi)) return;
    const auto confirmedSession = page.shown; // 确认前冻结原会话代次、sample和真实目标值。
    page.apiConfirming = true;
    Refresh(page);
    Ksword::ActionAnalyze::NativeBoundApiRequest request;
    std::wstring reason;
    const bool confirmed = CollectLightNativeSessionApi(page.hwnd, page.apiPid, page.apiCreation,
        page.apiDuration, confirmedSession.nativeTarget, request, reason);
    page.apiConfirming = false;
    if (confirmed) {
        if (!page.retiring && page.session.CaptureApi(confirmedSession, request)) page.inputError.clear();
        else page.inputError = L"确认期间原会话、sample或目标已变化，或已有在途操作。未派发API，请核对回执后重新确认。";
    } else page.inputError = std::move(reason);
    Refresh(page);
}

// 纯值选择必须仍属于原worker发布目录及同一NX会话；不读取工程或查询目标。
bool PrepareCandidateRange(Page& page, const LightPrivateExecutionCandidateSelection& selection) {
    if (page.preparingRange || !selection.page || selection.row >= selection.page->rows.size()) return false;
    const auto& fields = selection.page->rows[selection.row].origin.record.apiMemoryLifecycle; // 回调入口也核对原操作，不依赖按钮状态。
    if (!fields || (fields->operation != Ksword::Evidence::ApiMemoryOperation::Allocate &&
        fields->operation != Ksword::Evidence::ApiMemoryOperation::Protect))
    {
        return false; // Free和Unmap只保留历史请求，不能借手填地址载入NX草稿。
    }
    private_execution::PrivateExecutionRangeDraft draft;
    if (!private_execution::PreparePrivateExecutionRangeDraft(selection.page->rows[selection.row], selection.address, selection.bytes, draft)) return false;
    const auto matches = [&] {
        const auto& state = page.shown;
        return !page.retiring && state.active && !state.continuing && state.state != LightDataWatchState::Closing &&
            state.state != LightDataWatchState::RecoveryRequired && selection.sessionIdentity && selection.sessionIdentity == state.sessionIdentity &&
            state.candidates && state.candidates->page == selection.page && state.nativeTarget.attached && state.binding &&
            state.binding->rangeBytes && !state.binding->writeWatchBytes &&
            state.projectId == draft.projectId && state.memoryProject.sampleId == draft.sampleId &&
            state.nativeTarget.pid == draft.targetPid && state.nativeTarget.creationFileTime == draft.targetCreationFileTime;
    };
    Refresh(page);
    if (!matches()) return false;
    const auto oldBase = ReadText(page.rangeBase);
    const auto oldPages = ReadText(page.rangePages); // 模态确认期间保留原十进制草稿身份。
    const auto oldOrigin = page.rangeOrigin;
    page.preparingRange = true;
    Refresh(page);
    const bool replace = (oldBase.empty() && oldPages == L"1" && !oldOrigin) ||
        ::MessageBoxW(page.hwnd, L"将替换现有AddRange起点、页数及候选来源草稿。原停点和旧结果保留。这里只载入参数，不暂停、不继续、不纳入范围。是否载入？",
            L"载入范围候选草稿", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES;
    Refresh(page); // 确认期间可能清退、换目录或更新原会话，不能切换到后来对象。
    if (!replace || !matches() || oldBase != ReadText(page.rangeBase) ||
        oldPages != ReadText(page.rangePages) || oldOrigin != page.rangeOrigin) {
        page.preparingRange = false;
        Refresh(page);
        return false;
    }
    ::SetWindowTextW(page.rangeBase, PrivateCandidateHex(draft.address).c_str());
    ::SetWindowTextW(page.rangePages, std::to_wstring(draft.bytes / 4096).c_str());
    page.rangeOrigin = std::make_shared<const private_execution::PrivateExecutionRangeDraft>(std::move(draft));
    page.rangeOriginSession = selection.sessionIdentity;
    page.preparingRange = false;
    page.inputError = L"候选已载入原AddRange草稿。请核对来源，在当前完整NX Held停点显式点击纳入；尚未改变目标。";
    Refresh(page);
    page.parameters.Reveal(page.rangeBase);
    return true;
}

// 在原NX完整Held停点纳入新范围；只校验草稿，allocation/重叠和保护由原owner回读。
void AddExecutionRange(Page& page) {
    if (page.preparingRange || !::IsWindowEnabled(page.addRange)) return;
    const auto stop = page.shown.displayedStop;
    const auto baseText = ReadText(page.rangeBase);
    std::uint64_t pages = 0; // 明确十进制页数，不再以ComboBox索引计算范围。
    std::uint64_t base = 0;
    page.inputError.clear();
    if (!ReadPageCount(page.rangePages, pages, page.inputError)) {
        page.parameters.Reveal(page.rangePages); // 页数错误定位原编辑框，不把焦点移到有效的起点。
        ::SetFocus(page.rangePages);
        Refresh(page);
        return;
    }
    if (!Memory::ParseUnsignedInteger(baseText, (std::numeric_limits<std::uint64_t>::max)(), L"新增范围起点", base, page.inputError) ||
        !base || base % 4096 || base > UINT64_MAX - pages * 4096) {
        if (page.inputError.empty()) page.inputError = L"新增范围须为非零4 KiB对齐起点及正十进制页数，地址加字节数不能溢出；不会自动取整。";
        page.parameters.Reveal(page.rangeBase);
        ::SetFocus(page.rangeBase);
    } else if ((page.rangeOrigin && page.rangeOriginSession != page.shown.sessionIdentity) ||
        !page.session.AddPrivateExecutionRange(stop, base, pages * 4096, page.rangeOrigin)) {
        page.inputError = L"仅当前NX会话的完整Held停点可纳入范围，请核对原页回执及在途操作。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

// 把原生显示停点映射为纯值请求，复用严格范围解析；实际读取仍由原session再次核对。
void ReadStopMemory(Page& page, bool dump)
{
    const auto stop = page.shown.displayedStop; // 点击时冻结同一shared_ptr身份。
    if (!stop || !stop->responsibility || !stop->group) {
        return;
    }
    if (dump) {
        std::wstring reason;
        if (!CanDumpMemory(page, reason)) {
            page.inputError = std::move(reason);
            Refresh(page);
            return;
        }
    }
    native::ProcessMemorySnapshotRequest request; // 原sample/完整令牌来自本次显示回执。
    LightMemoryInputRejection rejection;
    const auto base = ReadText(page.memoryBase), bytes = ReadText(page.memoryBytes); // 相机冻结原页草稿，不读取第二范围。
    if (!PrepareStopMemory(stop, base, bytes, request, rejection)) {
        const std::string_view reason(rejection.detail);
        page.inputError = L"内存范围无效或停点不完整：" + std::wstring(reason.begin(), reason.end());
    } else if (!(dump ? page.session.DumpMemory(stop, request.plan) : page.session.ReadMemory(stop, request.plan))) {
        page.inputError = L"该停点已更新，请查看当前回执。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data) {
    const auto& page = *reinterpret_cast<Page*>(data);
    if (message == WM_KEYDOWN && wp == VK_TAB) {
        const std::array order{page.siteKind, page.path, page.browse, page.exportName, page.targetPid, page.targetCreation,
            page.privateAddress, page.privatePages, page.bytes, page.condition, page.stepMode,
            page.rangeBase, page.rangePages, page.addRange, page.projectMode, page.projectDirectory, page.memoryBase,
            page.memoryBytes, page.apiPid, page.apiCreation, page.apiDuration, page.captureApi,
            page.start, page.pause, page.followExecution, page.resume, page.close, page.step, page.cancelStep,
            page.saveExecution, page.readMemory, page.saveMemory,
            page.copyReceipt, page.exportReceipt, page.receipt};
        int index = static_cast<int>(std::find(order.begin(), order.end(), hwnd) - order.begin());
        const int count = static_cast<int>(order.size());
        const int direction = (::GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
        for (int step = 0; step < count; ++step) {
            index = (index + direction + count) % count;
            const auto next = order[static_cast<std::size_t>(index)];
            if (::IsWindowEnabled(next) && ::IsWindowVisible(next)) {
                page.parameters.Reveal(next); // 键盘导航不会把焦点留在参数视口外。
                ::SetFocus(next);
                break;
            }
        }
        return 0;
    }
    if (message == WM_KEYDOWN && wp == VK_RETURN && (hwnd == page.browse || hwnd == page.start || hwnd == page.resume ||
        hwnd == page.close || hwnd == page.followExecution || hwnd == page.step || hwnd == page.cancelStep || hwnd == page.readMemory ||
        hwnd == page.saveMemory || hwnd == page.saveExecution || hwnd == page.copyReceipt || hwnd == page.exportReceipt ||
        hwnd == page.addRange || hwnd == page.captureApi || hwnd == page.pause)) {
        if (!(lp & (1LL << 30)) && ::IsWindowEnabled(hwnd)) ::SendMessageW(hwnd, BM_CLICK, 0, 0);
        return 0;
    }
    if (message == WM_CHAR && (wp == L'\t' || wp == L'\r')) return 0;
    return ::DefSubclassProc(hwnd, message, wp, lp);
}

// 为原生字段和动作登记可读悬停说明；静态文本在 tooltip 生命周期内有效。
void AddTip(const Page& page, HWND control, const wchar_t* description) {
    if (!page.tooltip) {
        return;
    }
    TOOLINFOW tool{}; // 原生控件句柄是提示项的稳定标识。
    tool.cbSize = sizeof(tool);
    tool.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    tool.hwnd = page.hwnd;
    tool.uId = reinterpret_cast<UINT_PTR>(control);
    tool.lpszText = const_cast<wchar_t*>(description);
    ::SendMessageW(page.tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&tool));
}

// 输入已有按钮宿主，给复杂转换动作附系统真实链接图标；保留文字作为原生无障碍名称。
void AttachFollowIcon(Page& page)
{
    SHSTOCKICONINFO icon{}; // Shell提供的共享动作图形，临时HICON需要独立释放。
    icon.cbSize = sizeof(icon);
    if (FAILED(::SHGetStockIconInfo(SIID_LINK, SHGSI_ICON | SHGSI_SMALLICON, &icon)))
    {
        return; // 系统图标不可用时仍保留明确文字和tooltip，不新增自绘控件。
    }
    const int extent = Scale(16); // 跟随本页DPI，按钮布局仍由共享动作行承担。
    page.followImages = ::ImageList_Create(extent, extent, ILC_COLOR32 | ILC_MASK, 1, 0);
    if (page.followImages && ::ImageList_AddIcon(page.followImages, icon.hIcon) >= 0)
    {
        BUTTON_IMAGELIST images{}; // 系统BUTTON拥有呈现，不拥有图集生命周期。
        images.himl = page.followImages;
        images.margin = {Scale(6), 0, Scale(4), 0};
        images.uAlign = BUTTON_IMAGELIST_ALIGN_LEFT;
        ::SendMessageW(page.followExecution, BCM_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(&images));
    }
    ::DestroyIcon(icon.hIcon);
}

void AttachRangeIcon(Page& page) {
    SHSTOCKICONINFO icon{sizeof(icon)};
    if (FAILED(::SHGetStockIconInfo(SIID_FOLDEROPEN, SHGSI_ICON | SHGSI_SMALLICON, &icon))) return;
    page.rangeImages = ::ImageList_Create(Scale(16), Scale(16), ILC_COLOR32 | ILC_MASK, 1, 0);
    if (page.rangeImages && ::ImageList_AddIcon(page.rangeImages, icon.hIcon) >= 0) {
        BUTTON_IMAGELIST images{};
        images.himl = page.rangeImages;
        images.margin = {Scale(6), 0, Scale(4), 0};
        images.uAlign = BUTTON_IMAGELIST_ALIGN_LEFT;
        ::SendMessageW(page.addRange, BCM_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(&images));
    }
    ::DestroyIcon(icon.hIcon);
}

bool CreateControls(Page& page) {
    if (!page.parameters.Create(page.hwnd)) {
        return false; // 无共享滚动区时不交付会溢出的参数堆叠。
    }
    page.hint = Ui::CreateText(page.hwnd, 0, L"", 0, 0, 1, 1);
    page.pathLabel = Ui::CreateText(page.hwnd, 0, L"合作目标", 0, 0, 1, 1);
    page.path = MakeEdit(page.hwnd, kPath, ES_READONLY | ES_AUTOHSCROLL);
    page.browse = Ui::CreateButton(page.hwnd, kBrowse, L"选择 EXE…", 0, 0, 1, 1);
    page.exportLabel = Ui::CreateText(page.hwnd, 0, L"数据导出", 0, 0, 1, 1);
    page.exportName = MakeEdit(page.hwnd, kExport, ES_AUTOHSCROLL);
    page.bytesLabel = Ui::CreateText(page.hwnd, 0, L"字节数", 0, 0, 1, 1);
    page.bytes = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 1, 1, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kBytes)), ::GetModuleHandleW(nullptr), nullptr);
    page.conditionLabel = Ui::CreateText(page.hwnd, 0, L"停点条件", 0, 0, 1, 1);
    page.condition = MakeEdit(page.hwnd, kCondition, ES_AUTOHSCROLL);
    page.siteKindLabel = Ui::CreateText(page.hwnd, 0, L"绑定方式", 0, 0, 1, 1);
    page.siteKind = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 1, 1, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSiteKind)), ::GetModuleHandleW(nullptr), nullptr);
    for (const auto label : {L"映像数据导出", L"指针导出的私有区间", L"指针导出的私有执行入口",
         L"已有私有地址写入", L"已有私有地址执行", L"已有私有范围NX执行", L"已有模块精确PE导出执行", L"已有模块RVA执行", L"启动EXE并停在入口"}) {
        if (::SendMessageW(page.siteKind, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label)) < 0) return false;
    }
    ::SendMessageW(page.siteKind, CB_SETCURSEL, kSuspendedImageLaunch, 0);
    page.pidLabel = Ui::CreateText(page.hwnd, 0, L"目标 PID", 0, 0, 1, 1);
    page.targetPid = MakeEdit(page.hwnd, kTargetPid, ES_AUTOHSCROLL);
    page.creationLabel = Ui::CreateText(page.hwnd, 0, L"创建 FILETIME", 0, 0, 1, 1);
    page.targetCreation = MakeEdit(page.hwnd, kTargetCreation, ES_AUTOHSCROLL);
    page.addressLabel = Ui::CreateText(page.hwnd, 0, L"私有绝对地址", 0, 0, 1, 1);
    page.privateAddress = MakeEdit(page.hwnd, kPrivateAddress, ES_AUTOHSCROLL);
    page.pagesLabel = Ui::CreateText(page.hwnd, 0, L"4 KiB页数", 0, 0, 1, 1);
    page.privatePages = MakeEdit(page.hwnd, kPrivatePages, ES_AUTOHSCROLL | ES_NUMBER);
    page.rangeTitle = Ui::CreateText(page.hwnd, 0, L"纳入新的私有执行范围", 0, 0, 1, 1);
    page.rangeSource = Ui::CreateText(page.hwnd, 0, L"", 0, 0, 1, 1);
    page.rangeBaseLabel = Ui::CreateText(page.hwnd, 0, L"新范围起点", 0, 0, 1, 1);
    page.rangeBase = MakeEdit(page.hwnd, kRangeBase, ES_AUTOHSCROLL);
    page.rangePagesLabel = Ui::CreateText(page.hwnd, 0, L"4 KiB页数", 0, 0, 1, 1);
    page.rangePages = MakeEdit(page.hwnd, kRangePages, ES_AUTOHSCROLL | ES_NUMBER);
    page.addRange = Ui::CreateButton(page.hwnd, kAddRange, L"纳入新的执行范围", 0, 0, 1, 1);
    ::SetWindowTextW(page.privatePages, L"1"); // 默认1页，用户可输入实际范围，不设固定页数列表。
    ::SetWindowTextW(page.rangePages, L"1");
    page.stepLabel = Ui::CreateText(page.hwnd, 0, L"原生步进", 0, 0, 1, 1);
    page.stepMode = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 1, 1, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kStepMode)), ::GetModuleHandleW(nullptr), nullptr);
    for (const auto label : {L"步入一条机器指令", L"越过当前调用", L"跳出可信调用帧"}) {
        if (::SendMessageW(page.stepMode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label)) < 0) return false;
    }
    ::SendMessageW(page.stepMode, CB_SETCURSEL, 0, 0);
    page.start = Ui::CreateButton(page.hwnd, kStart, L"启动并监视", 0, 0, 1, 1, Ui::ButtonRole::Primary);
    page.pause = Ui::CreateButton(page.hwnd, kPause, L"主动暂停", 0, 0, 1, 1);
    page.resume = Ui::CreateButton(page.hwnd, kContinue, L"继续", 0, 0, 1, 1);
    page.close = Ui::CreateButton(page.hwnd, kClose, L"关闭监视", 0, 0, 1, 1);
    page.step = Ui::CreateButton(page.hwnd, kStep, L"执行步进", 0, 0, 1, 1);
    page.cancelStep = Ui::CreateButton(page.hwnd, kCancelStep, L"取消步进", 0, 0, 1, 1);
    page.followExecution = Ui::CreateButton(page.hwnd, kFollowExecution, L"同址写转执行", 0, 0, 1, 1);
    page.projectLabel = Ui::CreateText(page.hwnd, 0, L"项目路径", 0, 0, 1, 1);
    page.projectModeLabel = Ui::CreateText(page.hwnd, 0, L"项目模式", 0, 0, 1, 1);
    page.projectMode = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 1, 1, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kProjectMode)), ::GetModuleHandleW(nullptr), nullptr);
    for (const auto mode : {L"新建项目", L"打开项目并新建采样"}) {
        if (::SendMessageW(page.projectMode, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(mode)) < 0) return false;
    }
    ::SendMessageW(page.projectMode, CB_SETCURSEL, 0, 0);
    page.projectDirectory = MakeEdit(page.hwnd, kMemoryProject, ES_AUTOHSCROLL);
    page.memoryBaseLabel = Ui::CreateText(page.hwnd, 0, L"内存起点", 0, 0, 1, 1);
    page.memoryBase = MakeEdit(page.hwnd, kMemoryBase, ES_AUTOHSCROLL);
    page.memoryBytesLabel = Ui::CreateText(page.hwnd, 0, L"范围字节", 0, 0, 1, 1);
    page.memoryBytes = MakeEdit(page.hwnd, kMemoryBytes, ES_AUTOHSCROLL);
    page.apiTitle = Ui::CreateText(page.hwnd, 0, L"同采样API采集 · 独立来源", 0, 0, 1, 1);
    page.apiTarget = Ui::CreateText(page.hwnd, 0, L"", 0, 0, 1, 1);
    page.apiPidLabel = Ui::CreateText(page.hwnd, 0, L"来源 PID", 0, 0, 1, 1);
    page.apiPid = MakeEdit(page.hwnd, kApiPid, ES_AUTOHSCROLL);
    page.apiCreationLabel = Ui::CreateText(page.hwnd, 0, L"来源创建时间", 0, 0, 1, 1);
    page.apiCreation = MakeEdit(page.hwnd, kApiCreation, ES_AUTOHSCROLL);
    page.apiDurationLabel = Ui::CreateText(page.hwnd, 0, L"采集毫秒", 0, 0, 1, 1);
    page.apiDuration = MakeEdit(page.hwnd, kApiDuration, ES_AUTOHSCROLL);
    page.captureApi = Ui::CreateButton(page.hwnd, kCaptureApi, L"确认并采集来源API", 0, 0, 1, 1);
    ::SetWindowTextW(page.apiDuration, L"3000");
    page.readMemory = Ui::CreateButton(page.hwnd, kReadMemory, L"读取停点内存", 0, 0, 1, 1);
    page.saveMemory = Ui::CreateButton(page.hwnd, kSaveMemory, L"保存内存快照", 0, 0, 1, 1);
    page.saveExecution = Ui::CreateButton(page.hwnd, kSaveExecution, L"保存执行观测", 0, 0, 1, 1);
    page.copyReceipt = Ui::CreateButton(page.hwnd, kCopyReceipt, L"复制回执", 0, 0, 1, 1);
    page.exportReceipt = Ui::CreateButton(page.hwnd, kExportReceipt, L"导出回执", 0, 0, 1, 1);
    page.receipt = MakeEdit(page.hwnd, kReceipt, ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL);
    if (!page.hint || !page.pathLabel || !page.exportLabel || !page.bytesLabel || !page.conditionLabel || !page.stepLabel ||
        !page.siteKindLabel || !page.pidLabel || !page.creationLabel || !page.addressLabel || !page.pagesLabel ||
        !page.projectLabel || !page.projectModeLabel || !page.memoryBaseLabel || !page.memoryBytesLabel || !page.rangeTitle || !page.rangeSource || !page.rangeBaseLabel || !page.rangePagesLabel ||
        !page.apiTitle || !page.apiTarget || !page.apiPidLabel || !page.apiCreationLabel || !page.apiDurationLabel) return false;
    for (const auto control : {page.path, page.browse, page.exportName, page.bytes, page.condition,
              page.siteKind, page.targetPid, page.targetCreation, page.privateAddress, page.privatePages, page.rangeBase, page.rangePages, page.addRange,
              page.stepMode, page.start, page.pause, page.resume, page.close, page.followExecution, page.step, page.cancelStep, page.receipt,
             page.projectMode, page.projectDirectory, page.memoryBase, page.memoryBytes, page.readMemory, page.saveMemory, page.saveExecution,
             page.copyReceipt, page.exportReceipt, page.apiPid, page.apiCreation, page.apiDuration, page.captureApi}) {
        if (!control || !::SetWindowSubclass(control, Navigate, 1, reinterpret_cast<DWORD_PTR>(&page))) return false;
    }
    for (const auto control : {page.hint, page.pathLabel, page.path, page.browse, page.exportLabel, page.exportName,
        page.bytesLabel, page.bytes, page.conditionLabel, page.condition, page.siteKindLabel, page.siteKind,
        page.pidLabel, page.targetPid, page.creationLabel, page.targetCreation, page.addressLabel, page.privateAddress, page.pagesLabel, page.privatePages,
        page.rangeTitle, page.rangeSource, page.rangeBaseLabel, page.rangeBase, page.rangePagesLabel, page.rangePages, page.addRange,
        page.stepLabel, page.stepMode, page.projectModeLabel, page.projectMode, page.projectLabel, page.projectDirectory, page.memoryBaseLabel, page.memoryBase,
        page.memoryBytesLabel, page.memoryBytes, page.apiTitle, page.apiTarget, page.apiPidLabel, page.apiPid,
        page.apiCreationLabel, page.apiCreation, page.apiDurationLabel, page.apiDuration, page.captureApi}) {
        ::SetParent(control, page.parameters.Body()); // 唯一参数滚动责任，不包结果专业文本区。
    }
    const auto hintStyle = ::GetWindowLongPtrW(page.hint, GWL_STYLE);
    ::SetWindowLongPtrW(page.hint, GWL_STYLE, (hintStyle & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFT);
    for (const HWND label : {page.apiTarget, page.apiTitle, page.rangeTitle, page.rangeSource}) {
        const auto style = ::GetWindowLongPtrW(label, GWL_STYLE);
        ::SetWindowLongPtrW(label, GWL_STYLE, (style & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFT);
    }
    // 运行中可编辑下次条件；示例只是输入提示，不写入真实草稿。
    ::SendMessageW(page.condition, EM_SETCUEBANNER, TRUE,
        reinterpret_cast<LPARAM>(L"选填：stop.data.changedByteMask == 1u64"));
    ::SendMessageW(page.exportName, EM_SETLIMITTEXT, 255, 0);
    ::SendMessageW(page.receipt, EM_SETLIMITTEXT, 0, 0); // 复制与导出保留同一完整回执，不受EDIT默认输入长度限制。
    ::SendMessageW(page.targetPid, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"已有实例的非零 PID"));
    ::SendMessageW(page.targetCreation, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"精确创建 FILETIME，不是日期文本"));
    ::SendMessageW(page.privateAddress, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"0x 前缀十六进制，或十进制"));
    ::SendMessageW(page.rangeBase, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"非零4 KiB对齐绝对地址"));
    ::SendMessageW(page.apiPid, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"另一来源实例的十进制PID"));
    ::SendMessageW(page.apiCreation, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"来源创建FILETIME（十进制）"));
    ::SendMessageW(page.apiDuration, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"1000..10000 ms"));
    for (const auto width : kWatchWidths) {
        const auto label = std::to_wstring(width);
        if (::SendMessageW(page.bytes, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str())) < 0) return false;
    }
    ::SendMessageW(page.bytes, CB_SETCURSEL, 2, 0);
    page.tooltip = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, page.hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    AddTip(page, page.browse, L"选择已获明确授权的合作程序");
    AddTip(page, page.exportName, L"位置在开始时与目标实例一起冻结；精确PE导出区分大小写，模块RVA使用非零32位整数。");
    AddTip(page, page.start, L"按当前模式显式启动普通EXE并停在入口、启动合作程序，或附加已有实例的私有地址、已加载模块；运行中实例、路径和位置冻结，清退确认后可重新开始。");
    AddTip(page, page.pause, L"只在原绑定Armed且无Held、运行中步进或恢复责任时，用原owner请求pause/N；不新建暂停会话，不应用条件。"
        L"Pending不等于已停止，Preempted保留真实事件。ManualPause仅提供继续、完整Held内存读取/转储及关闭，本批不授步进或执行观测保存。");
    AddTip(page, page.resume, L"继续当前回执所对应的主动暂停、写入、执行或步进停点；NX范围内普通指令按真实BS推进。"
        L"POPF/SS/特权及需同时开放两页的跨页取指不支持；实际限制和结果见原生后端stage，尚未实测。");
    AddTip(page, page.close, L"由原所有者清退当前停点并脱离目标；清退未确认时保持原会话，不创建新的控制者。");
    AddTip(page, page.step, L"按所选模式步进当前停止事件的精确线程；本批ManualPause不支持步进。");
    AddTip(page, page.cancelStep, L"取消当前正在运行的原生步进并等待停止回执");
    AddTip(page, page.followExecution, L"仅将当前完整写入停点的原私有RWX起点切换为单地址执行关注，不继续线程。"
        L"沿用本轮冻结条件，仅后续真实执行命中求值；转换失败完整回滚，恢复未确认时使用关闭。");
    AddTip(page, page.projectDirectory, L"新建模式填尚不存在的新目录（空路径仅读取）；打开模式填原项目目录或project.ksaproj。每次Start新建采样冻结当前配置，不导入历史停点。打开失败不回退新建，原项目写租约被占用时请先关闭另一采集。");
    AddTip(page, page.projectMode, L"开始前显式选择新建或打开原项目，运行中冻结。两种方式都创建本轮新sample，内存、API和执行仅写本轮；不恢复历史stop或绕过API同采样准入。");
    AddTip(page, page.memoryBase, L"显式起始地址，0x为十六进制，其余为十进制；修改草稿不改变旧结果。");
    AddTip(page, page.memoryBytes, L"十进制非零范围字节数；逐页读取不是原子进程转储，失败不补零。");
    AddTip(page, page.readMemory, L"在原写入、执行或步进会话读取当前完整停点，不执行条件自动继续或暂停。");
    AddTip(page, page.saveMemory, L"保存显示中的完整读取结果到原sample，保留读前读后停点和成功页字节。");
    AddTip(page, page.saveExecution, L"仅保存真实执行入口或Into完成观测到独立raw-native；普通写入和ManualPause事件禁用。");
    AddTip(page, page.copyReceipt, L"复制当前完整回执文本，包含原目标、内存页状态和归档坐标。");
    AddTip(page, page.exportReceipt, L"将同一份完整回执导出为UTF-8文本；完整内存原字节使用保存内存快照。");
    AddTip(page, page.stepMode, L"改变模式不执行操作；跳出仅支持已核验的调用帧，失败时保留停点。");
    AddTip(page, page.siteKind, L"前三项启动合作程序；指针导出沿同一Ready/Gate，只有真实Armed才放行。"
        L"已有私有地址模式无需EXE或导出，核对PID、创建FILETIME、AMD64及MEM_PRIVATE区域后设置关注。"
        L"执行模式要求EXECUTE/RX/RWX；写入宽度为1/2/4/8字节。NX私有执行范围要求4 KiB对齐、正十进制页数并属同一allocation，"
        L"临时撤X，逐页保留不同RX/RWX等原保护，关闭时恢复，不装DR0。普通指令按真实BS推进；"
        L"POPF/SS/特权及需同时开放两页的跨页取指不支持，实际结果见后端stage，尚未实测。"
        L"已有模块两项以绝对路径及精确PE导出或非零uint32 RVA设置执行DR0，不改页保护、不查询PDB、不启动目标。"
        L"普通EXE启动项先挂起创建，由原owner确认入口武装后释放初始挂起；RVA留空使用PE入口，不要求合作标记，不覆盖此前TLS/loader。当前会话清退确认前不能修改绑定。");
    AddTip(page, page.targetPid, L"已有AMD64目标的非零32位PID；仅接受完整无符号十进制或0x十六进制，不截断。"
        L"点击附加时与创建FILETIME一起冻结；活会话中禁用。");
    AddTip(page, page.targetCreation, L"该精确实例的非零64位创建FILETIME；十进制或0x十六进制。"
        L"不是日期文本，也不自动改用后来同PID的进程；活会话中禁用。");
    AddTip(page, page.privateAddress, L"非零64位私有绝对地址，0x前缀十六进制，其余十进制。"
        L"私有页模式要求4 KiB对齐；不填模块RVA或指针导出地址。区域身份及保护由原所有者核验，活会话中禁用。");
    AddTip(page, page.privatePages, L"仅NX私有执行范围采用此项：输入正十进制页数，每页4 KiB，默认1。起点必须已对齐，不自动取整；"
        L"范围须属同一allocation，每页原RX/RWX等保护分别保留和恢复。开始时冻结总字节数，运行中禁用。");
    AddTip(page, page.addRange, L"仅当前NX会话完整Held可用：冻结此处起点/页数及原停点，在原owner纳入，不Continue。"
        L"可跨不同allocation且不连续，但每段须属同一allocation，重叠拒绝。失败仅回滚新增页，未恢复由原关闭负责。");
    AddTip(page, page.rangeBase, L"新增段的非零4 KiB对齐绝对地址，十进制或0x十六进制；不会自动取整，可与初始范围不连续。");
    AddTip(page, page.rangePages, L"新增段输入正十进制页数，每页4 KiB且属同一allocation；字节数转换不能溢出，后端核验重叠及原保护。");
    AddTip(page, page.apiPid, L"明确选择另一API来源的十进制PID，不从native目标或历史选区推导。原worker复核来源强实例。");
    AddTip(page, page.apiCreation, L"API来源的精确非零创建FILETIME（十进制），与来源PID一起冻结；不是当前native目标。");
    AddTip(page, page.apiDuration, L"Ready后有限采集区间：1000..10000毫秒，默认3000；不支持连续采集。");
    AddTip(page, page.captureApi, L"需已附加native会话及本轮项目。明确确认后由原worker查询native身份并调用共享CaptureApi，"
        L"沿用原writer/sample，API清退不继续或关闭native；已有raw/checkpoints由服务拒绝，不覆盖或跳段。关闭等待在途有限采集清退。");
    AddTip(page, page.bytes, L"写入关注只接受1/2/4/8字节；执行模式不使用写入宽度，因此禁用此项。"
        L"活会话的实际类型以右侧回执为准，写转执行保留最初请求。");
    AddTip(page, page.bytesLabel, L"执行模式无需写入宽度，字节数选择禁用；运行中绑定参数冻结，清退确认后才能修改。");
    AddTip(page, page.condition, L"条件在启动时冻结；假或未知请求自动继续。写入条件作用于字节变化，执行条件仅作用于入口尝试，普通step不复用条件。"
        L"主动暂停ManualPause不应用命中条件，不自动放行。NX范围stop.address为真实命中RIP，可不同于范围起点；推进结果见实际后端stage。"
        L"执行事件的stop.data字段未知，可使用stop.tid != 0u64；"
        L"支持 stop.address、stop.data.changedByteMask、stop.data.watchedBytes、stop.data.enrolledAfterStop、"
        L"stop.exceptionCode、stop.firstChance、stop.pid、stop.tid、stop.thread.creationFileTime、"
        L"stop.thread 下的 rip、rax、rbx、rcx、rdx、rbp、rsi、rdi、rsp、r8 至 r15、eflags。数值与位运算按C#优先级，用括号明确组合："
        L"(stop.thread.rax & 0xffu64)==0u64、stop.thread.rip>=stop.address。除零单列故障并返回未知。"
        L"v3还支持 condition ? trueBranch : falseBranch，分支须同类型，未知条件不读取分支。"
        L"布尔 &、^、| 不短路，始终求值两侧，不能混合bool/u64。"
        L"布尔字段或谓词也支持==、!=；任一未知即未知，不支持大小比较。"
        L"RIP、RAX、RSP 来自同一命中线程的冻结寄存器，采集失败时为未知。");
    if (page.tooltip) {
        ::SendMessageW(page.tooltip, TTM_SETMAXTIPWIDTH, 0, Scale(460)); // 字段说明由系统折行。
    }
    Ui::AttachTextFindSupport(page.receipt);
    AttachFollowIcon(page); // 不增加窗口或布局，只装饰已有原生按钮。
    AttachRangeIcon(page);
    Ui::SetWindowFontRecursive(page.hwnd);
    DescribeDraftMode(page);
    Layout(page);
    Refresh(page);
    return true;
}

LRESULT CALLBACK PageProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* page = reinterpret_cast<Page*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto owned = std::make_unique<Page>();
        owned->hwnd = hwnd;
        const auto* port = static_cast<const std::shared_ptr<LightNativeControlPort>*>(
            reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        if (port) owned->controlPort = *port;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    if (!page) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case kCandidateContext: {
        auto* context = reinterpret_cast<LightPrivateExecutionCandidatesContext*>(lp);
        if (!context) return FALSE;
        const auto state = page->session.ReadStatus();
        context->sessionIdentity = state.sessionIdentity;
        context->active = state.active;
        context->busy = state.continuing || state.state == LightDataWatchState::Starting || state.state == LightDataWatchState::Closing ||
            state.state == LightDataWatchState::RecoveryRequired || page->preparingRange;
        context->retiring = page->retiring;
        context->nxBinding = state.binding && state.binding->rangeBytes && !state.binding->writeWatchBytes;
        context->target = state.nativeTarget;
        context->projectId = state.projectId;
        context->sampleId = state.memoryProject.sampleId;
        context->projectDirectory = state.memoryProject.projectDirectory;
        context->view = state.candidates;
        context->diagnostic = state.candidatesDiagnostic;
        return TRUE;
    }
    case kReadCandidates: {
        const auto* command = reinterpret_cast<const CandidateReadCommand*>(lp);
        return command && !page->retiring && !page->preparingRange &&
            page->session.ReadExecutionCandidates(command->sessionIdentity, command->request);
    }
    case kPrepareRangeDraft: {
        const auto* selection = reinterpret_cast<const LightPrivateExecutionCandidateSelection*>(lp);
        return selection && PrepareCandidateRange(*page, *selection);
    }
    case kPrepareImageDraft: {
        const auto* draft = reinterpret_cast<const LightImageExecutionDraft*>(lp);
        Refresh(*page);
        if (!draft || !draft->rva || draft->modulePath.size() < 4 || draft->modulePath[1] != L':' ||
            (draft->modulePath[2] != L'\\' && draft->modulePath[2] != L'/') ||
            draft->definitionId.empty() || draft->projectId.empty() || draft->projectPath.empty() || page->retiring || page->shown.active) return FALSE;
        if ((!ReadText(page->path).empty() || !ReadText(page->exportName).empty() || !ReadText(page->privateAddress).empty() || !ReadText(page->projectDirectory).empty()) &&
            ::MessageBoxW(hwnd, L"将以所选定义替换模块、导出/RVA或私有位置及项目草稿，并选择打开原项目、新建采样。PID、创建时间、条件和旧结果保留。是否载入？",
                L"载入实时模块断点草稿", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return FALSE;
        Refresh(*page); // 模态确认期间可能开始清退或更换会话，确认后再次核对。
        if (page->retiring || page->shown.active) return FALSE;
        page->preparingDefinition = true;
        ::SendMessageW(page->siteKind, CB_SETCURSEL, kImageRvaExecution, 0);
        ::SetWindowTextW(page->path, draft->modulePath.c_str());
        wchar_t rva[16]{};
        swprintf_s(rva, L"0x%08X", static_cast<unsigned int>(draft->rva));
        ::SetWindowTextW(page->exportName, rva);
        page->definitionId = draft->definitionId;
        page->definitionProjectId = draft->projectId;
        ::SendMessageW(page->projectMode, CB_SETCURSEL, 1, 0);
        ::SetWindowTextW(page->projectDirectory, draft->projectPath.c_str());
        page->preparingDefinition = false;
        page->inputError = L"已载入定义位置及打开原项目草稿；请核对已有实例PID和创建FILETIME，再显式附加。原worker将新建sample并复核冻结定义、模块和RVA。";
        DescribeDraftMode(*page);
        Layout(*page);
        Refresh(*page);
        return TRUE;
    }
    case WM_CREATE:
        if (!CreateControls(*page)) return -1;
        if (page->controlPort) {
            page->controlSource = std::make_shared<LightNativeControlSource>();
            page->controlSource->submit = [page](LightNativeControlAction action) { SubmitControl(*page, action); };
            page->controlPort->Bind(false, page->controlSource);
            PublishToolbar(*page);
        }
        return 0;
    case WM_SIZE: Layout(*page); return 0;
    case WM_SHOWWINDOW:
        if (wp) {
            Refresh(*page);
            if (page->shown.active) ::SetTimer(hwnd, kDisplayTimer, kDisplayIntervalMs, nullptr);
        }
        break;
    case WM_TIMER:
        if (wp == kDisplayTimer) {
            Refresh(*page); // 沿原显示timer发布本地快照；隐藏页也更新总览工具条，不增加原生查询。
            return 0;
        }
        break;
    case WM_DRAWITEM:
        if (wp == kStart) { Ui::DrawThemedButton(*reinterpret_cast<const DRAWITEMSTRUCT*>(lp)); return TRUE; }
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        const auto child = reinterpret_cast<HWND>(lp);
        const auto dc = reinterpret_cast<HDC>(wp);
        auto& theme = Ui::AppTheme();
        if (child == page->hint || child == page->pathLabel || child == page->exportLabel || child == page->bytesLabel ||
            child == page->conditionLabel || child == page->stepLabel || child == page->siteKindLabel ||
            child == page->pidLabel || child == page->creationLabel || child == page->addressLabel || child == page->pagesLabel ||
            child == page->rangeTitle || child == page->rangeSource || child == page->rangeBaseLabel || child == page->rangePagesLabel ||
            child == page->apiTitle || child == page->apiTarget || child == page->apiPidLabel || child == page->apiCreationLabel || child == page->apiDurationLabel ||
            child == page->projectLabel || child == page->projectModeLabel || child == page->memoryBaseLabel || child == page->memoryBytesLabel) {
            return Ui::PaintLabelBackground(dc, child, theme.windowBrush(), theme.textColor);
        }
        ::SetTextColor(dc, theme.textColor);
        ::SetBkColor(dc, theme.panelColor);
        return reinterpret_cast<LRESULT>(theme.panelBrush());
    }
    case WM_COMMAND:
        if (!page->preparingRange && ((LOWORD(wp) == kRangeBase && HIWORD(wp) == EN_CHANGE) ||
            (LOWORD(wp) == kRangePages && HIWORD(wp) == EN_CHANGE))) {
            if (page->rangeOrigin) page->inputError = L"已手工编辑AddRange草稿，原候选来源已解除；需保留候选来源时请从候选页重新载入子范围。";
            page->rangeOrigin.reset();
            page->rangeOriginSession.reset();
            Refresh(*page);
            return 0;
        }
        if ((LOWORD(wp) == kMemoryBase || LOWORD(wp) == kMemoryBytes) && HIWORD(wp) == EN_CHANGE) {
            page->inputError.clear();
            Refresh(*page); // 仅更新相机范围资格；不派发读取、保存或原生Query。
            return 0;
        }
        if (LOWORD(wp) == kSiteKind && HIWORD(wp) == CBN_SELCHANGE) {
            page->definitionId.clear(); // 手工改模式后不保留不匹配定义来源。
            DescribeDraftMode(*page);
            Layout(*page);
            Refresh(*page); // 只更新草稿宽度资格，不触发启动或重绑。
            return 0;
        }
        if (LOWORD(wp) == kExport && HIWORD(wp) == EN_CHANGE && !page->preparingDefinition) page->definitionId.clear();
        if ((LOWORD(wp) == kCondition || LOWORD(wp) == kTargetPid || LOWORD(wp) == kTargetCreation ||
            LOWORD(wp) == kPrivateAddress || LOWORD(wp) == kPrivatePages || LOWORD(wp) == kExport) && HIWORD(wp) == EN_CHANGE && !page->inputError.empty()) {
            page->inputError.clear(); // 清除草稿校验提示，保留当前或上一轮实际回执。
            Refresh(*page);
            return 0;
        }
        if (HIWORD(wp) == BN_CLICKED && !page->retiring) {
            switch (LOWORD(wp)) {
            case kCaptureApi: CaptureSessionApi(*page); return 0;
            case kPause: SubmitControl(*page, LightNativeControlAction::Pause); return 0;
            case kAddRange: AddExecutionRange(*page); return 0;
            case kBrowse: if (!page->shown.active) Browse(*page); Refresh(*page); return 0;
            case kStart: Start(*page); return 0;
            case kCopyReceipt:
                if (!Ui::CopyTextToClipboard(hwnd, page->shownText, L"写入与步进停点回执")) {
                    page->inputError = L"复制回执失败，请重试。";
                }
                Refresh(*page);
                return 0;
            case kExportReceipt: {
                std::wstring error; // 用户取消不修改当前回执或参数。
                if (Ui::SaveUtf8TextFileWithDialog(hwnd, L"native-stop-receipt.txt", L"导出停点回执",
                    L"文本文件 (*.txt)\0*.txt\0", L"txt", page->shownText, &error) == Ui::SaveTextFileResult::Failed) {
                    page->inputError = std::move(error);
                }
                Refresh(*page);
                return 0;
            }
            case kReadMemory: ReadStopMemory(*page); return 0;
            case kSaveMemory:
                if (!page->session.SaveMemory(page->shown.memory)) {
                    page->inputError = L"当前内存结果不可保存，请核对原项目与回执。";
                }
                Refresh(*page);
                return 0;
            case kSaveExecution:
                if (!page->session.SaveExecution(page->shown.displayedStop)) {
                    page->inputError = L"当前事件没有可保存的执行观测，请核对原停点。";
                }
                Refresh(*page);
                return 0;
            case kContinue: SubmitControl(*page, LightNativeControlAction::Continue); return 0;
            case kFollowExecution:
                page->inputError.clear();
                if (!page->session.FollowPrivateExecution(page->shown.displayedStop)) {
                    page->inputError = L"当前完整私有写入停点不可转换，请核对原RWX起点与最新回执。";
                }
                Refresh(*page);
                return 0;
            case kClose: SubmitControl(*page, LightNativeControlAction::Detach); return 0;
            case kStep: {
                const auto index = ::SendMessageW(page->stepMode, CB_GETCURSEL, 0, 0); // 点击时冻结，后台不读控件。
                constexpr std::array actions{LightNativeControlAction::StepInto, LightNativeControlAction::StepOverCall,
                    LightNativeControlAction::StepOut};
                if (index >= 0 && static_cast<std::size_t>(index) < actions.size()) {
                    SubmitControl(*page, actions[static_cast<std::size_t>(index)]);
                }
                return 0;
            }
            case kCancelStep: SubmitControl(*page, LightNativeControlAction::CancelStep); return 0;
            }
        }
        break;
    case Ui::kBeginNativeRetirementMessage:
        page->retiring = true;
        page->session.BeginRetirement();
        Refresh(*page);
        return 0;
    case Ui::kPollNativeRetirementMessage: return page->session.Ready() ? 0 : 1;
    case Ui::kCancelNativeRetirementMessage:
        page->retiring = false;
        page->session.CancelRetirement();
        Refresh(*page);
        return 0;
    case WM_DESTROY:
        if (page->controlSource) {
            page->controlSource->submit = {};
            page->controlPort->Unbind(false, page->controlSource);
            page->controlSource.reset();
        }
        return 0;
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kDisplayTimer);
        if (page->tooltip) ::DestroyWindow(page->tooltip);
        if (page->followImages) ::ImageList_Destroy(page->followImages); // 页销毁时回收唯一图集。
        if (page->rangeImages) ::ImageList_Destroy(page->rangeImages);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete page;
        break;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}

HWND CreateDataWatchPage(HWND parent, const RECT& bounds, const std::shared_ptr<LightNativeControlPort>& port) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = PageProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ui::AppTheme().windowBrush();
    wc.lpszClassName = kPageClass;
    if (!::RegisterClassW(&wc) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    return ::CreateWindowExW(WS_EX_CONTROLPARENT, kPageClass, L"写入停点", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, parent, nullptr, wc.hInstance,
        const_cast<std::shared_ptr<LightNativeControlPort>*>(&port));
}

HWND CreateWorkspace(HWND parent, const RECT& bounds, const std::shared_ptr<LightNativeControlPort>& port) {
    Ui::WorkspaceOptions options{};
    options.tabControlId = kWorkspaceTabs;
    options.initialTabId = 1;
    return Ui::CreateWorkspaceHost(parent, bounds, {
        {1, L"工程与采集", L"打开 ActionAnalyze 工程、采集及回放证据。",
            [port](HWND host, const RECT& area) {
                return CreateLightNativeControlOverview(host, area, port, [host](HWND owner, const RECT& content) {
                    return CreateProjectBreakpointPane(owner, content, [host](const LightImageExecutionDraft& draft) {
                        const HWND target = Ui::WorkspaceHostPage(host, 2, true);
                        return target && PrepareDataWatchImageExecutionDraft(target, draft) && Ui::ActivateWorkspaceHostTab(host, 2);
                    });
                });
            }},
        {2, L"写入停点", L"启动合作程序，或附加已有实例的私有地址、普通模块，查看写入、执行与步进回执。",
            [port](HWND host, const RECT& area) { return CreateDataWatchPage(host, area, port); }},
        {3, L"私有范围候选", L"核验原会话API段，选择实际输出的整页子范围，仅载入原AddRange草稿。",
            [](HWND host, const RECT& area) {
                if (!Ui::WorkspaceHostPage(host, 2, true)) return static_cast<HWND>(nullptr);
                LightPrivateExecutionCandidatesPort candidates;
                candidates.read = [host] {
                    LightPrivateExecutionCandidatesContext context;
                    const HWND target = Ui::WorkspaceHostPage(host, 2);
                    if (target) ::SendMessageW(target, kCandidateContext, 0, reinterpret_cast<LPARAM>(&context));
                    return context;
                };
                candidates.request = [host](const std::shared_ptr<const std::uint8_t>& identity, const LightPrivateExecutionCandidatesRequest& request) {
                    const HWND target = Ui::WorkspaceHostPage(host, 2);
                    const CandidateReadCommand command{identity, request};
                    return target && ::SendMessageW(target, kReadCandidates, 0, reinterpret_cast<LPARAM>(&command)) != FALSE;
                };
                candidates.prepare = [host](const LightPrivateExecutionCandidateSelection& selection) {
                    const HWND target = Ui::WorkspaceHostPage(host, 2);
                    return target && ::SendMessageW(target, kPrepareRangeDraft, 0, reinterpret_cast<LPARAM>(&selection)) != FALSE &&
                        Ui::ActivateWorkspaceHostTab(host, 2);
                };
                return CreateLightPrivateExecutionCandidatesPane(host, area, std::move(candidates));
            }},
    }, std::move(options));
}

} // namespace

bool PrepareDataWatchImageExecutionDraft(HWND page, const LightImageExecutionDraft& draft) {
    wchar_t type[96]{};
    return ::IsWindow(page) && ::GetClassNameW(page, type, static_cast<int>(std::size(type))) &&
        std::wcscmp(type, kPageClass) == 0 && ::SendMessageW(page, kPrepareImageDraft, 0, reinterpret_cast<LPARAM>(&draft)) != FALSE;
}

HWND CreateActionAnalyzeWorkspace(HWND parent, const RECT& bounds) {
    return CreateWorkspace(parent, bounds, std::make_shared<LightNativeControlPort>());
}

HWND CreateActionAnalyzeControlWorkspace(HWND parent, const RECT& bounds) {
    const auto port = std::make_shared<LightNativeControlPort>(); // 每个工作台独立端口，不使用全局单例。
    Ui::WorkspaceOptions options{};
    options.tabControlId = 58590;
    options.initialTabId = 1;
    return Ui::CreateWorkspaceHost(parent, bounds, {
        {1, L"工程、采集与写入停点", L"保留已有行为分析工作台。",
            [port](HWND host, const RECT& area) { return CreateWorkspace(host, area, port); }},
        {2, L"进程集合控制", L"核验本会话显式集合，逐成员暂停、继续和恢复。",
            [port](HWND host, const RECT& area) { return CreateProcessGroupPage(host, area, port); }},
    }, std::move(options));
}

} // namespace Ksword::Features::ActionAnalyze
