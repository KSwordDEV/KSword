#include "NetworkTrafficPageState.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <commctrl.h>
#include <commdlg.h>
#include <limits>

namespace Ksword::Features::ActionAnalyze::network_traffic_page {
namespace project = Ksword::ActionAnalyze;
namespace {
constexpr wchar_t kClass[] = L"KswordARKLight.ActionAnalyzeNetworkTraffic"; // 原生页稳定类名。

// 只从当前控件复制本地草稿，后台不借用这些控件。
std::wstring Text(HWND control)
{
    std::wstring text(static_cast<std::size_t>(GetWindowTextLengthW(control)) + 1, L'\0'); // 包含NUL空间。
    const auto length = GetWindowTextW(control, text.data(), static_cast<int>(text.size())); // 实际复制长度。
    text.resize(static_cast<std::size_t>(length));
    return text;
}

// 严格无符号十进制解析，拒绝溢出和部分解析；空值只在显式optional时表示0。
bool Number(HWND input, std::uint64_t& value, bool optional = false)
{
    const auto text = Text(input); // 点击时冻结的输入。
    value = 0;
    if (text.empty()) {
        return optional;
    }
    for (const auto ch : text) {
        if (ch < L'0' || ch > L'9' || value > (UINT64_MAX - (ch - L'0')) / 10) {
            return false;
        }
        value = value * 10 + (ch - L'0');
    }
    return true;
}

// 状态改变后重新量自然高度，不向结果正文写入当前草稿身份。
void Status(Page& page, const wchar_t* text)
{
    SetWindowTextW(page.status, text);
    Layout(page);
}

// 仅选择已有manifest，不创建项目或sample。
void Browse(Page& page)
{
    wchar_t path[32768]{}; // 正式项目路径缓冲区，支持较长选择结果。
    OPENFILENAMEW dialog{sizeof(dialog)}; // 现有系统文件选择器，不接管其内部布局。
    dialog.hwndOwner = page.hwnd;
    dialog.lpstrFilter = L"ActionAnalyze (project.ksaproj)\0project.ksaproj\0\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(std::size(path));
    dialog.lpstrTitle = L"选择已有项目…";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&dialog)) {
        SetWindowTextW(page.project, path);
    }
}

// 接受一个完整冻结请求；已有任务不合并、不替换，关闭期间不接受副作用事务。
void Execute(Page& page, bool capture)
{
    if (page.retiring || page.worker->running()) {
        return;
    }
    project::NetworkTrafficRequest request; // worker使用的独立值副本。
    request.capture = capture;
    request.projectPath = Text(page.project);
    for (const auto ch : Text(page.sample)) {
        if (ch > 127) {
            Status(page, L"参数无效：采样 UUID 必须是 ASCII。");
            return;
        }
        request.plan.sampleId.push_back(static_cast<char>(ch));
    }
    bool valid = !request.projectPath.empty() && project::ProjectStorage::IsUuid(request.plan.sampleId);
    if (capture) {
        std::uint64_t pid = 0; // 避免强制转换前丢失PID溢出信息。
        std::uint64_t duration = 0; // 先按64位校验，再交给有界采集器。
        valid = Number(page.pid, pid) && Number(page.creation, request.plan.creationFileTime) &&
            Number(page.duration, duration) && valid;
        valid = valid && pid > 0 && pid < (std::numeric_limits<std::uint32_t>::max)() &&
            request.plan.creationFileTime && duration >= 100 && duration <= 60000;
        request.plan.pid = static_cast<std::uint32_t>(pid);
        request.plan.durationMs = static_cast<std::uint32_t>(duration);
        request.plan.backend = SendMessageW(page.source, CB_GETCURSEL, 0, 0) == 0 ?
            project::NetworkTrafficBackend::RawSocket : project::NetworkTrafficBackend::ExistingWfp;
    } else {
        valid = Number(page.ordinal, request.ordinal) && Number(page.sequence, request.recordSequence, true) && valid;
    }
    if (!valid) {
        Status(page, L"参数无效：请核对已有项目、采样 UUID 及完整十进制身份或段号。");
        return;
    }

    const auto cancelled = std::make_shared<std::atomic_bool>(false); // 页面销毁后仍由worker持有。
    page.cancelled = capture ? cancelled : nullptr;
    page.worker->request([request, cancelled]() { return RunLightNetworkTraffic(request, *cancelled); },
        [&page](std::uint64_t, std::optional<LightNetworkTrafficView>&& view, std::exception_ptr failure) {
            page.cancelled.reset();
            if (failure || !view) {
                Status(page, L"后台操作异常；保留原结果，请检查项目后重试。");
            } else {
                page.shownText = std::move(view->text);
                SetWindowTextW(page.receipt, page.shownText.c_str());
                const auto& result = view->result; // 实际结果，不从当前输入重建来源。
                const bool ok = result.opened && (result.request.capture ? result.receipt.status &&
                    result.receipt.sourceReady && result.receipt.cleanupConfirmed && result.receipt.reason == "duration-elapsed" &&
                    !result.receipt.queueDropped && !result.receipt.sourceGap && !result.receipt.unsupportedPackets &&
                    result.receipt.checkpoint.ordinal && result.read.status : bool(result.read.status));
                Status(page, ok ? L"操作已结束，实际来源与结果见回执。" :
                    L"操作未完整完成，错误或部分结果见回执；可修正参数后重试。");
            }
            UpdateActions(page);
        });
    if (page.worker->running()) {
        Status(page, L"正在执行冻结请求；当前回执仍属于上次结果。");
    } else {
        page.cancelled.reset();
        Status(page, L"后台操作未受理，请稍后重试。");
    }
    UpdateActions(page);
}

// 系统选择目标文件后，固定正文副本在后台写盘；运行中更新回执不改变导出内容。
void Export(Page& page)
{
    if (page.retiring || page.shownText.empty() || page.exporter->running()) {
        return;
    }
    Ui::TextExportDestination destination; // UI线程只选路径。
    if (Ui::ChooseTextExportDestination(page.hwnd, L"network-traffic.txt", L"导出回执",
        L"Text (*.txt)\0*.txt\0\0", L"txt", destination) != Ui::SaveTextFileResult::Saved) {
        return;
    }
    const auto text = page.shownText; // 正文与导出来源在点击时冻结。
    page.exporter->request([destination, text]() {
        std::wstring error; // 后台保存失败的原始诊断。
        const auto saved = Ui::WriteUtf8TextToDestination(destination, text, L"ActionAnalyze raw-network", L"text", &error);
        return saved == Ui::SaveTextFileResult::Saved ? std::wstring{} : error;
    }, [&page](std::uint64_t, std::optional<std::wstring>&& error, std::exception_ptr failure) {
        if (failure || !error || !error->empty()) {
            Status(page, L"回执导出失败，请重新选择保存路径。");
        }
        UpdateActions(page);
    });
    UpdateActions(page);
}

// 原生页消息只管理控件和值投递，不在UI线程做进程查询、抓包或项目读写。
LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp)
{
    auto* page = reinterpret_cast<Page*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA)); // 页根唯一状态。
    if (message == WM_NCCREATE) {
        page = new Page;
        page->hwnd = hwnd;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
    }
    if (!page) {
        return DefWindowProcW(hwnd, message, wp, lp);
    }
    switch (message) {
    case WM_CREATE:
        page->worker = std::make_unique<Ui::AsyncSnapshotTask<LightNetworkTrafficView>>(hwnd, kCompleted);
        page->exporter = std::make_unique<Ui::AsyncSnapshotTask<std::wstring>>(hwnd, kExported);
        return CreateControls(*page) ? 0 : -1;
    case WM_SIZE:
        if (page->receipt) {
            Layout(*page);
        }
        return 0;
    case kCompleted:
        page->worker->consume(hwnd, wp, lp);
        return 0;
    case kExported:
        page->exporter->consume(hwnd, wp, lp);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case kBrowse:
            Browse(*page);
            return 0;
        case kCapture:
            Execute(*page, true);
            return 0;
        case kRead:
            Execute(*page, false);
            return 0;
        case kCancel:
            if (page->cancelled) {
                page->cancelled->store(true);
                Status(*page, L"正在停止来源并排空归档…");
                UpdateActions(*page);
            }
            return 0;
        case kCopy:
            Ui::CopyTextToClipboard(hwnd, page->shownText, L"ActionAnalyze raw-network");
            return 0;
        case kExport:
            Export(*page);
            return 0;
        case kFind:
            Ui::OpenTextFindSupport(page->receipt);
            return 0;
        }
        break;
    case Ui::kBeginNativeRetirementMessage:
        page->retiring = true;
        if (page->cancelled) {
            page->cancelled->store(true);
        }
        UpdateActions(*page);
        return page->worker->running() || page->exporter->running() ? 1 : 0;
    case Ui::kPollNativeRetirementMessage:
        return page->worker->running() || page->exporter->running() ? 1 : 0;
    case Ui::kCancelNativeRetirementMessage:
        page->retiring = false;
        UpdateActions(*page);
        return 0;
    case WM_DRAWITEM:
        Ui::DrawThemedButton(*reinterpret_cast<const DRAWITEMSTRUCT*>(lp));
        return TRUE;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        const auto dc = reinterpret_cast<HDC>(wp); // 当前绘制上下文。
        auto& theme = Ui::AppTheme(); // 动态主题唯一拥有者。
        if (const auto brush = Ui::PaintLabelBackground(dc, reinterpret_cast<HWND>(lp), theme.windowBrush(), theme.textColor)) {
            return brush;
        }
        SetTextColor(dc, theme.textColor);
        SetBkColor(dc, theme.panelColor);
        return reinterpret_cast<LRESULT>(theme.panelBrush());
    }
    case WM_ERASEBKGND: {
        RECT bounds{}; // 页根实际不透明主题底色。
        GetClientRect(hwnd, &bounds);
        FillRect(reinterpret_cast<HDC>(wp), &bounds, Ui::AppTheme().windowBrush());
        return TRUE;
    }
    case WM_NCDESTROY:
        if (page->cancelled) {
            page->cancelled->store(true);
        }
        if (page->worker) {
            page->worker->cancel();
        }
        if (page->exporter) {
            page->exporter->cancel();
        }
        if (page->tooltip) {
            DestroyWindow(page->tooltip);
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete page;
        return DefWindowProcW(hwnd, message, wp, lp);
    }
    return DefWindowProcW(hwnd, message, wp, lp);
}
} // namespace

// 按真实后台状态更新动作，已有正文在忙/失败时仍可搜索、复制与导出。
void UpdateActions(Page& page)
{
    const bool busy = page.worker && page.worker->running(); // 单个本端在途操作。
    EnableWindow(page.capture, !busy && !page.retiring);
    EnableWindow(page.read, !busy && !page.retiring);
    EnableWindow(page.cancel, busy && page.cancelled && !page.cancelled->load());
    EnableWindow(page.copy, !page.shownText.empty());
    EnableWindow(page.find, !page.shownText.empty());
    EnableWindow(page.exportText, !page.retiring && !page.shownText.empty() && page.exporter && !page.exporter->running());
}

} // namespace Ksword::Features::ActionAnalyze::network_traffic_page

namespace Ksword::Features::ActionAnalyze {

// 主代理在Light原ActionAnalyzePage工厂登记本函数即可，无需另起宿主或运行副本。
HWND CreateNetworkTrafficPage(HWND parent, const RECT& bounds)
{
    WNDCLASSW type{}; // 幂等登记本页独立原生类。
    type.lpfnWndProc = network_traffic_page::WindowProc;
    type.hInstance = GetModuleHandleW(nullptr);
    type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    type.lpszClassName = network_traffic_page::kClass;
    if (!RegisterClassW(&type) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return nullptr;
    }
    return CreateWindowExW(WS_EX_CONTROLPARENT, type.lpszClassName, L"网络流量", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, type.hInstance, nullptr);
}

} // namespace Ksword::Features::ActionAnalyze
