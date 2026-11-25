#include "ActionAnalyzePage.h"

#include "EvidenceTimeline.h"
#include "StoredEvidence.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commdlg.h>

#include <algorithm>
#include <array>
#include <string_view>

namespace Ksword::Features::ActionAnalyze {
namespace {

constexpr wchar_t kPageClass[] = L"KswordARKLight.ActionAnalyze";
constexpr UINT kComplete = WM_APP + 936;
enum ControlId { kOpen = 68301, kRetry, kCategories, kFilter, kTimeline, kRecords, kDetails, kStatus, kEtwOnly };
using Ui::Scale;

struct Snapshot {
    std::wstring path;
    SegmentEvidence evidence;
    std::shared_ptr<const std::vector<Ui::VirtualListRow>> presentation;
};

struct Page {
    HWND hwnd = nullptr;
    HWND open = nullptr;
    HWND retry = nullptr;
    HWND categories = nullptr;
    HWND filterLabel = nullptr;
    HWND filter = nullptr;
    HWND etwOnly = nullptr;
    HWND actions = nullptr;
    HWND capability = nullptr;
    HWND projection = nullptr;
    HWND details = nullptr;
    HWND status = nullptr;
    EvidenceTimeline timeline;
    Ui::VirtualListView list;
    std::unique_ptr<Ui::AsyncSnapshotTask<Snapshot>> task;
    std::shared_ptr<const Snapshot> snapshot;
    std::wstring requestPath;
    std::wstring requestStatus = L"请选择一个 .ksaseg 归档段。";
    std::wstring snapshotStatus;
    std::optional<std::size_t> selected;
    bool applyingProjection = false;
    int columnProfile = -1;
    RECT graph{};
};

std::wstring WideAscii(std::string_view text) { return { text.begin(), text.end() }; }

template<typename T>
std::wstring Number(std::optional<T> value) { return value ? std::to_wstring(*value) : L"—"; }

std::wstring RecordName(const EvidenceRecord& row) {
    // ETW 源描述符独立于 CanonicalEvent 种类，沿用原记录序号定位。
    if (row.etw) {
        return L"ETW 事件 " + std::to_wstring(row.etw->eventId) + L" / v" + std::to_wstring(row.etw->version);
    }
    if (row.eventOrdinal) return L"事件 #" + std::to_wstring(*row.eventOrdinal) + L" · 种类 " +
        std::to_wstring(row.eventKind) + L" · 类别 " + std::to_wstring(row.category);
    if (row.type == 3 && row.schemaVersion == 1) return L"原始记录 #" + std::to_wstring(row.sequence);
    return L"不透明记录 #" + std::to_wstring(row.sequence) + L" · 类型 " + std::to_wstring(row.type);
}

Snapshot Load(const std::wstring& path) {
    Snapshot snapshot{ path, OpenStoredEvidence(path), {} };
    auto rows = std::make_shared<std::vector<Ui::VirtualListRow>>();
    rows->reserve(snapshot.evidence.rows.size());
    for (const auto& record : snapshot.evidence.rows) {
        Ui::VirtualListRow row;
        row.stableKey = std::to_wstring(record.sequence);
        row.itemData = static_cast<LPARAM>(rows->size());
        row.cells = { Number(record.receiveQpc), Number(record.headerPid), Number(record.headerTid), L"—",
            RecordName(record), record.etw ? WideAscii(record.etw->providerId) : Number(record.sourceDictionaryId),
            std::to_wstring(record.sequence) };
        rows->push_back(std::move(row));
    }
    snapshot.presentation = std::move(rows);
    return snapshot;
}

HWND MakeEdit(HWND owner, int id, DWORD style) {
    return ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
        0, 0, 0, 0, owner, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
}

void Layout(Page& page) {
    RECT area{};
    ::GetClientRect(page.hwnd, &area);
    const int inset = Scale(6), gap = Scale(8), height = Scale(28);
    const int right = (std::max)(inset, static_cast<int>(area.right) - inset);
    const int width = right - inset;
    const bool side = width >= Scale(900);
    const int timelineWidth = width >= Scale(640) ? Scale(178) : Scale(123);
    const int commandsWidth = side ? Scale(176) : 0;
    const int commandX = side ? right - commandsWidth : inset;
    const int mainX = inset + timelineWidth + gap;
    const int mainRight = side ? commandX - gap : right;
    const int top = inset + (side ? 0 : height + Scale(28));
    const int bottom = (std::max)(top + height + Scale(32), static_cast<int>(area.bottom) - inset - Scale(62));
    const int resultTop = top + height + gap;
    const int available = bottom - resultTop;
    const int detailHeight = available / 3;
    const int graphHeight = available >= Scale(350) ? Scale(68) : 0;
    const int graphTop = bottom - detailHeight - graphHeight;
    auto move = [](HWND hwnd, int x, int y, int w, int h) {
        ::MoveWindow(hwnd, x, y, (std::max)(1, w), (std::max)(1, h), TRUE);
    };
    ::ShowWindow(page.actions, side ? SW_SHOW : SW_HIDE);
    if (side) {
        move(page.actions, commandX, inset, commandsWidth, height);
        move(page.open, commandX, inset + height, commandsWidth, height);
        move(page.retry, commandX, inset + (height + gap) * 2 - gap, commandsWidth, height);
        move(page.capability, commandX, inset + (height + gap) * 3 - gap, commandsWidth, Scale(105));
    } else {
        move(page.open, inset, inset, Scale(106), height);
        move(page.retry, inset + Scale(114), inset, Scale(94), height);
        move(page.capability, inset, inset + height + Scale(3), width, Scale(25));
    }
    move(page.categories, inset, top, timelineWidth, height);
    const int etwWidth = Scale(102);
    const bool showFilterLabel = mainRight - mainX >= Scale(260);
    const int filterLeft = mainX + (showFilterLabel ? Scale(57) : 0);
    ::ShowWindow(page.filterLabel, showFilterLabel ? SW_SHOW : SW_HIDE);
    move(page.filterLabel, mainX, top + Scale(4), Scale(56), height - Scale(4));
    move(page.filter, filterLeft, top, mainRight - etwWidth - gap - filterLeft, height);
    move(page.etwOnly, mainRight - etwWidth, top, etwWidth, height);
    move(page.timeline.hwnd(), inset, resultTop, timelineWidth, graphTop - resultTop - gap);
    move(page.list.hwnd(), mainX, resultTop, mainRight - mainX, graphTop - resultTop - gap);
    const int tableWidth = mainRight - mainX;
    const int profile = tableWidth >= Scale(630) ? 2 : tableWidth >= Scale(390) ? 1 : 0;
    if (page.columnProfile != profile && page.list.hwnd()) {
        page.columnProfile = profile;
        const std::array widths = profile == 2 ? std::array{ 152, 66, 66, 76, 240, 168, 90 }
            : profile == 1 ? std::array{ 141, 55, 55, 57, 170, 154, 84 }
            : std::array{ 107, 45, 45, 45, 156, 154, 84 };
        for (int column = 0; column < static_cast<int>(widths.size()); ++column) {
            ListView_SetColumnWidth(page.list.hwnd(), column, Scale(widths[static_cast<std::size_t>(column)]));
        }
    }
    move(page.projection, mainX + Scale(8), resultTop + Scale(28), mainRight - mainX - Scale(16), Scale(36));
    page.graph = { inset, graphTop, right, graphTop + graphHeight };
    move(page.details, inset, graphTop + graphHeight, width, detailHeight - gap);
    move(page.status, inset, bottom, width, Scale(62));
    ::InvalidateRect(page.hwnd, nullptr, FALSE);
}

const EvidenceRecord* SelectedRecord(const Page& page) {
    if (!page.snapshot || !page.selected || *page.selected >= page.snapshot->evidence.rows.size()) return nullptr;
    return &page.snapshot->evidence.rows[*page.selected];
}

void UpdateDetails(Page& page) {
    const auto* record = SelectedRecord(page);
    std::wstring text;
    if (page.snapshot && page.snapshot->evidence.identity) {
        const auto& snapshot = *page.snapshot;
        const auto& evidence = snapshot.evidence;
        const auto& identity = *evidence.identity;
        text = L"归档：" + snapshot.path + L"\r\n项目：" + WideAscii(identity.projectId) +
            L"\r\n采样：" + WideAscii(identity.sampleId) + L"\r\n流编号：" + std::to_wstring(identity.streamKind) +
            L"    段号：" + std::to_wstring(identity.ordinal) +
            L"    段创建 FILETIME：" + std::to_wstring(evidence.createdUtc100ns) +
            L"\r\n文件身份（卷序列 / 文件索引 / 修改 FILETIME）：" +
            (evidence.fileIdentity.empty() ? L"不可用" : evidence.fileIdentity) + L"\r\n\r\n";
    }
    if (record) {
        text += RecordName(*record) + L"\r\n归档记录序号：" + std::to_wstring(record->sequence) +
            L"    块号：" + std::to_wstring(record->blockOrdinal) + L"    文件字节偏移：" + std::to_wstring(record->offset) +
            L"\r\n类型：" + std::to_wstring(record->type) + L"    格式版本：" + std::to_wstring(record->schemaVersion) +
            L"    标志：" + std::to_wstring(record->flags) + L"    负载字节：" + std::to_wstring(record->payloadBytes) + L"\r\n";
        if (record->eventOrdinal) {
            text += L"来源实例字典 ID：" + Number(record->sourceDictionaryId) + L"    来源代次字典 ID：" +
                Number(record->epochDictionaryId) + L"\r\n报头 PID：" + Number(record->headerPid) +
                L"    报头 TID：" + Number(record->headerTid) + L"\r\n引用状态：归档字段已读取，字典、跨流记录与对象尚未解析。\r\n";
        }
        text += L"\r\n" + record->preview;
    } else {
        text += page.snapshot ? L"选择一条记录查看归档字段。" : L"打开归档段后，选择一条记录查看原始证据。";
    }
    ::SetWindowTextW(page.details, text.c_str());
    ::InvalidateRect(page.hwnd, &page.graph, FALSE);
}

void UpdateStatus(Page& page) {
    std::wstring text = page.requestStatus;
    if (page.snapshot) {
        const auto& result = page.snapshot->evidence;
        if (!page.snapshotStatus.empty()) {
            if (!text.empty()) text += L"\r\n";
            text += page.snapshotStatus;
        }
        text += L"\r\n当前归档  ·  显示 " + std::to_wstring(page.list.visibleIndexes().size()) +
            L" / " + std::to_wstring(result.rows.size()) + L" 条预览  ·  帧记录 " + std::to_wstring(result.records) +
            L"  ·  帧前缀 " + std::to_wstring(result.framedBytes) + L" / " + std::to_wstring(result.fileBytes) +
            L" B  ·  解码前缀 " + std::to_wstring(result.decodedPrefixBytes) + L" B";
        if (page.selected && !std::binary_search(page.list.visibleIndexes().begin(), page.list.visibleIndexes().end(), *page.selected)) {
            text += L"  ·  已选记录被筛掉";
        }
        if (result.opaqueOptionalRecords || result.opaqueRequiredRecords) {
            text += L"  ·  不透明：可选 " + std::to_wstring(result.opaqueOptionalRecords) + L" / 必需 " +
                std::to_wstring(result.opaqueRequiredRecords);
        }
    }
    ::SetWindowTextW(page.status, text.c_str());
    const wchar_t* empty = !page.snapshot ? L"没有打开的归档" : page.snapshot->evidence.rows.empty() ?
        (page.snapshot->evidence.diagnostic.empty() ? L"此归档段没有记录" : L"已读前缀没有可显示记录") : L"没有匹配的记录";
    ::SetWindowTextW(page.projection, empty);
    ::ShowWindow(page.projection, page.list.visibleIndexes().empty() ? SW_SHOW : SW_HIDE);
}

void SetListSelection(Page& page, std::size_t record, bool reveal) {
    const auto& visible = page.list.visibleIndexes();
    const auto it = std::lower_bound(visible.begin(), visible.end(), record);
    if (it == visible.end() || *it != record) return;
    const auto position = static_cast<int>(it - visible.begin());
    ListView_SetItemState(page.list.hwnd(), position, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    if (reveal) ListView_EnsureVisible(page.list.hwnd(), position, FALSE);
}

void ApplyFilter(Page& page) {
    wchar_t query[257]{};
    ::GetWindowTextW(page.filter, query, static_cast<int>(std::size(query)));
    auto visible = Ui::VirtualListView::FilterRowIndexes(page.list.rows(), query);
    if (page.snapshot) {
        const auto& records = page.snapshot->evidence.rows;
        const bool etwOnly = page.timeline.hasEtw() && ::SendMessageW(page.etwOnly, BM_GETCHECK, 0, 0) == BST_CHECKED;
        std::erase_if(visible, [&](std::size_t i) {
            return (etwOnly && !records[i].etw) || !page.timeline.includes(records[i]);
        });
    }
    page.applyingProjection = true;
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    page.timeline.setVisible(visible);
    page.list.setVisibleIndexes(std::move(visible));
    if (page.selected) SetListSelection(page, *page.selected, false);
    page.applyingProjection = false;
    UpdateStatus(page);
}

std::wstring Diagnostic(const SegmentEvidence& result) {
    auto text = WideAscii(result.diagnostic) + L" @ " + std::to_wstring(result.failureOffset) + L" B";
    if (result.systemError) text += L" (Win32 " + std::to_wstring(result.systemError) + L")";
    return text;
}

void Open(Page& page, std::wstring path) {
    if (path.empty()) return;
    page.requestPath = std::move(path);
    ::EnableWindow(page.retry, TRUE);
    // Keep buttons and the currently focused control in place during an async read.
    // Another explicit open supersedes this request in AsyncSnapshotTask.
    page.requestStatus = L"正在读取：" + page.requestPath;
    UpdateStatus(page);
    page.task->request([path = page.requestPath] { return Load(path); },
        [&page](std::uint64_t, std::optional<Snapshot>&& loaded, std::exception_ptr error) {
            if (error || !loaded || !loaded->evidence.identity ||
                (!loaded->evidence.diagnostic.empty() && loaded->evidence.decodedPrefixBytes == 96)) {
                page.requestStatus = L"读取失败：" + (loaded ? Diagnostic(loaded->evidence) : L"后台读取失败") +
                    L" · " + page.requestPath + (page.snapshot ? L"（保留当前归档）" : L"");
                UpdateStatus(page);
                return;
            }
            auto next = std::make_shared<const Snapshot>(std::move(*loaded));
            auto previous = std::exchange(page.snapshot, std::move(next));
            page.selected.reset();
            page.timeline.replace(page.snapshot->evidence.rows);
            ::SetWindowTextW(page.categories, page.timeline.hasCategories() ? L"类别筛选…" : L"无可筛选类别");
            if (::GetFocus() == page.categories && !page.timeline.hasCategories()) ::SetFocus(page.filter);
            ::EnableWindow(page.categories, page.timeline.hasCategories());
            if (!page.timeline.hasEtw()) {
                if (::GetFocus() == page.etwOnly) ::SetFocus(page.filter);
                ::SendMessageW(page.etwOnly, BM_SETCHECK, BST_UNCHECKED, 0);
            }
            ::EnableWindow(page.etwOnly, page.timeline.hasEtw());
            page.applyingProjection = true;
            ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            page.list.setSharedRows(page.snapshot->presentation);
            if (page.list.rowCount()) ListView_EnsureVisible(page.list.hwnd(), 0, FALSE);
            page.applyingProjection = false;
            const auto& result = page.snapshot->evidence;
            if (!result.diagnostic.empty()) {
                page.snapshotStatus = (result.diagnostic == "view.scanLimit" ? L"预览范围受限：" : L"部分归档可读：") + Diagnostic(result);
            } else if (result.opaqueRequiredRecords) {
                page.snapshotStatus = L"只读归档 · 包含无法解释的必需记录";
            } else {
                page.snapshotStatus = L"只读归档 · 段内扫描完成";
            }
            page.snapshotStatus += L" · #" + std::to_wstring(result.identity->ordinal) + L" · " +
                WideAscii(result.identity->sampleId);
            page.requestStatus.clear();
            ApplyFilter(page);
            UpdateDetails(page);
            if (previous) Ui::RetireBackgroundValue(previous);
        });
}

void Browse(Page& page) {
    std::vector<wchar_t> path(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = ::GetAncestor(page.hwnd, GA_ROOT);
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrFilter = L"ActionAnalyze 归档段 (*.ksaseg)\0*.ksaseg\0所有文件\0*.*\0";
    dialog.lpstrTitle = L"打开 ActionAnalyze 归档段";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_DONTADDTORECENT;
    if (::GetOpenFileNameW(&dialog)) Open(page, path.data());
    else if (const DWORD error = ::CommDlgExtendedError()) {
        page.requestStatus = L"文件选择失败（" + std::to_wstring(error) + L"）";
        UpdateStatus(page);
    }
}

void PaintGraph(Page& page, HDC dc) {
    if (page.graph.bottom <= page.graph.top) return;
    auto& theme = Ui::AppTheme();
    ::FillRect(dc, &page.graph, theme.panelBrush());
    auto line = [&](const std::wstring& text, RECT bounds) {
        Ui::DrawTextLine(dc, text, bounds, theme.textColor, Ui::SystemUIFont(),
            DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    };
    const auto* record = SelectedRecord(page);
    const int x = page.graph.left + Scale(8), y = page.graph.top;
    line(record && record->eventOrdinal ? L"证据引用 · 归档字段 / 未解析" : L"证据引用 · 选择带引用的归档事件",
        { x, y, page.graph.right, y + Scale(24) });
    if (!record || !record->eventOrdinal) return;
    const int first = x + Scale(120);
    const int middle = y + Scale(45);
    line(L"事件 #" + Number(record->eventOrdinal), { x, y + Scale(32), first, y + Scale(58) });
    RECT stem{ first, middle, first + Scale(15), middle + 1 };
    RECT fork{ stem.right, middle - Scale(10), stem.right + 1, middle + Scale(10) + 1 };
    ::FillRect(dc, &stem, theme.accentBrush());
    ::FillRect(dc, &fork, theme.accentBrush());
    const auto node = [&](int lane, const wchar_t* type, std::optional<std::uint64_t> id) {
        if (!id) return;
        const int rowY = middle + Scale(10) * (lane == 0 ? -1 : 1);
        const int at = stem.right;
        RECT edge{ at, rowY, at + Scale(15), rowY + 1 };
        ::FillRect(dc, &edge, theme.accentBrush());
        line(std::wstring(type) + L" #" + Number(id), { at + Scale(20), rowY - Scale(10), page.graph.right, rowY + Scale(10) });
    };
    node(0, L"来源字典", record->sourceDictionaryId);
    if (record->rawSequence) node(1, L"主原始记录", record->rawSequence);
    else node(1, L"来源代次", record->epochDictionaryId);
}

LRESULT CALLBACK NavigateControls(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data) {
    if (msg == WM_KEYDOWN && wp == VK_TAB) {
        auto& page = *reinterpret_cast<Page*>(data);
        const std::array order{ page.categories, page.filter, page.etwOnly, page.timeline.hwnd(), page.list.hwnd(),
            page.open, page.retry, page.details, page.status };
        const auto found = std::find(order.begin(), order.end(), hwnd);
        const auto size = static_cast<int>(order.size());
        auto index = static_cast<int>(found - order.begin());
        const int direction = (::GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
        for (int i = 0; i < size; ++i) {
            index = (index + direction + size) % size;
            const HWND next = order[static_cast<std::size_t>(index)];
            if (::IsWindowEnabled(next) && ::IsWindowVisible(next)) { ::SetFocus(next); break; }
        }
        return 0;
    }
    if (msg == WM_CHAR && wp == L'\t') return 0;
    return ::DefSubclassProc(hwnd, msg, wp, lp);
}

bool CreateControls(Page& page) {
    page.open = Ui::CreateButton(page.hwnd, kOpen, L"打开归档段…", 0, 0, 0, 0, Ui::ButtonRole::Primary);
    page.retry = Ui::CreateButton(page.hwnd, kRetry, L"重读上次路径", 0, 0, 0, 0);
    page.actions = Ui::CreateText(page.hwnd, 0, L"归档操作", 0, 0, 0, 0);
    page.capability = Ui::CreateText(page.hwnd, 0, L"只读归档 · 支持 ETW 原始记录回放。", 0, 0, 0, 0);
    page.categories = Ui::CreateButton(page.hwnd, kCategories, L"无可筛选类别", 0, 0, 0, 0);
    page.filterLabel = Ui::CreateText(page.hwnd, 0, L"筛选记录", 0, 0, 0, 0);
    page.filter = MakeEdit(page.hwnd, kFilter, ES_AUTOHSCROLL);
    page.etwOnly = ::CreateWindowExW(0, L"BUTTON", L"只看 ETW", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEtwOnly)), ::GetModuleHandleW(nullptr), nullptr);
    if (!page.open || !page.retry || !page.actions || !page.capability || !page.categories || !page.filterLabel || !page.filter || !page.etwOnly) return false;
    ::EnableWindow(page.retry, FALSE);
    ::EnableWindow(page.categories, FALSE);
    ::EnableWindow(page.etwOnly, FALSE);
    ::SendMessageW(page.filter, EM_SETLIMITTEXT, 256, 0);
    ::SendMessageW(page.filter, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(L"筛选记录"));
    if (!page.timeline.create(page.hwnd, kTimeline, [&page](std::size_t index) {
        SetListSelection(page, index, true);
    })) return false;
    if (!page.list.create(page.hwnd, kRecords, 0, 0, 0, 0, WS_TABSTOP | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER)) return false;
    if (!page.list.addColumns({ { 0, 152, LVCFMT_LEFT, L"时间（接收 QPC）" }, { 1, 66, LVCFMT_RIGHT, L"PID" },
        { 2, 66, LVCFMT_RIGHT, L"TID" }, { 3, 76, LVCFMT_LEFT, L"进程" }, { 4, 240, LVCFMT_LEFT, L"事件 / 记录" },
        { 5, 168, LVCFMT_LEFT, L"来源" }, { 6, 90, LVCFMT_RIGHT, L"记录序号" } })) return false;
    page.projection = Ui::CreateText(page.hwnd, 0, L"", 0, 0, 0, 0);
    ::SetWindowPos(page.projection, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    page.details = MakeEdit(page.hwnd, kDetails, ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL);
    page.status = MakeEdit(page.hwnd, kStatus, ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL);
    if (!page.projection || !page.details || !page.status) return false;
    Ui::AttachTextFindSupport(page.details);
    for (HWND child : { page.categories, page.filter, page.etwOnly, page.timeline.hwnd(), page.list.hwnd(),
        page.open, page.retry, page.details, page.status }) {
        if (!::SetWindowSubclass(child, NavigateControls, 1, reinterpret_cast<DWORD_PTR>(&page))) return false;
    }
    Ui::SetWindowFontRecursive(page.hwnd);
    UpdateStatus(page);
    UpdateDetails(page);
    Layout(page);
    return true;
}

LRESULT CALLBACK PageProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* page = reinterpret_cast<Page*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        page = new Page{};
        page->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
    }
    if (!page) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_CREATE:
        page->task = std::make_unique<Ui::AsyncSnapshotTask<Snapshot>>(hwnd, kComplete);
        return CreateControls(*page) ? 0 : -1;
    case WM_SIZE:
        Layout(*page);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        const HDC dc = ::BeginPaint(hwnd, &ps);
        ::FillRect(dc, &ps.rcPaint, Ui::AppTheme().windowBrush());
        PaintGraph(*page, dc);
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_DRAWITEM:
        if (wp == kOpen) { Ui::DrawThemedButton(*reinterpret_cast<const DRAWITEMSTRUCT*>(lp)); return TRUE; }
        break;
    case WM_CTLCOLORSTATIC: {
        const auto child = reinterpret_cast<HWND>(lp);
        auto& theme = Ui::AppTheme();
        const auto dc = reinterpret_cast<HDC>(wp);
        if (child == page->details || child == page->status) {
            ::SetTextColor(dc, theme.textColor);
            ::SetBkColor(dc, theme.panelColor);
            return reinterpret_cast<LRESULT>(theme.panelBrush());
        }
        if (child == page->projection) return Ui::PaintLabelBackground(dc, child, theme.panelBrush(), theme.textColor);
        if (const LRESULT brush = Ui::PaintLabelBackground(dc, child, theme.windowBrush(), theme.textColor)) return brush;
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == kOpen && HIWORD(wp) == BN_CLICKED) Browse(*page);
        if (LOWORD(wp) == kRetry && HIWORD(wp) == BN_CLICKED) Open(*page, page->requestPath);
        if (LOWORD(wp) == kCategories && HIWORD(wp) == BN_CLICKED && page->timeline.chooseCategories(page->categories)) ApplyFilter(*page);
        if (LOWORD(wp) == kEtwOnly && HIWORD(wp) == BN_CLICKED) ApplyFilter(*page);
        if (LOWORD(wp) == kFilter && HIWORD(wp) == EN_CHANGE && page->status) ApplyFilter(*page);
        return 0;
    case WM_NOTIFY: {
        const auto& notice = *reinterpret_cast<const NMHDR*>(lp);
        LRESULT result = 0;
        if (page->list.handleNotify(notice, result)) return result;
        if (notice.idFrom == kRecords && notice.code == LVN_ITEMCHANGED && !page->applyingProjection) {
            const auto& item = *reinterpret_cast<const NMLISTVIEW*>(lp);
            if ((item.uChanged & LVIF_STATE) && (item.uNewState & LVIS_SELECTED) && item.iItem >= 0 &&
                static_cast<std::size_t>(item.iItem) < page->list.visibleIndexes().size()) {
                const auto index = page->list.visibleIndexes()[static_cast<std::size_t>(item.iItem)];
                if (page->selected != index) {
                    page->selected = index;
                    page->timeline.select(index, true);
                    UpdateDetails(*page);
                    UpdateStatus(*page);
                }
            }
        }
        break;
    }
    case kComplete: page->task->consume(hwnd, wp, lp); return 0;
    case WM_NCDESTROY:
        page->task.reset();
        if (page->snapshot) Ui::RetireBackgroundValue(page->snapshot);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete page;
        break;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}

} // namespace

HWND CreateActionAnalyzePage(HWND parent, const RECT& bounds) {
    const auto instance = reinterpret_cast<HINSTANCE>(::GetWindowLongPtrW(parent, GWLP_HINSTANCE));
    WNDCLASSW cls{};
    cls.hInstance = instance;
    cls.lpfnWndProc = PageProc;
    cls.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    cls.lpszClassName = kPageClass;
    if (!::RegisterClassW(&cls) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    return ::CreateWindowExW(WS_EX_CONTROLPARENT, kPageClass, L"ActionAnalyze", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, parent, nullptr, instance, nullptr);
}

} // namespace Ksword::Features::ActionAnalyze
