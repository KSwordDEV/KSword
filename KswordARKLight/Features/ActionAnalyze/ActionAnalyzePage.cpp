#include "ActionAnalyzePage.h"

#include "EvidenceTimeline.h"
#include "ProjectReplay.h"
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
#include <variant>

namespace Ksword::Features::ActionAnalyze {
namespace {

constexpr wchar_t kPageClass[] = L"KswordARKLight.ActionAnalyze";
constexpr UINT kComplete = WM_APP + 936;
enum ControlId {
    kOpen = 58301, kRetry, kCategories, kFilter, kTimeline, kRecords, kDetails, kStatus, kEtwOnly,
    kSampleChoice, kReplaySample, kCancelChoice, kApiOnly
};
static_assert(kApiOnly <= MAXWORD, "WM_COMMAND carries control IDs in its low word");
using Ui::Scale;

struct Snapshot {
    std::wstring path; // 已打开的段或项目清单路径。
    std::optional<ProjectReplayRequest> sample; // 项目回放选择；独立段保持为空。
    SegmentEvidence evidence; // raw 段或独立证据段的本地值快照。
    ReplayCheckpoint checkpoint; // 本次项目重读核对的段范围。
    bool hasApi = false; // 窗口中存在已核验的 API 线索。
    std::shared_ptr<const std::vector<Ui::VirtualListRow>> presentation; // 后台生成的虚拟表行。
};

using LoadResult = std::variant<Snapshot, ProjectReplayCatalog>; // 同一异步任务处理三种打开请求。

struct Page {
    HWND hwnd = nullptr;
    HWND open = nullptr;
    HWND retry = nullptr;
    HWND sampleChoice = nullptr; // 项目目录草稿的原生选择器。
    HWND replaySample = nullptr; // 显式提交所选采样。
    HWND cancelChoice = nullptr; // 只取消目录草稿。
    HWND tooltip = nullptr; // 本页新增按钮的原生释义宿主。
    HWND categories = nullptr;
    HWND filterLabel = nullptr;
    HWND filter = nullptr;
    HWND etwOnly = nullptr;
    HWND apiOnly = nullptr; // 只影响表和瀑布的来源筛选。
    HWND actions = nullptr;
    HWND capability = nullptr;
    HWND projection = nullptr;
    HWND details = nullptr;
    HWND status = nullptr;
    EvidenceTimeline timeline;
    Ui::VirtualListView list;
    std::unique_ptr<Ui::AsyncSnapshotTask<LoadResult>> task;
    std::shared_ptr<const Snapshot> snapshot;
    std::wstring requestPath;
    std::optional<ProjectReplayRequest> requestedSample; // 重读保留上次提交的完整请求。
    std::vector<ProjectReplayChoice> choices; // 只在确认前保存目录草稿。
    std::wstring requestStatus = L"打开项目清单或归档段。";
    std::wstring snapshotStatus;
    std::optional<std::size_t> selected;
    bool applyingProjection = false;
    int columnProfile = -1;
    RECT graph{};
};

std::wstring WideAscii(std::string_view text) { return { text.begin(), text.end() }; }

// 将已验证目录的 UTF-8 采样名转成供 Win32 控件使用的文本。
std::wstring WideTitle(const std::string& text) {
    const int length = static_cast<int>(text.size()); // 项目层已限制标题字节数。
    const int chars = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
    if (chars <= 0) return {};
    std::wstring result(static_cast<std::size_t>(chars), L'\0'); // 原样保留 Unicode 名称。
    ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, result.data(), chars);
    return result;
}

template<typename T>
std::wstring Number(std::optional<T> value) { return value ? std::to_wstring(*value) : L"—"; }

std::wstring RecordName(const EvidenceRecord& row) {
    if (!row.apiClue.empty()) return row.apiClue; // 显示通过尾记校验的 API 导出名。
    // ETW 源描述符独立于 CanonicalEvent 种类，沿用原记录序号定位。
    if (row.etw) {
        return L"ETW 事件 " + std::to_wstring(row.etw->eventId) + L" / v" + std::to_wstring(row.etw->version);
    }
    if (row.eventOrdinal) return L"事件 #" + std::to_wstring(*row.eventOrdinal) + L" · 种类 " +
        std::to_wstring(row.eventKind) + L" · 类别 " + std::to_wstring(row.category);
    if (row.type == 3 && row.schemaVersion == 1) return L"原始记录 #" + std::to_wstring(row.sequence);
    return L"不透明记录 #" + std::to_wstring(row.sequence) + L" · 类型 " + std::to_wstring(row.type);
}

// 在后台读取目录或具体段，根据冻结采样请求启用项目检查点核验。
LoadResult Load(const std::wstring& path, const std::optional<ProjectReplayRequest>& sample) {
    if (!sample && IsProjectReplayManifest(path)) return ReadProjectReplayCatalog(path);

    Snapshot snapshot; // 只有完成后台工作后才由 UI 决定是否发布。
    snapshot.path = path;
    snapshot.sample = sample;
    if (sample) {
        auto replay = ReadProjectReplay(*sample); // 使用与正式 CLI 共用的双流验证。
        snapshot.evidence = std::move(replay.raw);
        snapshot.checkpoint = replay.checkpoint;
    } else {
        snapshot.evidence = OpenStoredEvidence(path);
    }

    // 保持单段与项目回放的行结构一致，现有筛选、时间线及详情共享它。
    auto rows = std::make_shared<std::vector<Ui::VirtualListRow>>(); // 表格的后台值数据。
    rows->reserve(snapshot.evidence.rows.size());
    for (const auto& record : snapshot.evidence.rows) {
        snapshot.hasApi |= !record.apiClue.empty();
        Ui::VirtualListRow row; // 项目已验证的记录序号在整次采样内唯一。
        row.stableKey = std::to_wstring(record.sequence);
        row.itemData = static_cast<LPARAM>(rows->size());
        row.cells = { Number(record.receiveQpc), Number(record.headerPid), Number(record.headerTid), L"—",
            RecordName(record), !record.apiFamily.empty() ? record.apiFamily :
                record.etw ? WideAscii(record.etw->providerId) : Number(record.sourceDictionaryId),
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
    const int toolbarTop = inset + (side ? 0 : height + Scale(28)); // 原工作台工具行位置。
    const int choiceButtonWidth = Scale(98);
    const int choiceButtonsWidth = 2 * choiceButtonWidth + gap;
    const bool stackedChoice = mainRight - mainX < Scale(300) + choiceButtonsWidth + gap;
    const int choiceHeight = page.choices.empty() ? 0 : (stackedChoice ? 2 : 1) * (height + gap);
    const int top = toolbarTop + choiceHeight; // 样本草稿仅占用表格上方自然高度。
    const int sourceWidth = Scale(93); // 同列来源开关按成组宽度换行。
    const bool wrapSources = mainRight - mainX < sourceWidth * 2 + gap * 2 + Scale(125);
    const int resultTop = top + (wrapSources ? 2 : 1) * (height + gap);
    const int bottom = (std::max)(resultTop + Scale(24), static_cast<int>(area.bottom) - inset - Scale(62));
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
    // 草稿和确认动作独立于现有列表，横向空间不足时按钮换行。
    const int choiceLeft = stackedChoice ? inset : mainX;
    const int choiceButtonsX = mainRight - choiceButtonsWidth;
    const int choiceButtonsY = toolbarTop + (stackedChoice ? height + gap : 0);
    const int choiceRight = stackedChoice ? mainRight : choiceButtonsX - gap;
    move(page.sampleChoice, choiceLeft, toolbarTop, choiceRight - choiceLeft, height * 9);
    move(page.replaySample, choiceButtonsX, choiceButtonsY, choiceButtonWidth, height);
    move(page.cancelChoice, choiceButtonsX + choiceButtonWidth + gap, choiceButtonsY, choiceButtonWidth, height);
    move(page.categories, inset, top, timelineWidth, height);
    const int sourceX = wrapSources ? mainX : mainRight - sourceWidth * 2 - gap; // 窄窗时开关占独立一行。
    const int sourceY = wrapSources ? top + height + gap : top;
    const int filterRight = wrapSources ? mainRight : sourceX - gap;
    const bool showFilterLabel = filterRight - mainX >= Scale(180);
    const int filterLeft = mainX + (showFilterLabel ? Scale(57) : 0);
    ::ShowWindow(page.filterLabel, showFilterLabel ? SW_SHOW : SW_HIDE);
    move(page.filterLabel, mainX, top + Scale(4), Scale(56), height - Scale(4));
    move(page.filter, filterLeft, top, filterRight - filterLeft, height);
    move(page.apiOnly, sourceX, sourceY, sourceWidth, height);
    move(page.etwOnly, sourceX + sourceWidth + gap, sourceY, sourceWidth, height);
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
        text = (snapshot.sample ? L"清单：" : L"归档：") + snapshot.path + L"\r\n项目：" + WideAscii(identity.projectId) +
            L"\r\n采样：" + WideAscii(identity.sampleId) + L"\r\n流编号：" + std::to_wstring(identity.streamKind);
        // 多段采样的文件标识属于最新段，不用它描述选中的历史行。
        if (snapshot.checkpoint.lastVerifiedOrdinal <= 1) {
            text += L"    段号：" + std::to_wstring(identity.ordinal) +
                L"    段创建 FILETIME：" + std::to_wstring(evidence.createdUtc100ns) +
                L"\r\n文件身份（卷序列 / 文件索引 / 修改 FILETIME）：" +
                (evidence.fileIdentity.empty() ? L"不可用" : evidence.fileIdentity);
        }
        text += L"\r\n\r\n";
    }
    if (record) {
        text += RecordName(*record) + L"\r\n归档记录序号：" + std::to_wstring(record->sequence) +
            L"    所属段号：" + std::to_wstring(record->segmentOrdinal) + L"    块号：" +
            std::to_wstring(record->blockOrdinal) + L"    文件字节偏移：" + std::to_wstring(record->offset) +
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
        const auto ordinal = page.snapshot->checkpoint.lastVerifiedOrdinal; // 字节范围对应的已验证段。
        text += L"\r\n当前归档  ·  显示 " + std::to_wstring(page.list.visibleIndexes().size()) +
            L" / " + std::to_wstring(result.rows.size()) + L" 条预览";
        if (ordinal > 1) {
            text += L"  ·  已核验 " + std::to_wstring(result.lastSequence.value_or(0)) + L" 条  ·  第 " +
                std::to_wstring(ordinal) + L" 段";
        }
        text += L"  ·  帧记录 " + std::to_wstring(result.records) +
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
        const bool apiOnly = page.snapshot->hasApi && ::SendMessageW(page.apiOnly, BM_GETCHECK, 0, 0) == BST_CHECKED;
        std::erase_if(visible, [&](std::size_t i) {
            const auto& row = records[i]; // 同时选中 API、ETW 时取两类来源的并集。
            const bool sourceMatch = (!apiOnly && !etwOnly) || (apiOnly && !row.apiClue.empty()) || (etwOnly && row.etw);
            return !sourceMatch || !page.timeline.includes(row);
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

// 清空目录草稿，并在隐藏当前焦点控件前退回打开按钮。
void ClearChoices(Page& page) {
    if (page.choices.empty()) return;
    const HWND focus = ::GetFocus(); // 页内当前键盘焦点。
    if (focus == page.sampleChoice || focus == page.replaySample || focus == page.cancelChoice) {
        ::SetFocus(page.open);
    }
    for (HWND control : {page.sampleChoice, page.replaySample, page.cancelChoice}) {
        ::ShowWindow(control, SW_HIDE);
    }
    ::SendMessageW(page.sampleChoice, CB_RESETCONTENT, 0, 0);
    page.choices.clear();
    Layout(page);
}

// 显示读取失败及原请求，当前证据表和已选详情仍属于上次成功发布。
void ShowReadFailure(Page& page, const std::wstring& detail) {
    page.requestStatus = L"读取失败：" + detail + L" · " + page.requestPath;
    if (page.requestedSample) page.requestStatus += L" · " + WideAscii(page.requestedSample->sampleId);
    if (page.snapshot) page.requestStatus += L"（保留当前归档）";
    UpdateStatus(page);
}

// 将已提交的目录行交给选择器，明确确认前不触碰当前归档结果。
void PresentCatalog(Page& page, ProjectReplayCatalog catalog) {
    if (!catalog.diagnostic.empty()) {
        auto failure = WideAscii(catalog.diagnostic); // 共用只读目录的失败原因。
        if (catalog.systemError) failure += L" (Win32 " + std::to_wstring(catalog.systemError) + L")";
        ShowReadFailure(page, failure);
        return;
    }
    page.requestStatus = catalog.recoveredPrevious ? L"已读取上次有效项目目录。" : L"已读取项目目录。";
    if (catalog.choices.empty()) {
        page.requestStatus += L" 项目尚无已登记采样。";
        UpdateStatus(page);
        return;
    }

    // 标题可能重复或过长，列表先显示 UUID，再显示目录里的原始标题。
    page.choices = std::move(catalog.choices);
    for (const auto& choice : page.choices) {
        const auto label = WideAscii(choice.request.sampleId) + L" · " + WideTitle(choice.title);
        const auto index = ::SendMessageW(page.sampleChoice, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
        if (index == CB_ERR || index == CB_ERRSPACE) {
            ClearChoices(page);
            ShowReadFailure(page, L"无法显示采样目录");
            return;
        }
    }
    ::EnableWindow(page.replaySample, FALSE); // 需要明确选中一行。
    Layout(page);
    for (HWND control : {page.sampleChoice, page.replaySample, page.cancelChoice}) {
        ::ShowWindow(control, SW_SHOW);
    }
    page.requestStatus += L" 选择采样后点击回放。";
    UpdateStatus(page);
}

// 发布一份成功的加载结果。同一归档重读按记录序号保留原选择。
void PublishSnapshot(Page& page, Snapshot loaded) {
    if (!loaded.checkpoint.lastVerifiedOrdinal && loaded.checkpoint.state == CheckpointState::Pending) {
        page.requestStatus = L"等待第 1 段检查点发布，可重读。";
        UpdateStatus(page);
        return;
    }
    if (!loaded.evidence.identity || (!loaded.evidence.diagnostic.empty() && loaded.evidence.rows.empty())) {
        ShowReadFailure(page, Diagnostic(loaded.evidence));
        return;
    }
    const auto* selected = SelectedRecord(page); // 当前表中实际选中的旧记录。
    std::optional<std::size_t> selection; // 同一证据中的新行索引。
    if (selected && page.snapshot->path == loaded.path && page.snapshot->sample == loaded.sample &&
        page.snapshot->evidence.identity == loaded.evidence.identity) {
        const auto& rows = loaded.evidence.rows; // 新完成的证据快照。
        const auto found = std::find_if(rows.begin(), rows.end(), [selected](const auto& row) {
            return row.segmentOrdinal == selected->segmentOrdinal && row.sequence == selected->sequence;
        });
        if (found != rows.end()) selection = static_cast<std::size_t>(found - rows.begin());
    }

    // 替换既有时间线和虚拟列表，再按现有筛选重算可见行。
    auto next = std::make_shared<const Snapshot>(std::move(loaded)); // 将发布的数据固化为共享值。
    auto previous = std::exchange(page.snapshot, std::move(next)); // 旧大快照交给后台释放。
    page.selected = selection;
    page.timeline.replace(page.snapshot->evidence.rows);
    page.timeline.select(page.selected, false);
    ::SetWindowTextW(page.categories, page.timeline.hasCategories() ? L"类别筛选…" : L"无可筛选类别");
    if (::GetFocus() == page.categories && !page.timeline.hasCategories()) ::SetFocus(page.filter);
    ::EnableWindow(page.categories, page.timeline.hasCategories());
    if (!page.timeline.hasEtw()) {
        if (::GetFocus() == page.etwOnly) ::SetFocus(page.filter);
        ::SendMessageW(page.etwOnly, BM_SETCHECK, BST_UNCHECKED, 0);
    }
    ::EnableWindow(page.etwOnly, page.timeline.hasEtw());
    if (!page.snapshot->hasApi) {
        if (::GetFocus() == page.apiOnly) ::SetFocus(page.filter);
        ::SendMessageW(page.apiOnly, BM_SETCHECK, BST_UNCHECKED, 0);
    }
    ::EnableWindow(page.apiOnly, page.snapshot->hasApi);
    page.applyingProjection = true;
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    page.list.setSharedRows(page.snapshot->presentation);
    if (page.list.rowCount() && !page.selected) ListView_EnsureVisible(page.list.hwnd(), 0, FALSE);
    page.applyingProjection = false;

    // 分别显示项目提交状态、诊断预览和独立段的扫描状态。
    const auto& result = page.snapshot->evidence;
    const auto& checkpoint = page.snapshot->checkpoint; // 最新段的检查点和后续归档状态。
    if (checkpoint.state == CheckpointState::Verified) {
        page.snapshotStatus = L"终态检查点已验证 · records/" + std::to_wstring(checkpoint.lastVerifiedOrdinal) +
            L" " + std::to_wstring(checkpoint.recordsEnd) + L" B";
        if (result.fileBytes > result.decodedPrefixBytes) page.snapshotStatus += L" · raw 尾部未纳入";
    } else if (checkpoint.state == CheckpointState::Pending || checkpoint.state == CheckpointState::Partial) {
        page.snapshotStatus = L"已核验至第 " + std::to_wstring(checkpoint.lastVerifiedOrdinal) + L" 段 · 第 " +
            std::to_wstring(checkpoint.pendingOrdinal) +
            (checkpoint.state == CheckpointState::Pending ? L" 段检查点尚未发布" : L" 段核验失败 · " + Diagnostic(result));
    } else if (checkpoint.state == CheckpointState::NotPublished) {
        page.snapshotStatus = L"未发布终态检查点 · 仅查看 raw 段";
        if (!result.diagnostic.empty()) page.snapshotStatus += L" · " + Diagnostic(result);
    } else if (!result.diagnostic.empty()) {
        page.snapshotStatus = (result.diagnostic == "view.scanLimit" ? L"预览范围受限：" : L"部分归档可读：") + Diagnostic(result);
    } else {
        page.snapshotStatus = result.opaqueRequiredRecords ? L"只读归档 · 包含无法解释的必需记录" : L"只读归档 · 段内扫描完成";
    }
    page.snapshotStatus += L" · #" + std::to_wstring(result.identity->ordinal) + L" · " + WideAscii(result.identity->sampleId);
    page.requestStatus.clear();
    ApplyFilter(page);
    UpdateDetails(page);
    if (previous) Ui::RetireBackgroundValue(previous);
}

// 在原异步任务提交冻结的文件或样本请求。新请求代次取代在途旧回执。
void Open(Page& page, std::wstring path, std::optional<ProjectReplayRequest> sample = std::nullopt) {
    if (path.empty()) return;
    ClearChoices(page);
    page.requestPath = std::move(path);
    page.requestedSample = std::move(sample);
    ::EnableWindow(page.retry, TRUE);
    page.requestStatus = L"正在读取：" + page.requestPath;
    if (page.requestedSample) page.requestStatus += L" · " + WideAscii(page.requestedSample->sampleId);
    UpdateStatus(page);
    page.task->request([path = page.requestPath, request = page.requestedSample] { return Load(path, request); },
        [&page](std::uint64_t, std::optional<LoadResult>&& loaded, std::exception_ptr error) {
            if (error || !loaded) {
                ShowReadFailure(page, L"后台读取失败");
            } else if (auto* catalog = std::get_if<ProjectReplayCatalog>(&*loaded)) {
                PresentCatalog(page, std::move(*catalog));
            } else {
                PublishSnapshot(page, std::get<Snapshot>(std::move(*loaded)));
            }
        });
}

// 原打开入口同时接受项目清单或独立归档段。取消系统选择器不发请求。
void Browse(Page& page) {
    std::vector<wchar_t> path(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = ::GetAncestor(page.hwnd, GA_ROOT);
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrFilter = L"ActionAnalyze 项目或归档段\0project.ksaproj;*.ksaseg\0所有文件\0*.*\0";
    dialog.lpstrTitle = L"打开 ActionAnalyze 归档";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_DONTADDTORECENT;
    if (::GetOpenFileNameW(&dialog)) Open(page, path.data());
    else if (const DWORD error = ::CommDlgExtendedError()) {
        page.requestStatus = L"文件选择失败（" + std::to_wstring(error) + L"）";
        UpdateStatus(page);
    }
}

// 控件选择只更新提交按钮的状态。用户确认后才冻结目录行并发起读取。
void ReplaySelectedSample(Page& page) {
    const auto selected = ::SendMessageW(page.sampleChoice, CB_GETCURSEL, 0, 0); // 草稿中的采样索引。
    if (selected < 0 || static_cast<std::size_t>(selected) >= page.choices.size()) return;
    auto request = page.choices[static_cast<std::size_t>(selected)].request; // 不引用将被清空的草稿。
    const auto path = request.manifestPath; // 已冻结的清单路径，用于重读。
    Open(page, path, std::move(request));
}

// 原生工具提示跟随页内动作，不改变键盘或鼠标的焦点顺序。
void AddButtonTip(HWND tooltip, HWND page, HWND button, const wchar_t* title) {
    if (!tooltip) return;
    TOOLINFOW item{}; // 控件句柄作为悬停提示的身份。
    item.cbSize = sizeof(item);
    item.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    item.hwnd = page;
    item.uId = reinterpret_cast<UINT_PTR>(button);
    item.lpszText = const_cast<LPWSTR>(title); // 文本字面量与页面生命周期无关。
    ::SendMessageW(tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&item));
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
        const std::array order{ page.categories, page.filter, page.apiOnly, page.etwOnly, page.timeline.hwnd(), page.list.hwnd(),
            page.open, page.retry, page.sampleChoice, page.replaySample, page.cancelChoice, page.details, page.status };
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
    page.open = Ui::CreateButton(page.hwnd, kOpen, L"打开归档…", 0, 0, 0, 0, Ui::ButtonRole::Primary);
    page.retry = Ui::CreateButton(page.hwnd, kRetry, L"重读上次路径", 0, 0, 0, 0);
    page.actions = Ui::CreateText(page.hwnd, 0, L"归档操作", 0, 0, 0, 0);
    page.capability = Ui::CreateText(page.hwnd, 0, L"只读归档 · 支持 API 线索和 ETW 回放。", 0, 0, 0, 0);
    page.categories = Ui::CreateButton(page.hwnd, kCategories, L"无可筛选类别", 0, 0, 0, 0);
    page.filterLabel = Ui::CreateText(page.hwnd, 0, L"筛选记录", 0, 0, 0, 0);
    page.filter = MakeEdit(page.hwnd, kFilter, ES_AUTOHSCROLL);
    page.etwOnly = ::CreateWindowExW(0, L"BUTTON", L"只看 ETW", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEtwOnly)), ::GetModuleHandleW(nullptr), nullptr);
    page.apiOnly = ::CreateWindowExW(0, L"BUTTON", L"只看 API", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kApiOnly)), ::GetModuleHandleW(nullptr), nullptr);
    if (!page.open || !page.retry || !page.actions || !page.capability || !page.categories || !page.filterLabel ||
        !page.filter || !page.etwOnly || !page.apiOnly) return false;
    ::EnableWindow(page.retry, FALSE);
    ::EnableWindow(page.categories, FALSE);
    ::EnableWindow(page.etwOnly, FALSE);
    ::EnableWindow(page.apiOnly, FALSE);
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

    // 采样选择器只在收到已提交目录后显示，原工作台仍可查看当前证据。
    page.sampleChoice = ::CreateWindowExW(0, WC_COMBOBOXW, L"采样",
        WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSampleChoice)),
        ::GetModuleHandleW(nullptr), nullptr);
    page.replaySample = Ui::CreateButton(page.hwnd, kReplaySample, L"回放采样", 0, 0, 0, 0, Ui::ButtonRole::Primary);
    page.cancelChoice = Ui::CreateButton(page.hwnd, kCancelChoice, L"取消选择", 0, 0, 0, 0);
    if (!page.sampleChoice || !page.replaySample || !page.cancelChoice) return false;
    ::ShowWindow(page.replaySample, SW_HIDE);
    ::ShowWindow(page.cancelChoice, SW_HIDE);

    // 保留原生按钮的文字，并提供清单、段与重读范围的悬停说明。
    page.tooltip = ::CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, page.hwnd, nullptr,
        ::GetModuleHandleW(nullptr), nullptr);
    AddButtonTip(page.tooltip, page.hwnd, page.open, L"打开只读项目清单或独立归档段");
    AddButtonTip(page.tooltip, page.hwnd, page.retry, L"按上次请求的路径和采样身份重读");
    AddButtonTip(page.tooltip, page.hwnd, page.replaySample, L"只读回放当前选中的采样");
    AddButtonTip(page.tooltip, page.hwnd, page.cancelChoice, L"关闭当前采样选择并保留正在查看的归档");
    AddButtonTip(page.tooltip, page.hwnd, page.apiOnly, L"筛选 API 线索。与 ETW 同选时显示两类来源。");
    AddButtonTip(page.tooltip, page.hwnd, page.etwOnly, L"筛选 ETW 观察。与 API 同选时显示两类来源。");
    for (HWND child : { page.categories, page.filter, page.apiOnly, page.etwOnly, page.timeline.hwnd(), page.list.hwnd(),
        page.open, page.retry, page.sampleChoice, page.replaySample, page.cancelChoice, page.details, page.status }) {
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
        page->task = std::make_unique<Ui::AsyncSnapshotTask<LoadResult>>(hwnd, kComplete);
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
        if (wp == kOpen || wp == kReplaySample) {
            Ui::DrawThemedButton(*reinterpret_cast<const DRAWITEMSTRUCT*>(lp));
            return TRUE;
        }
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
        if (LOWORD(wp) == kRetry && HIWORD(wp) == BN_CLICKED) Open(*page, page->requestPath, page->requestedSample);
        // 目录下拉变化仅改变草稿。显式回放和取消都沿用本页状态区回执。
        if (LOWORD(wp) == kSampleChoice && HIWORD(wp) == CBN_SELCHANGE) {
            const auto index = ::SendMessageW(page->sampleChoice, CB_GETCURSEL, 0, 0); // 当前草稿行。
            ::EnableWindow(page->replaySample, index >= 0 && static_cast<std::size_t>(index) < page->choices.size());
        }
        if (LOWORD(wp) == kReplaySample && HIWORD(wp) == BN_CLICKED) ReplaySelectedSample(*page);
        if (LOWORD(wp) == kCancelChoice && HIWORD(wp) == BN_CLICKED) {
            ClearChoices(*page);
            page->requestStatus = L"已取消选择采样。";
            UpdateStatus(*page);
        }
        if (LOWORD(wp) == kCategories && HIWORD(wp) == BN_CLICKED && page->timeline.chooseCategories(page->categories)) ApplyFilter(*page);
        if ((LOWORD(wp) == kEtwOnly || LOWORD(wp) == kApiOnly) && HIWORD(wp) == BN_CLICKED) ApplyFilter(*page);
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
