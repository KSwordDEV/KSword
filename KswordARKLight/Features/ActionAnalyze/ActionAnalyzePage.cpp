#include "ActionAnalyzePage.h"

#include "EvidenceTimeline.h"
#include "NativeLiveSession.h"
#include "NetworkReplayPresentation.h"
#include "ProjectReplay.h"
#include "StoredEvidence.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commdlg.h>
#include <objbase.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <iterator>
#include <map>
#include <string_view>
#include <variant>

namespace Ksword::Features::ActionAnalyze {
namespace {

constexpr wchar_t kPageClass[] = L"KswordARKLight.ActionAnalyze";
constexpr UINT kComplete = WM_APP + 936;
constexpr UINT_PTR kLiveDisplayTimer = 1;
constexpr UINT kLiveDisplayIntervalMs = 400;
enum ControlId {
    kOpen = 58301, kRetry, kCategories, kFilter, kTimeline, kRecords, kDetails, kStatus, kEtwOnly,
    kSampleChoice, kReplaySample, kCancelChoice, kApiOnly, kNetworkOnly,
    kSwitchView, kLivePid, kLiveProvider, kReservedLiveArchive, kLiveStart, kLiveStop, kLiveFollow, kCreateProject,
    kEvidenceFamily, kLocateEvidence
};
static_assert(kLocateEvidence <= MAXWORD, "WM_COMMAND carries control IDs in its low word");
using Ui::Scale;

struct ApiFamilyGroup {
    std::size_t count = 0;
    std::size_t latest = 0; // 只在拥有此分组的不可变快照中解释行索引。
};

using ApiFamilyGroups = std::map<std::wstring, ApiFamilyGroup>;

struct Snapshot {
    std::wstring path; // 已打开的段或项目清单路径。
    std::optional<ProjectReplayRequest> sample; // 项目回放选择；独立段保持为空。
    SegmentEvidence evidence; // raw 段或独立证据段的本地值快照。
    ReplayCheckpoint checkpoint; // 本次项目重读核对的段范围。
    ApiFamilyGroups apiFamilies; // 已通过 API 导入尾记核验且处在当前预览窗口内的记录。
    bool hasNetwork = false; // 窗口中存在已核验的网络流。
    std::wstring classification; // 当前回放窗口的 API 分类与证据覆盖。
    std::shared_ptr<const std::vector<Ui::VirtualListRow>> presentation; // 后台生成的虚拟表行。
};

using LoadResult = std::variant<Snapshot, ProjectReplayCatalog>; // 同一异步任务处理三种打开请求。

struct Page {
    HWND hwnd = nullptr;
    HWND open = nullptr;
    HWND createProject = nullptr;
    HWND retry = nullptr;
    HWND switchView = nullptr;
    HWND livePid = nullptr;
    HWND liveProvider = nullptr;
    HWND liveStart = nullptr;
    HWND liveStop = nullptr;
    HWND liveFollow = nullptr;
    HWND sampleChoice = nullptr; // 项目目录草稿的原生选择器。
    HWND replaySample = nullptr; // 显式提交所选采样。
    HWND cancelChoice = nullptr; // 只取消目录草稿。
    HWND tooltip = nullptr; // 本页新增按钮的原生释义宿主。
    HWND categories = nullptr;
    HWND filterLabel = nullptr;
    HWND filter = nullptr;
    HWND etwOnly = nullptr;
    HWND apiOnly = nullptr; // 只影响表和瀑布的来源筛选。
    HWND networkOnly = nullptr; // 限定网络流，和其他已选来源取并集。
    HWND evidenceFamilyLabel = nullptr;
    HWND evidenceFamily = nullptr;
    HWND locateEvidence = nullptr;
    HWND actions = nullptr;
    HWND capability = nullptr;
    HWND projection = nullptr;
    HWND details = nullptr;
    HWND status = nullptr;
    EvidenceTimeline timeline;
    Ui::VirtualListView list;
    std::unique_ptr<Ui::AsyncSnapshotTask<LoadResult>> task;
    std::shared_ptr<const Snapshot> snapshot;
    std::shared_ptr<const Snapshot> samplePreview;
    std::optional<ProjectReplayRequest> previewRequest;
    NativeLiveSession live;
    NativeLiveSnapshot liveStatus;
    std::optional<NativeLiveProjection> liveProjection;
    std::wstring requestPath;
    std::optional<ProjectReplayRequest> requestedSample; // 重读保留上次提交的完整请求。
    std::optional<NativeLiveProject> project;
    std::vector<ProjectReplayChoice> choices; // 只在确认前保存目录草稿。
    std::wstring requestStatus = L"新建或打开工程后，可以查看已有采样或开始新一轮扫描。";
    std::wstring snapshotStatus;
    std::wstring liveInputError;
    std::wstring displayedStatus;
    std::wstring displayedEmpty;
    std::wstring displayedDetails;
    std::optional<std::size_t> selected;
    std::optional<std::size_t> historySelection, previewSelection, liveSelection;
    std::optional<SegmentIdentity> evidenceFamilyScope;
    std::wstring evidenceFamilyPath;
    std::wstring evidenceFamilyChoice; // 分类草稿用稳定类别值保存，不用控件下标。
    std::wstring historyFilter, liveFilter;
    bool historyEtwOnly = false, liveEtwOnly = false;
    bool liveView = false;
    bool followLive = true;
    bool liveStopRequested = false;
    bool catalogRefreshPending = false;
    bool retiring = false;
    bool catalogBusy = false;
    bool applyingProjection = false;
    int columnProfile = -1;
    RECT graph{};
};

const Snapshot* DisplayedArchive(const Page& page) {
    return page.samplePreview ? page.samplePreview.get() : page.snapshot.get();
}

const Snapshot* ClassifiedArchive(const Page& page) {
    const auto* archive = page.liveView ? nullptr : DisplayedArchive(page);
    return archive && !archive->apiFamilies.empty() ? archive : nullptr;
}

constexpr wchar_t kRelationshipCoverage[] = L"证据关系 · 当前回放未核验进程／线程关系及执行链。";

const SegmentEvidence* DisplayedEvidence(const Page& page) {
    if (page.liveView) return page.liveProjection ? &page.liveProjection->evidence : nullptr;
    const auto* archive = DisplayedArchive(page);
    return archive ? &archive->evidence : nullptr;
}

bool Checked(HWND button) { return ::SendMessageW(button, BM_GETCHECK, 0, 0) == BST_CHECKED; }

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
    if (row.network) {
        return NetworkReplaySummary(*row.network);
    }
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

std::wstring ApiFamilyLabel(std::wstring_view family) {
    if (family == L"memory-write") return L"内存写入";
    if (family == L"thread-create") return L"线程创建";
    if (family == L"apc-queue") return L"APC 入队";
    if (family == L"thread-context") return L"线程上下文";
    if (family == L"section-map") return L"节映射";
    return std::wstring(family);
}

std::wstring ClassificationSummary(const ApiFamilyGroups& families, std::uint64_t verifiedApiClues) {
    if (families.empty()) return L"敏感 API 分类：此预览窗口无已核验线索。";
    std::wstring summary = L"敏感 API 分类（当前预览窗口）：";
    std::size_t shown = 0;
    for (const auto& [family, group] : families) {
        if (shown) summary += L" / ";
        summary += ApiFamilyLabel(family) + L" " + std::to_wstring(group.count);
        shown += group.count;
    }
    if (verifiedApiClues > shown) summary += L" · 导入段共 " + std::to_wstring(verifiedApiClues) + L" 条已核验线索";
    return summary;
}

// 根据冻结采样请求启用项目检查点核验。
Snapshot Load(const std::wstring& path, const std::optional<ProjectReplayRequest>& sample,
    ProjectReplayMode mode = ProjectReplayMode::Explicit) {
    Snapshot snapshot; // 只有完成后台工作后才由 UI 决定是否发布。
    snapshot.path = path;
    snapshot.sample = sample;
    if (sample) {
        auto replay = ReadProjectReplay(*sample, mode); // 使用与正式 CLI 共用的双流验证。
        snapshot.evidence = std::move(replay.raw);
        snapshot.checkpoint = replay.checkpoint;
    } else {
        snapshot.evidence = OpenStoredEvidence(path);
    }

    // 保持单段与项目回放的行结构一致，现有筛选、时间线及详情共享它。
    auto rows = std::make_shared<std::vector<Ui::VirtualListRow>>(); // 表格的后台值数据。
    rows->reserve(snapshot.evidence.rows.size());
    for (const auto& record : snapshot.evidence.rows) {
        if (snapshot.evidence.apiClues && !record.apiClue.empty() && !record.apiFamily.empty()) {
            auto& group = snapshot.apiFamilies[record.apiFamily];
            ++group.count;
            group.latest = rows->size(); // API raw 行按已核验的归档序号递增。
        }
        snapshot.hasNetwork |= record.network.has_value();
        Ui::VirtualListRow row; // 项目已验证的记录序号在整次采样内唯一。
        row.stableKey = std::to_wstring(record.sequence);
        row.itemData = static_cast<LPARAM>(rows->size());
        const auto pid = record.network ? std::to_wstring(record.network->flow.observation.processId) : Number(record.headerPid);
        row.cells = { Number(record.receiveQpc), pid, Number(record.headerTid), L"—",
            RecordName(record), !record.apiFamily.empty() ? ApiFamilyLabel(record.apiFamily) + L" · " + record.apiFamily :
                record.network ? L"网络 · " + WideAscii(record.network->source.sourceId) :
                record.etw ? WideAscii(record.etw->providerId) : Number(record.sourceDictionaryId),
            std::to_wstring(record.sequence) };
        rows->push_back(std::move(row));
    }
    snapshot.classification = ClassificationSummary(snapshot.apiFamilies, snapshot.evidence.apiClues);
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
    const bool side = !page.liveView && width >= Scale(900);
    const int timelineWidth = width >= Scale(640) ? Scale(178) : Scale(123);
    const int commandsWidth = side ? Scale(176) : 0;
    const int commandX = side ? right - commandsWidth : inset;
    const int mainX = inset + timelineWidth + gap;
    const int mainRight = side ? commandX - gap : right;
    const int controlStep = height + gap;
    const int switchWidth = Scale(108);
    const int pidWidth = Scale(110), providerMin = Scale(152), actionWidth = Scale(110);
    const bool liveSingleRow = width >= switchWidth + pidWidth + providerMin + 3 * actionWidth + 5 * gap;
    const bool liveWrapInputs = width < switchWidth + pidWidth + providerMin + 2 * gap;
    const int liveToolbarRows = liveSingleRow ? 1 : liveWrapInputs ? 3 : 2;
    const int toolbarTop = inset + (page.liveView ? liveToolbarRows * controlStep :
        side ? 0 : height + Scale(28));
    const int choiceButtonWidth = Scale(98);
    const int choiceButtonsWidth = 2 * choiceButtonWidth + gap;
    const bool stackedChoice = mainRight - mainX < Scale(300) + choiceButtonsWidth + gap;
    const int choiceHeight = page.liveView || page.choices.empty() ? 0 : (stackedChoice ? 2 : 1) * controlStep;
    const int top = toolbarTop + choiceHeight; // 样本草稿仅占用表格上方自然高度。
    const int sourceWidth = Scale(88); // 三个来源开关保持同宽，对齐为一组。
    const int sourcesWidth = page.liveView ? sourceWidth : sourceWidth * 3 + gap * 2;
    const bool wrapSources = mainRight - mainX < sourcesWidth + gap + Scale(125);
    const bool showEvidenceNavigation = ClassifiedArchive(page) != nullptr;
    const int evidenceTop = top + (wrapSources ? 2 : 1) * controlStep;
    const int resultTop = evidenceTop + (showEvidenceNavigation ? controlStep : 0);
    const int bottom = (std::max)(resultTop + Scale(24), static_cast<int>(area.bottom) - inset - Scale(62));
    const int available = bottom - resultTop;
    const int detailHeight = available / 3;
    const int graphHeight = !page.liveView && available >= Scale(350) ? Scale(68) : 0;
    const int graphTop = bottom - detailHeight - graphHeight;
    auto move = [](HWND hwnd, int x, int y, int w, int h) {
        ::MoveWindow(hwnd, x, y, (std::max)(1, w), (std::max)(1, h), TRUE);
    };
    ::ShowWindow(page.actions, side ? SW_SHOW : SW_HIDE);
    if (page.liveView) {
        move(page.switchView, inset, inset, switchWidth, height);
        const int pidX = inset + switchWidth + gap;
        move(page.livePid, pidX, inset, pidWidth, height);
        const int providerX = liveWrapInputs ? inset : pidX + pidWidth + gap;
        const int providerY = inset + (liveWrapInputs ? controlStep : 0);
        const int suffixWidth = 3 * actionWidth + 2 * gap;
        const int providerRight = liveSingleRow ? right - suffixWidth - gap : right;
        move(page.liveProvider, providerX, providerY, (std::min)(Scale(370), providerRight - providerX), height);
        const int actionY = inset + (liveToolbarRows - 1) * controlStep;
        const int actionX = liveSingleRow ? right - suffixWidth : inset;
        const int actionSpace = liveSingleRow ? suffixWidth : width;
        const int buttonWidth = (std::min)(actionWidth, (std::max)(1, (actionSpace - 2 * gap) / 3));
        move(page.liveStart, actionX, actionY, buttonWidth, height);
        move(page.liveStop, actionX + buttonWidth + gap, actionY, buttonWidth, height);
        move(page.liveFollow, actionX + 2 * (buttonWidth + gap), actionY, buttonWidth, height);
    } else if (side) {
        move(page.actions, commandX, inset, commandsWidth, height);
        move(page.createProject, commandX, inset + controlStep, commandsWidth, height);
        move(page.open, commandX, inset + 2 * controlStep, commandsWidth, height);
        move(page.switchView, commandX, inset + 3 * controlStep, commandsWidth, height);
        move(page.retry, commandX, inset + 4 * controlStep, commandsWidth, height);
        move(page.capability, commandX, inset + 5 * controlStep, commandsWidth, Scale(105));
    } else {
        move(page.createProject, inset, inset, Scale(106), height);
        move(page.open, inset + Scale(106) + gap, inset, Scale(106), height);
        move(page.switchView, inset + 2 * Scale(106) + 2 * gap, inset, switchWidth, height);
        move(page.retry, inset + switchWidth + 2 * Scale(106) + 3 * gap, inset, Scale(116), height);
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
    const int sourceX = wrapSources ? inset : mainRight - sourcesWidth; // 换行时可用整页宽度。
    const int sourceY = wrapSources ? top + height + gap : top;
    const int filterRight = wrapSources ? mainRight : sourceX - gap;
    const bool showFilterLabel = filterRight - mainX >= Scale(180);
    const int filterLeft = mainX + (showFilterLabel ? Scale(57) : 0);
    ::ShowWindow(page.filterLabel, showFilterLabel ? SW_SHOW : SW_HIDE);
    move(page.filterLabel, mainX, top + Scale(4), Scale(56), height - Scale(4));
    move(page.filter, filterLeft, top, filterRight - filterLeft, height);
    move(page.apiOnly, sourceX, sourceY, sourceWidth, height);
    move(page.etwOnly, page.liveView ? sourceX : sourceX + sourceWidth + gap, sourceY, sourceWidth, height);
    move(page.networkOnly, sourceX + (sourceWidth + gap) * 2, sourceY, sourceWidth, height);
    const int tableWidth = mainRight - mainX;
    if (showEvidenceNavigation) {
        // 宽窗跟随表格左边界，窄窗沿用来源工具行的全宽布局。
        const int evidenceX = tableWidth >= Scale(315) ? mainX : inset;
        const int labelWidth = Scale(77), locateWidth = Scale(125);
        const int comboX = evidenceX + labelWidth;
        const int comboWidth = (std::clamp)(mainRight - comboX - locateWidth - gap, 1, Scale(265));
        move(page.evidenceFamilyLabel, evidenceX, evidenceTop + Scale(4), labelWidth, height - Scale(4));
        move(page.evidenceFamily, comboX, evidenceTop, comboWidth, height * 7);
        move(page.locateEvidence, comboX + comboWidth + gap, evidenceTop, locateWidth, height);
    }
    move(page.timeline.hwnd(), inset, resultTop, timelineWidth, graphTop - resultTop - gap);
    move(page.list.hwnd(), mainX, resultTop, mainRight - mainX, graphTop - resultTop - gap);
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
    const auto* evidence = DisplayedEvidence(page);
    if (!evidence || !page.selected || *page.selected >= evidence->rows.size()) return nullptr;
    return &evidence->rows[*page.selected];
}

void UpdateDetails(Page& page) {
    const auto* record = SelectedRecord(page);
    std::wstring text;
    if (page.liveView) {
        if (const auto* evidence = DisplayedEvidence(page); evidence && evidence->identity) {
            const auto& identity = *evidence->identity;
            text = identity.projectId.empty() ? L"实时会话 " + WideAscii(identity.sampleId) :
                L"项目 " + WideAscii(identity.projectId) + L" · 采样 " + WideAscii(identity.sampleId);
            text += L"\r\n\r\n";
        }
        if (record) {
            text += L"实时序号 " + std::to_wstring(record->sequence) + L" · 接收 QPC " + Number(record->receiveQpc);
            if (record->rawSequence) {
                text += L"\r\n已提交 raw 段 " + std::to_wstring(record->segmentOrdinal) + L" · 归档序号 " + Number(record->rawSequence);
            }
            text += L"\r\n\r\n" + record->preview;
        } else {
            text += L"选择一条实时记录查看证据。";
        }
        if (text != page.displayedDetails) {
            page.displayedDetails = std::move(text);
            ::SetWindowTextW(page.details, page.displayedDetails.c_str());
        }
        return;
    }
    if (const auto* archive = DisplayedArchive(page); archive && archive->evidence.identity) {
        const auto& snapshot = *archive;
        const auto& evidence = snapshot.evidence;
        const auto& identity = *evidence.identity;
        text = (page.samplePreview ? L"选中采样预览 · 采样：" : L"当前归档 · 采样：") + WideAscii(identity.sampleId) + L"\r\n" +
            snapshot.classification + L"\r\n" + kRelationshipCoverage + L"\r\n\r\n" +
            (snapshot.sample ? L"清单：" : L"归档：") + snapshot.path + L"\r\n项目：" + WideAscii(identity.projectId) +
            L"\r\n流编号：" + std::to_wstring(identity.streamKind);
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
        if (!record->apiFamily.empty()) {
            text += L"API 分类：" + ApiFamilyLabel(record->apiFamily) + L"（" + record->apiFamily + L"）\r\n";
        }
        if (record->eventOrdinal) {
            text += L"来源实例字典 ID：" + Number(record->sourceDictionaryId) + L"    来源代次字典 ID：" +
                Number(record->epochDictionaryId) + L"\r\n报头 PID：" + Number(record->headerPid) +
                L"    报头 TID：" + Number(record->headerTid) + L"\r\n引用状态：归档字段已读取，字典、跨流记录与对象尚未解析。\r\n";
        }
        text += L"\r\n" + (record->network ? NetworkReplayDetails(*record->network) : record->preview);
    } else {
        if (DisplayedArchive(page)) text += L"选择一条记录查看归档字段。";
        else if (page.project) text += L"工程：" + page.project->manifestPath + L"\r\n选择采样查看证据，或开始新一轮扫描。";
        else text += L"新建或打开工程后，可查看采样的分类和证据。";
    }
    if (text != page.displayedDetails) {
        page.displayedDetails = std::move(text);
        ::SetWindowTextW(page.details, page.displayedDetails.c_str());
    }
    ::InvalidateRect(page.hwnd, &page.graph, FALSE);
}

void UpdateStatus(Page& page) {
    std::wstring text = page.requestStatus;
    std::wstring empty;
    if (page.liveView) {
        text = FormatLiveStatus(page.liveStatus);
        if (!page.liveInputError.empty()) {
            if (!text.empty()) text += L"\r\n";
            text += page.liveInputError;
        }
        if (text.empty()) text = L"输入自有进程 PID 和 ETW 提供程序 GUID，再开始扫描。";
        if (page.liveStopRequested && page.liveStatus.active &&
            (page.liveStatus.capture.state == LiveCaptureState::Idle || page.liveStatus.capture.state == LiveCaptureState::Running)) {
            text += L" · 已请求停止";
        }
        if (page.project && !page.liveStatus.active) {
            text += L"\r\n下次扫描写入工程 · " + page.project->manifestPath;
        }
        const auto* result = DisplayedEvidence(page);
        if (result && !result->rows.empty()) {
            text += L"\r\n当前窗口 · 显示 " + std::to_wstring(page.list.visibleIndexes().size()) + L" / " +
                std::to_wstring(result->rows.size()) + L" 条";
            const auto& status = page.liveStatus.capture;
            if (result->identity && (status.sessionEpoch.empty() || result->identity->sampleId !=
                    (status.sampleId.empty() ? status.sessionEpoch : status.sampleId))) {
                text += L" · 上次采集的结果";
            }
            if (!page.followLive) text += page.liveStatus.active ? L" · 展示已暂停，采集仍在后台进行" : L" · 展示已暂停";
            if (page.selected && !std::binary_search(page.list.visibleIndexes().begin(), page.list.visibleIndexes().end(), *page.selected)) {
                text += L" · 已选记录被筛掉";
            }
            empty = L"没有匹配的实时记录";
        } else if (page.liveStatus.capture.state == LiveCaptureState::Failed) {
            empty = L"采集失败，请查看状态后重试";
        } else if (page.liveStatus.active) {
            empty = L"等待首条实时记录";
        } else {
            empty = page.liveStatus.capture.pid ? L"本次采集没有可显示的记录" : L"尚未开始实时采集";
        }
    } else if (const auto* archive = DisplayedArchive(page)) {
        const auto& result = archive->evidence;
        if (!page.samplePreview && !page.snapshotStatus.empty()) {
            if (!text.empty()) text += L"\r\n";
            text += page.snapshotStatus;
        }
        const auto ordinal = archive->checkpoint.lastVerifiedOrdinal; // 字节范围对应的已验证段。
        text += page.samplePreview ? L"\r\n选中采样预览  ·  显示 " : L"\r\n当前归档  ·  显示 ";
        text += std::to_wstring(page.list.visibleIndexes().size()) +
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
    if (!page.liveView) {
        const auto* archive = DisplayedArchive(page);
        if (page.project && text.find(page.project->manifestPath) == std::wstring::npos) {
            if (!text.empty()) text += L"\r\n";
            text += L"工程 · " + page.project->manifestPath;
        }
        empty = !archive ? (page.project ? L"选择采样或开始新一轮扫描" : L"尚未打开工程") : archive->evidence.rows.empty() ?
            (archive->evidence.diagnostic.empty() ? L"此归档段没有记录" : L"已读前缀没有可显示记录") : L"没有匹配的记录";
        if (page.liveStatus.active) {
            text += page.liveStatus.cleanupPending ? L"\r\n实时采集等待清退重试 · 返回实时视图处理" :
                L"\r\n实时会话 · PID " + std::to_wstring(page.liveStatus.capture.pid) + L" · 在后台运行";
        }
    }
    if (text != page.displayedStatus) {
        page.displayedStatus = std::move(text);
        ::SetWindowTextW(page.status, page.displayedStatus.c_str());
    }
    if (empty != page.displayedEmpty) {
        page.displayedEmpty = std::move(empty);
        ::SetWindowTextW(page.projection, page.displayedEmpty.c_str());
    }
    if (static_cast<bool>(::GetWindowLongPtrW(page.projection, GWL_STYLE) & WS_VISIBLE) != page.list.visibleIndexes().empty()) {
        ::ShowWindow(page.projection, page.list.visibleIndexes().empty() ? SW_SHOW : SW_HIDE);
    }
}

void SetListSelection(Page& page, std::size_t record, bool reveal) {
    const auto& visible = page.list.visibleIndexes();
    const auto it = std::lower_bound(visible.begin(), visible.end(), record);
    if (it == visible.end() || *it != record) return;
    const auto position = static_cast<int>(it - visible.begin());
    ListView_SetItemState(page.list.hwnd(), position, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    if (reveal) ListView_EnsureVisible(page.list.hwnd(), position, FALSE);
}

void SetLiveFollow(Page& page, bool enabled);

void SelectRecord(Page& page, std::size_t index) {
    if (page.selected == index) return;
    page.selected = index;
    if (page.liveView) page.liveSelection = index;
    else if (page.samplePreview) page.previewSelection = index;
    else page.historySelection = index;
    if (page.liveView && page.followLive && page.liveStatus.active) SetLiveFollow(page, false);
    page.timeline.select(index, true);
    UpdateDetails(page);
    UpdateStatus(page);
}

void SetEvidenceFamilyChoice(Page& page) {
    page.evidenceFamilyChoice.clear();
    const auto* archive = ClassifiedArchive(page);
    const auto index = ::SendMessageW(page.evidenceFamily, CB_GETCURSEL, 0, 0);
    if (archive && index > 0 && static_cast<std::size_t>(index) <= archive->apiFamilies.size()) {
        page.evidenceFamilyChoice = std::next(archive->apiFamilies.begin(), index - 1)->first;
    }
    if (page.evidenceFamilyChoice.empty() && ::GetFocus() == page.locateEvidence) ::SetFocus(page.evidenceFamily);
    ::EnableWindow(page.locateEvidence, !page.evidenceFamilyChoice.empty());
}

void RefreshEvidenceNavigation(Page& page) {
    const auto* archive = ClassifiedArchive(page);
    const auto scope = archive ? archive->evidence.identity : std::nullopt;
    const auto path = archive ? std::wstring_view(archive->path) : std::wstring_view{};
    if (!page.liveView && (page.evidenceFamilyScope != scope || page.evidenceFamilyPath != path)) {
        page.evidenceFamilyScope = scope;
        page.evidenceFamilyPath = path;
        page.evidenceFamilyChoice.clear();
    }
    if (!archive && (::GetFocus() == page.evidenceFamily || ::GetFocus() == page.locateEvidence)) {
        ::SetFocus(page.filter);
    }
    const bool wasVisible = (::GetWindowLongPtrW(page.evidenceFamily, GWL_STYLE) & WS_VISIBLE) != 0;
    if (wasVisible != (archive != nullptr)) {
        Layout(page);
        for (HWND control : {page.evidenceFamilyLabel, page.evidenceFamily, page.locateEvidence}) {
            ::ShowWindow(control, archive ? SW_SHOW : SW_HIDE);
        }
    }
    if (!archive) {
        ::EnableWindow(page.locateEvidence, FALSE);
        return;
    }

    ::SendMessageW(page.evidenceFamily, CB_RESETCONTENT, 0, 0);
    bool populated = ::SendMessageW(page.evidenceFamily, CB_ADDSTRING, 0,
        reinterpret_cast<LPARAM>(L"选择 API 分类")) == 0;
    LRESULT selected = 0;
    for (const auto& [family, group] : archive->apiFamilies) {
        if (!populated) break;
        const auto label = ApiFamilyLabel(family) + L"（" + std::to_wstring(group.count) + L"）";
        const auto index = ::SendMessageW(page.evidenceFamily, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
        populated = index > 0;
        if (populated && page.evidenceFamilyChoice == family) selected = index;
    }
    if (!populated) {
        ::SendMessageW(page.evidenceFamily, CB_RESETCONTENT, 0, 0);
        if (::GetFocus() == page.evidenceFamily || ::GetFocus() == page.locateEvidence) ::SetFocus(page.filter);
    }
    ::EnableWindow(page.evidenceFamily, populated);
    ::SendMessageW(page.evidenceFamily, CB_SETCURSEL, selected, 0);
    SetEvidenceFamilyChoice(page);
}

void LocateEvidence(Page& page) {
    if (page.retiring) return;
    const auto* archive = ClassifiedArchive(page);
    if (!archive) return;
    const auto family = archive->apiFamilies.find(page.evidenceFamilyChoice);
    if (family == archive->apiFamilies.end()) return;
    const auto index = family->second.latest;
    // 最新原始行与分类取自同一只读快照。筛选隐藏该行时沿用现有的详情和状态提示。
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    SelectRecord(page, index);
    SetListSelection(page, index, true);
}

void ApplyFilter(Page& page) {
    wchar_t query[257]{};
    ::GetWindowTextW(page.filter, query, static_cast<int>(std::size(query)));
    auto visible = Ui::VirtualListView::FilterRowIndexes(page.list.rows(), query);
    if (const auto* evidence = DisplayedEvidence(page)) {
        const auto& records = evidence->rows;
        const auto* archive = page.liveView ? nullptr : DisplayedArchive(page);
        const bool etwOnly = page.timeline.hasEtw() && Checked(page.etwOnly);
        const bool apiOnly = archive && !archive->apiFamilies.empty() && Checked(page.apiOnly);
        const bool networkOnly = archive && archive->hasNetwork && Checked(page.networkOnly);
        std::erase_if(visible, [&](std::size_t i) {
            const auto& row = records[i]; // 来源开关取并集，再与文字和类别相交。
            const bool sourceMatch = (!apiOnly && !etwOnly && !networkOnly) || (apiOnly && !row.apiClue.empty()) ||
                (etwOnly && row.etw) || (networkOnly && row.network);
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

void PresentResults(Page& page, bool refreshLive = false) {
    static const std::vector<EvidenceRecord> empty;
    const auto* evidence = DisplayedEvidence(page);
    const auto* archive = page.liveView ? nullptr : DisplayedArchive(page);
    page.timeline.replace(evidence ? evidence->rows : empty);
    page.timeline.select(page.selected, page.liveView);
    const bool categories = page.timeline.hasCategories();
    const bool etw = page.timeline.hasEtw();
    if (!refreshLive) ::SetWindowTextW(page.categories, categories ? L"类别筛选…" : L"无可筛选类别");
    const auto enableSource = [&](HWND control, bool enabled) {
        if (!enabled && ::GetFocus() == control) ::SetFocus(page.filter);
        ::EnableWindow(control, enabled);
    };
    enableSource(page.categories, categories);
    enableSource(page.etwOnly, etw);
    enableSource(page.apiOnly, ClassifiedArchive(page) != nullptr);
    enableSource(page.networkOnly, archive && archive->hasNetwork);
    if (!refreshLive) RefreshEvidenceNavigation(page);
    page.applyingProjection = true;
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (page.liveView && page.liveProjection) {
        page.list.setSharedRows(page.liveProjection->presentation);
    } else if (archive) {
        page.list.setSharedRows(archive->presentation);
    } else {
        page.list.setSharedRows({});
    }
    page.applyingProjection = false;
    ApplyFilter(page);
    if (page.liveView && page.followLive && !page.list.visibleIndexes().empty()) {
        ListView_EnsureVisible(page.list.hwnd(), static_cast<int>(page.list.visibleIndexes().size() - 1), FALSE);
    }
    UpdateDetails(page);
}

std::wstring Diagnostic(const SegmentEvidence& result) {
    auto text = WideAscii(result.diagnostic) + L" @ " + std::to_wstring(result.failureOffset) + L" B";
    if (result.systemError) text += L" (Win32 " + std::to_wstring(result.systemError) + L")";
    return text;
}

void ResetSamplePreview(Page& page) {
    page.previewRequest.reset();
    page.previewSelection.reset();
    if (!page.samplePreview) return;
    auto previous = std::exchange(page.samplePreview, {});
    if (!page.liveView) {
        page.selected = page.historySelection;
        PresentResults(page);
    }
    Ui::RetireBackgroundValue(previous);
}

// 清空目录草稿，并在隐藏当前焦点控件前退回打开按钮。
void ClearChoices(Page& page) {
    ResetSamplePreview(page);
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
    if (DisplayedArchive(page)) page.requestStatus += L"（保留当前归档）";
    UpdateStatus(page);
}

void UpdateProjectControls(Page& page) {
    ::EnableWindow(page.open, !page.catalogBusy);
    ::EnableWindow(page.createProject, !page.catalogBusy);
    ::EnableWindow(page.retry, !page.catalogBusy && !page.requestPath.empty());
    ::EnableWindow(page.sampleChoice, !page.catalogBusy);
    ::EnableWindow(page.cancelChoice, !page.catalogBusy);
    ::EnableWindow(page.switchView, !page.catalogBusy);
    ::EnableWindow(page.replaySample, !page.catalogBusy && ::SendMessageW(page.sampleChoice, CB_GETCURSEL, 0, 0) >= 0);
}

// 发布已提交的项目目录。不同项目的回放各自保有身份。
void PresentCatalog(Page& page, ProjectReplayCatalog catalog, bool created = false) {
    page.catalogBusy = false;
    UpdateProjectControls(page);
    if (!catalog.diagnostic.empty()) {
        auto failure = WideAscii(catalog.diagnostic); // 共用只读目录的失败原因。
        if (catalog.systemError) failure += L" (Win32 " + std::to_wstring(catalog.systemError) + L")";
        ShowReadFailure(page, failure);
        return;
    }
    const bool sameProject = page.project && page.project->projectId == catalog.projectId &&
        page.project->manifestPath == catalog.manifestPath;
    std::optional<ProjectReplayRequest> selection;
    const auto current = ::SendMessageW(page.sampleChoice, CB_GETCURSEL, 0, 0);
    if (sameProject && current >= 0 && static_cast<std::size_t>(current) < page.choices.size()) {
        selection = page.choices[static_cast<std::size_t>(current)].request;
    }
    if (sameProject) {
        ::SendMessageW(page.sampleChoice, CB_RESETCONTENT, 0, 0);
        page.choices.clear();
    } else {
        ClearChoices(page);
        page.catalogRefreshPending = false;
        page.historySelection.reset();
        auto previous = std::exchange(page.snapshot, {});
        if (previous) Ui::RetireBackgroundValue(previous);
        if (!page.liveView) page.selected.reset();
    }
    page.project = NativeLiveProject{std::move(catalog.manifestPath), std::move(catalog.projectId)};
    page.requestPath = page.project->manifestPath;
    page.requestedSample.reset();
    page.requestStatus = (created ? L"已新建工程 · " : catalog.recoveredPrevious ? L"已读取上次有效工程目录 · " : L"已打开工程 · ") +
        page.project->manifestPath;
    if (catalog.choices.empty()) {
        ResetSamplePreview(page);
        for (HWND control : {page.sampleChoice, page.replaySample, page.cancelChoice}) ::ShowWindow(control, SW_HIDE);
        Layout(page);
        page.requestStatus += L"\r\n工程尚无采样，请开始新一轮扫描。";
        if (!page.liveView) PresentResults(page);
        else UpdateStatus(page);
        UpdateProjectControls(page);
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
        if (selection == choice.request) ::SendMessageW(page.sampleChoice, CB_SETCURSEL, index, 0);
    }
    if (::SendMessageW(page.sampleChoice, CB_GETCURSEL, 0, 0) < 0) ResetSamplePreview(page);
    Layout(page);
    for (HWND control : {page.sampleChoice, page.replaySample, page.cancelChoice}) {
        ::ShowWindow(control, page.liveView ? SW_HIDE : SW_SHOW);
    }
    page.requestStatus += L"\r\n选择采样即可预览，点击回放可继续读取。";
    if (!page.liveView) PresentResults(page);
    else UpdateStatus(page);
    UpdateProjectControls(page);
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
    const bool commitsPreview = page.samplePreview && page.samplePreview->sample == loaded.sample;
    const bool restorePreviewSelection = commitsPreview && page.previewSelection.has_value();
    const auto* previousSelectionSnapshot = restorePreviewSelection ? page.samplePreview.get() : page.snapshot.get();
    const auto index = restorePreviewSelection ? page.previewSelection : page.historySelection;
    std::optional<std::size_t> selection; // 同一证据中的新行索引。
    if (previousSelectionSnapshot && index && *index < previousSelectionSnapshot->evidence.rows.size() &&
        previousSelectionSnapshot->path == loaded.path && previousSelectionSnapshot->sample == loaded.sample &&
        previousSelectionSnapshot->evidence.identity == loaded.evidence.identity) {
        // 项目、采样、流身份一致后，使用真正所属段与归档序号找回原始记录。
        const auto& selected = previousSelectionSnapshot->evidence.rows[*index];
        const auto& rows = loaded.evidence.rows; // 新完成的证据快照。
        const auto found = std::find_if(rows.begin(), rows.end(), [&selected](const auto& row) {
            if (row.segmentOrdinal != selected.segmentOrdinal || row.sequence != selected.sequence) return false;
            return selected.apiFamily.empty() || (row.offset == selected.offset && row.blockOrdinal == selected.blockOrdinal &&
                row.apiFamily == selected.apiFamily && row.apiClue == selected.apiClue && row.preview == selected.preview);
        });
        if (found != rows.end()) selection = static_cast<std::size_t>(found - rows.begin());
    }

    auto previousPreview = commitsPreview ? std::exchange(page.samplePreview, {}) : std::shared_ptr<const Snapshot>{};
    if (previousPreview) page.previewSelection.reset();
    auto next = std::make_shared<const Snapshot>(std::move(loaded)); // 将发布的数据固化为共享值。
    auto previous = std::exchange(page.snapshot, std::move(next)); // 旧大快照交给后台释放。
    page.historySelection = selection;

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
    if (!page.liveView) {
        page.selected = page.historySelection;
        PresentResults(page);
        if (selection) SetListSelection(page, *selection, true);
        else if (page.list.rowCount()) ListView_EnsureVisible(page.list.hwnd(), 0, FALSE);
    } else {
        UpdateStatus(page);
    }
    if (previous) Ui::RetireBackgroundValue(previous);
    if (previousPreview) Ui::RetireBackgroundValue(previousPreview);
}

// 在原异步任务提交冻结的文件或样本请求。新请求代次取代在途旧回执。
void Open(Page& page, std::wstring path, std::optional<ProjectReplayRequest> sample = std::nullopt) {
    if (path.empty() || page.retiring || page.catalogBusy) return;
    // 同一 API 采样的正式回放失败时仍可回看已核验预览与当前详情。
    if (!sample || !page.samplePreview || page.samplePreview->sample != sample || page.samplePreview->apiFamilies.empty()) {
        ResetSamplePreview(page);
    }
    page.previewRequest = sample;
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
            } else {
                PublishSnapshot(page, std::get<Snapshot>(std::move(*loaded)));
            }
        });
}

void OpenCatalog(Page& page, std::wstring path, bool create = false) {
    if (path.empty() || page.retiring || page.catalogBusy) return;
    page.catalogBusy = true;
    if (!page.samplePreview) page.previewRequest.reset();
    page.requestPath = create ? (std::filesystem::path(path) / L"project.ksaproj").wstring() : path;
    page.requestedSample.reset();
    page.requestStatus = (create ? L"正在新建工程 · " : L"正在读取工程 · ") + page.requestPath;
    UpdateProjectControls(page);
    UpdateStatus(page);
    page.task->request([path = std::move(path), create]() -> LoadResult {
            return create ? CreateProjectReplayCatalog(path) : ReadProjectReplayCatalog(path);
        }, [&page, create](std::uint64_t, std::optional<LoadResult>&& loaded, std::exception_ptr error) {
            if (error || !loaded) {
                page.catalogBusy = false;
                UpdateProjectControls(page);
                ShowReadFailure(page, create ? L"后台创建工程失败" : L"后台读取工程失败");
                return;
            }
            PresentCatalog(page, std::get<ProjectReplayCatalog>(std::move(*loaded)), create);
        });
}

void RefreshProjectAfterScan(Page& page) {
    if (!page.catalogRefreshPending || page.liveView || page.catalogBusy || page.retiring || !page.project ||
        page.task->running()) return;
    page.catalogRefreshPending = false;
    OpenCatalog(page, page.project->manifestPath);
}

// 默认筛选工程清单，独立段通过诊断筛选打开。
void Browse(Page& page) {
    std::vector<wchar_t> path(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = ::GetAncestor(page.hwnd, GA_ROOT);
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrFilter = L"ActionAnalyze 工程\0project.ksaproj\0独立归档段（诊断）\0*.ksaseg\0";
    dialog.nFilterIndex = 1;
    dialog.lpstrTitle = L"打开 ActionAnalyze 工程";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_DONTADDTORECENT;
    if (::GetOpenFileNameW(&dialog)) {
        if (IsProjectReplayManifest(path.data())) OpenCatalog(page, path.data());
        else Open(page, path.data());
    }
    else if (const DWORD error = ::CommDlgExtendedError()) {
        page.requestStatus = L"文件选择失败（" + std::to_wstring(error) + L"）";
        UpdateStatus(page);
    }
}

void BrowseNewProject(Page& page) {
    std::vector<wchar_t> path(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = ::GetAncestor(page.hwnd, GA_ROOT);
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrTitle = L"新建 ActionAnalyze 工程（输入新文件夹名称）";
    dialog.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_DONTADDTORECENT;
    if (::GetSaveFileNameW(&dialog)) OpenCatalog(page, path.data(), true);
    else if (const DWORD error = ::CommDlgExtendedError()) {
        page.requestStatus = L"工程位置选择失败（" + std::to_wstring(error) + L"）";
        UpdateStatus(page);
    }
}

const ProjectReplayRequest* SelectedSample(const Page& page) {
    const auto selected = ::SendMessageW(page.sampleChoice, CB_GETCURSEL, 0, 0); // 草稿中的采样索引。
    if (selected < 0 || static_cast<std::size_t>(selected) >= page.choices.size()) return nullptr;
    return &page.choices[static_cast<std::size_t>(selected)].request;
}

void PreviewSelectedSample(Page& page) {
    if (page.liveView || page.retiring || page.catalogBusy || page.choices.empty()) return;
    const auto* selected = SelectedSample(page);
    ::EnableWindow(page.replaySample, selected != nullptr);
    if (selected && page.previewRequest == *selected) return;
    ResetSamplePreview(page);
    if (!selected) {
        page.requestStatus = L"选择采样即可预览。";
        UpdateStatus(page);
        return;
    }

    const auto request = *selected;
    page.previewRequest = request;
    page.requestStatus = L"正在预览采样 · " + WideAscii(request.sampleId);
    UpdateStatus(page);
    page.task->request([request] { return Load(request.manifestPath, request, ProjectReplayMode::SelectionPreview); },
        [&page, request](std::uint64_t, std::optional<LoadResult>&& loaded, std::exception_ptr error) {
            if (page.retiring || page.previewRequest != request) return;
            auto* preview = !error && loaded ? std::get_if<Snapshot>(&*loaded) : nullptr;
            const auto sample = WideAscii(request.sampleId);
            if (preview && preview->evidence.diagnostic == "replaySelectionLimit") {
                page.requestStatus = L"采样 " + sample + L" 的 raw 段超过预览上限，请点击回放。";
            } else if (preview && preview->checkpoint.state == CheckpointState::Pending) {
                page.requestStatus = L"采样 " + sample + L" 的首段检查点尚未发布，可点击回放重试。";
            } else if (!preview || !preview->evidence.identity ||
                (!preview->evidence.diagnostic.empty() && preview->evidence.rows.empty())) {
                page.requestStatus = L"无法预览采样 " + sample + L"，请点击回放重试。";
                if (preview) page.requestStatus += L" · " + Diagnostic(preview->evidence);
            } else {
                page.requestStatus = L"快速预览 · " + sample;
                if (preview->checkpoint.state == CheckpointState::PreviewLimited) {
                    page.requestStatus += L" · 已核验首段，点击回放可读取后续段";
                } else if (preview->checkpoint.state == CheckpointState::NotPublished) {
                    page.requestStatus += preview->evidence.apiClues ? L" · API 导入尾记已核验" :
                        L" · 仅查看 raw 段，未发布终态检查点";
                } else if (preview->checkpoint.state == CheckpointState::Verified) {
                    page.requestStatus += L" · 首段终态检查点已核验";
                }
                if (!preview->evidence.diagnostic.empty()) {
                    page.requestStatus += L" · 部分可读 · " + Diagnostic(preview->evidence);
                }
                page.samplePreview = std::make_shared<const Snapshot>(std::move(*preview));
                if (!page.liveView) {
                    page.selected = page.previewSelection;
                    PresentResults(page);
                    if (page.list.rowCount()) ListView_EnsureVisible(page.list.hwnd(), 0, FALSE);
                    return;
                }
            }
            UpdateStatus(page);
        });
}

void ReplaySelectedSample(Page& page) {
    if (const auto* selected = SelectedSample(page)) {
        const auto request = *selected;
        Open(page, request.manifestPath, request);
    }
}

void UpdateLiveControls(Page& page) {
    const bool busy = page.liveStatus.active;
    const bool retry = page.liveStatus.cleanupPending;
    const auto enable = [&](HWND control, bool enabled) {
        if (enabled != static_cast<bool>(::IsWindowEnabled(control))) {
            if (!enabled && ::GetFocus() == control) ::SetFocus(page.switchView);
            ::EnableWindow(control, enabled);
        }
    };
    enable(page.liveStart, !busy && !page.retiring && page.project.has_value());
    enable(page.liveStop, busy && !page.retiring && (!page.liveStopRequested || retry));
    enable(page.liveFollow, busy || page.liveProjection.has_value());
    const wchar_t* stopText = retry ? L"重试清退" : L"停止采集";
    wchar_t current[32]{};
    ::GetWindowTextW(page.liveStop, current, static_cast<int>(std::size(current)));
    if (std::wstring_view(current) != stopText) ::SetWindowTextW(page.liveStop, stopText);
}

void SetLiveFollow(Page& page, bool enabled) {
    page.followLive = enabled;
    ::SetWindowTextW(page.liveFollow, enabled ? L"暂停跟随" : L"恢复实时");
}

void RefreshLive(Page& page) {
    const bool wasActive = page.liveStatus.active;
    page.liveStatus = page.live.ReadStatus();
    if (page.liveView && page.followLive && ::IsWindowVisible(page.hwnd)) {
        if (auto next = page.live.TakeProjection()) {
            std::optional<std::uint64_t> selectedSequence;
            if (const auto* selected = SelectedRecord(page); selected && page.liveProjection &&
                page.liveProjection->evidence.identity == next->evidence.identity) {
                selectedSequence = selected->sequence;
            }
            page.liveProjection = std::move(next);
            page.selected.reset();
            if (selectedSequence) {
                const auto& rows = page.liveProjection->evidence.rows;
                const auto found = std::lower_bound(rows.begin(), rows.end(), *selectedSequence,
                    [](const EvidenceRecord& row, std::uint64_t sequence) { return row.sequence < sequence; });
                if (found != rows.end() && found->sequence == *selectedSequence) {
                    page.selected = static_cast<std::size_t>(found - rows.begin());
                }
            }
            page.liveSelection = page.selected;
            PresentResults(page, true);
        }
        // Ask after consuming so at most one full projection is prepared per display tick.
        if (!page.retiring && page.liveStatus.active) page.live.RequestProjection();
    }
    if (!page.liveStatus.active) {
        page.liveStopRequested = false;
        ::KillTimer(page.hwnd, kLiveDisplayTimer);
        const auto& capture = page.liveStatus.capture;
        if (wasActive && page.project && capture.projectId == page.project->projectId && !capture.sampleId.empty()) {
            page.catalogRefreshPending = true;
        }
        RefreshProjectAfterScan(page);
    }
    if (::IsWindowVisible(page.hwnd)) {
        UpdateLiveControls(page);
        UpdateStatus(page);
    }
}

void ToggleView(Page& page) {
    if (!page.liveView && !page.project) {
        page.requestStatus = L"请先新建或打开工程，再开始新一轮扫描。";
        UpdateStatus(page);
        return;
    }
    wchar_t query[257]{};
    ::GetWindowTextW(page.filter, query, static_cast<int>(std::size(query)));
    (page.liveView ? page.liveFilter : page.historyFilter) = query;
    (page.liveView ? page.liveEtwOnly : page.historyEtwOnly) = Checked(page.etwOnly);
    page.liveView = !page.liveView;
    page.selected = page.liveView ? page.liveSelection : page.samplePreview ? page.previewSelection : page.historySelection;
    const int showLive = page.liveView ? SW_SHOW : SW_HIDE;
    const int showHistory = page.liveView ? SW_HIDE : SW_SHOW;
    ::SetWindowTextW(page.switchView, page.liveView ? L"返回工程" : L"新一轮扫描");
    for (const auto control : {page.createProject, page.open, page.retry, page.capability, page.apiOnly, page.networkOnly}) {
        ::ShowWindow(control, showHistory);
    }
    for (const auto control : {page.livePid, page.liveProvider, page.liveStart, page.liveStop, page.liveFollow}) {
        ::ShowWindow(control, showLive);
    }
    for (const auto control : {page.sampleChoice, page.replaySample, page.cancelChoice}) {
        ::ShowWindow(control, !page.liveView && !page.choices.empty() ? SW_SHOW : SW_HIDE);
    }
    page.applyingProjection = true;
    ::SetWindowTextW(page.filter, (page.liveView ? page.liveFilter : page.historyFilter).c_str());
    ::SendMessageW(page.etwOnly, BM_SETCHECK, (page.liveView ? page.liveEtwOnly : page.historyEtwOnly) ? BST_CHECKED : BST_UNCHECKED, 0);
    page.applyingProjection = false;
    Layout(page);
    PresentResults(page);
    RefreshLive(page);
}

// Parse a positive decimal Win32 PID without accepting partial input or wraparound.
DWORD ReadLivePid(HWND input) {
    wchar_t digits[12]{};
    const int length = ::GetWindowTextW(input, digits, static_cast<int>(std::size(digits)));
    if (length > 10) return 0;
    std::uint64_t value = 0;
    for (int i = 0; i < length; ++i) {
        if (digits[i] < L'0' || digits[i] > L'9') return 0;
        value = value * 10 + static_cast<std::uint64_t>(digits[i] - L'0');
    }
    return value <= MAXDWORD ? static_cast<DWORD>(value) : 0;
}

bool ReadLiveProvider(HWND input, std::optional<GUID>& provider) {
    wchar_t value[40]{};
    const int length = ::GetWindowTextW(input, value, static_cast<int>(std::size(value)));
    if (!length) return true;
    const std::wstring_view text(value, static_cast<std::size_t>(length));
    const std::wstring braced = length == 36 ? L"{" + std::wstring(text) + L"}" : std::wstring(text);
    if (braced.size() != 38 || braced.front() != L'{' || braced.back() != L'}') return false;
    provider.emplace();
    return SUCCEEDED(::CLSIDFromString(braced.c_str(), &*provider)) && !::IsEqualGUID(*provider, GUID{});
}

void StartLive(Page& page) {
    if (page.retiring || page.liveStatus.active || !page.project) return;
    NativeLiveRequest request;
    request.pid = ReadLivePid(page.livePid);
    if (!request.pid) {
        page.liveInputError = L"请输入有效的十进制 PID。";
        ::SetFocus(page.livePid);
    } else if (!ReadLiveProvider(page.liveProvider, request.provider) || !request.provider) {
        page.liveInputError = L"请输入有效的 ETW 提供程序 GUID，以将本次扫描写入工程。";
        ::SetFocus(page.liveProvider);
    } else if (!::SetTimer(page.hwnd, kLiveDisplayTimer, kLiveDisplayIntervalMs, nullptr)) {
        page.liveInputError = L"无法创建实时显示计时器，请重试。";
    } else {
        request.project = page.project;
        const DWORD error = page.live.Start(std::move(request));
        if (!error) {
            page.liveInputError.clear();
            page.liveStopRequested = false;
            SetLiveFollow(page, true);
            // Keep the last successful result until this request publishes its own projection.
            RefreshLive(page);
            return;
        }
        ::KillTimer(page.hwnd, kLiveDisplayTimer);
        page.liveInputError = L"无法开始采集（Win32 " + std::to_wstring(error) + L"），请重试。";
    }
    UpdateStatus(page);
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
    line(record && record->eventOrdinal ? L"证据引用 · 归档字段 / 未解析" :
            DisplayedArchive(page) ? kRelationshipCoverage : L"证据引用 · 选择带引用的归档事件",
        { x, y, page.graph.right, y + Scale(24) });
    if (!record) return;
    if (!record->eventOrdinal) {
        if (!record->apiFamily.empty()) {
            line(L"原始证据 · 段 " + std::to_wstring(record->segmentOrdinal) + L" / 归档记录 #" + std::to_wstring(record->sequence),
                { x, y + Scale(24), page.graph.right, y + Scale(58) });
        }
        return;
    }
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
    auto& page = *reinterpret_cast<Page*>(data);
    if (msg == WM_KEYDOWN && wp == VK_TAB) {
        const std::array order{ page.createProject, page.open, page.switchView, page.retry, page.sampleChoice, page.replaySample, page.cancelChoice,
            page.livePid, page.liveProvider, page.liveStart, page.liveStop, page.liveFollow,
            page.categories, page.filter, page.apiOnly, page.etwOnly, page.networkOnly,
            page.evidenceFamily, page.locateEvidence,
            page.timeline.hwnd(), page.list.hwnd(), page.details, page.status };
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
    if (hwnd == page.locateEvidence && wp == VK_RETURN) {
        // 页面不是对话框，为此原生按钮补齐 Enter。空格仍由按钮自身处理。
        if (msg == WM_KEYDOWN) {
            if (!(lp & (1LL << 30)) && ::IsWindowEnabled(hwnd)) LocateEvidence(page);
            return 0;
        }
        if (msg == WM_CHAR) return 0;
    }
    if (msg == WM_CHAR && wp == L'\t') return 0;
    return ::DefSubclassProc(hwnd, msg, wp, lp);
}

bool CreateControls(Page& page) {
    page.createProject = Ui::CreateButton(page.hwnd, kCreateProject, L"新建工程…", 0, 0, 0, 0, Ui::ButtonRole::Primary);
    page.open = Ui::CreateButton(page.hwnd, kOpen, L"打开工程…", 0, 0, 0, 0);
    page.retry = Ui::CreateButton(page.hwnd, kRetry, L"重读上次路径", 0, 0, 0, 0);
    page.switchView = Ui::CreateButton(page.hwnd, kSwitchView, L"新一轮扫描", 0, 0, 0, 0);
    page.livePid = MakeEdit(page.hwnd, kLivePid, ES_AUTOHSCROLL | ES_NUMBER);
    page.liveProvider = MakeEdit(page.hwnd, kLiveProvider, ES_AUTOHSCROLL);
    page.liveStart = Ui::CreateButton(page.hwnd, kLiveStart, L"开始采集", 0, 0, 0, 0, Ui::ButtonRole::Primary);
    page.liveStop = Ui::CreateButton(page.hwnd, kLiveStop, L"停止采集", 0, 0, 0, 0);
    page.liveFollow = Ui::CreateButton(page.hwnd, kLiveFollow, L"暂停跟随", 0, 0, 0, 0);
    page.actions = Ui::CreateText(page.hwnd, 0, L"工程", 0, 0, 0, 0);
    page.capability = Ui::CreateText(page.hwnd, 0, L"一个工程可保存多次行为采样。", 0, 0, 0, 0);
    page.categories = Ui::CreateButton(page.hwnd, kCategories, L"无可筛选类别", 0, 0, 0, 0);
    page.filterLabel = Ui::CreateText(page.hwnd, 0, L"筛选记录", 0, 0, 0, 0);
    page.filter = MakeEdit(page.hwnd, kFilter, ES_AUTOHSCROLL);
    page.etwOnly = ::CreateWindowExW(0, L"BUTTON", L"只看 ETW", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEtwOnly)), ::GetModuleHandleW(nullptr), nullptr);
    page.apiOnly = ::CreateWindowExW(0, L"BUTTON", L"只看 API", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kApiOnly)), ::GetModuleHandleW(nullptr), nullptr);
    page.networkOnly = ::CreateWindowExW(0, L"BUTTON", L"只看网络", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kNetworkOnly)), ::GetModuleHandleW(nullptr), nullptr);
    page.evidenceFamilyLabel = Ui::CreateText(page.hwnd, 0, L"证据分类", 0, 0, 0, 0);
    page.evidenceFamily = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEvidenceFamily)),
        ::GetModuleHandleW(nullptr), nullptr);
    page.locateEvidence = Ui::CreateButton(page.hwnd, kLocateEvidence, L"定位原始记录", 0, 0, 0, 0);
    if (!page.switchView || !page.livePid || !page.liveProvider || !page.liveStart || !page.liveStop || !page.liveFollow ||
        !page.createProject || !page.open || !page.retry || !page.actions || !page.capability || !page.categories || !page.filterLabel ||
        !page.filter || !page.etwOnly || !page.apiOnly || !page.networkOnly || !page.evidenceFamilyLabel ||
        !page.evidenceFamily || !page.locateEvidence) return false;
    ::ShowWindow(page.evidenceFamilyLabel, SW_HIDE);
    ::ShowWindow(page.locateEvidence, SW_HIDE);
    ::EnableWindow(page.locateEvidence, FALSE);
    for (const auto control : {page.livePid, page.liveProvider, page.liveStart, page.liveStop, page.liveFollow}) {
        ::ShowWindow(control, SW_HIDE);
    }
    ::SendMessageW(page.livePid, EM_SETLIMITTEXT, 11, 0);
    ::SendMessageW(page.liveProvider, EM_SETLIMITTEXT, 39, 0);
    ::SendMessageW(page.livePid, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"自有进程 PID"));
    ::SendMessageW(page.liveProvider, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"ETW 提供程序 GUID"));
    ::EnableWindow(page.retry, FALSE);
    ::EnableWindow(page.categories, FALSE);
    ::EnableWindow(page.etwOnly, FALSE);
    ::EnableWindow(page.apiOnly, FALSE);
    ::EnableWindow(page.networkOnly, FALSE);
    ::SendMessageW(page.filter, EM_SETLIMITTEXT, 256, 0);
    ::SendMessageW(page.filter, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(L"筛选记录"));
    if (!page.timeline.create(page.hwnd, kTimeline, [&page](std::size_t index) {
        SetListSelection(page, index, true);
    })) return false;
    if (!page.list.create(page.hwnd, kRecords, 0, 0, 0, 0, WS_TABSTOP | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER)) return false;
    if (!page.list.addColumns({ { 0, 152, LVCFMT_LEFT, L"时间（接收 QPC）" }, { 1, 66, LVCFMT_RIGHT, L"PID" },
        { 2, 66, LVCFMT_RIGHT, L"TID" }, { 3, 76, LVCFMT_LEFT, L"进程" }, { 4, 240, LVCFMT_LEFT, L"事件 / 记录" },
        { 5, 168, LVCFMT_LEFT, L"来源 / API 分类" }, { 6, 90, LVCFMT_RIGHT, L"记录序号" } })) return false;
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
    AddButtonTip(page.tooltip, page.hwnd, page.createProject, L"在指定的新文件夹中建立一个行为分析工程");
    AddButtonTip(page.tooltip, page.hwnd, page.open, L"打开已有行为分析工程");
    AddButtonTip(page.tooltip, page.hwnd, page.retry, L"按上次请求的路径和采样身份重读");
    AddButtonTip(page.tooltip, page.hwnd, page.replaySample, L"从首段开始核验并回放当前采样的可读范围");
    AddButtonTip(page.tooltip, page.hwnd, page.cancelChoice, L"取消采样预览并回到当前工程");
    AddButtonTip(page.tooltip, page.hwnd, page.apiOnly, L"显示归档 API 线索。可与其他来源同时选择。");
    AddButtonTip(page.tooltip, page.hwnd, page.etwOnly, L"显示 ETW 观察。回放时可与其他来源同时选择。");
    AddButtonTip(page.tooltip, page.hwnd, page.networkOnly, L"显示已核验的归档网络流。可与其他来源同时选择。");
    AddButtonTip(page.tooltip, page.hwnd, page.evidenceFamily, L"选择当前预览窗口中已核验的 API 证据分类");
    AddButtonTip(page.tooltip, page.hwnd, page.locateEvidence, L"查看所选分类中最新一条原始记录。筛选隐藏该行时仍显示详情。");
    AddButtonTip(page.tooltip, page.hwnd, page.switchView, L"在当前工程中开始新一轮被动扫描，或返回工程目录");
    AddButtonTip(page.tooltip, page.hwnd, page.livePid, L"输入自有进程的十进制 PID");
    AddButtonTip(page.tooltip, page.hwnd, page.liveProvider, L"输入 ETW 提供程序 GUID 以观察指定进程并将记录归档");
    AddButtonTip(page.tooltip, page.hwnd, page.liveStop, L"停止观察并清退本次采集会话，可重试失败的清退");
    AddButtonTip(page.tooltip, page.hwnd, page.liveFollow, L"暂停或恢复结果更新，采集与归档继续运行");
    for (HWND child : {page.createProject, page.open, page.switchView, page.retry, page.sampleChoice, page.replaySample, page.cancelChoice,
        page.livePid, page.liveProvider, page.liveStart, page.liveStop, page.liveFollow,
        page.categories, page.filter, page.apiOnly, page.etwOnly, page.networkOnly,
        page.evidenceFamily, page.locateEvidence,
        page.timeline.hwnd(), page.list.hwnd(), page.details, page.status}) {
        if (!::SetWindowSubclass(child, NavigateControls, 1, reinterpret_cast<DWORD_PTR>(&page))) return false;
    }
    Ui::SetWindowFontRecursive(page.hwnd);
    UpdateLiveControls(page);
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
        if (wp == kCreateProject || wp == kReplaySample || wp == kLiveStart) {
            Ui::DrawThemedButton(*reinterpret_cast<const DRAWITEMSTRUCT*>(lp));
            return TRUE;
        }
        break;
    case WM_CTLCOLOREDIT:
        if (const auto child = reinterpret_cast<HWND>(lp); child == page->livePid || child == page->liveProvider) {
            auto& theme = Ui::AppTheme();
            const auto dc = reinterpret_cast<HDC>(wp);
            ::SetTextColor(dc, theme.textColor);
            ::SetBkColor(dc, theme.panelColor);
            return reinterpret_cast<LRESULT>(theme.panelBrush());
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
        if (HIWORD(wp) == BN_CLICKED && !page->retiring) {
            switch (LOWORD(wp)) {
            case kSwitchView: if (!page->catalogBusy) ToggleView(*page); return 0;
            case kLiveStart: StartLive(*page); return 0;
            case kLiveStop:
                page->liveStopRequested = true;
                page->live.Stop();
                RefreshLive(*page);
                return 0;
            case kLiveFollow:
                SetLiveFollow(*page, !page->followLive);
                RefreshLive(*page);
                return 0;
            }
        }
        if (LOWORD(wp) == kCreateProject && HIWORD(wp) == BN_CLICKED && !page->retiring && !page->catalogBusy) BrowseNewProject(*page);
        if (LOWORD(wp) == kOpen && HIWORD(wp) == BN_CLICKED && !page->retiring && !page->catalogBusy) Browse(*page);
        if (LOWORD(wp) == kRetry && HIWORD(wp) == BN_CLICKED) {
            if (!page->requestedSample && IsProjectReplayManifest(page->requestPath)) OpenCatalog(*page, page->requestPath);
            else Open(*page, page->requestPath, page->requestedSample);
        }
        if (LOWORD(wp) == kSampleChoice && (HIWORD(wp) == CBN_SELCHANGE || HIWORD(wp) == CBN_CLOSEUP)) {
            PreviewSelectedSample(*page);
        }
        if (LOWORD(wp) == kEvidenceFamily && (HIWORD(wp) == CBN_SELCHANGE || HIWORD(wp) == CBN_CLOSEUP)) {
            SetEvidenceFamilyChoice(*page);
        }
        if (LOWORD(wp) == kLocateEvidence && HIWORD(wp) == BN_CLICKED) LocateEvidence(*page);
        if (LOWORD(wp) == kReplaySample && HIWORD(wp) == BN_CLICKED) ReplaySelectedSample(*page);
        if (LOWORD(wp) == kCancelChoice && HIWORD(wp) == BN_CLICKED && !page->catalogBusy) {
            ::SendMessageW(page->sampleChoice, CB_SETCURSEL, static_cast<WPARAM>(-1), 0);
            ResetSamplePreview(*page);
            UpdateProjectControls(*page);
            page->requestStatus = L"已取消选择采样。";
            UpdateStatus(*page);
        }
        if (LOWORD(wp) == kCategories && HIWORD(wp) == BN_CLICKED && page->timeline.chooseCategories(page->categories)) ApplyFilter(*page);
        if ((LOWORD(wp) == kEtwOnly || LOWORD(wp) == kApiOnly || LOWORD(wp) == kNetworkOnly) && HIWORD(wp) == BN_CLICKED) {
            ApplyFilter(*page);
        }
        if (LOWORD(wp) == kFilter && HIWORD(wp) == EN_CHANGE && page->status && !page->applyingProjection) ApplyFilter(*page);
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
                SelectRecord(*page, index);
            }
        }
        break;
    }
    case WM_TIMER:
        if (wp == kLiveDisplayTimer) {
            RefreshLive(*page);
            return 0;
        }
        break;
    case WM_SHOWWINDOW:
        if (wp && page->status) RefreshLive(*page);
        break;
    case Ui::kBeginNativeRetirementMessage:
        page->retiring = true;
        page->liveStopRequested = true;
        page->live.BeginRetirement();
        if (page->liveStatus.active) RefreshLive(*page);
        return page->live.Ready() ? 0 : 1;
    case Ui::kPollNativeRetirementMessage:
        return page->live.Ready() ? 0 : 1;
    case Ui::kCancelNativeRetirementMessage:
        page->retiring = false;
        page->live.CancelRetirement();
        if (page->status) RefreshLive(*page);
        return 0;
    case kComplete:
        page->task->consume(hwnd, wp, lp);
        RefreshProjectAfterScan(*page);
        return 0;
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kLiveDisplayTimer);
        page->live.BeginRetirement();
        page->task.reset();
        if (page->snapshot) Ui::RetireBackgroundValue(page->snapshot);
        if (page->samplePreview) Ui::RetireBackgroundValue(page->samplePreview);
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
