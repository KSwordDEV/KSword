#include "ActionAnalyzePage.h"
#include "ExecutionGroupPage.h"
#include "DataWatchPage.h"
#include "../../Ui/WorkspaceHost.h"
#include "LightNativeControlToolbar.h"
#include "ApiTransferPresentation.h"
#include "ApiTransferCandidateTree.h"
#include "NetworkTrafficPage.h"
#include "NativeExecutionPresentation.h"

#include "EvidenceTimeline.h"
#include "NativeLiveSession.h"
#include "NetworkReplayPresentation.h"
#include "ProjectReplay.h"
#include "ProjectBreakpointPane.h"
#include "StoredEvidence.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ParameterWorkspace.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/BehaviorPresets.h"
#include "../../../shared/usermode/backend/process/ProcessControls.h"

#include <commdlg.h>
#include <objbase.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <iterator>
#include <map>
#include <string_view>
#include <utility>
#include <variant>

namespace Ksword::Features::ActionAnalyze {
namespace {

constexpr wchar_t kPageClass[] = L"KswordARKLight.ActionAnalyze";
constexpr UINT kComplete = WM_APP + 936;
constexpr UINT_PTR kLiveDisplayTimer = 1;
constexpr UINT kLiveDisplayIntervalMs = 400;
constexpr LPARAM kBehaviorGroup = -10; // 原关系树的前九个负值由候选、历史和网络根拥有。
constexpr LPARAM kBehaviorLeaf = -11; // 行下标向负方向编码，不占用原树的证据叶值。
enum ControlId {
    kOpen = 58301, kRetry, kCategories, kFilter, kTimeline, kRecords, kDetails, kStatus, kEtwOnly,
    kSampleChoice, kReplaySample, kCancelChoice, kApiOnly, kNetworkOnly,
    kSwitchView, kLivePid, kLiveProvider, kReservedLiveArchive, kLiveStart, kLiveStop, kLiveFollow, kCreateProject,
    kEvidenceFamily, kLocateEvidence, kEvidenceRecord, kLiveApi, kApiPid, kApiSession, kApiCreation, kApiBrowse, kApiPath, kApiSource,
    kTransferCandidates, kApiDuration, kPrepareExecutionAddress, kPrepareExecutionRange, kAutoTransfer,
    kApiExecutable, kApiExecutableBrowse, // 独立EXE草稿和选择动作，不复用JSONL路径。
    kApiNetworkTraffic, // 同采样网络来源草稿，三种实时API来源共用。
    kApiCaptureAgentEtw // 原参数页的配套ETW草稿，不创建独立页面。
};
static_assert(kApiCaptureAgentEtw <= MAXWORD, "WM_COMMAND carries control IDs in its low word");
using Ui::Scale;

using ApiFamilyGroups = std::map<std::wstring, std::vector<std::size_t>>;
using ks::r3::process::Utf8ToWide;
namespace Rules = Ksword::ActionAnalyze::Rules;
static_assert(kEvidenceRows <= Rules::MaxApiPresetRows);

struct ApiRuleDetails {
    std::string grouped; // 当前快照拥有的汇总规则 ID。
    std::string byCategory; // 同一观测的细分规则 ID。
    std::optional<Rules::ApiPresetBehavior> behavior; // 同一原包的证据和释义。
};

struct EvidenceGroup {
    std::wstring key;
    std::wstring label;
    std::vector<std::size_t> rows; // 只在拥有这些分组的不可变快照中解释行索引。
};

struct RawCoordinate {
    bool mixedEtwLane;
    std::uint64_t segment;
    std::uint64_t sequence;
    std::uint64_t block;
    std::uint64_t offset;
    bool operator==(const RawCoordinate&) const = default;
};

RawCoordinate CoordinateOf(const EvidenceRecord& row) {
    return {row.mixedEtwLane, row.segmentOrdinal, row.sequence, row.blockOrdinal, row.offset};
}

std::wstring RawLocation(const EvidenceRecord& row) {
    return (row.mixedEtwLane ? L"raw-etw/" : L"raw/") + std::to_wstring(row.segmentOrdinal) + L" #" + std::to_wstring(row.sequence);
}

struct Snapshot {
    std::wstring path; // 已打开的段或项目清单路径。
    std::optional<ProjectReplayRequest> sample; // 项目回放选择；独立段保持为空。
    SegmentEvidence evidence; // raw 段或独立证据段的本地值快照。
    ReplayCheckpoint checkpoint; // 本次项目重读核对的段范围。
    std::wstring mixedStatus; // 混采来源分别保留状态；表格合并不改变归档坐标。
    std::optional<CallbackReplayBatch> callback; // 非空代表完整核验的批次，可有零条观测。
    std::vector<EvidenceGroup> evidenceGroups;
    std::optional<std::vector<ApiRuleDetails>> apiRules; // 成功时与本快照的原始行索引对齐。
    std::wstring rulePresetSet; // 当前回放使用的规则集标识，可为空。
    std::wstring ruleSourceSha256; // 与本快照已准备谓词绑定的规则文件摘要。
    std::wstring ruleConfigError; // 外置规则库加载失败时的诊断，不改变原始证据。
    bool hasApi = false;
    bool hasNetwork = false; // 窗口中存在已核验的网络流。
    std::wstring classification; // 当前回放窗口的 API 分类与证据覆盖。
    std::shared_ptr<const std::vector<Ui::VirtualListRow>> presentation; // 后台生成的虚拟表行。
};

using LoadResult = std::variant<Snapshot, ProjectReplayCatalog>; // 同一异步任务处理三种打开请求。

struct EvidenceDropdown {
    HWND control;
    LRESULT originalSelection;
    bool canceled = false;
};

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
    HWND liveApi = nullptr, apiPid = nullptr, apiSession = nullptr, apiCreation = nullptr, apiBrowse = nullptr, apiPath = nullptr;
    HWND apiSource = nullptr;
    HWND apiExecutable = nullptr, apiExecutableBrowse = nullptr; // 启动采集独立路径及选择器。
    HWND apiExecutableLabel = nullptr; // 普通EXE可见标签，不要求手填实例身份。
    HWND autoTransfer = nullptr; // 活API采样的调用前接管策略，开始时冻结。
    Ui::ParameterWorkspace apiParameters; // API 参数独立滚动，固定动作和原有结果视口不参与滚动。
    HWND apiSourceLabel = nullptr, apiPidLabel = nullptr, apiCreationLabel = nullptr; // 活采的可见身份标签。
    HWND apiSessionLabel = nullptr, apiPathLabel = nullptr; // 文件来源专用字段，不进入活采请求。
    HWND apiDurationLabel = nullptr; // 活采时限的可见单位与持续语义。
    HWND apiDuration = nullptr; // 用现有下拉输入选择时长，item data保存毫秒值。
    HWND apiNetworkTrafficLabel = nullptr; // 同采样网络来源的可见标签。
    HWND apiNetworkTraffic = nullptr; // 默认关闭；JSONL禁用但保留草稿，不创建网络独立会话。
    HWND apiCaptureAgentEtw = nullptr; // 普通checkbox；运行冻结，JSONL禁用但保留勾选草稿。
    bool apiConfirming = false; // 本轮确认框阻断重入开始，确认不保留到下一轮。
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
    HWND evidenceRecordLabel = nullptr;
    HWND evidenceRecord = nullptr;
    HWND locateEvidence = nullptr;
    HWND actions = nullptr;
    HWND capability = nullptr;
    HWND projection = nullptr;
    HWND details = nullptr;
    HWND status = nullptr;
    EvidenceTimeline timeline;
    ApiTransferCandidateTree transferTree; // 当前回放的写入与创建来源声明候选。
    HTREEITEM behaviorGroup = nullptr; // 行为组复用同一关系树，不创建额外控件。
    std::vector<RawCoordinate> behaviorCoordinates; // 只保存已发布行为叶的原包身份，不借用快照地址。
    LANGID behaviorLanguage = ::GetThreadUILanguage(); // Light 无应用语言管理器，沿用当前线程 UI 语言。
    HWND prepareExecutionAddress = nullptr, prepareExecutionRange = nullptr; // 当前树来源的两种显式草稿动作。
    std::optional<EvidenceRecord> selectedCandidate; // 原包已滚出列表时仍供共享详情读取。
    std::optional<Ksword::Evidence::ApiNativeExecutionCandidate<EvidenceRecord>> selectedExecution; // 只读原生来源，与 API 原行分别保存。
    std::optional<Ksword::Evidence::NativeExecutionHistoryEntry> selectedNativeHistory; // 独立历史选择，不依赖API候选。
    std::optional<SegmentIdentity> candidateScope; // 独立于目录草稿保留当前候选的采样身份。
    std::optional<ProjectReplayRequest> candidateSample; // 同一路径切换采样时禁止复用旧候选选择。
    std::wstring candidatePath; // 独立段与项目入口的真实读取路径。
    Ui::VirtualListView list;
    std::unique_ptr<Ui::AsyncSnapshotTask<LoadResult>> task;
    std::optional<std::pair<WPARAM, LPARAM>> deferredRead; // 异步完成消息的任务身份及代次。
    std::shared_ptr<const Snapshot> snapshot;
    std::shared_ptr<const Snapshot> samplePreview;
    std::optional<ProjectReplayRequest> previewRequest;
    NativeLiveSession live;
    NativeLiveSnapshot liveStatus;
    std::optional<NativeLiveProjection> liveProjection;
    std::wstring requestPath;
    std::optional<ProjectReplayRequest> requestedSample; // 重读保留上次提交的完整请求。
    std::optional<std::uint64_t> apiPrefixAttempt; // 正在跟随的同一回放已尝试的最高段号。
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
    std::optional<ProjectReplayRequest> evidenceFamilySample;
    std::wstring evidenceFamilyPath;
    std::wstring evidenceFamilyChoice; // 分类草稿用稳定类别值保存，不用控件下标。
    std::optional<RawCoordinate> evidenceRecordChoice;
    std::optional<EvidenceDropdown> evidenceDropdown;
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

const Snapshot* BrowsableArchive(const Page& page) {
    const auto* archive = page.liveView ? nullptr : DisplayedArchive(page);
    return archive && !archive->evidenceGroups.empty() ? archive : nullptr;
}

constexpr wchar_t kRelationshipCoverage[] = L"证据关系 · 当前回放未核验进程／线程关系及执行链。";

bool ApiMode(const Page& page) { return ::SendMessageW(page.liveApi, BM_GETCHECK, 0, 0) == BST_CHECKED; }
bool CooperativeMode(const Page& page) { return ::SendMessageW(page.apiSource, CB_GETCURSEL, 0, 0) == 1; }

// 只解释当前草稿选择；已有结果始终读取本次 worker 回执上的来源标记。
bool AttachmentMode(const Page& page) {
    return ::SendMessageW(page.apiSource, CB_GETCURSEL, 0, 0) == 2;
}

// 两种活管道都不使用外部文件/session；准入确认仍由各自模式独立处理。
// 第四来源创建本次自有EXE；结果实例只由后台创建句柄发布。
bool LaunchApiMode(const Page& page) {
    return ::SendMessageW(page.apiSource, CB_GETCURSEL, 0, 0) == 3;
}

bool LiveApiMode(const Page& page) {
    return CooperativeMode(page) || AttachmentMode(page) || LaunchApiMode(page);
}

const SegmentEvidence* DisplayedEvidence(const Page& page) {
    if (page.liveView) return !ApiMode(page) && page.liveProjection ? &page.liveProjection->evidence : nullptr;
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
    if (row.callback) return L"线程创建回调 · 源序号 " + std::to_wstring(row.callback->sourceSequence);
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
    // 恢复请求与实际执行分别呈现，零旧挂起计数不显示为失败。
    if (family == L"thread-resume")
    {
        return L"线程恢复请求";
    }
    if (family == L"section-map") return L"节映射";
    // 生命周期分类沿用现有详情分组，不由调用成功推断内容或执行。
    if (family == L"memory-allocation")
    {
        return L"内存分配";
    }
    if (family == L"memory-protection")
    {
        return L"内存保护变更";
    }
    if (family == L"memory-free-request")
    {
        return L"内存释放请求";
    }
    if (family == L"memory-unmap-request")
    {
        return L"解除映射请求"; // 独立分类，不使用Free或保护变更标签。
    }
    // 新类别沿用原分类展示入口，名称不宣称执行、连接或持久化已生效。
    const std::pair<std::wstring_view, std::wstring_view> labels[] = {
        {L"registry-query", L"注册表查询"},
        {L"registry-write", L"注册表值写入"},
        {L"process-enumeration", L"进程枚举"},
        {L"module-query", L"模块查询"},
        {L"system-query", L"系统信息查询"},
        {L"process-start", L"进程创建请求"},
        {L"file-open", L"文件句柄打开"},
        {L"file-copy", L"文件复制"},
        {L"file-write", L"文件写入"},
        {L"service-control", L"服务管理调用"},
        {L"network-name-query", L"名称解析调用"},
        {L"network-session", L"网络会话句柄"},
        {L"network-request", L"HTTP 请求调用"},
        {L"process-query", L"进程信息查询"},
    }; // 已核验分类键与用户可见名称的固定映射，不改变现有页面结构。
    for (const auto& [key, label] : labels)
    {
        if (family == key)
        {
            return std::wstring(label);
        }
    }
    return std::wstring(family);
}

std::wstring ClassificationSummary(const ApiFamilyGroups& families, std::uint64_t verifiedApiClues) {
    if (families.empty()) return L"敏感 API 分类：此预览窗口无已核验线索。";
    std::wstring summary = L"敏感 API 分类（当前预览窗口）：";
    std::size_t shown = 0;
    for (const auto& [family, rows] : families) {
        if (shown) summary += L" / ";
        summary += ApiFamilyLabel(family) + L" " + std::to_wstring(rows.size());
        shown += rows.size();
    }
    if (verifiedApiClues > shown) summary += L" · 已核验线索共 " + std::to_wstring(verifiedApiClues) + L" 条";
    return summary;
}

// API 名和分类来自已核验的 ASCII 目录，转换只用于共享求值器的输入。
std::string NarrowApiText(std::wstring_view text) {
    std::string ascii;
    ascii.reserve(text.size());
    for (const auto character : text) {
        ascii.push_back(static_cast<char>(character));
    }
    return ascii;
}

// 把一条已核验归档记录转换为规则引擎唯一认可的证据投影，不读取当前系统状态。
Rules::ApiPresetEvidence RuleEvidenceOf(const EvidenceRecord& record)
{
    Rules::ApiPresetEvidence evidence; // 当前归档行拥有的规则输入集合。
    evidence.actorPid = record.headerPid.value_or(0); // 仅保留原包报头 PID，零表示原包没有提供。
    evidence.memory = record.apiMemoryLifecycle; // 复制 AAIM1 的有效位与请求/返回字段。
    evidence.apc = record.apiApc; // 复制 AAAP1 的线程、例程和目标身份字段。
    evidence.apcOutcome = record.apcOutcome; // 保留原始入队结果，不把请求当成执行结果。
    evidence.context = record.apiContext; // 复制 AACT1 的上下文请求字段。
    evidence.contextOutcome = record.contextOutcome; // 保留原始上下文调用结果。
    evidence.map = record.apiSectionMap; // 复制 AASM1 的节映射请求及返回字段。
    evidence.mapOutcome = record.sectionMapOutcome; // 保留原始映射调用结果。
    evidence.behavior = record.behaviorObservation; // 复制普通强类型返回及严格解码参数。
    return evidence;
}

// 在项目或独立归档回放后台用同一份规则库处理已核验窗口，写入快照中的规则回执和加载诊断。
void EvaluateReplayApiRules(Snapshot& snapshot) {
    const auto database = Rules::LoadApiPresetDatabase(); // 两种配置均使用这次读取的版本。
    if (!database.error.empty()) {
        snapshot.ruleConfigError = Utf8ToWide(database.error);
        return;
    }
    snapshot.rulePresetSet = Utf8ToWide(database.presetSet);
    snapshot.ruleSourceSha256 = Utf8ToWide(database.sourceSha256);
    const auto& evidence = snapshot.evidence; // 归档仍归快照所有，规则失败不影响浏览。
    struct InputText {
        std::size_t rowIndex; // 线索在当前快照中的原始行索引。
        std::string api; // 精确导出名，供求值器同步借用。
        std::string family; // 已核验的 API 分类。
    };
    std::vector<InputText> input; // 为两个预置调用持有字符串和原始行关联。
    input.reserve(evidence.rows.size());
    std::vector<Rules::ArchivedApiObservation> observations; // 保留实际归档顺序与两种序号。
    observations.reserve(evidence.rows.size());
    for (std::size_t index = 0; index < evidence.rows.size(); ++index) {
        const auto& row = evidence.rows[index]; // 已提交检查点或已核验导入尾记中的一条记录。
        if (row.apiClue.empty()) {
            continue;
        }
        const auto& text = input.emplace_back(InputText{index, NarrowApiText(row.apiClue), NarrowApiText(row.apiFamily)});
        const auto& outcome = row.memoryWriteReturn; // 同一归档行的显式内存写入返回值。
        observations.push_back({row.sequence, row.apiSourceSequence, text.api, text.family,
            outcome ? std::optional{Rules::ArchivedApiMemoryWriteReturn{outcome->returned, outcome->statusCode}} : std::nullopt,
            RuleEvidenceOf(row)}); // 只传递已核验原包的拥有型值，不读取预览或活状态。
    }

    // 项目回放使用已核验前缀；独立归档使用完整读取器确认的行数，不把两种边界混为一谈。
    const auto analyze = [&](Rules::ApiPresetProfile profile) {
        return snapshot.sample ? Rules::AnalyzeVerifiedApiPresetPage(database, observations, evidence.apiClues, profile)
            : Rules::AnalyzeArchivedApiPresets(database, observations, evidence.apiClues, profile);
    };
    auto grouped = analyze(Rules::ApiPresetProfile::Grouped); // 汇总规则与 Qt/CLI 使用同一份配置。
    auto byCategory = analyze(Rules::ApiPresetProfile::ByCategory); // 细分规则保留原始归档坐标。
    if (grouped.error != Rules::ApiPresetError::None || byCategory.error != Rules::ApiPresetError::None ||
        grouped.matches.size() != input.size() || byCategory.matches.size() != input.size()) {
        return;
    }

    // 两种配置都要与同一条原始坐标相符，再把拥有型文本移入快照。
    std::vector<ApiRuleDetails> details(evidence.rows.size()); // 索引与快照的未筛选原始行一致。
    for (std::size_t index = 0; index < input.size(); ++index) {
        const auto& observation = observations[index]; // 当前回放输入的两套序号。
        auto& group = grouped.matches[index]; // 实际汇总规则和原包坐标。
        auto& category = byCategory.matches[index]; // 实际细分规则和原包坐标。
        if (group.rawSequence != observation.rawSequence || group.sourceSequence != observation.sourceSequence ||
            category.rawSequence != observation.rawSequence || category.sourceSequence != observation.sourceSequence) {
            return;
        }
        details[input[index].rowIndex] = {std::move(group.ruleId), std::move(category.ruleId), std::move(category.behavior)};
    }
    snapshot.apiRules = std::move(details);
}

// 根据冻结采样请求启用项目检查点核验。
Snapshot Load(const std::wstring& path, const std::optional<ProjectReplayRequest>& sample,
    ProjectReplayMode mode = ProjectReplayMode::Explicit) {
    Snapshot snapshot; // 只有完成后台工作后才由 UI 决定是否发布。
    snapshot.path = path;
    snapshot.sample = sample;
    if (sample) {
        auto replay = ReadProjectReplay(*sample, mode);
        snapshot.mixedStatus = DescribeMixedReplay(replay);
        snapshot.evidence = std::move(replay.raw);
        snapshot.checkpoint = std::move(replay.checkpoint);
        snapshot.callback = std::move(replay.callback);
        if (replay.mixedEtw) {
            // 各流保留自己的有界窗口和归档顺序，不据此推断跨来源的时间顺序。
            auto& etw = replay.mixedEtw->raw;
            if (!snapshot.evidence.identity) snapshot.evidence.identity = std::move(etw.identity);
            auto& combined = snapshot.evidence.rows;
            combined.reserve(combined.size() + etw.rows.size());
            combined.insert(combined.end(), std::make_move_iterator(etw.rows.begin()), std::make_move_iterator(etw.rows.end()));
        }
    } else {
        snapshot.evidence = OpenStoredEvidence(path);
    }

    // 保持单段与项目回放的行结构一致，现有筛选、时间线及详情共享它。
    auto rows = std::make_shared<std::vector<Ui::VirtualListRow>>(); // 表格的后台值数据。
    rows->reserve(snapshot.evidence.rows.size());
    ApiFamilyGroups apiFamilies;
    EvidenceGroup etw{L"source.etw", L"来源上下文 · ETW", {}};
    EvidenceGroup network{L"source.network", L"来源上下文 · 网络", {}};
    EvidenceGroup callback{L"source.kswordark.callback", L"来源上下文 · KSword 回调", {}};
    using ks::cli::action_analyze::archive::StreamKind;
    const bool isRaw = snapshot.evidence.identity &&
        snapshot.evidence.identity->streamKind == static_cast<std::uint32_t>(StreamKind::Raw);
    for (const auto& record : snapshot.evidence.rows) {
        if (record.segmentOrdinal) {
            // API 归档可来自 Records 流；不能用 Raw 流判断挡住合作 API 的规则回放。
            if (!record.apiClue.empty() && !record.apiFamily.empty()) {
                apiFamilies[record.apiFamily].push_back(rows->size());
            } else if (isRaw && record.etw) {
                etw.rows.push_back(rows->size());
            } else if (isRaw && record.network) {
                network.rows.push_back(rows->size());
            } else if (isRaw && record.callback) {
                callback.rows.push_back(rows->size());
            }
        }
        snapshot.hasNetwork |= record.network.has_value();
        Ui::VirtualListRow row;
        row.stableKey = snapshot.mixedStatus.empty() ? std::to_wstring(record.sequence) : RawLocation(record);
        row.itemData = static_cast<LPARAM>(rows->size());
        const auto pid = record.callback ? std::to_wstring(record.callback->targetPid) :
            record.network ? std::to_wstring(record.network->flow.observation.processId) : Number(record.headerPid);
        const auto tid = record.callback ? std::to_wstring(record.callback->targetTid) : Number(record.headerTid);
        auto source = !record.apiFamily.empty() ? ApiFamilyLabel(record.apiFamily) + L" · " + record.apiFamily :
                record.callback ? WideAscii(Ksword::ActionAnalyze::kProjectCallbackSourceId) :
                record.network ? L"网络 · " + WideAscii(record.network->source.sourceId) :
                record.etw ? WideAscii(record.etw->providerId) : snapshot.mixedStatus.empty() ? Number(record.sourceDictionaryId) :
                record.mixedEtwLane ? std::wstring(L"ETW · 归档记录") : std::wstring(L"被动 API · 归档记录");
        row.cells = { Number(record.receiveQpc), pid, tid, record.callback ? L"目标提示" : L"—",
            RecordName(record), std::move(source), std::to_wstring(record.sequence) };
        rows->push_back(std::move(row));
    }
    snapshot.hasApi = !apiFamilies.empty();
    snapshot.classification = ClassificationSummary(apiFamilies, snapshot.evidence.apiClues);
    if (snapshot.hasApi || (snapshot.sample &&
        (snapshot.checkpoint.kind == ReplayCheckpointKind::PassiveApi && snapshot.checkpoint.lastVerifiedOrdinal))) {
        EvaluateReplayApiRules(snapshot);
    }
    for (auto& [family, members] : apiFamilies) {
        snapshot.evidenceGroups.push_back({family, L"未解析候选 · " + ApiFamilyLabel(family), std::move(members)});
    }
    if (!etw.rows.empty()) snapshot.evidenceGroups.push_back(std::move(etw));
    if (!network.rows.empty()) snapshot.evidenceGroups.push_back(std::move(network));
    if (!callback.rows.empty()) snapshot.evidenceGroups.push_back(std::move(callback));
    snapshot.presentation = std::move(rows);
    return snapshot;
}

// 标题与详情共同投影已求值的双语原值，语言变化不重新读取规则库。
const std::string& BehaviorSummary(const Rules::ApiPresetBehavior& behavior, LANGID language)
{
    if (PRIMARYLANGID(language) == LANG_CHINESE && !behavior.summaryZh.empty())
    {
        return behavior.summaryZh;
    }
    return behavior.summary.empty() ? behavior.summaryZh : behavior.summary;
}

// 普通分类回执没有 behavior，不能据此展示为已解释的行为。
bool HasArchivedBehaviors(const Snapshot& snapshot)
{
    return snapshot.apiRules && std::any_of(snapshot.apiRules->begin(), snapshot.apiRules->end(),
        [](const ApiRuleDetails& rules) { return rules.behavior.has_value(); });
}

// 树中只存稳定坐标；发布新快照前仍可读取旧行为选择，不依赖当前表格行号。
std::optional<RawCoordinate> SelectedBehaviorCoordinate(const Page& page)
{
    TVITEMW item{};
    item.mask = TVIF_PARAM;
    item.hItem = TreeView_GetSelection(page.transferTree.hwnd());
    if (!item.hItem || !TreeView_GetItem(page.transferTree.hwnd(), &item) || item.lParam > kBehaviorLeaf)
    {
        return std::nullopt;
    }
    const auto index = static_cast<std::size_t>(kBehaviorLeaf - item.lParam);
    return index < page.behaviorCoordinates.size() ? std::optional(page.behaviorCoordinates[index]) : std::nullopt;
}

struct BehaviorTreeState
{
    bool expanded = true;
    bool groupSelected = false;
    std::optional<RawCoordinate> selected;
};

// 与原 API、网络树一样，范围不变时恢复展开和选择；换采样不沿用旧节点身份。
BehaviorTreeState CaptureBehaviorTreeState(const Page& page, bool sameScope)
{
    BehaviorTreeState state;
    if (sameScope && page.behaviorGroup)
    {
        const auto tree = page.transferTree.hwnd();
        state.expanded = (TreeView_GetItemState(tree, page.behaviorGroup, TVIS_EXPANDED) & TVIS_EXPANDED) != 0;
        state.groupSelected = TreeView_GetSelection(tree) == page.behaviorGroup;
        state.selected = SelectedBehaviorCoordinate(page);
    }
    return state;
}

// 只追加当前不可变快照中真实带行为解释的原行，和原候选、网络根共用主题及滚动。
void ProjectBehaviorTree(Page& page, const Snapshot* archive, const BehaviorTreeState& state)
{
    page.behaviorGroup = nullptr;
    page.behaviorCoordinates.clear();
    page.behaviorLanguage = ::GetThreadUILanguage();
    if (!archive || !archive->apiRules)
    {
        return;
    }
    const auto tree = page.transferTree.hwnd();
    const auto insert = [&](HTREEITEM parent, const std::wstring& text, LPARAM value)
    {
        TVINSERTSTRUCTW item{};
        item.hParent = parent;
        item.hInsertAfter = TVI_LAST;
        item.item.mask = TVIF_TEXT | TVIF_PARAM;
        item.item.pszText = const_cast<wchar_t*>(text.c_str());
        item.item.lParam = value;
        return TreeView_InsertItem(tree, &item);
    };
    for (std::size_t index = 0; index < archive->evidence.rows.size() && index < archive->apiRules->size(); ++index)
    {
        const auto& row = archive->evidence.rows[index];
        const auto& behavior = (*archive->apiRules)[index].behavior;
        if (!behavior || row.apiClue.empty())
        {
            continue;
        }
        if (!page.behaviorGroup)
        {
            page.behaviorGroup = insert(TVI_ROOT,
                PRIMARYLANGID(page.behaviorLanguage) == LANG_CHINESE ? L"行为规则" : L"Behavior Rules", kBehaviorGroup);
        }
        const auto& summary = BehaviorSummary(*behavior, page.behaviorLanguage);
        const auto title = Utf8ToWide(summary.empty() ? behavior->ruleId : summary) +
            L" · " + RawLocation(row) + L" · " + row.apiClue;
        const auto leaf = insert(page.behaviorGroup, title,
            kBehaviorLeaf - static_cast<LPARAM>(page.behaviorCoordinates.size()));
        page.behaviorCoordinates.push_back(CoordinateOf(row));
        if (state.selected == CoordinateOf(row))
        {
            TreeView_SelectItem(tree, leaf);
        }
    }
    if (page.behaviorGroup && state.expanded)
    {
        TreeView_Expand(tree, page.behaviorGroup, TVE_EXPAND);
    }
    if (page.behaviorGroup && state.groupSelected)
    {
        TreeView_SelectItem(tree, page.behaviorGroup);
    }
}

// 激活时再次核对当前快照的同一坐标及行为回执，交给原有证据行定位路径。
const EvidenceRecord* SelectedBehaviorRecord(const Page& page)
{
    const auto coordinate = SelectedBehaviorCoordinate(page);
    const auto* archive = page.liveView ? nullptr : DisplayedArchive(page);
    if (!coordinate || !archive || !archive->apiRules)
    {
        return nullptr;
    }
    for (std::size_t index = 0; index < archive->evidence.rows.size() && index < archive->apiRules->size(); ++index)
    {
        const auto& row = archive->evidence.rows[index];
        if (CoordinateOf(row) == *coordinate && (*archive->apiRules)[index].behavior && !row.apiClue.empty())
        {
            return &row;
        }
    }
    return nullptr;
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
    const bool api = page.liveView && ApiMode(page);
    const bool cooperative = api && LiveApiMode(page); // 活管道共享布局，来源模式不影响实例身份。
    const int modeWidth = Scale(94), modeX = inset + switchWidth + gap;
    const int identityX = modeX + modeWidth + gap;
    const int pidWidth = Scale(110), providerMin = Scale(152), actionWidth = Scale(110);
    const bool liveSingleRow = width >= switchWidth + modeWidth + pidWidth + providerMin + 3 * actionWidth + 6 * gap;
    const bool liveWrapInputs = width < switchWidth + modeWidth + pidWidth + providerMin + 3 * gap;
    const int apiBrowseWidth = Scale(138);
    const int liveToolbarRows = liveSingleRow ? 1 : liveWrapInputs ? 3 : 2; // ETW保留原有工具行换列。
    const std::array apiActions{page.liveStart, page.liveStop, page.liveFollow}; // 复用共享动作换行度量。
    const int apiActionHeight = Ui::LayoutParameterActions(apiActions, inset, inset, width, actionWidth, height, gap, false);
    const int apiParameterHeight = std::clamp(static_cast<int>(area.bottom) / 3, Scale(80), Scale(210)); // 结果仍保留主体空间。
    const int toolbarTop = inset + (api ? controlStep + apiParameterHeight + gap + apiActionHeight + gap :
        page.liveView ? liveToolbarRows * controlStep :
        side ? 0 : height + Scale(28));
    const int choiceButtonWidth = Scale(98);
    const int choiceButtonsWidth = 2 * choiceButtonWidth + gap;
    const bool stackedChoice = mainRight - mainX < Scale(300) + choiceButtonsWidth + gap;
    const int choiceHeight = page.liveView || page.choices.empty() ? 0 : (stackedChoice ? 2 : 1) * controlStep;
    const int top = toolbarTop + choiceHeight; // 样本草稿仅占用表格上方自然高度。
    const int sourceWidth = Scale(88); // 三个来源开关保持同宽，对齐为一组。
    const int sourcesWidth = api ? 0 : page.liveView ? sourceWidth : sourceWidth * 3 + gap * 2;
    const bool wrapSources = !api && mainRight - mainX < sourcesWidth + gap + Scale(125);
    const bool showEvidenceNavigation = BrowsableArchive(page) != nullptr;
    const int evidenceTop = top + (wrapSources ? 2 : 1) * controlStep;
    const int evidenceMinimum = Scale(610);
    const int evidenceX = mainRight - mainX >= evidenceMinimum ? mainX : inset;
    const bool wrapEvidence = mainRight - evidenceX < evidenceMinimum;
    const int resultTop = evidenceTop + (showEvidenceNavigation ? (wrapEvidence ? 2 : 1) * controlStep : 0);
    const int statusHeight = Scale(api ? 94 : 62);
    const int bottom = (std::max)(resultTop + Scale(24), static_cast<int>(area.bottom) - inset - statusHeight);
    const int available = bottom - resultTop;
    const int detailHeight = available / 3;
    const auto* candidateArchive = page.liveView ? nullptr : DisplayedArchive(page); // 与下方详情共用发布快照。
    const bool showCandidates = candidateArchive && (!candidateArchive->evidence.transferCandidates.empty() ||
        !candidateArchive->evidence.apcTransferCandidates.empty() ||
        !candidateArchive->evidence.contextTransferCandidates.empty() ||
        HasArchivedBehaviors(*candidateArchive) ||
        candidateArchive->evidence.evictedTransferWrites ||
        candidateArchive->evidence.nativeExecution.state != Ksword::Evidence::NativeHistoryState::NotRequested); // 成功空历史与失败也显示状态。
    const int graphHeight = showCandidates ? (std::min)(Scale(150), available / 3) :
        !page.liveView && available >= Scale(350) ? Scale(68) : 0;
    const int graphTop = bottom - detailHeight - graphHeight;
    auto move = [](HWND hwnd, int x, int y, int w, int h) {
        ::MoveWindow(hwnd, x, y, (std::max)(1, w), (std::max)(1, h), TRUE);
    };
    ::ShowWindow(page.actions, side ? SW_SHOW : SW_HIDE);
    if (page.liveView) {
        move(page.switchView, inset, inset, switchWidth, height);
        move(page.liveApi, modeX, inset, modeWidth, height);
        if (api) {
            // 标签与输入自然排列，只有参数正文滚动；正文宽度扣除共享滚动条及16px内边距。
            const int edge = Scale(16); // 参数画布四边等宽。
            const int fieldWidth = (std::max)(1, width - ::GetSystemMetrics(SM_CXVSCROLL) - 2 * edge);
            int y = edge; // 按可见参数累计自然高度，不把剩余空间平均分到输入行。
            const auto field = [&](HWND label, HWND input, bool combo = false) {
                move(label, edge, y, fieldWidth, Scale(22));
                y += Scale(22);
                move(input, edge, y, fieldWidth, combo ? height * 5 : height);
                y += height + gap;
            };
            field(page.apiSourceLabel, page.apiSource, true);
            if (LaunchApiMode(page))
            {
                field(page.apiExecutableLabel, page.apiExecutable);
                move(page.apiExecutableBrowse, edge, y, (std::min)(apiBrowseWidth, fieldWidth), height);
                y += height + gap; // 选择路径属于参数正文，动作与结果仍由原workspace负责。
            }
            else
            {
                field(page.apiPidLabel, page.apiPid);
                field(page.apiCreationLabel, page.apiCreation);
            }
            if (cooperative) {
                field(page.apiDurationLabel, page.apiDuration, true);
            }
            field(page.apiNetworkTrafficLabel, page.apiNetworkTraffic, true); // 文件模式也展示禁用草稿。
            move(page.apiCaptureAgentEtw, edge, y, fieldWidth, height);
            y += height + gap; // 配套ETW自然高度加入原参数画布，固定动作与结果不变。
            if (cooperative) {
                move(page.autoTransfer, edge, y, fieldWidth, height);
                y += height + gap; // 自然高度加入原参数滚动画布。
            }
            if (!cooperative) {
                field(page.apiSessionLabel, page.apiSession);
                field(page.apiPathLabel, page.apiPath);
                move(page.apiBrowse, edge, y, (std::min)(apiBrowseWidth, fieldWidth), height);
                y += height + gap;
            }
            page.apiParameters.Layout(inset, inset + controlStep, width, apiParameterHeight, y + edge);
            Ui::LayoutParameterActions(apiActions, inset, inset + controlStep + apiParameterHeight + gap,
                width, actionWidth, height, gap);
        } else {
            const int pidX = identityX;
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
        }
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
    const int filterRight = api || wrapSources ? mainRight : sourceX - gap;
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
        const int labelWidth = Scale(74), locateWidth = Scale(125);
        const int groupX = evidenceX + labelWidth;
        const int locateX = mainRight - locateWidth;
        const int groupWidth = wrapEvidence ? mainRight - groupX : (locateX - groupX - labelWidth - 2 * gap) / 2;
        const int recordLabelX = wrapEvidence ? evidenceX : groupX + groupWidth + gap;
        const int recordX = recordLabelX + labelWidth;
        const int recordY = evidenceTop + (wrapEvidence ? controlStep : 0);
        move(page.evidenceFamilyLabel, evidenceX, evidenceTop + Scale(4), labelWidth, height - Scale(4));
        move(page.evidenceFamily, groupX, evidenceTop, groupWidth, height * 8);
        ::SendMessageW(page.evidenceFamily, CB_SETDROPPEDWIDTH, (std::max)(1, (std::min)(Scale(300), mainRight - groupX)), 0);
        move(page.evidenceRecordLabel, recordLabelX, recordY + Scale(4), labelWidth, height - Scale(4));
        move(page.evidenceRecord, recordX, recordY, locateX - recordX - gap, height * 10);
        ::SendMessageW(page.evidenceRecord, CB_SETDROPPEDWIDTH, (std::max)(1, (std::min)(Scale(440), mainRight - recordX)), 0);
        move(page.locateEvidence, locateX, recordY, locateWidth, height);
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
    if (!showCandidates && ::GetFocus() == page.transferTree.hwnd()) {
        ::SetFocus(page.filter); // 切回实时或无候选范围时，键盘焦点回到可见筛选入口。
    }
    ::ShowWindow(page.transferTree.hwnd(), showCandidates ? SW_SHOW : SW_HIDE);
    ::ShowWindow(page.prepareExecutionAddress, showCandidates ? SW_SHOW : SW_HIDE);
    ::ShowWindow(page.prepareExecutionRange, showCandidates ? SW_SHOW : SW_HIDE);
    if (showCandidates) {
        const int actionWidth = (width - gap) / 2; // 两个简短动作同排等高，保留树作为本区主要内容。
        move(page.prepareExecutionAddress, inset, graphTop, actionWidth, height);
        move(page.prepareExecutionRange, inset + actionWidth + gap, graphTop, width - actionWidth - gap, height);
        move(page.transferTree.hwnd(), inset, graphTop + height + gap, width, (std::max)(0, graphHeight - height - 2 * gap));
    }
    move(page.details, inset, graphTop + graphHeight, width, detailHeight - gap);
    move(page.status, inset, bottom, width, statusHeight);
    ::InvalidateRect(page.hwnd, nullptr, FALSE);
}

const EvidenceRecord* SelectedRecord(const Page& page) {
    if (!page.liveView && page.selectedCandidate) {
        return &*page.selectedCandidate; // 表外候选仍从同一已发布范围进入现有详情。
    }
    const auto* evidence = DisplayedEvidence(page);
    if (!evidence || !page.selected || *page.selected >= evidence->rows.size()) return nullptr;
    return &evidence->rows[*page.selected];
}

// UpdateDetails 传入当前快照与详情行；按稳定坐标返回规则结果，未匹配时返回空。
const ApiRuleDetails* RuleDetailsForRecord(const Snapshot& snapshot, const EvidenceRecord& record)
{
    if (!snapshot.apiRules)
    {
        return nullptr; // 规则加载或求值失败时不伪造空命中。
    }
    const auto& rows = snapshot.evidence.rows; // 规则结果与未经筛选的原始行保持同一索引。
    const auto& details = *snapshot.apiRules; // 当前回放拥有的规则结果快照。
    const auto limit = (std::min)(rows.size(), details.size()); // 防止旧档或失败快照发生越界。
    for (std::size_t index = 0; index < limit; ++index)
    {
        if (CoordinateOf(rows[index]) == CoordinateOf(record))
        {
            return &details[index]; // 坐标匹配后返回同一行的汇总、细分和行为结果。
        }
    }
    return nullptr; // 表外行不在当前规则结果范围时保持未知。
}

// 从当前归档行生成底部证据标签，返回空串表示没有受支持的来源分类。
std::wstring ArchivedRelationText(const EvidenceRecord& record) {
    if (!record.segmentOrdinal) {
        return {};
    }
    const wchar_t* kind = nullptr; // 标签只表达回放器识别出的来源或候选。
    if (!record.apiFamily.empty()) {
        kind = L"未解析候选";
    } else if (record.callback) {
        kind = L"来源上下文 · KSword 回调";
    } else if (record.etw || record.network) {
        kind = L"来源上下文";
    }
    if (!kind) {
        return {};
    }
    // 使用当前选择实际所属的段号及记录序号，适用于跨段回放。
    return std::wstring(kind) + L" · " + RawLocation(record);
}

void UpdateDetails(Page& page) {
    if (!page.liveView && (page.selectedExecution || page.selectedNativeHistory))
    {
        const auto& source = page.selectedNativeHistory ? page.selectedNativeHistory->sourceDocument
            : page.selectedExecution->sourceDocument; // 两端同一份规范源，独立历史不补API请求。
        const auto text = NativeExecutionDetails(source);
        if (text != page.displayedDetails)
        {
            page.displayedDetails = text;
            ::SetWindowTextW(page.details, text.c_str());
        }
        return;
    }
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
        } else if (ApiMode(page)) {
            if (const auto& api = page.liveStatus.api; api) {
                text = L"本次工程 · " + api->manifestPath;
                // JSONL继续保留原文件身份，仅展示其已有latest；两类来源都复用原详情宿主全文。
                if (!api->explicitAttachment && !api->cooperative && !api->launched)
                {
                    text += L"\r\n来源文件 · " + api->sourcePath;
                }
                text += L"\r\n\r\n" + FormatLiveStatus(page.liveStatus);
            }
        } else {
            text += L"选择一条实时记录查看证据。";
        }
        if (text != page.displayedDetails) {
            page.displayedDetails = std::move(text);
            ::SetWindowTextW(page.details, page.displayedDetails.c_str());
        }
        return;
    }
    const auto* archive = DisplayedArchive(page); // 同时拥有当前选择的原始记录和规则回执。
    if (archive && archive->evidence.identity) {
        const auto& snapshot = *archive;
        const auto& evidence = snapshot.evidence;
        const auto& identity = *evidence.identity;
        text = (page.samplePreview ? L"选中采样预览 · 采样：" : L"当前归档 · 采样：") + WideAscii(identity.sampleId) + L"\r\n";
        if (snapshot.callback) text += CallbackReplayDetails(*snapshot.callback);
        else text += snapshot.classification + L"\r\n" + kRelationshipCoverage + L"\r\n";
        if (!snapshot.checkpoint.apiStartupJson.empty())
        {
            // 与当前采样一起复制/导出历史回执，既不读取活PID，也不授予控制入口。
            text += L"采集启动回执（历史）：\r\n" + Utf8ToWide(snapshot.checkpoint.apiStartupJson) + L"\r\n";
        }
        const bool hasRuleReplay = snapshot.apiRules.has_value() || !snapshot.rulePresetSet.empty() ||
            !snapshot.ruleConfigError.empty(); // 已加载、失败或配置诊断均需要在详情中留下状态。
        if (snapshot.sample && (evidence.apiClues || snapshot.checkpoint.kind == ReplayCheckpointKind::PassiveApi)) {
            text += L"采集覆盖：未知。规则使用已核验的归档 API 观测。\r\n";
        }
        if (hasRuleReplay) {
            const bool chinese = PRIMARYLANGID(page.behaviorLanguage) == LANG_CHINESE; // 详情语言与行为树使用同一快照。
            if (!snapshot.rulePresetSet.empty()) {
                text += L"规则集：" + snapshot.rulePresetSet + L"\r\n";
                text += L"SHA-256：" + snapshot.ruleSourceSha256 + L"\r\n";
            }
            const auto& recordedSha = snapshot.checkpoint.recordedRuleSourceSha256; // 采集计划实际记录的内容摘要。
            if (recordedSha.empty()) {
                text += chinese ? L"采集规则 SHA-256：未记录\r\n" : L"Recorded rule SHA-256: not recorded\r\n";
                text += chinese ? L"规则内容一致性：未知\r\n" : L"Rule content match: unknown\r\n";
            } else {
                text += chinese ? L"采集规则 SHA-256：" : L"Recorded rule SHA-256: ";
                text += Utf8ToWide(recordedSha) + L"\r\n";
                const bool currentShaKnown = !snapshot.ruleSourceSha256.empty(); // 加载失败或旧配置缺少摘要时不比较。
                const auto recordedWideSha = Utf8ToWide(recordedSha); // 用同一 UTF-8 转换器比较两个摘要文本。
                const bool sameRuleContent = currentShaKnown && recordedWideSha == snapshot.ruleSourceSha256;
                const auto comparison = !currentShaKnown ? (chinese ? L"未知" : L"unknown") :
                    sameRuleContent ? (chinese ? L"一致" : L"Match") : (chinese ? L"不一致" : L"Mismatch");
                text += chinese ? L"规则内容一致性：" : L"Rule content match: ";
                text += comparison;
                text += L"\r\n";
            }
            if (!snapshot.ruleConfigError.empty()) {
                text += L"规则库加载失败：" + snapshot.ruleConfigError + L"\r\n";
            } else if (!snapshot.apiRules) {
                text += L"预置规则求值失败。已核验的原始记录仍可查看。\r\n";
            }
        }
        if (!snapshot.callback && snapshot.evidenceGroups.empty()) text += L"当前回放窗口无可浏览的关系记录。\r\n";
        text += L"\r\n" + std::wstring(snapshot.sample ? L"清单：" : L"归档：") + snapshot.path + L"\r\n项目：" + WideAscii(identity.projectId) +
            L"\r\n流编号：" + std::to_wstring(identity.streamKind);
        // 多段采样的文件标识属于最新段，不用它描述选中的历史行。
        if (!snapshot.mixedStatus.empty()) text += L"\r\n" + snapshot.mixedStatus;
        else if (snapshot.checkpoint.lastVerifiedOrdinal <= 1) {
            text += L"    段号：" + std::to_wstring(identity.ordinal);
            if (!snapshot.callback && snapshot.checkpoint.kind != ReplayCheckpointKind::PassiveApi) {
                text += L"    段创建 FILETIME：" + std::to_wstring(evidence.createdUtc100ns) +
                    L"\r\n文件身份（卷序列 / 文件索引 / 修改 FILETIME）：" +
                    (evidence.fileIdentity.empty() ? L"不可用" : evidence.fileIdentity);
            }
        }
        text += L"\r\n\r\n";
    }
    if (record) {
        text += RecordName(*record) + L"\r\n";
        if (page.selectedCandidate) text += L"所选原包已移出表格窗口，仍显示同一已核验证据详情。\r\n";
        if (archive && !archive->mixedStatus.empty()) text += L"归档坐标：" + RawLocation(*record) + L"\r\n";
        text += L"归档记录序号：" + std::to_wstring(record->sequence) +
            L"    所属段号：" + std::to_wstring(record->segmentOrdinal) + L"    块号：" +
            std::to_wstring(record->blockOrdinal) + L"    文件字节偏移：" + std::to_wstring(record->offset) + L"\r\n";
        text += L"类型：" + std::to_wstring(record->type) + L"    格式版本：" + std::to_wstring(record->schemaVersion) +
            L"    标志：" + std::to_wstring(record->flags) + L"    负载字节：" + std::to_wstring(record->payloadBytes) + L"\r\n";
        if (!record->apiFamily.empty()) {
            text += L"API 分类：" + ApiFamilyLabel(record->apiFamily) + L"（" + record->apiFamily + L"）\r\n";
        }
        text += ApiTransferDetails(*record); // 同一已选原包的结构化参数进入原详情文档。
        // 窄窗隐藏图时仍可从已有可聚焦详情读取同一归档坐标。
        if (const auto relation = ArchivedRelationText(*record); !relation.empty()) {
            text += relation + L"\r\n";
        }
        if (archive && !record->apiClue.empty()) {
            const auto* rules = RuleDetailsForRecord(*archive, *record); // 表内和表外详情统一按原始坐标取结果。
            if (rules) {
                if (!rules->grouped.empty()) {
                    text += L"规则 ID（汇总）：" + Utf8ToWide(rules->grouped) + L"\r\n" +
                        L"规则 ID（细分）：" + Utf8ToWide(rules->byCategory) + L"\r\n";
                }
                if (const auto& behavior = rules->behavior) {
                    text += L"行为规则 ID：" + Utf8ToWide(behavior->ruleId) + L"\r\n" +
                        L"证据级别：" + Utf8ToWide(behavior->evidence) + L"\r\n";
                    const auto& summary = BehaviorSummary(*behavior, page.behaviorLanguage); // 和树标题使用同一已求值原值。
                    if (!summary.empty()) {
                        text += Utf8ToWide(summary) + L"\r\n";
                    }
                }
            }
            const auto ruleEvidence = RuleEvidenceOf(*record); // 与后台规则回放使用同一证据投影。
            const auto api = NarrowApiText(record->apiClue); // 使用生产规则输入中的原始API名称。
            const auto family = NarrowApiText(record->apiFamily); // 使用生产分类器产生的稳定类别ID。
            const auto fields = Rules::ProjectApiPresetFields(api, family,
                record->memoryWriteReturn, ruleEvidence); // 原谓词匹配器使用的本行字段。
            const auto inputText = Rules::FormatApiPresetFields(fields); // 显示与谓词求值完全相同的已知字段。
            const bool chinese = PRIMARYLANGID(page.behaviorLanguage) == LANG_CHINESE; // 保持详情与行为树使用同一线程语言。
            text += chinese ? L"规则比对输入：\r\n" : L"Rule match inputs:\r\n";
            text += Utf8ToWide(inputText) + L"\r\n";
        }
        if (record->eventOrdinal) {
            text += L"来源实例字典 ID：" + Number(record->sourceDictionaryId) + L"    来源代次字典 ID：" +
                Number(record->epochDictionaryId) + L"\r\n报头 PID：" + Number(record->headerPid) +
                L"    报头 TID：" + Number(record->headerTid) + L"\r\n引用状态：归档字段已读取，字典、跨流记录与对象尚未解析。\r\n";
        }
        text += L"\r\n" + (record->network ? NetworkReplayDetails(*record->network) : record->preview);
    } else {
        if (archive && archive->callback && archive->evidence.rows.empty()) text += L"空批次已核验：此批次没有归档的线程创建观测。";
        else if (archive) text += L"选择一条记录查看归档字段。";
        else if (page.project) text += L"工程：" + page.project->manifestPath + L"\r\n选择采样查看证据，或开始新一轮扫描。";
        else text += L"新建或打开工程后，可查看采样的分类和证据。";
    }
    if (text != page.displayedDetails) {
        page.displayedDetails = std::move(text);
        ::SetWindowTextW(page.details, page.displayedDetails.c_str());
    }
    ::InvalidateRect(page.hwnd, &page.graph, FALSE);
}

// Light 沿用线程 UI 语言；设置通知或重新显示时只替换行为组文字，保留原证据选择和详情。
void RefreshBehaviorLanguage(Page& page)
{
    if (page.behaviorLanguage == ::GetThreadUILanguage())
    {
        return;
    }
    if (!page.behaviorGroup)
    {
        page.behaviorLanguage = ::GetThreadUILanguage();
        UpdateDetails(page);
        return;
    }
    const auto state = CaptureBehaviorTreeState(page, true);
    const bool wasProjecting = page.applyingProjection;
    page.applyingProjection = true;
    const auto tree = page.transferTree.hwnd();
    ::SendMessageW(tree, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteItem(tree, page.behaviorGroup);
    ProjectBehaviorTree(page, page.liveView ? nullptr : DisplayedArchive(page), state);
    ::SendMessageW(tree, WM_SETREDRAW, TRUE, 0);
    ::InvalidateRect(tree, nullptr, TRUE);
    page.applyingProjection = wasProjecting;
    UpdateDetails(page);
}

void UpdateStatus(Page& page) {
    std::wstring text = page.requestStatus;
    std::wstring empty;
    if (page.liveView) {
        const bool api = ApiMode(page);
        text = api == page.liveStatus.api.has_value() ? FormatLiveStatus(page.liveStatus) : std::wstring{};
        if (!page.liveInputError.empty()) {
            if (!text.empty()) text += L"\r\n";
            text += page.liveInputError;
        }
        if (text.empty()) text = !api ? L"输入自有进程 PID 和 ETW 提供程序 GUID，再开始扫描。" : LaunchApiMode(page) ?
            L"选择普通 AMD64 EXE，入口停止后自动附加 Agent；Ready 与覆盖核验通过才恢复主线程。此前 TLS/loader 不在覆盖范围。" : AttachmentMode(page) ?
            L"按 PID 与创建 FILETIME 选择已运行实例；点击开始后确认装载。文件和外部会话 ID 不参与活采。" : CooperativeMode(page) ?
            L"仅接入已自行加载正式 Agent 的授权目标。" : L"仅跟随明确授权的本地 API JSONL。";
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
        } else if (api) {
            const bool live = page.liveStatus.api ? page.liveStatus.api->cooperative || page.liveStatus.api->explicitAttachment || page.liveStatus.api->launched : LiveApiMode(page);
            empty = live ? L"API 活采 · 工程采样" : L"被动 API 原包在停止后从工程采样回放。";
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
        if (archive->mixedStatus.empty()) {
            if (ordinal > 1) {
                text += L"  ·  已核验 " + std::to_wstring(result.lastSequence.value_or(0)) + L" 条  ·  第 " +
                    std::to_wstring(ordinal) + L" 段";
            }
            text += L"  ·  帧记录 " + std::to_wstring(result.records) +
                L"  ·  帧前缀 " + std::to_wstring(result.framedBytes) + L" / " + std::to_wstring(result.fileBytes) +
                L" B  ·  解码前缀 " + std::to_wstring(result.decodedPrefixBytes) + L" B";
        }
        if (page.selected && !std::binary_search(page.list.visibleIndexes().begin(), page.list.visibleIndexes().end(), *page.selected)) {
            text += L"  ·  已选记录被筛掉";
        }
        if (page.selectedCandidate) text += L"  ·  所选原包已移出表格窗口";
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
            (archive->callback ? L"空批次已核验 · 没有线程创建观测" :
                archive->evidence.diagnostic.empty() ? L"此归档段没有记录" : L"已读前缀没有可显示记录") : L"没有匹配的记录";
        if (page.liveStatus.active) {
            text += page.liveStatus.cleanupPending ? L"\r\n实时采集等待清退重试 · 返回实时视图处理" : page.liveStatus.api ?
                (page.liveStatus.api->launched ? L"\r\nEXE 启动采集在后台运行" : page.liveStatus.api->explicitAttachment ? L"\r\n显式 API 附加在后台运行" :
                    page.liveStatus.api->cooperative ? L"\r\n合作 Agent 会话在后台运行" : L"\r\n被动 API 文件跟随在后台运行") :
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
    if (page.selected == index && !page.selectedCandidate && !page.selectedExecution && !page.selectedNativeHistory) return;
    page.selectedNativeHistory.reset(); // 用户列表选择回到原事件详情。
    page.selectedExecution.reset(); // 用户从列表选择时回到 API/事件详情。
    page.selectedCandidate.reset(); // 列表和时间线主动选择后回到原有记录身份。
    page.selected = index;
    if (page.liveView) page.liveSelection = index;
    else if (page.samplePreview) page.previewSelection = index;
    else page.historySelection = index;
    if (page.liveView && page.followLive && page.liveStatus.active) SetLiveFollow(page, false);
    page.timeline.select(index, true);
    UpdateDetails(page);
    UpdateStatus(page);
}

const EvidenceGroup* SelectedEvidenceGroup(const Page& page, const Snapshot& archive) {
    const auto index = ::SendMessageW(page.evidenceFamily, CB_GETCURSEL, 0, 0);
    if (index <= 0 || static_cast<std::size_t>(index) > archive.evidenceGroups.size()) return nullptr;
    return &archive.evidenceGroups[static_cast<std::size_t>(index - 1)];
}

std::optional<std::size_t> SelectedEvidenceRow(const Page& page, const Snapshot& archive) {
    const auto* group = SelectedEvidenceGroup(page, archive); // 组和原始行来自同一次发布。
    const auto item = ::SendMessageW(page.evidenceRecord, CB_GETCURSEL, 0, 0); // 第零项是选择提示。
    if (!group || item <= 0 || static_cast<std::size_t>(item) > group->rows.size()) return std::nullopt;
    return group->rows[group->rows.size() - static_cast<std::size_t>(item)];
}

void SetEvidenceRecordChoice(Page& page, const Snapshot& archive) {
    const auto index = SelectedEvidenceRow(page, archive);
    page.evidenceRecordChoice = index ? std::optional{CoordinateOf(archive.evidence.rows[*index])} : std::nullopt;
    if (!index && ::GetFocus() == page.locateEvidence) {
        ::SetFocus(::IsWindowEnabled(page.evidenceRecord) ? page.evidenceRecord : page.evidenceFamily);
    }
    ::EnableWindow(page.locateEvidence, index.has_value());
}

// 刷新选定组的倒序原始行。同源窗口重叠时仅更新前后变化的条目。
void RefreshEvidenceRows(Page& page, const Snapshot& archive, const EvidenceGroup* group, bool selectNewest,
    const Snapshot* previous = nullptr) {
    const auto restore = page.evidenceRecordChoice; // 原包坐标在滚动时独立于控件下标。
    const HWND combo = page.evidenceRecord; // 保留原生下拉框及键盘交互。
    std::size_t retained = 0; // 新组前部仍在窗口中的旧行数。
    bool incremental = false; // 控件与前一次发布均匹配时才复用旧行。
    if (previous && group && !group->rows.empty() && ::IsWindowEnabled(combo)) {
        const auto old = std::find_if(previous->evidenceGroups.begin(), previous->evidenceGroups.end(),
            [&](const auto& candidate) { return candidate.key == group->key; }); // 同一稳定关系组。
        if (old != previous->evidenceGroups.end() &&
            ::SendMessageW(combo, CB_GETCOUNT, 0, 0) == static_cast<LRESULT>(old->rows.size() + 1)) {
            const auto sameRecord = [&](std::size_t oldIndex, std::size_t newIndex) {
                const auto& before = previous->evidence.rows[oldIndex]; // 旧组实际原包。
                const auto& after = archive.evidence.rows[newIndex]; // 新组实际原包。
                if (CoordinateOf(before) != CoordinateOf(after)) return false;
                return before.apiClue.empty() ? RecordName(before) == RecordName(after) : before.apiClue == after.apiClue;
            };
            const auto first = std::find_if(old->rows.begin(), old->rows.end(),
                [&](std::size_t index) { return sameRecord(index, group->rows.front()); }); // 旧组第一个保留的坐标。
            retained = static_cast<std::size_t>(old->rows.end() - first);
            incremental = retained <= group->rows.size() && std::equal(first, old->rows.end(), group->rows.begin(), sameRecord);
            // 倒序投影中最旧原包在尾部，从尾端向前移除滚出窗口的行。
            if (incremental) {
                for (auto item = old->rows.size(); item > retained; --item) {
                    ::SendMessageW(combo, CB_DELETESTRING, item, 0);
                }
            }
        }
    }
    bool populated = true; // 插入失败时进入原有不可用状态。
    if (!incremental) {
        retained = 0;
        ::SendMessageW(combo, CB_RESETCONTENT, 0, 0);
        const auto hint = group ? L"选择组内记录" : L"先选择关系分组"; // 倒序行之前的占位项。
        populated = ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(hint)) == 0;
    }
    LRESULT selected = 0; // 恢复坐标仍在窗口中的旧选择。
    if (group && populated) {
        const auto size = group->rows.size(); // 已发布窗口内该组的新节点总数。
        if (!incremental) ::SendMessageW(combo, CB_INITSTORAGE, size, size * 112 * sizeof(wchar_t));
        // 首次打开按倒序追加，增量则按升序将新后缀插入组首，保留旧项。
        for (auto index = retained; index < size && populated; ++index) {
            const auto offset = incremental ? index : size - 1 - index; // 由插入方向选取真实记录。
            const auto& record = archive.evidence.rows[group->rows[offset]]; // 归档行和关系叶项一一对应。
            const auto label = RawLocation(record) + L" · " + RecordName(record); // 只格式化新插入的文字。
            populated = ::SendMessageW(combo, incremental ? CB_INSERTSTRING : CB_ADDSTRING,
                incremental ? 1 : 0, reinterpret_cast<LPARAM>(label.c_str())) > 0;
        }
        if (restore) {
            const auto found = std::find_if(group->rows.rbegin(), group->rows.rend(), [&](std::size_t index) {
                return *restore == CoordinateOf(archive.evidence.rows[index]);
            }); // 在最终倒序视图中恢复原坐标。
            if (found != group->rows.rend()) selected = found - group->rows.rbegin() + 1;
        }
        if (!selected && selectNewest && size) selected = 1;
    }
    if (!populated) {
        ::SendMessageW(combo, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"无法列出组内记录"));
        selected = 0;
    }
    if (::SendMessageW(combo, CB_GETCURSEL, 0, 0) != selected) ::SendMessageW(combo, CB_SETCURSEL, selected, 0);
    if ((!group || !populated) && ::GetFocus() == combo) ::SetFocus(page.evidenceFamily);
    ::EnableWindow(combo, group && populated);
    SetEvidenceRecordChoice(page, archive);
}

void SetEvidenceFamilyChoice(Page& page) {
    const auto* archive = BrowsableArchive(page);
    if (!archive) return;
    const auto* group = SelectedEvidenceGroup(page, *archive);
    const auto key = group ? std::wstring_view(group->key) : std::wstring_view{};
    if (page.evidenceFamilyChoice == key) return;
    page.evidenceFamilyChoice = key;
    page.evidenceRecordChoice.reset();
    RefreshEvidenceRows(page, *archive, group, true);
}

void ResumeArchiveRead(Page& page) {
    if (!page.deferredRead) return;
    const auto [taskIdentity, generation] = *page.deferredRead;
    // 退出原生通知栈后再发布，让下拉框先提交或取消本次选择。
    if (::PostMessageW(page.hwnd, kComplete, taskIdentity, generation)) page.deferredRead.reset();
}

void RestoreEvidenceDropdownSelection(Page& page) {
    const auto dropdown = std::exchange(page.evidenceDropdown, std::nullopt);
    if (dropdown) ::SendMessageW(dropdown->control, CB_SETCURSEL, static_cast<WPARAM>(dropdown->originalSelection), 0);
}

void CancelEvidenceDropdown(Page& page) {
    if (!page.evidenceDropdown) return;
    page.evidenceDropdown->canceled = true;
    ::SendMessageW(page.evidenceDropdown->control, CB_SHOWDROPDOWN, FALSE, 0);
    // A programmatic close may leave no CBN_CLOSEUP to restore the selection.
    RestoreEvidenceDropdownSelection(page);
    ResumeArchiveRead(page);
}

void RefreshEvidenceNavigation(Page& page, const Snapshot* previous) {
    CancelEvidenceDropdown(page);
    const auto* archive = BrowsableArchive(page);
    const auto scope = archive ? archive->evidence.identity : std::nullopt;
    const auto sample = archive ? archive->sample : std::nullopt;
    const auto path = archive ? std::wstring_view(archive->path) : std::wstring_view{};
    if (!page.liveView && (page.evidenceFamilyScope != scope || page.evidenceFamilySample != sample || page.evidenceFamilyPath != path)) {
        page.evidenceFamilyScope = scope;
        page.evidenceFamilySample = sample;
        page.evidenceFamilyPath = path;
        page.evidenceFamilyChoice.clear();
        page.evidenceRecordChoice.reset();
    }
    const HWND focus = ::GetFocus();
    if (!archive && (focus == page.evidenceFamily || focus == page.evidenceRecord || focus == page.locateEvidence)) {
        ::SetFocus(page.filter);
    }
    const bool wasVisible = (::GetWindowLongPtrW(page.evidenceFamily, GWL_STYLE) & WS_VISIBLE) != 0;
    if (wasVisible != (archive != nullptr)) {
        Layout(page);
        for (HWND control : {page.evidenceFamilyLabel, page.evidenceFamily, page.evidenceRecordLabel, page.evidenceRecord, page.locateEvidence}) {
            ::ShowWindow(control, archive ? SW_SHOW : SW_HIDE);
        }
    }
    if (!archive) {
        if (!page.liveView) {
            ::SendMessageW(page.evidenceFamily, CB_RESETCONTENT, 0, 0);
            ::SendMessageW(page.evidenceRecord, CB_RESETCONTENT, 0, 0);
        }
        ::EnableWindow(page.locateEvidence, FALSE);
        return;
    }

    // 只对同一已核验 API 采样应用滚动增量。其它归档仍按原入口提交。
    const bool samePrefix = previous && previous->path == archive->path && previous->sample == sample &&
        previous->evidence.identity == scope && previous->checkpoint.kind == ReplayCheckpointKind::PassiveApi &&
        archive->checkpoint.kind == ReplayCheckpointKind::PassiveApi && previous->checkpoint.lastVerifiedOrdinal &&
        previous->checkpoint.lastVerifiedOrdinal <= archive->checkpoint.lastVerifiedOrdinal;
    if (samePrefix && ::IsWindowEnabled(page.evidenceFamily) && std::ranges::equal(previous->evidenceGroups,
        archive->evidenceGroups, [](const EvidenceGroup& before, const EvidenceGroup& after) {
            return before.key == after.key && before.rows.size() == after.rows.size();
        })) {
        if (const auto* group = SelectedEvidenceGroup(page, *archive)) RefreshEvidenceRows(page, *archive, group, false, previous);
        return;
    }

    ::SendMessageW(page.evidenceFamily, CB_RESETCONTENT, 0, 0);
    bool populated = ::SendMessageW(page.evidenceFamily, CB_ADDSTRING, 0,
        reinterpret_cast<LPARAM>(L"选择关系组")) == 0;
    LRESULT selected = 0;
    for (const auto& group : archive->evidenceGroups) {
        if (!populated) break;
        const auto label = group.label + L"（" + std::to_wstring(group.rows.size()) + L"）";
        const auto index = ::SendMessageW(page.evidenceFamily, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
        populated = index > 0;
        if (populated && page.evidenceFamilyChoice == group.key) selected = index;
    }
    if (!populated) {
        ::SendMessageW(page.evidenceFamily, CB_RESETCONTENT, 0, 0);
        if (focus == page.evidenceFamily || focus == page.evidenceRecord || focus == page.locateEvidence) ::SetFocus(page.filter);
        selected = 0;
    }
    if (!selected) page.evidenceFamilyChoice.clear();
    ::EnableWindow(page.evidenceFamily, populated);
    ::SendMessageW(page.evidenceFamily, CB_SETCURSEL, selected, 0);
    RefreshEvidenceRows(page, *archive, SelectedEvidenceGroup(page, *archive), false, samePrefix ? previous : nullptr);
}

void LocateEvidence(Page& page) {
    if (page.retiring) return;
    const auto* archive = BrowsableArchive(page);
    if (!archive) return;
    const auto index = SelectedEvidenceRow(page, *archive);
    if (!index || page.evidenceRecordChoice != CoordinateOf(archive->evidence.rows[*index])) return;
    // 组内原始行与分类取自同一只读快照。筛选隐藏该行时沿用现有的详情和状态提示。
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    SelectRecord(page, *index);
    SetListSelection(page, *index, true);
}

// 候选叶项复用原始列表定位和共享详情；隐藏或已滚出的原包不改变现有筛选草稿。
void LocateTransferCandidate(Page& page) {
    if (page.retiring || page.liveView) {
        return;
    }
    const auto* execution = page.transferTree.Execution(); // API一致性候选中的原生叶。
    const auto* history = page.transferTree.History(); // 无API依赖的独立历史叶。
    if (execution || history)
    {
        page.selectedExecution = execution ? std::optional(*execution) : std::nullopt;
        page.selectedNativeHistory = history ? std::optional(*history) : std::nullopt; // 均只读，不授实时控制权。
        page.selectedCandidate.reset();
        page.selected.reset();
        page.timeline.select(std::nullopt, false);
        ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED); // 避免旧 API 行仍显示为选中。
        if (page.samplePreview)
        {
            page.previewSelection.reset();
        }
        else
        {
            page.historySelection.reset();
        }
        UpdateDetails(page);
        UpdateStatus(page); // 原生选择清除了API选择，状态同步显示当前来源。
        return;
    }
    const auto* row = SelectedBehaviorRecord(page); // 行为叶复用原列表定位及 ApiRuleDetails 详情。
    if (!row)
    {
        row = page.transferTree.Activate(); // 当前候选双方中的真实 raw 原包。
    }
    const auto* archive = DisplayedArchive(page); // 当前已发布的同采样证据。
    if (!row || !archive) {
        return;
    }
    page.selectedExecution.reset(); // 同一树里的 API 叶仍走原定位路径。
    page.selectedNativeHistory.reset();
    const auto& rows = archive->evidence.rows; // 在有界近期表中按完整物理坐标查找。
    const auto found = std::find_if(rows.begin(), rows.end(), [&](const EvidenceRecord& record) {
        return CoordinateOf(record) == CoordinateOf(*row);
    });
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (found != rows.end()) {
        const auto index = static_cast<std::size_t>(found - rows.begin()); // 表和详情共享行下标。
        SelectRecord(page, index);
        SetListSelection(page, index, true);
    } else {
        page.selectedCandidate = *row; // 保存真实详情，不把候选原包追加进筛选后的事件表。
        page.selected.reset();
        if (page.samplePreview) {
            page.previewSelection.reset();
        } else {
            page.historySelection.reset(); // 后续同采样发布不恢复无关旧表行。
        }
        page.timeline.select(std::nullopt, false);
        UpdateDetails(page);
        UpdateStatus(page);
    }
}

void ApplyFilter(Page& page) {
    wchar_t query[257]{};
    ::GetWindowTextW(page.filter, query, static_cast<int>(std::size(query)));
    auto visible = Ui::VirtualListView::FilterRowIndexes(page.list.rows(), query);
    if (const auto* evidence = DisplayedEvidence(page)) {
        const auto& records = evidence->rows;
        const auto* archive = page.liveView ? nullptr : DisplayedArchive(page);
        const bool etwOnly = page.timeline.hasEtw() && Checked(page.etwOnly);
        const bool apiOnly = archive && archive->hasApi && Checked(page.apiOnly);
        const bool networkOnly = archive && archive->hasNetwork && Checked(page.networkOnly);
        std::erase_if(visible, [&](std::size_t i) {
            const auto& row = records[i]; // 来源开关取并集，再与文字和类别相交。
            const bool sourceMatch = (!apiOnly && !etwOnly && !networkOnly) || (apiOnly && !row.apiClue.empty()) ||
                (etwOnly && row.etw) || (networkOnly && row.network);
            return !sourceMatch || !page.timeline.includes(row);
        });
    }
    const auto& previous = page.list.visibleIndexes();
    const bool reveal = !page.liveView && page.selected && !std::binary_search(previous.begin(), previous.end(), *page.selected);
    page.applyingProjection = true;
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    page.timeline.setVisible(visible);
    page.list.setVisibleIndexes(std::move(visible));
    if (page.selected) SetListSelection(page, *page.selected, reveal);
    page.applyingProjection = false;
    UpdateStatus(page);
}

void PresentResults(Page& page, bool refreshLive = false, const Snapshot* previousArchive = nullptr) {
    static const std::vector<EvidenceRecord> empty;
    const auto* evidence = DisplayedEvidence(page);
    const auto* archive = page.liveView ? nullptr : DisplayedArchive(page);
    if (!refreshLive) {
        const bool sameCandidateScope = archive && page.candidateScope == archive->evidence.identity &&
            page.candidateSample == archive->sample && page.candidatePath == archive->path; // 完整范围身份。
        if (!sameCandidateScope) {
            page.selectedCandidate.reset();
            page.selectedExecution.reset();
            page.selectedNativeHistory.reset();
        }
        if (sameCandidateScope && page.selectedNativeHistory)
        {
            const auto& entries = archive->evidence.nativeExecution.observations; // 新快照重核原物理来源。
            const auto found = std::find_if(entries.begin(), entries.end(), [&](const auto& entry) {
                return Ksword::Evidence::SameNativeExecutionHistory(entry, *page.selectedNativeHistory);
            });
            page.selectedNativeHistory = found != entries.end() ? std::optional(*found) : std::nullopt;
        }
        if (sameCandidateScope && page.selectedExecution)
        {
            const auto& candidates = archive->evidence.nativeExecution.candidates; // 新快照重新核对完整分支来源。
            const auto found = std::find_if(candidates.begin(), candidates.end(), [&](const auto& item) {
                return item.kind == page.selectedExecution->kind && item.nativeOrdinal == page.selectedExecution->nativeOrdinal &&
                    item.nativeSequence == page.selectedExecution->nativeSequence &&
                    item.nativeRecordOffset == page.selectedExecution->nativeRecordOffset &&
                    item.nativeSha256 == page.selectedExecution->nativeSha256 &&
                    CoordinateOf(item.request) == CoordinateOf(page.selectedExecution->request) &&
                    item.write.has_value() == page.selectedExecution->write.has_value() &&
                    (!item.write || CoordinateOf(*item.write) == CoordinateOf(*page.selectedExecution->write));
            });
            if (found == candidates.end())
            {
                page.selectedExecution.reset();
            }
            else
            {
                page.selectedExecution = *found;
            }
        }
        if (sameCandidateScope && page.selectedCandidate) {
            const auto coordinate = CoordinateOf(*page.selectedCandidate); // 只沿用新快照重新核验的原包。
            std::optional<EvidenceRecord> retained; // 候选窗口淘汰后不保留不再发布的旧详情。
            for (const auto& pair : archive->evidence.transferCandidates) {
                if (CoordinateOf(pair.write) == coordinate) {
                    retained = pair.write;
                } else if (CoordinateOf(pair.threadCreate) == coordinate) {
                    retained = pair.threadCreate;
                }
            }
            for (const auto& pair : archive->evidence.apcTransferCandidates) // APC 行续持仍需新快照重新核对。
            {
                if (CoordinateOf(pair.write) == coordinate)
                {
                    retained = pair.write;
                }
                else if (CoordinateOf(pair.queue) == coordinate)
                {
                    retained = pair.queue;
                }
            }
            // pair 为新快照中的上下文双方，只有仍被发布的原行才能续持表外详情。
            for (const auto& pair : archive->evidence.contextTransferCandidates)
            {
                if (CoordinateOf(pair.write) == coordinate)
                {
                    retained = pair.write;
                }
                else if (CoordinateOf(pair.context) == coordinate)
                {
                    retained = pair.context;
                }
            }
            for (const auto& candidate : archive->evidence.nativeExecution.candidates) // 执行树持有的窗口外 API 叶。
            {
                if (CoordinateOf(candidate.request) == coordinate)
                {
                    retained = candidate.request;
                }
                else if (candidate.write && CoordinateOf(*candidate.write) == coordinate)
                {
                    retained = *candidate.write;
                }
            }
            page.selectedCandidate = std::move(retained);
        }
        const bool wasProjecting = page.applyingProjection; // 树重建的同步通知不得改变原选择身份。
        const auto behaviorState = CaptureBehaviorTreeState(page, sameCandidateScope);
        page.applyingProjection = true;
        page.transferTree.Publish(archive ? &archive->evidence : nullptr, sameCandidateScope);
        ProjectBehaviorTree(page, archive, behaviorState);
        page.applyingProjection = wasProjecting;
        page.candidateScope = archive ? archive->evidence.identity : std::nullopt;
        page.candidateSample = archive ? archive->sample : std::nullopt;
        page.candidatePath = archive ? archive->path : std::wstring{};
        Layout(page); // 有界候选树只占底部视口，保留原详情和表格主要空间。
    }
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
    enableSource(page.apiOnly, archive && archive->hasApi);
    enableSource(page.networkOnly, archive && archive->hasNetwork);
    page.applyingProjection = true;
    if (!refreshLive) RefreshEvidenceNavigation(page, previousArchive);
    ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (page.liveView && evidence && page.liveProjection) {
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

constexpr auto kLegacyApiFollowStatus = L"旧版被动 API 跟随归档未发布检查点，无可回放的记录。";

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
    PublishProjectBreakpointCatalog(page.hwnd, catalog); // 仅向明确宿主发布此轮后台读取的定义，含成功空项目。
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
    page.project = NativeLiveProject{std::move(catalog.manifestPath), std::move(catalog.projectId), std::move(catalog.revisionId)};
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
    const bool mixed = !loaded.mixedStatus.empty();
    const bool passiveApi = !mixed && loaded.checkpoint.kind == ReplayCheckpointKind::PassiveApi;
    if (passiveApi && loaded.checkpoint.state == CheckpointState::NotPublished) {
        page.requestStatus = kLegacyApiFollowStatus;
        if (loaded.sample) page.requestStatus += L" · " + WideAscii(loaded.sample->sampleId);
        if (DisplayedArchive(page)) page.requestStatus += L"（保留当前归档）";
        UpdateStatus(page);
        return;
    }
    if (!mixed && !loaded.checkpoint.lastVerifiedOrdinal && loaded.checkpoint.state == CheckpointState::Pending) {
        page.requestStatus = passiveApi ? L"等待被动 API 第 1 段检查点发布，可重读。" :
            L"等待第 1 段检查点发布，可重读。";
        if (passiveApi && loaded.sample) page.requestStatus += L" · " + WideAscii(loaded.sample->sampleId);
        UpdateStatus(page);
        return;
    }
    if (!loaded.evidence.identity || (!mixed && !loaded.evidence.diagnostic.empty() && loaded.evidence.rows.empty())) {
        ShowReadFailure(page, mixed ? loaded.mixedStatus : ReplayDiagnosticText(loaded.evidence));
        return;
    }
    const bool commitsPreview = page.samplePreview && page.samplePreview->sample == loaded.sample;
    const bool restorePreviewSelection = commitsPreview && page.previewSelection.has_value();
    const auto* previousSelectionSnapshot = restorePreviewSelection ? page.samplePreview.get() : page.snapshot.get();
    const auto index = restorePreviewSelection ? page.previewSelection : page.historySelection;
    std::optional<std::size_t> selection; // 同一证据中的新行索引。
    if (previousSelectionSnapshot && index && *index < previousSelectionSnapshot->evidence.rows.size() &&
        previousSelectionSnapshot->path == loaded.path && previousSelectionSnapshot->sample == loaded.sample &&
        previousSelectionSnapshot->evidence.identity == loaded.evidence.identity &&
        previousSelectionSnapshot->callback.has_value() == loaded.callback.has_value() &&
        (!loaded.callback || previousSelectionSnapshot->callback->prefixSha256 == loaded.callback->prefixSha256)) {
        // 项目、采样、流身份一致后，使用真正所属段与归档序号找回原始记录。
        const auto& selected = previousSelectionSnapshot->evidence.rows[*index];
        const auto& rows = loaded.evidence.rows; // 新完成的证据快照。
        const auto found = std::find_if(rows.begin(), rows.end(), [&selected](const auto& row) {
            if (CoordinateOf(row) != CoordinateOf(selected)) return false;
            return selected.apiFamily.empty() || (row.apiFamily == selected.apiFamily &&
                row.apiClue == selected.apiClue && row.preview == selected.preview);
        });
        if (found != rows.end()) selection = static_cast<std::size_t>(found - rows.begin());
    }

    const auto* previousArchive = DisplayedArchive(page); // 旧快照由下面的共享引用保留到发布结束。
    auto previousPreview = commitsPreview ? std::exchange(page.samplePreview, {}) : std::shared_ptr<const Snapshot>{};
    if (previousPreview) page.previewSelection.reset();
    auto next = std::make_shared<const Snapshot>(std::move(loaded)); // 将发布的数据固化为共享值。
    auto previous = std::exchange(page.snapshot, std::move(next)); // 旧大快照交给后台释放。
    page.historySelection = selection;

    // 分别显示项目提交状态、诊断预览和独立段的扫描状态。
    const auto& result = page.snapshot->evidence;
    const auto& checkpoint = page.snapshot->checkpoint; // 最新段的检查点和后续归档状态。
    if (mixed) {
        page.snapshotStatus = L"混采回放 · " + WideAscii(result.identity->sampleId) + L"\r\n" + page.snapshot->mixedStatus;
    } else if (page.snapshot->callback) {
        page.snapshotStatus = L"KSword 回调批次已核验 · 采集覆盖未知";
    } else if (auto status = DescribeReplayCheckpoint(checkpoint, result); !status.empty()) {
        page.snapshotStatus = std::move(status);
    } else if (checkpoint.state == CheckpointState::NotPublished) {
        page.snapshotStatus = L"未发布终态检查点 · 仅查看 raw 段";
        if (!result.diagnostic.empty()) page.snapshotStatus += L" · " + ReplayDiagnosticText(result);
    } else if (!result.diagnostic.empty()) {
        page.snapshotStatus = (result.diagnostic == "view.scanLimit" ? L"预览范围受限：" : L"部分归档可读：") + ReplayDiagnosticText(result);
    } else {
        page.snapshotStatus = result.opaqueRequiredRecords ? L"只读归档 · 包含无法解释的必需记录" : L"只读归档 · 段内扫描完成";
    }
    if (!mixed) page.snapshotStatus += L" · #" + std::to_wstring(result.identity->ordinal) + L" · " + WideAscii(result.identity->sampleId);
    page.requestStatus.clear();
    if (!page.liveView) {
        page.selected = page.historySelection;
        PresentResults(page, false, previousArchive);
        if (selection) SetListSelection(page, *selection, true);
        else if (page.list.rowCount()) ListView_EnsureVisible(page.list.hwnd(), 0, FALSE);
    } else {
        UpdateStatus(page);
    }
    if (previous) Ui::RetireBackgroundValue(previous);
    if (previousPreview) Ui::RetireBackgroundValue(previousPreview);
}

// 在原异步任务提交冻结的文件或样本请求。新请求代次取代在途旧回执。
void Open(Page& page, std::wstring path, std::optional<ProjectReplayRequest> sample = std::nullopt, bool followPrefix = false) {
    if (path.empty() || page.retiring || page.catalogBusy) return;
    if (!followPrefix && page.requestedSample != sample) page.apiPrefixAttempt.reset();
    // 同一采样的完整回放可接续当前预览及其原始行，失败仍可回看。
    if (!sample || !page.samplePreview || page.samplePreview->sample != sample) ResetSamplePreview(page);
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

void OpenCatalog(Page& page, std::wstring path, bool create = false, std::optional<ProjectReplayRequest> replay = {}) {
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
        }, [&page, create, replay = std::move(replay)](std::uint64_t, std::optional<LoadResult>&& loaded, std::exception_ptr error) {
            if (error || !loaded) {
                page.catalogBusy = false;
                UpdateProjectControls(page);
                ShowReadFailure(page, create ? L"后台创建工程失败" : L"后台读取工程失败");
                return;
            }
            PresentCatalog(page, std::get<ProjectReplayCatalog>(std::move(*loaded)), create);
            if (!replay || page.retiring) return;
            const auto found = std::find_if(page.choices.begin(), page.choices.end(), [&](const auto& choice) { return choice.request == *replay; });
            if (found != page.choices.end()) {
                ::SendMessageW(page.sampleChoice, CB_SETCURSEL, static_cast<WPARAM>(found - page.choices.begin()), 0);
                UpdateProjectControls(page);
            }
            Open(page, replay->manifestPath, *replay); // 回放层再次核对样本及散列。
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

void BrowseApi(Page& page) {
    const bool launched = LaunchApiMode(page); // 两个独立草稿只有对应来源可被选择器替换。
    std::vector<wchar_t> path(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = ::GetAncestor(page.hwnd, GA_ROOT);
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrFilter = launched ? L"程序 (*.exe)\0*.exe\0" : L"API JSONL\0*.jsonl\0";
    dialog.lpstrTitle = launched ? L"选择普通 AMD64 EXE" : L"选择已授权的本地 API JSONL";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER | OFN_DONTADDTORECENT;
    if (::GetOpenFileNameW(&dialog)) {
        ::SetWindowTextW(launched ? page.apiExecutable : page.apiPath, path.data());
        page.liveInputError.clear();
    } else if (const DWORD error = ::CommDlgExtendedError()) {
        page.liveInputError = L"文件选择失败（" + std::to_wstring(error) + L"）";
    }
    UpdateStatus(page);
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
            const bool mixed = preview && !preview->mixedStatus.empty();
            const bool passiveApi = preview && !mixed && preview->checkpoint.kind == ReplayCheckpointKind::PassiveApi;
            if (preview && preview->evidence.diagnostic == "replaySelectionLimit") {
                page.requestStatus = L"采样 " + sample + L" 的 raw 段超过预览上限，请点击回放。";
            } else if (passiveApi && preview->checkpoint.state == CheckpointState::NotPublished) {
                page.requestStatus = std::wstring(kLegacyApiFollowStatus) + L" · " + sample;
            } else if (preview && !mixed && preview->checkpoint.state == CheckpointState::Pending) {
                page.requestStatus = L"采样 " + sample + (passiveApi ? L" 的被动 API 首段检查点尚未发布，可点击回放重试。" :
                    L" 的首段检查点尚未发布，可点击回放重试。");
            } else if (!preview || !preview->evidence.identity ||
                (!mixed && !preview->evidence.diagnostic.empty() && preview->evidence.rows.empty())) {
                page.requestStatus = L"无法预览采样 " + sample;
                if (!preview || preview->evidence.diagnostic != kUnsupportedRawSource) {
                    page.requestStatus += L"，请点击回放重试。";
                }
                if (preview) page.requestStatus += mixed ? L"\r\n" + preview->mixedStatus : L" · " + ReplayDiagnosticText(preview->evidence);
            } else {
                page.requestStatus = L"快速预览 · " + sample;
                if (mixed) {
                    page.requestStatus += L" · 混采\r\n" + preview->mixedStatus;
                } else if (preview->callback) {
                    page.requestStatus += L" · KSword 回调批次已核验 · 采集覆盖未知";
                } else {
                    page.requestStatus += DescribeReplayPreview(preview->checkpoint, preview->evidence);
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

bool CanReplayApi(const Page& page) {
    const auto& status = page.liveStatus;
    return (!status.active || status.capture.verifiedSegments) && status.api && page.project && !status.capture.sampleId.empty() &&
        !status.api->sampleDescriptionHash.empty() && status.api->manifestPath == page.project->manifestPath &&
        status.capture.projectId == page.project->projectId;
}

// 沿用现有显示节拍和单个后台读取槽，仅新提交段触发当前采样的核验。
void RefreshCommittedApiPrefix(Page& page) {
    if (!page.apiPrefixAttempt || !page.requestedSample || !CanReplayApi(page) || page.liveView || page.retiring ||
        page.catalogBusy || page.task->running() || !::IsWindowVisible(page.hwnd) ||
        page.previewRequest != page.requestedSample) return;
    const auto& request = *page.requestedSample; // 由用户明确打开的当前回放。
    const auto& live = page.liveStatus; // 现有显示节拍已从采集所有者取到的只读回执。
    if (request.manifestPath != live.api->manifestPath || request.projectId != live.capture.projectId ||
        request.sampleId != live.capture.sampleId || request.descriptionHash != live.api->sampleDescriptionHash ||
        live.capture.verifiedSegments <= *page.apiPrefixAttempt) return;
    page.apiPrefixAttempt = live.capture.verifiedSegments;
    if (page.snapshot && page.snapshot->sample == page.requestedSample &&
        page.snapshot->checkpoint.lastVerifiedOrdinal >= *page.apiPrefixAttempt) return;
    Open(page, request.manifestPath, request, true);
}

void UpdateLiveMode(Page& page) {
    const bool api = ApiMode(page);
    const bool file = api && !LiveApiMode(page);
    ::ShowWindow(::GetParent(page.apiParameters.Body()), page.liveView && api ? SW_SHOW : SW_HIDE);
    for (const auto control : {page.livePid, page.liveProvider}) ::ShowWindow(control, page.liveView && !api ? SW_SHOW : SW_HIDE);
    ::ShowWindow(page.apiSource, page.liveView && api ? SW_SHOW : SW_HIDE);
    for (const auto control : {page.apiPid, page.apiCreation, page.apiPidLabel, page.apiCreationLabel})
    {
        ::ShowWindow(control, page.liveView && api && !LaunchApiMode(page) ? SW_SHOW : SW_HIDE);
    }
    for (const auto control : {page.apiExecutable, page.apiExecutableBrowse, page.apiExecutableLabel})
    {
        ::ShowWindow(control, page.liveView && api && LaunchApiMode(page) ? SW_SHOW : SW_HIDE);
    }
    ::ShowWindow(page.autoTransfer, page.liveView && api && LiveApiMode(page) ? SW_SHOW : SW_HIDE);
    for (const auto control : {page.apiSession, page.apiBrowse, page.apiPath}) ::ShowWindow(control, page.liveView && file ? SW_SHOW : SW_HIDE);
    ::ShowWindow(page.apiSourceLabel, page.liveView && api ? SW_SHOW : SW_HIDE);
    for (const auto control : {page.apiNetworkTrafficLabel, page.apiNetworkTraffic, page.apiCaptureAgentEtw})
    {
        ::ShowWindow(control, page.liveView && api ? SW_SHOW : SW_HIDE); // JSONL仍可辨识原选择，切换不重置。
    }
    for (const auto control : {page.apiSessionLabel, page.apiPathLabel}) ::ShowWindow(control, page.liveView && file ? SW_SHOW : SW_HIDE);
    for (const auto control : {page.apiDurationLabel, page.apiDuration}) {
        ::ShowWindow(control, page.liveView && api && !file ? SW_SHOW : SW_HIDE);
    }
    ::SendMessageW(page.apiPid, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(file ? L"归档源 PID" : L"目标 PID"));
    ::ShowWindow(page.liveApi, page.liveView ? SW_SHOW : SW_HIDE);
    ::ShowWindow(page.etwOnly, !page.liveView || !api ? SW_SHOW : SW_HIDE);
    ::EnableWindow(page.filter, !page.liveView || !api);
    ::SetWindowTextW(page.liveStart, file ? L"开始跟随" : L"开始采集");
    ::SetWindowTextW(page.liveFollow, api ? L"回放本次采样" : page.followLive ? L"暂停跟随" : L"恢复实时");
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
    enable(page.liveStart, !busy && !page.retiring && !page.apiConfirming && page.project.has_value());
    enable(page.liveStop, busy && !page.retiring && (!page.liveStopRequested || retry));
    enable(page.liveFollow, ApiMode(page) ? !page.retiring && CanReplayApi(page) : busy || page.liveProjection.has_value());
    for (const auto control : {page.liveApi, page.apiSource, page.apiPid, page.apiSession, page.apiCreation, page.apiBrowse, page.apiDuration}) enable(control, !busy && !page.retiring);
    enable(page.apiExecutableBrowse, !busy && !page.retiring); // 运行期间冻结EXE选择，已有草稿不被实际PID改写。
    enable(page.autoTransfer, !busy && !page.retiring);
    enable(page.apiNetworkTraffic, ApiMode(page) && LiveApiMode(page) && !busy && !page.retiring);
    enable(page.apiCaptureAgentEtw, ApiMode(page) && LiveApiMode(page) && !busy && !page.retiring); // 不清除禁用草稿。
    const wchar_t* stopText = retry ? L"重试清退" : L"停止采集";
    wchar_t current[32]{};
    ::GetWindowTextW(page.liveStop, current, static_cast<int>(std::size(current)));
    if (std::wstring_view(current) != stopText) ::SetWindowTextW(page.liveStop, stopText);
}

void SetLiveFollow(Page& page, bool enabled) {
    page.followLive = enabled;
    if (!ApiMode(page)) ::SetWindowTextW(page.liveFollow, enabled ? L"暂停跟随" : L"恢复实时");
}

void RefreshLive(Page& page) {
    const bool wasActive = page.liveStatus.active;
    page.liveStatus = page.live.ReadStatus();
    RefreshCommittedApiPrefix(page);
    if (page.liveView && !ApiMode(page) && page.followLive && ::IsWindowVisible(page.hwnd)) {
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
        if (wasActive && page.project && capture.projectId == page.project->projectId && !capture.sampleId.empty() &&
            (!page.liveStatus.api || page.liveStatus.api->manifestPath == page.project->manifestPath)) {
            page.catalogRefreshPending = true;
        }
        RefreshProjectAfterScan(page);
    }
    if (::IsWindowVisible(page.hwnd)) {
        UpdateLiveControls(page);
        UpdateStatus(page);
        if (page.liveView && ApiMode(page)) UpdateDetails(page);
    }
}

void ToggleView(Page& page, bool refreshStatus = true) {
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
    page.selected = page.liveView ? (ApiMode(page) ? std::nullopt : page.liveSelection) :
        page.samplePreview ? page.previewSelection : page.historySelection;
    const int showLive = page.liveView ? SW_SHOW : SW_HIDE;
    const int showHistory = page.liveView ? SW_HIDE : SW_SHOW;
    ::SetWindowTextW(page.switchView, page.liveView ? L"返回工程" : L"新一轮扫描");
    for (const auto control : {page.createProject, page.open, page.retry, page.capability, page.apiOnly, page.networkOnly}) {
        ::ShowWindow(control, showHistory);
    }
    for (const auto control : {page.liveStart, page.liveStop, page.liveFollow}) {
        ::ShowWindow(control, showLive);
    }
    UpdateLiveMode(page);
    for (const auto control : {page.sampleChoice, page.replaySample, page.cancelChoice}) {
        ::ShowWindow(control, !page.liveView && !page.choices.empty() ? SW_SHOW : SW_HIDE);
    }
    page.applyingProjection = true;
    ::SetWindowTextW(page.filter, (page.liveView ? page.liveFilter : page.historyFilter).c_str());
    ::SendMessageW(page.etwOnly, BM_SETCHECK, (page.liveView ? page.liveEtwOnly : page.historyEtwOnly) ? BST_CHECKED : BST_UNCHECKED, 0);
    page.applyingProjection = false;
    Layout(page);
    PresentResults(page);
    if (refreshStatus) RefreshLive(page);
}

void ReplayLiveApi(Page& page) {
    if (!page.liveView || !CanReplayApi(page) || page.catalogBusy) return;
    const auto& session = page.liveStatus;
    const ProjectReplayRequest replay{session.api->manifestPath, session.capture.projectId,
        session.capture.sampleId, session.api->sampleDescriptionHash};
    page.catalogRefreshPending = false;
    page.apiPrefixAttempt.reset();
    ::SetFocus(page.switchView);
    // 打开已冻结采样之后再继续查询状态，避免收尾刷新抢占后台读取槽。
    ToggleView(page, false);
    if (session.active) {
        // 采集中直接打开已提交采样，后续由现有显示定时器按段水位续读。
        page.apiPrefixAttempt = session.capture.verifiedSegments;
        Open(page, replay.manifestPath, replay, true);
        return;
    }
    OpenCatalog(page, replay.manifestPath, false, replay);
}

// Parse the full decimal value without accepting partial input or wraparound.
std::uint64_t ReadPositiveDecimal(HWND input, int maxDigits = 20) {
    wchar_t digits[22]{};
    const int length = ::GetWindowTextW(input, digits, static_cast<int>(std::size(digits)));
    if (length > maxDigits || length != ::GetWindowTextLengthW(input)) return 0;
    std::uint64_t value = 0;
    for (int i = 0; i < length; ++i) {
        if (digits[i] < L'0' || digits[i] > L'9') return 0;
        const auto digit = static_cast<std::uint64_t>(digits[i] - L'0');
        if (value > (UINT64_MAX - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    return value;
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
    if (!page.liveView || page.retiring || page.liveStatus.active || page.apiConfirming || !page.project) return;
    constexpr GUID kSysmonProvider{0x5770385f, 0xc22a, 0x43e0, {0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9}};
    NativeLiveRequest request;
    request.project = page.project; // 在确认框前冻结项目与修订，不能由嵌套消息循环换绑。
    const bool api = ApiMode(page);
    HWND pidBox = api ? page.apiPid : page.livePid;
    const auto pid = ReadPositiveDecimal(pidBox, 10);
    request.pid = api && LaunchApiMode(page) ? 0 : pid <= MAXDWORD ? static_cast<DWORD>(pid) : 0;
    page.liveInputError.clear();
    const auto source = ::SendMessageW(page.apiSource, CB_GETCURSEL, 0, 0); // 当前草稿只能选择一种来源。
    if (api && (source < 0 || source > 3)) {
        page.liveInputError = L"请选择一种 API 来源；JSONL、合作已装载、显式附加与启动EXE不能混用。";
    } else if (api && LaunchApiMode(page)) {
        const int length = ::GetWindowTextLengthW(page.apiExecutable); // 只冻结独立路径，不读取隐藏PID输入。
        if (!length)
        {
            page.liveInputError = L"请选择已授权的普通 AMD64 EXE。";
            ::SetFocus(page.apiExecutableBrowse);
        }
        else
        {
            request.api.emplace();
            request.api->launched = true;
            request.api->executable.resize(static_cast<std::size_t>(length) + 1);
            request.api->executable.resize(static_cast<std::size_t>(::GetWindowTextW(page.apiExecutable,
                request.api->executable.data(), length + 1)));
            request.api->autoTransfer = ::SendMessageW(page.autoTransfer, BM_GETCHECK, 0, 0) == BST_CHECKED;
            const auto index = ::SendMessageW(page.apiDuration, CB_GETCURSEL, 0, 0); // 本次Ready后时限。
            const auto duration = index == CB_ERR ? CB_ERR : ::SendMessageW(page.apiDuration, CB_GETITEMDATA, index, 0);
            if (duration == CB_ERR || duration < 0 || duration > 120000)
            {
                page.liveInputError = L"请选择采集时限；0 表示持续采集，有限区间从 Ready 起算。";
            }
            else
            {
                request.api->durationMs = static_cast<DWORD>(duration);
            }
        }
    } else if (!request.pid) {
        page.liveInputError = L"请输入有效的十进制 PID。";
        ::SetFocus(pidBox);
    } else if (api && LiveApiMode(page)) {
        const auto creation = ReadPositiveDecimal(page.apiCreation);
        if (!creation) {
            page.liveInputError = L"请填写目标实例的创建 FILETIME（十进制）。";
            ::SetFocus(page.apiCreation);
        } else {
            request.api = NativeLiveApiSource{{}, 0, creation, CooperativeMode(page)};
            request.api->explicitAttachment = AttachmentMode(page); // 不带文件/session，保持草稿但不提交隐藏字段。
            request.api->autoTransfer = ::SendMessageW(page.autoTransfer, BM_GETCHECK, 0, 0) == BST_CHECKED;
            const auto durationIndex = ::SendMessageW(page.apiDuration, CB_GETCURSEL, 0, 0); // 本次冻结的时限选项。
            const auto duration = durationIndex == CB_ERR ? CB_ERR :
                ::SendMessageW(page.apiDuration, CB_GETITEMDATA, durationIndex, 0); // 数据直接使用毫秒，不靠标签授权。
            if (duration == CB_ERR || duration < 0 || duration > 120000) {
                page.liveInputError = L"请选择采集时限；0 表示持续采集，有限区间从 Ready 起算。";
            } else {
                request.api->durationMs = static_cast<DWORD>(duration);
            }
            if (request.pid <= 4 || request.pid == ::GetCurrentProcessId()) {
                page.liveInputError = L"请选择其他已运行目标的有效 PID 与创建 FILETIME。";
            }
        }
    } else if (api) {
        const auto session = ReadPositiveDecimal(page.apiSession), creation = ReadPositiveDecimal(page.apiCreation);
        const int length = ::GetWindowTextLengthW(page.apiPath);
        if (!session || !creation || !length) {
            page.liveInputError = L"请选择授权 JSONL，并填写源会话 ID 和创建 FILETIME（十进制）。";
            ::SetFocus(!session ? page.apiSession : !creation ? page.apiCreation : page.apiBrowse);
        } else {
            std::wstring path(static_cast<std::size_t>(length) + 1, L'\0');
            path.resize(static_cast<std::size_t>(::GetWindowTextW(page.apiPath, path.data(), length + 1)));
            request.api = NativeLiveApiSource{std::move(path), session, creation};
        }
    } else if (!ReadLiveProvider(page.liveProvider, request.provider) || !request.provider) {
        page.liveInputError = L"请输入有效的 ETW 提供程序 GUID，以将本次扫描写入工程。";
        ::SetFocus(page.liveProvider);
    } else if (::IsEqualGUID(*request.provider, kSysmonProvider)) {
        page.liveInputError = L"ActionAnalyze 不支持 Sysmon ETW 提供程序。";
        ::SetFocus(page.liveProvider);
    }
    if (page.liveInputError.empty() && request.api && LiveApiMode(page))
    {
        // 在已有实例确认框前冻结来源；后端在原worker、同一sample中启动与关闭网络。
        request.api->captureAgentEtw = ::SendMessageW(page.apiCaptureAgentEtw, BM_GETCHECK, 0, 0) == BST_CHECKED; // 仅三种活API来源提交。
        const auto networkSource = ::SendMessageW(page.apiNetworkTraffic, CB_GETCURSEL, 0, 0); // 三值来源草稿。
        using Backend = Ksword::ActionAnalyze::NetworkTrafficBackend; // 使用共享定义，不重复声明后端枚举。
        if (networkSource == 1)
        {
            request.api->networkTraffic = Backend::RawSocket;
        }
        else if (networkSource == 2)
        {
            request.api->networkTraffic = Backend::ExistingWfp;
        }
        else if (networkSource != 0)
        {
            page.liveInputError = L"请选择网络采集来源：不采集、raw-socket 或 existing-wfp。";
            ::SetFocus(page.apiNetworkTraffic);
        }
    }
    if (!page.liveInputError.empty()) {
        UpdateStatus(page);
        return;
    }
    if (request.api && request.api->explicitAttachment) {
        // 系统确认框复用本端现有交互；仅授予本次冻结实例，关闭页面后不访问原Page。
        const HWND owner = page.hwnd; // 模态期间可能关闭的原生页句柄。
        const auto* expected = &page; // HWND复用时也必须仍是同一页面对象。
        const auto prompt = L"向 PID " + std::to_wstring(request.pid) + L"、创建 FILETIME " +
            std::to_wstring(request.api->creationFileTime) + L" 的已运行实例装载匹配架构的产品 Agent 并采集 API？\r\n"
            L"停止时恢复 Hook 并排空管道；Agent 按现有策略驻留到目标退出。";
        page.apiConfirming = true;
        const int answer = ::MessageBoxW(owner, prompt.c_str(), L"确认显式 API 附加", MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION);
        if (!::IsWindow(owner) || ::GetWindowLongPtrW(owner, GWLP_USERDATA) != reinterpret_cast<LONG_PTR>(expected)) return;
        page.apiConfirming = false;
        if (answer != IDYES || page.retiring || page.liveStatus.active || !page.project ||
            page.project->manifestPath != request.project->manifestPath ||
            page.project->projectId != request.project->projectId ||
            page.project->revisionId != request.project->revisionId) return;
        request.api->attachmentConfirmed = true; // worker仍重新核验创建时间及存活状态。
    }
    if (!::SetTimer(page.hwnd, kLiveDisplayTimer, kLiveDisplayIntervalMs, nullptr)) {
        page.liveInputError = L"无法创建实时显示计时器，请重试。";
    } else {
        const DWORD error = page.live.Start(std::move(request));
        if (!error) {
            page.liveInputError.clear();
            page.liveStopRequested = false;
            page.liveStatus.active = true; // 即使首个回读已经终止，也处理本次结束。
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
        // 对已选原始证据显示分类和同采样坐标，使用图内现有的正文行。
        if (const auto relation = ArchivedRelationText(*record); !relation.empty()) {
            line(relation, { x, y + Scale(24), page.graph.right, y + Scale(58) });
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
            page.liveApi, page.livePid, page.liveProvider, page.apiSource, page.apiPid, page.apiSession, page.apiCreation, page.apiDuration, page.apiBrowse, page.apiPath,
            page.apiExecutable, page.apiExecutableBrowse, page.apiNetworkTraffic, page.apiCaptureAgentEtw, page.autoTransfer, page.liveStart, page.liveStop, page.liveFollow,
            page.categories, page.filter, page.apiOnly, page.etwOnly, page.networkOnly,
            page.evidenceFamily, page.evidenceRecord, page.locateEvidence,
            page.timeline.hwnd(), page.list.hwnd(), page.prepareExecutionAddress, page.prepareExecutionRange,
            page.transferTree.hwnd(), page.details, page.status }; // 草稿动作与候选树共用原Tab／Shift+Tab顺序。
        const auto found = std::find(order.begin(), order.end(), hwnd);
        const auto size = static_cast<int>(order.size());
        auto index = static_cast<int>(found - order.begin());
        const int direction = (::GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
        for (int i = 0; i < size; ++i) {
            if ((direction < 0 && index == 0) || (direction > 0 && index == size - 1)) {
                if (::SendMessageW(::GetParent(page.hwnd), kFocusLightNativeToolbar, direction < 0, 0)) return 0;
            }
            index = (index + direction + size) % size;
            const HWND next = order[static_cast<std::size_t>(index)];
            if (::IsWindowEnabled(next) && ::IsWindowVisible(next)) {
                page.apiParameters.Reveal(next); // 键盘遍历滚到参数，固定动作和结果不跟着移动。
                ::SetFocus(next);
                break;
            }
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
    page.liveApi = ::CreateWindowExW(0, L"BUTTON", L"API 采样", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kLiveApi)), ::GetModuleHandleW(nullptr), nullptr);
    if (!page.apiParameters.Create(page.hwnd)) return false;
    const HWND apiBody = page.apiParameters.Body(); // API 参数的唯一正文宿主，复用共享滚动/主题。
    page.apiSource = ::CreateWindowExW(0, WC_COMBOBOXW, L"API 来源", WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, apiBody, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kApiSource)), ::GetModuleHandleW(nullptr), nullptr);
    if (!page.apiSource || ::SendMessageW(page.apiSource, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"JSONL 跟随")) != 0 ||
        ::SendMessageW(page.apiSource, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"合作已装载")) != 1 ||
        ::SendMessageW(page.apiSource, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"显式附加")) != 2 ||
        ::SendMessageW(page.apiSource, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"启动EXE并采集")) != 3) return false;
    ::SendMessageW(page.apiSource, CB_SETCURSEL, 0, 0);
    page.apiPid = MakeEdit(apiBody, kApiPid, ES_AUTOHSCROLL | ES_NUMBER);
    page.apiSession = MakeEdit(apiBody, kApiSession, ES_AUTOHSCROLL | ES_NUMBER);
    page.apiCreation = MakeEdit(apiBody, kApiCreation, ES_AUTOHSCROLL | ES_NUMBER);
    page.autoTransfer = ::CreateWindowExW(0, L"BUTTON", L"自动接管跨进程私有执行目标",
        WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX, 0, 0, 0, 0, apiBody,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kAutoTransfer)), ::GetModuleHandleW(nullptr), nullptr);
    page.apiBrowse = Ui::CreateButton(apiBody, kApiBrowse, L"选择授权 JSONL…", 0, 0, 0, 0);
    page.apiPath = MakeEdit(apiBody, kApiPath, ES_AUTOHSCROLL | ES_READONLY);
    page.apiExecutable = MakeEdit(apiBody, kApiExecutable, ES_AUTOHSCROLL | ES_READONLY);
    page.apiExecutableBrowse = Ui::CreateButton(apiBody, kApiExecutableBrowse, L"选择 EXE…", 0, 0, 0, 0);
    page.apiExecutableLabel = Ui::CreateText(apiBody, 0, L"启动 EXE", 0, 0, 0, 0);
    page.apiSourceLabel = Ui::CreateText(apiBody, 0, L"API 来源", 0, 0, 0, 0);
    page.apiPidLabel = Ui::CreateText(apiBody, 0, L"来源 PID", 0, 0, 0, 0);
    page.apiCreationLabel = Ui::CreateText(apiBody, 0, L"进程创建 FILETIME", 0, 0, 0, 0);
    page.apiSessionLabel = Ui::CreateText(apiBody, 0, L"来源会话 ID（仅 JSONL）", 0, 0, 0, 0);
    page.apiPathLabel = Ui::CreateText(apiBody, 0, L"本地 API JSONL", 0, 0, 0, 0);
    // 在原参数画布创建时限选择器；零持续，有限时长交给原会话从Ready后计算。
    page.apiDurationLabel = Ui::CreateText(apiBody, 0, L"采集时限（秒，0 为持续）", 0, 0, 0, 0);
    page.apiDuration = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, apiBody, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kApiDuration)), ::GetModuleHandleW(nullptr), nullptr);
    if (!page.apiDuration) return false;
    for (const DWORD seconds : {0UL, 1UL, 5UL, 10UL, 30UL, 60UL, 120UL}) { // 复用后端允许的0或1–120秒范围。
        const std::wstring label = seconds == 0 ? L"持续采集" : std::to_wstring(seconds); // 单位来自可见标签。
        const auto index = ::SendMessageW(page.apiDuration, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
        if (index == CB_ERR || index == CB_ERRSPACE ||
            ::SendMessageW(page.apiDuration, CB_SETITEMDATA, index, seconds * 1000) == CB_ERR) return false;
    }
    ::SendMessageW(page.apiDuration, CB_SETCURSEL, 0, 0);
    // 原参数正文中的网络选择器只保存草稿，默认不启用；两个采集来源不做隐式回退。
    page.apiNetworkTrafficLabel = Ui::CreateText(apiBody, 0, L"网络采集", 0, 0, 0, 0);
    page.apiNetworkTraffic = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, apiBody, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kApiNetworkTraffic)), ::GetModuleHandleW(nullptr), nullptr);
    if (!page.apiNetworkTraffic || !page.apiNetworkTrafficLabel ||
        ::SendMessageW(page.apiNetworkTraffic, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"不采集")) != 0 ||
        ::SendMessageW(page.apiNetworkTraffic, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"raw-socket")) != 1 ||
        ::SendMessageW(page.apiNetworkTraffic, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"existing-wfp")) != 2)
    {
        return false;
    }
    ::SendMessageW(page.apiNetworkTraffic, CB_SETCURSEL, 0, 0);
    page.apiCaptureAgentEtw = ::CreateWindowExW(0, L"BUTTON", L"采集自有 Agent ETW",
        WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX, 0, 0, 0, 0, apiBody,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kApiCaptureAgentEtw)), ::GetModuleHandleW(nullptr), nullptr); // 默认关闭，复用原生参数主题。
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
    page.evidenceFamilyLabel = Ui::CreateText(page.hwnd, 0, L"关系分组", 0, 0, 0, 0);
    page.evidenceFamily = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEvidenceFamily)),
        ::GetModuleHandleW(nullptr), nullptr);
    page.evidenceRecordLabel = Ui::CreateText(page.hwnd, 0, L"组内记录", 0, 0, 0, 0);
    page.evidenceRecord = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, page.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEvidenceRecord)),
        ::GetModuleHandleW(nullptr), nullptr);
    page.locateEvidence = Ui::CreateButton(page.hwnd, kLocateEvidence, L"定位原始记录", 0, 0, 0, 0);
    if (!page.switchView || !page.livePid || !page.liveProvider || !page.liveStart || !page.liveStop || !page.liveFollow ||
        !page.apiExecutable || !page.apiExecutableBrowse || !page.apiExecutableLabel || !page.apiCaptureAgentEtw ||
        !page.liveApi || !page.apiPid || !page.apiSession || !page.apiCreation || !page.apiBrowse || !page.apiPath || !page.autoTransfer ||
        !page.apiSourceLabel || !page.apiPidLabel || !page.apiCreationLabel || !page.apiSessionLabel || !page.apiPathLabel || !page.apiDurationLabel ||
        !page.createProject || !page.open || !page.retry || !page.actions || !page.capability || !page.categories || !page.filterLabel ||
        !page.filter || !page.etwOnly || !page.apiOnly || !page.networkOnly || !page.evidenceFamilyLabel ||
        !page.evidenceFamily || !page.evidenceRecordLabel || !page.evidenceRecord || !page.locateEvidence) return false;
    ::ShowWindow(page.evidenceFamilyLabel, SW_HIDE);
    ::ShowWindow(page.evidenceRecordLabel, SW_HIDE);
    ::ShowWindow(page.locateEvidence, SW_HIDE);
    ::EnableWindow(page.evidenceRecord, FALSE);
    ::EnableWindow(page.locateEvidence, FALSE);
    for (const auto control : {page.liveStart, page.liveStop, page.liveFollow}) {
        ::ShowWindow(control, SW_HIDE);
    }
    ::SendMessageW(page.livePid, EM_SETLIMITTEXT, 11, 0);
    ::SendMessageW(page.liveProvider, EM_SETLIMITTEXT, 39, 0);
    ::SendMessageW(page.livePid, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"自有进程 PID"));
    ::SendMessageW(page.liveProvider, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"ETW 提供程序 GUID"));
    ::SendMessageW(page.apiPid, EM_SETLIMITTEXT, 11, 0);
    ::SendMessageW(page.apiSession, EM_SETLIMITTEXT, 21, 0);
    ::SendMessageW(page.apiCreation, EM_SETLIMITTEXT, 21, 0);
    ::SendMessageW(page.apiSession, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"源会话 ID"));
    ::SendMessageW(page.apiCreation, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"创建 FILETIME"));
    ::SendMessageW(page.apiPath, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"未选择 JSONL"));
    ::SendMessageW(page.apiExecutable, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"未选择 EXE"));
    UpdateLiveMode(page);
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
    page.transferTree.Create(page.hwnd, kTransferCandidates);
    if (!page.transferTree.hwnd()) return false;
    page.prepareExecutionAddress = Ui::CreateButton(page.hwnd, kPrepareExecutionAddress, L"准备地址草稿", 0, 0, 0, 0);
    page.prepareExecutionRange = Ui::CreateButton(page.hwnd, kPrepareExecutionRange, L"准备范围草稿", 0, 0, 0, 0);
    if (!page.prepareExecutionAddress || !page.prepareExecutionRange) return false;
    ::EnableWindow(page.prepareExecutionAddress, FALSE); // 无原生来源时不提供虚假可用入口。
    ::EnableWindow(page.prepareExecutionRange, FALSE);
    AddButtonTip(page.tooltip, page.hwnd, page.prepareExecutionAddress, L"将当前私有执行观察的原进程实例与实际指令地址加入未启动的执行集合；不覆盖输入、不附加目标。");
    AddButtonTip(page.tooltip, page.hwnd, page.prepareExecutionRange, L"将包含实际指令的原已纳入 NX 范围加入未启动的执行集合；不扩大范围，现场资格在显式开始时重新核对。");
    AddButtonTip(page.tooltip, page.hwnd, page.transferTree.hwnd(), L"来源声明候选不证明实际执行或强归因。展开后双击或按 Enter 定位写入、线程创建双方原包。");
    AddButtonTip(page.tooltip, page.hwnd, page.createProject, L"在指定的新文件夹中建立一个行为分析工程");
    AddButtonTip(page.tooltip, page.hwnd, page.open, L"打开已有行为分析工程");
    AddButtonTip(page.tooltip, page.hwnd, page.retry, L"按上次请求的路径和采样身份重读");
    AddButtonTip(page.tooltip, page.hwnd, page.replaySample, L"从首段开始核验并回放当前采样的可读范围");
    AddButtonTip(page.tooltip, page.hwnd, page.cancelChoice, L"取消采样预览并回到当前工程");
    AddButtonTip(page.tooltip, page.hwnd, page.apiOnly, L"显示归档 API 线索。可与其他来源同时选择。");
    AddButtonTip(page.tooltip, page.hwnd, page.etwOnly, L"显示 ETW 观察。回放时可与其他来源同时选择。");
    AddButtonTip(page.tooltip, page.hwnd, page.networkOnly, L"显示已核验的归档网络流。可与其他来源同时选择。");
    AddButtonTip(page.tooltip, page.hwnd, page.evidenceFamily, L"浏览当前回放窗口的未解析候选和来源上下文。分组独立于表格筛选。");
    AddButtonTip(page.tooltip, page.hwnd, page.evidenceRecord, L"按实际归档顺序倒排，可选择该组的任意一条原始记录。");
    AddButtonTip(page.tooltip, page.hwnd, page.locateEvidence, L"查看所选原始记录。筛选隐藏该行时仍显示详情。");
    AddButtonTip(page.tooltip, page.hwnd, page.switchView, L"在当前工程中开始新一轮被动扫描，或返回工程目录");
    AddButtonTip(page.tooltip, page.hwnd, page.livePid, L"输入自有进程的十进制 PID");
    AddButtonTip(page.tooltip, page.hwnd, page.liveProvider, L"输入 ETW 提供程序 GUID 以观察指定进程并将记录归档");
    AddButtonTip(page.tooltip, page.hwnd, page.liveStop, L"停止观察并清退本次采集会话，可重试失败的清退");
    AddButtonTip(page.tooltip, page.hwnd, page.liveApi, L"选中时使用 API 来源；未选中时使用 ETW");
    AddButtonTip(page.tooltip, page.hwnd, page.apiSource, L"JSONL 跟随、合作已装载、显式附加、启动EXE并采集四选一；启动EXE在入口停止后自动附加 Agent，Ready后恢复主线程，此前TLS/loader不在覆盖范围。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiExecutableBrowse, L"选择普通 AMD64 EXE；开始后自动创建并采集，不需要手填PID或另行附加。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiExecutable, L"本次待启动EXE的独立路径；原JSONL和已有实例草稿保留，实际PID与创建时间见回执。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiSession, L"填写来源声明中的源会话 ID（十进制）");
    AddButtonTip(page.tooltip, page.hwnd, page.apiCreation, L"填写源进程或活采目标的创建 FILETIME（十进制）；与 PID 一起冻结实例。");
    AddButtonTip(page.tooltip, page.hwnd, page.autoTransfer, L"在已覆盖的线程创建、APC和上下文调用前自动解析私有范围并设防；执行命中保存后自动继续，失败单独报告。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiPid, L"填写明确授权目标或 JSONL 来源的十进制 PID，创建时间不匹配时拒绝采集。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiBrowse, L"选择明确授权的本地 API JSONL；切到活采时保留文件草稿但不提交它。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiDuration, L"从 Agent Ready 与覆盖核验通过后计时，最多 120 秒；0 表示持续采集。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiNetworkTraffic, L"与 API 使用同一采样和写入线程；自动接管时在调用放行前追加目标，根进程退出后继续采集。报文归属仍为 PID 线索，不解密 HTTPS。JSONL 跟随不启用。");
    AddButtonTip(page.tooltip, page.hwnd, page.apiCaptureAgentEtw, L"与 API 使用同一采样；自动接管目标在调用放行前加入同一 ETW 来源。报头 PID 仅作线索，JSONL 跟随不启用。");
    AddButtonTip(page.tooltip, page.hwnd, page.liveStart, L"按当前项目和来源开始采集；显式附加先确认精确实例。活采时限从 Ready 起算，0 为持续。");
    AddButtonTip(page.tooltip, page.hwnd, page.liveFollow, L"回放本次 API 采样，或暂停、恢复 ETW 结果更新");
    for (HWND child : {page.createProject, page.open, page.switchView, page.retry, page.sampleChoice, page.replaySample, page.cancelChoice,
        page.liveApi, page.livePid, page.liveProvider, page.apiSource, page.apiPid, page.apiSession, page.apiCreation, page.apiDuration, page.apiBrowse, page.apiPath,
        page.autoTransfer, page.apiExecutable, page.apiExecutableBrowse, page.apiNetworkTraffic, page.apiCaptureAgentEtw, page.liveStart, page.liveStop, page.liveFollow,
        page.categories, page.filter, page.apiOnly, page.etwOnly, page.networkOnly,
        page.evidenceFamily, page.evidenceRecord, page.locateEvidence,
        page.timeline.hwnd(), page.list.hwnd(), page.prepareExecutionAddress, page.prepareExecutionRange,
        page.transferTree.hwnd(), page.details, page.status}) { // 复用既有键盘遍历子类，不另加全局快捷键。
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
        if (page->evidenceDropdown &&
            !::SendMessageW(page->evidenceDropdown->control, CB_GETDROPPEDSTATE, 0, 0)) CancelEvidenceDropdown(*page);
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
        if (const auto child = reinterpret_cast<HWND>(lp); child == page->livePid || child == page->liveProvider ||
            child == page->apiPid || child == page->apiSession || child == page->apiCreation) {
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
        if (child == page->details || child == page->status || child == page->apiPath || child == page->apiExecutable) {
            ::SetTextColor(dc, theme.textColor);
            ::SetBkColor(dc, theme.panelColor);
            return reinterpret_cast<LRESULT>(theme.panelBrush());
        }
        if (child == page->projection) return Ui::PaintLabelBackground(dc, child, theme.panelBrush(), theme.textColor);
        if (const LRESULT brush = Ui::PaintLabelBackground(dc, child, theme.windowBrush(), theme.textColor)) return brush;
        break;
    }
    case WM_COMMAND:
        if ((LOWORD(wp) == kPrepareExecutionAddress || LOWORD(wp) == kPrepareExecutionRange) &&
            HIWORD(wp) == BN_CLICKED && !page->retiring && !page->liveView)
        {
            const auto* history = page->transferTree.History(); // 点击时冻结当前树来源，不使用残留旧详情。
            const auto* candidate = page->transferTree.Execution(); // 一致性候选和独立历史共用同一转换。
            const auto* source = history ? &history->sourceDocument : candidate ? &candidate->sourceDocument : nullptr;
            const auto draft = source ? Ksword::Evidence::PrepareNativeExecutionSiteDraft(*source,
                LOWORD(wp) == kPrepareExecutionRange) : std::nullopt;
            if (draft && !PrepareExecutionGroupEvidenceDraft(hwnd, *draft))
            {
                page->requestStatus = L"执行集合未接收草稿：请先清退并返回草稿，检查重复 PID。";
                UpdateStatus(*page);
            }
            return 0;
        }
        if (HIWORD(wp) == BN_CLICKED && !page->retiring) {
            switch (LOWORD(wp)) {
            case kSwitchView: if (!page->catalogBusy) ToggleView(*page); return 0;
            case kLiveApi:
                if (page->liveView && !page->liveStatus.active) {
                    page->liveInputError.clear();
                    page->selected = ApiMode(*page) ? std::nullopt : page->liveSelection;
                    UpdateLiveMode(*page);
                    Layout(*page);
                    PresentResults(*page);
                    RefreshLive(*page);
                }
                return 0;
            case kApiBrowse:
                if (page->liveView && ApiMode(*page) && !LiveApiMode(*page) && !page->liveStatus.active) BrowseApi(*page);
                return 0;
            case kApiExecutableBrowse:
                if (page->liveView && ApiMode(*page) && LaunchApiMode(*page) && !page->liveStatus.active) BrowseApi(*page);
                return 0;
            case kLiveStart: StartLive(*page); return 0;
            case kLiveStop:
                page->liveStopRequested = true;
                page->live.Stop();
                RefreshLive(*page);
                return 0;
            case kLiveFollow:
                if (ApiMode(*page)) { ReplayLiveApi(*page); return 0; }
                SetLiveFollow(*page, !page->followLive);
                RefreshLive(*page);
                return 0;
            }
        }
        if (LOWORD(wp) == kApiSource && page->liveView && !page->retiring && !page->liveStatus.active &&
            (HIWORD(wp) == CBN_CLOSEUP || (HIWORD(wp) == CBN_SELCHANGE && !::SendMessageW(page->apiSource, CB_GETDROPPEDSTATE, 0, 0)))) {
            page->liveInputError.clear();
            UpdateLiveMode(*page);
            UpdateLiveControls(*page); // 来源切换即同步网络选择资格，JSONL禁用且不重置草稿。
            Layout(*page);
            UpdateStatus(*page);
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
        if (LOWORD(wp) == kEvidenceFamily || LOWORD(wp) == kEvidenceRecord) {
            const auto combo = reinterpret_cast<HWND>(lp);
            const auto notice = HIWORD(wp);
            const bool tracking = page->evidenceDropdown && page->evidenceDropdown->control == combo;
            if (notice == CBN_DROPDOWN && !page->applyingProjection && !page->retiring) {
                page->evidenceDropdown = EvidenceDropdown{combo, ::SendMessageW(combo, CB_GETCURSEL, 0, 0)};
            }
            if (notice == CBN_SELENDCANCEL && tracking) page->evidenceDropdown->canceled = true;
            const bool closing = notice == CBN_CLOSEUP && tracking;
            const bool canCommit = !page->applyingProjection && !page->retiring;
            if (closing && (page->evidenceDropdown->canceled || !canCommit)) {
                RestoreEvidenceDropdownSelection(*page);
            } else if (canCommit && (closing || (notice == CBN_SELCHANGE && !tracking &&
                !::SendMessageW(combo, CB_GETDROPPEDSTATE, 0, 0)))) {
                if (closing) page->evidenceDropdown.reset();
                if (LOWORD(wp) == kEvidenceFamily) SetEvidenceFamilyChoice(*page);
                else if (const auto* archive = BrowsableArchive(*page)) SetEvidenceRecordChoice(*page, *archive);
            }
            if (notice == CBN_CLOSEUP) ResumeArchiveRead(*page);
            return 0;
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
        if (notice.idFrom == kTransferCandidates) {
            if (notice.code == TVN_SELCHANGEDW)
            {
                const auto* history = page->transferTree.History(); // 新旧树切换也立即清除原草稿动作资格。
                const auto* candidate = page->transferTree.Execution();
                const auto* source = history ? &history->sourceDocument : candidate ? &candidate->sourceDocument : nullptr;
                ::EnableWindow(page->prepareExecutionAddress, !page->retiring && source &&
                    Ksword::Evidence::PrepareNativeExecutionSiteDraft(*source, false).has_value());
                ::EnableWindow(page->prepareExecutionRange, !page->retiring && source &&
                    Ksword::Evidence::PrepareNativeExecutionSiteDraft(*source, true).has_value());
            }
            if (notice.code == TVN_SELCHANGEDW && !page->applyingProjection &&
                (SelectedBehaviorRecord(*page) || page->transferTree.Execution() || page->transferTree.History()))
            {
                LocateTransferCandidate(*page); // 行为和原生叶随选择更新只读详情，不发起 I/O。
            }
            if (notice.code == NM_DBLCLK || (notice.code == TVN_KEYDOWN &&
                reinterpret_cast<const NMTVKEYDOWN*>(lp)->wVKey == VK_RETURN)) {
                if (SelectedBehaviorRecord(*page) || page->transferTree.Activate() ||
                    page->transferTree.Execution() || page->transferTree.History()) {
                    LocateTransferCandidate(*page);
                } else if (notice.code == TVN_KEYDOWN) {
                    const auto node = TreeView_GetSelection(page->transferTree.hwnd()); // Enter 只切换分组展开。
                    TreeView_Expand(page->transferTree.hwnd(), node, TVE_TOGGLE);
                }
                return 0;
            }
        }
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
        if (!wp && page->evidenceDropdown) CancelEvidenceDropdown(*page);
        else ResumeArchiveRead(*page);
        if (wp && page->status)
        {
            RefreshBehaviorLanguage(*page);
            RefreshLive(*page);
        }
        break;
    case WM_SETTINGCHANGE:
        if (page->status)
        {
            RefreshBehaviorLanguage(*page);
        }
        break;
    case Ui::kBeginNativeRetirementMessage:
        page->retiring = true;
        CancelEvidenceDropdown(*page);
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
        if (::IsWindowVisible(page->evidenceFamily) &&
            (::SendMessageW(page->evidenceFamily, CB_GETDROPPEDSTATE, 0, 0) ||
                ::SendMessageW(page->evidenceRecord, CB_GETDROPPEDSTATE, 0, 0))) {
            // 完成值仍由单个异步槽持有，旧归档与展开的关系行保持一致。
            if (!page->deferredRead || page->deferredRead->first <= wp) page->deferredRead.emplace(wp, lp);
            return 0;
        }
        page->task->consume(hwnd, wp, lp);
        RefreshCommittedApiPrefix(*page);
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

HWND CreateActionAnalyzeExecutionWorkspace(HWND parent, const RECT& bounds) {
    // 真实页面目录在此登记；旧工厂保留其单目标页、集合暂停页及纯UI端口所有权。
    Ui::WorkspaceOptions options{};
    options.tabControlId = 58790;
    options.initialTabId = 1;
    return Ui::CreateWorkspaceHost(parent, bounds, {
        {1, L"工程、采集与进程控制", L"原有工程、单目标停点和进程集合控制工作台。",
            [](HWND host, const RECT& area) { return CreateActionAnalyzeControlWorkspace(host, area); }},
        {2, L"执行断点集合", L"冻结明确选择的进程站点，逐成员暂停、继续、步进和清退。",
            [](HWND host, const RECT& area) { return CreateExecutionGroupPage(host, area); }},
        // 稳定目录ID=3；直接进入原网络页，不复制采集器或另建宿主线程。
        {3, L"网络流量", L"选择目标进程并查看归档网络流量。",
            [](HWND host, const RECT& area) { return CreateNetworkTrafficPage(host, area); }},
    }, std::move(options));
}

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
