#pragma once

// T 模块：统一时间线与调查会话（分析层）。
//
// 这一层不采集任何东西。ETW / Callback Monitor / File Monitor 仍然是既有采集器；
// 本文件只提供"会话状态、事件 envelope、时间语义、进程归属、丢失账目、过滤分离、
// 有界与保留、保存与恢复、关系边"这九件判据，使同一套判据既能被离线样本驱动，
// 也能被真实采集驱动。
//
// 贯穿全模块的硬规则：
//   * T-01：**"暂停显示"与"停止采集"是两件事**。暂停只冻结 UI，后台继续记账与落盘；
//     停止之后不得再记入任何新事件。任何转移都必须显式说明"后台是否仍在记录"。
//   * T-02：未知 event version **不得**套用旧版本结构。未知就保存成未解析记录，
//     原始字段与原始载荷一并保留，解析版本单独记账。
//   * T-04：跨源不存在严格全序。排序键是确定的、可解释的，但"确定"来自 tiebreak
//     规则而不是来自"时间戳精确可比"这个假象；不可分辨的相邻顺序必须标出来。
//     两个时间相减一律走有符号路径 —— 无符号回绕会把 1ms 的回拨报成天文数字。
//   * T-05：缺进程开始事件时建立"身份不完整"的临时实体，**绝不**静默归给当前同
//     PID 的进程。PID 复用与"目标已结束后的迟到事件"必须能各自区分。
//   * T-06：六类丢失分开计数、不重复计数、0 也必须有具名统计来源；来源只给总计时
//     不得编造精确丢失时间区间。
//   * T-12：关系不是因果。因果措辞只允许出现在 SourceProvidedLink 上。
//
// 本层不产出恶意判定，也没有 malicious/threat/suspicious/riskScore 之类字段。

#include "EvidenceEnvelope.h"
#include "EvidenceJson.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Ksword::Evidence {

// ===========================================================================
// T-01 会话生命周期
// ===========================================================================

// 五个状态。DisplayPaused 与 Stopped 是两个独立状态 —— 既有实现把它们混成同一个
// 按钮，并且在 ETW 回调里直接 return（暂停 = 静默丢事件），这里从类型上堵死。
enum class SessionState {
    New,           // 已新建，未开始；范围与上限可改
    Collecting,    // 后台记录 + UI 刷新
    DisplayPaused, // UI 冻结，**后台仍在记录**
    Stopped,       // 采集已停；不再记入新事件，可保存
    Saved,         // 已落盘；只读
};

const char* SessionStateName(SessionState state) noexcept;

// T-01：停止后不得再记入新事件。只有这两个状态接纳新事件。
bool SessionAcceptsNewEvents(SessionState state) noexcept;

// T-01：UI 是否随事件刷新。DisplayPaused 时为 false，但这不影响上面那条。
bool SessionUpdatesDisplay(SessionState state) noexcept;

enum class SessionAction {
    Start,           // 开始采集
    PauseDisplay,    // 暂停显示（后台继续）
    ResumeDisplay,   // 继续显示
    StopCollection,  // 停止采集
    Save,            // 保存
    Reset,           // 新建（丢弃当前会话内容，回到 New）
};

const char* SessionActionName(SessionAction action) noexcept;

// 转移判据。allowed=false 时 nextState 保持 current，且 backgroundRecording /
// displayUpdating 描述的仍是**当前**状态 —— 非法动作不改变任何事实。
struct SessionTransition final {
    bool allowed = false;
    SessionState nextState = SessionState::New;
    bool backgroundRecording = false;  // 转移后后台是否仍在记录
    bool displayUpdating = false;      // 转移后 UI 是否随事件刷新
    // 暂停期的缓存/落盘策略说明键（T-01 通过条件："暂停期间的缓存/落盘策略可见"）。
    std::string bufferingNoticeKey;
    std::string rejectionKey;  // allowed=false 时的 i18n 原因键，合法转移时为空
};

SessionTransition EvaluateSessionTransition(SessionState current, SessionAction action);

// ===========================================================================
// T-02 事件 envelope 与解析结果
// ===========================================================================

// 首轮必需的六类。Other 用于已声明范围之外的事件，它不是"未知解析"的同义词。
enum class TimelineEventCategory {
    Process,
    Thread,
    Image,
    File,
    Registry,
    Network,
    Other,
};

const char* TimelineEventCategoryName(TimelineEventCategory category) noexcept;

// T-02：解析结果三态。默认是 UnparsedUnknownSchema —— 忘记跑解析器不能白得一个
// "已解析"，这正是既有实现（fallback 分支也把 decodedReady 置 true）的问题。
enum class EventParseOutcome {
    Parsed,                // 命中精确 (provider,eventId,version) 的解析器
    UnparsedUnknownSchema, // 没有该版本的解析器 —— 保存为未解析记录，不套旧结构
    Malformed,             // 载荷本身不合法/被截断，连原始字段都不完整
};

const char* EventParseOutcomeName(EventParseOutcome outcome) noexcept;

// 原始字段：名字 -> 原文。未解析记录同样保留它，供导出与后续重放。
using RawFieldList = std::vector<std::pair<std::string, std::string>>;

// 时间精度。跨源比较时用它换算"不可分辨窗口"，不是显示格式。
enum class TimeResolution {
    Unknown,
    Second,
    Millisecond,
    Microsecond,
    HundredNanosecond,
};

const char* TimeResolutionName(TimeResolution resolution) noexcept;

// 精度对应的不可分辨跨度（100ns 单位）。Unknown 返回 0，调用方据此判"无法界定"。
std::uint64_t ResolutionSpan100ns(TimeResolution resolution) noexcept;

// ===========================================================================
// T-04 时间语义
//
// 时钟校准是一份可用可不用的独立事实，绝不就地改写源时间：源时间原样保存，
// 校准偏移单独记录，"有效时间"是派生量。
// ===========================================================================

struct EventTimeStamp final {
    OptionalU64 sourceTime100ns;   // 来源给的原始时间，任何路径都不得改写
    OptionalU64 receiveTime100ns;  // R3 收到（入队）时刻
    TimeResolution sourceResolution = TimeResolution::Unknown;

    // 校准：有就记下来，展示时可用；sourceTime100ns 永远保持原值。
    bool calibrationAvailable = false;
    std::int64_t calibrationOffset100ns = 0;
    std::string calibrationId;  // 校准来源标识，校准变化时该 id 变

    std::string bootId;             // 启动周期。跨 bootId 的时间值不可相减
    OptionalU64 sourceMonotonic;    // QPC 计数，仅同 bootId 内可比

    bool lateArrival = false;    // 迟到补入（接收顺序晚于时间顺序）
    bool orderUncertain = false; // 与相邻事件的先后在精度内不可分辨

    // 有效时间 = 源时间（若有校准则叠加，饱和不回绕）；源时间缺失时退化到接收时间。
    // 第二个返回值说明用的是哪一个口径，UI 必须显示出来。
    OptionalU64 effectiveTime100ns() const noexcept;
    bool effectiveFromReceiveTime() const noexcept;
};

// 两个时间的比较结论。绝不用无符号相减：X 模块上一轮就栽在回绕上（实测把 1ms
// 回拨报成 5.8e13 年）。
enum class TimeComparison {
    Comparable,             // 顺序确定
    ComparableButUncertain, // 差值落在精度内（含时间戳完全相同）—— 顺序不可分辨
    IncomparableCrossBoot,  // 跨启动周期，时间值无可比性
    IncomparableUnknownTime,// 任一侧没有可用时间
    IncomparableMagnitude,  // 差值超出 int64 表示范围，宁可判不可比也不回绕
};

const char* TimeComparisonName(TimeComparison comparison) noexcept;

struct TimeComparisonResult final {
    TimeComparison kind = TimeComparison::IncomparableUnknownTime;
    std::int64_t delta100ns = 0;  // later - earlier，仅 Comparable* 时有效
    bool regression = false;      // later 的时间早于 earlier（乱序或时钟回拨）
    bool calibrationChanged = false;  // 两侧 calibrationId 不同 —— 顺序解释需附注

    bool comparable() const noexcept {
        return kind == TimeComparison::Comparable || kind == TimeComparison::ComparableButUncertain;
    }
};

// earlier / later 只是参数名，不预设顺序；regression 表示实际顺序与参数顺序相反。
TimeComparisonResult CompareEventTimes(const EventTimeStamp& earlier,
                                       const EventTimeStamp& later) noexcept;

// 跨源排序键。确定 = 全部字段参与比较且最后有唯一 tiebreak；可解释 = explanationKey
// 说明这一条为什么排在这里。**不宣称跨 CPU/源严格全序**：同一 explanationKey 为
// "tie-broken-by-arrival" 的两条，其真实先后是未知的。
struct TimelineSortKey final {
    std::uint32_t bootEpochRank = 0;    // bootId 首次出现的次序；跨 boot 只按它分组
    bool timeKnown = false;             // 有效时间是否可用
    std::uint64_t effectiveTime100ns = 0;
    std::uint64_t arrivalSequence = 0;  // R3 接收序号，确定性 tiebreak
    std::string sourceGroup;            // 来源分组，稳定 tiebreak
    std::string recordId;               // 最终唯一 tiebreak
    std::string explanationKey;         // 该键的排序依据说明（i18n 键）
};

// 严格弱序。时间未知的排在时间已知的之后（而不是被当成 0 排到最前）。
bool SortKeyLess(const TimelineSortKey& a, const TimelineSortKey& b) noexcept;

// ===========================================================================
// T-05 进程归属
// ===========================================================================

enum class AttributionKind {
    BoundToInstance,   // 落在某个已知实例的存活窗口内
    Provisional,       // 缺开始事件/落在所有已知窗口之外 —— 建立身份不完整临时实体
    AfterInstanceExit, // 已知同 PID 实例已结束，且事件时间在其之后又无新实例覆盖
    Ambiguous,         // 多个同 PID 实例窗口重叠地覆盖了该时间 —— 不猜
    UnknownProcess,    // 连 PID 都没有
};

const char* AttributionKindName(AttributionKind kind) noexcept;

// 临时实体。identityComplete 恒为 false，直到 confirmProvisional() 补齐证据。
struct ProvisionalProcessEntity final {
    std::string provisionalId;   // 稳定的临时 id，导出与后续关联都用它
    std::string bootId;
    OptionalU64 pid;
    OptionalU64 firstSeenTime100ns;
    OptionalU64 lastSeenTime100ns;
    std::uint64_t eventCount = 0;
    AttributionKind originKind = AttributionKind::Provisional;  // 建立时的原因

    bool identityComplete = false;
    std::string resolvedInstanceKey;  // 补齐后关联到的实例 crossSessionKey
    std::string resolutionNoteKey;    // 关联过程说明（i18n 键），供追踪
};

struct AttributionDecision final {
    AttributionKind kind = AttributionKind::UnknownProcess;
    ProcessInstanceId instance;  // 仅 BoundToInstance 时有意义
    std::string provisionalId;   // Provisional / AfterInstanceExit / Ambiguous 时有意义
    IdentityStrength identityStrength = IdentityStrength::Unusable;
    // ObjectIdentity 的统一门槛：身份不足时最强只给 Candidate。
    MatchResult identityMatch = MatchResult::Candidate;
    std::string reasonKey;
};

// 进程实例账本。只记录"看见过的开始/结束"，不做任何现场访问。
class ProcessInstanceLedger final {
public:
    // 观察到进程开始事件。identity 必须至少带 bootId+pid，否则拒绝登记并返回 false。
    bool observeStart(const ProcessInstanceId& identity, std::uint64_t startTime100ns);

    // 观察到进程结束事件。找不到对应实例返回 false（不凭空创建"已结束"实例）。
    //
    // T-05：identity 带 createTime100ns 时**必须**与实例记录里的 createTime 精确相等。
    // createTime 正是区分 PID 复用实例的那一个字段；只按 bootId/pid/"开始时间最晚"挑
    // 候选，会把 A 的迟到退出事件记到 B 头上（A 从此窗口无限延长、B 被判已结束），
    // 后续事件因此在 A 与 B 之间来回误归属。对不上就拒绝，由调用方记一次未匹配退出。
    bool observeExit(const ProcessInstanceId& identity, std::uint64_t exitTime100ns);

    // 没有 createTime 只能靠"开始时间最晚且尚未结束"挑候选，这是弱匹配。次数单独暴露，
    // 供 UI/报告说明"这些退出时刻是猜的"。
    std::size_t weakExitMatchCount() const noexcept { return weakExitMatchCount_; }

    // 归属判定。**不会**把落在窗口外的事件送给当前同 PID 进程。
    AttributionDecision attribute(const std::string& bootId,
                                  const OptionalU64& pid,
                                  const EventTimeStamp& time);

    // 后来补齐了开始证据：把临时实体挂到真实实例上，并留下可追踪的说明。
    bool confirmProvisional(const std::string& provisionalId,
                            const ProcessInstanceId& identity,
                            std::string noteKey);

    const std::vector<ProvisionalProcessEntity>& provisionals() const noexcept {
        return provisionals_;
    }
    const ProvisionalProcessEntity* findProvisional(const std::string& provisionalId) const noexcept;

    std::size_t instanceCount() const noexcept { return instances_.size(); }

private:
    struct InstanceRecord final {
        ProcessInstanceId identity;
        std::uint64_t startTime100ns = 0;
        bool exitKnown = false;
        std::uint64_t exitTime100ns = 0;
    };

    ProvisionalProcessEntity& touchProvisional(const std::string& bootId,
                                               const OptionalU64& pid,
                                               const OptionalU64& time,
                                               AttributionKind originKind);

    std::vector<InstanceRecord> instances_;
    std::vector<ProvisionalProcessEntity> provisionals_;
    // 临时实体 id -> 下标。id 用长度前缀编码，因此 id 相等 <=> (bootId,pid,originKind) 相等。
    std::unordered_map<std::string, std::size_t> provisionalIndex_;
    std::size_t weakExitMatchCount_ = 0;
};

// T-05：临时实体 id 由 (bootId, pid, originKind) 唯一决定。**不能**直接拼接 ——
// 空 bootId 退化成 "boot-unknown" 会和真的叫 "boot-unknown" 的启动周期撞成同一个实体，
// bootId 里含 ":pid=" 同样会撞。因此每段都带长度前缀，编码是单射的。
std::string MakeProvisionalEntityId(const std::string& bootId,
                                    const OptionalU64& pid,
                                    AttributionKind originKind);

// ===========================================================================
// T-06 丢失账目
// ===========================================================================

enum class LossCategory {
    SourceDrop,       // 源端（ETW session / provider）报告的丢失
    RingOverwrite,    // 驱动 ring 覆盖 / 游标落后
    QueueDiscard,     // R3 队列丢弃
    ParseFailure,     // 解析失败
    FilteredOut,      // 被采集过滤排除（**从未进入会话**，与显示过滤无关）
    RetentionEvicted, // 保留策略淘汰
};

inline constexpr std::size_t kLossCategoryCount = 6U;
const char* LossCategoryName(LossCategory category) noexcept;
LossCategory LossCategoryAt(std::size_t index) noexcept;

// 一类丢失的计数。count 未设置表示"未知"，与 0 是两件事；0 也必须带来源。
struct LossCounter final {
    OptionalU64 count;
    std::string statisticSource;      // "etw.EventsLost" / "ring.OverwriteCount" / "local.parser" …
    bool sourceIsAuthoritative = false;  // true = 由来源给绝对值，本地不得再自增
    bool intervalSupported = false;   // 来源是否真的提供丢失时间区间
    OptionalU64 intervalBegin100ns;
    OptionalU64 intervalEnd100ns;
};

// 记账规则（T-06 "不重复计数"）：
//   * declareSource() 为某一类指定唯一的统计来源。换来源要先 reset。
//   * 来源权威（sourceIsAuthoritative=true）的类别只能 setAbsolute()，不能 addObserved()；
//     本地自增的类别只能 addObserved()，不能 setAbsolute()。两条路混用即为重复计数。
//   * setInterval() 只在来源声明了 intervalSupported 时成立；否则拒绝 —— 不编造区间。
class LossLedger final {
public:
    bool declareSource(LossCategory category,
                       std::string statisticSource,
                       bool sourceIsAuthoritative,
                       bool intervalSupported);

    bool setAbsolute(LossCategory category, std::uint64_t count);
    bool addObserved(LossCategory category, std::uint64_t delta);
    bool setInterval(LossCategory category, std::uint64_t begin100ns, std::uint64_t end100ns);

    const LossCounter& counter(LossCategory category) const noexcept;
    LossCounter& mutableCounter(LossCategory category) noexcept;

    bool anyUnknown() const noexcept;   // 有任意一类没有具名来源/没有计数
    // 任一类未知即返回 unset：把未知当 0 相加会把"部分轨迹显示为完整"。
    OptionalU64 totalLost() const noexcept;

    // 供 UI/报告使用的说明键。没有丢失时也会给出"六类均有具名来源"的正面说明。
    std::vector<std::string> limitationKeys() const;

private:
    LossCounter counters_[kLossCategoryCount];
};

// ===========================================================================
// T-03 过滤分离
// ===========================================================================

enum class FilterStage {
    Collection,  // 采集过滤：命中即不进入会话，计入 FilteredOut
    Display,     // 显示过滤：只改变可见集合，会话内容不变
};

const char* FilterStageName(FilterStage stage) noexcept;

// 极简规则集：空列表表示该维度不限制。生产侧可以扩展，判据不变。
struct EventFilter final {
    bool active = false;
    std::string ruleId;
    std::vector<std::uint64_t> allowedPids;
    std::vector<TimelineEventCategory> allowedCategories;
    std::vector<std::string> allowedProviderIds;
};

struct TimelineEvent;  // 前置声明

bool FilterAdmits(const EventFilter& filter, const TimelineEvent& event) noexcept;

enum class ExportScope {
    VisibleOnly,  // 只导出当前显示过滤后的结果
    FullSession,  // 导出会话保留的全部事件（显示过滤不参与）
};

const char* ExportScopeName(ExportScope scope) noexcept;

struct ExportPlan final {
    ExportScope scope = ExportScope::VisibleOnly;
    std::uint64_t exportedEventCount = 0;
    std::uint64_t retainedEventCount = 0;       // 会话实际保留的条数
    std::uint64_t hiddenByDisplayFilter = 0;    // 被显示过滤隐藏，但仍存在于会话中
    std::uint64_t excludedByCollectionFilter = 0;  // 采集过滤排除，从未进入会话
    bool representsRetainedSession = false;     // 是否覆盖了会话保留的全部事件
    // 会话本身是否等于"完整系统活动"。要求**正面证据**：
    //   * 至少声明过一个 collector 能力，且每一个已声明的 collector 都是 Success；
    //   * 没有采集过滤、没有任何丢失/淘汰、没有到限；
    //   * 记账没有失败；
    //   * 若会话是从文件恢复的，该文件必须结构完整（status == Ok）且没有恢复不出的事件。
    // 任何一条缺失即为 false —— 声明了 collector 却一个都没跑起来的会话，绝不是完整采集。
    bool retainedSessionIsCompleteCapture = false;
    // 已声明但状态不是 Success 的 collector 个数（0 且 capabilities 非空才可能算完整）。
    std::uint64_t unavailableCollectorCount = 0;
    // T-10：文件里存在但恢复不出来的事件条数（未提交尾部 + trailer 声明多出的部分）。
    std::uint64_t unrecoverableFileEventCount = 0;
    std::vector<std::string> noticeKeys;        // 导出必须随附的说明键
};

// ===========================================================================
// T-08 有界与保留策略
// ===========================================================================

enum class RetentionPolicy {
    StopOnLimit,  // 达到上限停止记录新事件
    EvictOldest,  // 达到上限淘汰最旧的
};

const char* RetentionPolicyName(RetentionPolicy policy) noexcept;

struct BoundsPolicy final {
    OptionalU64 maxEventsInMemory;
    OptionalU64 maxArchiveBytes;
    OptionalU64 approximateBytesPerEvent;  // 用于把磁盘上限换算成条数，未知则不换算
    RetentionPolicy policy = RetentionPolicy::StopOnLimit;
    // T-08：上限与到限行为必须在**采集前**呈现过。未声明则不允许开始采集。
    bool declaredBeforeCollection = false;
};

enum class BoundsState {
    WithinLimits,
    MemoryLimitReached,
    ArchiveLimitReached,
};

const char* BoundsStateName(BoundsState state) noexcept;

struct IngestResult final {
    bool accepted = false;         // 事件是否进入会话
    bool evictedOldest = false;    // 是否为了腾位置淘汰了最旧的一条
    bool countedAsLoss = false;    // 是否已在账目里记了一笔
    LossCategory lossCategory = LossCategory::QueueDiscard;
    BoundsState bounds = BoundsState::WithinLimits;
    std::string reasonKey;
    std::uint64_t assignedSequence = 0;  // accepted 时的接收序号
};

// ===========================================================================
// T-02 事件本体
// ===========================================================================

struct TimelineEvent final {
    std::string recordId;      // 会话内稳定 id
    std::string providerId;    // provider 名或 GUID 文本
    std::string sourceGroup;   // 独立来源分组（同一 collector 的多层包装共用）
    std::uint32_t eventId = 0;
    std::uint32_t eventVersion = 0;
    std::uint32_t opcode = 0;
    std::uint32_t task = 0;
    TimelineEventCategory category = TimelineEventCategory::Other;

    EventParseOutcome parseOutcome = EventParseOutcome::UnparsedUnknownSchema;
    std::string parserId;              // 实际使用的解析器，未解析时为空
    std::uint32_t parserVersion = 0;   // 未解析时为 0 —— 不得填别的版本号
    std::string parseReasonKey;

    RawFieldList rawFields;      // 原始字段，未解析记录同样保留
    std::string rawPayloadHex;   // 原始载荷的十六进制文本，供后续重解析

    EventTimeStamp time;

    // 归属结果。事件绑定进程实例；缺证据时是 provisionalId 而不是"当前同 PID 进程"。
    AttributionKind attribution = AttributionKind::UnknownProcess;
    std::string processInstanceKey;  // crossSessionKey，身份不足时为空
    std::string provisionalProcessId;
    OptionalU64 pid;
    OptionalU64 tid;

    std::uint64_t arrivalSequence = 0;  // 由会话在 ingest 时赋值

    // 来源直接提供的关联字段（例如 ETW ActivityId / CorrelationId）。只有它能撑起
    // SourceProvidedLink 边，进而允许因果措辞。
    std::string sourceLinkId;
    std::string sourceLinkField;
};

// ---------------------------------------------------------------------------
// T-02 解析：未知版本不套旧结构
// ---------------------------------------------------------------------------

struct EventSchema final {
    std::string providerId;
    std::uint32_t eventId = 0;
    std::uint32_t version = 0;
    std::string parserId;
    std::uint32_t parserVersion = 0;
    TimelineEventCategory category = TimelineEventCategory::Other;
    std::vector<std::string> requiredFields;
};

class EventSchemaRegistry final {
public:
    void add(EventSchema schema);

    // 精确匹配 (provider,eventId,version)。**没有**"就近降级到较低版本"的路径。
    const EventSchema* findExact(const std::string& providerId,
                                 std::uint32_t eventId,
                                 std::uint32_t version) const noexcept;

    // 只用于区分"未知 provider/eventId"与"已知 event 的未知 version"，
    // 供 reasonKey 更精确 —— 它绝不参与选择解析器。
    bool knowsProviderEvent(const std::string& providerId, std::uint32_t eventId) const noexcept;

    std::size_t size() const noexcept { return schemas_.size(); }

private:
    std::vector<EventSchema> schemas_;
};

struct EventParseRequest final {
    std::string providerId;
    std::uint32_t eventId = 0;
    std::uint32_t version = 0;
    RawFieldList rawFields;
    std::string rawPayloadHex;
    bool payloadTruncated = false;  // 采集侧已知载荷不完整
};

struct EventParseReport final {
    EventParseOutcome outcome = EventParseOutcome::UnparsedUnknownSchema;
    std::string parserId;
    std::uint32_t parserVersion = 0;
    std::string reasonKey;
    std::vector<std::string> missingRequiredFields;
    TimelineEventCategory category = TimelineEventCategory::Other;
};

EventParseReport ParseEventPayload(const EventSchemaRegistry& registry,
                                   const EventParseRequest& request);

// 把解析结论落到事件上。未解析时 parserVersion 保持 0、rawFields 原样保留。
void ApplyParseReport(TimelineEvent& event, const EventParseReport& report);

// ===========================================================================
// T-12 关系边（不冒充因果）
// ===========================================================================

enum class TimelineEdgeKind {
    SameProcess,        // 同一进程实例
    ParentChild,        // 父子进程（来自进程创建事件的父实例字段）
    TemporalNeighbor,   // 时间相邻 —— 只是"挨着发生"
    SourceProvidedLink, // 来源直接提供的关联（ActivityId / CorrelationId）
};

const char* TimelineEdgeKindName(TimelineEdgeKind kind) noexcept;

// 只有 SourceProvidedLink 允许因果措辞。API 里没有也不会有 "causes" 字段。
bool EdgeKindAllowsCausalWording(TimelineEdgeKind kind) noexcept;

struct TimelineEdge final {
    TimelineEdgeKind kind = TimelineEdgeKind::TemporalNeighbor;
    std::string fromRecordId;
    std::string toRecordId;
    std::string basisKey;         // 建边依据（i18n 键），UI 点开即可看到
    std::string basisDetail;      // 依据的具体取值，例如实例 key 或 ActivityId
    OptionalU64 temporalGap100ns; // TemporalNeighbor 时的时间差
    bool orderUncertain = false;  // 两端顺序在精度内不可分辨
};

struct EdgeBuildOptions final {
    // 未设置就不产生 TemporalNeighbor 边 —— "相邻"必须由调用方明确要求。
    OptionalU64 temporalNeighborWindow100ns;
    bool includeSameProcess = true;
    bool includeParentChild = true;
    bool includeSourceProvidedLink = true;
};

// 父子关系来源：进程创建事件里由来源给出的 (child, parent) 实例键。
struct ParentChildFact final {
    std::string recordId;          // 承载该事实的事件
    std::string childInstanceKey;
    std::string parentInstanceKey;
};

std::vector<TimelineEdge> BuildEdges(const std::vector<TimelineEvent>& events,
                                     const std::vector<ParentChildFact>& parentFacts,
                                     const EdgeBuildOptions& options);

// ===========================================================================
// T-10 载入结果（会话需要在自己身上带着它，因此声明在会话之前）
// ===========================================================================

enum class SessionLoadStatus {
    Ok,                     // header + 全部批次 + trailer 齐全且自洽
    Empty,                  // 空输入
    MissingHeader,          // 第一行不是合法 header
    VersionTooNew,          // formatVersion 高于本版本 —— 不猜、不改文件
    IncompleteTail,         // 已提交批次可恢复，尾部不完整（缺 trailer / 半行）
    Corrupt,                // 中途出现结构损坏或校验不符；之前的批次仍然保留
    TrailerMismatch,        // trailer 声明的条数与实际恢复不一致
};

const char* SessionLoadStatusName(SessionLoadStatus status) noexcept;

// T-10：载入结论必须**长在会话身上**，而不是只挂在一次性的 SessionLoadResult 上。
// 否则把 result.session 交出去之后，下游（导出计划、envelope、UI）看到的就是一个
// 干干净净的会话，"尾部截断 / trailer 对不上"这件事在两行代码之后彻底消失。
struct SessionLoadIntegrity final {
    bool restoredFromFile = false;
    SessionLoadStatus status = SessionLoadStatus::Ok;
    std::string diagnosticKey;
    // 文件里存在、但恢复不出来的事件条数：未提交尾部 + trailer 声明比实际多出的部分。
    // 它**不是** T-06 的六类采集丢失（那六类说的是采集期），而是 T-10 的"未提交部分
    // 标记缺失"，因此单独记账、单独给统计来源，绝不并进 LossLedger::totalLost()
    // —— 两种口径混在一起，"这次采集丢了多少"就再也说不清了。
    std::uint64_t unrecoverableEventCount = 0;
    std::string unrecoverableStatisticSource;  // 例如 "local.session-file.uncommitted"

    bool representsCompleteFile() const noexcept { return status == SessionLoadStatus::Ok; }
};

// ===========================================================================
// 会话
// ===========================================================================

struct CollectorCapability final {
    std::string collectorId;
    std::uint32_t collectorVersion = 0;
    std::string sourceGroup;
    SourceOrigin origin = SourceOrigin::Unknown;
    std::vector<TimelineEventCategory> declaredCategories;
    // 该 collector 在本 profile 下是否真的可用；不可用要有原因（不得留空当"可用"）。
    CollectionOutcome availability;
};

struct SessionManifest final {
    std::string sessionId;
    std::string machineId;
    std::string bootId;
    std::string displayName;
    CaptureWindow window;
    std::vector<CollectorCapability> capabilities;
    // 查询范围（时间/序号），供重开后对照。
    OptionalU64 queryRangeBegin100ns;
    OptionalU64 queryRangeEnd100ns;
};

// 事件存储。用 deque 而不是 vector：
//   * T-08 的 EvictOldest 每次淘汰只能是 O(1)。vector::erase(begin()) 要搬动整个保留窗口
//     （实测 10 万条上限时只有 ~186 次淘汰/秒，比第 7 节 L2 要求的 1 万条/秒慢 54 倍）；
//   * 分页分配，扩容不整体搬迁，也不需要一整块连续内存；
//   * 元素引用在两端增删时保持有效，visibleEvents() 拿到的指针不会因为后续 ingest 失效。
using TimelineEventStore = std::deque<TimelineEvent>;

class TimelineSession final {
public:
    TimelineSession();
    TimelineSession(SessionManifest manifest, BoundsPolicy bounds);

    SessionState state() const noexcept { return state_; }
    const SessionManifest& manifest() const noexcept { return manifest_; }
    const BoundsPolicy& bounds() const noexcept { return bounds_; }
    void setManifest(SessionManifest manifest) { manifest_ = std::move(manifest); }

    // 执行状态转移。Start 额外要求（T-08）：
    //   1. 上限已在采集前声明；
    //   2. 声明的磁盘上限**可执行** —— 给了 maxArchiveBytes 却没给非零的
    //      approximateBytesPerEvent，等于给用户看了一个永远不会生效的上限；
    //   3. 至少存在一条能真正换算成条数的上限，否则"内存有上限"这条判据是空的。
    SessionTransition apply(SessionAction action);

    void setCollectionFilter(EventFilter filter) { collectionFilter_ = std::move(filter); }
    void setDisplayFilter(EventFilter filter) { displayFilter_ = std::move(filter); }
    const EventFilter& collectionFilter() const noexcept { return collectionFilter_; }
    const EventFilter& displayFilter() const noexcept { return displayFilter_; }

    // 采集侧入口：状态检查 -> recordId 校验 -> 采集过滤 -> 有界与保留 -> 时间标注 -> 落入会话。
    // 显示过滤在这里**不参与**任何判断（T-03）。
    //
    // recordId 为空或与已保留事件重复时拒绝：recordId 是排序的最终 tiebreak、关系边的
    // 连接键与导出主键，重复会让这三件事各自指向不同的记录。拒绝的那一条按 R3 侧丢弃
    // 入账，不静默吞掉。
    IngestResult ingest(TimelineEvent event);

    const TimelineEventStore& events() const noexcept { return events_; }
    std::vector<const TimelineEvent*> visibleEvents() const;

    LossLedger& loss() noexcept { return loss_; }
    const LossLedger& loss() const noexcept { return loss_; }
    ProcessInstanceLedger& processes() noexcept { return processes_; }
    const ProcessInstanceLedger& processes() const noexcept { return processes_; }

    // T-04：确定且可解释的排序键，按 SortKeyLess 排好返回。
    std::vector<TimelineSortKey> sortedOrder() const;

    // T-03：导出计划。VisibleOnly 必然带"存在被隐藏事件"的说明。
    ExportPlan buildExportPlan(ExportScope scope) const;

    BoundsState boundsState() const noexcept { return boundsState_; }
    std::uint64_t nextSequence() const noexcept { return nextSequence_; }

    std::uint64_t collectionFilteredOutCount() const noexcept { return filteredOutCount_; }

    // T-06：本地自增记不进账目时（来源被外部改成权威口径等）为真。为真时该类计数被
    // 打成"未知"，totalLost() 随之 unset —— 宁可整份账目判不出总数，也不静默丢一笔。
    bool lossAccountingFailed() const noexcept { return lossAccountingFailed_; }

    // T-10：本会话是不是从文件恢复的、那份文件完不完整。
    const SessionLoadIntegrity& loadIntegrity() const noexcept { return loadIntegrity_; }
    std::uint64_t unrecoverableFileEventCount() const noexcept {
        return loadIntegrity_.unrecoverableEventCount;
    }

    // 恢复路径专用：直接放入已提交批次的事件，不再走过滤与上限。
    // 这条路径存在的唯一理由是 T-10 —— 重开时必须复现"当时记了什么"，而不是
    // 拿今天的过滤器和上限把历史再筛一遍。
    // recordId 为空或重复时返回 false：文件结构坏了，调用方必须判 Corrupt。
    bool appendRestoredEvent(TimelineEvent event);
    void setStateForRestore(SessionState state) noexcept { state_ = state; }
    void setBoundsForRestore(BoundsPolicy bounds) { bounds_ = std::move(bounds); }
    void setStatsForRestore(std::uint64_t filteredOutCount, BoundsState bounds) noexcept;
    void setLoadIntegrityForRestore(SessionLoadIntegrity integrity) {
        loadIntegrity_ = std::move(integrity);
    }

private:
    struct BootEpoch final {
        std::string bootId;
        bool maxTimeKnown = false;
        std::uint64_t maxEffectiveTime100ns = 0U;
    };

    std::uint32_t registerBoot(const std::string& bootId);
    std::uint32_t bootRankOf(const std::string& bootId) const noexcept;
    // T-06：会话自己产生的四类丢失由会话自己声明来源。之前要靠调用方先跑一遍
    // declareSource()，忘了就等于 addObserved() 全部返回 false，丢掉的条数无处落账。
    void declareLocalLossSources();
    // 返回"这一笔是否真的记进了账目"。记不进去即为硬错误：该类计数被打成未知，
    // lossAccountingFailed_ 置位，绝不让这一笔悄悄消失。
    bool recordLocalLoss(LossCategory category, std::uint64_t delta);

    SessionManifest manifest_;
    BoundsPolicy bounds_;
    SessionState state_ = SessionState::New;
    EventFilter collectionFilter_;
    EventFilter displayFilter_;
    TimelineEventStore events_;
    std::unordered_set<std::string> recordIds_;  // 保留窗口内的 recordId，用于 O(1) 查重
    std::vector<BootEpoch> bootEpochs_;
    LossLedger loss_;
    ProcessInstanceLedger processes_;
    SessionLoadIntegrity loadIntegrity_;
    BoundsState boundsState_ = BoundsState::WithinLimits;
    std::uint64_t nextSequence_ = 1U;
    std::uint64_t filteredOutCount_ = 0U;
    bool lossAccountingFailed_ = false;
};

// ===========================================================================
// T-09 / T-10 保存与恢复
// ===========================================================================

// 行分隔格式：第 1 行 header，其后每行一个已提交批次，最后一行 trailer。
// 之所以不是单个 JSON 文档：写到一半被强杀时，单文档会整份解析失败，
// 做不到 T-10 要求的"已提交批次仍可恢复 + 未提交尾部标记缺失"。
inline constexpr std::uint32_t kTimelineFormatVersion = 1U;
inline constexpr const char* kTimelineFormatKind = "ksword.timeline.session";

struct SessionBatch final {
    std::uint64_t batchIndex = 0;
    bool committed = false;
    std::vector<TimelineEvent> events;
};

// T-08：流式写出。每产生一行就交给 sink，峰值内存是"一个批次"而不是"整个文件"。
// 20 万条 512B 载荷的会话，旧的 SerializeSession 会先在内存里堆出一个 360 MiB 的
// std::string；这条路径不会。batchSize=0 视为 1 批。
void SerializeSessionTo(const TimelineSession& session,
                        std::size_t batchSize,
                        const std::function<void(std::string_view)>& sink);

// 序列化整个会话到一个字符串。仅供小会话与测试使用；大会话请走 SerializeSessionTo。
std::string SerializeSession(const TimelineSession& session, std::size_t batchSize);

// 仅序列化 header 行（供增量写入路径复用）。
std::string SerializeSessionHeaderLine(const TimelineSession& session);
std::string SerializeBatchLine(const SessionBatch& batch);
std::string SerializeTrailerLine(const TimelineSession& session, std::uint64_t committedBatchCount);

struct SessionLoadResult final {
    SessionLoadStatus status = SessionLoadStatus::Empty;
    TimelineSession session;
    std::uint32_t fileFormatVersion = 0;
    std::uint64_t committedBatchCount = 0;
    std::uint64_t recoveredEventCount = 0;
    std::uint64_t uncommittedEventCount = 0;  // 未提交批次里的条数，标记为缺失
    bool trailerPresent = false;              // 是否读到过 trailer 行
    std::uint64_t declaredEventCount = 0;     // trailer 声明的条数（trailerPresent 时有效）
    // 文件里存在但恢复不出来的条数：未提交尾部 + trailer 多声明的部分。与
    // result.session.unrecoverableFileEventCount() 是同一个值。
    std::uint64_t unrecoverableEventCount = 0;
    std::size_t failedLineIndex = 0;          // 出问题的行号（0 基），status 为 Ok 时无意义
    JsonParseStatus jsonStatus = JsonParseStatus::Ok;
    std::string diagnosticKey;

    // T-09：离线重开只承诺已提交批次；这里明确说明"不是完整会话"。
    bool representsCompleteFile() const noexcept { return status == SessionLoadStatus::Ok; }
};

// 只读解析。任何分支都不写回、不修复源文件。
//
// 结构判据（T-10 "已提交数据可恢复或明确诊断"）：trailer 必须是最后一行。trailer 之后
// 还有非空行（第二个 trailer、被中断的重写留在中间的旧 trailer、追加上去的批次）一律
// 判 Corrupt —— 否则一份结构已经坏掉的文件会读回成"干净完整的会话"。
SessionLoadResult LoadSession(std::string_view text);

// 供导出/报告使用：把 collector 可用性、载入完整性、丢失账目与覆盖情况折进一个 envelope。
//
// 降级顺序（先到先得，且都只会往"更不确定"的方向走）：
//   New                                   -> NotCollected
//   一个 collector 能力都没声明             -> Partial（不知道该采什么，就不能说采全了）
//   有已声明但不是 Success 的 collector      -> Partial，并把该 collector 的
//                                            nativeCodeDomain / nativeCode / message 带进 outcome
//   会话恢复自不完整的文件 / 有恢复不出的事件 -> Partial
//   本地记账失败 / 账目有未知项              -> Partial
//   有丢失、到限或被采集过滤                 -> Partial
//   其余                                    -> Success
EvidenceEnvelope BuildSessionEnvelope(const TimelineSession& session);

} // namespace Ksword::Evidence
