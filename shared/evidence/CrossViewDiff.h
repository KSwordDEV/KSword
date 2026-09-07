#pragma once

// X 模块：Cross-view 差异解释与复核。
//
// 输入是若干轮采样，每轮包含多个视图的观测。输出不是"相等/不相等"，而是：
//   * 每个对象在每个视图里的命中情况，以及该视图当时是否有资格做"缺项"推断；
//   * 首次缺项后的复采样历史，区分瞬态、持续差异、对象已结束、无法复查；
//   * 视图数与**独立来源组数**分开计数，同一 collector 的两层包装不算两个来源。
//
// 三条贯穿全模块的硬规则：
//   * X-06：视图超时/拒绝/截断/不支持/整轮缺席，一律不是"该视图确认不存在"。
//     普查、复查、结论三处都必须按"无法判断"处理，绝不允许良性化成"对象已结束"
//     或"未发现差异"。
//   * X-01：可信度只能由**每轮都真实到场**的独立来源撑起。视图集合取全部轮次的
//     并集（缺席轮次会显式产出 NotCollected），来源组数取每轮独立组数的**最小值**。
//   * X-04：加载模块 / DriverObject / DeviceObject / 磁盘服务配置是四种不同的实体，
//     不要求一对一对应。缺项推断只在**同类别视图之间**进行，跨类别只记录基数事实。
//
// 这一层不认识 rootkit，也不产出恶意判定；它只给出可回到源记录的事实。

#include "EvidenceEnvelope.h"
#include "ObjectIdentity.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Evidence {

// 一个对象在一个视图里的存在性。
enum class ObjectPresence {
    Present,               // 该视图列出了这个对象
    AbsentInUsableView,    // 该视图成功、账目自洽且覆盖了目标范围，却没有这个对象
    UnknownViewFailed,     // 视图失败/超时/拒绝访问/整轮缺席 —— 不是"确认不存在"
    UnknownOutOfCoverage,  // 视图成功但被截断/未覆盖目标范围/账目不足以证明完整
    NotComparableCategory, // X-04：该视图枚举的是另一类实体，缺项在结构上合法
};

const char* ObjectPresenceName(ObjectPresence presence) noexcept;

// X-04：视图枚举的实体类别。缺项推断只在同类别之间成立。
// Unspecified 与 Unspecified 之间互相可比（单一实体域的调用方无需关心类别）。
enum class ViewEntityCategory {
    Unspecified,
    ProcessList,        // 进程列表
    ThreadList,         // 线程列表
    LoadedModuleList,   // 加载模块列表（PsLoadedModuleList / 模块枚举）
    DriverObjectTable,  // \Driver 目录下的 DriverObject
    DeviceObjectTree,   // 设备对象树
    ServiceConfig,      // 磁盘上的服务配置（注册表），与"已加载"无关
};

const char* ViewEntityCategoryName(ViewEntityCategory category) noexcept;

// X-06：只有成功、覆盖目标范围、且**账目正面证明了完整性**的视图才能做缺项推断。
// 注意：字段全默认的 CoverageAccount 会让 fullyCovered() 返回 true —— 那只说明
// "没有记录到失败"，不说明"确实枚举完了"。所以这里额外要求账目给出正面证据：
//   (a) totalKnown 已声明且 succeeded 达到了它；或
//   (b) requested/processed 四个端点都在，且 processed 覆盖了 requested。
// 两者都没有 = 账目一字未填 = 不能当"确认缺失"用。
bool ViewUsableForAbsence(const EvidenceEnvelope& envelope, bool coversTargetScope) noexcept;

// ---------------------------------------------------------------------------
// 输入
// ---------------------------------------------------------------------------

// 一条视图记录。identity 三选一按 kind 填；rawRecordId 指回原始行，供 X-07 展开。
struct ViewRecord final {
    ObjectKind kind = ObjectKind::Unknown;
    ProcessInstanceId process;
    ThreadInstanceId thread;
    DriverInstanceId driver;
    std::string rawRecordId;

    // 跨会话主键。身份不足时为空 —— 此时对象只能进入候选态（见 candidateKey）。
    std::string identityKey() const;

    // X-02：弱身份去重键。**只在本次分析内有效**，由 PID/TID/名字/路径这类可复用
    // 标识拼成，绝不是跨会话主键，也绝不允许据此判定"确实是同一个对象"。它存在的
    // 唯一目的是：让一个弱身份对象在报告里只出现一次，而不是被丢弃或按记录条数重复。
    std::string candidateKey() const;

    IdentityStrength strength() const noexcept;
    std::string displayText() const;
};

struct ViewSnapshot final {
    std::string viewId;
    EvidenceEnvelope envelope;
    // X-04：该视图枚举的实体类别。默认 Unspecified 表示"与其它未声明类别的视图同域"。
    ViewEntityCategory category = ViewEntityCategory::Unspecified;
    // 该视图本轮是否声称覆盖了本次比对的目标范围（例如"全部进程"）。
    bool coversTargetScope = true;
    std::vector<ViewRecord> records;
};

struct SampleRound final {
    std::uint64_t sampleId = 0;
    OptionalU64 sampleUtc100ns;
    std::vector<ViewSnapshot> views;
};

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------
enum class DiscrepancyState {
    NoDiscrepancy,   // 所有可用视图都看到了
    PendingRecheck,  // 首次缺项，复采样轮数还不够
    Transient,       // 后续采样里出现了 —— 采样时差，不是隐藏
    Persistent,      // 达到要求的复查轮数且始终在可用视图里缺失
    ObjectEnded,     // 复查前对象已结束（见证视图本轮全部可用且都不再列出它）
    Unverifiable,    // 复查轮里没有足够视图有资格做缺项推断
    CandidateOnly,   // X-02：身份不足，只保留候选关系，禁止参与任何差异升级
};

const char* DiscrepancyStateName(DiscrepancyState state) noexcept;

// F-05：状态与结论是两个轴，但不允许自相矛盾（例如 Persistent+NoEvidence、
// ObjectEnded+NoDifferenceObserved）。AnalyzeCrossView 末尾按此校验并兜底。
bool StateConclusionConsistent(DiscrepancyState state, AnalysisConclusion conclusion) noexcept;

struct ViewHit final {
    std::string viewId;
    std::string sourceGroup;   // 本轮该视图的独立来源组；整轮缺席时为空（本轮未知）
    ObjectPresence presence = ObjectPresence::UnknownViewFailed;
    std::string rawRecordId;   // Present 时指回源记录
    CollectionStatus viewStatus = CollectionStatus::NotCollected;
    ViewEntityCategory category = ViewEntityCategory::Unspecified;
};

// X-04：跨类别的"缺项"是结构现象，不是差异。这里只把基数事实摆出来，
// 例如"模块列表里有、DriverObject 视图里没有"是独立现象，默认不构成差异。
struct CategoryObservation final {
    ViewEntityCategory category = ViewEntityCategory::Unspecified;
    std::size_t viewsInCategory = 0;        // 该类别的视图数（含本轮缺席的）
    std::size_t viewsListing = 0;           // 其中列出了该对象的视图数
    std::size_t usableViewsNotListing = 0;  // 其中可用且未列出该对象的视图数
    bool comparable = false;                // 该类别是否参与本对象的缺项推断
};

struct RecheckEntry final {
    std::uint64_t sampleId = 0;
    OptionalU64 sampleUtc100ns;
    OptionalU64 intervalFromFirst100ns;  // 距首次观测的间隔；缺时间戳或时钟回拨即 unset
    bool clockWentBackwards = false;     // X-05：本轮 UTC 早于首轮，间隔不可用（NTP 校正）
    std::size_t presentViews = 0;
    std::size_t usableAbsentViews = 0;
    std::size_t unusableViews = 0;
    std::size_t crossCategoryViews = 0;  // X-04：不同实体类别，不参与缺项推断
    // X-07：每一轮都能展开逐视图命中与原始记录 id，而不是只留三个计数。
    std::vector<ViewHit> hits;
};

// X-02：弱身份记录与强身份对象之间的**候选关系**。
//
// 为什么需要它：弱记录（例如某个视图拿不到创建时间的进程）此前只落成一条孤立的
// CandidateOnly finding，报告里看不出"它可能就是那个已确认的对象"。但反过来也
// 绝不能把它合并进去 —— 那正是 X-02 禁止的误合并。
//
// 判定只走 ObjectIdentity 的 Match*，**结果永远不会是 Confirmed**：弱身份按定义
// 就不足以确认，统一身份门槛也会把它压到 Candidate。NoMatch 的对不会被记录。
struct CandidateLink final {
    std::string strongIdentityKey;  // 候选对应的强身份对象
    MatchResult match = MatchResult::Candidate;
    std::string basis;              // 依据说明：哪些字段一致、哪些缺失
};

struct CrossViewFinding final {
    ObjectKind kind = ObjectKind::Unknown;
    // 空表示身份不足（X-02），此时 candidateKey 非空且 state 恒为 CandidateOnly。
    std::string identityKey;
    // 弱身份去重键；identityKey 非空时为空。它不是主键，只用于报告去重与定位。
    std::string candidateKey;
    IdentityStrength strength = IdentityStrength::Unusable;
    std::string displayText;

    DiscrepancyState state = DiscrepancyState::NoDiscrepancy;
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;

    std::vector<ViewHit> latestHits;             // X-07：最后一轮逐视图命中情况
    std::vector<RecheckEntry> recheckHistory;    // X-07：复核历史（含逐轮 hits）
    std::vector<CategoryObservation> latestCategories;  // X-04：最后一轮的类别基数

    // X-02：本条是弱记录时，列出它可能对应的强身份对象（永不为 Confirmed）。
    // 强身份对象上则列出指向它的弱记录，方向由 identityKey 是否为空区分。
    std::vector<CandidateLink> candidateLinks;

    // X-07：从结论回到"最早报告过该对象的那条源记录"。
    std::string firstSeenViewId;
    std::string firstSeenRawRecordId;
    std::size_t firstSeenRoundIndex = 0;

    // X-01：viewCount 是"全部轮次视图 id 的并集"大小，恒等于 latestHits.size()；
    // independentSourceGroupCount 是**每轮独立来源组数的最小值** —— 只在第 1 轮
    // 到场、后面就消失的来源不能撑可信度。
    std::size_t viewCount = 0;
    std::size_t independentSourceGroupCount = 0;
    std::size_t latestRoundViewCount = 0;  // 最后一轮真正到场的视图数
};

struct CrossViewReport final {
    std::vector<CrossViewFinding> findings;
    TrustStatement trust;
    std::size_t roundCount = 0;
    // X-01：三个口径分开给，避免用"最好的那一轮"冒充整段采样的可信度。
    std::size_t viewCount = 0;             // 全部轮次视图 id 的并集
    std::size_t latestRoundViewCount = 0;  // 最后一轮实际到场
    std::size_t minRoundViewCount = 0;     // 最少的一轮实际到场
    std::size_t independentSourceGroupCount = 0;  // 每轮独立组数的最小值
    // 身份不足因而只能保留候选关系的**记录条数**（X-02/X-03：不误合并）。
    std::size_t weakIdentityRecords = 0;
    // 上述记录按弱键去重后的**对象个数**；每个对象都会有一条 CandidateOnly finding。
    std::size_t weakIdentityObjects = 0;
    // X-02：建立起来的"弱记录 <-> 强对象"候选边总数（每对计一次）。
    std::size_t candidateLinkCount = 0;
    // 内部一致性自检（见 .cpp 里的 SelfCheck）：正常路径恒为 true，false 说明
    // 计数口径与 hits 对不上，UI 必须把整份报告降级展示而不是照单全收。
    bool selfCheckPassed = true;
};

struct CrossViewOptions final {
    // X-05：默认在至少两个后续采样中尝试复查。
    std::size_t requiredRecheckRounds = 2;
};

CrossViewReport AnalyzeCrossView(const std::vector<SampleRound>& rounds,
                                 const CrossViewOptions& options = CrossViewOptions{});

} // namespace Ksword::Evidence
