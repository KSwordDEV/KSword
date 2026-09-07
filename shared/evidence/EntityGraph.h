#pragma once

// G 模块：实体关系与跨页调查。
//
// 这一层只有关系模型与展开策略，没有任何 UI、布局或渲染概念。它的职责是：
//   * G-01 每条边都带类型、方向、时间有效区间、证据引用和确定性，六类语义各自
//     成立，绝不塌成一条"相关"边；缺证据的关系不许显示为确定。
//   * G-02 节点身份来自 ObjectIdentity 的实例身份。不同启动周期、不同 PID 创建
//     时间、地址复用的对象是不同节点；历史边不会自动套到当前对象。
//   * G-03 三条最小可用调查链，无数据的环节显式落成"缺失"而不是被跳过。
//   * G-04 初始只给目标 + 一跳；默认 200 节点 / 500 边，更多必须由调用方显式请求；
//     计数区分"本次加载"和"总量"，总量不可知时就是 unknown。
//   * G-05 缺 owner / 已卸载 / 来源未采集 / 实际不一致是四种独立情况，没有任何
//     "无边就恶意"的规则，也没有任何恶意/风险评分字段。
//   * G-06 图、列表、详情、导出引用同一套实体 id 与证据 id；离线展开只用已保存
//     数据，遇到未保存的邻居落成"未保存"而不是发起查询。
//   * G-08 图是证据视图不是分析真值：推断可展开到规则与来源，模型里没有 layout /
//     size / color 之类会携带未定义风险含义的字段，同一数据换输入顺序后结论一致。
//
// 三条贯穿全模块的硬规则：
//   * 缺失即缺失。没有采到、不支持、被拒绝、超时、正确的空集合是五个不同状态，
//     一律保留原始错误码，绝不塌成"没有这一环"。
//   * 默认不等于完整。默认构造的 GraphEdge 是 Unknown 类型、Unknown 确定性、
//     Unknown 方向，会被 addEdge 直接拒收；默认构造的 EntityGraph 的 envelope 是
//     NotCollected，SummarizeGraph 只能给出 NoEvidence。
//   * 判据不越权。这一层不认识 rootkit，不打分，不产出"恶意/可疑"，只给出可回到
//     源记录的事实。

#include "EvidenceEnvelope.h"
#include "EvidenceJson.h"
#include "LiveNavigation.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"
#include "ScanBudget.h"

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// G-01：边的语义
// ---------------------------------------------------------------------------

// EdgeKind 是**关系类型**，不是"相关度"。每一类都有独立的含义与独立的证据要求；
// 这里刻意没有 Related / Associated 之类的兜底值 —— 拿不准的关系只能落到
// CandidateOwner（归属存疑）或 TemporalNeighbor（只是时间上挨着），两者都不表达
// 因果，也都不能升格成 Owns。
enum class EdgeKind {
    Unknown,           // 未指定 —— addEdge 拒收，不允许进图
    Owns,              // 生命周期归属：进程→线程 / 进程→句柄 / 进程→连接
    Loads,             // 加载映像：进程或内核→已加载模块
    Maps,              // 地址空间映射：进程→被映射的文件或区域
    Opens,             // 句柄→它打开的目标对象
    CandidateOwner,    // 归属只有候选级证据 —— 语义上永远不可能是 Confirmed
    TemporalNeighbor,  // 时间邻近。无方向，不表达因果（规范"不包含"里点名禁止）
    DeviceOf,          // DeviceObject→它所属的 DriverObject
    ImageOf,           // DriverObject→磁盘上的映像文件
    ServiceOf,         // 磁盘映像→可证实的服务配置
    TimelineEntry,     // 系统对象→时间线上的一条证据记录
};

const char* EdgeKindName(EdgeKind kind) noexcept;

// CandidateOwner 按定义就是"证据不足以确认归属"，因此它的确定性上限是 Candidate。
bool EdgeKindAllowsConfirmed(EdgeKind kind) noexcept;

// TemporalNeighbor 是对称的：A 在 B 附近发生，等价于 B 在 A 附近发生。给它一个
// 方向就等于把时间邻近画成了因果。
bool EdgeKindIsSymmetric(EdgeKind kind) noexcept;

enum class EdgeDirection {
    Unknown,    // 方向未知 —— addEdge 拒收，不许被当成 FromTo 使用
    FromTo,     // from 是主体，to 是客体
    Symmetric,  // 无方向
};

const char* EdgeDirectionName(EdgeDirection direction) noexcept;

// G-01：缺证据的关系不许显示为确定。Unknown 是默认值，表示"连候选都谈不上"。
enum class EdgeCertainty {
    Unknown,
    Candidate,
    Confirmed,
};

const char* EdgeCertaintyName(EdgeCertainty certainty) noexcept;

struct GraphEdge final {
    std::string edgeId;          // 留空则由 DeriveEdgeId 确定性生成
    EdgeKind kind = EdgeKind::Unknown;
    EdgeDirection direction = EdgeDirection::Unknown;
    std::string fromNodeId;
    std::string toNodeId;

    // 时间有效区间（UTC 100ns）。两端都 unset 表示"有效期未知"，那不是"一直有效"。
    OptionalU64 validFrom100ns;
    OptionalU64 validTo100ns;

    // G-01 / G-08：证据引用与推断规则。evidenceRefs 为空时确定性不得是 Confirmed。
    std::vector<std::string> evidenceRefs;
    EdgeCertainty certainty = EdgeCertainty::Unknown;
    std::string ruleId;              // 产生这条边的规则标识，UI 可展开
    std::string ruleDescriptionKey;  // 规则说明的 i18n 键
    std::string sourceGroup;         // 这条边来自哪个独立来源组
};

// 确定性生成的边 id：类型 + 端点 + 有效区间 + 规则。同一关系在不同时间区间上是
// 两条边，因此区间参与 id；这样导入顺序不同也得到同一套 id（G-08）。
std::string DeriveEdgeId(const GraphEdge& edge);

// 边的时间有效性。Unknown 不是"无效"，也不是"有效"。
enum class TemporalValidity {
    Unknown,
    Valid,
    NotValid,
    // 区间本身是坏的（validFrom > validTo）。这既不是"此刻无效"也不是"未知时刻"：
    // 把它塌成 NotValid 会让一条坏区间的边在任何带时刻的筛选下永久隐身，而且没有
    // 任何地方说得出"隐身是因为区间反了"。ScanBudget 的 AddressRange::reversed 是
    // 同一件事的另一处对应物。
    IntervalInvalid,
};

const char* TemporalValidityName(TemporalValidity validity) noexcept;

TemporalValidity EdgeValidAt(const GraphEdge& edge, const OptionalU64& utc100ns) noexcept;

// G-01：按 kind / certainty 筛选。空向量 = 该维度不筛。
struct EdgeFilter final {
    std::vector<EdgeKind> kinds;
    std::vector<EdgeCertainty> certainties;

    // 时间筛选。atUtc100ns 未设置时不按时间筛。
    OptionalU64 atUtc100ns;
    // 有效区间未知的边默认保留 —— "未知"不等于"无效"（G-05 的同一条原则）。
    // 只有调用方明确要求时才排除，并且这件事必须出现在导出的限制说明里。
    bool excludeUnknownValidity = false;
};

bool EdgeMatchesFilter(const GraphEdge& edge, const EdgeFilter& filter) noexcept;

// ---------------------------------------------------------------------------
// G-02：节点身份
// ---------------------------------------------------------------------------

// ObjectKind 描述的是系统对象。时间线记录/证据记录不是系统对象，硬塞进 ObjectKind
// 会让"进程"和"一条日志"用同一套匹配规则。因此再给一个正交的类别维度。
enum class NodeCategory {
    SystemObject,
    TimelineEntry,
    EvidenceRecord,
};

const char* NodeCategoryName(NodeCategory category) noexcept;

// 节点生命周期。Unknown 是默认值 —— "不知道它还在不在"不等于"它还在"。
enum class NodeLifecycle {
    Unknown,
    Observed,  // 采集时刻确实观察到它在
    Ended,     // 已退出 / 已卸载 / 连接已关闭
};

const char* NodeLifecycleName(NodeLifecycle lifecycle) noexcept;

// NodeIdentity 直接承载 ObjectIdentity.h 的六类实例身份，按 kind 取用其中一个。
// Device / Service 在 F-03 里没有生命周期身份结构，只能用 (bootId, name)，因此它们
// 的强度恒为 Weak —— 这一点必须显式表达，不能假装它们和进程一样可靠。
struct NodeIdentity final {
    NodeCategory category = NodeCategory::SystemObject;
    ObjectKind kind = ObjectKind::Unknown;

    ProcessInstanceId process;
    ThreadInstanceId thread;
    DriverInstanceId driver;  // Driver 与 Module 共用
    FileIdentity file;
    HandleIdentity handle;
    ConnectionIdentity connection;

    std::string bootId;      // Device / Service / 非系统对象用
    std::string name;        // Device / Service 名，或记录 id
    // instanceTag：调用方给的实例判别标签（例如"第 N 次观察"或采集会话序号）。
    // G-02：地址会被复用，名字会被重用。身份**不够强**时，同名同址的两次观察必须
    // 靠这个标签分开；否则两个不同的对象会被合并成一个节点。身份足够强（拿得到
    // crossSessionKey）时它不参与主键，以免同一个对象被拆成两个节点。
    std::string instanceTag;

    IdentityStrength strength() const noexcept;

    // 跨会话主键。身份不足返回空串（沿用 F-03 的约定）。
    std::string crossSessionKey() const;

    // 图内唯一键。强身份用 crossSessionKey，弱身份把所有可得字段 + instanceTag
    // 全部编进去 —— 宁可把同一个对象拆成两个节点，也不把两个对象合成一个。
    std::string nodeKey() const;

    // 用于导航与证据引用。navigable() 为假时不允许跳转（F-12 身份门槛）。
    ObjectRef makeRef(const std::string& evidenceId, const std::string& displayText) const;
};

// 按 kind 分派到对应的 Match*。kind / category 不同一律 NoMatch；Device / Service
// 因为没有生命周期身份，最强只能给 Candidate。
//
// Device / Service / 记录这一支还有一道门槛：任一侧 strength() == Unusable，或者
// (bootId, name, instanceTag) 三个字段在某一侧全空，一律 NoMatch。MatchResult 没有
// "信息不足"这一档，Candidate 会被调用方当成"弱匹配"用作身份门槛；把"什么都没填"
// 读成"可能是同一个"，正是 G-02 要防的把两个对象合成一个。
MatchResult MatchNodeIdentity(const NodeIdentity& a, const NodeIdentity& b) noexcept;

struct GraphNode final {
    // 留空则由 NodeIdentity::nodeKey() 生成。调用方给了就用调用方的（会话回放时
    // 必须能原样还原保存下来的 id —— G-06 要求跨视图 id 一致）。
    std::string nodeId;
    NodeIdentity identity;
    std::string displayText;
    std::string evidenceId;      // 产生该节点的 envelope；空 = 打不开原始证据
    NodeLifecycle lifecycle = NodeLifecycle::Unknown;

    // G-05：这个节点"本该"由哪种关系连到 owner。填了才能区分"来源没采"和
    // "采了但确实没有 owner"；不填时按"来源未采集"处理（默认不是良性结论）。
    EdgeKind ownerRelation = EdgeKind::Unknown;
    ObjectKind ownerKind = ObjectKind::Unknown;

    // G-05 第四类：其它模块（例如 X 的 cross-view）观察到的实际不一致。
    // 这里只搬运事实与证据 id，不做任何风险判断。
    bool inconsistencyObserved = false;
    std::vector<std::string> inconsistencyEvidenceIds;

    // 该节点自身的采集结果。失败时保留原始错误码。
    CollectionOutcome outcome;

    bool objectNavigable() const noexcept;   // 身份够不够用来跳转对象页
    bool evidenceOpenable() const noexcept;  // 能不能打开原始证据
};

enum class NodeAdmission {
    AcceptedNew,
    AcceptedMerged,                   // 同一 nodeId 再次出现，证据合并
    AcceptedMergedLifecycleConflict,  // 合并时两侧生命周期矛盾，降级为 Unknown
    RejectedNoIdentity,               // 连图内唯一键都构不出来
    // G-02：同一个 nodeId 上出现了两份互相矛盾的身份（MatchNodeIdentity 判 NoMatch
    // 且两侧 nodeKey 不同）。合并会把两个对象压成一个，静默丢弃会让第二次观察连账
    // 都不进 —— 两者都禁止，因此这里拒收并让调用方看见冲突。
    RejectedIdentityConflict,
};

const char* NodeAdmissionName(NodeAdmission admission) noexcept;
bool NodeAdmissionAccepted(NodeAdmission admission) noexcept;

enum class EdgeAdmission {
    Accepted,
    DemotedMissingEvidence,        // G-01：evidenceRefs 为空，Confirmed 降为 Candidate
    DemotedCandidateOwnerKind,     // candidate-owner 语义上不可能确定
    DemotedTemporalDirectionDropped,  // 时间邻近被给了方向，方向被丢弃
    RejectedUnknownKind,
    RejectedUnknownDirection,
    RejectedMissingEndpoint,
    RejectedDuplicateId,
    RejectedInvalidInterval,       // validFrom > validTo：区间本身不成立
};

const char* EdgeAdmissionName(EdgeAdmission admission) noexcept;
bool EdgeAdmissionAccepted(EdgeAdmission admission) noexcept;

// 边入图前的规范化。返回值说明被改动了什么；out 是实际会被存下来的边。
// 单独暴露是为了让调用方在不建图的情况下也能复核判据（G-08 推断可展开）。
EdgeAdmission NormalizeEdge(const GraphEdge& input, GraphEdge& out);

// ---------------------------------------------------------------------------
// G-03 / G-05：关系覆盖声明
// ---------------------------------------------------------------------------

// "这一跳没有数据"和"这一跳没采"必须分开。图本身不知道调用方跑过哪些采集，所以
// 调用方必须显式声明。没有声明 = NotCollected（默认绝不是"采过且是空的"）。
struct RelationCoverage final {
    CollectionOutcome outcome;   // 默认 NotCollected
    CoverageAccount coverage;    // F-06 账目；空账目不是完整覆盖
    std::string evidenceId;
};

// 已声明的一条覆盖。导出与会话回放要能原样搬运这份声明（G-06）。
struct RelationCoverageEntry final {
    EdgeKind kind = EdgeKind::Unknown;
    ObjectKind targetKind = ObjectKind::Unknown;
    RelationCoverage coverage;
};

// ---------------------------------------------------------------------------
// 图
// ---------------------------------------------------------------------------

// G-06：离线展开策略。离线会话里 allowLiveQueries 恒为 false —— 遇到未保存的邻居
// 只能记账，绝不能悄悄发起现场查询。
struct OfflineExpansionPolicy final {
    bool allowLiveQueries = false;
    DataOrigin origin = DataOrigin::Session;
};

// 未保存的邻居：边指向一个当前数据集里没有的节点。这是"没保存"，不是"不存在"。
struct UnsavedNeighbor final {
    std::string edgeId;
    std::string missingNodeId;
    EdgeKind relation = EdgeKind::Unknown;
};

class EntityGraph final {
public:
    EntityGraph() = default;

    NodeAdmission addNode(GraphNode node);
    EdgeAdmission addEdge(const GraphEdge& edge);

    const GraphNode* findNode(const std::string& nodeId) const noexcept;
    const GraphEdge* findEdge(const std::string& edgeId) const noexcept;

    // 内部索引。展开与链路遍历全部走它，避免任何 O(n^2) 扫描（G-04）。
    bool nodeIndexOf(const std::string& nodeId, std::size_t& out) const noexcept;
    const std::vector<GraphNode>& nodes() const noexcept { return nodes_; }
    const std::vector<GraphEdge>& edges() const noexcept { return edges_; }
    std::size_t nodeCount() const noexcept { return nodes_.size(); }
    std::size_t edgeCount() const noexcept { return edges_.size(); }

    // 与某节点相连的边下标，按 edgeId 升序。顺序与插入顺序无关（G-08）。
    const std::vector<std::size_t>& incidentEdges(std::size_t nodeIndex) const;

    // G-05：EdgeKind::Unknown 不是一种关系，只是"没填"。让它进覆盖表就等于给每个
    // 没标注 ownerRelation 的节点发了一张"这一跳我们查全了"的证明，因此拒收并返回
    // false。ObjectKind::Unknown 是合法的目标类别（时间线记录没有 ObjectKind）。
    bool declareRelationCoverage(EdgeKind kind, ObjectKind targetKind, RelationCoverage coverage);
    // 未声明时返回默认值：NotCollected。
    RelationCoverage relationCoverage(EdgeKind kind, ObjectKind targetKind) const;
    // 已声明的全部覆盖，按 (kind, targetKind) 升序。导出与回放用。
    std::vector<RelationCoverageEntry> declaredRelationCoverages() const;

    // 建图期被 RejectedIdentityConflict 挡下的观察数。刻意不进 GraphConclusion，也
    // 不进导出：它记的是**输入流**（哪一次观察先到），不是数据本身，"谁被拒"随到达
    // 顺序变化，放进结论会破坏 G-08 的顺序无关性。
    std::uint64_t identityConflictCount() const noexcept { return identityConflicts_; }

    void setEnvelope(EvidenceEnvelope envelope) { envelope_ = std::move(envelope); }
    const EvidenceEnvelope& envelope() const noexcept { return envelope_; }

    void setOfflinePolicy(OfflineExpansionPolicy policy) noexcept { policy_ = policy; }
    const OfflineExpansionPolicy& offlinePolicy() const noexcept { return policy_; }

private:
    void attachEdgeToNode(const std::string& nodeId, std::size_t edgeIndex);

    std::vector<GraphNode> nodes_;
    std::vector<GraphEdge> edges_;
    std::unordered_map<std::string, std::size_t> nodeIndex_;
    std::unordered_map<std::string, std::size_t> edgeIndex_;
    // 指向尚未入图的节点的边（未保存邻居）。节点补齐后自动接进邻接表。
    std::unordered_map<std::string, std::vector<std::size_t>> pending_;
    // 邻接表排序是惰性的：查询时才排一次，之后复用。这样建图是 O(E)，遍历是
    // O(V+E)，不会出现按 nodeId 线性搜索的 O(n^2)（G-04）。
    // 两个 mutable 仅服务于这次惰性排序，本类不保证线程安全。
    mutable std::vector<std::vector<std::size_t>> adjacency_;
    mutable std::vector<char> adjacencySorted_;
    std::map<std::pair<EdgeKind, ObjectKind>, RelationCoverage> coverage_;
    EvidenceEnvelope envelope_;
    OfflineExpansionPolicy policy_;
    std::uint64_t identityConflicts_ = 0;
};

// ---------------------------------------------------------------------------
// G-04：有界展开
// ---------------------------------------------------------------------------

inline constexpr std::uint64_t kDefaultMaxNodes = 200;
inline constexpr std::uint64_t kDefaultMaxEdges = 500;
inline constexpr std::uint64_t kDefaultMaxHops = 1;

struct ExpansionLimits final {
    std::uint64_t maxNodes = kDefaultMaxNodes;
    std::uint64_t maxEdges = kDefaultMaxEdges;
    std::uint64_t maxHops = kDefaultMaxHops;
};

struct ExpansionRequest final {
    std::vector<std::string> rootNodeIds;
    ExpansionLimits limits;
    EdgeFilter filter;
    // G-04：默认上限之外的任何东西都必须由调用方显式请求继续。没有这一位时，
    // 超过默认值的 limits / hops 会被夹回默认值并在结果里说明。
    bool continueRequestedByUser = false;
};

struct ExpansionResult final {
    std::vector<std::string> nodeIds;  // 按 nodeId 升序，与输入顺序无关
    std::vector<std::string> edgeIds;  // 按 edgeId 升序

    // G-04：计数不许暗示已加载全部。loaded* 是本次真正装进来的；totalKnown 只有在
    // **遍历确实走到头**时才有值，且"走到头"要同时满足：没有命中任何上限、没有未保
    // 存邻居、并且装载数等于图里保存的全部节点与边。少最后一条就会出现"只走完一个
    // 连通分量却宣称总量已知"——那是拿 loadedNodes 冒充总量的另一种写法。
    std::uint64_t loadedNodes = 0;
    std::uint64_t loadedEdges = 0;
    bool moreAvailable = false;
    OptionalU64 totalKnownNodes;
    OptionalU64 totalKnownEdges;

    bool nodeLimitHit = false;
    bool edgeLimitHit = false;
    bool hopLimitHit = false;
    bool limitsClampedToDefault = false;  // 越过默认上限但没显式请求继续
    bool hopsClampedToDefault = false;

    // 被筛选条件排除的边数。这是用户的选择，不是覆盖缺口，因此不进 coverage。
    std::uint64_t filteredEdgeCount = 0;

    // G-06：未保存的邻居。offline 策略下必须为"记账"而不是"查询"。
    std::vector<UnsavedNeighbor> unsavedNeighbors;
    // 本次展开发起过几次现场查询。ExpandGraph 里没有任何现场查询出口，因此它只会
    // 保持默认的 0；函数末尾**不许**再写一次 0 —— 那样这个字段就恒等于 0，上层拿它
    // 做的断言也就恒成立，等于什么都没验证。
    std::uint64_t liveQueriesIssued = 0;

    CoverageAccount coverage;
    std::vector<std::string> limitationKeys;  // 已排序去重的 i18n 键
};

ExpansionResult ExpandGraph(const EntityGraph& graph, const ExpansionRequest& request);

// ---------------------------------------------------------------------------
// G-02：历史边定位到现场
// ---------------------------------------------------------------------------

enum class EndpointRole {
    From,
    To,
};

const char* EndpointRoleName(EndpointRole role) noexcept;

struct HistoricalEdgeLiveRequest final {
    std::string edgeId;
    EndpointRole endpoint = EndpointRole::To;
    LiveResolution live;               // 调用方在现场查到的候选（可能 found=false）
    NavigationPage page = NavigationPage::Unknown;
    bool targetPageAvailable = false;
    bool objectPresentInPage = false;
    bool evidencePresentInSession = false;
};

struct HistoricalEdgeLiveResult final {
    bool edgeFound = false;
    bool nodeFound = false;
    bool liveResolverSupported = false;  // 目前只有进程有现场重解析契约
    ObjectKind kind = ObjectKind::Unknown;
    std::string savedNodeId;
    // 只有身份 Allow 时才非空。身份不匹配时**绝不**填新对象的 id（G-02 核心）。
    std::string liveNodeId;
    LiveNavigationDecision identityDecision = LiveNavigationDecision::RejectIdentityUnverifiable;
    bool navigationAttempted = false;
    NavigationOutcome navigation = NavigationOutcome::IdentityUnusable;
    std::string reasonKey;
};

// 历史边不许自动套到当前对象：先用 ResolveProcessNavigation 做身份校验，只有
// Allow 才继续 DecideNavigation；其余情况一律不发起导航，也不给现场 id。
HistoricalEdgeLiveResult ResolveHistoricalEdgeToLive(const EntityGraph& graph,
                                                     const HistoricalEdgeLiveRequest& request);

// ---------------------------------------------------------------------------
// G-03：最小可用调查链
// ---------------------------------------------------------------------------

enum class ChainKind {
    ProcessSubjects,       // Process → Thread / Module / Handle
    DeviceToService,       // Device → DriverObject → Driver image → Service
    ConnectionToTimeline,  // Connection → Process instance → Timeline
};

const char* ChainKindName(ChainKind kind) noexcept;

// 每一环的可用性。五种"缺失"互不等价，都保留原始采集结果。
enum class StepAvailability {
    Present,                   // 这一环有对象
    MissingNoData,             // 来源成功且账目正面证明覆盖完整，确实没有这一环
    MissingCoverageIncomplete, // 来源只覆盖了一部分，"没有"无法确认
    MissingNotCollected,       // 根本没采
    MissingUnsupported,
    MissingAccessDenied,
    MissingCollectionFailed,   // 超时 / 其它错误，原始码在 outcome 里
    MissingIdentityUnusable,   // 有记录但身份不足，不能当作确定的一跳
    // 上一环就缺失，这一环连"从哪儿开始查"都没有。它和"这一环的来源没采"不是
    // 一回事：来源可能采得好好的，只是没有起点。塌成 MissingNotCollected 会把
    // 采集账目说反。
    MissingPreviousStepMissing,
};

const char* StepAvailabilityName(StepAvailability availability) noexcept;
bool StepIsMissing(StepAvailability availability) noexcept;

struct ChainStep final {
    std::size_t index = 0;
    std::string labelKey;                       // i18n 键，UI 负责翻译
    NodeCategory expectedCategory = NodeCategory::SystemObject;
    ObjectKind expectedKind = ObjectKind::Unknown;
    EdgeKind relationFromPrevious = EdgeKind::Unknown;
    StepAvailability availability = StepAvailability::MissingNotCollected;
    CollectionOutcome outcome;                  // 保留原始错误码
    std::string evidenceId;

    std::vector<std::string> nodeIds;           // 按 nodeId 升序
    std::vector<std::string> edgeIds;           // 按 edgeId 升序
    EdgeCertainty weakestEdgeCertainty = EdgeCertainty::Unknown;
    bool truncated = false;                     // 命中 maxNodesPerStep
    std::uint64_t matchCount = 0;

    // "这一环能不能跳到对象页"有两个完全不同的答案，必须分开给：any 是"至少一个能"，
    // every 是"列出来的每一个都能"。UI 用 any 决定要不要给按钮，用 every 决定能不能
    // 说这一环整体可导航。上一环缺失时两个都为假 —— 起点不成立的一跳不许可导航。
    bool anyObjectNavigable = false;
    bool everyObjectNavigable = false;
    // G-03 通过条件是"每一步可打开来源详情"，所以这一位是 every 语义：这一环里只要
    // 有一个节点打不开原始证据，它就是假。用 any 会让 3 选 1 的环被判成满足。
    bool evidenceOpenable = false;
};

struct ChainOptions final {
    std::uint64_t maxNodesPerStep = 50;
    EdgeFilter filter;
};

struct InvestigationChain final {
    ChainKind kind = ChainKind::ProcessSubjects;
    std::string rootNodeId;
    bool rootFound = false;
    std::vector<ChainStep> steps;

    std::size_t missingStepCount() const noexcept;
    // 所有环节都 Present 才算完整。默认构造的链绝不是"完整"。
    bool complete() const noexcept;
    // 每一步都能打开来源详情（G-03 的通过条件："不能只画出节点而不能导航"）。
    bool everyPresentStepOpensSource() const noexcept;
};

InvestigationChain BuildChain(const EntityGraph& graph,
                              ChainKind kind,
                              const std::string& rootNodeId,
                              const ChainOptions& options);

// ---------------------------------------------------------------------------
// G-05：孤立与未知不等于异常
// ---------------------------------------------------------------------------

// 四种情况分开。默认值刻意是 SourceNotCollected 而不是 NotIsolated —— 一个什么都
// 没填的报告不许读作"这个节点关系正常"。
//
// 命名上刻意避开"cause"：这里描述的是**观察到的数据状态**（有没有边、来源采没采、
// 对象在不在），不是对任何行为的因果或性质判定。四个取值里没有一个表达风险，也
// 没有任何一条规则从"孤立"推出"异常"（G-05 通过条件）。
enum class IsolationState {
    NotIsolated,
    OwnerMissing,           // 来源采全了、对象还在，就是没有 owner 边
    ObjectUnloaded,         // 对象已退出 / 已卸载，没有当前关系是正常的
    SourceNotCollected,     // 本该给出关系的来源没采 / 不支持 / 被拒 / 失败 / 不完整
    ObservedInconsistency,  // 其它模块观察到的实际不一致
};

const char* IsolationStateName(IsolationState state) noexcept;

struct IsolationReport final {
    std::string nodeId;
    bool nodeFound = false;
    bool isolated = false;
    IsolationState state = IsolationState::SourceNotCollected;
    std::uint64_t edgeCountAfterFilter = 0;
    std::uint64_t edgeCountBeforeFilter = 0;

    CollectionOutcome ownerLookupOutcome;   // owner 来源的原始采集结果
    std::string evidenceId;
    // G-05：孤立节点仍能查看原始证据。这一位为真时 UI 必须给出"打开原始证据"。
    bool rawEvidenceAvailable = false;
    // 为假时说明"连原始证据都没有"，UI 必须显示这句话而不是灰掉一个按钮了事。
    std::string rawEvidenceMissingKey;
    std::vector<std::string> inconsistencyEvidenceIds;
    std::string explanationKey;
};

IsolationReport ClassifyIsolation(const EntityGraph& graph,
                                  const std::string& nodeId,
                                  const EdgeFilter& filter);

// ---------------------------------------------------------------------------
// G-06 / G-08：列表、详情、导出与结论
// ---------------------------------------------------------------------------

// 列表视图的排序键。排序只影响**显示顺序**，不影响任何结论（G-08）。
enum class EntityListOrder {
    ByNodeId,
    ByDisplayText,
    ByKind,
    ByEdgeCountDescending,
};

const char* EntityListOrderName(EntityListOrder order) noexcept;

struct EntityListRow final {
    std::string nodeId;       // 与图、详情、导出用的是同一个 id（G-06）
    NodeCategory category = NodeCategory::SystemObject;
    ObjectKind kind = ObjectKind::Unknown;
    std::string displayText;
    std::string evidenceId;
    IdentityStrength strength = IdentityStrength::Unusable;
    NodeLifecycle lifecycle = NodeLifecycle::Unknown;
    std::uint64_t edgeCount = 0;
    bool objectNavigable = false;
    bool evidenceOpenable = false;
};

// expansion.nodeIds 里指向图中已不存在的 id 会被跳过（视图与图不同步时会发生）。
// 跳过的条数写进 outMissingNodeCount，绝不静默丢：行数与 loadedNodes 对不上时
// 调用方必须能说出差在哪儿（G-04：计数不许暗示已加载全部）。
std::vector<EntityListRow> BuildEntityList(const EntityGraph& graph,
                                           const ExpansionResult& expansion,
                                           const EdgeFilter& filter,
                                           EntityListOrder order,
                                           std::uint64_t* outMissingNodeCount = nullptr);

// 一条边的推断说明。G-08："所有推断可展开规则与来源"。
struct EdgeInferenceNote final {
    std::string edgeId;
    EdgeKind kind = EdgeKind::Unknown;
    EdgeCertainty certainty = EdgeCertainty::Unknown;
    std::string ruleId;
    std::string ruleDescriptionKey;
    std::vector<std::string> evidenceRefs;  // 已排序
    // 为什么不是 Confirmed。已经是 Confirmed 时为空。
    std::string notConfirmedReasonKey;
};

EdgeInferenceNote DescribeEdgeInference(const GraphEdge& edge);

struct NodeDetail final {
    std::string nodeId;
    bool nodeFound = false;
    NodeCategory category = NodeCategory::SystemObject;
    ObjectKind kind = ObjectKind::Unknown;
    std::string displayText;
    std::string evidenceId;
    IdentityStrength strength = IdentityStrength::Unusable;
    NodeLifecycle lifecycle = NodeLifecycle::Unknown;
    std::vector<std::string> incomingEdgeIds;  // 已排序
    std::vector<std::string> outgoingEdgeIds;
    std::vector<std::string> symmetricEdgeIds;
    std::vector<EdgeInferenceNote> inferences;
    IsolationReport isolation;
};

NodeDetail BuildNodeDetail(const EntityGraph& graph,
                           const std::string& nodeId,
                           const EdgeFilter& filter);

// G-08：图层结论。字段全部来自证据与账目，没有任何风险/恶意维度。
// 同一数据换输入顺序、换排序方式，这个结构必须逐字段相同。
struct GraphConclusion final {
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;

    std::uint64_t nodeCount = 0;
    std::uint64_t edgeCountAfterFilter = 0;
    std::uint64_t edgeCountBeforeFilter = 0;

    std::uint64_t confirmedEdgeCount = 0;
    std::uint64_t candidateEdgeCount = 0;
    std::uint64_t unknownCertaintyEdgeCount = 0;

    std::uint64_t isolatedNodeCount = 0;
    std::uint64_t ownerMissingCount = 0;
    std::uint64_t unloadedCount = 0;
    std::uint64_t sourceNotCollectedCount = 0;
    std::uint64_t inconsistencyCount = 0;

    std::uint64_t unusableIdentityNodeCount = 0;
    std::uint64_t nodesWithoutEvidenceCount = 0;

    CoverageAccount coverage;
    std::vector<std::string> limitationKeys;  // 已排序去重

    friend bool operator==(const GraphConclusion& a, const GraphConclusion& b);
    friend bool operator!=(const GraphConclusion& a, const GraphConclusion& b) { return !(a == b); }
};

GraphConclusion SummarizeGraph(const EntityGraph& graph, const EdgeFilter& filter);

// 导出。节点按 nodeId、边按 edgeId 排序输出，因此与插入顺序无关（G-08）。
// 所有 64 位量走 LosslessValue 的文本形式，没有浮点（F-08）。
//
// G-06：导出件必须能把同一张图重新开出来，因此它带的不只是"屏幕上看得见的东西"：
//   * 每个节点写出完整的 ObjectIdentity 载荷（按 kind 取对应的实例身份）与
//     ownerRelation / ownerKind —— 少了它们，重开的会话里身份强度、跨会话主键、
//     可导航性、孤立判据全部退化，"身份与关系一致"结构性地无法满足。
//   * 图级别写出 envelope、已声明的关系覆盖与离线策略 —— 少了它们，结论会从
//     NoDifferenceObserved 掉回 NoEvidence，链路会从 Present 掉成缺失。
// 身份载荷只写该 kind 用得到的那一份：nodeKey / crossSessionKey / strength /
// MatchNodeIdentity 全部按 kind 分派，别的槽位里的字节在本模块里没有任何含义。
JsonValue ExportGraph(const EntityGraph& graph,
                      const ExpansionResult& expansion,
                      const EdgeFilter& filter);

// 导入的账目。解析失败不抛异常，也不给"半张图"当成功：每一条被拒的记录都计数。
struct GraphImport final {
    bool schemaRecognised = false;   // 认得出 schema 才谈得上导入
    EntityGraph graph;

    std::uint64_t nodesAccepted = 0;
    std::uint64_t nodesRejected = 0;
    std::uint64_t edgesAccepted = 0;
    std::uint64_t edgesRejected = 0;
    std::uint64_t coverageAccepted = 0;
    std::uint64_t coverageRejected = 0;

    std::vector<std::string> limitationKeys;  // 已排序去重
};

// ExportGraph 的逆。导入只用文档里写着的东西，任何缺失字段都保持该字段的默认值
// （默认不等于完整：缺 envelope 就是 NotCollected，缺覆盖声明就是没采）。
GraphImport ImportGraph(const JsonValue& document);

// 导出使用的 schema 标识。v2 起节点带完整身份载荷、图带 envelope 与覆盖声明。
inline constexpr const char* kEntityGraphSchema = "ksword.entityGraph.v2";

} // namespace Ksword::Evidence
