// G 模块（实体关系与跨页调查）的离线自动测试。
//
// 覆盖编号：G-01 G-02 G-03 G-04 G-05 G-06 G-08。
// G-07（键盘可达、主题/语言）是 UI 实测项，本文件不声称覆盖。
//
// 断言原则（Q-01 / Q-02）：
//   * 期望值全部独立手算写死。10,000 节点 / 50,000 边的性能数据集用固定偏移量
//     {1,7,113,1237,4999} 构造，一跳邻域大小 11、边数 10 是在纸上算出来的，不是
//     跑一遍生产函数再抄回来；全图展开的 10000/50000 同理。
//   * 绝不把生产函数的输出当成"另一侧"输入去比较。唯一一处两次调用互相比较的是
//     G-08 要求的"打乱输入顺序后结论一致"，而那两次的**绝对值**也各自被写死断言，
//     因此静默损坏不会因为两边一起变而逃逸。
//   * 分支覆盖：EdgeAdmission 8 个取值、StepAvailability 9 个取值、IsolationState
//     5 个取值、LiveNavigationDecision 4 个取值都各有用例，不留零覆盖枚举。
//   * 越权字段用编译期检测封死：GraphNode / GraphEdge / GraphConclusion 上不存在
//     color / layout / size / riskScore / malicious / suspicious / threat / causes
//     这类字段，缺一个 static_assert 就编不过。

#include "TestSupport.h"

#include "../shared/evidence/EntityGraph.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cwchar>
#include <exception>
#include <locale>
#include <string>
#include <type_traits>
#include <vector>

namespace {

using namespace Ksword::Evidence;

constexpr const char* kBoot = "boot-G-1";
constexpr const char* kBoot2 = "boot-G-2";

// ---------------------------------------------------------------------------
// G-08：模型里不许有携带未定义风险含义的字段，也不许有越权判定字段。
// 成员探测：字段一旦被加回来，static_assert 立刻编译失败。
// ---------------------------------------------------------------------------
#define KSWORD_MEMBER_DETECTOR(DetectorName, MemberName)                                    \
    template <typename T, typename = void>                                                  \
    struct DetectorName : std::false_type {};                                               \
    template <typename T>                                                                   \
    struct DetectorName<T, std::void_t<decltype(std::declval<T&>().MemberName)>>             \
        : std::true_type {}

KSWORD_MEMBER_DETECTOR(HasColor, color);
KSWORD_MEMBER_DETECTOR(HasLayout, layout);
KSWORD_MEMBER_DETECTOR(HasPosition, position);
KSWORD_MEMBER_DETECTOR(HasSize, size);
KSWORD_MEMBER_DETECTOR(HasRadius, radius);
KSWORD_MEMBER_DETECTOR(HasRiskScore, riskScore);
KSWORD_MEMBER_DETECTOR(HasMalicious, malicious);
KSWORD_MEMBER_DETECTOR(HasSuspicious, suspicious);
KSWORD_MEMBER_DETECTOR(HasThreat, threat);
KSWORD_MEMBER_DETECTOR(HasIsRootkit, isRootkit);
KSWORD_MEMBER_DETECTOR(HasCauses, causes);
KSWORD_MEMBER_DETECTOR(HasVerdict, verdict);

#define KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(Type)                                     \
    static_assert(!HasColor<Type>::value, #Type " must not carry a color field");            \
    static_assert(!HasLayout<Type>::value, #Type " must not carry a layout field");          \
    static_assert(!HasPosition<Type>::value, #Type " must not carry a position field");      \
    static_assert(!HasSize<Type>::value, #Type " must not carry a size field");              \
    static_assert(!HasRadius<Type>::value, #Type " must not carry a radius field");          \
    static_assert(!HasRiskScore<Type>::value, #Type " must not carry a riskScore field");    \
    static_assert(!HasMalicious<Type>::value, #Type " must not carry a malicious field");    \
    static_assert(!HasSuspicious<Type>::value, #Type " must not carry a suspicious field");  \
    static_assert(!HasThreat<Type>::value, #Type " must not carry a threat field");          \
    static_assert(!HasIsRootkit<Type>::value, #Type " must not carry an isRootkit field");   \
    static_assert(!HasCauses<Type>::value, #Type " must not carry a causes field");          \
    static_assert(!HasVerdict<Type>::value, #Type " must not carry a verdict field")

KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(GraphNode);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(GraphEdge);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(GraphConclusion);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(IsolationReport);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(EntityListRow);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(ChainStep);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(ExpansionResult);

// G-06："离线展开只用已保存数据，不偷偷现场查询"。运行期只能断言计数为 0，那句话
// 在函数末尾无条件写 0 的实现下永远成立。这里改成结构性证明：ExpandGraph 的入参
// 只有图和请求，没有任何 resolver / 回调 / 客户端句柄可以用来发起查询 —— 想加一条
// 查询路径，就得先改这个签名，而改签名会在这里编译失败。
static_assert(
    std::is_same_v<decltype(ExpandGraph),
                   ExpansionResult(const EntityGraph&, const ExpansionRequest&)>,
    "ExpandGraph must take only saved data: no resolver, no callback, no live client");

// ---------------------------------------------------------------------------
// 构造工具
// ---------------------------------------------------------------------------
NodeIdentity ProcessIdentity(const char* boot, std::uint64_t pid, std::uint64_t createTime,
                             const char* image) {
    NodeIdentity id;
    id.category = NodeCategory::SystemObject;
    id.kind = ObjectKind::Process;
    id.process.bootId = boot;
    id.process.pid = OptionalU64::of(pid);
    id.process.createTime100ns = OptionalU64::of(createTime);
    id.process.imageName = image;
    return id;
}

NodeIdentity WeakProcessIdentity(std::uint64_t pid, const char* tag) {
    NodeIdentity id;
    id.category = NodeCategory::SystemObject;
    id.kind = ObjectKind::Process;
    id.process.pid = OptionalU64::of(pid);  // 无 bootId / 无创建时间 -> Weak
    id.instanceTag = tag;
    return id;
}

NodeIdentity ThreadIdentity(const char* boot, std::uint64_t pid, std::uint64_t processCreate,
                            std::uint64_t tid, std::uint64_t threadCreate) {
    NodeIdentity id;
    id.kind = ObjectKind::Thread;
    id.thread.process.bootId = boot;
    id.thread.process.pid = OptionalU64::of(pid);
    id.thread.process.createTime100ns = OptionalU64::of(processCreate);
    id.thread.tid = OptionalU64::of(tid);
    id.thread.createTime100ns = OptionalU64::of(threadCreate);
    return id;
}

NodeIdentity ModuleIdentity(const char* path, const char* pdb, std::uint64_t base) {
    NodeIdentity id;
    id.kind = ObjectKind::Module;
    id.driver.bootId = kBoot;
    id.driver.imagePath = path;
    id.driver.pdbSignature = pdb;
    id.driver.imageBase = OptionalU64::of(base);
    return id;
}

NodeIdentity DriverIdentity(const char* path, const char* pdb, std::uint64_t base) {
    NodeIdentity id = ModuleIdentity(path, pdb, base);
    id.kind = ObjectKind::Driver;
    return id;
}

NodeIdentity HandleIdentity_(const char* boot, std::uint64_t pid, std::uint64_t processCreate,
                             std::uint64_t handleValue, const char* typeName) {
    NodeIdentity id;
    id.kind = ObjectKind::Handle;
    id.handle.owner.bootId = boot;
    id.handle.owner.pid = OptionalU64::of(pid);
    id.handle.owner.createTime100ns = OptionalU64::of(processCreate);
    id.handle.handleValue = OptionalU64::of(handleValue);
    id.handle.typeName = typeName;
    return id;
}

NodeIdentity FileIdentity_(const char* path, std::uint64_t volume, const char* fileId) {
    NodeIdentity id;
    id.kind = ObjectKind::File;
    id.file.path = path;
    id.file.volumeSerial = OptionalU64::of(volume);
    id.file.fileId = fileId;
    return id;
}

NodeIdentity DeviceIdentity(const char* boot, const char* name, const char* tag) {
    NodeIdentity id;
    id.kind = ObjectKind::Device;
    id.bootId = boot;
    id.name = name;
    id.instanceTag = tag;
    return id;
}

NodeIdentity ServiceIdentity(const char* boot, const char* name) {
    NodeIdentity id;
    id.kind = ObjectKind::Service;
    id.bootId = boot;
    id.name = name;
    return id;
}

NodeIdentity ConnectionIdentity_(const char* boot, std::uint16_t localPort,
                                 std::uint64_t firstSeen, std::uint64_t lastSeen) {
    NodeIdentity id;
    id.kind = ObjectKind::Connection;
    id.connection.bootId = boot;
    id.connection.protocol = 6U;
    id.connection.localAddress = "10.0.0.5";
    id.connection.localPort = localPort;
    id.connection.remoteAddress = "93.184.216.34";
    id.connection.remotePort = 443U;
    id.connection.observedFirstUtc100ns = OptionalU64::of(firstSeen);
    id.connection.observedLastUtc100ns = OptionalU64::of(lastSeen);
    return id;
}

NodeIdentity TimelineIdentity(const char* recordId) {
    NodeIdentity id;
    id.category = NodeCategory::TimelineEntry;
    id.kind = ObjectKind::Unknown;
    id.name = recordId;
    return id;
}

GraphNode MakeNode(const NodeIdentity& identity, const char* display, const char* evidenceId,
                   NodeLifecycle lifecycle) {
    GraphNode node;
    node.identity = identity;
    node.displayText = display;
    node.evidenceId = evidenceId;
    node.lifecycle = lifecycle;
    node.outcome = CollectionOutcome::success();
    return node;
}

GraphEdge MakeEdge(EdgeKind kind, const std::string& from, const std::string& to,
                   EdgeCertainty certainty, const char* evidenceRef, const char* ruleId) {
    GraphEdge edge;
    edge.kind = kind;
    edge.direction = EdgeDirection::FromTo;
    edge.fromNodeId = from;
    edge.toNodeId = to;
    edge.certainty = certainty;
    if (evidenceRef != nullptr) {
        edge.evidenceRefs.emplace_back(evidenceRef);
    }
    edge.ruleId = ruleId;
    edge.ruleDescriptionKey = "graph.rule.description";
    edge.sourceGroup = "r0.enum";
    return edge;
}

RelationCoverage FullySuccessfulCoverage(std::uint64_t total, const char* evidenceId) {
    RelationCoverage coverage;
    coverage.outcome = CollectionOutcome::success();
    coverage.coverage.totalKnown = OptionalU64::of(total);
    coverage.coverage.succeeded = total;
    coverage.evidenceId = evidenceId;
    return coverage;
}

RelationCoverage FailedCoverage(CollectionStatus status, const char* domain, std::uint64_t code,
                                const char* message) {
    RelationCoverage coverage;
    coverage.outcome = CollectionOutcome::failure(status, domain, code, message);
    return coverage;
}

bool Contains(const std::vector<std::string>& values, const std::string& needle) {
    for (const std::string& value : values) {
        if (value == needle) {
            return true;
        }
    }
    return false;
}

// 单次操作的耗时。§7 L4 的预算是**单次**关系视图 p95 ≤ 200 ms，所以计时必须落在
// 每一次调用上，而不是总时长除以轮数。
long long MicrosSince(std::chrono::steady_clock::time_point start) {
    return static_cast<long long>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count());
}

std::vector<std::string> FilteredEdgeIds(const EntityGraph& graph, const EdgeFilter& filter) {
    std::vector<std::string> ids;
    for (const GraphEdge& edge : graph.edges()) {
        if (EdgeMatchesFilter(edge, filter)) {
            ids.push_back(edge.edgeId);
        }
    }
    return ids;
}

// ---------------------------------------------------------------------------
// G-01：边的语义与筛选
// ---------------------------------------------------------------------------
void TestEdgeSemantics(KswordTests::Suite& s) {
    EntityGraph graph;

    const std::string proc = ProcessIdentity(kBoot, 1000, 111, "worker.exe").nodeKey();
    const std::string thread = ThreadIdentity(kBoot, 1000, 111, 2000, 222).nodeKey();
    const std::string moduleNode = ModuleIdentity("C:\\Windows\\System32\\ntdll.dll", "PDB-NTDLL", 0x7FFE0000ULL).nodeKey();
    const std::string handle = HandleIdentity_(kBoot, 1000, 111, 0x2C, "File").nodeKey();
    const std::string file = FileIdentity_("C:\\Windows\\System32\\ntdll.dll", 0xA1B2, "file-1").nodeKey();
    const std::string other = ProcessIdentity(kBoot, 1500, 333, "peer.exe").nodeKey();

    s.expect(graph.addNode(MakeNode(ProcessIdentity(kBoot, 1000, 111, "worker.exe"), "worker.exe",
                                    "ev-proc", NodeLifecycle::Observed)) ==
                 NodeAdmission::AcceptedNew,
             L"G-01 the process node enters the graph");
    graph.addNode(MakeNode(ThreadIdentity(kBoot, 1000, 111, 2000, 222), "tid 2000", "ev-thread",
                           NodeLifecycle::Observed));
    graph.addNode(MakeNode(ModuleIdentity("C:\\Windows\\System32\\ntdll.dll", "PDB-NTDLL", 0x7FFE0000ULL),
                           "ntdll.dll", "ev-module", NodeLifecycle::Observed));
    graph.addNode(MakeNode(HandleIdentity_(kBoot, 1000, 111, 0x2C, "File"), "handle 0x2C",
                           "ev-handle", NodeLifecycle::Observed));
    graph.addNode(MakeNode(FileIdentity_("C:\\Windows\\System32\\ntdll.dll", 0xA1B2, "file-1"),
                           "ntdll on disk", "ev-file", NodeLifecycle::Observed));
    graph.addNode(MakeNode(ProcessIdentity(kBoot, 1500, 333, "peer.exe"), "peer.exe", "ev-peer",
                           NodeLifecycle::Observed));

    // 六种 edge kind 各一条，各自独立。
    GraphEdge owns = MakeEdge(EdgeKind::Owns, proc, thread, EdgeCertainty::Confirmed, "ev-thread",
                              "rule.process.ownsThread");
    GraphEdge loads = MakeEdge(EdgeKind::Loads, proc, moduleNode, EdgeCertainty::Confirmed, "ev-module",
                               "rule.process.loadsModule");
    GraphEdge maps = MakeEdge(EdgeKind::Maps, proc, file, EdgeCertainty::Candidate, "ev-map",
                              "rule.process.mapsFile");
    GraphEdge opens = MakeEdge(EdgeKind::Opens, handle, file, EdgeCertainty::Confirmed, "ev-handle",
                               "rule.handle.opensFile");
    GraphEdge candidateOwner = MakeEdge(EdgeKind::CandidateOwner, other, handle,
                                        EdgeCertainty::Confirmed, "ev-guess",
                                        "rule.handle.candidateOwner");
    GraphEdge temporal = MakeEdge(EdgeKind::TemporalNeighbor, other, proc, EdgeCertainty::Candidate,
                                  "ev-timeline", "rule.temporal.window");

    s.expect(graph.addEdge(owns) == EdgeAdmission::Accepted, L"G-01 an owns edge with evidence is accepted as given");
    s.expect(graph.addEdge(loads) == EdgeAdmission::Accepted, L"G-01 a loads edge with evidence is accepted as given");
    s.expect(graph.addEdge(maps) == EdgeAdmission::Accepted, L"G-01 a maps edge is accepted as given");
    s.expect(graph.addEdge(opens) == EdgeAdmission::Accepted, L"G-01 an opens edge is accepted as given");
    s.expect(graph.addEdge(candidateOwner) == EdgeAdmission::DemotedCandidateOwnerKind,
             L"G-01 a candidate-owner edge can never be confirmed, however much evidence it carries");
    s.expect(graph.addEdge(temporal) == EdgeAdmission::DemotedTemporalDirectionDropped,
             L"G-01 a temporal-neighbor edge loses the direction it was given");

    s.expect(graph.edgeCount() == 6U, L"G-01 six distinct relation kinds coexist as six edges");

    // 六类各自可筛出来，且互不串味。
    struct KindCase final {
        EdgeKind kind;
        std::size_t expectedCount;
        const wchar_t* label;
    };
    const KindCase kindCases[] = {
        {EdgeKind::Owns, 1U, L"G-01 filtering by owns yields exactly the owns edge"},
        {EdgeKind::Loads, 1U, L"G-01 filtering by loads yields exactly the loads edge"},
        {EdgeKind::Maps, 1U, L"G-01 filtering by maps yields exactly the maps edge"},
        {EdgeKind::Opens, 1U, L"G-01 filtering by opens yields exactly the opens edge"},
        {EdgeKind::CandidateOwner, 1U, L"G-01 filtering by candidate-owner yields exactly that edge"},
        {EdgeKind::TemporalNeighbor, 1U, L"G-01 filtering by temporal-neighbor yields exactly that edge"},
    };
    for (const KindCase& testCase : kindCases) {
        EdgeFilter filter;
        filter.kinds.push_back(testCase.kind);
        const std::vector<std::string> ids = FilteredEdgeIds(graph, filter);
        s.expect(ids.size() == testCase.expectedCount, testCase.label);
        bool allSameKind = true;
        for (const std::string& id : ids) {
            const GraphEdge* edge = graph.findEdge(id);
            if (edge == nullptr || edge->kind != testCase.kind) {
                allSameKind = false;
            }
        }
        s.expect(allSameKind, L"G-01 a kind filter never lets another relation type through");
    }

    // 多类同时筛。
    EdgeFilter ownsAndLoads;
    ownsAndLoads.kinds.push_back(EdgeKind::Owns);
    ownsAndLoads.kinds.push_back(EdgeKind::Loads);
    s.expect(FilteredEdgeIds(graph, ownsAndLoads).size() == 2U,
             L"G-01 a two-kind filter returns exactly those two edges");

    // 确定性筛选。手算：Confirmed 只有 owns / loads / opens 三条 —— candidate-owner
    // 被降级，maps 与 temporal 本来就是 Candidate。
    EdgeFilter confirmedOnly;
    confirmedOnly.certainties.push_back(EdgeCertainty::Confirmed);
    s.expect(FilteredEdgeIds(graph, confirmedOnly).size() == 3U,
             L"G-01 exactly three edges survive as confirmed");
    EdgeFilter candidateOnly;
    candidateOnly.certainties.push_back(EdgeCertainty::Candidate);
    s.expect(FilteredEdgeIds(graph, candidateOnly).size() == 3U,
             L"G-01 exactly three edges are candidates");

    // 缺证据的关系不许是确定的。
    GraphEdge noEvidence = MakeEdge(EdgeKind::Owns, proc, handle, EdgeCertainty::Confirmed, nullptr,
                                    "rule.process.ownsHandle");
    s.expect(graph.addEdge(noEvidence) == EdgeAdmission::DemotedMissingEvidence,
             L"G-01 a confirmed edge without evidence refs is demoted on admission");
    GraphEdge storedNoEvidence;
    s.expect(NormalizeEdge(noEvidence, storedNoEvidence) == EdgeAdmission::DemotedMissingEvidence &&
                 storedNoEvidence.certainty == EdgeCertainty::Candidate,
             L"G-01 the stored certainty of an evidence-free edge is candidate, not confirmed");
    const GraphEdge* storedInGraph = graph.findEdge(storedNoEvidence.edgeId);
    s.expect(storedInGraph != nullptr && storedInGraph->certainty == EdgeCertainty::Candidate,
             L"G-01 the graph never holds a confirmed edge with an empty evidence list");
    bool noConfirmedWithoutEvidence = true;
    for (const GraphEdge& edge : graph.edges()) {
        if (edge.certainty == EdgeCertainty::Confirmed && edge.evidenceRefs.empty()) {
            noConfirmedWithoutEvidence = false;
        }
    }
    s.expect(noConfirmedWithoutEvidence,
             L"G-01 the whole graph holds no confirmed edge without evidence");

    // 拒收路径：默认构造 / 缺端点 / 方向未知 / 重复 id。
    GraphEdge defaulted;
    s.expect(graph.addEdge(defaulted) == EdgeAdmission::RejectedUnknownKind,
             L"G-01 a default-constructed edge is rejected rather than becoming a related edge");
    GraphEdge missingEndpoint = MakeEdge(EdgeKind::Owns, proc, "", EdgeCertainty::Candidate,
                                         "ev-x", "rule.x");
    s.expect(graph.addEdge(missingEndpoint) == EdgeAdmission::RejectedMissingEndpoint,
             L"G-01 an edge missing an endpoint is rejected");
    GraphEdge unknownDirection = MakeEdge(EdgeKind::Owns, proc, other, EdgeCertainty::Candidate,
                                          "ev-x", "rule.x");
    unknownDirection.direction = EdgeDirection::Unknown;
    s.expect(graph.addEdge(unknownDirection) == EdgeAdmission::RejectedUnknownDirection,
             L"G-01 an edge whose direction is unknown is rejected, never read as from-to");
    s.expect(graph.addEdge(owns) == EdgeAdmission::RejectedDuplicateId,
             L"G-01 the same relation is not stored twice");

    // 时间有效区间的三态。
    GraphEdge windowed = MakeEdge(EdgeKind::Owns, proc, other, EdgeCertainty::Candidate, "ev-w",
                                  "rule.window");
    windowed.validFrom100ns = OptionalU64::of(1000);
    windowed.validTo100ns = OptionalU64::of(2000);
    s.expect(EdgeValidAt(windowed, OptionalU64::of(1500)) == TemporalValidity::Valid,
             L"G-01 an edge is valid inside its interval");
    s.expect(EdgeValidAt(windowed, OptionalU64::of(999)) == TemporalValidity::NotValid,
             L"G-01 an edge is not valid before its interval");
    s.expect(EdgeValidAt(windowed, OptionalU64::of(2000)) == TemporalValidity::NotValid,
             L"G-01 the interval end is exclusive");
    s.expect(EdgeValidAt(windowed, OptionalU64::unset()) == TemporalValidity::Unknown,
             L"G-01 asking about an unknown instant yields unknown, not valid");
    GraphEdge openEnded = windowed;
    openEnded.validTo100ns = OptionalU64::unset();
    s.expect(EdgeValidAt(openEnded, OptionalU64::of(1500)) == TemporalValidity::Unknown,
             L"G-01 a half-open interval cannot claim the relation still holds");
    s.expect(EdgeValidAt(owns, OptionalU64::of(1500)) == TemporalValidity::Unknown,
             L"G-01 an edge with no interval at all is unknown, not always-valid");

    // 区间四种写法的边界。from == to 是一个合法的空区间（关系持续了零长时间），
    // from > to 是**区间本身坏了**，两者不是一回事。
    GraphEdge zeroWidth = windowed;
    zeroWidth.validFrom100ns = OptionalU64::of(1000);
    zeroWidth.validTo100ns = OptionalU64::of(1000);
    s.expect(EdgeValidAt(zeroWidth, OptionalU64::of(1000)) == TemporalValidity::NotValid &&
                 EdgeValidAt(zeroWidth, OptionalU64::of(999)) == TemporalValidity::NotValid,
             L"G-01 a zero-length interval is a real but empty interval, never valid");
    GraphEdge onlyTo = windowed;
    onlyTo.validFrom100ns = OptionalU64::unset();
    s.expect(EdgeValidAt(onlyTo, OptionalU64::of(1500)) == TemporalValidity::Unknown,
             L"G-01 an interval with only an end cannot claim the relation had already started");
    s.expect(EdgeValidAt(onlyTo, OptionalU64::of(2500)) == TemporalValidity::NotValid,
             L"G-01 an interval with only an end still expires at that end");

    GraphEdge reversedInterval = windowed;
    reversedInterval.validFrom100ns = OptionalU64::of(2000);
    reversedInterval.validTo100ns = OptionalU64::of(1000);
    s.expect(EdgeValidAt(reversedInterval, OptionalU64::of(500)) ==
                     TemporalValidity::IntervalInvalid &&
                 EdgeValidAt(reversedInterval, OptionalU64::of(1500)) ==
                     TemporalValidity::IntervalInvalid &&
                 EdgeValidAt(reversedInterval, OptionalU64::of(2500)) ==
                     TemporalValidity::IntervalInvalid,
             L"G-01 a reversed interval is reported as a broken interval at every instant, not as expired");
    s.expect(EdgeValidAt(reversedInterval, OptionalU64::unset()) ==
                 TemporalValidity::IntervalInvalid,
             L"G-01 a reversed interval is broken whether or not an instant was given");
    GraphEdge normalizedReversed;
    s.expect(NormalizeEdge(reversedInterval, normalizedReversed) ==
                 EdgeAdmission::RejectedInvalidInterval,
             L"G-01 an edge whose interval runs backwards is rejected instead of entering the graph invisibly");
    s.expect(!EdgeAdmissionAccepted(EdgeAdmission::RejectedInvalidInterval),
             L"G-01 a broken interval counts as a rejection, not as an accepted demotion");
    const std::size_t edgesBeforeReversed = graph.edgeCount();
    s.expect(graph.addEdge(reversedInterval) == EdgeAdmission::RejectedInvalidInterval &&
                 graph.edgeCount() == edgesBeforeReversed,
             L"G-01 the graph never stores an edge that could never be visible at any instant");
    GraphEdge zeroWidthStored;
    s.expect(EdgeAdmissionAccepted(NormalizeEdge(zeroWidth, zeroWidthStored)),
             L"G-01 a zero-length interval is still a well-formed interval and is admitted");

    EdgeFilter atInstant;
    atInstant.atUtc100ns = OptionalU64::of(1500);
    s.expect(EdgeMatchesFilter(windowed, atInstant),
             L"G-01 a time filter keeps an edge that is valid at that instant");
    GraphEdge expired = windowed;
    expired.validFrom100ns = OptionalU64::of(10);
    expired.validTo100ns = OptionalU64::of(20);
    s.expect(!EdgeMatchesFilter(expired, atInstant),
             L"G-01 a time filter drops an edge that had already expired");
    s.expect(EdgeMatchesFilter(owns, atInstant),
             L"G-01 unknown validity is kept by default because unknown is not invalid");
    EdgeFilter strictInstant = atInstant;
    strictInstant.excludeUnknownValidity = true;
    s.expect(!EdgeMatchesFilter(owns, strictInstant),
             L"G-01 unknown validity is dropped only when the caller explicitly asks");

    // 推断说明可展开到规则与来源（G-08 的一半，在这里顺带验证）。
    const GraphEdge* storedOwns = graph.findEdge(DeriveEdgeId(owns));
    s.expect(storedOwns != nullptr, L"G-08 the owns edge can be looked up by its derived id");
    if (storedOwns != nullptr) {
        const EdgeInferenceNote ownsNote = DescribeEdgeInference(*storedOwns);
        s.expect(ownsNote.ruleId == "rule.process.ownsThread" &&
                     ownsNote.evidenceRefs.size() == 1U &&
                     ownsNote.notConfirmedReasonKey.empty(),
                 L"G-08 a confirmed edge names its rule and evidence and has no not-confirmed reason");
    }
    GraphEdge candidateOwnerStored;
    NormalizeEdge(candidateOwner, candidateOwnerStored);
    s.expect(DescribeEdgeInference(candidateOwnerStored).notConfirmedReasonKey ==
                 "graph.edge.candidateOwnerKind",
             L"G-08 a candidate-owner edge explains that its kind cannot be confirmed");
    s.expect(DescribeEdgeInference(storedNoEvidence).notConfirmedReasonKey ==
                 "graph.edge.noEvidence",
             L"G-08 an evidence-free edge explains that it has no evidence");
    GraphEdge unknownCertainty = MakeEdge(EdgeKind::Maps, proc, file, EdgeCertainty::Unknown,
                                          "ev-m2", "rule.m2");
    s.expect(DescribeEdgeInference(unknownCertainty).notConfirmedReasonKey ==
                 "graph.edge.certaintyUnknown",
             L"G-08 an unknown-certainty edge says so instead of pretending to be a candidate");
    s.expect(DescribeEdgeInference(maps).notConfirmedReasonKey == "graph.edge.candidateEvidence",
             L"G-08 a candidate edge with evidence explains that the evidence is only candidate level");

    // 降级优先级：既没有证据、这一类又不可能确定时，报的必须是"缺证据"。反过来说
    // 成"这一类不能确定"，调用方会以为换个 kind 就能 Confirmed。
    GraphEdge candidateOwnerNoEvidence = MakeEdge(EdgeKind::CandidateOwner, other, thread,
                                                  EdgeCertainty::Confirmed, nullptr,
                                                  "rule.handle.candidateOwner2");
    GraphEdge candidateOwnerNoEvidenceStored;
    s.expect(NormalizeEdge(candidateOwnerNoEvidence, candidateOwnerNoEvidenceStored) ==
                     EdgeAdmission::DemotedMissingEvidence &&
                 candidateOwnerNoEvidenceStored.certainty == EdgeCertainty::Candidate,
             L"G-01 an edge with neither evidence nor a confirmable kind reports the missing evidence first");
    s.expect(DescribeEdgeInference(candidateOwnerNoEvidence).notConfirmedReasonKey ==
                 "graph.edge.noEvidence",
             L"G-08 the same priority holds in the inference note: no evidence is named before the kind");

    // G-08 的推断说明是对外接口，调用方完全可以拿一条没进过图的边来问。它不许原样
    // 相信传进来的 certainty —— 否则会呈现出一条"已确认、无需解释、零来源"的关系。
    GraphEdge fabricated;
    fabricated.kind = EdgeKind::Owns;
    fabricated.direction = EdgeDirection::FromTo;
    fabricated.fromNodeId = proc;
    fabricated.toNodeId = thread;
    fabricated.certainty = EdgeCertainty::Confirmed;  // 没有任何 evidenceRefs
    const EdgeInferenceNote fabricatedNote = DescribeEdgeInference(fabricated);
    s.expect(fabricatedNote.certainty == EdgeCertainty::Candidate &&
                 fabricatedNote.evidenceRefs.empty() &&
                 fabricatedNote.notConfirmedReasonKey == "graph.edge.noEvidence",
             L"G-01 an unstored confirmed edge with no evidence is described as candidate, with the reason spelled out");
    GraphEdge fabricatedUnknownKind = fabricated;
    fabricatedUnknownKind.kind = EdgeKind::Unknown;
    s.expect(DescribeEdgeInference(fabricatedUnknownKind).certainty == EdgeCertainty::Candidate,
             L"G-01 even an edge the graph would reject outright is never described as confirmed without evidence");

    // 同一对端点、同一关系、不同时间区间是两个事实，不是同一条边（G-01 的"时间有效
    // 区间"如果不进身份，第二段区间会被当成重复而丢掉）。
    EntityGraph intervalGraph;
    intervalGraph.addNode(MakeNode(ProcessIdentity(kBoot, 1000, 111, "worker.exe"), "worker.exe",
                                   "ev-proc", NodeLifecycle::Observed));
    intervalGraph.addNode(MakeNode(FileIdentity_("C:\\Windows\\System32\\ntdll.dll", 0xA1B2,
                                                 "file-1"),
                                   "ntdll on disk", "ev-file", NodeLifecycle::Observed));
    GraphEdge firstWindow = MakeEdge(EdgeKind::Maps, proc, file, EdgeCertainty::Candidate, "ev-m1",
                                     "rule.maps");
    firstWindow.validFrom100ns = OptionalU64::of(1000);
    firstWindow.validTo100ns = OptionalU64::of(2000);
    GraphEdge secondWindow = firstWindow;
    secondWindow.validFrom100ns = OptionalU64::of(5000);
    secondWindow.validTo100ns = OptionalU64::of(6000);
    s.expect(EdgeAdmissionAccepted(intervalGraph.addEdge(firstWindow)),
             L"G-01 the first mapping window is admitted");
    s.expect(EdgeAdmissionAccepted(intervalGraph.addEdge(secondWindow)) &&
                 intervalGraph.edgeCount() == 2U,
             L"G-01 the same relation over a different interval is a second edge, not a duplicate");
    EdgeFilter earlyInstant;
    earlyInstant.atUtc100ns = OptionalU64::of(1500);
    s.expect(FilteredEdgeIds(intervalGraph, earlyInstant).size() == 1U,
             L"G-01 a time filter separates the two intervals of the same relation");

    // 对称边的端点归一化：A-B 与 B-A 是同一条边。
    EntityGraph symmetricGraph;
    symmetricGraph.addNode(MakeNode(ProcessIdentity(kBoot, 1000, 111, "a.exe"), "a", "ev-a",
                                    NodeLifecycle::Observed));
    symmetricGraph.addNode(MakeNode(ProcessIdentity(kBoot, 1500, 333, "b.exe"), "b", "ev-b",
                                    NodeLifecycle::Observed));
    GraphEdge forward = MakeEdge(EdgeKind::TemporalNeighbor, proc, other, EdgeCertainty::Candidate,
                                 "ev-t", "rule.t");
    GraphEdge backward = MakeEdge(EdgeKind::TemporalNeighbor, other, proc, EdgeCertainty::Candidate,
                                  "ev-t", "rule.t");
    s.expect(EdgeAdmissionAccepted(symmetricGraph.addEdge(forward)),
             L"G-01 the first temporal-neighbor edge is admitted");
    s.expect(symmetricGraph.addEdge(backward) == EdgeAdmission::RejectedDuplicateId,
             L"G-01 the same temporal neighbourhood stated backwards is the same edge");
    s.expect(symmetricGraph.edges().front().direction == EdgeDirection::Symmetric,
             L"G-01 a temporal-neighbor edge is stored without direction so it cannot read as cause");
}

// ---------------------------------------------------------------------------
// G-02：生命周期与旧对象
// ---------------------------------------------------------------------------
void TestLifecycleIdentity(KswordTests::Suite& s) {
    // 同 PID 不同创建时间 -> 两个节点。
    const NodeIdentity firstInstance = ProcessIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity reusedPid = ProcessIdentity(kBoot, 1000, 999, "worker.exe");
    s.expect(firstInstance.nodeKey() != reusedPid.nodeKey(),
             L"G-02 the same pid with a different creation time is a different node");
    s.expect(MatchProcessInstance(firstInstance.process, reusedPid.process) == MatchResult::NoMatch,
             L"G-02 pid reuse is a mismatch, not a weak match");

    // 不同启动周期 -> 两个节点。
    const NodeIdentity acrossBoot = ProcessIdentity(kBoot2, 1000, 111, "worker.exe");
    s.expect(firstInstance.nodeKey() != acrossBoot.nodeKey(),
             L"G-02 the same pid and creation time in a different boot cycle is a different node");

    // 强身份的节点键必须包含跨会话主键；弱身份根本没有主键。
    s.expect(!firstInstance.crossSessionKey().empty() &&
                 firstInstance.nodeKey().find(firstInstance.crossSessionKey()) != std::string::npos,
             L"G-02 a strong node key is built on the cross-session key");
    const NodeIdentity weakA = WeakProcessIdentity(1000, "observation-1");
    const NodeIdentity weakB = WeakProcessIdentity(1000, "observation-2");
    s.expect(weakA.crossSessionKey().empty() && weakA.strength() == IdentityStrength::Weak,
             L"G-02 a process without a creation time gets no cross-session key");
    s.expect(weakA.nodeKey() != weakB.nodeKey(),
             L"G-02 two weak observations of the same pid stay two nodes");
    s.expect(weakA.nodeKey() != firstInstance.nodeKey(),
             L"G-02 a weak observation is never merged into the strong instance");

    // 地址复用：同名同址的设备两次观察必须分开。
    const NodeIdentity deviceFirst = DeviceIdentity(kBoot, "\\Device\\Foo", "epoch-1");
    const NodeIdentity deviceSecond = DeviceIdentity(kBoot, "\\Device\\Foo", "epoch-2");
    s.expect(deviceFirst.nodeKey() != deviceSecond.nodeKey(),
             L"G-02 two observations of a reusable device name stay two nodes");
    s.expect(deviceFirst.strength() == IdentityStrength::Weak,
             L"G-02 a device has no lifecycle identity so its strength is capped at weak");
    s.expect(MatchNodeIdentity(deviceFirst, DeviceIdentity(kBoot, "\\Device\\Foo", "epoch-1")) ==
                 MatchResult::Candidate,
             L"G-02 identical device names are at most a candidate, never confirmed");
    s.expect(MatchNodeIdentity(deviceFirst, deviceSecond) == MatchResult::NoMatch,
             L"G-02 different instance tags on the same device name are a mismatch");
    s.expect(MatchNodeIdentity(deviceFirst, ServiceIdentity(kBoot, "\\Device\\Foo")) ==
                 MatchResult::NoMatch,
             L"G-02 a device and a service with the same name are never the same node");

    // "什么都没填"不是"弱匹配"。MatchResult 没有"信息不足"这一档，Candidate 会被
    // 调用方当成身份证据用，所以没有信息必须落到 NoMatch 那一侧。
    s.expect(MatchNodeIdentity(NodeIdentity{}, NodeIdentity{}) == MatchResult::NoMatch,
             L"G-02 two default-constructed identities are not a candidate for being the same object");
    NodeIdentity namelessDevice;
    namelessDevice.kind = ObjectKind::Device;
    namelessDevice.bootId = kBoot;  // 没有名字 -> Unusable
    s.expect(namelessDevice.strength() == IdentityStrength::Unusable,
             L"G-02 a device with no name has an unusable identity");
    s.expect(MatchNodeIdentity(deviceFirst, namelessDevice) == MatchResult::NoMatch,
             L"G-02 a named device and an unusable one are not a candidate match");
    s.expect(MatchNodeIdentity(namelessDevice, namelessDevice) == MatchResult::NoMatch,
             L"G-02 an unusable identity is not even a candidate for being itself");

    // 同基址不同映像 -> 不同节点。
    const NodeIdentity driverA = DriverIdentity("C:\\Windows\\System32\\drivers\\a.sys", "PDB-A",
                                                0xFFFFF80000000000ULL);
    const NodeIdentity driverB = DriverIdentity("C:\\Windows\\System32\\drivers\\b.sys", "PDB-B",
                                                0xFFFFF80000000000ULL);
    s.expect(driverA.nodeKey() != driverB.nodeKey(),
             L"G-02 two images loaded at the same reused base address are different nodes");

    // 完全没有身份也没有判别标签 -> 拒收。
    EntityGraph graph;
    GraphNode empty;
    s.expect(graph.addNode(empty) == NodeAdmission::RejectedNoIdentity,
             L"G-02 a node with neither identity nor discriminator is rejected");
    GraphNode tagged;
    tagged.identity.instanceTag = "observation-1";
    s.expect(graph.addNode(tagged) == NodeAdmission::AcceptedNew,
             L"G-02 a caller-supplied discriminator makes an otherwise unusable record addressable");

    // 合并语义。
    EntityGraph merged;
    s.expect(merged.addNode(MakeNode(firstInstance, "worker.exe", "ev-1",
                                     NodeLifecycle::Observed)) == NodeAdmission::AcceptedNew,
             L"G-02 the first observation creates the node");
    s.expect(merged.addNode(MakeNode(firstInstance, "worker.exe", "ev-1",
                                     NodeLifecycle::Observed)) == NodeAdmission::AcceptedMerged,
             L"G-02 the same instance observed twice merges into one node");
    s.expect(merged.addNode(MakeNode(firstInstance, "worker.exe", "ev-2", NodeLifecycle::Ended)) ==
                 NodeAdmission::AcceptedMergedLifecycleConflict,
             L"G-02 contradictory lifecycles are reported, not silently resolved");
    s.expect(merged.findNode(firstInstance.nodeKey()) != nullptr &&
                 merged.findNode(firstInstance.nodeKey())->lifecycle == NodeLifecycle::Unknown,
             L"G-02 a lifecycle conflict downgrades to unknown instead of picking a side");
    s.expect(merged.nodeCount() == 1U, L"G-02 merging never adds a second node");
    s.expect(merged.addNode(MakeNode(reusedPid, "worker.exe", "ev-3", NodeLifecycle::Observed)) ==
                 NodeAdmission::AcceptedNew,
             L"G-02 the pid-reusing instance becomes its own node next to the historical one");
    s.expect(merged.nodeCount() == 2U,
             L"G-02 the historical object survives alongside the current one");

    // 会话回放：nodeId 由已保存数据给出，两条来源不同的记录完全可能带着同一个 id
    // 和两份互相矛盾的身份。按 id 合并会把第二次观察整条抹掉 —— 那正是"把两个对象
    // 合成一个"。
    EntityGraph replay;
    GraphNode savedRow = MakeNode(firstInstance, "worker.exe", "ev-row-7", NodeLifecycle::Observed);
    savedRow.nodeId = "saved-row-7";
    s.expect(replay.addNode(savedRow) == NodeAdmission::AcceptedNew,
             L"G-02 a replayed row keeps the node id that was saved with it");
    GraphNode otherObject = MakeNode(ProcessIdentity(kBoot, 4444, 999, "evil.exe"), "evil.exe",
                                     "ev-row-7b", NodeLifecycle::Observed);
    otherObject.nodeId = "saved-row-7";
    s.expect(MatchNodeIdentity(savedRow.identity, otherObject.identity) == MatchResult::NoMatch,
             L"G-02 the two records really are different objects by identity");
    s.expect(replay.addNode(otherObject) == NodeAdmission::RejectedIdentityConflict,
             L"G-02 a second, contradictory identity on the same node id is rejected, not merged away");
    s.expect(!NodeAdmissionAccepted(NodeAdmission::RejectedIdentityConflict),
             L"G-02 an identity conflict counts as a rejection, so callers cannot read it as accepted");
    s.expect(replay.identityConflictCount() == 1U,
             L"G-02 the rejected observation is accounted for instead of silently disappearing");
    const GraphNode* keptRow = replay.findNode("saved-row-7");
    s.expect(keptRow != nullptr && keptRow->identity.process.pid == OptionalU64::of(1000) &&
                 keptRow->displayText == "worker.exe" && keptRow->evidenceId == "ev-row-7",
             L"G-02 the first observation is kept intact and never overwritten by the conflicting one");
    s.expect(replay.nodeCount() == 1U,
             L"G-02 a rejected identity conflict does not quietly create a second node either");
    s.expect(replay.addNode(savedRow) == NodeAdmission::AcceptedMerged,
             L"G-02 the very same record arriving twice still merges");

    // 身份不足但调用方给了判别标签的记录，重复观察仍然要能合并 —— 身份门槛不能把
    // "同一行读了两遍"也判成冲突。
    GraphNode weakRow;
    weakRow.nodeId = "saved-row-9";
    weakRow.identity.kind = ObjectKind::Process;
    weakRow.identity.instanceTag = "row-9";
    weakRow.displayText = "unknown process";
    weakRow.evidenceId = "ev-row-9";
    weakRow.lifecycle = NodeLifecycle::Observed;
    s.expect(replay.addNode(weakRow) == NodeAdmission::AcceptedNew &&
                 replay.addNode(weakRow) == NodeAdmission::AcceptedMerged,
             L"G-02 re-observing the same weak record under the same id still merges");
}

// ---------------------------------------------------------------------------
// G-02：历史边不许自动套到当前对象
// ---------------------------------------------------------------------------
void TestHistoricalEdgeToLive(KswordTests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity savedProcess = ProcessIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity savedThread = ThreadIdentity(kBoot, 1000, 111, 2000, 222);
    const NodeIdentity savedDevice = DeviceIdentity(kBoot, "\\Device\\Foo", "epoch-1");

    graph.addNode(MakeNode(savedProcess, "worker.exe", "ev-proc", NodeLifecycle::Ended));
    graph.addNode(MakeNode(savedThread, "tid 2000", "ev-thread", NodeLifecycle::Ended));
    graph.addNode(MakeNode(savedDevice, "\\Device\\Foo", "ev-device", NodeLifecycle::Ended));

    GraphEdge owns = MakeEdge(EdgeKind::Owns, savedProcess.nodeKey(), savedThread.nodeKey(),
                              EdgeCertainty::Confirmed, "ev-thread", "rule.owns");
    graph.addEdge(owns);
    GraphEdge deviceEdge = MakeEdge(EdgeKind::DeviceOf, savedDevice.nodeKey(),
                                    savedProcess.nodeKey(), EdgeCertainty::Candidate, "ev-device",
                                    "rule.deviceOf");
    graph.addEdge(deviceEdge);
    const std::string ownsId = DeriveEdgeId(owns);
    const std::string deviceEdgeId = DeriveEdgeId(deviceEdge);

    HistoricalEdgeLiveRequest request;
    request.edgeId = ownsId;
    request.endpoint = EndpointRole::From;
    request.page = NavigationPage::Process;
    request.targetPageAvailable = true;
    request.objectPresentInPage = true;
    request.evidencePresentInSession = true;

    // 1) PID 复用：现场是同 PID 的另一个实例。
    HistoricalEdgeLiveRequest reused = request;
    reused.live.found = true;
    reused.live.liveProcess = ProcessIdentity(kBoot, 1000, 999, "worker.exe").process;
    const HistoricalEdgeLiveResult mismatch = ResolveHistoricalEdgeToLive(graph, reused);
    s.expect(mismatch.edgeFound && mismatch.nodeFound && mismatch.liveResolverSupported,
             L"G-02 the historical edge and its saved endpoint are found");
    s.expect(mismatch.identityDecision == LiveNavigationDecision::RejectIdentityMismatch,
             L"G-02 a reused pid is rejected as an identity mismatch");
    s.expect(mismatch.liveNodeId.empty(),
             L"G-02 a rejected historical edge never names a live node id");
    s.expect(!mismatch.navigationAttempted,
             L"G-02 navigation is not even attempted when the identity does not match");
    s.expect(mismatch.navigation != NavigationOutcome::Delivered,
             L"G-02 a rejected historical edge never reports a delivered navigation");
    s.expect(mismatch.reasonKey == "graph.live.identityMismatch",
             L"G-02 the rejection names pid reuse rather than a generic failure");

    // 2) 对象已退出。
    HistoricalEdgeLiveRequest exited = request;
    exited.live.found = false;
    const HistoricalEdgeLiveResult gone = ResolveHistoricalEdgeToLive(graph, exited);
    s.expect(gone.identityDecision == LiveNavigationDecision::RejectObjectExited &&
                 !gone.navigationAttempted && gone.liveNodeId.empty(),
             L"G-02 an object that no longer exists is reported as exited, not as mismatch");

    // 3) 身份不足以确认（现场记录缺创建时间）。
    HistoricalEdgeLiveRequest unverifiable = request;
    unverifiable.live.found = true;
    unverifiable.live.liveProcess.bootId = kBoot;
    unverifiable.live.liveProcess.pid = OptionalU64::of(1000);
    const HistoricalEdgeLiveResult weak = ResolveHistoricalEdgeToLive(graph, unverifiable);
    s.expect(weak.identityDecision == LiveNavigationDecision::RejectIdentityUnverifiable &&
                 !weak.navigationAttempted && weak.liveNodeId.empty(),
             L"G-02 a live record without a creation time cannot confirm the historical object");

    // 4) 身份确认一致 -> 允许导航。
    HistoricalEdgeLiveRequest allowed = request;
    allowed.live.found = true;
    allowed.live.liveProcess = savedProcess.process;
    const HistoricalEdgeLiveResult ok = ResolveHistoricalEdgeToLive(graph, allowed);
    s.expect(ok.identityDecision == LiveNavigationDecision::Allow && ok.navigationAttempted,
             L"G-02 a confirmed identity is the only path that reaches navigation");
    s.expect(ok.navigation == NavigationOutcome::Delivered,
             L"G-02 a confirmed identity with a live page and saved evidence is delivered");
    s.expect(ok.liveNodeId == savedProcess.nodeKey(),
             L"G-02 a confirmed match resolves to the very same node id, not a new one");

    // 5) 证据没保存 -> 不许悄悄现场补齐。
    HistoricalEdgeLiveRequest unsavedEvidence = allowed;
    unsavedEvidence.evidencePresentInSession = false;
    s.expect(ResolveHistoricalEdgeToLive(graph, unsavedEvidence).navigation ==
                 NavigationOutcome::EvidenceNotSaved,
             L"G-06 navigation stops when the evidence behind the edge was never saved");

    // 6) 没有现场重解析契约的类别 -> 明确说不可校验，而不是放行。
    HistoricalEdgeLiveRequest deviceRequest = request;
    deviceRequest.edgeId = deviceEdgeId;
    deviceRequest.endpoint = EndpointRole::From;
    deviceRequest.live.found = true;
    deviceRequest.live.liveProcess = savedProcess.process;
    const HistoricalEdgeLiveResult device = ResolveHistoricalEdgeToLive(graph, deviceRequest);
    s.expect(device.nodeFound && !device.liveResolverSupported &&
                 device.identityDecision == LiveNavigationDecision::RejectIdentityUnverifiable &&
                 !device.navigationAttempted,
             L"G-02 a kind without a live resolver is reported unverifiable rather than allowed");
    s.expect(device.reasonKey == "graph.live.noResolverForKind",
             L"G-02 an unverifiable kind explains that no resolver exists, not that it mismatched");

    // 7) 边不存在。
    HistoricalEdgeLiveRequest missingEdge = request;
    missingEdge.edgeId = "no-such-edge";
    const HistoricalEdgeLiveResult none = ResolveHistoricalEdgeToLive(graph, missingEdge);
    s.expect(!none.edgeFound && !none.navigationAttempted && none.liveNodeId.empty(),
             L"G-02 a missing historical edge resolves to nothing at all");
}

// ---------------------------------------------------------------------------
// G-03：三条最小可用调查链
// ---------------------------------------------------------------------------
void TestProcessChain(KswordTests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity process = ProcessIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity thread = ThreadIdentity(kBoot, 1000, 111, 2000, 222);
    const NodeIdentity threadTwo = ThreadIdentity(kBoot, 1000, 111, 2100, 223);
    graph.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    graph.addNode(MakeNode(thread, "tid 2000", "ev-thread", NodeLifecycle::Observed));
    graph.addNode(MakeNode(threadTwo, "tid 2100", "ev-thread", NodeLifecycle::Observed));

    graph.addEdge(MakeEdge(EdgeKind::Owns, process.nodeKey(), thread.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-thread", "rule.owns"));
    graph.addEdge(MakeEdge(EdgeKind::Owns, process.nodeKey(), threadTwo.nodeKey(),
                           EdgeCertainty::Candidate, "ev-thread", "rule.owns"));

    // 线程采到了；模块根本没声明覆盖；句柄采全了确实是空的。
    graph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Thread,
                                  FullySuccessfulCoverage(2, "ev-thread"));
    graph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Handle,
                                  FullySuccessfulCoverage(0, "ev-handle"));

    ChainOptions options;
    const InvestigationChain chain =
        BuildChain(graph, ChainKind::ProcessSubjects, process.nodeKey(), options);
    s.expect(chain.rootFound && chain.steps.size() == 4U,
             L"G-03 the process chain has a root plus thread, module and handle steps");
    s.expect(chain.steps[0].availability == StepAvailability::Present,
             L"G-03 the process root step is present");
    s.expect(chain.steps[1].availability == StepAvailability::Present &&
                 chain.steps[1].matchCount == 2U,
             L"G-03 both owned threads are reached in one hop");
    s.expect(chain.steps[1].weakestEdgeCertainty == EdgeCertainty::Candidate,
             L"G-03 the thread step reports its weakest edge certainty, not its strongest");
    s.expect(chain.steps[2].availability == StepAvailability::MissingNotCollected,
             L"G-03 an undeclared module source is reported as not collected, not as no modules");
    s.expect(chain.steps[2].outcome.status == CollectionStatus::NotCollected,
             L"G-03 the not-collected step keeps its collection status");
    s.expect(chain.steps[3].availability == StepAvailability::MissingNoData,
             L"G-03 a fully accounted empty handle enumeration is a true empty, not a gap");
    s.expect(chain.missingStepCount() == 2U && !chain.complete(),
             L"G-03 the chain reports exactly two missing links and is not complete");
    s.expect(chain.everyPresentStepOpensSource(),
             L"G-03 every present step can open its source detail");
    s.expect(chain.steps[1].evidenceOpenable && !chain.steps[1].evidenceId.empty(),
             L"G-03 the thread step names the evidence that backs it");
    s.expect(chain.steps[1].anyObjectNavigable && chain.steps[1].everyObjectNavigable,
             L"G-03 both threads of the thread step can be navigated to, so the step is navigable either way");

    // 一环里只有一部分节点带证据时，"这一步能打开来源"必须是假：G-03 要的是每一步
    // 都能打开来源详情，不是"随便有一个能打开就算"。手算：3 个线程，只有第 1 个有
    // evidenceId，matchCount=3、nodeIds=3、能开证据的只有 1 个。
    EntityGraph partialEvidence;
    partialEvidence.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    for (std::uint64_t i = 0; i < 3; ++i) {
        const NodeIdentity subject = ThreadIdentity(kBoot, 1000, 111, 7000 + i, 800 + i);
        partialEvidence.addNode(MakeNode(subject, "t", (i == 0) ? "ev-thread-0" : "",
                                         NodeLifecycle::Observed));
        partialEvidence.addEdge(MakeEdge(EdgeKind::Owns, process.nodeKey(), subject.nodeKey(),
                                         EdgeCertainty::Confirmed, "ev-thread-0", "rule.owns"));
    }
    const InvestigationChain mixedChain =
        BuildChain(partialEvidence, ChainKind::ProcessSubjects, process.nodeKey(), options);
    s.expect(mixedChain.steps[1].availability == StepAvailability::Present &&
                 mixedChain.steps[1].matchCount == 3U && mixedChain.steps[1].nodeIds.size() == 3U,
             L"G-03 all three threads are reached even though only one carries evidence");
    s.expect(!mixedChain.steps[1].evidenceOpenable,
             L"G-03 a step whose nodes cannot all open their source does not claim to be openable");
    s.expect(!mixedChain.everyPresentStepOpensSource(),
             L"G-03 one openable node out of three does not satisfy every-step-opens-source");
    s.expect(mixedChain.steps[1].anyObjectNavigable && mixedChain.steps[1].everyObjectNavigable,
             L"G-03 object navigation is reported separately from source openability");

    // 覆盖只到一半 -> 与"确实没有"必须分开。
    EntityGraph partialGraph;
    partialGraph.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    RelationCoverage partial = FullySuccessfulCoverage(9, "ev-thread");
    partial.outcome.status = CollectionStatus::Partial;
    partial.coverage.succeeded = 3;
    partialGraph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Thread, partial);
    const InvestigationChain partialChain =
        BuildChain(partialGraph, ChainKind::ProcessSubjects, process.nodeKey(), options);
    s.expect(partialChain.steps[1].availability == StepAvailability::MissingCoverageIncomplete,
             L"G-03 a partially covered enumeration cannot claim there are no threads");

    // 成功但账目一字未填 -> 也不算"确实没有"。
    EntityGraph unaccounted;
    unaccounted.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    RelationCoverage blank;
    blank.outcome = CollectionOutcome::success();
    unaccounted.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Thread, blank);
    s.expect(BuildChain(unaccounted, ChainKind::ProcessSubjects, process.nodeKey(), options)
                     .steps[1]
                     .availability == StepAvailability::MissingCoverageIncomplete,
             L"G-03 a success with an empty account is not positive evidence of absence");

    // 根节点不在数据里。
    const InvestigationChain noRoot =
        BuildChain(graph, ChainKind::ProcessSubjects, "not-saved", options);
    s.expect(!noRoot.rootFound && noRoot.steps[0].availability == StepAvailability::MissingNotCollected,
             L"G-03 a root that was never saved is reported missing instead of silently empty");
    s.expect(noRoot.steps[1].availability == StepAvailability::MissingPreviousStepMissing,
             L"G-03 a step whose predecessor is missing says so rather than blaming its own source");
    s.expect(!noRoot.complete() && noRoot.missingStepCount() == 4U,
             L"G-03 a chain with no root is not complete");

    // 身份不足的邻居不能当作确定的一跳。
    EntityGraph weakGraph;
    weakGraph.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    GraphNode weakThread;
    weakThread.identity.kind = ObjectKind::Thread;   // 没有 tid -> Unusable
    weakThread.identity.instanceTag = "row-7";
    weakThread.displayText = "unknown thread";
    weakThread.evidenceId = "ev-weak";
    weakThread.lifecycle = NodeLifecycle::Observed;
    weakGraph.addNode(weakThread);
    weakGraph.addEdge(MakeEdge(EdgeKind::Owns, process.nodeKey(),
                               weakThread.identity.nodeKey(), EdgeCertainty::Candidate, "ev-weak",
                               "rule.owns"));
    weakGraph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Thread,
                                      FullySuccessfulCoverage(1, "ev-weak"));
    const InvestigationChain weakChain =
        BuildChain(weakGraph, ChainKind::ProcessSubjects, process.nodeKey(), options);
    s.expect(weakChain.steps[1].availability == StepAvailability::MissingIdentityUnusable &&
                 weakChain.steps[1].matchCount == 1U,
             L"G-03 a record with an unusable identity is counted but is not a confirmed hop");
    const GraphNode* storedWeak = weakGraph.findNode(weakThread.identity.nodeKey());
    s.expect(storedWeak != nullptr && !storedWeak->objectNavigable(),
             L"G-02 an unusable identity never becomes navigable just because it has a node id");
    s.expect(storedWeak != nullptr &&
                 storedWeak->identity.makeRef("ev-weak", "unknown thread").key.empty(),
             L"G-02 an unusable identity hands out no navigation key at all");
    s.expect(storedWeak != nullptr && storedWeak->evidenceOpenable(),
             L"G-05 an unusable identity can still open its own raw evidence");
    s.expect(!weakChain.steps[1].anyObjectNavigable && !weakChain.steps[1].everyObjectNavigable &&
                 weakChain.steps[1].evidenceOpenable,
             L"G-03 an unusable hop offers the source detail but not object navigation");
    const GraphNode* storedStrong = graph.findNode(thread.nodeKey());
    s.expect(storedStrong != nullptr && storedStrong->objectNavigable(),
             L"G-02 a strong identity really is navigable, so the check above is not vacuous");

    // 根节点身份不足：整条链的第一步就不成立。
    EntityGraph unusableRootGraph;
    GraphNode unusableRoot;
    unusableRoot.identity.kind = ObjectKind::Process;  // 没有 pid -> Unusable
    unusableRoot.identity.instanceTag = "row-1";
    unusableRoot.displayText = "unknown process";
    unusableRoot.evidenceId = "ev-row";
    unusableRoot.lifecycle = NodeLifecycle::Observed;
    unusableRootGraph.addNode(unusableRoot);
    const InvestigationChain unusableChain = BuildChain(
        unusableRootGraph, ChainKind::ProcessSubjects, unusableRoot.identity.nodeKey(), options);
    s.expect(unusableChain.rootFound &&
                 unusableChain.steps[0].availability == StepAvailability::MissingIdentityUnusable,
             L"G-03 a root whose identity is unusable is not reported as a usable first step");
    s.expect(unusableChain.steps[0].evidenceOpenable &&
                 !unusableChain.steps[0].anyObjectNavigable &&
                 !unusableChain.steps[0].everyObjectNavigable,
             L"G-03 an unusable root can open its raw evidence but cannot be navigated to");
    s.expect(unusableChain.steps[1].availability == StepAvailability::MissingPreviousStepMissing,
             L"G-03 the hops after an unusable root report the broken predecessor");

    // 上一环身份不足时，下一环不许从那些对象继续走成"确定的一跳"。手算：
    // Device --DeviceOf--> Driver（身份不足）--ImageOf--> File，两条边都在、覆盖都
    // 声明为采全了，第 1 环 MissingIdentityUnusable，第 2、3 环都必须是"上一环缺失"。
    EntityGraph brokenPredecessor;
    const NodeIdentity deviceRoot = DeviceIdentity(kBoot, "\\Device\\Chain", "epoch-1");
    GraphNode unusableDriver;
    unusableDriver.identity.kind = ObjectKind::Driver;  // 没有 imagePath / pdb -> Unusable
    unusableDriver.identity.instanceTag = "row-3";
    unusableDriver.displayText = "unknown driver";
    unusableDriver.evidenceId = "ev-unknown-driver";
    unusableDriver.lifecycle = NodeLifecycle::Observed;
    const NodeIdentity chainImage =
        FileIdentity_("C:\\Windows\\System32\\drivers\\chain.sys", 0xA1B2, "file-chain");
    brokenPredecessor.addNode(MakeNode(deviceRoot, "\\Device\\Chain", "ev-device",
                                       NodeLifecycle::Observed));
    brokenPredecessor.addNode(unusableDriver);
    brokenPredecessor.addNode(MakeNode(chainImage, "chain.sys", "ev-image", NodeLifecycle::Observed));
    brokenPredecessor.addEdge(MakeEdge(EdgeKind::DeviceOf, deviceRoot.nodeKey(),
                                       unusableDriver.identity.nodeKey(), EdgeCertainty::Confirmed,
                                       "ev-device", "rule.deviceOf"));
    brokenPredecessor.addEdge(MakeEdge(EdgeKind::ImageOf, unusableDriver.identity.nodeKey(),
                                       chainImage.nodeKey(), EdgeCertainty::Confirmed, "ev-image",
                                       "rule.imageOf"));
    brokenPredecessor.declareRelationCoverage(EdgeKind::DeviceOf, ObjectKind::Driver,
                                              FullySuccessfulCoverage(1, "ev-device"));
    brokenPredecessor.declareRelationCoverage(EdgeKind::ImageOf, ObjectKind::File,
                                              FullySuccessfulCoverage(1, "ev-image"));
    const InvestigationChain brokenChain =
        BuildChain(brokenPredecessor, ChainKind::DeviceToService, deviceRoot.nodeKey(), options);
    s.expect(brokenChain.steps[1].availability == StepAvailability::MissingIdentityUnusable,
             L"G-03 a driver whose identity is unusable is not a confirmed hop");
    s.expect(brokenChain.steps[2].availability == StepAvailability::MissingPreviousStepMissing,
             L"G-03 the hop after an unusable predecessor is not present, however many records it finds");
    s.expect(!brokenChain.steps[2].anyObjectNavigable && !brokenChain.steps[2].everyObjectNavigable,
             L"G-03 a hop starting from an unverified predecessor offers no object navigation");
    s.expect(brokenChain.steps[3].availability == StepAvailability::MissingPreviousStepMissing &&
                 brokenChain.missingStepCount() == 3U,
             L"G-03 the broken predecessor propagates instead of blaming the service source");

    // 每步条数上限。
    EntityGraph manyGraph;
    manyGraph.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    for (std::uint64_t i = 0; i < 5; ++i) {
        const NodeIdentity extra = ThreadIdentity(kBoot, 1000, 111, 3000 + i, 400 + i);
        manyGraph.addNode(MakeNode(extra, "t", "ev-thread", NodeLifecycle::Observed));
        manyGraph.addEdge(MakeEdge(EdgeKind::Owns, process.nodeKey(), extra.nodeKey(),
                                   EdgeCertainty::Confirmed, "ev-thread", "rule.owns"));
    }
    ChainOptions tight;
    tight.maxNodesPerStep = 2;
    const InvestigationChain truncated =
        BuildChain(manyGraph, ChainKind::ProcessSubjects, process.nodeKey(), tight);
    s.expect(truncated.steps[1].matchCount == 5U && truncated.steps[1].nodeIds.size() == 2U &&
                 truncated.steps[1].truncated,
             L"G-03 a per-step cap reports the real match count next to the truncated list");
}

void TestDeviceChain(KswordTests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity device = DeviceIdentity(kBoot, "\\Device\\Ksword0", "epoch-1");
    const NodeIdentity driverObject =
        DriverIdentity("\\Driver\\Ksword", "PDB-KSWORD", 0xFFFFF80100000000ULL);
    const NodeIdentity image = FileIdentity_("C:\\Windows\\System32\\drivers\\ksword.sys", 0xA1B2,
                                             "file-ksword");
    const NodeIdentity service = ServiceIdentity(kBoot, "KswordArk");

    graph.addNode(MakeNode(device, "\\Device\\Ksword0", "ev-device", NodeLifecycle::Observed));
    graph.addNode(MakeNode(driverObject, "\\Driver\\Ksword", "ev-driver", NodeLifecycle::Observed));
    graph.addNode(MakeNode(image, "ksword.sys", "ev-image", NodeLifecycle::Observed));
    graph.addNode(MakeNode(service, "KswordArk", "ev-service", NodeLifecycle::Observed));

    graph.addEdge(MakeEdge(EdgeKind::DeviceOf, device.nodeKey(), driverObject.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-device", "rule.deviceOf"));
    graph.addEdge(MakeEdge(EdgeKind::ImageOf, driverObject.nodeKey(), image.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-image", "rule.imageOf"));
    graph.addEdge(MakeEdge(EdgeKind::ServiceOf, image.nodeKey(), service.nodeKey(),
                           EdgeCertainty::Candidate, "ev-service", "rule.serviceOf"));

    graph.declareRelationCoverage(EdgeKind::DeviceOf, ObjectKind::Driver,
                                  FullySuccessfulCoverage(1, "ev-device"));
    graph.declareRelationCoverage(EdgeKind::ImageOf, ObjectKind::File,
                                  FullySuccessfulCoverage(1, "ev-image"));
    graph.declareRelationCoverage(EdgeKind::ServiceOf, ObjectKind::Service,
                                  FullySuccessfulCoverage(1, "ev-service"));

    ChainOptions options;
    const InvestigationChain chain =
        BuildChain(graph, ChainKind::DeviceToService, device.nodeKey(), options);
    s.expect(chain.steps.size() == 4U && chain.complete(),
             L"G-03 the device chain reaches the service in four steps");
    s.expect(chain.steps[1].relationFromPrevious == EdgeKind::DeviceOf &&
                 chain.steps[2].relationFromPrevious == EdgeKind::ImageOf &&
                 chain.steps[3].relationFromPrevious == EdgeKind::ServiceOf,
             L"G-03 each device-chain hop names its own relation kind rather than a generic link");
    s.expect(chain.steps[3].nodeIds.size() == 1U && chain.steps[3].nodeIds[0] == service.nodeKey(),
             L"G-03 the device chain ends on the service node id, usable by every other view");
    s.expect(chain.everyPresentStepOpensSource(),
             L"G-03 every device-chain step can open its source detail");

    // 中间一环被拒 -> 该环报 AccessDenied，下一环报"上一环缺失"。
    EntityGraph denied;
    denied.addNode(MakeNode(device, "\\Device\\Ksword0", "ev-device", NodeLifecycle::Observed));
    denied.addNode(MakeNode(driverObject, "\\Driver\\Ksword", "ev-driver", NodeLifecycle::Observed));
    denied.addEdge(MakeEdge(EdgeKind::DeviceOf, device.nodeKey(), driverObject.nodeKey(),
                            EdgeCertainty::Confirmed, "ev-device", "rule.deviceOf"));
    denied.declareRelationCoverage(EdgeKind::DeviceOf, ObjectKind::Driver,
                                   FullySuccessfulCoverage(1, "ev-device"));
    denied.declareRelationCoverage(EdgeKind::ImageOf, ObjectKind::File,
                                   FailedCoverage(CollectionStatus::AccessDenied, "NTSTATUS",
                                                  0xC0000022ULL, "STATUS_ACCESS_DENIED"));
    const InvestigationChain deniedChain =
        BuildChain(denied, ChainKind::DeviceToService, device.nodeKey(), options);
    s.expect(deniedChain.steps[2].availability == StepAvailability::MissingAccessDenied,
             L"G-03 an access-denied image lookup is reported as denied, not as no image");
    s.expect(deniedChain.steps[2].outcome.nativeCode == OptionalU64::of(0xC0000022ULL) &&
                 deniedChain.steps[2].outcome.nativeCodeDomain == "NTSTATUS",
             L"G-03 the denied step keeps the original NTSTATUS code and domain");
    s.expect(deniedChain.steps[3].availability == StepAvailability::MissingPreviousStepMissing,
             L"G-03 the service step reports that its predecessor is missing, not that services were absent");
    s.expect(deniedChain.missingStepCount() == 2U,
             L"G-03 the broken device chain reports exactly two missing links");

    // 不支持 / 超时 两个分支。
    EntityGraph unsupported;
    unsupported.addNode(MakeNode(device, "\\Device\\Ksword0", "ev-device", NodeLifecycle::Observed));
    unsupported.declareRelationCoverage(EdgeKind::DeviceOf, ObjectKind::Driver,
                                        FailedCoverage(CollectionStatus::Unsupported, "WIN32",
                                                       50ULL, "ERROR_NOT_SUPPORTED"));
    s.expect(BuildChain(unsupported, ChainKind::DeviceToService, device.nodeKey(), options)
                     .steps[1]
                     .availability == StepAvailability::MissingUnsupported,
             L"G-03 an unsupported capability is its own state, not a collection failure");
    EntityGraph timedOut;
    timedOut.addNode(MakeNode(device, "\\Device\\Ksword0", "ev-device", NodeLifecycle::Observed));
    timedOut.declareRelationCoverage(EdgeKind::DeviceOf, ObjectKind::Driver,
                                     FailedCoverage(CollectionStatus::Timeout, "WIN32", 1460ULL,
                                                    "ERROR_TIMEOUT"));
    const ChainStep timeoutStep =
        BuildChain(timedOut, ChainKind::DeviceToService, device.nodeKey(), options).steps[1];
    s.expect(timeoutStep.availability == StepAvailability::MissingCollectionFailed &&
                 timeoutStep.outcome.status == CollectionStatus::Timeout,
             L"G-03 a timeout is a collection failure whose original status stays readable");
}

void TestConnectionChain(KswordTests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity connection = ConnectionIdentity_(kBoot, 51000, 1000, 2000);
    const NodeIdentity process = ProcessIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity timeline = TimelineIdentity("tl-000042");

    graph.addNode(MakeNode(connection, "10.0.0.5:51000", "ev-conn", NodeLifecycle::Ended));
    graph.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    graph.addNode(MakeNode(timeline, "connect", "ev-timeline", NodeLifecycle::Observed));

    // 进程拥有连接：边的方向是 Process -> Connection。
    graph.addEdge(MakeEdge(EdgeKind::Owns, process.nodeKey(), connection.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-conn", "rule.socketOwner"));
    graph.addEdge(MakeEdge(EdgeKind::TimelineEntry, process.nodeKey(), timeline.nodeKey(),
                           EdgeCertainty::Candidate, "ev-timeline", "rule.timeline"));
    graph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process,
                                  FullySuccessfulCoverage(1, "ev-conn"));
    graph.declareRelationCoverage(EdgeKind::TimelineEntry, ObjectKind::Unknown,
                                  FullySuccessfulCoverage(1, "ev-timeline"));

    ChainOptions options;
    const InvestigationChain chain =
        BuildChain(graph, ChainKind::ConnectionToTimeline, connection.nodeKey(), options);
    s.expect(chain.steps.size() == 3U && chain.complete(),
             L"G-03 the connection chain reaches the timeline in three steps");
    s.expect(chain.steps[1].nodeIds.size() == 1U && chain.steps[1].nodeIds[0] == process.nodeKey(),
             L"G-03 the connection resolves to the owning process instance, not to a bare pid");
    s.expect(chain.steps[2].expectedCategory == NodeCategory::TimelineEntry &&
                 chain.steps[2].nodeIds.size() == 1U,
             L"G-03 the timeline step reaches a timeline record rather than a system object");

    // 反方向的边不许被当成同一跳。
    EntityGraph reversed;
    reversed.addNode(MakeNode(connection, "10.0.0.5:51000", "ev-conn", NodeLifecycle::Ended));
    reversed.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    reversed.addEdge(MakeEdge(EdgeKind::Owns, connection.nodeKey(), process.nodeKey(),
                              EdgeCertainty::Confirmed, "ev-conn", "rule.reversed"));
    reversed.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process,
                                     FullySuccessfulCoverage(1, "ev-conn"));
    s.expect(BuildChain(reversed, ChainKind::ConnectionToTimeline, connection.nodeKey(), options)
                     .steps[1]
                     .availability == StepAvailability::MissingNoData,
             L"G-03 an edge pointing the other way is not walked backwards to fake a hop");

    // 时间线来源不支持。
    EntityGraph noTimeline;
    noTimeline.addNode(MakeNode(connection, "10.0.0.5:51000", "ev-conn", NodeLifecycle::Ended));
    noTimeline.addNode(MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed));
    noTimeline.addEdge(MakeEdge(EdgeKind::Owns, process.nodeKey(), connection.nodeKey(),
                                EdgeCertainty::Confirmed, "ev-conn", "rule.socketOwner"));
    noTimeline.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process,
                                       FullySuccessfulCoverage(1, "ev-conn"));
    noTimeline.declareRelationCoverage(EdgeKind::TimelineEntry, ObjectKind::Unknown,
                                       FailedCoverage(CollectionStatus::Unsupported, "WIN32", 50ULL,
                                                      "ERROR_NOT_SUPPORTED"));
    const InvestigationChain partial =
        BuildChain(noTimeline, ChainKind::ConnectionToTimeline, connection.nodeKey(), options);
    s.expect(partial.steps[2].availability == StepAvailability::MissingUnsupported &&
                 partial.missingStepCount() == 1U && !partial.complete(),
             L"G-03 a missing timeline source leaves the chain explicitly incomplete");

    // 默认构造的链不许读作"完整"。
    InvestigationChain empty;
    s.expect(!empty.complete() && !empty.everyPresentStepOpensSource(),
             L"G-03 a default-constructed chain is never complete");
}

// ---------------------------------------------------------------------------
// G-04：有界展开
// ---------------------------------------------------------------------------
void TestBoundedExpansion(KswordTests::Suite& s) {
    // 手算目标：一个中心节点 + 12 个一跳邻居 + 12 个二跳节点。
    EntityGraph graph;
    const NodeIdentity root = ProcessIdentity(kBoot, 1000, 111, "root.exe");
    graph.addNode(MakeNode(root, "root.exe", "ev-root", NodeLifecycle::Observed));
    std::vector<std::string> firstHop;
    std::vector<std::string> secondHop;
    for (std::uint64_t i = 0; i < 12; ++i) {
        const NodeIdentity near = ThreadIdentity(kBoot, 1000, 111, 2000 + i, 300 + i);
        graph.addNode(MakeNode(near, "near", "ev-near", NodeLifecycle::Observed));
        firstHop.push_back(near.nodeKey());
        graph.addEdge(MakeEdge(EdgeKind::Owns, root.nodeKey(), near.nodeKey(),
                               EdgeCertainty::Confirmed, "ev-near", "rule.owns"));

        const NodeIdentity far = HandleIdentity_(kBoot, 1000, 111, 0x100 + i, "File");
        graph.addNode(MakeNode(far, "far", "ev-far", NodeLifecycle::Observed));
        secondHop.push_back(far.nodeKey());
        graph.addEdge(MakeEdge(EdgeKind::Opens, near.nodeKey(), far.nodeKey(),
                               EdgeCertainty::Candidate, "ev-far", "rule.opens"));
    }
    s.expect(graph.nodeCount() == 25U && graph.edgeCount() == 24U,
             L"G-04 the fixture holds 25 nodes and 24 edges as constructed");

    // 默认：只给目标 + 一跳。
    ExpansionRequest request;
    request.rootNodeIds.push_back(root.nodeKey());
    const ExpansionResult oneHop = ExpandGraph(graph, request);
    s.expect(oneHop.loadedNodes == 13U && oneHop.loadedEdges == 12U,
             L"G-04 the default expansion loads the target plus exactly one hop");
    s.expect(oneHop.moreAvailable && oneHop.hopLimitHit && !oneHop.nodeLimitHit,
             L"G-04 stopping at the hop budget is reported as a hop limit, not a node limit");
    s.expect(!oneHop.totalKnownNodes.present && !oneHop.totalKnownEdges.present,
             L"G-04 the total is unknown while more remains, and is not faked from the loaded count");
    s.expect(Contains(oneHop.limitationKeys, "graph.expand.totalUnknown") &&
                 Contains(oneHop.limitationKeys, "graph.expand.moreAvailable"),
             L"G-04 the result says out loud that more is available and the total is unknown");
    s.expect(oneHop.nodeIds.size() == 13U && oneHop.edgeIds.size() == 12U,
             L"G-04 the id lists match the loaded counts exactly");
    s.expect(!oneHop.coverage.fullyCovered(),
             L"G-04 a partial expansion never accounts itself as full coverage");

    // 越过默认上限但没显式请求继续 -> 夹回默认值。
    ExpansionRequest greedy = request;
    greedy.limits.maxNodes = 5000;
    greedy.limits.maxEdges = 9000;
    greedy.limits.maxHops = 6;
    const ExpansionResult clamped = ExpandGraph(graph, greedy);
    s.expect(clamped.limitsClampedToDefault && clamped.hopsClampedToDefault,
             L"G-04 raising the budget without asking to continue is clamped back to the default");
    s.expect(clamped.loadedNodes == 13U,
             L"G-04 the clamped expansion still only loads the target plus one hop");

    // 显式请求继续 -> 走满两跳。
    ExpansionRequest continued = greedy;
    continued.continueRequestedByUser = true;
    const ExpansionResult full = ExpandGraph(graph, continued);
    s.expect(!full.limitsClampedToDefault && !full.hopsClampedToDefault,
             L"G-04 an explicit continue is honoured");
    s.expect(full.loadedNodes == 25U && full.loadedEdges == 24U,
             L"G-04 continuing loads the whole reachable set, all 25 nodes and 24 edges");
    s.expect(!full.moreAvailable && full.totalKnownNodes == OptionalU64::of(25) &&
                 full.totalKnownEdges == OptionalU64::of(24),
             L"G-04 the total becomes known only once the traversal really finished");
    s.expect(full.coverage.fullyCovered(),
             L"G-04 a finished expansion accounts itself as full coverage");

    // 节点上限命中：与跳数上限区分开。
    ExpansionRequest capped = request;
    capped.limits.maxNodes = 5;
    const ExpansionResult small = ExpandGraph(graph, capped);
    s.expect(small.loadedNodes == 5U && small.nodeLimitHit && small.moreAvailable,
             L"G-04 the node budget stops the expansion at exactly five nodes");
    s.expect(!small.totalKnownNodes.present && small.coverage.limitHit &&
                 small.coverage.limit == OptionalU64::of(5),
             L"G-04 the account names the budget that actually stopped the scan");
    s.expect(small.coverage.describeRemaining().rfind("limit-hit:", 0) == 0U,
             L"G-04 the remaining description leads with the stop reason");

    // 边上限命中。
    ExpansionRequest edgeCapped = request;
    edgeCapped.limits.maxEdges = 4;
    const ExpansionResult fewEdges = ExpandGraph(graph, edgeCapped);
    s.expect(fewEdges.loadedEdges == 4U && fewEdges.edgeLimitHit && fewEdges.moreAvailable,
             L"G-04 the edge budget stops edge loading at exactly four edges");
    s.expect(fewEdges.loadedNodes == 5U,
             L"G-04 the edge budget also stops pulling in nodes whose edge cannot be shown");

    // 筛选与展开叠加：只要 Opens，一跳里一条都没有。
    ExpansionRequest filtered = request;
    filtered.filter.kinds.push_back(EdgeKind::Opens);
    const ExpansionResult opensOnly = ExpandGraph(graph, filtered);
    s.expect(opensOnly.loadedNodes == 1U && opensOnly.loadedEdges == 0U,
             L"G-04 filtering to a relation the root does not have leaves only the root");
    s.expect(opensOnly.filteredEdgeCount == 12U,
             L"G-04 the filtered-out edges are counted separately from coverage gaps");
    s.expect(opensOnly.coverage.skipped == 0U,
             L"G-04 a user filter is not recorded as a collection gap");
    // 新判据：走完可达集不等于走完全图。这次只装了 1 个节点，图里保存着 25 个，
    // 因此总量仍然是未知 —— 旧断言在这里写的是 totalKnownNodes == 1，那正是"拿
    // loadedNodes 冒充总量"，一次只走完一个连通分量的展开会照样声称总量已知。
    s.expect(!opensOnly.totalKnownNodes.present && !opensOnly.totalKnownEdges.present,
             L"G-04 a view that loaded 1 of the 25 saved nodes does not claim to know the total");
    s.expect(Contains(opensOnly.limitationKeys, "graph.expand.totalUnknown"),
             L"G-04 the filtered view says out loud that the total is unknown");
    s.expect(!opensOnly.coverage.fullyCovered() &&
                 opensOnly.coverage.totalKnown == OptionalU64::of(25),
             L"G-04 the account measures itself against the saved graph, not against its own load count");

    // 断开的连通分量：从 a 出发走不到 c/d，遍历"走到头"了但只看到了一半。
    // 手算：4 个节点 a,b,c,d，两条边 a-b、c-d；从 a 出发装 2 节点 1 边。
    EntityGraph split;
    const NodeIdentity splitA = ProcessIdentity(kBoot, 7001, 901, "a.exe");
    const NodeIdentity splitB = ThreadIdentity(kBoot, 7001, 901, 7101, 902);
    const NodeIdentity splitC = ProcessIdentity(kBoot, 7002, 903, "c.exe");
    const NodeIdentity splitD = ThreadIdentity(kBoot, 7002, 903, 7102, 904);
    split.addNode(MakeNode(splitA, "a.exe", "ev-a", NodeLifecycle::Observed));
    split.addNode(MakeNode(splitB, "tid 7101", "ev-b", NodeLifecycle::Observed));
    split.addNode(MakeNode(splitC, "c.exe", "ev-c", NodeLifecycle::Observed));
    split.addNode(MakeNode(splitD, "tid 7102", "ev-d", NodeLifecycle::Observed));
    split.addEdge(MakeEdge(EdgeKind::Owns, splitA.nodeKey(), splitB.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-b", "rule.owns"));
    split.addEdge(MakeEdge(EdgeKind::Owns, splitC.nodeKey(), splitD.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-d", "rule.owns"));
    ExpansionRequest oneComponent;
    oneComponent.rootNodeIds.push_back(splitA.nodeKey());
    const ExpansionResult component = ExpandGraph(split, oneComponent);
    s.expect(component.loadedNodes == 2U && component.loadedEdges == 1U &&
                 !component.moreAvailable && component.unsavedNeighbors.empty(),
             L"G-04 walking one connected component finishes without anything left to fetch");
    s.expect(!component.totalKnownNodes.present && !component.totalKnownEdges.present,
             L"G-04 finishing one component of a split graph still leaves the total unknown");
    s.expect(!component.coverage.fullyCovered(),
             L"G-04 seeing half the saved nodes is never accounted as full coverage");
    s.expect(Contains(component.limitationKeys, "graph.expand.totalUnknown"),
             L"G-04 the split-graph view names the unknown total in its limitations");
    s.expect(SummarizeGraph(split, EdgeFilter{}).nodeCount == 4U,
             L"G-04 the whole saved graph really holds twice what that view could see");

    // 反复展开/折叠：同一请求重复执行结果稳定。
    const ExpansionResult again = ExpandGraph(graph, request);
    s.expect(again.nodeIds == oneHop.nodeIds && again.edgeIds == oneHop.edgeIds &&
                 again.loadedNodes == oneHop.loadedNodes,
             L"G-04 expanding, collapsing and expanding again yields the identical view");

    // 空请求不许被读成"全都覆盖到了"。
    ExpansionRequest empty;
    const ExpansionResult nothing = ExpandGraph(graph, empty);
    s.expect(nothing.loadedNodes == 0U && !nothing.totalKnownNodes.present &&
                 Contains(nothing.limitationKeys, "graph.expand.noRoots"),
             L"G-04 an expansion with no roots reports no roots instead of a complete empty view");

    // 被预算挡下的边必须进账目。手算：root + 3 个邻居、3 条边，maxEdges=1 ->
    // 装 1 条、延迟 2 条，truncated 恰好是 2。
    EntityGraph deferGraph;
    const NodeIdentity deferRoot = ProcessIdentity(kBoot, 8000, 950, "defer.exe");
    deferGraph.addNode(MakeNode(deferRoot, "defer.exe", "ev-defer", NodeLifecycle::Observed));
    for (std::uint64_t i = 0; i < 3; ++i) {
        const NodeIdentity leaf = ThreadIdentity(kBoot, 8000, 950, 8100 + i, 960 + i);
        deferGraph.addNode(MakeNode(leaf, "t", "ev-leaf", NodeLifecycle::Observed));
        deferGraph.addEdge(MakeEdge(EdgeKind::Owns, deferRoot.nodeKey(), leaf.nodeKey(),
                                    EdgeCertainty::Confirmed, "ev-leaf", "rule.owns"));
    }
    ExpansionRequest oneEdgeOnly;
    oneEdgeOnly.rootNodeIds.push_back(deferRoot.nodeKey());
    oneEdgeOnly.limits.maxEdges = 1;
    const ExpansionResult deferred = ExpandGraph(deferGraph, oneEdgeOnly);
    s.expect(deferred.loadedEdges == 1U && deferred.loadedNodes == 2U && deferred.edgeLimitHit,
             L"G-04 the one-edge budget loads exactly one edge and the node it brings in");
    s.expect(deferred.coverage.truncated == 2U,
             L"G-04 the two edges left behind by the budget are counted as truncated, not forgotten");
    s.expect(deferred.coverage.limitHit && deferred.coverage.limit == OptionalU64::of(1),
             L"G-04 the account names the edge budget that stopped the scan");

    // 根节点本身就超过节点预算：多出来的根不许被静默丢掉。手算：3 个孤立节点、
    // maxNodes=2 -> 装 2 个，命中节点上限，还有更多。
    EntityGraph rootsGraph;
    std::vector<std::string> rootKeys;
    for (std::uint64_t i = 0; i < 3; ++i) {
        const NodeIdentity lone = ProcessIdentity(kBoot, 9000 + i, 970 + i, "lone.exe");
        rootsGraph.addNode(MakeNode(lone, "lone.exe", "ev-lone", NodeLifecycle::Observed));
        rootKeys.push_back(lone.nodeKey());
    }
    std::sort(rootKeys.begin(), rootKeys.end());
    ExpansionRequest tooManyRoots;
    tooManyRoots.rootNodeIds = rootKeys;
    tooManyRoots.limits.maxNodes = 2;
    const ExpansionResult droppedRoot = ExpandGraph(rootsGraph, tooManyRoots);
    s.expect(droppedRoot.loadedNodes == 2U,
             L"G-04 a node budget smaller than the root list loads exactly the budget");
    s.expect(droppedRoot.nodeLimitHit && droppedRoot.moreAvailable,
             L"G-04 a root that did not fit in the budget is reported, never silently dropped");
    s.expect(!droppedRoot.totalKnownNodes.present &&
                 Contains(droppedRoot.limitationKeys, "graph.expand.nodeLimitHit"),
             L"G-04 dropping a root keeps the total unknown and names the budget in the limitations");

    // 截断时"保留哪一部分"必须与根的输入顺序无关：展开前要先把根规范化。
    ExpansionRequest reversedRoots = tooManyRoots;
    reversedRoots.rootNodeIds.assign(rootKeys.rbegin(), rootKeys.rend());
    reversedRoots.rootNodeIds.push_back(rootKeys.front());  // 重复的根不许多占一个名额
    const ExpansionResult droppedReversed = ExpandGraph(rootsGraph, reversedRoots);
    s.expect(droppedReversed.nodeIds == droppedRoot.nodeIds &&
                 droppedReversed.loadedNodes == 2U,
             L"G-04 handing the same roots in the opposite order truncates to the same two nodes");
}

// ---------------------------------------------------------------------------
// G-04：10,000 节点 / 50,000 边的性能
// ---------------------------------------------------------------------------
void TestLargeDatasetPerformance(KswordTests::Suite& s) {
    // 固定结构：环 + 弦。节点 i 指向 (i + o) mod N，o 取五个固定偏移。
    // 因此边数恰好 N * 5 = 50,000，每个节点的度恰好 10（五出五入）。
    // 五个偏移及其相反数在 mod 10000 下互不相同，且任意两个邻居之差都不是偏移，
    // 所以一跳邻域恰好是 1 + 10 = 11 个节点、10 条边。这些数字是纸上算出来的。
    constexpr std::size_t kNodes = 10000;
    const std::uint64_t offsets[5] = {1, 7, 113, 1237, 4999};

    const auto buildStart = std::chrono::steady_clock::now();
    EntityGraph graph;
    std::vector<std::string> ids;
    ids.reserve(kNodes);
    for (std::size_t i = 0; i < kNodes; ++i) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "node-%06zu", i);
        GraphNode node;
        node.nodeId = buffer;  // G-06：会话回放时 id 由已保存数据给出
        node.identity.kind = ObjectKind::Process;
        node.identity.instanceTag = buffer;
        node.displayText = buffer;
        node.evidenceId = "ev-bulk";
        node.lifecycle = NodeLifecycle::Observed;
        node.outcome = CollectionOutcome::success();
        graph.addNode(std::move(node));
        ids.emplace_back(buffer);
    }
    for (std::size_t i = 0; i < kNodes; ++i) {
        for (std::size_t k = 0; k < 5; ++k) {
            const std::size_t target = (i + static_cast<std::size_t>(offsets[k])) % kNodes;
            GraphEdge edge;
            edge.kind = (k % 2 == 0) ? EdgeKind::Owns : EdgeKind::Loads;
            edge.direction = EdgeDirection::FromTo;
            edge.fromNodeId = ids[i];
            edge.toNodeId = ids[target];
            edge.certainty = EdgeCertainty::Candidate;
            edge.evidenceRefs.emplace_back("ev-bulk");
            edge.ruleId = "rule.bulk";
            graph.addEdge(edge);
        }
    }
    const auto buildEnd = std::chrono::steady_clock::now();
    s.expect(graph.nodeCount() == 10000U && graph.edgeCount() == 50000U,
             L"G-04 the performance dataset really holds 10,000 nodes and 50,000 edges");

    // 一跳展开：手算 11 个节点、10 条边。
    ExpansionRequest oneHop;
    oneHop.rootNodeIds.push_back(ids[0]);
    const ExpansionResult firstView = ExpandGraph(graph, oneHop);
    s.expect(firstView.loadedNodes == 11U && firstView.loadedEdges == 10U,
             L"G-04 one hop out of the ring-and-chord dataset is exactly 11 nodes and 10 edges");
    s.expect(firstView.moreAvailable && !firstView.totalKnownNodes.present,
             L"G-04 the one-hop view of the large dataset does not claim to know the total");

    // 反复展开 / 折叠 / 筛选。折叠 = 丢掉上一份结果重新展开。
    // 每一次展开单独计时：规范 §7 L4 给关系视图的预算是 p95 ≤ 200 ms，那是**单次**
    // 首屏展开的预算，总时长除以轮数只能看出平均值，看不出尾延迟。
    std::vector<long long> ringRoundsUs;
    ringRoundsUs.reserve(400);
    const auto loopStart = std::chrono::steady_clock::now();
    std::uint64_t nodeChecksum = 0;
    for (std::size_t round = 0; round < 200; ++round) {
        ExpansionRequest request;
        request.rootNodeIds.push_back(ids[(round * 37U) % kNodes]);
        const auto viewStart = std::chrono::steady_clock::now();
        const ExpansionResult view = ExpandGraph(graph, request);
        ringRoundsUs.push_back(MicrosSince(viewStart));
        nodeChecksum += view.loadedNodes;

        ExpansionRequest filtered = request;
        filtered.filter.kinds.push_back(EdgeKind::Owns);
        const auto filteredStart = std::chrono::steady_clock::now();
        const ExpansionResult ownsView = ExpandGraph(graph, filtered);
        ringRoundsUs.push_back(MicrosSince(filteredStart));
        nodeChecksum += ownsView.loadedNodes;
    }
    const auto loopEnd = std::chrono::steady_clock::now();
    // 每轮 11 + 7 = 18：Owns 只保留偏移 {1, 113, 4999} 三族，出入各三条 -> 6 个邻居。
    s.expect(nodeChecksum == 200U * 18U,
             L"G-04 every expand/collapse/filter round returns the hand-computed node count");

    // 全图展开：需要显式请求继续。
    const auto fullStart = std::chrono::steady_clock::now();
    ExpansionRequest whole;
    whole.rootNodeIds.push_back(ids[0]);
    whole.continueRequestedByUser = true;
    whole.limits.maxNodes = 20000;
    whole.limits.maxEdges = 100000;
    whole.limits.maxHops = 64;
    ExpansionResult wholeView;
    for (std::size_t round = 0; round < 10; ++round) {
        wholeView = ExpandGraph(graph, whole);
    }
    const auto fullEnd = std::chrono::steady_clock::now();
    s.expect(wholeView.loadedNodes == 10000U && wholeView.loadedEdges == 50000U,
             L"G-04 a fully continued expansion reaches every node and every edge exactly once");
    s.expect(!wholeView.moreAvailable && wholeView.totalKnownNodes == OptionalU64::of(10000),
             L"G-04 the total is known only after the whole dataset was really walked");

    // 全图结论与导出。
    const auto summaryStart = std::chrono::steady_clock::now();
    EdgeFilter noFilter;
    const GraphConclusion conclusion = SummarizeGraph(graph, noFilter);
    const auto summaryEnd = std::chrono::steady_clock::now();
    s.expect(conclusion.nodeCount == 10000U && conclusion.edgeCountAfterFilter == 50000U &&
                 conclusion.isolatedNodeCount == 0U,
             L"G-04 summarising the large dataset counts every node and edge and finds no isolates");

    // 第二种拓扑：星形。同样 10,000 节点，但 49,995 条边全部挂在一个 hub 上。
    // 环+弦数据集每个点的度恒为 10，是最好的情况；一个真实的会话里"一个进程拥有
    // 上万个句柄"就是这个形状。只测环形，任何与单点度数成正比的退化都测不出来。
    const auto hubBuildStart = std::chrono::steady_clock::now();
    EntityGraph hub;
    std::vector<std::string> hubIds;
    hubIds.reserve(kNodes);
    for (std::size_t i = 0; i < kNodes; ++i) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "hub-%06zu", i);
        GraphNode node;
        node.nodeId = buffer;
        node.identity.kind = ObjectKind::Process;
        node.identity.instanceTag = buffer;
        node.displayText = buffer;
        node.evidenceId = "ev-hub";
        node.lifecycle = NodeLifecycle::Observed;
        node.outcome = CollectionOutcome::success();
        hub.addNode(std::move(node));
        hubIds.emplace_back(buffer);
    }
    for (std::size_t i = 1; i < kNodes; ++i) {
        for (std::size_t k = 0; k < 5; ++k) {
            char rule[24];
            std::snprintf(rule, sizeof(rule), "rule.hub.%zu", k);
            GraphEdge edge;
            edge.kind = EdgeKind::Owns;
            edge.direction = EdgeDirection::FromTo;
            edge.fromNodeId = hubIds[0];
            edge.toNodeId = hubIds[i];
            edge.certainty = EdgeCertainty::Candidate;
            edge.evidenceRefs.emplace_back("ev-hub");
            edge.ruleId = rule;
            hub.addEdge(edge);
        }
    }
    const auto hubBuildEnd = std::chrono::steady_clock::now();
    s.expect(hub.nodeCount() == 10000U && hub.edgeCount() == 49995U,
             L"G-04 the hub dataset really holds 10,000 nodes and 49,995 edges on one node");

    // 手算：默认预算 200 节点 / 500 边，hub 的每个邻居带 5 条边，因此边预算先满 ——
    // 500 / 5 = 100 个邻居 + hub 自己 = 101 个节点、500 条边，命中的是边上限不是
    // 节点上限。这两个数字来自预算本身，不是跑一遍抄回来的。
    std::vector<long long> hubRoundsUs;
    hubRoundsUs.reserve(100);
    ExpansionResult hubView;
    for (std::size_t round = 0; round < 100; ++round) {
        ExpansionRequest request;
        request.rootNodeIds.push_back(hubIds[0]);
        const auto roundStart = std::chrono::steady_clock::now();
        hubView = ExpandGraph(hub, request);
        hubRoundsUs.push_back(MicrosSince(roundStart));
    }
    s.expect(hubView.loadedNodes == 101U && hubView.loadedEdges == 500U,
             L"G-04 one hop out of the hub is exactly 101 nodes and 500 edges under the default budget");
    s.expect(hubView.edgeLimitHit && !hubView.nodeLimitHit && hubView.moreAvailable,
             L"G-04 the hub view is stopped by the edge budget and says so");
    s.expect(!hubView.totalKnownNodes.present,
             L"G-04 a budget-stopped hub view never claims to know the total");

    const auto ms = [](std::chrono::steady_clock::time_point a,
                       std::chrono::steady_clock::time_point b) {
        return static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count());
    };
    const auto p95Us = [](std::vector<long long> samples) {
        if (samples.empty()) {
            return static_cast<long long>(-1);  // 没有样本不是"很快"
        }
        std::sort(samples.begin(), samples.end());
        std::size_t index = (samples.size() * 95U) / 100U;
        if (index >= samples.size()) {
            index = samples.size() - 1;
        }
        return samples[index];
    };
    const long long buildMs = ms(buildStart, buildEnd);
    const long long loopMs = ms(loopStart, loopEnd);
    const long long fullMs = ms(fullStart, fullEnd);
    const long long summaryMs = ms(summaryStart, summaryEnd);
    const long long hubBuildMs = ms(hubBuildStart, hubBuildEnd);
    const long long ringP95Us = p95Us(ringRoundsUs);
    const long long hubP95Us = p95Us(hubRoundsUs);
    std::wprintf(L"    [G-04 perf] build ring=%lldms hub=%lldms  400 ring rounds=%lldms "
                 L"(p95=%lldus)  100 hub rounds p95=%lldus  10 full walks=%lldms  "
                 L"summarize=%lldms\n",
                 buildMs, hubBuildMs, loopMs, ringP95Us, hubP95Us, fullMs, summaryMs);

    // 规范 §7 L4：关系视图 p95 ≤ 200 ms。阈值就贴着预算写，不写成 15 秒 —— 15 秒的
    // 阈值比预算宽 75 倍，75 倍以内的复杂度退化一条都抓不到。
    constexpr long long kViewBudgetUs = 200000;
    s.expect(ringP95Us >= 0 && ringP95Us < kViewBudgetUs,
             L"G-04 the p95 of a single bounded expansion on the ring dataset is inside the 200 ms view budget");
    s.expect(hubP95Us >= 0 && hubP95Us < kViewBudgetUs,
             L"G-04 the p95 of a single bounded expansion on the hub dataset is inside the 200 ms view budget");
    // 下面三项不是首屏视图：建图与"用户显式请求走完全图"都不受 L4 的 200 ms 约束，
    // 但仍然必须是线性量级 —— O(V*E) 会把它们推到几十秒。
    s.expect(buildMs < 2000, L"G-04 building the ring dataset stays linear, not quadratic");
    s.expect(hubBuildMs < 2000, L"G-04 building the hub dataset stays linear, not quadratic");
    s.expect(loopMs < 2000, L"G-04 400 bounded expansions together stay well inside a second-scale budget");
    s.expect(fullMs < 2000, L"G-04 ten user-requested full traversals stay linear in nodes and edges");
    s.expect(summaryMs < 1000, L"G-04 summarising the whole dataset stays linear in nodes and edges");
}

// ---------------------------------------------------------------------------
// G-05：孤立与未知不等于异常
// ---------------------------------------------------------------------------
void TestIsolationStates(KswordTests::Suite& s) {
    EntityGraph graph;
    EdgeFilter noFilter;

    // 默认构造的报告不许读作"正常"。
    IsolationReport defaulted;
    s.expect(defaulted.state == IsolationState::SourceNotCollected && !defaulted.isolated &&
                 !defaulted.nodeFound,
             L"G-05 a default isolation report is not a clean bill of health");

    // 1) 缺 owner：来源采全了、对象还在，就是没有归属边。
    NodeIdentity ownerless = ProcessIdentity(kBoot, 2000, 500, "orphan.exe");
    GraphNode ownerlessNode = MakeNode(ownerless, "orphan.exe", "ev-orphan", NodeLifecycle::Observed);
    ownerlessNode.ownerRelation = EdgeKind::Owns;
    ownerlessNode.ownerKind = ObjectKind::Process;
    graph.addNode(ownerlessNode);
    graph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process,
                                  FullySuccessfulCoverage(4, "ev-parents"));

    // 2) 对象已卸载。
    NodeIdentity unloaded = DriverIdentity("C:\\Windows\\System32\\drivers\\gone.sys", "PDB-GONE",
                                           0xFFFFF80200000000ULL);
    GraphNode unloadedNode = MakeNode(unloaded, "gone.sys", "ev-gone", NodeLifecycle::Ended);
    unloadedNode.ownerRelation = EdgeKind::Owns;
    unloadedNode.ownerKind = ObjectKind::Process;
    graph.addNode(unloadedNode);

    // 3) 来源未采集。
    NodeIdentity uncollected = HandleIdentity_(kBoot, 2000, 500, 0x44, "Key");
    GraphNode uncollectedNode = MakeNode(uncollected, "handle 0x44", "ev-handle",
                                         NodeLifecycle::Observed);
    uncollectedNode.ownerRelation = EdgeKind::Opens;
    uncollectedNode.ownerKind = ObjectKind::File;  // 从未声明过覆盖
    graph.addNode(uncollectedNode);

    // 4) 实际不一致。
    NodeIdentity conflicting = ProcessIdentity(kBoot, 3000, 600, "conflict.exe");
    GraphNode conflictingNode = MakeNode(conflicting, "conflict.exe", "ev-conflict",
                                         NodeLifecycle::Observed);
    conflictingNode.ownerRelation = EdgeKind::Owns;
    conflictingNode.ownerKind = ObjectKind::Process;
    conflictingNode.inconsistencyObserved = true;
    conflictingNode.inconsistencyEvidenceIds.emplace_back("ev-crossview-7");
    graph.addNode(conflictingNode);

    // 5) 有边的节点：不孤立。
    NodeIdentity connectedA = ProcessIdentity(kBoot, 4000, 700, "a.exe");
    NodeIdentity connectedB = ThreadIdentity(kBoot, 4000, 700, 4100, 701);
    graph.addNode(MakeNode(connectedA, "a.exe", "ev-a", NodeLifecycle::Observed));
    graph.addNode(MakeNode(connectedB, "tid 4100", "ev-b", NodeLifecycle::Observed));
    graph.addEdge(MakeEdge(EdgeKind::Owns, connectedA.nodeKey(), connectedB.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-b", "rule.owns"));

    // 6) owner 来源被拒：绝不能因为"没看到 owner 边"就说成"确实没有 owner"。
    NodeIdentity denied = ProcessIdentity(kBoot, 5000, 800, "denied.exe");
    GraphNode deniedNode = MakeNode(denied, "denied.exe", "ev-denied", NodeLifecycle::Observed);
    deniedNode.ownerRelation = EdgeKind::Loads;
    deniedNode.ownerKind = ObjectKind::Module;
    graph.addNode(deniedNode);
    graph.declareRelationCoverage(EdgeKind::Loads, ObjectKind::Module,
                                  FailedCoverage(CollectionStatus::AccessDenied, "NTSTATUS",
                                                 0xC0000022ULL, "STATUS_ACCESS_DENIED"));

    // 7) owner 来源只覆盖了一部分：同样不足以判"确实没有 owner"。
    NodeIdentity halfSeen = ProcessIdentity(kBoot, 6000, 900, "partial.exe");
    GraphNode halfSeenNode = MakeNode(halfSeen, "partial.exe", "ev-partial", NodeLifecycle::Observed);
    halfSeenNode.ownerRelation = EdgeKind::Maps;
    halfSeenNode.ownerKind = ObjectKind::File;
    graph.addNode(halfSeenNode);
    RelationCoverage halfCoverage = FullySuccessfulCoverage(9, "ev-maps");
    halfCoverage.outcome.status = CollectionStatus::Partial;
    halfCoverage.coverage.succeeded = 3;
    graph.declareRelationCoverage(EdgeKind::Maps, ObjectKind::File, halfCoverage);

    const IsolationReport deniedReport = ClassifyIsolation(graph, denied.nodeKey(), noFilter);
    s.expect(deniedReport.isolated && deniedReport.state == IsolationState::SourceNotCollected,
             L"G-05 a denied owner lookup is never reported as a genuinely missing owner");
    s.expect(deniedReport.ownerLookupOutcome.status == CollectionStatus::AccessDenied &&
                 deniedReport.ownerLookupOutcome.nativeCode == OptionalU64::of(0xC0000022ULL),
             L"G-05 the denied owner lookup keeps its original NTSTATUS instead of collapsing");
    const IsolationReport partialReport = ClassifyIsolation(graph, halfSeen.nodeKey(), noFilter);
    s.expect(partialReport.isolated && partialReport.state == IsolationState::SourceNotCollected,
             L"G-05 a partially covered owner lookup is never reported as a missing owner");
    s.expect(partialReport.ownerLookupOutcome.status == CollectionStatus::Partial,
             L"G-05 the partially covered owner lookup keeps its partial status");

    const IsolationReport ownerMissing = ClassifyIsolation(graph, ownerless.nodeKey(), noFilter);
    s.expect(ownerMissing.isolated && ownerMissing.state == IsolationState::OwnerMissing,
             L"G-05 a live object whose owner source was fully collected is owner-missing");
    s.expect(ownerMissing.rawEvidenceAvailable && ownerMissing.evidenceId == "ev-orphan",
             L"G-05 an isolated node still points at its own raw evidence");
    s.expect(ownerMissing.explanationKey == "graph.isolation.ownerMissing",
             L"G-05 the owner-missing state carries its own explanation key");

    const IsolationReport unloadedReport = ClassifyIsolation(graph, unloaded.nodeKey(), noFilter);
    s.expect(unloadedReport.isolated && unloadedReport.state == IsolationState::ObjectUnloaded,
             L"G-05 an unloaded object having no current relation is its own state");

    const IsolationReport uncollectedReport =
        ClassifyIsolation(graph, uncollected.nodeKey(), noFilter);
    s.expect(uncollectedReport.isolated &&
                 uncollectedReport.state == IsolationState::SourceNotCollected,
             L"G-05 a node whose owner source was never collected is not owner-missing");
    s.expect(uncollectedReport.ownerLookupOutcome.status == CollectionStatus::NotCollected,
             L"G-05 the not-collected state keeps the original collection status");

    const IsolationReport conflictReport = ClassifyIsolation(graph, conflicting.nodeKey(), noFilter);
    s.expect(conflictReport.isolated &&
                 conflictReport.state == IsolationState::ObservedInconsistency,
             L"G-05 an observed inconsistency is reported as such and not as a missing owner");
    s.expect(conflictReport.inconsistencyEvidenceIds.size() == 1U &&
                 conflictReport.inconsistencyEvidenceIds[0] == "ev-crossview-7",
             L"G-05 the inconsistency state carries the evidence that recorded it");

    const IsolationReport connectedReport = ClassifyIsolation(graph, connectedA.nodeKey(), noFilter);
    s.expect(!connectedReport.isolated && connectedReport.state == IsolationState::NotIsolated &&
                 connectedReport.edgeCountAfterFilter == 1U,
             L"G-05 a node with an edge is not isolated");

    // 未保存的节点。
    const IsolationReport unknownNode = ClassifyIsolation(graph, "no-such-node", noFilter);
    s.expect(!unknownNode.nodeFound && unknownNode.state == IsolationState::SourceNotCollected,
             L"G-05 asking about a node that was never saved does not produce a clean verdict");

    // 筛选造成的孤立不许被读成来源缺失以外的东西：把边筛掉后仍能解释原因。
    EdgeFilter opensOnly;
    opensOnly.kinds.push_back(EdgeKind::Opens);
    const IsolationReport filteredOut = ClassifyIsolation(graph, connectedA.nodeKey(), opensOnly);
    s.expect(filteredOut.isolated && filteredOut.edgeCountBeforeFilter == 1U &&
                 filteredOut.edgeCountAfterFilter == 0U,
             L"G-05 a node hidden by the current filter reports both edge counts");
    s.expect(filteredOut.rawEvidenceAvailable,
             L"G-05 a node isolated only by the filter can still open its raw evidence");

    // 全图统计：四类各一个，且没有任何"无边即异常"的结论。
    const GraphConclusion conclusion = SummarizeGraph(graph, noFilter);
    s.expect(conclusion.isolatedNodeCount == 6U && conclusion.ownerMissingCount == 1U &&
                 conclusion.unloadedCount == 1U && conclusion.sourceNotCollectedCount == 3U &&
                 conclusion.inconsistencyCount == 1U,
             L"G-05 the four isolation states are counted separately with the right node in each");
    s.expect(conclusion.conclusion == AnalysisConclusion::NoEvidence,
             L"G-05 with no session envelope the conclusion is no-evidence, never a clean result");

    // 成功但账目一字未填 -> 仍然不是"确实没有 owner"。这一条是 G-05 的正面缺席判据：
    // 只有 Success **加上**账目给出的正面覆盖证据才够。
    EntityGraph blankAccount;
    const NodeIdentity accounted = ProcessIdentity(kBoot, 7800, 1200, "accounted.exe");
    GraphNode accountedNode = MakeNode(accounted, "accounted.exe", "ev-accounted",
                                       NodeLifecycle::Observed);
    accountedNode.ownerRelation = EdgeKind::Owns;
    accountedNode.ownerKind = ObjectKind::Process;
    blankAccount.addNode(accountedNode);
    RelationCoverage blankCoverage;
    blankCoverage.outcome = CollectionOutcome::success();  // 账目一字未填
    blankAccount.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process, blankCoverage);
    const IsolationReport blankReport =
        ClassifyIsolation(blankAccount, accounted.nodeKey(), noFilter);
    s.expect(blankReport.isolated && blankReport.state == IsolationState::SourceNotCollected,
             L"G-05 a successful owner lookup with an empty account is not proof that there is no owner");
    s.expect(blankReport.ownerLookupOutcome.status == CollectionStatus::Success,
             L"G-05 that verdict keeps the original successful status instead of rewriting it");

    // ownerRelation 没填 = "来源未采集"，而且不许被一条与它无关的覆盖声明改判。
    EntityGraph unlabelledGraph;
    const NodeIdentity unlabelled = ProcessIdentity(kBoot, 7700, 1100, "unlabelled.exe");
    unlabelledGraph.addNode(MakeNode(unlabelled, "unlabelled.exe", "ev-unlabelled",
                                     NodeLifecycle::Observed));  // ownerRelation 保持 Unknown
    const NodeIdentity labelled = ProcessIdentity(kBoot, 7701, 1101, "labelled.exe");
    GraphNode labelledNode = MakeNode(labelled, "labelled.exe", "ev-labelled",
                                      NodeLifecycle::Observed);
    labelledNode.ownerRelation = EdgeKind::Owns;
    labelledNode.ownerKind = ObjectKind::Process;
    unlabelledGraph.addNode(labelledNode);
    unlabelledGraph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process,
                                            FullySuccessfulCoverage(2, "ev-parents"));
    const IsolationReport unlabelledBefore =
        ClassifyIsolation(unlabelledGraph, unlabelled.nodeKey(), noFilter);
    s.expect(unlabelledBefore.isolated &&
                 unlabelledBefore.state == IsolationState::SourceNotCollected &&
                 unlabelledBefore.explanationKey == "graph.isolation.ownerRelationNotDeclared",
             L"G-05 a node that never named its owner relation is treated as not collected, with its own explanation");
    s.expect(unlabelledBefore.ownerLookupOutcome.status == CollectionStatus::NotCollected,
             L"G-05 an unnamed owner relation has no collection outcome to report");
    RelationCoverage blanket = FullySuccessfulCoverage(1, "ev-anything");
    s.expect(!unlabelledGraph.declareRelationCoverage(EdgeKind::Unknown, ObjectKind::Unknown,
                                                      blanket),
             L"G-05 an unnamed relation cannot be declared covered at all");
    const IsolationReport unlabelledAfter =
        ClassifyIsolation(unlabelledGraph, unlabelled.nodeKey(), noFilter);
    s.expect(unlabelledAfter.state == IsolationState::SourceNotCollected &&
                 unlabelledAfter.explanationKey == "graph.isolation.ownerRelationNotDeclared",
             L"G-05 declaring coverage for an unnamed relation never flips a node into owner-missing");
    s.expect(ClassifyIsolation(unlabelledGraph, labelled.nodeKey(), noFilter).state ==
                 IsolationState::OwnerMissing,
             L"G-05 the node that did name its owner relation still reads its own declared coverage");

    // 有观测但没有不一致 -> NoDifferenceObserved；有不一致 -> DifferenceObserved。
    EntityGraph observed;
    EvidenceEnvelope envelope;
    envelope.outcome = CollectionOutcome::success();
    envelope.coverage.totalKnown = OptionalU64::of(1);
    envelope.coverage.succeeded = 1;
    observed.setEnvelope(envelope);
    observed.addNode(MakeNode(connectedA, "a.exe", "ev-a", NodeLifecycle::Observed));
    observed.addNode(MakeNode(connectedB, "tid 4100", "ev-b", NodeLifecycle::Observed));
    observed.addEdge(MakeEdge(EdgeKind::Owns, connectedA.nodeKey(), connectedB.nodeKey(),
                              EdgeCertainty::Confirmed, "ev-b", "rule.owns"));
    s.expect(SummarizeGraph(observed, noFilter).conclusion ==
                 AnalysisConclusion::NoDifferenceObserved,
             L"G-05 a fully collected graph without conflicts observes no difference");
    EntityGraph observedConflict = observed;
    GraphNode conflictCopy = conflictingNode;
    observedConflict.addNode(conflictCopy);
    s.expect(SummarizeGraph(observedConflict, noFilter).conclusion ==
                 AnalysisConclusion::DifferenceObserved,
             L"G-05 only a recorded inconsistency drives the difference conclusion, not isolation");
}

// ---------------------------------------------------------------------------
// G-05：孤立不是差异，缺口计数器要有非零用例
// ---------------------------------------------------------------------------
EvidenceEnvelope FullyObservedEnvelope() {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = "r0.graph";
    envelope.source.sourceGroup = "r0.graph";
    envelope.source.origin = SourceOrigin::OfflineSample;
    envelope.outcome = CollectionOutcome::success();
    envelope.coverage.totalKnown = OptionalU64::of(3);
    envelope.coverage.succeeded = 3;
    envelope.evidenceId = "ev-session";
    return envelope;
}

void TestIsolationDoesNotDriveConclusion(KswordTests::Suite& s) {
    // 这是 G-05"不存在'无边就恶意'的规则"的**正面**用例：观测齐全、图里全是孤立
    // 节点、一条记录在案的不一致都没有 —— 结论必须是"未发现差异"。少了这一条，
    // 把"有孤立节点"直接升格成 DifferenceObserved 的改动一条断言都碰不到。
    EdgeFilter noFilter;
    EntityGraph graph;
    graph.setEnvelope(FullyObservedEnvelope());
    graph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process,
                                  FullySuccessfulCoverage(3, "ev-parents"));

    const NodeIdentity orphan = ProcessIdentity(kBoot, 1100, 210, "orphan.exe");
    GraphNode orphanNode = MakeNode(orphan, "orphan.exe", "ev-orphan", NodeLifecycle::Observed);
    orphanNode.ownerRelation = EdgeKind::Owns;
    orphanNode.ownerKind = ObjectKind::Process;
    graph.addNode(orphanNode);

    const NodeIdentity ungathered = ProcessIdentity(kBoot, 1200, 220, "ungathered.exe");
    GraphNode ungatheredNode = MakeNode(ungathered, "ungathered.exe", "ev-ungathered",
                                        NodeLifecycle::Observed);
    ungatheredNode.ownerRelation = EdgeKind::Loads;   // 从未声明过覆盖
    ungatheredNode.ownerKind = ObjectKind::Module;
    graph.addNode(ungatheredNode);

    const NodeIdentity gone = DriverIdentity("C:\\Windows\\System32\\drivers\\gone2.sys",
                                             "PDB-GONE2", 0xFFFFF80300000000ULL);
    GraphNode goneNode = MakeNode(gone, "gone2.sys", "ev-gone2", NodeLifecycle::Ended);
    goneNode.ownerRelation = EdgeKind::Owns;
    goneNode.ownerKind = ObjectKind::Process;
    graph.addNode(goneNode);

    const GraphConclusion conclusion = SummarizeGraph(graph, noFilter);
    s.expect(conclusion.nodeCount == 3U && conclusion.edgeCountBeforeFilter == 0U,
             L"G-05 the fixture is three nodes with no edge at all between them");
    s.expect(conclusion.isolatedNodeCount == 3U && conclusion.ownerMissingCount == 1U &&
                 conclusion.sourceNotCollectedCount == 1U && conclusion.unloadedCount == 1U,
             L"G-05 all three nodes are isolated and land in three different states");
    s.expect(conclusion.inconsistencyCount == 0U,
             L"G-05 not one of them is a recorded inconsistency");
    s.expect(conclusion.conclusion == AnalysisConclusion::NoDifferenceObserved,
             L"G-05 a fully observed graph made entirely of isolated nodes still observes no difference");

    // 再加一个孤立节点：计数变，结论不变。
    const NodeIdentity anotherOrphan = ProcessIdentity(kBoot, 1300, 230, "orphan2.exe");
    GraphNode anotherOrphanNode = MakeNode(anotherOrphan, "orphan2.exe", "ev-orphan2",
                                           NodeLifecycle::Observed);
    anotherOrphanNode.ownerRelation = EdgeKind::Owns;
    anotherOrphanNode.ownerKind = ObjectKind::Process;
    graph.addNode(anotherOrphanNode);
    const GraphConclusion more = SummarizeGraph(graph, noFilter);
    s.expect(more.isolatedNodeCount == 4U && more.ownerMissingCount == 2U,
             L"G-05 the fourth isolated node really does move the counts");
    s.expect(more.conclusion == AnalysisConclusion::NoDifferenceObserved,
             L"G-05 more isolated nodes never move the conclusion towards a difference");

    // 只有记录在案的不一致才推得动结论。
    const NodeIdentity conflicted = ProcessIdentity(kBoot, 1400, 240, "conflict2.exe");
    GraphNode conflictedNode = MakeNode(conflicted, "conflict2.exe", "ev-conflict2",
                                        NodeLifecycle::Observed);
    conflictedNode.inconsistencyObserved = true;
    conflictedNode.inconsistencyEvidenceIds.emplace_back("ev-crossview-9");
    graph.addNode(conflictedNode);
    const GraphConclusion withConflict = SummarizeGraph(graph, noFilter);
    s.expect(withConflict.inconsistencyCount == 1U &&
                 withConflict.conclusion == AnalysisConclusion::DifferenceObserved,
             L"G-05 one recorded inconsistency is what moves the conclusion, and nothing else does");

    // 两个"缺口计数器"的非零用例：身份不足 + 连原始证据都没有的节点。
    EntityGraph gaps;
    gaps.setEnvelope(FullyObservedEnvelope());
    GraphNode blind;
    blind.nodeId = "row-9";
    blind.identity.kind = ObjectKind::Process;     // 没有 pid / 创建时间 -> Unusable
    blind.identity.instanceTag = "row-9";
    blind.displayText = "unknown process";
    blind.evidenceId = "";                          // 连原始证据都打不开
    blind.lifecycle = NodeLifecycle::Observed;
    blind.outcome = CollectionOutcome::success();
    s.expect(gaps.addNode(blind) == NodeAdmission::AcceptedNew,
             L"G-05 a record with only a discriminator still enters the graph");
    const GraphConclusion gapConclusion = SummarizeGraph(gaps, noFilter);
    s.expect(gapConclusion.unusableIdentityNodeCount == 1U,
             L"G-08 the unusable-identity counter really counts an unusable identity");
    s.expect(gapConclusion.nodesWithoutEvidenceCount == 1U,
             L"G-08 the missing-evidence counter really counts a node with no evidence id");
    s.expect(Contains(gapConclusion.limitationKeys, "graph.summary.unusableIdentityNodes") &&
                 Contains(gapConclusion.limitationKeys, "graph.summary.nodesWithoutEvidence"),
             L"G-08 both gaps show up in the limitation keys instead of staying silent");
    const IsolationReport blindReport = ClassifyIsolation(gaps, "row-9", noFilter);
    s.expect(blindReport.isolated && !blindReport.rawEvidenceAvailable,
             L"G-05 an isolated node with no evidence id cannot open any raw evidence");
    s.expect(blindReport.rawEvidenceMissingKey == "graph.isolation.noRawEvidence",
             L"G-05 that node says out loud that there is no raw evidence, rather than offering a dead button");
    s.expect(blindReport.evidenceId.empty(),
             L"G-05 and it does not invent an evidence id to point at");
}

// ---------------------------------------------------------------------------
// G-06：离线展开与跨视图一致
// ---------------------------------------------------------------------------
void TestOfflineAndCrossView(KswordTests::Suite& s) {
    EntityGraph graph;
    OfflineExpansionPolicy policy;
    policy.allowLiveQueries = false;
    policy.origin = DataOrigin::Session;
    graph.setOfflinePolicy(policy);
    s.expect(!graph.offlinePolicy().allowLiveQueries &&
                 graph.offlinePolicy().origin == DataOrigin::Session,
             L"G-06 an offline session never allows live queries");

    const NodeIdentity saved = ProcessIdentity(kBoot, 1000, 111, "saved.exe");
    const NodeIdentity alsoSaved = ThreadIdentity(kBoot, 1000, 111, 2000, 222);
    graph.addNode(MakeNode(saved, "saved.exe", "ev-saved", NodeLifecycle::Observed));
    graph.addNode(MakeNode(alsoSaved, "tid 2000", "ev-thread", NodeLifecycle::Observed));
    graph.addEdge(MakeEdge(EdgeKind::Owns, saved.nodeKey(), alsoSaved.nodeKey(),
                           EdgeCertainty::Confirmed, "ev-thread", "rule.owns"));

    // 一条指向"没保存"的邻居的边。
    const std::string unsavedId = ProcessIdentity(kBoot, 1200, 150, "never-saved.exe").nodeKey();
    GraphEdge danglingEdge = MakeEdge(EdgeKind::CandidateOwner, saved.nodeKey(), unsavedId,
                                      EdgeCertainty::Candidate, "ev-guess", "rule.candidateOwner");
    s.expect(EdgeAdmissionAccepted(graph.addEdge(danglingEdge)),
             L"G-06 an edge to an unsaved neighbour is still recorded as a known relation");

    ExpansionRequest request;
    request.rootNodeIds.push_back(saved.nodeKey());
    const ExpansionResult view = ExpandGraph(graph, request);
    s.expect(view.liveQueriesIssued == 0U,
             L"G-06 offline expansion issues no live query at all");
    s.expect(view.unsavedNeighbors.size() == 1U &&
                 view.unsavedNeighbors[0].missingNodeId == unsavedId &&
                 view.unsavedNeighbors[0].relation == EdgeKind::CandidateOwner,
             L"G-06 the unsaved neighbour is recorded with the relation that pointed at it");
    s.expect(!Contains(view.nodeIds, unsavedId),
             L"G-06 an unsaved neighbour is never materialised as a node");
    s.expect(view.loadedNodes == 2U && view.loadedEdges == 1U,
             L"G-06 only the saved part of the neighbourhood is loaded");
    s.expect(!view.totalKnownNodes.present && view.coverage.skipped == 1U,
             L"G-06 an unsaved neighbour keeps the total unknown and shows up in the account");
    s.expect(Contains(view.limitationKeys, "graph.expand.unsavedNeighbors"),
             L"G-06 the limitation list names the unsaved neighbours");

    // 根节点本身没保存。
    ExpansionRequest missingRoot;
    missingRoot.rootNodeIds.push_back("never-stored");
    const ExpansionResult noRoot = ExpandGraph(graph, missingRoot);
    s.expect(noRoot.loadedNodes == 0U && noRoot.unsavedNeighbors.size() == 1U &&
                 Contains(noRoot.limitationKeys, "graph.expand.rootNotSaved"),
             L"G-06 an unsaved root is reported as not saved rather than as an empty graph");

    // 图 / 列表 / 详情 / 导出引用同一套 id。
    EdgeFilter noFilter;
    const std::vector<EntityListRow> rows = BuildEntityList(graph, view, noFilter,
                                                            EntityListOrder::ByNodeId);
    s.expect(rows.size() == 2U, L"G-06 the list view holds exactly the loaded nodes");
    bool listMatchesGraph = true;
    for (const EntityListRow& row : rows) {
        if (!Contains(view.nodeIds, row.nodeId)) {
            listMatchesGraph = false;
        }
        const NodeDetail detail = BuildNodeDetail(graph, row.nodeId, noFilter);
        if (!detail.nodeFound || detail.nodeId != row.nodeId ||
            detail.evidenceId != row.evidenceId) {
            listMatchesGraph = false;
        }
    }
    s.expect(listMatchesGraph,
             L"G-06 list rows and node details use the same entity id and evidence id as the graph");

    const NodeDetail rootDetail = BuildNodeDetail(graph, saved.nodeKey(), noFilter);
    s.expect(rootDetail.outgoingEdgeIds.size() == 2U && rootDetail.incomingEdgeIds.empty(),
             L"G-06 the detail view separates outgoing from incoming relations");
    s.expect(rootDetail.inferences.size() == 2U,
             L"G-08 the detail view can expand the rule behind every relation it shows");
    s.expect(!rootDetail.isolation.isolated,
             L"G-06 the detail view carries the same isolation reading as the graph");

    const JsonValue exported = ExportGraph(graph, view, noFilter);
    const JsonValue* exportedNodes = exported.find("nodes");
    const JsonValue* exportedEdges = exported.find("edges");
    s.expect(exportedNodes != nullptr && exportedNodes->asArray() != nullptr &&
                 exportedNodes->asArray()->size() == 2U,
             L"G-06 the export holds exactly the nodes of the exported view");
    s.expect(exportedEdges != nullptr && exportedEdges->asArray() != nullptr &&
                 exportedEdges->asArray()->size() == 1U,
             L"G-06 the export holds exactly the edges of the exported view");
    bool exportIdsMatch = true;
    if (exportedNodes != nullptr && exportedNodes->asArray() != nullptr) {
        for (const JsonValue& entry : *exportedNodes->asArray()) {
            const JsonValue* idValue = entry.find("nodeId");
            std::string id;
            if (idValue == nullptr || !idValue->tryGetString(id) || !Contains(view.nodeIds, id)) {
                exportIdsMatch = false;
            }
        }
    }
    s.expect(exportIdsMatch, L"G-06 exported node ids are the very ids the graph and list use");

    const JsonValue* exportedUnsaved = exported.find("unsavedNeighbors");
    s.expect(exportedUnsaved != nullptr && exportedUnsaved->asArray() != nullptr &&
                 exportedUnsaved->asArray()->size() == 1U,
             L"G-06 the export states the unsaved neighbour instead of dropping it");
    const JsonValue* scope = exported.find("scope");
    s.expect(scope != nullptr && scope->find("viewIsExpansionResult") != nullptr,
             L"G-06 the export says which scope its counts belong to");

    // 导出的孤立条目描述的是**观察到的数据状态**，不是因果。头文件里刻意避开的
    // "cause" 这个词，不许在给报告和下游看的制品里又冒出来。
    const JsonValue* exportedIsolation = exported.find("isolation");
    s.expect(exportedIsolation != nullptr && exportedIsolation->asArray() != nullptr &&
                 exportedIsolation->asArray()->size() == 2U,
             L"G-05 the export carries one isolation entry per exported node");
    if (exportedIsolation != nullptr && exportedIsolation->asArray() != nullptr &&
        !exportedIsolation->asArray()->empty()) {
        const JsonValue& firstIsolation = exportedIsolation->asArray()->front();
        const JsonObject* isolationFields = firstIsolation.asObject();
        std::vector<std::string> keys;
        if (isolationFields != nullptr) {
            for (const std::pair<std::string, JsonValue>& field : *isolationFields) {
                keys.push_back(field.first);
            }
        }
        const std::vector<std::string> expectedKeys = {
            "nodeId", "isolated", "state", "explanationKey", "rawEvidenceAvailable",
            "rawEvidenceMissingKey", "ownerLookupOutcome",
        };
        s.expect(keys == expectedKeys,
                 L"G-05 the exported isolation entry names a data state and nothing that reads as a cause");
        s.expect(firstIsolation.find("cause") == nullptr &&
                     firstIsolation.find("state") != nullptr,
                 L"G-05 the isolation field is called state, the word the header actually promises");
    }

    // 视图里有、图里没有的 id：跳过可以，但计数与内容不许互相矛盾。
    ExpansionResult ghostView = view;
    ghostView.nodeIds.emplace_back("ghost-node");
    ghostView.edgeIds.emplace_back("ghost-edge");
    std::uint64_t missingRows = 0;
    const std::vector<EntityListRow> ghostRows =
        BuildEntityList(graph, ghostView, noFilter, EntityListOrder::ByNodeId, &missingRows);
    s.expect(ghostRows.size() == 2U && missingRows == 1U,
             L"G-04 a list row whose node is gone from the graph is counted, not silently dropped");
    const JsonValue ghostExport = ExportGraph(graph, ghostView, noFilter);
    const JsonValue* ghostViewObject = ghostExport.find("view");
    std::string exportedNodeCount;
    std::string missingNodeCount;
    std::string missingEdgeCount;
    if (ghostViewObject != nullptr) {
        const JsonValue* exportedNodes2 = ghostViewObject->find("exportedNodes");
        const JsonValue* missingNodes = ghostViewObject->find("viewNodeMissing");
        const JsonValue* missingEdges = ghostViewObject->find("viewEdgeMissing");
        if (exportedNodes2 != nullptr) {
            (void)exportedNodes2->tryGetString(exportedNodeCount);
        }
        if (missingNodes != nullptr) {
            (void)missingNodes->tryGetString(missingNodeCount);
        }
        if (missingEdges != nullptr) {
            (void)missingEdges->tryGetString(missingEdgeCount);
        }
    }
    s.expect(exportedNodeCount == "2" && missingNodeCount == "1" && missingEdgeCount == "1",
             L"G-04 the export states how many entries it actually wrote and how many it could not");
    const std::string ghostText = WriteJson(ghostExport, 0);
    s.expect(ghostText.find("graph.export.viewNodeMissing") != std::string::npos &&
                 ghostText.find("graph.export.viewEdgeMissing") != std::string::npos,
             L"G-04 the export names the missing view entries in its own limitation keys");

    // 离线展开在有未保存邻居、命中预算、还带筛选的情况下同样一次现场查询都不发。
    ExpansionRequest pressured;
    pressured.rootNodeIds.push_back(saved.nodeKey());
    pressured.limits.maxNodes = 1;
    pressured.limits.maxEdges = 1;
    pressured.filter.kinds.push_back(EdgeKind::Owns);
    pressured.filter.kinds.push_back(EdgeKind::CandidateOwner);
    const ExpansionResult pressuredView = ExpandGraph(graph, pressured);
    s.expect(pressuredView.liveQueriesIssued == 0U,
             L"G-06 an expansion that runs out of budget still never issues a live query");
    s.expect(pressuredView.moreAvailable && pressuredView.loadedNodes == 1U,
             L"G-06 the pressured expansion really did hit its budget, so the check above is not vacuous");

    // 无浮点，且 64 位量写成字符串。
    const std::string text = WriteJson(exported, 0);
    const JsonParseResult reparsed = ParseJson(text);
    s.expect(reparsed.ok(), L"G-06 the export round-trips through the lossless json reader");
    s.expect(text.find("\"loadedNodes\":\"2\"") != std::string::npos,
             L"F-08 counts are exported as text so 64-bit values never pass through a double");
}

// ---------------------------------------------------------------------------
// G-08：图是证据视图不是分析真值
// ---------------------------------------------------------------------------
struct GraphFixture final {
    std::vector<GraphNode> nodes;
    std::vector<GraphEdge> edges;
};

GraphFixture MakeConclusionFixture() {
    GraphFixture fixture;
    const NodeIdentity process = ProcessIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity thread = ThreadIdentity(kBoot, 1000, 111, 2000, 222);
    const NodeIdentity handle = HandleIdentity_(kBoot, 1000, 111, 0x2C, "File");
    const NodeIdentity orphan = ProcessIdentity(kBoot, 2000, 500, "orphan.exe");
    const NodeIdentity ended = DriverIdentity("C:\\gone.sys", "PDB-GONE", 0x1000);
    const NodeIdentity conflicted = ProcessIdentity(kBoot, 3000, 600, "conflict.exe");

    GraphNode processNode = MakeNode(process, "worker.exe", "ev-proc", NodeLifecycle::Observed);
    processNode.ownerRelation = EdgeKind::Owns;
    processNode.ownerKind = ObjectKind::Process;
    GraphNode orphanNode = MakeNode(orphan, "orphan.exe", "ev-orphan", NodeLifecycle::Observed);
    orphanNode.ownerRelation = EdgeKind::Owns;
    orphanNode.ownerKind = ObjectKind::Process;
    GraphNode endedNode = MakeNode(ended, "gone.sys", "ev-gone", NodeLifecycle::Ended);
    GraphNode conflictedNode = MakeNode(conflicted, "conflict.exe", "ev-conflict",
                                        NodeLifecycle::Observed);
    conflictedNode.inconsistencyObserved = true;
    conflictedNode.inconsistencyEvidenceIds.emplace_back("ev-crossview-1");

    fixture.nodes.push_back(processNode);
    fixture.nodes.push_back(MakeNode(thread, "tid 2000", "ev-thread", NodeLifecycle::Observed));
    fixture.nodes.push_back(MakeNode(handle, "handle 0x2C", "ev-handle", NodeLifecycle::Observed));
    fixture.nodes.push_back(orphanNode);
    fixture.nodes.push_back(endedNode);
    fixture.nodes.push_back(conflictedNode);

    fixture.edges.push_back(MakeEdge(EdgeKind::Owns, process.nodeKey(), thread.nodeKey(),
                                     EdgeCertainty::Confirmed, "ev-thread", "rule.owns"));
    fixture.edges.push_back(MakeEdge(EdgeKind::Owns, process.nodeKey(), handle.nodeKey(),
                                     EdgeCertainty::Candidate, "ev-handle", "rule.owns"));
    GraphEdge unknownCertainty = MakeEdge(EdgeKind::Maps, process.nodeKey(), handle.nodeKey(),
                                          EdgeCertainty::Unknown, "ev-map", "rule.maps");
    fixture.edges.push_back(unknownCertainty);
    return fixture;
}

EntityGraph BuildFromFixture(const GraphFixture& fixture, bool reverseOrder) {
    EntityGraph graph;
    EvidenceEnvelope envelope;
    envelope.source.collectorId = "r0.graph";
    envelope.source.sourceGroup = "r0.graph";
    envelope.source.origin = SourceOrigin::OfflineSample;
    envelope.outcome = CollectionOutcome::success();
    envelope.coverage.totalKnown = OptionalU64::of(6);
    envelope.coverage.succeeded = 6;
    envelope.evidenceId = "ev-session";
    graph.setEnvelope(envelope);
    graph.declareRelationCoverage(EdgeKind::Owns, ObjectKind::Process,
                                  FullySuccessfulCoverage(6, "ev-parents"));

    if (reverseOrder) {
        for (std::size_t i = fixture.nodes.size(); i > 0; --i) {
            graph.addNode(fixture.nodes[i - 1]);
        }
        for (std::size_t i = fixture.edges.size(); i > 0; --i) {
            graph.addEdge(fixture.edges[i - 1]);
        }
    } else {
        for (const GraphNode& node : fixture.nodes) {
            graph.addNode(node);
        }
        for (const GraphEdge& edge : fixture.edges) {
            graph.addEdge(edge);
        }
    }
    return graph;
}

void TestOrderIndependence(KswordTests::Suite& s) {
    const GraphFixture fixture = MakeConclusionFixture();
    const EntityGraph forward = BuildFromFixture(fixture, false);
    const EntityGraph reversed = BuildFromFixture(fixture, true);
    EdgeFilter noFilter;

    const GraphConclusion a = SummarizeGraph(forward, noFilter);
    const GraphConclusion b = SummarizeGraph(reversed, noFilter);

    // 先把第一遍的绝对值写死（独立手算），再比较两遍 —— 否则"两边一起坏掉"会逃逸。
    s.expect(a.nodeCount == 6U, L"G-08 the fixture has six nodes");
    s.expect(a.edgeCountBeforeFilter == 3U && a.edgeCountAfterFilter == 3U,
             L"G-08 the fixture has three edges and no filter drops any of them");
    s.expect(a.confirmedEdgeCount == 1U && a.candidateEdgeCount == 1U &&
                 a.unknownCertaintyEdgeCount == 1U,
             L"G-08 the fixture holds one confirmed, one candidate and one unknown-certainty edge");
    s.expect(a.isolatedNodeCount == 3U, L"G-08 exactly three fixture nodes have no edge");
    s.expect(a.ownerMissingCount == 1U && a.unloadedCount == 1U && a.inconsistencyCount == 1U &&
                 a.sourceNotCollectedCount == 0U,
             L"G-08 the three isolated fixture nodes fall into three different states");
    s.expect(a.conclusion == AnalysisConclusion::DifferenceObserved,
             L"G-08 the recorded inconsistency drives the fixture conclusion");
    s.expect(a.unusableIdentityNodeCount == 0U && a.nodesWithoutEvidenceCount == 0U,
             L"G-08 every fixture node has a usable identity and openable evidence");

    // 逐字段比较：换输入顺序后必须完全一致。
    s.expect(a.conclusion == b.conclusion, L"G-08 the conclusion field survives reordering");
    s.expect(a.nodeCount == b.nodeCount, L"G-08 the node count survives reordering");
    s.expect(a.edgeCountBeforeFilter == b.edgeCountBeforeFilter,
             L"G-08 the unfiltered edge count survives reordering");
    s.expect(a.edgeCountAfterFilter == b.edgeCountAfterFilter,
             L"G-08 the filtered edge count survives reordering");
    s.expect(a.confirmedEdgeCount == b.confirmedEdgeCount,
             L"G-08 the confirmed edge count survives reordering");
    s.expect(a.candidateEdgeCount == b.candidateEdgeCount,
             L"G-08 the candidate edge count survives reordering");
    s.expect(a.unknownCertaintyEdgeCount == b.unknownCertaintyEdgeCount,
             L"G-08 the unknown-certainty edge count survives reordering");
    s.expect(a.isolatedNodeCount == b.isolatedNodeCount,
             L"G-08 the isolated node count survives reordering");
    s.expect(a.ownerMissingCount == b.ownerMissingCount,
             L"G-08 the owner-missing count survives reordering");
    s.expect(a.unloadedCount == b.unloadedCount, L"G-08 the unloaded count survives reordering");
    s.expect(a.sourceNotCollectedCount == b.sourceNotCollectedCount,
             L"G-08 the not-collected count survives reordering");
    s.expect(a.inconsistencyCount == b.inconsistencyCount,
             L"G-08 the inconsistency count survives reordering");
    s.expect(a.unusableIdentityNodeCount == b.unusableIdentityNodeCount,
             L"G-08 the unusable identity count survives reordering");
    s.expect(a.nodesWithoutEvidenceCount == b.nodesWithoutEvidenceCount,
             L"G-08 the missing-evidence count survives reordering");
    s.expect(a.coverage.succeeded == b.coverage.succeeded &&
                 a.coverage.totalKnown == b.coverage.totalKnown &&
                 a.coverage.limitHit == b.coverage.limitHit,
             L"G-08 the coverage account survives reordering");
    s.expect(a.limitationKeys == b.limitationKeys,
             L"G-08 the limitation keys survive reordering, in the same order");
    s.expect(a == b, L"G-08 the whole conclusion compares equal field by field after reordering");

    // 导出逐字节一致。
    ExpansionRequest request;
    for (const GraphNode& node : fixture.nodes) {
        request.rootNodeIds.push_back(node.identity.nodeKey());
    }
    const ExpansionResult forwardView = ExpandGraph(forward, request);
    ExpansionRequest shuffled;
    for (std::size_t i = request.rootNodeIds.size(); i > 0; --i) {
        shuffled.rootNodeIds.push_back(request.rootNodeIds[i - 1]);
    }
    const ExpansionResult reversedView = ExpandGraph(reversed, shuffled);
    s.expect(forwardView.loadedNodes == 6U && forwardView.loadedEdges == 3U,
             L"G-08 the exported view holds all six nodes and three edges");
    s.expect(forwardView.nodeIds == reversedView.nodeIds &&
                 forwardView.edgeIds == reversedView.edgeIds,
             L"G-08 the loaded id lists are identical whichever order the roots arrive in");
    const std::string forwardJson = WriteJson(ExportGraph(forward, forwardView, noFilter), 0);
    const std::string reversedJson = WriteJson(ExportGraph(reversed, reversedView, noFilter), 0);
    s.expect(forwardJson == reversedJson,
             L"G-08 the export is byte-for-byte identical after reordering the input");

    // 导出必须自己保证顺序无关，而不是靠"展开结果碰巧是有序的"。这里把 id 列表故意
    // 打乱后再导出：少了导出侧的排序，这一条就会红。
    ExpansionResult shuffledView = forwardView;
    for (std::size_t i = 0; i + 1 < shuffledView.nodeIds.size(); i += 2) {
        std::swap(shuffledView.nodeIds[i], shuffledView.nodeIds[i + 1]);
    }
    for (std::size_t i = 0; i + 1 < shuffledView.edgeIds.size(); i += 2) {
        std::swap(shuffledView.edgeIds[i], shuffledView.edgeIds[i + 1]);
    }
    s.expect(shuffledView.nodeIds != forwardView.nodeIds &&
                 shuffledView.edgeIds != forwardView.edgeIds,
             L"G-08 the shuffled view really is in a different order");
    s.expect(WriteJson(ExportGraph(forward, shuffledView, noFilter), 0) == forwardJson,
             L"G-08 the export canonicalises its own order instead of trusting the caller's");

    // 换列表排序方式不影响结论，也不影响导出。
    const std::vector<EntityListRow> byId =
        BuildEntityList(forward, forwardView, noFilter, EntityListOrder::ByNodeId);
    const std::vector<EntityListRow> byEdges =
        BuildEntityList(forward, forwardView, noFilter, EntityListOrder::ByEdgeCountDescending);
    const std::vector<EntityListRow> byKind =
        BuildEntityList(forward, forwardView, noFilter, EntityListOrder::ByKind);
    s.expect(byId.size() == 6U && byEdges.size() == 6U && byKind.size() == 6U,
             L"G-08 every ordering shows the same six rows");
    s.expect(byEdges.front().edgeCount == 3U,
             L"G-08 ordering by edge count puts the three-edge node first");
    s.expect(SummarizeGraph(forward, noFilter) == a,
             L"G-08 building the list in another order does not change the conclusion");
    s.expect(WriteJson(ExportGraph(forward, forwardView, noFilter), 0) == forwardJson,
             L"G-08 exporting again after re-sorting the list yields the same bytes");

    // 排序确实换了顺序（否则上面的不变性是空的）。
    bool orderActuallyDiffers = false;
    for (std::size_t i = 0; i < byId.size(); ++i) {
        if (byId[i].nodeId != byEdges[i].nodeId) {
            orderActuallyDiffers = true;
        }
    }
    s.expect(orderActuallyDiffers,
             L"G-08 the two orderings really produce different row orders");

    // 命中上限时"保留哪一部分"也必须与插入顺序无关。邻接表若按插入顺序遍历，
    // 正序图和逆序图会截出两个不同的子集。
    ExpansionRequest truncating;
    truncating.rootNodeIds.push_back(fixture.nodes[0].identity.nodeKey());
    truncating.limits.maxNodes = 2;
    const ExpansionResult truncatedForward = ExpandGraph(forward, truncating);
    const ExpansionResult truncatedReversed = ExpandGraph(reversed, truncating);
    s.expect(truncatedForward.loadedNodes == 2U && truncatedForward.nodeLimitHit,
             L"G-08 the truncating expansion really stops at the node budget");
    s.expect(truncatedForward.nodeIds == truncatedReversed.nodeIds,
             L"G-08 a truncated view keeps the same nodes whichever order the graph was built in");
    s.expect(truncatedForward.edgeIds == truncatedReversed.edgeIds,
             L"G-08 a truncated view keeps the same edges whichever order the graph was built in");

    // 结论字段里没有任何风险维度：能读到的只有计数、覆盖和限制说明。
    s.expect(a.limitationKeys.size() >= 2U &&
                 Contains(a.limitationKeys, "graph.summary.isolatedNodes") &&
                 Contains(a.limitationKeys, "graph.summary.unknownCertaintyEdges"),
             L"G-08 the conclusion explains its own limits instead of scoring anything");
}

// ---------------------------------------------------------------------------
// G-06：导出件必须能把同一张图重新开出来
// ---------------------------------------------------------------------------
void TestExportImportRoundTrip(KswordTests::Suite& s) {
    const GraphFixture fixture = MakeConclusionFixture();
    const EntityGraph original = BuildFromFixture(fixture, false);
    EdgeFilter noFilter;

    ExpansionRequest request;
    for (const GraphNode& node : fixture.nodes) {
        request.rootNodeIds.push_back(node.identity.nodeKey());
    }
    const ExpansionResult view = ExpandGraph(original, request);
    s.expect(view.loadedNodes == 6U && view.loadedEdges == 3U,
             L"G-06 the exported view really covers the whole saved fixture");

    const std::string text = WriteJson(ExportGraph(original, view, noFilter), 0);
    const JsonParseResult reparsed = ParseJson(text);
    s.expect(reparsed.ok(), L"G-06 the export parses back through the lossless json reader");

    const GraphImport imported = ImportGraph(reparsed.value);
    s.expect(imported.schemaRecognised, L"G-06 the importer recognises the exported schema");
    s.expect(imported.nodesAccepted == 6U && imported.nodesRejected == 0U,
             L"G-06 all six saved nodes are reopened, none rejected");
    s.expect(imported.edgesAccepted == 3U && imported.edgesRejected == 0U,
             L"G-06 all three saved edges are reopened, none rejected");
    s.expect(imported.coverageAccepted == 1U && imported.coverageRejected == 0U,
             L"G-06 the declared relation coverage is reopened with the graph");
    s.expect(imported.graph.nodeCount() == 6U && imported.graph.edgeCount() == 3U,
             L"G-06 the reopened graph holds the same six nodes and three edges");

    // 结论：先把绝对值独立写死，再逐字段比较，避免"两边一起坏掉"。
    const GraphConclusion before = SummarizeGraph(original, noFilter);
    const GraphConclusion after = SummarizeGraph(imported.graph, noFilter);
    s.expect(after.conclusion == AnalysisConclusion::DifferenceObserved,
             L"G-06 the reopened session still reaches difference-observed instead of falling back to no-evidence");
    s.expect(after.nodeCount == 6U && after.edgeCountAfterFilter == 3U,
             L"G-06 the reopened session counts the same six nodes and three edges");
    s.expect(after.ownerMissingCount == 1U && after.sourceNotCollectedCount == 0U,
             L"G-06 owner-missing does not decay into source-not-collected when the session is reopened");
    s.expect(after.unusableIdentityNodeCount == 0U && after.nodesWithoutEvidenceCount == 0U,
             L"G-06 no identity turns unusable just because the session was written out and read back");
    s.expect(after == before,
             L"G-06 the reopened conclusion equals the saved one field by field");

    // 身份本身：可导航性与跨会话主键都不许退化。
    bool identitiesSurvived = true;
    for (const GraphNode& node : original.nodes()) {
        const GraphNode* reopened = imported.graph.findNode(node.nodeId);
        if (reopened == nullptr || reopened->identity.crossSessionKey() != node.identity.crossSessionKey() ||
            reopened->identity.strength() != node.identity.strength() ||
            reopened->objectNavigable() != node.objectNavigable() ||
            reopened->identity.nodeKey() != node.identity.nodeKey() ||
            reopened->ownerRelation != node.ownerRelation ||
            reopened->ownerKind != node.ownerKind) {
            identitiesSurvived = false;
        }
    }
    s.expect(identitiesSurvived,
             L"G-06 every reopened node keeps its identity payload, owner relation and navigability");
    const std::string processKey = ProcessIdentity(kBoot, 1000, 111, "worker.exe").nodeKey();
    const GraphNode* reopenedProcess = imported.graph.findNode(processKey);
    s.expect(reopenedProcess != nullptr && reopenedProcess->objectNavigable() &&
                 !reopenedProcess->identity.crossSessionKey().empty(),
             L"G-06 the reopened process is still navigable and still has a cross-session key");

    // 链路：同一条 G-03 调查链在重开的会话里逐环相同。
    ChainOptions options;
    const InvestigationChain chainBefore =
        BuildChain(original, ChainKind::ProcessSubjects, processKey, options);
    const InvestigationChain chainAfter =
        BuildChain(imported.graph, ChainKind::ProcessSubjects, processKey, options);
    s.expect(chainAfter.steps.size() == 4U &&
                 chainAfter.steps[0].availability == StepAvailability::Present &&
                 chainAfter.steps[1].availability == StepAvailability::Present &&
                 chainAfter.steps[3].availability == StepAvailability::Present,
             L"G-06 the reopened process chain still reaches its thread and handle steps");
    bool chainSurvived = chainBefore.steps.size() == chainAfter.steps.size();
    for (std::size_t i = 0; chainSurvived && i < chainBefore.steps.size(); ++i) {
        const ChainStep& x = chainBefore.steps[i];
        const ChainStep& y = chainAfter.steps[i];
        if (x.availability != y.availability || x.matchCount != y.matchCount ||
            x.nodeIds != y.nodeIds || x.edgeIds != y.edgeIds ||
            x.evidenceOpenable != y.evidenceOpenable ||
            x.anyObjectNavigable != y.anyObjectNavigable ||
            x.everyObjectNavigable != y.everyObjectNavigable ||
            x.outcome.status != y.outcome.status) {
            chainSurvived = false;
        }
    }
    s.expect(chainSurvived,
             L"G-06 every chain step is field-for-field what it was before the session was written out");

    // 再导出一次：逐字节相同。这条把"导出格式本身缺字段"这一类问题一次钉死。
    const ExpansionResult reopenedView = ExpandGraph(imported.graph, request);
    s.expect(reopenedView.nodeIds == view.nodeIds && reopenedView.edgeIds == view.edgeIds,
             L"G-06 expanding the reopened graph yields the very same id lists");
    s.expect(WriteJson(ExportGraph(imported.graph, reopenedView, noFilter), 0) == text,
             L"G-06 exporting the reopened session reproduces the saved document byte for byte");

    // 认不出 schema 就不猜：半张图被当成整张图用比拒绝危险得多。
    JsonObject strangerFields;
    strangerFields.emplace_back("schema", JsonValue::makeString("ksword.entityGraph.v0"));
    const GraphImport stranger = ImportGraph(JsonValue::makeObject(std::move(strangerFields)));
    s.expect(!stranger.schemaRecognised && stranger.graph.nodeCount() == 0U &&
                 Contains(stranger.limitationKeys, "graph.import.schemaUnknown"),
             L"G-06 an unrecognised schema is refused outright instead of importing half a graph");
    const GraphImport notAnObject = ImportGraph(JsonValue::makeString("nope"));
    s.expect(!notAnObject.schemaRecognised &&
                 Contains(notAnObject.limitationKeys, "graph.import.notAnObject"),
             L"G-06 a document that is not even an object is refused with its own reason");
}

} // namespace

int RunEntityGraphTests() {
    // 套件名里有中文。std::wcout 在默认的 "C" locale 下编不出这些字符，会置 badbit
    // 并让**后面每一个套件**的报告全部消失 —— 一个套件的名字不该吞掉别人的输出。
    // 这里临时换成系统 locale 打完再换回去，并兜底清掉状态位。
    //
    // 同一件事对 std::wcerr 更要命：失败行是 L"FAIL [" << 套件名 << ...，套件名一旦
    // 转换失败就置 badbit，**后面每一条失败行都会被静默丢掉** —— 一次跑出十条失败，
    // 屏幕上只看得见半行。诊断信息不该因为名字里有汉字就消失。
    const std::locale previousLocale = std::wcout.getloc();
    const std::locale previousErrLocale = std::wcerr.getloc();
    bool imbued = false;
    try {
        std::wcout.imbue(std::locale(""));
        std::wcerr.imbue(std::locale(""));
        imbued = true;
    } catch (const std::exception&) {
        imbued = false;
    }

    KswordTests::Suite suite(L"G entity graph");
    TestEdgeSemantics(suite);
    TestLifecycleIdentity(suite);
    TestHistoricalEdgeToLive(suite);
    TestProcessChain(suite);
    TestDeviceChain(suite);
    TestConnectionChain(suite);
    TestBoundedExpansion(suite);
    TestLargeDatasetPerformance(suite);
    TestIsolationStates(suite);
    TestIsolationDoesNotDriveConclusion(suite);
    TestOfflineAndCrossView(suite);
    TestOrderIndependence(suite);
    TestExportImportRoundTrip(suite);
    suite.report();

    if (imbued) {
        std::wcout.imbue(previousLocale);
        std::wcerr.imbue(previousErrLocale);
    }
    if (!std::wcout.good()) {
        std::wcout.clear();
    }
    if (!std::wcerr.good()) {
        std::wcerr.clear();
    }
    return suite.failures();
}
