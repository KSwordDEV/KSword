#include "CrossProcessEvidenceGraph.h"

#include <algorithm>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {

// 检查证据锚点能否回到本采样。Sysmon 原生报告允许没有本机启动身份，
// 原生进程和线程身份仍通过 InjectionDiscovery 的完整采样闸门。
bool HasDisplayLocation(const SampleScope& scope, const EvidenceRef& evidence) noexcept
{
    return !scope.projectId.empty() && !scope.sampleId.empty() &&
        scope.projectId == evidence.projectId && scope.sampleId == evidence.sampleId &&
        !evidence.sourceId.empty() && !evidence.sourceEpoch.empty() &&
        (!evidence.raw || (evidence.raw->segmentOrdinal != 0 && evidence.raw->sequence != 0)) &&
        (evidence.eventOrdinal || evidence.raw);
}

// 将缺口按首次出现的顺序并入显示记录。
void AddGap(GraphObservation& result, Issue issue)
{
    if (std::find(result.gaps.begin(), result.gaps.end(), issue) == result.gaps.end()) {
        result.gaps.push_back(issue);
    }
}

// 调用方完成强身份核验后，提取本采样内的进程键。
GraphProcessInstance ProcessKey(const ProcessBinding& binding) noexcept
{
    return {static_cast<std::uint32_t>(binding.instance.pid.value), binding.instance.createTime100ns.value};
}

// 同一事件中的同一 PID 若有两个创建代次，不能视为同时生存的两个角色。
bool ConflictingInstances(const ProcessBinding& a, const ProcessBinding& b) noexcept
{
    return a.instance.pid == b.instance.pid && a.instance.createTime100ns != b.instance.createTime100ns;
}

class GraphBuilder {
public:
    explicit GraphBuilder(const SampleScope& scope)
    {
        graph.scope = scope;
    }

    void Add(const GraphEventInput& input);
    void Add(const GraphSysmonInput& input);

    EvidenceGraph graph; // 构建完成后移交调用方。

private:
    // 优先用规范事件序号。不同规范事件可以引用同一份原始包。
    using Anchor = std::variant<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>>;

    std::size_t Node(const GraphNodeKey& key);
    void Edge(GraphRelation relation, std::size_t from, std::size_t to, const EvidenceRef& evidence);
    bool BindLocation(GraphObservation& result, const std::optional<EvidenceRef>& evidence) const;
    bool IsProcessRole(const std::optional<ProcessBinding>& binding, std::uint32_t pidHint) const noexcept;
    bool IsThreadRole(const ThreadBinding& thread, const ProcessBinding& owner, std::uint32_t tidHint) const noexcept;
    void AddRoles(const WriteObservation& row, GraphObservation& result);
    void AddRoles(const ThreadCreationObservation& row, GraphObservation& result);
    void AddRoles(const ExecutionObservation& row, GraphObservation& result);

    std::map<GraphNodeKey, std::size_t> nodeIndex_; // 实例键到节点下标。
    std::map<std::tuple<GraphRelation, std::size_t, std::size_t>, std::size_t> edgeIndex_; // 关系键到边下标。
    std::set<std::pair<std::size_t, Anchor>> edgeAnchors_; // 已加入各条边的证据锚点。
};

// 查找或追加实例节点，返回投影内索引。
std::size_t GraphBuilder::Node(const GraphNodeKey& key)
{
    const auto [position, added] = nodeIndex_.try_emplace(key, graph.nodes.size());
    if (added) {
        graph.nodes.push_back(key);
    }
    return position->second;
}

// 将当前处理的证据追加到两个节点的同类边。调用方已校验锚点。
void GraphBuilder::Edge(GraphRelation relation, std::size_t from, std::size_t to, const EvidenceRef& evidence)
{
    const auto [position, added] = edgeIndex_.try_emplace(std::tuple{relation, from, to}, graph.edges.size());
    const auto index = position->second;
    if (added) {
        graph.edges.push_back({relation, from, to, {}});
    }
    // 同一锚点至多支撑同一条边一次，观察列表仍保留输入记录。
    const auto anchor = evidence.eventOrdinal ? Anchor{*evidence.eventOrdinal}
        : Anchor{std::pair{evidence.raw->segmentOrdinal, evidence.raw->sequence}};
    if (edgeAnchors_.emplace(index, anchor).second) {
        graph.edges[index].observations.push_back(graph.observations.size());
    }
}

// 绑定同采样锚点；失败时返回 false 并登记缺口。
bool GraphBuilder::BindLocation(GraphObservation& result, const std::optional<EvidenceRef>& evidence) const
{
    if (evidence && HasDisplayLocation(graph.scope, *evidence)) {
        result.evidence = evidence;
        return true;
    }
    AddGap(result, Issue::EvidenceUnavailable);
    return false;
}

// PID 提示只在有强身份时检查矛盾，不能填补强身份。
bool GraphBuilder::IsProcessRole(const std::optional<ProcessBinding>& binding, std::uint32_t pidHint) const noexcept
{
    return binding && IsBoundProcess(graph.scope, *binding) &&
        (!pidHint || binding->instance.pid.value == pidHint);
}

// 核对已验证的线程宿主、TID 和创建时间。调用方已核验传入的宿主。
bool GraphBuilder::IsThreadRole(const ThreadBinding& thread, const ProcessBinding& owner, std::uint32_t tidHint) const noexcept
{
    return IsBoundProcess(graph.scope, thread.owner) && ProcessKey(thread.owner) == ProcessKey(owner) &&
        thread.tid != 0 && (!tidHint || thread.tid == tidHint) &&
        thread.creationFileTime >= owner.instance.createTime100ns.value;
}

// 投影写入双方的角色，有实际完成写入时才建立操作边。
void GraphBuilder::AddRoles(const WriteObservation& row, GraphObservation& result)
{
    result.actorPidHint = row.actorPidHint;
    result.actorTidHint = row.actorTidHint;
    if (row.header.trust != InputTrust::Validated) {
        return;
    }

    // 相同 PID 的不同代次不能同时出现在同一写入事件中。
    const auto actor = IsProcessRole(row.actor, row.actorPidHint);
    const auto target = IsProcessRole(row.target, 0);
    if (actor && target && ConflictingInstances(*row.actor, *row.target)) {
        AddGap(result, Issue::IdentityConflict);
        return;
    }
    if (!actor && row.actor && row.actor->instance.pid.present && row.actorPidHint &&
        row.actor->instance.pid.value != row.actorPidHint) {
        AddGap(result, Issue::IdentityConflict);
    }
    if (actor) {
        result.actorProcess = Node(ProcessKey(*row.actor));
    }
    if (target) {
        result.targetProcess = Node(ProcessKey(*row.target));
    }
    if (result.finding && result.finding->kind == FindingKind::ExternalWrite &&
        result.actorProcess && result.targetProcess) {
        Edge(GraphRelation::ExternalWrite, *result.actorProcess, *result.targetProcess, row.header.evidence);
    }
}

// 分别投影创建者、目标及新线程的角色，创建未知时保留可核验的归属。
void GraphBuilder::AddRoles(const ThreadCreationObservation& row, GraphObservation& result)
{
    result.actorPidHint = row.creatorPidHint;
    result.actorTidHint = row.creatorTidHint;
    result.targetPidHint = row.targetPidHint;
    result.targetTidHint = row.targetTidHint;
    if (row.header.trust != InputTrust::Validated) {
        return;
    }

    const auto actor = IsProcessRole(row.creator, row.creatorPidHint);
    const auto target = IsProcessRole(row.target, row.targetPidHint);
    if (actor && (!target || !ConflictingInstances(*row.creator, *row.target))) {
        result.actorProcess = Node(ProcessKey(*row.creator));
    }
    if (!target) {
        return;
    }
    // 线程绑定给出的宿主必须和明确的目标角色匹配。
    const auto targetKey = ProcessKey(*row.target);
    result.targetProcess = Node(targetKey);
    if (!row.newThread || !IsThreadRole(*row.newThread, *row.target, row.targetTidHint)) {
        return;
    }
    result.newThread = Node(GraphThreadInstance{targetKey, row.newThread->tid, row.newThread->creationFileTime});
    if (!result.finding || result.finding->kind != FindingKind::ThreadCreated) {
        return;
    }

    Edge(GraphRelation::ProcessOwnsThread, *result.targetProcess, *result.newThread, row.header.evidence);
    if (result.finding->attribution == Attribution::DirectThreadCreator && result.actorProcess) {
        Edge(GraphRelation::ThreadCreated, *result.actorProcess, *result.newThread, row.header.evidence);
    }
}

// 将执行事实关联到实际观察线程。该记录只有宿主归属边和独立的执行结论。
void GraphBuilder::AddRoles(const ExecutionObservation& row, GraphObservation& result)
{
    if (row.header.trust != InputTrust::Validated || !row.observedThread ||
        !IsThreadRole(*row.observedThread, row.observedThread->owner, 0)) {
        return;
    }

    const auto& thread = *row.observedThread;
    const auto owner = ProcessKey(thread.owner);
    result.observedThread = Node(GraphThreadInstance{owner, thread.tid, thread.creationFileTime});
    if (result.finding) {
        Edge(GraphRelation::ProcessOwnsThread, Node(owner), *result.observedThread, row.header.evidence);
    }
}

// 按本采样重新校验类型化事件，或仅登记有效的上下文锚点。
void GraphBuilder::Add(const GraphEventInput& input)
{
    GraphObservation result;
    const auto& event = input.event;
    if (event.observation) {
        const auto& evidence = std::visit([](const auto& row) -> const EvidenceRef& {
            return row.header.evidence;
        }, *event.observation);
        if (BindLocation(result, evidence)) {
            // 按阶段、结果和身份重新计算事实，避免缓存结论绕过闸门。
            const auto checked = ProjectInjectionEvent(graph.scope, *event.observation);
            result.gaps = checked.gaps;
            result.finding = checked.finding;
            if (checked.observation) {
                std::visit([&](const auto& row) { AddRoles(row, result); }, *checked.observation);
            }
            for (const auto gap : event.gaps) {
                AddGap(result, gap);
            }
        }
    } else if (BindLocation(result, input.contextEvidence)) {
        if (result.evidence->raw) {
            result.archiveContext = input.archiveContext;
        }
        for (const auto gap : event.gaps) {
            AddGap(result, gap);
        }
    }
    graph.observations.push_back(std::move(result));
}

// 为验真的 Sysmon Event 8 建来源身份边，未确认时只保留证据定位和缺口。
void GraphBuilder::Add(const GraphSysmonInput& input)
{
    GraphObservation result;
    if (BindLocation(result, input.evidence)) {
        if (input.trust != InputTrust::Validated) {
            AddGap(result, Issue::SourceUnverified);
        } else {
            // 复用 Sysmon 字段解码闸门，检查日志来源、版本和入口地址。
            const auto& original = input.observation.fields;
            const auto decoded = DecodeSysmonThreadEvent(original.targetGuid, original);
            if (decoded.state != SysmonThreadDecode::Observed || !decoded.observation ||
                decoded.observation->reportedStartAddress != input.observation.reportedStartAddress) {
                AddGap(result, Issue::InvalidNativeRecord);
            } else {
                const auto& fields = decoded.observation->fields;
                result.actorPidHint = fields.sourcePid;
                result.targetPidHint = fields.targetPid;
                result.targetTidHint = fields.newThreadId;
                // ProcessGuid 仅在 Sysmon 命名空间中聚合，线程号仍是单条报告的提示。
                result.actorProcess = Node(GraphSysmonProcess{fields.computer, fields.sourceGuid});
                result.targetProcess = Node(GraphSysmonProcess{fields.computer, fields.targetGuid});
                result.sysmon = GraphSysmonRecord{fields.recordId, fields.timeCreatedFileTime,
                    decoded.observation->reportedStartAddress};
                AddGap(result, Issue::ThreadInstanceUnknown);
                AddGap(result, Issue::ExecutionUnknown);
                Edge(GraphRelation::SysmonThreadReported, *result.actorProcess, *result.targetProcess, input.evidence);
            }
        }
    }
    graph.observations.push_back(std::move(result));
}

} // namespace

EvidenceGraph BuildCrossProcessEvidenceGraph(const SampleScope& scope, std::span<const GraphInput> input)
{
    // 使用本次传入的有界批次建立索引，返回快照时丢弃构建索引。
    GraphBuilder builder(scope);
    builder.graph.observations.reserve(input.size());
    for (const auto& row : input) {
        std::visit([&](const auto& value) { builder.Add(value); }, row);
    }
    return std::move(builder.graph);
}

} // namespace Ksword::ActionAnalyze::Detection
