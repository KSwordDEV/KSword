#include "EntityGraph.h"

#include <algorithm>
#include <utility>

namespace Ksword::Evidence {
namespace {

// 主键分隔符沿用 ObjectIdentity.cpp 的约定：这两个字节不会出现在路径、GUID 或
// 数字里，"a|b" 与 "a" + "|b" 不会撞键。
constexpr char kFieldSep = '\x1F';
constexpr char kGroupSep = '\x1E';

void AppendField(std::string& key, const std::string& value) {
    key.push_back(kFieldSep);
    key.append(value);
}

void AppendField(std::string& key, const OptionalU64& value, U64Format format) {
    key.push_back(kFieldSep);
    if (value.present) {
        key.append(FormatU64(value.value, format));
    }
}

void AppendField(std::string& key, std::uint64_t value) {
    key.push_back(kFieldSep);
    key.append(FormatU64(value, U64Format::Decimal));
}

void SortUnique(std::vector<std::string>& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

void MergeSortedUnique(std::vector<std::string>& target, const std::vector<std::string>& extra) {
    target.insert(target.end(), extra.begin(), extra.end());
    SortUnique(target);
}

// 弱身份的字段转储。宁可把同一个对象拆成两个节点，也不把两个对象合成一个
// （G-02：地址复用、名字重用都必须分开）。
void AppendProcessFields(std::string& key, const ProcessInstanceId& id) {
    AppendField(key, id.bootId);
    AppendField(key, id.pid, U64Format::Decimal);
    AppendField(key, id.createTime100ns, U64Format::Decimal);
    AppendField(key, id.eprocessAddress, U64Format::HexAddress);
    AppendField(key, id.imageName);
}

void AppendWeakFields(std::string& key, const NodeIdentity& id) {
    switch (id.kind) {
    case ObjectKind::Process:
        AppendProcessFields(key, id.process);
        break;
    case ObjectKind::Thread:
        AppendProcessFields(key, id.thread.process);
        AppendField(key, id.thread.tid, U64Format::Decimal);
        AppendField(key, id.thread.createTime100ns, U64Format::Decimal);
        AppendField(key, id.thread.ethreadAddress, U64Format::HexAddress);
        break;
    case ObjectKind::Driver:
    case ObjectKind::Module:
        AppendField(key, id.driver.bootId);
        AppendField(key, id.driver.imagePath);
        AppendField(key, id.driver.imageBase, U64Format::HexAddress);
        AppendField(key, id.driver.imageSize, U64Format::Decimal);
        AppendField(key, id.driver.timeDateStamp, U64Format::Decimal);
        AppendField(key, id.driver.checksum, U64Format::Decimal);
        AppendField(key, id.driver.pdbSignature);
        AppendField(key, id.driver.loadOrderIndex, U64Format::Decimal);
        break;
    case ObjectKind::File:
        AppendField(key, id.file.path);
        AppendField(key, id.file.volumeSerial, U64Format::Decimal);
        AppendField(key, id.file.fileId);
        AppendField(key, id.file.sizeBytes, U64Format::Decimal);
        AppendField(key, id.file.lastWriteUtc100ns, U64Format::Decimal);
        AppendField(key, id.file.contentHash);
        break;
    case ObjectKind::Handle:
        AppendProcessFields(key, id.handle.owner);
        AppendField(key, id.handle.handleValue, U64Format::Decimal);
        AppendField(key, id.handle.objectAddress, U64Format::HexAddress);
        AppendField(key, id.handle.typeName);
        break;
    case ObjectKind::Connection:
        AppendField(key, id.connection.bootId);
        AppendField(key, static_cast<std::uint64_t>(id.connection.protocol));
        AppendField(key, id.connection.localAddress);
        AppendField(key, static_cast<std::uint64_t>(id.connection.localPort));
        AppendField(key, id.connection.remoteAddress);
        AppendField(key, static_cast<std::uint64_t>(id.connection.remotePort));
        AppendField(key, id.connection.observedFirstUtc100ns, U64Format::Decimal);
        AppendField(key, id.connection.observedLastUtc100ns, U64Format::Decimal);
        AppendProcessFields(key, id.connection.owner);
        break;
    case ObjectKind::Device:
    case ObjectKind::Service:
    case ObjectKind::Unknown:
        break;
    }
    // bootId / name / instanceTag 对每一类都追加：Device、Service 与非系统对象只有
    // 这三样，其它类别多带上也只会增加区分度，不会把两个对象合到一起。
    AppendField(key, id.bootId);
    AppendField(key, id.name);
    AppendField(key, id.instanceTag);
}

// 名字/启动周期这类弱字段的三态比较，语义与 ObjectIdentity.cpp 一致。
enum class WeakCompare { Equal, Differ, Missing };

WeakCompare CompareText(const std::string& a, const std::string& b) noexcept {
    if (a.empty() || b.empty()) {
        return WeakCompare::Missing;
    }
    return a == b ? WeakCompare::Equal : WeakCompare::Differ;
}

const RelationCoverage& EmptyCoverage() {
    static const RelationCoverage kEmpty;  // 默认即 NotCollected
    return kEmpty;
}

const std::vector<std::size_t>& EmptyIndexList() {
    static const std::vector<std::size_t> kEmpty;
    return kEmpty;
}

// G-05 / G-03 共用：一次采集是否**正面证明**了"这一环确实没有数据"。
// 需要两件事同时成立：状态是 Success，且账目给出了正面覆盖证据。
bool CoverageProvesAbsence(const RelationCoverage& coverage) {
    return coverage.outcome.status == CollectionStatus::Success && coverage.coverage.fullyCovered();
}

} // namespace

// ---------------------------------------------------------------------------
// 枚举名
// ---------------------------------------------------------------------------
const char* EdgeKindName(EdgeKind kind) noexcept {
    switch (kind) {
    case EdgeKind::Unknown:          return "Unknown";
    case EdgeKind::Owns:             return "owns";
    case EdgeKind::Loads:            return "loads";
    case EdgeKind::Maps:             return "maps";
    case EdgeKind::Opens:            return "opens";
    case EdgeKind::CandidateOwner:   return "candidate-owner";
    case EdgeKind::TemporalNeighbor: return "temporal-neighbor";
    case EdgeKind::DeviceOf:         return "device-of";
    case EdgeKind::ImageOf:          return "image-of";
    case EdgeKind::ServiceOf:        return "service-of";
    case EdgeKind::TimelineEntry:    return "timeline-entry";
    }
    return "Unknown";
}

bool EdgeKindAllowsConfirmed(EdgeKind kind) noexcept {
    // candidate-owner 按定义就是"归属只有候选级证据"。它若能是 Confirmed，这一类
    // 与 owns 就没有区别了 —— 那正是"不同关系用一条相关边混掉"的另一种形态。
    return kind != EdgeKind::CandidateOwner && kind != EdgeKind::Unknown;
}

bool EdgeKindIsSymmetric(EdgeKind kind) noexcept {
    return kind == EdgeKind::TemporalNeighbor;
}

const char* EdgeDirectionName(EdgeDirection direction) noexcept {
    switch (direction) {
    case EdgeDirection::Unknown:   return "Unknown";
    case EdgeDirection::FromTo:    return "FromTo";
    case EdgeDirection::Symmetric: return "Symmetric";
    }
    return "Unknown";
}

const char* EdgeCertaintyName(EdgeCertainty certainty) noexcept {
    switch (certainty) {
    case EdgeCertainty::Unknown:   return "Unknown";
    case EdgeCertainty::Candidate: return "Candidate";
    case EdgeCertainty::Confirmed: return "Confirmed";
    }
    return "Unknown";
}

const char* TemporalValidityName(TemporalValidity validity) noexcept {
    switch (validity) {
    case TemporalValidity::Unknown:         return "Unknown";
    case TemporalValidity::Valid:           return "Valid";
    case TemporalValidity::NotValid:        return "NotValid";
    case TemporalValidity::IntervalInvalid: return "IntervalInvalid";
    }
    return "Unknown";
}

const char* NodeCategoryName(NodeCategory category) noexcept {
    switch (category) {
    case NodeCategory::SystemObject:  return "SystemObject";
    case NodeCategory::TimelineEntry: return "TimelineEntry";
    case NodeCategory::EvidenceRecord:return "EvidenceRecord";
    }
    return "SystemObject";
}

const char* NodeLifecycleName(NodeLifecycle lifecycle) noexcept {
    switch (lifecycle) {
    case NodeLifecycle::Unknown:  return "Unknown";
    case NodeLifecycle::Observed: return "Observed";
    case NodeLifecycle::Ended:    return "Ended";
    }
    return "Unknown";
}

const char* NodeAdmissionName(NodeAdmission admission) noexcept {
    switch (admission) {
    case NodeAdmission::AcceptedNew:                     return "AcceptedNew";
    case NodeAdmission::AcceptedMerged:                  return "AcceptedMerged";
    case NodeAdmission::AcceptedMergedLifecycleConflict: return "AcceptedMergedLifecycleConflict";
    case NodeAdmission::RejectedNoIdentity:              return "RejectedNoIdentity";
    case NodeAdmission::RejectedIdentityConflict:        return "RejectedIdentityConflict";
    }
    return "RejectedNoIdentity";
}

bool NodeAdmissionAccepted(NodeAdmission admission) noexcept {
    switch (admission) {
    case NodeAdmission::AcceptedNew:
    case NodeAdmission::AcceptedMerged:
    case NodeAdmission::AcceptedMergedLifecycleConflict:
        return true;
    case NodeAdmission::RejectedNoIdentity:
    case NodeAdmission::RejectedIdentityConflict:
        return false;
    }
    return false;
}

const char* EdgeAdmissionName(EdgeAdmission admission) noexcept {
    switch (admission) {
    case EdgeAdmission::Accepted:                        return "Accepted";
    case EdgeAdmission::DemotedMissingEvidence:          return "DemotedMissingEvidence";
    case EdgeAdmission::DemotedCandidateOwnerKind:       return "DemotedCandidateOwnerKind";
    case EdgeAdmission::DemotedTemporalDirectionDropped: return "DemotedTemporalDirectionDropped";
    case EdgeAdmission::RejectedUnknownKind:             return "RejectedUnknownKind";
    case EdgeAdmission::RejectedUnknownDirection:        return "RejectedUnknownDirection";
    case EdgeAdmission::RejectedMissingEndpoint:         return "RejectedMissingEndpoint";
    case EdgeAdmission::RejectedDuplicateId:             return "RejectedDuplicateId";
    case EdgeAdmission::RejectedInvalidInterval:         return "RejectedInvalidInterval";
    }
    return "RejectedUnknownKind";
}

bool EdgeAdmissionAccepted(EdgeAdmission admission) noexcept {
    switch (admission) {
    case EdgeAdmission::Accepted:
    case EdgeAdmission::DemotedMissingEvidence:
    case EdgeAdmission::DemotedCandidateOwnerKind:
    case EdgeAdmission::DemotedTemporalDirectionDropped:
        return true;
    case EdgeAdmission::RejectedUnknownKind:
    case EdgeAdmission::RejectedUnknownDirection:
    case EdgeAdmission::RejectedMissingEndpoint:
    case EdgeAdmission::RejectedDuplicateId:
    case EdgeAdmission::RejectedInvalidInterval:
        return false;
    }
    return false;
}

const char* EndpointRoleName(EndpointRole role) noexcept {
    switch (role) {
    case EndpointRole::From: return "From";
    case EndpointRole::To:   return "To";
    }
    return "To";
}

const char* ChainKindName(ChainKind kind) noexcept {
    switch (kind) {
    case ChainKind::ProcessSubjects:      return "ProcessSubjects";
    case ChainKind::DeviceToService:      return "DeviceToService";
    case ChainKind::ConnectionToTimeline: return "ConnectionToTimeline";
    }
    return "ProcessSubjects";
}

const char* StepAvailabilityName(StepAvailability availability) noexcept {
    switch (availability) {
    case StepAvailability::Present:                    return "Present";
    case StepAvailability::MissingNoData:              return "MissingNoData";
    case StepAvailability::MissingCoverageIncomplete:  return "MissingCoverageIncomplete";
    case StepAvailability::MissingNotCollected:        return "MissingNotCollected";
    case StepAvailability::MissingUnsupported:         return "MissingUnsupported";
    case StepAvailability::MissingAccessDenied:        return "MissingAccessDenied";
    case StepAvailability::MissingCollectionFailed:    return "MissingCollectionFailed";
    case StepAvailability::MissingIdentityUnusable:    return "MissingIdentityUnusable";
    case StepAvailability::MissingPreviousStepMissing: return "MissingPreviousStepMissing";
    }
    return "MissingNotCollected";
}

bool StepIsMissing(StepAvailability availability) noexcept {
    return availability != StepAvailability::Present;
}

const char* IsolationStateName(IsolationState state) noexcept {
    switch (state) {
    case IsolationState::NotIsolated:           return "NotIsolated";
    case IsolationState::OwnerMissing:          return "OwnerMissing";
    case IsolationState::ObjectUnloaded:        return "ObjectUnloaded";
    case IsolationState::SourceNotCollected:    return "SourceNotCollected";
    case IsolationState::ObservedInconsistency: return "ObservedInconsistency";
    }
    return "SourceNotCollected";
}

const char* EntityListOrderName(EntityListOrder order) noexcept {
    switch (order) {
    case EntityListOrder::ByNodeId:              return "ByNodeId";
    case EntityListOrder::ByDisplayText:         return "ByDisplayText";
    case EntityListOrder::ByKind:                return "ByKind";
    case EntityListOrder::ByEdgeCountDescending: return "ByEdgeCountDescending";
    }
    return "ByNodeId";
}

// ---------------------------------------------------------------------------
// G-02：节点身份
// ---------------------------------------------------------------------------
IdentityStrength NodeIdentity::strength() const noexcept {
    if (category != NodeCategory::SystemObject) {
        // 时间线/证据记录不是系统对象，没有生命周期身份可谈。有记录 id 就是弱身份。
        return name.empty() ? IdentityStrength::Unusable : IdentityStrength::Weak;
    }
    switch (kind) {
    case ObjectKind::Process:    return process.strength();
    case ObjectKind::Thread:     return thread.strength();
    case ObjectKind::Driver:
    case ObjectKind::Module:     return driver.strength();
    case ObjectKind::File:       return file.strength();
    case ObjectKind::Handle:     return handle.strength();
    case ObjectKind::Connection: return connection.strength();
    case ObjectKind::Device:
    case ObjectKind::Service:
        // F-03 没有为设备/服务定义生命周期身份，因此它们的强度封顶在 Weak。
        // 这一条必须显式写出来，不能让它们看起来和进程一样可靠。
        return name.empty() ? IdentityStrength::Unusable : IdentityStrength::Weak;
    case ObjectKind::Unknown:
        break;
    }
    return name.empty() ? IdentityStrength::Unusable : IdentityStrength::Weak;
}

std::string NodeIdentity::crossSessionKey() const {
    if (category != NodeCategory::SystemObject) {
        return std::string();
    }
    switch (kind) {
    case ObjectKind::Process:    return process.crossSessionKey();
    case ObjectKind::Thread:     return thread.crossSessionKey();
    case ObjectKind::Driver:
    case ObjectKind::Module:     return driver.crossSessionKey();
    case ObjectKind::File:       return file.crossSessionKey();
    case ObjectKind::Handle:     return handle.crossSessionKey();
    case ObjectKind::Connection: return connection.crossSessionKey();
    case ObjectKind::Device:
    case ObjectKind::Service:
    case ObjectKind::Unknown:
        break;
    }
    return std::string();
}

std::string NodeIdentity::nodeKey() const {
    std::string key(NodeCategoryName(category));
    key.push_back(kGroupSep);
    key.append(ObjectKindName(kind));
    key.push_back(kGroupSep);

    const std::string strong = crossSessionKey();
    if (!strong.empty()) {
        // 强身份：instanceTag 不参与，否则同一个对象会被拆成两个节点。
        key.append("strong");
        key.push_back(kGroupSep);
        key.append(strong);
        return key;
    }
    if (strength() == IdentityStrength::Unusable && instanceTag.empty()) {
        // 既没有可用身份，调用方也没有给判别标签 —— 这样的节点无法与任何别的
        // 观察区分开，进图只会制造假的"同一个对象"。
        return std::string();
    }
    key.append("weak");
    AppendWeakFields(key, *this);
    return key;
}

ObjectRef NodeIdentity::makeRef(const std::string& evidenceIdIn,
                                const std::string& displayTextIn) const {
    ObjectRef ref;
    ref.kind = kind;
    ref.key = crossSessionKey();  // 身份不足即空串，navigable() 自然为假
    ref.strength = strength();
    ref.displayText = displayTextIn;
    ref.evidenceId = evidenceIdIn;
    return ref;
}

MatchResult MatchNodeIdentity(const NodeIdentity& a, const NodeIdentity& b) noexcept {
    if (a.category != b.category || a.kind != b.kind) {
        return MatchResult::NoMatch;
    }
    if (a.category == NodeCategory::SystemObject) {
        switch (a.kind) {
        case ObjectKind::Process:    return MatchProcessInstance(a.process, b.process);
        case ObjectKind::Thread:     return MatchThreadInstance(a.thread, b.thread);
        case ObjectKind::Driver:
        case ObjectKind::Module:     return MatchDriverInstance(a.driver, b.driver);
        case ObjectKind::File:       return MatchFileIdentity(a.file, b.file);
        case ObjectKind::Handle:     return MatchHandleIdentity(a.handle, b.handle);
        case ObjectKind::Connection: return MatchConnectionIdentity(a.connection, b.connection);
        case ObjectKind::Device:
        case ObjectKind::Service:
        case ObjectKind::Unknown:
            break;
        }
    }
    // 设备/服务/记录：只有 (bootId, name, instanceTag)。矛盾能判 NoMatch，一致最多
    // 只能是 Candidate —— 没有生命周期标识就没有"确认是同一个"的资格。
    //
    // 先过门槛再比。三次 CompareText 在字段全缺时全部返回 Missing，一路落到最后的
    // Candidate —— 于是两个什么都没填的身份会被判成"可能是同一个对象"。MatchResult
    // 没有"信息不足"这一档，调用方（例如历史边定位现场）拿 Candidate 当身份证据用，
    // 所以"没有信息"必须落到 NoMatch 这一侧，而不是弱匹配那一侧。
    if (a.strength() == IdentityStrength::Unusable || b.strength() == IdentityStrength::Unusable) {
        return MatchResult::NoMatch;
    }
    const bool aBlank = a.bootId.empty() && a.name.empty() && a.instanceTag.empty();
    const bool bBlank = b.bootId.empty() && b.name.empty() && b.instanceTag.empty();
    if (aBlank || bBlank) {
        return MatchResult::NoMatch;
    }
    if (CompareText(a.bootId, b.bootId) == WeakCompare::Differ) {
        return MatchResult::NoMatch;
    }
    if (CompareText(a.name, b.name) == WeakCompare::Differ) {
        return MatchResult::NoMatch;
    }
    if (CompareText(a.instanceTag, b.instanceTag) == WeakCompare::Differ) {
        return MatchResult::NoMatch;
    }
    return MatchResult::Candidate;
}

bool GraphNode::objectNavigable() const noexcept {
    return identity.makeRef(evidenceId, displayText).navigable();
}

bool GraphNode::evidenceOpenable() const noexcept {
    return !evidenceId.empty();
}

// ---------------------------------------------------------------------------
// G-01：边
// ---------------------------------------------------------------------------
std::string DeriveEdgeId(const GraphEdge& edge) {
    std::string id(EdgeKindName(edge.kind));
    AppendField(id, edge.fromNodeId);
    AppendField(id, edge.toNodeId);
    AppendField(id, edge.validFrom100ns, U64Format::Decimal);
    AppendField(id, edge.validTo100ns, U64Format::Decimal);
    AppendField(id, edge.ruleId);
    return id;
}

TemporalValidity EdgeValidAt(const GraphEdge& edge, const OptionalU64& utc100ns) noexcept {
    // 区间反了先说出来：两端都在场且 from > to 时，下面两条 if 会对**任意**时刻都
    // 命中 NotValid，这条边在任何带时刻的筛选下永久隐身，而且没有一个取值能说出
    // "隐身是因为区间坏了"。坏区间与"此刻确实失效"不是一回事。
    if (edge.validFrom100ns.present && edge.validTo100ns.present &&
        edge.validFrom100ns.value > edge.validTo100ns.value) {
        return TemporalValidity::IntervalInvalid;
    }
    if (!utc100ns.present) {
        return TemporalValidity::Unknown;
    }
    if (!edge.validFrom100ns.present && !edge.validTo100ns.present) {
        // 有效期完全未知。这既不是"一直有效"，也不是"已失效"。
        return TemporalValidity::Unknown;
    }
    if (edge.validFrom100ns.present && utc100ns.value < edge.validFrom100ns.value) {
        return TemporalValidity::NotValid;
    }
    if (edge.validTo100ns.present && utc100ns.value >= edge.validTo100ns.value) {
        return TemporalValidity::NotValid;
    }
    // 只给了一端时，另一端仍然未知：给了起点且时刻在起点之后，但没有终点，无法
    // 断言"此刻仍然有效"。
    if (!edge.validFrom100ns.present || !edge.validTo100ns.present) {
        return TemporalValidity::Unknown;
    }
    return TemporalValidity::Valid;
}

bool EdgeMatchesFilter(const GraphEdge& edge, const EdgeFilter& filter) noexcept {
    if (!filter.kinds.empty() &&
        std::find(filter.kinds.begin(), filter.kinds.end(), edge.kind) == filter.kinds.end()) {
        return false;
    }
    if (!filter.certainties.empty() &&
        std::find(filter.certainties.begin(), filter.certainties.end(), edge.certainty) ==
            filter.certainties.end()) {
        return false;
    }
    if (filter.atUtc100ns.present) {
        const TemporalValidity validity = EdgeValidAt(edge, filter.atUtc100ns);
        switch (validity) {
        case TemporalValidity::NotValid:
            return false;
        case TemporalValidity::Unknown:
        case TemporalValidity::IntervalInvalid:
            // 未知不等于无效。区间坏了同样问不出"此刻有没有效"，因此走同一条路：
            // 默认保留，只有调用方明确要求排除未知时才丢。
            return !filter.excludeUnknownValidity;
        case TemporalValidity::Valid:
            break;
        }
    }
    return true;
}

EdgeAdmission NormalizeEdge(const GraphEdge& input, GraphEdge& out) {
    out = input;
    if (out.kind == EdgeKind::Unknown) {
        return EdgeAdmission::RejectedUnknownKind;
    }
    if (out.fromNodeId.empty() || out.toNodeId.empty()) {
        return EdgeAdmission::RejectedMissingEndpoint;
    }
    if (out.direction == EdgeDirection::Unknown) {
        // 默认构造的边不许进图：一条"方向未知"的边会被读成 from→to。
        return EdgeAdmission::RejectedUnknownDirection;
    }
    if (out.validFrom100ns.present && out.validTo100ns.present &&
        out.validFrom100ns.value > out.validTo100ns.value) {
        // G-01：有效区间是边身份的一部分（DeriveEdgeId 把两端都编进去）。一条
        // from > to 的边照样能拿到独立 id 进图，却在任何带时刻的筛选下永久不可见，
        // 而且没有任何一处说得出为什么。区间不成立就是这条边不成立，直接拒收。
        // from == to 是合法的空区间（"这段关系持续了零长时间"），不在此列。
        return EdgeAdmission::RejectedInvalidInterval;
    }

    // 证据引用去重排序：同一批证据换个顺序不应产生"另一条边"（G-08）。
    SortUnique(out.evidenceRefs);

    EdgeAdmission admission = EdgeAdmission::Accepted;

    if (EdgeKindIsSymmetric(out.kind)) {
        if (out.direction != EdgeDirection::Symmetric) {
            // 规范"不包含"里点名禁止把时间邻近画成确定因果，方向直接丢弃。
            out.direction = EdgeDirection::Symmetric;
            admission = EdgeAdmission::DemotedTemporalDirectionDropped;
        }
        if (out.toNodeId < out.fromNodeId) {
            std::swap(out.fromNodeId, out.toNodeId);
        }
    }

    if (out.certainty == EdgeCertainty::Confirmed) {
        if (out.evidenceRefs.empty()) {
            // G-01 通过条件：缺证据关系不显示为确定。优先级最高 —— 连证据都没有时，
            // 报"这一类不能确定"会让调用方以为换个 kind 就能 Confirmed。
            out.certainty = EdgeCertainty::Candidate;
            admission = EdgeAdmission::DemotedMissingEvidence;
        } else if (!EdgeKindAllowsConfirmed(out.kind)) {
            out.certainty = EdgeCertainty::Candidate;
            admission = EdgeAdmission::DemotedCandidateOwnerKind;
        }
    }

    if (out.edgeId.empty()) {
        out.edgeId = DeriveEdgeId(out);
    }
    return admission;
}

// ---------------------------------------------------------------------------
// EntityGraph
// ---------------------------------------------------------------------------
void EntityGraph::attachEdgeToNode(const std::string& nodeId, std::size_t edgeIndex) {
    const auto it = nodeIndex_.find(nodeId);
    if (it == nodeIndex_.end()) {
        // G-06：邻居还没入图 —— 记成"未保存"，绝不在这里发起任何查询。
        pending_[nodeId].push_back(edgeIndex);
        return;
    }
    adjacency_[it->second].push_back(edgeIndex);
    adjacencySorted_[it->second] = 0;
}

NodeAdmission EntityGraph::addNode(GraphNode node) {
    if (node.nodeId.empty()) {
        node.nodeId = node.identity.nodeKey();
    }
    if (node.nodeId.empty()) {
        return NodeAdmission::RejectedNoIdentity;
    }

    const auto existingIt = nodeIndex_.find(node.nodeId);
    if (existingIt != nodeIndex_.end()) {
        GraphNode& existing = nodes_[existingIt->second];
        // G-02：nodeId 相同不代表是同一个对象 —— 会话回放时 id 由已保存数据给出，
        // 两条来源不同的记录完全可能带着同一个 id 和两份互相矛盾的身份。直接合并
        // 会把第二次观察整条抹掉（"宁可拆成两个节点，也不合成一个"的反面），所以
        // 这里先问身份：nodeKey 相同说明身份内容一致，可以合并；否则只要匹配器判
        // 得出 NoMatch，就拒收并记账，绝不静默丢弃。
        if (existing.identity.nodeKey() != node.identity.nodeKey() &&
            MatchNodeIdentity(existing.identity, node.identity) == MatchResult::NoMatch) {
            ++identityConflicts_;
            return NodeAdmission::RejectedIdentityConflict;
        }
        NodeAdmission admission = NodeAdmission::AcceptedMerged;
        if (existing.lifecycle != node.lifecycle) {
            if (existing.lifecycle == NodeLifecycle::Unknown) {
                existing.lifecycle = node.lifecycle;
            } else if (node.lifecycle != NodeLifecycle::Unknown) {
                // 两次观察互相矛盾。不许挑一个"看起来更好"的，降级为未知并让调用方
                // 知道发生过冲突。
                existing.lifecycle = NodeLifecycle::Unknown;
                admission = NodeAdmission::AcceptedMergedLifecycleConflict;
            }
        }
        if (existing.displayText.empty()) {
            existing.displayText = node.displayText;
        }
        if (existing.evidenceId.empty()) {
            existing.evidenceId = node.evidenceId;
        }
        if (existing.ownerRelation == EdgeKind::Unknown) {
            existing.ownerRelation = node.ownerRelation;
            existing.ownerKind = node.ownerKind;
        }
        existing.inconsistencyObserved = existing.inconsistencyObserved || node.inconsistencyObserved;
        MergeSortedUnique(existing.inconsistencyEvidenceIds, node.inconsistencyEvidenceIds);
        if (existing.outcome.status == CollectionStatus::NotCollected) {
            existing.outcome = node.outcome;
        }
        return admission;
    }

    SortUnique(node.inconsistencyEvidenceIds);
    const std::string nodeId = node.nodeId;
    const std::size_t index = nodes_.size();
    nodes_.push_back(std::move(node));
    nodeIndex_.emplace(nodeId, index);
    adjacency_.emplace_back();
    adjacencySorted_.push_back(1);

    const auto pendingIt = pending_.find(nodeId);
    if (pendingIt != pending_.end()) {
        adjacency_[index] = std::move(pendingIt->second);
        adjacencySorted_[index] = 0;
        pending_.erase(pendingIt);
    }
    return NodeAdmission::AcceptedNew;
}

EdgeAdmission EntityGraph::addEdge(const GraphEdge& edge) {
    GraphEdge normalized;
    const EdgeAdmission admission = NormalizeEdge(edge, normalized);
    if (!EdgeAdmissionAccepted(admission)) {
        return admission;
    }
    if (edgeIndex_.find(normalized.edgeId) != edgeIndex_.end()) {
        return EdgeAdmission::RejectedDuplicateId;
    }
    const std::size_t index = edges_.size();
    const std::string fromId = normalized.fromNodeId;
    const std::string toId = normalized.toNodeId;
    const std::string edgeId = normalized.edgeId;
    edges_.push_back(std::move(normalized));
    edgeIndex_.emplace(edgeId, index);
    attachEdgeToNode(fromId, index);
    if (toId != fromId) {
        attachEdgeToNode(toId, index);
    }
    return admission;
}

const GraphNode* EntityGraph::findNode(const std::string& nodeId) const noexcept {
    const auto it = nodeIndex_.find(nodeId);
    return it == nodeIndex_.end() ? nullptr : &nodes_[it->second];
}

const GraphEdge* EntityGraph::findEdge(const std::string& edgeId) const noexcept {
    const auto it = edgeIndex_.find(edgeId);
    return it == edgeIndex_.end() ? nullptr : &edges_[it->second];
}

bool EntityGraph::nodeIndexOf(const std::string& nodeId, std::size_t& out) const noexcept {
    const auto it = nodeIndex_.find(nodeId);
    if (it == nodeIndex_.end()) {
        return false;
    }
    out = it->second;
    return true;
}

const std::vector<std::size_t>& EntityGraph::incidentEdges(std::size_t nodeIndex) const {
    if (nodeIndex >= adjacency_.size()) {
        return EmptyIndexList();
    }
    if (!adjacencySorted_[nodeIndex]) {
        std::vector<std::size_t>& list = adjacency_[nodeIndex];
        std::sort(list.begin(), list.end(), [this](std::size_t a, std::size_t b) {
            return edges_[a].edgeId < edges_[b].edgeId;
        });
        adjacencySorted_[nodeIndex] = 1;
    }
    return adjacency_[nodeIndex];
}

bool EntityGraph::declareRelationCoverage(EdgeKind kind,
                                          ObjectKind targetKind,
                                          RelationCoverage coverage) {
    if (kind == EdgeKind::Unknown) {
        // G-05：EdgeKind::Unknown 是"没填"，不是一种关系。收下它就等于给每一个没有
        // 标注 ownerRelation 的节点发了一张"这一跳我们查全了、确实没有 owner"的证明。
        return false;
    }
    coverage_[std::make_pair(kind, targetKind)] = std::move(coverage);
    return true;
}

std::vector<RelationCoverageEntry> EntityGraph::declaredRelationCoverages() const {
    std::vector<RelationCoverageEntry> entries;
    entries.reserve(coverage_.size());
    for (const auto& entry : coverage_) {
        RelationCoverageEntry out;
        out.kind = entry.first.first;
        out.targetKind = entry.first.second;
        out.coverage = entry.second;
        entries.push_back(std::move(out));
    }
    return entries;  // std::map 已按 (kind, targetKind) 有序
}

RelationCoverage EntityGraph::relationCoverage(EdgeKind kind, ObjectKind targetKind) const {
    const auto it = coverage_.find(std::make_pair(kind, targetKind));
    if (it == coverage_.end()) {
        // 没声明 = 没采。默认绝不是"采过而且是空的"。
        return EmptyCoverage();
    }
    return it->second;
}

// ---------------------------------------------------------------------------
// G-04：有界展开
// ---------------------------------------------------------------------------
namespace {

// 每条边在一次展开里的处理状态，保证同一条边不被两个端点重复计数。
enum class EdgeVisit : unsigned char {
    Unseen = 0,
    FilteredOut,
    Included,
    DeferredByLimit,
    UnsavedNeighbor,
};

struct ExpansionState final {
    std::vector<char> loaded;
    std::vector<EdgeVisit> edgeVisit;
    std::vector<std::size_t> order;
    std::uint64_t deferredEdges = 0;
};

} // namespace

ExpansionResult ExpandGraph(const EntityGraph& graph, const ExpansionRequest& request) {
    ExpansionResult result;

    ExpansionLimits limits = request.limits;
    if (!request.continueRequestedByUser) {
        // G-04：初始只给目标 + 一跳，默认 200/500。越过默认值必须由调用方显式请求
        // 继续，而不是把一个大 limits 传进来就悄悄放行。
        if (limits.maxNodes > kDefaultMaxNodes) {
            limits.maxNodes = kDefaultMaxNodes;
            result.limitsClampedToDefault = true;
        }
        if (limits.maxEdges > kDefaultMaxEdges) {
            limits.maxEdges = kDefaultMaxEdges;
            result.limitsClampedToDefault = true;
        }
        if (limits.maxHops > kDefaultMaxHops) {
            limits.maxHops = kDefaultMaxHops;
            result.hopsClampedToDefault = true;
        }
    }

    ExpansionState state;
    state.loaded.assign(graph.nodeCount(), 0);
    state.edgeVisit.assign(graph.edgeCount(), EdgeVisit::Unseen);

    std::vector<std::string> roots = request.rootNodeIds;
    SortUnique(roots);  // 输入顺序不影响装载顺序（G-08）
    bool anyRootResolved = false;
    for (const std::string& rootId : roots) {
        std::size_t index = 0;
        if (!graph.nodeIndexOf(rootId, index)) {
            UnsavedNeighbor missing;
            missing.missingNodeId = rootId;
            result.unsavedNeighbors.push_back(missing);
            result.limitationKeys.emplace_back("graph.expand.rootNotSaved");
            continue;
        }
        anyRootResolved = true;
        if (state.loaded[index]) {
            continue;
        }
        if (result.loadedNodes >= limits.maxNodes) {
            result.nodeLimitHit = true;
            result.moreAvailable = true;
            continue;
        }
        state.loaded[index] = 1;
        state.order.push_back(index);
        ++result.loadedNodes;
    }

    // 扫描一个节点的关联边。allowNewNodes 为假时只做闭包（把两端都已装载的边补齐），
    // 不再引入新节点。
    const auto scanNode = [&](std::size_t nodeIndex, bool allowNewNodes) {
        const std::string& nodeId = graph.nodes()[nodeIndex].nodeId;
        for (const std::size_t edgeIndex : graph.incidentEdges(nodeIndex)) {
            EdgeVisit& visit = state.edgeVisit[edgeIndex];
            if (visit == EdgeVisit::FilteredOut || visit == EdgeVisit::Included ||
                visit == EdgeVisit::UnsavedNeighbor) {
                continue;
            }
            if (visit == EdgeVisit::DeferredByLimit && result.loadedEdges >= limits.maxEdges) {
                // 边预算已经满了，这条边的状态不会再变：装载判在预算判之后，而它的
                // 另一端一定是已保存的节点（指向未保存邻居的边在第一次访问时就落成
                // UnsavedNeighbor 了，不会是 Deferred）。再走一遍只是白花一次哈希
                // 查找 —— 一个挂着几万条边的 hub 上，这一遍就是整个展开的主要开销。
                // 账目不受影响：deferredEdges 已经在第一次访问时记过了。
                continue;
            }
            const GraphEdge& edge = graph.edges()[edgeIndex];
            if (visit == EdgeVisit::Unseen) {
                if (!EdgeMatchesFilter(edge, request.filter)) {
                    visit = EdgeVisit::FilteredOut;
                    ++result.filteredEdgeCount;
                    continue;
                }
            }
            const std::string& otherId = (edge.fromNodeId == nodeId) ? edge.toNodeId : edge.fromNodeId;
            std::size_t otherIndex = 0;
            if (!graph.nodeIndexOf(otherId, otherIndex)) {
                // G-06：邻居没保存。记账，不查询。
                UnsavedNeighbor missing;
                missing.edgeId = edge.edgeId;
                missing.missingNodeId = otherId;
                missing.relation = edge.kind;
                result.unsavedNeighbors.push_back(missing);
                if (visit == EdgeVisit::DeferredByLimit) {
                    --state.deferredEdges;
                }
                visit = EdgeVisit::UnsavedNeighbor;
                continue;
            }
            // 边预算先判：装不下这条边就别把它指向的节点拖进来，否则会出现"图里多了
            // 一个节点，却看不见把它带进来的那条边"。
            if (result.loadedEdges >= limits.maxEdges) {
                if (visit != EdgeVisit::DeferredByLimit) {
                    visit = EdgeVisit::DeferredByLimit;
                    ++state.deferredEdges;
                }
                result.edgeLimitHit = true;
                result.moreAvailable = true;
                continue;
            }
            if (!state.loaded[otherIndex]) {
                if (!allowNewNodes || result.loadedNodes >= limits.maxNodes) {
                    if (visit != EdgeVisit::DeferredByLimit) {
                        visit = EdgeVisit::DeferredByLimit;
                        ++state.deferredEdges;
                    }
                    result.moreAvailable = true;
                    if (result.loadedNodes >= limits.maxNodes) {
                        result.nodeLimitHit = true;
                    } else {
                        // 节点上限还没到，是跳数走完了 —— 两者原因不同，不许混用。
                        result.hopLimitHit = true;
                    }
                    continue;
                }
                state.loaded[otherIndex] = 1;
                state.order.push_back(otherIndex);
                ++result.loadedNodes;
            }
            if (visit == EdgeVisit::DeferredByLimit) {
                --state.deferredEdges;
            }
            visit = EdgeVisit::Included;
            ++result.loadedEdges;
        }
    };

    std::size_t levelBegin = 0;
    std::size_t levelEnd = state.order.size();
    for (std::uint64_t hop = 0; hop < limits.maxHops; ++hop) {
        if (levelBegin >= levelEnd) {
            break;
        }
        for (std::size_t i = levelBegin; i < levelEnd; ++i) {
            scanNode(state.order[i], true);
        }
        levelBegin = levelEnd;
        levelEnd = state.order.size();
    }
    // 闭包：已装载节点之间的边一条都不能藏起来，否则图上看得见两个节点却看不见
    // 它们之间的关系。同时这一遍会把最后一层节点通向外部的边标成"还有更多"。
    for (const std::size_t nodeIndex : state.order) {
        scanNode(nodeIndex, false);
    }

    const std::uint64_t savedNodes = static_cast<std::uint64_t>(graph.nodeCount());
    const std::uint64_t savedEdges = static_cast<std::uint64_t>(graph.edgeCount());

    result.coverage.succeeded = result.loadedNodes;
    result.coverage.skipped = static_cast<std::uint64_t>(result.unsavedNeighbors.size());
    result.coverage.truncated = state.deferredEdges;
    result.coverage.limitHit = result.nodeLimitHit || result.edgeLimitHit;
    if (result.nodeLimitHit) {
        result.coverage.limit = OptionalU64::of(limits.maxNodes);
    } else if (result.edgeLimitHit) {
        result.coverage.limit = OptionalU64::of(limits.maxEdges);
    }

    // G-04：总量只有在遍历确实走到头、没有未保存邻居、**并且装载数等于图里保存的
    // 全部节点与边**时才是已知的。前两个条件在只走完一个连通分量时天然成立：一次
    // 从孤岛出发的展开既不会 moreAvailable，也不会有未保存邻居，于是 loadedNodes
    // 会被当成总量写进导出，读的人看到的是"总量已知、覆盖完整"，实际只有一半。
    // 装载数与图的规模一比，这条路就堵死了。
    const bool walkedWholeGraph = result.loadedNodes == savedNodes && result.loadedEdges == savedEdges;
    if (anyRootResolved && !result.moreAvailable && result.unsavedNeighbors.empty() &&
        walkedWholeGraph) {
        result.totalKnownNodes = OptionalU64::of(savedNodes);
        result.totalKnownEdges = OptionalU64::of(savedEdges);
    }
    // 账目里的总量取图的规模，不取本次装载数：让"这次装了多少"自己去当"总共有多少"
    // 的正面证据，fullyCovered() 就成了一句永远为真的空话。
    result.coverage.totalKnown = OptionalU64::of(savedNodes);

    result.nodeIds.reserve(state.order.size());
    for (const std::size_t nodeIndex : state.order) {
        result.nodeIds.push_back(graph.nodes()[nodeIndex].nodeId);
    }
    for (std::size_t i = 0; i < state.edgeVisit.size(); ++i) {
        if (state.edgeVisit[i] == EdgeVisit::Included) {
            result.edgeIds.push_back(graph.edges()[i].edgeId);
        }
    }
    std::sort(result.nodeIds.begin(), result.nodeIds.end());
    std::sort(result.edgeIds.begin(), result.edgeIds.end());
    std::sort(result.unsavedNeighbors.begin(), result.unsavedNeighbors.end(),
              [](const UnsavedNeighbor& a, const UnsavedNeighbor& b) {
                  if (a.missingNodeId != b.missingNodeId) {
                      return a.missingNodeId < b.missingNodeId;
                  }
                  return a.edgeId < b.edgeId;
              });

    if (roots.empty()) {
        result.limitationKeys.emplace_back("graph.expand.noRoots");
    }
    if (result.limitsClampedToDefault) {
        result.limitationKeys.emplace_back("graph.expand.limitsClampedToDefault");
    }
    if (result.hopsClampedToDefault) {
        result.limitationKeys.emplace_back("graph.expand.hopsClampedToDefault");
    }
    if (result.nodeLimitHit) {
        result.limitationKeys.emplace_back("graph.expand.nodeLimitHit");
    }
    if (result.edgeLimitHit) {
        result.limitationKeys.emplace_back("graph.expand.edgeLimitHit");
    }
    if (result.hopLimitHit) {
        result.limitationKeys.emplace_back("graph.expand.hopLimitHit");
    }
    if (result.moreAvailable) {
        result.limitationKeys.emplace_back("graph.expand.moreAvailable");
    }
    if (!result.unsavedNeighbors.empty()) {
        result.limitationKeys.emplace_back("graph.expand.unsavedNeighbors");
    }
    if (!result.totalKnownNodes.present) {
        result.limitationKeys.emplace_back("graph.expand.totalUnknown");
    }
    if (result.filteredEdgeCount > 0) {
        result.limitationKeys.emplace_back("graph.expand.filterApplied");
    }
    SortUnique(result.limitationKeys);

    // G-06：这一层没有任何现场查询出口，所以 liveQueriesIssued 一路保持默认的 0。
    // 这里**故意不再写一次 = 0**：那一句会把函数体里发生的任何自增抹平，上层那条
    // "恒为 0"的断言就永远成立、永远抓不到偷偷发起的查询。真要有查询出口，只能由
    // 那个出口自己自增，然后被这条断言抓住。
    return result;
}

// ---------------------------------------------------------------------------
// G-02：历史边定位到现场
// ---------------------------------------------------------------------------
HistoricalEdgeLiveResult ResolveHistoricalEdgeToLive(const EntityGraph& graph,
                                                     const HistoricalEdgeLiveRequest& request) {
    HistoricalEdgeLiveResult result;
    const GraphEdge* edge = graph.findEdge(request.edgeId);
    if (edge == nullptr) {
        result.reasonKey = "graph.live.edgeNotFound";
        return result;
    }
    result.edgeFound = true;
    result.savedNodeId =
        (request.endpoint == EndpointRole::To) ? edge->toNodeId : edge->fromNodeId;

    const GraphNode* node = graph.findNode(result.savedNodeId);
    if (node == nullptr) {
        result.reasonKey = "graph.live.nodeNotSaved";
        return result;
    }
    result.nodeFound = true;
    result.kind = node->identity.kind;

    if (node->identity.category != NodeCategory::SystemObject ||
        node->identity.kind != ObjectKind::Process) {
        // 目前只有进程有"现场重新解析身份"的契约（LiveNavigation.h）。别的类别不是
        // "不匹配"，是我们无法校验 —— 这两件事必须分开说。
        result.liveResolverSupported = false;
        result.identityDecision = LiveNavigationDecision::RejectIdentityUnverifiable;
        result.reasonKey = "graph.live.noResolverForKind";
        return result;
    }

    result.liveResolverSupported = true;
    result.identityDecision = ResolveProcessNavigation(node->identity.process, request.live);
    switch (result.identityDecision) {
    case LiveNavigationDecision::RejectObjectExited:
        result.reasonKey = "graph.live.objectExited";
        return result;
    case LiveNavigationDecision::RejectIdentityMismatch:
        // G-02 核心：同 PID 不同实例。绝不填 liveNodeId，也绝不发起导航。
        result.reasonKey = "graph.live.identityMismatch";
        return result;
    case LiveNavigationDecision::RejectIdentityUnverifiable:
        result.reasonKey = "graph.live.identityUnverifiable";
        return result;
    case LiveNavigationDecision::Allow:
        break;
    }

    NodeIdentity liveIdentity = node->identity;
    liveIdentity.process = request.live.liveProcess;
    result.liveNodeId = liveIdentity.nodeKey();

    NavigationRequest navigation;
    navigation.page = request.page;
    navigation.object = liveIdentity.makeRef(node->evidenceId, node->displayText);
    navigation.evidenceId = node->evidenceId;
    navigation.requireExactMatch = true;
    result.navigationAttempted = true;
    result.navigation = DecideNavigation(navigation,
                                         request.targetPageAvailable,
                                         request.objectPresentInPage,
                                         request.evidencePresentInSession);
    result.reasonKey = (result.navigation == NavigationOutcome::Delivered)
                           ? "graph.live.delivered"
                           : "graph.live.navigationRejected";
    return result;
}

// ---------------------------------------------------------------------------
// G-03：调查链
// ---------------------------------------------------------------------------
namespace {

struct NeighborScan final {
    std::vector<std::size_t> nodeIndices;   // 已按 nodeId 排序
    std::vector<std::string> nodeIds;
    std::vector<std::string> edgeIds;
    std::uint64_t matchCount = 0;
    bool truncated = false;
    bool anyIdentityUsable = false;
    bool everyPresentEvidenceOpenable = true;
    bool anyObjectNavigable = false;
    bool everyObjectNavigable = true;
    EdgeCertainty weakestCertainty = EdgeCertainty::Confirmed;
    std::string evidenceId;
};

int CertaintyRank(EdgeCertainty certainty) noexcept {
    switch (certainty) {
    case EdgeCertainty::Unknown:   return 0;
    case EdgeCertainty::Candidate: return 1;
    case EdgeCertainty::Confirmed: return 2;
    }
    return 0;
}

// 从若干起点沿某一类关系走一跳。neighborRole 说的是**邻居**在边里的位置。
NeighborScan ScanRelation(const EntityGraph& graph,
                          const std::vector<std::size_t>& sources,
                          EdgeKind relation,
                          NodeCategory expectedCategory,
                          ObjectKind expectedKind,
                          EndpointRole neighborRole,
                          const ChainOptions& options) {
    NeighborScan scan;
    std::vector<std::pair<std::string, std::size_t>> found;
    std::vector<std::string> edgeIds;
    for (const std::size_t sourceIndex : sources) {
        const std::string& sourceId = graph.nodes()[sourceIndex].nodeId;
        for (const std::size_t edgeIndex : graph.incidentEdges(sourceIndex)) {
            const GraphEdge& edge = graph.edges()[edgeIndex];
            if (edge.kind != relation) {
                continue;
            }
            if (!EdgeMatchesFilter(edge, options.filter)) {
                continue;
            }
            const std::string& neighborId =
                (neighborRole == EndpointRole::To) ? edge.toNodeId : edge.fromNodeId;
            const std::string& selfId =
                (neighborRole == EndpointRole::To) ? edge.fromNodeId : edge.toNodeId;
            if (selfId != sourceId) {
                continue;  // 方向不对，这一跳不成立
            }
            std::size_t neighborIndex = 0;
            if (!graph.nodeIndexOf(neighborId, neighborIndex)) {
                continue;  // 未保存的邻居由展开负责记账，链路这里只当作没有
            }
            const GraphNode& neighbor = graph.nodes()[neighborIndex];
            if (neighbor.identity.category != expectedCategory) {
                continue;
            }
            if (expectedKind != ObjectKind::Unknown && neighbor.identity.kind != expectedKind) {
                continue;
            }
            found.emplace_back(neighborId, neighborIndex);
            edgeIds.push_back(edge.edgeId);
            if (CertaintyRank(edge.certainty) < CertaintyRank(scan.weakestCertainty)) {
                scan.weakestCertainty = edge.certainty;
            }
        }
    }
    std::sort(found.begin(), found.end());
    found.erase(std::unique(found.begin(), found.end()), found.end());
    SortUnique(edgeIds);

    scan.matchCount = static_cast<std::uint64_t>(found.size());
    if (found.empty()) {
        scan.weakestCertainty = EdgeCertainty::Unknown;
        // 一个节点都没有的时候，"每一个都能打开证据 / 每一个都可导航"是空真。空真
        // 不能被读成"这一环可以打开来源"，因此显式落成假。
        scan.everyPresentEvidenceOpenable = false;
        scan.everyObjectNavigable = false;
    }
    for (const std::pair<std::string, std::size_t>& entry : found) {
        if (static_cast<std::uint64_t>(scan.nodeIds.size()) >= options.maxNodesPerStep) {
            scan.truncated = true;
            // 被截断就意味着还有没看过的节点，"每一个都能打开证据 / 每一个都可导航"
            // 这两句话在这一环上不再有依据。
            scan.everyPresentEvidenceOpenable = false;
            scan.everyObjectNavigable = false;
            break;
        }
        const GraphNode& neighbor = graph.nodes()[entry.second];
        scan.nodeIds.push_back(entry.first);
        scan.nodeIndices.push_back(entry.second);
        if (neighbor.identity.strength() != IdentityStrength::Unusable) {
            scan.anyIdentityUsable = true;
        }
        if (neighbor.objectNavigable()) {
            scan.anyObjectNavigable = true;
        } else {
            scan.everyObjectNavigable = false;
        }
        if (!neighbor.evidenceOpenable()) {
            scan.everyPresentEvidenceOpenable = false;
        } else if (scan.evidenceId.empty()) {
            scan.evidenceId = neighbor.evidenceId;
        }
    }
    scan.edgeIds = std::move(edgeIds);
    return scan;
}

StepAvailability DecideAvailability(const NeighborScan& scan,
                                    const RelationCoverage& coverage,
                                    bool previousStepMissing) {
    // 上一环缺失先判。上一环被判"有记录但身份不足，不能当作确定的一跳"时，从那些
    // 对象出发再走一跳照样能扫出邻居；先看 matchCount 就会把这一环报成 Present，
    // UI 上出现"上一跳不能确认，下一跳却是确定的、还能点进对象页"。起点不成立时，
    // 这一环的状态就是"上一环缺失"，与"这一环的来源没采"是两回事。
    if (previousStepMissing) {
        return StepAvailability::MissingPreviousStepMissing;
    }
    if (scan.matchCount > 0) {
        // 有记录但一个身份都不够用：不能当作确定的一跳（G-02）。
        return scan.anyIdentityUsable ? StepAvailability::Present
                                      : StepAvailability::MissingIdentityUnusable;
    }
    switch (coverage.outcome.status) {
    case CollectionStatus::Success:
        // 只有账目正面证明了完整覆盖，"没有"才是"确实没有"。
        return coverage.coverage.fullyCovered() ? StepAvailability::MissingNoData
                                                : StepAvailability::MissingCoverageIncomplete;
    case CollectionStatus::Partial:
        return StepAvailability::MissingCoverageIncomplete;
    case CollectionStatus::NotCollected:
        return StepAvailability::MissingNotCollected;
    case CollectionStatus::Unsupported:
        return StepAvailability::MissingUnsupported;
    case CollectionStatus::AccessDenied:
        return StepAvailability::MissingAccessDenied;
    case CollectionStatus::Timeout:
    case CollectionStatus::Error:
        return StepAvailability::MissingCollectionFailed;
    }
    return StepAvailability::MissingNotCollected;
}

ChainStep MakeRootStep(const EntityGraph& graph,
                       const std::string& rootNodeId,
                       const char* labelKey,
                       ObjectKind expectedKind,
                       std::vector<std::size_t>& outSources) {
    ChainStep step;
    step.index = 0;
    step.labelKey = labelKey;
    step.expectedKind = expectedKind;
    step.expectedCategory = NodeCategory::SystemObject;
    step.relationFromPrevious = EdgeKind::Unknown;

    std::size_t index = 0;
    if (!graph.nodeIndexOf(rootNodeId, index)) {
        // 根本没有这个节点：这是"没保存/没采到"，不是"这个对象不存在"。
        step.availability = StepAvailability::MissingNotCollected;
        step.outcome = CollectionOutcome::notCollected();
        return step;
    }
    const GraphNode& node = graph.nodes()[index];
    step.outcome = node.outcome;
    step.evidenceId = node.evidenceId;
    step.nodeIds.push_back(node.nodeId);
    step.matchCount = 1;
    step.anyObjectNavigable = node.objectNavigable();
    step.everyObjectNavigable = node.objectNavigable();
    step.evidenceOpenable = node.evidenceOpenable();
    if (node.identity.strength() == IdentityStrength::Unusable) {
        step.availability = StepAvailability::MissingIdentityUnusable;
    } else {
        step.availability = StepAvailability::Present;
    }
    outSources.push_back(index);
    return step;
}

ChainStep MakeRelationStep(const EntityGraph& graph,
                           std::size_t stepIndex,
                           const char* labelKey,
                           EdgeKind relation,
                           NodeCategory expectedCategory,
                           ObjectKind expectedKind,
                           EndpointRole neighborRole,
                           const std::vector<std::size_t>& sources,
                           bool previousStepMissing,
                           const ChainOptions& options,
                           std::vector<std::size_t>& outSources) {
    ChainStep step;
    step.index = stepIndex;
    step.labelKey = labelKey;
    step.relationFromPrevious = relation;
    step.expectedCategory = expectedCategory;
    step.expectedKind = expectedKind;

    const RelationCoverage coverage = graph.relationCoverage(relation, expectedKind);
    step.outcome = coverage.outcome;

    const NeighborScan scan =
        ScanRelation(graph, sources, relation, expectedCategory, expectedKind, neighborRole, options);
    step.availability = DecideAvailability(scan, coverage, previousStepMissing);
    step.matchCount = scan.matchCount;
    step.truncated = scan.truncated;
    step.nodeIds = scan.nodeIds;
    step.edgeIds = scan.edgeIds;
    step.weakestEdgeCertainty = scan.weakestCertainty;
    step.anyObjectNavigable = scan.anyObjectNavigable;
    step.everyObjectNavigable = scan.everyObjectNavigable;
    // G-03 通过条件是"每一步可打开来源详情"。这里必须是 every：只要这一环里有一个
    // 节点打不开原始证据，"这一步能打开来源"就是假话 —— 3 个线程只有 1 个带证据时
    // 用 any 会把它判成满足，UI 上画出 3 个点却只有 1 个点得开。
    step.evidenceOpenable = scan.matchCount > 0 && scan.everyPresentEvidenceOpenable;
    step.evidenceId = scan.matchCount > 0 ? scan.evidenceId : coverage.evidenceId;
    outSources = scan.nodeIndices;

    if (previousStepMissing) {
        // 起点本身不成立：这一环扫到的东西照实报（matchCount / nodeIds / edgeIds 是
        // 事实），但它不是一次确定的跳转，因此不给对象导航，也不把这些对象继续当作
        // 下一环的起点 —— 否则一条"上一跳存疑"的链会一路生出确定的下游。
        step.anyObjectNavigable = false;
        step.everyObjectNavigable = false;
        outSources.clear();
    }
    return step;
}

} // namespace

std::size_t InvestigationChain::missingStepCount() const noexcept {
    std::size_t count = 0;
    for (const ChainStep& step : steps) {
        if (StepIsMissing(step.availability)) {
            ++count;
        }
    }
    return count;
}

bool InvestigationChain::complete() const noexcept {
    // 默认构造的链 steps 为空 —— 那不是"完整"，是"什么都没有"。
    return !steps.empty() && missingStepCount() == 0;
}

bool InvestigationChain::everyPresentStepOpensSource() const noexcept {
    if (steps.empty()) {
        return false;
    }
    for (const ChainStep& step : steps) {
        if (step.availability == StepAvailability::Present && !step.evidenceOpenable) {
            return false;
        }
    }
    return true;
}

InvestigationChain BuildChain(const EntityGraph& graph,
                              ChainKind kind,
                              const std::string& rootNodeId,
                              const ChainOptions& options) {
    InvestigationChain chain;
    chain.kind = kind;
    chain.rootNodeId = rootNodeId;

    std::vector<std::size_t> rootSources;
    switch (kind) {
    case ChainKind::ProcessSubjects: {
        ChainStep root = MakeRootStep(graph, rootNodeId, "graph.chain.process.root",
                                      ObjectKind::Process, rootSources);
        chain.rootFound = !rootSources.empty();
        const bool rootMissing = StepIsMissing(root.availability);
        chain.steps.push_back(root);

        std::vector<std::size_t> unusedSources;
        chain.steps.push_back(MakeRelationStep(graph, 1, "graph.chain.process.threads",
                                               EdgeKind::Owns, NodeCategory::SystemObject,
                                               ObjectKind::Thread, EndpointRole::To, rootSources,
                                               rootMissing, options, unusedSources));
        chain.steps.push_back(MakeRelationStep(graph, 2, "graph.chain.process.modules",
                                               EdgeKind::Loads, NodeCategory::SystemObject,
                                               ObjectKind::Module, EndpointRole::To, rootSources,
                                               rootMissing, options, unusedSources));
        chain.steps.push_back(MakeRelationStep(graph, 3, "graph.chain.process.handles",
                                               EdgeKind::Owns, NodeCategory::SystemObject,
                                               ObjectKind::Handle, EndpointRole::To, rootSources,
                                               rootMissing, options, unusedSources));
        break;
    }
    case ChainKind::DeviceToService: {
        ChainStep root = MakeRootStep(graph, rootNodeId, "graph.chain.device.root",
                                      ObjectKind::Device, rootSources);
        chain.rootFound = !rootSources.empty();
        bool previousMissing = StepIsMissing(root.availability);
        chain.steps.push_back(root);

        std::vector<std::size_t> driverSources;
        ChainStep driverStep = MakeRelationStep(graph, 1, "graph.chain.device.driverObject",
                                                EdgeKind::DeviceOf, NodeCategory::SystemObject,
                                                ObjectKind::Driver, EndpointRole::To, rootSources,
                                                previousMissing, options, driverSources);
        previousMissing = StepIsMissing(driverStep.availability);
        chain.steps.push_back(driverStep);

        std::vector<std::size_t> imageSources;
        ChainStep imageStep = MakeRelationStep(graph, 2, "graph.chain.device.driverImage",
                                               EdgeKind::ImageOf, NodeCategory::SystemObject,
                                               ObjectKind::File, EndpointRole::To, driverSources,
                                               previousMissing, options, imageSources);
        previousMissing = StepIsMissing(imageStep.availability);
        chain.steps.push_back(imageStep);

        std::vector<std::size_t> serviceSources;
        chain.steps.push_back(MakeRelationStep(graph, 3, "graph.chain.device.service",
                                               EdgeKind::ServiceOf, NodeCategory::SystemObject,
                                               ObjectKind::Service, EndpointRole::To, imageSources,
                                               previousMissing, options, serviceSources));
        break;
    }
    case ChainKind::ConnectionToTimeline: {
        ChainStep root = MakeRootStep(graph, rootNodeId, "graph.chain.connection.root",
                                      ObjectKind::Connection, rootSources);
        chain.rootFound = !rootSources.empty();
        bool previousMissing = StepIsMissing(root.availability);
        chain.steps.push_back(root);

        std::vector<std::size_t> processSources;
        // 进程拥有连接，因此边是 Process --Owns--> Connection：邻居在 From 一侧。
        ChainStep processStep = MakeRelationStep(graph, 1, "graph.chain.connection.process",
                                                 EdgeKind::Owns, NodeCategory::SystemObject,
                                                 ObjectKind::Process, EndpointRole::From,
                                                 rootSources, previousMissing, options,
                                                 processSources);
        previousMissing = StepIsMissing(processStep.availability);
        chain.steps.push_back(processStep);

        std::vector<std::size_t> timelineSources;
        chain.steps.push_back(MakeRelationStep(graph, 2, "graph.chain.connection.timeline",
                                               EdgeKind::TimelineEntry, NodeCategory::TimelineEntry,
                                               ObjectKind::Unknown, EndpointRole::To,
                                               processSources, previousMissing, options,
                                               timelineSources));
        break;
    }
    }
    return chain;
}

// ---------------------------------------------------------------------------
// G-05：孤立与未知
// ---------------------------------------------------------------------------
IsolationReport ClassifyIsolation(const EntityGraph& graph,
                                  const std::string& nodeId,
                                  const EdgeFilter& filter) {
    IsolationReport report;
    report.nodeId = nodeId;
    std::size_t index = 0;
    if (!graph.nodeIndexOf(nodeId, index)) {
        report.explanationKey = "graph.isolation.nodeNotSaved";
        report.rawEvidenceMissingKey = "graph.isolation.noRawEvidence";
        report.ownerLookupOutcome = CollectionOutcome::notCollected();
        return report;  // state 保持默认的 SourceNotCollected，绝不是"正常"
    }
    report.nodeFound = true;
    const GraphNode& node = graph.nodes()[index];
    report.evidenceId = node.evidenceId;
    report.rawEvidenceAvailable = node.evidenceOpenable();
    if (!report.rawEvidenceAvailable) {
        // G-05：这一档 UI 必须说出"连原始证据都没有"，而不是灰掉一个可点的按钮。
        report.rawEvidenceMissingKey = "graph.isolation.noRawEvidence";
    }
    report.inconsistencyEvidenceIds = node.inconsistencyEvidenceIds;

    const std::vector<std::size_t>& incident = graph.incidentEdges(index);
    report.edgeCountBeforeFilter = static_cast<std::uint64_t>(incident.size());
    for (const std::size_t edgeIndex : incident) {
        if (EdgeMatchesFilter(graph.edges()[edgeIndex], filter)) {
            ++report.edgeCountAfterFilter;
        }
    }

    // G-05：ownerRelation 没填时按"来源未采集"处理。拿 EdgeKind::Unknown 去查覆盖表
    // 会读到别人为了完全不同的目的声明的那一格，一次无关的 (Unknown, Unknown) 声明
    // 就能把这个节点从"我们没查"翻成"我们查全了，确实没有 owner"—— 而这条关系从来
    // 没有被命名过。没命名就没有"查全"可言，直接落到未采集这一档。
    const bool ownerRelationDeclared = node.ownerRelation != EdgeKind::Unknown;
    const RelationCoverage ownerCoverage =
        ownerRelationDeclared ? graph.relationCoverage(node.ownerRelation, node.ownerKind)
                              : RelationCoverage{};
    report.ownerLookupOutcome = ownerCoverage.outcome;

    if (report.edgeCountAfterFilter > 0) {
        report.isolated = false;
        report.state = IsolationState::NotIsolated;
        report.explanationKey = "graph.isolation.notIsolated";
        return report;
    }
    report.isolated = true;

    // 顺序说明：只有"实际不一致"是由正面证据支撑的陈述，另外三种都是在解释"为什么
    // 没看到边"，所以它先判。其余按"能确定的先说"排：对象已卸载 -> 来源没采全 ->
    // 采全了确实没有 owner。任何一档都不表达风险。
    if (node.inconsistencyObserved) {
        report.state = IsolationState::ObservedInconsistency;
        report.explanationKey = "graph.isolation.observedInconsistency";
        return report;
    }
    if (node.lifecycle == NodeLifecycle::Ended) {
        report.state = IsolationState::ObjectUnloaded;
        report.explanationKey = "graph.isolation.objectUnloaded";
        return report;
    }
    if (!ownerRelationDeclared) {
        report.state = IsolationState::SourceNotCollected;
        report.explanationKey = "graph.isolation.ownerRelationNotDeclared";
        return report;
    }
    if (!CoverageProvesAbsence(ownerCoverage)) {
        // 没采 / 不支持 / 被拒 / 超时 / 出错 / 只采了一部分都归到这一档，但原始状态
        // 与错误码在 ownerLookupOutcome 里原样保留，调用方要区分随时能区分。
        report.state = IsolationState::SourceNotCollected;
        report.explanationKey = "graph.isolation.sourceNotCollected";
        return report;
    }
    report.state = IsolationState::OwnerMissing;
    report.explanationKey = "graph.isolation.ownerMissing";
    return report;
}

// ---------------------------------------------------------------------------
// G-06 / G-08：列表、详情、推断说明
// ---------------------------------------------------------------------------
std::vector<EntityListRow> BuildEntityList(const EntityGraph& graph,
                                           const ExpansionResult& expansion,
                                           const EdgeFilter& filter,
                                           EntityListOrder order,
                                           std::uint64_t* outMissingNodeCount) {
    std::vector<EntityListRow> rows;
    std::uint64_t missing = 0;
    rows.reserve(expansion.nodeIds.size());
    for (const std::string& nodeId : expansion.nodeIds) {
        std::size_t index = 0;
        if (!graph.nodeIndexOf(nodeId, index)) {
            // 视图里有、图里没有：跳过，但记账。行数与 loadedNodes 对不上时调用方
            // 必须能说出差在哪儿，而不是让两个数字互相矛盾。
            ++missing;
            continue;
        }
        const GraphNode& node = graph.nodes()[index];
        EntityListRow row;
        row.nodeId = node.nodeId;  // G-06：与图、详情、导出同一个 id
        row.category = node.identity.category;
        row.kind = node.identity.kind;
        row.displayText = node.displayText;
        row.evidenceId = node.evidenceId;
        row.strength = node.identity.strength();
        row.lifecycle = node.lifecycle;
        row.objectNavigable = node.objectNavigable();
        row.evidenceOpenable = node.evidenceOpenable();
        for (const std::size_t edgeIndex : graph.incidentEdges(index)) {
            if (EdgeMatchesFilter(graph.edges()[edgeIndex], filter)) {
                ++row.edgeCount;
            }
        }
        rows.push_back(std::move(row));
    }
    if (outMissingNodeCount != nullptr) {
        *outMissingNodeCount = missing;
    }

    // 所有排序都以 nodeId 兜底，保证同一数据的顺序完全确定；排序只影响显示，
    // 不影响任何结论（G-08）。
    switch (order) {
    case EntityListOrder::ByNodeId:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            return a.nodeId < b.nodeId;
        });
        break;
    case EntityListOrder::ByDisplayText:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            if (a.displayText != b.displayText) {
                return a.displayText < b.displayText;
            }
            return a.nodeId < b.nodeId;
        });
        break;
    case EntityListOrder::ByKind:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            if (a.kind != b.kind) {
                return static_cast<int>(a.kind) < static_cast<int>(b.kind);
            }
            return a.nodeId < b.nodeId;
        });
        break;
    case EntityListOrder::ByEdgeCountDescending:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            if (a.edgeCount != b.edgeCount) {
                return a.edgeCount > b.edgeCount;
            }
            return a.nodeId < b.nodeId;
        });
        break;
    }
    return rows;
}

EdgeInferenceNote DescribeEdgeInference(const GraphEdge& edge) {
    // G-01 的"缺证据关系不许显示为确定"不能只在 addEdge 那条路上成立：这个函数是
    // 头文件对外暴露的推断说明接口（G-08"推断可展开规则和来源"），调用方完全可能
    // 拿一条没进过图的边来问。原样相信传进来的 certainty，就会对外呈现出一条
    // "已确认、无需解释、零来源"的关系。因此先跑一次规范化，再复核不变式。
    GraphEdge normalized;
    NormalizeEdge(edge, normalized);

    EdgeInferenceNote note;
    note.edgeId = normalized.edgeId.empty() ? edge.edgeId : normalized.edgeId;
    note.kind = normalized.kind;
    note.certainty = normalized.certainty;
    note.ruleId = normalized.ruleId;
    note.ruleDescriptionKey = normalized.ruleDescriptionKey;
    note.evidenceRefs = normalized.evidenceRefs;
    SortUnique(note.evidenceRefs);
    // 被 NormalizeEdge 在更早的分支上拒收的边（未知类型 / 缺端点 / 方向未知 /
    // 区间不成立）走不到降级那一步，所以这里再钉一次同一条不变式。
    if (note.certainty == EdgeCertainty::Confirmed &&
        (note.evidenceRefs.empty() || !EdgeKindAllowsConfirmed(note.kind))) {
        note.certainty = EdgeCertainty::Candidate;
    }
    if (note.certainty == EdgeCertainty::Confirmed) {
        return note;
    }
    if (note.evidenceRefs.empty()) {
        note.notConfirmedReasonKey = "graph.edge.noEvidence";
    } else if (!EdgeKindAllowsConfirmed(note.kind)) {
        note.notConfirmedReasonKey = "graph.edge.candidateOwnerKind";
    } else if (note.certainty == EdgeCertainty::Unknown) {
        note.notConfirmedReasonKey = "graph.edge.certaintyUnknown";
    } else {
        note.notConfirmedReasonKey = "graph.edge.candidateEvidence";
    }
    return note;
}

NodeDetail BuildNodeDetail(const EntityGraph& graph,
                           const std::string& nodeId,
                           const EdgeFilter& filter) {
    NodeDetail detail;
    detail.nodeId = nodeId;
    detail.isolation = ClassifyIsolation(graph, nodeId, filter);
    std::size_t index = 0;
    if (!graph.nodeIndexOf(nodeId, index)) {
        return detail;
    }
    detail.nodeFound = true;
    const GraphNode& node = graph.nodes()[index];
    detail.category = node.identity.category;
    detail.kind = node.identity.kind;
    detail.displayText = node.displayText;
    detail.evidenceId = node.evidenceId;
    detail.strength = node.identity.strength();
    detail.lifecycle = node.lifecycle;

    for (const std::size_t edgeIndex : graph.incidentEdges(index)) {
        const GraphEdge& edge = graph.edges()[edgeIndex];
        if (!EdgeMatchesFilter(edge, filter)) {
            continue;
        }
        if (edge.direction == EdgeDirection::Symmetric) {
            detail.symmetricEdgeIds.push_back(edge.edgeId);
        } else if (edge.toNodeId == nodeId) {
            detail.incomingEdgeIds.push_back(edge.edgeId);
        } else {
            detail.outgoingEdgeIds.push_back(edge.edgeId);
        }
        detail.inferences.push_back(DescribeEdgeInference(edge));
    }
    SortUnique(detail.incomingEdgeIds);
    SortUnique(detail.outgoingEdgeIds);
    SortUnique(detail.symmetricEdgeIds);
    std::sort(detail.inferences.begin(), detail.inferences.end(),
              [](const EdgeInferenceNote& a, const EdgeInferenceNote& b) {
                  return a.edgeId < b.edgeId;
              });
    return detail;
}

// ---------------------------------------------------------------------------
// G-08：结论与导出
// ---------------------------------------------------------------------------
bool operator==(const GraphConclusion& a, const GraphConclusion& b) {
    return a.conclusion == b.conclusion && a.nodeCount == b.nodeCount &&
           a.edgeCountAfterFilter == b.edgeCountAfterFilter &&
           a.edgeCountBeforeFilter == b.edgeCountBeforeFilter &&
           a.confirmedEdgeCount == b.confirmedEdgeCount &&
           a.candidateEdgeCount == b.candidateEdgeCount &&
           a.unknownCertaintyEdgeCount == b.unknownCertaintyEdgeCount &&
           a.isolatedNodeCount == b.isolatedNodeCount &&
           a.ownerMissingCount == b.ownerMissingCount && a.unloadedCount == b.unloadedCount &&
           a.sourceNotCollectedCount == b.sourceNotCollectedCount &&
           a.inconsistencyCount == b.inconsistencyCount &&
           a.unusableIdentityNodeCount == b.unusableIdentityNodeCount &&
           a.nodesWithoutEvidenceCount == b.nodesWithoutEvidenceCount &&
           a.coverage.requestedBegin == b.coverage.requestedBegin &&
           a.coverage.requestedEnd == b.coverage.requestedEnd &&
           a.coverage.processedBegin == b.coverage.processedBegin &&
           a.coverage.processedEnd == b.coverage.processedEnd &&
           a.coverage.succeeded == b.coverage.succeeded && a.coverage.failed == b.coverage.failed &&
           a.coverage.skipped == b.coverage.skipped &&
           a.coverage.truncated == b.coverage.truncated &&
           a.coverage.limitHit == b.coverage.limitHit &&
           a.coverage.cancelled == b.coverage.cancelled &&
           a.coverage.limit == b.coverage.limit && a.coverage.totalKnown == b.coverage.totalKnown &&
           a.limitationKeys == b.limitationKeys;
}

GraphConclusion SummarizeGraph(const EntityGraph& graph, const EdgeFilter& filter) {
    GraphConclusion conclusion;
    conclusion.nodeCount = static_cast<std::uint64_t>(graph.nodeCount());
    conclusion.edgeCountBeforeFilter = static_cast<std::uint64_t>(graph.edgeCount());

    for (const GraphEdge& edge : graph.edges()) {
        if (!EdgeMatchesFilter(edge, filter)) {
            continue;
        }
        ++conclusion.edgeCountAfterFilter;
        switch (edge.certainty) {
        case EdgeCertainty::Confirmed: ++conclusion.confirmedEdgeCount; break;
        case EdgeCertainty::Candidate: ++conclusion.candidateEdgeCount; break;
        case EdgeCertainty::Unknown:   ++conclusion.unknownCertaintyEdgeCount; break;
        }
    }

    for (const GraphNode& node : graph.nodes()) {
        if (node.identity.strength() == IdentityStrength::Unusable) {
            ++conclusion.unusableIdentityNodeCount;
        }
        if (!node.evidenceOpenable()) {
            ++conclusion.nodesWithoutEvidenceCount;
        }
        const IsolationReport report = ClassifyIsolation(graph, node.nodeId, filter);
        if (!report.isolated) {
            continue;
        }
        ++conclusion.isolatedNodeCount;
        switch (report.state) {
        case IsolationState::OwnerMissing:          ++conclusion.ownerMissingCount; break;
        case IsolationState::ObjectUnloaded:        ++conclusion.unloadedCount; break;
        case IsolationState::SourceNotCollected:    ++conclusion.sourceNotCollectedCount; break;
        case IsolationState::ObservedInconsistency: ++conclusion.inconsistencyCount; break;
        case IsolationState::NotIsolated:           break;
        }
    }

    conclusion.coverage = graph.envelope().coverage;
    // F-05：没有观测就不能得出"未发现差异"。差异这一位只由**观察到的不一致**驱动，
    // "孤立"和"缺 owner"不是差异，更不是风险（G-05）。
    conclusion.conclusion = graph.envelope().deriveConclusion(conclusion.inconsistencyCount > 0);

    if (conclusion.unusableIdentityNodeCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.unusableIdentityNodes");
    }
    if (conclusion.nodesWithoutEvidenceCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.nodesWithoutEvidence");
    }
    if (conclusion.unknownCertaintyEdgeCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.unknownCertaintyEdges");
    }
    if (conclusion.isolatedNodeCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.isolatedNodes");
    }
    if (!conclusion.coverage.fullyCovered()) {
        conclusion.limitationKeys.emplace_back("graph.summary.coverageIncomplete");
    }
    if (!filter.kinds.empty() || !filter.certainties.empty() || filter.atUtc100ns.present) {
        conclusion.limitationKeys.emplace_back("graph.summary.filterApplied");
    }
    SortUnique(conclusion.limitationKeys);
    return conclusion;
}

namespace {

JsonValue StringArray(const std::vector<std::string>& values) {
    JsonArray array;
    array.reserve(values.size());
    for (const std::string& value : values) {
        array.push_back(JsonValue::makeString(value));
    }
    return JsonValue::makeArray(std::move(array));
}

// ---------------------------------------------------------------------------
// 回读小工具。缺字段一律回落到该字段的**默认值**：默认不等于完整，导出件里没写的
// 东西不许在导入时被补成"正常"。
// ---------------------------------------------------------------------------
const JsonValue* Child(const JsonValue& object, const char* name) noexcept {
    return object.find(name);
}

std::string ReadString(const JsonValue& object, const char* name) {
    const JsonValue* value = object.find(name);
    std::string out;
    if (value != nullptr && value->tryGetString(out)) {
        return out;
    }
    return std::string();
}

bool ReadBool(const JsonValue& object, const char* name) noexcept {
    const JsonValue* value = object.find(name);
    bool out = false;
    if (value != nullptr && value->tryGetBool(out)) {
        return out;
    }
    return false;
}

std::uint64_t ReadU64(const JsonValue& object, const char* name) noexcept {
    const JsonValue* value = object.find(name);
    std::uint64_t out = 0;
    if (value != nullptr && value->tryGetU64(out)) {
        return out;
    }
    return 0;
}

OptionalU64 ReadOptionalU64(const JsonValue& object, const char* name) noexcept {
    const JsonValue* value = object.find(name);
    OptionalU64 out;
    if (value != nullptr && value->tryGetOptionalU64(out)) {
        return out;
    }
    return OptionalU64::unset();
}

std::vector<std::string> ReadStringArray(const JsonValue& object, const char* name) {
    std::vector<std::string> out;
    const JsonValue* value = object.find(name);
    if (value == nullptr) {
        return out;
    }
    const JsonArray* array = value->asArray();
    if (array == nullptr) {
        return out;
    }
    out.reserve(array->size());
    for (const JsonValue& entry : *array) {
        std::string text;
        if (entry.tryGetString(text)) {
            out.push_back(std::move(text));
        }
    }
    return out;
}

// 枚举回读一律用同一套 *Name() 反查，名字只有一处定义，导出与导入不会各写各的。
ObjectKind ParseObjectKind(const std::string& text) noexcept {
    static constexpr ObjectKind kAll[] = {
        ObjectKind::Unknown, ObjectKind::Process, ObjectKind::Thread,   ObjectKind::Driver,
        ObjectKind::Module,  ObjectKind::File,    ObjectKind::Handle,   ObjectKind::Connection,
        ObjectKind::Device,  ObjectKind::Service,
    };
    for (const ObjectKind kind : kAll) {
        if (text == ObjectKindName(kind)) {
            return kind;
        }
    }
    return ObjectKind::Unknown;
}

NodeCategory ParseNodeCategory(const std::string& text) noexcept {
    static constexpr NodeCategory kAll[] = {
        NodeCategory::SystemObject, NodeCategory::TimelineEntry, NodeCategory::EvidenceRecord,
    };
    for (const NodeCategory category : kAll) {
        if (text == NodeCategoryName(category)) {
            return category;
        }
    }
    return NodeCategory::SystemObject;
}

NodeLifecycle ParseNodeLifecycle(const std::string& text) noexcept {
    static constexpr NodeLifecycle kAll[] = {
        NodeLifecycle::Unknown, NodeLifecycle::Observed, NodeLifecycle::Ended,
    };
    for (const NodeLifecycle lifecycle : kAll) {
        if (text == NodeLifecycleName(lifecycle)) {
            return lifecycle;
        }
    }
    return NodeLifecycle::Unknown;
}

EdgeKind ParseEdgeKind(const std::string& text) noexcept {
    static constexpr EdgeKind kAll[] = {
        EdgeKind::Unknown,  EdgeKind::Owns,             EdgeKind::Loads,
        EdgeKind::Maps,     EdgeKind::Opens,            EdgeKind::CandidateOwner,
        EdgeKind::TemporalNeighbor, EdgeKind::DeviceOf, EdgeKind::ImageOf,
        EdgeKind::ServiceOf, EdgeKind::TimelineEntry,
    };
    for (const EdgeKind kind : kAll) {
        if (text == EdgeKindName(kind)) {
            return kind;
        }
    }
    return EdgeKind::Unknown;
}

EdgeDirection ParseEdgeDirection(const std::string& text) noexcept {
    static constexpr EdgeDirection kAll[] = {
        EdgeDirection::Unknown, EdgeDirection::FromTo, EdgeDirection::Symmetric,
    };
    for (const EdgeDirection direction : kAll) {
        if (text == EdgeDirectionName(direction)) {
            return direction;
        }
    }
    return EdgeDirection::Unknown;
}

EdgeCertainty ParseEdgeCertainty(const std::string& text) noexcept {
    static constexpr EdgeCertainty kAll[] = {
        EdgeCertainty::Unknown, EdgeCertainty::Candidate, EdgeCertainty::Confirmed,
    };
    for (const EdgeCertainty certainty : kAll) {
        if (text == EdgeCertaintyName(certainty)) {
            return certainty;
        }
    }
    return EdgeCertainty::Unknown;
}

CollectionStatus ParseCollectionStatus(const std::string& text) noexcept {
    static constexpr CollectionStatus kAll[] = {
        CollectionStatus::NotCollected, CollectionStatus::Success,      CollectionStatus::Partial,
        CollectionStatus::Unsupported,  CollectionStatus::AccessDenied, CollectionStatus::Timeout,
        CollectionStatus::Error,
    };
    for (const CollectionStatus status : kAll) {
        if (text == CollectionStatusName(status)) {
            return status;
        }
    }
    return CollectionStatus::NotCollected;
}

SourceOrigin ParseSourceOrigin(const std::string& text) noexcept {
    static constexpr SourceOrigin kAll[] = {
        SourceOrigin::Unknown,      SourceOrigin::LiveKernel,   SourceOrigin::LiveUserMode,
        SourceOrigin::ExternalFile, SourceOrigin::OfflineSample,
    };
    for (const SourceOrigin origin : kAll) {
        if (text == SourceOriginName(origin)) {
            return origin;
        }
    }
    return SourceOrigin::Unknown;
}

CaptureMode ParseCaptureMode(const std::string& text) noexcept {
    static constexpr CaptureMode kAll[] = {
        CaptureMode::Unknown, CaptureMode::Snapshot, CaptureMode::Streaming, CaptureMode::Replay,
    };
    for (const CaptureMode mode : kAll) {
        if (text == CaptureModeName(mode)) {
            return mode;
        }
    }
    return CaptureMode::Unknown;
}

// DataOrigin 在 ScanBudget.h 里没有名字函数，这里就地给一对，读写共用同一组字面量。
const char* DataOriginText(DataOrigin origin) noexcept {
    return origin == DataOrigin::Session ? "Session" : "Live";
}

DataOrigin ParseDataOrigin(const std::string& text) noexcept {
    // 只有 "Live" 才是现场；认不出来一律当会话数据，宁可多拒绝一次覆盖刷新。
    return text == "Live" ? DataOrigin::Live : DataOrigin::Session;
}

JsonValue CoverageToJson(const CoverageAccount& coverage) {
    JsonObject object;
    object.emplace_back("requestedBegin",
                        JsonValue::makeOptionalU64Text(coverage.requestedBegin, U64Format::Decimal));
    object.emplace_back("requestedEnd",
                        JsonValue::makeOptionalU64Text(coverage.requestedEnd, U64Format::Decimal));
    object.emplace_back("processedBegin",
                        JsonValue::makeOptionalU64Text(coverage.processedBegin, U64Format::Decimal));
    object.emplace_back("processedEnd",
                        JsonValue::makeOptionalU64Text(coverage.processedEnd, U64Format::Decimal));
    object.emplace_back("succeeded", JsonValue::makeU64Text(coverage.succeeded, U64Format::Decimal));
    object.emplace_back("failed", JsonValue::makeU64Text(coverage.failed, U64Format::Decimal));
    object.emplace_back("skipped", JsonValue::makeU64Text(coverage.skipped, U64Format::Decimal));
    object.emplace_back("truncated", JsonValue::makeU64Text(coverage.truncated, U64Format::Decimal));
    object.emplace_back("limitHit", JsonValue::makeBool(coverage.limitHit));
    object.emplace_back("cancelled", JsonValue::makeBool(coverage.cancelled));
    object.emplace_back("limit",
                        JsonValue::makeOptionalU64Text(coverage.limit, U64Format::Decimal));
    object.emplace_back("totalKnown",
                        JsonValue::makeOptionalU64Text(coverage.totalKnown, U64Format::Decimal));
    object.emplace_back("fullyCovered", JsonValue::makeBool(coverage.fullyCovered()));
    object.emplace_back("remaining", JsonValue::makeString(coverage.describeRemaining()));
    return JsonValue::makeObject(std::move(object));
}

// fullyCovered / remaining 是从其余字段算出来的展示项，读回时一律忽略：账目的真值
// 只有一份，绝不让导出件里的一个布尔反过来定义覆盖是否完整。
CoverageAccount CoverageFromJson(const JsonValue* value) {
    CoverageAccount coverage;
    if (value == nullptr) {
        return coverage;
    }
    coverage.requestedBegin = ReadOptionalU64(*value, "requestedBegin");
    coverage.requestedEnd = ReadOptionalU64(*value, "requestedEnd");
    coverage.processedBegin = ReadOptionalU64(*value, "processedBegin");
    coverage.processedEnd = ReadOptionalU64(*value, "processedEnd");
    coverage.succeeded = ReadU64(*value, "succeeded");
    coverage.failed = ReadU64(*value, "failed");
    coverage.skipped = ReadU64(*value, "skipped");
    coverage.truncated = ReadU64(*value, "truncated");
    coverage.limitHit = ReadBool(*value, "limitHit");
    coverage.cancelled = ReadBool(*value, "cancelled");
    coverage.limit = ReadOptionalU64(*value, "limit");
    coverage.totalKnown = ReadOptionalU64(*value, "totalKnown");
    return coverage;
}

JsonValue OutcomeToJson(const CollectionOutcome& outcome) {
    JsonObject object;
    object.emplace_back("status", JsonValue::makeString(CollectionStatusName(outcome.status)));
    object.emplace_back("nativeCodeDomain", JsonValue::makeString(outcome.nativeCodeDomain));
    object.emplace_back("nativeCode",
                        JsonValue::makeOptionalU64Text(outcome.nativeCode, U64Format::Decimal));
    object.emplace_back("message", JsonValue::makeString(outcome.message));
    return JsonValue::makeObject(std::move(object));
}

CollectionOutcome OutcomeFromJson(const JsonValue* value) {
    CollectionOutcome outcome;  // 默认 NotCollected
    if (value == nullptr) {
        return outcome;
    }
    outcome.status = ParseCollectionStatus(ReadString(*value, "status"));
    outcome.nativeCodeDomain = ReadString(*value, "nativeCodeDomain");
    outcome.nativeCode = ReadOptionalU64(*value, "nativeCode");
    outcome.message = ReadString(*value, "message");
    return outcome;
}

// ---------------------------------------------------------------------------
// G-06：身份载荷。少写一个字段，重开的会话里这个对象就换了一个身份强度。
// ---------------------------------------------------------------------------
JsonValue ProcessToJson(const ProcessInstanceId& id) {
    JsonObject object;
    object.emplace_back("bootId", JsonValue::makeString(id.bootId));
    object.emplace_back("pid", JsonValue::makeOptionalU64Text(id.pid, U64Format::Decimal));
    object.emplace_back("createTime100ns",
                        JsonValue::makeOptionalU64Text(id.createTime100ns, U64Format::Decimal));
    object.emplace_back("eprocessAddress",
                        JsonValue::makeOptionalU64Text(id.eprocessAddress, U64Format::HexAddress));
    object.emplace_back("imageName", JsonValue::makeString(id.imageName));
    return JsonValue::makeObject(std::move(object));
}

ProcessInstanceId ProcessFromJson(const JsonValue* value) {
    ProcessInstanceId id;
    if (value == nullptr) {
        return id;
    }
    id.bootId = ReadString(*value, "bootId");
    id.pid = ReadOptionalU64(*value, "pid");
    id.createTime100ns = ReadOptionalU64(*value, "createTime100ns");
    id.eprocessAddress = ReadOptionalU64(*value, "eprocessAddress");
    id.imageName = ReadString(*value, "imageName");
    return id;
}

JsonValue IdentityToJson(const NodeIdentity& identity) {
    JsonObject object;
    object.emplace_back("category", JsonValue::makeString(NodeCategoryName(identity.category)));
    object.emplace_back("kind", JsonValue::makeString(ObjectKindName(identity.kind)));
    object.emplace_back("bootId", JsonValue::makeString(identity.bootId));
    object.emplace_back("name", JsonValue::makeString(identity.name));
    object.emplace_back("instanceTag", JsonValue::makeString(identity.instanceTag));

    // 只写这一 kind 用得到的那一份：nodeKey / crossSessionKey / strength /
    // MatchNodeIdentity 全部按 kind 分派，别的槽位里的字节在本模块里没有含义。
    switch (identity.kind) {
    case ObjectKind::Process:
        object.emplace_back("process", ProcessToJson(identity.process));
        break;
    case ObjectKind::Thread: {
        JsonObject thread;
        thread.emplace_back("process", ProcessToJson(identity.thread.process));
        thread.emplace_back("tid",
                            JsonValue::makeOptionalU64Text(identity.thread.tid, U64Format::Decimal));
        thread.emplace_back("createTime100ns",
                            JsonValue::makeOptionalU64Text(identity.thread.createTime100ns,
                                                           U64Format::Decimal));
        thread.emplace_back("ethreadAddress",
                            JsonValue::makeOptionalU64Text(identity.thread.ethreadAddress,
                                                           U64Format::HexAddress));
        object.emplace_back("thread", JsonValue::makeObject(std::move(thread)));
        break;
    }
    case ObjectKind::Driver:
    case ObjectKind::Module: {
        JsonObject driver;
        driver.emplace_back("bootId", JsonValue::makeString(identity.driver.bootId));
        driver.emplace_back("imagePath", JsonValue::makeString(identity.driver.imagePath));
        driver.emplace_back("imageBase",
                            JsonValue::makeOptionalU64Text(identity.driver.imageBase,
                                                           U64Format::HexAddress));
        driver.emplace_back("imageSize", JsonValue::makeOptionalU64Text(identity.driver.imageSize,
                                                                       U64Format::Decimal));
        driver.emplace_back("timeDateStamp",
                            JsonValue::makeOptionalU64Text(identity.driver.timeDateStamp,
                                                           U64Format::Decimal));
        driver.emplace_back("checksum", JsonValue::makeOptionalU64Text(identity.driver.checksum,
                                                                       U64Format::Decimal));
        driver.emplace_back("pdbSignature", JsonValue::makeString(identity.driver.pdbSignature));
        driver.emplace_back("loadOrderIndex",
                            JsonValue::makeOptionalU64Text(identity.driver.loadOrderIndex,
                                                           U64Format::Decimal));
        object.emplace_back("driver", JsonValue::makeObject(std::move(driver)));
        break;
    }
    case ObjectKind::File: {
        JsonObject file;
        file.emplace_back("path", JsonValue::makeString(identity.file.path));
        file.emplace_back("volumeSerial",
                          JsonValue::makeOptionalU64Text(identity.file.volumeSerial,
                                                         U64Format::Decimal));
        file.emplace_back("fileId", JsonValue::makeString(identity.file.fileId));
        file.emplace_back("sizeBytes", JsonValue::makeOptionalU64Text(identity.file.sizeBytes,
                                                                     U64Format::Decimal));
        file.emplace_back("lastWriteUtc100ns",
                          JsonValue::makeOptionalU64Text(identity.file.lastWriteUtc100ns,
                                                         U64Format::Decimal));
        file.emplace_back("contentHash", JsonValue::makeString(identity.file.contentHash));
        object.emplace_back("file", JsonValue::makeObject(std::move(file)));
        break;
    }
    case ObjectKind::Handle: {
        JsonObject handle;
        handle.emplace_back("owner", ProcessToJson(identity.handle.owner));
        handle.emplace_back("handleValue",
                            JsonValue::makeOptionalU64Text(identity.handle.handleValue,
                                                           U64Format::Decimal));
        handle.emplace_back("objectAddress",
                            JsonValue::makeOptionalU64Text(identity.handle.objectAddress,
                                                           U64Format::HexAddress));
        handle.emplace_back("typeName", JsonValue::makeString(identity.handle.typeName));
        object.emplace_back("handle", JsonValue::makeObject(std::move(handle)));
        break;
    }
    case ObjectKind::Connection: {
        JsonObject connection;
        connection.emplace_back("bootId", JsonValue::makeString(identity.connection.bootId));
        connection.emplace_back("protocol",
                                JsonValue::makeU64Text(identity.connection.protocol,
                                                       U64Format::Decimal));
        connection.emplace_back("localAddress",
                                JsonValue::makeString(identity.connection.localAddress));
        connection.emplace_back("localPort",
                                JsonValue::makeU64Text(identity.connection.localPort,
                                                       U64Format::Decimal));
        connection.emplace_back("remoteAddress",
                                JsonValue::makeString(identity.connection.remoteAddress));
        connection.emplace_back("remotePort",
                                JsonValue::makeU64Text(identity.connection.remotePort,
                                                       U64Format::Decimal));
        connection.emplace_back("observedFirstUtc100ns",
                                JsonValue::makeOptionalU64Text(
                                    identity.connection.observedFirstUtc100ns, U64Format::Decimal));
        connection.emplace_back("observedLastUtc100ns",
                                JsonValue::makeOptionalU64Text(
                                    identity.connection.observedLastUtc100ns, U64Format::Decimal));
        connection.emplace_back("owner", ProcessToJson(identity.connection.owner));
        object.emplace_back("connection", JsonValue::makeObject(std::move(connection)));
        break;
    }
    case ObjectKind::Device:
    case ObjectKind::Service:
    case ObjectKind::Unknown:
        // 这三类的全部身份就是上面那三个文本字段（F-03 没有为它们定义生命周期身份）。
        break;
    }
    return JsonValue::makeObject(std::move(object));
}

NodeIdentity IdentityFromJson(const JsonValue* value) {
    NodeIdentity identity;
    if (value == nullptr) {
        return identity;
    }
    identity.category = ParseNodeCategory(ReadString(*value, "category"));
    identity.kind = ParseObjectKind(ReadString(*value, "kind"));
    identity.bootId = ReadString(*value, "bootId");
    identity.name = ReadString(*value, "name");
    identity.instanceTag = ReadString(*value, "instanceTag");

    switch (identity.kind) {
    case ObjectKind::Process:
        identity.process = ProcessFromJson(Child(*value, "process"));
        break;
    case ObjectKind::Thread: {
        const JsonValue* thread = Child(*value, "thread");
        if (thread != nullptr) {
            identity.thread.process = ProcessFromJson(Child(*thread, "process"));
            identity.thread.tid = ReadOptionalU64(*thread, "tid");
            identity.thread.createTime100ns = ReadOptionalU64(*thread, "createTime100ns");
            identity.thread.ethreadAddress = ReadOptionalU64(*thread, "ethreadAddress");
        }
        break;
    }
    case ObjectKind::Driver:
    case ObjectKind::Module: {
        const JsonValue* driver = Child(*value, "driver");
        if (driver != nullptr) {
            identity.driver.bootId = ReadString(*driver, "bootId");
            identity.driver.imagePath = ReadString(*driver, "imagePath");
            identity.driver.imageBase = ReadOptionalU64(*driver, "imageBase");
            identity.driver.imageSize = ReadOptionalU64(*driver, "imageSize");
            identity.driver.timeDateStamp = ReadOptionalU64(*driver, "timeDateStamp");
            identity.driver.checksum = ReadOptionalU64(*driver, "checksum");
            identity.driver.pdbSignature = ReadString(*driver, "pdbSignature");
            identity.driver.loadOrderIndex = ReadOptionalU64(*driver, "loadOrderIndex");
        }
        break;
    }
    case ObjectKind::File: {
        const JsonValue* file = Child(*value, "file");
        if (file != nullptr) {
            identity.file.path = ReadString(*file, "path");
            identity.file.volumeSerial = ReadOptionalU64(*file, "volumeSerial");
            identity.file.fileId = ReadString(*file, "fileId");
            identity.file.sizeBytes = ReadOptionalU64(*file, "sizeBytes");
            identity.file.lastWriteUtc100ns = ReadOptionalU64(*file, "lastWriteUtc100ns");
            identity.file.contentHash = ReadString(*file, "contentHash");
        }
        break;
    }
    case ObjectKind::Handle: {
        const JsonValue* handle = Child(*value, "handle");
        if (handle != nullptr) {
            identity.handle.owner = ProcessFromJson(Child(*handle, "owner"));
            identity.handle.handleValue = ReadOptionalU64(*handle, "handleValue");
            identity.handle.objectAddress = ReadOptionalU64(*handle, "objectAddress");
            identity.handle.typeName = ReadString(*handle, "typeName");
        }
        break;
    }
    case ObjectKind::Connection: {
        const JsonValue* connection = Child(*value, "connection");
        if (connection != nullptr) {
            identity.connection.bootId = ReadString(*connection, "bootId");
            identity.connection.protocol =
                static_cast<std::uint32_t>(ReadU64(*connection, "protocol"));
            identity.connection.localAddress = ReadString(*connection, "localAddress");
            identity.connection.localPort =
                static_cast<std::uint16_t>(ReadU64(*connection, "localPort"));
            identity.connection.remoteAddress = ReadString(*connection, "remoteAddress");
            identity.connection.remotePort =
                static_cast<std::uint16_t>(ReadU64(*connection, "remotePort"));
            identity.connection.observedFirstUtc100ns =
                ReadOptionalU64(*connection, "observedFirstUtc100ns");
            identity.connection.observedLastUtc100ns =
                ReadOptionalU64(*connection, "observedLastUtc100ns");
            identity.connection.owner = ProcessFromJson(Child(*connection, "owner"));
        }
        break;
    }
    case ObjectKind::Device:
    case ObjectKind::Service:
    case ObjectKind::Unknown:
        break;
    }
    return identity;
}

JsonValue EnvelopeToJson(const EvidenceEnvelope& envelope) {
    JsonObject source;
    source.emplace_back("collectorId", JsonValue::makeString(envelope.source.collectorId));
    source.emplace_back("collectorVersion",
                        JsonValue::makeU64Text(envelope.source.collectorVersion,
                                               U64Format::Decimal));
    source.emplace_back("sourceGroup", JsonValue::makeString(envelope.source.sourceGroup));
    source.emplace_back("origin", JsonValue::makeString(SourceOriginName(envelope.source.origin)));
    source.emplace_back("dependsOn", JsonValue::makeString(envelope.source.dependsOn));

    JsonObject window;
    window.emplace_back("startUtc100ns",
                        JsonValue::makeOptionalU64Text(envelope.window.startUtc100ns,
                                                       U64Format::Decimal));
    window.emplace_back("endUtc100ns",
                        JsonValue::makeOptionalU64Text(envelope.window.endUtc100ns,
                                                       U64Format::Decimal));
    window.emplace_back("startMonotonic",
                        JsonValue::makeOptionalU64Text(envelope.window.startMonotonic,
                                                       U64Format::Decimal));
    window.emplace_back("endMonotonic",
                        JsonValue::makeOptionalU64Text(envelope.window.endMonotonic,
                                                       U64Format::Decimal));
    window.emplace_back("monotonicFrequency",
                        JsonValue::makeOptionalU64Text(envelope.window.monotonicFrequency,
                                                       U64Format::Decimal));
    window.emplace_back("machineId", JsonValue::makeString(envelope.window.machineId));
    window.emplace_back("bootId", JsonValue::makeString(envelope.window.bootId));
    window.emplace_back("sessionId", JsonValue::makeString(envelope.window.sessionId));
    window.emplace_back("mode", JsonValue::makeString(CaptureModeName(envelope.window.mode)));

    JsonObject object;
    object.emplace_back("evidenceId", JsonValue::makeString(envelope.evidenceId));
    object.emplace_back("source", JsonValue::makeObject(std::move(source)));
    object.emplace_back("window", JsonValue::makeObject(std::move(window)));
    object.emplace_back("outcome", OutcomeToJson(envelope.outcome));
    object.emplace_back("coverage", CoverageToJson(envelope.coverage));
    return JsonValue::makeObject(std::move(object));
}

EvidenceEnvelope EnvelopeFromJson(const JsonValue* value) {
    EvidenceEnvelope envelope;  // 默认 outcome 就是 NotCollected
    if (value == nullptr) {
        return envelope;
    }
    envelope.evidenceId = ReadString(*value, "evidenceId");
    const JsonValue* source = Child(*value, "source");
    if (source != nullptr) {
        envelope.source.collectorId = ReadString(*source, "collectorId");
        envelope.source.collectorVersion =
            static_cast<std::uint32_t>(ReadU64(*source, "collectorVersion"));
        envelope.source.sourceGroup = ReadString(*source, "sourceGroup");
        envelope.source.origin = ParseSourceOrigin(ReadString(*source, "origin"));
        envelope.source.dependsOn = ReadString(*source, "dependsOn");
    }
    const JsonValue* window = Child(*value, "window");
    if (window != nullptr) {
        envelope.window.startUtc100ns = ReadOptionalU64(*window, "startUtc100ns");
        envelope.window.endUtc100ns = ReadOptionalU64(*window, "endUtc100ns");
        envelope.window.startMonotonic = ReadOptionalU64(*window, "startMonotonic");
        envelope.window.endMonotonic = ReadOptionalU64(*window, "endMonotonic");
        envelope.window.monotonicFrequency = ReadOptionalU64(*window, "monotonicFrequency");
        envelope.window.machineId = ReadString(*window, "machineId");
        envelope.window.bootId = ReadString(*window, "bootId");
        envelope.window.sessionId = ReadString(*window, "sessionId");
        envelope.window.mode = ParseCaptureMode(ReadString(*window, "mode"));
    }
    envelope.outcome = OutcomeFromJson(Child(*value, "outcome"));
    envelope.coverage = CoverageFromJson(Child(*value, "coverage"));
    return envelope;
}

} // namespace

JsonValue ExportGraph(const EntityGraph& graph,
                      const ExpansionResult& expansion,
                      const EdgeFilter& filter) {
    // 节点与边先算，因为"视图里有、图里没有"的条数要写进 view 的账目里。
    std::vector<std::string> nodeIds = expansion.nodeIds;
    std::sort(nodeIds.begin(), nodeIds.end());
    JsonArray nodes;
    JsonArray isolation;
    std::uint64_t missingNodes = 0;
    for (const std::string& nodeId : nodeIds) {
        std::size_t index = 0;
        if (!graph.nodeIndexOf(nodeId, index)) {
            // 视图引用了一个图里没有的 id。跳过可以，但必须记账并说出来：导出件里
            // 写着 loadedNodes=2 却只有 1 个节点、通篇搜不到那个 id，就是自相矛盾。
            ++missingNodes;
            continue;
        }
        const GraphNode& node = graph.nodes()[index];
        JsonObject object;
        object.emplace_back("nodeId", JsonValue::makeString(node.nodeId));
        object.emplace_back("category",
                            JsonValue::makeString(NodeCategoryName(node.identity.category)));
        object.emplace_back("kind", JsonValue::makeString(ObjectKindName(node.identity.kind)));
        object.emplace_back("displayText", JsonValue::makeString(node.displayText));
        object.emplace_back("evidenceId", JsonValue::makeString(node.evidenceId));
        object.emplace_back("identityStrength",
                            JsonValue::makeString(IdentityStrengthName(node.identity.strength())));
        object.emplace_back("crossSessionKey",
                            JsonValue::makeString(node.identity.crossSessionKey()));
        object.emplace_back("lifecycle", JsonValue::makeString(NodeLifecycleName(node.lifecycle)));
        object.emplace_back("objectNavigable", JsonValue::makeBool(node.objectNavigable()));
        object.emplace_back("evidenceOpenable", JsonValue::makeBool(node.evidenceOpenable()));
        // G-05：这个节点"本该"由哪种关系连到 owner。不写出去，重开的会话里每个节点
        // 都退回 EdgeKind::Unknown，孤立判据全部塌成"来源未采集"。
        object.emplace_back("ownerRelation", JsonValue::makeString(EdgeKindName(node.ownerRelation)));
        object.emplace_back("ownerKind", JsonValue::makeString(ObjectKindName(node.ownerKind)));
        object.emplace_back("outcome", OutcomeToJson(node.outcome));
        object.emplace_back("inconsistencyObserved",
                            JsonValue::makeBool(node.inconsistencyObserved));
        object.emplace_back("inconsistencyEvidenceIds",
                            StringArray(node.inconsistencyEvidenceIds));
        // 身份载荷放最后：它是重开会话的唯一依据，上面那些 identityStrength /
        // crossSessionKey / objectNavigable 都只是从它算出来的展示项。
        object.emplace_back("identity", IdentityToJson(node.identity));
        nodes.push_back(JsonValue::makeObject(std::move(object)));

        const IsolationReport report = ClassifyIsolation(graph, nodeId, filter);
        JsonObject isolationObject;
        isolationObject.emplace_back("nodeId", JsonValue::makeString(report.nodeId));
        isolationObject.emplace_back("isolated", JsonValue::makeBool(report.isolated));
        // 键名是 "state" 而不是 "cause"：这里描述的是观察到的数据状态（有没有边、
        // 来源采没采、对象在不在），不是对任何行为的因果或性质判定。导出件是给报告
        // 和下游读的对外制品，读者看到的词必须和头文件里承诺的是同一个。
        isolationObject.emplace_back("state",
                                     JsonValue::makeString(IsolationStateName(report.state)));
        isolationObject.emplace_back("explanationKey",
                                     JsonValue::makeString(report.explanationKey));
        isolationObject.emplace_back("rawEvidenceAvailable",
                                     JsonValue::makeBool(report.rawEvidenceAvailable));
        isolationObject.emplace_back("rawEvidenceMissingKey",
                                     JsonValue::makeString(report.rawEvidenceMissingKey));
        isolationObject.emplace_back("ownerLookupOutcome",
                                     OutcomeToJson(report.ownerLookupOutcome));
        isolation.push_back(JsonValue::makeObject(std::move(isolationObject)));
    }

    std::vector<std::string> edgeIds = expansion.edgeIds;
    std::sort(edgeIds.begin(), edgeIds.end());
    JsonArray edges;
    std::uint64_t missingEdges = 0;
    for (const std::string& edgeId : edgeIds) {
        const GraphEdge* edge = graph.findEdge(edgeId);
        if (edge == nullptr) {
            ++missingEdges;
            continue;
        }
        const EdgeInferenceNote note = DescribeEdgeInference(*edge);
        JsonObject object;
        object.emplace_back("edgeId", JsonValue::makeString(edge->edgeId));
        object.emplace_back("kind", JsonValue::makeString(EdgeKindName(edge->kind)));
        object.emplace_back("direction",
                            JsonValue::makeString(EdgeDirectionName(edge->direction)));
        object.emplace_back("from", JsonValue::makeString(edge->fromNodeId));
        object.emplace_back("to", JsonValue::makeString(edge->toNodeId));
        object.emplace_back("validFrom100ns", JsonValue::makeOptionalU64Text(edge->validFrom100ns,
                                                                            U64Format::Decimal));
        object.emplace_back("validTo100ns", JsonValue::makeOptionalU64Text(edge->validTo100ns,
                                                                          U64Format::Decimal));
        object.emplace_back("certainty",
                            JsonValue::makeString(EdgeCertaintyName(edge->certainty)));
        object.emplace_back("evidenceRefs", StringArray(note.evidenceRefs));
        object.emplace_back("ruleId", JsonValue::makeString(edge->ruleId));
        object.emplace_back("ruleDescriptionKey",
                            JsonValue::makeString(edge->ruleDescriptionKey));
        object.emplace_back("notConfirmedReasonKey",
                            JsonValue::makeString(note.notConfirmedReasonKey));
        object.emplace_back("sourceGroup", JsonValue::makeString(edge->sourceGroup));
        edges.push_back(JsonValue::makeObject(std::move(object)));
    }

    std::vector<std::string> viewLimitations = expansion.limitationKeys;
    if (missingNodes > 0) {
        viewLimitations.emplace_back("graph.export.viewNodeMissing");
    }
    if (missingEdges > 0) {
        viewLimitations.emplace_back("graph.export.viewEdgeMissing");
    }
    SortUnique(viewLimitations);

    JsonObject root;
    root.emplace_back("schema", JsonValue::makeString(kEntityGraphSchema));

    // 导出有两个作用域，必须写清楚，否则读的人会把视图计数当成全集计数（G-04）。
    JsonObject scope;
    scope.emplace_back("viewIsExpansionResult", JsonValue::makeBool(true));
    scope.emplace_back("conclusionIsWholeSavedGraph", JsonValue::makeBool(true));
    root.emplace_back("scope", JsonValue::makeObject(std::move(scope)));

    JsonObject view;
    view.emplace_back("loadedNodes",
                      JsonValue::makeU64Text(expansion.loadedNodes, U64Format::Decimal));
    view.emplace_back("loadedEdges",
                      JsonValue::makeU64Text(expansion.loadedEdges, U64Format::Decimal));
    // 实际写出去的条数与被跳过的条数分开给：两个数字对不上时，读的人要能立刻看出
    // 差在哪儿，而不是自己去数数组长度。
    view.emplace_back("exportedNodes",
                      JsonValue::makeU64Text(static_cast<std::uint64_t>(nodes.size()),
                                             U64Format::Decimal));
    view.emplace_back("exportedEdges",
                      JsonValue::makeU64Text(static_cast<std::uint64_t>(edges.size()),
                                             U64Format::Decimal));
    view.emplace_back("viewNodeMissing", JsonValue::makeU64Text(missingNodes, U64Format::Decimal));
    view.emplace_back("viewEdgeMissing", JsonValue::makeU64Text(missingEdges, U64Format::Decimal));
    view.emplace_back("moreAvailable", JsonValue::makeBool(expansion.moreAvailable));
    view.emplace_back("totalKnownNodes", JsonValue::makeOptionalU64Text(expansion.totalKnownNodes,
                                                                       U64Format::Decimal));
    view.emplace_back("totalKnownEdges", JsonValue::makeOptionalU64Text(expansion.totalKnownEdges,
                                                                       U64Format::Decimal));
    view.emplace_back("nodeLimitHit", JsonValue::makeBool(expansion.nodeLimitHit));
    view.emplace_back("edgeLimitHit", JsonValue::makeBool(expansion.edgeLimitHit));
    view.emplace_back("hopLimitHit", JsonValue::makeBool(expansion.hopLimitHit));
    view.emplace_back("limitsClampedToDefault",
                      JsonValue::makeBool(expansion.limitsClampedToDefault));
    view.emplace_back("hopsClampedToDefault", JsonValue::makeBool(expansion.hopsClampedToDefault));
    view.emplace_back("filteredEdgeCount",
                      JsonValue::makeU64Text(expansion.filteredEdgeCount, U64Format::Decimal));
    view.emplace_back("liveQueriesIssued",
                      JsonValue::makeU64Text(expansion.liveQueriesIssued, U64Format::Decimal));
    view.emplace_back("coverage", CoverageToJson(expansion.coverage));
    view.emplace_back("limitationKeys", StringArray(viewLimitations));
    root.emplace_back("view", JsonValue::makeObject(std::move(view)));

    const GraphConclusion conclusion = SummarizeGraph(graph, filter);
    JsonObject summary;
    summary.emplace_back("conclusion",
                         JsonValue::makeString(AnalysisConclusionName(conclusion.conclusion)));
    summary.emplace_back("nodeCount",
                         JsonValue::makeU64Text(conclusion.nodeCount, U64Format::Decimal));
    summary.emplace_back("edgeCountBeforeFilter",
                         JsonValue::makeU64Text(conclusion.edgeCountBeforeFilter, U64Format::Decimal));
    summary.emplace_back("edgeCountAfterFilter",
                         JsonValue::makeU64Text(conclusion.edgeCountAfterFilter, U64Format::Decimal));
    summary.emplace_back("confirmedEdgeCount",
                         JsonValue::makeU64Text(conclusion.confirmedEdgeCount, U64Format::Decimal));
    summary.emplace_back("candidateEdgeCount",
                         JsonValue::makeU64Text(conclusion.candidateEdgeCount, U64Format::Decimal));
    summary.emplace_back("unknownCertaintyEdgeCount",
                         JsonValue::makeU64Text(conclusion.unknownCertaintyEdgeCount,
                                                U64Format::Decimal));
    summary.emplace_back("isolatedNodeCount",
                         JsonValue::makeU64Text(conclusion.isolatedNodeCount, U64Format::Decimal));
    summary.emplace_back("ownerMissingCount",
                         JsonValue::makeU64Text(conclusion.ownerMissingCount, U64Format::Decimal));
    summary.emplace_back("unloadedCount",
                         JsonValue::makeU64Text(conclusion.unloadedCount, U64Format::Decimal));
    summary.emplace_back("sourceNotCollectedCount",
                         JsonValue::makeU64Text(conclusion.sourceNotCollectedCount,
                                                U64Format::Decimal));
    summary.emplace_back("inconsistencyCount",
                         JsonValue::makeU64Text(conclusion.inconsistencyCount, U64Format::Decimal));
    summary.emplace_back("unusableIdentityNodeCount",
                         JsonValue::makeU64Text(conclusion.unusableIdentityNodeCount,
                                                U64Format::Decimal));
    summary.emplace_back("nodesWithoutEvidenceCount",
                         JsonValue::makeU64Text(conclusion.nodesWithoutEvidenceCount,
                                                U64Format::Decimal));
    summary.emplace_back("coverage", CoverageToJson(conclusion.coverage));
    summary.emplace_back("limitationKeys", StringArray(conclusion.limitationKeys));
    root.emplace_back("summary", JsonValue::makeObject(std::move(summary)));

    // G-06：图级别的证据 envelope。缺了它，重开的会话只能给出 NoEvidence —— 不是
    // 因为真的没有观测，而是因为观测没被搬过来。
    root.emplace_back("envelope", EnvelopeToJson(graph.envelope()));

    JsonObject policy;
    policy.emplace_back("allowLiveQueries",
                        JsonValue::makeBool(graph.offlinePolicy().allowLiveQueries));
    policy.emplace_back("origin", JsonValue::makeString(DataOriginText(graph.offlinePolicy().origin)));
    root.emplace_back("offlinePolicy", JsonValue::makeObject(std::move(policy)));

    // G-03 / G-05：关系覆盖声明。缺了它，每一条链都会从"采全了确实没有"掉回
    // "根本没采"，孤立判据也会全部塌成同一档。
    JsonArray coverageArray;
    for (const RelationCoverageEntry& entry : graph.declaredRelationCoverages()) {
        JsonObject object;
        object.emplace_back("kind", JsonValue::makeString(EdgeKindName(entry.kind)));
        object.emplace_back("targetKind", JsonValue::makeString(ObjectKindName(entry.targetKind)));
        object.emplace_back("outcome", OutcomeToJson(entry.coverage.outcome));
        object.emplace_back("coverage", CoverageToJson(entry.coverage.coverage));
        object.emplace_back("evidenceId", JsonValue::makeString(entry.coverage.evidenceId));
        coverageArray.push_back(JsonValue::makeObject(std::move(object)));
    }
    root.emplace_back("relationCoverage", JsonValue::makeArray(std::move(coverageArray)));

    // 节点与边按 id 排序输出：换输入顺序、换排序方式，导出逐字节相同（G-08）。
    root.emplace_back("nodes", JsonValue::makeArray(std::move(nodes)));
    root.emplace_back("edges", JsonValue::makeArray(std::move(edges)));
    root.emplace_back("isolation", JsonValue::makeArray(std::move(isolation)));

    JsonArray unsaved;
    for (const UnsavedNeighbor& neighbor : expansion.unsavedNeighbors) {
        JsonObject object;
        object.emplace_back("edgeId", JsonValue::makeString(neighbor.edgeId));
        object.emplace_back("missingNodeId", JsonValue::makeString(neighbor.missingNodeId));
        object.emplace_back("relation", JsonValue::makeString(EdgeKindName(neighbor.relation)));
        object.emplace_back("state", JsonValue::makeString("NotSaved"));
        unsaved.push_back(JsonValue::makeObject(std::move(object)));
    }
    root.emplace_back("unsavedNeighbors", JsonValue::makeArray(std::move(unsaved)));

    return JsonValue::makeObject(std::move(root));
}

GraphImport ImportGraph(const JsonValue& document) {
    GraphImport result;
    if (document.asObject() == nullptr) {
        result.limitationKeys.emplace_back("graph.import.notAnObject");
        return result;
    }
    if (ReadString(document, "schema") != kEntityGraphSchema) {
        // 认不出 schema 就不猜。半张图被当成整张图用，比干脆拒绝危险得多。
        result.limitationKeys.emplace_back("graph.import.schemaUnknown");
        return result;
    }
    result.schemaRecognised = true;

    result.graph.setEnvelope(EnvelopeFromJson(Child(document, "envelope")));

    const JsonValue* policy = Child(document, "offlinePolicy");
    if (policy != nullptr) {
        OfflineExpansionPolicy imported;
        imported.allowLiveQueries = ReadBool(*policy, "allowLiveQueries");
        imported.origin = ParseDataOrigin(ReadString(*policy, "origin"));
        result.graph.setOfflinePolicy(imported);
    }

    const JsonValue* coverageValue = Child(document, "relationCoverage");
    if (coverageValue != nullptr && coverageValue->asArray() != nullptr) {
        for (const JsonValue& entry : *coverageValue->asArray()) {
            RelationCoverage coverage;
            coverage.outcome = OutcomeFromJson(Child(entry, "outcome"));
            coverage.coverage = CoverageFromJson(Child(entry, "coverage"));
            coverage.evidenceId = ReadString(entry, "evidenceId");
            const bool accepted = result.graph.declareRelationCoverage(
                ParseEdgeKind(ReadString(entry, "kind")),
                ParseObjectKind(ReadString(entry, "targetKind")), std::move(coverage));
            if (accepted) {
                ++result.coverageAccepted;
            } else {
                ++result.coverageRejected;
            }
        }
    }

    const JsonValue* nodesValue = Child(document, "nodes");
    if (nodesValue != nullptr && nodesValue->asArray() != nullptr) {
        for (const JsonValue& entry : *nodesValue->asArray()) {
            GraphNode node;
            node.nodeId = ReadString(entry, "nodeId");
            node.identity = IdentityFromJson(Child(entry, "identity"));
            node.displayText = ReadString(entry, "displayText");
            node.evidenceId = ReadString(entry, "evidenceId");
            node.lifecycle = ParseNodeLifecycle(ReadString(entry, "lifecycle"));
            node.ownerRelation = ParseEdgeKind(ReadString(entry, "ownerRelation"));
            node.ownerKind = ParseObjectKind(ReadString(entry, "ownerKind"));
            node.inconsistencyObserved = ReadBool(entry, "inconsistencyObserved");
            node.inconsistencyEvidenceIds = ReadStringArray(entry, "inconsistencyEvidenceIds");
            node.outcome = OutcomeFromJson(Child(entry, "outcome"));
            if (NodeAdmissionAccepted(result.graph.addNode(std::move(node)))) {
                ++result.nodesAccepted;
            } else {
                ++result.nodesRejected;
            }
        }
    }

    const JsonValue* edgesValue = Child(document, "edges");
    if (edgesValue != nullptr && edgesValue->asArray() != nullptr) {
        for (const JsonValue& entry : *edgesValue->asArray()) {
            GraphEdge edge;
            edge.edgeId = ReadString(entry, "edgeId");
            edge.kind = ParseEdgeKind(ReadString(entry, "kind"));
            edge.direction = ParseEdgeDirection(ReadString(entry, "direction"));
            edge.fromNodeId = ReadString(entry, "from");
            edge.toNodeId = ReadString(entry, "to");
            edge.validFrom100ns = ReadOptionalU64(entry, "validFrom100ns");
            edge.validTo100ns = ReadOptionalU64(entry, "validTo100ns");
            edge.evidenceRefs = ReadStringArray(entry, "evidenceRefs");
            edge.certainty = ParseEdgeCertainty(ReadString(entry, "certainty"));
            edge.ruleId = ReadString(entry, "ruleId");
            edge.ruleDescriptionKey = ReadString(entry, "ruleDescriptionKey");
            edge.sourceGroup = ReadString(entry, "sourceGroup");
            if (EdgeAdmissionAccepted(result.graph.addEdge(edge))) {
                ++result.edgesAccepted;
            } else {
                ++result.edgesRejected;
            }
        }
    }

    if (result.nodesRejected > 0) {
        result.limitationKeys.emplace_back("graph.import.nodesRejected");
    }
    if (result.edgesRejected > 0) {
        result.limitationKeys.emplace_back("graph.import.edgesRejected");
    }
    if (result.coverageRejected > 0) {
        result.limitationKeys.emplace_back("graph.import.coverageRejected");
    }
    SortUnique(result.limitationKeys);
    return result;
}

} // namespace Ksword::Evidence
