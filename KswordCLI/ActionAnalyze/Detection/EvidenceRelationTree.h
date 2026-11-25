#pragma once

#include "CrossProcessEvidenceGraph.h"

namespace Ksword::ActionAnalyze::Detection {

enum class TreeEdgeBasis { Unknown, DirectFact, SourceReport };

constexpr TreeEdgeBasis EvidenceTreeBasis(GraphRelation relation) noexcept
{
    switch (relation) {
    case GraphRelation::ExternalWrite:
    case GraphRelation::ThreadCreated:
    case GraphRelation::ProcessOwnsThread:
        return TreeEdgeBasis::DirectFact;
    case GraphRelation::SysmonThreadReported:
        return TreeEdgeBasis::SourceReport;
    }
    return TreeEdgeBasis::Unknown;
}

// 树节点与图节点使用同一下标。边和观察均回查原图，保留完整依据及缺口。
struct EvidenceTreeNode {
    std::optional<std::size_t> displayParentEdge;
    std::vector<std::size_t> incomingEdges, outgoingEdges;
    std::vector<std::size_t> observations; // 该实例在观察中的明确角色。
};

struct EvidenceTreeCandidate {
    GraphApiClue clue;
    std::size_t observation; // 回查原始包及身份缺口。两端实例均未解析。
};

struct EvidenceRelationTree {
    std::vector<std::size_t> roots; // 浏览入口，可包含环内节点。
    std::vector<EvidenceTreeNode> nodes;
    std::vector<EvidenceTreeCandidate> unresolvedCandidates;
    std::vector<std::size_t> contextObservations; // 无可确认实例且不属 API 候选的观察。
};

// 输入为 BuildCrossProcessEvidenceGraph 的同采样有界结果。图及同页归档坐标由调用方保留，索引仅在该快照内有效。
// 展开出边时，只有与目标节点 displayParentEdge 相同的边进入子树，其余边显示为实例引用。
// 显示父边只决定展开位置。创建、归属、写入和来源报告的语义以图中原边为准。
[[nodiscard]] EvidenceRelationTree ProjectEvidenceRelationTree(const EvidenceGraph& graph);

} // namespace Ksword::ActionAnalyze::Detection
