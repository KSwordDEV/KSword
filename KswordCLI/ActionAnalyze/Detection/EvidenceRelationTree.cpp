#include "EvidenceRelationTree.h"

#include <array>

namespace Ksword::ActionAnalyze::Detection {

EvidenceRelationTree ProjectEvidenceRelationTree(const EvidenceGraph& graph)
{
    EvidenceRelationTree tree;
    tree.nodes.resize(graph.nodes.size());
    for (std::size_t index = 0; index < graph.edges.size(); ++index) {
        const auto& edge = graph.edges[index];
        tree.nodes[edge.from].outgoingEdges.push_back(index);
        tree.nodes[edge.to].incomingEdges.push_back(index);
    }

    for (std::size_t index = 0; index < graph.observations.size(); ++index) {
        const auto& row = graph.observations[index];
        bool linked = false; // 有明确实例角色的观察归入相应节点。
        for (const auto role : std::array{row.actorProcess, row.targetProcess, row.newThread, row.observedThread}) {
            if (role) {
                auto& observations = tree.nodes[*role].observations;
                if (observations.empty() || observations.back() != index) {
                    observations.push_back(index);
                }
                linked = true;
            }
        }
        if (linked) {
            continue;
        }
        if (row.archiveContext && row.archiveContext->apiClue) {
            tree.unresolvedCandidates.push_back({*row.archiveContext->apiClue, index});
        } else {
            tree.contextObservations.push_back(index);
        }
    }

    // 先从无入边的节点展开。首次到达目标时选择唯一的显示父边。
    std::vector<bool> seen(tree.nodes.size());
    std::vector<std::size_t> pending;
    pending.reserve(tree.nodes.size());
    const auto addRoot = [&](std::size_t node) {
        tree.roots.push_back(node);
        seen[node] = true;
        pending.push_back(node);
    };
    for (std::size_t node = 0; node < tree.nodes.size(); ++node) {
        if (tree.nodes[node].incomingEdges.empty()) {
            addRoot(node);
        }
    }
    std::size_t next = 0;
    const auto expand = [&] {
        while (next < pending.size()) {
            for (const auto index : tree.nodes[pending[next++]].outgoingEdges) {
                const auto child = graph.edges[index].to;
                if (!seen[child]) {
                    seen[child] = true;
                    tree.nodes[child].displayParentEdge = index;
                    pending.push_back(child);
                }
            }
        }
    };
    expand();

    // 不可从首批入口到达的节点逐个补入口。回边仍在出入边目录中。
    for (std::size_t node = 0; node < tree.nodes.size(); ++node) {
        if (!seen[node]) {
            addRoot(node);
            expand();
        }
    }
    return tree;
}

} // namespace Ksword::ActionAnalyze::Detection
