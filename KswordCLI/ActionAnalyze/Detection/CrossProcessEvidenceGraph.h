#pragma once

#include "InjectionDiscovery.h"

#include <compare>
#include <cstddef>
#include <span>
#include <string_view>

namespace Ksword::ActionAnalyze::Detection {

enum class GraphApiClue { MemoryWrite, ThreadCreate, ApcQueue, ThreadContext, SectionMap };

// 输入为共用归档分类器已验证的 family，包括五类 API 线索。
constexpr std::optional<GraphApiClue> GraphApiClueFromFamily(std::string_view family) noexcept
{
    if (family == "memory-write") {
        return GraphApiClue::MemoryWrite;
    }
    if (family == "thread-create") {
        return GraphApiClue::ThreadCreate;
    }
    if (family == "apc-queue") {
        return GraphApiClue::ApcQueue;
    }
    if (family == "thread-context") {
        return GraphApiClue::ThreadContext;
    }
    if (family == "section-map") {
        return GraphApiClue::SectionMap;
    }
    return std::nullopt;
}

struct GraphArchiveContext {
    std::optional<std::uint32_t> headerPid, headerTid; // 来源报头，仅供显示。
    std::optional<GraphApiClue> apiClue;                // ETW 上下文为空。
};

struct GraphEventInput {
    EventProjection event;                       // 来源适配器输出的类型化事实与缺口。
    // 只有上下文或解码失败时，用单独的定位锚点回读来源。
    std::optional<EvidenceRef> contextEvidence;
    std::optional<GraphArchiveContext> archiveContext = std::nullopt;
};

// 原生键须与 EvidenceGraph::scope 中的机器和启动期一起使用。
struct GraphProcessInstance {
    std::uint32_t pid;                             // 原生进程号。
    std::uint64_t creationFileTime;                // 该 PID 代次的创建时间。
    auto operator<=>(const GraphProcessInstance&) const = default;
};

struct GraphThreadInstance {
    GraphProcessInstance owner;                   // 线程所属的进程实例。
    std::uint32_t tid;                             // 宿主进程内关联的原生线程号。
    std::uint64_t creationFileTime;                // 该 TID 代次的创建时间。
    auto operator<=>(const GraphThreadInstance&) const = default;
};

using GraphNodeKey = std::variant<GraphProcessInstance, GraphThreadInstance>;

enum class GraphRelation {
    ExternalWrite,          // 原生进程 → 原生进程，来源证实实际写入。
    ThreadCreated,          // 原生进程 → 原生线程，来源证实创建者。
    ProcessOwnsThread,      // 原生进程 → 原生线程，来源证实线程所属实例。
};

struct GraphObservation {
    std::optional<EvidenceRef> evidence;           // 存在时可回读同采样源记录。
    // 角色是 EvidenceGraph::nodes 的下标，缺失表示未知。
    std::optional<std::size_t> actorProcess, targetProcess, newThread, observedThread;
    // 仅作来源元数据显示，不用于生成或补全实例键。
    std::uint32_t actorPidHint = 0, actorTidHint = 0, targetPidHint = 0, targetTidHint = 0;
    std::optional<Finding> finding;               // 经事实闸门核验的原生结论。
    std::vector<Issue> gaps;                      // 本条证据的缺口和校验状态。
    std::optional<GraphArchiveContext> archiveContext = std::nullopt;
};

struct GraphEdge {
    GraphRelation relation;                      // 该有向边的证据语义。
    std::size_t from, to;                         // 起点和终点在 nodes 中的索引。
    std::vector<std::size_t> observations;         // 支撑记录在 observations 中的索引。
};

struct EvidenceGraph {
    SampleScope scope;                           // 本次投影唯一的采样范围。
    std::vector<GraphNodeKey> nodes;               // 去重后的实例键目录。
    std::vector<GraphObservation> observations;    // 与调用方提交顺序一致的证据记录。
    std::vector<GraphEdge> edges;                  // 按关系类型和端点聚合的显示边。
};

// 传入调用方选定的同采样有界前缀或页，返回只读证据图。来源验真、归档水位和覆盖回执由调用方管理。
// 按边类型与端点聚合，同一规范定位在同一边只计一次。索引仅在本次投影有效。
// 共用节点表达实例身份相同，跨事件顺序和执行状态仍按原始证据判断。
EvidenceGraph BuildCrossProcessEvidenceGraph(const SampleScope& scope, std::span<const GraphEventInput> input);

} // namespace Ksword::ActionAnalyze::Detection
