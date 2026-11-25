#include "../CrossProcessEvidenceGraph.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <utility>

using namespace Ksword::ActionAnalyze::Detection;
using Ksword::Evidence::OptionalU64;

namespace {

// 全部输入为同一虚构样本的内存数据。计数器分别记录断言数和失败数。
const SampleScope scope{"project", "sample", "machine", "boot"};
int assertions = 0;
int failures = 0;

// 报告单项断言，不让一次失败中断后续覆盖。
void Check(bool passed, const char* test)
{
    ++assertions;
    if (!passed) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", test);
    }
}

// 生成给定规范序号和来源的合成锚点。
EvidenceRef Anchor(std::uint64_t ordinal, const char* source, const char* group)
{
    return {scope.projectId, scope.sampleId, source, "epoch", ordinal, RawLocator{1, ordinal + 1},
        std::nullopt, group};
}

// 生成已绑定到当前样本机器及启动期的指定 PID 代次。
ProcessBinding Process(std::uint32_t pid, std::uint64_t created = 100)
{
    ProcessBinding result;
    result.machineId = scope.machineId;
    result.instance.bootId = scope.bootId;
    result.instance.pid = OptionalU64::of(pid);
    result.instance.createTime100ns = OptionalU64::of(created);
    return result;
}

// 构造调用后报告实际写长的记录，目标固定为第二个进程。
WriteObservation Write(std::uint64_t ordinal, ProcessBinding actor)
{
    WriteObservation row;
    row.header.evidence = Anchor(ordinal, "api", "api-group");
    row.header.trust = InputTrust::Validated;
    row.header.phase = Phase::Return;
    row.actor = std::move(actor);
    row.target = Process(20);
    row.outcome = Outcome::Succeeded;
    row.address = 0x1000;
    row.completedLength = 8;
    return row;
}

// 模拟目标进程中同一 TID 的一个明确创建代次。
ThreadCreationObservation Created(std::uint64_t ordinal, std::uint64_t creationTime = 101)
{
    ThreadCreationObservation row;
    row.header.evidence = Anchor(ordinal, "lifecycle", "lifecycle-group");
    row.header.trust = InputTrust::Validated;
    row.creator = Process(10);
    row.target = Process(20);
    row.newThread = ThreadBinding{*row.target, 30, creationTime};
    row.outcome = Outcome::Succeeded;
    return row;
}

// 在固定已知线程上分别构造执行确认和取指观察。
ExecutionObservation Execution(std::uint64_t ordinal, ExecutionState state)
{
    ExecutionObservation row;
    row.header.evidence = Anchor(ordinal, "execution", "execution-group");
    row.header.trust = InputTrust::Validated;
    row.observedThread = ThreadBinding{Process(20), 30, 101};
    row.instructionPointer = 0x1000;
    row.state = state;
    return row;
}

// 通过现有来源投影闸门生成图模块输入。
GraphInput Event(InjectionEvent event)
{
    return GraphEventInput{ProjectInjectionEvent(scope, std::move(event)), std::nullopt};
}

// 构造 Event 8 记录。号码与原生记录相同，用于检测是否发生错误关联。
GraphSysmonInput Sysmon(std::uint64_t ordinal, std::wstring computer = L"sample-host")
{
    SysmonThreadFields fields;
    fields.channel = kSysmonChannel;
    fields.provider = kSysmonProvider;
    fields.providerGuid = kSysmonProviderGuid;
    fields.computer = std::move(computer);
    fields.eventId = kSysmonThreadEventId;
    fields.version = kSysmonThreadEventVersion;
    fields.recordId = ordinal + 50;
    fields.timeCreatedFileTime = 101;
    fields.sourceGuid = L"{37A740D7-7285-8DCF-BC7D-270100000001}";
    fields.targetGuid = L"37a740d7-7285-8dcf-bc7d-270100000002";
    fields.sourcePid = 10;
    fields.targetPid = 20;
    fields.newThreadId = 30;
    fields.startAddress = L"0x1000";
    return {Anchor(ordinal, "sysmon", "windows-event-log"), {std::move(fields), 0x1000}, InputTrust::Validated};
}

// 检查给定的证据缺口是否实际出现在观察回执中。
bool Gap(const GraphObservation& row, Issue issue)
{
    return std::find(row.gaps.begin(), row.gaps.end(), issue) != row.gaps.end();
}

// 按关系和节点身份查找边，避免依赖数组中的节点次序。
const GraphEdge* Edge(const EvidenceGraph& graph, GraphRelation relation, const GraphNodeKey& from,
    const GraphNodeKey& to)
{
    const auto position = std::find_if(graph.edges.begin(), graph.edges.end(), [&](const GraphEdge& edge) {
        return edge.relation == relation && graph.nodes.at(edge.from) == from && graph.nodes.at(edge.to) == to;
    });
    return position == graph.edges.end() ? nullptr : &*position;
}

// 验证同类边聚合、重用代次分离和独立角色。
void TestNative()
{
    auto otherSource = Write(1, Process(10));
    otherSource.header.evidence.sourceId = "independent";
    otherSource.header.evidence.sourceGroup = "independent-group";
    // 一份原始记录可关联多个规范事件。输入倒序以及重复锚点都保留在观察数组中。
    otherSource.header.evidence.raw = RawLocator{1, 1};
    const std::array input{Event(Execution(5, ExecutionState::Executed)), Event(Write(0, Process(10))),
        Event(otherSource), Event(Write(0, Process(10))), Event(Write(2, Process(10, 120))),
        Event(Created(3)), Event(Created(4, 130)), Event(Execution(6, ExecutionState::FetchAttempt))};
    const auto graph = BuildCrossProcessEvidenceGraph(scope, input);
    constexpr GraphProcessInstance actor{10, 100}, reusedActor{10, 120}, target{20, 100};
    constexpr GraphThreadInstance thread{target, 30, 101}, reusedThread{target, 30, 130};
    // 按实例找边，并核对每条边实际保留的回读锚点。
    const auto write = Edge(graph, GraphRelation::ExternalWrite, actor, target);
    const auto reusedWrite = Edge(graph, GraphRelation::ExternalWrite, reusedActor, target);
    const auto owns = Edge(graph, GraphRelation::ProcessOwnsThread, target, thread);

    Check(graph.scope.machineId == scope.machineId && graph.scope.bootId == scope.bootId, "native-scope");
    Check(graph.nodes.size() == 5 && graph.edges.size() == 6, "native-roles-and-relations");
    Check(write && write->observations == std::vector<std::size_t>{1, 2}, "merge-edge-retain-distinct-locators");
    Check(reusedWrite && reusedWrite->observations == std::vector<std::size_t>{4}, "pid-reuse-does-not-merge");
    Check(owns && owns->observations == std::vector<std::size_t>{0, 5, 7}, "owner-evidence-from-both-role-types");
    Check(Edge(graph, GraphRelation::ThreadCreated, actor, thread), "direct-creator-only");
    Check(Edge(graph, GraphRelation::ThreadCreated, actor, reusedThread), "tid-reuse-creates-new-node");
    Check(graph.observations[1].evidence && graph.observations[1].evidence->eventOrdinal == 0, "ordinal-zero");
    Check(graph.observations[2].evidence && graph.observations[2].evidence->sourceGroup == "independent-group",
        "source-group-retained");
    Check(graph.observations[0].observedThread == graph.observations[5].newThread &&
        !graph.observations[0].newThread && !graph.observations[5].observedThread, "new-and-observed-roles-distinct");
    Check(graph.observations[0].finding && graph.observations[0].finding->kind == FindingKind::ExecutionConfirmed &&
        graph.observations[0].finding->attribution == Attribution::Unknown && !graph.observations[0].actorProcess,
        "execution-has-no-creator-attribution");
    Check(graph.observations[7].finding && graph.observations[7].finding->kind == FindingKind::ExecutionFetched,
        "fetch-is-a-separate-fact");
}

// 分别模拟缺角色、弱标识、错采样、无写长以及来源未经验证的记录。
void TestUnknowns()
{
    auto weak = Write(0, Process(10));
    weak.actor.reset();
    weak.actorPidHint = 10;
    auto entry = Write(1, Process(10));
    entry.header.phase = Phase::Entry;
    auto wrongBoot = Write(2, Process(10));
    wrongBoot.actor->instance.bootId = "different-boot";
    auto missingActual = Write(3, Process(10));
    missingActual.completedLength.reset();
    // 身份冲突和线程宿主冲突应分别报告，独立核实的目标仍能显示。
    auto conflict = Write(4, Process(20, 110));
    auto unknownCreator = Created(5);
    unknownCreator.creator.reset();
    unknownCreator.creatorPidHint = 10;
    auto wrongOwner = Created(6);
    wrongOwner.newThread->owner = Process(20, 101);
    auto rawOnly = Write(7, Process(10));
    rawOnly.header.trust = InputTrust::RawOnly;
    EventProjection context;
    context.gaps.push_back(Issue::EtwContextOnly);
    auto foreignAnchor = Anchor(8, "etw", "etw");
    foreignAnchor.sampleId = "other";
    auto cached = std::get<GraphEventInput>(Event(entry));
    cached.event.finding = Finding{FindingKind::ExternalWrite, Attribution::DirectWriter, true};
    auto failed = Write(9, Process(10));
    failed.outcome = Outcome::Failed;
    // 失败回包虽然携带非零数值，仍须经实际写入判据核实。
    const std::array input{Event(weak), GraphInput{cached}, Event(wrongBoot), Event(missingActual), Event(conflict),
        Event(unknownCreator), Event(wrongOwner), Event(rawOnly),
        GraphInput{GraphEventInput{context, Anchor(8, "etw", "etw")}},
        GraphInput{GraphEventInput{context, foreignAnchor}}, Event(failed)};
    const auto graph = BuildCrossProcessEvidenceGraph(scope, input);
    const auto& rows = graph.observations;
    Check(graph.edges.size() == 1 && graph.edges[0].relation == GraphRelation::ProcessOwnsThread, "only-verified-owner-edge");
    Check(!rows[0].actorProcess && rows[0].targetProcess && rows[0].actorPidHint == 10 &&
        Gap(rows[0], Issue::ActorInstanceUnknown), "pid-hint-never-resolves-via-neighbor");
    Check(!rows[1].finding && Gap(rows[1], Issue::WrongPhase), "cached-finding-cannot-bypass-phase");
    Check(!rows[2].actorProcess && Gap(rows[2], Issue::ActorInstanceUnknown), "foreign-boot-role-unknown");
    Check(!rows[3].finding && Gap(rows[3], Issue::ActualWriteRangeUnknown), "unknown-completion-length");
    Check(!rows[4].actorProcess && !rows[4].targetProcess && Gap(rows[4], Issue::IdentityConflict), "simultaneous-pid-conflict");
    Check(!rows[5].actorProcess && rows[5].newThread && rows[5].finding &&
        rows[5].finding->attribution == Attribution::Unknown, "thread-owner-kept-when-creator-unknown");
    Check(!rows[6].newThread && Gap(rows[6], Issue::IdentityConflict), "thread-owner-conflict");
    Check(!rows[7].actorProcess && !rows[7].targetProcess && Gap(rows[7], Issue::SourceUnverified), "raw-only-role-unknown");
    Check(rows[8].evidence && Gap(rows[8], Issue::EtwContextOnly), "context-only-anchor-retained");
    Check(!rows[9].evidence && Gap(rows[9], Issue::EvidenceUnavailable), "foreign-sample-anchor-rejected");
    Check(rows[10].actorProcess && rows[10].targetProcess && !rows[10].finding &&
        Gap(rows[10], Issue::OutcomeInconsistent), "failed-write-retains-roles-without-operation-edge");
}

// 混合两台虚构来源主机和原生事件，核对 GUID 边与原生结论的边界。
void TestSysmon()
{
    auto raw = Sysmon(3);
    raw.trust = InputTrust::RawOnly;
    auto wrongVersion = Sysmon(4);
    wrongVersion.observation.fields.version = 99;
    auto badAddress = Sysmon(5);
    badAddress.observation.reportedStartAddress = 0x2000;
    auto another = Sysmon(7);
    another.evidence.eventOrdinal.reset();
    // 原始段定位可独立使用，两次传入同一锚点只支撑边一次。
    const std::array<GraphInput, 9> input{Event(Created(0)), Sysmon(1), Sysmon(2, L"another-host"),
        raw, wrongVersion, badAddress, Sysmon(6), another, another};
    const auto graph = BuildCrossProcessEvidenceGraph(scope, input);
    const GraphSysmonProcess source{L"sample-host", L"37a740d7-7285-8dcf-bc7d-270100000001"};
    const GraphSysmonProcess target{L"sample-host", L"37a740d7-7285-8dcf-bc7d-270100000002"};
    const auto edge = Edge(graph, GraphRelation::SysmonThreadReported, source, target);
    const auto& report = graph.observations[1];
    Check(graph.nodes.size() == 7 && graph.edges.size() == 4, "sysmon-and-native-identity-spaces-distinct");
    Check(edge && edge->observations == std::vector<std::size_t>{1, 6, 7}, "report-grouping-includes-raw-only-locator-once");
    Check(report.actorProcess != graph.observations[0].actorProcess && report.targetProcess != graph.observations[0].targetProcess,
        "matching-provider-pids-cannot-link-native-processes");
    Check(report.targetTidHint == 30 && !report.newThread && !report.observedThread && !report.finding &&
        Gap(report, Issue::ExecutionUnknown) && Gap(report, Issue::ThreadInstanceUnknown), "sysmon-has-no-native-finding");
    Check(report.sysmon && report.sysmon->recordId == 51 && report.sysmon->reportedStartAddress == 0x1000 &&
        report.sysmon->timeCreatedFileTime == 101, "provider-metadata-retained");
    Check(!graph.observations[3].actorProcess && Gap(graph.observations[3], Issue::SourceUnverified), "sysmon-needs-source-validation");
    Check(Gap(graph.observations[4], Issue::InvalidNativeRecord) && Gap(graph.observations[5], Issue::InvalidNativeRecord),
        "sysmon-version-and-address-rechecked");

    // 没有机器和启动期时，以来源 GUID 提供报告，原生身份保持未知。
    auto providerScope = scope;
    providerScope.machineId.clear();
    providerScope.bootId.clear();
    const auto providerOnly = BuildCrossProcessEvidenceGraph(providerScope, input);
    Check(providerOnly.nodes.size() == 4 && providerOnly.edges.size() == 2, "provider-guid-usable-with-native-scope-unknown");
    Check(providerOnly.observations[0].evidence && Gap(providerOnly.observations[0], Issue::EvidenceUnavailable) &&
        !providerOnly.observations[0].actorProcess, "missing-native-scope-retains-anchor-with-no-instance");
    Check(BuildCrossProcessEvidenceGraph(scope, {}).edges.empty(), "empty-input-no-evidence");
}

} // namespace

// 运行离线断言，对外仅输出通过数和进程退出状态。
int main()
{
    TestNative();
    TestUnknowns();
    TestSysmon();
    std::printf("CrossProcessEvidenceGraph: %d/%d passed\n", assertions - failures, assertions);
    return failures == 0 ? 0 : 1;
}
