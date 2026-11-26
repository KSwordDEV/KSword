#include "../CrossProcessEvidenceGraph.h"
#include "../ArchivedEvidenceGraph.h"
#include "../../../../shared/driver/KswordArkCallbackIoctl.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
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
GraphEventInput Event(InjectionEvent event)
{
    return GraphEventInput{ProjectInjectionEvent(scope, std::move(event)), std::nullopt};
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
    auto cached = Event(entry); // 模拟带有旧结论的入口观察，图构建须重新核对。
    cached.event.finding = Finding{FindingKind::ExternalWrite, Attribution::DirectWriter, true};
    auto failed = Write(9, Process(10));
    failed.outcome = Outcome::Failed;
    // 失败回包虽然携带非零数值，仍须经实际写入判据核实。
    const std::array input{Event(weak), cached, Event(wrongBoot), Event(missingActual), Event(conflict),
        Event(unknownCreator), Event(wrongOwner), Event(rawOnly),
        GraphEventInput{context, Anchor(8, "etw", "etw")},
        GraphEventInput{context, foreignAnchor}, Event(failed)};
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

// 采样缺少机器及启动期时，保留同采样坐标，但不生成原生实例或关系。
void TestUnknownMachine()
{
    auto incompleteScope = scope; // 仅保留冻结项目和采样身份。
    incompleteScope.machineId.clear();
    incompleteScope.bootId.clear();
    const std::array input{Event(Created(0))}; // 可通过坐标回查的合成创建行。
    const auto graph = BuildCrossProcessEvidenceGraph(incompleteScope, input); // 显示层不补造机器信息。
    Check(graph.nodes.empty() && graph.edges.empty(), "no-native-relation-without-machine-and-boot");
    const auto& observation = graph.observations.front(); // 保留同一条来源记录。
    Check(observation.evidence && Gap(observation, Issue::EvidenceUnavailable) && !observation.actorProcess,
        "missing-native-scope-retains-anchor-with-no-instance");
    Check(BuildCrossProcessEvidenceGraph(scope, {}).edges.empty(), "empty-input-no-evidence");
}

void TestThreadCreationEvidence()
{
    auto created = Created(0);
    created.creator = Process(10, 102); // This PID generation began after the target thread.
    created.creatorPidHint = 10;
    const std::array input{Event(created)};
    const auto graph = BuildCrossProcessEvidenceGraph(scope, input);
    const auto& observation = graph.observations.front();
    Check(observation.evidence && observation.actorPidHint == 10 && !observation.actorProcess &&
        Gap(observation, Issue::IdentityConflict), "later-pid-generation-cannot-be-creator");
    Check(observation.finding && observation.finding->attribution == Attribution::Unknown &&
        graph.edges.size() == 1 && graph.edges.front().relation == GraphRelation::ProcessOwnsThread,
        "creator-time-conflict-retains-target-thread-ownership");

    auto notice = Created(1);
    notice.header.trust = InputTrust::RawOnly;
    notice.creatorPidHint = 10;
    notice.creatorTidHint = 11;
    notice.targetPidHint = 20;
    notice.targetTidHint = 30;
    auto clue = Event(notice);
    clue.event.finding = Finding{FindingKind::ThreadCreated, Attribution::DirectThreadCreator, true};
    auto archiveScope = scope;
    archiveScope.machineId.clear();
    archiveScope.bootId.clear();
    const std::array rawInput{std::move(clue)};
    const auto archive = BuildCrossProcessEvidenceGraph(archiveScope, rawInput);
    const auto& raw = archive.observations.front();
    Check(raw.evidence && raw.actorPidHint == 10 && raw.actorTidHint == 11 &&
        raw.targetPidHint == 20 && raw.targetTidHint == 30 && Gap(raw, Issue::SourceUnverified),
        "raw-notification-retains-hints-without-machine-or-boot");
    Check(!raw.finding && archive.nodes.empty() && archive.edges.empty(), "raw-notification-cannot-add-relationships");
}

void TestCallbackArchiveTruncation(const std::filesystem::path& root)
{
    using namespace Ksword::ActionAnalyze;

    ProjectDocument writer;
    const auto created = writer.Create(root.wstring(), {"Callback graph fixture", "Synthetic archive only"});
    Check(static_cast<bool>(created), "callback-project-create");
    if (!created) return;

    SampleInfo sample;
    const auto registered = writer.CreateSample("Thread create context", sample);
    Check(static_cast<bool>(registered), "callback-sample-create");
    if (!registered) return;

    KSWORD_ARK_CALLBACK_MONITOR_EVENT event{};
    event.version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    event.size = static_cast<unsigned long>(sizeof(event));
    event.sequence = 107;
    event.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    event.operation = KSWORD_ARK_THREAD_OP_CREATE;
    event.originatingProcessId = 10;
    event.originatingThreadId = 11;
    event.targetProcessId = 20;
    event.targetThreadId = 30;
    auto events = std::array{event, event, event};
    events[0].flags = KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_PRESENT |
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_TRUNCATED;
    std::fill_n(events[0].processName, KSWORD_ARK_CALLBACK_MONITOR_PROCESS_NAME_CHARS - 1, L'n');
    events[1].sequence = 108;
    events[1].flags = KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_PRESENT |
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_TRUNCATED;
    std::fill_n(events[1].path, KSWORD_ARK_CALLBACK_MONITOR_PATH_CHARS - 1, L'p');
    events[2].sequence = 109;
    events[2].flags = KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_PRESENT |
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_PRESENT;
    events[2].processName[0] = L'n';
    events[2].path[0] = L'p';
    const ProjectCallbackEvidencePlan plan{"11111111-1111-4111-8111-111111111111", 106, 8};
    const ProjectCallbackEvidenceEnd end{CallbackBatchState::CaughtUp, 109, 109, 3, 0, std::nullopt};
    ProjectCallbackEvidenceReceipt receipt;
    const auto written = WriteInitialCallbackEvidence(writer, sample.sampleId, plan, end, events, receipt);
    Check(static_cast<bool>(written), "callback-raw-first-segment");
    if (!written) return;
    writer.Close();

    ProjectDocument reader;
    const auto opened = reader.Open(root.wstring());
    Check(static_cast<bool>(opened), "callback-reopen-read-only");
    if (!opened) return;
    ArchivedGraphPage page;
    const auto status = ReadArchivedEvidenceGraph(reader, {sample.sampleId, 1, 0, events.size(), receipt.prefixSha256}, page);
    Check(status && page.source == ArchivedGraphSource::CallbackBatch && page.sha256 == receipt.prefixSha256 &&
        page.segmentOrdinal == 1 && page.records.size() == events.size() && page.graph.nodes.empty() &&
        page.graph.edges.empty(), "callback-first-segment-context-only");
    const auto& observations = page.graph.observations;
    Check(observations.size() == events.size(), "callback-observations-preserved");
    if (observations.size() != events.size()) return;
    Check(Gap(observations[0], Issue::SourcePayloadTruncated), "callback-process-name-truncation");
    Check(Gap(observations[1], Issue::SourcePayloadTruncated), "callback-path-truncation");
    Check(!Gap(observations[2], Issue::SourcePayloadTruncated), "callback-complete-text-no-truncation");
    for (std::size_t index = 0; index < events.size(); ++index) {
        const auto& row = observations[index];
        Check(row.evidence && row.evidence->raw == RawLocator{1, receipt.records[index].rawSequence} &&
            row.evidence->sourceSequence == events[index].sequence && !row.finding &&
            row.actorPidHint == 10 && row.actorTidHint == 11 && row.targetPidHint == 20 && row.targetTidHint == 30 &&
            Gap(row, Issue::ThreadInstanceUnknown) && Gap(row, Issue::ExecutionUnknown), "callback-weak-evidence-retains-anchor");
    }
}

} // namespace

// 运行离线断言，对外仅输出通过数和进程退出状态。
int wmain(int argc, wchar_t** argv)
{
    TestNative();
    TestUnknowns();
    TestUnknownMachine();
    TestThreadCreationEvidence();
    if (argc == 2) {
        TestCallbackArchiveTruncation(argv[1]);
    }
    std::printf("CrossProcessEvidenceGraph: %d/%d passed\n", assertions - failures, assertions);
    return failures == 0 ? 0 : 1;
}
