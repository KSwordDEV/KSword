#include "../CrossProcessEvidenceGraph.h"
#include "../ArchivedEvidenceGraph.h"
#include "../../../../shared/driver/KswordArkCallbackIoctl.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace Ksword::ActionAnalyze::Detection;
using Ksword::Evidence::OptionalU64;
namespace Monitor = ks::winapi_monitor;

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

// 构造带显式 AAIP1 字段的普通 API 包。返回位非零才满足原调用成功语义。
Monitor::ApiMonitorEventPacket InjectionPacket(const wchar_t* module, const wchar_t* api,
    Monitor::EventCategory category, const Ksword::Evidence::ApiInjectionFieldsV1& fields,
    std::uint64_t session = 1234, std::uint64_t returnBits = 8)
{
    Monitor::ApiMonitorEventPacket packet;
    packet.pid = 10;
    packet.tid = 11;
    packet.category = static_cast<std::uint32_t>(category);
    const std::wstring_view moduleText{module};
    const std::wstring_view apiText{api};
    std::copy(moduleText.begin(), moduleText.end(), packet.moduleName);
    std::copy(apiText.begin(), apiText.end(), packet.apiName);
    packet.snapshotIndex = Monitor::kApiCallReturnValueMarker; // 返回位槽位标记。
    packet.hookAddress = returnBits; // BOOL 或线程句柄，非零表示成功。
    packet.sessionIdentity = session;
    Ksword::Evidence::StoreApiInjectionFields(packet, fields); // 同一份字段写入详情槽和覆盖标记。
    return packet;
}

// 写入字段只声明调用窗口内解析出的身份、实际范围与 QPC。
Ksword::Evidence::ApiInjectionFieldsV1 WriteFields(std::uint64_t address, std::uint64_t requested,
    std::uint64_t completed, std::uint64_t enterQpc = 100, std::uint64_t returnQpc = 110,
    std::uint64_t actorCreated = 1000, std::uint64_t targetPid = 20, std::uint64_t targetCreated = 2000)
{
    using namespace Ksword::Evidence;
    ApiInjectionFieldsV1 fields;
    fields.operation = ApiInjectionOperation::MemoryWrite;
    fields.flags = ApiInjectionActorIdentity | ApiInjectionTargetIdentity | ApiInjectionTargetStable |
        ApiInjectionAddress | ApiInjectionCompletedLength;
    fields.actorCreationFileTime = actorCreated;
    fields.targetPid = targetPid;
    fields.targetCreationFileTime = targetCreated;
    fields.address = address;
    fields.requestedBytes = requested;
    fields.completedBytes = completed;
    fields.enterQpc = enterQpc;
    fields.returnQpc = returnQpc;
    return fields;
}

// 线程创建字段包含返回线程身份，但入口地址仍只是请求值。
Ksword::Evidence::ApiInjectionFieldsV1 ThreadFields(std::uint64_t startAddress, std::uint64_t enterQpc = 200,
    std::uint64_t returnQpc = 210, std::uint64_t actorCreated = 1000, std::uint64_t targetPid = 20,
    std::uint64_t targetCreated = 2000)
{
    using namespace Ksword::Evidence;
    ApiInjectionFieldsV1 fields;
    fields.operation = ApiInjectionOperation::ThreadCreate;
    fields.flags = ApiInjectionActorIdentity | ApiInjectionTargetIdentity | ApiInjectionThreadIdentity |
        ApiInjectionTargetStable | ApiInjectionStartAddress;
    fields.actorCreationFileTime = actorCreated;
    fields.targetPid = targetPid;
    fields.targetCreationFileTime = targetCreated;
    fields.targetTid = 30;
    fields.targetThreadCreationFileTime = 3000;
    fields.startAddress = startAddress;
    fields.enterQpc = enterQpc;
    fields.returnQpc = returnQpc;
    return fields;
}

// 同一采样内允许跨段，来源和代次仍须逐项相同。
EvidenceRef TransferEvidence(std::uint64_t segment, std::uint64_t sequence, const char* source = "api",
    const char* epoch = "epoch")
{
    EvidenceRef result;
    result.projectId = scope.projectId;
    result.sampleId = scope.sampleId;
    result.sourceId = source;
    result.sourceEpoch = epoch;
    result.raw = RawLocator{segment, sequence};
    result.sourceGroup = "api-group";
    return result;
}

// 每次用独立链状态验证一组输入，避免前一个负例影响后续覆盖。
std::vector<ApiTransferLink> TransferLinks(const Monitor::ApiMonitorEventPacket& writePacket,
    const Monitor::ApiMonitorEventPacket& createPacket, const EvidenceRef& writeEvidence,
    const EvidenceRef& createEvidence)
{
    ApiTransferChain chain(scope);
    chain.Accept(writeEvidence, writePacket); // 写入自身不产生候选。
    return chain.Accept(createEvidence, createPacket);
}

// 读取固定小文件用于恢复测试段；测试只操作自己创建的项目目录。
std::vector<unsigned char> ReadBytes(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void WriteBytes(const std::filesystem::path& path, const std::vector<unsigned char>& bytes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
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

void TestApiTransferCandidates()
{
    // 写入位于第 1 段，线程创建请求位于第 2 段；候选保留双方真实原包坐标。
    const auto write = InjectionPacket(L"KernelBase", L"WriteProcessMemory", Monitor::EventCategory::Memory,
        WriteFields(0x1000, 8, 8));
    const auto create = InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread", Monitor::EventCategory::Thread,
        ThreadFields(0x1004));
    const auto writeAt = TransferEvidence(1, 2);
    const auto createAt = TransferEvidence(2, 2);
    const auto positive = TransferLinks(write, create, writeAt, createAt);
    Check(positive.size() == 1, "cross-segment-source-candidate");
    if (positive.size() == 1) {
        const auto& link = positive.front();
        Check(link.write == writeAt && link.threadCreate == createAt, "candidate-keeps-both-raw-coordinates");
        Check(link.actorPid == 10 && link.actorCreationFileTime == 1000 && link.targetPid == 20 &&
            link.targetCreationFileTime == 2000, "candidate-keeps-both-generation-identities");
        Check(link.writtenAddress == 0x1000 && link.writtenBytes == 8 &&
            link.requestedStartAddress == 0x1004, "candidate-uses-actual-write-range");
    }

    // 入口必须落在 [address, address + completedBytes) 的半开区间内。
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x1000)), writeAt, createAt).size() == 1,
        "half-open-interval-includes-start");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x1007)), writeAt, createAt).size() == 1,
        "half-open-interval-includes-last-byte");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x1008)), writeAt, createAt).empty(),
        "half-open-interval-excludes-end");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x0fff)), writeAt, createAt).empty(),
        "half-open-interval-excludes-before-start");

    // 部分写入只按实际完成长度构成区间，不沿用请求长度。
    const auto partialWrite = InjectionPacket(L"KernelBase", L"WriteProcessMemory", Monitor::EventCategory::Memory,
        WriteFields(0x2000, 16, 8));
    const auto partialInside = TransferLinks(partialWrite, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x2007)), writeAt, createAt);
    Check(partialInside.size() == 1 && partialInside.front().writtenBytes == 8, "partial-write-uses-completed-length");
    Check(TransferLinks(partialWrite, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x2008)), writeAt, createAt).empty(),
        "partial-write-range-is-half-open");

    // 失败调用按源端契约不携带实际完成长度，因此不能形成可关联区间。
    auto failedFields = WriteFields(0x1000, 8, 8);
    failedFields.flags &= ~Ksword::Evidence::ApiInjectionCompletedLength; // 来源只应在成功且安全读取后置位。
    Check(TransferLinks(InjectionPacket(L"KernelBase", L"WriteProcessMemory", Monitor::EventCategory::Memory,
        failedFields, 1234, 0), create, writeAt, createAt).empty(),
        "failed-write-without-completion-is-not-a-candidate-source");
    auto missingCompletion = WriteFields(0x1000, 8, 8);
    missingCompletion.flags &= ~Ksword::Evidence::ApiInjectionCompletedLength;
    Check(TransferLinks(InjectionPacket(L"KernelBase", L"WriteProcessMemory", Monitor::EventCategory::Memory,
        missingCompletion), create, writeAt, createAt).empty(), "missing-completion-length-is-not-a-range");
    auto missingAddress = WriteFields(0x1000, 8, 8);
    missingAddress.flags &= ~Ksword::Evidence::ApiInjectionAddress;
    Check(TransferLinks(InjectionPacket(L"KernelBase", L"WriteProcessMemory", Monitor::EventCategory::Memory,
        missingAddress), create, writeAt, createAt).empty(), "missing-write-address-is-not-a-range");
    auto missingStart = ThreadFields(0x1004);
    missingStart.flags &= ~Ksword::Evidence::ApiInjectionStartAddress;
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread", Monitor::EventCategory::Thread,
        missingStart), writeAt, createAt).empty(), "missing-requested-entry-is-not-a-candidate");

    // 来源、会话、身份代次或事实时钟不一致时都必须断开候选。
    auto differentSource = createAt;
    differentSource.sourceId = "other-api";
    Check(TransferLinks(write, create, writeAt, differentSource).empty(), "different-source-breaks-candidate");
    auto differentEpoch = createAt;
    differentEpoch.sourceEpoch = "other-epoch";
    Check(TransferLinks(write, create, writeAt, differentEpoch).empty(), "different-source-epoch-breaks-candidate");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x1004), 999), writeAt, createAt).empty(),
        "different-session-breaks-candidate");
    Check(TransferLinks(InjectionPacket(L"KernelBase", L"WriteProcessMemory", Monitor::EventCategory::Memory,
        WriteFields(0x1000, 8, 8, 100, 110, 1000, 20, 2000)), InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread",
        Monitor::EventCategory::Thread, ThreadFields(0x1004, 200, 210, 1001)), writeAt, createAt).empty(),
        "different-actor-generation-breaks-candidate");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread", Monitor::EventCategory::Thread,
        ThreadFields(0x1004, 200, 210, 1000, 21)), writeAt, createAt).empty(),
        "different-target-process-breaks-candidate");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread", Monitor::EventCategory::Thread,
        ThreadFields(0x1004, 200, 210, 1000, 20, 2001)), writeAt, createAt).empty(),
        "different-target-generation-breaks-candidate");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread", Monitor::EventCategory::Thread,
        ThreadFields(0x1004, 110)), writeAt, createAt).empty(),
        "equal-qpc-breaks-candidate");
    Check(TransferLinks(write, InjectionPacket(L"Kernel32.dll", L"CreateRemoteThread", Monitor::EventCategory::Thread,
        ThreadFields(0x1004, 105)), writeAt, createAt).empty(),
        "reverse-qpc-breaks-candidate");

    // 坏原包锚点不能参与跨段状态，也不能借用同数字的邻居补全。
    auto zeroWriteSequence = writeAt;
    zeroWriteSequence.raw->sequence = 0;
    Check(TransferLinks(write, create, zeroWriteSequence, createAt).empty(), "zero-write-sequence-rejected");
    auto zeroCreateSegment = createAt;
    zeroCreateSegment.raw->segmentOrdinal = 0;
    Check(TransferLinks(write, create, writeAt, zeroCreateSegment).empty(), "zero-create-segment-rejected");
    auto foreignSample = writeAt;
    foreignSample.sampleId = "other-sample";
    Check(TransferLinks(write, create, foreignSample, createAt).empty(), "foreign-sample-anchor-rejected");
    auto missingRaw = createAt;
    missingRaw.raw.reset();
    Check(TransferLinks(write, create, writeAt, missingRaw).empty(), "missing-raw-anchor-rejected");
    auto emptySource = createAt;
    emptySource.sourceId.clear();
    Check(TransferLinks(write, create, writeAt, emptySource).empty(), "empty-source-anchor-rejected");

    // 重复消费同一原包不增加链路状态；创建操作仍只形成一条候选。
    {
        ApiTransferChain chain(scope);
        chain.Accept(writeAt, write);
        chain.Accept(writeAt, write);
        const auto links = chain.Accept(createAt, create);
        Check(links.size() == 1 && chain.EvictedWrites() == 0, "duplicate-write-packet-keeps-one-state");
    }

    // 写入窗口满后淘汰旧状态，后续创建不能再关联已被淘汰的写入。
    {
        ApiTransferChain chain(scope);
        chain.Accept(TransferEvidence(1, 1), write); // 将被淘汰的首条写入。
        for (std::uint64_t index = 1; index <= 1024; ++index) {
            chain.Accept(TransferEvidence(1, index + 2), InjectionPacket(L"KernelBase", L"WriteProcessMemory",
                Monitor::EventCategory::Memory, WriteFields(0x3000, 8, 8)));
        }
        Check(chain.EvictedWrites() == 1, "transfer-write-window-evicts-oldest");
        Check(chain.Accept(createAt, create).empty(), "evicted-write-cannot-support-a-candidate");
    }

    // 候选只连接来源报告的两份包，不产生执行确认或原生角色。
    EventProjection projection; // 与归档读侧相同的来源上下文缺口。
    projection.gaps = {Issue::SourceUnverified, Issue::ThreadInstanceUnknown, Issue::ExecutionUnknown};
    const std::array<GraphEventInput, 1> input{GraphEventInput{projection, createAt,
        GraphArchiveContext{10, 11, GraphApiClue::ThreadCreate}}};
    const auto graph = BuildCrossProcessEvidenceGraph(scope, input);
    Check(graph.observations.size() == 1 && graph.observations.front().evidence &&
        !graph.observations.front().finding && !graph.observations.front().observedThread &&
        graph.nodes.empty() && graph.edges.empty(), "transfer-candidate-does-not-prove-execution");
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

    // 坏段或错请求不得替换调用方上一次完整结果，也不能发布部分回调观察。
    ArchivedGraphPage sentinel;
    sentinel.sha256 = "sentinel-prefix"; // 失败时保持不变的旧结果标识。
    sentinel.segmentOrdinal = 77;
    const auto missing = ReadArchivedEvidenceGraph(reader, {sample.sampleId, 2, 0, events.size(), {}}, sentinel);
    Check(!missing && sentinel.sha256 == "sentinel-prefix" && sentinel.segmentOrdinal == 77,
        "missing-segment-keeps-previous-page");
    const auto stale = ReadArchivedEvidenceGraph(reader, {sample.sampleId, 1, 0, events.size(),
        std::string(64, '0')}, sentinel);
    Check(!stale && sentinel.sha256 == "sentinel-prefix", "wrong-prefix-hash-keeps-previous-page");

    const auto segment = root / "samples" / sample.sampleId / "raw" / "00000000000000000001.ksaseg";
    const auto original = ReadBytes(segment);
    auto corrupted = original; // 只修改本次测试创建段的临时副本。
    corrupted[corrupted.size() / 2] ^= 0xff;
    WriteBytes(segment, corrupted);
    const auto broken = ReadArchivedEvidenceGraph(reader, {sample.sampleId, 1, 0, events.size(), receipt.prefixSha256}, sentinel);
    Check(!broken && sentinel.sha256 == "sentinel-prefix" && sentinel.segmentOrdinal == 77,
        "corrupt-segment-keeps-previous-page");
    WriteBytes(segment, original); // 恢复后同一前缀必须重新完整发布。
    ArchivedGraphPage restored;
    const auto reread = ReadArchivedEvidenceGraph(reader, {sample.sampleId, 1, 0, events.size(), receipt.prefixSha256}, restored);
    Check(reread && restored.sha256 == receipt.prefixSha256 && restored.records.size() == events.size() &&
        restored.graph.observations.size() == events.size(), "restored-segment-publishes-complete-page");
}

} // namespace

// 运行离线断言，对外仅输出通过数和进程退出状态。
int wmain(int argc, wchar_t** argv)
{
    TestNative();
    TestUnknowns();
    TestUnknownMachine();
    TestThreadCreationEvidence();
    TestApiTransferCandidates();
    if (argc == 2) {
        TestCallbackArchiveTruncation(argv[1]);
    }
    std::printf("CrossProcessEvidenceGraph: %d/%d passed\n", assertions - failures, assertions);
    return failures == 0 ? 0 : 1;
}
