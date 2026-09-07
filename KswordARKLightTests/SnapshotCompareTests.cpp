// D 模块（快照比较与变化解释）的离线自动测试。
//
// 覆盖编号：D-01 D-02 D-03 D-04 D-05 D-06 D-07，以及 D-08 的离线一半
// （预期变化清单核对；真正的"改配置—采快照—清理"属于目标环境实测）。
//
// 断言原则（Q-01/Q-02）：
//   * 期望值一律独立写死：RVA、键、计数、枚举都是手算或手写常量，比较两侧绝不
//     来自同一个被测函数的输出；
//   * 每种"未知"分别断言精确的 EntitySideState，不塌进一个计数器 —— 否则
//     "拒绝访问"与"确实没有"会互相冒充；
//   * 每个负面用例都同时断言"没有产生假增删"和"确实标出了不可比较"，只查其一
//     会让"全部标不可比较"这种偷懒实现蒙混过关；
//   * 持久化用手写的 JSON 字面量当 fixture，而不是先写再读自我印证。

#include "TestSupport.h"

#include "../shared/evidence/SnapshotCompare.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

constexpr const char* kBootA = "boot-A";
constexpr const char* kBootB = "boot-B";
constexpr const char* kMachine = "machine-D";
constexpr std::uint64_t kUtcEarlier = 133100000000000000ULL;
constexpr std::uint64_t kUtcLater = 133100006000000000ULL;

// ---------------------------------------------------------------------------
// fixture 构造
// ---------------------------------------------------------------------------
EvidenceEnvelope MakeEnvelope(const char* collectorId,
                              CollectionStatus status,
                              const char* bootId,
                              std::uint64_t utc,
                              const char* evidenceId) {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = collectorId;
    envelope.source.sourceGroup = collectorId;
    envelope.source.collectorVersion = 7U;
    envelope.source.origin = SourceOrigin::LiveKernel;
    envelope.outcome.status = status;
    envelope.window.machineId = kMachine;
    envelope.window.bootId = bootId;
    envelope.window.sessionId = "session-1";
    envelope.window.mode = CaptureMode::Snapshot;
    envelope.window.startUtc100ns = OptionalU64::of(utc);
    envelope.window.endUtc100ns = OptionalU64::of(utc + 1000ULL);
    envelope.evidenceId = evidenceId;
    return envelope;
}

// D-04/F-06：完整覆盖需要正面证据，因此账目必须明写"总数 n、成功 n"。
SnapshotPartition MakePartition(const char* partitionId,
                                ObjectKind kind,
                                CollectionStatus status,
                                const char* bootId,
                                std::uint64_t utc,
                                std::uint64_t count,
                                const char* evidenceId) {
    SnapshotPartition partition;
    partition.partitionId = partitionId;
    partition.kind = kind;
    partition.coversScope = true;
    partition.envelope = MakeEnvelope(partitionId, status, bootId, utc, evidenceId);
    partition.envelope.coverage.totalKnown = OptionalU64::of(count);
    partition.envelope.coverage.succeeded = count;
    return partition;
}

Snapshot MakeSnapshot(const char* id, const char* bootId, std::uint64_t utc) {
    Snapshot snapshot;
    snapshot.snapshotId = id;
    snapshot.envelope = MakeEnvelope("d.snapshot", CollectionStatus::Success, bootId, utc, id);
    snapshot.scope.scopeId = "system";
    snapshot.scope.declared = true;
    snapshot.scope.wholeDomain = true;
    return snapshot;
}

EntityField TextField(const char* name, const char* value) {
    EntityField field;
    field.name = name;
    field.kind = FieldValueKind::Text;
    field.text = value;
    return field;
}

EntityField NumberField(const char* name, std::uint64_t value, FieldSemantics semantics) {
    EntityField field;
    field.name = name;
    field.semantics = semantics;
    field.kind = FieldValueKind::Number;
    field.number = OptionalU64::of(value);
    field.numberFormat = U64Format::HexAddress;
    return field;
}

// 未采集的字段仍然要声明它的比较语义 —— 语义是列的属性，不是这一次取到的值的属性。
EntityField AbsentField(const char* name, FieldSemantics semantics = FieldSemantics::Opaque) {
    EntityField field;
    field.name = name;
    field.semantics = semantics;
    field.kind = FieldValueKind::Absent;
    return field;
}

SnapshotEntity MakeProcess(const char* partitionId,
                           const char* bootId,
                           std::uint64_t pid,
                           std::uint64_t createTime,
                           const char* imageName,
                           const char* rawId,
                           std::size_t order) {
    SnapshotEntity entity;
    entity.partitionId = partitionId;
    entity.kind = ObjectKind::Process;
    entity.process.bootId = bootId;
    entity.process.pid = OptionalU64::of(pid);
    if (createTime != 0ULL) {
        entity.process.createTime100ns = OptionalU64::of(createTime);
    }
    entity.process.imageName = imageName;
    entity.rawRecordId = rawId;
    entity.displayOrder = order;
    return entity;
}

SnapshotEntity MakeDriverEntity(const char* partitionId,
                                const char* imagePath,
                                const char* pdb,
                                std::uint64_t stamp,
                                std::uint64_t size,
                                const char* rawId,
                                std::size_t order) {
    SnapshotEntity entity;
    entity.partitionId = partitionId;
    entity.kind = ObjectKind::Driver;
    entity.driver.imagePath = imagePath;
    entity.driver.pdbSignature = pdb;
    entity.driver.timeDateStamp = OptionalU64::of(stamp);
    entity.driver.imageSize = OptionalU64::of(size);
    entity.rawRecordId = rawId;
    entity.displayOrder = order;
    return entity;
}

SnapshotEntity MakeServiceEntity(const char* partitionId,
                                 const char* name,
                                 const char* rawId,
                                 std::size_t order) {
    SnapshotEntity entity;
    entity.partitionId = partitionId;
    entity.kind = ObjectKind::Service;
    entity.logical.domain = "service";
    entity.logical.name = name;
    entity.rawRecordId = rawId;
    entity.displayOrder = order;
    return entity;
}

SnapshotModule MakeModule(const char* moduleId,
                          const char* imagePath,
                          const char* pdb,
                          std::uint64_t stamp,
                          std::uint64_t base,
                          std::uint64_t size) {
    SnapshotModule module;
    module.moduleId = moduleId;
    module.identity.imagePath = imagePath;
    module.identity.pdbSignature = pdb;
    module.identity.timeDateStamp = OptionalU64::of(stamp);
    module.identity.imageSize = OptionalU64::of(size);
    module.imageBase = OptionalU64::of(base);
    module.imageSize = OptionalU64::of(size);
    return module;
}

const EntityDelta* FindDelta(const SnapshotComparison& comparison, const std::string& display) {
    for (const EntityDelta& delta : comparison.deltas) {
        if (delta.displayText == display) {
            return &delta;
        }
    }
    return nullptr;
}

const EntityDelta* FindDeltaByRaw(const SnapshotComparison& comparison, const std::string& rawId) {
    for (const EntityDelta& delta : comparison.deltas) {
        if (delta.earlierRawRecordId == rawId || delta.laterRawRecordId == rawId) {
            return &delta;
        }
    }
    return nullptr;
}

const FieldDelta* FindField(const EntityDelta& delta, const std::string& name) {
    for (const FieldDelta& field : delta.fields) {
        if (field.name == name) {
            return &field;
        }
    }
    return nullptr;
}

const PartitionAccount* FindAccount(const SnapshotComparison& comparison, const std::string& id) {
    for (const PartitionAccount& account : comparison.partitions) {
        if (account.partitionId == id) {
            return &account;
        }
    }
    return nullptr;
}

bool Contains(const std::vector<std::string>& list, const std::string& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

bool TextContains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------------------
// D-01 快照范围和来源
// ---------------------------------------------------------------------------
void TestScopeAndProvenance(KswordTests::Suite& s) {
    // --- CompareScopes 的六个取值都要有断言，枚举分支不许零覆盖 ---
    SnapshotScope whole;
    whole.scopeId = "system";
    whole.declared = true;
    whole.wholeDomain = true;

    SnapshotScope undeclared;
    undeclared.scopeId = "system";

    SnapshotScope narrowA;
    narrowA.scopeId = "system";
    narrowA.declared = true;
    narrowA.selectors = {"C:", "D:"};

    SnapshotScope narrowSubset;
    narrowSubset.scopeId = "system";
    narrowSubset.declared = true;
    narrowSubset.selectors = {"C:"};

    SnapshotScope narrowOther;
    narrowOther.scopeId = "system";
    narrowOther.declared = true;
    narrowOther.selectors = {"E:"};

    SnapshotScope narrowOverlap;
    narrowOverlap.scopeId = "system";
    narrowOverlap.declared = true;
    narrowOverlap.selectors = {"D:", "E:"};

    SnapshotScope otherDomain;
    otherDomain.scopeId = "network";
    otherDomain.declared = true;
    otherDomain.wholeDomain = true;

    s.expect(CompareScopes(whole, whole) == ScopeComparability::Identical,
             L"D-01 identical whole-domain scopes compare as identical");
    s.expect(CompareScopes(whole, undeclared) == ScopeComparability::Unknown,
             L"D-01 an undeclared scope is unknown, never assumed identical");
    s.expect(CompareScopes(undeclared, undeclared) == ScopeComparability::Unknown,
             L"D-01 two undeclared scopes stay unknown");
    s.expect(CompareScopes(narrowSubset, whole) == ScopeComparability::EarlierSubsetOfLater,
             L"D-01 earlier narrow vs later whole is EarlierSubsetOfLater");
    s.expect(CompareScopes(whole, narrowSubset) == ScopeComparability::LaterSubsetOfEarlier,
             L"D-01 earlier whole vs later narrow is LaterSubsetOfEarlier");
    s.expect(CompareScopes(narrowSubset, narrowA) == ScopeComparability::EarlierSubsetOfLater,
             L"D-01 selector subset is recognised");
    s.expect(CompareScopes(narrowA, narrowOther) == ScopeComparability::Disjoint,
             L"D-01 disjoint selector sets are disjoint");
    s.expect(CompareScopes(narrowA, narrowOverlap) == ScopeComparability::PartialOverlap,
             L"D-01 partially overlapping selector sets are PartialOverlap");
    s.expect(CompareScopes(whole, otherDomain) == ScopeComparability::Disjoint,
             L"D-01 different scope ids are disjoint");

    s.expect(RemovalInferable(ScopeComparability::Identical),
             L"D-01 removal is inferable when scopes match");
    s.expect(RemovalInferable(ScopeComparability::EarlierSubsetOfLater),
             L"D-01 removal is inferable when the later scope covers the earlier one");
    s.expect(!RemovalInferable(ScopeComparability::LaterSubsetOfEarlier),
             L"D-01 removal is NOT inferable when the later scope is narrower");
    s.expect(!RemovalInferable(ScopeComparability::Unknown),
             L"D-01 removal is NOT inferable when the scope is undeclared");
    s.expect(!RemovalInferable(ScopeComparability::PartialOverlap),
             L"D-01 removal is NOT inferable on partial overlap");
    s.expect(!RemovalInferable(ScopeComparability::Disjoint),
             L"D-01 removal is NOT inferable on disjoint scopes");
    s.expect(AdditionInferable(ScopeComparability::LaterSubsetOfEarlier),
             L"D-01 addition is inferable when the earlier scope covers the later one");
    s.expect(!AdditionInferable(ScopeComparability::EarlierSubsetOfLater),
             L"D-01 addition is NOT inferable when the earlier scope is narrower");

    // --- 快照 1：全范围 ---
    Snapshot fullEarlier = MakeSnapshot("full-early", kBootA, kUtcEarlier);
    fullEarlier.partitions.push_back(
        MakePartition("processes", ObjectKind::Process, CollectionStatus::Success, kBootA,
                      kUtcEarlier, 2U, "ev-early-proc"));
    fullEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "e-row-1", 0U));
    fullEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 200U, 222ULL, "beta.exe", "e-row-2", 1U));

    Snapshot fullLater = MakeSnapshot("full-late", kBootA, kUtcLater);
    fullLater.partitions.push_back(
        MakePartition("processes", ObjectKind::Process, CollectionStatus::Success, kBootA, kUtcLater,
                      1U, "ev-late-proc"));
    fullLater.entities.push_back(
        MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));

    const SnapshotComparison fullPair = CompareSnapshots(fullEarlier, fullLater);
    s.expect(fullPair.scope == ScopeComparability::Identical,
             L"D-01 two whole-domain snapshots compare as identical scope");
    s.expect(fullPair.removedCount == 1U,
             L"D-01 with identical scope and complete coverage a real removal is reported");
    const EntityDelta* beta = FindDelta(fullPair, "beta.exe");
    s.expect(beta != nullptr && beta->change == EntityChange::Removed,
             L"D-01 the removed process is the one that disappeared");
    s.expect(beta != nullptr && beta->laterState == EntitySideState::AbsentCovered,
             L"D-01 the removed process is absent in a covered later snapshot");
    s.expect(fullPair.conclusion == AnalysisConclusion::DifferenceObserved,
             L"D-01 a removal makes the conclusion DifferenceObserved");

    // --- 快照 2：部分范围 —— D-01 的核心陷阱 ---
    Snapshot narrowLater = MakeSnapshot("narrow-late", kBootA, kUtcLater);
    narrowLater.scope.wholeDomain = false;
    narrowLater.scope.selectors = {"session-0"};
    narrowLater.partitions.push_back(
        MakePartition("processes", ObjectKind::Process, CollectionStatus::Success, kBootA, kUtcLater,
                      1U, "ev-late-proc"));
    narrowLater.entities.push_back(
        MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));

    const SnapshotComparison narrowPair = CompareSnapshots(fullEarlier, narrowLater);
    s.expect(narrowPair.scope == ScopeComparability::LaterSubsetOfEarlier,
             L"D-01 a narrower later selection is recognised as such");
    s.expect(narrowPair.removedCount == 0U,
             L"D-01 a narrower later selection never reports removals");
    const EntityDelta* narrowBeta = FindDelta(narrowPair, "beta.exe");
    s.expect(narrowBeta != nullptr && narrowBeta->change == EntityChange::NotComparable,
             L"D-01 the object outside the later selection is NotComparable, not removed");
    s.expect(narrowBeta != nullptr && narrowBeta->laterState == EntitySideState::AbsentOutOfScope,
             L"D-01 the later side is marked out of scope rather than absent");
    s.expect(narrowBeta != nullptr &&
                 Contains(narrowBeta->limitationKeys, "snapshot.limitation.scopeNotComparable"),
             L"D-01 the scope limitation is stated on the delta");
    s.expect(Contains(narrowPair.limitationKeys, "snapshot.limitation.scopeDiffers"),
             L"D-01 the report states that the selections differ");
    s.expect(narrowPair.conclusion == AnalysisConclusion::Indeterminate,
             L"D-01 differing selections cannot yield NoDifferenceObserved");
    s.expect(narrowPair.selfCheckPassed, L"D-01 narrow-scope comparison passes its self check");

    // 反方向：旧范围更窄时可以判新增，但不能判删除。
    const SnapshotComparison widened = CompareSnapshots(narrowLater, fullEarlier);
    s.expect(widened.scope == ScopeComparability::EarlierSubsetOfLater,
             L"D-01 widening the selection is EarlierSubsetOfLater");
    s.expect(widened.addedCount == 0U,
             L"D-01 a widened later selection never reports additions");
    s.expect(widened.removedCount == 0U,
             L"D-01 a widened selection with no missing object reports no removals");

    // --- 快照 3：部分失败 ---
    Snapshot partialLater = MakeSnapshot("partial-late", kBootA, kUtcLater);
    partialLater.partitions.push_back(
        MakePartition("processes", ObjectKind::Process, CollectionStatus::Partial, kBootA, kUtcLater,
                      2U, "ev-late-proc"));
    partialLater.partitions.back().envelope.coverage.truncated = 1U;
    partialLater.partitions.back().envelope.coverage.succeeded = 1U;
    partialLater.entities.push_back(
        MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));

    const SnapshotComparison partialPair = CompareSnapshots(fullEarlier, partialLater);
    s.expect(partialPair.removedCount == 0U,
             L"D-01 a truncated later snapshot never reports removals");
    const EntityDelta* partialBeta = FindDelta(partialPair, "beta.exe");
    s.expect(partialBeta != nullptr && partialBeta->change == EntityChange::InsufficientCoverage,
             L"D-01 a truncated later snapshot yields InsufficientCoverage");
    s.expect(partialBeta != nullptr && partialBeta->laterState == EntitySideState::UnknownCoverage,
             L"D-01 truncation is reported as unknown coverage, not absence");

    // 状态说"没采全"但账目看着满：状态与账目任一说不完整就不得支撑缺席结论。
    Snapshot partialButTidy = MakeSnapshot("partial-tidy", kBootA, kUtcLater);
    partialButTidy.partitions.push_back(
        MakePartition("processes", ObjectKind::Process, CollectionStatus::Partial, kBootA, kUtcLater,
                      1U, "ev-late-proc"));
    partialButTidy.entities.push_back(
        MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));
    const SnapshotComparison tidyPair = CompareSnapshots(fullEarlier, partialButTidy);
    s.expect(tidyPair.removedCount == 0U,
             L"D-01 a Partial status never supports a removal even with a tidy-looking account");
    const EntityDelta* tidyBeta = FindDelta(tidyPair, "beta.exe");
    s.expect(tidyBeta != nullptr && tidyBeta->laterState == EntitySideState::UnknownCoverage,
             L"D-01 a Partial status is reported as unknown coverage");

    // 两份快照来自不同机器：增删失去意义。
    Snapshot otherMachine = fullLater;
    otherMachine.envelope.window.machineId = "machine-OTHER";
    const SnapshotComparison crossMachine = CompareSnapshots(fullEarlier, otherMachine);
    s.expect(Contains(crossMachine.limitationKeys, "snapshot.limitation.machineMismatch"),
             L"D-01 comparing two machines is stated as a limitation");
    s.expect(crossMachine.removedCount == 0U,
             L"D-01 two different machines never produce a removal");
    const EntityDelta* crossBeta = FindDelta(crossMachine, "beta.exe");
    s.expect(crossBeta != nullptr && crossBeta->laterState == EntitySideState::AbsentOutOfScope,
             L"D-01 the cross-machine object is out of comparable scope, not removed");

    // --- 来源与账目本身必须可核对 ---
    const PartitionAccount* account = FindAccount(fullPair, "processes");
    s.expect(account != nullptr && account->earlierStatus == CollectionStatus::Success,
             L"D-01 the partition account records the earlier collection status");
    s.expect(account != nullptr && account->comparable,
             L"D-01 both sides carrying observations makes the partition comparable");
    s.expect(account != nullptr && account->earlierUsableForAbsence && account->laterUsableForAbsence,
             L"D-01 a fully accounted partition may support absence claims");
    s.expect(fullEarlier.envelope.source.collectorVersion == 7U,
             L"D-01 the snapshot envelope carries a collector version");
    s.expect(fullEarlier.envelope.window.bootId == std::string(kBootA),
             L"D-01 the snapshot envelope carries the boot identity");
    s.expect(fullPair.trust.viewCount >= 4U,
             L"D-01 the trust statement counts both snapshots and their partitions");
    s.expect(fullPair.boot == CrossBootComparability::SameBoot,
             L"D-01 two snapshots from one boot are recognised as same-boot");

    // 空账目不得白得"完整覆盖"。
    Snapshot blankLater = MakeSnapshot("blank-late", kBootA, kUtcLater);
    SnapshotPartition blank;
    blank.partitionId = "processes";
    blank.kind = ObjectKind::Process;
    blank.coversScope = true;
    blank.envelope = MakeEnvelope("processes", CollectionStatus::Success, kBootA, kUtcLater, "ev-b");
    blankLater.partitions.push_back(blank);
    blankLater.entities.push_back(
        MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));
    const SnapshotComparison blankPair = CompareSnapshots(fullEarlier, blankLater);
    s.expect(blankPair.removedCount == 0U,
             L"D-01 an empty coverage account never supports a removal claim");
    const PartitionAccount* blankAccount = FindAccount(blankPair, "processes");
    s.expect(blankAccount != nullptr && !blankAccount->laterUsableForAbsence,
             L"D-01 an unfilled coverage account is not usable for absence");
    s.expect(blankAccount != nullptr &&
                 Contains(blankAccount->limitationKeys, "snapshot.partition.laterCoverageIncomplete"),
             L"D-01 the unfilled account is stated as incomplete coverage");
}

// ---------------------------------------------------------------------------
// D-02 语义比较键
// ---------------------------------------------------------------------------
void TestSemanticKeys(KswordTests::Suite& s) {
    s.expect(!KindComparableAcrossBoot(ObjectKind::Process),
             L"D-02 process instances are not comparable across boots");
    s.expect(!KindComparableAcrossBoot(ObjectKind::Thread),
             L"D-02 thread instances are not comparable across boots");
    s.expect(!KindComparableAcrossBoot(ObjectKind::Handle),
             L"D-02 handles are not comparable across boots");
    s.expect(!KindComparableAcrossBoot(ObjectKind::Connection),
             L"D-02 connections are not comparable across boots");
    s.expect(KindComparableAcrossBoot(ObjectKind::Driver),
             L"D-02 drivers are comparable across boots by logical identity");
    s.expect(KindComparableAcrossBoot(ObjectKind::Service),
             L"D-02 services are comparable across boots by logical identity");
    s.expect(KindComparableAcrossBoot(ObjectKind::File),
             L"D-02 files are comparable across boots by logical identity");

    LogicalObjectId svcA;
    svcA.domain = "service";
    svcA.name = "AcmeSvc";
    LogicalObjectId svcB = svcA;
    LogicalObjectId svcScoped = svcA;
    svcScoped.scopeKey = "policy-2";
    LogicalObjectId svcOtherScope = svcA;
    svcOtherScope.scopeKey = "policy-3";
    LogicalObjectId nameless;
    nameless.domain = "service";

    s.expect(MatchLogicalObject(svcA, svcB) == MatchResult::Confirmed,
             L"D-02 identical logical identities are confirmed");
    s.expect(MatchLogicalObject(svcScoped, svcOtherScope) == MatchResult::NoMatch,
             L"D-02 same name in a different scope is a different object");
    s.expect(MatchLogicalObject(svcA, svcScoped) == MatchResult::Candidate,
             L"D-02 a missing scope key can only produce a candidate");
    s.expect(MatchLogicalObject(svcA, nameless) == MatchResult::Candidate,
             L"D-02 an unusable logical identity is capped at candidate");
    s.expect(nameless.crossSessionKey().empty(),
             L"D-02 an unusable logical identity yields no cross-session key");
    s.expect(!svcA.crossSessionKey().empty(),
             L"D-02 a complete logical identity yields a cross-session key");

    // --- 同名异对象：PID 复用 ---
    Snapshot earlier = MakeSnapshot("k-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 1U,
                                               "ev-e"));
    earlier.entities.push_back(
        MakeProcess("processes", kBootA, 4242U, 900ULL, "svc.exe", "e-1", 0U));

    Snapshot later = MakeSnapshot("k-late", kBootA, kUtcLater);
    later.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                             CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                             "ev-l"));
    later.entities.push_back(
        MakeProcess("processes", kBootA, 4242U, 1700ULL, "svc.exe", "l-1", 0U));

    const SnapshotComparison reuse = CompareSnapshots(earlier, later);
    s.expect(reuse.deltas.size() == 2U,
             L"D-02 a reused PID with a different creation time stays two objects");
    s.expect(reuse.removedCount == 1U && reuse.addedCount == 1U,
             L"D-02 the reused PID produces one removal and one addition, never a modification");
    s.expect(reuse.modifiedCount == 0U,
             L"D-02 two different process instances are never merged into one modification");

    // --- 排序变化：不得产生任何假增删 ---
    Snapshot orderedEarlier = MakeSnapshot("o-early", kBootA, kUtcEarlier);
    orderedEarlier.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                      CollectionStatus::Success, kBootA,
                                                      kUtcEarlier, 3U, "ev-e"));
    orderedEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 10U, 10ULL, "a.exe", "e-a", 0U));
    orderedEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 20U, 20ULL, "b.exe", "e-b", 1U));
    orderedEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 30U, 30ULL, "c.exe", "e-c", 2U));

    Snapshot orderedLater = MakeSnapshot("o-late", kBootA, kUtcLater);
    orderedLater.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                    CollectionStatus::Success, kBootA, kUtcLater,
                                                    3U, "ev-l"));
    orderedLater.entities.push_back(
        MakeProcess("processes", kBootA, 30U, 30ULL, "c.exe", "l-c", 0U));
    orderedLater.entities.push_back(
        MakeProcess("processes", kBootA, 10U, 10ULL, "a.exe", "l-a", 1U));
    orderedLater.entities.push_back(
        MakeProcess("processes", kBootA, 20U, 20ULL, "b.exe", "l-b", 2U));

    const SnapshotComparison reordered = CompareSnapshots(orderedEarlier, orderedLater);
    s.expect(reordered.addedCount == 0U && reordered.removedCount == 0U,
             L"D-02 reordering produces no phantom additions or removals");
    s.expect(reordered.modifiedCount == 0U, L"D-02 reordering produces no modifications");
    s.expect(reordered.unchangedCount == 3U, L"D-02 all three reordered objects stay unchanged");
    const EntityDelta* movedA = FindDelta(reordered, "a.exe");
    s.expect(movedA != nullptr && movedA->displayOrderChanged,
             L"D-02 the display-order change is recorded separately from the verdict");
    s.expect(movedA != nullptr && movedA->earlierDisplayOrder == 0U && movedA->laterDisplayOrder == 1U,
             L"D-02 both display orders are preserved for the reader");
    s.expect(reordered.conclusion == AnalysisConclusion::NoDifferenceObserved,
             L"D-02 a pure reorder over a fully covered identical scope observes no difference");

    // --- 重启前后：进程不许跨启动硬配，驱动可以 ---
    Snapshot bootOne = MakeSnapshot("b1", kBootA, kUtcEarlier);
    bootOne.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 1U,
                                               "ev-p1"));
    bootOne.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 1U,
                                               "ev-d1"));
    bootOne.entities.push_back(MakeProcess("processes", kBootA, 500U, 5000ULL, "svchost.exe", "e-p",
                                           0U));
    {
        SnapshotEntity driver = MakeDriverEntity("drivers", "\\SystemRoot\\System32\\acme.sys",
                                                 "RSDS-ACME-1", 0x600DU, 0x8000U, "e-d", 0U);
        driver.fields.push_back(NumberField("imageBase", 0xFFFFF80000100000ULL,
                                            FieldSemantics::LoadBaseAddress));
        driver.fields.push_back(TextField("startType", "boot"));
        bootOne.entities.push_back(driver);
    }

    Snapshot bootTwo = MakeSnapshot("b2", kBootB, kUtcLater);
    bootTwo.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                               CollectionStatus::Success, kBootB, kUtcLater, 1U,
                                               "ev-p2"));
    bootTwo.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                               CollectionStatus::Success, kBootB, kUtcLater, 1U,
                                               "ev-d2"));
    bootTwo.entities.push_back(MakeProcess("processes", kBootB, 500U, 9000ULL, "svchost.exe", "l-p",
                                           0U));
    {
        SnapshotEntity driver = MakeDriverEntity("drivers", "\\SystemRoot\\System32\\acme.sys",
                                                 "RSDS-ACME-1", 0x600DU, 0x8000U, "l-d", 0U);
        // 重启后装载基址一定不同 —— 这不是差异。
        driver.fields.push_back(NumberField("imageBase", 0xFFFFF80000940000ULL,
                                            FieldSemantics::LoadBaseAddress));
        driver.fields.push_back(TextField("startType", "boot"));
        bootTwo.entities.push_back(driver);
    }

    const SnapshotComparison reboot = CompareSnapshots(bootOne, bootTwo);
    s.expect(reboot.boot == CrossBootComparability::DifferentBoot,
             L"D-02 different boot ids are recognised");
    s.expect(reboot.removedCount == 0U && reboot.addedCount == 0U,
             L"D-02 a reboot does not turn every process into an add/remove pair");
    const EntityDelta* rebootProcess = FindDeltaByRaw(reboot, "e-p");
    s.expect(rebootProcess != nullptr && rebootProcess->change == EntityChange::NotComparable,
             L"D-02 a process instance across boots is NotComparable");
    s.expect(rebootProcess != nullptr &&
                 rebootProcess->laterState == EntitySideState::UnknownCrossBoot,
             L"D-02 the cross-boot reason is stated on the process delta");
    s.expect(rebootProcess != nullptr &&
                 Contains(rebootProcess->limitationKeys, "snapshot.limitation.crossBootInstance"),
             L"D-02 the cross-boot limitation key is emitted");
    const EntityDelta* rebootDriver = FindDelta(reboot, "\\SystemRoot\\System32\\acme.sys");
    s.expect(rebootDriver != nullptr && rebootDriver->change == EntityChange::Unchanged,
             L"D-02 the same driver across boots compares as unchanged");
    s.expect(rebootDriver != nullptr && rebootDriver->matchConfidence == MatchConfidence::Confirmed,
             L"D-02 the driver match across boots is confirmed by image identity");
    const FieldDelta* baseField =
        rebootDriver != nullptr ? FindField(*rebootDriver, "imageBase") : nullptr;
    s.expect(baseField != nullptr && baseField->change == FieldChange::NormalizedUnchanged,
             L"D-02 a changed load base is normalized away instead of becoming a difference");

    // --- 同一稳定键出现多条：配对关系无法确定，不许挑第一条硬配、也不许丢掉其余 ---
    Snapshot dupEarlier = MakeSnapshot("d-early", kBootA, kUtcEarlier);
    dupEarlier.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                  CollectionStatus::Success, kBootA, kUtcEarlier,
                                                  2U, "ev-e"));
    dupEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 55U, 550ULL, "dup.exe", "e-dup-1", 0U));
    dupEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 55U, 550ULL, "dup.exe", "e-dup-2", 1U));

    Snapshot dupLater = MakeSnapshot("d-late", kBootA, kUtcLater);
    dupLater.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                                "ev-l"));
    dupLater.entities.push_back(
        MakeProcess("processes", kBootA, 55U, 550ULL, "dup.exe", "l-dup-1", 0U));

    const SnapshotComparison dup = CompareSnapshots(dupEarlier, dupLater);
    s.expect(dup.deltas.size() == 3U,
             L"D-02 every record behind a duplicated identity key is still reported");
    s.expect(dup.addedCount == 0U && dup.removedCount == 0U && dup.unchangedCount == 0U,
             L"D-02 a duplicated identity key yields no verdict at all");
    s.expect(dup.notComparableCount == 3U,
             L"D-02 all records behind a duplicated key are NotComparable");
    s.expect(!dup.deltas.empty() &&
                 Contains(dup.deltas.front().limitationKeys,
                          "snapshot.limitation.duplicateIdentityKey"),
             L"D-02 the duplicated-key limitation is stated");

    // --- 无法稳定匹配 -> 不确定，不许变成假增删 ---
    Snapshot weakEarlier = MakeSnapshot("w-early", kBootA, kUtcEarlier);
    weakEarlier.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                   CollectionStatus::Success, kBootA, kUtcEarlier,
                                                   1U, "ev-e"));
    weakEarlier.entities.push_back(
        MakeProcess("processes", kBootA, 777U, 0ULL, "weak.exe", "e-w", 0U));

    Snapshot weakLater = MakeSnapshot("w-late", kBootA, kUtcLater);
    weakLater.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                 CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                                 "ev-l"));
    weakLater.entities.push_back(
        MakeProcess("processes", kBootA, 777U, 0ULL, "weak.exe", "l-w", 0U));

    const SnapshotComparison weak = CompareSnapshots(weakEarlier, weakLater);
    s.expect(weak.deltas.size() == 1U,
             L"D-02 two weak records with the same weak key are reported once");
    s.expect(!weak.deltas.empty() && weak.deltas.front().matchConfidence == MatchConfidence::Uncertain,
             L"D-02 a weak identity match is marked uncertain");
    s.expect(!weak.deltas.empty() && weak.deltas.front().identityKey.empty(),
             L"D-02 a weak identity gets no cross-session key");
    s.expect(weak.addedCount == 0U && weak.removedCount == 0U,
             L"D-02 an unstable match never becomes an add/remove pair");

    // 弱身份且一侧缺席：仍然不许判成移除。
    Snapshot weakGone = MakeSnapshot("w-gone", kBootA, kUtcLater);
    weakGone.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                CollectionStatus::Success, kBootA, kUtcLater, 0U,
                                                "ev-l"));
    const SnapshotComparison weakMissing = CompareSnapshots(weakEarlier, weakGone);
    s.expect(weakMissing.removedCount == 0U,
             L"D-02 a vanished weak-identity record is not reported as removed");
    s.expect(!weakMissing.deltas.empty() &&
                 weakMissing.deltas.front().change == EntityChange::NotComparable,
             L"D-02 a vanished weak-identity record is NotComparable");
    s.expect(!weakMissing.deltas.empty() &&
                 Contains(weakMissing.deltas.front().limitationKeys,
                          "snapshot.limitation.identityInsufficient"),
             L"D-02 the insufficient-identity limitation is stated");
}

// ---------------------------------------------------------------------------
// D-03 地址归一化
// ---------------------------------------------------------------------------
void TestAddressNormalization(KswordTests::Suite& s) {
    // 手算：base 0xFFFFF80000100000 + 0x1234 = 0xFFFFF80000101234
    //       base 0xFFFFF80000940000 + 0x1234 = 0xFFFFF80000941234
    constexpr std::uint64_t kEarlyBase = 0xFFFFF80000100000ULL;
    constexpr std::uint64_t kLateBase = 0xFFFFF80000940000ULL;
    constexpr std::uint64_t kSize = 0x8000ULL;
    constexpr std::uint64_t kEarlyHook = 0xFFFFF80000101234ULL;
    constexpr std::uint64_t kLateHook = 0xFFFFF80000941234ULL;
    constexpr std::uint64_t kLateHookMoved = 0xFFFFF80000942000ULL;  // RVA 0x2000

    auto makeHookSnapshot = [](const char* id, const char* bootId, std::uint64_t utc,
                               std::uint64_t hookAddress) {
        Snapshot snapshot = MakeSnapshot(id, bootId, utc);
        snapshot.partitions.push_back(MakePartition("hooks", ObjectKind::Service,
                                                    CollectionStatus::Success, bootId, utc, 1U,
                                                    "ev-hooks"));
        SnapshotEntity entity;
        entity.partitionId = "hooks";
        entity.kind = ObjectKind::Service;
        entity.logical.domain = "hook-point";
        entity.logical.name = "IofCallDriver";
        entity.rawRecordId = id;
        entity.fields.push_back(NumberField("target", hookAddress, FieldSemantics::KernelAddress));
        snapshot.entities.push_back(entity);
        return snapshot;
    };

    // --- 同映像不同装载基址：不得产生假差异 ---
    Snapshot earlier = makeHookSnapshot("h-early", kBootA, kUtcEarlier, kEarlyHook);
    earlier.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                         "RSDS-ACME-1", 0x600DU, kEarlyBase, kSize));
    Snapshot later = makeHookSnapshot("h-late", kBootB, kUtcLater, kLateHook);
    later.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys", "RSDS-ACME-1",
                                       0x600DU, kLateBase, kSize));

    const SnapshotComparison rebased = CompareSnapshots(earlier, later);
    const EntityDelta* hook = FindDelta(rebased, "IofCallDriver");
    s.expect(hook != nullptr && hook->change == EntityChange::Unchanged,
             L"D-03 the same image at a different load base produces no difference");
    const FieldDelta* target = hook != nullptr ? FindField(*hook, "target") : nullptr;
    s.expect(target != nullptr && target->change == FieldChange::NormalizedUnchanged,
             L"D-03 the rebased address is reported as normalized-unchanged");
    s.expect(target != nullptr &&
                 target->normalization.state == AddressNormalizationState::Normalized,
             L"D-03 normalization only happens when the images are confirmed comparable");
    s.expect(target != nullptr && target->normalization.earlierRva.present &&
                 target->normalization.earlierRva.value == 0x1234ULL,
             L"D-03 the earlier RVA is computed as 0x1234");
    s.expect(target != nullptr && target->normalization.laterRva.present &&
                 target->normalization.laterRva.value == 0x1234ULL,
             L"D-03 the later RVA is computed as 0x1234");
    s.expect(target != nullptr && target->earlierText == std::string("0xFFFFF80000101234"),
             L"D-03 the raw earlier address is still shown to the reader");
    s.expect(target != nullptr && target->laterText == std::string("0xFFFFF80000941234"),
             L"D-03 the raw later address is still shown to the reader");

    // --- 同映像，RVA 真的变了 -> 真差异 ---
    Snapshot moved = makeHookSnapshot("h-moved", kBootB, kUtcLater, kLateHookMoved);
    moved.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys", "RSDS-ACME-1",
                                       0x600DU, kLateBase, kSize));
    const SnapshotComparison movedPair = CompareSnapshots(earlier, moved);
    const EntityDelta* movedHook = FindDelta(movedPair, "IofCallDriver");
    const FieldDelta* movedTarget = movedHook != nullptr ? FindField(*movedHook, "target") : nullptr;
    s.expect(movedTarget != nullptr && movedTarget->change == FieldChange::Changed,
             L"D-03 a genuinely different RVA in the same image is a real change");
    s.expect(movedTarget != nullptr && movedTarget->normalization.laterRva.present &&
                 movedTarget->normalization.laterRva.value == 0x2000ULL,
             L"D-03 the moved RVA is computed as 0x2000");
    s.expect(movedHook != nullptr && movedHook->change == EntityChange::Modified,
             L"D-03 the entity carrying a changed address is Modified");

    // --- 不同版本相同 RVA：绝不当成相同代码 ---
    Snapshot otherVersion = makeHookSnapshot("h-ver", kBootB, kUtcLater, kLateHook);
    otherVersion.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                              "RSDS-ACME-2", 0x700DU, kLateBase, kSize));
    const SnapshotComparison versionPair = CompareSnapshots(earlier, otherVersion);
    const EntityDelta* versionHook = FindDelta(versionPair, "IofCallDriver");
    const FieldDelta* versionTarget =
        versionHook != nullptr ? FindField(*versionHook, "target") : nullptr;
    s.expect(versionTarget != nullptr && versionTarget->change == FieldChange::NotComparable,
             L"D-03 the same RVA in a different image version is NOT comparable");
    s.expect(versionTarget != nullptr &&
                 versionTarget->normalization.state ==
                     AddressNormalizationState::ImageVersionDiffers,
             L"D-03 the different-version reason is stated explicitly");
    s.expect(versionTarget != nullptr && versionTarget->normalization.earlierRva.present &&
                 versionTarget->normalization.laterRva.present &&
                 versionTarget->normalization.earlierRva.value ==
                     versionTarget->normalization.laterRva.value,
             L"D-03 the RVAs are equal yet the verdict is still not-comparable");
    s.expect(versionHook != nullptr && versionHook->change == EntityChange::PartiallyComparable,
             L"D-03 an entity whose only field is not comparable is PartiallyComparable");
    s.expect(versionPair.modifiedCount == 0U,
             L"D-03 a version difference does not manufacture a field change");

    // --- 模块缺失：不归一化，也不拿原值硬比 ---
    Snapshot noModules = makeHookSnapshot("h-nomod", kBootB, kUtcLater, kLateHook);
    const SnapshotComparison missingPair = CompareSnapshots(earlier, noModules);
    const EntityDelta* missingHook = FindDelta(missingPair, "IofCallDriver");
    const FieldDelta* missingTarget =
        missingHook != nullptr ? FindField(*missingHook, "target") : nullptr;
    s.expect(missingTarget != nullptr && missingTarget->change == FieldChange::NotComparable,
             L"D-03 a missing module means the address is not comparable");
    s.expect(missingTarget != nullptr &&
                 missingTarget->normalization.state == AddressNormalizationState::ModuleNotFound,
             L"D-03 the missing-module reason is stated explicitly");
    s.expect(missingTarget != nullptr && missingTarget->normalization.earlierRva.present &&
                 !missingTarget->normalization.laterRva.present,
             L"D-03 the resolvable side keeps its RVA and the other stays unknown");
    s.expect(missingPair.modifiedCount == 0U,
             L"D-03 a missing module never manufactures a difference");

    // --- 不同模块 ---
    Snapshot otherModule = makeHookSnapshot("h-other", kBootB, kUtcLater, kLateHook);
    otherModule.modules.push_back(MakeModule("m-other", "\\SystemRoot\\System32\\other.sys",
                                             "RSDS-OTHER", 0x900DU, kLateBase, kSize));
    const SnapshotComparison otherPair = CompareSnapshots(earlier, otherModule);
    const EntityDelta* otherHook = FindDelta(otherPair, "IofCallDriver");
    const FieldDelta* otherTarget = otherHook != nullptr ? FindField(*otherHook, "target") : nullptr;
    s.expect(otherTarget != nullptr &&
                 otherTarget->normalization.state == AddressNormalizationState::DifferentModule,
             L"D-03 resolving into a different module is stated as such");
    s.expect(otherTarget != nullptr && otherTarget->change == FieldChange::NotComparable,
             L"D-03 a different module is not comparable");

    // --- 只能候选匹配的映像：不确认可比就不归一化 ---
    Snapshot weakModule = makeHookSnapshot("h-weak", kBootB, kUtcLater, kLateHook);
    weakModule.modules.push_back(MakeModule("m-copy", "\\Device\\Copy\\acme.sys", "", 0x600DU,
                                            kLateBase, kSize));
    Snapshot weakEarlier = makeHookSnapshot("h-weak-e", kBootA, kUtcEarlier, kEarlyHook);
    weakEarlier.modules.push_back(MakeModule("m-orig", "\\SystemRoot\\System32\\acme.sys", "",
                                             0x600DU, kEarlyBase, kSize));
    const SnapshotComparison weakPair = CompareSnapshots(weakEarlier, weakModule);
    const EntityDelta* weakHook = FindDelta(weakPair, "IofCallDriver");
    const FieldDelta* weakTarget = weakHook != nullptr ? FindField(*weakHook, "target") : nullptr;
    s.expect(weakTarget != nullptr &&
                 weakTarget->normalization.state == AddressNormalizationState::ImageIdentityWeak,
             L"D-03 a candidate-only image match does not license normalization");
    s.expect(weakTarget != nullptr && weakTarget->change == FieldChange::NotComparable,
             L"D-03 a candidate-only image match yields not-comparable");

    // --- 地址未知：未知不是变化 ---
    Snapshot absentAddress = makeHookSnapshot("h-absent", kBootB, kUtcLater, kLateHook);
    absentAddress.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                               "RSDS-ACME-1", 0x600DU, kLateBase, kSize));
    absentAddress.entities.front().fields.clear();
    absentAddress.entities.front().fields.push_back(
        AbsentField("target", FieldSemantics::KernelAddress));
    const SnapshotComparison absentPair = CompareSnapshots(earlier, absentAddress);
    const EntityDelta* absentHook = FindDelta(absentPair, "IofCallDriver");
    const FieldDelta* absentTarget =
        absentHook != nullptr ? FindField(*absentHook, "target") : nullptr;
    s.expect(absentTarget != nullptr && absentTarget->change == FieldChange::Unknown,
             L"D-03 an uncollected address is unknown, not a change");
    s.expect(absentTarget != nullptr && absentTarget->earlierKnown && !absentTarget->laterKnown,
             L"D-03 the unknown side is flagged rather than rendered as an empty value");
    s.expect(absentPair.modifiedCount == 0U,
             L"D-03 an uncollected address never becomes a modification");
    s.expect(absentTarget != nullptr &&
                 absentTarget->normalization.state == AddressNormalizationState::ValueMissing,
             L"D-03 the missing-value reason is stated instead of a module verdict");

    // 同名字段两侧声明了不同的比较语义：说不清在比什么，不给结论。
    Snapshot mixedSemantics = makeHookSnapshot("h-mixed", kBootB, kUtcLater, kLateHook);
    mixedSemantics.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                                "RSDS-ACME-1", 0x600DU, kLateBase, kSize));
    mixedSemantics.entities.front().fields.clear();
    mixedSemantics.entities.front().fields.push_back(
        NumberField("target", kLateHook, FieldSemantics::Opaque));
    const SnapshotComparison mixedPair = CompareSnapshots(earlier, mixedSemantics);
    const EntityDelta* mixedHook = FindDelta(mixedPair, "IofCallDriver");
    const FieldDelta* mixedTarget = mixedHook != nullptr ? FindField(*mixedHook, "target") : nullptr;
    s.expect(mixedTarget != nullptr && mixedTarget->change == FieldChange::NotComparable,
             L"D-03 two sides declaring different field semantics are not comparable");
    s.expect(mixedPair.modifiedCount == 0U,
             L"D-03 a semantics mismatch never becomes a modification");

    // --- 模块尺寸未知：不许把整个地址空间都算成"落在这个模块里" ---
    Snapshot sizelessModule = makeHookSnapshot("h-nosize", kBootB, kUtcLater, kLateHook);
    {
        SnapshotModule module;
        module.moduleId = "m-nosize";
        module.identity.imagePath = "\\SystemRoot\\System32\\acme.sys";
        module.identity.pdbSignature = "RSDS-ACME-1";
        module.identity.timeDateStamp = OptionalU64::of(0x600DU);
        module.identity.imageSize = OptionalU64::of(kSize);
        module.imageBase = OptionalU64::of(kLateBase);  // 尺寸未知
        sizelessModule.modules.push_back(module);
    }
    const SnapshotComparison sizelessPair = CompareSnapshots(earlier, sizelessModule);
    const EntityDelta* sizelessHook = FindDelta(sizelessPair, "IofCallDriver");
    const FieldDelta* sizelessTarget =
        sizelessHook != nullptr ? FindField(*sizelessHook, "target") : nullptr;
    s.expect(sizelessTarget != nullptr &&
                 sizelessTarget->normalization.state == AddressNormalizationState::ModuleNotFound,
             L"D-03 a module with unknown size never claims an address");
    s.expect(sizelessPair.modifiedCount == 0U,
             L"D-03 a module with unknown size does not manufacture a difference");

    // 地址正好落在映像末尾之后：区间是半开的，不得被算成命中。
    Snapshot pastEndEarlier = makeHookSnapshot("h-past-e", kBootA, kUtcEarlier, kEarlyBase + kSize);
    pastEndEarlier.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                                "RSDS-ACME-1", 0x600DU, kEarlyBase, kSize));
    Snapshot pastEndLater = makeHookSnapshot("h-past-l", kBootB, kUtcLater, kLateBase + kSize);
    pastEndLater.modules.push_back(MakeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                              "RSDS-ACME-1", 0x600DU, kLateBase, kSize));
    const SnapshotComparison pastEnd = CompareSnapshots(pastEndEarlier, pastEndLater);
    const EntityDelta* pastHook = FindDelta(pastEnd, "IofCallDriver");
    const FieldDelta* pastTarget = pastHook != nullptr ? FindField(*pastHook, "target") : nullptr;
    s.expect(pastTarget != nullptr &&
                 pastTarget->normalization.state == AddressNormalizationState::ModuleNotFound,
             L"D-03 an address one byte past the image end is outside the image");

    // --- 弱映像身份的驱动实体：候选匹配不足以把基址差异抹掉 ---
    auto makeWeakDriverSnapshot = [](const char* id, const char* bootId, std::uint64_t utc,
                                     std::uint64_t base) {
        Snapshot snapshot = MakeSnapshot(id, bootId, utc);
        snapshot.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                                    CollectionStatus::Success, bootId, utc, 1U,
                                                    "ev-drv"));
        SnapshotEntity entity;
        entity.partitionId = "drivers";
        entity.kind = ObjectKind::Driver;
        entity.driver.imagePath = "\\??\\C:\\tmp\\unsigned.sys";  // 没有 pdb、没有 stamp/size
        entity.rawRecordId = id;
        entity.fields.push_back(NumberField("imageBase", base, FieldSemantics::LoadBaseAddress));
        snapshot.entities.push_back(entity);
        return snapshot;
    };
    const SnapshotComparison weakDriver =
        CompareSnapshots(makeWeakDriverSnapshot("wd-e", kBootA, kUtcEarlier, kEarlyBase),
                         makeWeakDriverSnapshot("wd-l", kBootB, kUtcLater, kLateBase));
    const EntityDelta* weakDriverDelta = FindDelta(weakDriver, "\\??\\C:\\tmp\\unsigned.sys");
    s.expect(weakDriverDelta != nullptr &&
                 weakDriverDelta->matchConfidence == MatchConfidence::Uncertain,
             L"D-03 a driver with only a path matches at most as uncertain");
    const FieldDelta* weakDriverBase =
        weakDriverDelta != nullptr ? FindField(*weakDriverDelta, "imageBase") : nullptr;
    s.expect(weakDriverBase != nullptr &&
                 weakDriverBase->normalization.state == AddressNormalizationState::ImageIdentityWeak,
             L"D-03 a candidate-only driver identity does not license base normalization");
    s.expect(weakDriverBase != nullptr && weakDriverBase->change == FieldChange::NotComparable,
             L"D-03 an unconfirmed image identity leaves the base not comparable");
    s.expect(weakDriver.modifiedCount == 0U,
             L"D-03 an unconfirmed image identity does not manufacture a modification");

    // --- LoadBaseAddress 语义只在有映像身份时才敢归一化 ---
    Snapshot svcEarlier = MakeSnapshot("s-early", kBootA, kUtcEarlier);
    svcEarlier.partitions.push_back(MakePartition("svc", ObjectKind::Service,
                                                  CollectionStatus::Success, kBootA, kUtcEarlier,
                                                  1U, "ev-e"));
    {
        SnapshotEntity entity = MakeServiceEntity("svc", "AcmeSvc", "e-s", 0U);
        entity.fields.push_back(NumberField("imageBase", kEarlyBase, FieldSemantics::LoadBaseAddress));
        svcEarlier.entities.push_back(entity);
    }
    Snapshot svcLater = MakeSnapshot("s-late", kBootA, kUtcLater);
    svcLater.partitions.push_back(MakePartition("svc", ObjectKind::Service,
                                                CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                                "ev-l"));
    {
        SnapshotEntity entity = MakeServiceEntity("svc", "AcmeSvc", "l-s", 0U);
        entity.fields.push_back(NumberField("imageBase", kLateBase, FieldSemantics::LoadBaseAddress));
        svcLater.entities.push_back(entity);
    }
    const SnapshotComparison svcPair = CompareSnapshots(svcEarlier, svcLater);
    const EntityDelta* svcDelta = FindDelta(svcPair, "AcmeSvc");
    const FieldDelta* svcBase = svcDelta != nullptr ? FindField(*svcDelta, "imageBase") : nullptr;
    s.expect(svcBase != nullptr && svcBase->change == FieldChange::NotComparable,
             L"D-03 a load base on an entity without image identity is not comparable");
    s.expect(svcBase != nullptr &&
                 svcBase->normalization.state == AddressNormalizationState::ImageIdentityWeak,
             L"D-03 the missing image identity is stated as the reason");
    s.expect(svcPair.modifiedCount == 0U,
             L"D-03 an unnormalizable load base does not become a modification");
}

// ---------------------------------------------------------------------------
// D-04 未知不等于删除
// ---------------------------------------------------------------------------
Snapshot BuildFourPartitionSnapshot(const char* id, std::uint64_t utc, const char* prefix) {
    Snapshot snapshot = MakeSnapshot(id, kBootA, utc);
    snapshot.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                CollectionStatus::Success, kBootA, utc, 1U,
                                                "ev-proc"));
    snapshot.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                                CollectionStatus::Success, kBootA, utc, 1U,
                                                "ev-drv"));
    snapshot.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                                CollectionStatus::Success, kBootA, utc, 1U,
                                                "ev-svc"));
    snapshot.partitions.push_back(MakePartition("files", ObjectKind::File, CollectionStatus::Success,
                                                kBootA, utc, 1U, "ev-file"));
    snapshot.entities.push_back(
        MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", (std::string(prefix) + "-p").c_str(), 0U));
    snapshot.entities.push_back(MakeDriverEntity("drivers", "\\SystemRoot\\System32\\acme.sys",
                                                 "RSDS-ACME-1", 0x600DU, 0x8000U,
                                                 (std::string(prefix) + "-d").c_str(), 0U));
    snapshot.entities.push_back(
        MakeServiceEntity("services", "AcmeSvc", (std::string(prefix) + "-s").c_str(), 0U));
    {
        SnapshotEntity file;
        file.partitionId = "files";
        file.kind = ObjectKind::File;
        file.file.path = "C:\\Program Files\\Acme\\acme.exe";
        file.file.contentHash = "sha256:aaaa";
        file.rawRecordId = std::string(prefix) + "-f";
        snapshot.entities.push_back(file);
    }
    return snapshot;
}

void TestUnknownIsNotRemoval(KswordTests::Suite& s) {
    const Snapshot baseEarlier = BuildFourPartitionSnapshot("u-early", kUtcEarlier, "e");
    const Snapshot baseLater = BuildFourPartitionSnapshot("u-late", kUtcLater, "l");

    const SnapshotComparison clean = CompareSnapshots(baseEarlier, baseLater);
    s.expect(clean.unchangedCount == 4U, L"D-04 the untouched baseline compares as four unchanged");
    s.expect(clean.removedCount == 0U && clean.addedCount == 0U,
             L"D-04 the untouched baseline reports no additions or removals");
    s.expect(clean.conclusion == AnalysisConclusion::NoDifferenceObserved,
             L"D-04 a fully covered identical pair observes no difference");
    s.expect(clean.selfCheckPassed, L"D-04 the baseline comparison passes its self check");

    struct Injection final {
        const char* partitionId;
        const char* entityRaw;
        CollectionStatus status;
    };
    const Injection injections[] = {
        {"processes", "e-p", CollectionStatus::AccessDenied},
        {"drivers", "e-d", CollectionStatus::Unsupported},
        {"services", "e-s", CollectionStatus::Timeout},
        {"files", "e-f", CollectionStatus::Error},
    };

    for (const Injection& injection : injections) {
        Snapshot broken = baseLater;
        for (SnapshotPartition& partition : broken.partitions) {
            if (partition.partitionId == std::string(injection.partitionId)) {
                partition.envelope.outcome = CollectionOutcome::failure(
                    injection.status, "NTSTATUS", 0xC0000022ULL, "collector reported failure");
                partition.envelope.coverage = CoverageAccount{};
            }
        }
        // 采集失败的 collector 产不出行 —— 这正是"空表被读成全部移除"的现场。
        std::vector<SnapshotEntity> kept;
        for (const SnapshotEntity& entity : broken.entities) {
            if (entity.partitionId != std::string(injection.partitionId)) {
                kept.push_back(entity);
            }
        }
        broken.entities = kept;

        const SnapshotComparison result = CompareSnapshots(baseEarlier, broken);
        s.expect(result.removedCount == 0U,
                 L"D-04 an injected collector failure never reports removals");
        const EntityDelta* orphan = FindDeltaByRaw(result, injection.entityRaw);
        s.expect(orphan != nullptr && orphan->change == EntityChange::NotComparable,
                 L"D-04 the orphaned entity is NotComparable");
        s.expect(orphan != nullptr && orphan->laterState == EntitySideState::UnknownSourceFailed,
                 L"D-04 the failed side is marked source-failed, not absent");
        s.expect(orphan != nullptr &&
                     Contains(orphan->limitationKeys, "snapshot.limitation.sourceFailed"),
                 L"D-04 the source-failure limitation is stated on the delta");
        const PartitionAccount* account = FindAccount(result, injection.partitionId);
        s.expect(account != nullptr && account->laterStatus == injection.status,
                 L"D-04 the original collection status is preserved in the account");
        s.expect(account != nullptr && !account->comparable,
                 L"D-04 a failed partition is not comparable");
        s.expect(account != nullptr && account->conclusion == AnalysisConclusion::NoEvidence,
                 L"D-04 a failed partition concludes NoEvidence, never NoDifferenceObserved");
        // 其余三个分区照常比较 —— 一个 collector 失败不牵连别的。
        s.expect(result.unchangedCount == 3U,
                 L"D-04 the successfully covered partitions still compare on their own");
        s.expect(result.conclusion == AnalysisConclusion::Indeterminate,
                 L"D-04 a partially failed comparison is Indeterminate");
    }

    // 分区整体缺席：必须显式落成 NotCollected 并计入账目，不能被跳过。
    {
        Snapshot missing = baseLater;
        std::vector<SnapshotPartition> keptPartitions;
        for (const SnapshotPartition& partition : missing.partitions) {
            if (partition.partitionId != std::string("drivers")) {
                keptPartitions.push_back(partition);
            }
        }
        missing.partitions = keptPartitions;
        std::vector<SnapshotEntity> keptEntities;
        for (const SnapshotEntity& entity : missing.entities) {
            if (entity.partitionId != std::string("drivers")) {
                keptEntities.push_back(entity);
            }
        }
        missing.entities = keptEntities;

        const SnapshotComparison result = CompareSnapshots(baseEarlier, missing);
        s.expect(result.partitions.size() == 4U,
                 L"D-04 an entirely absent partition still appears in the account");
        const PartitionAccount* account = FindAccount(result, "drivers");
        s.expect(account != nullptr && !account->laterPresent,
                 L"D-04 the absent partition is recorded as absent");
        s.expect(account != nullptr && account->laterStatus == CollectionStatus::NotCollected,
                 L"D-04 an absent partition is NotCollected, not silently successful");
        s.expect(account != nullptr &&
                     Contains(account->limitationKeys, "snapshot.partition.laterNotCollected"),
                 L"D-04 the absent partition states its limitation");
        s.expect(result.removedCount == 0U,
                 L"D-04 an entirely absent partition never reports removals");
        s.expect(result.conclusion != AnalysisConclusion::NoDifferenceObserved,
                 L"D-04 an entirely absent partition cannot yield NoDifferenceObserved");
    }

    // 已成功覆盖部分仍可单独比较：drivers 失败的同时 processes 真的少了一行。
    {
        Snapshot mixed = baseLater;
        for (SnapshotPartition& partition : mixed.partitions) {
            if (partition.partitionId == std::string("drivers")) {
                partition.envelope.outcome = CollectionOutcome::failure(
                    CollectionStatus::AccessDenied, "WIN32", 5ULL, "access denied");
                partition.envelope.coverage = CoverageAccount{};
            }
            if (partition.partitionId == std::string("processes")) {
                partition.envelope.coverage.totalKnown = OptionalU64::of(0U);
                partition.envelope.coverage.succeeded = 0U;
            }
        }
        std::vector<SnapshotEntity> kept;
        for (const SnapshotEntity& entity : mixed.entities) {
            if (entity.partitionId != std::string("drivers") &&
                entity.partitionId != std::string("processes")) {
                kept.push_back(entity);
            }
        }
        mixed.entities = kept;

        const SnapshotComparison result = CompareSnapshots(baseEarlier, mixed);
        s.expect(result.removedCount == 1U,
                 L"D-04 a covered partition still reports its own genuine removal");
        const EntityDelta* removed = FindDeltaByRaw(result, "e-p");
        s.expect(removed != nullptr && removed->change == EntityChange::Removed,
                 L"D-04 the removal comes from the partition that really covered its scope");
        const EntityDelta* blocked = FindDeltaByRaw(result, "e-d");
        s.expect(blocked != nullptr && blocked->change == EntityChange::NotComparable,
                 L"D-04 the failed partition's entity stays not comparable in the same run");
        s.expect(result.conclusion == AnalysisConclusion::DifferenceObserved,
                 L"D-04 a genuine removal alongside a failure is still DifferenceObserved");
    }

    // 实体引用了一个从未声明账目的分区：必须进账并落成 NotCollected，不能被静默跳过
    // ——"没有账目"和"账目说采全了"绝不能是同一种结果。
    {
        Snapshot rogueEarlier = baseEarlier;
        SnapshotEntity rogue = MakeServiceEntity("rogue", "GhostSvc", "e-rogue", 0U);
        rogueEarlier.entities.push_back(rogue);

        const SnapshotComparison result = CompareSnapshots(rogueEarlier, baseLater);
        const PartitionAccount* account = FindAccount(result, "rogue");
        s.expect(account != nullptr,
                 L"D-04 a partition referenced only by entities still appears in the account");
        s.expect(account != nullptr && !account->earlierPresent && !account->laterPresent,
                 L"D-04 an undeclared partition is recorded as absent on both sides");
        s.expect(account != nullptr && account->earlierStatus == CollectionStatus::NotCollected &&
                     account->laterStatus == CollectionStatus::NotCollected,
                 L"D-04 an undeclared partition is NotCollected on both sides");
        s.expect(account != nullptr && !account->comparable,
                 L"D-04 an undeclared partition is not comparable");
        const EntityDelta* ghost = FindDeltaByRaw(result, "e-rogue");
        s.expect(ghost != nullptr && ghost->change == EntityChange::NotComparable,
                 L"D-04 an entity without a collection account cannot be compared");
        s.expect(result.removedCount == 0U,
                 L"D-04 an entity without a collection account is never reported as removed");
    }

    // 唯一的分区也失败：整份比较没有任何可用观测，结论必须是 NoEvidence。
    {
        Snapshot soloEarlier = MakeSnapshot("solo-e", kBootA, kUtcEarlier);
        soloEarlier.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                                       CollectionStatus::Success, kBootA,
                                                       kUtcEarlier, 1U, "ev-e"));
        soloEarlier.entities.push_back(
            MakeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "solo-p", 0U));

        Snapshot soloLater = MakeSnapshot("solo-l", kBootA, kUtcLater);
        SnapshotPartition denied = MakePartition("processes", ObjectKind::Process,
                                                 CollectionStatus::AccessDenied, kBootA, kUtcLater,
                                                 0U, "ev-l");
        denied.envelope.coverage = CoverageAccount{};
        denied.envelope.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32",
                                                             5ULL, "access denied");
        soloLater.partitions.push_back(denied);

        const SnapshotComparison result = CompareSnapshots(soloEarlier, soloLater);
        s.expect(result.conclusion == AnalysisConclusion::NoEvidence,
                 L"D-04 a comparison with no usable partition concludes NoEvidence");
        s.expect(result.removedCount == 0U,
                 L"D-04 a comparison with no usable partition reports no removals");
        s.expect(result.notComparableCount == 1U,
                 L"D-04 the orphaned entity is still reported, just not comparable");
    }

    // 旧侧失败同样不许变成"新增"。
    {
        Snapshot brokenEarlier = baseEarlier;
        for (SnapshotPartition& partition : brokenEarlier.partitions) {
            if (partition.partitionId == std::string("services")) {
                partition.envelope.outcome = CollectionOutcome::failure(
                    CollectionStatus::Unsupported, "WIN32", 50ULL, "not supported");
                partition.envelope.coverage = CoverageAccount{};
            }
        }
        std::vector<SnapshotEntity> kept;
        for (const SnapshotEntity& entity : brokenEarlier.entities) {
            if (entity.partitionId != std::string("services")) {
                kept.push_back(entity);
            }
        }
        brokenEarlier.entities = kept;
        const SnapshotComparison result = CompareSnapshots(brokenEarlier, baseLater);
        s.expect(result.addedCount == 0U,
                 L"D-04 an earlier-side collector failure never reports additions");
        const EntityDelta* svc = FindDeltaByRaw(result, "l-s");
        s.expect(svc != nullptr && svc->earlierState == EntitySideState::UnknownSourceFailed,
                 L"D-04 the failed earlier side is marked source-failed");
    }
}

// ---------------------------------------------------------------------------
// D-05 变化说明
// ---------------------------------------------------------------------------
void TestChangeExplanation(KswordTests::Suite& s) {
    Snapshot earlier = MakeSnapshot("c-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 1U,
                                               "ev-svc-early"));
    {
        SnapshotEntity entity = MakeServiceEntity("services", "AcmeSvc", "e-svc", 0U);
        entity.fields.push_back(TextField("startType", "manual"));
        entity.fields.push_back(TextField("imagePath", "C:\\Program Files\\Acme\\acme.exe"));
        earlier.entities.push_back(entity);
    }

    Snapshot later = MakeSnapshot("c-late", kBootA, kUtcLater);
    later.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                             CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                             "ev-svc-late"));
    {
        SnapshotEntity entity = MakeServiceEntity("services", "AcmeSvc", "l-svc", 0U);
        entity.fields.push_back(TextField("startType", "auto"));
        entity.fields.push_back(TextField("imagePath", "C:\\Program Files\\Acme\\acme.exe"));
        later.entities.push_back(entity);
    }

    const SnapshotComparison plain = CompareSnapshots(earlier, later);
    const EntityDelta* svc = FindDelta(plain, "AcmeSvc");
    s.expect(svc != nullptr && svc->change == EntityChange::Modified,
             L"D-05 a changed configuration field makes the entity Modified");
    s.expect(svc != nullptr && svc->fields.size() == 1U,
             L"D-05 only the field that actually has something to say is reported");
    const FieldDelta* startType = svc != nullptr ? FindField(*svc, "startType") : nullptr;
    s.expect(startType != nullptr && startType->earlierText == std::string("manual"),
             L"D-05 the old value is reported verbatim");
    s.expect(startType != nullptr && startType->laterText == std::string("auto"),
             L"D-05 the new value is reported verbatim");
    s.expect(startType != nullptr && startType->earlierKnown && startType->laterKnown,
             L"D-05 both sides are flagged as known");
    s.expect(startType != nullptr && startType->earlierCollectorId == std::string("services"),
             L"D-05 the field change names the collector it came from");
    s.expect(startType != nullptr && startType->earlierEvidenceId == std::string("ev-svc-early"),
             L"D-05 the field change references the earlier evidence id");
    s.expect(startType != nullptr && startType->laterEvidenceId == std::string("ev-svc-late"),
             L"D-05 the field change references the later evidence id");
    s.expect(startType != nullptr && startType->earlierObservedUtc100ns.present &&
                 startType->earlierObservedUtc100ns.value == kUtcEarlier + 1000ULL,
             L"D-05 the field change carries the earlier observation time");
    s.expect(startType != nullptr && startType->laterObservedUtc100ns.present &&
                 startType->laterObservedUtc100ns.value == kUtcLater + 1000ULL,
             L"D-05 the field change carries the later observation time");
    s.expect(svc != nullptr && svc->earlierRawRecordId == std::string("e-svc") &&
                 svc->laterRawRecordId == std::string("l-svc"),
             L"D-05 the delta links back to both source records");

    // 风险解释与变化事实分开：没有声明规则时不产生任何优先级。
    s.expect(svc != nullptr && svc->review.priority == ReviewPriority::NotAssessed,
             L"D-05 with no declared policy a configuration change carries no review priority");
    s.expect(svc != nullptr && svc->review.reasonKeys.empty(),
             L"D-05 with no declared policy there are no review reasons");

    SnapshotCompareOptions options;
    ReviewRule rule;
    rule.partitionId = "services";
    rule.fieldName = "startType";
    rule.priority = ReviewPriority::NeedsReview;
    rule.reasonKey = "review.service.startTypeChanged";
    options.reviewRules.push_back(rule);
    ReviewRule unrelated;
    unrelated.partitionId = "services";
    unrelated.fieldName = "imagePath";
    unrelated.priority = ReviewPriority::NeedsReview;
    unrelated.reasonKey = "review.service.imagePathChanged";
    options.reviewRules.push_back(unrelated);

    const SnapshotComparison reviewed = CompareSnapshots(earlier, later, options);
    const EntityDelta* reviewedSvc = FindDelta(reviewed, "AcmeSvc");
    s.expect(reviewedSvc != nullptr && reviewedSvc->review.priority == ReviewPriority::NeedsReview,
             L"D-05 a declared review rule raises the priority");
    s.expect(reviewedSvc != nullptr &&
                 Contains(reviewedSvc->review.reasonKeys, "review.service.startTypeChanged"),
             L"D-05 the declared reason key is attached");
    s.expect(reviewedSvc != nullptr &&
                 !Contains(reviewedSvc->review.reasonKeys, "review.service.imagePathChanged"),
             L"D-05 a rule for an unchanged field does not fire");
    s.expect(reviewedSvc != nullptr && reviewedSvc->change == EntityChange::Modified,
             L"D-05 the review priority does not alter the change fact");
    s.expect(reviewed.modifiedCount == plain.modifiedCount,
             L"D-05 declaring a review policy does not change the observed counts");

    // 未知字段不得被写成"变成了空值"。
    Snapshot absentLater = later;
    absentLater.entities.front().fields.clear();
    absentLater.entities.front().fields.push_back(AbsentField("startType"));
    absentLater.entities.front().fields.push_back(
        TextField("imagePath", "C:\\Program Files\\Acme\\acme.exe"));
    const SnapshotComparison absentPair = CompareSnapshots(earlier, absentLater);
    const EntityDelta* absentSvc = FindDelta(absentPair, "AcmeSvc");
    const FieldDelta* absentField =
        absentSvc != nullptr ? FindField(*absentSvc, "startType") : nullptr;
    s.expect(absentField != nullptr && absentField->change == FieldChange::Unknown,
             L"D-05 an uncollected field is unknown rather than changed");
    s.expect(absentField != nullptr && !absentField->laterKnown && absentField->laterText.empty(),
             L"D-05 an uncollected field does not render as an empty value");
    s.expect(absentSvc != nullptr && absentSvc->change == EntityChange::PartiallyComparable,
             L"D-05 an entity with one unknown field is PartiallyComparable, not Modified");
    s.expect(absentPair.modifiedCount == 0U,
             L"D-05 an uncollected field never counts as a modification");
}

// ---------------------------------------------------------------------------
// D-06 持久化兼容
// ---------------------------------------------------------------------------
void TestPersistence(KswordTests::Suite& s) {
    // --- 手写的旧版 fixture：只填首个格式版本要求的字段 ---
    const char* legacy =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"versionMinor\":0,"
        "\"snapshotId\":\"legacy-1\","
        "\"partitions\":[{\"partitionId\":\"services\",\"kind\":\"Service\",\"coversScope\":true,"
        "\"envelope\":{\"outcome\":{\"status\":\"Success\"},"
        "\"coverage\":{\"totalKnown\":\"1\",\"succeeded\":\"1\"}}}],"
        "\"entities\":[{\"partitionId\":\"services\",\"kind\":\"Service\",\"rawRecordId\":\"row-1\","
        "\"logical\":{\"domain\":\"service\",\"name\":\"AcmeSvc\"},"
        "\"fields\":[{\"name\":\"startType\",\"kind\":\"Text\",\"text\":\"auto\"}]}]}";
    const SnapshotLoadResult legacyResult = ReadSnapshotJson(legacy);
    s.expect(legacyResult.status == SnapshotLoadStatus::Ok,
             L"D-06 a legacy first-version fixture still loads");
    s.expect(legacyResult.versionMajor == 1U && legacyResult.versionMinor == 0U,
             L"D-06 the legacy fixture reports version 1.0");
    s.expect(legacyResult.snapshot.snapshotId == std::string("legacy-1"),
             L"D-06 the legacy snapshot id is read back");
    s.expect(legacyResult.snapshot.entities.size() == 1U,
             L"D-06 the legacy fixture yields exactly one entity");
    s.expect(!legacyResult.snapshot.entities.empty() &&
                 legacyResult.snapshot.entities.front().logical.name == std::string("AcmeSvc"),
             L"D-06 the legacy logical identity is read back");
    s.expect(!legacyResult.snapshot.entities.empty() &&
                 legacyResult.snapshot.entities.front().fields.size() == 1U &&
                 legacyResult.snapshot.entities.front().fields.front().text == std::string("auto"),
             L"D-06 the legacy field value is read back");
    s.expect(!legacyResult.snapshot.partitions.empty() &&
                 legacyResult.snapshot.partitions.front().envelope.coverage.totalKnown.present &&
                 legacyResult.snapshot.partitions.front().envelope.coverage.totalKnown.value == 1ULL,
             L"D-06 the legacy coverage account is read back losslessly");
    s.expect(!legacyResult.snapshot.scope.declared,
             L"D-06 a legacy snapshot without a scope block stays undeclared");
    const SnapshotComparison legacyPair =
        CompareSnapshots(legacyResult.snapshot, legacyResult.snapshot);
    s.expect(legacyPair.scope == ScopeComparability::Unknown,
             L"D-06 legacy data with no declared scope is still viewable but scope-unknown");
    s.expect(legacyPair.removedCount == 0U,
             L"D-06 legacy data with no declared scope never reports removals");

    // --- 未来的可选字段：保留并原样回写 ---
    const char* future =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"versionMinor\":4,"
        "\"snapshotId\":\"future-1\",\"futureTopLevel\":{\"nested\":\"keep-top\"},"
        "\"entities\":[{\"partitionId\":\"services\",\"kind\":\"Service\","
        "\"logical\":{\"domain\":\"service\",\"name\":\"AcmeSvc\"},"
        "\"futureEntityField\":\"keep-entity\"}]}";
    const SnapshotLoadResult futureResult = ReadSnapshotJson(future);
    s.expect(futureResult.status == SnapshotLoadStatus::OkWithUnknownFields,
             L"D-06 unknown optional fields load with an explicit status");
    s.expect(futureResult.ok(), L"D-06 unknown optional fields are not an error");
    s.expect(futureResult.versionMinor == 4U,
             L"D-06 a newer minor version is accepted and reported");
    s.expect(Contains(futureResult.unknownFieldPaths, "root.futureTopLevel"),
             L"D-06 the unknown top-level field is listed");
    s.expect(Contains(futureResult.unknownFieldPaths, "root.entities[].futureEntityField"),
             L"D-06 the unknown entity field is listed");
    const std::string rewritten = WriteSnapshotJson(futureResult.snapshot);
    s.expect(TextContains(rewritten, "keep-top"),
             L"D-06 an unknown top-level field survives a save");
    s.expect(TextContains(rewritten, "keep-entity"),
             L"D-06 an unknown entity field survives a save");
    const SnapshotLoadResult reloaded = ReadSnapshotJson(rewritten);
    s.expect(reloaded.status == SnapshotLoadStatus::OkWithUnknownFields,
             L"D-06 the rewritten document still reports its unknown fields");

    // --- 未来的主版本：明确拒绝 ---
    const char* futureMajor =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":2,\"versionMinor\":0,"
        "\"snapshotId\":\"v2\",\"entities\":[]}";
    const SnapshotLoadResult majorResult = ReadSnapshotJson(futureMajor);
    s.expect(majorResult.status == SnapshotLoadStatus::UnsupportedMajorVersion,
             L"D-06 an unknown major version is rejected explicitly");
    s.expect(!majorResult.ok(), L"D-06 an unknown major version is not treated as loadable");
    s.expect(majorResult.versionMajor == 2U,
             L"D-06 the rejected major version is reported back");
    s.expect(majorResult.snapshot.entities.empty() && majorResult.snapshot.snapshotId.empty(),
             L"D-06 a rejected document leaves no half-parsed snapshot behind");

    // --- 损坏格式 ---
    const SnapshotLoadResult broken = ReadSnapshotJson("{\"schema\":");
    s.expect(broken.status == SnapshotLoadStatus::MalformedJson,
             L"D-06 malformed JSON produces an explicit error state");
    s.expect(!broken.errorDetail.empty(),
             L"D-06 the malformed-JSON error keeps the parser's own status name");
    s.expect(broken.snapshot.entities.empty(),
             L"D-06 malformed JSON leaves no partially applied snapshot");
    const SnapshotLoadResult empty = ReadSnapshotJson("");
    s.expect(empty.status == SnapshotLoadStatus::EmptyInput,
             L"D-06 empty input is distinguished from malformed input");
    const SnapshotLoadResult wrongSchema =
        ReadSnapshotJson("{\"schema\":\"other.tool\",\"versionMajor\":1}");
    s.expect(wrongSchema.status == SnapshotLoadStatus::WrongSchemaId,
             L"D-06 a foreign schema id is rejected as such");
    const SnapshotLoadResult noSchema = ReadSnapshotJson("{\"versionMajor\":1}");
    s.expect(noSchema.status == SnapshotLoadStatus::MissingSchema,
             L"D-06 a missing schema id is its own error state");
    const SnapshotLoadResult badEnum =
        ReadSnapshotJson("{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,"
                         "\"entities\":[{\"partitionId\":\"p\",\"kind\":\"Alien\"}]}");
    s.expect(badEnum.status == SnapshotLoadStatus::InvalidFieldValue,
             L"D-06 an unknown enum name fails instead of silently defaulting");
    s.expect(TextContains(badEnum.errorDetail, "Alien"),
             L"D-06 the offending enum value is reported back");
    const SnapshotLoadResult floatRejected =
        ReadSnapshotJson("{\"schema\":\"ksword.snapshot\",\"versionMajor\":1.0}");
    s.expect(floatRejected.status == SnapshotLoadStatus::MalformedJson,
             L"D-06 a floating point number is rejected by the lossless reader");

    // --- 往返：先构造一份完整快照，再核对手写的期望值 ---
    Snapshot rich = MakeSnapshot("rt-1", kBootA, kUtcEarlier);
    rich.scope.wholeDomain = false;
    rich.scope.selectors = {"C:", "D:"};
    rich.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                            CollectionStatus::Partial, kBootA, kUtcEarlier, 9U,
                                            "ev-rt"));
    rich.partitions.back().envelope.outcome.nativeCode = OptionalU64::of(0xC0000022ULL);
    rich.partitions.back().envelope.outcome.nativeCodeDomain = "NTSTATUS";
    rich.partitions.back().envelope.outcome.message = "partial enumeration";
    rich.partitions.back().envelope.coverage.truncated = 2U;
    rich.modules.push_back(MakeModule("m1", "\\SystemRoot\\acme.sys", "RSDS-1", 0x600DU,
                                      0xFFFFF80000100000ULL, 0x8000ULL));
    {
        SnapshotEntity driver = MakeDriverEntity("drivers", "\\SystemRoot\\acme.sys", "RSDS-1",
                                                 0x600DU, 0x8000U, "row-9", 3U);
        driver.fields.push_back(NumberField("target", 0xFFFFF80000101234ULL,
                                            FieldSemantics::KernelAddress));
        driver.fields.push_back(AbsentField("notes"));
        rich.entities.push_back(driver);
    }
    const std::string written = WriteSnapshotJson(rich, 0U);
    s.expect(TextContains(written, "\"schema\":\"ksword.snapshot\""),
             L"D-06 the written document declares the schema id");
    s.expect(TextContains(written, "0xFFFFF80000101234"),
             L"D-06 a 64-bit address is written as a lossless hex string");
    const SnapshotLoadResult roundTrip = ReadSnapshotJson(written);
    s.expect(roundTrip.status == SnapshotLoadStatus::Ok,
             L"D-06 the round-tripped document loads cleanly");
    s.expect(roundTrip.snapshot.scope.selectors.size() == 2U &&
                 roundTrip.snapshot.scope.selectors.front() == std::string("C:"),
             L"D-06 the declared selection survives the round trip");
    s.expect(!roundTrip.snapshot.partitions.empty() &&
                 roundTrip.snapshot.partitions.front().envelope.outcome.status ==
                     CollectionStatus::Partial,
             L"D-06 the collection status survives the round trip");
    s.expect(!roundTrip.snapshot.partitions.empty() &&
                 roundTrip.snapshot.partitions.front().envelope.outcome.nativeCode.present &&
                 roundTrip.snapshot.partitions.front().envelope.outcome.nativeCode.value ==
                     0xC0000022ULL,
             L"D-06 the original native error code survives the round trip");
    s.expect(!roundTrip.snapshot.partitions.empty() &&
                 roundTrip.snapshot.partitions.front().envelope.coverage.truncated == 2U,
             L"D-06 the truncation count survives the round trip");
    s.expect(!roundTrip.snapshot.entities.empty() &&
                 roundTrip.snapshot.entities.front().displayOrder == 3U,
             L"D-06 the display order survives the round trip");
    s.expect(roundTrip.snapshot.entities.size() == 1U &&
                 roundTrip.snapshot.entities.front().fields.size() == 2U,
             L"D-06 both fields survive the round trip");
    s.expect(!roundTrip.snapshot.entities.empty() &&
                 roundTrip.snapshot.entities.front().fields.front().number.present &&
                 roundTrip.snapshot.entities.front().fields.front().number.value ==
                     0xFFFFF80000101234ULL,
             L"D-06 the 64-bit address is restored bit for bit");
    s.expect(!roundTrip.snapshot.entities.empty() &&
                 roundTrip.snapshot.entities.front().fields.back().kind == FieldValueKind::Absent &&
                 !roundTrip.snapshot.entities.front().fields.back().number.present,
             L"D-06 an absent value stays absent instead of becoming zero");

    // 显式的 0 与 null 必须读回成两个不同的状态。
    const SnapshotLoadResult zeroVsNull = ReadSnapshotJson(
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,"
        "\"entities\":[{\"partitionId\":\"p\",\"kind\":\"Service\",\"fields\":["
        "{\"name\":\"a\",\"kind\":\"Number\",\"number\":\"0\"},"
        "{\"name\":\"b\",\"kind\":\"Number\",\"number\":null}]}]}");
    s.expect(zeroVsNull.ok(), L"D-06 the zero-versus-null fixture loads");
    s.expect(zeroVsNull.ok() && zeroVsNull.snapshot.entities.front().fields.front().number.present &&
                 zeroVsNull.snapshot.entities.front().fields.front().number.value == 0ULL,
             L"D-06 an explicit zero is read back as a present zero");
    s.expect(zeroVsNull.ok() && !zeroVsNull.snapshot.entities.front().fields.back().number.present,
             L"D-06 a null value is read back as unknown, not as zero");
}

// ---------------------------------------------------------------------------
// D-07 脱敏不破坏关联
// ---------------------------------------------------------------------------
Snapshot BuildSensitiveSnapshot(const char* id, std::uint64_t utc, const char* startType) {
    Snapshot snapshot = MakeSnapshot(id, kBootA, utc);
    snapshot.envelope.window.machineId = "WORKSTATION-7";
    snapshot.partitions.push_back(MakePartition("files", ObjectKind::File, CollectionStatus::Success,
                                                kBootA, utc, 3U, "ev-files"));
    snapshot.partitions.back().envelope.window.machineId = "WORKSTATION-7";
    snapshot.partitions.back().envelope.outcome.message =
        "opened C:\\Users\\alice\\ntuser.dat on WORKSTATION-7";
    snapshot.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                                CollectionStatus::Success, kBootA, utc, 1U,
                                                "ev-svc"));
    snapshot.partitions.back().envelope.window.machineId = "WORKSTATION-7";

    auto addFile = [&snapshot](const char* path, const char* hash, const char* rawId) {
        SnapshotEntity entity;
        entity.partitionId = "files";
        entity.kind = ObjectKind::File;
        entity.file.path = path;
        entity.file.contentHash = hash;
        entity.rawRecordId = rawId;
        snapshot.entities.push_back(entity);
    };
    addFile("C:\\Users\\alice\\Documents\\report.docx", "sha256:1111", "f-1");
    addFile("C:\\Users\\alice\\AppData\\Local\\Temp\\stage.tmp", "sha256:2222", "f-2");
    addFile("C:\\Users\\bob\\Desktop\\notes.txt", "sha256:3333", "f-3");

    SnapshotEntity service = MakeServiceEntity("services", "AcmeSvc", "s-1", 0U);
    service.fields.push_back(TextField("startType", startType));
    EntityField owner = TextField("owner", "alice");
    owner.redaction = RedactionClass::UserName;
    service.fields.push_back(owner);
    EntityField sid = TextField("ownerSid", "S-1-5-21-1111-2222-3333-1001");
    sid.redaction = RedactionClass::AccountSid;
    service.fields.push_back(sid);
    service.fields.push_back(TextField("logPath", "\\\\WORKSTATION-7\\logs\\alice\\svc.log"));
    snapshot.entities.push_back(service);
    return snapshot;
}

void TestRedaction(KswordTests::Suite& s) {
    const Snapshot earlier = BuildSensitiveSnapshot("r-early", kUtcEarlier, "manual");
    const Snapshot later = BuildSensitiveSnapshot("r-late", kUtcLater, "auto");

    const SnapshotComparison plain = CompareSnapshots(earlier, later);
    s.expect(plain.modifiedCount == 1U,
             L"D-07 the unredacted pair shows exactly one modified object");
    s.expect(plain.unchangedCount == 3U,
             L"D-07 the unredacted pair shows three unchanged files");
    s.expect(plain.addedCount == 0U && plain.removedCount == 0U,
             L"D-07 the unredacted pair has no additions or removals");

    RedactionSession session;
    Snapshot redactedEarlier;
    Snapshot redactedLater;
    session.redact(earlier, redactedEarlier);
    session.redact(later, redactedLater);

    const std::string aliceToken = session.replacementFor(RedactionClass::UserName, "alice");
    const std::string aliceUpper = session.replacementFor(RedactionClass::UserName, "ALICE");
    const std::string bobToken = session.replacementFor(RedactionClass::UserName, "bob");
    const std::string hostToken = session.replacementFor(RedactionClass::Hostname, "WORKSTATION-7");
    const std::string sidToken =
        session.replacementFor(RedactionClass::AccountSid, "S-1-5-21-1111-2222-3333-1001");
    s.expect(!aliceToken.empty(), L"D-07 the user name gets a placeholder");
    s.expect(aliceToken == aliceUpper,
             L"D-07 the same user in different letter case maps to the same placeholder");
    s.expect(!bobToken.empty() && bobToken != aliceToken,
             L"D-07 two different users never collide onto the same placeholder");
    s.expect(!hostToken.empty() && hostToken != aliceToken,
             L"D-07 the host identifier gets its own placeholder");
    s.expect(!sidToken.empty(), L"D-07 the account SID gets a placeholder");

    // 同一用户的多条路径必须共享同一个占位符 —— 关联不能被抹平。
    std::size_t aliceHits = 0;
    for (const SnapshotEntity& entity : redactedEarlier.entities) {
        if (entity.kind == ObjectKind::File && TextContains(entity.file.path, aliceToken)) {
            ++aliceHits;
        }
    }
    s.expect(aliceHits == 2U,
             L"D-07 both of the same user's paths carry the same placeholder");
    s.expect(redactedEarlier.envelope.window.machineId == hostToken,
             L"D-07 the machine identifier is replaced by its placeholder");

    // 敏感原值不许残留在任何字段或导出里。
    const std::string exportEarlier = WriteSnapshotJson(redactedEarlier);
    const std::string exportLater = WriteSnapshotJson(redactedLater);
    s.expect(!TextContains(exportEarlier, "alice"),
             L"D-07 the user name does not survive anywhere in the earlier export");
    s.expect(!TextContains(exportLater, "alice"),
             L"D-07 the user name does not survive anywhere in the later export");
    s.expect(!TextContains(exportEarlier, "bob"),
             L"D-07 the second user name does not survive in the export");
    s.expect(!TextContains(exportEarlier, "WORKSTATION-7"),
             L"D-07 the host identifier does not survive in the export");
    s.expect(!TextContains(exportEarlier, "S-1-5-21-1111-2222-3333-1001"),
             L"D-07 the account SID does not survive in the export");
    s.expect(!TextContains(exportEarlier, "ntuser.dat") ||
                 !TextContains(exportEarlier, "Users\\alice"),
             L"D-07 the collector message keeps no user path");

    // 源会话不被覆盖。
    s.expect(earlier.envelope.window.machineId == std::string("WORKSTATION-7"),
             L"D-07 the source snapshot keeps its original machine identifier");
    s.expect(TextContains(WriteSnapshotJson(earlier), "alice"),
             L"D-07 the source session is not overwritten by redaction");

    // 关联仍可用：脱敏后的两份快照比出来的结论与原始一致。
    const SnapshotComparison redactedPair = CompareSnapshots(redactedEarlier, redactedLater);
    s.expect(redactedPair.modifiedCount == 1U,
             L"D-07 the redacted pair still shows exactly one modified object");
    s.expect(redactedPair.unchangedCount == 3U,
             L"D-07 the redacted pair still shows three unchanged files");
    s.expect(redactedPair.addedCount == 0U && redactedPair.removedCount == 0U,
             L"D-07 redaction introduces no phantom additions or removals");
    s.expect(redactedPair.deltas.size() == plain.deltas.size(),
             L"D-07 redaction preserves the number of compared objects");

    // 声明：哪些字段被改写、哪些被删除。
    s.expect(!session.report().replacedFieldPaths.empty(),
             L"D-07 the report lists which fields were rewritten");
    s.expect(session.report().replacementCount > 0U,
             L"D-07 the report counts the replacements it made");
    s.expect(session.report().removedFieldPaths.empty(),
             L"D-07 nothing is silently dropped when message removal is off");
    bool mappingsCoverUsers = false;
    for (const RedactionMapping& mapping : session.report().mappings) {
        if (mapping.cls == RedactionClass::UserName && mapping.original == std::string("alice")) {
            mappingsCoverUsers = mapping.replacement == aliceToken;
        }
    }
    s.expect(mappingsCoverUsers, L"D-07 the in-memory mapping table records the user mapping");

    RedactionOptions dropping;
    dropping.dropCollectorMessages = true;
    Snapshot dropped;
    RedactionReport dropReport;
    RedactSnapshot(earlier, dropping, dropped, dropReport);
    s.expect(Contains(dropReport.removedFieldPaths, "partitions[0].envelope.outcome.message"),
             L"D-07 removed content is declared as removed, not merely rewritten");
    s.expect(dropped.partitions.front().envelope.outcome.message.empty(),
             L"D-07 the dropped collector message really is gone");
    s.expect(!TextContains(WriteSnapshotJson(dropped), "ntuser.dat"),
             L"D-07 the dropped message leaves no residue in the export");
    s.expect(!earlier.partitions.front().envelope.outcome.message.empty(),
             L"D-07 dropping content in the copy does not touch the source");
}

// ---------------------------------------------------------------------------
// D-08 预期变化清单（离线一半）
// ---------------------------------------------------------------------------
void TestExpectationChecklist(KswordTests::Suite& s) {
    Snapshot earlier = MakeSnapshot("x-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 2U,
                                               "ev-e"));
    {
        SnapshotEntity entity = MakeServiceEntity("services", "AcmeSvc", "e-1", 0U);
        entity.fields.push_back(TextField("startType", "manual"));
        earlier.entities.push_back(entity);
    }
    {
        SnapshotEntity entity = MakeServiceEntity("services", "OtherSvc", "e-2", 1U);
        entity.fields.push_back(TextField("startType", "auto"));
        earlier.entities.push_back(entity);
    }

    Snapshot later = MakeSnapshot("x-late", kBootA, kUtcLater);
    later.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                             CollectionStatus::Success, kBootA, kUtcLater, 2U,
                                             "ev-l"));
    {
        SnapshotEntity entity = MakeServiceEntity("services", "AcmeSvc", "l-1", 0U);
        entity.fields.push_back(TextField("startType", "auto"));  // 授权范围内的改动
        later.entities.push_back(entity);
    }
    {
        SnapshotEntity entity = MakeServiceEntity("services", "OtherSvc", "l-2", 1U);
        entity.fields.push_back(TextField("startType", "disabled"));  // 未声明的改动
        later.entities.push_back(entity);
    }

    LogicalObjectId acme;
    acme.domain = "service";
    acme.name = "AcmeSvc";
    LogicalObjectId ghost;
    ghost.domain = "service";
    ghost.name = "GhostSvc";

    const SnapshotComparison comparison = CompareSnapshots(earlier, later);
    s.expect(comparison.modifiedCount == 2U,
             L"D-08 both configuration changes are observed");

    std::vector<ExpectedChange> expected;
    ExpectedChange want;
    want.partitionId = "services";
    want.identityKey = acme.crossSessionKey();
    want.change = EntityChange::Modified;
    want.fieldNames = {"startType"};
    expected.push_back(want);

    const ExpectationCheck check = CheckExpectedChanges(comparison, expected);
    s.expect(check.satisfied.size() == 1U, L"D-08 the declared change is satisfied");
    s.expect(check.missing.empty(), L"D-08 nothing declared is missing");
    s.expect(check.unexpectedKeys.size() == 1U,
             L"D-08 the undeclared change is listed without any attribution");
    s.expect(check.allSatisfied, L"D-08 all declared expectations are met");

    std::vector<ExpectedChange> overreaching = expected;
    ExpectedChange absent;
    absent.partitionId = "services";
    absent.identityKey = ghost.crossSessionKey();
    absent.change = EntityChange::Removed;
    overreaching.push_back(absent);
    const ExpectationCheck missingCheck = CheckExpectedChanges(comparison, overreaching);
    s.expect(missingCheck.missing.size() == 1U,
             L"D-08 a declared change that never happened is reported missing");
    s.expect(!missingCheck.allSatisfied,
             L"D-08 a missing declared change fails the checklist");

    std::vector<ExpectedChange> wrongField = expected;
    wrongField.front().fieldNames = {"imagePath"};
    const ExpectationCheck fieldCheck = CheckExpectedChanges(comparison, wrongField);
    s.expect(fieldCheck.satisfied.empty() && fieldCheck.missing.size() == 1U,
             L"D-08 declaring the wrong field does not count as satisfied");
}

// ---------------------------------------------------------------------------
// D-02 表示归一化：大小写/分隔符差异不得变成假增删
//
// 服务名、注册表键名、内核模块路径在 Windows 上都是大小写不敏感的，而 SCM、
// 注册表枚举、PsLoadedModuleList 与磁盘枚举给出的写法本来就不同。两侧落进不同的
// 身份桶就会直接造出一对假增删 —— D-02 的通过条件明确禁止。
// ---------------------------------------------------------------------------
void TestRepresentationFolding(KswordTests::Suite& s) {
    // --- 逻辑身份：仅大小写不同 ---
    LogicalObjectId upper;
    upper.domain = "service";
    upper.name = "Schedule";
    LogicalObjectId lower = upper;
    lower.name = "schedule";
    LogicalObjectId other = upper;
    other.name = "Spooler";

    s.expect(upper.crossSessionKey() == lower.crossSessionKey(),
             L"D-02 a case-only service name difference yields the same identity key");
    s.expect(upper.crossSessionKey() != other.crossSessionKey(),
             L"D-02 two genuinely different service names keep different identity keys");
    s.expect(MatchLogicalObject(upper, lower) == MatchResult::Candidate,
             L"D-02 a case-only difference is a candidate, never a confirmed same-object claim");
    s.expect(MatchLogicalObject(upper, other) == MatchResult::NoMatch,
             L"D-02 different service names still do not match");

    // 大小写不同的作用域同样只降级，不再被判成两个对象。
    LogicalObjectId scopedUpper = upper;
    scopedUpper.scopeKey = "S-1-5-21-9-8-7-1001";
    LogicalObjectId scopedLower = upper;
    scopedLower.scopeKey = "s-1-5-21-9-8-7-1001";
    s.expect(MatchLogicalObject(scopedUpper, scopedLower) == MatchResult::Candidate,
             L"D-02 a case-only scope key difference is a candidate, not a different object");

    Snapshot earlier = MakeSnapshot("f-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 1U,
                                               "ev-e"));
    earlier.entities.push_back(MakeServiceEntity("services", "Schedule", "e-1", 0U));

    Snapshot later = MakeSnapshot("f-late", kBootA, kUtcLater);
    later.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                             CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                             "ev-l"));
    later.entities.push_back(MakeServiceEntity("services", "schedule", "l-1", 0U));

    const SnapshotComparison folded = CompareSnapshots(earlier, later);
    s.expect(folded.deltas.size() == 1U,
             L"D-02 a case-only service rename stays one object, not an add/remove pair");
    s.expect(folded.addedCount == 0U && folded.removedCount == 0U,
             L"D-02 a case-only service rename produces no phantom add or remove");
    s.expect(folded.notComparableCount == 0U,
             L"D-02 a case-only service rename is still comparable");
    s.expect(!folded.deltas.empty() &&
                 folded.deltas.front().matchConfidence == MatchConfidence::Uncertain,
             L"D-02 a case-only match is marked uncertain rather than confirmed");
    s.expect(folded.selfCheckPassed, L"D-02 the folded comparison passes its self check");

    // --- 驱动映像路径：大小写 + 分隔符写法不同，映像身份相同 ---
    Snapshot drvEarlier = MakeSnapshot("dp-early", kBootA, kUtcEarlier);
    drvEarlier.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                                  CollectionStatus::Success, kBootA, kUtcEarlier,
                                                  1U, "ev-e"));
    drvEarlier.entities.push_back(MakeDriverEntity(
        "drivers", "\\SystemRoot\\System32\\DRIVERS\\acme.sys", "", 0x5A1B2C3DULL, 0x8000ULL,
        "e-d", 0U));

    Snapshot drvLater = MakeSnapshot("dp-late", kBootA, kUtcLater);
    drvLater.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                                CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                                "ev-l"));
    drvLater.entities.push_back(MakeDriverEntity(
        "drivers", "\\systemroot/system32/drivers/acme.sys", "", 0x5A1B2C3DULL, 0x8000ULL, "l-d",
        0U));

    const DriverInstanceId& earlierDriver = drvEarlier.entities.front().driver;
    const DriverInstanceId& laterDriver = drvLater.entities.front().driver;
    s.expect(earlierDriver.crossSessionKey() != laterDriver.crossSessionKey(),
             L"D-02 the raw ObjectIdentity key still differs (the fold lives in the snapshot layer)");
    s.expect(SnapshotDriverKey(earlierDriver) == SnapshotDriverKey(laterDriver),
             L"D-02 the snapshot-layer driver key folds path case and separators");
    s.expect(SnapshotDriverKey(DriverInstanceId{}).empty(),
             L"D-02 an unusable driver identity still yields no snapshot key");

    const SnapshotComparison driverFolded = CompareSnapshots(drvEarlier, drvLater);
    s.expect(driverFolded.deltas.size() == 1U,
             L"D-02 the same driver written with a different path case stays one object");
    s.expect(driverFolded.addedCount == 0U && driverFolded.removedCount == 0U,
             L"D-02 a path-case difference produces no phantom driver add or remove");
    s.expect(!driverFolded.deltas.empty() &&
                 driverFolded.deltas.front().matchConfidence == MatchConfidence::Uncertain,
             L"D-02 a path-representation-only driver match is uncertain, not confirmed");

    // 真正不同的映像（timeDateStamp 不同）仍然必须分开。
    Snapshot drvOther = MakeSnapshot("dp-other", kBootA, kUtcLater);
    drvOther.partitions.push_back(MakePartition("drivers", ObjectKind::Driver,
                                                CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                                "ev-o"));
    drvOther.entities.push_back(MakeDriverEntity(
        "drivers", "\\SystemRoot\\System32\\DRIVERS\\acme.sys", "", 0x600DBEEFULL, 0x8000ULL,
        "o-d", 0U));
    const SnapshotComparison drvChanged = CompareSnapshots(drvEarlier, drvOther);
    s.expect(drvChanged.deltas.size() == 2U,
             L"D-02 a different image version behind the same path stays two objects");
}

// ---------------------------------------------------------------------------
// D-04 重复身份键不得改写对面那一侧的真实采集状态
// ---------------------------------------------------------------------------
void TestDuplicateKeyKeepsSideState(KswordTests::Suite& s) {
    Snapshot earlier = MakeSnapshot("dk-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("svc", ObjectKind::Service, CollectionStatus::Success,
                                               kBootA, kUtcEarlier, 2U, "ev-e"));
    earlier.entities.push_back(MakeServiceEntity("svc", "Dup", "e-dup-1", 0U));
    earlier.entities.push_back(MakeServiceEntity("svc", "Dup", "e-dup-2", 1U));

    Snapshot denied = MakeSnapshot("dk-late", kBootA, kUtcLater);
    SnapshotPartition failing = MakePartition("svc", ObjectKind::Service,
                                              CollectionStatus::AccessDenied, kBootA, kUtcLater, 0U,
                                              "ev-l");
    failing.envelope.coverage = CoverageAccount{};
    failing.envelope.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied, "NTSTATUS",
                                                          0xC0000022ULL, "STATUS_ACCESS_DENIED");
    denied.partitions.push_back(failing);

    const SnapshotComparison result = CompareSnapshots(earlier, denied);
    s.expect(result.deltas.size() == 2U,
             L"D-04 both records behind the duplicated key are still reported");
    s.expect(result.notComparableCount == 2U && result.removedCount == 0U,
             L"D-04 a duplicated key over a failed side yields no removals");
    bool allSourceFailed = !result.deltas.empty();
    bool allDeclareBoth = !result.deltas.empty();
    for (const EntityDelta& delta : result.deltas) {
        allSourceFailed = allSourceFailed &&
                          delta.laterState == EntitySideState::UnknownSourceFailed;
        allDeclareBoth = allDeclareBoth &&
                         Contains(delta.limitationKeys, "snapshot.limitation.sourceFailed") &&
                         Contains(delta.limitationKeys, "snapshot.limitation.duplicateIdentityKey");
    }
    s.expect(allSourceFailed,
             L"D-04 an access-denied side stays source-failed even on duplicated-key rows");
    s.expect(allDeclareBoth,
             L"D-04 the duplicated-key limitation is added to the real side state, not instead of it");
    const PartitionAccount* account = FindAccount(result, "svc");
    s.expect(account != nullptr && account->laterStatus == CollectionStatus::AccessDenied,
             L"D-04 the row state and the partition account agree about the failed side");

    // 对面桶里确实有同键记录时：既不是"没有"，也不能说"在场"。
    Snapshot later = MakeSnapshot("dk-ok", kBootA, kUtcLater);
    later.partitions.push_back(MakePartition("svc", ObjectKind::Service, CollectionStatus::Success,
                                             kBootA, kUtcLater, 1U, "ev-l"));
    later.entities.push_back(MakeServiceEntity("svc", "Dup", "l-dup-1", 0U));

    const SnapshotComparison ambiguous = CompareSnapshots(earlier, later);
    s.expect(ambiguous.deltas.size() == 3U,
             L"D-04 every record behind an ambiguous pairing is still reported");
    bool ambiguousMarked = true;
    for (const EntityDelta& delta : ambiguous.deltas) {
        const EntitySideState other = delta.earlierState == EntitySideState::Present
                                          ? delta.laterState
                                          : delta.earlierState;
        ambiguousMarked = ambiguousMarked &&
                          other == EntitySideState::UnknownAmbiguousIdentity;
    }
    s.expect(ambiguousMarked,
             L"D-04 an unpairable but populated side is UnknownAmbiguousIdentity, not AbsentCovered");
    s.expect(ambiguous.removedCount == 0U && ambiguous.addedCount == 0U,
             L"D-04 an ambiguous pairing never becomes an add or a remove");
}

// ---------------------------------------------------------------------------
// D-04 两侧同名分区声明了不同实体类型：不是同一份采集视图，不能比
// ---------------------------------------------------------------------------
void TestPartitionKindMismatch(KswordTests::Suite& s) {
    Snapshot earlier = MakeSnapshot("km-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("p", ObjectKind::Service, CollectionStatus::Success,
                                               kBootA, kUtcEarlier, 1U, "ev-e"));
    earlier.entities.push_back(MakeServiceEntity("p", "AcmeSvc", "e-1", 0U));

    Snapshot later = MakeSnapshot("km-late", kBootA, kUtcLater);
    // 同一个分区 id 在新快照里装的是进程 —— 两个 collector 装了不同的东西。
    later.partitions.push_back(MakePartition("p", ObjectKind::Process, CollectionStatus::Success,
                                             kBootA, kUtcLater, 1U, "ev-l"));
    later.entities.push_back(MakeProcess("p", kBootA, 100U, 111ULL, "alpha.exe", "l-1", 0U));

    const SnapshotComparison result = CompareSnapshots(earlier, later);
    const PartitionAccount* account = FindAccount(result, "p");
    s.expect(account != nullptr && !account->comparable,
             L"D-04 a partition whose declared entity kind differs is not comparable");
    s.expect(account != nullptr &&
                 Contains(account->limitationKeys, "snapshot.partition.kindMismatch"),
             L"D-04 the kind mismatch is stated on the partition account");
    s.expect(account != nullptr && account->conclusion == AnalysisConclusion::NoEvidence,
             L"D-04 a kind-mismatched partition concludes NoEvidence");
    s.expect(result.removedCount == 0U && result.addedCount == 0U,
             L"D-04 a kind mismatch never turns the two different views into an add/remove pair");
    s.expect(result.notComparableCount == 2U,
             L"D-04 both records of a kind-mismatched partition are reported as not comparable");
    const EntityDelta* svc = FindDeltaByRaw(result, "e-1");
    s.expect(svc != nullptr &&
                 Contains(svc->limitationKeys, "snapshot.partition.kindMismatch"),
             L"D-04 the row states the kind mismatch, not just a scope excuse");
    s.expect(result.conclusion == AnalysisConclusion::NoEvidence,
             L"D-04 a comparison whose only partition is kind-mismatched has no usable evidence");
    s.expect(result.selfCheckPassed && CheckComparisonSelfConsistency(result),
             L"D-04 the kind-mismatch result is internally consistent");
}

// ---------------------------------------------------------------------------
// D-01 自检必须能被反例打成 false
// ---------------------------------------------------------------------------
void TestSelfCheckIsFalsifiable(KswordTests::Suite& s) {
    Snapshot earlier = MakeSnapshot("sc-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 2U,
                                               "ev-e"));
    earlier.entities.push_back(MakeServiceEntity("services", "AcmeSvc", "e-1", 0U));
    earlier.entities.push_back(MakeServiceEntity("services", "GoneSvc", "e-2", 1U));

    Snapshot later = MakeSnapshot("sc-late", kBootA, kUtcLater);
    later.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                             CollectionStatus::Success, kBootA, kUtcLater, 1U,
                                             "ev-l"));
    later.entities.push_back(MakeServiceEntity("services", "AcmeSvc", "l-1", 0U));

    const SnapshotComparison good = CompareSnapshots(earlier, later);
    s.expect(good.removedCount == 1U && good.unchangedCount == 1U,
             L"D-01 the reference comparison really contains one removal and one unchanged row");
    s.expect(good.selfCheckPassed && CheckComparisonSelfConsistency(good),
             L"D-01 a genuine comparison passes the independent consistency check");

    // 1) 计数被改动 —— 逐条重算必须发现。
    SnapshotComparison bumped = good;
    bumped.addedCount += 1U;
    s.expect(!CheckComparisonSelfConsistency(bumped),
             L"D-01 a counter that disagrees with the rows fails the self check");

    // 2) 移除结论所依据的账目被抽掉 —— 自检读账目，不读产生它的局部变量。
    SnapshotComparison unsupported = good;
    for (PartitionAccount& account : unsupported.partitions) {
        account.laterUsableForAbsence = false;
    }
    s.expect(!CheckComparisonSelfConsistency(unsupported),
             L"D-01 a removal whose later partition cannot prove completeness fails the self check");

    // 3) 行结论与两侧状态自相矛盾。
    SnapshotComparison forged = good;
    for (EntityDelta& delta : forged.deltas) {
        if (delta.change == EntityChange::Unchanged) {
            delta.change = EntityChange::Removed;
            break;
        }
    }
    s.expect(!CheckComparisonSelfConsistency(forged),
             L"D-01 a Removed row whose both sides are Present fails the self check");

    // 4) 结论与计数不相容。
    SnapshotComparison mislabeled = good;
    mislabeled.conclusion = AnalysisConclusion::NoDifferenceObserved;
    s.expect(!CheckComparisonSelfConsistency(mislabeled),
             L"D-01 claiming NoDifferenceObserved with an observed removal fails the self check");

    // 5) 分区结论被改写。
    SnapshotComparison badAccount = good;
    for (PartitionAccount& account : badAccount.partitions) {
        account.conclusion = AnalysisConclusion::NoDifferenceObserved;
    }
    s.expect(!CheckComparisonSelfConsistency(badAccount),
             L"D-01 a partition that observed a removal cannot conclude NoDifferenceObserved");
}

// ---------------------------------------------------------------------------
// D-08 声明必须指名对象，空清单不是通过
// ---------------------------------------------------------------------------
void TestExpectationBinding(KswordTests::Suite& s) {
    // 弱身份（无创建时间）的两个进程：identityKey 为空，只有 candidateKey。
    Snapshot earlier = MakeSnapshot("eb-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                               CollectionStatus::Success, kBootA, kUtcEarlier, 2U,
                                               "ev-e"));
    {
        SnapshotEntity one = MakeProcess("processes", kBootA, 4242U, 0ULL, "weakone.exe", "e-1", 0U);
        one.fields.push_back(TextField("start", "manual"));
        earlier.entities.push_back(one);
        SnapshotEntity two = MakeProcess("processes", kBootA, 4243U, 0ULL, "weaktwo.exe", "e-2", 1U);
        two.fields.push_back(TextField("start", "auto"));
        earlier.entities.push_back(two);
    }
    Snapshot later = MakeSnapshot("eb-late", kBootA, kUtcLater);
    later.partitions.push_back(MakePartition("processes", ObjectKind::Process,
                                             CollectionStatus::Success, kBootA, kUtcLater, 2U,
                                             "ev-l"));
    {
        SnapshotEntity one = MakeProcess("processes", kBootA, 4242U, 0ULL, "weakone.exe", "l-1", 0U);
        one.fields.push_back(TextField("start", "auto"));  // 唯一真实变化
        later.entities.push_back(one);
        SnapshotEntity two = MakeProcess("processes", kBootA, 4243U, 0ULL, "weaktwo.exe", "l-2", 1U);
        two.fields.push_back(TextField("start", "auto"));
        later.entities.push_back(two);
    }

    const SnapshotComparison comparison = CompareSnapshots(earlier, later);
    s.expect(comparison.modifiedCount == 1U && comparison.unchangedCount == 1U,
             L"D-08 exactly one of the two weak-identity objects changed");

    // candidateKey 的构成是手写常量，不从被测代码反算：
    //   "cand" + US + kind 名 + US + pid 十进制 + US + 折叠后的映像名
    const std::string us(1, '\x1F');
    const std::string weakOneKey = "cand" + us + "Process" + us + "4242" + us + "weakone.exe";
    const std::string weakTwoKey = "cand" + us + "Process" + us + "4243" + us + "weaktwo.exe";
    const EntityDelta* changed = FindDeltaByRaw(comparison, "e-1");
    s.expect(changed != nullptr && changed->identityKey.empty() &&
                 changed->candidateKey == weakOneKey,
             L"D-08 a weak-identity row carries only the hand-computed candidate key");

    // 身份键为空的声明不指向任何对象 —— 它绝不能被"随便配上第一条"算成通过。
    ExpectedChange nameless;
    nameless.partitionId = "processes";
    nameless.change = EntityChange::Modified;
    nameless.fieldNames = {"start"};
    const ExpectationCheck namelessCheck = CheckExpectedChanges(comparison, {nameless});
    s.expect(namelessCheck.invalid.size() == 1U && namelessCheck.satisfied.empty(),
             L"D-08 a declaration naming no object is invalid, never satisfied");
    s.expect(!namelessCheck.allSatisfied &&
                 namelessCheck.outcome == ExpectationOutcome::Violated,
             L"D-08 an unbindable declaration fails the checklist");

    // 用 candidateKey 声明：必须绑到真正改了的那一个。
    ExpectedChange rightOne;
    rightOne.partitionId = "processes";
    rightOne.candidateKey = weakOneKey;
    rightOne.change = EntityChange::Modified;
    rightOne.fieldNames = {"start"};
    const ExpectationCheck bound = CheckExpectedChanges(comparison, {rightOne});
    s.expect(bound.satisfied.size() == 1U && bound.satisfied.front() == weakOneKey,
             L"D-08 a weak-identity change can be declared by candidate key and binds to it");
    s.expect(bound.allSatisfied && bound.outcome == ExpectationOutcome::Satisfied,
             L"D-08 the correctly bound declaration satisfies the checklist");
    s.expect(bound.unexpectedKeys.empty(),
             L"D-08 the declared weak-identity change is no longer listed as undeclared");

    // 声明成另一个弱身份对象：必须报 missing，而不是被第一条顶上。
    ExpectedChange wrongOne = rightOne;
    wrongOne.candidateKey = weakTwoKey;
    const ExpectationCheck wrong = CheckExpectedChanges(comparison, {wrongOne});
    s.expect(wrong.missing.size() == 1U && wrong.satisfied.empty(),
             L"D-08 declaring the object that did not change is reported missing");

    // 空清单：无从核对，不是通过。
    const ExpectationCheck none = CheckExpectedChanges(comparison, {});
    s.expect(none.outcome == ExpectationOutcome::NotAssessed && !none.allSatisfied,
             L"D-08 an empty expectation list is NotAssessed, not a green checklist");
    s.expect(none.unexpectedKeys.size() == 1U,
             L"D-08 an empty expectation list still lists the observed change");

    // 零证据的比较：同样无从核对。
    const SnapshotComparison nothing = CompareSnapshots(Snapshot{}, Snapshot{});
    s.expect(nothing.conclusion == AnalysisConclusion::NoEvidence,
             L"D-08 comparing two empty snapshots yields NoEvidence");
    const ExpectationCheck onNothing = CheckExpectedChanges(nothing, {rightOne});
    s.expect(onNothing.outcome == ExpectationOutcome::NotAssessed && !onNothing.allSatisfied,
             L"D-08 a declaration checked against a no-evidence comparison is NotAssessed");

    // 声明指向一个没比出来的分区：不可核对，不能算通过也不能算"没变"。
    Snapshot brokenLater = later;
    for (SnapshotPartition& partition : brokenLater.partitions) {
        partition.envelope.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied,
                                                                "WIN32", 5ULL, "access denied");
        partition.envelope.coverage = CoverageAccount{};
    }
    brokenLater.entities.clear();
    brokenLater.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                                   CollectionStatus::Success, kBootA, kUtcLater, 0U,
                                                   "ev-svc"));
    Snapshot brokenEarlier = earlier;
    brokenEarlier.partitions.push_back(MakePartition("services", ObjectKind::Service,
                                                     CollectionStatus::Success, kBootA, kUtcEarlier,
                                                     0U, "ev-svc-e"));
    const SnapshotComparison broken = CompareSnapshots(brokenEarlier, brokenLater);
    const ExpectationCheck onBroken = CheckExpectedChanges(broken, {rightOne});
    s.expect(onBroken.invalid.size() == 1U && onBroken.missing.empty(),
             L"D-08 a declaration aimed at a non-comparable partition is invalid, not missing");
    s.expect(!onBroken.allSatisfied,
             L"D-08 an unassessable declaration never counts as satisfied");
}

// ---------------------------------------------------------------------------
// D-06 + 7.2 规定负载下的往返；超限与损坏必须是两种状态
//
// 每条实体写出的 JSON 节点数是手数出来的：
//   实体对象 1；partitionId/kind/rawRecordId/displayOrder 4；process 1+5；
//   thread 1+(1+5)+3；driver 1+8；file 1+6；logical 1+3；fields 数组 1
//   => 骨架 42 个节点，外加每个字段 (1 对象 + 7 成员) = 8 个。
// 4 个字段 -> 74 个节点/条；10,000 条 = 740,000 个节点，越过通用默认档的
// maxTotalNodes = 524,288，但仍低于 maxEstimatedNodeBytes(64 MiB)/sizeof(JsonValue)
// 所允许的节点数，因此报的必然是 NodeLimit。
// ---------------------------------------------------------------------------
constexpr std::size_t kBulkEntityCount = 10000;

Snapshot BuildBulkSnapshot() {
    Snapshot snapshot = MakeSnapshot("bulk-1", kBootA, kUtcEarlier);
    snapshot.partitions.push_back(MakePartition("bulk", ObjectKind::Unknown,
                                                CollectionStatus::Success, kBootA, kUtcEarlier,
                                                kBulkEntityCount, "ev-bulk"));
    const ObjectKind kinds[5] = {ObjectKind::Process, ObjectKind::Driver, ObjectKind::File,
                                 ObjectKind::Service, ObjectKind::Module};
    snapshot.entities.reserve(kBulkEntityCount);
    for (std::size_t i = 0; i < kBulkEntityCount; ++i) {
        const std::string index = FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal);
        SnapshotEntity entity;
        entity.partitionId = "bulk";
        entity.kind = kinds[i % 5U];
        entity.rawRecordId = "row-" + index;
        entity.displayOrder = i;
        entity.process.bootId = kBootA;
        entity.process.pid = OptionalU64::of(1000ULL + i);
        entity.process.imageName = "image-" + index + ".exe";
        entity.driver.imagePath =
            "\\SystemRoot\\System32\\drivers\\vendor\\deeply\\nested\\module-" + index + ".sys";
        entity.driver.timeDateStamp = OptionalU64::of(0x5A1B0000ULL + i);
        entity.driver.imageSize = OptionalU64::of(0x8000ULL);
        entity.file.path =
            "C:\\Program Files\\Acme Corporation\\Components\\payload-" + index + ".dat";
        entity.file.contentHash = "sha256:" + index;
        entity.logical.domain = "service";
        entity.logical.name = "svc-" + index;
        entity.fields.push_back(NumberField("target", 0xFFFFF80000100000ULL + i * 16ULL,
                                            FieldSemantics::KernelAddress));
        entity.fields.push_back(NumberField("imageBase", 0xFFFFF80000000000ULL + i * 4096ULL,
                                            FieldSemantics::LoadBaseAddress));
        entity.fields.push_back(TextField("startType", (i % 2U) == 0U ? "auto" : "manual"));
        entity.fields.push_back(
            TextField("displayName", ("Acme Component " + index).c_str()));
        snapshot.entities.push_back(std::move(entity));
    }
    return snapshot;
}

void TestPersistenceAtLoad(KswordTests::Suite& s) {
    // 超限与损坏必须是两种状态，且超限保留解析器自己的原因码。
    JsonLimits tiny;
    tiny.maxTotalNodes = 4U;
    const SnapshotLoadResult tooManyNodes = ReadSnapshotJson(
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"snapshotId\":\"t\","
        "\"entities\":[{\"partitionId\":\"p\",\"kind\":\"Service\"}]}",
        tiny);
    s.expect(tooManyNodes.status == SnapshotLoadStatus::LimitExceeded,
             L"D-06 a well-formed document over the node limit is LimitExceeded, not MalformedJson");
    s.expect(tooManyNodes.errorDetail == std::string("NodeLimit"),
             L"D-06 the limit failure keeps the parser's own reason code");
    s.expect(!tooManyNodes.ok(), L"D-06 a limit failure is not a loadable result");
    s.expect(tooManyNodes.snapshot.entities.empty(),
             L"D-06 a limit failure leaves no half-parsed snapshot behind");

    JsonLimits shortBytes;
    shortBytes.maxTotalBytes = 8U;
    const SnapshotLoadResult tooManyBytes =
        ReadSnapshotJson("{\"schema\":\"ksword.snapshot\",\"versionMajor\":1}", shortBytes);
    s.expect(tooManyBytes.status == SnapshotLoadStatus::LimitExceeded,
             L"D-06 an over-length document is LimitExceeded too");

    // 7.2 L1 规模的往返：通用默认档读不回来，快照持久化档位必须读得回来。
    const Snapshot bulk = BuildBulkSnapshot();
    const std::string text = WriteSnapshotJson(bulk);
    s.expect(text.size() > 1024U * 1024U,
             L"D-06 the load-scale document really is large enough to matter");

    const SnapshotLoadResult withGenericLimits = ReadSnapshotJson(text, JsonLimits{});
    s.expect(withGenericLimits.status == SnapshotLoadStatus::LimitExceeded,
             L"D-06 the generic untrusted-input limits reject the module's own load-scale document");
    s.expect(withGenericLimits.errorDetail == std::string("NodeLimit"),
             L"D-06 the generic-limit rejection is the node budget, as counted by hand");

    const JsonLimits profile = SnapshotJsonLimits();
    s.expect(profile.maxTotalNodes >= 740000U * 10U,
             L"D-06 the snapshot profile budgets the documented 100,000-record load");

    const SnapshotLoadResult loaded = ReadSnapshotJson(text);
    s.expect(loaded.status == SnapshotLoadStatus::Ok,
             L"D-06 the default snapshot limits load the module's own load-scale document");
    s.expect(loaded.snapshot.entities.size() == kBulkEntityCount,
             L"D-06 every record survives the load-scale round trip");
    // 手算的期望值：第 9,999 条（i = 9999）的地址 = 0xFFFFF80000100000 + 9999*16。
    const std::uint64_t expectedTarget = 0xFFFFF80000100000ULL + 9999ULL * 16ULL;
    s.expect(loaded.snapshot.entities.size() == kBulkEntityCount &&
                 loaded.snapshot.entities.back().fields.front().number.present &&
                 loaded.snapshot.entities.back().fields.front().number.value == expectedTarget,
             L"D-06 the last record's 64-bit address survives the load-scale round trip");
    s.expect(loaded.snapshot.entities.size() == kBulkEntityCount &&
                 loaded.snapshot.entities.back().rawRecordId == std::string("row-9999"),
             L"D-06 the last record keeps its raw record id at load scale");
}

// ---------------------------------------------------------------------------
// D-07 未知可选字段同样要脱敏；扫描代价与占位名数量无关；取消不交付半成品
// ---------------------------------------------------------------------------
void TestRedactionCoversUnknownFields(KswordTests::Suite& s) {
    // 手写的 fixture：敏感原值只出现在 D-06 承诺"原样回写"的未知字段里。
    const char* raw =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"versionMinor\":9,"
        "\"snapshotId\":\"leak-1\","
        "\"vendorNote\":\"collected by alice on WORKSTATION-7\","
        "\"vendorAudit\":{\"operator\":\"alice\",\"rows\":[\"seen by alice\",7]},"
        "\"envelope\":{\"window\":{\"machineId\":\"WORKSTATION-7\"}},"
        "\"partitions\":[{\"partitionId\":\"files\",\"kind\":\"File\",\"coversScope\":true,"
        "\"envelope\":{\"outcome\":{\"status\":\"Success\"},"
        "\"coverage\":{\"totalKnown\":\"1\",\"succeeded\":\"1\"}}}],"
        "\"entities\":[{\"partitionId\":\"files\",\"kind\":\"File\","
        "\"file\":{\"path\":\"C:\\\\Users\\\\alice\\\\a.txt\",\"contentHash\":\"sha256:1111\"},"
        "\"originalPath\":\"C:\\\\Users\\\\alice\\\\secret\\\\a.txt\","
        "\"note-alice\":\"key names can carry it too\"}]}";
    const SnapshotLoadResult loaded = ReadSnapshotJson(raw);
    s.expect(loaded.status == SnapshotLoadStatus::OkWithUnknownFields,
             L"D-07 the fixture really goes through the unknown-field preservation path");
    s.expect(Contains(loaded.unknownFieldPaths, "root.vendorNote") &&
                 Contains(loaded.unknownFieldPaths, "root.entities[].originalPath"),
             L"D-07 the unknown fields carrying the sensitive values are the preserved ones");

    Snapshot redacted;
    RedactionReport report;
    RedactSnapshot(loaded.snapshot, RedactionOptions{}, redacted, report);
    const std::string exported = WriteSnapshotJson(redacted);

    s.expect(!TextContains(exported, "alice"),
             L"D-07 the user name does not survive inside an unknown vendor field");
    s.expect(!TextContains(exported, "WORKSTATION-7"),
             L"D-07 the host identifier does not survive inside an unknown vendor field");
    s.expect(TextContains(exported, "vendorNote"),
             L"D-07 a scrubbed unknown field is kept, not silently dropped");
    s.expect(TextContains(exported, "collected by") && TextContains(exported, " on "),
             L"D-07 only the sensitive substring of the unknown field is replaced");
    s.expect(Contains(report.replacedFieldPaths, "unknownFields.vendorNote"),
             L"D-07 the rewritten unknown top-level field is declared by path");
    s.expect(Contains(report.replacedFieldPaths, "entities[0].unknownFields.originalPath"),
             L"D-07 the rewritten unknown entity field is declared by path");
    s.expect(Contains(report.replacedFieldPaths, "unknownFields.vendorAudit.operator"),
             L"D-07 a nested unknown field is reached and declared by its full path");
    s.expect(Contains(report.replacedFieldPaths, "unknownFields.vendorAudit.rows[0]"),
             L"D-07 an unknown array element is reached and declared by index");
    // 键名带敏感原值时不能改名（会撞键），只能整条删除并声明 —— 而且声明里也不许
    // 抄回原值。
    bool removedKeyDeclared = false;
    bool removalLeaksOriginal = false;
    for (const std::string& path : report.removedFieldPaths) {
        if (TextContains(path, "note-")) {
            removedKeyDeclared = true;
        }
        if (TextContains(path, "alice")) {
            removalLeaksOriginal = true;
        }
    }
    s.expect(removedKeyDeclared,
             L"D-07 an unknown field whose key carries the value is removed and declared");
    s.expect(!removalLeaksOriginal,
             L"D-07 the removal declaration does not copy the original value back out");
    s.expect(!TextContains(exported, "note-alice"),
             L"D-07 the removed key name is gone from the export");
    s.expect(loaded.snapshot.entities.size() == 1U &&
                 !loaded.snapshot.entities.front().unknownFields.empty(),
             L"D-07 the source snapshot keeps its unknown fields untouched");
}

void TestRedactionCostAndCancellation(KswordTests::Suite& s) {
    // 目标快照里没有任何 'z'；诱饵快照里的用户名全部以 'z' 开头，因此它们**永远**
    // 不可能命中。带首字符索引时扫描代价与这些占位名的数量无关。
    auto makeDecoy = [](std::size_t userCount) {
        Snapshot decoy = MakeSnapshot("decoy", kBootA, kUtcEarlier);
        decoy.partitions.push_back(MakePartition("files", ObjectKind::File,
                                                 CollectionStatus::Success, kBootA, kUtcEarlier,
                                                 userCount, "ev-decoy"));
        for (std::size_t i = 0; i < userCount; ++i) {
            SnapshotEntity entity;
            entity.partitionId = "files";
            entity.kind = ObjectKind::File;
            entity.file.path = "C:\\Users\\zeta" +
                               FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal) +
                               "\\f.txt";
            entity.file.contentHash = "sha256:decoy";
            decoy.entities.push_back(entity);
        }
        return decoy;
    };

    Snapshot target = MakeSnapshot("target", kBootA, kUtcEarlier);
    target.partitions.push_back(MakePartition("files", ObjectKind::File, CollectionStatus::Success,
                                              kBootA, kUtcEarlier, 200U, "ev-target"));
    for (std::size_t i = 0; i < 200U; ++i) {
        SnapshotEntity entity;
        entity.partitionId = "files";
        entity.kind = ObjectKind::File;
        entity.file.path = "C:\\ProgramData\\Acme\\Components\\payload-" +
                           FormatU64(static_cast<std::uint64_t>(i), U64Format::Decimal) + ".dat";
        entity.file.contentHash = "sha256:target";
        entity.fields.push_back(TextField("startType", "auto"));
        target.entities.push_back(entity);
    }
    // 被扫描的是字段值，不是 JSON 键名，所以只核对值这一侧没有 'z'/'Z'。
    s.expect(!TextContains(target.entities.front().file.path, "z") &&
                 !TextContains(target.entities.front().file.path, "Z") &&
                 !TextContains(target.envelope.window.machineId, "z") &&
                 !TextContains(target.snapshotId, "z"),
             L"D-07 the cost probe's scanned values contain none of the decoy first letters");

    RedactionSession few;
    few.learn(makeDecoy(8U));
    Snapshot outFew;
    few.redact(target, outFew);

    RedactionSession many;
    many.learn(makeDecoy(512U));
    Snapshot outMany;
    many.redact(target, outMany);

    s.expect(few.report().mappings.size() + 504U == many.report().mappings.size(),
             L"D-07 the two sessions really differ by 504 additional placeholders");
    s.expect(few.report().needleComparisons > 0U,
             L"D-07 the scrub really scanned the target text");
    s.expect(few.report().needleComparisons == many.report().needleComparisons,
             L"D-07 scan cost does not grow with placeholders that cannot match");
    s.expect(!TextContains(WriteSnapshotJson(outMany), "zeta") &&
                 few.report().replacementCount == many.report().replacementCount,
             L"D-07 the decoy placeholders never matched, so both runs replaced the same content");

    // 取消：不交付半脱敏的快照。
    RedactionSession cancelling;
    cancelling.setCancelHook([]() { return true; });
    Snapshot cancelled;
    cancelling.redact(target, cancelled);
    s.expect(cancelling.report().cancelled,
             L"D-07 a cancelled redaction says so in its report");
    s.expect(cancelled.entities.empty() && cancelled.snapshotId.empty(),
             L"D-07 a cancelled redaction delivers nothing rather than a half-scrubbed snapshot");
    s.expect(target.entities.size() == 200U,
             L"D-07 cancelling does not touch the source snapshot");

    RedactionSession running;
    Snapshot finished;
    running.redact(target, finished);
    s.expect(!running.report().cancelled && finished.entities.size() == 200U,
             L"D-07 a redaction without a cancel hook still completes normally");
}

} // namespace

int RunSnapshotCompareTests() {
    KswordTests::Suite suite(L"D snapshot compare");
    TestScopeAndProvenance(suite);
    TestSemanticKeys(suite);
    TestRepresentationFolding(suite);
    TestAddressNormalization(suite);
    TestUnknownIsNotRemoval(suite);
    TestDuplicateKeyKeepsSideState(suite);
    TestPartitionKindMismatch(suite);
    TestSelfCheckIsFalsifiable(suite);
    TestChangeExplanation(suite);
    TestPersistence(suite);
    TestPersistenceAtLoad(suite);
    TestRedaction(suite);
    TestRedactionCoversUnknownFields(suite);
    TestRedactionCostAndCancellation(suite);
    TestExpectationChecklist(suite);
    TestExpectationBinding(suite);
    suite.report();
    return suite.failures();
}
