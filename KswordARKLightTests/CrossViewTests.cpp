// X 模块（Cross-view 差异解释与复核）的离线自动测试。
//
// 覆盖编号：X-01 X-02 X-03 X-04 X-05 X-06 X-07 X-08。
// X-08 的"检测正例"由测试自己从快照副本里删记录构造 —— 改写器只存在于测试代码，
// 生产采集路径（AnalyzeCrossView）没有任何读取测试真值的分支。
//
// 断言原则（Q-02）：
//   * 期望值一律独立写死，不从被测代码反算；
//   * 逐视图断言 presence / viewStatus / sourceGroup / rawRecordId 的**精确值**，
//     不把两种"未知"塌进同一个计数器；
//   * 每个视图的 rawRecordId 带自己的前缀，绝不互相复制 —— 否则归属错误测不出来；
//   * 各轮的视图集合刻意不同（后续轮少一个 / 多一个 / 同 viewId 换来源组），
//     否则"只看第 1 轮"和"整轮缺席被当成干净"这两类缺陷会全部逃逸。

#include "TestSupport.h"

#include "../shared/evidence/CrossViewDiff.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

constexpr const char* kBoot = "boot-X";
constexpr std::uint64_t kUtcBase = 133000000000000000ULL;

EvidenceEnvelope MakeEnvelope(const char* collectorId,
                              const char* sourceGroup,
                              CollectionStatus status) {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = collectorId;
    envelope.source.sourceGroup = sourceGroup;
    envelope.source.origin = SourceOrigin::LiveKernel;
    envelope.source.collectorVersion = 1U;
    envelope.outcome.status = status;
    envelope.window.bootId = kBoot;
    envelope.window.machineId = "machine-1";
    return envelope;
}

// X-06：完整覆盖需要正面证据。这里把"我枚举了 n 个、n 个都成功"写进账目 ——
// 空账目不是完整覆盖，因此不写这一步的视图没有"确认缺失"资格。
void SetAccounting(ViewSnapshot& view) {
    view.envelope.coverage.totalKnown = OptionalU64::of(view.records.size());
    view.envelope.coverage.succeeded = view.records.size();
}

// 直接给 ViewUsableForAbsence 用的独立 envelope 构造器。
EvidenceEnvelope MakeAccountedEnvelope(CollectionStatus status, std::uint64_t count) {
    EvidenceEnvelope envelope = MakeEnvelope("v", "v", status);
    envelope.coverage.totalKnown = OptionalU64::of(count);
    envelope.coverage.succeeded = count;
    return envelope;
}

ViewRecord MakeProcessRecord(std::uint64_t pid, std::uint64_t createTime, const char* name,
                             const char* rawId) {
    ViewRecord record;
    record.kind = ObjectKind::Process;
    record.process.bootId = kBoot;
    record.process.pid = OptionalU64::of(pid);
    record.process.createTime100ns = OptionalU64::of(createTime);
    record.process.imageName = name;
    record.rawRecordId = rawId;
    return record;
}

ViewRecord MakeThreadRecord(std::uint64_t pid, std::uint64_t processCreate, std::uint64_t tid,
                            std::uint64_t threadCreate, const char* rawId) {
    ViewRecord record;
    record.kind = ObjectKind::Thread;
    record.thread.process.bootId = kBoot;
    record.thread.process.pid = OptionalU64::of(pid);
    record.thread.process.createTime100ns = OptionalU64::of(processCreate);
    record.thread.process.imageName = "worker.exe";
    record.thread.tid = OptionalU64::of(tid);
    record.thread.createTime100ns = OptionalU64::of(threadCreate);
    record.rawRecordId = rawId;
    return record;
}

ViewRecord MakeDriverRecord(const char* path, std::uint64_t stamp, std::uint64_t size,
                            const char* pdb, const char* rawId) {
    ViewRecord record;
    record.kind = ObjectKind::Driver;
    record.driver.bootId = kBoot;
    record.driver.imagePath = path;
    record.driver.timeDateStamp = OptionalU64::of(stamp);
    record.driver.imageSize = OptionalU64::of(size);
    record.driver.pdbSignature = pdb;
    record.rawRecordId = rawId;
    return record;
}

const CrossViewFinding* FindByDisplay(const CrossViewReport& report, const std::string& needle) {
    for (const CrossViewFinding& finding : report.findings) {
        if (finding.displayText.find(needle) != std::string::npos) {
            return &finding;
        }
    }
    return nullptr;
}

// 强身份 / 候选态分别定位，避免两条 finding 的 displayText 相同时抓错。
const CrossViewFinding* FindStrong(const CrossViewReport& report, const std::string& needle) {
    for (const CrossViewFinding& finding : report.findings) {
        if (!finding.identityKey.empty() && finding.displayText.find(needle) != std::string::npos) {
            return &finding;
        }
    }
    return nullptr;
}

const CrossViewFinding* FindCandidate(const CrossViewReport& report, const std::string& needle) {
    for (const CrossViewFinding& finding : report.findings) {
        if (finding.identityKey.empty() && finding.displayText.find(needle) != std::string::npos) {
            return &finding;
        }
    }
    return nullptr;
}

const ViewHit* HitFor(const CrossViewFinding* finding, const char* viewId) {
    if (finding == nullptr) {
        return nullptr;
    }
    for (const ViewHit& hit : finding->latestHits) {
        if (hit.viewId == viewId) {
            return &hit;
        }
    }
    return nullptr;
}

bool HitIs(const CrossViewFinding* finding, const char* viewId, ObjectPresence presence,
           CollectionStatus status) {
    const ViewHit* hit = HitFor(finding, viewId);
    return hit != nullptr && hit->presence == presence && hit->viewStatus == status;
}

bool HitGroupIs(const CrossViewFinding* finding, const char* viewId, const char* group) {
    const ViewHit* hit = HitFor(finding, viewId);
    return hit != nullptr && hit->sourceGroup == group;
}

bool HitRawIs(const CrossViewFinding* finding, const char* viewId, const char* rawId) {
    const ViewHit* hit = HitFor(finding, viewId);
    return hit != nullptr && hit->rawRecordId == rawId;
}

bool HasLimitationKey(const CrossViewReport& report, const char* key) {
    return std::find(report.trust.limitationKeys.begin(), report.trust.limitationKeys.end(),
                     std::string(key)) != report.trust.limitationKeys.end();
}

// 测试专用的快照改写器：从一个视图里删掉一条已知记录，并同步修正该视图的账目 ——
// 一个"被隐藏了一条记录"的 collector 自己并不知道少了东西，它报的仍是自洽的账目。
// 只存在于测试翻译单元，生产代码不引用它。
void RemoveRecordFromView(SampleRound& round, const std::string& viewId, const std::string& rawId) {
    for (ViewSnapshot& view : round.views) {
        if (view.viewId != viewId) {
            continue;
        }
        view.records.erase(std::remove_if(view.records.begin(), view.records.end(),
                                          [&rawId](const ViewRecord& r) {
                                              return r.rawRecordId == rawId;
                                          }),
                           view.records.end());
        SetAccounting(view);
    }
}

// 让某个视图本轮整体失败（超时/拒绝），记录清空、账目清空。
void FailView(SampleRound& round, const std::string& viewId, CollectionStatus status) {
    for (ViewSnapshot& view : round.views) {
        if (view.viewId != viewId) {
            continue;
        }
        view.envelope.outcome =
            CollectionOutcome::failure(status, "WIN32", 1460ULL, "collector failed");
        view.records.clear();
        view.envelope.coverage = CoverageAccount{};
    }
}

// 让某个视图本轮**整个不到场**（collector 崩溃 / 驱动卸载，连 envelope 都没送上来）。
void DropView(SampleRound& round, const std::string& viewId) {
    round.views.erase(std::remove_if(round.views.begin(), round.views.end(),
                                     [&viewId](const ViewSnapshot& v) { return v.viewId == viewId; }),
                      round.views.end());
}

// 三个视图的基线一轮：两个视图共用同一个底层 collector（X-01）。
// 每个视图的 rawRecordId 带自己的前缀，不复制别人的 —— 归属错误必须能被断言抓到。
SampleRound MakeBaselineRound(std::uint64_t sampleId, std::uint64_t utc) {
    SampleRound round;
    round.sampleId = sampleId;
    round.sampleUtc100ns = OptionalU64::of(utc);

    ViewSnapshot r3Api;
    r3Api.viewId = "r3.toolhelp";
    r3Api.envelope = MakeEnvelope("r3.toolhelp", "r3.toolhelp.snapshot", CollectionStatus::Success);
    r3Api.category = ViewEntityCategory::ProcessList;
    r3Api.records = {
        MakeProcessRecord(1000U, kUtcBase, "explorer.exe", "r3-1000"),
        MakeProcessRecord(2000U, kUtcBase + 100000ULL, "worker.exe", "r3-2000"),
    };
    SetAccounting(r3Api);

    ViewSnapshot r0Enum;
    r0Enum.viewId = "r0.process.enum";
    r0Enum.envelope = MakeEnvelope("r0.process.enum", "r0.process.enum", CollectionStatus::Success);
    r0Enum.category = ViewEntityCategory::ProcessList;
    r0Enum.records = {
        MakeProcessRecord(1000U, kUtcBase, "explorer.exe", "r0-1000"),
        MakeProcessRecord(2000U, kUtcBase + 100000ULL, "worker.exe", "r0-2000"),
    };
    SetAccounting(r0Enum);

    // 同一个 R0 collector 的第二层包装 —— 不是第三个独立来源，但它有自己的行 id。
    ViewSnapshot r0Wrapper;
    r0Wrapper.viewId = "ui.processTable";
    r0Wrapper.envelope =
        MakeEnvelope("ui.processTable", "r0.process.enum", CollectionStatus::Success);
    r0Wrapper.category = ViewEntityCategory::ProcessList;
    r0Wrapper.records = {
        MakeProcessRecord(1000U, kUtcBase, "explorer.exe", "ui-1000"),
        MakeProcessRecord(2000U, kUtcBase + 100000ULL, "worker.exe", "ui-2000"),
    };
    SetAccounting(r0Wrapper);

    round.views = {r3Api, r0Enum, r0Wrapper};
    return round;
}

// ---------------------------------------------------------------------------
// X-01：来源独立性可见
// ---------------------------------------------------------------------------
void TestSourceIndependence(KswordTests::Suite& s) {
    const CrossViewReport report = AnalyzeCrossView({MakeBaselineRound(1U, 1000U)});
    s.expect(report.roundCount == 1U, L"X-01 the report states how many rounds it analysed");
    s.expect(report.viewCount == 3U, L"X-01 the report counts three views");
    s.expect(report.trust.viewCount == 3U, L"X-01 the trust statement counts three views");
    s.expect(report.latestRoundViewCount == 3U && report.minRoundViewCount == 3U,
             L"X-01 latest and minimum per-round view counts are both three here");
    s.expect(report.independentSourceGroupCount == 2U &&
                 report.trust.independentSourceGroupCount == 2U,
             L"X-01 two wrappers over one collector collapse into one source group");
    s.expect(report.selfCheckPassed, L"X-01 the report passes its own consistency check");

    const CrossViewFinding* explorer = FindStrong(report, "explorer.exe");
    s.expect(explorer != nullptr, L"X-01 the baseline object is present in the report");
    s.expect(explorer != nullptr && explorer->viewCount == 3U &&
                 explorer->independentSourceGroupCount == 2U,
             L"X-01 each finding carries both the view count and the source group count");
    s.expect(explorer != nullptr && explorer->latestHits.size() == 3U,
             L"X-01 the per-view hit list covers every view exactly once");
    s.expect(explorer != nullptr && explorer->strength == IdentityStrength::Strong,
             L"X-02 an object keyed by boot id, pid and creation time is a strong identity");

    // sourceGroup 必须来自 envelope 的分组键，不是 collectorId —— 否则包装层会被
    // 当成第三个独立来源，正是 X-01 禁止的"靠重复视图提高可信度"。
    s.expect(HitGroupIs(explorer, "ui.processTable", "r0.process.enum"),
             L"X-01 the wrapper view reports the underlying source group, not its own collector id");
    s.expect(HitGroupIs(explorer, "r0.process.enum", "r0.process.enum"),
             L"X-01 the kernel view reports its own source group");
    s.expect(HitGroupIs(explorer, "r3.toolhelp", "r3.toolhelp.snapshot"),
             L"X-01 the user mode view reports its own source group");
    s.expect(HitRawIs(explorer, "r3.toolhelp", "r3-1000") &&
                 HitRawIs(explorer, "r0.process.enum", "r0-1000") &&
                 HitRawIs(explorer, "ui.processTable", "ui-1000"),
             L"X-07 every view hit links back to that view's own raw record id");
    s.expect(!report.trust.anyIncompleteCoverage,
             L"X-01 fully accounted successful views are not flagged as incomplete coverage");
    s.expect(HasLimitationKey(report, "trust.limitation.noAbsenceProof"),
             L"X-01 agreement across views never claims the absence of hidden objects");
    s.expect(!HasLimitationKey(report, "trust.limitation.singleSourceGroup"),
             L"X-01 two independent source groups do not raise the single-source warning");
}

// ---------------------------------------------------------------------------
// X-01 / X-06：普查必须跨全部轮次，整轮缺席的视图不是"干净"
// ---------------------------------------------------------------------------
void TestCrossRoundCensus(KswordTests::Suite& s) {
    // (a) 后续轮少两个视图：R0 collector 崩了，它和它的 UI 包装层（同一个来源组）
    //     连 envelope 都没送上来。整个 r0.process.enum 来源组就此消失。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            DropView(*round, "r0.process.enum");
            DropView(*round, "ui.processTable");
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});

        s.expect(report.viewCount == 3U,
                 L"X-01 the view set is the union over all rounds, not just the first one");
        s.expect(report.latestRoundViewCount == 1U,
                 L"X-01 the latest round only had one view actually present");
        s.expect(report.minRoundViewCount == 1U,
                 L"X-01 the worst round is reported alongside the union");
        s.expect(report.independentSourceGroupCount == 1U,
                 L"X-01 a source group that vanished after round one cannot prop up the trust count");
        s.expect(HasLimitationKey(report, "trust.limitation.singleSourceGroup"),
                 L"X-01 losing the second source group raises the single-source limitation");
        s.expect(report.selfCheckPassed, L"X-01 the census stays internally consistent");

        const CrossViewFinding* explorer = FindStrong(report, "explorer.exe");
        s.expect(explorer != nullptr && explorer->latestHits.size() == 3U,
                 L"X-06 a view missing for the whole round still gets a hit entry");
        s.expect(HitIs(explorer, "r0.process.enum", ObjectPresence::UnknownViewFailed,
                       CollectionStatus::NotCollected),
                 L"X-06 a view that was never collected this round is unknown, not absent");
        const ViewHit* dropped = HitFor(explorer, "r0.process.enum");
        s.expect(dropped != nullptr && dropped->sourceGroup.empty(),
                 L"X-01 a view absent for the round contributes no source group for that round");
    }

    // (b) 整轮缺席的视图不得推出"对象已结束 / 未发现差异"（BLOCKER 3 的实测拓扑）。
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot kernel;
            kernel.viewId = "r0.process.enum";
            kernel.envelope =
                MakeEnvelope("r0.process.enum", "r0.process.enum", CollectionStatus::Success);
            kernel.category = ViewEntityCategory::ProcessList;
            kernel.records = {MakeProcessRecord(4242U, kUtcBase + 200000ULL, "ghost.exe", "r0-4242")};
            SetAccounting(kernel);

            ViewSnapshot api;
            api.viewId = "r3.api";
            api.envelope = MakeEnvelope("r3.api", "r3.api", CollectionStatus::Success);
            api.category = ViewEntityCategory::ProcessList;
            SetAccounting(api);

            ViewSnapshot wmi;
            wmi.viewId = "r3.wmi";
            wmi.envelope = MakeEnvelope("r3.wmi", "r3.wmi", CollectionStatus::Success);
            wmi.category = ViewEntityCategory::ProcessList;
            SetAccounting(wmi);

            round.views = {kernel, api, wmi};
            if (i > 0U) {
                DropView(round, "r0.process.enum");  // 见证视图整轮缺席
            }
            rounds.push_back(round);
        }
        const CrossViewReport report = AnalyzeCrossView(rounds);
        const CrossViewFinding* ghost = FindStrong(report, "ghost.exe");
        s.expect(ghost != nullptr, L"X-06 the object reported by the vanished view is still tracked");
        s.expect(ghost != nullptr && ghost->state != DiscrepancyState::ObjectEnded,
                 L"X-06 a view that was never collected cannot prove the object ended");
        s.expect(ghost != nullptr && ghost->state == DiscrepancyState::Unverifiable,
                 L"X-06 losing the only witnessing view makes the recheck unverifiable");
        s.expect(ghost != nullptr && ghost->conclusion != AnalysisConclusion::NoDifferenceObserved,
                 L"F-05 a never-collected view can never yield no-difference-observed");
        s.expect(ghost != nullptr && ghost->conclusion == AnalysisConclusion::Indeterminate,
                 L"F-05 the conclusion for an unverifiable recheck is indeterminate");
        s.expect(ghost != nullptr && ghost->recheckHistory.size() == 3U &&
                     ghost->recheckHistory[1].unusableViews == 1U &&
                     ghost->recheckHistory[1].presentViews == 0U &&
                     ghost->recheckHistory[1].usableAbsentViews == 2U,
                 L"X-06 the recheck history counts the absent view as unusable, not as clean");
    }

    // (c) 后续轮多一个视图，且最后一轮带拒绝访问与命中上限。
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot kernel;
            kernel.viewId = "r0.process.enum";
            kernel.envelope =
                MakeEnvelope("r0.process.enum", "r0.process.enum", CollectionStatus::Success);
            kernel.category = ViewEntityCategory::ProcessList;
            kernel.records = {MakeProcessRecord(1000U, kUtcBase, "explorer.exe", "r0-1000")};
            SetAccounting(kernel);
            round.views = {kernel};

            if (i > 0U) {
                ViewSnapshot denied;
                denied.viewId = "r3.wmi";
                denied.envelope = MakeEnvelope("r3.wmi", "r3.wmi", CollectionStatus::AccessDenied);
                denied.category = ViewEntityCategory::ProcessList;
                round.views.push_back(denied);

                ViewSnapshot capped;
                capped.viewId = "r0.scan";
                capped.envelope = MakeEnvelope("r0.scan", "r0.scan", CollectionStatus::Success);
                capped.category = ViewEntityCategory::ProcessList;
                capped.envelope.coverage.limitHit = true;
                capped.envelope.coverage.limit = OptionalU64::of(1U);
                round.views.push_back(capped);
            }
            rounds.push_back(round);
        }
        const CrossViewReport report = AnalyzeCrossView(rounds);
        s.expect(report.viewCount == 3U,
                 L"X-01 views that only appear in later rounds still join the union");
        s.expect(report.minRoundViewCount == 1U && report.latestRoundViewCount == 3U,
                 L"X-01 both the worst and the latest per-round view counts are reported");
        s.expect(report.independentSourceGroupCount == 1U,
                 L"X-01 the source group count is the minimum across rounds, not the best round");
        s.expect(report.trust.anyIncompleteCoverage,
                 L"X-01 an access denied view in the last round stays visible in the trust statement");
        const CrossViewFinding* explorer = FindStrong(report, "explorer.exe");
        s.expect(explorer != nullptr && explorer->latestHits.size() == 3U,
                 L"X-01 the finding hit list matches the union view count");
        s.expect(HitIs(explorer, "r3.wmi", ObjectPresence::UnknownViewFailed,
                       CollectionStatus::AccessDenied),
                 L"X-06 an access denied view is unknown-failed, never absent");
        s.expect(HitIs(explorer, "r0.scan", ObjectPresence::UnknownOutOfCoverage,
                       CollectionStatus::Success),
                 L"X-06 a successful but capped view is unknown-out-of-coverage");
    }

    // (d) 同一个 viewId 在后续轮换到共享来源组：独立来源数必须掉到 1。
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));
            const char* groupA = (i == 0U) ? "group.A" : "group.SHARED";
            const char* groupB = (i == 0U) ? "group.B" : "group.SHARED";

            ViewSnapshot a;
            a.viewId = "view.a";
            a.envelope = MakeEnvelope("view.a", groupA, CollectionStatus::Success);
            a.category = ViewEntityCategory::ProcessList;
            a.records = {MakeProcessRecord(1000U, kUtcBase, "explorer.exe", "a-1000")};
            SetAccounting(a);

            ViewSnapshot b;
            b.viewId = "view.b";
            b.envelope = MakeEnvelope("view.b", groupB, CollectionStatus::Success);
            b.category = ViewEntityCategory::ProcessList;
            b.records = {MakeProcessRecord(1000U, kUtcBase, "explorer.exe", "b-1000")};
            SetAccounting(b);

            round.views = {a, b};
            rounds.push_back(round);
        }
        const CrossViewReport report = AnalyzeCrossView(rounds);
        s.expect(report.viewCount == 2U, L"X-01 the two views are counted once each");
        s.expect(report.independentSourceGroupCount == 1U,
                 L"X-01 two views that collapsed into one source group are one independent source");
        const CrossViewFinding* explorer = FindStrong(report, "explorer.exe");
        s.expect(HitGroupIs(explorer, "view.a", "group.SHARED") &&
                     HitGroupIs(explorer, "view.b", "group.SHARED"),
                 L"X-01 the latest hits report the source group actually in effect");
        s.expect(report.selfCheckPassed,
                 L"X-01 claiming more independent sources than the latest round shows fails self check");
    }
}

// ---------------------------------------------------------------------------
// X-06：失败不是缺项
// ---------------------------------------------------------------------------
void TestFailureIsNotAbsence(KswordTests::Suite& s) {
    s.expect(!ViewUsableForAbsence(MakeAccountedEnvelope(CollectionStatus::Timeout, 3U), true),
             L"X-06 a timed out view cannot confirm absence");
    s.expect(!ViewUsableForAbsence(MakeAccountedEnvelope(CollectionStatus::AccessDenied, 3U), true),
             L"X-06 an access denied view cannot confirm absence");
    s.expect(!ViewUsableForAbsence(MakeAccountedEnvelope(CollectionStatus::Unsupported, 3U), true),
             L"X-06 an unsupported view cannot confirm absence");
    s.expect(!ViewUsableForAbsence(MakeAccountedEnvelope(CollectionStatus::NotCollected, 3U), true),
             L"X-06 a view that was never collected cannot confirm absence");
    s.expect(!ViewUsableForAbsence(MakeAccountedEnvelope(CollectionStatus::Partial, 3U), true),
             L"X-06 a partial view cannot confirm absence");
    s.expect(!ViewUsableForAbsence(MakeAccountedEnvelope(CollectionStatus::Success, 3U), false),
             L"X-06 a view that did not cover the target scope cannot confirm absence");
    {
        EvidenceEnvelope truncated = MakeAccountedEnvelope(CollectionStatus::Success, 3U);
        truncated.coverage.truncated = 1U;
        s.expect(!ViewUsableForAbsence(truncated, true),
                 L"X-06 a truncated view cannot confirm absence");
    }
    {
        EvidenceEnvelope capped = MakeAccountedEnvelope(CollectionStatus::Success, 3U);
        capped.coverage.limitHit = true;
        s.expect(!ViewUsableForAbsence(capped, true),
                 L"X-06 a view that stopped at its limit cannot confirm absence");
    }
    {
        // 账目一字未填：状态成功、范围声称覆盖，但没有任何完整性的正面证据。
        EvidenceEnvelope blank = MakeEnvelope("v", "v", CollectionStatus::Success);
        s.expect(!ViewUsableForAbsence(blank, true),
                 L"X-06 an empty coverage account is unknown coverage, not a complete scan");
    }
    {
        // 范围口径：四个端点齐全且处理范围盖住请求范围。
        EvidenceEnvelope ranged = MakeEnvelope("v", "v", CollectionStatus::Success);
        ranged.coverage.requestedBegin = OptionalU64::of(0x1000ULL);
        ranged.coverage.requestedEnd = OptionalU64::of(0x9000ULL);
        ranged.coverage.processedBegin = OptionalU64::of(0x1000ULL);
        ranged.coverage.processedEnd = OptionalU64::of(0x9000ULL);
        s.expect(ViewUsableForAbsence(ranged, true),
                 L"X-06 a fully processed requested range is positive evidence of completeness");
        ranged.coverage.processedEnd = OptionalU64::of(0x5000ULL);
        s.expect(!ViewUsableForAbsence(ranged, true),
                 L"X-06 a range that stopped early cannot confirm absence");
    }
    s.expect(ViewUsableForAbsence(MakeAccountedEnvelope(CollectionStatus::Success, 3U), true),
             L"X-06 a complete successful view with a settled account is usable for absence");

    // 一份视图有对象、一份空但成功、一份拒绝访问、一份只返回上限数量、一份不支持、
    // 一份根本没跑。逐视图断言精确值 —— 两种"未知"绝不塌进一个计数器。
    SampleRound round;
    round.sampleId = 1U;
    round.sampleUtc100ns = OptionalU64::of(1000U);

    ViewSnapshot present;
    present.viewId = "r0.enum";
    present.envelope = MakeEnvelope("r0.enum", "r0.enum", CollectionStatus::Success);
    present.category = ViewEntityCategory::ProcessList;
    present.records = {MakeProcessRecord(4242U, kUtcBase + 200000ULL, "ghost.exe", "r0-4242")};
    SetAccounting(present);

    ViewSnapshot emptySuccess;
    emptySuccess.viewId = "r3.api";
    emptySuccess.envelope = MakeEnvelope("r3.api", "r3.api", CollectionStatus::Success);
    emptySuccess.category = ViewEntityCategory::ProcessList;
    SetAccounting(emptySuccess);

    ViewSnapshot denied;
    denied.viewId = "r3.wmi";
    denied.envelope = MakeEnvelope("r3.wmi", "r3.wmi", CollectionStatus::AccessDenied);
    denied.category = ViewEntityCategory::ProcessList;

    ViewSnapshot capped;
    capped.viewId = "r0.scan";
    capped.envelope = MakeEnvelope("r0.scan", "r0.scan", CollectionStatus::Success);
    capped.category = ViewEntityCategory::ProcessList;
    capped.envelope.coverage.limitHit = true;
    capped.envelope.coverage.limit = OptionalU64::of(1U);

    ViewSnapshot unsupported;
    unsupported.viewId = "r0.hvm";
    unsupported.envelope = MakeEnvelope("r0.hvm", "r0.hvm", CollectionStatus::Unsupported);
    unsupported.category = ViewEntityCategory::ProcessList;

    ViewSnapshot notRun;
    notRun.viewId = "r3.etw";
    notRun.envelope = MakeEnvelope("r3.etw", "r3.etw", CollectionStatus::NotCollected);
    notRun.category = ViewEntityCategory::ProcessList;

    round.views = {present, emptySuccess, denied, capped, unsupported, notRun};
    const CrossViewReport report = AnalyzeCrossView({round});
    const CrossViewFinding* ghost = FindStrong(report, "ghost.exe");
    s.expect(ghost != nullptr, L"X-06 the object seen by one view is tracked");
    s.expect(ghost != nullptr && ghost->latestHits.size() == 6U,
             L"X-06 every view produces exactly one hit entry");
    s.expect(HitIs(ghost, "r0.enum", ObjectPresence::Present, CollectionStatus::Success),
             L"X-06 the view that listed the object reports Present");
    s.expect(HitIs(ghost, "r3.api", ObjectPresence::AbsentInUsableView, CollectionStatus::Success),
             L"X-06 only the complete successful view counts as absent");
    s.expect(HitIs(ghost, "r3.wmi", ObjectPresence::UnknownViewFailed, CollectionStatus::AccessDenied),
             L"X-06 access denied is UnknownViewFailed, not UnknownOutOfCoverage");
    s.expect(HitIs(ghost, "r0.scan", ObjectPresence::UnknownOutOfCoverage, CollectionStatus::Success),
             L"X-06 a successful capped view is UnknownOutOfCoverage, not UnknownViewFailed");
    s.expect(HitIs(ghost, "r0.hvm", ObjectPresence::UnknownViewFailed, CollectionStatus::Unsupported),
             L"X-06 an unsupported view is UnknownViewFailed");
    s.expect(HitIs(ghost, "r3.etw", ObjectPresence::UnknownViewFailed, CollectionStatus::NotCollected),
             L"X-06 a view that never ran is UnknownViewFailed");
    s.expect(HitRawIs(ghost, "r0.enum", "r0-4242") && HitRawIs(ghost, "r3.api", ""),
             L"X-07 only the Present hit carries a raw record id");
    s.expect(ghost != nullptr && ghost->state == DiscrepancyState::PendingRecheck,
             L"X-05 a first-round discrepancy is pending recheck, not a confirmed difference");
    s.expect(ghost != nullptr && ghost->conclusion == AnalysisConclusion::Indeterminate,
             L"X-06 a partially covered round does not conclude no-difference");

    // 静默损坏的 collector：Success、账目说成功了 500 条、实际一条记录都没返回。
    {
        SampleRound broken;
        broken.sampleId = 1U;
        broken.sampleUtc100ns = OptionalU64::of(1000U);

        ViewSnapshot good;
        good.viewId = "r0.enum";
        good.envelope = MakeEnvelope("r0.enum", "r0.enum", CollectionStatus::Success);
        good.category = ViewEntityCategory::ProcessList;
        good.records = {MakeProcessRecord(1000U, kUtcBase, "explorer.exe", "r0-1000")};
        SetAccounting(good);

        ViewSnapshot silent;
        silent.viewId = "r3.broken";
        silent.envelope = MakeEnvelope("r3.broken", "r3.broken", CollectionStatus::Success);
        silent.category = ViewEntityCategory::ProcessList;
        silent.envelope.coverage.totalKnown = OptionalU64::of(500U);
        silent.envelope.coverage.succeeded = 500U;

        broken.views = {good, silent};
        const CrossViewReport brokenReport = AnalyzeCrossView({broken, broken, broken});
        const CrossViewFinding* explorer = FindStrong(brokenReport, "explorer.exe");
        s.expect(HitIs(explorer, "r3.broken", ObjectPresence::UnknownOutOfCoverage,
                       CollectionStatus::Success),
                 L"X-06 an account claiming 500 successes with zero records is not usable for absence");
        s.expect(explorer != nullptr && explorer->state == DiscrepancyState::NoDiscrepancy,
                 L"X-06 a silently broken collector must not turn a normal object into a difference");
        s.expect(explorer != nullptr && explorer->conclusion == AnalysisConclusion::Indeterminate,
                 L"F-05 a round containing an unusable view cannot conclude no-difference-observed");
    }
}

// ---------------------------------------------------------------------------
// X-05：复采样确认（瞬态 / 持续 / 已结束 / 无法复查）
// ---------------------------------------------------------------------------
void TestResampleClassification(KswordTests::Suite& s) {
    // 瞬态：第一轮缺，第二轮出现。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        RemoveRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Transient,
                 L"X-05 an object that reappears on recheck is transient, not hidden");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::NoDifferenceObserved,
                 L"X-05 a transient discrepancy explained under full coverage observes no difference");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 3U &&
                     worker->recheckHistory[1].intervalFromFirst100ns.present &&
                     worker->recheckHistory[1].intervalFromFirst100ns.value == 1000U,
                 L"X-05 the recheck interval is recorded");
        s.expect(worker != nullptr && worker->recheckHistory[0].hits.size() == 3U &&
                     worker->recheckHistory[0].usableAbsentViews == 1U &&
                     worker->recheckHistory[0].presentViews == 2U,
                 L"X-07 every recheck round can be expanded into its per-view hits");
    }

    // 持续差异：三轮都缺。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            RemoveRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Persistent,
                 L"X-05 a discrepancy surviving two rechecks becomes persistent");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::DifferenceObserved,
                 L"X-05 a persistent discrepancy is reported as an observed difference");
        s.expect(HitIs(worker, "r3.toolhelp", ObjectPresence::AbsentInUsableView,
                       CollectionStatus::Success),
                 L"X-08 the affected view is named precisely");
    }

    // 只要一轮复查即可升级：requiredRecheckRounds = 1。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        RemoveRecordFromView(r1, "r3.toolhelp", "r3-2000");
        RemoveRecordFromView(r2, "r3.toolhelp", "r3-2000");
        CrossViewOptions options;
        options.requiredRecheckRounds = 1U;
        const CrossViewReport report = AnalyzeCrossView({r1, r2}, options);
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Persistent,
                 L"X-05 one recheck round is enough when the caller asked for one");
    }

    // 要求三轮复查时同样的三轮输入只能停在待复核。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            RemoveRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        CrossViewOptions options;
        options.requiredRecheckRounds = 3U;
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3}, options);
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::PendingRecheck,
                 L"X-05 three required recheck rounds are not met by two available ones");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::Indeterminate,
                 L"F-05 a pending recheck never claims no difference");
    }

    // 对象已结束：复查轮里所有视图都可用且都不再列出它。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        RemoveRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            RemoveRecordFromView(*round, "r3.toolhelp", "r3-2000");
            RemoveRecordFromView(*round, "r0.process.enum", "r0-2000");
            RemoveRecordFromView(*round, "ui.processTable", "ui-2000");
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::ObjectEnded,
                 L"X-05 an object gone from every usable view is reported as ended, not hidden");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::Indeterminate,
                 L"F-05 object-ended explains the gap but is not a no-difference conclusion");
    }

    // BLOCKER 1：见证视图本轮超时，绝不能读成"对象已结束"。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        RemoveRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            RemoveRecordFromView(*round, "r3.toolhelp", "r3-2000");
            RemoveRecordFromView(*round, "ui.processTable", "ui-2000");
            FailView(*round, "r0.process.enum", CollectionStatus::Timeout);
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state != DiscrepancyState::ObjectEnded,
                 L"X-06 a timed out witnessing view must not be read as the object having ended");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Unverifiable,
                 L"X-06 with the witness timed out the recheck stays unverifiable");
        s.expect(HitIs(worker, "r0.process.enum", ObjectPresence::UnknownViewFailed,
                       CollectionStatus::Timeout),
                 L"X-06 the timed out witness is reported as UnknownViewFailed with its real status");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::Indeterminate,
                 L"F-05 an unverifiable recheck is indeterminate, never no-difference");
    }

    // 无法复查：复查轮里所有视图都失败（三个计数里 present/usableAbsent 全 0 -> 跳过）。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        RemoveRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            for (ViewSnapshot& view : round->views) {
                FailView(*round, view.viewId, CollectionStatus::Timeout);
            }
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Unverifiable,
                 L"X-05 failing rechecks yield unverifiable, never a persistent difference");
    }

    // 空轮次（一个视图都没有）不得被算成一次有效复查。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        RemoveRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound empty;
        empty.sampleId = 2U;
        empty.sampleUtc100ns = OptionalU64::of(2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        RemoveRecordFromView(r3, "r3.toolhelp", "r3-2000");
        const CrossViewReport report = AnalyzeCrossView({r1, empty, r3});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Unverifiable,
                 L"X-05 a round with no views at all is not a usable recheck round");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 3U &&
                     worker->recheckHistory[1].presentViews == 0U &&
                     worker->recheckHistory[1].usableAbsentViews == 0U &&
                     worker->recheckHistory[1].unusableViews == 3U,
                 L"X-06 an empty round marks every union view as unusable, not as clean");
        s.expect(report.minRoundViewCount == 0U && report.viewCount == 3U,
                 L"X-01 the empty round is reported as zero views without shrinking the union");
    }

    // 阈值必须真的比较轮数：可用复查够了，但持续缺失的轮数不够 -> 无法复查。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        SampleRound r4 = MakeBaselineRound(4U, 4000U);
        RemoveRecordFromView(r1, "r3.toolhelp", "r3-2000");
        RemoveRecordFromView(r2, "r3.toolhelp", "r3-2000");
        for (SampleRound* round : {&r3, &r4}) {
            RemoveRecordFromView(*round, "r3.toolhelp", "r3-2000");
            RemoveRecordFromView(*round, "ui.processTable", "ui-2000");
            FailView(*round, "r0.process.enum", CollectionStatus::Timeout);
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3, r4});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Unverifiable,
                 L"X-05 one persistent round out of three rechecks does not reach the threshold of two");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 4U,
                 L"X-07 the recheck history keeps every round from the first discrepancy onward");
    }

    // X-05：时钟回拨。无符号裸相减会把 5 秒的 NTP 校正变成 5.8e13 年的"有效间隔"。
    {
        SampleRound r1 = MakeBaselineRound(1U, kUtcBase);
        SampleRound r2 = MakeBaselineRound(2U, kUtcBase - 50000000ULL);
        SampleRound r3 = MakeBaselineRound(3U, kUtcBase + 100000000ULL);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            RemoveRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 3U,
                 L"X-05 all three rounds are kept in the recheck history");
        s.expect(worker != nullptr && !worker->recheckHistory[1].intervalFromFirst100ns.present,
                 L"X-05 a backwards clock leaves the interval unset instead of wrapping around");
        s.expect(worker != nullptr && worker->recheckHistory[1].clockWentBackwards,
                 L"X-05 the backwards clock is stated explicitly rather than silently dropped");
        s.expect(worker != nullptr && worker->recheckHistory[2].intervalFromFirst100ns.present &&
                     worker->recheckHistory[2].intervalFromFirst100ns.value == 100000000ULL &&
                     !worker->recheckHistory[2].clockWentBackwards,
                 L"X-05 a later sample after the correction still gets its real interval");
    }

    // 状态与结论必须取同一证据窗口：三轮持续缺失后整轮超时，仍是持续差异。
    {
        SampleRound r1 = MakeBaselineRound(1U, 1000U);
        SampleRound r2 = MakeBaselineRound(2U, 2000U);
        SampleRound r3 = MakeBaselineRound(3U, 3000U);
        SampleRound r4 = MakeBaselineRound(4U, 4000U);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            RemoveRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        for (ViewSnapshot& view : r4.views) {
            FailView(r4, view.viewId, CollectionStatus::Timeout);
        }
        const CrossViewReport report = AnalyzeCrossView({r1, r2, r3, r4});
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::Persistent,
                 L"X-05 a round where every view timed out does not undo the persistent classification");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::DifferenceObserved,
                 L"F-05 a persistent state can never carry a no-evidence conclusion");
        s.expect(worker != nullptr &&
                     StateConclusionConsistent(worker->state, worker->conclusion),
                 L"F-05 state and conclusion pass the contradiction check");
    }
}

// ---------------------------------------------------------------------------
// X-08：可重放的检测正例（进程 / 线程 / 驱动）
// ---------------------------------------------------------------------------
void TestReplayablePositives(KswordTests::Suite& s) {
    // 进程
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round = MakeBaselineRound(i + 1U, 1000U * (i + 1U));
            RemoveRecordFromView(round, "r3.toolhelp", "r3-1000");
            rounds.push_back(round);
        }
        const CrossViewReport report = AnalyzeCrossView(rounds);
        const CrossViewFinding* explorer = FindStrong(report, "explorer.exe");
        const CrossViewFinding* worker = FindStrong(report, "worker.exe");
        s.expect(explorer != nullptr && explorer->state == DiscrepancyState::Persistent,
                 L"X-08 the deleted process record is located exactly");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::NoDiscrepancy,
                 L"X-08 the untouched process is not reported as a discrepancy");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::NoDifferenceObserved,
                 L"X-07 a clean object still reports the coverage it was checked under");
        s.expect(HitIs(explorer, "r3.toolhelp", ObjectPresence::AbsentInUsableView,
                       CollectionStatus::Success),
                 L"X-08 the affected view is named precisely");
        s.expect(HitRawIs(explorer, "r0.process.enum", "r0-1000") &&
                     HitRawIs(explorer, "ui.processTable", "ui-1000"),
                 L"X-07 each remaining view links back to its own raw source record");
        s.expect(explorer != nullptr && explorer->firstSeenViewId == "r0.process.enum" &&
                     explorer->firstSeenRawRecordId == "r0-1000" &&
                     explorer->firstSeenRoundIndex == 0U,
                 L"X-07 the finding names the earliest source record that reported the object");
    }

    // 线程
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot r0;
            r0.viewId = "r0.thread.enum";
            r0.envelope = MakeEnvelope("r0.thread.enum", "r0.thread", CollectionStatus::Success);
            r0.category = ViewEntityCategory::ThreadList;
            r0.records = {
                MakeThreadRecord(2000U, kUtcBase + 100000ULL, 3001U, kUtcBase + 110000ULL, "r0-t3001"),
                MakeThreadRecord(2000U, kUtcBase + 100000ULL, 3002U, kUtcBase + 120000ULL, "r0-t3002"),
            };
            SetAccounting(r0);

            ViewSnapshot r3;
            r3.viewId = "r3.thread.snapshot";
            r3.envelope =
                MakeEnvelope("r3.thread.snapshot", "r3.thread", CollectionStatus::Success);
            r3.category = ViewEntityCategory::ThreadList;
            r3.records = {
                MakeThreadRecord(2000U, kUtcBase + 100000ULL, 3001U, kUtcBase + 110000ULL, "r3-t3001"),
                MakeThreadRecord(2000U, kUtcBase + 100000ULL, 3002U, kUtcBase + 120000ULL, "r3-t3002"),
            };
            SetAccounting(r3);

            round.views = {r0, r3};
            RemoveRecordFromView(round, "r3.thread.snapshot", "r3-t3002");
            rounds.push_back(round);
        }
        const CrossViewReport report = AnalyzeCrossView(rounds);
        const CrossViewFinding* hidden = FindStrong(report, "TID 3002");
        const CrossViewFinding* normal = FindStrong(report, "TID 3001");
        s.expect(hidden != nullptr && hidden->state == DiscrepancyState::Persistent,
                 L"X-08 the deleted thread record is located exactly");
        s.expect(normal != nullptr && normal->state == DiscrepancyState::NoDiscrepancy,
                 L"X-08 the untouched thread is clean");
        s.expect(HitRawIs(hidden, "r0.thread.enum", "r0-t3002"),
                 L"X-07 the thread finding links back to the kernel view's own record id");
        s.expect(HitIs(hidden, "r3.thread.snapshot", ObjectPresence::AbsentInUsableView,
                       CollectionStatus::Success),
                 L"X-08 the affected thread view is named precisely");
    }

    // 驱动：同类别（两个加载模块列表）之间的缺项才是 cross-view 要解释的东西。
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot kernelModules;
            kernelModules.viewId = "r0.module.list";
            kernelModules.envelope =
                MakeEnvelope("r0.module.list", "r0.module", CollectionStatus::Success);
            kernelModules.category = ViewEntityCategory::LoadedModuleList;
            kernelModules.records = {
                MakeDriverRecord("\\SystemRoot\\System32\\drivers\\ksword.sys", 0x65000000ULL,
                                 0x30000ULL, "GUID-K/1", "r0-mod-ksword"),
                MakeDriverRecord("\\SystemRoot\\System32\\ntoskrnl.exe", 0x64000000ULL, 0xA00000ULL,
                                 "GUID-N/1", "r0-mod-ntos"),
            };
            SetAccounting(kernelModules);

            // 另一个**同类别**的加载模块视图（R3 侧的模块枚举）。
            ViewSnapshot userModules;
            userModules.viewId = "r3.module.enum";
            userModules.envelope =
                MakeEnvelope("r3.module.enum", "r3.module", CollectionStatus::Success);
            userModules.category = ViewEntityCategory::LoadedModuleList;
            userModules.records = {
                MakeDriverRecord("\\SystemRoot\\System32\\drivers\\ksword.sys", 0x65000000ULL,
                                 0x30000ULL, "GUID-K/1", "r3-mod-ksword"),
                MakeDriverRecord("\\SystemRoot\\System32\\ntoskrnl.exe", 0x64000000ULL, 0xA00000ULL,
                                 "GUID-N/1", "r3-mod-ntos"),
            };
            SetAccounting(userModules);

            round.views = {kernelModules, userModules};
            RemoveRecordFromView(round, "r3.module.enum", "r3-mod-ksword");
            rounds.push_back(round);
        }
        const CrossViewReport report = AnalyzeCrossView(rounds);
        const CrossViewFinding* driver = FindStrong(report, "ksword.sys");
        const CrossViewFinding* ntos = FindStrong(report, "ntoskrnl.exe");
        s.expect(driver != nullptr && driver->state == DiscrepancyState::Persistent,
                 L"X-08 a module missing from another loaded-module view is located exactly");
        s.expect(ntos != nullptr && ntos->state == DiscrepancyState::NoDiscrepancy,
                 L"X-08 the untouched driver is clean");
        s.expect(HitIs(driver, "r3.module.enum", ObjectPresence::AbsentInUsableView,
                       CollectionStatus::Success),
                 L"X-08 the affected module view is named precisely");
        s.expect(HitRawIs(driver, "r0.module.list", "r0-mod-ksword"),
                 L"X-07 the driver finding links back to the module list's own record id");
    }
}

// ---------------------------------------------------------------------------
// X-04：加载模块 / DriverObject / DeviceObject / 磁盘服务配置是四种不同的实体
// ---------------------------------------------------------------------------
void TestEntityCategories(KswordTests::Suite& s) {
    // 一个 boot-start 驱动：在加载模块列表里，合法地没有服务项、没有设备对象。
    std::vector<SampleRound> rounds;
    for (std::uint64_t i = 0; i < 3U; ++i) {
        SampleRound round;
        round.sampleId = i + 1U;
        round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

        ViewSnapshot modules;
        modules.viewId = "r0.module.list";
        modules.envelope = MakeEnvelope("r0.module.list", "r0.module", CollectionStatus::Success);
        modules.category = ViewEntityCategory::LoadedModuleList;
        modules.records = {
            MakeDriverRecord("\\SystemRoot\\System32\\drivers\\bootdrv.sys", 0x65000000ULL,
                             0x20000ULL, "GUID-B/1", "r0-mod-boot"),
        };
        SetAccounting(modules);

        ViewSnapshot devices;
        devices.viewId = "r0.device.tree";
        devices.envelope = MakeEnvelope("r0.device.tree", "r0.device", CollectionStatus::Success);
        devices.category = ViewEntityCategory::DeviceObjectTree;
        SetAccounting(devices);  // 该驱动没有创建任何设备对象：合法的空列表

        ViewSnapshot services;
        services.viewId = "r3.service.registry";
        services.envelope =
            MakeEnvelope("r3.service.registry", "r3.service", CollectionStatus::Success);
        services.category = ViewEntityCategory::ServiceConfig;
        services.records = {
            // 服务存在但当前未加载：它不在加载模块列表里，同样是合法结构。
            MakeDriverRecord("\\SystemRoot\\System32\\drivers\\phantom.sys", 0x66000000ULL,
                             0x10000ULL, "GUID-P/1", "r3-svc-phantom"),
        };
        SetAccounting(services);

        round.views = {modules, devices, services};
        rounds.push_back(round);
    }
    const CrossViewReport report = AnalyzeCrossView(rounds);

    const CrossViewFinding* boot = FindStrong(report, "bootdrv.sys");
    s.expect(boot != nullptr, L"X-04 the loaded boot driver is tracked");
    s.expect(boot != nullptr && boot->state == DiscrepancyState::NoDiscrepancy,
             L"X-04 a module with no DriverObject and no service entry is not a persistent difference");
    s.expect(boot != nullptr && boot->state != DiscrepancyState::Persistent,
             L"X-04 legitimate many-to-many structure is never reported as a rootkit");
    s.expect(HitIs(boot, "r0.device.tree", ObjectPresence::NotComparableCategory,
                   CollectionStatus::Success),
             L"X-04 a device object view is a different entity class, not an absent module");
    s.expect(HitIs(boot, "r3.service.registry", ObjectPresence::NotComparableCategory,
                   CollectionStatus::Success),
             L"X-04 a service configuration view is a different entity class than a module list");
    s.expect(HitIs(boot, "r0.module.list", ObjectPresence::Present, CollectionStatus::Success),
             L"X-04 the loaded module list is the class that actually listed the driver");

    const CrossViewFinding* phantom = FindStrong(report, "phantom.sys");
    s.expect(phantom != nullptr && phantom->state == DiscrepancyState::NoDiscrepancy,
             L"X-04 a configured but unloaded service is not a module list discrepancy");
    s.expect(HitIs(phantom, "r0.module.list", ObjectPresence::NotComparableCategory,
                   CollectionStatus::Success),
             L"X-04 the module list not listing a service entry is a class difference, not a gap");

    // 类别基数事实必须能展开：模块列表里有 1 个视图列出，设备树里 0 个。
    bool sawModuleCategory = false;
    bool sawDeviceCategory = false;
    if (boot != nullptr) {
        for (const CategoryObservation& observation : boot->latestCategories) {
            if (observation.category == ViewEntityCategory::LoadedModuleList) {
                sawModuleCategory = observation.viewsInCategory == 1U &&
                                    observation.viewsListing == 1U && observation.comparable;
            }
            if (observation.category == ViewEntityCategory::DeviceObjectTree) {
                sawDeviceCategory = observation.viewsInCategory == 1U &&
                                    observation.viewsListing == 0U &&
                                    observation.usableViewsNotListing == 0U && !observation.comparable;
            }
        }
    }
    s.expect(sawModuleCategory,
             L"X-04 the module class reports one view that listed the driver");
    s.expect(sawDeviceCategory,
             L"X-04 the device object class is reported as a cardinality fact, not as a missing item");

    // 同类别的真实隐藏仍然必须被抓到 —— 类别隔离不是免罪符。
    {
        std::vector<SampleRound> hidden;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round = rounds[static_cast<std::size_t>(i)];
            ViewSnapshot second;
            second.viewId = "r3.module.enum";
            second.envelope =
                MakeEnvelope("r3.module.enum", "r3.module", CollectionStatus::Success);
            second.category = ViewEntityCategory::LoadedModuleList;
            SetAccounting(second);  // 同类别视图，但它就是不列 bootdrv.sys
            round.views.push_back(second);
            hidden.push_back(round);
        }
        const CrossViewReport hiddenReport = AnalyzeCrossView(hidden);
        const CrossViewFinding* boot2 = FindStrong(hiddenReport, "bootdrv.sys");
        s.expect(boot2 != nullptr && boot2->state == DiscrepancyState::Persistent,
                 L"X-04 a module missing from a same-class module view is still a persistent difference");
        s.expect(HitIs(boot2, "r3.module.enum", ObjectPresence::AbsentInUsableView,
                       CollectionStatus::Success),
                 L"X-04 same-class absence is absence, not a class difference");
        s.expect(HitIs(boot2, "r0.device.tree", ObjectPresence::NotComparableCategory,
                       CollectionStatus::Success),
                 L"X-04 the cross-class views stay out of the absence inference");
    }
}

// ---------------------------------------------------------------------------
// X-02：身份不足不合并，但也不许消失
// ---------------------------------------------------------------------------
void TestIdentityGuards(KswordTests::Suite& s) {
    SampleRound round;
    round.sampleId = 1U;
    round.sampleUtc100ns = OptionalU64::of(1000U);

    ViewSnapshot withCreateTime;
    withCreateTime.viewId = "r0.enum";
    withCreateTime.envelope = MakeEnvelope("r0.enum", "r0.enum", CollectionStatus::Success);
    withCreateTime.category = ViewEntityCategory::ProcessList;
    withCreateTime.records = {MakeProcessRecord(500U, kUtcBase + 300000ULL, "svc.exe", "r0-500")};
    SetAccounting(withCreateTime);

    // 只有一个视图有创建时间：另一视图的记录身份不足，不得被合并成同一对象。
    ViewSnapshot withoutCreateTime;
    withoutCreateTime.viewId = "r3.enum";
    withoutCreateTime.envelope = MakeEnvelope("r3.enum", "r3.enum", CollectionStatus::Success);
    withoutCreateTime.category = ViewEntityCategory::ProcessList;
    ViewRecord weak = MakeProcessRecord(500U, 0U, "svc.exe", "r3-500");
    weak.process.createTime100ns = OptionalU64::unset();
    withoutCreateTime.records = {weak};
    SetAccounting(withoutCreateTime);

    round.views = {withCreateTime, withoutCreateTime};
    const CrossViewReport report = AnalyzeCrossView({round});
    s.expect(report.weakIdentityRecords == 1U,
             L"X-02 a record without a creation time is counted as a weak candidate record");
    s.expect(report.weakIdentityObjects == 1U,
             L"X-02 weak records are also counted as objects after deduplication");
    s.expect(report.findings.size() == 2U,
             L"X-02 the weak record gets its own candidate finding instead of being dropped");

    const CrossViewFinding* strong = FindStrong(report, "svc.exe");
    const CrossViewFinding* candidate = FindCandidate(report, "svc.exe");
    s.expect(strong != nullptr && !strong->identityKey.empty() &&
                 strong->strength == IdentityStrength::Strong,
             L"X-02 the record with a creation time keeps its strong cross-session key");
    s.expect(candidate != nullptr && candidate->identityKey.empty() &&
                 !candidate->candidateKey.empty(),
             L"X-02 the weak record carries a candidate key and no cross-session key");
    s.expect(candidate != nullptr && candidate->strength == IdentityStrength::Weak,
             L"X-02 the weak record is labelled as a weak association, not a strong one");
    s.expect(candidate != nullptr && candidate->state == DiscrepancyState::CandidateOnly,
             L"X-02 a candidate object can never be escalated to a persistent difference");
    s.expect(candidate != nullptr && candidate->conclusion == AnalysisConclusion::Indeterminate,
             L"X-02 a candidate relation is indeterminate, never a confirmed difference");
    s.expect(candidate != nullptr && candidate->kind == ObjectKind::Process &&
                 candidate->displayText.find("svc.exe") != std::string::npos,
             L"X-02 the candidate finding still says what was skipped");
    s.expect(HitRawIs(candidate, "r3.enum", "r3-500"),
             L"X-07 the candidate finding links back to the raw record that produced it");
    s.expect(HitIs(candidate, "r0.enum", ObjectPresence::AbsentInUsableView,
                   CollectionStatus::Success),
             L"X-02 the candidate is still shown per view without being merged into the strong object");
    s.expect(strong != nullptr && candidate != nullptr &&
                 strong->identityKey != candidate->candidateKey,
             L"X-02 the strong key space and the candidate key space never collide");

    // 同一个弱身份对象出现在 3 视图 x 2 轮：记录数 6，对象数 1，findings 只加 1 条。
    {
        SampleRound weakRound;
        weakRound.sampleId = 1U;
        weakRound.sampleUtc100ns = OptionalU64::of(1000U);
        const char* viewIds[] = {"v1", "v2", "v3"};
        const char* rawIds[] = {"v1-weak", "v2-weak", "v3-weak"};
        for (int i = 0; i < 3; ++i) {
            ViewSnapshot view;
            view.viewId = viewIds[i];
            view.envelope = MakeEnvelope(viewIds[i], viewIds[i], CollectionStatus::Success);
            view.category = ViewEntityCategory::ProcessList;
            ViewRecord record = MakeProcessRecord(666U, 0U, "suspicious.exe", rawIds[i]);
            record.process.createTime100ns = OptionalU64::unset();
            view.records = {record};
            SetAccounting(view);
            weakRound.views.push_back(view);
        }
        const CrossViewReport weakReport = AnalyzeCrossView({weakRound, weakRound});
        s.expect(weakReport.weakIdentityRecords == 6U,
                 L"X-02 six weak record sightings are counted as six records");
        s.expect(weakReport.weakIdentityObjects == 1U,
                 L"X-02 the six sightings deduplicate into a single candidate object");
        s.expect(weakReport.findings.size() == 1U,
                 L"X-02 one weak object produces exactly one candidate finding");
        const CrossViewFinding* suspicious = FindCandidate(weakReport, "suspicious.exe");
        s.expect(suspicious != nullptr && suspicious->latestHits.size() == 3U,
                 L"X-07 the candidate finding expands into per-view hits like any other finding");
        s.expect(HitRawIs(suspicious, "v1", "v1-weak") && HitRawIs(suspicious, "v2", "v2-weak") &&
                     HitRawIs(suspicious, "v3", "v3-weak"),
                 L"X-07 each view keeps its own raw record id for the candidate object");
        s.expect(suspicious != nullptr && suspicious->state == DiscrepancyState::CandidateOnly,
                 L"X-02 a weak object stays a candidate no matter how many rounds agree");
    }

    // PID 复用：同 PID 不同创建时间必须是两个对象。
    SampleRound reuse;
    reuse.sampleId = 1U;
    reuse.sampleUtc100ns = OptionalU64::of(1000U);
    ViewSnapshot before;
    before.viewId = "r0.enum";
    before.envelope = MakeEnvelope("r0.enum", "r0.enum", CollectionStatus::Success);
    before.category = ViewEntityCategory::ProcessList;
    before.records = {
        MakeProcessRecord(700U, kUtcBase + 400000ULL, "short.exe", "r0-a"),
        MakeProcessRecord(700U, kUtcBase + 500000ULL, "short.exe", "r0-b"),
    };
    SetAccounting(before);
    reuse.views = {before};
    const CrossViewReport reuseReport = AnalyzeCrossView({reuse});
    s.expect(reuseReport.findings.size() == 2U,
             L"X-02 the same PID with two creation times stays two distinct objects");
    s.expect(reuseReport.weakIdentityRecords == 0U,
             L"X-02 records with full lifetime identity are never counted as weak");
}

// ---------------------------------------------------------------------------
// X-03：线程所属与生命周期（TID 复用）
// ---------------------------------------------------------------------------
void TestThreadIdentity(KswordTests::Suite& s) {
    // 同一个 TID 两次不同的创建时间：TID 复用，必须是两个对象。
    {
        SampleRound round;
        round.sampleId = 1U;
        round.sampleUtc100ns = OptionalU64::of(1000U);
        ViewSnapshot view;
        view.viewId = "r0.thread.enum";
        view.envelope = MakeEnvelope("r0.thread.enum", "r0.thread", CollectionStatus::Success);
        view.category = ViewEntityCategory::ThreadList;
        view.records = {
            MakeThreadRecord(2000U, kUtcBase + 100000ULL, 4001U, kUtcBase + 110000ULL, "r0-t-first"),
            MakeThreadRecord(2000U, kUtcBase + 100000ULL, 4001U, kUtcBase + 900000ULL, "r0-t-second"),
        };
        SetAccounting(view);
        round.views = {view};
        const CrossViewReport report = AnalyzeCrossView({round});
        s.expect(report.findings.size() == 2U,
                 L"X-03 the same TID with two creation times stays two distinct thread instances");
        s.expect(report.findings[0].state == DiscrepancyState::NoDiscrepancy &&
                     report.findings[1].state == DiscrepancyState::NoDiscrepancy,
                 L"X-03 TID reuse alone is never a discrepancy");
    }

    // 同一个 TID 挂到同 PID 的**新进程实例**：进程创建时间不同 -> 不是同一个线程。
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot r0;
            r0.viewId = "r0.thread.enum";
            r0.envelope = MakeEnvelope("r0.thread.enum", "r0.thread", CollectionStatus::Success);
            r0.category = ViewEntityCategory::ThreadList;
            ViewSnapshot r3;
            r3.viewId = "r3.thread.snapshot";
            r3.envelope =
                MakeEnvelope("r3.thread.snapshot", "r3.thread", CollectionStatus::Success);
            r3.category = ViewEntityCategory::ThreadList;

            // 前两轮是老进程实例的线程，最后一轮 PID 被新进程实例复用。
            const std::uint64_t processCreate =
                (i < 2U) ? (kUtcBase + 100000ULL) : (kUtcBase + 700000ULL);
            const std::uint64_t threadCreate =
                (i < 2U) ? (kUtcBase + 110000ULL) : (kUtcBase + 710000ULL);
            r0.records = {MakeThreadRecord(2000U, processCreate, 5001U, threadCreate, "r0-t5001")};
            r3.records = {MakeThreadRecord(2000U, processCreate, 5001U, threadCreate, "r3-t5001")};
            SetAccounting(r0);
            SetAccounting(r3);
            round.views = {r0, r3};
            rounds.push_back(round);
        }
        const CrossViewReport report = AnalyzeCrossView(rounds);
        s.expect(report.findings.size() == 2U,
                 L"X-03 a reused TID under a new process instance is a second object, not the same one");
        for (const CrossViewFinding& finding : report.findings) {
            s.expect(finding.state != DiscrepancyState::Persistent,
                     L"X-03 a lifecycle race is never escalated into a confirmed hidden thread");
            s.expect(finding.conclusion != AnalysisConclusion::DifferenceObserved,
                     L"X-03 neither thread instance is reported as an observed difference");
        }
    }
}

// ---------------------------------------------------------------------------
// X-07 / F-05：证据可回溯，状态与结论不自相矛盾
// ---------------------------------------------------------------------------
void TestTraceabilityAndInvariants(KswordTests::Suite& s) {
    // latestHits 必须来自**最后一轮**：第一轮的命中不能冒充最新状态。
    SampleRound r1 = MakeBaselineRound(1U, 1000U);
    SampleRound r2 = MakeBaselineRound(2U, 2000U);
    SampleRound r3 = MakeBaselineRound(3U, 3000U);
    RemoveRecordFromView(r2, "r3.toolhelp", "r3-2000");
    RemoveRecordFromView(r3, "r3.toolhelp", "r3-2000");
    FailView(r3, "ui.processTable", CollectionStatus::AccessDenied);
    const CrossViewReport report = AnalyzeCrossView({r1, r2, r3});

    const CrossViewFinding* worker = FindStrong(report, "worker.exe");
    s.expect(HitIs(worker, "r3.toolhelp", ObjectPresence::AbsentInUsableView,
                   CollectionStatus::Success),
             L"X-07 the latest hits describe the last round, not the first");
    s.expect(HitIs(worker, "ui.processTable", ObjectPresence::UnknownViewFailed,
                   CollectionStatus::AccessDenied),
             L"X-07 a view that failed only in the last round shows that failure in the latest hits");
    s.expect(worker != nullptr && worker->recheckHistory.size() == 2U,
             L"X-07 the recheck history starts at the first discrepancy round");
    s.expect(worker != nullptr && !worker->recheckHistory.empty() &&
                 worker->recheckHistory[0].hits.size() == 3U,
             L"X-07 the first discrepancy round keeps its own per-view hits");
    s.expect(worker != nullptr && !worker->recheckHistory.empty() &&
                 worker->recheckHistory[0].hits[1].viewId == "r0.process.enum" &&
                 worker->recheckHistory[0].hits[1].rawRecordId == "r0-2000",
             L"X-07 an earlier round still links back to the raw record it reported");
    s.expect(worker != nullptr && worker->firstSeenViewId == "r3.toolhelp" &&
                 worker->firstSeenRawRecordId == "r3-2000",
             L"X-07 the finding names the first source record that ever reported the object");

    for (const CrossViewFinding& finding : report.findings) {
        s.expect(StateConclusionConsistent(finding.state, finding.conclusion),
                 L"F-05 no finding pairs a state with a contradictory conclusion");
        s.expect(finding.latestHits.size() == report.viewCount,
                 L"X-01 every finding covers the whole view union exactly once");
        s.expect(finding.independentSourceGroupCount <= finding.latestHits.size(),
                 L"X-01 a finding never claims more independent sources than it has views");
    }
    s.expect(report.selfCheckPassed,
             L"X-01 the report's own consistency check passes on a normal run");

    // 状态到结论的映射必须是显式的，不能靠一个默认构造的 envelope 反推。
    s.expect(!StateConclusionConsistent(DiscrepancyState::Persistent,
                                        AnalysisConclusion::NoEvidence),
             L"F-05 persistent plus no-evidence is rejected as contradictory");
    s.expect(!StateConclusionConsistent(DiscrepancyState::ObjectEnded,
                                        AnalysisConclusion::NoDifferenceObserved),
             L"F-05 object-ended plus no-difference-observed is rejected as contradictory");
    s.expect(!StateConclusionConsistent(DiscrepancyState::Unverifiable,
                                        AnalysisConclusion::DifferenceObserved),
             L"F-05 unverifiable plus difference-observed is rejected as contradictory");
    s.expect(StateConclusionConsistent(DiscrepancyState::Persistent,
                                       AnalysisConclusion::DifferenceObserved),
             L"F-05 persistent plus difference-observed is the only allowed pairing");
}

// ---------------------------------------------------------------------------
// X-02：弱记录与强对象之间的候选边（不合并、也不丢弃）
// ---------------------------------------------------------------------------
void TestCandidateLinks(KswordTests::Suite& s) {
    // 一个视图给出完整身份（含创建时间），另一个视图同 PID 但拿不到创建时间。
    // 期望：两条独立 finding（绝不合并），且两者互相持有一条 Candidate 边。
    SampleRound round;
    round.sampleId = 1U;
    round.sampleUtc100ns = OptionalU64::of(kUtcBase);

    ViewSnapshot strongView;
    strongView.viewId = "r0.enum";
    strongView.category = ViewEntityCategory::ProcessList;
    strongView.envelope = MakeEnvelope("r0.enum", "r0.enum", CollectionStatus::Success);
    strongView.records = { MakeProcessRecord(4242U, kUtcBase + 500ULL, "svc.exe", "r0-4242") };
    SetAccounting(strongView);

    ViewSnapshot weakView;
    weakView.viewId = "r3.enum";
    weakView.category = ViewEntityCategory::ProcessList;
    weakView.envelope = MakeEnvelope("r3.enum", "r3.enum", CollectionStatus::Success);
    ViewRecord weakRecord = MakeProcessRecord(4242U, 0U, "svc.exe", "r3-4242");
    weakRecord.process.createTime100ns = OptionalU64::unset();
    weakView.records = { weakRecord };
    SetAccounting(weakView);

    round.views = { strongView, weakView };
    const CrossViewReport report = AnalyzeCrossView({ round });

    s.expect(report.findings.size() == 2U,
             L"X-02 a weak record and a strong object stay two separate findings");
    s.expect(report.weakIdentityObjects == 1U && report.candidateLinkCount == 1U,
             L"X-02 exactly one candidate link is built for the one weak object");

    const CrossViewFinding* weakFinding = nullptr;
    const CrossViewFinding* strongFinding = nullptr;
    for (const CrossViewFinding& f : report.findings) {
        if (f.identityKey.empty()) {
            weakFinding = &f;
        } else {
            strongFinding = &f;
        }
    }
    s.expect(weakFinding != nullptr && strongFinding != nullptr,
             L"X-02 one finding is weak and the other carries a cross-session key");
    if (weakFinding == nullptr || strongFinding == nullptr) {
        return;
    }

    s.expect(weakFinding->state == DiscrepancyState::CandidateOnly,
             L"X-02 the weak finding stays candidate-only and never escalates");
    s.expect(weakFinding->candidateLinks.size() == 1U &&
                 weakFinding->candidateLinks[0].strongIdentityKey == strongFinding->identityKey,
             L"X-02 the weak finding points at the strong object it may correspond to");
    s.expect(weakFinding->candidateLinks[0].match == MatchResult::Candidate,
             L"X-02 a link involving a weak identity is never Confirmed");
    s.expect(weakFinding->candidateLinks[0].basis.find("pid=4242") != std::string::npos,
             L"X-02 the link states which field carried it");
    s.expect(strongFinding->candidateLinks.size() == 1U &&
                 strongFinding->candidateLinks[0].strongIdentityKey == weakFinding->candidateKey,
             L"X-02 the strong object carries the reverse link back to the weak record");

    // 反例一：同 PID 但创建时间**不同** —— 这是 PID 复用，Match* 判 NoMatch，不许建边。
    {
        SampleRound reuse = round;
        ViewRecord other = MakeProcessRecord(4242U, kUtcBase + 900000ULL, "svc.exe", "r3-other");
        reuse.views[1].records = { other };
        const CrossViewReport reuseReport = AnalyzeCrossView({ reuse });
        s.expect(reuseReport.candidateLinkCount == 0U,
                 L"X-02 a reused PID with a different creation time gets no candidate link");
        s.expect(reuseReport.findings.size() == 2U,
                 L"X-02 the reused PID still stays two distinct objects");
    }

    // 反例二：PID 不同 —— 连桶都不同，更不许建边。
    {
        SampleRound other = round;
        ViewRecord unrelated = MakeProcessRecord(9999U, 0U, "other.exe", "r3-9999");
        unrelated.process.createTime100ns = OptionalU64::unset();
        other.views[1].records = { unrelated };
        const CrossViewReport otherReport = AnalyzeCrossView({ other });
        s.expect(otherReport.candidateLinkCount == 0U,
                 L"X-02 a different PID gets no candidate link");
    }
}

} // namespace

int RunCrossViewTests() {
    KswordTests::Suite suite(L"X cross-view");
    TestSourceIndependence(suite);
    TestCrossRoundCensus(suite);
    TestFailureIsNotAbsence(suite);
    TestResampleClassification(suite);
    TestReplayablePositives(suite);
    TestEntityCategories(suite);
    TestIdentityGuards(suite);
    TestThreadIdentity(suite);
    TestTraceabilityAndInvariants(suite);
    TestCandidateLinks(suite);
    suite.report();
    return suite.failures();
}
