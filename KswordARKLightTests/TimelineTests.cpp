// T 模块（统一时间线与调查会话）的离线自动测试。
//
// 覆盖编号：T-01 T-02 T-03 T-04 T-05 T-06 T-08 T-09 T-10 T-12。
// 未覆盖：T-07（独立游标/租约，只能在目标环境实测）、T-11（受控负载辅助程序，
// 需要真实进程/文件/注册表/loopback 操作，本层无法产生）。
//
// 断言原则（Q-01 / Q-02）：
//   * 期望值一律独立手写。判"排序对不对"时给出手写的期望 recordId 序列，
//     不拿被测排序函数的输出去和它自己比；判"时间差对不对"时写死 -50、10000
//     这类手算值，不调用被测的差值函数生成期望。
//   * 坏文件用例的输入由测试自己改字节（截断、替换 payload、改 trailer 计数），
//     生产解析路径没有任何读取测试真值的分支。
//   * 每一条"必须拒绝"的判据都有对应的反例断言：默认账目不算完整、裸 PID 不建
//     SameProcess 边、未知 version 不套旧解析器、弱身份不给确认。

#include "TestSupport.h"

#include "../shared/evidence/TimelineCore.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace Ksword::Evidence;

constexpr const char* kBoot1 = "boot-T-1";
constexpr const char* kBoot2 = "boot-T-2";

// 手写的时间基准：2022-08-01 前后的 FILETIME 量级，全部十进制手算。
constexpr std::uint64_t kT0 = 133000000000000000ULL;

BoundsPolicy MakeBounds(std::uint64_t maxEvents, RetentionPolicy policy) {
    BoundsPolicy bounds;
    bounds.maxEventsInMemory = OptionalU64::of(maxEvents);
    bounds.policy = policy;
    bounds.declaredBeforeCollection = true;  // T-08：采集前已呈现
    return bounds;
}

// T-08：会话必须存在一条能真正换算成条数的上限才允许开始采集，所以"声明过但完全无界"
// 这种写法已经不存在了。这里给一个远高于任何用例条数的内存上限（10000），
// 上限因此从不生效，同时满足"内存有上限"的前置条件。
BoundsPolicy MakeRoomyDeclaredBounds() {
    BoundsPolicy bounds;
    bounds.maxEventsInMemory = OptionalU64::of(10000ULL);
    bounds.policy = RetentionPolicy::StopOnLimit;
    bounds.declaredBeforeCollection = true;
    return bounds;
}

SessionManifest MakeManifest() {
    SessionManifest manifest;
    manifest.sessionId = "session-T-1";
    manifest.machineId = "machine-T";
    manifest.bootId = kBoot1;
    manifest.displayName = "T timeline";
    manifest.window.machineId = "machine-T";
    manifest.window.bootId = kBoot1;
    manifest.window.sessionId = "session-T-1";
    manifest.window.mode = CaptureMode::Streaming;
    manifest.window.startUtc100ns = OptionalU64::of(kT0);
    manifest.window.endUtc100ns = OptionalU64::of(kT0 + 1000000ULL);
    manifest.queryRangeBegin100ns = OptionalU64::of(kT0);
    manifest.queryRangeEnd100ns = OptionalU64::of(kT0 + 1000000ULL);
    return manifest;
}

// T-06："会话等于完整系统活动"需要正面证据：至少声明过一个 collector 能力，
// 且每一个已声明的 collector 都真的跑成功了。裸 manifest 一个能力都没声明，
// 因此它永远不算完整采集 —— 这正是下面两个 manifest 分开的原因。
CollectorCapability MakeHealthyCapability() {
    CollectorCapability capability;
    capability.collectorId = "etw.kernel";
    capability.collectorVersion = 3U;
    capability.sourceGroup = "etw.kernel";
    capability.origin = SourceOrigin::LiveKernel;
    capability.declaredCategories.push_back(TimelineEventCategory::Process);
    capability.declaredCategories.push_back(TimelineEventCategory::File);
    capability.availability = CollectionOutcome::success();
    return capability;
}

SessionManifest MakeManifestWithHealthyCollector() {
    SessionManifest manifest = MakeManifest();
    manifest.capabilities.push_back(MakeHealthyCapability());
    return manifest;
}

EventTimeStamp MakeTime(const char* bootId,
                        std::uint64_t sourceTime,
                        std::uint64_t receiveTime,
                        TimeResolution resolution) {
    EventTimeStamp time;
    time.bootId = bootId;
    time.sourceTime100ns = OptionalU64::of(sourceTime);
    time.receiveTime100ns = OptionalU64::of(receiveTime);
    time.sourceResolution = resolution;
    return time;
}

TimelineEvent MakeEvent(const char* recordId,
                        const char* providerId,
                        TimelineEventCategory category,
                        std::uint64_t pid,
                        const EventTimeStamp& time) {
    TimelineEvent event;
    event.recordId = recordId;
    event.providerId = providerId;
    event.sourceGroup = "etw.kernel";
    event.eventId = 1U;
    event.eventVersion = 1U;
    event.category = category;
    event.pid = OptionalU64::of(pid);
    event.time = time;
    event.parseOutcome = EventParseOutcome::Parsed;
    event.parserId = "test.parser";
    event.parserVersion = 1U;
    event.rawFields.emplace_back("Field", std::string(recordId) + "-value");
    event.rawPayloadHex = "00112233";
    return event;
}

// 六类都声明具名来源，本地口径从 0 起算 —— 这样 totalLost() 才敢给出确定值。
void DeclareAllLossSources(LossLedger& ledger) {
    ledger.declareSource(LossCategory::SourceDrop, "etw.EventsLost", true, false);
    ledger.declareSource(LossCategory::RingOverwrite, "ring.OverwriteCount", true, false);
    ledger.declareSource(LossCategory::QueueDiscard, "local.r3queue", false, false);
    ledger.declareSource(LossCategory::ParseFailure, "local.parser", false, false);
    ledger.declareSource(LossCategory::FilteredOut, "local.collectionFilter", false, false);
    ledger.declareSource(LossCategory::RetentionEvicted, "local.retention", false, false);
    ledger.setAbsolute(LossCategory::SourceDrop, 0ULL);
    ledger.setAbsolute(LossCategory::RingOverwrite, 0ULL);
}

std::vector<std::string> SplitTextLines(const std::string& text) {
    std::vector<std::string> lines;
    std::size_t begin = 0;
    while (begin < text.size()) {
        const std::size_t pos = text.find('\n', begin);
        if (pos == std::string::npos) {
            lines.push_back(text.substr(begin));
            break;
        }
        lines.push_back(text.substr(begin, pos - begin + 1U));  // 保留换行符
        begin = pos + 1U;
    }
    return lines;
}

// 越界读会让整个套件崩掉、一条失败都报不出来。断言里一律走这个取元素器：
// 索引越界时返回一个默认对象，于是失败表现为"值不对"而不是进程死掉。
template <typename Container>
const typename Container::value_type& ElementOrDefault(const Container& items, std::size_t index) {
    static const typename Container::value_type kFallback{};
    return index < items.size() ? items[index] : kFallback;
}

bool ContainsKey(const std::vector<std::string>& keys, const char* needle) {
    return std::find(keys.begin(), keys.end(), std::string(needle)) != keys.end();
}

bool HasEdge(const std::vector<TimelineEdge>& edges, TimelineEdgeKind kind, const char* from, const char* to) {
    for (const TimelineEdge& edge : edges) {
        if (edge.kind == kind && edge.fromRecordId == from && edge.toRecordId == to) {
            return true;
        }
    }
    return false;
}

std::size_t CountEdges(const std::vector<TimelineEdge>& edges, TimelineEdgeKind kind) {
    std::size_t count = 0;
    for (const TimelineEdge& edge : edges) {
        if (edge.kind == kind) {
            ++count;
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// T-01 会话生命周期
// ---------------------------------------------------------------------------
void TestSessionLifecycle(KswordTests::Suite& s) {
    // 核心分离：暂停显示时后台仍在记录；只有"停止采集"让后台停。
    s.expect(SessionAcceptsNewEvents(SessionState::Collecting),
             L"T-01 Collecting records events");
    s.expect(SessionAcceptsNewEvents(SessionState::DisplayPaused),
             L"T-01 DisplayPaused still records in background");
    s.expect(!SessionUpdatesDisplay(SessionState::DisplayPaused),
             L"T-01 DisplayPaused freezes the display only");
    s.expect(!SessionAcceptsNewEvents(SessionState::Stopped),
             L"T-01 Stopped records nothing");
    s.expect(!SessionAcceptsNewEvents(SessionState::Saved),
             L"T-01 Saved records nothing");
    s.expect(!SessionAcceptsNewEvents(SessionState::New),
             L"T-01 New records nothing before Start");

    const SessionTransition start = EvaluateSessionTransition(SessionState::New, SessionAction::Start);
    s.expect(start.allowed && start.nextState == SessionState::Collecting,
             L"T-01 New + Start -> Collecting");
    s.expect(start.backgroundRecording && start.displayUpdating,
             L"T-01 Collecting records and displays");

    const SessionTransition pause =
        EvaluateSessionTransition(SessionState::Collecting, SessionAction::PauseDisplay);
    s.expect(pause.allowed && pause.nextState == SessionState::DisplayPaused,
             L"T-01 Collecting + PauseDisplay -> DisplayPaused");
    s.expect(pause.backgroundRecording,
             L"T-01 pausing the display does NOT stop background recording");
    s.expect(!pause.displayUpdating, L"T-01 paused display stops updating");
    s.expect(pause.bufferingNoticeKey == "timeline.session.buffering.recording-display-frozen",
             L"T-01 paused state exposes its buffering policy key");

    const SessionTransition stopFromPause =
        EvaluateSessionTransition(SessionState::DisplayPaused, SessionAction::StopCollection);
    s.expect(stopFromPause.allowed && stopFromPause.nextState == SessionState::Stopped,
             L"T-01 StopCollection is reachable from DisplayPaused");
    s.expect(!stopFromPause.backgroundRecording,
             L"T-01 StopCollection is the only action that stops recording");

    const SessionTransition badResume =
        EvaluateSessionTransition(SessionState::Collecting, SessionAction::ResumeDisplay);
    s.expect(!badResume.allowed && badResume.nextState == SessionState::Collecting,
             L"T-01 ResumeDisplay while collecting is rejected without changing state");
    s.expect(badResume.rejectionKey == "timeline.session.display-not-paused",
             L"T-01 rejected resume names its reason");
    s.expect(badResume.backgroundRecording,
             L"T-01 a rejected action still reports the true current recording state");

    const SessionTransition restart =
        EvaluateSessionTransition(SessionState::Stopped, SessionAction::Start);
    s.expect(!restart.allowed &&
                 restart.rejectionKey == "timeline.session.restart-requires-new-session",
             L"T-01 a stopped session cannot be restarted in place");
    const SessionTransition saveWhileCollecting =
        EvaluateSessionTransition(SessionState::Collecting, SessionAction::Save);
    s.expect(!saveWhileCollecting.allowed &&
                 saveWhileCollecting.rejectionKey == "timeline.session.stop-before-save",
             L"T-01 saving requires a determined end boundary");
    s.expect(EvaluateSessionTransition(SessionState::Stopped, SessionAction::Save).allowed,
             L"T-01 Stopped + Save -> Saved");
    s.expect(EvaluateSessionTransition(SessionState::Saved, SessionAction::Reset).allowed,
             L"T-01 Saved + Reset -> New");
    s.expect(!EvaluateSessionTransition(SessionState::New, SessionAction::Save).allowed,
             L"T-01 New has nothing to save");

    // T-08 前置条件：上限没有在采集前声明就不许开始。
    SessionManifest manifest = MakeManifest();
    BoundsPolicy undeclared;
    undeclared.maxEventsInMemory = OptionalU64::of(10ULL);
    undeclared.declaredBeforeCollection = false;
    TimelineSession undeclaredSession(manifest, undeclared);
    const SessionTransition blocked = undeclaredSession.apply(SessionAction::Start);
    s.expect(!blocked.allowed && blocked.rejectionKey == "timeline.session.bounds-not-declared",
             L"T-08 collection cannot start before the bounds are declared");
    s.expect(undeclaredSession.state() == SessionState::New,
             L"T-08 a blocked Start leaves the session in New");

    // 真实流水：开始 -> 记 1 条 -> 暂停显示 -> 再记 1 条（必须进会话）-> 停止 -> 再记（必须拒绝）。
    TimelineSession session(manifest, MakeRoomyDeclaredBounds());
    s.expect(session.apply(SessionAction::Start).allowed, L"T-01 session starts");
    const IngestResult first = session.ingest(
        MakeEvent("e1", "P", TimelineEventCategory::Process, 100U,
                  MakeTime(kBoot1, kT0 + 10ULL, kT0 + 20ULL, TimeResolution::Microsecond)));
    s.expect(first.accepted && first.assignedSequence == 1U,
             L"T-01 first event is accepted with sequence 1");
    s.expect(session.apply(SessionAction::PauseDisplay).allowed, L"T-01 display pauses");
    const IngestResult duringPause = session.ingest(
        MakeEvent("e2", "P", TimelineEventCategory::File, 100U,
                  MakeTime(kBoot1, kT0 + 30ULL, kT0 + 40ULL, TimeResolution::Microsecond)));
    s.expect(duringPause.accepted,
             L"T-01 events collected while the display is paused still enter the session");
    s.expect(session.events().size() == 2U, L"T-01 two events retained after the pause");
    s.expect(session.apply(SessionAction::StopCollection).allowed, L"T-01 collection stops");
    const IngestResult afterStop = session.ingest(
        MakeEvent("e3", "P", TimelineEventCategory::File, 100U,
                  MakeTime(kBoot1, kT0 + 50ULL, kT0 + 60ULL, TimeResolution::Microsecond)));
    s.expect(!afterStop.accepted &&
                 afterStop.reasonKey == "timeline.ingest.session-not-collecting",
             L"T-01 no new event is recorded after StopCollection");
    s.expect(session.events().size() == 2U,
             L"T-01 the stopped session still holds exactly the two collected events");
    s.expect(!afterStop.countedAsLoss,
             L"T-01 a post-stop event is not counted as a capture loss");
}

// ---------------------------------------------------------------------------
// T-02 事件 envelope 与解析
// ---------------------------------------------------------------------------
EventSchemaRegistry MakeRegistry() {
    EventSchemaRegistry registry;
    const struct {
        const char* provider;
        std::uint32_t eventId;
        const char* parserId;
        std::uint32_t parserVersion;
        TimelineEventCategory category;
        const char* requiredField;
    } kSpecs[] = {
        { "Kernel-Process",  1U, "parser.process",  11U, TimelineEventCategory::Process,  "ProcessId" },
        { "Kernel-Thread",   2U, "parser.thread",   12U, TimelineEventCategory::Thread,   "ThreadId" },
        { "Kernel-Image",    3U, "parser.image",    13U, TimelineEventCategory::Image,    "ImageBase" },
        { "Kernel-File",     4U, "parser.file",     14U, TimelineEventCategory::File,     "FileName" },
        { "Kernel-Registry", 5U, "parser.registry", 15U, TimelineEventCategory::Registry, "KeyName" },
        { "Kernel-Network",  6U, "parser.network",  16U, TimelineEventCategory::Network,  "RemotePort" },
    };
    for (const auto& spec : kSpecs) {
        EventSchema schema;
        schema.providerId = spec.provider;
        schema.eventId = spec.eventId;
        schema.version = 1U;
        schema.parserId = spec.parserId;
        schema.parserVersion = spec.parserVersion;
        schema.category = spec.category;
        schema.requiredFields.push_back(spec.requiredField);
        registry.add(schema);
    }
    // 同一个 event 的第 3 版也已知：用于证明"请求第 2 版时既不退到 1 也不跳到 3"。
    EventSchema v3;
    v3.providerId = "Kernel-File";
    v3.eventId = 4U;
    v3.version = 3U;
    v3.parserId = "parser.file.v3";
    v3.parserVersion = 34U;
    v3.category = TimelineEventCategory::File;
    v3.requiredFields.push_back("FileName");
    registry.add(v3);
    return registry;
}

void TestEventEnvelope(KswordTests::Suite& s) {
    const EventSchemaRegistry registry = MakeRegistry();
    s.expect(registry.size() == 7U, L"T-02 registry holds the seven declared schemas");

    // 六类各一个固定样本，期望的 parserVersion 与类别在测试里独立写死。
    const struct {
        const char* provider;
        std::uint32_t eventId;
        const char* field;
        std::uint32_t expectedParserVersion;
        TimelineEventCategory expectedCategory;
    } kSamples[] = {
        { "Kernel-Process",  1U, "ProcessId",  11U, TimelineEventCategory::Process },
        { "Kernel-Thread",   2U, "ThreadId",   12U, TimelineEventCategory::Thread },
        { "Kernel-Image",    3U, "ImageBase",  13U, TimelineEventCategory::Image },
        { "Kernel-File",     4U, "FileName",   14U, TimelineEventCategory::File },
        { "Kernel-Registry", 5U, "KeyName",    15U, TimelineEventCategory::Registry },
        { "Kernel-Network",  6U, "RemotePort", 16U, TimelineEventCategory::Network },
    };
    std::size_t parsedCount = 0;
    for (const auto& sample : kSamples) {
        EventParseRequest request;
        request.providerId = sample.provider;
        request.eventId = sample.eventId;
        request.version = 1U;
        request.rawFields.emplace_back(sample.field, "sample");
        request.rawPayloadHex = "AABB";
        const EventParseReport report = ParseEventPayload(registry, request);
        if (report.outcome == EventParseOutcome::Parsed &&
            report.parserVersion == sample.expectedParserVersion &&
            report.category == sample.expectedCategory &&
            report.reasonKey == "timeline.parse.ok") {
            ++parsedCount;
        }
    }
    s.expect(parsedCount == 6U, L"T-02 all six declared categories parse with their own parser");

    // 未知 version：既不套 v1 也不套 v3。
    EventParseRequest unknown;
    unknown.providerId = "Kernel-File";
    unknown.eventId = 4U;
    unknown.version = 2U;
    unknown.rawFields.emplace_back("FileName", "C:\\t\\a.txt");
    unknown.rawFields.emplace_back("NewFieldInV2", "42");
    unknown.rawPayloadHex = "DEADBEEF";
    const EventParseReport unknownReport = ParseEventPayload(registry, unknown);
    s.expect(unknownReport.outcome == EventParseOutcome::UnparsedUnknownSchema,
             L"T-02 an unknown event version is kept as an unparsed record");
    s.expect(unknownReport.parserVersion == 0U,
             L"T-02 an unknown version never borrows another version's parser version");
    s.expect(unknownReport.parserId.empty(),
             L"T-02 an unknown version names no parser");
    s.expect(unknownReport.reasonKey == "timeline.parse.unknown-event-version",
             L"T-02 unknown version and unknown provider are distinguishable");

    EventParseRequest unknownProvider = unknown;
    unknownProvider.providerId = "Some-Third-Party";
    const EventParseReport unknownProviderReport = ParseEventPayload(registry, unknownProvider);
    s.expect(unknownProviderReport.reasonKey == "timeline.parse.unknown-provider-event",
             L"T-02 an unknown provider gets its own reason key");
    s.expect(unknownProviderReport.outcome == EventParseOutcome::UnparsedUnknownSchema,
             L"T-02 an unknown provider is also an unparsed record, not a malformed one");

    // 缺必需字段 -> Malformed，且解析器身份被记录下来（是"这个解析器失败了"）。
    EventParseRequest missing;
    missing.providerId = "Kernel-File";
    missing.eventId = 4U;
    missing.version = 1U;
    missing.rawFields.emplace_back("SomethingElse", "x");
    const EventParseReport missingReport = ParseEventPayload(registry, missing);
    s.expect(missingReport.outcome == EventParseOutcome::Malformed,
             L"T-02 a missing required field is Malformed, not Parsed");
    s.expect(missingReport.missingRequiredFields.size() == 1U &&
                 missingReport.missingRequiredFields[0] == "FileName",
             L"T-02 the missing field is named");
    s.expect(missingReport.parserVersion == 14U,
             L"T-02 a malformed payload still records which parser tried");

    // 采集侧已知载荷被截断 -> Malformed，且不去选解析器。
    EventParseRequest truncated;
    truncated.providerId = "Kernel-File";
    truncated.eventId = 4U;
    truncated.version = 1U;
    truncated.payloadTruncated = true;
    const EventParseReport truncatedReport = ParseEventPayload(registry, truncated);
    s.expect(truncatedReport.outcome == EventParseOutcome::Malformed &&
                 truncatedReport.reasonKey == "timeline.parse.payload-truncated",
             L"T-02 a truncated payload is Malformed with its own reason");
    s.expect(truncatedReport.parserId.empty(),
             L"T-02 a truncated payload selects no parser at all");

    // 未解析记录必须完整保留原始字段与原始载荷，且类别不被反推。
    TimelineEvent event;
    event.recordId = "u1";
    event.providerId = "Kernel-File";
    event.eventId = 4U;
    event.eventVersion = 2U;
    event.category = TimelineEventCategory::Other;
    event.rawFields = unknown.rawFields;
    event.rawPayloadHex = unknown.rawPayloadHex;
    ApplyParseReport(event, unknownReport);
    s.expect(event.parseOutcome == EventParseOutcome::UnparsedUnknownSchema,
             L"T-02 the unparsed outcome lands on the event");
    s.expect(event.rawFields.size() == 2U && event.rawFields[0].first == "FileName" &&
                 event.rawFields[0].second == "C:\\t\\a.txt" &&
                 event.rawFields[1].first == "NewFieldInV2" && event.rawFields[1].second == "42",
             L"T-02 raw fields survive an unparsed record byte for byte");
    s.expect(event.rawPayloadHex == "DEADBEEF",
             L"T-02 the raw payload survives an unparsed record");
    s.expect(event.category == TimelineEventCategory::Other,
             L"T-02 an unparsed record does not get a guessed category");
    s.expect(event.eventVersion == 2U,
             L"T-02 the original event version is preserved on the record");

    TimelineEvent parsedEvent;
    parsedEvent.category = TimelineEventCategory::Other;
    EventParseRequest fileRequest;
    fileRequest.providerId = "Kernel-File";
    fileRequest.eventId = 4U;
    fileRequest.version = 1U;
    fileRequest.rawFields.emplace_back("FileName", "C:\\t\\b.txt");
    ApplyParseReport(parsedEvent, ParseEventPayload(registry, fileRequest));
    s.expect(parsedEvent.category == TimelineEventCategory::File &&
                 parsedEvent.parserVersion == 14U,
             L"T-02 a parsed record takes the schema's category and parser version");

    TimelineEvent defaultEvent;
    s.expect(defaultEvent.parseOutcome == EventParseOutcome::UnparsedUnknownSchema &&
                 defaultEvent.parserVersion == 0U,
             L"T-02 a default-constructed event is unparsed, not silently Parsed");
}

// ---------------------------------------------------------------------------
// T-04 时间语义
// ---------------------------------------------------------------------------
void TestTimeSemantics(KswordTests::Suite& s) {
    s.expect(ResolutionSpan100ns(TimeResolution::Millisecond) == 10000ULL,
             L"T-04 one millisecond is 10000 units of 100ns");
    s.expect(ResolutionSpan100ns(TimeResolution::Second) == 10000000ULL,
             L"T-04 one second is 10000000 units of 100ns");
    s.expect(ResolutionSpan100ns(TimeResolution::Unknown) == 0ULL,
             L"T-04 an unknown resolution declares no span");

    // 校准是派生量：源时间原封不动，effective 才叠加偏移。
    EventTimeStamp calibrated = MakeTime(kBoot1, 1000ULL, 1100ULL, TimeResolution::Microsecond);
    calibrated.calibrationAvailable = true;
    calibrated.calibrationOffset100ns = -250;
    calibrated.calibrationId = "cal-A";
    s.expect(calibrated.sourceTime100ns.present && calibrated.sourceTime100ns.value == 1000ULL,
             L"T-04 calibration never rewrites the source time");
    s.expect(calibrated.effectiveTime100ns().present &&
                 calibrated.effectiveTime100ns().value == 750ULL,
             L"T-04 the effective time applies the calibration offset");

    EventTimeStamp underflow = MakeTime(kBoot1, 100ULL, 100ULL, TimeResolution::Microsecond);
    underflow.calibrationAvailable = true;
    underflow.calibrationOffset100ns = -500;
    s.expect(underflow.effectiveTime100ns().value == 0ULL,
             L"T-04 a negative calibration saturates at zero instead of wrapping");

    EventTimeStamp receiveOnly;
    receiveOnly.bootId = kBoot1;
    receiveOnly.receiveTime100ns = OptionalU64::of(4242ULL);
    receiveOnly.sourceResolution = TimeResolution::Millisecond;
    s.expect(receiveOnly.effectiveFromReceiveTime() &&
                 receiveOnly.effectiveTime100ns().value == 4242ULL,
             L"T-04 a missing source time falls back to the receive time and says so");

    EventTimeStamp noTime;
    noTime.bootId = kBoot1;
    s.expect(!noTime.effectiveTime100ns().present,
             L"T-04 an event with no time at all stays unknown, not zero");

    // 顺序比较。期望的 delta 全部手算。
    const EventTimeStamp a = MakeTime(kBoot1, 100000ULL, 100000ULL, TimeResolution::Microsecond);
    const EventTimeStamp b = MakeTime(kBoot1, 110000ULL, 110000ULL, TimeResolution::Microsecond);
    const TimeComparisonResult forward = CompareEventTimes(a, b);
    s.expect(forward.kind == TimeComparison::Comparable && forward.delta100ns == 10000,
             L"T-04 a forward pair is comparable with a positive delta");
    s.expect(!forward.regression, L"T-04 a forward pair reports no regression");

    const TimeComparisonResult backward = CompareEventTimes(b, a);
    s.expect(backward.delta100ns == -10000 && backward.regression,
             L"T-04 a reversed pair reports a negative delta and a regression");

    // 时钟回拨的回绕陷阱：无符号相减会把 -50 报成 1.8e19。
    const EventTimeStamp late = MakeTime(kBoot1, 100ULL, 100ULL, TimeResolution::HundredNanosecond);
    const EventTimeStamp rolledBack = MakeTime(kBoot1, 50ULL, 120ULL, TimeResolution::HundredNanosecond);
    const TimeComparisonResult regression = CompareEventTimes(late, rolledBack);
    s.expect(regression.delta100ns == -50,
             L"T-04 a 50-unit clock rollback reports exactly -50, never a wrapped value");
    s.expect(regression.regression && regression.kind == TimeComparison::Comparable,
             L"T-04 the rollback is flagged as a regression");

    const EventTimeStamp same = MakeTime(kBoot1, 100000ULL, 100001ULL, TimeResolution::Microsecond);
    const TimeComparisonResult duplicate = CompareEventTimes(a, same);
    s.expect(duplicate.kind == TimeComparison::ComparableButUncertain && duplicate.delta100ns == 0,
             L"T-04 identical timestamps are comparable but order-uncertain");

    const EventTimeStamp close = MakeTime(kBoot1, 100003ULL, 100003ULL, TimeResolution::Microsecond);
    s.expect(CompareEventTimes(a, close).kind == TimeComparison::ComparableButUncertain,
             L"T-04 a gap smaller than the resolution is order-uncertain");

    const EventTimeStamp coarse = MakeTime(kBoot1, 200000ULL, 200000ULL, TimeResolution::Unknown);
    s.expect(CompareEventTimes(a, coarse).kind == TimeComparison::ComparableButUncertain,
             L"T-04 an unknown resolution never claims a strict order");

    const EventTimeStamp otherBoot = MakeTime(kBoot2, 110000ULL, 110000ULL, TimeResolution::Microsecond);
    const TimeComparisonResult crossBoot = CompareEventTimes(a, otherBoot);
    s.expect(crossBoot.kind == TimeComparison::IncomparableCrossBoot && crossBoot.delta100ns == 0,
             L"T-04 timestamps from two boot cycles are never subtracted");

    EventTimeStamp noBoot = MakeTime("", 110000ULL, 110000ULL, TimeResolution::Microsecond);
    s.expect(CompareEventTimes(a, noBoot).kind == TimeComparison::IncomparableCrossBoot,
             L"T-04 a missing boot id also blocks subtraction");

    s.expect(CompareEventTimes(a, noTime).kind == TimeComparison::IncomparableUnknownTime,
             L"T-04 a missing time is incomparable, not zero");

    const EventTimeStamp low = MakeTime(kBoot1, 0ULL, 0ULL, TimeResolution::HundredNanosecond);
    const EventTimeStamp high =
        MakeTime(kBoot1, 18000000000000000000ULL, 0ULL, TimeResolution::HundredNanosecond);
    const TimeComparisonResult huge = CompareEventTimes(low, high);
    s.expect(huge.kind == TimeComparison::IncomparableMagnitude && huge.delta100ns == 0,
             L"T-04 a difference beyond int64 is reported incomparable rather than wrapped");

    EventTimeStamp calA = MakeTime(kBoot1, 100000ULL, 100000ULL, TimeResolution::Microsecond);
    calA.calibrationId = "cal-1";
    EventTimeStamp calB = MakeTime(kBoot1, 200000ULL, 200000ULL, TimeResolution::Microsecond);
    calB.calibrationId = "cal-2";
    const TimeComparisonResult calibrationChange = CompareEventTimes(calA, calB);
    s.expect(calibrationChange.calibrationChanged &&
                 calibrationChange.kind == TimeComparison::ComparableButUncertain,
             L"T-04 a calibration change downgrades the order to uncertain");

    // 排序键：手写期望顺序。
    TimelineSortKey k1;
    k1.bootEpochRank = 0U;
    k1.timeKnown = true;
    k1.effectiveTime100ns = 200ULL;
    k1.arrivalSequence = 5U;
    k1.recordId = "b";
    TimelineSortKey k2 = k1;
    k2.effectiveTime100ns = 100ULL;
    k2.arrivalSequence = 9U;
    k2.recordId = "a";
    s.expect(SortKeyLess(k2, k1) && !SortKeyLess(k1, k2),
             L"T-04 an earlier effective time sorts first regardless of arrival order");
    TimelineSortKey unknownKey = k1;
    unknownKey.timeKnown = false;
    unknownKey.effectiveTime100ns = 0ULL;
    s.expect(SortKeyLess(k1, unknownKey) && !SortKeyLess(unknownKey, k1),
             L"T-04 unknown-time keys sort after known ones, not to the front");
    TimelineSortKey epochKey = k2;
    epochKey.bootEpochRank = 1U;
    s.expect(SortKeyLess(k1, epochKey),
             L"T-04 a later boot epoch sorts after the first epoch even with a smaller timestamp");
    TimelineSortKey tieA = k1;
    TimelineSortKey tieB = k1;
    tieB.arrivalSequence = 6U;
    s.expect(SortKeyLess(tieA, tieB), L"T-04 equal timestamps are tie-broken by arrival sequence");
    TimelineSortKey groupA = k1;
    TimelineSortKey groupB = k1;
    groupA.sourceGroup = "etw";
    groupB.sourceGroup = "ring";
    s.expect(SortKeyLess(groupA, groupB), L"T-04 the source group is a stable final tie-break");

    // 会话内：乱序补入、两个启动周期、重复时间。
    TimelineSession session(MakeManifest(), MakeRoomyDeclaredBounds());
    session.apply(SessionAction::Start);
    session.ingest(MakeEvent("t1", "P", TimelineEventCategory::Process, 100U,
                             MakeTime(kBoot1, kT0 + 30000ULL, kT0, TimeResolution::Microsecond)));
    session.ingest(MakeEvent("t2", "P", TimelineEventCategory::Process, 100U,
                             MakeTime(kBoot1, kT0 + 10000ULL, kT0 + 1ULL, TimeResolution::Microsecond)));
    session.ingest(MakeEvent("t3", "P", TimelineEventCategory::Process, 100U,
                             MakeTime(kBoot1, kT0 + 50000ULL, kT0 + 2ULL, TimeResolution::Microsecond)));
    session.ingest(MakeEvent("t4", "P", TimelineEventCategory::Process, 100U,
                             MakeTime(kBoot2, kT0 + 5000ULL, kT0 + 3ULL, TimeResolution::Microsecond)));
    s.expect(session.events().size() == 4U, L"T-04 four events retained");
    s.expect(ElementOrDefault(session.events(), 1).time.lateArrival,
             L"T-04 an out-of-order event is admitted and flagged as late");
    s.expect(!ElementOrDefault(session.events(), 0).time.lateArrival && !ElementOrDefault(session.events(), 2).time.lateArrival,
             L"T-04 in-order events are not flagged as late");
    s.expect(!ElementOrDefault(session.events(), 3).time.lateArrival,
             L"T-04 a smaller timestamp in a NEW boot cycle is not a late arrival");
    s.expect(ElementOrDefault(session.events(), 1).time.sourceTime100ns.value == kT0 + 10000ULL,
             L"T-04 the late event keeps its original source time");

    const std::vector<TimelineSortKey> order = session.sortedOrder();
    s.expect(order.size() == 4U, L"T-04 the sort produces one key per event");
    // 手写期望：boot-1 内按时间 t2 < t1 < t3，boot-2 整体排在后面。
    const bool orderMatches = order.size() == 4U && order[0].recordId == "t2" &&
                              order[1].recordId == "t1" && order[2].recordId == "t3" &&
                              order[3].recordId == "t4";
    s.expect(orderMatches, L"T-04 the cross-source order is t2,t1,t3,t4 as computed by hand");
    s.expect(order.size() == 4U && order[3].bootEpochRank == 1U &&
                 order[3].explanationKey == "timeline.order.cross-boot-grouped-by-epoch",
             L"T-04 the second boot cycle is grouped by epoch and says so");
    s.expect(order.size() == 4U && order[0].explanationKey == "timeline.order.by-source-time",
             L"T-04 an ordinary key explains that it sorted by source time");

    TimelineSession duplicates(MakeManifest(), MakeRoomyDeclaredBounds());
    duplicates.apply(SessionAction::Start);
    duplicates.ingest(MakeEvent("d1", "P", TimelineEventCategory::File, 100U,
                                MakeTime(kBoot1, kT0 + 700ULL, kT0, TimeResolution::Microsecond)));
    duplicates.ingest(MakeEvent("d2", "P", TimelineEventCategory::File, 100U,
                                MakeTime(kBoot1, kT0 + 700ULL, kT0 + 1ULL, TimeResolution::Microsecond)));
    s.expect(ElementOrDefault(duplicates.events(), 0).time.orderUncertain && ElementOrDefault(duplicates.events(), 1).time.orderUncertain,
             L"T-04 two identical timestamps mark both events order-uncertain");
    const std::vector<TimelineSortKey> duplicateOrder = duplicates.sortedOrder();
    s.expect(duplicateOrder.size() == 2U &&
                 duplicateOrder[0].explanationKey == "timeline.order.uncertain-within-resolution",
             L"T-04 the sort explains that these two neighbours are indistinguishable");
}

// ---------------------------------------------------------------------------
// T-05 进程复用与归属
// ---------------------------------------------------------------------------
ProcessInstanceId MakeProcessId(std::uint64_t pid, std::uint64_t createTime, const char* image) {
    ProcessInstanceId id;
    id.bootId = kBoot1;
    id.pid = OptionalU64::of(pid);
    id.createTime100ns = OptionalU64::of(createTime);
    id.imageName = image;
    return id;
}

void TestAttribution(KswordTests::Suite& s) {
    ProcessInstanceLedger ledger;
    // 同一个 PID 1000 的两次生命周期：A[100,200]，B[300,400]。
    s.expect(ledger.observeStart(MakeProcessId(1000U, 100U, "a.exe"), 100U),
             L"T-05 instance A start is recorded");
    s.expect(ledger.observeExit(MakeProcessId(1000U, 100U, "a.exe"), 200U),
             L"T-05 instance A exit is recorded");
    s.expect(ledger.observeStart(MakeProcessId(1000U, 300U, "b.exe"), 300U),
             L"T-05 instance B start is recorded");
    s.expect(ledger.observeExit(MakeProcessId(1000U, 300U, "b.exe"), 400U),
             L"T-05 instance B exit is recorded");
    s.expect(ledger.instanceCount() == 2U, L"T-05 the two lifetimes are separate instances");

    const OptionalU64 pid1000 = OptionalU64::of(1000ULL);
    const AttributionDecision inA =
        ledger.attribute(kBoot1, pid1000, MakeTime(kBoot1, 150U, 150U, TimeResolution::HundredNanosecond));
    s.expect(inA.kind == AttributionKind::BoundToInstance &&
                 inA.instance.createTime100ns.value == 100ULL,
             L"T-05 an event inside A's window binds to A");
    s.expect(inA.identityMatch == MatchResult::Confirmed &&
                 inA.identityStrength == IdentityStrength::Strong,
             L"T-05 a complete instance identity yields a Confirmed match");

    const AttributionDecision inB =
        ledger.attribute(kBoot1, pid1000, MakeTime(kBoot1, 350U, 350U, TimeResolution::HundredNanosecond));
    s.expect(inB.kind == AttributionKind::BoundToInstance &&
                 inB.instance.createTime100ns.value == 300ULL,
             L"T-05 after PID reuse an event inside B's window binds to B, not to A");

    const AttributionDecision between =
        ledger.attribute(kBoot1, pid1000, MakeTime(kBoot1, 250U, 250U, TimeResolution::HundredNanosecond));
    s.expect(between.kind == AttributionKind::AfterInstanceExit,
             L"T-05 an event in the gap between two lifetimes is not attributed to either");
    s.expect(!between.provisionalId.empty() && between.instance.pid.present == false,
             L"T-05 the gap event becomes a provisional entity rather than a silent guess");
    s.expect(between.reasonKey == "timeline.attribution.after-known-exit",
             L"T-05 the gap event names the reason");

    const AttributionDecision afterAll =
        ledger.attribute(kBoot1, pid1000, MakeTime(kBoot1, 900U, 900U, TimeResolution::HundredNanosecond));
    s.expect(afterAll.kind == AttributionKind::AfterInstanceExit,
             L"T-05 a late event arriving after the target ended is not re-hung on a live PID");

    const AttributionDecision beforeAll =
        ledger.attribute(kBoot1, pid1000, MakeTime(kBoot1, 50U, 50U, TimeResolution::HundredNanosecond));
    s.expect(beforeAll.kind == AttributionKind::Provisional &&
                 beforeAll.reasonKey == "timeline.attribution.missing-start-event",
             L"T-05 an event before every known start is provisional");

    // 完全没有开始事件的 PID。
    const AttributionDecision orphan =
        ledger.attribute(kBoot1, OptionalU64::of(2000ULL),
                         MakeTime(kBoot1, 150U, 150U, TimeResolution::HundredNanosecond));
    s.expect(orphan.kind == AttributionKind::Provisional && !orphan.provisionalId.empty(),
             L"T-05 a PID with no start event gets an incomplete-identity provisional entity");
    const ProvisionalProcessEntity* entity = ledger.findProvisional(orphan.provisionalId);
    s.expect(entity != nullptr && !entity->identityComplete,
             L"T-05 the provisional entity is explicitly identity-incomplete");
    s.expect(entity != nullptr && entity->pid.present && entity->pid.value == 2000ULL,
             L"T-05 the provisional entity keeps the observed PID");

    // 弱证据不许把临时实体标成已补齐。
    ProcessInstanceId weak;
    weak.bootId = kBoot1;
    weak.pid = OptionalU64::of(2000ULL);  // 没有 createTime -> crossSessionKey 为空
    s.expect(!ledger.confirmProvisional(orphan.provisionalId, weak, "note"),
             L"T-05 weak evidence cannot confirm a provisional entity");
    const ProvisionalProcessEntity* stillWeak = ledger.findProvisional(orphan.provisionalId);
    s.expect(stillWeak != nullptr && !stillWeak->identityComplete &&
                 stillWeak->resolutionNoteKey ==
                     "timeline.provisional.resolve-rejected-weak-identity",
             L"T-05 the rejected resolution is recorded instead of silently succeeding");

    s.expect(ledger.confirmProvisional(orphan.provisionalId, MakeProcessId(2000U, 140U, "c.exe"),
                                       "timeline.provisional.resolved-by-later-start-event"),
             L"T-05 a complete identity confirms the provisional entity");
    const ProvisionalProcessEntity* resolved = ledger.findProvisional(orphan.provisionalId);
    s.expect(resolved != nullptr && resolved->identityComplete &&
                 !resolved->resolvedInstanceKey.empty() &&
                 resolved->resolutionNoteKey ==
                     "timeline.provisional.resolved-by-later-start-event",
             L"T-05 the resolution keeps a traceable note and the resolved instance key");

    // 身份不完整的实例：窗口对上了也只能给 Candidate。
    ProcessInstanceLedger weakLedger;
    ProcessInstanceId weakInstance;
    weakInstance.bootId = kBoot1;
    weakInstance.pid = OptionalU64::of(3000ULL);
    s.expect(weakLedger.observeStart(weakInstance, 100U),
             L"T-05 an instance without a create time can still be registered");
    const AttributionDecision weakBind =
        weakLedger.attribute(kBoot1, OptionalU64::of(3000ULL),
                             MakeTime(kBoot1, 150U, 150U, TimeResolution::HundredNanosecond));
    s.expect(weakBind.kind == AttributionKind::BoundToInstance &&
                 weakBind.identityStrength == IdentityStrength::Weak &&
                 weakBind.identityMatch == MatchResult::Candidate,
             L"T-05 a weak instance identity caps the match at Candidate");

    // 缺 PID / 缺 bootId / 缺时间的三条退路。
    const AttributionDecision noPid =
        ledger.attribute(kBoot1, OptionalU64::unset(),
                         MakeTime(kBoot1, 150U, 150U, TimeResolution::HundredNanosecond));
    s.expect(noPid.kind == AttributionKind::UnknownProcess &&
                 noPid.reasonKey == "timeline.attribution.no-pid",
             L"T-05 an event without a PID is UnknownProcess");
    const AttributionDecision noBoot =
        ledger.attribute("", pid1000, MakeTime("", 150U, 150U, TimeResolution::HundredNanosecond));
    s.expect(noBoot.kind == AttributionKind::Provisional &&
                 noBoot.reasonKey == "timeline.attribution.no-boot-id",
             L"T-05 without a boot id the PID is never resolved to a live instance");
    EventTimeStamp timeless;
    timeless.bootId = kBoot1;
    const AttributionDecision noTime = ledger.attribute(kBoot1, pid1000, timeless);
    s.expect(noTime.kind == AttributionKind::Provisional &&
                 noTime.reasonKey == "timeline.attribution.no-time",
             L"T-05 an event without a usable time is not placed into any window");

    s.expect(!ledger.observeStart(ProcessInstanceId{}, 10U),
             L"T-05 an instance with neither boot id nor PID is refused");
    s.expect(!ledger.observeExit(MakeProcessId(4321U, 1U, "x.exe"), 10U),
             L"T-05 an exit for an unknown instance does not fabricate one");

    // 会话路径同样不许静默归属。
    TimelineSession session(MakeManifest(), MakeRoomyDeclaredBounds());
    session.apply(SessionAction::Start);
    session.processes().observeStart(MakeProcessId(5000U, kT0 + 100ULL, "live.exe"), kT0 + 100ULL);
    session.ingest(MakeEvent("p1", "Kernel-File", TimelineEventCategory::File, 5000U,
                             MakeTime(kBoot1, kT0 + 200ULL, kT0 + 200ULL, TimeResolution::Microsecond)));
    session.ingest(MakeEvent("p2", "Kernel-File", TimelineEventCategory::File, 6000U,
                             MakeTime(kBoot1, kT0 + 300ULL, kT0 + 300ULL, TimeResolution::Microsecond)));
    s.expect(ElementOrDefault(session.events(), 0).attribution == AttributionKind::BoundToInstance &&
                 !ElementOrDefault(session.events(), 0).processInstanceKey.empty(),
             L"T-05 a known instance produces a cross-session instance key on the event");
    s.expect(ElementOrDefault(session.events(), 1).attribution == AttributionKind::Provisional &&
                 ElementOrDefault(session.events(), 1).processInstanceKey.empty() &&
                 !ElementOrDefault(session.events(), 1).provisionalProcessId.empty(),
             L"T-05 an unknown PID gets a provisional id and NO instance key");

    // -----------------------------------------------------------------------
    // T-05 PID 复用 + 迟到的结束事件。手写时间线：
    //   A: createTime=100, start=100，结束事件迟到，报告时刻 350
    //   B: createTime=300, start=300，尚未看到结束
    // 只按 (bootId, pid, 开始时间最晚且未结束) 挑候选，A 的退出会被记到 B 头上。
    // -----------------------------------------------------------------------
    ProcessInstanceLedger reuse;
    s.expect(reuse.observeStart(MakeProcessId(1000U, 100U, "a.exe"), 100U),
             L"T-05 reuse fixture: instance A starts at 100");
    s.expect(reuse.observeStart(MakeProcessId(1000U, 300U, "b.exe"), 300U),
             L"T-05 reuse fixture: instance B starts at 300 on the same PID");
    s.expect(reuse.observeExit(MakeProcessId(1000U, 100U, "a.exe"), 350U),
             L"T-05 a late exit is matched to A by createTime, not to the newest same-PID instance");
    const AttributionDecision reuseAt400 =
        reuse.attribute(kBoot1, pid1000, MakeTime(kBoot1, 400U, 400U, TimeResolution::HundredNanosecond));
    s.expect(reuseAt400.kind == AttributionKind::BoundToInstance &&
                 reuseAt400.instance.createTime100ns.present &&
                 reuseAt400.instance.createTime100ns.value == 300ULL,
             L"T-05 after that late exit an event at t=400 binds to B (createTime 300), not to the dead A (createTime 100)");
    const AttributionDecision reuseAt320 =
        reuse.attribute(kBoot1, pid1000, MakeTime(kBoot1, 320U, 320U, TimeResolution::HundredNanosecond));
    s.expect(reuseAt320.kind == AttributionKind::Ambiguous,
             L"T-05 t=320 sits inside both windows and is reported Ambiguous instead of being picked");

    // 退出事件带 createTime，但登记的实例没有 —— 无从核对，拒绝而不是硬挂上去。
    ProcessInstanceLedger weakStart;
    ProcessInstanceId noCreateTime;
    noCreateTime.bootId = kBoot1;
    noCreateTime.pid = OptionalU64::of(1500ULL);
    s.expect(weakStart.observeStart(noCreateTime, 100U),
             L"T-05 an instance with no create time can be registered");
    s.expect(!weakStart.observeExit(MakeProcessId(1500U, 100U, "x.exe"), 200U),
             L"T-05 an exit carrying a createTime is refused when the registered instance has none to compare");
    s.expect(weakStart.weakExitMatchCount() == 0U,
             L"T-05 a refused exit is not booked as a weak match");
    s.expect(weakStart.observeExit(noCreateTime, 200U),
             L"T-05 an exit with no createTime falls back to the start-time heuristic");
    s.expect(weakStart.weakExitMatchCount() == 1U,
             L"T-05 the start-time fallback is counted as a weak exit match instead of passing as certain");

    // 同 PID、同开始时间、不同 createTime：两个实例，不能被后来的登记覆盖成一个。
    ProcessInstanceLedger sameStart;
    sameStart.observeStart(MakeProcessId(1600U, 10U, "p.exe"), 50U);
    sameStart.observeStart(MakeProcessId(1600U, 20U, "q.exe"), 50U);
    s.expect(sameStart.instanceCount() == 2U,
             L"T-05 two different createTimes at the same start time are two instances, not one overwritten record");

    // -----------------------------------------------------------------------
    // T-05 Ambiguous：两个同 PID 实例窗口重叠（都缺结束事件）。
    // -----------------------------------------------------------------------
    ProcessInstanceLedger overlap;
    overlap.observeStart(MakeProcessId(50U, 100U, "o1.exe"), 100U);
    overlap.observeStart(MakeProcessId(50U, 150U, "o2.exe"), 150U);
    const AttributionDecision ambiguous =
        overlap.attribute(kBoot1, OptionalU64::of(50ULL),
                          MakeTime(kBoot1, 200U, 200U, TimeResolution::HundredNanosecond));
    s.expect(ambiguous.kind == AttributionKind::Ambiguous,
             L"T-05 two overlapping same-PID windows are reported Ambiguous, never silently picked");
    s.expect(ambiguous.reasonKey == "timeline.attribution.overlapping-instances",
             L"T-05 the ambiguous attribution names its reason");
    s.expect(!ambiguous.provisionalId.empty(),
             L"T-05 the ambiguous event still gets a stable provisional entity id");
    s.expect(ambiguous.identityStrength == IdentityStrength::Unusable &&
                 ambiguous.identityMatch == MatchResult::Candidate,
             L"T-05 an ambiguous attribution never claims a Confirmed identity match");
    s.expect(!ambiguous.instance.pid.present,
             L"T-05 an ambiguous attribution carries no bound instance at all");

    TimelineSession ambiguousSession(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    ambiguousSession.apply(SessionAction::Start);
    ambiguousSession.processes().observeStart(MakeProcessId(50U, kT0 + 100ULL, "o1.exe"), kT0 + 100ULL);
    ambiguousSession.processes().observeStart(MakeProcessId(50U, kT0 + 150ULL, "o2.exe"), kT0 + 150ULL);
    ambiguousSession.ingest(MakeEvent("amb1", "P", TimelineEventCategory::Process, 50U,
                                      MakeTime(kBoot1, kT0 + 200ULL, kT0 + 200ULL,
                                               TimeResolution::Microsecond)));
    const TimelineEvent& ambiguousEvent = ElementOrDefault(ambiguousSession.events(), 0);
    s.expect(ambiguousEvent.attribution == AttributionKind::Ambiguous,
             L"T-05 the session marks the overlapping-instance event Ambiguous");
    s.expect(ambiguousEvent.processInstanceKey.empty(),
             L"T-05 an ambiguous event carries NO cross-session instance key");
    s.expect(!ambiguousEvent.provisionalProcessId.empty(),
             L"T-05 an ambiguous event carries a provisional id instead");

    // -----------------------------------------------------------------------
    // T-05 临时实体 id 不能靠裸拼接：空 bootId 与字面量 boot-unknown 曾经撞成一个实体。
    // -----------------------------------------------------------------------
    s.expect(MakeProvisionalEntityId(std::string(), OptionalU64::of(7ULL),
                                     AttributionKind::Provisional) !=
                 MakeProvisionalEntityId(std::string("boot-unknown"), OptionalU64::of(7ULL),
                                         AttributionKind::Provisional),
             L"T-05 an absent boot id and a boot cycle literally named boot-unknown encode to different ids");
    ProcessInstanceLedger collide;
    EventTimeStamp missingBoot;
    missingBoot.sourceTime100ns = OptionalU64::of(100ULL);
    missingBoot.sourceResolution = TimeResolution::HundredNanosecond;
    const AttributionDecision absentBoot =
        collide.attribute(std::string(), OptionalU64::of(7ULL), missingBoot);
    const AttributionDecision namedBoot =
        collide.attribute(std::string("boot-unknown"), OptionalU64::of(7ULL),
                          MakeTime("boot-unknown", 900U, 900U, TimeResolution::HundredNanosecond));
    s.expect(absentBoot.provisionalId != namedBoot.provisionalId,
             L"T-05 the two events do not share one provisional id");
    s.expect(collide.provisionals().size() == 2U,
             L"T-05 they stay two provisional entities instead of merging into one (hand-count: 2)");
    const ProvisionalProcessEntity* absentEntity = collide.findProvisional(absentBoot.provisionalId);
    const ProvisionalProcessEntity* namedEntity = collide.findProvisional(namedBoot.provisionalId);
    s.expect(absentEntity != nullptr && absentEntity->eventCount == 1U && absentEntity->bootId.empty(),
             L"T-05 the boot-less entity keeps exactly its own one event and an empty boot id");
    s.expect(namedEntity != nullptr && namedEntity->eventCount == 1U &&
                 namedEntity->bootId == "boot-unknown",
             L"T-05 the named boot cycle is not folded into an entity whose recorded boot id is empty");
    s.expect(absentEntity != nullptr && absentEntity->firstSeenTime100ns.present &&
                 absentEntity->firstSeenTime100ns.value == 100ULL &&
                 absentEntity->lastSeenTime100ns.value == 100ULL,
             L"T-05 the boot-less entity first/last seen stay at 100, not stretched to 900 by the other event");
}

// ---------------------------------------------------------------------------
// T-06 丢失账目
// ---------------------------------------------------------------------------
void TestLossAccounting(KswordTests::Suite& s) {
    LossLedger fresh;
    s.expect(fresh.anyUnknown(),
             L"T-06 an untouched ledger is unknown, not a clean zero");
    s.expect(!fresh.totalLost().present,
             L"T-06 an untouched ledger refuses to report a total");
    s.expect(!fresh.counter(LossCategory::SourceDrop).count.present,
             L"T-06 an untouched category has no count at all");

    LossLedger ledger;
    s.expect(!ledger.declareSource(LossCategory::SourceDrop, "", true, false),
             L"T-06 an empty statistic source is refused");
    s.expect(ledger.declareSource(LossCategory::SourceDrop, "etw.EventsLost", true, false),
             L"T-06 an authoritative source can be declared");
    s.expect(!ledger.counter(LossCategory::SourceDrop).count.present,
             L"T-06 an authoritative category stays unknown until the source reports");
    s.expect(!ledger.declareSource(LossCategory::SourceDrop, "other.counter", true, false),
             L"T-06 a category cannot switch to a second statistic source");
    s.expect(ledger.counter(LossCategory::SourceDrop).statisticSource == "etw.EventsLost",
             L"T-06 the rejected re-declaration leaves the original source intact");

    s.expect(!ledger.addObserved(LossCategory::SourceDrop, 1ULL),
             L"T-06 local increments on an authoritative category would double count");
    s.expect(ledger.setAbsolute(LossCategory::SourceDrop, 5ULL),
             L"T-06 the authoritative source sets an absolute count");
    s.expect(ledger.counter(LossCategory::SourceDrop).count.present &&
                 ledger.counter(LossCategory::SourceDrop).count.value == 5ULL,
             L"T-06 the absolute count is stored losslessly");

    s.expect(ledger.declareSource(LossCategory::QueueDiscard, "local.r3queue", false, false),
             L"T-06 a locally counted category can be declared");
    s.expect(ledger.counter(LossCategory::QueueDiscard).count.present &&
                 ledger.counter(LossCategory::QueueDiscard).count.value == 0ULL,
             L"T-06 a local category starts at an explained zero");
    s.expect(!ledger.setAbsolute(LossCategory::QueueDiscard, 9ULL),
             L"T-06 a local category refuses an absolute overwrite");
    s.expect(ledger.addObserved(LossCategory::QueueDiscard, 3ULL) &&
                 ledger.counter(LossCategory::QueueDiscard).count.value == 3ULL,
             L"T-06 local increments accumulate");

    s.expect(!ledger.setInterval(LossCategory::SourceDrop, 10ULL, 20ULL),
             L"T-06 a total-only source cannot be given a fabricated loss interval");
    s.expect(!ledger.counter(LossCategory::SourceDrop).intervalBegin100ns.present,
             L"T-06 the refused interval leaves no residue");
    s.expect(ledger.declareSource(LossCategory::RingOverwrite, "ring.OverwriteCount", true, true),
             L"T-06 a source that does provide intervals declares it");
    s.expect(ledger.setInterval(LossCategory::RingOverwrite, 10ULL, 20ULL),
             L"T-06 an interval-capable source may record the interval");
    s.expect(!ledger.setInterval(LossCategory::RingOverwrite, 30ULL, 20ULL),
             L"T-06 a reversed interval is refused");

    s.expect(ledger.anyUnknown(),
             L"T-06 the ledger is still unknown while RingOverwrite has no count");
    s.expect(!ledger.totalLost().present,
             L"T-06 an unknown category poisons the total instead of counting as zero");
    ledger.setAbsolute(LossCategory::RingOverwrite, 7ULL);
    ledger.declareSource(LossCategory::ParseFailure, "local.parser", false, false);
    ledger.declareSource(LossCategory::FilteredOut, "local.collectionFilter", false, false);
    ledger.declareSource(LossCategory::RetentionEvicted, "local.retention", false, false);
    s.expect(!ledger.anyUnknown(), L"T-06 all six categories now have named sources and counts");
    const OptionalU64 total = ledger.totalLost();
    // 手算：5 (SourceDrop) + 7 (RingOverwrite) + 3 (QueueDiscard) + 0 + 0 + 0 = 15
    s.expect(total.present && total.value == 15ULL, L"T-06 the total is 5+7+3 = 15");
    const std::vector<std::string> keys = ledger.limitationKeys();
    s.expect(ContainsKey(keys, "timeline.loss.total-only.SourceDrop"),
             L"T-06 a total-only positive count is reported as total-only");
    s.expect(!ContainsKey(keys, "timeline.loss.total-only.RingOverwrite"),
             L"T-06 an interval-capable source is not marked total-only");

    LossLedger clean;
    DeclareAllLossSources(clean);
    s.expect(!clean.anyUnknown() && clean.totalLost().present && clean.totalLost().value == 0ULL,
             L"T-06 a fully sourced ledger can report a real zero");
    s.expect(ContainsKey(clean.limitationKeys(), "timeline.loss.none-all-categories-sourced"),
             L"T-06 the zero case is a positive statement, not an empty default");
    LossLedger partial;
    partial.declareSource(LossCategory::SourceDrop, "etw.EventsLost", true, false);
    s.expect(ContainsKey(partial.limitationKeys(), "timeline.loss.no-source.QueueDiscard"),
             L"T-06 a category with no source is named explicitly");
    s.expect(ContainsKey(partial.limitationKeys(), "timeline.loss.unknown-count.SourceDrop"),
             L"T-06 a declared but unreported category is named explicitly");

    // 强制队列溢出：上限 3 + StopOnLimit。
    TimelineSession stopping(MakeManifest(), MakeBounds(3ULL, RetentionPolicy::StopOnLimit));
    DeclareAllLossSources(stopping.loss());
    stopping.apply(SessionAction::Start);
    std::size_t accepted = 0;
    std::size_t rejected = 0;
    for (int i = 0; i < 5; ++i) {
        const std::string id = "q" + std::to_string(i);
        const IngestResult result = stopping.ingest(
            MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                      MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                               kT0, TimeResolution::Microsecond)));
        if (result.accepted) {
            ++accepted;
        } else {
            ++rejected;
        }
    }
    s.expect(accepted == 3U && rejected == 2U, L"T-08 StopOnLimit accepts 3 and refuses 2");
    s.expect(stopping.events().size() == 3U, L"T-08 the memory bound really is 3 events");
    s.expect(stopping.boundsState() == BoundsState::MemoryLimitReached,
             L"T-08 reaching the memory limit is marked, not silent");
    s.expect(stopping.loss().counter(LossCategory::QueueDiscard).count.value == 2ULL,
             L"T-06 the two refused events are counted as queue discards");
    s.expect(stopping.loss().counter(LossCategory::RetentionEvicted).count.value == 0ULL,
             L"T-06 StopOnLimit does not also count them as retention evictions");

    // 强制 ring 覆盖式淘汰：上限 3 + EvictOldest。
    TimelineSession evicting(MakeManifest(), MakeBounds(3ULL, RetentionPolicy::EvictOldest));
    DeclareAllLossSources(evicting.loss());
    evicting.apply(SessionAction::Start);
    for (int i = 0; i < 5; ++i) {
        const std::string id = "r" + std::to_string(i);
        evicting.ingest(MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                                  MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                           kT0, TimeResolution::Microsecond)));
    }
    s.expect(evicting.events().size() == 3U, L"T-08 EvictOldest keeps the window at 3 events");
    s.expect(ElementOrDefault(evicting.events(), 0).recordId == "r2",
             L"T-08 the two oldest records are the ones evicted");
    s.expect(evicting.loss().counter(LossCategory::RetentionEvicted).count.value == 2ULL,
             L"T-06 the evictions are counted under the retention category");
    s.expect(evicting.loss().counter(LossCategory::QueueDiscard).count.value == 0ULL,
             L"T-06 evictions are not double counted as queue discards");

    // 磁盘上限换算：100 字节 / 每条 40 字节 = 2 条。
    BoundsPolicy diskBounds;
    diskBounds.maxArchiveBytes = OptionalU64::of(100ULL);
    diskBounds.approximateBytesPerEvent = OptionalU64::of(40ULL);
    diskBounds.policy = RetentionPolicy::StopOnLimit;
    diskBounds.declaredBeforeCollection = true;
    TimelineSession disk(MakeManifest(), diskBounds);
    DeclareAllLossSources(disk.loss());
    disk.apply(SessionAction::Start);
    for (int i = 0; i < 4; ++i) {
        const std::string id = "d" + std::to_string(i);
        disk.ingest(MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                              MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                       kT0, TimeResolution::Microsecond)));
    }
    s.expect(disk.events().size() == 2U, L"T-08 100 bytes at 40 bytes per event bounds at 2");
    s.expect(disk.boundsState() == BoundsState::ArchiveLimitReached,
             L"T-08 the archive limit is reported separately from the memory limit");

    BoundsPolicy zeroBounds = MakeBounds(0ULL, RetentionPolicy::EvictOldest);
    TimelineSession zero(MakeManifest(), zeroBounds);
    DeclareAllLossSources(zero.loss());
    zero.apply(SessionAction::Start);
    const IngestResult zeroResult =
        zero.ingest(MakeEvent("z0", "P", TimelineEventCategory::Process, 100U,
                              MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    s.expect(!zeroResult.accepted && zeroResult.reasonKey == "timeline.ingest.capacity-zero",
             L"T-08 a zero capacity refuses everything instead of looping");
    s.expect(zero.events().empty(), L"T-08 nothing is retained under a zero capacity");

    // 解析失败计入 ParseFailure，未知 schema 不计（原始记录完整保留）。
    TimelineSession parsing(MakeManifest(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(parsing.loss());
    parsing.apply(SessionAction::Start);
    TimelineEvent malformed = MakeEvent("m1", "P", TimelineEventCategory::Other, 100U,
                                        MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond));
    malformed.parseOutcome = EventParseOutcome::Malformed;
    parsing.ingest(malformed);
    TimelineEvent unparsed = MakeEvent("m2", "P", TimelineEventCategory::Other, 100U,
                                       MakeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::Microsecond));
    unparsed.parseOutcome = EventParseOutcome::UnparsedUnknownSchema;
    parsing.ingest(unparsed);
    s.expect(parsing.loss().counter(LossCategory::ParseFailure).count.value == 1ULL,
             L"T-06 only the malformed record counts as a parse failure");
    s.expect(parsing.events().size() == 2U,
             L"T-06 both records are still retained for later re-parsing");
}

// ---------------------------------------------------------------------------
// T-03 采集过滤与显示过滤分离
// ---------------------------------------------------------------------------
void TestFilterSeparation(KswordTests::Suite& s) {
    TimelineSession session(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(session.loss());
    session.apply(SessionAction::Start);
    const std::uint64_t pids[] = { 4100ULL, 4200ULL, 4100ULL, 4200ULL };
    for (int i = 0; i < 4; ++i) {
        const std::string id = "f" + std::to_string(i);
        session.ingest(MakeEvent(id.c_str(), "Kernel-File", TimelineEventCategory::File,
                                 pids[i],
                                 MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                          kT0, TimeResolution::Microsecond)));
    }
    s.expect(session.events().size() == 4U, L"T-03 all four events entered the session");

    EventFilter display;
    display.active = true;
    display.ruleId = "ui.only-4100";
    display.allowedPids.push_back(4100ULL);
    session.setDisplayFilter(display);
    s.expect(session.visibleEvents().size() == 2U, L"T-03 the display filter shows two events");
    s.expect(session.events().size() == 4U,
             L"T-03 the display filter does not remove anything from the session");

    const ExportPlan visible = session.buildExportPlan(ExportScope::VisibleOnly);
    s.expect(visible.exportedEventCount == 2U && visible.retainedEventCount == 4U,
             L"T-03 the visible export carries 2 of 4 retained events");
    s.expect(visible.hiddenByDisplayFilter == 2U,
             L"T-03 the visible export states how many events it hid");
    s.expect(!visible.representsRetainedSession,
             L"T-03 the visible export does not claim to be the whole session");
    s.expect(ContainsKey(visible.noticeKeys, "timeline.export.hidden-events-still-in-session"),
             L"T-03 the visible export says the hidden events still exist");

    const ExportPlan full = session.buildExportPlan(ExportScope::FullSession);
    s.expect(full.exportedEventCount == 4U && full.representsRetainedSession,
             L"T-03 the full export carries every retained event");
    s.expect(full.hiddenByDisplayFilter == 2U,
             L"T-03 the full export still reports what the UI is hiding");
    s.expect(ContainsKey(full.noticeKeys, "timeline.export.display-filter-not-applied"),
             L"T-03 the full export states that the display filter was not applied");
    s.expect(full.excludedByCollectionFilter == 0U,
             L"T-03 nothing was excluded at collection time in this run");
    // 新判据：除了"无过滤 / 无丢失 / 未到限"，还要求至少声明过一个 collector 能力
    // 且每一个都是 Success —— 这个 manifest 声明了一个 Success 的 etw.kernel。
    s.expect(full.retainedSessionIsCompleteCapture,
             L"T-03 no filter + no loss + no bound hit + one declared collector that succeeded = complete capture");
    s.expect(full.unavailableCollectorCount == 0U,
             L"T-03 the complete-capture session has zero unavailable declared collectors");

    // 反例：同样的数据，manifest 里一个 collector 能力都没声明 -> 不知道本该采到什么。
    TimelineSession undeclaredCollectors(MakeManifest(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(undeclaredCollectors.loss());
    undeclaredCollectors.apply(SessionAction::Start);
    undeclaredCollectors.ingest(MakeEvent("nc1", "Kernel-File", TimelineEventCategory::File, 4100U,
                                          MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    const ExportPlan undeclaredPlan =
        undeclaredCollectors.buildExportPlan(ExportScope::FullSession);
    s.expect(!undeclaredPlan.retainedSessionIsCompleteCapture,
             L"T-06 a session that declared no collector capability at all is never a complete capture");
    s.expect(ContainsKey(undeclaredPlan.noticeKeys,
                         "timeline.export.no-collector-capability-declared"),
             L"T-06 the export says why: nothing declared what was supposed to be collected");

    // 采集过滤：命中的事件从未进入会话，与显示过滤是两件事。
    TimelineSession collecting(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(collecting.loss());
    EventFilter collection;
    collection.active = true;
    collection.ruleId = "capture.only-4100";
    collection.allowedPids.push_back(4100ULL);
    collecting.setCollectionFilter(collection);
    collecting.apply(SessionAction::Start);
    std::size_t admitted = 0;
    for (int i = 0; i < 4; ++i) {
        const std::string id = "c" + std::to_string(i);
        const IngestResult result = collecting.ingest(
            MakeEvent(id.c_str(), "Kernel-File", TimelineEventCategory::File, pids[i],
                      MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                               kT0, TimeResolution::Microsecond)));
        if (result.accepted) {
            ++admitted;
        } else {
            s.expect(result.reasonKey == "timeline.ingest.excluded-by-collection-filter" &&
                         result.lossCategory == LossCategory::FilteredOut,
                     L"T-03 a collection-filtered event is accounted as FilteredOut");
        }
    }
    s.expect(admitted == 2U, L"T-03 the collection filter admitted exactly two events");
    s.expect(collecting.events().size() == 2U,
             L"T-03 collection-filtered events never entered the session");
    s.expect(collecting.loss().counter(LossCategory::FilteredOut).count.value == 2ULL,
             L"T-06 collection-filtered events are counted in their own category");
    const ExportPlan collectedFull = collecting.buildExportPlan(ExportScope::FullSession);
    s.expect(collectedFull.excludedByCollectionFilter == 2U,
             L"T-03 the full export reports what the collection filter removed");
    s.expect(!collectedFull.retainedSessionIsCompleteCapture,
             L"T-03 a collection-filtered session is never called a complete capture");
    s.expect(ContainsKey(collectedFull.noticeKeys, "timeline.export.collection-filter-applied"),
             L"T-03 the full export names the collection filter");

    // 过滤器语义本身。
    TimelineEvent probe = MakeEvent("probe", "Kernel-File", TimelineEventCategory::File, 4100U,
                                    MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond));
    EventFilter inactive;
    s.expect(FilterAdmits(inactive, probe), L"T-03 an inactive filter admits everything");
    EventFilter byCategory;
    byCategory.active = true;
    byCategory.allowedCategories.push_back(TimelineEventCategory::Registry);
    s.expect(!FilterAdmits(byCategory, probe), L"T-03 a category filter rejects other categories");
    EventFilter byProvider;
    byProvider.active = true;
    byProvider.allowedProviderIds.push_back("Kernel-File");
    s.expect(FilterAdmits(byProvider, probe), L"T-03 a provider filter admits its provider");
    TimelineEvent noPid = probe;
    noPid.pid = OptionalU64::unset();
    EventFilter byPid;
    byPid.active = true;
    byPid.allowedPids.push_back(4100ULL);
    s.expect(!FilterAdmits(byPid, noPid),
             L"T-03 an event with an unknown PID is not silently admitted by a PID filter");
}

// ---------------------------------------------------------------------------
// T-09 / T-10 保存与恢复
// ---------------------------------------------------------------------------
TimelineSession BuildPersistenceSession() {
    SessionManifest manifest = MakeManifest();
    CollectorCapability etw;
    etw.collectorId = "etw.kernel";
    etw.collectorVersion = 3U;
    etw.sourceGroup = "etw.kernel";
    etw.origin = SourceOrigin::LiveKernel;
    etw.declaredCategories.push_back(TimelineEventCategory::Process);
    etw.declaredCategories.push_back(TimelineEventCategory::File);
    etw.availability = CollectionOutcome::success();
    manifest.capabilities.push_back(etw);
    CollectorCapability ring;
    ring.collectorId = "r0.callback.ring";
    ring.collectorVersion = 2U;
    ring.sourceGroup = "r0.callback.ring";
    ring.origin = SourceOrigin::LiveKernel;
    ring.declaredCategories.push_back(TimelineEventCategory::Registry);
    ring.availability = CollectionOutcome::failure(CollectionStatus::AccessDenied, "NTSTATUS",
                                                   0xC0000022ULL, "STATUS_ACCESS_DENIED");
    manifest.capabilities.push_back(ring);

    TimelineSession session(manifest, MakeRoomyDeclaredBounds());
    DeclareAllLossSources(session.loss());
    session.loss().setAbsolute(LossCategory::RingOverwrite, 7ULL);
    session.loss().setAbsolute(LossCategory::SourceDrop, 2ULL);
    session.processes().observeStart(MakeProcessId(7000U, kT0 + 5ULL, "target.exe"), kT0 + 5ULL);
    session.apply(SessionAction::Start);

    const TimelineEventCategory kCategories[] = {
        TimelineEventCategory::Process, TimelineEventCategory::Thread,
        TimelineEventCategory::Image,   TimelineEventCategory::File,
        TimelineEventCategory::Registry, TimelineEventCategory::Network,
    };
    for (int i = 0; i < 6; ++i) {
        const std::string id = "s" + std::to_string(i);
        TimelineEvent event = MakeEvent(id.c_str(), "Kernel-Sample", kCategories[i], 7000U,
                                        MakeTime(kBoot1,
                                                 kT0 + 100ULL + static_cast<std::uint64_t>(i) * 10000ULL,
                                                 kT0 + 200ULL, TimeResolution::Microsecond));
        event.rawFields.clear();
        event.rawFields.emplace_back("Payload", "payload-" + std::to_string(i));
        event.eventId = static_cast<std::uint32_t>(i + 1);
        if (i == 0) {
            event.sourceLinkId = "activity-A";
            event.sourceLinkField = "ActivityId";
        }
        session.ingest(event);
    }
    TimelineEvent unknownSchema =
        MakeEvent("s6", "Third-Party", TimelineEventCategory::Other, 7000U,
                  MakeTime(kBoot1, kT0 + 100ULL + 60000ULL, kT0 + 200ULL, TimeResolution::Microsecond));
    unknownSchema.rawFields.clear();
    unknownSchema.rawFields.emplace_back("Payload", "payload-6");
    unknownSchema.eventVersion = 9U;
    unknownSchema.parseOutcome = EventParseOutcome::UnparsedUnknownSchema;
    unknownSchema.parserId.clear();
    unknownSchema.parserVersion = 0U;
    unknownSchema.rawPayloadHex = "CAFEBABE";
    session.ingest(unknownSchema);
    session.apply(SessionAction::StopCollection);
    return session;
}

void TestPersistence(KswordTests::Suite& s) {
    const TimelineSession original = BuildPersistenceSession();
    s.expect(original.events().size() == 7U, L"T-09 the sample session holds seven events");

    const std::string text = SerializeSession(original, 2U);
    const std::vector<std::string> lines = SplitTextLines(text);
    // 手算：1 行 header + ceil(7/2)=4 个批次 + 1 行 trailer = 6 行。
    s.expect(lines.size() == 6U, L"T-09 the file is header + 4 batches + trailer");

    const SessionLoadResult loaded = LoadSession(text);
    s.expect(loaded.status == SessionLoadStatus::Ok, L"T-09 a complete file loads cleanly");
    s.expect(loaded.recoveredEventCount == 7U && loaded.committedBatchCount == 4U,
             L"T-09 all seven events across four committed batches are recovered");
    s.expect(loaded.uncommittedEventCount == 0U, L"T-09 nothing is left uncommitted");
    s.expect(loaded.fileFormatVersion == 1U, L"T-09 the file declares format version 1");

    // 统计一致：期望值是测试里手写的 7 / 2 / "ring.OverwriteCount"。
    s.expect(loaded.session.loss().counter(LossCategory::RingOverwrite).count.present &&
                 loaded.session.loss().counter(LossCategory::RingOverwrite).count.value == 7ULL,
             L"T-09 the ring overwrite count survives the round trip");
    s.expect(loaded.session.loss().counter(LossCategory::RingOverwrite).statisticSource ==
                 "ring.OverwriteCount",
             L"T-09 the statistic source name survives the round trip");
    s.expect(loaded.session.loss().counter(LossCategory::SourceDrop).count.value == 2ULL,
             L"T-09 the source drop count survives the round trip");
    s.expect(loaded.session.loss().totalLost().present &&
                 loaded.session.loss().totalLost().value == 9ULL,
             L"T-09 the restored total is 7+2 = 9");

    // 抽样一致：第 4 条（索引 3）是 File 类，payload-3。
    s.expect(loaded.session.events().size() == 7U, L"T-09 seven events are in the reopened session");
    const TimelineEvent& sample = ElementOrDefault(loaded.session.events(), 3);
    s.expect(sample.recordId == "s3" && sample.category == TimelineEventCategory::File,
             L"T-09 the sampled event keeps its id and category");
    s.expect(sample.rawFields.size() == 1U && sample.rawFields[0].first == "Payload" &&
                 sample.rawFields[0].second == "payload-3",
             L"T-09 the sampled event keeps its raw field");
    s.expect(sample.time.sourceTime100ns.present &&
                 sample.time.sourceTime100ns.value == kT0 + 100ULL + 30000ULL,
             L"T-09 the sampled source time is byte-identical after reopening");
    s.expect(sample.arrivalSequence == 4U, L"T-09 the arrival sequence survives");
    const TimelineEvent& unparsed = ElementOrDefault(loaded.session.events(), 6);
    s.expect(unparsed.parseOutcome == EventParseOutcome::UnparsedUnknownSchema &&
                 unparsed.parserVersion == 0U && unparsed.eventVersion == 9U,
             L"T-09 the unparsed record reopens as an unparsed record with its own version");
    s.expect(unparsed.rawPayloadHex == "CAFEBABE",
             L"T-09 the unparsed record keeps its raw payload");
    s.expect(loaded.session.manifest().capabilities.size() == 2U,
             L"T-09 the collector capabilities are stored with the session");
    s.expect(ElementOrDefault(loaded.session.manifest().capabilities, 1).availability.status ==
                 CollectionStatus::AccessDenied,
             L"T-09 an unavailable collector keeps its failure status");
    s.expect(ElementOrDefault(loaded.session.manifest().capabilities, 1).availability.nativeCode.present &&
                 ElementOrDefault(loaded.session.manifest().capabilities, 1).availability.nativeCode.value ==
                     0xC0000022ULL,
             L"T-09 the native error code is preserved, not flattened");
    s.expect(loaded.session.manifest().queryRangeBegin100ns.present &&
                 loaded.session.manifest().queryRangeBegin100ns.value == kT0,
             L"T-09 the query range is stored with the session");
    s.expect(loaded.session.state() == SessionState::Saved,
             L"T-09 a reopened session is read-only, never Collecting");
    s.expect(!SessionAcceptsNewEvents(loaded.session.state()),
             L"T-09 reopening offline cannot start recording anything");

    // 截断尾部：只承诺已提交批次。手算：保留 header + batch0 + batch1 = 4 条事件。
    std::string truncated = ElementOrDefault(lines, 0) + ElementOrDefault(lines, 1) + ElementOrDefault(lines, 2) + ElementOrDefault(lines, 3).substr(0, 25U);
    const SessionLoadResult truncatedResult = LoadSession(truncated);
    s.expect(truncatedResult.status == SessionLoadStatus::IncompleteTail,
             L"T-10 a truncated tail is IncompleteTail, not Corrupt");
    s.expect(truncatedResult.recoveredEventCount == 4U,
             L"T-10 the two complete batches before the cut are still recovered");
    s.expect(truncatedResult.committedBatchCount == 2U,
             L"T-10 exactly two committed batches are reported");
    s.expect(truncatedResult.diagnosticKey == "timeline.load.unterminated-final-line",
             L"T-10 the truncation diagnostic is specific");
    s.expect(truncated.size() == ElementOrDefault(lines, 0).size() + ElementOrDefault(lines, 1).size() + ElementOrDefault(lines, 2).size() + 25U,
             L"T-10 loading does not modify the source text");

    // 缺 trailer：批次齐全但会话没有正常收尾。
    const std::string noTrailer = ElementOrDefault(lines, 0) + ElementOrDefault(lines, 1) + ElementOrDefault(lines, 2) + ElementOrDefault(lines, 3) + ElementOrDefault(lines, 4);
    const SessionLoadResult noTrailerResult = LoadSession(noTrailer);
    s.expect(noTrailerResult.status == SessionLoadStatus::IncompleteTail &&
                 noTrailerResult.diagnosticKey == "timeline.load.missing-trailer",
             L"T-10 a missing trailer is reported as an incomplete tail");
    s.expect(noTrailerResult.recoveredEventCount == 7U,
             L"T-10 every committed batch is still recovered without a trailer");

    // 损坏的第一个批次：校验不符，之前没有可恢复的批次。
    std::string corruptFirst = text;
    const std::size_t firstPayload = corruptFirst.find("payload-0");
    s.expect(firstPayload != std::string::npos, L"T-10 the corruption target exists");
    if (firstPayload != std::string::npos) {
        corruptFirst.replace(firstPayload, 9U, "payload-Z");
    }
    const SessionLoadResult corruptFirstResult = LoadSession(corruptFirst);
    s.expect(corruptFirstResult.status == SessionLoadStatus::Corrupt &&
                 corruptFirstResult.diagnosticKey == "timeline.load.batch-checksum-mismatch",
             L"T-10 a silently altered batch is detected as corrupt");
    s.expect(corruptFirstResult.recoveredEventCount == 0U,
             L"T-10 nothing is recovered when the first batch is the corrupt one");

    // 损坏第二个批次：第一个批次仍然可恢复。
    std::string corruptSecond = text;
    const std::size_t secondPayload = corruptSecond.find("payload-2");
    if (secondPayload != std::string::npos) {
        corruptSecond.replace(secondPayload, 9U, "payload-Y");
    }
    const SessionLoadResult corruptSecondResult = LoadSession(corruptSecond);
    s.expect(corruptSecondResult.status == SessionLoadStatus::Corrupt,
             L"T-10 corruption in a later batch is still corrupt");
    s.expect(corruptSecondResult.recoveredEventCount == 2U &&
                 corruptSecondResult.committedBatchCount == 1U,
             L"T-10 the committed batch before the corruption is preserved");
    s.expect(corruptSecondResult.failedLineIndex == 2U,
             L"T-10 the failing line is identified");

    // 版本过新：独立状态，不猜着读，也不改文件。
    std::string tooNew = text;
    const std::size_t versionPos = tooNew.find("\"formatVersion\":1");
    s.expect(versionPos != std::string::npos, L"T-10 the format version field is present");
    if (versionPos != std::string::npos) {
        tooNew.replace(versionPos, 17U, "\"formatVersion\":9");
    }
    const std::string tooNewCopy = tooNew;
    const SessionLoadResult tooNewResult = LoadSession(tooNew);
    s.expect(tooNewResult.status == SessionLoadStatus::VersionTooNew,
             L"T-10 a newer format version has its own status");
    s.expect(tooNewResult.fileFormatVersion == 9U,
             L"T-10 the newer version number is reported back");
    s.expect(tooNewResult.recoveredEventCount == 0U,
             L"T-10 nothing is guessed out of a newer format");
    s.expect(tooNew == tooNewCopy, L"T-10 the source text is untouched by the failed load");

    // 坏 header 与空输入。
    const SessionLoadResult garbage = LoadSession("this is not json\n");
    s.expect(garbage.status == SessionLoadStatus::MissingHeader,
             L"T-10 a garbage first line is a missing header");
    s.expect(LoadSession("").status == SessionLoadStatus::Empty,
             L"T-10 an empty file is Empty, not Corrupt");
    const SessionLoadResult wrongKind = LoadSession("{\"kind\":\"something.else\"}\n");
    s.expect(wrongKind.status == SessionLoadStatus::MissingHeader &&
                 wrongKind.diagnosticKey == "timeline.load.header-kind-mismatch",
             L"T-10 a foreign JSON document is rejected by kind");

    // trailer 条数对不上。
    std::string mismatched = text;
    const std::size_t countPos = mismatched.find("\"eventCount\":\"7\"");
    s.expect(countPos != std::string::npos, L"T-10 the trailer event count is present");
    if (countPos != std::string::npos) {
        mismatched.replace(countPos, 16U, "\"eventCount\":\"9\"");
    }
    const SessionLoadResult mismatchResult = LoadSession(mismatched);
    s.expect(mismatchResult.status == SessionLoadStatus::TrailerMismatch,
             L"T-10 a trailer that disagrees with the data is its own status");
    s.expect(mismatchResult.recoveredEventCount == 7U,
             L"T-10 the recovered events are still reported on a trailer mismatch");

    // 未提交的尾部批次：不恢复，但要报出条数。
    TimelineSession mini(MakeManifest(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(mini.loss());
    mini.apply(SessionAction::Start);
    mini.ingest(MakeEvent("u0", "P", TimelineEventCategory::Process, 100U,
                          MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    mini.ingest(MakeEvent("u1", "P", TimelineEventCategory::Process, 100U,
                          MakeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::Microsecond)));
    mini.apply(SessionAction::StopCollection);
    SessionBatch committedBatch;
    committedBatch.batchIndex = 0U;
    committedBatch.committed = true;
    committedBatch.events.assign(mini.events().begin(), mini.events().end());
    SessionBatch pendingBatch;
    pendingBatch.batchIndex = 1U;
    pendingBatch.committed = false;
    pendingBatch.events.push_back(MakeEvent("u2", "P", TimelineEventCategory::Process, 100U,
                                            MakeTime(kBoot1, kT0 + 20000ULL, kT0,
                                                     TimeResolution::Microsecond)));
    pendingBatch.events.push_back(MakeEvent("u3", "P", TimelineEventCategory::Process, 100U,
                                            MakeTime(kBoot1, kT0 + 30000ULL, kT0,
                                                     TimeResolution::Microsecond)));
    const std::string pendingText = SerializeSessionHeaderLine(mini) +
                                    SerializeBatchLine(committedBatch) +
                                    SerializeBatchLine(pendingBatch) + SerializeTrailerLine(mini, 1U);
    const SessionLoadResult pendingResult = LoadSession(pendingText);
    s.expect(pendingResult.status == SessionLoadStatus::IncompleteTail &&
                 pendingResult.diagnosticKey == "timeline.load.uncommitted-batch-present",
             L"T-10 an uncommitted batch keeps the load from claiming a clean file");
    s.expect(pendingResult.recoveredEventCount == 2U,
             L"T-10 only the committed batch is recovered");
    s.expect(pendingResult.uncommittedEventCount == 2U,
             L"T-10 the uncommitted events are reported as missing, not as recovered");
}

// ---------------------------------------------------------------------------
// T-12 关系不冒充因果
// ---------------------------------------------------------------------------
void TestRelationEdges(KswordTests::Suite& s) {
    s.expect(EdgeKindAllowsCausalWording(TimelineEdgeKind::SourceProvidedLink),
             L"T-12 only a source-provided link may carry causal wording");
    s.expect(!EdgeKindAllowsCausalWording(TimelineEdgeKind::TemporalNeighbor),
             L"T-12 temporal adjacency is never causal");
    s.expect(!EdgeKindAllowsCausalWording(TimelineEdgeKind::SameProcess),
             L"T-12 same-process is never causal");
    s.expect(!EdgeKindAllowsCausalWording(TimelineEdgeKind::ParentChild),
             L"T-12 parent-child is never causal");

    // 两个时间接近但完全无关的事件：不同进程实例、无来源关联。
    TimelineEvent left = MakeEvent("x1", "Kernel-Process", TimelineEventCategory::Process, 9100U,
                                   MakeTime(kBoot1, kT0 + 1000ULL, kT0, TimeResolution::Microsecond));
    left.processInstanceKey = "proc-instance-9100";
    left.arrivalSequence = 1U;
    TimelineEvent right = MakeEvent("x2", "Kernel-File", TimelineEventCategory::File, 9200U,
                                    MakeTime(kBoot1, kT0 + 1200ULL, kT0, TimeResolution::Microsecond));
    right.processInstanceKey = "proc-instance-9200";
    right.arrivalSequence = 2U;
    const std::vector<TimelineEvent> unrelated = { left, right };

    EdgeBuildOptions options;
    options.temporalNeighborWindow100ns = OptionalU64::of(5000ULL);
    const std::vector<TimelineEdge> edges = BuildEdges(unrelated, {}, options);
    s.expect(edges.size() == 1U, L"T-12 two unrelated neighbours produce exactly one edge");
    s.expect(CountEdges(edges, TimelineEdgeKind::TemporalNeighbor) == 1U,
             L"T-12 that edge is a temporal neighbour");
    s.expect(CountEdges(edges, TimelineEdgeKind::SameProcess) == 0U &&
                 CountEdges(edges, TimelineEdgeKind::ParentChild) == 0U &&
                 CountEdges(edges, TimelineEdgeKind::SourceProvidedLink) == 0U,
             L"T-12 no causal-capable edge is invented between unrelated events");
    s.expect(!edges.empty() && edges[0].basisKey == "timeline.edge.basis.adjacent-in-time-only",
             L"T-12 the basis of the edge says it is adjacency only");
    // 手算：1200 - 1000 = 200
    s.expect(!edges.empty() && edges[0].temporalGap100ns.present &&
                 edges[0].temporalGap100ns.value == 200ULL,
             L"T-12 the temporal gap is the hand-computed 200");
    s.expect(!edges.empty() && !EdgeKindAllowsCausalWording(edges[0].kind),
             L"T-12 the produced edge refuses causal wording");

    // 不给窗口就不产生"相邻"边。
    EdgeBuildOptions noWindow;
    const std::vector<TimelineEdge> noNeighbour = BuildEdges(unrelated, {}, noWindow);
    s.expect(CountEdges(noNeighbour, TimelineEdgeKind::TemporalNeighbor) == 0U,
             L"T-12 adjacency edges only exist when a window is requested");

    // 窗口之外就不算相邻。
    EdgeBuildOptions tinyWindow;
    tinyWindow.temporalNeighborWindow100ns = OptionalU64::of(100ULL);
    s.expect(CountEdges(BuildEdges(unrelated, {}, tinyWindow), TimelineEdgeKind::TemporalNeighbor) == 0U,
             L"T-12 a gap larger than the window produces no adjacency edge");

    // 同实例：建 SameProcess 边。
    TimelineEvent sameA = left;
    TimelineEvent sameB = right;
    sameB.processInstanceKey = "proc-instance-9100";
    const std::vector<TimelineEvent> sameProcess = { sameA, sameB };
    const std::vector<TimelineEdge> sameEdges = BuildEdges(sameProcess, {}, noWindow);
    s.expect(HasEdge(sameEdges, TimelineEdgeKind::SameProcess, "x1", "x2"),
             L"T-12 two events of the same confirmed instance are linked as SameProcess");
    s.expect(!sameEdges.empty() && sameEdges[0].basisDetail == "proc-instance-9100",
             L"T-12 the SameProcess basis names the instance key it used");

    // 反例：同 PID 但身份不完整（无实例主键）—— 绝不建边。
    TimelineEvent provisionalA = left;
    provisionalA.processInstanceKey.clear();
    provisionalA.provisionalProcessId = "prov:boot-T-1:pid=9100:Provisional";
    TimelineEvent provisionalB = right;
    provisionalB.pid = OptionalU64::of(9100ULL);
    provisionalB.processInstanceKey.clear();
    provisionalB.provisionalProcessId = "prov:boot-T-1:pid=9100:Provisional";
    const std::vector<TimelineEvent> provisionalPair = { provisionalA, provisionalB };
    s.expect(CountEdges(BuildEdges(provisionalPair, {}, noWindow), TimelineEdgeKind::SameProcess) == 0U,
             L"T-12 a bare PID never produces a SameProcess edge");

    // 来源直接提供的关联。
    TimelineEvent linkedA = left;
    linkedA.sourceLinkId = "activity-7";
    linkedA.sourceLinkField = "ActivityId";
    TimelineEvent linkedB = right;
    linkedB.sourceLinkId = "activity-7";
    linkedB.sourceLinkField = "ActivityId";
    const std::vector<TimelineEvent> linked = { linkedA, linkedB };
    const std::vector<TimelineEdge> linkedEdges = BuildEdges(linked, {}, noWindow);
    s.expect(HasEdge(linkedEdges, TimelineEdgeKind::SourceProvidedLink, "x1", "x2"),
             L"T-12 a shared source-provided link id builds a SourceProvidedLink edge");
    bool linkBasisOk = false;
    for (const TimelineEdge& edge : linkedEdges) {
        if (edge.kind == TimelineEdgeKind::SourceProvidedLink && edge.basisDetail == "ActivityId=activity-7") {
            linkBasisOk = true;
        }
    }
    s.expect(linkBasisOk, L"T-12 the source link edge names the field and value it came from");

    // 父子：来源提供的创建事实，且父实例必须在会话里有可点开的事件。
    TimelineEvent parentEvent = MakeEvent("pa", "Kernel-Process", TimelineEventCategory::Process,
                                          9000U,
                                          MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond));
    parentEvent.processInstanceKey = "proc-parent";
    TimelineEvent childEvent = MakeEvent("ch", "Kernel-Process", TimelineEventCategory::Process,
                                         9100U,
                                         MakeTime(kBoot1, kT0 + 500ULL, kT0,
                                                  TimeResolution::Microsecond));
    childEvent.processInstanceKey = "proc-child";
    ParentChildFact fact;
    fact.recordId = "ch";
    fact.childInstanceKey = "proc-child";
    fact.parentInstanceKey = "proc-parent";
    const std::vector<TimelineEvent> family = { parentEvent, childEvent };
    const std::vector<TimelineEdge> familyEdges = BuildEdges(family, { fact }, noWindow);
    s.expect(HasEdge(familyEdges, TimelineEdgeKind::ParentChild, "pa", "ch"),
             L"T-12 a source-provided creation fact builds a ParentChild edge");

    ParentChildFact orphanFact = fact;
    orphanFact.parentInstanceKey = "proc-missing";
    s.expect(CountEdges(BuildEdges(family, { orphanFact }, noWindow), TimelineEdgeKind::ParentChild) == 0U,
             L"T-12 a parent with no event in the session yields no unprovable edge");
}

// ---------------------------------------------------------------------------
// 会话 envelope（复用 F 层判据）
// ---------------------------------------------------------------------------
void TestSessionEnvelope(KswordTests::Suite& s) {
    TimelineSession fresh(MakeManifest(), MakeRoomyDeclaredBounds());
    const EvidenceEnvelope freshEnvelope = BuildSessionEnvelope(fresh);
    s.expect(freshEnvelope.outcome.status == CollectionStatus::NotCollected,
             L"T-06 a session that never ran is NotCollected, not an empty Success");
    s.expect(freshEnvelope.deriveConclusion(false) == AnalysisConclusion::NoEvidence,
             L"T-06 a session that never ran yields NoEvidence, not NoDifferenceObserved");

    TimelineSession unaccounted(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    unaccounted.apply(SessionAction::Start);
    unaccounted.ingest(MakeEvent("a1", "P", TimelineEventCategory::Process, 100U,
                                 MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    const EvidenceEnvelope unaccountedEnvelope = BuildSessionEnvelope(unaccounted);
    s.expect(unaccountedEnvelope.outcome.status == CollectionStatus::Partial,
             L"T-06 a session with an unfilled loss ledger is Partial, never Success");
    s.expect(unaccountedEnvelope.outcome.message == "loss accounting incomplete",
             L"T-06 the Partial names the loss ledger as the reason, not the collectors");
    s.expect(!unaccountedEnvelope.coverage.processedBegin.present,
             L"T-06 an unfilled ledger withholds the processed-range positive evidence");
    s.expect(!unaccountedEnvelope.coverage.fullyCovered(),
             L"T-06 an unfilled ledger is never full coverage");

    TimelineSession accounted(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(accounted.loss());
    accounted.apply(SessionAction::Start);
    accounted.ingest(MakeEvent("b1", "P", TimelineEventCategory::Process, 100U,
                               MakeTime(kBoot1, kT0 + 10ULL, kT0, TimeResolution::Microsecond)));
    accounted.ingest(MakeEvent("b2", "P", TimelineEventCategory::Process, 100U,
                               MakeTime(kBoot1, kT0 + 20000ULL, kT0, TimeResolution::Microsecond)));
    const EvidenceEnvelope accountedEnvelope = BuildSessionEnvelope(accounted);
    // 新判据：还要求 manifest 里每一个已声明的 collector 都是 Success。
    s.expect(accountedEnvelope.outcome.status == CollectionStatus::Success,
             L"T-06 fully accounted + unfiltered + within bounds + every declared collector Success = Success");
    s.expect(accountedEnvelope.coverage.processedBegin.present &&
                 accountedEnvelope.coverage.processedBegin.value == kT0 + 10ULL &&
                 accountedEnvelope.coverage.processedEnd.value == kT0 + 20000ULL,
             L"T-06 the processed range is the observed min and max effective time");
    s.expect(!accountedEnvelope.coverage.totalKnown.present,
             L"T-06 a timeline never claims to know how many events the system produced");
    s.expect(accountedEnvelope.coverage.succeeded == 2U,
             L"T-06 the coverage account carries the retained event count");
    s.expect(accountedEnvelope.source.origin == SourceOrigin::LiveUserMode,
             L"T-06 a live session is not labelled as an offline sample");
}


// ---------------------------------------------------------------------------
// T-06 collector 能力必须被读，不能只写不看
// ---------------------------------------------------------------------------
void TestCollectorAvailability(KswordTests::Suite& s) {
    // 声明两个 collector：一个 Error（本该供 File），一个 Unsupported（本该供 Registry）。
    // 两类事件因此一条都采不到 —— 那不是"系统里没发生过"，导出成完整采集就是把
    // 采集失败说成了正常。
    SessionManifest manifest = MakeManifest();
    CollectorCapability fileCollector;
    fileCollector.collectorId = "etw.file";
    fileCollector.collectorVersion = 1U;
    fileCollector.sourceGroup = "etw.file";
    fileCollector.origin = SourceOrigin::LiveKernel;
    fileCollector.declaredCategories.push_back(TimelineEventCategory::File);
    fileCollector.availability = CollectionOutcome::failure(CollectionStatus::Error, "WIN32", 5ULL,
                                                            "StartTrace failed");
    manifest.capabilities.push_back(fileCollector);
    CollectorCapability registryCollector;
    registryCollector.collectorId = "r0.registry";
    registryCollector.collectorVersion = 2U;
    registryCollector.sourceGroup = "r0.registry";
    registryCollector.origin = SourceOrigin::LiveKernel;
    registryCollector.declaredCategories.push_back(TimelineEventCategory::Registry);
    registryCollector.availability.status = CollectionStatus::Unsupported;
    manifest.capabilities.push_back(registryCollector);

    TimelineSession broken(manifest, MakeRoomyDeclaredBounds());
    DeclareAllLossSources(broken.loss());
    broken.apply(SessionAction::Start);
    broken.ingest(MakeEvent("cap1", "P", TimelineEventCategory::Process, 100U,
                            MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    s.expect(broken.events().size() == 1U && broken.loss().totalLost().present &&
                 broken.loss().totalLost().value == 0ULL,
             L"T-06 fixture: one event, zero accounted loss - only the collectors are broken");

    const ExportPlan brokenPlan = broken.buildExportPlan(ExportScope::FullSession);
    s.expect(!brokenPlan.retainedSessionIsCompleteCapture,
             L"T-06 a session whose declared File and Registry collectors never ran is NOT a complete capture");
    s.expect(brokenPlan.unavailableCollectorCount == 2U,
             L"T-06 both unavailable collectors are counted (hand-count: 2 of 2 declared)");
    s.expect(ContainsKey(brokenPlan.noticeKeys,
                         "timeline.export.collector-unavailable:etw.file:Error:File"),
             L"T-06 the notice names the collector, its status and the category it owed");
    s.expect(ContainsKey(brokenPlan.noticeKeys,
                         "timeline.export.collector-unavailable:r0.registry:Unsupported:Registry"),
             L"T-06 an unsupported collector gets its own notice with its own category");

    const EvidenceEnvelope brokenEnvelope = BuildSessionEnvelope(broken);
    s.expect(brokenEnvelope.outcome.status == CollectionStatus::Partial,
             L"T-06 an unavailable declared collector downgrades the envelope to Partial, never Success");
    s.expect(brokenEnvelope.outcome.nativeCodeDomain == "WIN32" &&
                 brokenEnvelope.outcome.nativeCode.present &&
                 brokenEnvelope.outcome.nativeCode.value == 5ULL,
             L"T-06 the failing collector native error domain and code reach the envelope outcome");
    s.expect(brokenEnvelope.outcome.message.find("StartTrace failed") != std::string::npos,
             L"T-06 the collector own failure message is carried, not replaced by a generic one");
    s.expect(brokenEnvelope.deriveConclusion(false) != AnalysisConclusion::NoDifferenceObserved ||
                 StatusCarriesObservation(brokenEnvelope.outcome.status),
             L"T-06 a Partial envelope still carries observation, so the conclusion path stays consistent");

    // 全部 Success 才可能算完整采集 —— 证明新判据不是"永远判 false"。
    TimelineSession healthy(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(healthy.loss());
    healthy.apply(SessionAction::Start);
    healthy.ingest(MakeEvent("cap2", "P", TimelineEventCategory::Process, 100U,
                             MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    s.expect(healthy.buildExportPlan(ExportScope::FullSession).retainedSessionIsCompleteCapture,
             L"T-06 a session whose only declared collector succeeded can still be a complete capture");
    s.expect(BuildSessionEnvelope(healthy).outcome.status == CollectionStatus::Success,
             L"T-06 an all-Success capability set does not block Success");

    // T-06 覆盖账目：采集过滤排除的条数不能被写成 0。
    // 手写数据：12 条事件，pid 4100 的 5 条准入，pid 4200 的 7 条被采集过滤排除。
    TimelineSession filtered(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(filtered.loss());
    EventFilter onlyOne;
    onlyOne.active = true;
    onlyOne.ruleId = "capture.only-4100";
    onlyOne.allowedPids.push_back(4100ULL);
    filtered.setCollectionFilter(onlyOne);
    filtered.apply(SessionAction::Start);
    for (int i = 0; i < 12; ++i) {
        const std::string id = "cv" + std::to_string(i);
        filtered.ingest(MakeEvent(id.c_str(), "Kernel-File", TimelineEventCategory::File,
                                  i < 5 ? 4100ULL : 4200ULL,
                                  MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                           kT0, TimeResolution::Microsecond)));
    }
    s.expect(filtered.events().size() == 5U && filtered.collectionFilteredOutCount() == 7U,
             L"T-03 fixture: 5 admitted, 7 excluded by the collection filter (hand-count)");
    const EvidenceEnvelope filteredEnvelope = BuildSessionEnvelope(filtered);
    s.expect(filteredEnvelope.coverage.skipped == 7U,
             L"T-06 coverage.skipped carries the 7 collection-filtered events, not a flattened 0");
    s.expect(filteredEnvelope.coverage.succeeded == 5U,
             L"T-06 coverage.succeeded carries the 5 retained events");
    s.expect(filteredEnvelope.outcome.status == CollectionStatus::Partial,
             L"T-06 a collection-filtered session is Partial");
}

// ---------------------------------------------------------------------------
// T-06 会话自己声明自己产生的四类丢失来源
// ---------------------------------------------------------------------------
void TestSelfDeclaredLossSources(KswordTests::Suite& s) {
    // 这里**故意不调用** DeclareAllLossSources：以前这条路径上被淘汰的事件计数
    // 根本不存在（count 未设置、statisticSource 是空串），丢掉的条数无处可查。
    TimelineSession session(MakeManifestWithHealthyCollector(),
                            MakeBounds(3ULL, RetentionPolicy::EvictOldest));
    session.apply(SessionAction::Start);
    for (int i = 0; i < 10; ++i) {
        const std::string id = "sd" + std::to_string(i);
        session.ingest(MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                                 MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                          kT0, TimeResolution::Microsecond)));
    }
    s.expect(session.events().size() == 3U, L"T-08 the eviction window holds 3 events (hand-count)");
    const LossCounter& evicted = session.loss().counter(LossCategory::RetentionEvicted);
    s.expect(evicted.count.present && evicted.count.value == 7ULL,
             L"T-06 10 ingested minus 3 retained = 7 evictions are counted with no caller-side declareSource");
    s.expect(evicted.statisticSource == "local.retention" && !evicted.sourceIsAuthoritative,
             L"T-06 the session names the statistic source of its own retention losses");
    s.expect(session.loss().counter(LossCategory::QueueDiscard).count.present &&
                 session.loss().counter(LossCategory::ParseFailure).count.present &&
                 session.loss().counter(LossCategory::FilteredOut).count.present,
             L"T-06 all four locally generated categories start at an explained zero");
    s.expect(!session.loss().counter(LossCategory::SourceDrop).count.present &&
                 session.loss().counter(LossCategory::SourceDrop).statisticSource.empty(),
             L"T-06 the session does not fake a source for the two counters only the collector can report");

    // Reset 之后本地四类仍然必须有具名来源，不能被 LossLedger() 一把清空。
    session.apply(SessionAction::StopCollection);
    session.apply(SessionAction::Reset);
    const LossCounter& afterReset = session.loss().counter(LossCategory::RetentionEvicted);
    s.expect(afterReset.statisticSource == "local.retention" && afterReset.count.present &&
                 afterReset.count.value == 0ULL,
             L"T-06 Reset restores the explained zero instead of wiping the local sources");

    // 记不进账目就是硬错误：该类被打成未知，总数随之 unset，绝不静默丢掉这一笔。
    TimelineSession unbookable(MakeManifestWithHealthyCollector(),
                               MakeBounds(1ULL, RetentionPolicy::EvictOldest));
    DeclareAllLossSources(unbookable.loss());
    // 把本地口径强行改成"来源权威"，addObserved 从此被拒绝（模拟外部改写记账口径）。
    unbookable.loss().mutableCounter(LossCategory::RetentionEvicted).sourceIsAuthoritative = true;
    unbookable.apply(SessionAction::Start);
    for (int i = 0; i < 3; ++i) {
        const std::string id = "ub" + std::to_string(i);
        unbookable.ingest(MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                                    MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                             kT0, TimeResolution::Microsecond)));
    }
    s.expect(unbookable.lossAccountingFailed(),
             L"T-06 a loss that cannot be booked is a hard error, not a dropped count");
    s.expect(!unbookable.loss().counter(LossCategory::RetentionEvicted).count.present,
             L"T-06 the unbookable category is marked unknown instead of staying at a stale number");
    s.expect(!unbookable.loss().totalLost().present,
             L"T-06 the unbookable category poisons the total instead of silently reading 0");
    s.expect(!unbookable.buildExportPlan(ExportScope::FullSession).retainedSessionIsCompleteCapture,
             L"T-06 a session whose accounting failed is never a complete capture");
}

// ---------------------------------------------------------------------------
// T-08 声明的上限必须真的可执行
// ---------------------------------------------------------------------------
void TestBoundsEnforceability(KswordTests::Suite& s) {
    // 声明了 4096 字节的磁盘上限却不给单条估算字节数：那个上限永远不会生效。
    BoundsPolicy unenforceable;
    unenforceable.maxArchiveBytes = OptionalU64::of(4096ULL);
    unenforceable.policy = RetentionPolicy::StopOnLimit;
    unenforceable.declaredBeforeCollection = true;
    TimelineSession noPerEvent(MakeManifest(), unenforceable);
    const SessionTransition rejectedA = noPerEvent.apply(SessionAction::Start);
    s.expect(!rejectedA.allowed &&
                 rejectedA.rejectionKey == "timeline.session.archive-limit-unenforceable",
             L"T-08 an archive limit with no bytes-per-event estimate is refused before collection starts");
    s.expect(noPerEvent.state() == SessionState::New,
             L"T-08 the refused Start leaves the session in New");

    BoundsPolicy zeroPerEvent = unenforceable;
    zeroPerEvent.approximateBytesPerEvent = OptionalU64::of(0ULL);
    TimelineSession zeroBytes(MakeManifest(), zeroPerEvent);
    s.expect(zeroBytes.apply(SessionAction::Start).rejectionKey ==
                 "timeline.session.archive-limit-unenforceable",
             L"T-08 a zero bytes-per-event estimate is just as unenforceable");

    // 一条能换算成条数的上限都没有 -> "内存有上限"这条判据是空的。
    BoundsPolicy noLimit;
    noLimit.policy = RetentionPolicy::StopOnLimit;
    noLimit.declaredBeforeCollection = true;
    TimelineSession unbounded(MakeManifest(), noLimit);
    const SessionTransition rejectedB = unbounded.apply(SessionAction::Start);
    s.expect(!rejectedB.allowed && rejectedB.rejectionKey == "timeline.session.no-memory-bound",
             L"T-08 a bounds policy that declares no limit at all cannot start collecting");

    // 补齐单条估算字节数就允许开始，而且上限真的生效：手算 4096 / 512 = 8 条。
    BoundsPolicy enforceable = unenforceable;
    enforceable.approximateBytesPerEvent = OptionalU64::of(512ULL);
    TimelineSession bounded(MakeManifest(), enforceable);
    DeclareAllLossSources(bounded.loss());
    s.expect(bounded.apply(SessionAction::Start).allowed,
             L"T-08 an enforceable archive limit is allowed to start");
    for (int i = 0; i < 20; ++i) {
        const std::string id = "ae" + std::to_string(i);
        bounded.ingest(MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                                 MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                          kT0, TimeResolution::Microsecond)));
    }
    s.expect(bounded.events().size() == 8U,
             L"T-08 4096 bytes at 512 bytes per event really bounds the session at 8 events");
    s.expect(bounded.boundsState() == BoundsState::ArchiveLimitReached,
             L"T-08 hitting the archive bound is reported as the archive bound");
    s.expect(bounded.loss().counter(LossCategory::QueueDiscard).count.value == 12ULL,
             L"T-08 the 12 refused events are accounted, not silently dropped (hand-count: 20 - 8)");
}

// ---------------------------------------------------------------------------
// T-04 / T-12 recordId 必须唯一：排序 tiebreak、边的连接键、导出主键都靠它
// ---------------------------------------------------------------------------
void TestRecordIdDiscipline(KswordTests::Suite& s) {
    TimelineSession session(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    session.apply(SessionAction::Start);
    const IngestResult first =
        session.ingest(MakeEvent("dup", "P", TimelineEventCategory::Process, 100U,
                                 MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    s.expect(first.accepted, L"T-04 the first event with a given record id is accepted");
    const IngestResult repeat =
        session.ingest(MakeEvent("dup", "P", TimelineEventCategory::Process, 100U,
                                 MakeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::Microsecond)));
    s.expect(!repeat.accepted && repeat.reasonKey == "timeline.ingest.duplicate-record-id",
             L"T-04 a duplicate record id is refused instead of producing two records that share a sort tiebreak");
    s.expect(repeat.countedAsLoss && repeat.lossCategory == LossCategory::QueueDiscard,
             L"T-04 the refused duplicate is accounted as an R3-side discard, not silently swallowed");

    TimelineEvent nameless = MakeEvent("x", "P", TimelineEventCategory::Process, 100U,
                                       MakeTime(kBoot1, kT0 + 20000ULL, kT0,
                                                TimeResolution::Microsecond));
    nameless.recordId.clear();
    const IngestResult empty = session.ingest(nameless);
    s.expect(!empty.accepted && empty.reasonKey == "timeline.ingest.missing-record-id",
             L"T-04 an event with no record id is refused: it has no final sort tiebreak and no export key");
    s.expect(session.events().size() == 1U,
             L"T-04 only the one well-formed event is retained (hand-count: 1)");
    s.expect(session.loss().counter(LossCategory::QueueDiscard).count.value == 2ULL,
             L"T-04 both refusals are counted (hand-count: 1 duplicate + 1 nameless)");

    // 淘汰之后该 id 重新可用 —— 查重表跟着保留窗口走，不会无限膨胀。
    TimelineSession ring(MakeManifestWithHealthyCollector(),
                         MakeBounds(2ULL, RetentionPolicy::EvictOldest));
    ring.apply(SessionAction::Start);
    ring.ingest(MakeEvent("g0", "P", TimelineEventCategory::Process, 100U,
                          MakeTime(kBoot1, kT0, kT0, TimeResolution::Microsecond)));
    ring.ingest(MakeEvent("g1", "P", TimelineEventCategory::Process, 100U,
                          MakeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::Microsecond)));
    ring.ingest(MakeEvent("g2", "P", TimelineEventCategory::Process, 100U,
                          MakeTime(kBoot1, kT0 + 20000ULL, kT0, TimeResolution::Microsecond)));
    const IngestResult reused =
        ring.ingest(MakeEvent("g0", "P", TimelineEventCategory::Process, 100U,
                              MakeTime(kBoot1, kT0 + 30000ULL, kT0, TimeResolution::Microsecond)));
    s.expect(reused.accepted,
             L"T-08 a record id whose event was evicted can be used again by a later event");
}

// ---------------------------------------------------------------------------
// T-10 载入结论必须长在会话上；trailer 必须是最后一行；坏枚举名就是坏文件
// ---------------------------------------------------------------------------
void TestLoadIntegrityPropagation(KswordTests::Suite& s) {
    TimelineSession source(MakeManifestWithHealthyCollector(), MakeRoomyDeclaredBounds());
    DeclareAllLossSources(source.loss());
    source.loss().setAbsolute(LossCategory::SourceDrop, 0ULL);
    source.loss().setAbsolute(LossCategory::RingOverwrite, 0ULL);
    source.apply(SessionAction::Start);
    for (int i = 0; i < 6; ++i) {
        const std::string id = "L" + std::to_string(i);
        source.ingest(MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                                MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                         kT0, TimeResolution::Microsecond)));
    }
    source.apply(SessionAction::StopCollection);
    const std::string text = SerializeSession(source, 3U);
    const std::vector<std::string> lines = SplitTextLines(text);
    // 手算：1 行 header + ceil(6/3)=2 个批次 + 1 行 trailer = 4 行。
    s.expect(lines.size() == 4U, L"T-09 six events at batch size three write header + 2 batches + trailer");

    // 基准：结构完整的文件恢复出来的会话仍然可以被判为完整采集。
    const SessionLoadResult clean = LoadSession(text);
    s.expect(clean.status == SessionLoadStatus::Ok && clean.recoveredEventCount == 6U,
             L"T-10 the complete file loads cleanly with all six events");
    s.expect(clean.session.loadIntegrity().restoredFromFile &&
                 clean.session.loadIntegrity().representsCompleteFile(),
             L"T-10 the loaded session itself knows it came from a structurally complete file");
    s.expect(clean.unrecoverableEventCount == 0U &&
                 clean.session.unrecoverableFileEventCount() == 0U,
             L"T-10 a complete file leaves nothing unrecoverable");
    s.expect(clean.session.buildExportPlan(ExportScope::FullSession).retainedSessionIsCompleteCapture,
             L"T-10 a session restored from a complete file may still export as a complete capture");
    s.expect(BuildSessionEnvelope(clean.session).outcome.status == CollectionStatus::Success,
             L"T-10 a session restored from a complete file may still envelope as Success");

    // 缺 trailer：同样的 6 条数据，但文件没有正常收尾。
    const std::string noTrailer =
        ElementOrDefault(lines, 0) + ElementOrDefault(lines, 1) + ElementOrDefault(lines, 2);
    const SessionLoadResult tail = LoadSession(noTrailer);
    s.expect(tail.status == SessionLoadStatus::IncompleteTail && tail.recoveredEventCount == 6U,
             L"T-10 a trailer-less file still recovers its six committed events");
    s.expect(tail.session.loadIntegrity().restoredFromFile &&
                 tail.session.loadIntegrity().status == SessionLoadStatus::IncompleteTail,
             L"T-10 the loaded session carries the IncompleteTail verdict, not a clean slate");
    const ExportPlan tailPlan = tail.session.buildExportPlan(ExportScope::FullSession);
    s.expect(!tailPlan.retainedSessionIsCompleteCapture,
             L"T-10 the SAME six events restored from a trailer-less file are no longer a complete capture");
    s.expect(ContainsKey(tailPlan.noticeKeys,
                         "timeline.export.restored-from-incomplete-file.IncompleteTail"),
             L"T-10 the export notice names the load status that made the session incomplete");
    const EvidenceEnvelope tailEnvelope = BuildSessionEnvelope(tail.session);
    s.expect(tailEnvelope.outcome.status == CollectionStatus::Partial,
             L"T-10 a session restored from a trailer-less file envelopes as Partial, never Success");
    s.expect(tailEnvelope.outcome.message.find("timeline.load.missing-trailer") != std::string::npos,
             L"T-10 the envelope message carries the load diagnostic key");

    // trailer 声明 9 条、实际恢复 6 条：手算 3 条恢复不出来。
    std::string mismatched = text;
    const std::string countNeedle = "\"eventCount\":\"6\"";
    const std::size_t countPos = mismatched.find(countNeedle);
    s.expect(countPos != std::string::npos, L"T-10 the trailer event count field is present");
    if (countPos != std::string::npos) {
        mismatched.replace(countPos, countNeedle.size(), "\"eventCount\":\"9\"");
    }
    const SessionLoadResult mismatch = LoadSession(mismatched);
    s.expect(mismatch.status == SessionLoadStatus::TrailerMismatch,
             L"T-10 a trailer that disagrees with the data keeps its own status");
    s.expect(mismatch.declaredEventCount == 9U && mismatch.recoveredEventCount == 6U,
             L"T-10 both the declared and the recovered counts are reported");
    s.expect(mismatch.unrecoverableEventCount == 3U &&
                 mismatch.session.unrecoverableFileEventCount() == 3U,
             L"T-10 the 3 events the trailer claims but the file cannot produce are accounted (hand-count: 9 - 6)");
    s.expect(!mismatch.session.buildExportPlan(ExportScope::FullSession)
                  .retainedSessionIsCompleteCapture,
             L"T-10 a trailer-mismatched session is never exported as a complete capture");
    s.expect(BuildSessionEnvelope(mismatch.session).outcome.status == CollectionStatus::Partial,
             L"T-10 a trailer-mismatched session envelopes as Partial");
    s.expect(BuildSessionEnvelope(mismatch.session).coverage.truncated == 3U,
             L"T-10 the unrecoverable events show up in the coverage account as truncated");

    // trailer 之后还有内容：被中断的重写、追加上去的批次、第二个 trailer。
    const std::string afterTrailerBatch = text + ElementOrDefault(lines, 1);
    const SessionLoadResult afterBatch = LoadSession(afterTrailerBatch);
    s.expect(afterBatch.status == SessionLoadStatus::Corrupt &&
                 afterBatch.diagnosticKey == "timeline.load.content-after-trailer",
             L"T-10 a batch line after the trailer is Corrupt, not a clean complete session");
    s.expect(!afterBatch.representsCompleteFile(),
             L"T-10 a file with content after its trailer never claims to be complete");
    const std::string twoTrailers = text + ElementOrDefault(lines, 3);
    const SessionLoadResult second = LoadSession(twoTrailers);
    s.expect(second.status == SessionLoadStatus::Corrupt &&
                 second.diagnosticKey == "timeline.load.content-after-trailer",
             L"T-10 a second trailer line is rejected the same way");

    // 同一个批次写了两遍：recordId 重复，结构已经坏了。
    const std::string duplicated = ElementOrDefault(lines, 0) + ElementOrDefault(lines, 1) +
                                   ElementOrDefault(lines, 1) + ElementOrDefault(lines, 3);
    const SessionLoadResult dup = LoadSession(duplicated);
    s.expect(dup.status == SessionLoadStatus::Corrupt &&
                 dup.diagnosticKey == "timeline.load.duplicate-record-id",
             L"T-10 a repeated batch is detected through its duplicate record ids");
    s.expect(dup.recoveredEventCount == 3U,
             L"T-10 the first copy of the batch is still recovered (hand-count: 3)");

    // 认不出的枚举名就是坏文件，不能悄悄退成一个良性默认值。
    std::string badStatus = text;
    const std::string statusNeedle = "\"availabilityStatus\":\"Success\"";
    const std::size_t statusPos = badStatus.find(statusNeedle);
    s.expect(statusPos != std::string::npos, L"T-10 the capability availability status field is present");
    if (statusPos != std::string::npos) {
        badStatus.replace(statusPos, statusNeedle.size(), "\"availabilityStatus\":\"HypervisorDenied\"");
    }
    const SessionLoadResult badStatusResult = LoadSession(badStatus);
    s.expect(badStatusResult.status == SessionLoadStatus::MissingHeader &&
                 badStatusResult.diagnosticKey == "timeline.load.header-fields-invalid",
             L"T-10 an unrecognised availabilityStatus fails the header instead of decoding to NotCollected");
    s.expect(badStatusResult.session.manifest().capabilities.empty(),
             L"T-10 nothing is half-restored out of a header carrying an unknown enum name");

    std::string badOrigin = text;
    const std::string originNeedle = "\"origin\":\"LiveKernel\"";
    const std::size_t originPos = badOrigin.find(originNeedle);
    s.expect(originPos != std::string::npos, L"T-10 the capability origin field is present");
    if (originPos != std::string::npos) {
        badOrigin.replace(originPos, originNeedle.size(), "\"origin\":\"LiveHypervisor\"");
    }
    s.expect(LoadSession(badOrigin).status == SessionLoadStatus::MissingHeader,
             L"T-10 an unrecognised source origin fails the header instead of decoding to Unknown");
    s.expect(badOrigin.find("LiveHypervisor") != std::string::npos,
             L"T-10 the failed load leaves the source text untouched");
}

// ---------------------------------------------------------------------------
// T-08 流式落盘：一次一行，不把整个文件堆成一个字符串
// ---------------------------------------------------------------------------
void TestStreamingSerialization(KswordTests::Suite& s) {
    const TimelineSession original = BuildPersistenceSession();
    const std::string oneShot = SerializeSession(original, 2U);

    std::vector<std::string> chunks;
    SerializeSessionTo(original, 2U,
                       [&chunks](std::string_view line) { chunks.emplace_back(line); });
    // 手算：1 行 header + ceil(7/2)=4 个批次 + 1 行 trailer = 6 块。
    s.expect(chunks.size() == 6U, L"T-08 the streaming writer yields exactly 6 chunks for 7 events at batch size 2");
    std::string joined;
    for (const std::string& chunk : chunks) {
        joined += chunk;
    }
    s.expect(joined == oneShot,
             L"T-08 the streamed bytes are identical to the one-shot serialization");
    bool everyChunkIsOneLine = true;
    for (const std::string& chunk : chunks) {
        if (chunk.empty() || chunk.back() != '\n' || chunk.find('\n') != chunk.size() - 1U) {
            everyChunkIsOneLine = false;
        }
    }
    s.expect(everyChunkIsOneLine,
             L"T-08 every streamed chunk is exactly one terminated line, so a sink can write it and forget it");
    s.expect(LoadSession(joined).status == SessionLoadStatus::Ok,
             L"T-08 the streamed file loads back cleanly");

    std::size_t counted = 0;
    SerializeSessionTo(original, 0U, [&counted](std::string_view) { ++counted; });
    // batchSize=0 视为一个批次：header + 1 批 + trailer = 3 块（手算）。
    s.expect(counted == 3U, L"T-08 batch size zero streams header + one batch + trailer");
}

// ---------------------------------------------------------------------------
// 规模：判据是"n 翻倍时耗时不得接近翻四倍"。
//
// 三处热点原来都是 O(n^2)：sortedOrder 的不确定性复核按 recordId 回表线性查找、
// EvictOldest 用 vector::erase(begin()) 搬动整个保留窗口、BuildEdges 的内层扫描在
// 键互不相同时一路扫到数组末尾。绝对耗时会随机器负载浮动，所以这里比的是**比值**：
// O(n log n) / O(n) 约 2.1 倍，O(n^2) 是 4 倍，阈值取 3.0 倍并加 20 ms 抖动余量。
// 每次测量取三轮最小值 —— 微基准的标准稳健估计。
// ---------------------------------------------------------------------------
template <typename Fn>
double BestMillisOfThree(Fn&& fn) {
    double best = 0.0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        const std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
        fn();
        const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double, std::milli>(end - begin).count();
        if (attempt == 0 || elapsed < best) {
            best = elapsed;
        }
    }
    return best;
}

BoundsPolicy MakeLargeBounds(std::uint64_t maxEvents, RetentionPolicy policy) {
    BoundsPolicy bounds;
    bounds.maxEventsInMemory = OptionalU64::of(maxEvents);
    bounds.policy = policy;
    bounds.declaredBeforeCollection = true;
    return bounds;
}

std::vector<TimelineEvent> MakeSyntheticEvents(std::size_t count, bool uniqueLinkKeys) {
    std::vector<TimelineEvent> events;
    events.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::string id = "n" + std::to_string(i);
        TimelineEvent event = MakeEvent(id.c_str(), "P", TimelineEventCategory::Process, 100U,
                                        MakeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                                 kT0, TimeResolution::Microsecond));
        event.arrivalSequence = static_cast<std::uint64_t>(i) + 1U;
        if (uniqueLinkKeys) {
            // 忙机器上的常态：实例键与 ActivityId 各不相同，一条边都建不出来。
            event.processInstanceKey = "inst-" + std::to_string(i);
            event.sourceLinkId = "act-" + std::to_string(i);
            event.sourceLinkField = "ActivityId";
        }
        events.push_back(std::move(event));
    }
    return events;
}

void TestScalability(KswordTests::Suite& s) {
    // ---- sortedOrder ----
    const std::vector<TimelineEvent> sortSmall = MakeSyntheticEvents(6000U, false);
    const std::vector<TimelineEvent> sortLarge = MakeSyntheticEvents(12000U, false);
    TimelineSession sortSmallSession(MakeManifest(), MakeLargeBounds(200000ULL, RetentionPolicy::StopOnLimit));
    TimelineSession sortLargeSession(MakeManifest(), MakeLargeBounds(200000ULL, RetentionPolicy::StopOnLimit));
    sortSmallSession.apply(SessionAction::Start);
    sortLargeSession.apply(SessionAction::Start);
    for (const TimelineEvent& event : sortSmall) {
        sortSmallSession.ingest(event);
    }
    for (const TimelineEvent& event : sortLarge) {
        sortLargeSession.ingest(event);
    }
    s.expect(sortSmallSession.events().size() == 6000U && sortLargeSession.events().size() == 12000U,
             L"T-04 scale fixture: 6000 and 12000 events are retained");
    std::size_t sortSink = 0;
    const double sortSmallMs = BestMillisOfThree([&sortSmallSession, &sortSink]() {
        sortSink += sortSmallSession.sortedOrder().size();
    });
    const double sortLargeMs = BestMillisOfThree([&sortLargeSession, &sortSink]() {
        sortSink += sortLargeSession.sortedOrder().size();
    });
    s.expect(sortSink == 3U * (6000U + 12000U),
             L"T-04 scale fixture: every sortedOrder call returned one key per event");
    s.expect(sortLargeMs <= 3.0 * sortSmallMs + 20.0,
             L"T-04 doubling the event count must not quadruple sortedOrder: quadratic order-uncertainty lookup is refused");
    const std::vector<TimelineSortKey> order = sortLargeSession.sortedOrder();
    s.expect(order.size() == 12000U && ElementOrDefault(order, 0).recordId == "n0" &&
                 ElementOrDefault(order, 11999U).recordId == "n11999",
             L"T-04 the hand-written expected order still holds at scale: n0 first, n11999 last");

    // ---- EvictOldest ----
    // 两次都恰好淘汰 5000 条，只有保留窗口大小不同（500 vs 4000）。
    // O(1) 淘汰的耗时随入队条数走（5500 -> 9000，约 1.6 倍）；
    // 搬整个窗口的实现随窗口大小走（500 -> 4000，约 8 倍）。
    const std::vector<TimelineEvent> evictSmall = MakeSyntheticEvents(5500U, false);
    const std::vector<TimelineEvent> evictLarge = MakeSyntheticEvents(9000U, false);
    std::size_t evictSink = 0;
    const double evictSmallMs = BestMillisOfThree([&evictSmall, &evictSink]() {
        TimelineSession session(MakeManifest(), MakeLargeBounds(500ULL, RetentionPolicy::EvictOldest));
        session.apply(SessionAction::Start);
        for (const TimelineEvent& event : evictSmall) {
            session.ingest(event);
        }
        evictSink += session.events().size();
    });
    const double evictLargeMs = BestMillisOfThree([&evictLarge, &evictSink]() {
        TimelineSession session(MakeManifest(), MakeLargeBounds(4000ULL, RetentionPolicy::EvictOldest));
        session.apply(SessionAction::Start);
        for (const TimelineEvent& event : evictLarge) {
            session.ingest(event);
        }
        evictSink += session.events().size();
    });
    s.expect(evictSink == 3U * (500U + 4000U),
             L"T-08 scale fixture: each run retained exactly its configured window");
    s.expect(evictLargeMs <= 3.0 * evictSmallMs + 20.0,
             L"T-08 the same number of evictions must not cost 8x more just because the window is 8x larger");

    // ---- BuildEdges ----
    const std::vector<TimelineEvent> edgeSmall = MakeSyntheticEvents(16000U, true);
    const std::vector<TimelineEvent> edgeLarge = MakeSyntheticEvents(32000U, true);
    EdgeBuildOptions noWindow;
    std::size_t edgeSink = 0;
    const double edgeSmallMs = BestMillisOfThree([&edgeSmall, &noWindow, &edgeSink]() {
        edgeSink += BuildEdges(edgeSmall, {}, noWindow).size();
    });
    const double edgeLargeMs = BestMillisOfThree([&edgeLarge, &noWindow, &edgeSink]() {
        edgeSink += BuildEdges(edgeLarge, {}, noWindow).size();
    });
    s.expect(edgeSink == 0U,
             L"T-12 scale fixture: all keys are distinct, so no edge is produced at either size");
    s.expect(edgeLargeMs <= 3.0 * edgeSmallMs + 20.0,
             L"T-12 doubling the event count must not quadruple BuildEdges: the no-match full scan is refused");

    // 分组之后边的取值语义不变：只连到下一条同键事件，且依据可点开。
    std::vector<TimelineEvent> paired = MakeSyntheticEvents(5000U, true);
    paired[0].processInstanceKey = "shared-instance";
    paired[4999].processInstanceKey = "shared-instance";
    paired[1].sourceLinkId = "shared-activity";
    paired[2].sourceLinkId = "shared-activity";
    paired[3].sourceLinkId = "shared-activity";
    const std::vector<TimelineEdge> pairedEdges = BuildEdges(paired, {}, noWindow);
    s.expect(CountEdges(pairedEdges, TimelineEdgeKind::SameProcess) == 1U &&
                 HasEdge(pairedEdges, TimelineEdgeKind::SameProcess, "n0", "n4999"),
             L"T-12 one shared instance key across 5000 events builds exactly one SameProcess edge, n0 -> n4999");
    s.expect(CountEdges(pairedEdges, TimelineEdgeKind::SourceProvidedLink) == 2U &&
                 HasEdge(pairedEdges, TimelineEdgeKind::SourceProvidedLink, "n1", "n2") &&
                 HasEdge(pairedEdges, TimelineEdgeKind::SourceProvidedLink, "n2", "n3"),
             L"T-12 three events sharing one activity id chain into 2 edges, each to the next one only");
}

} // namespace

int RunTimelineTests() {
    KswordTests::Suite suite(L"T timeline");
    TestSessionLifecycle(suite);
    TestEventEnvelope(suite);
    TestTimeSemantics(suite);
    TestAttribution(suite);
    TestLossAccounting(suite);
    TestFilterSeparation(suite);
    TestPersistence(suite);
    TestRelationEdges(suite);
    TestSessionEnvelope(suite);
    TestCollectorAvailability(suite);
    TestSelfDeclaredLossSources(suite);
    TestBoundsEnforceability(suite);
    TestRecordIdDiscipline(suite);
    TestLoadIntegrityPropagation(suite);
    TestStreamingSerialization(suite);
    TestScalability(suite);
    suite.report();
    return suite.failures();
}
