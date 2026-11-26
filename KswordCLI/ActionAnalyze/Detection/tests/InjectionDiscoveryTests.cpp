#include "../InjectionSurveyProjection.h"
#include "../InjectionTelemetry.h"

#include "../../../../shared/driver/KswordArkCallbackIoctl.h"

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <limits>

using namespace Ksword::ActionAnalyze::Detection;
using namespace Ksword::Evidence;

namespace {

// 完全合成、不可执行的遥测记录。无 Windows 目标句柄、内存写入、注入或调试控制。
const SampleScope scope{"project", "sample", "machine", "boot"};
int failures = 0;
int assertions = 0;

void Check(bool passed, const char* name)
{
    ++assertions;
    if (!passed) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", name);
    }
}

ProcessBinding Process(std::uint32_t pid, std::uint64_t created = 100)
{
    ProcessBinding binding;
    binding.machineId = scope.machineId;
    binding.instance.bootId = scope.bootId;
    binding.instance.pid = OptionalU64::of(pid);
    binding.instance.createTime100ns = OptionalU64::of(created);
    return binding;
}

EvidenceRef Anchor(std::uint64_t ordinal, const char* source, const char* group)
{
    return {scope.projectId, scope.sampleId, source, "epoch", ordinal, RawLocator{1, ordinal + 1},
        std::nullopt, group};
}

ObservationHeader Header(std::uint64_t ordinal, const char* name, const char* group, Phase phase)
{
    ObservationHeader header;
    header.evidence = Anchor(ordinal, name, group);
    header.trust = InputTrust::Validated;
    header.phase = phase;
    return header;
}

WriteObservation Write()
{
    WriteObservation row;
    row.header = Header(0, "api", "agent", Phase::Return);
    row.header.time = FactTime{"clock", 110, 112};
    row.actor = Process(10);
    row.target = Process(20);
    row.outcome = Outcome::PartiallySucceeded;
    row.address = 0x1004;
    row.completedLength = 8;
    row.requestedLength = 16;
    row.regionAfter = RegionVersion{"region", 7, 8, 0x1000, 0x1000};
    return row;
}

ExecutionObservation Execution()
{
    ExecutionObservation row;
    row.header = Header(1, "native-witness", "target-native", Phase::Observation);
    row.header.time = FactTime{"clock", 113, 115};
    row.observedThread = ThreadBinding{Process(20), 31, 101};
    row.state = ExecutionState::Executed;
    row.instructionPointer = 0x100b;
    row.regionAtExecution = Write().regionAfter;
    return row;
}

bool Gap(const EventProjection& result, Issue issue)
{
    return std::find(result.gaps.begin(), result.gaps.end(), issue) != result.gaps.end();
}

void TestWrite()
{
    auto row = Write();
    const auto external = ProjectInjectionEvent(scope, row);
    Check(external.finding && external.finding->kind == FindingKind::ExternalWrite, "external-write");
    Check(external.finding && external.finding->attribution == Attribution::DirectWriter, "writer-only");
    Check(external.finding && external.finding->externalOperation, "external-alert");
    Check(external.observation && std::get<WriteObservation>(*external.observation).completedLength == 8, "actual-length");
    Check(external.observation && std::get<WriteObservation>(*external.observation).header.evidence.eventOrdinal == 0, "ordinal-zero");
    auto legacyScope = scope;
    legacyScope.bootId = "live";
    Check(!ProjectInjectionEvent(legacyScope, row).observation, "generic-live-is-not-strong-sample-boot");

    row.completedLength.reset();
    auto result = ProjectInjectionEvent(scope, row);
    Check(!result.finding && Gap(result, Issue::ActualWriteRangeUnknown), "request-is-not-completion");
    row = Write();
    row.completedLength = 0;
    Check(!ProjectInjectionEvent(scope, row).finding, "zero-actual-range");
    row = Write();
    row.outcome = Outcome::Failed;
    Check(Gap(ProjectInjectionEvent(scope, row), Issue::OutcomeInconsistent), "failure-nonzero-conflicts");
    Check(!ProjectInjectionEvent(scope, row).finding, "failed-write-not-an-edge");
    row = Write();
    row.completedLength = 17;
    Check(Gap(ProjectInjectionEvent(scope, row), Issue::InvalidWriteRange), "actual-exceeds-requested");
    row = Write();
    row.address = (std::numeric_limits<std::uint64_t>::max)() - 1;
    Check(Gap(ProjectInjectionEvent(scope, row), Issue::InvalidWriteRange), "write-range-overflow");

    row = Write();
    row.actor = row.target;
    Check(!ProjectInjectionEvent(scope, row).finding, "not-cross-process");
    row.actor = Process(20, 102);
    Check(Gap(ProjectInjectionEvent(scope, row), Issue::IdentityConflict), "same-pid-different-instance");
    row.actor = Process(10);
    row.actor->instance.createTime100ns = {};
    result = ProjectInjectionEvent(scope, row);
    Check(!result.finding && Gap(result, Issue::ActorInstanceUnknown), "weak-writer");

    row = Write();
    row.target->machineId = "foreign";
    Check(!ProjectInjectionEvent(scope, row).finding, "machine-identity");
    row = Write();
    row.target->instance.bootId = "previous";
    Check(!ProjectInjectionEvent(scope, row).finding, "boot-identity");
    row = Write();
    row.header.evidence.sampleId = "other";
    result = ProjectInjectionEvent(scope, row);
    Check(!result.observation && !result.finding && Gap(result, Issue::EvidenceUnavailable), "sample-identity");
    row = Write();
    row.header.evidence.eventOrdinal.reset();
    row.header.evidence.raw.reset();
    row.header.evidence.sourceSequence = 1;
    Check(!ProjectInjectionEvent(scope, row).observation, "native-sequence-is-not-locator");
    row = Write();
    row.header.phase = Phase::Entry;
    Check(!ProjectInjectionEvent(scope, row).finding, "entry-is-not-completion");
    row = Write();
    row.header.trust = InputTrust::RawOnly;
    Check(!ProjectInjectionEvent(scope, row).finding, "raw-source-no-edge");
    row = Write();
    row.regionAfter.reset();
    result = ProjectInjectionEvent(scope, row);
    Check(result.finding && Gap(result, Issue::RegionVersionUnknown), "write-fact-without-region-ledger");
}

void TestThreadsAndExecution()
{
    ThreadCreationObservation row;
    row.header = Header(2, "lifecycle", "kernel", Phase::Observation);
    row.creator = Process(10);
    row.target = Process(20);
    row.newThread = ThreadBinding{*row.target, 31, 101};
    row.outcome = Outcome::Succeeded;
    row.startAddress = 0x100b;
    auto result = ProjectInjectionEvent(scope, row);
    Check(result.finding && result.finding->kind == FindingKind::ThreadCreated, "thread-not-execution");
    Check(result.finding && result.finding->attribution == Attribution::DirectThreadCreator, "actual-creator");
    row.creator.reset();
    result = ProjectInjectionEvent(scope, row);
    Check(result.finding && result.finding->attribution == Attribution::Unknown && !result.finding->externalOperation,
        "new-thread-unknown-creator");
    row.newThread->owner = Process(20, 102);
    Check(!ProjectInjectionEvent(scope, row).finding, "thread-pid-reuse");
    row.newThread->owner = Process(20);
    row.targetTidHint = 32;
    Check(!ProjectInjectionEvent(scope, row).finding, "thread-hint-conflict");
    row.targetTidHint = 31;
    row.outcome = Outcome::Failed;
    Check(!ProjectInjectionEvent(scope, row).finding, "failed-thread-create");

    const auto write = Write();
    auto execution = Execution();
    result = ProjectInjectionEvent(scope, execution);
    Check(result.finding && result.finding->kind == FindingKind::ExecutionConfirmed &&
        result.finding->attribution == Attribution::Unknown, "independent-execution-unknown-writer");
    const auto relation = CorrelateWriteExecution(scope, write, execution);
    Check(relation && relation->write.eventOrdinal == 0 && relation->execution.eventOrdinal == 1, "two-evidence-anchors");
    execution.state = ExecutionState::FetchAttempt;
    result = ProjectInjectionEvent(scope, execution);
    Check(result.finding && result.finding->kind == FindingKind::ExecutionFetched, "fetch-only");
    Check(!CorrelateWriteExecution(scope, write, execution), "fetch-not-executed");
    execution = Execution();
    execution.instructionPointer = 0x100c;
    Check(!CorrelateWriteExecution(scope, write, execution), "end-exclusive");
    execution = Execution();
    ++execution.regionAtExecution->mappingGeneration;
    Check(!CorrelateWriteExecution(scope, write, execution), "mapping-reuse");
    execution = Execution();
    ++execution.regionAtExecution->contentVersion;
    Check(!CorrelateWriteExecution(scope, write, execution), "changed-content");
    execution = Execution();
    execution.observedThread->owner = Process(20, 101);
    Check(!CorrelateWriteExecution(scope, write, execution), "execution-pid-reuse");
    execution = Execution();
    execution.header.time->earliest = 112;
    Check(!CorrelateWriteExecution(scope, write, execution), "clock-uncertainty-overlap");
    execution = Execution();
    execution.header.evidence.sourceGroup = write.header.evidence.sourceGroup;
    Check(!CorrelateWriteExecution(scope, write, execution), "wrappers-not-independent");
    execution = Execution();
    execution.header.evidence.raw = write.header.evidence.raw;
    Check(!CorrelateWriteExecution(scope, write, execution), "same-raw-not-independent");
}

void TestExistingSources()
{
    using namespace ks::winapi_monitor;
    const auto evidence = Anchor(1, "test-source", "test-group");
    ApiMonitorEventPacket api;
    api.pid = 10;
    api.category = static_cast<std::uint32_t>(EventCategory::Memory);
    api.snapshotIndex = kApiCallReturnValueMarker;
    api.hookAddress = 1;
    wcscpy_s(api.apiName, L"WriteProcessMemory");
    wcscpy_s(api.moduleName, L"KernelBase");
    wcscpy_s(api.detailText, L"process=0x100 address=0x1004 size=16 written=16");
    auto projected = ProjectArchivedApiCall(scope, evidence, api);
    Check(projected.disposition == TelemetryDisposition::Projected && !projected.event.finding, "summary-does-not-prove-write");
    Check(Gap(projected.event, Issue::LegacySummaryOnly) && Gap(projected.event, Issue::ActualWriteRangeUnknown), "explicit-legacy-gaps");
    Check(std::get<WriteObservation>(*projected.event.observation).outcome == Outcome::Succeeded, "marked-return-preserved");
    api.snapshotIndex = 0;
    projected = ProjectArchivedApiCall(scope, evidence, api);
    Check(Gap(projected.event, Issue::OutcomeUnknown), "missing-return-marker");
    api.snapshotIndex = kApiCallReturnValueMarker;
    api.hookAddress = 0;
    api.resultCode = ERROR_PARTIAL_COPY;
    projected = ProjectArchivedApiCall(scope, evidence, api);
    Check(!projected.event.finding && Gap(projected.event, Issue::ActualWriteRangeUnknown), "legacy-partial-range-unknown");
    api.version = 0;
    Check(ProjectArchivedApiCall(scope, evidence, api).disposition == TelemetryDisposition::InvalidRecord, "unknown-api-version");

    ks::r3::monitor::PassiveEtwRecord etw;
    etw.sourceEpoch = evidence.sourceEpoch;
    etw.headerPid = 10;
    etw.headerTid = 11;
    etw.originalPayloadBytes = 4;
    projected = ProjectPassiveEtwContext(scope, evidence, etw);
    Check(!projected.event.finding && Gap(projected.event, Issue::EtwContextOnly), "etw-header-context-only");
    Check(Gap(projected.event, Issue::SourcePayloadTruncated), "etw-truncation-visible");
    ks::r3::monitor::PassiveEtwStatus status;
    status.queueDropped = 2;
    status.payloadTruncated = 1;
    Check(PassiveEtwCoverageGaps(status).size() == 3, "etw-loss-tail-truncation");
}

void TestCallbackThreadCreation()
{
    auto evidence = Anchor(0, "kswordark.callback", "kswordark");
    evidence.raw = RawLocator{7, 19};
    KSWORD_ARK_CALLBACK_MONITOR_EVENT callback{};
    callback.version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    callback.size = sizeof(callback);
    callback.sequence = 4;
    callback.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    callback.operation = KSWORD_ARK_THREAD_OP_CREATE;
    callback.originatingProcessId = 10;
    callback.originatingThreadId = 11;
    callback.targetProcessId = 20;
    callback.targetThreadId = 21;
    auto projected = ProjectCallbackThreadCreation(scope, evidence, callback);
    const auto* row = projected.event.observation ? std::get_if<ThreadCreationObservation>(&*projected.event.observation) : nullptr;
    Check(row && row->header.trust == InputTrust::Validated && row->outcome == Outcome::Succeeded &&
        !projected.event.finding && Gap(projected.event, Issue::ThreadInstanceUnknown), "callback-ids-are-hints");
    Check(projected.evidence && projected.evidence->sourceSequence == 4 && projected.evidence->raw == evidence.raw,
        "source-and-raw-sequences-stay-distinct");
    auto canonicalOnly = evidence;
    canonicalOnly.raw.reset();
    projected = ProjectCallbackThreadCreation(scope, canonicalOnly, callback);
    Check(projected.event.observation && projected.evidence && projected.evidence->eventOrdinal == 0 &&
        !projected.evidence->raw, "callback-strong-entry-raw-remains-optional");

    const SampleScope archiveScope{scope.projectId, scope.sampleId, {}, {}};
    auto rawOnly = evidence;
    rawOnly.eventOrdinal.reset();
    projected = ProjectCallbackThreadCreation(archiveScope, rawOnly, callback);
    Check(projected.disposition == TelemetryDisposition::InvalidRecord && !projected.event.observation &&
        Gap(projected.event, Issue::EvidenceUnavailable), "callback-strong-entry-still-requires-machine-and-boot");

    projected = ProjectArchivedCallbackThreadCreation(archiveScope, rawOnly, callback);
    row = projected.event.observation ? std::get_if<ThreadCreationObservation>(&*projected.event.observation) : nullptr;
    Check(projected.disposition == TelemetryDisposition::Projected && projected.evidence &&
        projected.evidence->raw == rawOnly.raw && projected.evidence->sourceSequence == 4 &&
        !projected.evidence->eventOrdinal, "archived-callback-keeps-raw-and-native-coordinates");
    Check(row && row->header.operation == "callback.thread.create.v1" && row->header.phase == Phase::Observation &&
        row->header.evidence.raw == rawOnly.raw && row->header.evidence.sourceSequence == 4 &&
        row->header.evidence.sourceId == rawOnly.sourceId && row->header.evidence.sourceEpoch == rawOnly.sourceEpoch &&
        row->creatorPidHint == 10 && row->creatorTidHint == 11 && row->targetPidHint == 20 && row->targetTidHint == 21,
        "archived-callback-observation-and-hints");
    Check(row && row->header.trust == InputTrust::RawOnly && row->outcome == Outcome::Unknown &&
        !row->creator && !row->target && !row->newThread && !row->startAddress && !projected.event.finding,
        "archived-callback-does-not-prove-native-facts");
    Check(Gap(projected.event, Issue::SourceUnverified) && Gap(projected.event, Issue::OutcomeUnknown) &&
        Gap(projected.event, Issue::ActorInstanceUnknown) && Gap(projected.event, Issue::TargetInstanceUnknown) &&
        Gap(projected.event, Issue::ThreadInstanceUnknown), "archived-callback-source-and-instance-gaps");

    auto changed = callback;
    changed.originatingProcessId = 0;
    changed.originatingThreadId = 0;
    const SampleScope liveMarker{scope.projectId, scope.sampleId, scope.machineId, "live"};
    evidence.sourceSequence = callback.sequence;
    projected = ProjectArchivedCallbackThreadCreation(liveMarker, evidence, changed);
    row = projected.event.observation ? std::get_if<ThreadCreationObservation>(&*projected.event.observation) : nullptr;
    Check(row && row->creatorPidHint == 0 && row->creatorTidHint == 0 && row->header.evidence.eventOrdinal == 0 &&
        Gap(projected.event, Issue::ActorInstanceUnknown), "archived-callback-optional-origin-and-event-ordinal-zero");

    const auto badRecord = [&](const KSWORD_ARK_CALLBACK_MONITOR_EVENT& record, const EvidenceRef& locator) {
        const auto result = ProjectArchivedCallbackThreadCreation(archiveScope, locator, record);
        return result.disposition == TelemetryDisposition::InvalidRecord && result.evidence &&
            result.evidence->raw == locator.raw && !result.event.observation && !result.event.finding &&
            Gap(result.event, Issue::InvalidNativeRecord);
    };
    changed = callback;
    changed.version = 0;
    Check(badRecord(changed, rawOnly), "archived-callback-version");
    changed = callback;
    --changed.size;
    Check(badRecord(changed, rawOnly), "archived-callback-size");
    changed = callback;
    changed.sequence = 0;
    Check(badRecord(changed, rawOnly), "archived-callback-native-sequence-zero");
    changed = callback;
    changed.targetProcessId = 0;
    Check(badRecord(changed, rawOnly), "archived-callback-target-pid-zero");
    changed = callback;
    changed.targetThreadId = 0;
    Check(badRecord(changed, rawOnly), "archived-callback-target-tid-zero");
    evidence.sourceSequence = callback.sequence + 1;
    Check(badRecord(callback, evidence), "archived-callback-native-sequence-conflict");

    const auto badLocation = [&](const EvidenceRef& locator) {
        const auto result = ProjectArchivedCallbackThreadCreation(archiveScope, locator, callback);
        return result.disposition == TelemetryDisposition::InvalidRecord && !result.evidence &&
            !result.event.observation && !result.event.finding && Gap(result.event, Issue::EvidenceUnavailable);
    };
    auto locator = rawOnly;
    locator.raw.reset();
    locator.sourceSequence = callback.sequence;
    Check(badLocation(locator), "archived-callback-native-sequence-is-not-raw-coordinate");
    locator.eventOrdinal = 0;
    Check(badLocation(locator), "archived-callback-canonical-ordinal-is-not-raw-coordinate");
    locator = rawOnly;
    locator.sampleId = "other";
    Check(badLocation(locator), "archived-callback-foreign-sample");
    locator = rawOnly;
    locator.sourceEpoch.clear();
    Check(badLocation(locator), "archived-callback-source-epoch-required");
    locator = rawOnly;
    locator.raw->segmentOrdinal = 0;
    Check(badLocation(locator), "archived-callback-invalid-raw-segment");
    locator = rawOnly;
    locator.raw->sequence = 0;
    Check(badLocation(locator), "archived-callback-current-raw-sequence-convention");

    callback.operation = KSWORD_ARK_THREAD_OP_EXIT;
    Check(ProjectCallbackThreadCreation(scope, rawOnly, callback).disposition == TelemetryDisposition::Unrelated &&
        ProjectArchivedCallbackThreadCreation(archiveScope, rawOnly, callback).disposition == TelemetryDisposition::Unrelated,
        "exit-not-create");
    callback.operation = KSWORD_ARK_THREAD_OP_CREATE;
    callback.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
    Check(ProjectArchivedCallbackThreadCreation(archiveScope, rawOnly, callback).disposition == TelemetryDisposition::Unrelated,
        "object-access-not-thread-create");
}

void TestSurvey()
{
    const auto evidence = Anchor(0, "survey", "onsite");
    const auto expected = Process(20);
    SurveyReport report;
    report.process = expected.instance;
    report.identity = IdentityRecheckVerdict::Same;
    report.firstObservedUtc100ns = OptionalU64::of(1000);
    report.coverageGapKeys.push_back("example-gap");
    report.capabilityLimitKeys.push_back("example-limit");
    InjectionFinding row;
    row.ruleId = "example";
    row.facts.push_back("observed=1");
    report.findings.push_back(row);
    const auto bound = ProjectSurveySnapshot(scope, evidence, expected, report);
    const auto* finding = ReadSurveyFinding(bound, 0);
    Check(bound.status == SurveyProjectionStatus::Bound && finding && finding->facts.front() == "observed=1", "survey-finding-readback");
    Check(bound.report && bound.report->coverageGapKeys != bound.report->capabilityLimitKeys, "survey-coverage-distinction");
    Check(!ReadSurveyFinding(bound, 1), "survey-item-bounds");
    Check(ProjectSurveySnapshot(scope, evidence, Process(20, 999), report).status == SurveyProjectionStatus::IdentityMismatch,
        "survey-pid-reuse");
    report.process.bootId = "live";
    Check(!ProjectSurveySnapshot(scope, evidence, expected, report).report, "archived-live-marker-not-a-boot-id");
    const auto local = ProjectCurrentLocalSurveySnapshot(scope, evidence, expected, report);
    Check(local.report && local.report->process.bootId == "live" && local.target &&
        local.target->instance.bootId == scope.bootId, "live-survey-identity-separated-from-original");
    Check(!ProjectCurrentLocalSurveySnapshot(scope, evidence, Process(20, 999), report).report, "live-survey-no-pid-reuse");
    report.identity = IdentityRecheckVerdict::Unverifiable;
    Check(!ProjectCurrentLocalSurveySnapshot(scope, evidence, expected, report).report, "survey-unverified-identity");
}

} // namespace

int main()
{
    TestWrite();
    TestThreadsAndExecution();
    TestExistingSources();
    TestCallbackThreadCreation();
    TestSurvey();
    std::printf("InjectionDiscovery: %d assertions, %d failures\n", assertions, failures);
    return failures != 0;
}
