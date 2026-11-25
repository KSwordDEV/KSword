#include "InjectionTelemetry.h"

#include "../../../shared/driver/KswordArkCallbackIoctl.h"

#include <algorithm>
#include <string_view>
#include <utility>

namespace Ksword::ActionAnalyze::Detection {
namespace {
using namespace ks::winapi_monitor;

// 定长数组必须在界内终止，不能交给隐式 wcslen 越过原包。
template<std::size_t N>
std::optional<std::wstring_view> ReadText(const wchar_t (&text)[N]) noexcept
{
    const auto* end = std::find(text, text + N, L'\0');
    if (end == text + N) {
        return std::nullopt;
    }
    return std::wstring_view(text, static_cast<std::size_t>(end - text));
}

TelemetryProjection Invalid(const SampleScope& scope, const EvidenceRef& evidence)
{
    TelemetryProjection result;
    result.disposition = TelemetryDisposition::InvalidRecord;
    if (HasEvidenceLocation(scope, evidence)) {
        result.evidence = evidence;
        result.event.gaps.push_back(Issue::InvalidNativeRecord);
    } else {
        result.event.gaps.push_back(Issue::EvidenceUnavailable);
    }
    return result;
}

// 返回位和结果码职责不同。只读精确 API 回包的标记；无标记时结果保留未知。
Outcome LegacyOutcome(const ApiMonitorEventPacket& packet, bool isWrite, ObservationHeader& header)
{
    if (packet.resultKind != static_cast<std::uint32_t>(EventResultKind::StatusCode) ||
        packet.snapshotIndex != kApiCallReturnValueMarker) {
        return Outcome::Unknown;
    }
    header.phase = Phase::Return;
    header.returnBits = packet.hookAddress;
    header.errorDomain = "win32";
    if (packet.hookAddress == 0) {
        header.nativeError = static_cast<std::uint32_t>(packet.resultCode);
        return Outcome::Failed;
    }
    if (packet.resultCode != 0 || (isWrite && packet.hookAddress > UINT32_MAX)) {
        header.nativeError = static_cast<std::uint32_t>(packet.resultCode);
        return Outcome::Unknown;
    }
    return Outcome::Succeeded;
}

} // namespace

TelemetryProjection ProjectArchivedApiCall(const SampleScope& scope, const EvidenceRef& evidence,
    const ApiMonitorEventPacket& packet)
{
    if (packet.size != sizeof(packet) || packet.version != kProtocolVersion) {
        return Invalid(scope, evidence);
    }
    if (packet.eventKind != static_cast<std::uint32_t>(EventKind::ApiCall)) {
        return {};
    }
    const auto name = ReadText(packet.apiName);
    const auto module = ReadText(packet.moduleName);
    if (!name || !module) {
        return Invalid(scope, evidence);
    }
    // 限定已核过实现的包装器；未验证的 native 布局不通过名字猜测返回语义。
    if (*module != L"KernelBase" && *module != L"kernelbase.dll" &&
        *module != L"kernel32.dll" && *module != L"Kernel32") {
        return {};
    }
    const bool isWrite = *name == L"WriteProcessMemory";
    const bool isThread = *name == L"CreateRemoteThread" || *name == L"CreateRemoteThreadEx";
    if (!isWrite && !isThread) {
        return {};
    }
    const auto category = isWrite ? EventCategory::Memory : EventCategory::Thread;
    if (!HasEvidenceLocation(scope, evidence) || packet.category != static_cast<std::uint32_t>(category)) {
        return Invalid(scope, evidence);
    }

    ObservationHeader header;
    header.evidence = evidence;
    header.phase = packet.resultKind == static_cast<std::uint32_t>(EventResultKind::EntryOnly)
        ? Phase::Entry : Phase::Observation;
    header.operation = isWrite ? "WriteProcessMemory" :
        (*name == L"CreateRemoteThread" ? "CreateRemoteThread" : "CreateRemoteThreadEx");
    // 只核返回；现有 detailText 未保留字段有效性、稳定目标或句柄代次，所以整条仍是线索。
    const auto outcome = LegacyOutcome(packet, isWrite, header);
    EventProjection event;
    if (isWrite) {
        WriteObservation row;
        row.header = std::move(header);
        row.outcome = outcome;
        row.actorPidHint = packet.pid;
        row.actorTidHint = packet.tid;
        event = ProjectInjectionEvent(scope, std::move(row));
        if (outcome == Outcome::Failed && packet.resultCode == ERROR_PARTIAL_COPY) {
            event.gaps.push_back(Issue::ActualWriteRangeUnknown);
        }
    } else {
        ThreadCreationObservation row;
        row.header = std::move(header);
        row.outcome = outcome;
        row.creatorPidHint = packet.pid;
        row.creatorTidHint = packet.tid;
        event = ProjectInjectionEvent(scope, std::move(row));
    }
    event.gaps.push_back(Issue::LegacySummaryOnly);
    return {TelemetryDisposition::Projected, evidence, std::move(event)};
}

TelemetryProjection ProjectCallbackThreadCreation(const SampleScope& scope, const EvidenceRef& evidence,
    const KSWORD_ARK_CALLBACK_MONITOR_EVENT& record)
{
    if (record.version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION || record.size != sizeof(record)) {
        return Invalid(scope, evidence);
    }
    if (record.category != KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD ||
        record.operation != KSWORD_ARK_THREAD_OP_CREATE) {
        return {};
    }
    if (!HasEvidenceLocation(scope, evidence) || record.sequence == 0 ||
        (evidence.sourceSequence && *evidence.sourceSequence != record.sequence) ||
        record.targetProcessId == 0 || record.targetThreadId == 0) {
        return Invalid(scope, evidence);
    }

    ThreadCreationObservation row;
    row.header.evidence = evidence;
    row.header.evidence.sourceSequence = record.sequence;
    row.header.operation = "callback.thread.create.v1";
    row.header.trust = InputTrust::Validated;
    row.outcome = Outcome::Succeeded;
    // 经典 PsSetCreateThreadNotifyRoutine 在创建线程的线程上下文调用，但 v1 没有任何实例创建时间。
    row.creatorPidHint = record.originatingProcessId;
    row.creatorTidHint = record.originatingThreadId;
    row.targetPidHint = record.targetProcessId;
    row.targetTidHint = record.targetThreadId;
    const auto locator = row.header.evidence;
    return {TelemetryDisposition::Projected, locator, ProjectInjectionEvent(scope, std::move(row))};
}

TelemetryProjection ProjectPassiveEtwContext(const SampleScope& scope, const EvidenceRef& evidence,
    const ks::r3::monitor::PassiveEtwRecord& record)
{
    if (!HasEvidenceLocation(scope, evidence) || evidence.sourceEpoch != record.sourceEpoch ||
        record.malformedPayload || record.payloadPrefix.size() > record.originalPayloadBytes) {
        return Invalid(scope, evidence);
    }
    TelemetryProjection result;
    result.disposition = TelemetryDisposition::ContextOnly;
    result.evidence = evidence;
    result.event.gaps.push_back(Issue::EtwContextOnly);
    if (record.payloadPrefix.size() < record.originalPayloadBytes) {
        result.event.gaps.push_back(Issue::SourcePayloadTruncated);
    }
    return result;
}

std::vector<Issue> PassiveEtwCoverageGaps(const ks::r3::monitor::PassiveEtwStatus& status)
{
    std::vector<Issue> result;
    const auto& native = status.native;
    if (status.state != ks::r3::monitor::PassiveEtwState::Stopped || !native.statisticsKnown ||
        !native.processCompleted || native.processStatus != ERROR_SUCCESS || native.tailDeliveryUnconfirmed ||
        status.headerFiltered != 0) {
        result.push_back(Issue::SourceCoverageUnknown);
    }
    if ((native.statisticsKnown && (native.eventsLost || native.logBuffersLost || native.realTimeBuffersLost)) ||
        status.queueDropped || native.callbackFailed) {
        result.push_back(Issue::SourceLoss);
    }
    if (status.payloadTruncated || status.malformedPayload) {
        result.push_back(Issue::SourcePayloadTruncated);
    }
    return result;
}

} // namespace Ksword::ActionAnalyze::Detection
