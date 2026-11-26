#include "NativeStopMemoryJournal.h"

#include "../Project/MemorySnapshotReader.h"
#include "../Project/ProjectMemorySnapshot.h"
#include "../Project/ProjectStorage.h"

#include <charconv>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
using V = JsonValue;
constexpr std::uint64_t kMemorySegmentLimit = 4096;

V Text(std::string_view value) { return V::makeString(std::string(value)); }
V Count(std::uint64_t value) { return Text(std::to_string(value)); }

NativeStopMemoryReply Invalid(const char* id, const char* message)
{
    return {false, FaultJson({id, message, std::nullopt, 1, "cli", 0, "native-stop-memory"})};
}

bool Decimal(std::string_view text, std::uint64_t& value)
{
    if (text.empty() || text.front() == '0') return false;
    const auto read = std::from_chars(text.data(), text.data() + text.size(), value);
    return read.ec == std::errc{} && read.ptr == text.data() + text.size() && value != 0;
}

bool String(const V* value, std::string& text) { return value && value->tryGetString(text); }

V Boundary(const std::optional<archive::RawEvidenceBoundary>& value)
{
    return value ? V::makeObject({{"byteOffset", Count(value->byteOffset)}, {"blockOrdinal", Count(value->blockOrdinal)},
        {"lastSequence", Count(value->lastSequence)}}) : V::makeNull();
}

V Stop(const std::optional<control::ProcessGroupStop>& stop)
{
    return stop ? V::makeObject({{"pid", V::makeUInt(stop->target.pid)}, {"creationFileTime", Count(stop->target.creationFileTime)},
        {"groupId", Text(stop->groupId)}, {"stopId", Text(stop->stopId)},
        {"backendInstanceId", Text(stop->event.backendInstanceId)}, {"eventSerial", Count(stop->event.serial)},
        {"stateRevision", Count(stop->stateRevision)}}) : V::makeNull();
}

V Context(const control::ProcessMemorySnapshotResult& capture)
{
    return V::makeObject({{"source", Text("held-event")}, {"stage", Text(capture.stage)},
        {"win32Error", V::makeUInt(capture.win32Error)}, {"before", Stop(capture.before)}, {"after", Stop(capture.after)},
        {"heldAtBothChecks", V::makeBool(capture.heldAtBothChecks)}});
}
} // namespace

project::ProjectResult NativeStopMemoryJournal::Open(project::ProjectDocument& document,
    const std::wstring& path, std::string_view sample)
{
    project_ = &document;
    sampleId_ = sample;
    const auto initialize = [&]() -> project::ProjectResult {
        std::uint64_t count = 0;
        if (const auto status = InspectNativeJournalLane(path, sample, L"raw-memory", count); !status) return status;
        if (count > kMemorySegmentLimit) return storage::Failure(project::ProjectError::LimitExceeded, "memorySnapshotCount");
        for (std::uint64_t ordinal = 1; ordinal <= count; ++ordinal) {
            project::ArchivedMemorySnapshot checked;
            nextOrdinal_ = ordinal;
            if (const auto status = project::ReadMemorySnapshot(document, sample, ordinal, previousSequence_, checked); !status)
                return status;
            previousSequence_ = checked.boundary.lastSequence;
        }
        nextOrdinal_ = count + 1;
        return {};
    };
    if (const auto status = initialize(); !status) {
        // 旧内存坏段仅禁用本lane，不能阻止同一采样的原生执行证据保存。
        failedWrite_ = V::makeObject({{"projectId", Text(document.Info()->projectId)}, {"sampleId", Text(sampleId_)},
            {"stream", Text("raw-memory")}, {"ordinal", Count(nextOrdinal_)}, {"exitCode", V::makeUInt(3)},
            {"appendBlocked", V::makeBool(true)}, {"segmentVerified", V::makeBool(false)},
            {"error", V::makeObject({{"errorId", Text(project::ProjectErrorName(status.error))},
                {"stage", Text(status.detail)}, {"win32Error", V::makeUInt(status.nativeError)}})}});
    }
    return {};
}

V NativeStopMemoryJournal::Describe() const
{
    return V::makeObject({{"stream", Text("raw-memory")}, {"nextOrdinal", Count(nextOrdinal_)},
        {"segmentLimit", Count(kMemorySegmentLimit)}, {"appendBlocked", V::makeBool(failedWrite_.has_value())},
        {"failure", failedWrite_ ? *failedWrite_ : V::makeNull()}});
}

NativeStopMemoryReply NativeStopMemoryJournal::Capture(const Request& request, bool jsonl,
    const control::OwnerIdentity& identity, control::NativeDebugOwner& owner)
{
    std::string base, bytes, stop, revision;
    if (jsonl) {
        const auto* params = request.params.asObject();
        const auto* expected = request.expected ? request.expected->asObject() : nullptr;
        if (!request.session || request.session->id != identity.sessionId || request.session->epoch != identity.epoch ||
            !params || params->size() != 2 || !String(request.params.find("base"), base) || !String(request.params.find("bytes"), bytes) ||
            !expected || expected->size() != 2 || !String(request.expected->find("stopId"), stop) ||
            !String(request.expected->find("stateRevision"), revision))
            return Invalid("invalid-memory-snapshot", "Require current session, decimal-string base/bytes and exact expected stopId/stateRevision");
    } else {
        const auto* args = request.params.asArray();
        if (request.expected || !args || args->size() != 4 || !(*args)[0].tryGetString(base) || !(*args)[1].tryGetString(bytes) ||
            !(*args)[2].tryGetString(stop) || !(*args)[3].tryGetString(revision))
            return Invalid("invalid-memory-snapshot", "Usage: memory-snapshot BASE BYTES STOP_ID STATE_REVISION (positive decimal values)");
    }
    control::ProcessMemorySnapshotRequest capture;
    std::uint64_t expectedRevision = 0;
    if (stop.empty() || stop.size() > kRequestIdBytes || !Decimal(revision, expectedRevision))
        return Invalid("invalid-memory-stop", "Require a stopId and a canonical positive decimal revision");
    if (!Decimal(base, capture.plan.range.base) || !Decimal(bytes, capture.plan.range.length) ||
        capture.plan.range.base > UINT64_MAX - capture.plan.range.length)
        return Invalid("invalid-memory-range", "Require a positive decimal range without overflow");
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    if (!system.dwPageSize || (capture.plan.range.base + capture.plan.range.length - 1) / system.dwPageSize -
        capture.plan.range.base / system.dwPageSize >= memory::kMaxTrackedPages)
        return Invalid("invalid-memory-range", "The selected range may cover at most 64 pages");
    if (!project_ || identity.sampleId != sampleId_)
        return Invalid("memory-snapshot-unavailable", "Memory capture requires this project sample");
    if (failedWrite_) return {false, *failedWrite_};
    if (nextOrdinal_ > kMemorySegmentLimit)
        return Invalid("memory-snapshot-limit", "raw-memory supports at most 4096 segments per sample");

    // 先核对调用者显示的ID/修订，再冻结同一活owner完整令牌。读取核心会再次前后核对。
    const auto state = owner.Query();
    if (state.status != control::NativeControlStatus::Held || !state.group || !state.responsibility || !state.pending ||
        state.group->state != control::GroupState::HeldComplete || state.group->historical ||
        state.responsibility->stopId != stop || state.group->stateRevision != expectedRevision ||
        state.group->sampleId != identity.sampleId || state.group->sessionId != identity.sessionId || state.group->epoch != identity.epoch ||
        state.pending->event.backendInstanceId != identity.backendInstanceId)
        return Invalid("stale-memory-stop", "Query the current complete owned stop before reading memory");
    capture.source = control::ProcessMemorySource::HeldEvent;
    capture.stop = control::ProcessGroupStop{{state.pid, state.processCreationTime}, state.group->groupId, stop,
        state.pending->event, expectedRevision};
    capture.plan.sampleId = sampleId_;
    if (!storage::NewId(capture.plan.trackingEpoch))
        return Invalid("memory-identity-failed", "Could not allocate the snapshot identity");
    capture.plan.target = {identity.sessionId, identity.epoch, state.processInstanceId, state.pid, state.processCreationTime};
    capture.plan.authorizedOwnedProcess = true;
    capture.plan.rounds.reset();
    const auto captured = control::CaptureNativeStopMemory(owner, identity, capture);
    if (!captured.snapshot) {
        return {false, V::makeObject({{"errorId", Text("memory-read-not-started")}, {"exitCode", V::makeUInt(3)},
            {"projectId", Text(project_->Info()->projectId)}, {"sampleId", Text(sampleId_)}, {"readContext", Context(captured)}})};
    }
    project::ProjectMemorySnapshotReceipt receipt;
    auto written = project::WriteProcessGroupMemorySnapshot(*project_, sampleId_, nextOrdinal_, previousSequence_, captured, receipt);
    project::ArchivedMemorySnapshot archived;
    if (written) written = project::ReadMemorySnapshot(*project_, sampleId_, nextOrdinal_, previousSequence_, archived);
    JsonArray pages;
    if (written) {
        for (const auto& page : archived.pages) pages.push_back(V::makeObject({{"recordSequence", Count(page.sequence)},
            {"recordOffset", Count(page.offset)}, {"validLength", Count(page.bytes.size())}, {"observation", page.metadata}}));
    }
    const auto* readContext = written ? archived.plan.find("readContext") : nullptr;
    const auto code = !written ? 3u : archived.completeRange && captured.heldAtBothChecks ? 0u : 6u;
    auto report = V::makeObject({{"projectId", Text(project_->Info()->projectId)}, {"sampleId", Text(sampleId_)},
        {"stream", Text("raw-memory")}, {"ordinal", Count(nextOrdinal_)}, {"exitCode", V::makeUInt(code)},
        {"segmentVerified", V::makeBool(written && receipt.verified)},
        {"sha256", receipt.sha256.empty() ? V::makeNull() : Text(receipt.sha256)},
        {"capturedBytes", Count(receipt.capturedBytes)}, {"unavailablePages", Count(receipt.unavailablePages)},
        {"completeRange", V::makeBool(receipt.completeRange)}, {"atomicProcessSnapshot", V::makeBool(false)},
        {"readContext", readContext ? *readContext : Context(captured)},
        {"plan", written ? archived.plan : V::makeNull()}, {"end", written ? archived.end : V::makeNull()},
        {"pages", V::makeArray(std::move(pages))},
        {"raw", V::makeObject({{"written", Boundary(receipt.raw.written)}, {"flushed", Boundary(receipt.raw.flushed)},
            {"status", V::makeUInt(static_cast<unsigned>(receipt.raw.result.status))},
            {"issue", V::makeUInt(static_cast<unsigned>(receipt.raw.result.error.issue))},
            {"errorOffset", Count(receipt.raw.result.error.offset)}, {"win32Error", V::makeUInt(receipt.raw.result.error.win32Error)},
            {"inputIssue", V::makeUInt(static_cast<unsigned>(receipt.raw.inputIssue))},
            {"rejectedInput", receipt.raw.rejectedInput ? Count(*receipt.raw.rejectedInput) : V::makeNull()}})},
        {"error", written ? V::makeNull() : V::makeObject({{"errorId", Text(project::ProjectErrorName(written.error))},
            {"stage", Text(written.detail)}, {"win32Error", V::makeUInt(written.nativeError)}})},
        {"appendBlocked", V::makeBool(!written)}});
    if (!written) {
        failedWrite_ = report;
        return {false, std::move(report)};
    }
    previousSequence_ = archived.boundary.lastSequence;
    ++nextOrdinal_; // 同事件不同时间/范围仍是新读取，不按执行event去重。
    return {true, std::move(report)};
}
} // namespace ks::cli::action_analyze
