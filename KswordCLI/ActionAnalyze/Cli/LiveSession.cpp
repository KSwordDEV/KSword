#include "LiveSession.h"

#include "Controller.h"
#include "../Project/ProjectRawEvidence.h"
#include "../Project/ProjectStorage.h"
#include "../../../shared/usermode/backend/monitor/PassiveEtwSource.h"

#include <charconv>
#include <chrono>
#include <objbase.h>

namespace ks::cli::action_analyze {
namespace {
using namespace Ksword::ActionAnalyze;
using namespace Ksword::ActionAnalyze::ProjectStorage;
using namespace ks::r3::monitor;
using Ksword::Evidence::WriteJson;
using V = JsonValue;
using Clock = std::chrono::steady_clock;
constexpr unsigned kMaxDurationMs = 120000;
constexpr unsigned kMinDurationMs = 1000;
constexpr std::size_t kBatchSize = 32;

constexpr LiveCommand kCommands[] = {
    {LiveMethod::Open, "session.open", "open", "PID CREATION_FILETIME PROVIDER_UUID DURATION_MS TITLE",
        "Start one bounded passive ETW sample in the writable project."},
    {LiveMethod::Query, "session.query", "status", "", "Read the current sample, native source status and archive receipt."},
    {LiveMethod::Stop, "session.stop", "stop", "", "Stop the source and write and verify the Stored raw segment."},
    {LiveMethod::Close, "session.close", "close", "", "Release a finalized sample. Stop it first if it is still active."},
};

Reply Reject(const char* id, const char* message, int code = 1, DWORD native = 0) {
    return {{}, {}, {id, message, {}, code, native ? "win32" : "cli", native, "live"}};
}

Reply Observation(V value, bool effect = false) {
    return {std::move(value), {}, {}, false, effect};
}

std::uint64_t FileTime(const FILETIME& time) {
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::string GuidText(const GUID& guid) {
    const auto native = GuidToString(guid);
    std::string text;
    for (std::size_t i = 1; i + 1 < native.size(); ++i) {
        const auto ch = native[i];
        text.push_back(static_cast<char>(ch >= L'A' && ch <= L'F' ? ch + (L'a' - L'A') : ch));
    }
    return text;
}

const char* SourceState(PassiveEtwState state) {
    switch (state) {
    case PassiveEtwState::Idle: return "idle";
    case PassiveEtwState::Starting: return "starting";
    case PassiveEtwState::Running: return "running";
    case PassiveEtwState::Stopping: return "stopping";
    case PassiveEtwState::Stopped: return "stopped";
    case PassiveEtwState::AccessDenied: return "access-denied";
    case PassiveEtwState::ProviderUnavailable: return "provider-unavailable";
    case PassiveEtwState::Failed: return "failed";
    case PassiveEtwState::CleanupPending: return "cleanup-pending";
    }
    return "failed";
}

V OptionalStatus(bool attempted, ULONG code) {
    return attempted ? V::makeUInt(code) : V::makeNull();
}

V SourceJson(const PassiveEtwStatus& status) {
    const auto& native = status.native;
    // Retain the first and latest STOP code and the attempt count across retries.
    const auto& stop = native.stopStatuses;
    return Object({{"state", Text(SourceState(status.state))}, {"sourceEpoch", Text(status.sourceEpoch)},
        {"inputWin32Error", V::makeUInt(status.inputError)},
        {"startWin32Error", OptionalStatus(native.startAttempted, native.startStatus)},
        {"enableWin32Error", native.providers.empty() ? V::makeNull() : V::makeUInt(native.providers.front().status)},
        {"openWin32Error", OptionalStatus(native.openAttempted, native.openStatus)},
        {"processAttempted", V::makeBool(native.processAttempted)},
        {"processWin32Error", OptionalStatus(native.processCompleted, native.processStatus)},
        {"closeWin32Error", OptionalStatus(native.closeAttempted, native.closeStatus)},
        {"firstStopWin32Error", stop.empty() ? V::makeNull() : V::makeUInt(stop.front())},
        {"lastStopWin32Error", stop.empty() ? V::makeNull() : V::makeUInt(stop.back())},
        {"stopAttempts", Number(stop.size())}, {"nativeSessionStopped", V::makeBool(native.sessionStopped)},
        {"callbackFailed", V::makeBool(native.callbackFailed)},
        {"eventsLost", OptionalStatus(native.statisticsKnown, native.eventsLost)},
        {"logBuffersLost", OptionalStatus(native.statisticsKnown, native.logBuffersLost)},
        {"realTimeBuffersLost", OptionalStatus(native.statisticsKnown, native.realTimeBuffersLost)},
        {"providerEvents", Number(status.providerEvents)}, {"headerFiltered", Number(status.headerFiltered)},
        {"enqueued", Number(status.enqueued)}, {"queued", Number(status.queued)},
        {"queueDropped", Number(status.queueDropped)}, {"payloadTruncated", Number(status.payloadTruncated)},
        {"malformedPayload", Number(status.malformedPayload)}});
}

std::string RecordMetadata(const PassiveEtwRecord& record) {
    const auto& desc = record.descriptor;
    return WriteJson(Object({{"kind", Text("etw-observation-v1")},
        {"sourceEpoch", Text(record.sourceEpoch)}, {"providerId", Text(GuidText(record.provider))},
        {"descriptor", Object({{"id", V::makeUInt(desc.id)}, {"version", V::makeUInt(desc.version)},
            {"channel", V::makeUInt(desc.channel)}, {"level", V::makeUInt(desc.level)},
            {"opcode", V::makeUInt(desc.opcode)}, {"task", V::makeUInt(desc.task)}, {"keyword", Number(desc.keyword)}})},
        {"headerPid", V::makeUInt(record.headerPid)}, {"headerTid", V::makeUInt(record.headerTid)},
        {"headerFlags", V::makeUInt(record.headerFlags)}, {"sourceFileTime100ns", Number(record.sourceFileTime100ns)},
        {"receiveQpc", record.receivedQpc ? Number(*record.receivedQpc) : V::makeNull()},
        {"qpcFrequencyHz", record.receivedQpc ? Number(record.qpcFrequencyHz) : V::makeNull()},
        {"activityId", Text(GuidText(record.activityId))},
        {"relatedActivityId", record.relatedActivityId ? Text(GuidText(*record.relatedActivityId)) : V::makeNull()},
        {"extendedDataCount", V::makeUInt(record.extendedDataCount)},
        {"originalPayloadBytes", V::makeUInt(record.originalPayloadBytes)},
        {"malformedPayload", V::makeBool(record.malformedPayload)},
        {"storedPayloadBytes", Number(record.payloadPrefix.size())}}));
}

ProjectResult AppendResult(const archive::RawEvidenceReceipt& receipt) {
    if (receipt.result.status == archive::SegmentWriteStatus::Ok) return {};
    if (receipt.result.status == archive::SegmentWriteStatus::IoError)
        return WinFailure("archiveRawWrite", receipt.result.error.win32Error);
    return Failure(ProjectError::InvalidArgument, "archiveRawInput");
}
} // namespace

struct LiveSession::State {
    std::string projectId, providerId, epoch;
    SampleInfo sample;
    std::string revisionHash, configSemanticHash;
    Handle target;
    std::uint32_t pid = 0;
    std::uint64_t created = 0;
    unsigned durationMs = 0;
    Clock::time_point deadline;
    std::string reason;
    PassiveEtwSource source;
    PassiveEtwStatus terminal;
    archive::RawEvidenceReceipt raw;
    ProjectResult archiveResult;
    bool cleanupPending = false;
    bool finalized = false;
    bool verified = false;

    V Identity() const { return Object({{"id", Text(sample.sampleId)}, {"epoch", Text(epoch)}}); }
    std::uint64_t Revision() const noexcept { return finalized ? 3 : cleanupPending ? 2 : 1; }

    V Plan(const PassiveEtwStatus& status) const {
        return Object({{"kind", Text("etw-capture-plan-v1")}, {"backend", Text("r3")},
            {"session", Identity()}, {"sourceEpoch", Text(status.sourceEpoch)},
            {"revisionId", Text(sample.revisionId)}, {"snapshotId", Text(sample.snapshotId)},
            {"revisionHash", Text(revisionHash)}, {"configSemanticHash", Text(configSemanticHash)},
            {"providerId", Text(providerId)}, {"headerPid", V::makeUInt(pid)},
            {"processCreationFileTime", Number(created)}, {"durationMs", V::makeUInt(durationMs)},
            {"headerRole", Text("record-context")}, {"sourceClock", Text("filetime-100ns")},
            {"receiveClock", Text("local-qpc")}, {"maxRecords", V::makeUInt(PassiveEtwOptions{}.maxQueuedRecords)},
            {"maxPayloadBytes", V::makeUInt(PassiveEtwOptions{}.maxPayloadBytes)}});
    }

    bool Partial() const noexcept {
        return cleanupPending || (finalized && (!verified || terminal.state != PassiveEtwState::Stopped ||
            !terminal.native.statisticsKnown || !terminal.native.processAttempted ||
            terminal.native.eventsLost || terminal.native.logBuffersLost ||
            terminal.native.realTimeBuffersLost || terminal.queueDropped || terminal.payloadTruncated ||
            terminal.malformedPayload));
    }

    V Report() const {
        const auto status = finalized ? terminal : source.status();
        return Object({{"session", Identity()}, {"projectId", Text(projectId)}, {"sampleId", Text(sample.sampleId)},
            {"stateRevision", Number(Revision())}, {"capture", Text(!finalized ?
                (cleanupPending ? "cleanup-pending" : "active") : (Partial() ? "partial" : "stopped"))},
            {"stopReason", reason.empty() ? V::makeNull() : Text(reason)}, {"plan", Plan(status)},
            {"source", SourceJson(status)}, {"archive", Object({
                {"status", Text(verified ? "raw-verified" : finalized ? "failed" : "pending")},
                {"segmentOrdinal", Number(1)},
                {"flushedBytes", raw.flushed ? Number(raw.flushed->byteOffset) : V::makeNull()},
                {"lastSequence", raw.flushed ? Number(raw.flushed->lastSequence) : V::makeNull()},
                {"error", archiveResult ? V::makeNull() : Text(archiveResult.detail)},
                {"win32Error", archiveResult.nativeError ? V::makeUInt(archiveResult.nativeError) : V::makeNull()}})}});
    }

    ProjectResult Append(archive::RawEvidenceArchive& writer) {
        const auto plan = WriteJson(Plan(terminal));
        const archive::RawEvidenceInput head{plan, {}};
        if (const auto result = AppendResult(writer.Append(std::span(&head, 1))); !result) return result;
        for (auto records = source.drain(kBatchSize); !records.empty(); records = source.drain(kBatchSize)) {
            std::vector<std::string> metadata;
            std::vector<archive::RawEvidenceInput> inputs;
            metadata.reserve(records.size());
            inputs.reserve(records.size());
            for (const auto& record : records) {
                metadata.push_back(RecordMetadata(record));
                const auto& bytes = record.payloadPrefix;
                inputs.push_back({metadata.back(), bytes.empty() ? std::string_view{} :
                    std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size())});
            }
            if (const auto result = AppendResult(writer.Append(inputs)); !result) return result;
        }
        auto coverage = source.status();
        const auto end = WriteJson(Object({{"kind", Text("etw-capture-end-v1")}, {"stopReason", Text(reason)},
            {"source", SourceJson(coverage)}}));
        const archive::RawEvidenceInput tail{end, {}};
        return AppendResult(writer.Append(std::span(&tail, 1)));
    }

    void Stop(ProjectDocument& project, std::string_view why) {
        if (finalized) return;
        if (reason.empty()) reason = why;
        cleanupPending = !source.stop();
        if (cleanupPending) return;
        terminal = source.status();
        const auto enqueued = terminal.enqueued;
        archiveResult = project.WriteRawEvidenceSegment({projectId, sample.sampleId, 1, {},
            [this](auto& writer) { return Append(writer); }}, raw);
        if (archiveResult && raw.flushed && raw.flushed->lastSequence == enqueued + 2) {
            archive::RawEvidenceScanResult checked;
            archiveResult = project.ReadRawEvidenceSegment({projectId, sample.sampleId, 1,
                raw.flushed->byteOffset, 0, {}}, checked);
            verified = archiveResult && checked.VerifiedBoundary(*raw.flushed);
        }
        if (archiveResult && !verified) archiveResult = Failure(ProjectError::Corrupt, "archiveRawVerification");
        terminal = source.status();
        target.reset();
        finalized = true;
    }
};

LiveSession::LiveSession() = default;
LiveSession::~LiveSession() = default;
std::span<const LiveCommand> LiveSession::Catalog() noexcept { return kCommands; }
bool LiveSession::HasSample() const noexcept { return static_cast<bool>(state_); }
bool LiveSession::NeedsTick() const noexcept { return state_ && !state_->finalized && !state_->cleanupPending; }
bool LiveSession::CleanupPending() const noexcept { return state_ && state_->cleanupPending; }
bool LiveSession::Incomplete() const noexcept { return state_ && state_->Partial(); }

bool LiveSession::CanFinalize(LiveMethod method, const Request& request) const {
    if (!state_ || !request.session || request.session->id != state_->sample.sampleId ||
        request.session->epoch != state_->epoch || !Fields(request.params, {}) ||
        !request.expected || !Fields(*request.expected, {"stateRevision"})) return false;
    std::uint64_t revision = 0;
    if (!GetNumber(*request.expected, "stateRevision", revision) || revision != state_->Revision()) return false;
    return (method == LiveMethod::Stop && !state_->finalized) || (method == LiveMethod::Close && state_->finalized);
}

void LiveSession::Tick(ProjectDocument& project) {
    if (!NeedsTick()) return;
    if (Clock::now() >= state_->deadline) state_->Stop(project, "duration-limit");
    else if (WaitForSingleObject(state_->target.get(), 0) == WAIT_OBJECT_0) state_->Stop(project, "target-exited");
    else {
        const auto state = state_->source.status().state;
        if (state != PassiveEtwState::Starting && state != PassiveEtwState::Running)
            state_->Stop(project, "source-unavailable");
    }
}

JsonValue LiveSession::Finish(ProjectDocument& project, std::string_view reason) {
    if (!state_) return V::makeNull();
    state_->Stop(project, reason);
    return state_->Report();
}

Reply LiveSession::Dispatch(LiveMethod method, const Request& request, ProjectDocument& project) {
    if (method == LiveMethod::Open) {
        if (request.session || !request.expected || !Fields(*request.expected, {"revisionId"}))
            return Reject("invalid-session", "Open requires expected.revisionId and omits session");
        if (state_) return Reject("session-already-open", "Close the current sample before starting another");
        const auto* info = project.Info();
        if (!info) return Reject("project-not-open", "Open a writable project first");
        if (info->access != ProjectAccess::ReadWrite) return Reject("project-read-only", "Open a writable project first");
        std::string projectId, revision, title, provider;
        std::uint64_t pid = 0, created = 0, duration = 0;
        const auto& params = request.params;
        const auto* pidField = params.find("pid");
        const auto* durationField = params.find("durationMs");
        if (!Fields(params, {"projectId", "title", "providerId", "pid", "creationFileTime", "durationMs"}) ||
            !GetUuid(params, "projectId", projectId) || !GetUuid(*request.expected, "revisionId", revision) ||
            !GetUuid(params, "providerId", provider) || !GetString(params, "title", title) || !IsText(title, kMaxTitleBytes) ||
            !GetNumber(params, "creationFileTime", created) || !created ||
            !pidField || pidField->type() != JsonType::UInt || !pidField->tryGetU64(pid) || !pid || pid > MAXDWORD ||
            !durationField || durationField->type() != JsonType::UInt || !durationField->tryGetU64(duration) ||
            duration < kMinDurationMs || duration > kMaxDurationMs)
            return Reject("invalid-params", "Expected projectId, title, providerId, PID, creation FILETIME and durationMs in 1000..120000");
        if (info->projectId != projectId || info->revisionId != revision)
            return Reject("stale-revision", "The open project or its saved revision changed");

        PassiveEtwOptions options;
        const auto wide = L"{" + WideAscii(provider) + L"}";
        if (FAILED(CLSIDFromString(wide.c_str(), &options.provider)))
            return Reject("invalid-params", "Invalid providerId");
        options.headerPid = static_cast<DWORD>(pid);
        const auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, *options.headerPid);
        if (!handle) return Reject("target-unavailable", "OpenProcess failed", 5, GetLastError());
        Handle pin(handle);
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (!GetProcessTimes(handle, &creation, &exit, &kernel, &user))
            return Reject("target-unavailable", "GetProcessTimes failed", 5, GetLastError());
        if (FileTime(creation) != created || WaitForSingleObject(handle, 0) != WAIT_TIMEOUT)
            return Reject("target-identity-mismatch", "PID and creation FILETIME do not identify a live instance", 5);

        auto next = std::make_unique<State>();
        if (const auto result = NewId(next->epoch); !result)
            return Reject("session-create-failed", result.detail, 3, result.nativeError);
        next->target = std::move(pin);
        next->projectId = std::move(projectId);
        next->providerId = std::move(provider);
        next->pid = *options.headerPid;
        next->created = created;
        next->durationMs = static_cast<unsigned>(duration);
        next->revisionHash = info->revisionHash;
        next->configSemanticHash = info->configSemanticHash;
        if (const auto result = project.CreateSample(title, next->sample); !result)
            return Reject("sample-create-failed", result.detail, 3, result.nativeError);
        state_ = std::move(next);
        state_->deadline = Clock::now() + std::chrono::milliseconds(duration);
        if (!state_->source.start(options)) state_->Stop(project, "source-unavailable");
        return Observation(state_->Report(), true);
    }

    if (!state_ || !request.session || request.session->id != state_->sample.sampleId ||
        request.session->epoch != state_->epoch)
        return Reject("session-id-mismatch", "The current controller does not own this session epoch");
    if (!Fields(request.params, {})) return Reject("invalid-params", "This method requires empty params");
    if (method == LiveMethod::Query) {
        if (request.expected) return Reject("invalid-expected", "Query omits expected");
        return Observation(state_->Report());
    }
    std::uint64_t revision = 0;
    if (!request.expected || !Fields(*request.expected, {"stateRevision"}) ||
        !GetNumber(*request.expected, "stateRevision", revision))
        return Reject("invalid-expected", "Stop and close require expected.stateRevision");
    if (revision != state_->Revision()) return Reject("stale-state-revision", "Query the current state before retrying");
    if (method == LiveMethod::Stop) {
        const bool wasActive = !state_->finalized;
        state_->Stop(project, "requested");
        return Observation(state_->Report(), wasActive);
    }
    if (!state_->finalized) return Reject("session-still-active", "Stop and finalize the sample before closing it");
    auto result = Object({{"session", state_->Identity()}, {"sampleId", Text(state_->sample.sampleId)},
        {"stateRevision", Number(4)}, {"closed", V::makeBool(true)}});
    state_.reset();
    return Observation(std::move(result), true);
}

Reply LiveSession::DispatchRepl(LiveMethod method, const JsonArray& args, ProjectDocument& project) {
    Request request;
    request.params = Object({});
    if (method == LiveMethod::Open) {
        if (!project.Info()) return Reject("project-not-open", "Open a writable project first");
        std::string pidText, created, provider, durationText, title;
        if (args.size() != 5 || !args[0].tryGetString(pidText) || !args[1].tryGetString(created) ||
            !args[2].tryGetString(provider) || !args[3].tryGetString(durationText) || !args[4].tryGetString(title))
            return Reject("invalid-params", "Usage: open PID CREATION_FILETIME PROVIDER_UUID DURATION_MS TITLE");
        const auto toUInt = [](const std::string& text) -> V {
            std::uint64_t value = 0;
            const auto end = text.data() + text.size();
            const auto parsed = std::from_chars(text.data(), end, value);
            return parsed.ec == std::errc{} && parsed.ptr == end ? V::makeUInt(value) : V::makeNull();
        };
        request.params = Object({{"projectId", Text(project.Info()->projectId)}, {"title", Text(title)},
            {"pid", toUInt(pidText)}, {"durationMs", toUInt(durationText)},
            {"creationFileTime", Text(created)}, {"providerId", Text(provider)}});
        request.expected = Object({{"revisionId", Text(project.Info()->revisionId)}});
    } else {
        if (!args.empty()) return Reject("invalid-params", "This command takes no arguments");
        if (state_) {
            request.session = RequestSession{state_->sample.sampleId, state_->epoch};
            if (method != LiveMethod::Query) request.expected = Object({{"stateRevision", Number(state_->Revision())}});
        }
    }
    auto reply = Dispatch(method, request, project);
    if (!reply.error) reply.text = WriteJson(reply.result);
    return reply;
}

} // namespace ks::cli::action_analyze
