#include "LiveSession.h"

#include "Controller.h"
#include "PassiveApiCapture.h"
#include "../../CommandRegistry.h"
#include "../Project/ProjectEtwCheckpoint.h"
#include "../Project/ProjectEtwEvidence.h"
#include "../Project/ProjectRawEvidence.h"
#include "../Project/ProjectStorage.h"
#include "../../../shared/evidence/ActionAnalyzeEtwProvider.h"
#include "../../../shared/evidence/PassiveApiSourceDiagnosis.h"
#include "../../../shared/usermode/backend/monitor/PassiveEtwSource.h"

#include <algorithm>
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
constexpr std::size_t kSegmentRecords = 512;
constexpr auto kFlushInterval = std::chrono::seconds(1);
constexpr std::string_view kSysmonProviderId = "5770385f-c22a-43e0-bf4c-06f5698ffbd9";

constexpr LiveCommand kCommands[] = {
    {LiveMethod::Open, "session.open", "open", "PID CREATION_FILETIME PROVIDER_UUID [DURATION_MS] TITLE",
        "Start passive ETW. For a local API archive: open PID CREATION_FILETIME api=SESSION_ID ARCHIVE authorized [DURATION_MS] TITLE. Use api+etw=SESSION_ID for the same sample with KSword ETW. Omit duration to follow continuously."},
    {LiveMethod::Query, "session.query", "status", "", "Read the current sample, native source status and archive receipt."},
    {LiveMethod::Findings, "session.findings", "findings", "", "Read rules evaluated on committed API records. ETW alone has no rules configured."},
    {LiveMethod::Stop, "session.stop", "stop", "", "Stop the local capture, verify Stored evidence and report the source-specific receipt."},
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

std::optional<Reply> PinTarget(DWORD pid, std::uint64_t created, Handle& target) {
    const auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!handle) return Reject("target-unavailable", "OpenProcess failed", 5, GetLastError());
    Handle pin(handle);
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(handle, &creation, &exit, &kernel, &user))
        return Reject("target-unavailable", "GetProcessTimes failed", 5, GetLastError());
    if (FileTime(creation) != created || WaitForSingleObject(handle, 0) != WAIT_TIMEOUT)
        return Reject("target-identity-mismatch", "PID and creation FILETIME do not identify a live instance", 5);
    target = std::move(pin);
    return std::nullopt;
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
    Clock::time_point nextFlush;
    std::string reason;
    PassiveEtwSource source;
    std::unique_ptr<PassiveApiCapture> api;
    bool mixedEtw = false;
    bool apiFinished = false;
    PassiveEtwStatus terminal;
    archive::RawEvidenceReceipt raw;
    ProjectResult archiveResult;
    ProjectResult checkpointResult;
    bool cleanupPending = false;
    bool finalized = false;
    bool verified = false;
    std::uint64_t segmentOrdinal = 0;
    std::uint64_t recorded = 0;

    bool Continuous() const noexcept { return durationMs == 0; }
    ProjectEvidenceLane EtwLane() const noexcept {
        return mixedEtw ? ProjectEvidenceLane::MixedEtw : ProjectEvidenceLane::Primary;
    }

    // 复用查询回执的已提交规则结果；ETW 不参与 API 规则求值。
    V FindingsReport() const {
        if (api) {
            const auto rules = api->RulesReport(); // 当前检查点累计结果，不推进采集、归档或求值。
            return Object({{"session", Identity()}, {"sampleId", Text(sample.sampleId)},
                {"state", *rules.find("state")}, {"source", Text("api-archive-follow")},
                {"observations", *rules.find("matchedRows")}, {"latest", *rules.find("latest")}});
        }
        return Object({{"session", Identity()}, {"sampleId", Text(sample.sampleId)},
            {"state", Text("not-configured")}, {"source", V::makeNull()},
            {"observations", Number(0)}, {"latest", V::makeNull()}});
    }

    V Identity() const { return Object({{"id", Text(sample.sampleId)}, {"epoch", Text(epoch)}}); }
    std::uint64_t Revision() const noexcept { return finalized ? 3 : cleanupPending ? 2 : 1; }

    V Plan(const PassiveEtwStatus& status) const {
        JsonObject fields{{"kind", Text("etw-capture-plan-v1")}, {"backend", Text("r3")},
            {"session", Identity()}, {"sourceEpoch", Text(status.sourceEpoch)},
            {"revisionId", Text(sample.revisionId)}, {"snapshotId", Text(sample.snapshotId)},
            {"revisionHash", Text(revisionHash)}, {"configSemanticHash", Text(configSemanticHash)},
            {"providerId", Text(providerId)}, {"headerPid", V::makeUInt(pid)},
            {"processCreationFileTime", Number(created)}, {"durationMs", V::makeUInt(durationMs)},
            {"headerRole", Text("record-context")}, {"sourceClock", Text("filetime-100ns")},
            {"receiveClock", Text("local-qpc")}, {"maxRecords", V::makeUInt(PassiveEtwOptions{}.maxQueuedRecords)},
            {"maxPayloadBytes", V::makeUInt(PassiveEtwOptions{}.maxPayloadBytes)}};
        if (mixedEtw) fields.emplace_back("mixedEtw", V::makeBool(true));
        return Object(std::move(fields));
    }

    bool Partial() const noexcept {
        return cleanupPending || (finalized && (!verified || !checkpointResult || terminal.state != PassiveEtwState::Stopped ||
             !terminal.native.statisticsKnown || !terminal.native.processAttempted ||
             !terminal.native.processCompleted || terminal.native.processStatus != ERROR_SUCCESS ||
             terminal.native.tailDeliveryUnconfirmed || terminal.native.callbackFailed ||
            terminal.native.eventsLost || terminal.native.logBuffersLost ||
            terminal.native.realTimeBuffersLost || terminal.queueDropped || terminal.payloadTruncated ||
             terminal.malformedPayload || (Continuous() && recorded != terminal.enqueued)));
    }

    V EtwArchiveReport() const {
        auto archiveStatus = JsonObject{
            {"status", Text(!archiveResult ? "failed" : verified ? "raw-verified" : finalized ? "failed" : "pending")},
            {"segmentOrdinal", Number(segmentOrdinal ? segmentOrdinal : 1)},
            {"flushedBytes", raw.flushed ? Number(raw.flushed->byteOffset) : V::makeNull()},
            {"lastSequence", raw.flushed ? Number(raw.flushed->lastSequence) : V::makeNull()},
            {"error", archiveResult ? V::makeNull() : Text(archiveResult.detail)},
            {"win32Error", V::makeUInt(archiveResult.nativeError)},
            {"checkpoint", Object({{"status", Text(!archiveResult ? "raw-unavailable" : !checkpointResult ? "failed" :
                verified ? "verified" : finalized ? "raw-unavailable" : "pending")},
                {"error", checkpointResult ? V::makeNull() : Text(checkpointResult.detail)}})}};
        if (Continuous()) archiveStatus.emplace_back("recordedObservations", Number(recorded));
        return Object(std::move(archiveStatus));
    }

    bool Incomplete() const noexcept {
        return (api && api->Incomplete()) || ((!api || mixedEtw) && Partial());
    }

    V Report() const {
        const auto phase = !finalized ? (cleanupPending ? "cleanup-pending" : "active") :
            (Incomplete() ? "partial" : "stopped");
        if (api) {
            JsonObject fields{{"session", Identity()}, {"projectId", Text(projectId)}, {"sampleId", Text(sample.sampleId)},
                {"stateRevision", Number(Revision())}, {"capture", Text(phase)},
                {"stopReason", reason.empty() ? V::makeNull() : Text(reason)}, {"plan", api->Plan()},
                {"source", api->SourceReport()}, {"archive", api->ArchiveReport()}, {"readiness", api->ReadinessReport()},
                {"rules", api->RulesReport()}};
            if (mixedEtw) {
                const auto status = finalized ? terminal : source.status();
                fields.emplace_back("etw", Object({{"rawStream", Text("raw-etw")}, {"plan", Plan(status)},
                     {"source", EtwSourceReceipt(status)}, {"archive", EtwArchiveReport()}}));
            }
            return Object(std::move(fields));
        }
        const auto status = finalized ? terminal : source.status();
        return Object({{"session", Identity()}, {"projectId", Text(projectId)}, {"sampleId", Text(sample.sampleId)},
            {"stateRevision", Number(Revision())}, {"capture", Text(phase)},
            {"stopReason", reason.empty() ? V::makeNull() : Text(reason)}, {"plan", Plan(status)},
              {"source", EtwSourceReceipt(status)}, {"archive", EtwArchiveReport()}});
    }

    // 写入至多一个队列快照，只有双流检查点提交后才推进对外可见的段号。
    bool FlushContinuous(ProjectDocument& project, bool final) {
        if (!archiveResult || !checkpointResult) return false;
        auto records = source.drain(kSegmentRecords);
        if (records.empty() && !final) return true;
        const auto status = source.status();
        const auto ordinal = segmentOrdinal + 1;
        const auto previous = raw.flushed ? raw.flushed->lastSequence : 0;
        archive::RawEvidenceReceipt next;
        archiveResult = project.WriteRawEvidenceSegment({projectId, sample.sampleId, ordinal, previous,
            [&](auto& writer) -> ProjectResult {
                const auto plan = WriteJson(Plan(status));
                const archive::RawEvidenceInput head{plan, {}};
                if (const auto result = AppendResult(writer.Append(std::span(&head, 1))); !result) return result;
                const std::span observations(records);
                for (std::size_t i = 0; i < observations.size(); i += kBatchSize) {
                    if (const auto result = AppendEtwObservations(writer, observations.subspan(i,
                            (std::min)(kBatchSize, observations.size() - i))); !result) return result;
                }
                const auto end = WriteJson(Object({{"kind", Text("etw-capture-end-v1")},
                    {"stopReason", Text(final ? std::string_view(reason) : "segment-rotated")},
                    {"finalSegment", V::makeBool(final)}, {"segmentObservations", Number(records.size())},
                    {"source", EtwSourceReceipt(status)}}));
                const archive::RawEvidenceInput tail{end, {}};
                return AppendResult(writer.Append(std::span(&tail, 1)));
            }, EtwLane()}, next);
        if (!archiveResult) return false;
        if (!next.flushed || next.flushed->lastSequence <= previous ||
            next.flushed->lastSequence - previous != records.size() + 2) {
            archiveResult = Failure(ProjectError::Corrupt, "archiveRawVerification");
            return false;
        }
        const auto statistic = [known = status.native.statisticsKnown](ULONG value) -> std::optional<std::uint32_t> {
            if (!known) return std::nullopt;
            return static_cast<std::uint32_t>(value);
        };
        const archive::EtwCoverageV1 coverage{providerId, status.sourceEpoch, ordinal, previous + 1,
            next.flushed->lastSequence, records.size(), statistic(status.native.eventsLost),
            statistic(status.native.logBuffersLost), statistic(status.native.realTimeBuffersLost),
            status.queueDropped, status.payloadTruncated, status.malformedPayload};
        ProjectEtwCheckpoint checkpoint;
        checkpointResult = project.PublishEtwCheckpoint(sample.sampleId, *next.flushed, coverage, checkpoint, EtwLane());
        if (!checkpointResult) return false;
        raw = std::move(next);
        segmentOrdinal = ordinal;
        recorded += records.size();
        verified = true;
        return true;
    }

    void Stop(ProjectDocument& project, std::string_view why) {
        if (finalized) return;
        if (reason.empty()) reason = why;
        if (api && !apiFinished) {
            api->Finish(project, sample.sampleId, reason);
            apiFinished = true;
        }
        if (api && !mixedEtw) {
            finalized = true;
            return;
        }
        cleanupPending = !source.stop();
        if (cleanupPending) return;
        terminal = source.status();
        if (Continuous()) {
            FlushContinuous(project, true);
            terminal = source.status();
            target.reset();
            finalized = true;
            return;
        }
        segmentOrdinal = 1;
        // 有限采样与合作 Agent 复用同一 raw 封段和 ETW 检查点。
        archiveResult = CommitFiniteEtwEvidence(project, sample.sampleId, EtwLane(), Plan(terminal), reason,
            source, raw, checkpointResult);
        verified = static_cast<bool>(archiveResult);
        terminal = source.status();
        target.reset();
        finalized = true;
    }
};

LiveSession::LiveSession() = default;
LiveSession::~LiveSession() = default;
std::span<const LiveCommand> LiveSession::Catalog() noexcept { return kCommands; }
bool LiveSession::HasSample() const noexcept { return static_cast<bool>(state_); }
bool LiveSession::UncachedQuery() const noexcept { return state_ && (state_->api || state_->Continuous()); }
bool LiveSession::NeedsTick() const noexcept { return state_ && !state_->finalized && !state_->cleanupPending; }
bool LiveSession::CleanupPending() const noexcept { return state_ && state_->cleanupPending; }
bool LiveSession::Incomplete() const noexcept {
    return state_ && state_->Incomplete();
}

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
    const auto now = Clock::now();
    // API 只观察文件；混采仍由 ETW 侧观察被冻结的目标进程。
    if (state_->api) {
        if (!state_->Continuous() && now >= state_->deadline) {
            state_->Stop(project, "duration-limit");
        } else if (!state_->api->Tick(project, state_->sample.sampleId)) {
            state_->Stop(project, state_->api->FailureReason());
        }
        if (!state_->mixedEtw || !NeedsTick()) return;
    }
    if (!state_->Continuous() && now >= state_->deadline) state_->Stop(project, "duration-limit");
    else if (WaitForSingleObject(state_->target.get(), 0) == WAIT_OBJECT_0) state_->Stop(project, "target-exited");
    else {
        const auto status = state_->source.status();
        if (status.state != PassiveEtwState::Starting && status.state != PassiveEtwState::Running)
            state_->Stop(project, "source-unavailable");
        else if (state_->Continuous() && (now >= state_->nextFlush || status.queued >= kSegmentRecords / 2)) {
            state_->nextFlush = now + kFlushInterval;
            if (!state_->FlushContinuous(project, false)) state_->Stop(project, "archive-unavailable");
        }
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
        if (request.params.find("apiArchive")) {
            return OpenApiArchive(request, project);
        }
        std::string projectId, revision, title, provider;
        std::uint64_t pid = 0, created = 0, duration = 0;
        const auto& params = request.params;
        const auto* pidField = params.find("pid");
        const auto* durationField = params.find("durationMs");
        const bool fieldsValid = durationField ? Fields(params, {"projectId", "title", "providerId", "pid", "creationFileTime", "durationMs"}) :
            Fields(params, {"projectId", "title", "providerId", "pid", "creationFileTime"});
        if (!fieldsValid ||
            !GetUuid(params, "projectId", projectId) || !GetUuid(*request.expected, "revisionId", revision) ||
            !GetUuid(params, "providerId", provider) || !GetString(params, "title", title) || !IsText(title, kMaxTitleBytes) ||
            !GetNumber(params, "creationFileTime", created) || !created ||
            !pidField || pidField->type() != JsonType::UInt || !pidField->tryGetU64(pid) || !pid || pid > MAXDWORD ||
            (durationField && (durationField->type() != JsonType::UInt || !durationField->tryGetU64(duration) ||
                duration < kMinDurationMs || duration > kMaxDurationMs)))
            return Reject("invalid-params", "Expected projectId, title, providerId, PID, creation FILETIME and optional durationMs in 1000..120000");
        if (provider == kSysmonProviderId)
            return Reject("invalid-params", "Sysmon is not a supported ActionAnalyze provider");
        if (info->projectId != projectId || info->revisionId != revision)
            return Reject("stale-revision", "The open project or its saved revision changed");

        PassiveEtwOptions options;
        const auto wide = L"{" + WideAscii(provider) + L"}";
        if (FAILED(CLSIDFromString(wide.c_str(), &options.provider)))
            return Reject("invalid-params", "Invalid providerId");
        options.headerPid = static_cast<DWORD>(pid);
        Handle pin;
        if (auto failure = PinTarget(*options.headerPid, created, pin)) return std::move(*failure);

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
        if (const auto result = project.CreateSample(title, next->sample, revision); !result)
            return Reject("sample-create-failed", result.detail, 3, result.nativeError);
        state_ = std::move(next);
        state_->deadline = Clock::now() + std::chrono::milliseconds(duration);
        state_->nextFlush = Clock::now() + kFlushInterval;
        if (!state_->source.start(options)) state_->Stop(project, "source-unavailable");
        return Observation(state_->Report(), true);
    }

    if (!state_ || !request.session || request.session->id != state_->sample.sampleId ||
        request.session->epoch != state_->epoch)
        return Reject("session-id-mismatch", "The current controller does not own this session epoch");
    if (!Fields(request.params, {})) return Reject("invalid-params", "This method requires empty params");
    if (method == LiveMethod::Query || method == LiveMethod::Findings) {
        if (request.expected) return Reject("invalid-expected", "Query omits expected");
        return Observation(method == LiveMethod::Query ? state_->Report() : state_->FindingsReport());
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

Reply LiveSession::OpenApiArchive(const Request& request, ProjectDocument& project)
{
    const auto& params = request.params; // 只读取已有的一次授权输入描述。
    const auto& input = *params.find("apiArchive"); // 通过公开方法分支固定的对象。
    const auto* durationField = params.find("durationMs"); // 缺失表示持续跟随。
    const auto* pidField = params.find("pid"); // 授权提供的归档调用方 PID。
    const auto* authorization = input.find("authorized"); // 调用方必须作明确授权声明。
    const auto* providerField = params.find("providerId");
    const bool fieldsValid = providerField ? (durationField ?
        Fields(params, {"projectId", "title", "pid", "creationFileTime", "apiArchive", "durationMs", "providerId"}) :
        Fields(params, {"projectId", "title", "pid", "creationFileTime", "apiArchive", "providerId"})) : durationField ?
        Fields(params, {"projectId", "title", "pid", "creationFileTime", "apiArchive", "durationMs"}) :
        Fields(params, {"projectId", "title", "pid", "creationFileTime", "apiArchive"});
    std::string projectId, revision, title, path; // 冻结项目身份、标题及本地文件选择。
    std::uint64_t pid = 0, creation = 0, identity = 0, duration = 0; // 无损输入数值。
    bool authorized = false; // 显式确认前不打开任何源文件。
    if (!fieldsValid || !Fields(input, {"path", "sessionIdentity", "authorized"}) ||
        !GetUuid(params, "projectId", projectId) || !GetUuid(*request.expected, "revisionId", revision) ||
        !GetString(params, "title", title) || !IsText(title, kMaxTitleBytes) || !GetString(input, "path", path) ||
        !pidField || pidField->type() != JsonType::UInt || !pidField->tryGetU64(pid) || !pid || pid > MAXDWORD ||
        !GetNumber(params, "creationFileTime", creation) || !creation || !GetNumber(input, "sessionIdentity", identity) ||
        !identity || (durationField && (durationField->type() != JsonType::UInt || !durationField->tryGetU64(duration) ||
            duration < kMinDurationMs || duration > kMaxDurationMs))) {
        return Reject("invalid-params", "Expected projectId, title, PID, creation FILETIME and apiArchive with path, sessionIdentity and authorized");
    }
    if (!authorization || !authorization->tryGetBool(authorized) || !authorized) {
        return Reject("source-not-authorized", "apiArchive.authorized must affirm this existing local archive is authorized");
    }
    if (providerField && !IsString(params, "providerId", ks::action_analyze::etw::kProviderId)) {
        return Reject("invalid-params", "API and ETW together require the KSword-owned ETW provider");
    }

    const auto* info = project.Info(); // 已打开的唯一写项目，当前调用期间仍保持原租约。
    if (info->projectId != projectId || info->revisionId != revision) {
        return Reject("stale-revision", "The open project or its saved revision changed");
    }
    auto next = std::make_unique<State>(); // 所有资格检查通过后才发布的会话。
    next->api = std::make_unique<PassiveApiCapture>();
    PassiveEtwOptions options;
    if (providerField) {
        next->mixedEtw = true;
        next->providerId = ks::action_analyze::etw::kProviderId;
        next->pid = static_cast<std::uint32_t>(pid);
        next->created = creation;
        next->revisionHash = info->revisionHash;
        next->configSemanticHash = info->configSemanticHash;
        if (auto failure = PinTarget(next->pid, creation, next->target)) return std::move(*failure);
        const auto wide = L"{" + WideAscii(next->providerId) + L"}";
        if (FAILED(CLSIDFromString(wide.c_str(), &options.provider)))
            return Reject("invalid-params", "Invalid KSword ETW provider");
        options.headerPid = next->pid;
    }
    const PassiveApiStartRequest capture{path, projectId, revision, title,
        {identity, static_cast<std::uint32_t>(pid), creation}, static_cast<unsigned>(duration), next->mixedEtw};
    PassiveApiStartStage failedStage{};
    if (const auto result = next->api->BeginProject(project, capture, next->sample, next->epoch, failedStage); !result) {
        if (failedStage == PassiveApiStartStage::Source) {
            const auto reason = Ksword::Evidence::PassiveApiOpenFailureName(result.nativeError);
            return Reject(reason.data(), result.detail, 5, result.nativeError);
        }
        const auto* error = failedStage == PassiveApiStartStage::Sample ? "sample-create-failed" : "session-create-failed";
        return Reject(error, result.detail, 3, result.nativeError);
    }

    // 已冻结的共享后端计划与采集写端一致，CLI 只持有本端调度周期。
    next->projectId = std::move(projectId);
    next->durationMs = static_cast<unsigned>(duration);
    next->deadline = Clock::now() + std::chrono::milliseconds(duration);
    next->nextFlush = Clock::now() + kFlushInterval;
    state_ = std::move(next);
    if (state_->mixedEtw && !state_->source.start(options)) state_->Stop(project, "source-unavailable");
    return Observation(state_->Report(), true);
}

Reply LiveSession::DispatchRepl(LiveMethod method, const JsonArray& args, ProjectDocument& project) {
    Request request;
    request.params = Object({});
    if (method == LiveMethod::Open) {
        if (!project.Info()) return Reject("project-not-open", "Open a writable project first");
        std::string pidText, created, source, title;
        if (args.size() < 4 || !args[0].tryGetString(pidText) || !args[1].tryGetString(created) ||
            !args[2].tryGetString(source) || !args.back().tryGetString(title))
            return Reject("invalid-params", "Usage: help open");
        const auto toUInt = [](const std::string& text) -> V {
            std::uint64_t value = 0;
            const auto end = text.data() + text.size();
            const auto parsed = std::from_chars(text.data(), end, value);
            return parsed.ec == std::errc{} && parsed.ptr == end ? V::makeUInt(value) : V::makeNull();
        };
        JsonObject fields{{"projectId", Text(project.Info()->projectId)}, {"title", Text(title)},
            {"pid", toUInt(pidText)}, {"creationFileTime", Text(created)}};
        const bool mixed = source.starts_with("api+etw=");
        if (mixed || source.starts_with("api=")) {
            std::string path, authorization, duration;
            if ((args.size() != 6 && args.size() != 7) || !args[3].tryGetString(path) ||
                !args[4].tryGetString(authorization) || (args.size() == 7 && !args[5].tryGetString(duration)))
                return Reject("invalid-params", "Usage: open PID CREATION_FILETIME api=SESSION_ID|api+etw=SESSION_ID ARCHIVE authorized [DURATION_MS] TITLE");
            fields.emplace_back("apiArchive", Object({{"path", Text(path)},
                {"sessionIdentity", Text(std::string_view(source).substr(mixed ? 8 : 4))},
                {"authorized", V::makeBool(authorization == "authorized")}}));
            if (mixed) fields.emplace_back("providerId", Text(ks::action_analyze::etw::kProviderId));
            if (args.size() == 7) fields.emplace_back("durationMs", toUInt(duration));
        } else {
            std::string option;
            if ((args.size() != 4 && args.size() != 5) || (args.size() == 5 && !args[3].tryGetString(option)))
                return Reject("invalid-params", "Usage: open PID CREATION_FILETIME PROVIDER_UUID [DURATION_MS] TITLE");
            fields.emplace_back("providerId", Text(source));
            if (args.size() == 5) fields.emplace_back("durationMs", toUInt(option));
        }
        request.params = Object(std::move(fields));
        request.expected = Object({{"revisionId", Text(project.Info()->revisionId)}});
    } else {
        if (!args.empty()) return Reject("invalid-params", "This command takes no arguments");
        if (state_) {
            request.session = RequestSession{state_->sample.sampleId, state_->epoch};
            if (method != LiveMethod::Query && method != LiveMethod::Findings)
                request.expected = Object({{"stateRevision", Number(state_->Revision())}});
        }
    }
    auto reply = Dispatch(method, request, project);
    if (!reply.error) reply.text = WriteJson(reply.result);
    return reply;
}

} // namespace ks::cli::action_analyze
