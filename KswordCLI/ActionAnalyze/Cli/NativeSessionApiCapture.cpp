#include "NativeSessionApiCapture.h"

#include "../Project/NativeBoundApiCapture.h"
#include "../Project/ProjectStorage.h"

#include <algorithm>
#include <atomic>
#include <charconv>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
using V = JsonValue;

V Text(std::string_view value) { return V::makeString(std::string(value)); }
V Count(std::uint64_t value) { return Text(std::to_string(value)); }

NativeSessionApiReply Invalid(const char* id, const char* message)
{
    return {false, FaultJson({id, message, std::nullopt, 1, "cli", 0, "native-session-api-capture"})};
}

// FILETIME及REPL数值严格使用无损的规范正十进制，不从显示摘要或候选补值。
bool Decimal(std::string_view text, std::uint64_t& value)
{
    if (text.empty() || text.front() == '0') return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && value != 0;
}

bool DecimalField(const V* field, std::uint64_t& value)
{
    std::string text;
    return field && field->tryGetString(text) && Decimal(text, value);
}

// PID和时长沿用JSONL的UInt字段，不能以字符串、布尔或浮点数代替。
bool UIntField(const V* field, std::uint64_t& value)
{
    return field && field->type() == Ksword::Evidence::JsonType::UInt && field->tryGetU64(value);
}

V Issue(const project::ProjectResult& status)
{
    return status ? V::makeNull() : V::makeObject({
        {"errorId", Text(project::ProjectErrorName(status.error))},
        {"stage", Text(status.detail)},
        {"win32Error", V::makeUInt(status.nativeError)}
    });
}

V Boundary(const std::optional<archive::RawEvidenceBoundary>& value)
{
    return value ? V::makeObject({
        {"byteOffset", Count(value->byteOffset)},
        {"blockOrdinal", Count(value->blockOrdinal)},
        {"lastSequence", Count(value->lastSequence)}
    }) : V::makeNull();
}

// 控制器错误原文可能包含路径或本地化文本，按UTF-8保留而非按ASCII截断。
V WideText(const std::wstring& value)
{
    if (value.empty()) return Text({});
    const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!length) return V::makeNull();
    std::string text(length, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        text.data(), length, nullptr, nullptr)) return V::makeNull();
    return V::makeString(std::move(text));
}

// 采集、归档、规则和清退分别呈现；已提交前缀不因后续失败被隐藏。
V Report(const project::NativeBoundApiResult& result, const control::NativeControlResult& nativeBefore,
    const control::NativeControlResult& nativeAfter)
{
    const auto& run = result.receipt; // 三端共用服务的原始回执，CLI仅负责JSON投影。
    const auto& projectId = result.projectId; // 原writer的冻结项目身份。
    const auto& sampleId = result.sampleId; // 原native会话的采样身份。
    const auto sourcePid = result.request.sourcePid; // 本次明确选择的来源。
    const auto sourceCreation = result.request.sourceCreationFileTime; // 来源强实例。
    const auto duration = result.request.durationMs; // Ready后有限采样时长。
    const auto& capture = run.capture; // 附加控制器的真实结果，不以归档成功替代。
    const auto source = std::find_if(capture.processes.begin(), capture.processes.end(), [&](const auto& process) {
        return process.pid == sourcePid && process.creation == sourceCreation;
    });
    const auto* process = source == capture.processes.end() ? nullptr : &*source;
    const bool connected = process && process->connected;
    const int code = result.ExitCode(); // 状态规则由共享服务定义，JSON字段保持原协议。
    JsonArray errors;
    for (const auto& error : capture.errors) errors.push_back(WideText(error));
    const auto state = [](const control::NativeControlResult& value) {
        // 只报告原owner回读结果，不在API响应中制造可释放的停点令牌。
        return V::makeObject({
            {"pid", V::makeUInt(value.pid)},
            {"creationFileTime", Count(value.processCreationTime)},
            {"stage", Text(value.stage)},
            {"attached", V::makeBool(value.attached)},
            {"held", V::makeBool(value.status == control::NativeControlStatus::Held)},
            {"clean", V::makeBool(value.clean)},
            {"win32Error", V::makeUInt(value.win32Error)}
        });
    };
    return V::makeObject({
        {"projectId", Text(projectId)},
        {"sampleId", Text(sampleId)},
        {"captureSampleId", run.sample.sampleId.empty() ? V::makeNull() : Text(run.sample.sampleId)},
        {"revisionId", run.sample.revisionId.empty() ? V::makeNull() : Text(run.sample.revisionId)},
        {"captureMode", Text("explicit-r3-attachment")},
        {"durationMs", V::makeUInt(duration)},
        {"exitCode", V::makeUInt(static_cast<unsigned>(code))},
        {"status", Text(code == 0 ? "capture-complete" : code == 6 ? "capture-partial" : "capture-failed")},
        {"sampleError", Issue(run.sampleStatus)},
        {"source", V::makeObject({
            {"pid", V::makeUInt(sourcePid)},
            {"creationFileTime", Count(sourceCreation)},
            {"reportedPid", process ? V::makeUInt(process->pid) : V::makeNull()},
            {"reportedCreationFileTime", process ? Count(process->creation) : V::makeNull()},
            {"attachmentIdentityVerified", V::makeBool(capture.attachmentIdentityVerified)},
            {"connected", V::makeBool(connected)},
            {"sessionIdentity", connected ? Count(process->session) : V::makeNull()},
            {"sessionReady", connected ? V::makeBool(process->sessionReady) : V::makeNull()},
            {"coverageRevision", connected && process->coverageComplete ? Count(process->revision) : V::makeNull()},
            {"coverageSnapshotCurrent", process ? V::makeBool(process->coverageComplete && !process->coverageStale) : V::makeNull()},
            {"partialHooks", process ? V::makeBool(process->partialHooks) : V::makeNull()},
            {"pipeError", process ? V::makeUInt(process->pipeError) : V::makeNull()},
            {"agentReportedDrops", connected ? Count(process->agentDropped) : V::makeNull()}
        })},
        {"capture", V::makeObject({
            {"code", V::makeUInt(static_cast<unsigned>(capture.code))},
            {"agentPathAvailable", V::makeBool(run.agentPathAvailable)},
            {"agentPath", WideText(capture.agentPath)},
            {"sessionId", WideText(capture.sessionId)},
            {"agentLoadAttempted", V::makeBool(capture.agentLoadAttempted)},
            {"agentModuleVerified", V::makeBool(capture.agentModuleVerified)},
            {"reusedResident", V::makeBool(capture.reusedResident)},
            {"configPublished", V::makeBool(capture.configPublished)},
            {"startup", Ksword::ActionAnalyze::ApiCaptureStartupJson(capture.startup)},
            {"started", V::makeBool(capture.started)},
            {"hooksInstalled", process ? V::makeBool(process->installed) : V::makeNull()},
            {"installFailed", process ? V::makeBool(process->installFailed) : V::makeNull()},
            {"completedInterval", V::makeBool(capture.completedInterval)},
            {"cancelled", V::makeBool(capture.cancelled)},
            {"elapsedMs", Count(capture.elapsedMs)},
            {"readyAfterMs", capture.readyAfterMs ? Count(*capture.readyAfterMs) : V::makeNull()},
            {"readyCoverageRevision", capture.readyCoverageRevision ? Count(*capture.readyCoverageRevision) : V::makeNull()},
            {"intervalElapsedMs", capture.intervalElapsedMs ? Count(*capture.intervalElapsedMs) : V::makeNull()},
            {"received", Count(capture.received)},
            {"bufferDropped", Count(capture.bufferDropped)},
            {"invalidPackets", Count(capture.invalidPackets)},
            {"preFiltered", Count(capture.preFiltered)},
            {"errors", V::makeArray(std::move(errors))}
        })},
        {"archive", V::makeObject({
            {"stream", Text("raw")},
            {"ordinaryPackets", Count(run.ordinaryPackets)},
            {"archivedPackets", Count(run.archivedPackets)},
            {"committedSegments", Count(run.committedSegments)},
            {"retainedClues", Count(run.retainedClues)},
            {"omittedClues", Count(run.omittedClues)},
            {"publishedPrefix", V::makeBool(run.committedSegments != 0)},
            {"error", Issue(run.archiveStatus)},
            {"written", Boundary(run.archive.written)},
            {"flushed", Boundary(run.archive.flushed)},
            {"rawStatus", V::makeUInt(static_cast<unsigned>(run.archive.result.status))},
            {"rawIssue", V::makeUInt(static_cast<unsigned>(run.archive.result.error.issue))},
            {"rawErrorOffset", Count(run.archive.result.error.offset)},
            {"rawWin32Error", V::makeUInt(run.archive.result.error.win32Error)}
        })},
        {"rules", V::makeObject({
            {"presetSet", Text(run.rules.presetSet)},
            {"sourceSha256", run.rules.sourceSha256.empty() ? V::makeNull() : Text(run.rules.sourceSha256)},
            {"configError", run.rules.configError.empty() ? V::makeNull() : Text(run.rules.configError)},
            {"failed", V::makeBool(run.rules.failed)},
            {"matchedRows", Count(run.rules.matchedRows)},
            {"latestSegment", Count(run.rules.latestSegment)}
        })},
        {"transfers", V::makeObject({
            {"candidateCount", Count(run.transfers.candidateCount)},
            {"apcCandidateCount", Count(run.transfers.apcCandidateCount)},
            {"contextCandidateCount", Count(run.transfers.contextCandidateCount)},
            {"evictedWrites", Count(run.transfers.evictedWrites)}
        })},
        {"cleanup", V::makeObject({
            {"complete", V::makeBool(capture.cleanupComplete)},
            {"stopMarkerWritten", V::makeBool(capture.stopWritten)},
            {"hooksRemoved", connected ? V::makeBool(process->removed) : V::makeNull()},
            {"cleanPipeEof", connected ? V::makeBool(process->cleanPipeEof) : V::makeNull()},
            {"sourceExited", process ? V::makeBool(process->exited) : V::makeNull()},
            {"requiredFinalCoverageRevision", connected && process->removed && process->finalRevision ?
                Count(process->finalRevision) : V::makeNull()}
        })},
        {"nativeBefore", state(nativeBefore)},
        {"nativeAfter", state(nativeAfter)},
        {"nativeContinueIssued", V::makeBool(false)},
        {"nativeCloseIssued", V::makeBool(false)},
        {"agentEtwRequested", V::makeBool(false)},
        {"sourceAuthenticated", V::makeBool(false)},
        {"regionVersionVerified", V::makeBool(false)},
        {"causalityConfirmed", V::makeBool(false)},
        {"commonClockVerified", V::makeBool(false)},
        {"limitations", Text("Same-sample storage only; API source and native target remain distinct. No native event was automatically saved. Capture, archive and cleanup results are independent; no causal or source-authentication claim.")}
    });
}
} // namespace

NativeSessionApiReply CaptureNativeSessionApi(project::ProjectDocument& document,
    std::string_view sampleId, const Request& request, bool jsonl,
    const control::OwnerIdentity& identity, control::NativeDebugOwner& owner)
{
    std::uint64_t pid = 0, creation = 0, duration = 0; // 显式来源身份及有限采集时长。
    bool confirmed = false;
    if (jsonl) {
        const auto* params = request.params.asObject();
        const auto* confirm = request.params.find("confirm");
        if (!request.session || request.session->id != identity.sessionId || request.session->epoch != identity.epoch ||
            request.expected || !params || params->size() != 4 ||
            !UIntField(request.params.find("sourcePid"), pid) ||
            !DecimalField(request.params.find("sourceCreationFileTime"), creation) ||
            !UIntField(request.params.find("durationMs"), duration) || !confirm ||
            !confirm->tryGetBool(confirmed) || !confirmed) {
            return Invalid("invalid-api-capture", "Require current session and only sourcePid:UInt, sourceCreationFileTime:decimal-string, durationMs:UInt, confirm:true; omit expected");
        }
    } else {
        const auto* args = request.params.asArray();
        std::string pidText, creationText, durationText, confirmText;
        if (request.expected || !args || args->size() != 4 || !(*args)[0].tryGetString(pidText) ||
            !(*args)[1].tryGetString(creationText) || !(*args)[2].tryGetString(durationText) ||
            !(*args)[3].tryGetString(confirmText) || confirmText != "confirm" ||
            !Decimal(pidText, pid) || !Decimal(creationText, creation) || !Decimal(durationText, duration)) {
            return Invalid("invalid-api-capture", "Usage: api-capture PID FILETIME DURATION confirm (positive decimal numbers)");
        }
        confirmed = true; // REPL字面confirm与JSONL confirm:true具有相同授权语义。
    }
    if (pid <= 4 || pid > MAXDWORD || pid == GetCurrentProcessId() || !creation || duration < 1000 || duration > 10000) {
        return Invalid("invalid-api-source", "Select another explicit process instance and durationMs 1000..10000; zero or continuous capture is not supported");
    }
    if (identity.sampleId != sampleId) {
        return Invalid("api-capture-unavailable", "Require this native session's existing writable project and sample");
    }
    const auto before = owner.Query(); // 必须从活owner读取目标PID，不采用调用者或候选的目标值。
    project::NativeBoundApiRequest capture; // CLI只解析协议，writer/sample及采集均由共享服务复用。
    capture.sourcePid = static_cast<DWORD>(pid);
    capture.sourceCreationFileTime = creation;
    capture.durationMs = static_cast<DWORD>(duration);
    capture.confirmed = confirmed;
    const project::NativeBoundApiTarget nativeTarget{before.pid, before.processCreationTime, before.attached}; // 活owner纯值。
    const std::atomic_bool cancel{false}; // 有限同步区间，不在回调中接管控制指令或保存执行事件。
    const auto result = project::CaptureNativeBoundApi(document, sampleId, capture, nativeTarget, cancel); // 原writer调用。
    if (result.rejection == project::NativeBoundApiRejection::NativeUnavailable) {
        return Invalid("native-owner-unavailable", "Query an attached native owner before capturing another source process");
    }
    if (result.rejection == project::NativeBoundApiRejection::SourceIsNativeTarget) {
        return Invalid("api-source-is-native-target", "The API source must not be the process controlled by this native owner");
    }
    if (!result.accepted) {
        return Invalid("api-capture-unavailable", "Require this native session's existing writable project and sample");
    }
    // 原采样本身读失败保留原短错误响应；采集与封段后的失败仍使用完整Report。
    if (!result.receipt.sampleStatus && result.receipt.sample.sampleId.empty())
    {
        return {true, V::makeObject({{"exitCode", V::makeUInt(3)}, {"sampleId", Text(sampleId)},
            {"sampleError", Issue(result.receipt.sampleStatus)}})};
    }
    const auto after = owner.Query(); // 仅回读原owner；API停止不释放原调试事件。
    return {true, Report(result, before, after)};
}
} // namespace ks::cli::action_analyze
