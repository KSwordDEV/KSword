#include "NativeSessionApiCapture.h"
#include "ApiCaptureProgress.h"

#include "../Project/NativeBoundApiCapture.h"
#include "../Project/ProjectStorage.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <iostream>

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
        {"accepted", V::makeBool(result.accepted)},
        {"admissionError", Issue(result.admission)},
        {"rejection", V::makeUInt(static_cast<unsigned>(result.rejection))},
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
        // 原生REPL/JSONL与运行进度使用同一候选文档，保留实际双方坐标供后续回读。
        {"transfers", ApiCaptureTransferCandidatesJson(run.transfers)},
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

// 输入REPL或JSONL参数，返回相同强实例草稿；此层不接管控制包络与原owner。
NativeSessionApiInput PrepareNativeSessionApi(const Request& request, bool jsonl)
{
    std::uint64_t pid = 0, creation = 0, duration = 0; // 显式来源身份及有限采集时长。
    bool confirmed = false;
    bool startupProgress = false; // 显式选择才向stderr输出本次启动阶段，stdout仍是原命令响应。
    bool captureProgress = false; // 与原启动选项独立，支持只查看运行中已归档水位。
    const auto invalid = [](const char* id, const char* message) {
        return NativeSessionApiInput{std::nullopt, false, false, Invalid(id, message).result};
    }; // 参数错误沿用原协议结构，不为不同控制页面复制一套解析规则。
    if (jsonl) {
        const auto* params = request.params.asObject();
        const auto* confirm = request.params.find("confirm");
        const auto* progress = request.params.find("startupProgress"); // 仅接受两个明确进度字段，其余未知字段拒绝。
        const auto* running = request.params.find("captureProgress"); // 运行进度开关必须为bool，不接受数值代替。
        if (!params || params->size() != 4u + (progress ? 1u : 0u) + (running ? 1u : 0u) ||
            (progress && !progress->tryGetBool(startupProgress)) ||
            (running && !running->tryGetBool(captureProgress)) ||
            !UIntField(request.params.find("sourcePid"), pid) ||
            !DecimalField(request.params.find("sourceCreationFileTime"), creation) ||
            !UIntField(request.params.find("durationMs"), duration) || !confirm ||
            !confirm->tryGetBool(confirmed) || !confirmed) {
            return invalid("invalid-api-capture", "Require sourcePid:UInt, sourceCreationFileTime:decimal-string, durationMs:UInt, confirm:true, optional startupProgress:bool and captureProgress:bool");
        }
    } else {
        const auto* args = request.params.asArray();
        std::string pidText, creationText, durationText, confirmText;
        if (!args || args->size() < 4 || args->size() > 6 ||
            !(*args)[0].tryGetString(pidText) ||
            !(*args)[1].tryGetString(creationText) || !(*args)[2].tryGetString(durationText) ||
            !(*args)[3].tryGetString(confirmText) || confirmText != "confirm" ||
            !Decimal(pidText, pid) || !Decimal(creationText, creation) || !Decimal(durationText, duration)) {
            return invalid("invalid-api-capture", "Usage: api-capture PID FILETIME DURATION confirm [progress] [capture-progress] (positive decimal numbers)");
        }
        // 兼容原progress；两个选项可独立或并用，重复项与未知项均拒绝。
        for (std::size_t index = 4; index < args->size(); ++index)
        {
            std::string option; // 当前可选字面参数，不包含来源身份或控制令牌。
            if (!(*args)[index].tryGetString(option))
            {
                return invalid("invalid-api-capture", "Progress options must be strings");
            }
            if (option == "progress" && !startupProgress)
            {
                startupProgress = true;
            }
            else if (option == "capture-progress" && !captureProgress)
            {
                captureProgress = true;
            }
            else
            {
                return invalid("invalid-api-capture", "Unknown or duplicate progress option");
            }
        }
        confirmed = true; // REPL字面confirm与JSONL confirm:true具有相同授权语义。
    }
    if (pid <= 4 || pid > MAXDWORD || pid == GetCurrentProcessId() || !creation || duration < 1000 || duration > 10000) {
        return invalid("invalid-api-source", "Select another explicit process instance and durationMs 1000..10000; zero or continuous capture is not supported");
    }
    project::NativeBoundApiRequest capture; // 所有端复用同一宽度与区间限制，错误时不交付半份参数。
    capture.sourcePid = static_cast<DWORD>(pid);
    capture.sourceCreationFileTime = creation;
    capture.durationMs = static_cast<DWORD>(duration);
    capture.confirmed = confirmed;
    return {capture, startupProgress, captureProgress, V::makeNull()};
}

// 输入共享完整回执及前后原owner快照，输出原JSON结构，保持单目标和集合字段一致。
JsonValue DescribeNativeSessionApi(const project::NativeBoundApiResult& result,
    const control::NativeControlResult& before, const control::NativeControlResult& after)
{
    return Report(result, before, after);
}

NativeSessionApiReply CaptureNativeSessionApi(project::ProjectDocument& document,
    std::string_view sampleId, const Request& request, bool jsonl,
    const control::OwnerIdentity& identity, control::NativeDebugOwner& owner)
{
    if (request.expected || (jsonl && (!request.session || request.session->id != identity.sessionId ||
        request.session->epoch != identity.epoch)))
    {
        return Invalid("invalid-api-capture", "Require current session and omit expected");
    }
    const auto input = PrepareNativeSessionApi(request, jsonl); // 原单目标入口复用同一参数解析。
    if (!input.capture)
    {
        return {false, input.error};
    }
    if (identity.sampleId != sampleId) {
        return Invalid("api-capture-unavailable", "Require this native session's existing writable project and sample");
    }
    const auto before = owner.Query(); // 必须从活owner读取目标PID，不采用调用者或候选的目标值。
    const auto& capture = *input.capture; // CLI只解析协议，writer/sample及采集均由共享服务复用。
    const project::NativeBoundApiTarget nativeTarget{before.pid, before.processCreationTime, before.attached}; // 活owner纯值。
    const std::atomic_bool cancel{false}; // 有限同步区间，不在回调中接管控制指令或保存执行事件。
    ApiCaptureProgress progressOutput(input.startupProgress || input.captureProgress,
        document.Info() ? document.Info()->projectId : std::string{}); // 原打开文档身份，不新开项目或接管owner。
    project::CooperativeApiCommitted onCommitted; // 复用三种独立采集入口的同一帧格式。
    project::CooperativeApiTransferCommitted onTransfers; // 仅记录已归档候选，不授予因果或执行确认。
    if (input.captureProgress)
    {
        onCommitted = [&](const project::SampleInfo& sample, const project::ProjectApiCheckpoint& checkpoint,
            const project::CooperativeApiRuleReceipt& rules)
        {
            progressOutput.Committed(sample, checkpoint, rules);
        };
        onTransfers = [&](const project::CooperativeApiTransferReceipt& transfers)
        {
            progressOutput.Transfers(transfers);
        };
    }
    project::NativeBoundApiStartup onStartup; // 未订阅时不输出阶段，不改变原JSONL请求响应次序。
    if (input.startupProgress)
    {
        onStartup = [&](const project::NativeBoundApiProgress& progress) {
            // 每行包括原项目/采样身份；同一控制线程串行输出，不制造stdout响应或控制ACK。
            const auto value = V::makeObject({{"projectId", Text(progress.projectId)},
                {"sampleId", Text(progress.sampleId)},
                {"nativeTarget", V::makeObject({{"pid", V::makeUInt(progress.nativeTarget.pid)},
                    {"creationFileTime", Count(progress.nativeTarget.creationFileTime)}})},
                {"startup", project::ApiCaptureStartupJson(progress.startup)}});
            progressOutput.Publish(value); // stderr满时丢通知，不把原生停点恢复绑到终端读者。
        };
    }
    const auto result = project::CaptureNativeBoundApi(document, sampleId, capture, nativeTarget, cancel,
        onStartup, onCommitted, onTransfers);
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
        return {true, progressOutput.AttachDelivery(V::makeObject({{"exitCode", V::makeUInt(3)}, {"sampleId", Text(sampleId)},
            {"sampleError", Issue(result.receipt.sampleStatus)}}))};
    }
    const auto after = owner.Query(); // 仅回读原owner；API停止不释放原调试事件。
    return {true, progressOutput.AttachDelivery(Report(result, before, after))};
}
} // namespace ks::cli::action_analyze
