#include "BreakpointCommand.h"

#include "../Control/NativeDebugOwner.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"
#include "../../../shared/usermode/backend/Common.h"
#include "Transport.h"

#include <charconv>
#include <cstdio>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
namespace native = control;
using V = JsonValue;
constexpr std::size_t kReleaseReplayEntries = 128;

// 这条 CLI 入口只接绝对 DOS 路径和普通 EXE，不接受命令行或 shell 语法。
bool AbsoluteImage(std::wstring_view path)
{
    return path.size() > 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\' && path.find_first_of(L"\"\r\n") == std::wstring_view::npos;
}

V Text(std::string_view text) { return V::makeString(std::string(text)); }
V Count(std::uint64_t value) { return Text(std::to_string(value)); }
std::string ReleaseId(std::uint64_t sequence) { return std::string(native::kSequencedReleasePrefix) + std::to_string(sequence); }

// 64 位地址不经 JSON Number 传递。
V Address(std::uint64_t value)
{
    char buffer[19]{};
    std::snprintf(buffer, sizeof(buffer), "0x%016llx", static_cast<unsigned long long>(value));
    return Text(buffer);
}

const char* BindingState(native::NativeBreakpointState state)
{
    using enum native::NativeBreakpointState;
    switch (state) {
    case Installing: return "installing";
    case Armed: return "armed";
    case Held: return "held";
    case Retiring: return "retiring";
    case Retired: return "retired";
    case Rejected: return "rejected";
    case RecoveryRequired: return "recovery-required";
    }
    return "unknown";
}

const char* ControlState(native::NativeControlStatus state)
{
    using enum native::NativeControlStatus;
    switch (state) {
    case Idle: return "idle";
    case Accepted: return "accepted";
    case Held: return "held";
    case Released: return "released";
    case Detached: return "detached";
    case Ended: return "ended";
    case ClosePending: return "close-pending";
    case Closed: return "closed";
    case Rejected: return "rejected";
    case RecoveryRequired: return "recovery-required";
    }
    return "unknown";
}

// 将原生持有、命中、安装数量与可继续的精确令牌分别投影。
V Report(const native::NativeControlResult& result)
{
    JsonObject body{{"state", Text(ControlState(result.status))}, {"stage", Text(result.stage)},
        {"win32Error", V::makeUInt(result.win32Error)}, {"clean", V::makeBool(result.clean)},
        {"attached", V::makeBool(result.attached)}, {"pid", V::makeUInt(result.pid)},
        {"creationFileTime", result.processCreationTime ? Count(result.processCreationTime) : V::makeNull()},
        {"processInstanceId", result.processInstanceId.empty() ? V::makeNull() : Text(result.processInstanceId)}};
    if (const auto& binding = result.breakpoint) {
        body.emplace_back("breakpoint", V::makeObject({{"state", Text(BindingState(binding->state))},
            {"stage", Text(binding->stage)}, {"win32Error", V::makeUInt(binding->win32Error)},
            {"address", binding->address ? Address(binding->address) : V::makeNull()},
            {"enrolledThreads", Count(binding->enrolledThreads)}}));
    }
    if (const auto& hit = result.breakpointHit) {
        body.emplace_back("hit", V::makeObject({{"address", Address(hit->address)},
            {"tid", result.pending ? V::makeUInt(result.pending->tid) : V::makeNull()}}));
    }
    if (result.group && result.responsibility) {
        body.emplace_back("stop", V::makeObject({{"id", Text(result.responsibility->stopId)},
            {"groupId", Text(result.group->groupId)}, {"stateRevision", Count(result.group->stateRevision)},
            {"memberCount", Count(result.group->members.size())}}));
    }
    if (result.release && result.release->receipt) {
        const auto& receipt = *result.release->receipt;
        const auto name = receipt.result == native::ReleaseResult::Continued ? "continued" :
            receipt.result == native::ReleaseResult::StillPending ? "still-pending" : "indeterminate";
        body.emplace_back("release", V::makeObject({{"result", Text(name)},
            {"win32Error", receipt.nativeError ? V::makeUInt(*receipt.nativeError) : V::makeNull()}}));
    }
    return V::makeObject(std::move(body));
}

// REPL 和 JSONL 共用原生所有者。控制线程没有 stdout，也不借用管道来保持暂停状态。
class BreakpointSession {
public:
    BreakpointSession(bool jsonl, const native::OwnerIdentity& id)
        : jsonl_(jsonl), identity_(id), owner_(id) {}

    int Run(const std::wstring& executable, native::NativeBreakpointRequest request)
    {
        if (const auto fault = transport_.Start(jsonl_)) {
            std::cerr << fault.message << '\n';
            return fault.code;
        }
        // 子进程不继承控制管道或 console；关闭调试会话按约定继续子进程，不代为终止。
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION created{};
        auto line = L"\"" + executable + L"\"";
        if (!CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, FALSE, DETACHED_PROCESS,
                nullptr, nullptr, &startup, &created)) {
            return LaunchFailed("create-process", GetLastError(), 0);
        }
        const ks::r3::common::UniqueHandle child(created.hProcess);
        const ks::r3::common::UniqueHandle initialThread(created.hThread);
        FILETIME start{}, exit{}, kernel{}, user{};
        if (!GetProcessTimes(child.get(), &start, &exit, &kernel, &user)) {
            return LaunchFailed("query-process-creation", GetLastError(), created.dwProcessId);
        }
        request.target.pid = created.dwProcessId;
        request.target.processCreationTime = (static_cast<std::uint64_t>(start.dwHighDateTime) << 32) | start.dwLowDateTime;
        const auto accepted = owner_.ArmBreakpoint(request);
        if (!Emit("hello", {}, V::makeObject({{"targetPid", V::makeUInt(request.target.pid)},
                {"targetCreationFileTime", Count(request.target.processCreationTime)}, {"control", Report(accepted)},
                {"continueProtocol", jsonl_ ? V::makeObject({{"firstRequestId", Text(ReleaseId(1))},
                    {"requestIdFormat", Text("continue/<next positive uint64 decimal>")},
                    {"replayEntries", Count(kReleaseReplayEntries)}}) : V::makeNull()}}))) {
            return End("output-lost", 3);
        }
        if (!accepted.breakpoint || accepted.status == native::NativeControlStatus::Rejected) return End("arm-rejected", 3);

        for (;;) {
            const auto input = transport_.Next();
            switch (input.kind) {
            case InputKind::Eof: return End("eof", 0);
            case InputKind::Break: return End("ctrl-break", 6);
            case InputKind::OutputLost: return End("output-lost", 3);
            case InputKind::Fatal: return End("input-failed", input.fault.code);
            case InputKind::Tick: continue;
            case InputKind::Line: break;
            }
            const auto decoded = jsonl_ ? DecodeJsonLine(input.line, RequestProfile::Live) : DecodeReplLine(input.line);
            if (decoded.error) {
                if (!Emit("error", decoded.request.id, FaultJson(decoded.error))) return End("output-lost", 3);
                continue;
            }
            if (decoded.request.method.empty()) continue;
            if (const int action = Dispatch(decoded.request); action != 0) {
                return action == 1 ? End("requested", 0) : End("output-lost", 3);
            }
        }
    }

private:
    bool Emit(std::string_view kind, std::string_view requestId, V result)
    {
        JsonObject frame{{"schemaVersion", V::makeUInt(1)}, {"type", Text(kind)},
            {"session", V::makeObject({{"id", Text(identity_.sessionId)}, {"epoch", Text(identity_.epoch)}})},
            {"streamSequence", Count(sequence_ + 1)}, {"requestId", requestId.empty() ? V::makeNull() : Text(requestId)},
            {"result", std::move(result)}};
        if (!transport_.Send(Ksword::Evidence::WriteJson(V::makeObject(std::move(frame))) + '\n')) return false;
        ++sequence_;
        return true;
    }

    int LaunchFailed(const char* stage, DWORD error, DWORD pid)
    {
        (void)Emit("summary", {}, V::makeObject({{"reason", Text(stage)}, {"win32Error", V::makeUInt(error)},
            {"targetPid", V::makeUInt(pid)}, {"clean", V::makeBool(true)}, {"exitCode", V::makeUInt(3)}}));
        (void)transport_.Finish();
        return 3;
    }

    // 保存未完成责任；无法确认清退时，不发 clean 成功回执。
    int End(std::string_view reason, int code)
    {
        auto state = owner_.Close();
        const auto deadline = GetTickCount64() + 3000;
        while (!state.clean && state.status != native::NativeControlStatus::RecoveryRequired && GetTickCount64() < deadline) {
            Sleep(20);
            state = owner_.Query();
        }
        if (!code && !state.clean) code = 6;
        const bool sent = Emit("summary", {}, V::makeObject({{"reason", Text(reason)},
            {"exitCode", V::makeUInt(code)}, {"control", Report(state)}}));
        return sent && transport_.Finish() ? code : 3;
    }

    static V ControlError(const char* id, const char* message)
    {
        const Fault fault{id, message, std::nullopt, 1, "cli", 0, "breakpoint-control"};
        return FaultJson(fault);
    }

    int Invalid(const Request& request, const char* id, const char* message)
    {
        return Emit("error", request.id, ControlError(id, message)) ? 0 : 3;
    }

    int Dispatch(const Request& request)
    {
        const auto* args = request.params.asArray();
        const auto* fields = request.params.asObject();
        const bool empty = jsonl_ ? fields && fields->empty() : args && args->empty();
        const auto method = std::string_view(request.method);
        const bool isContinue = method == "continue" || method == "control.continue";
        if (request.session && (request.session->id != identity_.sessionId || request.session->epoch != identity_.epoch))
            return Invalid(request, "wrong-session", "Session identity mismatch");
        if (jsonl_ && !isContinue && request.id.starts_with(native::kSequencedReleasePrefix))
            return Invalid(request, "reserved-request-id", "The continue/ request ID namespace is reserved for continue");
        if ((method == "quit" || method == "controller.shutdown") && empty && !request.expected) return 1;
        if ((method == "status" || method == "control.query") && empty && !request.expected)
            return Emit("response", request.id, Report(owner_.Query())) ? 0 : 3;
        if (method == "help" && !jsonl_ && empty)
            return Emit("response", {}, Text("status | continue STOP_ID STATE_REVISION | quit")) ? 0 : 3;
        if (!isContinue)
            return Invalid(request, "unsupported-method", "Use control.query, control.continue or controller.shutdown");

        std::string stop, revision;
        if (jsonl_) {
            const auto* expected = request.expected ? request.expected->asObject() : nullptr;
            const auto* stopField = request.expected ? request.expected->find("stopId") : nullptr;
            const auto* revField = request.expected ? request.expected->find("stateRevision") : nullptr;
            if (!request.session || !empty || !expected || expected->size() != 2 || !stopField || !revField ||
                !stopField->tryGetString(stop) || !revField->tryGetString(revision))
                return Invalid(request, "invalid-continue", "Continue requires session and expected stopId/stateRevision");
        } else if (!args || args->size() != 2 || !(*args)[0].tryGetString(stop) || !(*args)[1].tryGetString(revision)) {
            return Invalid(request, "invalid-continue", "Usage: continue STOP_ID STATE_REVISION");
        }
        std::uint64_t expectedRevision = 0;
        const auto parsed = std::from_chars(revision.data(), revision.data() + revision.size(), expectedRevision);
        if (stop.empty() || stop.size() > kRequestIdBytes || !expectedRevision ||
            revision != std::to_string(expectedRevision) || parsed.ec != std::errc{})
            return Invalid(request, "invalid-continue", "Invalid stopId or canonical revision");

        // 请求序号的水位不随回执窗口滚动。窗口之外的 ID 永远不能成为新副作用。
        std::uint64_t releaseSequence = 0;
        if (jsonl_) {
            const auto number = native::SequencedReleaseId(request.id);
            if (!number) return Invalid(request, "invalid-continue-request-id", "Continue requestId must be continue/<positive uint64 decimal>");
            releaseSequence = *number;
            if (const auto cached = releases_.find(releaseSequence); cached != releases_.end()) {
                if (cached->second.stop != stop || cached->second.revision != expectedRevision)
                    return Invalid(request, "request-id-conflict", "Request ID already identifies another release");
                return Emit(cached->second.type, request.id, cached->second.response) ? 0 : 3;
            }
            if (releaseSequence <= releaseSequenceHighWater_)
                return Invalid(request, "release-replay-expired", "Original continue receipt is outside the retained window; no release was attempted");
            if (releaseSequence - releaseSequenceHighWater_ != 1)
                return Invalid(request, "invalid-continue-sequence", "Continue requires the next consecutive request ID, starting at continue/1");
        }

        const auto current = owner_.Query();
        const bool live = current.group && current.responsibility && current.group->stateRevision == expectedRevision &&
            current.responsibility->stopId == stop;
        if (!jsonl_) {
            if (!live) return Invalid(request, "stale-stop", "Query the active stop before continuing");
            if (releaseSequenceHighWater_ == std::numeric_limits<std::uint64_t>::max())
                return Invalid(request, "continue-sequence-exhausted", "Continue IDs are exhausted");
            releaseSequence = ++releaseSequenceHighWater_;
        }

        const auto type = live ? "response" : "error";
        auto report = live ? Report(owner_.Continue({identity_, current.group->groupId, stop,
            current.responsibility->event, ReleaseId(releaseSequence), expectedRevision})) :
            ControlError("stale-stop", "Query the active stop before continuing");
        if (jsonl_) {
            // 对通过形状和序号校验的请求，连 stale-stop 也消费 ID，防止重放日后执行。
            releaseSequenceHighWater_ = releaseSequence;
            releases_.emplace(releaseSequence, SavedRelease{std::move(stop), expectedRevision, type, report});
            if (releases_.size() > kReleaseReplayEntries) releases_.erase(releases_.begin());
        }
        return Emit(type, request.id, std::move(report)) ? 0 : 3;
    }

    struct SavedRelease {
        std::string stop;
        std::uint64_t revision;
        const char* type;
        V response;
    };
    bool jsonl_;
    native::OwnerIdentity identity_;
    native::NativeDebugOwner owner_;
    Transport transport_;
    std::uint64_t sequence_ = 0;
    std::uint64_t releaseSequenceHighWater_ = 0;
    std::map<std::uint64_t, SavedRelease> releases_;
};

int Run(const Args& args)
{
    const auto executable = args.require(L"--exe");
    auto module = args.get(L"--module", executable);
    const auto input = args.get(L"--input", L"repl");
    if (!args.has(L"--confirm") || args.get(L"--disposition") != L"resume-detach" ||
        !AbsoluteImage(executable) || !AbsoluteImage(module) || (input != L"repl" && input != L"jsonl") ||
        args.has(L"--rva") == args.has(L"--export")) {
        throw std::invalid_argument("Require an explicitly authorized child EXE, one site, and --disposition resume-detach");
    }
    native::NativeBreakpointRequest request;
    request.modulePath = std::move(module);
    request.target.explicitlyAuthorized = true;
    request.target.disposition = native::NativeTargetDisposition::ResumeAndDetach;
    if (args.has(L"--rva")) {
        const auto rva = args.u32(L"--rva");
        if (!rva) throw std::invalid_argument("Require a nonzero instruction-boundary RVA");
        request.rva = rva;
    } else {
        const auto name = args.require(L"--export");
        if (name.empty() || name.size() > 255) throw std::invalid_argument("Invalid PE export name");
        for (const auto character : name) {
            if (character < 0x21 || character > 0x7e) throw std::invalid_argument("Require an ASCII PE export name");
            request.exportName.push_back(static_cast<char>(character));
        }
    }

    // 此会话没有项目写权限，样本及控制代次均是单次会话身份。
    using Ksword::ActionAnalyze::ProjectStorage::NewId;
    native::OwnerIdentity id;
    if (!NewId(id.sampleId) || !NewId(id.sessionId) || !NewId(id.epoch) || !NewId(id.backendInstanceId) ||
        !NewId(request.target.requestId)) return 3;
    return BreakpointSession(input == L"jsonl", id).Run(executable, std::move(request));
}
} // namespace

void RegisterBreakpointCommand()
{
    Command command;
    command.path = L"analyze breakpoint session";
    command.syntax = L"KswordCLI.exe analyze breakpoint session --exe PATH [--module PATH] (--export NAME | --rva RVA) --confirm --disposition resume-detach [--input repl|jsonl]";
    command.summary = L"Arm one process-wide execution breakpoint in an explicitly authorized AMD64 child process.";
    command.options = L"The EXE and optional loaded module use absolute DOS paths; module defaults to the EXE. Use an exact PE export or instruction-boundary RVA.";
    command.notes = L"REPL: status, continue STOP_ID STATE_REVISION, quit. JSONL continue request IDs are continue/1, continue/2, etc.; expired receipts cannot be replayed. Exit cleanup resumes/detaches; early execution before arm is not covered.";
    command.runStreaming = Run;
    addCommand(std::move(command));
}

} // namespace ks::cli::action_analyze
