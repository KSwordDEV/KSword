#include "BreakpointStepProtocol.h"

#include <charconv>
#include <cstdio>
#include <limits>

namespace ks::cli::action_analyze {
namespace {
using V = JsonValue;
namespace native = control;
constexpr std::size_t kStepReplayEntries = 128;

V Text(std::string_view value) { return V::makeString(std::string(value)); }
V Count(std::uint64_t value) { return Text(std::to_string(value)); }

// 地址沿用活控制协议的十六进制字符串，不经 JSON 浮点数传递。
V Address(std::uint64_t value)
{
    char text[19]{};
    std::snprintf(text, sizeof(text), "0x%016llx", static_cast<unsigned long long>(value));
    return Text(text);
}

Fault Error(const char* id, const char* message)
{
    return {id, message, std::nullopt, 1, "cli", 0, "breakpoint-step"};
}

// 请求代次、FILETIME 和序号统一要求无前导零的非零十进制表示。
std::optional<std::uint64_t> Decimal(std::string_view text)
{
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (!value || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        text != std::to_string(value)) return std::nullopt;
    return value;
}

std::optional<std::uint64_t> StepSequence(std::string_view id)
{
    return id.starts_with("step/") ? Decimal(id.substr(5)) : std::nullopt;
}

std::string StepId(std::uint64_t sequence) { return "step/" + std::to_string(sequence); }

const char* ModeName(native::NativeStepMode mode)
{
    using enum native::NativeStepMode;
    switch (mode) {
    case Into: return "into";
    case OverCall: return "over-call";
    case Out: return "out";
    }
    return "unknown";
}

const char* StateName(native::NativeStepState state)
{
    using enum native::NativeStepState;
    switch (state) {
    case Running: return "running";
    case Completed: return "completed";
    case Interrupted: return "interrupted";
    case Cancelled: return "cancelled";
    case Exited: return "exited";
    case RecoveryRequired: return "recovery-required";
    }
    return "unknown";
}

struct Arguments {
    std::string mode, stop, revision, thread, creation;
    std::uint64_t tid = 0;
};

// 只解析本方法自己的参数；JSONL 必须同时携带会话和精确停点预期。
std::optional<Arguments> Parse(const Request& request, bool jsonl)
{
    Arguments out;
    if (jsonl) {
        const auto* fields = request.params.asObject();
        const auto* expected = request.expected ? request.expected->asObject() : nullptr;
        const auto* mode = request.params.find("mode");
        const auto* thread = request.params.find("threadId");
        const auto* tid = request.params.find("tid");
        const auto* creation = request.params.find("threadCreationFileTime");
        const auto* stop = request.expected ? request.expected->find("stopId") : nullptr;
        const auto* revision = request.expected ? request.expected->find("stateRevision") : nullptr;
        if (!request.session || !fields || fields->size() != 4 || !expected || expected->size() != 2 ||
            !mode || !mode->tryGetString(out.mode) || !thread || !thread->tryGetString(out.thread) ||
            !tid || tid->type() != Ksword::Evidence::JsonType::UInt || !tid->tryGetU64(out.tid) ||
            !creation || !creation->tryGetString(out.creation) || !stop || !stop->tryGetString(out.stop) ||
            !revision || !revision->tryGetString(out.revision)) return std::nullopt;
    } else {
        const auto* args = request.params.asArray();
        std::string tid;
        if (!args || args->size() != 6 || request.expected || !(*args)[0].tryGetString(out.mode) ||
            !(*args)[1].tryGetString(out.stop) || !(*args)[2].tryGetString(out.revision) ||
            !(*args)[3].tryGetString(out.thread) || !(*args)[4].tryGetString(tid) ||
            !(*args)[5].tryGetString(out.creation)) return std::nullopt;
        const auto parsed = Decimal(tid);
        if (!parsed) return std::nullopt;
        out.tid = *parsed;
    }
    if ((out.mode != "into" && out.mode != "over-call" && out.mode != "out") ||
        out.stop.empty() || out.stop.size() > kRequestIdBytes || out.thread.empty() ||
        out.thread.size() > kRequestIdBytes || !out.tid || out.tid > UINT32_MAX ||
        !Decimal(out.revision) || !Decimal(out.creation)) return std::nullopt;
    return out;
}
} // namespace

// 查询和取消均通过先前接纳的客户端请求映射，不能提交任意原生继续 ID。
BreakpointStepReply BreakpointStepProtocol::Dispatch(const Request& request, bool jsonl, bool supported,
    const native::OwnerIdentity& identity, native::NativeDebugOwner& owner, std::uint64_t& nativeReleaseSequence)
{
    const bool submit = request.method == "step" || request.method == "control.step";
    const bool query = request.method == "step-status" || request.method == "control.step.query";
    const bool cancel = request.method == "step-cancel" || request.method == "control.step.cancel";
    if (!submit && !query && !cancel) return {};
    const auto fail = [](const char* id, const char* message) {
        return BreakpointStepReply{true, Error(id, message), std::nullopt};
    };
    if (!supported) return fail("step-mode-unavailable", "Step requires a single-target execution breakpoint session");
    if (request.session && (request.session->id != identity.sessionId || request.session->epoch != identity.epoch))
        return fail("wrong-session", "Session identity mismatch");
    if (jsonl && !request.session) return fail("invalid-step", "Step operations require the live session identity");
    if (!submit) {
        std::string id;
        const auto* field = request.params.find("requestId");
        const auto* args = request.params.asArray();
        const auto* object = request.params.asObject();
        if (request.expected || (jsonl ? !object || object->size() != 1 || !field || !field->tryGetString(id) :
            !args || args->size() != 1 || !(*args)[0].tryGetString(id)))
            return fail("invalid-step-query", "Provide exactly the original step requestId");
        const auto sequence = StepSequence(id);
        if (!sequence) return fail("invalid-step-request-id", "Step requestId must be step/<positive uint64 decimal>");
        const auto saved = requests_.find(*sequence);
        if (saved == requests_.end()) return fail("step-replay-expired", "Step request is not retained; no action was attempted");
        if (saved->second.error) return {true, saved->second.error, std::nullopt};
        return {true, {}, cancel ? owner.CancelStep(saved->second.nativeRequestId) : owner.QueryStep(saved->second.nativeRequestId)};
    }

    const auto args = Parse(request, jsonl);
    if (!args) return fail("invalid-step", "Require mode, frozen thread identity and expected stopId/stateRevision");
    if (!jsonl && highWater_ == std::numeric_limits<std::uint64_t>::max())
        return fail("step-sequence-exhausted", "Step request IDs are exhausted");
    const auto sequence = jsonl ? StepSequence(request.id) : std::optional<std::uint64_t>{highWater_ + 1};
    if (!sequence) return fail("invalid-step-request-id", "Step requestId must be step/<positive uint64 decimal>");
    const auto signature = CanonicalParams(V::makeArray({Text(args->mode), Text(args->stop), Text(args->revision),
        Text(args->thread), Count(args->tid), Text(args->creation)}));
    if (const auto old = requests_.find(*sequence); old != requests_.end()) {
        if (old->second.signature != signature) return fail("request-id-conflict", "Step request ID identifies different arguments");
        return {true, old->second.error, old->second.control};
    }
    if (*sequence <= highWater_) return fail("step-replay-expired", "Original step receipt is outside the retained window");
    if (*sequence - highWater_ != 1) return fail("invalid-step-sequence", "Step requires the next consecutive request ID, starting at step/1");

    SavedStep saved{signature, {}, {}, std::nullopt};
    const auto current = owner.Query();
    const auto revision = *Decimal(args->revision);
    const auto creation = *Decimal(args->creation);
    const native::NativeFrozenThread* selected = nullptr;
    for (const auto& thread : current.frozenThreads) {
        if (thread.identity.threadId == args->thread && thread.tid == args->tid && thread.creationTime == creation) {
            selected = &thread;
            break;
        }
    }
    if (current.status != native::NativeControlStatus::Held || !current.group || !current.responsibility ||
        current.group->stateRevision != revision || current.responsibility->stopId != args->stop ||
        current.responsibility->state != native::EventState::Held || !selected ||
        selected->identity != current.responsibility->actualEventThread) {
        saved.error = Error("stale-stop", "Query the active stop and its frozen origin thread before stepping");
    } else if (nativeReleaseSequence == std::numeric_limits<std::uint64_t>::max()) {
        saved.error = Error("continue-sequence-exhausted", "Native continue IDs are exhausted");
    } else {
        saved.nativeRequestId = std::string(native::kSequencedReleasePrefix) + std::to_string(++nativeReleaseSequence);
        const auto mode = args->mode == "into" ? native::NativeStepMode::Into :
            args->mode == "over-call" ? native::NativeStepMode::OverCall : native::NativeStepMode::Out;
        saved.control = owner.Step({{identity, current.group->groupId, args->stop, current.responsibility->event,
            saved.nativeRequestId, revision}, selected->identity, selected->tid, creation, mode});
    }
    highWater_ = *sequence;
    requests_.emplace(*sequence, saved);
    if (requests_.size() > kStepReplayEntries) requests_.erase(requests_.begin());
    return {true, saved.error, std::move(saved.control)};
}

// 状态取自原生所有者；客户端 step 序号仅用于找到本会话的那次原生动作。
V BreakpointStepProtocol::Report(const native::NativeStepReceipt& receipt) const
{
    V id = V::makeNull();
    for (const auto& [sequence, saved] : requests_) {
        if (saved.nativeRequestId == receipt.request.release.requestId) { id = Text(StepId(sequence)); break; }
    }
    const auto& request = receipt.request;
    return V::makeObject({{"requestId", std::move(id)}, {"mode", Text(ModeName(request.mode))},
        {"state", Text(StateName(receipt.state))}, {"stage", Text(receipt.stage)},
        {"win32Error", V::makeUInt(receipt.win32Error)}, {"threadId", Text(request.thread.threadId)},
        {"tid", V::makeUInt(request.tid)}, {"threadCreationFileTime", Count(request.threadCreationTime)},
        {"startIp", Address(receipt.startIp)}, {"startSp", Address(receipt.startSp)},
        {"destination", receipt.destination ? Address(*receipt.destination) : V::makeNull()},
        {"observedIp", receipt.observedIp ? Address(*receipt.observedIp) : V::makeNull()},
        {"observedSp", receipt.observedSp ? Address(*receipt.observedSp) : V::makeNull()},
        {"observedEvent", receipt.observedEvent ? V::makeObject({
            {"backendInstanceId", Text(receipt.observedEvent->backendInstanceId)},
            {"serial", Count(receipt.observedEvent->serial)}}) : V::makeNull()},
        {"stopGroupId", receipt.stopGroupId ? Text(*receipt.stopGroupId) : V::makeNull()},
        {"resourcesRestored", V::makeBool(receipt.resourcesRestored)}});
}

V BreakpointStepProtocol::Capabilities() const
{
    return V::makeObject({{"modes", V::makeArray({Text("into"), Text("over-call"), Text("out")})},
        {"firstRequestId", Text("step/1")}, {"requestIdFormat", Text("step/<next positive uint64 decimal>")},
        {"replayEntries", Count(kStepReplayEntries)}, {"queryMethod", Text("control.step.query")},
        {"cancelMethod", Text("control.step.cancel")}});
}

} // namespace ks::cli::action_analyze
