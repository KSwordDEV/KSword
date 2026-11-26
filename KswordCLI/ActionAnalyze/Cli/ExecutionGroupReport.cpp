#include "ExecutionGroupProtocol.h"

namespace ks::cli::action_analyze::execution_group {
namespace {
using V = JsonValue;
namespace n = control;
V Text(std::string_view s) { return V::makeString(std::string(s)); }
V Count(std::uint64_t v) { return Text(std::to_string(v)); }
V Event(const n::NativeEventKey& event)
{
    return V::makeObject({{"backendInstanceId", Text(event.backendInstanceId)}, {"serial", Count(event.serial)}});
}
V Owner(const n::OwnerIdentity& owner)
{
    return V::makeObject({{"sampleId", Text(owner.sampleId)}, {"sessionId", Text(owner.sessionId)},
        {"epoch", Text(owner.epoch)}, {"backendInstanceId", Text(owner.backendInstanceId)}});
}
const char* State(n::ExecutionGroupState value)
{
    using enum n::ExecutionGroupState;
    switch (value) {
    case Idle: return "idle";
    case Active: return "active";
    case HeldPartial: return "held-partial";
    case HeldComplete: return "held-complete";
    case PartialFailure: return "partial-failure";
    case RecoveryRequired: return "recovery-required";
    case Closing: return "closing";
    case Closed: return "closed";
    }
    return "unknown";
}
const char* Action(n::ExecutionGroupAction value)
{
    using enum n::ExecutionGroupAction;
    switch (value) {
    case Start: return "start";
    case Pause: return "pause";
    case Continue: return "continue";
    case Step: return "step";
    case CancelStep: return "step-cancel";
    case Close: return "close";
    }
    return "unknown";
}
const char* NativeState(n::NativeControlStatus value)
{
    using enum n::NativeControlStatus;
    switch (value) {
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
V Condition(const n::DataWatchConditionReport& report)
{
    V last = V::makeNull();
    if (report.last) {
        const auto& decision = *report.last;
        const auto truth = decision.evaluation.truth;
        last = V::makeObject({{"event", Event(decision.event)}, {"groupId", Text(decision.groupId)},
            {"stateRevision", Count(decision.stateRevision)}, {"truth", Text(truth == Ksword::ActionAnalyze::Rules::Truth::True ?
                "true" : truth == Ksword::ActionAnalyze::Rules::Truth::False ? "false" : "unknown")},
            {"evaluationFault", V::makeUInt(static_cast<unsigned>(decision.evaluation.fault))},
            {"evaluationWorkUsed", Count(decision.evaluation.workUsed)},
            {"release", decision.release ? V::makeUInt(static_cast<unsigned>(*decision.release)) : V::makeNull()},
            {"failureStage", decision.failureStage ? Text(decision.failureStage) : V::makeNull()},
            {"releaseError", V::makeUInt(decision.releaseError)}});
    }
    return V::makeObject({{"trueCount", Count(report.trueCount)}, {"falseCount", Count(report.falseCount)},
        {"unknownCount", Count(report.unknownCount)}, {"last", std::move(last)}});
}
} // namespace

V ControlReport(const n::NativeControlResult& s)
{
    JsonObject fields{{"state", Text(NativeState(s.status))}, {"stage", Text(s.stage)}, {"win32Error", V::makeUInt(s.win32Error)},
        {"ledgerResult", V::makeUInt(static_cast<unsigned>(s.ledgerResult))}, {"attached", V::makeBool(s.attached)},
        {"clean", V::makeBool(s.clean)}, {"pid", V::makeUInt(s.pid)}, {"creationFileTime", Count(s.processCreationTime)},
        {"processInstanceId", Text(s.processInstanceId)}, {"pauseRequestId", Text(s.pauseRequestId)},
        {"stopReason", V::makeUInt(static_cast<unsigned>(s.stopReason))}};
    if (s.armedPause)
    {
        const auto& pause = *s.armedPause; // 原执行owner暂停请求与Continue/step字段分列，不把Pending当Held。
        fields.emplace_back("armedPause", V::makeObject({{"owner", Owner(pause.owner)},
            {"requestId", Text(pause.request.requestId)}, {"state", V::makeUInt(static_cast<unsigned>(pause.state))},
            {"stage", Text(pause.stage)}, {"win32Error", V::makeUInt(pause.win32Error)},
            {"groupId", pause.groupId ? Text(*pause.groupId) : V::makeNull()},
            {"event", pause.event ? Event(*pause.event) : V::makeNull()}}));
    }
    if (s.breakpoint) {
        const auto& b = *s.breakpoint;
        JsonArray ranges;
        for (const auto& r : b.executionRanges) ranges.push_back(V::makeObject({{"base", Count(r.base)},
            {"bytes", Count(r.bytes)}, {"allocationBase", Count(r.allocationBase)}}));
        fields.emplace_back("breakpoint", V::makeObject({{"requestId", Text(b.requestId)},
            {"state", V::makeUInt(static_cast<unsigned>(b.state))}, {"stage", Text(b.stage)}, {"win32Error", V::makeUInt(b.win32Error)},
            {"address", Count(b.address)}, {"moduleBase", Count(b.moduleBase)}, {"rva", V::makeUInt(b.rva)},
            {"enrolledThreads", Count(b.enrolledThreads)}, {"rangeBytes", Count(b.rangeBytes)},
            {"allocationBase", Count(b.allocationBase)}, {"regionBase", Count(b.regionBase)}, {"regionBytes", Count(b.regionBytes)},
            {"regionProtection", V::makeUInt(b.regionProtection)}, {"explicitPrivateAddress", V::makeBool(b.explicitPrivateAddress)},
            {"executionRanges", V::makeArray(std::move(ranges))}, {"allocationGenerationVerified", V::makeBool(false)}}));
    }
    if (s.breakpointHit) fields.emplace_back("hit", V::makeObject({{"requestId", Text(s.breakpointHit->requestId)},
        {"address", Count(s.breakpointHit->address)}}));
    if (s.registers) {
        std::vector<std::pair<std::string, V>> values{{"threadId", Text(s.registers->thread.threadId)}};
        for (const auto& field : control::NativeStopRegisterFields) {
            values.emplace_back(field.name, Count((*s.registers).*(field.value)));
        }
        fields.emplace_back("registers", V::makeObject(std::move(values))); // 64位数值仍以十进制字符串保真。
    }
    if (s.step) {
        const auto& step = *s.step;
        const auto token = StopToken(s);
        fields.emplace_back("step", V::makeObject({{"request", *token.find("stepRequest")},
            {"state", V::makeUInt(static_cast<unsigned>(step.state))}, {"stage", Text(step.stage)}, {"win32Error", V::makeUInt(step.win32Error)},
            {"startIp", Count(step.startIp)}, {"startSp", Count(step.startSp)},
            {"destination", step.destination ? Count(*step.destination) : V::makeNull()},
            {"observedIp", step.observedIp ? Count(*step.observedIp) : V::makeNull()},
            {"observedSp", step.observedSp ? Count(*step.observedSp) : V::makeNull()},
            {"observedEvent", step.observedEvent ? Event(*step.observedEvent) : V::makeNull()},
            {"stopGroupId", step.stopGroupId ? Text(*step.stopGroupId) : V::makeNull()},
            {"resourcesRestored", V::makeBool(step.resourcesRestored)}}));
    }
    if (s.release) {
        const auto receipt = [](const std::optional<n::ReleaseReceipt>& r) {
            return r ? V::makeObject({{"result", V::makeUInt(static_cast<unsigned>(r->result))},
                {"nativeError", r->nativeError ? V::makeUInt(*r->nativeError) : V::makeNull()}}) : V::makeNull();
        };
        fields.emplace_back("release", V::makeObject({{"requestId", s.releaseRequestId ? Text(*s.releaseRequestId) : V::makeNull()},
            {"issuedRevision", Count(s.release->issuedRevision)}, {"receipt", receipt(s.release->receipt)},
            {"readback", receipt(s.release->readback)}, {"eventRetiredOnExit", V::makeBool(s.release->eventRetiredOnExit)}}));
    }
    if (s.retirement) fields.emplace_back("retirement", V::makeObject({{"kind", Text(s.retirement->kind == n::NativeRetirementKind::Detached ?
        "detached" : "exit-event-continued")}, {"owner", Owner(s.retirement->owner)},
        {"exitEvent", s.retirement->exitEvent ? Event(*s.retirement->exitEvent) : V::makeNull()},
        {"exitCode", s.retirement->exitCode ? V::makeUInt(*s.retirement->exitCode) : V::makeNull()}}));
    if (s.firstRecoveryFailure) fields.emplace_back("firstRecoveryFailure", V::makeObject({
        {"stage", Text(s.firstRecoveryFailure->stage)}, {"win32Error", V::makeUInt(s.firstRecoveryFailure->win32Error)},
        {"owner", Owner(s.firstRecoveryFailure->owner)},
        {"pendingEvent", s.firstRecoveryFailure->pendingEvent ? Event(*s.firstRecoveryFailure->pendingEvent) : V::makeNull()},
        {"releaseRequestId", s.firstRecoveryFailure->releaseRequestId ? Text(*s.firstRecoveryFailure->releaseRequestId) : V::makeNull()}}));
    fields.emplace_back("timing", V::makeObject({{"qpcFrequency", Count(s.timing.qpcFrequency)},
        {"attachSubmittedQpc", s.timing.attachSubmittedQpc ? Count(*s.timing.attachSubmittedQpc) : V::makeNull()},
        {"eventObservedQpc", s.timing.eventObservedQpc ? Count(*s.timing.eventObservedQpc) : V::makeNull()},
        {"continueReturnedQpc", s.timing.continueReturnedQpc ? Count(*s.timing.continueReturnedQpc) : V::makeNull()}}));
    // 即便当前不可继续，原停止投影也保留用于诊断，stopToken 资格在成员层单列。
    fields.emplace_back("nativeSnapshot", StopToken(s));
    return V::makeObject(std::move(fields));
}

V Report(const n::ExecutionGroupResult& result, bool repl)
{
    JsonArray members, sessions; // sessions为完整固定成员表，包括Held、Armed与失败诊断，不能只选首行。
    for (const auto& member : result.members) {
        const auto& site = member.site;
        JsonObject config{{"pid", V::makeUInt(site.pid)}, {"creationFileTime", Count(site.creationFileTime)},
            {"condition", Text(Utf8(site.conditionSource))}};
        if (site.address) { config.emplace_back("address", Count(site.address)); config.emplace_back("rangeBytes", Count(site.rangeBytes)); }
        else {
            config.emplace_back("module", Text(Utf8(site.modulePath)));
            if (site.rva) config.emplace_back("rva", V::makeUInt(*site.rva));
            else config.emplace_back("exactExport", Text(site.exactExport));
        }
        const bool held = n::DataWatchHeldStop(member.control) != nullptr;
        const bool stepping = member.control.step.has_value();
        const bool pausable = n::OwnedExecutionGroup::MatchesPause(member.control, member.control); // 活绑定不需要旧stop。
        const auto token = StopToken(member.control);
        const auto session = SessionToken(member); // 原owner与完整当前快照始终成对输出。
        sessions.push_back(session);
        JsonObject fields{{"site", V::makeObject(std::move(config))}, {"owner", Owner(member.owner)},
            {"attachAccepted", V::makeBool(member.attachAccepted)}, {"held", V::makeBool(held)},
            {"control", ControlReport(member.control)}, {"condition", Condition(member.condition)},
            {"sessionToken", session}, {"canPause", V::makeBool(n::OwnedExecutionGroup::CanPauseMember(member))},
            {"canContinue", V::makeBool(n::OwnedExecutionGroup::CanContinueMember(member))},
            {"pauseToken", pausable ? token : V::makeNull()}, {"stopToken", held ? token : V::makeNull()}, {"stepToken", stepping ? token : V::makeNull()}};
        if (repl) {
            fields.emplace_back("replToken", pausable || held || stepping ? Text(TokenText(token)) : V::makeNull());
            fields.emplace_back("replSessionToken", Text(TokenText(session))); // REPL旧完整token列表仍接受，新列表包含显式owner。
        }
        members.push_back(V::makeObject(std::move(fields)));
    }
    V operation = V::makeNull();
    if (result.operation) {
        JsonArray outcomes;
        for (const auto& outcome : result.operation->outcomes) outcomes.push_back(V::makeObject({{"pid", V::makeUInt(outcome.pid)},
            {"creationFileTime", Count(outcome.creationFileTime)}, {"actionAttempted", V::makeBool(outcome.actionAttempted)},
            {"disposition", Text(outcome.disposition)}, {"control", ControlReport(outcome.control)}}));
        operation = V::makeObject({{"action", Text(Action(result.operation->action))}, {"admitted", V::makeBool(result.operation->admitted)},
            {"stage", Text(result.operation->stage)}, {"win32Error", V::makeUInt(result.operation->win32Error)},
            {"outcomes", V::makeArray(std::move(outcomes))}});
    }
    return V::makeObject({{"collectionId", Text(result.collectionId)}, {"state", Text(State(result.state))}, {"clean", V::makeBool(result.clean)},
        {"simultaneousFreeze", V::makeBool(false)}, {"observation", Text("sequential-member-readback")},
        {"members", V::makeArray(std::move(members))}, {"sessions", V::makeArray(std::move(sessions))}, {"operation", std::move(operation)}});
}
} // namespace ks::cli::action_analyze::execution_group
