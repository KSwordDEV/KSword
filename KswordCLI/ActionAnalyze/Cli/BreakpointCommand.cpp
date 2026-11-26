#include "BreakpointCommand.h"

#include "../Control/NativeDebugOwner.h"
#include "../Control/OwnedBreakpointGroup.h"
#include "../Project/ProjectStorage.h"
#include "../Rules/RuleExpression.h"
#include "../../CommandRegistry.h"
#include "../../../shared/usermode/backend/Common.h"
#include "Transport.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
namespace native = control;
namespace rules = Ksword::ActionAnalyze::Rules;
using V = JsonValue;
constexpr std::size_t kReleaseReplayEntries = 128;

// Rules 的 Entry 阶段在此指原生执行进入尝试。
constexpr auto kConditionPhase = rules::Phase::Entry;
constexpr rules::FieldBinding kConditionFields[] = {
    {"stop.address", rules::FieldType::U64, kConditionPhase},
    {"stop.exceptionCode", rules::FieldType::U64, kConditionPhase},
    {"stop.firstChance", rules::FieldType::Bool, kConditionPhase},
    {"stop.pid", rules::FieldType::U64, kConditionPhase},
    {"stop.thread.creationFileTime", rules::FieldType::U64, kConditionPhase},
    {"stop.thread.rax", rules::FieldType::U64, kConditionPhase}, // 本切片未采集。
    {"stop.thread.rip", rules::FieldType::U64, kConditionPhase},
    {"stop.tid", rules::FieldType::U64, kConditionPhase},
};

struct BreakpointCondition {
    std::string expression;
    rules::PreparedPredicate predicate;
};

BreakpointCondition PrepareCondition(std::wstring_view wide)
{
    if (wide.size() > rules::MaxPredicateExpressionBytes)
        throw std::invalid_argument("--condition expression-byte-limit (max 8192 UTF-8 bytes)");
    std::string expression;
    if (!wide.empty()) {
        const auto length = static_cast<int>(wide.size());
        const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), length, nullptr, 0, nullptr, nullptr);
        if (!bytes) throw std::invalid_argument("--condition invalid Unicode");
        expression.resize(bytes);
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), length, expression.data(), bytes, nullptr, nullptr) != bytes)
            throw std::invalid_argument("--condition invalid Unicode");
    }
    auto result = rules::PreparePredicateExpression(expression, kConditionPhase, kConditionFields);
    if (result.error != rules::ExpressionError::None) {
        std::string diagnostic(rules::ExpressionErrorId(result.error));
        switch (result.preparationError) {
        case rules::PrepareError::UnknownField: diagnostic += " (unknown-field)"; break;
        case rules::PrepareError::FieldNotInPhase: diagnostic += " (field-not-in-phase)"; break;
        case rules::PrepareError::TypeMismatch: diagnostic += " (type-mismatch)"; break;
        case rules::PrepareError::UnsupportedOperator: diagnostic += " (unsupported-operator)"; break;
        default: break;
        }
        const auto& at = result.location;
        throw std::invalid_argument("--condition " + diagnostic + " at UTF-8 byte " + std::to_string(at.offset) +
            " (length " + std::to_string(at.length) + ", line " + std::to_string(at.line) +
            ", byte column " + std::to_string(at.byteColumn) + ")");
    }
    return {std::move(expression), std::move(result.predicate)};
}

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

const char* ReleaseState(native::ReleaseResult result)
{
    return result == native::ReleaseResult::Continued ? "continued" :
        result == native::ReleaseResult::StillPending ? "still-pending" : "indeterminate";
}

// 将账本中的停止组状态映射为协议名称。无法投影的原生持有仍保留独立状态。
const char* StopGroupState(native::GroupState state)
{
    using enum native::GroupState;
    switch (state) {
    case GroupBuilding: return "group-building";
    case OriginHeld: return "origin-held";
    case HeldComplete: return "held-complete";
    case HeldPartial: return "held-partial";
    case NotHeld: return "not-held";
    case ReleasePending: return "release-pending";
    case Released: return "released";
    case RecoveryRequired: return "recovery-required";
    case Ended: return "ended";
    case UnprojectableNativeHold: return "unprojectable-native-hold";
    }
    return "unknown";
}

// 从同一冻结组统计成员状态。附带线程及范围完整性不计入请求成员。
V ReportStopGroup(const native::StopGroupSnapshot& group)
{
    using native::MemberState;
    std::uint64_t held = 0; // 已核验受本事件覆盖的冻结线程。
    std::uint64_t unresolved = 0; // 收集待定或没有充分覆盖证据的成员。
    std::uint64_t exited = 0; // 已有退出观察的成员。
    std::uint64_t releasing = 0; // 已持有且等待继续或恢复回执的成员。
    for (const auto& member : group.members) {
        switch (member.state) {
        case MemberState::Held: ++held; break;
        case MemberState::Pending:
        case MemberState::Unknown: ++unresolved; break;
        case MemberState::Exited: ++exited; break;
        case MemberState::ReleasePending:
        case MemberState::RecoveryRequired: ++releasing; break;
        default: break;
        }
    }
    // 组在继续后仍可回读。历史投影不包含可再次提交的继续令牌。
    return V::makeObject({{"id", Text(group.groupId)}, {"state", Text(StopGroupState(group.state))},
        {"stateRevision", Count(group.stateRevision)}, {"membershipRevision", Count(group.membershipRevision)},
        {"membershipSha256", Text(group.membershipSha256)}, {"requestedMembers", Count(group.members.size())},
        {"heldMembers", Count(held)}, {"unresolvedMembers", Count(unresolved)}, {"exitedMembers", Count(exited)},
        {"releasePendingMembers", Count(releasing)}, {"incidentalMembers", Count(group.incidentalThreadIds.size())},
        {"incidentalQuality", Text(group.incidentalQuality == native::IncidentalQuality::Verified ? "verified" :
            group.incidentalQuality == native::IncidentalQuality::Partial ? "partial" : "not-collected")},
        {"historical", V::makeBool(group.historical)}});
}

// 由原生停点来源的稳定线程 ID 查找冻结成员。没有对应成员时不从当前 PID/TID 反查。
const native::NativeFrozenThread* FrozenOriginThread(const native::NativeControlResult& result)
{
    if (!result.group || !result.group->origin) {
        return nullptr;
    }
    const auto& id = result.group->origin->threadId; // 原生账本记录的触发线程身份。
    const auto thread = std::find_if(result.frozenThreads.begin(), result.frozenThreads.end(),
        [&](const auto& member) { return member.identity.threadId == id; });
    return thread == result.frozenThreads.end() ? nullptr : &*thread;
}

// 事件流水号仅在所属原生后端内唯一；没有事件凭据时保留空值。
V ReportNativeEvent(const std::optional<native::NativeEventKey>& event)
{
    return event ? V::makeObject({{"backendInstanceId", Text(event->backendInstanceId)},
        {"serial", Count(event->serial)}}) : V::makeNull();
}

// 将原生持有、命中、安装数量与可继续的精确令牌分别投影。
JsonObject ReportFields(const native::NativeControlResult& result, bool includeStop = true)
{
    JsonObject body{{"state", Text(ControlState(result.status))}, {"stage", Text(result.stage)},
        {"win32Error", V::makeUInt(result.win32Error)}, {"clean", V::makeBool(result.clean)},
        {"attached", V::makeBool(result.attached)}, {"pid", V::makeUInt(result.pid)},
        {"creationFileTime", result.processCreationTime ? Count(result.processCreationTime) : V::makeNull()},
        {"processInstanceId", result.processInstanceId.empty() ? V::makeNull() : Text(result.processInstanceId)}};
    if (const auto& binding = result.breakpoint) {
        JsonObject fields{{"state", Text(BindingState(binding->state))},
            {"stage", Text(binding->stage)}, {"win32Error", V::makeUInt(binding->win32Error)},
            {"address", binding->address ? Address(binding->address) : V::makeNull()},
            {"enrolledThreads", Count(binding->enrolledThreads)}}; // 当前实际安装的线程数。
        if (binding->writeWatchBytes) {
            fields.emplace_back("watchedBytes", V::makeUInt(binding->writeWatchBytes));
        }
        body.emplace_back("breakpoint", V::makeObject(std::move(fields)));
    }
    if (const auto& hit = result.breakpointHit) {
        JsonObject fields{{"address", Address(hit->address)}};
        // 数据停点的身份从冻结组取，继续后仍可核对。
        V tid = !hit->dataChange && result.pending ? V::makeUInt(result.pending->tid) : V::makeNull();
        if (const auto& change = hit->dataChange) {
            fields.emplace_back("phase", Text("data-write-observed"));
            fields.emplace_back("watchedBytes", V::makeUInt(change->watchedBytes));
            fields.emplace_back("changedByteMask", V::makeUInt(change->changedByteMask));
            fields.emplace_back("enrolledAfterStop", Count(change->enrolledAfterStop));
            if (const auto* thread = FrozenOriginThread(result)) {
                tid = V::makeUInt(thread->tid);
                fields.emplace_back("threadId", Text(thread->identity.threadId));
                fields.emplace_back("threadCreationFileTime", Count(thread->creationTime));
            }
        }
        fields.emplace_back("tid", std::move(tid));
        body.emplace_back("hit", V::makeObject(std::move(fields)));
    }
    if (result.group) {
        body.emplace_back("stopGroup", ReportStopGroup(*result.group));
    }
    if (includeStop && result.group && result.responsibility) {
        body.emplace_back("stop", V::makeObject({{"id", Text(result.responsibility->stopId)},
            {"groupId", Text(result.group->groupId)}, {"stateRevision", Count(result.group->stateRevision)},
            {"memberCount", Count(result.group->members.size())}}));
    }
    if (result.release && result.release->receipt) {
        const auto& receipt = *result.release->receipt;
        body.emplace_back("release", V::makeObject({{"result", Text(ReleaseState(receipt.result))},
            {"win32Error", receipt.nativeError ? V::makeUInt(*receipt.nativeError) : V::makeNull()}}));
    }
    // 清退成功和首次恢复失败可同时存在，两者均来自当前原生所有者。
    if (const auto& retirement = result.retirement) {
        const auto* kind = retirement->kind == native::NativeRetirementKind::Detached
            ? "detached" : "exit-event-continued"; // 区分主动脱离与消费进程退出事件。
        body.emplace_back("retirement", V::makeObject({{"kind", Text(kind)},
            {"backendInstanceId", Text(retirement->owner.backendInstanceId)},
            {"exitEvent", ReportNativeEvent(retirement->exitEvent)},
            {"exitCode", retirement->exitCode ? V::makeUInt(*retirement->exitCode) : V::makeNull()}}));
    }
    if (const auto& failure = result.firstRecoveryFailure) {
        body.emplace_back("firstRecoveryFailure", V::makeObject({{"stage", Text(failure->stage)},
            {"win32Error", V::makeUInt(failure->win32Error)},
            {"backendInstanceId", Text(failure->owner.backendInstanceId)},
            {"pendingEvent", ReportNativeEvent(failure->pendingEvent)},
            {"releaseRequestId", failure->releaseRequestId ? Text(*failure->releaseRequestId) : V::makeNull()}}));
    }
    return body;
}

// 将两个合作程序的原生状态和值化回执投影到同一个 CLI 会话。成员自己的令牌不对外发布。
JsonObject PairFields(const native::OwnedBreakpointGroupResult& result)
{
    using enum native::OwnedBreakpointGroupState;
    const char* state = "idle"; // 组级状态独立于两个原生所有者。
    switch (result.state) {
    case Idle: break;
    case Starting: state = "starting"; break;
    case Running: state = "running"; break;
    case HeldPartial: state = "held-partial"; break;
    case HeldComplete: state = "held-complete"; break;
    case Closing: state = "closing"; break;
    case Closed: state = "closed"; break;
    case Ended: state = "ended"; break;
    case Failed: state = "failed"; break;
    case RecoveryRequired: state = "recovery-required"; break;
    }
    JsonArray members; // 原生状态按成员启动顺序输出，位置与释放回执一致。
    for (const auto& member : result.members) {
        members.push_back(V::makeObject({{"pid", member.pid ? V::makeUInt(member.pid) : V::makeNull()},
            {"creationFileTime", member.creationFileTime ? Count(member.creationFileTime) : V::makeNull()},
            {"ready", V::makeBool(member.ready)}, {"gateOpened", V::makeBool(member.gateOpened)},
            {"held", V::makeBool(member.held)},
            {"exitCode", member.exitCode ? V::makeUInt(*member.exitCode) : V::makeNull()},
            {"control", member.control ? V::makeObject(ReportFields(*member.control, false)) : V::makeNull()}}));
    }
    JsonObject report{{"mode", Text("cooperative-pair")}, {"state", Text(state)}, {"stage", Text(result.stage)},
        {"win32Error", V::makeUInt(result.win32Error)}, {"clean", V::makeBool(result.clean)},
        {"outcomeMember", result.outcomeMember ? V::makeUInt(*result.outcomeMember) : V::makeNull()},
        {"frozen", V::makeBool(result.frozen)}, {"members", V::makeArray(std::move(members))}};
    // 清退原因在重试前已经冻结，独立于当前是否已清退。
    if (const auto reason = result.endReason) {
        using enum native::OwnedBreakpointGroupEndReason;
        const char* name = nullptr; // 原生所有者记录的初次结束原因。
        switch (*reason) {
        case Requested: name = "requested"; break;
        case native::OwnedBreakpointGroupEndReason::Failed: name = "failed"; break;
        case MemberEnded: name = "member-ended"; break;
        }
        report.emplace_back("endReason", name ? Text(name) : V::makeNull());
    }
    if (const auto& stop = result.stop) {
        report.emplace_back("stop", V::makeObject({{"id", Text(stop->stopId)},
            {"stateRevision", Count(stop->stateRevision)}}));
    }
    if (const auto& release = result.lastRelease) {
        JsonArray outcomes; // 即使部分继续失败，也保持每个目标的原始释放结果。
        for (const auto& member : release->members) {
            outcomes.push_back(V::makeObject(ReportFields(member, false)));
        }
        report.emplace_back("release", V::makeObject({{"stopId", Text(release->stop.stopId)},
            {"stateRevision", Count(release->stop.stateRevision)}, {"continued", V::makeBool(release->continued)},
            {"members", V::makeArray(std::move(outcomes))}}));
    }
    return report;
}

// REPL 和 JSONL 共用原生所有者。控制线程没有 stdout，也不借用管道来保持暂停状态。
class BreakpointSession {
public:
    BreakpointSession(bool jsonl, const native::OwnerIdentity& id, std::optional<BreakpointCondition> condition,
        bool cooperativePair)
        : jsonl_(jsonl), identity_(id), condition_(std::move(condition)), owner_(id),
          pair_(cooperativePair ? std::make_unique<native::OwnedBreakpointGroup>(id) : nullptr) {}

    int Run(const std::wstring& executable, native::NativeBreakpointRequest request)
    {
        if (const auto fault = transport_.Start(jsonl_)) {
            std::cerr << fault.message << '\n';
            return fault.code;
        }
        if (!condition_ && !pair_) return RunControl(executable, std::move(request));
        try {
            if (pair_) {
                return RunPair(executable, request.exportName);
            }
            return RunControl(executable, std::move(request));
        } catch (...) {
            // 求值、快照或输出异常都先走正式关闭路径，归还可能已被账本接纳的事件。
            return End(pair_ ? "cooperative-pair-processing-failed" : "condition-processing-failed", 6);
        }
    }

private:
    // 为原有会话包络生成继续协议；两种控制模式复用请求序号和重放窗口。
    V ContinueProtocol() const
    {
        return jsonl_ ? V::makeObject({{"firstRequestId", Text(ReleaseId(1))},
            {"requestIdFormat", Text("continue/<next positive uint64 decimal>")},
            {"replayEntries", Count(kReleaseReplayEntries)}}) : V::makeNull();
    }

    // 启动两个主动合作的子程序。武装进度由下面的同一命令循环推进。
    int RunPair(const std::wstring& executable, const std::string& exportName)
    {
        const auto started = pair_->Start(executable, exportName); // 组启动回执包含实际创建的成员。
        if (!Emit("hello", {}, V::makeObject({{"control", ReportPair(started)}, {"continueProtocol", ContinueProtocol()}}))) {
            return End("output-lost", 3);
        }
        if (started.win32Error) {
            return End("cooperative-pair-start-failed", 3);
        }
        return RunCommands();
    }

    int RunControl(const std::wstring& executable, native::NativeBreakpointRequest request)
    {
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
                {"targetCreationFileTime", Count(request.target.processCreationTime)}, {"control", ReportControl(accepted)},
                {"continueProtocol", ContinueProtocol()}}))) {
            return End("output-lost", 3);
        }
        if (!accepted.breakpoint || accepted.status == native::NativeControlStatus::Rejected) return End("arm-rejected", 3);
        return RunCommands();
    }

    // 统一处理 REPL 和 JSONL；空闲时也推进组武装和清退。
    int RunCommands()
    {
        for (;;) {
            const auto input = transport_.Next(pair_ || (condition_.has_value() && !closeRequested_));
            switch (input.kind) {
            case InputKind::Eof: return End("eof", 0);
            case InputKind::Break: return End("ctrl-break", 6);
            case InputKind::OutputLost: return End("output-lost", 3);
            case InputKind::Fatal: return End("input-failed", input.fault.code);
            case InputKind::Tick:
            case InputKind::Line: break;
            }
            // 输入繁忙和空闲时都处理停点。命令分发沿用同一快照，不能绕过对新停点求值。
            std::optional<native::NativeControlResult> observed;
            std::optional<native::OwnedBreakpointGroupResult> pairObserved; // 本轮命令与条件使用同一组快照。
            if (pair_) {
                pairObserved = pair_->Query();
                if (condition_ && !closeRequested_) {
                    if (const char* failure = ApplyPairCondition(*pairObserved)) return End(failure, 6);
                }
            } else if (condition_ && !closeRequested_) {
                observed = owner_.Query();
                if (const char* failure = ApplyCondition(*observed)) return End(failure, 6);
            }
            if (input.kind == InputKind::Tick) {
                continue;
            }
            const auto decoded = jsonl_ ? DecodeJsonLine(input.line, RequestProfile::Live) : DecodeReplLine(input.line);
            if (decoded.error) {
                if (!Emit("error", decoded.request.id, FaultJson(decoded.error))) return End("output-lost", 3);
                continue;
            }
            if (decoded.request.method.empty()) continue;
            std::optional<V> closed; // 显式退出成功时携带已确认的清退回执。
            if (const int action = Dispatch(decoded.request, std::move(observed), std::move(pairObserved), closed); action != 0) {
                return closed ? WriteSummary("requested", 0, std::move(*closed), true) : End("output-lost", 3);
            }
        }
    }

    struct ConditionDecision {
        std::uint64_t eventSerial;
        std::string groupId;
        std::uint64_t stateRevision;
        rules::Evaluation evaluation;
        std::optional<native::ReleaseResult> release;
        const char* releaseStage = nullptr;
        std::uint32_t releaseError = 0;
    };

    // 单目标和双目标均只从真实持有的同一冻结快照取字段，不用现场枚举补身份。
    bool VerifiedConditionStop(const native::NativeControlResult& observed) const
    {
        return observed.status == native::NativeControlStatus::Held && observed.breakpointHit && observed.pending &&
            observed.pending->ledgerOwned && observed.group && observed.group->origin &&
            observed.group->origin->phase == native::StopPhase::ExecutionEnterAttempt && observed.responsibility &&
            observed.responsibility->state == native::EventState::Held &&
            observed.responsibility->event == observed.pending->event;
    }

    // 调用方先核验真实停点；输出保留三值，不把缺少的寄存器补成零。
    rules::Evaluation EvaluateCondition(const native::NativeControlResult& observed) const
    {
        const auto& event = *observed.pending;
        using enum rules::Quality;
        const auto* thread = FrozenOriginThread(observed); // 从同一停点快照确认创建时间。
        rules::FieldSample threadCreated{"stop.thread.creationFileTime", NotCollected, std::monostate{}};
        if (thread && thread->tid == event.tid && thread->creationTime) {
            threadCreated = {"stop.thread.creationFileTime", Known, thread->creationTime};
        }
        rules::FieldSample samples[] = {
            {"stop.address", Known, observed.breakpointHit->address},
            {"stop.exceptionCode", NotCollected, std::monostate{}},
            {"stop.firstChance", NotCollected, std::monostate{}},
            {"stop.pid", Known, std::uint64_t{event.pid}},
            threadCreated,
            {"stop.thread.rax", NotCollected, std::monostate{}},
            // 原生所有者接纳执行停点前已核验命中线程的冻结 RIP 等于绑定地址。
            {"stop.thread.rip", Known, observed.breakpointHit->address},
            {"stop.tid", Known, std::uint64_t{event.tid}},
        };
        if (event.exceptionCode) samples[1] = {"stop.exceptionCode", Known, std::uint64_t{*event.exceptionCode}};
        if (event.exceptionFirstChance.has_value()) samples[2] = {"stop.firstChance", Known, *event.exceptionFirstChance};
        return rules::EvaluatePredicate(condition_->predicate, kConditionPhase, samples);
    }

    const char* ApplyCondition(native::NativeControlResult& observed)
    {
        if (observed.status != native::NativeControlStatus::Held) return nullptr;
        if (!VerifiedConditionStop(observed)) return "condition-stop-unverified";
        const auto& event = *observed.pending;
        if (lastCondition_ && lastCondition_->eventSerial == event.event.serial) return nullptr;
        const auto evaluation = EvaluateCondition(observed);
        lastCondition_ = ConditionDecision{event.event.serial, observed.group->groupId, observed.group->stateRevision,
            evaluation, std::nullopt};
        if (evaluation.truth == rules::Truth::True) {
            ++conditionTrue_;
            return nullptr;
        }
        if (evaluation.truth == rules::Truth::False) ++conditionFalse_;
        else ++conditionUnknown_;

        // 先通过同一个事件令牌释放，再向控制端投影结果。失败由 End/Close 接手。
        if (nativeReleaseSequence_ == std::numeric_limits<std::uint64_t>::max()) return "condition-release-sequence-exhausted";
        observed = ContinueStop(observed, ++nativeReleaseSequence_);
        if (observed.release && observed.release->receipt) lastCondition_->release = observed.release->receipt->result;
        lastCondition_->releaseStage = observed.stage;
        lastCondition_->releaseError = observed.win32Error;
        if (lastCondition_->release != native::ReleaseResult::Continued ||
            observed.status == native::NativeControlStatus::RecoveryRequired)
            return "condition-release-failed";
        return nullptr;
    }

    struct PairConditionDecision {
        native::OwnedBreakpointGroupToken stop; // 两成员全部持有后才冻结的组令牌。
        JsonArray members; // 启动顺序中的身份、原生代次与各自三值结果。
        bool hold = false; // 任一成员为真时保留整个组；否则整组自动继续。
        bool continued = false; // 原生组确认两份释放均成功后才置位。
    };

    // 部分持有不求值、不释放；完整组按同一表达式逐成员求值且每代只执行一次。
    const char* ApplyPairCondition(native::OwnedBreakpointGroupResult& observed)
    {
        if (!observed.stop) return nullptr;
        if (lastPairCondition_ && lastPairCondition_->stop == *observed.stop) return nullptr;
        PairConditionDecision decision{*observed.stop, {}};
        for (const auto& member : observed.members) {
            if (!member.held || !member.control || !VerifiedConditionStop(*member.control) ||
                member.control->pending->pid != member.pid ||
                member.control->pid != member.pid || member.control->processCreationTime != member.creationFileTime) {
                return "pair-condition-stop-unverified";
            }
            const auto& state = *member.control; // 字段与原生事件都来自此次组快照。
            const auto evaluation = EvaluateCondition(state);
            const auto truth = evaluation.truth;
            decision.hold |= truth == rules::Truth::True;
            if (truth == rules::Truth::True) ++conditionTrue_;
            else if (truth == rules::Truth::False) ++conditionFalse_;
            else ++conditionUnknown_;
            decision.members.push_back(V::makeObject({{"pid", V::makeUInt(member.pid)},
                {"creationFileTime", Count(member.creationFileTime)}, {"groupId", Text(state.group->groupId)},
                {"stateRevision", Count(state.group->stateRevision)}, {"eventSerial", Count(state.pending->event.serial)},
                {"truth", Text(truth == rules::Truth::True ? "true" : truth == rules::Truth::False ? "false" : "unknown")},
                {"evaluationFault", evaluation.fault == rules::EvaluationFault::None ? V::makeNull() :
                    Text(evaluation.fault == rules::EvaluationFault::Budget ? "budget" : "invalid-input")}}));
        }
        lastPairCondition_ = std::move(decision);
        if (lastPairCondition_->hold) return nullptr;
        // 仅提交这次求值冻结的组令牌；组控制器继续核对两份真实原生责任。
        observed = pair_->Continue(lastPairCondition_->stop);
        lastPairCondition_->continued = observed.lastRelease &&
            observed.lastRelease->stop == lastPairCondition_->stop && observed.lastRelease->continued;
        return lastPairCondition_->continued ? nullptr : "pair-condition-release-failed";
    }

    // 组判定与清退回执并列保留，自动继续不占用客户端 continue/N 序号。
    V ReportPair(const native::OwnedBreakpointGroupResult& result) const
    {
        auto report = PairFields(result);
        if (!condition_) return V::makeObject(std::move(report));
        V last = V::makeNull(); // 尚未出现完整停点组时没有判定。
        if (lastPairCondition_) {
            const auto& decision = *lastPairCondition_;
            last = V::makeObject({{"stopId", Text(decision.stop.stopId)},
                {"stateRevision", Count(decision.stop.stateRevision)},
                {"action", Text(decision.hold ? "hold" : "auto-continue")},
                {"continued", V::makeBool(decision.continued)}, {"members", V::makeArray(decision.members)}});
        }
        report.emplace_back("condition", V::makeObject({{"profile", Text(rules::PredicateExpressionProfile)},
            {"expression", Text(condition_->expression)}, {"phase", Text("execution-enter-attempt")},
            {"aggregation", Text("any-true-holds-group")}, {"trueCount", Count(conditionTrue_)},
            {"falseCount", Count(conditionFalse_)}, {"unknownCount", Count(conditionUnknown_)}, {"last", std::move(last)}}));
        return V::makeObject(std::move(report));
    }

    V ReportControl(const native::NativeControlResult& result) const
    {
        auto report = ReportFields(result);
        if (!condition_) return V::makeObject(std::move(report));
        V last = V::makeNull();
        if (const auto& decision = lastCondition_) {
            const auto truth = decision->evaluation.truth;
            const auto fault = decision->evaluation.fault;
            last = V::makeObject({{"groupId", Text(decision->groupId)}, {"stateRevision", Count(decision->stateRevision)},
                {"truth", Text(truth == rules::Truth::True ? "true" : truth == rules::Truth::False ? "false" : "unknown")},
                {"evaluationFault", fault == rules::EvaluationFault::None ? V::makeNull() :
                    Text(fault == rules::EvaluationFault::Budget ? "budget" : "invalid-input")},
                {"action", Text(truth == rules::Truth::True ? "hold" : "auto-continue")},
                {"release", decision->release ? Text(ReleaseState(*decision->release)) : V::makeNull()},
                {"releaseStage", decision->releaseStage ? Text(decision->releaseStage) : V::makeNull()},
                {"win32Error", decision->releaseStage ? V::makeUInt(decision->releaseError) : V::makeNull()}});
        }
        report.emplace_back("condition", V::makeObject({{"profile", Text(rules::PredicateExpressionProfile)},
            {"expression", Text(condition_->expression)}, {"phase", Text("execution-enter-attempt")},
            {"trueCount", Count(conditionTrue_)}, {"falseCount", Count(conditionFalse_)},
            {"unknownCount", Count(conditionUnknown_)}, {"last", std::move(last)}}));
        return V::makeObject(std::move(report));
    }

    native::NativeControlResult ContinueStop(const native::NativeControlResult& current, std::uint64_t sequence)
    {
        return owner_.Continue({identity_, current.group->groupId, current.responsibility->stopId,
            current.responsibility->event, ReleaseId(sequence), current.group->stateRevision});
    }

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

    // 在发终态前观察关闭结果。只有账本确认从未发出原生继续调用才做一次重试。
    native::NativeControlResult CloseAndObserve()
    {
        closeRequested_ = true;
        const auto deadline = GetTickCount64() + 3000; // 本次命令等待异步清退的上限。
        auto state = owner_.Close(); // 真实拥有者继续处理已登记的原生责任。
        bool retried = false; // 自动重试只执行一次，运行中的再次关闭由调用方决定。
        while (!state.clean && GetTickCount64() < deadline) {
            if (state.status == native::NativeControlStatus::RecoveryRequired) {
                if (retried || !state.responsibility || state.responsibility->state != native::EventState::Retryable) {
                    break;
                }
                retried = true;
                state = owner_.Close();
                continue;
            }
            Sleep(20);
            state = owner_.Query();
        }
        return state;
    }

    struct CloseReport {
        bool clean; // 由当前模式的原生所有者确认清退。
        V control; // 断开传输前保留真实控制状态。
    };

    // 发起清退后有限等待。两目标各自保留责任；显式再次关闭可重试未确认的清退。
    CloseReport CloseControl()
    {
        if (!pair_) {
            const auto state = CloseAndObserve(); // 保留旧单目标的原生重试规则。
            return {state.clean, ReportControl(state)};
        }
        const auto deadline = GetTickCount64() + 3000; // 与单目标关闭等待预算相同。
        closeRequested_ = true; // 关闭重试期间也禁止组条件自动继续。
        auto state = pair_->Close(); // 先向全部已接管成员发出关闭，再等回执。
        while (!state.clean && state.state != native::OwnedBreakpointGroupState::RecoveryRequired &&
            GetTickCount64() < deadline) {
            Sleep(20);
            state = pair_->Query();
        }
        return {state.clean, ReportPair(state)};
    }

    // 输入或输出已结束时，按实际关闭回执生成终态。
    int End(std::string_view reason, int code)
    {
        auto closed = CloseControl(); // 清退在输出最终回执之前完成一次有界确认。
        return WriteSummary(reason, code, std::move(closed.control), closed.clean);
    }

    int WriteSummary(std::string_view reason, int code, V control, bool clean)
    {
        if (!code && !clean) code = 6;
        const bool sent = Emit("summary", {}, V::makeObject({{"reason", Text(reason)},
            {"exitCode", V::makeUInt(code)}, {"control", std::move(control)}}));
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

    int Dispatch(const Request& request, std::optional<native::NativeControlResult> observed,
          std::optional<native::OwnedBreakpointGroupResult> pairObserved,
          std::optional<V>& closed)
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
        if ((method == "quit" || method == "controller.shutdown") && empty && !request.expected) {
            auto state = CloseControl(); // 成功沿用终态回执；未完成时保留输入并回应本次请求。
            if (!state.clean) {
                return Emit("response", request.id, std::move(state.control)) ? 0 : 3;
            }
            closed = std::move(state.control);
            return 1;
        }
        if ((method == "status" || method == "control.query") && empty && !request.expected) {
            auto status = pair_ ? ReportPair(pairObserved ? *pairObserved : pair_->Query()) :
                ReportControl(observed ? *observed : owner_.Query());
            return Emit("response", request.id, std::move(status)) ? 0 : 3;
        }
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

        bool live = false; // 只有当前令牌确实可用才返回控制回执。
        V report; // 保留模式自己的释放回执，失败也要落到共同的重放窗口。
        if (pair_) {
            const auto result = pair_->Continue({stop, expectedRevision}); // 只允许提交组冻结的两份原生令牌。
            live = result.ledgerResult == native::LedgerResult::Applied;
            if (live) {
                report = ReportPair(result);
            }
        } else {
            const auto current = observed ? std::move(*observed) : owner_.Query(); // 单目标沿用原生当前停点。
            live = current.group && current.responsibility && current.group->stateRevision == expectedRevision &&
                current.responsibility->stopId == stop;
            if (live) {
                // 客户端继续序号与自动继续隔离，原生账本仍接收严格递增的释放序列。
                if ((!jsonl_ && releaseSequenceHighWater_ == std::numeric_limits<std::uint64_t>::max()) ||
                    (condition_ && nativeReleaseSequence_ == std::numeric_limits<std::uint64_t>::max())) {
                    return Invalid(request, "continue-sequence-exhausted", "Native continue IDs are exhausted");
                }
                if (!jsonl_) {
                    releaseSequence = ++releaseSequenceHighWater_;
                }
                report = ReportControl(ContinueStop(current, condition_ ? ++nativeReleaseSequence_ : releaseSequence));
            }
        }
        if (!live) {
            report = ControlError("stale-stop", "Query the active stop before continuing");
        }

        const auto type = live ? "response" : "error"; // 过期令牌不触发本轮释放。
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
    const std::optional<BreakpointCondition> condition_;
    std::optional<ConditionDecision> lastCondition_;
    std::optional<PairConditionDecision> lastPairCondition_; // 最近完整组判定在继续和清退后仍可回读。
    std::uint64_t conditionTrue_ = 0;
    std::uint64_t conditionFalse_ = 0;
    std::uint64_t conditionUnknown_ = 0;
    std::uint64_t nativeReleaseSequence_ = 0;
    Transport transport_;
    native::NativeDebugOwner owner_;
    std::unique_ptr<native::OwnedBreakpointGroup> pair_; // 仅显式双目标模式创建组控制器。
    bool closeRequested_ = false; // 清退由拥有者处理，停掉会话中的自动条件继续。
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
    const bool cooperativePair = args.has(L"--cooperative-pair"); // 仅接本工具启动的同一合作 EXE 的两个实例。
    if (cooperativePair && (!args.has(L"--export") || args.has(L"--module") ||
        args.has(L"--watch-write-bytes"))) {
        throw std::invalid_argument("Cooperative pair requires one EXE execution export and no module or data watch");
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

    // 数据关注点限定为自有子程序的对齐可写数据导出，条件表达式仍绑定既有执行阶段。
    if (args.has(L"--watch-write-bytes")) {
        const auto width = args.u32(L"--watch-write-bytes"); // 真实硬件关注宽度，单位字节。
        if ((width != 1 && width != 2 && width != 4 && width != 8) || args.has(L"--rva") ||
            args.has(L"--module") || args.has(L"--condition")) {
            throw std::invalid_argument("Data write watch requires an EXE data export, a width of 1/2/4/8, and no execution condition");
        }
        request.writeWatchBytes = width;
    }

    std::optional<BreakpointCondition> condition;
    if (args.has(L"--condition")) condition = PrepareCondition(args.require(L"--condition"));
    // 此会话没有项目写权限，样本及控制代次均是单次会话身份。
    using Ksword::ActionAnalyze::ProjectStorage::NewId;
    native::OwnerIdentity id;
    if (!NewId(id.sampleId) || !NewId(id.sessionId) || !NewId(id.epoch) || !NewId(id.backendInstanceId) ||
        !NewId(request.target.requestId)) return 3;
    return BreakpointSession(input == L"jsonl", id, std::move(condition), cooperativePair).Run(executable, std::move(request));
}
} // namespace

void RegisterBreakpointCommand()
{
    Command command;
    command.path = L"analyze breakpoint session";
    command.syntax = L"KswordCLI.exe analyze breakpoint session --exe PATH [--module PATH] (--export NAME | --rva RVA) --confirm --disposition resume-detach [--input repl|jsonl] [--condition EXPR] [--watch-write-bytes 1|2|4|8 | --cooperative-pair]";
    command.summary = L"Control breakpoints in explicitly authorized AMD64 child processes.";
    command.options = L"The EXE and optional loaded module use absolute DOS paths; module defaults to the EXE. Use an exact PE export or instruction-boundary RVA. Optional --condition uses predicate-expr-v2 at execution-enter-attempt. Fields: stop.address, stop.exceptionCode, stop.pid, stop.tid, stop.thread.rip and stop.thread.creationFileTime (u64), stop.firstChance (bool), stop.thread.rax (u64, not collected).";
    command.notes = L"Data write watch requires the EXE's aligned writable data export. --cooperative-pair requires the EXE's execution export and two children that acknowledge inherited Ready/Gate handles. Pair conditions evaluate only a fully held group: any true member holds both; otherwise both auto-continue. REPL: status, continue STOP_ID STATE_REVISION, quit. JSONL continue request IDs start at continue/1; expired receipts cannot be replayed. Shutdown reports confirmed cleanup or keeps the session open if cleanup is unresolved. Native retirement and the first recovery failure are reported independently when recorded.";
    command.runStreaming = Run;
    addCommand(std::move(command));
}

} // namespace ks::cli::action_analyze
