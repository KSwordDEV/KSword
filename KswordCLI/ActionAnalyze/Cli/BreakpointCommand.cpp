#include "BreakpointCommand.h"
#include "BreakpointStepProtocol.h"
#include "BreakpointFollowProtocol.h"
#include "BreakpointRangeProtocol.h"
#include "BreakpointPauseProtocol.h"
#include "NativeExecutionJournal.h"

#include "../Control/NativeDebugOwner.h"
#include "../Control/NativeStopCondition.h"
#include "../Control/NativeExecutionEvidence.h"
#include "../Control/CooperativeBreakpointGate.h"
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

// 条件在原生断点停止时求值，执行/写入字段按实际事件提供，缺失保持未知。
constexpr auto kConditionPhase = rules::Phase::Entry;
constexpr auto kConditionFields = native::NativeStopConditionFields(kConditionPhase);

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
// 普通步进停点不带 phase 来源：其冻结线程取自同组步进回执已核验的强线程身份。
const native::NativeFrozenThread* FrozenOriginThread(const native::NativeControlResult& result)
{
    std::string id;
    if (result.group && result.group->origin) {
        id = result.group->origin->threadId;
    } else if (result.group && result.step && result.step->stopGroupId &&
        *result.step->stopGroupId == result.group->groupId) {
        id = result.step->request.thread.threadId;
    } else {
        return nullptr;
    }
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
    body.emplace_back("stopReason", Text(result.stopReason == native::NativeStopReason::ManualPause ? "manual-pause" :
        result.stopReason == native::NativeStopReason::Breakpoint ? "breakpoint" :
        result.stopReason == native::NativeStopReason::NativeStep ? "native-step" : "none"));
    if (result.armedPause)
    {
        body.emplace_back("armedPause", BreakpointPauseProtocol::Report(*result.armedPause));
    }
    if (const auto& binding = result.breakpoint) {
        JsonObject fields{{"state", Text(BindingState(binding->state))},
            {"stage", Text(binding->stage)}, {"win32Error", V::makeUInt(binding->win32Error)},
            {"address", binding->address ? Address(binding->address) : V::makeNull()},
            {"enrolledThreads", Count(binding->enrolledThreads)},
            {"privateExecutionFollowAvailable", V::makeBool(binding->privateExecutionFollowAvailable)}}; // 原绑定声明，调用时仍核验活停点。
        fields.emplace_back("imageSha256", binding->imageSha256 ? Text(*binding->imageSha256) : V::makeNull());
        if (binding->writeWatchBytes) {
            fields.emplace_back("watchedBytes", V::makeUInt(binding->writeWatchBytes));
            fields.emplace_back("siteKind", Text(binding->explicitPrivateAddress ? "private-address-write" :
                binding->pointerExportAddress ? "private-pointer-export" : "image-data-export"));
        } else if (binding->explicitPrivateAddress) {
            fields.emplace_back("siteKind", Text(binding->rangeBytes ? "private-page-execution" : "private-address-execution"));
            fields.emplace_back("rangeBytes", Count(binding->rangeBytes));
        } else if (binding->executePointerExport) {
            // 私有执行使用实际指针目的地址，选择器导出本身不视为执行位置。
            fields.emplace_back("siteKind", Text("private-execution-pointer-export"));
            fields.emplace_back("executePointerExport", V::makeBool(true));
        } else {
            // 普通模块绑定单独回传实际映像坐标，不把模块RVA当私有分配身份。
            fields.emplace_back("siteKind", Text("image-execution"));
            fields.emplace_back("moduleBase", Address(binding->moduleBase));
            fields.emplace_back("rva", V::makeUInt(binding->rva));
        }
        if (binding->pointerExportAddress || binding->explicitPrivateAddress) {
            // 两种私有绑定都保留冻结的区域；这些字段不证明同址分配代次。
            if (binding->pointerExportAddress)
                fields.emplace_back("pointerExportAddress", Address(binding->pointerExportAddress));
            fields.emplace_back("explicitPrivateAddress", V::makeBool(binding->explicitPrivateAddress));
            fields.emplace_back("allocationBase", Address(binding->allocationBase));
            fields.emplace_back("regionBase", Address(binding->regionBase));
            fields.emplace_back("regionBytes", Count(binding->regionBytes));
            fields.emplace_back("regionProtection", V::makeUInt(binding->regionProtection));
            fields.emplace_back("allocationGenerationVerified", V::makeBool(false));
        }
        JsonArray ranges; // 成功纳入的真实范围，原始address/rangeBytes仍保留兼容。
        for (const auto& range : binding->executionRanges)
        {
            ranges.push_back(V::makeObject({{"base", Address(range.base)}, {"bytes", Count(range.bytes)},
                {"allocationBase", Address(range.allocationBase)}}));
        }
        fields.emplace_back("executionRanges", V::makeArray(std::move(ranges)));
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
    if (const auto execution = native::NativeExecutionFromOwnedStop(result)) {
        // 实际执行观测与 API 入口请求分列；TF 完成只确认所记录的单条原生指令。
        body.emplace_back("execution", V::makeObject({
            {"kind", Text(execution->kind == native::NativeExecutionKind::InstructionCompleted ?
                "instruction-completed" : "execution-enter-attempt")},
            {"instructionAddress", Address(execution->instructionAddress)},
            {"nextInstructionAddress", execution->nextInstructionAddress ? Address(*execution->nextInstructionAddress) : V::makeNull()},
            {"pid", V::makeUInt(execution->pid)}, {"processCreationFileTime", Count(execution->processCreationFileTime)},
            {"threadId", Text(execution->thread.identity.threadId)}, {"tid", V::makeUInt(execution->thread.tid)},
            {"threadCreationFileTime", Count(execution->thread.creationTime)},
            {"event", ReportNativeEvent(execution->event)}, {"groupId", Text(execution->groupId)},
            {"stopId", Text(execution->stopId)}, {"stateRevision", Count(execution->stateRevision)},
            {"observedQpc", execution->observedQpc ? Count(*execution->observedQpc) : V::makeNull()},
            {"qpcFrequency", Count(execution->qpcFrequency)}, {"source", Text("native-debug-owner")}}));
    }
    if (result.group) {
        body.emplace_back("stopGroup", ReportStopGroup(*result.group));
    }
    if (const auto* origin = FrozenOriginThread(result)) {
        body.emplace_back("originThread", V::makeObject({{"threadId", Text(origin->identity.threadId)},
            {"tid", V::makeUInt(origin->tid)}, {"creationFileTime", Count(origin->creationTime)}}));
    }
    if (const auto& registers = result.registers) {
        // 只投影原生事件冻结的寄存器，不在输出时查询运行中的线程。
        std::vector<std::pair<std::string, V>> values{{"threadId", Text(registers->thread.threadId)}};
        for (const auto& field : native::NativeStopRegisterFields) {
            const auto value = (*registers).*(field.value); // 同一冻结快照，地址字段保留原十六进制表示。
            values.emplace_back(field.name, field.value == &native::NativeStopRegisters::rip ||
                field.value == &native::NativeStopRegisters::rsp ? Address(value) : Count(value));
        }
        body.emplace_back("registers", V::makeObject(std::move(values)));
    }
    if (result.executionRange)
    {
        body.emplace_back("executionRange", BreakpointRangeProtocol::Report(*result.executionRange));
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
        bool cooperativePair, std::unique_ptr<NativeExecutionJournal> journal)
        : jsonl_(jsonl), identity_(id), condition_(std::move(condition)), journal_(std::move(journal)), owner_(id),
          pair_(cooperativePair ? std::make_unique<native::OwnedBreakpointGroup>(id) : nullptr) {}

    int Run(const std::wstring& executable, native::NativeBreakpointRequest request)
    {
        if (const auto fault = transport_.Start(jsonl_)) {
            std::cerr << fault.message << '\n';
            return fault.code;
        }
        try {
            if (pair_) {
                return RunPair(executable, request.exportName);
            }
            return RunControl(executable, std::move(request));
        } catch (...) {
            // 求值、快照或输出异常都先走正式关闭路径，归还可能已被账本接纳的事件。
            return End(pair_ ? "cooperative-pair-processing-failed" : "breakpoint-processing-failed", 6);
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
        privateWriteWatch_ = request.writeWatchBytes != 0 && (request.writeWatchPointerExport || request.privateAddress);
        if (request.privateAddress || request.explicitImageAttachment) return BeginControl(request);
        // 子进程不继承控制管道或 console；关闭调试会话按约定继续子进程，不代为终止。
        STARTUPINFOEXW startup{}; // 私有区间模式先等待合作应用初始化指针，再由调试所有者武装。
        startup.StartupInfo.cb = sizeof(STARTUPINFOW);
        PROCESS_INFORMATION created{};
        auto line = L"\"" + executable + L"\"";
        if (request.writeWatchPointerExport || request.executePointerExport) {
            // 私有写入和私有执行都先初始化指针，再由真实Armed回执放行业务。
            launchGate_ = std::make_unique<native::CooperativeBreakpointGate>();
            if (const auto error = launchGate_->Prepare(startup, line)) {
                return LaunchFailed("prepare-private-data-gate", error, 0);
            }
        }
        const DWORD launchFlags = DETACHED_PROCESS | (launchGate_ ? EXTENDED_STARTUPINFO_PRESENT : 0);
        if (!CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, launchGate_ != nullptr, launchFlags,
                nullptr, nullptr, &startup.StartupInfo, &created)) {
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
        if (launchGate_) {
            if (const auto error = launchGate_->AwaitReady(child.get())) {
                return LaunchFailed("private-data-target-not-ready", error, created.dwProcessId);
            }
        }
        return BeginControl(request);
    }

    int BeginControl(const native::NativeBreakpointRequest& request)
    {
        const auto accepted = owner_.ArmBreakpoint(request);
        if (!Emit("hello", {}, V::makeObject({{"targetPid", V::makeUInt(request.target.pid)},
                {"targetCreationFileTime", Count(request.target.processCreationTime)}, {"control", ReportControl(accepted)},
                   {"targetMode", Text(request.explicitImageAttachment ? "attached-image-execution" :
                       request.privateAddress ? "attached-private-address" : "launched-child")},
                 {"continueProtocol", ContinueProtocol()},
                 {"executionArchive", journal_ ? journal_->Describe() : V::makeNull()},
                  {"stepProtocol", steps_.Capabilities()},
                  {"followProtocol", privateWriteWatch_ ? follows_.Capabilities() : V::makeNull()},
                  {"rangeProtocol", request.privateRangeBytes ? ranges_.Capabilities() : V::makeNull()},
                  {"pauseProtocol", pauses_.Capabilities()}}))) {
            return End("output-lost", 3);
        }
        if (!accepted.breakpoint || accepted.status == native::NativeControlStatus::Rejected) return End("arm-rejected", 3);
        return RunCommands();
    }

    // 统一处理 REPL 和 JSONL；空闲时也推进组武装和清退。
    int RunCommands()
    {
        for (;;) {
            const auto input = transport_.Next(pair_ || (launchGate_ && launchGate_->Waiting()) ||
                (condition_.has_value() && !closeRequested_));
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
            if (launchGate_ && launchGate_->Waiting()) {
                const auto state = owner_.Query(); // 只有真实武装后才允许初始化完成的合作目标写入。
                if (const auto error = launchGate_->Observe(state)) {
                    return End("private-data-gate-release-failed", 6);
                }
            }
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
            (observed.group->origin->phase == native::StopPhase::ExecutionEnterAttempt ||
                observed.group->origin->phase == native::StopPhase::DataWriteObserved) && observed.responsibility &&
            observed.responsibility->state == native::EventState::Held &&
            observed.responsibility->event == observed.pending->event;
    }

    // 调用方先核验真实停点；输出保留三值，不把缺少的寄存器补成零。
    rules::Evaluation EvaluateCondition(const native::NativeControlResult& observed) const
    {
        const auto samples = native::NativeStopConditionSamples(observed);
        return rules::EvaluatePredicate(condition_->predicate, kConditionPhase, samples);
    }

    const char* ApplyCondition(native::NativeControlResult& observed)
    {
        if (observed.status != native::NativeControlStatus::Held) return nullptr;
        // 单步完成或应用异常产生的新停点由调用方决定，不套用原执行断点的条件。
        if (!observed.breakpointHit) return nullptr;
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
                    Text(rules::EvaluationFaultId(evaluation.fault))}}));
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
        if (result.step) report.emplace_back("step", steps_.Report(*result.step));
        if (result.executionFollow) report.emplace_back("executionFollow", follows_.Report(*result.executionFollow));
        if (!condition_) return V::makeObject(std::move(report));
        V last = V::makeNull();
        if (const auto& decision = lastCondition_) {
            const auto truth = decision->evaluation.truth;
            const auto fault = decision->evaluation.fault;
            last = V::makeObject({{"groupId", Text(decision->groupId)}, {"stateRevision", Count(decision->stateRevision)},
                {"truth", Text(truth == rules::Truth::True ? "true" : truth == rules::Truth::False ? "false" : "unknown")},
                {"evaluationFault", fault == rules::EvaluationFault::None ? V::makeNull() :
                    Text(rules::EvaluationFaultId(fault))},
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
        if (launchGate_) launchGate_->Close(); // 尚未开门时以 EOF 取消目标业务，原生清退仍由 owner 执行。
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
        const bool isStep = method == "step" || method == "control.step";
        if (jsonl_ && !isStep && request.id.starts_with("step/"))
            return Invalid(request, "reserved-request-id", "The step/ request ID namespace is reserved for step");
        const bool isFollow = method == "execution-follow" || method == "control.execution.follow";
        if (jsonl_ && !isFollow && request.id.starts_with("follow/"))
            return Invalid(request, "reserved-request-id", "The follow/ request ID namespace is reserved for execution follow");
        const bool isRange = method == "execution-range-add" || method == "control.execution.range.add";
        if (jsonl_ && !isRange && request.id.starts_with("range/"))
            return Invalid(request, "reserved-request-id", "The range/ request ID namespace is reserved for range addition");
        const bool isPause = method == "pause" || method == "control.pause";
        if (jsonl_ && !isPause && request.id.starts_with("pause/"))
            return Invalid(request, "reserved-request-id", "The pause/ request ID namespace is reserved for pause");
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
            return Emit("response", {}, Text("pause PID CREATION_FILETIME | pause-status pause/N | status | continue STOP_ID STATE_REVISION | execution-save STOP_ID STATE_REVISION | execution-follow ADDRESS STOP_ID STATE_REVISION | execution-range-add ADDRESS BYTES STOP_ID STATE_REVISION（规范正十进制；仅当前完整NX停点，最多合计64页，不继续目标） | memory-snapshot BASE BYTES STOP_ID STATE_REVISION | api-capture PID FILETIME DURATION confirm（采集区间最多10秒，启动和清退另计；同步期间不处理其他指令，完成后继续操作） | step into|over-call|out STOP_ID STATE_REVISION THREAD_ID TID CREATION_FILETIME | step-status STEP_REQUEST_ID | step-cancel STEP_REQUEST_ID | quit | status 另带 execution 执行观测（execution-enter-attempt / instruction-completed）；主动暂停沿原owner，等待armedPause.state=held后用当前stop恢复，不产生执行证据。")) ? 0 : 3;
        if (method == "execution-save" || method == "control.execution.save") {
            if (pair_ || !journal_)
                return Invalid(request, "execution-save-unavailable", "Save requires --project in a single-target session and a current execution observation");
            auto saved = journal_->Save(request, jsonl_, identity_, owner_);
            return Emit(saved.ok ? "response" : "error", request.id, std::move(saved.result)) ? 0 : 3;
        }
        if (method == "memory-snapshot" || method == "control.memory.snapshot") {
            if (pair_ || !journal_)
                return Invalid(request, "memory-snapshot-unavailable", "Snapshot requires --project in a single-target breakpoint session");
            auto captured = journal_->CaptureMemory(request, jsonl_, identity_, owner_);
            return Emit(captured.ok ? "response" : "error", request.id, std::move(captured.result)) ? 0 : 3;
        }
        if (method == "api-capture" || method == "control.api.capture") {
            if (pair_ || !journal_) {
                return Invalid(request, "api-capture-unavailable", "API capture requires --project in a single-target native session");
            }
            // 借用当前串行控制线程及原writer；停止API不继续或关闭原生owner。
            auto captured = journal_->CaptureApi(request, jsonl_, identity_, owner_);
            return Emit(captured.accepted ? "response" : "error", request.id, std::move(captured.result)) ? 0 : 3;
        }
        if (const auto pause = pauses_.Dispatch(request, jsonl_, !pair_, identity_, owner_); pause.handled)
        {
            return pause.error ? (Emit("error", request.id, FaultJson(pause.error)) ? 0 : 3) :
                (Emit("response", request.id, ReportControl(*pause.control)) ? 0 : 3);
        }
        if (isStep && !pair_ && owner_.Query().stopReason == native::NativeStopReason::ManualPause)
        {
            return Invalid(request, "manual-pause-step-unavailable", "Continue or close the manual interruption; stepping requires an execution or native-step stop");
        }
        if (const auto step = steps_.Dispatch(request, jsonl_, !pair_,
            identity_, owner_, nativeReleaseSequence_); step.handled) {
            return step.error ? (Emit("error", request.id, FaultJson(step.error)) ? 0 : 3) :
                (Emit("response", request.id, ReportControl(*step.control)) ? 0 : 3);
        }
        if (const auto follow = follows_.Dispatch(request, jsonl_, !pair_ && privateWriteWatch_,
            identity_, owner_); follow.handled) {
            // 转换保留原写停点；后续保存只接受原生层提取的真实执行事件。
            return follow.error ? (Emit("error", request.id, FaultJson(follow.error)) ? 0 : 3) :
                (Emit("response", request.id, ReportControl(*follow.control)) ? 0 : 3);
        }
        if (const auto range = ranges_.Dispatch(request, jsonl_, !pair_, identity_, owner_); range.handled)
        {
            return range.error ? (Emit("error", request.id, FaultJson(range.error)) ? 0 : 3) :
                (Emit("response", request.id, ReportControl(*range.control)) ? 0 : 3);
        }
        if (!isContinue)
            return Invalid(request, "unsupported-method", "Use control.query, control.pause, control.pause.query, control.continue, control.execution.save, control.execution.follow, control.execution.range.add, control.memory.snapshot, control.api.capture, control.step, control.step.query, control.step.cancel or controller.shutdown");

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
                    nativeReleaseSequence_ == std::numeric_limits<std::uint64_t>::max()) {
                    return Invalid(request, "continue-sequence-exhausted", "Native continue IDs are exhausted");
                }
                if (!jsonl_) {
                    releaseSequence = ++releaseSequenceHighWater_;
                }
                report = ReportControl(ContinueStop(current, ++nativeReleaseSequence_));
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
    BreakpointStepProtocol steps_;
    BreakpointFollowProtocol follows_;
    BreakpointRangeProtocol ranges_; // 原owner范围事务的独立CLI重放窗口。
    BreakpointPauseProtocol pauses_; // 同一原生附加内的主动暂停及查询入口。
    bool privateWriteWatch_ = false; // 原请求的私有写入口；转换后只开放后续真实执行事件的Step。
    std::unique_ptr<native::CooperativeBreakpointGate> launchGate_; // 私有写入/执行共用的指针初始化握手。
    std::unique_ptr<NativeExecutionJournal> journal_; // 晚于原生 owner 销毁，保持整个会话的项目写租约。
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
    const bool attached = args.has(L"--pid");
    const bool imageAttachment = args.has(L"--attach-image"); // 已有实例模块内执行入口，与私有地址选择分开。
    const bool definition = args.has(L"--definition"); // 定义从同轮项目sample冻结配置读取，不从历史事件授控制。
    if (definition && (!imageAttachment || !attached || !args.has(L"--project")))
    {
        throw std::invalid_argument("--definition requires --attach-image, --pid and --project");
    }
    const auto executable = attached ? std::wstring{} : args.require(L"--exe");
    auto module = attached ? std::wstring{} : args.get(L"--module", executable);
    const auto input = args.get(L"--input", L"repl");
    if (!args.has(L"--confirm") || args.get(L"--disposition") != L"resume-detach" ||
        (input != L"repl" && input != L"jsonl")) {
        throw std::invalid_argument("Require --confirm, --disposition resume-detach and --input repl|jsonl");
    }
    if (attached) {
        if (!args.has(L"--creation-filetime") || args.has(L"--exe") ||
            args.has(L"--watch-pointer-export") || args.has(L"--execute-pointer-export") || args.has(L"--cooperative-pair"))
            throw std::invalid_argument("Explicit attachment requires PID and creation FILETIME; no EXE/pointer/pair selectors");
        if (imageAttachment)
        {
            module = args.require(L"--module"); // 对已有实例只选择目标已加载模块，不创建进程。
            const auto selectors = static_cast<unsigned>(args.has(L"--rva")) +
                static_cast<unsigned>(args.has(L"--export")) + static_cast<unsigned>(definition);
            if (!AbsoluteImage(module) || selectors != 1 ||
                args.has(L"--address") || args.has(L"--range-bytes") || args.has(L"--watch-write-bytes"))
            {
                throw std::invalid_argument("--attach-image requires an absolute module and exactly one export, RVA or saved definition; no private address or data watch");
            }
        }
        else if (!args.has(L"--address") || args.has(L"--module") || args.has(L"--export") || args.has(L"--rva"))
        {
            throw std::invalid_argument("Private attachment requires --address; use --attach-image for module export/RVA attachment");
        }
    } else if (!AbsoluteImage(executable) || !AbsoluteImage(module) ||
        args.has(L"--rva") == args.has(L"--export") || args.has(L"--address") || args.has(L"--creation-filetime") || imageAttachment) {
        throw std::invalid_argument("Require an explicitly authorized child EXE and exactly one export or RVA");
    }
    const bool cooperativePair = args.has(L"--cooperative-pair"); // 仅接本工具启动的同一合作 EXE 的两个实例。
    if (cooperativePair && (!args.has(L"--export") || args.has(L"--module") ||
        args.has(L"--watch-write-bytes"))) {
        throw std::invalid_argument("Cooperative pair requires one EXE execution export and no module or data watch");
    }
    native::NativeBreakpointRequest request;
    request.modulePath = std::move(module);
    request.explicitImageAttachment = imageAttachment;
    request.target.explicitlyAuthorized = true;
    request.target.disposition = native::NativeTargetDisposition::ResumeAndDetach;
    if (attached) {
        request.target.pid = args.u32(L"--pid");
        request.target.processCreationTime = args.integer(L"--creation-filetime");
        if (!imageAttachment)
        {
            request.privateAddress = args.integer(L"--address"); // 单地址/NX范围的实际起点。
        }
        if (args.has(L"--range-bytes"))
        {
            request.privateRangeBytes = args.integer(L"--range-bytes"); // 显式NX范围，实际可用长度由原生层核验。
        }
        if (!request.target.pid || !request.target.processCreationTime || (!imageAttachment && !request.privateAddress))
            throw std::invalid_argument("PID, creation FILETIME and the selected private address must be nonzero");
    }
    if ((!attached || imageAttachment) && args.has(L"--rva")) {
        const auto rva = args.u32(L"--rva");
        if (!rva) throw std::invalid_argument("Require a nonzero instruction-boundary RVA");
        request.rva = rva;
    } else if ((!attached || imageAttachment) && !definition) {
        const auto name = args.require(L"--export");
        if (name.empty() || name.size() > 255) throw std::invalid_argument("Invalid PE export name");
        for (const auto character : name) {
            if (character < 0x21 || character > 0x7e) throw std::invalid_argument("Require an ASCII PE export name");
            request.exportName.push_back(static_cast<char>(character));
        }
    }

    // 写关注接受导出或明确私有地址；条件按真实写入事件提供变化字段与冻结寄存器。
    if (args.has(L"--watch-write-bytes")) {
        const auto width = args.u32(L"--watch-write-bytes"); // 真实硬件关注宽度，单位字节。
        if ((width != 1 && width != 2 && width != 4 && width != 8) || args.has(L"--rva") ||
            args.has(L"--module") || request.privateRangeBytes) {
            throw std::invalid_argument("Data write watch requires a width of 1/2/4/8 and no module or RVA");
        }
        request.writeWatchBytes = width;
    }
    if (args.has(L"--watch-pointer-export")) {
        if (!request.writeWatchBytes) {
            throw std::invalid_argument("--watch-pointer-export requires --watch-write-bytes and the EXE's AMD64 pointer data export");
        }
        request.writeWatchPointerExport = true;
    }
    if (args.has(L"--execute-pointer-export")) {
        // 首版仅启动自有合作EXE，沿用唯一原生owner及单目标执行的条件、步进和归档。
        if (request.writeWatchBytes || request.writeWatchPointerExport || cooperativePair ||
            args.has(L"--rva") || args.has(L"--module")) {
            throw std::invalid_argument("--execute-pointer-export requires one EXE pointer data export and no data watch, module, RVA or pair");
        }
        request.executePointerExport = true;
    }
    if (args.has(L"--range-bytes") && (!attached || !request.privateRangeBytes))
    {
        throw std::invalid_argument("--range-bytes requires an explicit private address and a nonzero page-aligned execution range");
    }

    std::optional<BreakpointCondition> condition;
    if (args.has(L"--condition")) condition = PrepareCondition(args.require(L"--condition"));
    if (args.has(L"--sample") && !args.has(L"--project"))
        throw std::invalid_argument("--sample requires --project");
    if (args.has(L"--project") && cooperativePair)
        throw std::invalid_argument("--project requires a single-target breakpoint session");
    std::unique_ptr<NativeExecutionJournal> journal;
    if (args.has(L"--project")) {
        std::string sample;
        if (args.has(L"--sample")) {
            for (const auto ch : args.require(L"--sample")) {
                if (ch > 127) throw std::invalid_argument("--sample must be a canonical UUID");
                sample.push_back(static_cast<char>(ch));
            }
            if (!Ksword::ActionAnalyze::ProjectStorage::IsUuid(sample))
                throw std::invalid_argument("--sample must be a canonical UUID");
        }
        journal = std::make_unique<NativeExecutionJournal>();
        if (const auto status = journal->Open(args.require(L"--project"), sample); !status) {
            std::cerr << Ksword::ActionAnalyze::ProjectErrorName(status.error) << ": " << status.detail
                << " (" << status.nativeError << ")\n";
            return 3;
        }
        if (definition)
        {
            std::string definitionId; // CLI定义ID仅接受ASCII规范UUID，不经过有损代码页转换。
            for (const auto character : args.require(L"--definition"))
            {
                if (character > 127)
                {
                    throw std::invalid_argument("--definition must be a canonical UUID");
                }
                definitionId.push_back(static_cast<char>(character));
            }
            std::uint32_t rva = 0; // 由冻结定义解析后才提交原native。
            if (const auto status = journal->ResolveImageDefinition(definitionId, request.modulePath, rva, request.imageSha256); !status)
            {
                std::cerr << Ksword::ActionAnalyze::ProjectErrorName(status.error) << ": " << status.detail
                    << " (" << status.nativeError << ")\n";
                return 3;
            }
            request.rva = rva;
        }
    }
    // 归档会话使用真实已提交采样，其余会话保持一次性身份。
    using Ksword::ActionAnalyze::ProjectStorage::NewId;
    native::OwnerIdentity id;
    if (!NewId(id.sampleId) || !NewId(id.sessionId) || !NewId(id.epoch) || !NewId(id.backendInstanceId) ||
        !NewId(request.target.requestId)) return 3;
    if (journal) id.sampleId = journal->SampleId();
    return BreakpointSession(input == L"jsonl", id, std::move(condition), cooperativePair, std::move(journal)).Run(executable, std::move(request));
}
} // namespace

void RegisterBreakpointCommand()
{
    Command command;
    command.path = L"analyze breakpoint session";
    command.syntax = L"KswordCLI.exe analyze breakpoint session (--exe PATH [--module PATH] (--export NAME | --rva RVA) | --pid PID --creation-filetime N (--address ADDR [--range-bytes N] | --attach-image --module PATH (--export NAME | --rva RVA | --definition UUID))) --confirm --disposition resume-detach [--input repl|jsonl] [--condition EXPR] [--project PATH [--sample UUID]] [--watch-write-bytes 1|2|4|8 [--watch-pointer-export] | --execute-pointer-export | --cooperative-pair]";
    command.summary = L"Control execution or write breakpoints in an explicitly selected AMD64 process instance.";
    command.options = L"The EXE and optional loaded module use absolute DOS paths; module defaults to the EXE. Use an exact PE export or instruction-boundary RVA. --watch-pointer-export resolves an aligned AMD64 pointer data export to one committed writable private interval; the child must acknowledge inherited --ksword-breakpoint-ready and --ksword-breakpoint-gate handles after initializing the pointer and wait for byte '1'. Pointer/region changes retire the binding, with no automatic rebinding or verified allocation generation. Optional --condition uses predicate-expr-v3 at execution entry or data-write observation. Fields: stop.address, stop.exceptionCode, stop.pid, stop.tid, stop.thread.creationFileTime, stop.thread.rip, stop.thread.rax and stop.thread.rsp (u64), stop.firstChance (bool). Registers come from the actual event thread's frozen context; failed collection remains unknown. Write observations also provide stop.data.changedByteMask, stop.data.enrolledAfterStop and stop.data.watchedBytes (u64); execution events leave data fields unknown.";
    command.options += L" Numeric conditions support field-to-field comparisons, parentheses, unary ~ and +, multiplication/division/remainder, addition/subtraction, shifts and bitwise &, ^, | with C# precedence. Parenthesize bitwise expressions before comparison, for example (stop.thread.rax & 0xffu64) == 0u64 and stop.thread.rip >= stop.address. Unsigned overflow wraps; shift counts use their low six bits. Division or remainder by zero returns Unknown with evaluationFault=division-by-zero. Unknown fields are never treated as zero. Legacy v1/v2 profiles remain readable.";
    command.options += L" Full frozen AMD64 register fields under stop.thread are eflags, rax, rbx, rcx, rdx, rbp, rsi, rdi, rsp, rip and r8 through r15 (all u64). control.registers reports the same event snapshot; zero is a known value. Manual pause does not collect registers or evaluate breakpoint conditions. Example: (stop.thread.eflags & 0x40u64) != 0u64 && stop.thread.rcx == stop.thread.rdx.";
    command.options += L" Into uses the shared bounded AMD64 instruction decoder for supported memory, arithmetic, branch, near call/return and SSE/AVX encodings. It reads at most one 15-byte instruction and requires an actual TF event for completion. Unknown encodings, REP string completion, POPF, SS changes, privileged transitions and competing debug state are rejected; Out still requires a proven frame or actual RET boundary.";
    command.options += L" Add private execution ranges at the current complete NX stop: REPL execution-range-add ADDRESS BYTES STOP_ID STATE_REVISION; JSONL control.execution.range.add requires params:{address,bytes} as positive decimal strings, exact expected:{stopId,stateRevision}, the live session and consecutive range/N IDs starting at range/1. The original owner retains 128 receipts independently of Continue/Step. New ranges may be disjoint or belong to different allocations; each range must cover committed executable private pages within one allocation. Total pages across all ranges cannot exceed 64; overlaps are rejected. No Continue occurs and the original event and initial binding.address/rangeBytes remain unchanged. binding.executionRanges lists successful ranges; control.executionRange separates added, rollbackComplete, stage and error. Cleanup retains unresolved protection responsibilities.";
    command.options += L" --execute-pointer-export uses the EXE's aligned AMD64 pointer data export to select one committed MEM_PRIVATE EXECUTE/RX/RWX destination. It requires the same Ready/Gate handshake and is exclusive with data watch, module, RVA and pair. The selector is image data; DR0 watches its frozen destination without changing page protection. Pointer or region changes retire the binding without rebinding. Single-target condition, step and project evidence commands remain available.";
    command.options += L" To attach to an existing AMD64 process, use --pid PID --creation-filetime FILETIME --address ADDR instead of --exe/module/export/rva/pointer/pair selectors. The selected address must be committed private memory: EXECUTE/RX/RWX for execution, or aligned RW/RWX for --watch-write-bytes. The default single-address mode uses DR0 without changing protection. No cooperative gate is needed. The original owner enrolls new threads, retains stop tokens and retires the binding if the frozen region changes. Addresses accept decimal or 0x notation. An existing target may execute before the armed receipt; this mode does not claim earliest-start coverage.";
    // 范围模式改变执行权限，必须与默认单地址DR0的说明分开呈现。
    command.options += L" Use --attach-image with --pid, --creation-filetime, an absolute --module path and exactly one --export or --rva to monitor execution in an already running process's loaded image. No child process or cooperative handshake is created. The native owner verifies the process instance and executable image site and uses its original DR0, thread enrollment, conditions, step, memory and execution archive paths. This selector excludes private addresses, NX ranges and data write watches. The export is an exact PE export; PDB symbols are not resolved.";
    command.options += L" Optional --range-bytes selects private NX execution monitoring, exclusive with data watch. Use a 4096-byte-aligned base and a nonzero page-aligned length accepted by the native owner. This temporarily removes execute permission while preserving the original read/write permissions, and restores protection during cleanup. binding.rangeBytes identifies the monitored range; hit.address is the actual instruction address within it. Continue advances the stopped instruction with native TF and rearms NX before releasing peer threads. Unsupported advancement retains the stop and reports its stage.";
    command.notes = L"Data write watch requires an aligned writable data export or an explicit private address. --cooperative-pair requires the EXE's execution export and two children that acknowledge inherited Ready/Gate handles. Pair conditions evaluate only a fully held group: any true member holds both; otherwise both auto-continue. REPL: status, continue STOP_ID STATE_REVISION, step into|over-call|out STOP_ID STATE_REVISION THREAD_ID TID CREATION_FILETIME, step-status STEP_REQUEST_ID, step-cancel STEP_REQUEST_ID, quit. Step requires a single-target session and its current frozen originThread; write stops use the actual event thread's current instruction, not the watched data address. JSONL adds control.step, control.step.query and control.step.cancel; independent step/N and continue/N IDs start at 1, with 128 retained receipts. Step modes support known native instructions/frames; unknown instructions or frames are rejected. A new step stop is held without reapplying the breakpoint condition. Shutdown reports confirmed cleanup or keeps the session open if cleanup is unresolved. Native retirement and the first recovery failure are reported independently when recorded.";
    command.options += L" Saved definition activation uses --attach-image --module PATH --definition UUID --project PATH, exclusive with --export and --rva. The definition is read from the session sample's frozen settings, not a later project revision. It must be saved, enabled, a nonzero RVA and have a matching module basename. Optional imageSha256 is verified against the actual CREATE_PROCESS/LOAD_DLL event file for the resolved module before DR0 is armed; missing files and mismatches reject activation. control.breakpoint.imageSha256 reports the measured hash. File identity does not authenticate modified runtime image pages. Debug-symbol resolution is not supported. hello.executionArchive.breakpointDefinitionId records the actual source definition. Existing stop tokens are never imported from the project.";
    command.notes += L" Active single-target owners support REPL pause PID CREATION_FILETIME and pause-status pause/N. JSONL control.pause requires the current session, no expected, params:{targetPid:UInt,targetCreationFileTime:positive-decimal-string} and consecutive independent pause/N IDs (128 receipts). control.pause.query takes params:{requestId:pause/N} with an ordinary query ID. Acceptance means pending; armedPause.state=held and stopReason=manual-pause identify an actual interruption. Real target hits can preempt the interruption and retain their original identity. Continue uses the current exact stop token; manual pauses do not apply the breakpoint condition, create execution evidence or enable stepping on the interrupt helper. The original owner retains all breakpoint and page recovery responsibilities.";
    command.runStreaming = Run;
    command.options += L" Optional --project opens an existing project with an exclusive writer lease for this entire single-target session; --sample reuses a committed sample, otherwise creates one from the current revision. Startup verifies the complete raw-native chain before launching or attaching. Write sessions support held memory snapshots and same-sample API capture; execution-save requires an actual execution observation.";
    command.notes += L" REPL execution-save STOP_ID STATE_REVISION / JSONL control.execution.save explicitly saves the current owned execution observation without continuing. JSONL requires the current session, empty params and exact expected stopId/stateRevision. Repeated saves of the same native event return its original coordinates. At most 4096 events are saved per session; any write/readback failure blocks further appends and retains written/flushed receipts. Read history with analyze execution read.";
    command.notes += L" Project sessions also provide REPL memory-snapshot BASE BYTES STOP_ID STATE_REVISION and JSONL control.memory.snapshot with params:{base,bytes} as canonical positive decimal strings and exact expected stopId/stateRevision. The same live owner must hold a complete stop before and after the read. No continue is issued. Each explicit read stores a new raw-memory segment (up to 64 pages; at most 4096 segments per sample), preserving readContext, actual bytes, SHA-256 and gaps. Response exitCode 6 means an incomplete range or changed stop; the session remains open. Memory write/readback failure blocks only raw-memory. Read/export with analyze memory read/export.";
    command.notes += L" Same-sample API capture: REPL api-capture PID FILETIME DURATION confirm; JSONL control.api.capture requires the current session, no expected, and exactly params:{sourcePid:UInt,sourceCreationFileTime:decimal-string,durationMs:UInt,confirm:true}. Source must differ from the native target. The 1000..10000ms interval runs synchronously; startup and stop/drain timeouts are additional. Other control instructions wait until completion (no zero-duration mode). The independent debug thread retains any owned stop; API shutdown never continues or closes native control. Reuses the original project writer/sample, without Agent ETW; raw or checkpoints directory already present, including empty or damaged content, rejects capture. Response exitCode, capture, archive prefix, rule SHA, transfer counts and cleanup are independent. Explicitly use execution-save afterwards; no native event is saved automatically. Same-sample storage does not authenticate sources or establish causality.";
    command.notes += L" Private write-to-execution follow: REPL execution-follow ADDRESS STOP_ID STATE_REVISION; JSONL control.execution.follow requires the current session, exactly params:{address:positive-decimal-string}, exact expected:{stopId,stateRevision}, and independent consecutive follow/N IDs starting at follow/1 (128 retained receipts). Use a single-target private write watch and query breakpoint.privateExecutionFollowAvailable with the current complete write stop; confirm the exact original address, originally at the start of an RWX private region. The same owner verifies every live thread and rolls back failed conversion. The operation changes the same-address watch to execution without Continue or Step or changing page protection; the original held hit remains a write observation. hello.followProtocol describes the protocol; control.executionFollow reports converted, rollbackComplete, stage and native error. Continue explicitly with the current stop only after inspecting the result. Old validation does not cover this entry.";
    addCommand(std::move(command));
}

} // namespace ks::cli::action_analyze
