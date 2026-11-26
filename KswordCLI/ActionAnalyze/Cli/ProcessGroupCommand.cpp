#include "ProcessGroupCommand.h"

#include "Transport.h"
#include "ProcessGroupMemoryArchive.h"
#include "../Control/OwnedProcessGroup.h"
#include "../Control/ProcessGroupMemorySnapshot.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"
#include "../../../shared/usermode/backend/Common.h"

#include <charconv>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
namespace native = control;
using V = JsonValue;

V Text(std::string_view value) { return V::makeString(std::string(value)); }
V Count(std::uint64_t value) { return Text(std::to_string(value)); }

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

bool StringField(const V* field, std::string& value)
{
    return field && field->tryGetString(value) && !value.empty() && value.size() <= kRequestIdBytes;
}

std::vector<std::string_view> Split(std::string_view text, char separator)
{
    std::vector<std::string_view> result;
    for (;;) {
        const auto at = text.find(separator);
        result.push_back(text.substr(0, at));
        if (at == std::string_view::npos) return result;
        text.remove_prefix(at + 1);
    }
}

bool TargetText(std::string_view text, native::ProcessGroupTarget& target)
{
    const auto pieces = Split(text, ':');
    std::uint64_t pid = 0;
    if (pieces.size() != 2 || !Decimal(pieces[0], pid) || pid > std::numeric_limits<std::uint32_t>::max() ||
        !Decimal(pieces[1], target.creationFileTime)) return false;
    target.pid = static_cast<std::uint32_t>(pid);
    return true;
}

bool TargetValue(const V& value, native::ProcessGroupTarget& target)
{
    const auto* fields = value.asObject();
    const auto* pid = value.find("pid");
    std::uint64_t number = 0;
    if (!fields || fields->size() != 2 || !pid || pid->type() != Ksword::Evidence::JsonType::UInt ||
        !pid->tryGetU64(number) || !number || number > std::numeric_limits<std::uint32_t>::max() ||
        !DecimalField(value.find("creationFileTime"), target.creationFileTime)) return false;
    target.pid = static_cast<std::uint32_t>(number);
    return true;
}

bool TargetList(std::string_view text, std::vector<native::ProcessGroupTarget>& targets)
{
    const auto pieces = Split(text, ',');
    for (const auto piece : pieces) {
        native::ProcessGroupTarget target;
        if (!TargetText(piece, target)) return false;
        targets.push_back(target);
    }
    return !targets.empty();
}

V Target(const native::ProcessGroupTarget& target)
{
    return V::makeObject({{"pid", V::makeUInt(target.pid)}, {"creationFileTime", Count(target.creationFileTime)}});
}

V Event(const native::NativeEventKey& event)
{
    return V::makeObject({{"backendInstanceId", Text(event.backendInstanceId)}, {"serial", Count(event.serial)}});
}

V Stop(const native::ProcessGroupStop& stop)
{
    return V::makeObject({{"target", Target(stop.target)}, {"groupId", Text(stop.groupId)},
        {"stopId", Text(stop.stopId)}, {"event", Event(stop.event)}, {"stateRevision", Count(stop.stateRevision)}});
}

bool StopValue(const V& value, native::ProcessGroupStop& stop)
{
    const auto* fields = value.asObject();
    const auto* target = value.find("target");
    const auto* event = value.find("event");
    return fields && fields->size() == 5 && target && TargetValue(*target, stop.target) &&
        StringField(value.find("groupId"), stop.groupId) && StringField(value.find("stopId"), stop.stopId) &&
        DecimalField(value.find("stateRevision"), stop.stateRevision) && event && event->asObject() &&
        event->asObject()->size() == 2 && StringField(event->find("backendInstanceId"), stop.event.backendInstanceId) &&
        DecimalField(event->find("serial"), stop.event.serial);
}

// REPL 的显式令牌包含与 JSONL 完全相同的身份字段，不从当前选择补任何字段。
bool StopText(std::string_view text, native::ProcessGroupStop& stop)
{
    const auto pieces = Split(text, ':');
    if (pieces.size() != 7 || !TargetText(std::string(pieces[0]) + ":" + std::string(pieces[1]), stop.target) ||
        pieces[2].empty() || pieces[3].empty() || pieces[4].empty() ||
        pieces[2].size() > kRequestIdBytes || pieces[3].size() > kRequestIdBytes || pieces[4].size() > kRequestIdBytes ||
        !Decimal(pieces[5], stop.event.serial) || !Decimal(pieces[6], stop.stateRevision)) return false;
    stop.groupId = pieces[2];
    stop.stopId = pieces[3];
    stop.event.backendInstanceId = pieces[4];
    return true;
}

bool MemoryAddress(std::string_view text, std::uint64_t& value)
{
    if (!text.starts_with("0x")) return Decimal(text, value);
    text.remove_prefix(2);
    if (text.empty() || text.size() > 16) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && value != 0;
}

const char* MemoryState(memory::State state)
{
    using enum memory::State;
    switch (state) {
    case Idle: return "idle";
    case Active: return "active";
    case Completed: return "completed";
    case Stopped: return "stopped";
    case Canceled: return "canceled";
    case TargetExited: return "target-exited";
    case Rejected: return "rejected";
    case Failed: return "failed";
    }
    return "unknown";
}

const char* MemoryPageState(memory::PageStatus state)
{
    using enum memory::PageStatus;
    switch (state) {
    case NotCommitted: return "not-committed";
    case Guarded: return "guarded";
    case UnsafeReadAttributes: return "unsafe-read-attributes";
    case NotReadable: return "not-readable";
    case QueryFailed: return "query-failed";
    case ReadFailed: return "read-failed";
    case MappingUnstable: return "mapping-unstable";
    case HashFailed: return "hash-failed";
    case Sampled: return "sampled";
    }
    return "unknown";
}

V MemoryIssue(const memory::Issue& issue)
{
    using enum memory::Stage;
    const char* stage = "unknown";
    switch (issue.stage) {
    case None: return V::makeNull();
    case ValidatePlan: stage = "validate-plan"; break;
    case DuplicateProcess: stage = "duplicate-process"; break;
    case ProcessId: stage = "process-id"; break;
    case ProcessCreation: stage = "process-creation"; break;
    case ProcessMismatch: stage = "process-mismatch"; break;
    case ProcessLifetime: stage = "process-lifetime"; break;
    case OpenOwnerToken: stage = "open-owner-token"; break;
    case OpenTargetToken: stage = "open-target-token"; break;
    case ReadTokenIdentity: stage = "read-token-identity"; break;
    case TokenOwnerMismatch: stage = "token-owner-mismatch"; break;
    case CriticalProcess: stage = "critical-process"; break;
    case TargetMachine: stage = "target-machine"; break;
    case Clock: stage = "clock"; break;
    case OpenHashProvider: stage = "open-hash-provider"; break;
    case QueryBeforeRead: stage = "query-before-read"; break;
    case ReadMemory: stage = "read-memory"; break;
    case QueryAfterRead: stage = "query-after-read"; break;
    case CompareMappings: stage = "compare-mappings"; break;
    case HashContent: stage = "hash-content"; break;
    }
    return V::makeObject({{"stage", Text(stage)}, {"win32Error", V::makeUInt(issue.win32Error)},
        {"ntStatus", issue.ntStatus ? V::makeInt(*issue.ntStatus) : V::makeNull()}});
}

V MemoryRange(const memory::Range& range)
{
    return V::makeObject({{"base", Count(range.base)}, {"length", Count(range.length)}});
}

V MemoryWindow(const memory::QpcWindow& window)
{
    return V::makeObject({{"begin", Count(window.begin)}, {"end", Count(window.end)}});
}

V MemoryMapping(const std::optional<memory::Mapping>& mapping)
{
    return mapping ? V::makeObject({{"region", MemoryRange(mapping->region)},
        {"allocationBase", Count(mapping->allocationBase)}, {"state", V::makeUInt(mapping->state)},
        {"type", V::makeUInt(mapping->type)}, {"protection", V::makeUInt(mapping->protection)},
        {"allocationProtection", V::makeUInt(mapping->allocationProtection)}}) : V::makeNull();
}

std::string MemoryHash(const memory::Sha256& hash)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(hash.size() * 2);
    for (const auto byte : hash) {
        text.push_back(digits[byte >> 4]);
        text.push_back(digits[byte & 15]);
    }
    return text;
}

V MemoryReport(const native::ProcessMemorySnapshotResult& result)
{
    const auto& plan = result.request.plan;
    V snapshot = V::makeNull();
    if (result.snapshot) {
        const auto& capture = *result.snapshot;
        std::uint64_t capturedBytes = 0;
        for (const auto& page : capture.captured) capturedBytes += page.bytes.size();
        JsonArray pages;
        if (capture.round) for (const auto& page : capture.round->pages) {
            // 成功字节及系统实际返回长度分别报告；失败读取不当作已核验内容。
            std::uint64_t validLength = 0;
            for (const auto& stored : capture.captured) {
                if (stored.observation.pageBase == page.pageBase && stored.observation.sampledRange == page.sampledRange)
                    validLength += stored.bytes.size();
            }
            pages.push_back(V::makeObject({{"pageBase", Count(page.pageBase)}, {"range", MemoryRange(page.sampledRange)},
                {"state", Text(MemoryPageState(page.status))}, {"validLength", Count(validLength)},
                {"returnedBytes", page.returnedBytes ? Count(*page.returnedBytes) : V::makeNull()},
                {"sha256", page.content ? Text(MemoryHash(page.content->sha256)) : V::makeNull()},
                {"readQpc", page.readQpc ? MemoryWindow(*page.readQpc) : V::makeNull()},
                {"mappingBefore", MemoryMapping(page.before)}, {"mappingAfter", MemoryMapping(page.after)},
                {"issue", MemoryIssue(page.issue)},
                {"additionalIssue", page.additionalIssue ? MemoryIssue(*page.additionalIssue) : V::makeNull()}}));
        }
        const auto& status = capture.status;
        snapshot = V::makeObject({{"state", Text(MemoryState(status.state))}, {"issue", MemoryIssue(status.issue)},
            {"completeRange", V::makeBool(capture.completeRange)}, {"capturedBytes", Count(capturedBytes)},
            {"sampledPages", Count(status.sampledPages)}, {"unavailablePages", Count(status.unavailablePages)},
            {"plannedPages", V::makeUInt(status.plannedPages)}, {"pageSize", V::makeUInt(status.pageSize)},
            {"pointerWidth", V::makeUInt(status.pointerWidth)}, {"qpcFrequency", Count(status.qpcFrequency)},
            {"allPagesVisited", V::makeBool(capture.round && capture.round->allPagesVisited)},
            {"beginQpc", capture.round ? Count(capture.round->beginQpc) : V::makeNull()},
            {"endQpc", capture.round && capture.round->endQpc ? Count(*capture.round->endQpc) : V::makeNull()},
            {"pages", V::makeArray(std::move(pages))}});
    }
    return V::makeObject({{"stage", Text(result.stage)}, {"win32Error", V::makeUInt(result.win32Error)},
        {"source", Text(result.request.source == native::ProcessMemorySource::LiveRead ? "live-read" : "held-event")},
        {"sampleId", Text(plan.sampleId)}, {"trackingEpoch", Text(plan.trackingEpoch)},
        {"captureId", Text(plan.trackingEpoch)}, {"captureAvailable", V::makeBool(result.snapshot && result.snapshot->round)},
        {"target", Target({plan.target.pid, plan.target.creationFileTime100ns})}, {"range", MemoryRange(plan.range)},
        {"requestedStop", result.request.stop ? Stop(*result.request.stop) : V::makeNull()},
        {"before", result.before ? Stop(*result.before) : V::makeNull()},
        {"after", result.after ? Stop(*result.after) : V::makeNull()}, {"heldAtBothChecks", V::makeBool(result.heldAtBothChecks)},
        {"atomicProcessSnapshot", V::makeBool(false)}, {"bytesIncluded", V::makeBool(false)},
        {"snapshot", std::move(snapshot)}});
}

const char* Ledger(native::LedgerResult result)
{
    using enum native::LedgerResult;
    switch (result) {
    case Applied: return "applied";
    case Duplicate: return "duplicate";
    case InvalidEvidence: return "invalid-evidence";
    case MissingGroup: return "missing-group";
    case IdentityMismatch: return "identity-mismatch";
    case Conflict: return "conflict";
    case Capacity: return "capacity";
    case StaleRevision: return "stale-revision";
    case InvalidTransition: return "invalid-transition";
    case Historical: return "historical";
    case ReadbackRequired: return "readback-required";
    case ReplayExpired: return "replay-expired";
    }
    return "unknown";
}

const char* State(native::ProcessGroupState state)
{
    using enum native::ProcessGroupState;
    switch (state) {
    case Idle: return "idle";
    case Ready: return "ready";
    case Active: return "active";
    case HeldPartial: return "held-partial";
    case HeldComplete: return "held-complete";
    case Closing: return "closing";
    case Closed: return "closed";
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

V Control(const native::NativeControlResult& state)
{
    JsonObject fields{{"state", Text(ControlState(state.status))}, {"stage", Text(state.stage)},
        {"win32Error", V::makeUInt(state.win32Error)}, {"ledgerResult", Text(Ledger(state.ledgerResult))},
        {"attached", V::makeBool(state.attached)}, {"clean", V::makeBool(state.clean)},
        {"pid", V::makeUInt(state.pid)}, {"creationFileTime", Count(state.processCreationTime)},
        {"processInstanceId", Text(state.processInstanceId)}};
    if (state.group) {
        fields.emplace_back("stopGroup", V::makeObject({{"groupId", Text(state.group->groupId)},
            {"stateRevision", Count(state.group->stateRevision)}, {"membershipRevision", Count(state.group->membershipRevision)},
            {"membershipSha256", Text(state.group->membershipSha256)}, {"memberCount", Count(state.group->members.size())},
            {"historical", V::makeBool(state.group->historical)}}));
    }
    if (state.pending) fields.emplace_back("pending", V::makeObject({{"event", Event(state.pending->event)},
        {"tid", V::makeUInt(state.pending->tid)}, {"ledgerOwned", V::makeBool(state.pending->ledgerOwned)},
        {"continuationIndeterminate", V::makeBool(state.pending->continuationIndeterminate)}}));
    if (state.release && state.release->receipt) {
        const auto& receipt = *state.release->receipt;
        fields.emplace_back("release", V::makeObject({{"result", Text(receipt.result == native::ReleaseResult::Continued ?
            "continued" : receipt.result == native::ReleaseResult::StillPending ? "still-pending" : "indeterminate")},
            {"win32Error", receipt.nativeError ? V::makeUInt(*receipt.nativeError) : V::makeNull()}}));
    }
    if (state.retirement) fields.emplace_back("retirement", V::makeObject({
        {"kind", Text(state.retirement->kind == native::NativeRetirementKind::Detached ? "detached" : "exit-event-continued")},
        {"backendInstanceId", Text(state.retirement->owner.backendInstanceId)},
        {"exitEvent", state.retirement->exitEvent ? Event(*state.retirement->exitEvent) : V::makeNull()},
        {"exitCode", state.retirement->exitCode ? V::makeUInt(*state.retirement->exitCode) : V::makeNull()}}));
    if (state.firstRecoveryFailure) fields.emplace_back("firstRecoveryFailure", V::makeObject({
        {"stage", Text(state.firstRecoveryFailure->stage)}, {"win32Error", V::makeUInt(state.firstRecoveryFailure->win32Error)},
        {"backendInstanceId", Text(state.firstRecoveryFailure->owner.backendInstanceId)},
        {"pendingEvent", state.firstRecoveryFailure->pendingEvent ? Event(*state.firstRecoveryFailure->pendingEvent) : V::makeNull()},
        {"releaseRequestId", state.firstRecoveryFailure->releaseRequestId ? Text(*state.firstRecoveryFailure->releaseRequestId) : V::makeNull()}}));
    return V::makeObject(std::move(fields));
}

V Report(const native::ProcessGroupResult& state)
{
    JsonArray members;
    for (const auto& member : state.members) members.push_back(V::makeObject({{"target", Target(member.target)},
        {"clean", V::makeBool(member.clean)}, {"stop", member.stop ? Stop(*member.stop) : V::makeNull()},
        {"control", member.control ? Control(*member.control) : V::makeNull()}}));
    V operation = V::makeNull();
    if (state.operation) {
        JsonArray outcomes;
        for (const auto& outcome : state.operation->outcomes) outcomes.push_back(V::makeObject({
            {"target", Target(outcome.target)}, {"control", Control(outcome.control)}}));
        operation = V::makeObject({{"requestId", Text(state.operation->requestId)},
            {"action", Text(state.operation->action == native::ProcessGroupAction::Pause ? "pause" :
                state.operation->action == native::ProcessGroupAction::Continue ? "continue" : "recover")},
            {"ledgerResult", Text(Ledger(state.operation->ledgerResult))}, {"stage", Text(state.operation->stage)},
            {"win32Error", V::makeUInt(state.operation->win32Error)},
            {"outcomes", V::makeArray(std::move(outcomes))}});
    }
    return V::makeObject({{"state", Text(State(state.state))}, {"stage", Text(state.stage)},
        {"win32Error", V::makeUInt(state.win32Error)}, {"ledgerResult", Text(Ledger(state.ledgerResult))},
        {"clean", V::makeBool(state.clean)}, {"members", V::makeArray(std::move(members))}, {"operation", std::move(operation)}});
}

class ProcessGroupSession final {
public:
    // 绑定对象由启动入口先行冻结；原控制组和项目写租约共同保留到真实清退结束。
    ProcessGroupSession(bool jsonl, native::OwnerIdentity identity, std::vector<native::ProcessGroupTarget> targets,
        ProcessGroupMemoryArchive& archive)
        : jsonl_(jsonl), identity_(std::move(identity)), targets_(std::move(targets)), group_(identity_), archive_(archive) {}

    int Run()
    {
        if (const auto error = transport_.Start(jsonl_)) {
            std::cerr << error.message << '\n';
            return error.code;
        }
        try {
            const auto configured = group_.Configure(targets_, true, native::NativeTargetDisposition::ResumeAndDetach);
            if (!Emit("hello", {}, V::makeObject({{"control", Report(configured)},
                {"sampleId", Text(identity_.sampleId)}, {"memoryArchive", archive_.Describe()},
                {"groupProtocol", V::makeObject({{"requestIdFormat", Text("group/<strictly increasing positive uint64 decimal>")},
                    {"firstRequestId", Text("group/1")}, {"replayEntries", Count(128)},
                    {"maxMembers", V::makeNull()}, {"configurationPauses", V::makeBool(false)},
                    {"memorySnapshot", V::makeBool(true)}, {"memorySave", V::makeBool(!archive_.SampleId().empty())},
                    {"memorySources", V::makeArray({Text("live-read"), Text("held-event")})},
                    {"memorySaveRequires", Text("displayed captureId and frozen sampleId; never rereads")}})}})))
                return End("output-lost", 3);
            if (configured.win32Error) return End("configuration-rejected", 3);
            return Loop();
        } catch (...) {
            return End("process-group-processing-failed", 6);
        }
    }

private:
    // 在现有集合回执上附加保存通道状态，不改动成员或原始操作票据。
    V ControlReport(const native::ProcessGroupResult& state) const
    {
        const auto report = Report(state); // 原成员与票据投影，维持既有 JSON 字段布局。
        auto fields = *report.asObject(); // 仅复制字段容器，不修改共享 JSON 文档。
        fields.emplace_back("memoryArchive", archive_.Describe());
        return V::makeObject(std::move(fields));
    }

    // 只保存当前已显示 capture，显式样本和 capture 身份缺一不可。
    bool MemorySave(const Request& request)
    {
        if (jsonl_ && !request.session) {
            return Invalid(request, "session-required", "Memory save requires the hello session identity");
        }
        if (request.expected) {
            return Invalid(request, "invalid-memory-save", "Memory save accepts captureId and sampleId, not a live stop token");
        }
        std::string captureId; // 用户明确指认的已显示 capture，不从当前参数重建。
        std::string sampleId; // 用户确认的冻结采样，不允许保存到其它采样。
        if (jsonl_) {
            const auto* fields = request.params.asObject(); // 严格限制保存参数，禁止混入重读范围。
            if (!fields || fields->size() != 2 || !StringField(request.params.find("captureId"), captureId) ||
                !StringField(request.params.find("sampleId"), sampleId)) {
                return Invalid(request, "invalid-memory-save", "Require params:{captureId:displayed captureId,sampleId:frozen sampleId}");
            }
        } else {
            const auto* args = request.params.asArray(); // REPL 同样显式冻结两项身份。
            if (!args || args->size() != 2 || !(*args)[0].tryGetString(captureId) || !(*args)[1].tryGetString(sampleId)) {
                return Invalid(request, "invalid-memory-save", "Usage: memory-save CAPTURE_UUID SAMPLE_UUID");
            }
        }
        return Emit("response", request.id, archive_.Save(captureId, sampleId));
    }

    bool MemorySnapshot(const Request& request)
    {
        if (jsonl_ && !request.session)
            return Invalid(request, "session-required", "Memory snapshot requires the hello session identity");
        native::ProcessMemorySnapshotRequest capture;
        native::ProcessGroupTarget target;
        std::string source, base, length;
        if (jsonl_) {
            const auto* params = request.params.asObject();
            const auto* selected = request.params.find("target");
            const auto* range = request.params.find("range");
            // 可选 sampleId 只用于确认启动时的固定采样，绝不切换到另一采样。
            const auto* requestedSample = request.params.find("sampleId"); // 调用者显式预期的冻结采样。
            if (!params || params->size() != (requestedSample ? 4 : 3) || !selected || !TargetValue(*selected, target) ||
                !StringField(request.params.find("source"), source) || !range || !range->asObject() || range->asObject()->size() != 2 ||
                !range->find("base") || !range->find("base")->tryGetString(base) ||
                !range->find("length") || !range->find("length")->tryGetString(length))
                return Invalid(request, "invalid-memory-snapshot", "Require params:{source,target:{pid,creationFileTime},range:{base,length},sampleId?:frozen sample} with string addresses/length");
            if (requestedSample) {
                std::string sampleId; // 显式确认必须匹配本控制组，不借读取切换样本。
                if (!StringField(requestedSample, sampleId) || sampleId != identity_.sampleId) {
                    return Invalid(request, "memory-snapshot-wrong-sample", "Memory snapshot must use the frozen hello sampleId");
                }
            }
        } else {
            const auto* args = request.params.asArray();
            std::string selected;
            if (!args || (args->size() != 4 && args->size() != 5) || !(*args)[0].tryGetString(source) ||
                !(*args)[1].tryGetString(selected) || !TargetText(selected, target) ||
                !(*args)[2].tryGetString(base) || !(*args)[3].tryGetString(length))
                return Invalid(request, "invalid-memory-snapshot", "Usage: memory-snapshot live-read|held-event PID:CREATION BASE LENGTH [EXACT_STOP_TOKEN]");
        }
        if (source != "live-read" && source != "held-event")
            return Invalid(request, "invalid-memory-source", "Explicit source must be live-read or held-event");
        capture.source = source == "held-event" ? native::ProcessMemorySource::HeldEvent : native::ProcessMemorySource::LiveRead;
        if (!MemoryAddress(base, capture.plan.range.base) || !Decimal(length, capture.plan.range.length) ||
            capture.plan.range.base > std::numeric_limits<std::uint64_t>::max() - capture.plan.range.length)
            return Invalid(request, "invalid-memory-range", "Require a positive decimal or 0x base and positive decimal length without overflow");
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        if (!system.dwPageSize || (capture.plan.range.base + capture.plan.range.length - 1) / system.dwPageSize -
            capture.plan.range.base / system.dwPageSize >= memory::kMaxTrackedPages)
            return Invalid(request, "invalid-memory-range", "Selected range may cover at most 64 pages");
        if (jsonl_) {
            if (capture.source == native::ProcessMemorySource::HeldEvent) {
                const auto* expected = request.expected ? request.expected->asObject() : nullptr;
                const auto* value = request.expected ? request.expected->find("stops") : nullptr;
                const auto* stops = value ? value->asArray() : nullptr;
                native::ProcessGroupStop stop;
                if (!expected || expected->size() != 1 || !stops || stops->size() != 1 || !StopValue(stops->front(), stop) || stop.target != target)
                    return Invalid(request, "invalid-memory-stop", "Held-event requires expected:{stops:[one complete stop matching target]}");
                capture.stop = std::move(stop);
            } else if (request.expected) return Invalid(request, "invalid-memory-stop", "Live-read must not include expected stops");
        } else {
            const auto& args = *request.params.asArray();
            if (capture.source == native::ProcessMemorySource::HeldEvent) {
                native::ProcessGroupStop stop;
                std::string text;
                if (args.size() != 5 || !args[4].tryGetString(text) || !StopText(text, stop) || stop.target != target)
                    return Invalid(request, "invalid-memory-stop", "Held-event requires one complete stop matching target");
                capture.stop = std::move(stop);
            } else if (args.size() != 4) return Invalid(request, "invalid-memory-stop", "Live-read does not accept a stop token");
        }
        // 此调用与 Continue/Close 使用同一个分发线程，不存在并发释放停点的路径。
        capture.plan.sampleId = identity_.sampleId;
        if (!Ksword::ActionAnalyze::ProjectStorage::NewId(capture.plan.trackingEpoch))
            return Invalid(request, "memory-identity-failed", "Could not allocate a memory capture identity");
        capture.plan.target.pid = target.pid;
        capture.plan.target.creationFileTime100ns = target.creationFileTime;
        capture.plan.target.processInstanceId = std::to_string(target.pid) + ":" + std::to_string(target.creationFileTime);
        // 会话内标签不冒充可跨采样关联的操作系统机器或启动身份。
        capture.plan.target.machineId = identity_.sessionId;
        capture.plan.target.bootId = identity_.epoch;
        capture.plan.authorizedOwnedProcess = true;
        capture.plan.rounds.reset();
        auto result = native::CaptureProcessGroupMemory(group_, capture); // 保存完整 Live/Held 及读前后停点上下文。
        if (!Emit("response", request.id, MemoryReport(result))) {
            return false;
        }
        // 仅成功进入输出队列的实际读取结果成为可保存对象；输出队列不等于接收端 ACK。
        archive_.Remember(std::move(result));
        return true;
    }

    bool Emit(std::string_view type, std::string_view requestId, V result)
    {
        auto text = Ksword::Evidence::WriteJson(V::makeObject({{"schemaVersion", V::makeUInt(1)}, {"type", Text(type)},
            {"session", V::makeObject({{"id", Text(identity_.sessionId)}, {"epoch", Text(identity_.epoch)}})},
            {"streamSequence", Count(sequence_ + 1)}, {"requestId", requestId.empty() ? V::makeNull() : Text(requestId)},
            {"result", std::move(result)}}));
        if (text.size() + 1 > kOutputBytes || !transport_.Send(std::move(text) + '\n')) return false;
        ++sequence_;
        return true;
    }

    bool Invalid(const Request& request, const char* id, const char* message)
    {
        return Emit("error", request.id, FaultJson({id, message, std::nullopt, 1, "cli", 0, "process-group-control"}));
    }

    native::ProcessGroupResult CloseAndObserve()
    {
        auto state = group_.Close();
        const auto deadline = GetTickCount64() + 3000;
        while (!state.clean && state.state != native::ProcessGroupState::RecoveryRequired && GetTickCount64() < deadline) {
            Sleep(20);
            state = group_.Query();
        }
        return state;
    }

    int Summary(std::string_view reason, int code, const native::ProcessGroupResult& state)
    {
        const bool sent = Emit("summary", {}, V::makeObject({{"reason", Text(reason)}, {"exitCode", V::makeUInt(code)},
            {"control", ControlReport(state)}}));
        return sent && transport_.Finish() ? code : 3;
    }

    int End(std::string_view reason, int code)
    {
        auto state = CloseAndObserve();
        if (!state.clean) {
            // 输入断开仍保留原所有者。未决原生责任不能因发出 summary 或销毁会话而消失。
            std::cerr << "process-group-cleanup-pending: original owners retained\n";
            cleanupOnly_ = true;
            while (!state.clean) {
                const auto input = transport_.Next(true); // 存活输入仍接受查询／恢复／清退；EOF 不建立新会话。
                if (input.kind == InputKind::Line) {
                    try {
                        const auto decoded = jsonl_ ? DecodeJsonLine(input.line, RequestProfile::Live) : DecodeReplLine(input.line); // 原会话包络校验。
                        if (decoded.error) {
                            (void)Emit("error", decoded.request.id, FaultJson(decoded.error));
                        } else if (!decoded.request.method.empty()) {
                            bool closed = false; // 只由真实 clean 允许退出，不因 Close 请求本身丢 owner。
                            (void)Dispatch(decoded.request, closed);
                        }
                    } catch (...) {
                        // 清退中的坏输入或响应投影异常不能销毁仍有原生责任的所有者。
                        std::cerr << "process-group-cleanup-command-failed: original owners retained\n";
                    }
                } else if (input.kind != InputKind::Tick) {
                    Sleep(100);
                }
                state = group_.Query();
            }
        }
        return Summary(reason, code, state);
    }

    int Loop()
    {
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
            bool closed = false;
            if (!Dispatch(decoded.request, closed)) return End("output-lost", 3);
            if (closed) return Summary("requested", 0, group_.Query());
        }
    }

    bool Dispatch(const Request& request, bool& closed)
    {
        const auto method = std::string_view(request.method);
        const auto* args = request.params.asArray();
        const auto* fields = request.params.asObject();
        const bool empty = jsonl_ ? fields && fields->empty() : args && args->empty();
        const bool pause = method == "pause" || method == "control.pause";
        const bool resume = method == "continue" || method == "control.continue";
        const bool recover = method == "recover" || method == "control.recover";
        const bool query = method == "status" || method == "query" || method == "control.query"; // 原所有者只读查询入口。
        const bool close = method == "close" || method == "quit" || method == "control.close" || method == "controller.shutdown"; // 原所有者清退入口。
        if (request.session && (request.session->id != identity_.sessionId || request.session->epoch != identity_.epoch))
            return Invalid(request, "wrong-session", "Session identity mismatch");
        if (jsonl_ && !pause && !resume && request.id.starts_with("group/"))
            return Invalid(request, "reserved-request-id", "The group/ namespace is reserved for pause and continue");
        if (cleanupOnly_ && !query && !recover && !close) {
            return Invalid(request, "cleanup-pending", "Original owners retained; use control.query, control.recover or control.close");
        }
        if (method == "control.memory.snapshot" || (!jsonl_ && method == "memory-snapshot"))
            return MemorySnapshot(request);
        if (method == "control.memory.save" || (!jsonl_ && method == "memory-save")) {
            return MemorySave(request);
        }
        if (query && empty && !request.expected)
            return Emit("response", request.id, ControlReport(group_.Query()));
        if (close && empty && !request.expected) {
            if (jsonl_ && !request.session)
                return Invalid(request, "session-required", "Close requires the hello session identity");
            const auto state = CloseAndObserve();
            closed = state.clean;
            cleanupOnly_ = !state.clean;
            return Emit("response", request.id, ControlReport(state));
        }
        if (!jsonl_ && method == "help" && empty) return Emit("response", {}, Text(
            "status | pause group/N [all|PID:CREATION,...] | continue group/N PID:CREATION:GROUP_ID:STOP_ID:BACKEND_ID:SERIAL:REVISION,... | recover group/N | memory-snapshot live-read|held-event PID:CREATION BASE LENGTH [EXACT_STOP_TOKEN] | memory-save CAPTURE_UUID SAMPLE_UUID | close"));
        if (!pause && !resume && !recover)
            return Invalid(request, "unsupported-method", "Use control.pause, control.query, control.continue, control.recover, control.memory.snapshot, control.memory.save or controller.shutdown");
        if (jsonl_ && !request.session)
            return Invalid(request, "session-required", "Mutation requires the hello session identity");

        std::string id = request.id;
        if (!jsonl_) {
            if (!args || args->empty() || !(*args)[0].tryGetString(id))
                return Invalid(request, "group-request-required", "Provide the explicit group/N request ID");
        }
        if (recover) {
            if (request.expected) return Invalid(request, "invalid-recover", "Recover takes the original continue request ID only");
            if (jsonl_) {
                if (!fields || fields->size() != 1 || !StringField(request.params.find("requestId"), id))
                    return Invalid(request, "invalid-recover", "Use params:{requestId:group/N} for the original continue");
            } else if (args->size() != 1) return Invalid(request, "invalid-recover", "Usage: recover group/N");
            return Emit("response", request.id, ControlReport(group_.Recover(id)));
        }
        if (pause) {
            if (request.expected) return Invalid(request, "invalid-pause", "Pause has no expected stop");
            auto selected = targets_; // 空 params 明确表示初始固定全集，不扩展任何后代。
            if (jsonl_) {
                if (!fields || fields->size() > 1) return Invalid(request, "invalid-pause", "Use params:{} or params:{targets:[...]} only");
                if (!fields->empty()) {
                    const auto* value = request.params.find("targets");
                    const auto* list = value ? value->asArray() : nullptr;
                    if (!list || list->empty())
                        return Invalid(request, "invalid-targets", "Require a nonempty explicit target array");
                    selected.clear();
                    for (const auto& item : *list) {
                        native::ProcessGroupTarget target;
                        if (!TargetValue(item, target)) return Invalid(request, "invalid-target", "Target requires numeric pid and decimal-string creationFileTime");
                        selected.push_back(target);
                    }
                }
            } else {
                if (args->size() > 2) return Invalid(request, "invalid-pause", "Usage: pause group/N [all|PID:CREATION,...]");
                if (args->size() == 2) {
                    std::string text;
                    if (!(*args)[1].tryGetString(text)) return Invalid(request, "invalid-targets", "Invalid target list");
                    if (text != "all") {
                        selected.clear();
                        if (!TargetList(text, selected)) return Invalid(request, "invalid-targets", "Invalid PID:CREATION list");
                    }
                }
            }
            return Emit("response", request.id, ControlReport(group_.Pause(std::move(id), selected)));
        }
        std::vector<native::ProcessGroupStop> stops;
        if (jsonl_) {
            const auto* expected = request.expected ? request.expected->asObject() : nullptr;
            const auto* value = request.expected ? request.expected->find("stops") : nullptr;
            const auto* list = value ? value->asArray() : nullptr;
            if (!empty || !expected || expected->size() != 1 || !list || list->empty())
                return Invalid(request, "invalid-continue", "Continue requires params:{} and expected:{stops:[exact ProcessGroupStop,...]}");
            for (const auto& item : *list) {
                native::ProcessGroupStop stop;
                if (!StopValue(item, stop)) return Invalid(request, "invalid-stop", "Copy each complete current member.stop token");
                stops.push_back(std::move(stop));
            }
        } else {
            std::string text;
            if (args->size() != 2 || !(*args)[1].tryGetString(text))
                return Invalid(request, "invalid-continue", "Usage: continue group/N PID:CREATION:GROUP_ID:STOP_ID:BACKEND_ID:SERIAL:REVISION,...");
            const auto list = Split(text, ',');
            for (const auto item : list) {
                native::ProcessGroupStop stop;
                if (!StopText(item, stop)) return Invalid(request, "invalid-stop", "Require all seven token fields");
                stops.push_back(std::move(stop));
            }
        }
        return Emit("response", request.id, ControlReport(group_.Continue(std::move(id), stops)));
    }

    const bool jsonl_;
    const native::OwnerIdentity identity_;
    const std::vector<native::ProcessGroupTarget> targets_;
    Transport transport_;
    native::OwnedProcessGroup group_;
    ProcessGroupMemoryArchive& archive_; // 启动前固定并持有的项目写租约与唯一已显示内存结果。
    bool cleanupOnly_ = false; // 未决清退保留原控制对象，只允许 Query／Recover／Close。
    std::uint64_t sequence_ = 0;
};

int Run(const Args& args)
{
    const auto input = args.get(L"--input", L"repl");
    if (!args.has(L"--confirm") || args.get(L"--disposition") != L"resume-detach" ||
        (input != L"jsonl" && input != L"repl") || (args.has(L"--backend") && args.get(L"--backend") != L"r3"))
        throw std::invalid_argument("Require --confirm --disposition resume-detach and --input jsonl|repl (R3 only)");
    const auto wide = args.require(L"--targets");
    std::string text;
    if (wide.size() > 1024) throw std::invalid_argument("Target list exceeds 1024 characters");
    for (const auto character : wide) {
        if (character > 0x7f) throw std::invalid_argument("Targets require ASCII PID:CREATION pairs");
        text.push_back(static_cast<char>(character));
    }
    std::vector<native::ProcessGroupTarget> targets;
    if (!TargetList(text, targets)) throw std::invalid_argument("Require one or more canonical positive decimal PID:CREATION pairs");
    const auto projectPath = args.has(L"--project") ? args.require(L"--project") : std::wstring{}; // 可选项目，空值不隐式创建。
    const auto wideSample = args.has(L"--sample") ? args.require(L"--sample") : std::wstring{}; // 只接受启动时指定的规范 UUID。
    std::string sampleId; // 项目绑定前无损校验的 ASCII 样本 UUID。
    for (const auto character : wideSample) { // UUID 按 ASCII 校验，拒绝静默截断 Unicode。
        if (character > 0x7f) {
            throw std::invalid_argument("--sample requires a canonical UUID");
        }
        sampleId.push_back(static_cast<char>(character));
    }
    ProcessGroupMemoryArchive archive; // 比控制组寿命更长，未决清退期间不释放项目单写租约。
    if (const auto bound = archive.Bind(projectPath, sampleId); !bound) { // 项目／采样错误须在任何附加前失败。
        std::cerr << "process-group-project-bind: " << bound.detail << " win32=" << bound.nativeError << '\n';
        return 3;
    }
    native::OwnerIdentity identity;
    using Ksword::ActionAnalyze::ProjectStorage::NewId;
    identity.sampleId = archive.SampleId();
    if ((identity.sampleId.empty() && !NewId(identity.sampleId)) || !NewId(identity.sessionId) ||
        !NewId(identity.epoch) || !NewId(identity.backendInstanceId)) {
        return 3;
    }
    return ProcessGroupSession(input == L"jsonl", std::move(identity), std::move(targets), archive).Run();
}
} // namespace

void RegisterProcessGroupCommand()
{
    Command command;
    command.path = L"analyze process-group session";
    command.syntax = L"KswordCLI.exe analyze process-group session --targets PID:CREATION,PID:CREATION --confirm --disposition resume-detach [--input repl|jsonl] [--project PATH [--sample UUID]]";
    command.summary = L"Control an explicit fixed collection of authorized AMD64 process instances with independent native owners.";
    command.options = L"--targets contains one or more exact PID and creation FILETIME pairs in canonical decimal, without a fixed member limit. hello.groupProtocol.maxMembers is null; transport byte budgets remain independent. "
        L"Configuration pins exact live identities without pausing; each actual Pause independently checks native AMD64, same user/session and native admission. "
        L"Optional --project opens an existing project with its single-writer lease before creating the controller. "
        L"--sample selects an existing frozen sample; omission creates a sample from the current committed revision. "
        L"Without --project all existing control and memory reads remain available, but memory save is unavailable. R3 only; no automatic descendants or system targets.";
    command.notes = L"REPL: status, pause group/N [all|PID:CREATION,...], "
        L"continue group/N PID:CREATION:GROUP_ID:STOP_ID:BACKEND_ID:SERIAL:REVISION,..., recover group/N, "
        L"memory-snapshot live-read|held-event PID:CREATION BASE LENGTH [EXACT_STOP_TOKEN], memory-save CAPTURE_UUID SAMPLE_UUID, close. "
        L"JSONL uses control.pause params:{} or {targets:[{pid,creationFileTime}]}, control.query, "
        L"control.continue params:{} expected:{stops:[complete member.stop tokens]}, "
        L"control.recover params:{requestId:original group/N}, controller.shutdown. "
        L"control.memory.snapshot requires session and params:{source:live-read|held-event,target:{pid,creationFileTime},range:{base,length},sampleId?:frozen hello sampleId} "
        L"(base and length strings; base also accepts 0x hex). Held-event requires expected:{stops:[one exact matching stop]}; live-read rejects expected. "
        L"Reads at most 64 pages on the same serial controller, returning captureId, actual lengths, page failures, hashes and timing without echoing bytes or changing stop ownership. "
        L"control.memory.save requires session, params:{captureId:displayed captureId,sampleId:frozen hello sampleId}, and no expected. "
        L"Only the last displayed actual capture is saveable; rejected reads, Query and parameter drafts do not replace it. "
        L"Save never rereads or continues; repeated save returns the original receipt. raw-memory preserves full Live/Held readContext and before/after checks. "
        L"A write/readback failure blocks further memory-lane appends without overwriting the bad tail. Independent analyze memory read/export reuses these archives. "
        L"Mutations require the hello session; pause and continue share strictly increasing group/N IDs and 128 receipts. "
        L"Every well-formed group request reaching admission, including rejection, consumes its ID; correcting parameters requires a new higher group/N. "
        L"Same-content replay is duplicate, changed content is conflict. operation.ledgerResult/stage/win32Error preserve first admission independently of current top-level replay/state. "
        L"Recover of a rejected Continue is readback-required and never executes. Query reports current members separately from immutable operation outcomes. "
        L"Partial failures retain successful holds. Close/EOF retain unresolved original owners and allow available Query/Recover/Close input; owner-death recovery is not provided.";
    command.runStreaming = Run;
    command.supportsR3 = true;
    command.defaultBackend = L"r3";
    addCommand(std::move(command));
}
} // namespace ks::cli::action_analyze
