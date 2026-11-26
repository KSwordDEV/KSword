#include "BreakpointFollowProtocol.h"

#include <charconv>
#include <limits>

namespace ks::cli::action_analyze {
namespace {
using V = JsonValue;
namespace native = control;
constexpr std::size_t kReplayEntries = 128;

V Text(std::string_view value) { return V::makeString(std::string(value)); }
V Count(std::uint64_t value) { return Text(std::to_string(value)); }

Fault Error(const char* id, const char* message)
{
    return {id, message, std::nullopt, 1, "cli", 0, "private-execution-follow"};
}

// 地址和修订均用正十进制字符串传递，避免JSON数值丢失64位精度。
std::optional<std::uint64_t> Decimal(std::string_view text)
{
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (!value || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        text != std::to_string(value)) return std::nullopt;
    return value;
}
} // namespace

BreakpointStepReply BreakpointFollowProtocol::Dispatch(const Request& request, bool jsonl, bool supported,
    const native::OwnerIdentity& identity, native::NativeDebugOwner& owner)
{
    if (request.method != "execution-follow" && request.method != "control.execution.follow") return {};
    const auto fail = [](const char* id, const char* message) {
        return BreakpointStepReply{true, Error(id, message), std::nullopt};
    };
    if (!supported) return fail("execution-follow-unavailable", "Follow requires a single-target private write-watch session");
    if ((jsonl && !request.session) || (request.session &&
        (request.session->id != identity.sessionId || request.session->epoch != identity.epoch)))
        return fail("wrong-session", "Require the current live session identity");

    std::string address, stop, revision; // 用户显式确认的原地址和当前停点，不从选中历史行补造。
    if (jsonl) {
        const auto* params = request.params.asObject();
        const auto* expected = request.expected ? request.expected->asObject() : nullptr;
        const auto* field = request.params.find("address");
        const auto* stopField = request.expected ? request.expected->find("stopId") : nullptr;
        const auto* revisionField = request.expected ? request.expected->find("stateRevision") : nullptr;
        if (!params || params->size() != 1 || !field || !field->tryGetString(address) ||
            !expected || expected->size() != 2 || !stopField || !stopField->tryGetString(stop) ||
            !revisionField || !revisionField->tryGetString(revision))
            return fail("invalid-execution-follow", "Require params:{address:decimal-string} and exact expected stopId/stateRevision");
    } else {
        const auto* args = request.params.asArray();
        if (request.expected || !args || args->size() != 3 || !(*args)[0].tryGetString(address) ||
            !(*args)[1].tryGetString(stop) || !(*args)[2].tryGetString(revision))
            return fail("invalid-execution-follow", "Usage: execution-follow ADDRESS STOP_ID STATE_REVISION (positive decimal values)");
    }
    const auto parsedAddress = Decimal(address);
    const auto parsedRevision = Decimal(revision);
    if (!parsedAddress || !parsedRevision || stop.empty() || stop.size() > kRequestIdBytes)
        return fail("invalid-execution-follow", "Require a positive decimal address/revision and a bounded nonempty stopId");
    if (!jsonl && highWater_ == std::numeric_limits<std::uint64_t>::max())
        return fail("follow-sequence-exhausted", "Follow request IDs are exhausted");
    const auto sequence = jsonl ? (request.id.starts_with("follow/") ? Decimal(std::string_view(request.id).substr(7)) :
        std::nullopt) : std::optional<std::uint64_t>{highWater_ + 1};
    if (!sequence) return fail("invalid-follow-request-id", "Require requestId follow/<next positive uint64 decimal>");
    const auto signature = CanonicalParams(V::makeArray({Text(address), Text(stop), Text(revision)}));
    if (const auto found = requests_.find(*sequence); found != requests_.end()) {
        if (found->second.signature != signature)
            return fail("request-id-conflict", "Follow request ID identifies different arguments");
        return {true, found->second.error, found->second.result};
    }
    if (*sequence <= highWater_) return fail("follow-replay-expired", "Original follow receipt is outside the retained window");
    if (*sequence - highWater_ != 1) return fail("invalid-follow-sequence", "Follow IDs must be consecutive, starting at follow/1");

    Saved saved{signature, {}, std::nullopt};
    const auto current = owner.Query(); // 原控制线程获取活owner，转换核心还会核验完整令牌及每线程DR。
    if (current.status != native::NativeControlStatus::Held || !current.group || !current.responsibility ||
        !current.pending || !current.breakpoint || !current.breakpointHit || !current.breakpointHit->dataChange ||
        current.group->historical || current.group->state != native::GroupState::HeldComplete ||
        current.group->sampleId != identity.sampleId || current.group->sessionId != identity.sessionId ||
        current.group->epoch != identity.epoch || current.responsibility->state != native::EventState::Held ||
        current.pending->event != current.responsibility->event || !current.pending->ledgerOwned ||
        current.pending->continuationIndeterminate || current.responsibility->stopId != stop ||
        current.group->stateRevision != *parsedRevision || current.breakpoint->address != *parsedAddress ||
        current.breakpointHit->address != *parsedAddress) {
        saved.error = Error("stale-follow-stop", "Query the current complete private write stop and confirm its exact address");
    } else {
        saved.result = owner.FollowPrivateExecution({{identity, current.group->groupId, stop,
            current.responsibility->event, "follow/" + std::to_string(*sequence), *parsedRevision}, *parsedAddress});
    }
    highWater_ = *sequence;
    requests_.emplace(*sequence, saved);
    if (requests_.size() > kReplayEntries) requests_.erase(requests_.begin());
    return {true, saved.error, std::move(saved.result)};
}

JsonValue BreakpointFollowProtocol::Report(const native::NativeExecutionFollowReceipt& receipt) const
{
    return V::makeObject({{"requestId", Text(receipt.request.stop.requestId)}, {"address", Count(receipt.request.address)},
        {"sourceStopId", Text(receipt.request.stop.stopId)},
        {"sourceStateRevision", Count(receipt.request.stop.expectedStateRevision)},
        {"converted", V::makeBool(receipt.converted)}, {"rollbackComplete", V::makeBool(receipt.rollbackComplete)},
        {"stage", Text(receipt.stage)}, {"win32Error", V::makeUInt(receipt.win32Error)},
        {"continued", V::makeBool(false)}});
}

JsonValue BreakpointFollowProtocol::Capabilities() const
{
    return V::makeObject({{"method", Text("control.execution.follow")}, {"firstRequestId", Text("follow/1")},
        {"requestIdFormat", Text("follow/<next positive uint64 decimal>")}, {"replayEntries", Count(kReplayEntries)},
        {"addressEncoding", Text("positive-decimal-string")}, {"continuesTarget", V::makeBool(false)}});
}

} // namespace ks::cli::action_analyze
