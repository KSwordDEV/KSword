#include "StopLedger.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace ks::cli::action_analyze::control {
namespace {

constexpr std::size_t kMaxGroups = 64;
constexpr std::size_t kMaxThreads = 1024;
constexpr std::size_t kMaxReleaseAttemptsPerGroup = 64;
constexpr std::size_t kMaxRequestIdBytes = 128;

bool HexDigit(char digit) {
    return (digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f');
}

bool IsId(std::string_view value) {
    if (value.size() != 36) { return false; }
    for (std::size_t i = 0; i != value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') { return false; }
        } else if (!HexDigit(value[i])) {
            return false;
        }
    }
    return true;
}

bool IsThread(const ThreadIdentity& thread) {
    return IsId(thread.threadId) && IsId(thread.processInstanceId);
}

bool ThreadLess(const ThreadIdentity& left, const ThreadIdentity& right) {
    return left.threadId < right.threadId;
}

bool NormalizeThreads(std::vector<ThreadIdentity>& threads) {
    if (!std::all_of(threads.begin(), threads.end(), IsThread)) { return false; }
    std::sort(threads.begin(), threads.end(), ThreadLess);
    return std::adjacent_find(threads.begin(), threads.end(), [](const auto& a, const auto& b) {
        return a.threadId == b.threadId;
    }) == threads.end();
}

bool EventUnresolved(EventState state) {
    return state != EventState::Released && state != EventState::RetiredOnExit;
}

bool EventConfirmedHeld(EventState state) {
    return state == EventState::Held || state == EventState::Retryable;
}

bool ValidPhase(StopPhase phase) {
    return phase == StopPhase::CallEnter || phase == StopPhase::CallReturn || phase == StopPhase::ExecutionEnterAttempt;
}

bool ValidReceipt(const ReleaseReceipt& receipt) {
    switch (receipt.result) {
    case ReleaseResult::Continued: return !receipt.nativeError || *receipt.nativeError == 0;
    case ReleaseResult::StillPending:
    case ReleaseResult::Indeterminate: return true;
    }
    return false;
}

} // namespace

StopLedger::StopLedger(OwnerIdentity owner) : owner_(std::move(owner)) {
    if (!IsId(owner_.sampleId) || !IsId(owner_.sessionId) || !IsId(owner_.epoch) || !IsId(owner_.backendInstanceId)) {
        throw std::invalid_argument("ActionAnalyze control requires canonical owner identity");
    }
}

StopLedger::Group* StopLedger::Find(std::string_view groupId) {
    const auto it = groups_.find(groupId);
    return it == groups_.end() ? nullptr : &it->second;
}

const StopLedger::Group* StopLedger::Find(std::string_view groupId) const {
    const auto it = groups_.find(groupId);
    return it == groups_.end() ? nullptr : &it->second;
}

LedgerResult StopLedger::Freeze(FrozenStopGroup group) {
    if (!IsId(group.groupId) || group.membershipSha256.size() != 64 ||
        !std::all_of(group.membershipSha256.begin(), group.membershipSha256.end(), HexDigit) || group.requested.empty()) {
        return LedgerResult::InvalidEvidence;
    }
    if (group.requested.size() > kMaxThreads) { return LedgerResult::Capacity; }
    if (!NormalizeThreads(group.requested)) { return LedgerResult::InvalidEvidence; }
    if (const auto* prior = Find(group.groupId)) {
        return prior->frozen == group ? LedgerResult::Duplicate : LedgerResult::Conflict;
    }
    if (active_) { return LedgerResult::InvalidTransition; }
    if (groups_.size() == kMaxGroups) { return LedgerResult::Capacity; }

    Group entry;
    entry.members.reserve(group.requested.size());
    for (const auto& thread : group.requested) { entry.members.push_back({thread}); }
    auto key = group.groupId;
    entry.frozen = std::move(group);
    active_ = &groups_.emplace(std::move(key), std::move(entry)).first->second;
    return LedgerResult::Applied;
}

LedgerResult StopLedger::AdoptNativeStop(std::string_view groupId, const NativeStop& evidence) {
    auto* group = Find(groupId);
    if (!group) { return LedgerResult::MissingGroup; }
    if (evidence.event.backendInstanceId != owner_.backendInstanceId) { return LedgerResult::IdentityMismatch; }
    if (!evidence.event.serial || !IsThread(evidence.eventThread) || !IsId(evidence.stopId) ||
        (evidence.phase && !ValidPhase(*evidence.phase))) { return LedgerResult::InvalidEvidence; }
    if (group->native) {
        if (*group->native == evidence) { return LedgerResult::Duplicate; }
        return group->closed ? LedgerResult::Historical : LedgerResult::Conflict;
    }
    if (group->closed) { return LedgerResult::Historical; }
    if (group->noNativeEventConfirmed) { return LedgerResult::Conflict; }
    if (evidence.event.serial <= lastNativeSerial_) { return LedgerResult::IdentityMismatch; }
    for (const auto& [id, prior] : groups_) {
        if (id != groupId && prior.native && prior.native->stopId == evidence.stopId) { return LedgerResult::Conflict; }
    }
    const auto origin = std::find_if(group->members.begin(), group->members.end(), [&](const auto& member) {
        return member.identity.threadId == evidence.eventThread.threadId;
    });
    if (origin != group->members.end() && (origin->identity != evidence.eventThread || origin->evidence == MemberEvidence::Exited)) {
        return LedgerResult::IdentityMismatch;
    }
    group->native.emplace(evidence);
    lastNativeSerial_ = evidence.event.serial;
    for (auto& member : group->members) {
        if (member.identity.processInstanceId == evidence.eventThread.processInstanceId &&
            member.evidence == MemberEvidence::NoOwnedHold) {
            // 旧的无持有证明不能覆盖新到达的进程级原生事件。
            member.evidence = MemberEvidence::Unknown;
        }
    }
    if (origin != group->members.end()) {
        origin->evidence = MemberEvidence::CoveredByEvent;
        origin->wasCovered = true;
    }
    ++group->revision;
    return LedgerResult::Applied;
}

LedgerResult StopLedger::ObserveMember(std::string_view groupId, const ThreadIdentity& thread,
    MemberEvidence evidence, std::optional<NativeEventKey> event) {
    auto* group = Find(groupId);
    if (!group) { return LedgerResult::MissingGroup; }
    const auto member = std::find_if(group->members.begin(), group->members.end(), [&](const auto& entry) {
        return entry.identity == thread;
    });
    if (member == group->members.end()) { return LedgerResult::IdentityMismatch; }
    switch (evidence) {
    case MemberEvidence::CoveredByEvent:
        if (!event || !group->native || group->native->event != *event ||
            thread.processInstanceId != group->native->eventThread.processInstanceId) { return LedgerResult::IdentityMismatch; }
        break;
    case MemberEvidence::NoOwnedHold:
    case MemberEvidence::Exited:
    case MemberEvidence::Unknown:
        if (event) { return LedgerResult::InvalidEvidence; }
        break;
    case MemberEvidence::Pending:
    default: return LedgerResult::InvalidEvidence;
    }
    if (member->evidence == evidence) { return LedgerResult::Duplicate; }
    if (group->closed) { return LedgerResult::Historical; }
    if (member->evidence == MemberEvidence::Exited || (member->wasCovered && evidence != MemberEvidence::Exited) ||
        (member->evidence == MemberEvidence::NoOwnedHold && evidence == MemberEvidence::Unknown)) {
        return LedgerResult::InvalidTransition;
    }
    if (evidence == MemberEvidence::CoveredByEvent && !EventConfirmedHeld(group->eventState)) {
        return LedgerResult::InvalidTransition;
    }
    // 所属进程存在已知 native hold 时，同进程线程只接受“已验证覆盖”或“未知/已退出”。
    if (evidence == MemberEvidence::NoOwnedHold && group->native && EventUnresolved(group->eventState) &&
        thread.processInstanceId == group->native->eventThread.processInstanceId) { return LedgerResult::InvalidTransition; }
    member->evidence = evidence;
    member->wasCovered = member->wasCovered || evidence == MemberEvidence::CoveredByEvent;
    if (evidence == MemberEvidence::Exited && group->native && thread == group->native->eventThread) {
        group->originExited = true;
    }
    ++group->revision;
    CloseIfResolved(*group);
    return LedgerResult::Applied;
}

LedgerResult StopLedger::ObserveOriginExit(std::string_view groupId, const NativeEventKey& event,
    const ThreadIdentity& exitedThread) {
    auto* group = Find(groupId);
    if (!group) { return LedgerResult::MissingGroup; }
    if (!group->native || group->native->event != event || group->native->eventThread != exitedThread) {
        return LedgerResult::IdentityMismatch;
    }
    if (group->originExited) { return LedgerResult::Duplicate; }
    if (group->closed) { return LedgerResult::Historical; }
    const auto member = std::find_if(group->members.begin(), group->members.end(), [&](const auto& entry) {
        return entry.identity == exitedThread;
    });
    if (member != group->members.end()) { return ObserveMember(groupId, exitedThread, MemberEvidence::Exited); }
    // 命中线程退出不代表 owner 已处理完该进程的原生事件。
    group->originExited = true;
    ++group->revision;
    return LedgerResult::Applied;
}

LedgerResult StopLedger::ObserveIncidental(std::string_view groupId, const NativeEventKey& event,
    IncidentalQuality quality, std::vector<ThreadIdentity> known) {
    auto* group = Find(groupId);
    if (!group) { return LedgerResult::MissingGroup; }
    if (!group->native || group->native->event != event) { return LedgerResult::IdentityMismatch; }
    if (known.size() > kMaxThreads) { return LedgerResult::Capacity; }
    if (quality != IncidentalQuality::Verified && quality != IncidentalQuality::Partial &&
        quality != IncidentalQuality::NotCollected) { return LedgerResult::InvalidEvidence; }
    if ((quality == IncidentalQuality::NotCollected && !known.empty()) || !NormalizeThreads(known)) {
        return LedgerResult::InvalidEvidence;
    }
    for (const auto& thread : known) {
        const auto& origin = group->native->eventThread;
        if (thread.processInstanceId != origin.processInstanceId || thread.threadId == origin.threadId ||
            std::any_of(group->members.begin(), group->members.end(), [&](const auto& member) {
                return member.identity.threadId == thread.threadId;
            })) { return LedgerResult::IdentityMismatch; }
    }
    if (quality == group->incidentalQuality && known == group->incidental) { return LedgerResult::Duplicate; }
    if (group->closed) { return LedgerResult::Historical; }
    if (!EventConfirmedHeld(group->eventState) || group->incidentalQuality == IncidentalQuality::Verified ||
        quality == IncidentalQuality::NotCollected ||
        !std::includes(known.begin(), known.end(), group->incidental.begin(), group->incidental.end(), ThreadLess)) {
        return LedgerResult::InvalidTransition;
    }
    group->incidentalQuality = quality;
    group->incidental = std::move(known);
    ++group->revision;
    return LedgerResult::Applied;
}

LedgerResult StopLedger::SealMembership(std::string_view groupId) {
    auto* group = Find(groupId);
    if (!group) { return LedgerResult::MissingGroup; }
    if (group->membershipSealed) { return LedgerResult::Duplicate; }
    if (group->closed) { return LedgerResult::Historical; }
    group->membershipSealed = true;
    ++group->revision;
    CloseIfResolved(*group);
    return LedgerResult::Applied;
}

LedgerResult StopLedger::ConfirmNoNativeEvent(std::string_view groupId) {
    auto* group = Find(groupId);
    if (!group) { return LedgerResult::MissingGroup; }
    if (group->noNativeEventConfirmed) { return LedgerResult::Duplicate; }
    if (group->closed) { return LedgerResult::Historical; }
    if (group->native) { return LedgerResult::Conflict; }
    group->noNativeEventConfirmed = true;
    ++group->revision;
    CloseIfResolved(*group);
    return LedgerResult::Applied;
}

ReleaseDecision StopLedger::BeginRelease(const ReleaseRequest& request) {
    if (request.owner != owner_ || request.event.backendInstanceId != owner_.backendInstanceId) {
        return {LedgerResult::IdentityMismatch};
    }
    if (request.requestId.empty() || request.requestId.size() > kMaxRequestIdBytes) { return {LedgerResult::InvalidEvidence}; }
    if (const auto prior = commands_.find(request.requestId); prior != commands_.end()) {
        return {prior->second.attempt.request == request ? LedgerResult::Duplicate : LedgerResult::Conflict};
    }
    auto* group = Find(request.groupId);
    if (!group) { return {LedgerResult::MissingGroup}; }
    if (group->closed) { return {LedgerResult::Historical}; }
    if (!group->native || group->native->event != request.event || group->native->stopId != request.stopId) {
        return {LedgerResult::IdentityMismatch};
    }
    if (group->revision != request.expectedStateRevision) { return {LedgerResult::StaleRevision}; }
    if (group->eventState == EventState::Indeterminate || group->eventState == EventState::ReleasePending) {
        return {LedgerResult::ReadbackRequired};
    }
    if (!EventConfirmedHeld(group->eventState)) { return {LedgerResult::InvalidTransition}; }
    if (group->releaseAttempts == kMaxReleaseAttemptsPerGroup) { return {LedgerResult::Capacity}; }

    ReleaseAttempt attempt{request, group->revision + 1};
    std::string requestId = request.requestId;
    commands_.emplace(requestId, Command{attempt, {attempt.issuedRevision, std::nullopt, std::nullopt}});
    group->lastRequestId = std::move(requestId);
    group->eventState = EventState::ReleasePending;
    ++group->releaseAttempts;
    ++group->revision;
    return {LedgerResult::Applied, std::move(attempt)};
}

LedgerResult StopLedger::RecordReleaseReceipt(const ReleaseAttempt& attempt, ReleaseReceipt receipt) {
    return RecordRelease(attempt, receipt, false);
}

LedgerResult StopLedger::RecordReleaseReadback(const ReleaseAttempt& attempt, ReleaseReceipt proof) {
    return RecordRelease(attempt, proof, true);
}

LedgerResult StopLedger::RecordRelease(const ReleaseAttempt& attempt, ReleaseReceipt receipt, bool readback) {
    if (attempt.request.owner != owner_) { return LedgerResult::IdentityMismatch; }
    const auto command = commands_.find(attempt.request.requestId);
    if (command == commands_.end() || command->second.attempt != attempt) { return LedgerResult::IdentityMismatch; }
    if (!ValidReceipt(receipt) || (readback && receipt.result == ReleaseResult::Indeterminate)) {
        return LedgerResult::InvalidEvidence;
    }
    auto& record = command->second.record;
    auto& slot = readback ? record.readback : record.receipt;
    if (slot) { return *slot == receipt ? LedgerResult::Duplicate : LedgerResult::Conflict; }

    auto& group = *Find(attempt.request.groupId);
    if (group.closed) { return LedgerResult::Historical; }
    if (!group.lastRequestId || *group.lastRequestId != attempt.request.requestId) { return LedgerResult::IdentityMismatch; }
    const bool accepted = group.eventState == EventState::ReleasePending ||
        (readback && group.eventState == EventState::Indeterminate);
    if (!accepted) { return LedgerResult::InvalidTransition; }
    slot = receipt;
    ApplyReceipt(group, receipt.result);
    return LedgerResult::Applied;
}

void StopLedger::ApplyReceipt(Group& group, ReleaseResult result) {
    switch (result) {
    case ReleaseResult::Continued: group.eventState = EventState::Released; break;
    case ReleaseResult::StillPending: group.eventState = EventState::Retryable; break;
    case ReleaseResult::Indeterminate: group.eventState = EventState::Indeterminate; break;
    }
    ++group.revision;
    CloseIfResolved(group);
}

LedgerResult StopLedger::RecordRetiredOnExit(std::string_view groupId, const NativeEventKey& event,
    std::string_view exitedProcessInstanceId) {
    auto* group = Find(groupId);
    if (!group) { return LedgerResult::MissingGroup; }
    if (!group->native || group->native->event != event ||
        group->native->eventThread.processInstanceId != exitedProcessInstanceId) { return LedgerResult::IdentityMismatch; }
    if (group->eventState == EventState::RetiredOnExit) { return LedgerResult::Duplicate; }
    if (group->closed) { return LedgerResult::Historical; }
    group->eventState = EventState::RetiredOnExit;
    group->originExited = true;
    for (auto& member : group->members) {
        if (member.identity.processInstanceId == exitedProcessInstanceId) { member.evidence = MemberEvidence::Exited; }
    }
    if (group->lastRequestId) { commands_.find(*group->lastRequestId)->second.record.eventRetiredOnExit = true; }
    ++group->revision;
    CloseIfResolved(*group);
    return LedgerResult::Applied;
}

void StopLedger::CloseIfResolved(Group& group) {
    const bool conclusiveWithoutNative = !group.native && group.membershipSealed && group.noNativeEventConfirmed &&
        std::all_of(group.members.begin(), group.members.end(), [](const auto& member) {
            return member.evidence == MemberEvidence::Exited || member.evidence == MemberEvidence::NoOwnedHold;
        });
    if (conclusiveWithoutNative || (group.native && !EventUnresolved(group.eventState))) {
        group.closed = true;
        active_ = nullptr;
    }
}

MemberState StopLedger::ProjectMember(const Group& group, const Member& member) {
    if (member.evidence == MemberEvidence::Exited) { return MemberState::Exited; }
    if (group.native && !EventUnresolved(group.eventState)) {
        // 这里只投影本账本责任。原始成员证据仍在 MemberSnapshot::evidence。
        return member.wasCovered ? MemberState::Released : MemberState::NotHeld;
    }
    switch (member.evidence) {
    case MemberEvidence::CoveredByEvent:
        switch (group.eventState) {
        case EventState::Held: return MemberState::Held;
        case EventState::ReleasePending: return MemberState::ReleasePending;
        case EventState::Retryable:
        case EventState::Indeterminate: return MemberState::RecoveryRequired;
        case EventState::Released: return MemberState::Released;
        case EventState::RetiredOnExit: return MemberState::Exited;
        }
        break;
    case MemberEvidence::Pending: return group.membershipSealed ? MemberState::Unknown : MemberState::Pending;
    case MemberEvidence::NoOwnedHold: return MemberState::NotHeld;
    case MemberEvidence::Exited: return MemberState::Exited;
    case MemberEvidence::Unknown: return MemberState::Unknown;
    }
    return MemberState::Unknown;
}

GroupState StopLedger::ProjectGroup(const Group& group) {
    if (group.native) {
        switch (group.eventState) {
        case EventState::Retryable:
        case EventState::Indeterminate: return GroupState::RecoveryRequired;
        case EventState::ReleasePending: return GroupState::ReleasePending;
        default: break;
        }
    }
    const bool allExited = std::all_of(group.members.begin(), group.members.end(), [](const auto& member) {
        return member.evidence == MemberEvidence::Exited;
    });
    if (group.closed) {
        if (allExited) { return GroupState::Ended; }
        return group.native ? GroupState::Released : GroupState::NotHeld;
    }
    if (!group.native) { return GroupState::GroupBuilding; }

    bool held = false;
    bool unresolved = false;
    for (const auto& member : group.members) {
        const auto state = ProjectMember(group, member);
        held = held || state == MemberState::Held;
        unresolved = unresolved || (state != MemberState::Held && state != MemberState::Exited);
    }
    if (held && !unresolved) { return GroupState::HeldComplete; }
    if (!group.membershipSealed && !allExited) { return GroupState::GroupBuilding; }
    const bool originHeld = group.native->phase && !group.originExited;
    return unresolved && (held || originHeld) ? GroupState::HeldPartial : GroupState::UnprojectableNativeHold;
}

std::optional<StopGroupSnapshot> StopLedger::Query(std::string_view groupId) const {
    const auto* group = Find(groupId);
    if (!group) { return std::nullopt; }

    StopGroupSnapshot snapshot{owner_.sampleId, owner_.sessionId, owner_.epoch, group->frozen.groupId, group->revision,
        group->frozen.membershipRevision, group->frozen.membershipSha256, ProjectGroup(*group), std::nullopt, {},
        group->incidentalQuality, {}, group->closed};
    if (group->native && group->native->phase) {
        OriginHold hold = OriginHold::Unknown;
        if (group->originExited) { hold = OriginHold::Exited; }
        else if (group->eventState == EventState::Released) { hold = OriginHold::Released; }
        else if (EventConfirmedHeld(group->eventState)) { hold = OriginHold::Held; }
        snapshot.origin = OriginSnapshot{group->native->eventThread.threadId, *group->native->phase, hold};
    }
    snapshot.members.reserve(group->members.size());
    for (const auto& member : group->members) {
        snapshot.members.push_back({member.identity.threadId, ProjectMember(*group, member),
            member.wasCovered ? std::optional(group->native->stopId) : std::nullopt, member.evidence});
    }
    snapshot.incidentalThreadIds.reserve(group->incidental.size());
    for (const auto& thread : group->incidental) { snapshot.incidentalThreadIds.push_back(thread.threadId); }
    return snapshot;
}

std::optional<ReleaseRecord> StopLedger::QueryRelease(std::string_view requestId) const {
    const auto command = commands_.find(requestId);
    return command == commands_.end() ? std::nullopt : std::optional(command->second.record);
}

std::optional<EventResponsibility> StopLedger::UnresolvedNativeResponsibility() const {
    if (!active_ || !active_->native) { return std::nullopt; }
    const auto& event = *active_->native;
    return EventResponsibility{active_->frozen.groupId, event.event, event.eventThread, event.stopId, active_->eventState,
        active_->lastRequestId};
}

bool StopLedger::CanRetireLedger() const noexcept {
    return active_ == nullptr;
}

} // namespace ks::cli::action_analyze::control
