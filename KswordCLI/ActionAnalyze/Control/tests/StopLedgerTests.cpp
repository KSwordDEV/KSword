#include "../StopLedger.h"

#include <cstdio>
#include <cstdlib>
#include <source_location>
#include <utility>

namespace {

using namespace ks::cli::action_analyze::control;
using R = LedgerResult;
using M = MemberEvidence;

unsigned checks = 0;

void Check(bool condition, std::source_location location = std::source_location::current()) {
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL %s:%u\n", location.function_name(), location.line());
        std::exit(EXIT_FAILURE);
    }
}

std::string Id(unsigned n) {
    char id[37]{};
    std::snprintf(id, sizeof(id), "00000000-0000-0000-0000-%012x", n);
    return id;
}

const OwnerIdentity owner{Id(1), Id(2), Id(3), Id(4)};
const auto group = Id(5);
const auto stop = Id(6);
const ThreadIdentity origin{Id(7), Id(10)};
const ThreadIdentity worker{Id(8), Id(10)};
const ThreadIdentity outside{Id(9), Id(11)};
const ThreadIdentity incidental{Id(12), Id(10)};
const NativeEventKey event{owner.backendInstanceId, 1};

FrozenStopGroup Freeze(std::vector<ThreadIdentity> requested, std::string groupId = group) {
    return {std::move(groupId), 4, std::string(64, 'e'), std::move(requested)};
}

NativeStop Hit(std::optional<StopPhase> phase = StopPhase::CallEnter) {
    return {event, origin, stop, phase};
}

ReleaseRequest Request(const StopLedger& ledger, std::string id) {
    return {owner, group, stop, event, std::move(id), ledger.Query(group).value().stateRevision};
}

void AssertSameProjection(const StopLedger& ledger, const StopGroupSnapshot& prior) {
    const auto now = ledger.Query(prior.groupId).value();
    Check(now.stateRevision == prior.stateRevision && now.membershipRevision == prior.membershipRevision &&
        now.membershipSha256 == prior.membershipSha256 && now.historical == prior.historical && now.state == prior.state);
}

void ScopeAndFirstContinue() {
    StopLedger ledger(owner);
    Check(ledger.Freeze(Freeze({outside, worker, origin})) == R::Applied);
    Check(ledger.Freeze(Freeze({origin, worker, outside})) == R::Duplicate);
    Check(ledger.Freeze(Freeze({origin, outside})) == R::Conflict);
    Check(ledger.ObserveMember(group, worker, M::NoOwnedHold) == R::Applied);
    Check(ledger.AdoptNativeStop(group, Hit()) == R::Applied);
    const auto building = ledger.Query(group).value();
    Check(building.state == GroupState::GroupBuilding && building.origin->hold == OriginHold::Held);
    Check(building.members[0].state == MemberState::Held && building.members[0].stopId == stop);
    Check(building.members[1].state == MemberState::Unknown && building.members[2].state == MemberState::Pending);
    Check(building.incidentalQuality == IncidentalQuality::NotCollected && building.incidentalThreadIds.empty());
    Check(ledger.AdoptNativeStop(group, Hit()) == R::Duplicate);
    Check(ledger.ObserveMember(group, outside, M::CoveredByEvent, event) == R::IdentityMismatch);
    Check(ledger.ObserveMember(group, {worker.threadId, outside.processInstanceId}, M::Exited) == R::IdentityMismatch);
    Check(ledger.ObserveIncidental(group, event, IncidentalQuality::Partial, {origin}) == R::IdentityMismatch);
    Check(ledger.ObserveIncidental(group, event, IncidentalQuality::Partial, {worker}) == R::IdentityMismatch);
    Check(ledger.ObserveIncidental(group, event, IncidentalQuality::NotCollected, {incidental}) == R::InvalidEvidence);
    AssertSameProjection(ledger, building);

    Check(ledger.ObserveIncidental(group, event, IncidentalQuality::Partial, {incidental}) == R::Applied);
    Check(ledger.ObserveMember(group, worker, M::CoveredByEvent, event) == R::Applied);
    Check(ledger.SealMembership(group) == R::Applied);
    const auto partial = ledger.Query(group).value();
    Check(partial.state == GroupState::HeldPartial && partial.members[2].state == MemberState::Unknown);
    Check(partial.members[1].stopId == partial.members[0].stopId);
    Check(ledger.ObserveMember(group, outside, M::Exited) == R::Applied);
    const auto complete = ledger.Query(group).value();
    Check(complete.state == GroupState::HeldComplete && complete.incidentalQuality == IncidentalQuality::Partial);
    Check(ledger.UnresolvedNativeResponsibility()->state == EventState::Held && !ledger.CanRetireLedger());
    auto stale = Request(ledger, "cmd-stale-revision");
    stale.expectedStateRevision = partial.stateRevision;
    Check(ledger.BeginRelease(stale).result == R::StaleRevision);
    AssertSameProjection(ledger, complete);

    const auto command = Request(ledger, "cmd-continue");
    const auto begun = ledger.BeginRelease(command);
    Check(begun.result == R::Applied && begun.effect.has_value());
    const auto pending = ledger.Query(group).value();
    Check(pending.state == GroupState::ReleasePending && pending.origin->hold == OriginHold::ReleasePending);
    Check(pending.incidentalThreadIds == std::vector{incidental.threadId} && !ledger.CanRetireLedger());
    const auto duplicate = ledger.BeginRelease(command);
    Check(duplicate.result == R::Duplicate && !duplicate.effect);
    Check(ledger.BeginRelease(Request(ledger, "cmd-second")).result == R::ReadbackRequired);
    auto conflict = command;
    ++conflict.expectedStateRevision;
    Check(ledger.BeginRelease(conflict).result == R::Conflict);
    AssertSameProjection(ledger, pending);

    const ReleaseReceipt success{ReleaseResult::Continued, std::nullopt};
    Check(ledger.RecordReleaseReceipt(*begun.effect, success) == R::Applied);
    const auto released = ledger.Query(group).value();
    Check(released.state == GroupState::Released && released.historical && released.origin->hold == OriginHold::Released);
    Check(released.members[0].state == MemberState::Released && released.members[1].state == MemberState::Released);
    Check(released.members[2].state == MemberState::Exited && released.incidentalThreadIds == pending.incidentalThreadIds);
    Check(!ledger.UnresolvedNativeResponsibility() && ledger.CanRetireLedger());
    Check(ledger.RecordReleaseReceipt(*begun.effect, success) == R::Duplicate);
    Check(ledger.QueryRelease(command.requestId)->receipt == success);
    Check(ledger.BeginRelease(Request(ledger, "historic")).result == R::Historical);
    AssertSameProjection(ledger, released);

    const auto next = Id(20);
    Check(ledger.Freeze(Freeze({origin}, next)) == R::Applied);
    Check(ledger.AdoptNativeStop(next, Hit()) == R::IdentityMismatch);
    auto nextHit = Hit(StopPhase::CallReturn);
    nextHit.event.serial = 2;
    Check(ledger.AdoptNativeStop(next, nextHit) == R::Conflict); // stopId 与事件一一对应。
    nextHit.stopId = Id(21);
    Check(ledger.AdoptNativeStop(next, nextHit) == R::Applied);
    Check(ledger.BeginRelease(command).result == R::Duplicate);
    Check(ledger.RecordReleaseReceipt(*begun.effect, success) == R::Duplicate);
    Check(ledger.UnresolvedNativeResponsibility()->event == nextHit.event);
    auto wrongEpoch = ReleaseRequest{owner, next, nextHit.stopId, nextHit.event, "epoch", ledger.Query(next)->stateRevision};
    wrongEpoch.owner.epoch = Id(22);
    Check(ledger.BeginRelease(wrongEpoch).result == R::IdentityMismatch);
    AssertSameProjection(ledger, released);
}

void IndeterminateContinueAndExplicitRetry() {
    StopLedger ledger(owner);
    Check(ledger.Freeze(Freeze({origin})) == R::Applied);
    Check(ledger.AdoptNativeStop(group, Hit(StopPhase::CallReturn)) == R::Applied);
    const auto first = ledger.BeginRelease(Request(ledger, "original")).effect.value();
    const ReleaseReceipt unknown{ReleaseResult::Indeterminate, 6};
    Check(ledger.RecordReleaseReceipt(first, unknown) == R::Applied);
    const auto recovery = ledger.Query(group).value();
    Check(recovery.state == GroupState::RecoveryRequired && recovery.origin->hold == OriginHold::RecoveryRequired);
    Check(recovery.members[0].state == MemberState::RecoveryRequired && !ledger.CanRetireLedger());
    Check(ledger.Freeze(Freeze({origin}, Id(32))) == R::InvalidTransition);
    Check(ledger.QueryRelease("original")->receipt == unknown);
    Check(ledger.BeginRelease(Request(ledger, "blind-retry")).result == R::ReadbackRequired);
    Check(ledger.RecordReleaseReadback(first, unknown) == R::InvalidEvidence);
    Check(ledger.RecordReleaseReceipt(first, unknown) == R::Duplicate);
    AssertSameProjection(ledger, recovery);

    const ReleaseReceipt held{ReleaseResult::StillPending, std::nullopt};
    Check(ledger.RecordReleaseReadback(first, held) == R::Applied);
    Check(ledger.Query(group)->origin->hold == OriginHold::RecoveryRequired && ledger.Query(group)->state == GroupState::RecoveryRequired);
    Check(ledger.UnresolvedNativeResponsibility()->state == EventState::Retryable);
    Check(ledger.QueryRelease("original")->receipt == unknown && ledger.QueryRelease("original")->readback == held);
    const auto second = ledger.BeginRelease(Request(ledger, "proof-backed-retry")).effect.value();
    const ReleaseReceipt success{ReleaseResult::Continued, 0};
    Check(ledger.RecordReleaseReadback(first, success) == R::Conflict);
    Check(ledger.UnresolvedNativeResponsibility()->lastRequestId == second.request.requestId);
    Check(ledger.RecordReleaseReceipt(second, success) == R::Applied);
    Check(ledger.Query(group)->historical && ledger.CanRetireLedger());
}

void OriginAndIncidentalOutliveFrozenSet() {
    StopLedger ledger(owner);
    Check(ledger.Freeze(Freeze({outside})) == R::Applied);
    Check(ledger.ObserveMember(group, outside, M::Exited) == R::Applied);
    Check(ledger.SealMembership(group) == R::Applied);
    Check(!ledger.CanRetireLedger() && !ledger.Query(group)->historical);
    Check(ledger.AdoptNativeStop(group, Hit()) == R::Applied);
    Check(ledger.ObserveIncidental(group, event, IncidentalQuality::Partial, {incidental}) == R::Applied);
    Check(ledger.ConfirmNoNativeEvent(group) == R::Conflict);
    const auto gap = ledger.Query(group).value();
    Check(gap.state == GroupState::OriginHeld && gap.origin->threadId == origin.threadId && !gap.historical);
    Check(gap.incidentalThreadIds == std::vector{incidental.threadId} && !ledger.CanRetireLedger());
    Check(ledger.RecordRetiredOnExit(group, event, outside.processInstanceId) == R::IdentityMismatch);
    Check(ledger.ObserveOriginExit(group, event, outside) == R::IdentityMismatch);
    AssertSameProjection(ledger, gap);
    Check(ledger.ObserveOriginExit(group, event, origin) == R::Applied);
    Check(ledger.ObserveOriginExit(group, event, origin) == R::Duplicate);
    Check(ledger.Query(group)->origin->hold == OriginHold::Exited && !ledger.CanRetireLedger());
    Check(ledger.UnresolvedNativeResponsibility()->state == EventState::Held);
    Check(ledger.Query(group)->state == GroupState::UnprojectableNativeHold);

    const auto attempt = ledger.BeginRelease(Request(ledger, "exit-race")).effect.value();
    Check(ledger.RecordRetiredOnExit(group, event, origin.processInstanceId) == R::Applied);
    const auto ended = ledger.Query(group).value();
    Check(ended.state == GroupState::Ended && ended.origin->hold == OriginHold::Exited && ended.historical);
    Check(!ledger.UnresolvedNativeResponsibility() && ledger.QueryRelease("exit-race")->eventRetiredOnExit);
    Check(ledger.RecordReleaseReceipt(attempt, {ReleaseResult::Continued, 0}) == R::Historical);
    Check(ledger.RecordRetiredOnExit(group, event, origin.processInstanceId) == R::Duplicate);
    AssertSameProjection(ledger, ended);
}

void UnknownPhaseAndLostReceipt() {
    StopLedger ledger(owner);
    Check(ledger.Freeze(Freeze({outside})) == R::Applied);
    Check(ledger.AdoptNativeStop(group, Hit(std::nullopt)) == R::Applied);
    Check(ledger.SealMembership(group) == R::Applied);
    Check(ledger.Query(group)->state == GroupState::UnprojectableNativeHold && !ledger.Query(group)->origin);
    Check(ledger.UnresolvedNativeResponsibility()->actualEventThread == origin);
    Check(ledger.ObserveIncidental(group, event, IncidentalQuality::Verified, {}) == R::Applied);
    Check(ledger.Query(group)->incidentalQuality == IncidentalQuality::Verified);
    const auto attempt = ledger.BeginRelease(Request(ledger, "no-return")).effect.value();
    Check(ledger.BeginRelease(Request(ledger, "repeat-native-call")).result == R::ReadbackRequired);
    Check(ledger.RecordReleaseReadback(attempt, {ReleaseResult::Continued, std::nullopt}) == R::Applied);
    const auto closed = ledger.Query(group).value();
    Check(closed.state == GroupState::Released && !closed.origin && closed.members[0].state == MemberState::NotHeld);
    Check(closed.members[0].evidence == M::Pending && !ledger.QueryRelease("no-return")->receipt);
}

void NoNativeHold() {
    StopLedger ledger(owner);
    Check(ledger.Freeze(Freeze({origin, outside})) == R::Applied);
    Check(ledger.ObserveMember(group, origin, M::Exited) == R::Applied);
    Check(ledger.SealMembership(group) == R::Applied);
    Check(ledger.Query(group)->state == GroupState::GroupBuilding && !ledger.CanRetireLedger());
    Check(ledger.ObserveMember(group, origin, M::NoOwnedHold) == R::InvalidTransition);
    Check(ledger.ObserveMember(group, outside, M::NoOwnedHold) == R::Applied);
    Check(ledger.Query(group)->state == GroupState::GroupBuilding && !ledger.CanRetireLedger());
    Check(ledger.ConfirmNoNativeEvent(group) == R::Applied);
    Check(ledger.Query(group)->state == GroupState::NotHeld && ledger.CanRetireLedger());
    Check(ledger.ConfirmNoNativeEvent(group) == R::Duplicate);
}

void FailedContinueRetainsItsEvent() {
    StopLedger ledger(owner);
    Check(ledger.Freeze(Freeze({origin})) == R::Applied);
    Check(ledger.AdoptNativeStop(group, Hit()) == R::Applied);
    const auto first = ledger.BeginRelease(Request(ledger, "native-failed")).effect.value();
    const ReleaseReceipt failure{ReleaseResult::StillPending, 5};
    Check(ledger.RecordReleaseReceipt(first, failure) == R::Applied);
    Check(ledger.Query(group)->state == GroupState::RecoveryRequired && ledger.Query(group)->origin->hold == OriginHold::RecoveryRequired);
    Check(ledger.UnresolvedNativeResponsibility()->event == event && !ledger.CanRetireLedger());
    Check(ledger.QueryRelease("native-failed")->receipt == failure);
    const auto retry = ledger.BeginRelease(Request(ledger, "native-explicit-retry")).effect.value();
    Check(ledger.RecordReleaseReceipt(first, failure) == R::Duplicate);
    Check(ledger.UnresolvedNativeResponsibility()->lastRequestId == retry.request.requestId);
    Check(ledger.RecordReleaseReceipt(retry, {ReleaseResult::Continued, 0}) == R::Applied);
    Check(ledger.CanRetireLedger());
}

void RollingGroupsAndReplayWatermark() {
    StopLedger ledger(owner);
    const ReleaseReceipt success{ReleaseResult::Continued, std::nullopt};
    ReleaseRequest first;
    ReleaseAttempt firstAttempt;
    for (unsigned sequence = 1; sequence <= 160; ++sequence) {
        const auto groupId = Id(1000 + sequence);
        const auto stopId = Id(2000 + sequence);
        const NativeEventKey native{owner.backendInstanceId, sequence};
        auto frozen = Freeze({origin}, groupId);
        frozen.membershipRevision = sequence;
        Check(ledger.Freeze(frozen, HistoryRetention::Rolling) == R::Applied);
        if (sequence > kStopHistoryGroups) {
            Check(!ledger.Query(Id(1000 + sequence - kStopHistoryGroups)));
            Check(ledger.Query(Id(1001 + sequence - kStopHistoryGroups))->historical);
        }
        if (sequence == 160) {
            Check(ledger.AdoptNativeStop(groupId, {first.event, origin, first.stopId, StopPhase::CallEnter}) == R::IdentityMismatch);
        }
        Check(ledger.AdoptNativeStop(groupId, {native, origin, stopId, StopPhase::CallEnter}) == R::Applied);
        const ReleaseRequest request{owner, groupId, stopId, native, "continue/" + std::to_string(sequence),
            ledger.Query(groupId)->stateRevision};
        if (sequence == 160) {
            const auto held = ledger.Query(groupId).value();
            Check(!ledger.QueryRelease(first.requestId) && !ledger.QueryRelease("continue/159", groupId));
            Check(ledger.BeginRelease(first).result == R::ReplayExpired);
            auto reused = request;
            reused.requestId = first.requestId;
            Check(ledger.BeginRelease(reused).result == R::ReplayExpired);
            reused.requestId = "continue/159";
            Check(ledger.BeginRelease(reused).result == R::Conflict);
            reused.requestId = "legacy-opaque-id";
            Check(ledger.BeginRelease(reused).result == R::InvalidEvidence);
            Check(ledger.RecordReleaseReceipt(firstAttempt, success) == R::IdentityMismatch);
            Check(ledger.UnresolvedNativeResponsibility()->event == native);
            AssertSameProjection(ledger, held);
        }
        const auto attempt = ledger.BeginRelease(request).effect.value();
        if (sequence == 1) { first = request; firstAttempt = attempt; }
        Check(ledger.RecordReleaseReceipt(attempt, success) == R::Applied);
    }
    auto replayedGroup = Freeze({origin}, first.groupId);
    replayedGroup.membershipRevision = 1;
    Check(ledger.Freeze(replayedGroup, HistoryRetention::Rolling) == R::Historical);
    Check(ledger.Freeze(replayedGroup) == R::InvalidTransition);
    Check(ledger.QueryRelease("continue/160")->receipt == success && ledger.CanRetireLedger());
}

void RollingRetryKeepsUnresolvedResponsibility() {
    StopLedger ledger(owner);
    Check(ledger.Freeze(Freeze({origin}), HistoryRetention::Rolling) == R::Applied);
    Check(ledger.AdoptNativeStop(group, Hit()) == R::Applied);
    Check(SequencedReleaseId("continue/18446744073709551615").has_value());
    for (const auto id : {"continue/", "continue/0", "continue/01", "continue/+1", "continue/-1", "continue/1 ",
             "continue/18446744073709551616", "unsequenced"}) {
        Check(!SequencedReleaseId(id) && ledger.BeginRelease(Request(ledger, id)).result == R::InvalidEvidence);
    }
    const ReleaseReceipt retryable{ReleaseResult::StillPending, 5};
    ReleaseAttempt first;
    for (unsigned i = 1; i <= 75; ++i) {
        const auto command = Request(ledger, "continue/" + std::to_string(i));
        const auto attempt = ledger.BeginRelease(command).effect.value();
        if (i == 1) { first = attempt; }
        Check(ledger.BeginRelease(command).result == R::Duplicate && ledger.QueryRelease(command.requestId) &&
            !ledger.QueryRelease(command.requestId)->receipt);
        Check(ledger.RecordReleaseReceipt(attempt, retryable) == R::Applied);
    }
    Check(!ledger.QueryRelease(first.request.requestId) && ledger.BeginRelease(first.request).result == R::ReplayExpired);
    Check(ledger.RecordReleaseReceipt(first, retryable) == R::IdentityMismatch);
    Check(ledger.QueryRelease("continue/75")->receipt == retryable);
    const auto cleanup = ledger.BeginRelease(Request(ledger, "owner-cleanup"), true).effect.value();
    const ReleaseReceipt unknown{ReleaseResult::Indeterminate, 6};
    Check(ledger.RecordReleaseReceipt(cleanup, unknown) == R::Applied);
    Check(ledger.BeginRelease(Request(ledger, "continue/76")).result == R::ReadbackRequired);
    Check(ledger.Freeze(Freeze({origin}, Id(90)), HistoryRetention::Rolling) == R::InvalidTransition);
    Check(!ledger.CanRetireLedger() && ledger.UnresolvedNativeResponsibility()->event == event &&
        ledger.QueryRelease("owner-cleanup")->receipt == unknown);
    Check(ledger.RecordReleaseReadback(cleanup, {ReleaseResult::Continued, std::nullopt}) == R::Applied);
    Check(ledger.CanRetireLedger());
}

} // namespace

int main() {
    ScopeAndFirstContinue();
    IndeterminateContinueAndExplicitRetry();
    OriginAndIncidentalOutliveFrozenSet();
    UnknownPhaseAndLostReceipt();
    NoNativeHold();
    FailedContinueRetainsItsEvent();
    RollingGroupsAndReplayWatermark();
    RollingRetryKeepsUnresolvedResponsibility();
    std::printf("RESULT=PASS scenarios=8 checks=%u\n", checks);
}
