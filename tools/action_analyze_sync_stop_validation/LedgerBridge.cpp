#include "LedgerBridge.h"

#include <bcrypt.h>
#include <objbase.h>
#include <array>
#include <cstdio>
#include <stdexcept>

namespace sb02 {
namespace {

using namespace ks::cli::action_analyze::control;
using R = LedgerResult;

void Check(bool ok, const char* condition) {
    if (!ok) { throw std::runtime_error(condition); }
}

std::string NewId() {
    GUID guid{};
    wchar_t text[39]{};
    Check(SUCCEEDED(CoCreateGuid(&guid)) && StringFromGUID2(guid, text, 39) == 39, "allocate fixture instance identifier");
    std::string id;
    for (unsigned i = 1; i < 37; ++i) {
        const auto ch = text[i];
        id.push_back(static_cast<char>(ch >= L'A' && ch <= L'F' ? ch - L'A' + L'a' : ch));
    }
    return id;
}

std::string MemberDigest(const ThreadIdentity& member) {
    auto bytes = member.processInstanceId + ":" + member.threadId;
    std::array<unsigned char, 32> digest{};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "open fixture digest algorithm");
    const auto hashed = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(bytes.data()),
        static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size()));
    const auto closed = BCryptCloseAlgorithmProvider(algorithm, 0);
    Check(hashed == 0 && closed == 0, "hash fixture membership");
    constexpr char hex[] = "0123456789abcdef";
    std::string text;
    for (const auto byte : digest) {
        text.push_back(hex[byte >> 4]);
        text.push_back(hex[byte & 15]);
    }
    return text;
}

} // namespace

LedgerBridge::LedgerBridge(DWORD pid, DWORD tid, DWORD workerTid, DWORD retiredTid)
    : ownerTid_(GetCurrentThreadId()), pid_(pid), originTid_(tid), workerTid_(workerTid), retiredTid_(retiredTid),
      owner_{NewId(), NewId(), NewId(), NewId()}, origin_{NewId(), NewId()},
      worker_{NewId(), origin_.processInstanceId}, retired_{NewId(), origin_.processInstanceId}, ledger_(owner_) {}

LedgerBridge::Attempt LedgerBridge::AdoptAndBegin(const DEBUG_EVENT& event, Serial serial, bool returning) {
    Check(GetCurrentThreadId() == ownerTid_ && event.dwProcessId == pid_ && event.dwThreadId == originTid_ &&
        event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event.u.Exception.dwFirstChance == 1 && !withheld_,
        "only the current owned gate may enter the ledger");
    const auto groupId = NewId();
    const auto stopId = NewId();
    const NativeEventKey key{owner_.backendInstanceId, serial};
    const auto& requested = returning ? retired_ : origin_;
    const auto digest = MemberDigest(requested);
    Check(ledger_.Freeze({groupId, 1, digest, {requested}}) == R::Applied, "freeze fixture group once");
    if (returning) {
        Check(ledger_.ObserveMember(groupId, retired_, MemberEvidence::Exited) == R::Applied, "import exact prior thread exit");
    }
    Check(ledger_.SealMembership(groupId) == R::Applied, "seal fixture group");
    Check(ledger_.AdoptNativeStop(groupId, {key, origin_, stopId, returning ? StopPhase::CallReturn : StopPhase::CallEnter}) == R::Applied,
        "adopt native gate once");
    Check(ledger_.ObserveIncidental(groupId, key, IncidentalQuality::Partial, {worker_}) == R::Applied,
        "only the known incidental worker is claimed");

    const auto view = ledger_.Query(groupId).value();
    Check(view.origin && view.origin->threadId == origin_.threadId && view.origin->hold == OriginHold::Held &&
        view.membershipRevision == 1 && view.membershipSha256 == digest && view.members.size() == 1 &&
        view.members.front().threadId == requested.threadId && view.incidentalQuality == IncidentalQuality::Partial &&
        view.incidentalThreadIds == std::vector{worker_.threadId} && !view.historical && HasResponsibility(),
        "independent frozen, origin, and incidental evidence");
    Check(returning ? view.state == GroupState::OriginHeld && view.members.front().state == MemberState::Exited
                    : view.state == GroupState::HeldComplete && view.members.front().state == MemberState::Held,
        "project only verified scope at the held boundary");
    if (previous_) {
        const auto replay = ledger_.BeginRelease(previous_->request);
        Check(replay.result == R::Duplicate && !replay.effect && ledger_.UnresolvedNativeResponsibility()->event == key &&
            ledger_.Query(groupId)->stateRevision == view.stateRevision, "old release replay cannot continue the current gate");
    }
    const ReleaseRequest request{owner_, groupId, stopId, key, NewId(), view.stateRevision};
    const auto result = ledger_.BeginRelease(request);
    const auto duplicate = ledger_.BeginRelease(request);
    Check(result.result == R::Applied && result.effect && duplicate.result == R::Duplicate && !duplicate.effect &&
        ledger_.Query(groupId)->state == GroupState::ReleasePending && HasResponsibility(), "issue one release and retain pending responsibility");
    std::printf("LEDGER pid=%lu phase=%s event=%llu state=%s revision=%llu groupId=%s originTid=%lu workerTid=%lu requestedTid=%lu\n",
        pid_, returning ? "call-return" : "call-enter", serial, returning ? "origin-held" : "held-complete",
        view.stateRevision, groupId.c_str(), originTid_, workerTid_, returning ? retiredTid_ : originTid_);
    return *result.effect;
}

bool LedgerBridge::MatchAttempt(const Attempt& attempt, const DEBUG_EVENT& event, Serial serial) const {
    const auto responsibility = ledger_.UnresolvedNativeResponsibility();
    return GetCurrentThreadId() == ownerTid_ && event.dwProcessId == pid_ && event.dwThreadId == originTid_ &&
        event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && attempt.request.event.serial == serial && responsibility &&
        responsibility->event == attempt.request.event && responsibility->groupId == attempt.request.groupId &&
        responsibility->stopId == attempt.request.stopId && responsibility->lastRequestId == attempt.request.requestId &&
        responsibility->state == EventState::ReleasePending;
}

LedgerBridge::Attempt LedgerBridge::RecordFailureAndRetry(const Attempt& attempt, DWORD nativeError) {
    auto request = attempt.request;
    Check(ledger_.RecordReleaseReceipt(attempt, {ReleaseResult::StillPending, nativeError}) == R::Applied,
        "record native failure after verified continued hold");
    const auto view = ledger_.Query(request.groupId).value();
    const auto receipt = ledger_.QueryRelease(request.requestId).value();
    const auto duplicate = ledger_.BeginRelease(request);
    Check(view.state == GroupState::RecoveryRequired && view.origin && view.origin->hold == OriginHold::RecoveryRequired &&
        view.incidentalThreadIds == std::vector{worker_.threadId} && HasResponsibility() &&
        ledger_.UnresolvedNativeResponsibility()->state == EventState::Retryable &&
        receipt.receipt && receipt.receipt->nativeError == nativeError && duplicate.result == R::Duplicate && !duplicate.effect,
        "failed attempt retains exact event and blocks close or duplicate release");
    std::printf("LEDGER_FAILURE pid=%lu event=%llu error=%lu revision=%llu ledgerUnresolved=1\n",
        pid_, request.event.serial, nativeError, view.stateRevision);
    request.requestId = NewId();
    request.expectedStateRevision = view.stateRevision;
    const auto retry = ledger_.BeginRelease(request);
    Check(retry.result == R::Applied && retry.effect && retry.effect->request.event == attempt.request.event,
        "explicit retry belongs to same held native event");
    return *retry.effect;
}

void LedgerBridge::RecordOwnerFailure(const Attempt& attempt, DWORD nativeError) {
    Check(ledger_.RecordReleaseReceipt(attempt, {ReleaseResult::Indeterminate, nativeError}) == R::Applied && HasResponsibility(),
        "actual owner failure stays unresolved");
    std::printf("LEDGER_OWNER_FAILURE pid=%lu event=%llu error=%lu ledgerUnresolved=1\n", pid_, attempt.request.event.serial, nativeError);
}

void LedgerBridge::RecordContinue(const Attempt& attempt, bool withholdReceipt, bool deferToExit) {
    Check(GetCurrentThreadId() == ownerTid_ && !withheld_, "successful Continue recorded by same owner");
    if (!withholdReceipt) {
        Check(ledger_.RecordReleaseReceipt(attempt, {ReleaseResult::Continued, 0}) == R::Applied, "accept native Continue result");
        CheckClosed(attempt, false);
        return;
    }
    // 故障注入只扣留给账本的回执，owner 已获得真实 Continue 返回且仍持有本地记录。
    withheld_ = attempt;
    deferToExit_ = deferToExit;
    auto retry = attempt.request;
    retry.expectedStateRevision = ledger_.Query(retry.groupId)->stateRevision;
    retry.requestId = NewId();
    const auto blocked = ledger_.BeginRelease(retry);
    Check(blocked.result == R::ReadbackRequired && !blocked.effect && HasResponsibility() &&
        !ledger_.QueryRelease(attempt.request.requestId)->receipt, "withheld receipt prevents second Continue or closing ledger");
    std::printf("LEDGER_WITHHELD pid=%lu event=%llu reconcile=%s ledgerUnresolved=1\n",
        pid_, attempt.request.event.serial, deferToExit ? "child-exit" : "next-native-event");
}

void LedgerBridge::ObserveNextEvent(const DEBUG_EVENT& event, Serial serial) {
    if (!withheld_ || deferToExit_) { return; }
    Check(GetCurrentThreadId() == ownerTid_ && event.dwProcessId == pid_ && serial > withheld_->request.event.serial,
        "distinct subsequent native event from same owned debuggee");
    const auto attempt = *withheld_;
    Check(ledger_.RecordReleaseReadback(attempt, {ReleaseResult::Continued, 0}) == R::Applied &&
        ledger_.QueryRelease(attempt.request.requestId)->readback.has_value(), "accept corroborated owner readback without another Continue");
    withheld_.reset();
    CheckClosed(attempt, false);
    std::printf("LEDGER_READBACK pid=%lu releasedEvent=%llu observedEvent=%llu observedKind=%lu\n",
        pid_, attempt.request.event.serial, serial, event.dwDebugEventCode);
}

void LedgerBridge::Finish(const DEBUG_EVENT& exit, Serial serial) {
    Check(GetCurrentThreadId() == ownerTid_ && exit.dwProcessId == pid_ && exit.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT,
        "ledger finish follows actual exit event and signaled process");
    if (withheld_) {
        const auto attempt = *withheld_;
        Check(deferToExit_ && serial > attempt.request.event.serial && HasResponsibility(), "unresolved record survived until child exit");
        Check(ledger_.RecordRetiredOnExit(attempt.request.groupId, attempt.request.event, origin_.processInstanceId) == R::Applied &&
            ledger_.QueryRelease(attempt.request.requestId)->eventRetiredOnExit, "retire the exact event after verified process exit");
        withheld_.reset();
        CheckClosed(attempt, true);
        std::printf("LEDGER_EXIT_RETIRED pid=%lu releasedEvent=%llu exitEvent=%llu\n", pid_, attempt.request.event.serial, serial);
    }
    Check(!HasResponsibility(), "close only after all fixture ledger responsibility cleared");
}

void LedgerBridge::CheckClosed(const Attempt& attempt, bool retiredOnExit) {
    const auto view = ledger_.Query(attempt.request.groupId).value();
    const auto duplicate = ledger_.BeginRelease(attempt.request);
    Check(view.historical && !HasResponsibility() && duplicate.result == R::Duplicate && !duplicate.effect &&
        view.origin->hold == (retiredOnExit ? OriginHold::Exited : OriginHold::Released) &&
        view.state == (view.members.front().state == MemberState::Exited ? GroupState::Ended : GroupState::Released) &&
        view.incidentalThreadIds == std::vector{worker_.threadId} && view.stateRevision > attempt.issuedRevision,
        "native confirmation retires responsibility and keeps frozen historical evidence");
    previous_ = attempt;
    std::printf("LEDGER_RELEASED pid=%lu event=%llu revision=%llu origin=%s ledgerUnresolved=0\n", pid_,
        attempt.request.event.serial, view.stateRevision, retiredOnExit ? "exited" : "released");
}

bool LedgerBridge::HasResponsibility() const {
    return ledger_.UnresolvedNativeResponsibility().has_value() || !ledger_.CanRetireLedger();
}

} // namespace sb02
