#pragma once

#include "../../KswordCLI/ActionAnalyze/Control/StopLedger.h"

#include <Windows.h>

namespace sb02 {

// 只用于本夹具的单一事件循环。原生事件及操作权限留在 Session。
class LedgerBridge final {
public:
    LedgerBridge(DWORD pid, DWORD tid, DWORD workerTid, DWORD retiredTid);

    using Attempt = ks::cli::action_analyze::control::ReleaseAttempt;
    using Serial = std::uint64_t;

    Attempt AdoptAndBegin(const DEBUG_EVENT& event, Serial serial, bool returning);
    bool MatchAttempt(const Attempt& attempt, const DEBUG_EVENT& event, Serial serial) const;
    Attempt RecordFailureAndRetry(const Attempt& attempt, DWORD nativeError);
    void RecordOwnerFailure(const Attempt& attempt, DWORD nativeError);
    void RecordContinue(const Attempt& attempt, bool withholdReceipt, bool deferToExit);
    void ObserveNextEvent(const DEBUG_EVENT& event, Serial serial);
    void Finish(const DEBUG_EVENT& exit, Serial serial);
    bool HasResponsibility() const;

private:
    void CheckClosed(const Attempt& attempt, bool retiredOnExit);

    const DWORD ownerTid_;
    const DWORD pid_;
    const DWORD originTid_;
    const DWORD workerTid_;
    const DWORD retiredTid_;
    const ks::cli::action_analyze::control::OwnerIdentity owner_;
    const ks::cli::action_analyze::control::ThreadIdentity origin_;
    const ks::cli::action_analyze::control::ThreadIdentity worker_;
    const ks::cli::action_analyze::control::ThreadIdentity retired_;
    ks::cli::action_analyze::control::StopLedger ledger_;
    std::optional<Attempt> previous_;
    std::optional<Attempt> withheld_;
    bool deferToExit_ = false;
};

} // namespace sb02
