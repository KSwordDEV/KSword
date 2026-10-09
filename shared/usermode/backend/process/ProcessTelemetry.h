#pragma once

#include "ProcessFields.h"
#include "../../../../Ksword5.1/Ksword5.1/ksword/network/network_process_etw_monitor.h"

namespace ks::r3::process {

// Owned by one process view, accessed by its serialized refresh worker only.
// Closing the view releases its ETW session after the last worker finishes.
class ProcessTelemetry final {
public:
    void Sample(std::vector<ProcessSnapshotRow>& rows, const std::vector<ProcessFieldId>& columns,
        ULONGLONG tickMs = ::GetTickCount64());

private:
    struct Baseline {
        ULONGLONG creationTime = 0;
        ULONGLONG tickMs = 0;
        ULONGLONG ioReadBytes = 0;
        ULONGLONG ioWriteBytes = 0;
        std::uint64_t rxBytes = 0;
        std::uint64_t txBytes = 0;
        bool networkKnown = false;
    };
    std::unordered_map<DWORD, Baseline> baselines_;
    ks::network::ProcessNetworkEtwMonitor network_;
    ULONGLONG networkRetryTick_ = 0;
};

} // namespace ks::r3::process
