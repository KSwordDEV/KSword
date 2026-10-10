#include "ProcessTelemetry.h"

#include <algorithm>
#include <unordered_set>

namespace ks::r3::process {
namespace {
std::wstring RateText(double bytesPerSecond) {
    const wchar_t* units[] = { L"B/s", L"KiB/s", L"MiB/s", L"GiB/s" };
    int unit = 0;
    while (bytesPerSecond >= 1024.0 && unit < 3) { bytesPerSecond /= 1024.0; ++unit; }
    wchar_t text[64]{};
    ::swprintf_s(text, L"%.1f %s", bytesPerSecond, units[unit]);
    return text;
}
} // namespace

void ProcessTelemetry::Sample(std::vector<ProcessSnapshotRow>& rows,
    const std::vector<ProcessFieldId>& columns, ULONGLONG tickMs) {
    const bool wantNetwork = std::find(columns.begin(), columns.end(), ProcessFieldId::Net) != columns.end();
    if (!wantNetwork) {
        network_.Stop();
        networkRetryTick_ = 0;
    } else if (!network_.IsRunning() && (networkRetryTick_ == 0 || tickMs >= networkRetryTick_)) {
        network_.Stop();
        (void)network_.Start();
        for (auto& entry : baselines_) entry.second.networkKnown = false;
        networkRetryTick_ = tickMs + 30000;
    }
    const auto health = network_.SnapshotHealth();
    const bool networkKnown = wantNetwork && health.isRunning && !health.dataLossDetected;
    const auto counters = networkKnown ? network_.SnapshotCounters() :
        std::unordered_map<std::uint32_t, ks::network::ProcessNetworkTrafficCounters>{};
    std::unordered_set<std::uint32_t> livePids;
    for (auto& row : rows) {
        if (row.r0KernelOnly) continue;
        livePids.insert(row.processId);
        const auto net = counters.find(row.processId);
        const std::uint64_t rx = net == counters.end() ? 0 : net->second.rxBytes;
        const std::uint64_t tx = net == counters.end() ? 0 : net->second.txBytes;
        row.networkCountersKnown = networkKnown;
        row.networkRxBytes = rx; row.networkTxBytes = tx;
        row.networkRateKnown = false; row.networkBytesPerSecond = 0.0;
        const auto previous = baselines_.find(row.processId);
        const bool sameInstance = previous != baselines_.end() && row.creationTime100ns != 0 &&
            row.creationTime100ns == previous->second.creationTime && tickMs > previous->second.tickMs;
        row.diskRateKnown = sameInstance && row.ioReadBytes >= previous->second.ioReadBytes &&
            row.ioWriteBytes >= previous->second.ioWriteBytes;
        if (row.diskRateKnown) {
            const double elapsedSeconds = static_cast<double>(tickMs - previous->second.tickMs) / 1000.0;
            row.diskBytesPerSecond = (static_cast<double>(row.ioReadBytes - previous->second.ioReadBytes) +
                static_cast<double>(row.ioWriteBytes - previous->second.ioWriteBytes)) / elapsedSeconds;
        }
        if (wantNetwork) {
            std::wstring text;
            if (!health.isRunning) {
                const auto error = network_.LastErrorText();
                text = L"ETW 启动失败（需要权限）：" + std::wstring(error.begin(), error.end());
            } else if (health.dataLossDetected) {
                text = L"ETW 丢失事件";
            } else if (sameInstance && previous->second.networkKnown &&
                rx >= previous->second.rxBytes && tx >= previous->second.txBytes) {
                const double elapsedSeconds = static_cast<double>(tickMs - previous->second.tickMs) / 1000.0;
                row.networkRateKnown = true;
                row.networkBytesPerSecond = (static_cast<double>(rx - previous->second.rxBytes) +
                    static_cast<double>(tx - previous->second.txBytes)) / elapsedSeconds;
                text = RateText(row.networkBytesPerSecond);
            } else {
                text = L"采样中";
            }
            row.detailTexts[static_cast<std::uint8_t>(ProcessFieldId::Net)] = std::move(text);
        }
        baselines_[row.processId] = { row.creationTime100ns, tickMs, row.ioReadBytes, row.ioWriteBytes,
            rx, tx, networkKnown };
    }
    std::erase_if(baselines_, [&livePids](const auto& entry) { return livePids.find(entry.first) == livePids.end(); });
    network_.PruneCounters(livePids);
}

} // namespace ks::r3::process
