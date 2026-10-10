#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessTelemetry.h"
#include "../shared/usermode/backend/process/ProcessCounters.h"
#include "../Ksword5.1/Ksword5.1/ksword/string/string.h"
#include <algorithm>
#include <chrono>
#include <thread>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process;
Json health(const ks::network::ProcessNetworkEtwHealth& value) {
    return Json::object({{L"running", Json::boolean(value.isRunning)}, {L"dataLossDetected", Json::boolean(value.dataLossDetected)},
        {L"eventsLost", Json::count(value.eventsLost)}, {L"win32Error", value.errorCodeKnown ? Json::number(value.errorCode) : Json{}},
        {L"errorText", Json::string(ks::str::Utf8ToUtf16(value.errorText))}});
}
Result sample(const Args& args) {
    const auto interval = args.u32(L"--interval-ms", 1000); const auto network = args.get(L"--network", L"off");
    if (interval < 100 || interval > 30000) throw std::invalid_argument("--interval-ms must be 100..30000");
    if (network != L"on" && network != L"off") throw std::invalid_argument("--network must be on|off");
    process::Lease lease(args);
    if (!lease.handle.valid() || !lease.matches || !lease.alive()) return {3, Json::object({{L"target", lease.json()}}), {L"Target identity could not be acquired, changed, or has exited."}};
    backend::ProcessTelemetry telemetry; Cancellation cancellation;
    const std::vector<backend::ProcessFieldId> columns = network == L"on" ? std::vector<backend::ProcessFieldId>{backend::ProcessFieldId::Net} : std::vector<backend::ProcessFieldId>{};
    auto collect = [&lease] {
        auto snapshot = backend::EnumerateProcessesByNtQuerySystemInformation();
        std::erase_if(snapshot.rows, [&lease](const auto& row) { return row.processId != lease.pid || row.creationTime100ns != lease.creationTime; });
        return snapshot;
    };
    auto first = collect();
    if (!first.success || first.malformed || first.rows.empty()) return {first.malformed ? 4 : 3, Json::object({{L"target", lease.json()},
        {L"stage", Json::string(L"initial")}, {L"ntStatus", Json::hex(static_cast<DWORD>(first.ntStatus))}, {L"malformed", Json::boolean(first.malformed)}}),
        {L"Initial native process sample is unavailable.", first.diagnosticText}};
    const auto start = GetTickCount64(); telemetry.Sample(first.rows, columns, start);
    while (!cancellation.token->load() && GetTickCount64() - start < interval && lease.alive())
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    if (cancellation.token->load()) return {6, Json::object({{L"target", lease.json()}, {L"cancelled", Json::boolean(true)}}), {L"Sampling cancelled; the owned ETW session is released."}};
    if (!lease.alive()) return {3, Json::object({{L"target", lease.json()}}), {L"Target exited during sampling; no rates are published."}};
    auto second = collect(); const auto finish = GetTickCount64(), elapsed = finish - start;
    if (!second.success || second.malformed || second.rows.empty()) return {second.malformed ? 4 : 3, Json::object({{L"target", lease.json()},
        {L"stage", Json::string(L"final")}, {L"ntStatus", Json::hex(static_cast<DWORD>(second.ntStatus))}, {L"malformed", Json::boolean(second.malformed)}}),
        {L"Final native process sample is unavailable.", second.diagnosticText}};
    telemetry.Sample(second.rows, columns, finish);
    auto& row = second.rows.front(); const auto& before = first.rows.front();
    const auto cpuBefore = before.kernelTime100ns + before.userTime100ns, cpuAfter = row.kernelTime100ns + row.userTime100ns;
    const auto processors = backend::ProcessProcessorCount(); const bool cpuKnown = elapsed && cpuAfter >= cpuBefore;
    backend::UpdateCpuCounterDelta(row, cpuKnown ? &cpuBefore : nullptr, elapsed, processors);
    backend::UpdateMemoryCounterDeltas(row, &before);
    const auto during = telemetry.NetworkHealth(); telemetry.Stop(); const auto stopped = telemetry.NetworkHealth();
    const bool networkKnown = network == L"on" && row.networkRateKnown && !stopped.dataLossDetected;
    const bool complete = cpuKnown && row.diskRateKnown && (network == L"off" || networkKnown);
    const auto signedCount = [](LONGLONG value) { return Json::string(std::to_wstring(value)); };
    return {complete ? 0 : 6, Json::object({{L"target", lease.json()}, {L"source", Json::string(L"two native snapshots; optional private Kernel-Network ETW")},
        {L"requestedIntervalMs", Json::number(interval)}, {L"elapsedMs", Json::count(elapsed)}, {L"logicalProcessors", Json::number(processors)},
        {L"cpuKnown", Json::boolean(cpuKnown)}, {L"cpuPercent", cpuKnown ? Json::real(row.cpuUsagePercent) : Json{}},
        {L"cpuBefore100ns", Json::count(cpuBefore)}, {L"cpuAfter100ns", Json::count(cpuAfter)},
        {L"diskRateKnown", Json::boolean(row.diskRateKnown)}, {L"diskBytesPerSecond", row.diskRateKnown ? Json::real(row.diskBytesPerSecond) : Json{}},
        {L"ioReadBytesBefore", Json::count(before.ioReadBytes)}, {L"ioReadBytesAfter", Json::count(row.ioReadBytes)},
        {L"ioWriteBytesBefore", Json::count(before.ioWriteBytes)}, {L"ioWriteBytesAfter", Json::count(row.ioWriteBytes)},
        {L"workingSetDeltaBytes", signedCount(row.workingSetDeltaBytes)}, {L"pageFaultDelta", signedCount(row.pageFaultDelta)},
        {L"networkRequested", Json::boolean(network == L"on")}, {L"networkRateKnown", Json::boolean(networkKnown)},
        {L"networkBytesPerSecond", networkKnown ? Json::real(row.networkBytesPerSecond) : Json{}},
        {L"networkRxBytesBefore", first.rows.front().networkCountersKnown ? Json::count(first.rows.front().networkRxBytes) : Json{}},
        {L"networkTxBytesBefore", first.rows.front().networkCountersKnown ? Json::count(first.rows.front().networkTxBytes) : Json{}},
        {L"networkRxBytesAfter", row.networkCountersKnown ? Json::count(row.networkRxBytes) : Json{}},
        {L"networkTxBytesAfter", row.networkCountersKnown ? Json::count(row.networkTxBytes) : Json{}},
        {L"networkHealth", health(during)}, {L"networkFinalHealth", health(stopped)}, {L"cancelled", Json::boolean(false)}}),
        complete ? std::vector<std::wstring>{} : std::vector<std::wstring>{L"Some sampled counters reset or optional ETW evidence is unavailable/incomplete."}};
}
}
void registerProcessTelemetry() {
    addCommand({L"process telemetry sample", L"KswordCLI.exe process telemetry sample --pid PID [--creation-time FILETIME] [--interval-ms N] [--network on|off] [--backend r3] [--json]",
        L"Sample bounded CPU, I/O and memory deltas with optional private network ETW.", L"Required: --pid. Optional: --creation-time expected identity, --interval-ms 100..30000 (default 1000), --network on|off (default off), --backend r3, --json.",
        L"Fields: elapsedMs, CPU/I/O baselines and rates, memory deltas, network totals and ETW health. CPU is normalized over all logical processors; disk counts process read/write I/O, not physical disk traffic. Network totals begin at this session. Stops owned ETW session on completion, failure or Ctrl+C; partial/cancelled evidence returns 6.", sample});
}
}
