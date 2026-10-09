#include "ProcessCounters.h"
#include <algorithm>
namespace ks::r3::process {
DWORD ProcessProcessorCount() { return std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)); }
void UpdateMemoryCounterDeltas(ProcessSnapshotRow& row, const ProcessSnapshotRow* previousRow) {
        if (previousRow) {
            row.workingSetDeltaBytes = static_cast<LONGLONG>(row.workingSetBytes) - static_cast<LONGLONG>(previousRow->workingSetBytes);
            row.pageFaultDelta = static_cast<LONGLONG>(row.pageFaultCount) - static_cast<LONGLONG>(previousRow->pageFaultCount);
        }
}
void UpdateCpuCounterDelta(ProcessSnapshotRow& row, const ULONGLONG* previous, ULONGLONG elapsedMs, DWORD processorCount) {
    const ULONGLONG total100ns = row.kernelTime100ns + row.userTime100ns;
        row.cpuUsagePercent = 0.0;
        if (elapsedMs > 0 && previous != nullptr && total100ns >= *previous) {
            const ULONGLONG delta100ns = total100ns - *previous;
            const double capacity100ns = static_cast<double>(elapsedMs) * 10000.0 * static_cast<double>(processorCount);
            if (capacity100ns > 0.0) {
                row.cpuUsagePercent = std::clamp((static_cast<double>(delta100ns) * 100.0) / capacity100ns, 0.0, 999.9);
            }
        }
}
}
