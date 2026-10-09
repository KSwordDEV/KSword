#pragma once
#include "ProcessEnumerator.h"
namespace ks::r3::process {
DWORD ProcessProcessorCount();
void UpdateMemoryCounterDeltas(ProcessSnapshotRow& row, const ProcessSnapshotRow* previousRow);
void UpdateCpuCounterDelta(ProcessSnapshotRow& row, const ULONGLONG* previous, ULONGLONG elapsedMs, DWORD processorCount);
}
