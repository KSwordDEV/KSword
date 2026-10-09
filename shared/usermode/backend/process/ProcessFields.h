#pragma once
#include "ProcessEnumerator.h"
#include <cstdint>
#include <vector>
namespace ks::r3::process {
enum class ProcessFieldId : std::uint8_t {
    Name, Pid, ParentPid, Path, CommandLine, User, StartTime, SessionId, Status, Description, ProcessType,
    Cpu, CpuTime, CycleTime, Disk, Gpu, Net, ThreadCount, BasePriority, PowerThrottling, GpuEngine, GpuDedicatedMemory, GpuSharedMemory,
    WorkingSet, PeakWorkingSet, WorkingSetDelta, PrivateWorkingSet, VirtualMemory, CommitSize, PagedPool, NonPagedPool, PageFaults, PageFaultDelta,
    IoReads, IoWrites, IoOther, IoReadBytes, IoWriteBytes, IoOtherBytes,
    Signature, IsAdmin, PplLevel, UacVirtualization, DataExecutionPrevention, ControlFlowGuard, HardwareStackProtection, PackageName, DpiAwareness, EnterpriseContext, JobObject,
    Protection, Ppl, HandleCount, HandleTable, SectionObject, R0Status, Eprocess, R0Source, R0Anomaly,
    Count
};
}
