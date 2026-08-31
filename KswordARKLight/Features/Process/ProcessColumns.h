#pragma once

// ============================================================
// ProcessColumns.h
// 作用：定义 ARKLight 进程列表的稳定列 ID、列分组和视图预设。
// 所有列表、筛选和列选择 UI 均通过本文件的描述表工作，避免散落的列号。
// ============================================================

#include "ProcessEnumerator.h"

#include <commctrl.h>

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Process {

// ProcessColumnGroup 用途：为“选择列”窗口和表头菜单提供语义分组。
enum class ProcessColumnGroup : std::uint8_t {
    General,
    Performance,
    Memory,
    Io,
    Security,
    Kernel
};

// ProcessColumnId 用途：进程表的稳定逻辑列编号；不得依赖其显示顺序。
enum class ProcessColumnId : std::uint8_t {
    Name, Pid, ParentPid, Path, CommandLine, User, StartTime, SessionId, Status, Description, ProcessType,
    Cpu, CpuTime, CycleTime, Disk, Gpu, Net, ThreadCount, BasePriority, PowerThrottling, GpuEngine, GpuDedicatedMemory, GpuSharedMemory,
    WorkingSet, PeakWorkingSet, WorkingSetDelta, PrivateWorkingSet, VirtualMemory, CommitSize, PagedPool, NonPagedPool, PageFaults, PageFaultDelta,
    IoReads, IoWrites, IoOther, IoReadBytes, IoWriteBytes, IoOtherBytes,
    Signature, IsAdmin, PplLevel, UacVirtualization, DataExecutionPrevention, ControlFlowGuard, HardwareStackProtection, PackageName, DpiAwareness, EnterpriseContext, JobObject,
    Protection, Ppl, HandleCount, HandleTable, SectionObject, R0Status, Eprocess, R0Source, R0Anomaly,
    Count
};

// ProcessViewPreset 用途：内置精简列组；Custom 表示用户手工修改后的当前布局。
enum class ProcessViewPreset : std::uint8_t {
    Monitor, Detail, Memory, DiskIo, Gpu, Security, Kernel, Custom
};

// ProcessColumnDescriptor 用途：描述一列的标题、分组、宽度及 ListView 对齐方式。
struct ProcessColumnDescriptor {
    ProcessColumnId id;
    ProcessColumnGroup group;
    const wchar_t* title;
    int width;
    int format;
    bool locked;
};

const std::vector<ProcessColumnDescriptor>& ProcessColumnDescriptors();
const ProcessColumnDescriptor* FindProcessColumn(ProcessColumnId id);
std::vector<ProcessColumnId> DefaultProcessColumns(ProcessViewPreset preset);
const wchar_t* ProcessViewPresetTitle(ProcessViewPreset preset);
const wchar_t* ProcessColumnGroupTitle(ProcessColumnGroup group);
std::wstring ProcessColumnText(const ProcessSnapshotRow& row, ProcessColumnId column);

} // namespace Ksword::Features::Process
