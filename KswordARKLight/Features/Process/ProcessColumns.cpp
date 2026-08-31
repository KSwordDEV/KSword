#include "ProcessColumns.h"

#include <array>
#include <cwchar>

namespace Ksword::Features::Process {
namespace {

// NumberText 用途：将无符号计数格式化为 ListView 可直接显示的文本。
std::wstring NumberText(ULONGLONG value) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"%llu", static_cast<unsigned long long>(value));
    return buffer;
}

// BytesText 用途：把字节数转换为紧凑容量文本，避免表格中出现难读的大整数。
std::wstring BytesText(ULONGLONG value) {
    const wchar_t* suffixes[] = { L"B", L"KiB", L"MiB", L"GiB", L"TiB" };
    double display = static_cast<double>(value);
    int suffix = 0;
    while (display >= 1024.0 && suffix < 4) { display /= 1024.0; ++suffix; }
    wchar_t buffer[64]{};
    if (suffix == 0) {
        ::swprintf_s(buffer, L"%llu %s", static_cast<unsigned long long>(value), suffixes[suffix]);
    } else {
        ::swprintf_s(buffer, L"%.1f %s", display, suffixes[suffix]);
    }
    return buffer;
}

// TimeText 用途：将 100ns 累计 CPU 时间转换为秒，适合任务管理器式进程表。
std::wstring TimeText(ULONGLONG time100ns) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"%.2f s", static_cast<double>(time100ns) / 10000000.0);
    return buffer;
}

const std::vector<ProcessColumnDescriptor> kColumns = {
    { ProcessColumnId::Name, ProcessColumnGroup::General, L"进程", 250, LVCFMT_LEFT, true },
    { ProcessColumnId::Pid, ProcessColumnGroup::General, L"PID", 78, LVCFMT_RIGHT, true },
    { ProcessColumnId::ParentPid, ProcessColumnGroup::General, L"父 PID", 78, LVCFMT_RIGHT, false },
    { ProcessColumnId::Path, ProcessColumnGroup::General, L"映像路径", 380, LVCFMT_LEFT, false },
    { ProcessColumnId::CommandLine, ProcessColumnGroup::General, L"命令行", 360, LVCFMT_LEFT, false },
    { ProcessColumnId::User, ProcessColumnGroup::General, L"用户", 140, LVCFMT_LEFT, false },
    { ProcessColumnId::StartTime, ProcessColumnGroup::General, L"启动时间", 150, LVCFMT_LEFT, false },
    { ProcessColumnId::SessionId, ProcessColumnGroup::General, L"会话", 70, LVCFMT_RIGHT, false },
    { ProcessColumnId::Status, ProcessColumnGroup::General, L"状态", 95, LVCFMT_LEFT, false },
    { ProcessColumnId::Description, ProcessColumnGroup::General, L"描述", 200, LVCFMT_LEFT, false },
    { ProcessColumnId::ProcessType, ProcessColumnGroup::General, L"类型", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::Cpu, ProcessColumnGroup::Performance, L"CPU", 74, LVCFMT_RIGHT, false },
    { ProcessColumnId::CpuTime, ProcessColumnGroup::Performance, L"CPU 时间", 105, LVCFMT_RIGHT, false },
    { ProcessColumnId::CycleTime, ProcessColumnGroup::Performance, L"周期", 125, LVCFMT_RIGHT, false },
    { ProcessColumnId::Disk, ProcessColumnGroup::Performance, L"磁盘", 90, LVCFMT_RIGHT, false },
    { ProcessColumnId::Gpu, ProcessColumnGroup::Performance, L"GPU", 74, LVCFMT_RIGHT, false },
    { ProcessColumnId::Net, ProcessColumnGroup::Performance, L"网络", 90, LVCFMT_RIGHT, false },
    { ProcessColumnId::ThreadCount, ProcessColumnGroup::Performance, L"线程", 70, LVCFMT_RIGHT, false },
    { ProcessColumnId::BasePriority, ProcessColumnGroup::Performance, L"基础优先级", 95, LVCFMT_RIGHT, false },
    { ProcessColumnId::PowerThrottling, ProcessColumnGroup::Performance, L"效率模式", 95, LVCFMT_LEFT, false },
    { ProcessColumnId::GpuEngine, ProcessColumnGroup::Performance, L"GPU 引擎", 140, LVCFMT_LEFT, false },
    { ProcessColumnId::GpuDedicatedMemory, ProcessColumnGroup::Performance, L"专用 GPU 内存", 125, LVCFMT_RIGHT, false },
    { ProcessColumnId::GpuSharedMemory, ProcessColumnGroup::Performance, L"共享 GPU 内存", 125, LVCFMT_RIGHT, false },
    { ProcessColumnId::WorkingSet, ProcessColumnGroup::Memory, L"工作集", 110, LVCFMT_RIGHT, false },
    { ProcessColumnId::PeakWorkingSet, ProcessColumnGroup::Memory, L"峰值工作集", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::WorkingSetDelta, ProcessColumnGroup::Memory, L"工作集增量", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::PrivateWorkingSet, ProcessColumnGroup::Memory, L"专用工作集", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::VirtualMemory, ProcessColumnGroup::Memory, L"虚拟内存", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::CommitSize, ProcessColumnGroup::Memory, L"提交大小", 110, LVCFMT_RIGHT, false },
    { ProcessColumnId::PagedPool, ProcessColumnGroup::Memory, L"分页池", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::NonPagedPool, ProcessColumnGroup::Memory, L"非分页池", 105, LVCFMT_RIGHT, false },
    { ProcessColumnId::PageFaults, ProcessColumnGroup::Memory, L"页面错误", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::PageFaultDelta, ProcessColumnGroup::Memory, L"页面错误增量", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::IoReads, ProcessColumnGroup::Io, L"I/O 读取", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::IoWrites, ProcessColumnGroup::Io, L"I/O 写入", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::IoOther, ProcessColumnGroup::Io, L"I/O 其他", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::IoReadBytes, ProcessColumnGroup::Io, L"I/O 读取字节", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::IoWriteBytes, ProcessColumnGroup::Io, L"I/O 写入字节", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::IoOtherBytes, ProcessColumnGroup::Io, L"I/O 其他字节", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::Signature, ProcessColumnGroup::Security, L"数字签名", 120, LVCFMT_LEFT, false },
    { ProcessColumnId::IsAdmin, ProcessColumnGroup::Security, L"管理员", 82, LVCFMT_LEFT, false },
    { ProcessColumnId::PplLevel, ProcessColumnGroup::Security, L"PPL 级别", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::UacVirtualization, ProcessColumnGroup::Security, L"UAC 虚拟化", 105, LVCFMT_LEFT, false },
    { ProcessColumnId::DataExecutionPrevention, ProcessColumnGroup::Security, L"DEP", 85, LVCFMT_LEFT, false },
    { ProcessColumnId::ControlFlowGuard, ProcessColumnGroup::Security, L"CFG", 85, LVCFMT_LEFT, false },
    { ProcessColumnId::HardwareStackProtection, ProcessColumnGroup::Security, L"硬件堆栈保护", 130, LVCFMT_LEFT, false },
    { ProcessColumnId::PackageName, ProcessColumnGroup::Security, L"程序包名称", 220, LVCFMT_LEFT, false },
    { ProcessColumnId::DpiAwareness, ProcessColumnGroup::Security, L"DPI 感知", 115, LVCFMT_LEFT, false },
    { ProcessColumnId::EnterpriseContext, ProcessColumnGroup::Security, L"企业上下文", 110, LVCFMT_LEFT, false },
    { ProcessColumnId::JobObject, ProcessColumnGroup::Security, L"作业对象", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::Protection, ProcessColumnGroup::Kernel, L"保护状态", 115, LVCFMT_LEFT, false },
    { ProcessColumnId::Ppl, ProcessColumnGroup::Kernel, L"PPL", 70, LVCFMT_LEFT, false },
    { ProcessColumnId::HandleCount, ProcessColumnGroup::Kernel, L"句柄", 85, LVCFMT_RIGHT, false },
    { ProcessColumnId::HandleTable, ProcessColumnGroup::Kernel, L"对象表", 95, LVCFMT_LEFT, false },
    { ProcessColumnId::SectionObject, ProcessColumnGroup::Kernel, L"SectionObject", 125, LVCFMT_LEFT, false },
    { ProcessColumnId::R0Status, ProcessColumnGroup::Kernel, L"R0 状态", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::Eprocess, ProcessColumnGroup::Kernel, L"EPROCESS", 150, LVCFMT_RIGHT, false },
    { ProcessColumnId::R0Source, ProcessColumnGroup::Kernel, L"R0 来源", 150, LVCFMT_LEFT, false },
    { ProcessColumnId::R0Anomaly, ProcessColumnGroup::Kernel, L"R0 异常", 180, LVCFMT_LEFT, false },
};

} // namespace

const std::vector<ProcessColumnDescriptor>& ProcessColumnDescriptors() { return kColumns; }
const ProcessColumnDescriptor* FindProcessColumn(ProcessColumnId id) {
    for (const auto& column : kColumns) if (column.id == id) return &column;
    return nullptr;
}

std::vector<ProcessColumnId> DefaultProcessColumns(ProcessViewPreset preset) {
    using C = ProcessColumnId;
    switch (preset) {
    case ProcessViewPreset::Detail: return { C::Name, C::Pid, C::ParentPid, C::Path, C::CommandLine, C::User, C::StartTime, C::SessionId, C::Status, C::Signature };
    case ProcessViewPreset::Memory: return { C::Name, C::Pid, C::WorkingSet, C::PeakWorkingSet, C::WorkingSetDelta, C::PrivateWorkingSet, C::VirtualMemory, C::CommitSize, C::PagedPool, C::NonPagedPool, C::PageFaults, C::PageFaultDelta };
    case ProcessViewPreset::DiskIo: return { C::Name, C::Pid, C::Disk, C::IoReads, C::IoWrites, C::IoOther, C::IoReadBytes, C::IoWriteBytes, C::IoOtherBytes };
    case ProcessViewPreset::Gpu: return { C::Name, C::Pid, C::Gpu, C::GpuEngine, C::GpuDedicatedMemory, C::GpuSharedMemory, C::Cpu, C::WorkingSet };
    case ProcessViewPreset::Security: return { C::Name, C::Pid, C::Signature, C::IsAdmin, C::PplLevel, C::UacVirtualization, C::DataExecutionPrevention, C::ControlFlowGuard, C::HardwareStackProtection, C::PackageName, C::DpiAwareness, C::JobObject };
    case ProcessViewPreset::Kernel: return { C::Name, C::Pid, C::Protection, C::Ppl, C::HandleCount, C::HandleTable, C::SectionObject, C::R0Status, C::Eprocess, C::R0Source, C::R0Anomaly };
    case ProcessViewPreset::Monitor:
    case ProcessViewPreset::Custom:
    default: return { C::Name, C::Pid, C::Cpu, C::WorkingSet, C::PrivateWorkingSet, C::VirtualMemory, C::ThreadCount, C::SessionId, C::PageFaults };
    }
}

const wchar_t* ProcessViewPresetTitle(ProcessViewPreset preset) {
    switch (preset) { case ProcessViewPreset::Monitor: return L"监视"; case ProcessViewPreset::Detail: return L"详细"; case ProcessViewPreset::Memory: return L"内存"; case ProcessViewPreset::DiskIo: return L"磁盘 I/O"; case ProcessViewPreset::Gpu: return L"GPU"; case ProcessViewPreset::Security: return L"安全"; case ProcessViewPreset::Kernel: return L"内核"; default: return L"自定义"; }
}
const wchar_t* ProcessColumnGroupTitle(ProcessColumnGroup group) {
    switch (group) { case ProcessColumnGroup::General: return L"常规"; case ProcessColumnGroup::Performance: return L"性能"; case ProcessColumnGroup::Memory: return L"内存"; case ProcessColumnGroup::Io: return L"磁盘 I/O"; case ProcessColumnGroup::Security: return L"安全与策略"; default: return L"内核扩展"; }
}

std::wstring ProcessColumnText(const ProcessSnapshotRow& row, ProcessColumnId column) {
    using C = ProcessColumnId;
    const auto collected = row.detailTexts.find(static_cast<std::uint8_t>(column));
    if (collected != row.detailTexts.end()) return collected->second;
    switch (column) {
    case C::Name: return row.imageName; case C::Pid: return NumberText(row.processId); case C::ParentPid: return NumberText(row.parentProcessId); case C::Path: return row.imagePath.empty() ? L"<访问被拒绝>" : row.imagePath; case C::SessionId: return NumberText(row.sessionId); case C::ThreadCount: return NumberText(row.threadCount); case C::BasePriority: return NumberText(row.basePriority); case C::Cpu: { wchar_t b[32]{}; ::swprintf_s(b, L"%.1f%%", row.cpuUsagePercent); return b; }
    case C::CpuTime: return TimeText(row.kernelTime100ns + row.userTime100ns); case C::CycleTime: return NumberText(row.cycleTime); case C::WorkingSet: return BytesText(row.workingSetBytes); case C::PeakWorkingSet: return BytesText(row.peakWorkingSetBytes); case C::WorkingSetDelta: return (row.workingSetDeltaBytes >= 0 ? L"+" : L"") + BytesText(static_cast<ULONGLONG>(row.workingSetDeltaBytes >= 0 ? row.workingSetDeltaBytes : -row.workingSetDeltaBytes)); case C::PrivateWorkingSet: return BytesText(row.privatePageBytes); case C::VirtualMemory: return BytesText(row.virtualSizeBytes); case C::CommitSize: return BytesText(row.commitBytes); case C::PagedPool: return BytesText(row.pagedPoolBytes); case C::NonPagedPool: return BytesText(row.nonPagedPoolBytes); case C::PageFaults: return NumberText(row.pageFaultCount); case C::PageFaultDelta: return (row.pageFaultDelta >= 0 ? L"+" : L"") + NumberText(static_cast<ULONGLONG>(row.pageFaultDelta >= 0 ? row.pageFaultDelta : -row.pageFaultDelta)); case C::IoReads: return NumberText(row.ioReadOperations); case C::IoWrites: return NumberText(row.ioWriteOperations); case C::IoOther: return NumberText(row.ioOtherOperations); case C::IoReadBytes: return BytesText(row.ioReadBytes); case C::IoWriteBytes: return BytesText(row.ioWriteBytes); case C::IoOtherBytes: return BytesText(row.ioOtherBytes); case C::HandleCount: return NumberText(row.handleCount); case C::Eprocess: { wchar_t b[32]{}; ::swprintf_s(b, L"0x%0*llX", sizeof(void*) == 8 ? 16 : 8, static_cast<unsigned long long>(row.r0ProcessObjectAddress)); return row.r0ProcessObjectAddress ? b : L"-"; }
    case C::R0Source: return row.r0AuditSummary.empty() ? L"不可用" : row.r0AuditSummary; case C::R0Anomaly: return row.r0AuditDetail.empty() ? L"-" : row.r0AuditDetail; case C::R0Status: return row.r0KernelOnly ? L"仅 R0" : (row.r0AuditSummary.empty() ? L"不可用" : L"已审计"); case C::ProcessType: return row.r0KernelOnly ? L"仅内核" : L"进程"; case C::Status: return L"运行中";
    default: return L"不可用";
    }
}

} // namespace Ksword::Features::Process
