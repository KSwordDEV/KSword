#pragma once

#include "../../Core/Win32Lean.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace Ksword::Features::Process {

// ProcessSnapshotRow is the raw R3 process record produced from
// NtQuerySystemInformation(SystemProcessInformation). Inputs are kernel-returned
// SYSTEM_PROCESS_INFORMATION fields plus optional Win32 image-path enrichment;
// consumers should treat each row as a point-in-time snapshot.
struct ProcessSnapshotRow {
    DWORD processId = 0;
    DWORD parentProcessId = 0;
    ULONG handleCount = 0;
    ULONG sessionId = 0;
    ULONG threadCount = 0;
    LONG basePriority = 0;
    ULONGLONG kernelTime100ns = 0;
    ULONGLONG userTime100ns = 0;
    ULONGLONG cycleTime = 0;
    // creationTime100ns distinguishes a recycled PID from the snapshot process instance.
    ULONGLONG creationTime100ns = 0;
    SIZE_T workingSetBytes = 0;
    // peakWorkingSetBytes 用途：NtQuery 快照中的峰值工作集，供“内存”列显示。
    SIZE_T peakWorkingSetBytes = 0;
    SIZE_T privatePageBytes = 0;
    SIZE_T virtualSizeBytes = 0;
    // commitBytes/pagedPoolBytes/nonPagedPoolBytes 用途：SystemProcessInformation 原始内存统计。
    SIZE_T commitBytes = 0;
    SIZE_T pagedPoolBytes = 0;
    SIZE_T nonPagedPoolBytes = 0;
    ULONG pageFaultCount = 0;
    // workingSetDeltaBytes/pageFaultDelta 用途：由相邻快照计算的动态内存增量。
    LONGLONG workingSetDeltaBytes = 0;
    LONGLONG pageFaultDelta = 0;
    // I/O 计数与传输量来自 SystemProcessInformation，避免逐进程句柄查询。
    ULONGLONG ioReadOperations = 0;
    ULONGLONG ioWriteOperations = 0;
    ULONGLONG ioOtherOperations = 0;
    ULONGLONG ioReadBytes = 0;
    ULONGLONG ioWriteBytes = 0;
    ULONGLONG ioOtherBytes = 0;
    double cpuUsagePercent = 0.0;
    std::wstring imageName;
    std::wstring imagePath;
    std::uintptr_t r0ProcessObjectAddress = 0;
    ULONG r0SourceMask = 0;
    ULONG r0AnomalyFlags = 0;
    ULONG r0Confidence = 0;
    // r0KernelOnly 用途：标记该行只由 R0 枚举返回，R3 公开列表不可见。
    bool r0KernelOnly = false;
    // r0EnumFlags/r0EnumStatus 用途：保存 R0 进程枚举协议中的 flags/status，供隐藏进程诊断和高亮使用。
    std::uint32_t r0EnumFlags = 0;
    std::uint32_t r0EnumStatus = 0;
    // r0EnumImagePath 用途：保存 R0 读取到的映像路径，R3 无路径或合成隐藏行时作为诊断证据。
    std::wstring r0EnumImagePath;
    std::wstring r0AuditSummary;
    std::wstring r0AuditDetail;
    // detailTexts 用途：保存主程序进程库按需采集到的扩展列文本，键为 ProcessColumnId 的整数值。
    std::unordered_map<std::uint8_t, std::wstring> detailTexts;
};

// ProcessEnumerationResult groups all rows from one enumeration pass. success is
// false only for fatal NtApi failures; partial per-process enrichment failures
// leave individual imagePath fields empty and keep success true.
struct ProcessEnumerationResult {
    bool success = false;
    LONG ntStatus = 0;
    std::wstring diagnosticText;
    std::vector<ProcessSnapshotRow> rows;
};

// EnumerateProcessesByNtQuerySystemInformation queries the system process list
// using dynamically-bound NtQuerySystemInformation. Inputs: none. Processing:
// grow a raw buffer, parse SYSTEM_PROCESS_INFORMATION entries, and enrich image
// paths through QueryFullProcessImageNameW when permissions allow. Return value:
// a ProcessEnumerationResult containing rows or a fatal diagnostic.
ProcessEnumerationResult EnumerateProcessesByNtQuerySystemInformation();

// QueryProcessImagePath opens one process with PROCESS_QUERY_LIMITED_INFORMATION
// and queries its full executable path. Input is a PID. Processing is best-effort
// and never terminates or modifies the target process. Return value is an empty
// string when access is denied, PID is invalid, or the image path is unavailable.
std::wstring QueryProcessImagePath(DWORD processId);

} // namespace Ksword::Features::Process
