#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ks::ui
{
    // MemoryDebugProcessCandidate：选择器的一行；创建时间与 PID 一起识别进程实例。
    struct MemoryDebugProcessCandidate
    {
        std::uint32_t pid = 0;                 // 系统进程号。
        std::uint64_t createTime100ns = 0;      // 0 表示无法核验身份，不允许建立会话。
        std::wstring name;                     // 快照中的进程文件名。
    };

    // MemoryDebugProcessCatalog：轻量枚举结果，不带句柄或任何进程控制权限。
    struct MemoryDebugProcessCatalog
    {
        std::vector<MemoryDebugProcessCandidate> processes; // 供 UI 排序和筛选的值快照。
        std::uint32_t error = 0;                            // 枚举失败的 Win32 错误。
    };

    // EnumerateMemoryDebugProcesses：在工作线程枚举名称/PID/创建时间，不采样性能或签名。
    // 无入参；返回不拥有目标句柄的快照，调用方选择时仍须核验创建时间。
    MemoryDebugProcessCatalog EnumerateMemoryDebugProcesses();

    // CanWriteMemoryDebugProcess：用真实访问权限和创建时间查询写能力，仅用于展示。
    // 传入已选进程身份；返回能否打开同一实例的内存读写句柄，实际写入仍由工作台事务验证。
    bool CanWriteMemoryDebugProcess(std::uint32_t pid, std::uint64_t createTime100ns);
}
