#include "MemoryDebugProcessCatalog.h"

// 此轻量系统查询模块保持 Qt/Framework 无关，方便直接测试真实身份与权限查询。
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <utility>

namespace ks::ui
{
    namespace
    {
        // CreationTime：从已打开的同一进程对象读取身份；失败返回 0，绝不猜测。
        std::uint64_t CreationTime(HANDLE process)
        {
            FILETIME created{}; // 创建时间是本次查询的唯一输出。
            FILETIME exited{};  // GetProcessTimes 要求提供的退出时间。
            FILETIME kernel{};  // GetProcessTimes 要求提供的内核时间。
            FILETIME user{};    // GetProcessTimes 要求提供的用户时间。
            if (!::GetProcessTimes(process, &created, &exited, &kernel, &user))
            {
                return 0;
            }
            return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32)
                | created.dwLowDateTime;
        }
    }

    MemoryDebugProcessCatalog EnumerateMemoryDebugProcesses()
    {
        MemoryDebugProcessCatalog result; // 整轮枚举只返回值，不把句柄跨线程交给 UI。
        const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            result.error = ::GetLastError();
            return result;
        }

        // 每个候选只申请查询权限；受保护目标仍显示，但不会成为未经核验的内存会话。
        PROCESSENTRY32W entry{}; // Toolhelp 当前行缓冲区。
        entry.dwSize = sizeof(entry);
        BOOL available = ::Process32FirstW(snapshot, &entry);
        while (available)
        {
            if (entry.th32ProcessID != 0)
            {
                MemoryDebugProcessCandidate candidate; // 不持有进程句柄的独立行快照。
                candidate.pid = entry.th32ProcessID;
                candidate.name = entry.szExeFile;
                const HANDLE process = ::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, FALSE, candidate.pid);
                if (process != nullptr)
                {
                    candidate.createTime100ns = CreationTime(process);
                    // 名称也从同一对象读取：Toolhelp 快照后 PID 被复用时不能把旧名称套到新身份。
                    std::vector<wchar_t> image(32768); // Win32 完整映像路径的有界缓冲区。
                    DWORD characters = static_cast<DWORD>(image.size()); // API 输入容量/输出长度。
                    if (::QueryFullProcessImageNameW(process, 0, image.data(), &characters))
                    {
                        const std::wstring path(image.data(), characters); // 持有对象的真实映像路径。
                        const auto separator = path.find_last_of(L"\\/"); // 只展示文件名，不引入查盘操作。
                        candidate.name = path.substr(separator == std::wstring::npos ? 0 : separator + 1);
                    }
                    else
                    {
                        // 仅有快照名称却无法核验同对象名称时保留行，禁止创建强身份会话。
                        candidate.createTime100ns = 0;
                    }
                    ::CloseHandle(process);
                }
                result.processes.push_back(std::move(candidate));
            }
            available = ::Process32NextW(snapshot, &entry);
        }
        const DWORD error = ::GetLastError(); // 正常穷尽必须是 ERROR_NO_MORE_FILES。
        ::CloseHandle(snapshot);
        if (error != ERROR_NO_MORE_FILES)
        {
            result.error = error;
            result.processes.clear();
        }
        return result;
    }

    bool CanWriteMemoryDebugProcess(const std::uint32_t pid, const std::uint64_t createTime100ns)
    {
        if (pid == 0 || createTime100ns == 0)
        {
            return false;
        }
        // 权限检查与创建时间复核使用同一对象句柄，PID 被复用时不会显示新进程的能力。
        const HANDLE process = ::OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (process == nullptr)
        {
            return false;
        }
        const bool sameInstance = CreationTime(process) == createTime100ns;
        ::CloseHandle(process);
        return sameInstance;
    }
}
