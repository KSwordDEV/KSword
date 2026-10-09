// ============================================================
// WorkbenchTarget.Anchor.cpp
// 作用：
// - 本组件唯一包含 Windows.h 的文件。实现 WorkbenchTarget.h 顶部声明的四个
//   自由函数：AcquireAnchorFromDockHandle / AcquireAnchorForPid /
//   ReleaseAnchorHandle / QueryAnchorAlive。
// - "锚点"指的是 target.md 第 2.4 节描述的身份锚定：复制（或打开）一个仅有
//   PROCESS_QUERY_INFORMATION 权限的降权句柄，在它上面调用 GetProcessTimes
//   （取创建时间，用于识别"同一个进程实例"而不是同 PID 的另一个进程）、
//   IsWow64Process（取地址宽度）、GetExitCodeProcess（退出检测）。
// - 拿不到锚点（例如目标只在内核可见，用户态打不开）不代表目标无效：这里一律
//   返回 identityWeak=true、createTime100ns=0，调用方（WorkbenchTarget）据此
//   把身份标记为"未锚定"，继续把 pid 当成目标，只是不能再靠创建时间识别
//   "pid 是否被系统复用成了另一个进程"。
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "WorkbenchTarget.h"

#include <Windows.h>

namespace ks::ui
{
    namespace
    {
        // FileTimeToUint64：把一个 FILETIME 拼成 100ns 单位的 64 位整数。
        // 传入：fileTime 来自 GetProcessTimes 的创建时间字段。
        // 传出：高 32 位左移 32 位后与低 32 位相或，就是标准的 FILETIME→uint64 转换
        //       （不经过 Framework.h 里 ks::str::FileTimeToUint64，本组件自包含）。
        std::uint64_t FileTimeToUint64(const FILETIME& fileTime) noexcept
        {
            return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32)
                | static_cast<std::uint64_t>(fileTime.dwLowDateTime);
        }

        // QueryAnchorDetails：在一个已经拿到手的降权句柄上查创建时间与地址宽度。
        // 传入：handle 有效的 Win32 进程句柄（至少有 PROCESS_QUERY_INFORMATION 权限）。
        // 传出：AnchorInfo，handle 字段原样填回；GetProcessTimes/IsWow64Process
        //       任一失败都只影响对应字段（创建时间置 0 / 位数回退默认 64），
        //       不影响 handle 本身的有效性判断。identityWeak 仅在 GetProcessTimes
        //       成功且创建时间非零时才为 false——这是"身份已锚定"的唯一判据。
        AnchorInfo QueryAnchorDetails(HANDLE handle) noexcept
        {
            AnchorInfo info;
            info.handle = handle;

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const BOOL timesOk = ::GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime);
            if (timesOk != FALSE)
            {
                const std::uint64_t createTime = FileTimeToUint64(creationTime);
                if (createTime != 0)
                {
                    info.createTime100ns = createTime;
                    info.identityWeak = false;
                }
            }

            BOOL isWow64 = FALSE;
            if (::IsWow64Process(handle, &isWow64) != FALSE && isWow64 != FALSE)
            {
                info.addressBits = 32;
            }
            else
            {
                info.addressBits = 64;
            }

            return info;
        }
    }

    AnchorInfo AcquireAnchorFromDockHandle(void* dockHandle)
    {
        if (dockHandle == nullptr)
        {
            return AnchorInfo{};
        }

        // D3 修复：降权复制改成只要 PROCESS_QUERY_LIMITED_INFORMATION（原来是
        // PROCESS_QUERY_INFORMATION）。审核报告实测：对 audiodg.exe 等受保护
        // 进程，QUERY_INFORMATION 必然被拒绝，但 LIMITED 已经足够支撑本文件
        // 唯一要用到的三个调用——GetProcessTimes/IsWow64Process/GetExitCodeProcess。
        // 注意：DuplicateHandle 并不保证"复制出来的句柄权限不超过源句柄"（那取决于
        // 目标进程的安全描述符，不是源句柄掩码的函数）；这里显式只申请 LIMITED
        // 是遵循最小权限原则，不是依赖一个不存在的权限封顶（D9：旧注释的说法
        // 不成立，审核报告 probe 已经实测反例）。
        HANDLE duplicated = nullptr;
        const BOOL duplicateOk = ::DuplicateHandle(
            ::GetCurrentProcess(),
            static_cast<HANDLE>(dockHandle),
            ::GetCurrentProcess(),
            &duplicated,
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            0);
        if (duplicateOk == FALSE || duplicated == nullptr)
        {
            AnchorInfo info;
            info.lastError = ::GetLastError();
            return info;
        }

        return QueryAnchorDetails(duplicated);
    }

    AnchorInfo AcquireAnchorForPid(std::uint32_t pid)
    {
        if (pid == 0)
        {
            return AnchorInfo{};
        }

        // D3 修复：同上，改用 PROCESS_QUERY_LIMITED_INFORMATION。
        const HANDLE handle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
        if (handle == nullptr)
        {
            // D6 修复：打开失败时把 GetLastError() 原样带回，并单独标记
            // "这个 pid 根本不是任何进程"（ERROR_INVALID_PARAMETER）这一种情形，
            // 供 WorkbenchTarget::requestIdentity 在问离开守卫之前就区分"目标已经
            // 不存在"与"目标存在但打不开"（后者只是权限问题，不等于目标消失）。
            AnchorInfo info;
            info.lastError = ::GetLastError();
            info.targetGone = (info.lastError == ERROR_INVALID_PARAMETER);
            return info;
        }

        return QueryAnchorDetails(handle);
    }

    void ReleaseAnchorHandle(void* handle) noexcept
    {
        if (handle != nullptr)
        {
            ::CloseHandle(static_cast<HANDLE>(handle));
        }
    }

    std::optional<bool> QueryAnchorAlive(void* handle) noexcept
    {
        if (handle == nullptr)
        {
            return std::nullopt;
        }

        DWORD exitCode = 0;
        if (::GetExitCodeProcess(static_cast<HANDLE>(handle), &exitCode) == FALSE)
        {
            return std::nullopt; // 查询本身失败，调用方应保留上一次已知状态。
        }

        if (exitCode != STILL_ACTIVE)
        {
            return false; // 退出码不是 259，确定已退出。
        }

        // D4 修复：退出码恰好等于 STILL_ACTIVE（259）时不能直接当"仍在运行"——
        // 进程本身也可能是以 259 作为真实退出码退出的（例如 `cmd /c exit 259`），
        // GetExitCodeProcess 在 API 层面完全无法区分"哨兵值"与"恰好是 259 的
        // 真实退出码"。唯一的旁证是 GetProcessTimes 的退出时间字段：仍在运行的
        // 进程该字段恒为全零 FILETIME，已退出的进程（哪怕退出码凑巧是 259）该
        // 字段必然非零。
        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(static_cast<HANDLE>(handle), &creationTime, &exitTime, &kernelTime, &userTime)
            == FALSE)
        {
            return true; // 查不到退出时间时保守按"仍在运行"处理（与旧行为一致）。
        }
        return FileTimeToUint64(exitTime) == 0;
    }
}
