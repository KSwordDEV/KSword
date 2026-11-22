// CLI 来宾夹具：创建两个自有 x64 线程，分别执行已知内核等待和有界用户态忙循环。
// 调用：LiveKernelDiagnosticVmTarget.exe，运行脚本可指定唯一的就绪文件和停止文件。
// 参数：<ready.json> <stop-file> <lifetime-ms> [--lifecycle|--exit-with-pending]。身份均来自公开 Win32 API。
// 生命周期模式另建从未运行的自有挂起线程，仅验证真实排队超时，不修改任何既有目标线程。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <initializer_list>

namespace
{
    // 验收期间临时阻止系统空闲睡眠；只作用于本主线程，退出时归还，不更改电源计划或屏幕状态。
    struct ExecutionStateLease
    {
        EXECUTION_STATE previous = SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED); // 记录公开 API 是否接受本次短租约。
        ~ExecutionStateLease()
        {
            if (previous != 0)
            {
                SetThreadExecutionState(previous); // 所有正常与失败出口均恢复原线程的执行要求。
            }
        }
    };

    // 共享状态只属于本夹具；就绪事件区分真正到达工作函数和仅已创建。
    struct State
    {
        HANDLE release = nullptr;   // 控制两工作线程退出的手动重置事件。
        HANDLE waitReady = nullptr; // 等待线程即将进入固定 Win32 等待点。
        HANDLE busyReady = nullptr; // 忙线程即将进入可判定的 CPU 循环。
        std::atomic<bool> stopBusy{false}; // 忙循环不反复进入内核等待。
        std::atomic<std::uint64_t> sink{0}; // 保存计算结果，避免编译器删除负载。
    };

    // 将公开 API 回执的 FILETIME 转成 CLI 需要的无符号十进制值。
    std::uint64_t Pack(const FILETIME& time)
    {
        return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32U) | time.dwLowDateTime;
    }

    // 等待线程入口：向控件报告到达后，只阻塞在本夹具自己的事件上。
    DWORD WINAPI WaitWorker(void* argument)
    {
        auto& state = *static_cast<State*>(argument); // 由 wmain 持有直到 join。
        if (!SetEvent(state.waitReady))
        {
            return 1;
        }
        const auto result = WaitForSingleObject(state.release, INFINITE); // 预期在采样时仍阻塞。
        return result == WAIT_OBJECT_0 ? 0 : 2;
    }

    // 忙线程入口：仅做整数运算，且外部控制线程可无强制结束地停止它。
    DWORD WINAPI BusyWorker(void* argument)
    {
        auto& state = *static_cast<State*>(argument); // 由 wmain 持有直到 join。
        if (!SetEvent(state.busyReady))
        {
            return 1;
        }
        std::uint64_t value = 1; // 无符号算术允许自然回绕。
        while (!state.stopBusy.load(std::memory_order_relaxed))
        {
            for (unsigned step = 0; step != 16384; ++step)
            {
                value = value * 6364136223846793005ULL + 1ULL;
            }
            state.sink.store(value, std::memory_order_relaxed);
        }
        return 0;
    }

    // 获取保持打开的原始线程对象创建时间和累计执行时间（100ns）。
    bool ReadThread(HANDLE thread, std::uint64_t& creation, std::uint64_t& cpu)
    {
        FILETIME created{}, exited{}, kernel{}, user{}; // GetThreadTimes 的四项公开结果。
        if (!GetThreadTimes(thread, &created, &exited, &kernel, &user))
        {
            return false;
        }
        creation = Pack(created);
        cpu = Pack(kernel) + Pack(user);
        return creation != 0;
    }
}

// 主进程：准备 → 独立取样验证 → 发布身份 → 等待本轮专用停止文件或超时 → 回收。
int wmain(const int argc, wchar_t** argv)
{
    if (argc != 4 && (argc != 5 || (std::wcscmp(argv[4], L"--lifecycle") != 0 &&
        std::wcscmp(argv[4], L"--exit-with-pending") != 0)))
    {
        return 64;
    }
    const wchar_t* readyPath = argv[1]; // 调用脚本提供的本轮专用新文件。
    const wchar_t* stopPath = argv[2];  // 调用脚本只在验收完成后创建。
    const bool lifecycle = argc == 5; // 不改变原两线程验收默认行为。
    const bool exitWithPending = argc == 5 && std::wcscmp(argv[4], L"--exit-with-pending") == 0; // 仅独立退出夹具选择正常进程退出语义。
    wchar_t* end = nullptr;           // 停止时间参数必须完整解析。
    const auto lifetime = std::wcstoul(argv[3], &end, 10); // 支持 5–180 秒。
    if (end == argv[3] || *end || lifetime < 5000 || lifetime > 180000 ||
        GetFileAttributesW(readyPath) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(stopPath) != INVALID_FILE_ATTRIBUTES)
    {
        return 64;
    }

    const ExecutionStateLease awake; // 双 VM 已实测空闲睡眠会中断 CLI 取证；不修改来宾的持久策略。
    if (awake.previous == 0)
    {
        return 66;
    }
    State state; // 所有线程句柄关闭前保持有效。
    state.release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    state.waitReady = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    state.busyReady = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD waitId = 0; // 只使用 CreateThread 返回的线程号。
    DWORD busyId = 0;
    DWORD dormantId = 0; // 可选从未运行线程的公开数值身份。
    HANDLE waiter = nullptr; // 分配失败仍进入统一回收。
    HANDLE busy = nullptr;
    HANDLE dormant = nullptr; // 仅本夹具创建时使用 CREATE_SUSPENDED，退出前正常恢复并 join。
    int status = 65;          // 只有证实两个线程种类并发布身份后才成功退出。
    if (state.release && state.waitReady && state.busyReady)
    {
        waiter = CreateThread(nullptr, 0, WaitWorker, &state, 0, &waitId);
        busy = CreateThread(nullptr, 0, BusyWorker, &state, 0, &busyId);
        if (lifecycle)
        {
            dormant = CreateThread(nullptr, 0, WaitWorker, &state, CREATE_SUSPENDED, &dormantId);
        }
    }

    if (waiter && busy && (!lifecycle || dormant))
    {
        const HANDLE ready[] = {state.waitReady, state.busyReady}; // 两线程都进工作函数。
        if (WaitForMultipleObjects(2, ready, TRUE, 3000) == WAIT_OBJECT_0)
        {
            FILETIME created{}, exited{}, kernel{}, user{}; // 当前进程准确身份。
            std::uint64_t waitCreated = 0, busyCreated = 0, waitBefore = 0, busyBefore = 0;
            std::uint64_t waitAfter = 0, busyAfter = 0; // 活性控制读数，单位 100ns。
            std::uint64_t dormantCreated = 0, dormantCpu = 0; // 未运行线程仍具有公开创建身份。
            if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) &&
                ReadThread(waiter, waitCreated, waitBefore) && ReadThread(busy, busyCreated, busyBefore) &&
                (!lifecycle || ReadThread(dormant, dormantCreated, dormantCpu)))
            {
                Sleep(300); // 让等待进入稳定状态，并证明另一个线程确在消耗 CPU。
                if (ReadThread(waiter, waitCreated, waitAfter) && ReadThread(busy, busyCreated, busyAfter) &&
                    waitAfter == waitBefore && busyAfter > busyBefore)
                {
                    FILE* receipt = nullptr; // 只新建本次身份文件；不会覆盖既有证据。
                    if (_wfopen_s(&receipt, readyPath, L"wbx") == 0)
                    {
                        auto wrote = std::fprintf(receipt,
                            "{\"systemRequiredHeld\":true,\"pid\":%lu,\"processCreationTime\":\"%llu\","
                            "\"wait\":{\"tid\":%lu,\"creationTime\":\"%llu\",\"cpuDelta100ns\":%llu},"
                            "\"busy\":{\"tid\":%lu,\"creationTime\":\"%llu\",\"cpuDelta100ns\":%llu}",
                            GetCurrentProcessId(), static_cast<unsigned long long>(Pack(created)),
                            waitId, static_cast<unsigned long long>(waitCreated),
                            static_cast<unsigned long long>(waitAfter - waitBefore),
                            busyId, static_cast<unsigned long long>(busyCreated),
                            static_cast<unsigned long long>(busyAfter - busyBefore));
                        if (lifecycle && wrote > 0)
                        {
                            wrote = std::fprintf(receipt,
                                ",\"dormant\":{\"tid\":%lu,\"creationTime\":\"%llu\",\"initiallySuspended\":true,\"cpu100ns\":%llu}",
                                dormantId, static_cast<unsigned long long>(dormantCreated),
                                static_cast<unsigned long long>(dormantCpu));
                        }
                        if (wrote > 0)
                        {
                            wrote = std::fprintf(receipt, "}\n"); // 完整关闭 JSON 后才发布文件成功。
                        }
                        const auto closed = std::fclose(receipt); // 关闭后才把完整证据视为已发布。
                        if (wrote > 0 && closed == 0)
                        {
                            status = 0;
                            const auto deadline = GetTickCount64() + lifetime; // 未发送停止文件也有界退出。
                            while (GetTickCount64() < deadline && GetFileAttributesW(stopPath) == INVALID_FILE_ATTRIBUTES)
                            {
                                Sleep(30);
                            }
                            if (exitWithPending)
                            {
                                // 本进程主动正常退出，让系统退休仍挂在自有未运行线程上的 APC；不调用 TerminateThread 或修改外部目标。
                                ExitProcess(0);
                            }
                        }
                    }
                }
            }
        }
    }

    // 只回收本进程所属线程；不挂起、不篡改、不终止其他进程。
    state.stopBusy.store(true, std::memory_order_relaxed);
    if (state.release)
    {
        SetEvent(state.release);
    }
    if (dormant && ResumeThread(dormant) == static_cast<DWORD>(-1))
    {
        status = 67; // 不把恢复失败说成已验证取消后的正常退出。
    }
    for (const auto worker : {waiter, busy, dormant})
    {
        if (worker)
        {
            WaitForSingleObject(worker, INFINITE);
            CloseHandle(worker);
        }
    }
    for (const auto event : {state.release, state.waitReady, state.busyReady})
    {
        if (event)
        {
            CloseHandle(event);
        }
    }
    return status;
}
