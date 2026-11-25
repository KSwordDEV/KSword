// 固定两个自有工作线程，验证先统一停止、单线程步进、重设 NX 后再恢复的次序。
// 控制器位于同进程，但不执行被测代码；本夹具不证明任意进程的线程冻结完整性。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <cstdio>

namespace
{
    constexpr DWORD waitMs = 5000;
    constexpr DWORD trapFlag = 0x100;

    struct Worker
    {
        HANDLE thread = nullptr;
        DWORD tid = 0;
        HANDLE ready = nullptr;
        HANDLE start = nullptr;
        HANDLE fault = nullptr;
        HANDLE grant = nullptr;
        HANDLE rearmed = nullptr;
        HANDLE finish = nullptr;
        bool held = false; // 控制器只归还本次成功增加的一次挂起计数。
        bool verifiedHeld = false; // GetThreadContext 完成后才把挂起纳入放行屏障。
        volatile LONG stepping = 0;
        volatile LONG faults = 0;
        volatile LONG steps = 0;
        volatile LONG completed = 0;
    };

    Worker workers[2];
    std::uintptr_t page = 0;
    SIZE_T pageBytes = 0;
    DWORD originalProtection = 0;
    bool changedProtection = false;
    void* observer = nullptr;
    volatile LONG effects = 0;
    volatile LONG failure = 0;
    volatile LONG aborting = 0;

    // 普通编译函数，独占一个映像节；原始代码及数据均不在运行中改写。
    __declspec(noinline) __declspec(code_seg(".ksstop"))
    void RunImageInstruction()
    {
        InterlockedIncrement(&effects);
    }

    bool InPage(std::uintptr_t address)
    {
        return address >= page && address - page < pageBytes;
    }

    bool Protect(DWORD protection)
    {
        DWORD previous = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(page), pageBytes, protection, &previous))
        {
            InterlockedExchange(&failure, 1);
            return false;
        }
        return true;
    }

    // 只处理自有代码页的 NX 和自己发起的 TF；其它异常继续原有分发。
    LONG CALLBACK Observe(EXCEPTION_POINTERS* exception)
    {
        if (!exception || !exception->ExceptionRecord || !exception->ContextRecord)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        Worker* worker = nullptr;
        const DWORD tid = GetCurrentThreadId();
        for (auto& candidate : workers)
        {
            if (candidate.tid == tid)
            {
                worker = &candidate;
                break;
            }
        }
        if (!worker)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        const auto* record = exception->ExceptionRecord;
        auto* context = exception->ContextRecord;
        if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION
            && record->NumberParameters >= 2 && record->ExceptionInformation[0] == 8
            && InPage(record->ExceptionInformation[1]))
        {
            InterlockedIncrement(&worker->faults);
            SetEvent(worker->fault);
            if (WaitForSingleObject(worker->grant, waitMs) != WAIT_OBJECT_0)
            {
                InterlockedExchange(&failure, 1);
            }
            if (!aborting && !failure)
            {
                InterlockedExchange(&worker->stepping, 1);
                context->EFlags |= trapFlag;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (record->ExceptionCode != EXCEPTION_SINGLE_STEP || !worker->stepping)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        const LONG steps = InterlockedIncrement(&worker->steps);
        if (!aborting && !failure && InPage(context->Rip) && steps < 128)
        {
            context->EFlags |= trapFlag;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (steps >= 128)
        {
            InterlockedExchange(&failure, 1);
        }
        context->EFlags &= ~trapFlag;
        InterlockedExchange(&worker->stepping, 0);
        if (!aborting && !failure)
        {
            // 当前 RIP 已在页外，其它工作线程仍由控制器持有，先恢复 NX 再发回执。
            if (!Protect(PAGE_READONLY))
            {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            SetEvent(worker->rearmed);
            if (WaitForSingleObject(worker->finish, waitMs) != WAIT_OBJECT_0)
            {
                InterlockedExchange(&failure, 1);
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    DWORD WINAPI WorkerMain(void* context)
    {
        auto* worker = static_cast<Worker*>(context);
        SetEvent(worker->ready);
        if (WaitForSingleObject(worker->start, waitMs) != WAIT_OBJECT_0)
        {
            InterlockedExchange(&failure, 1);
            return 2;
        }
        if (!aborting)
        {
            RunImageInstruction();
            InterlockedIncrement(&worker->completed);
        }
        return 0;
    }

    bool Hold(Worker& worker)
    {
        if (worker.held)
        {
            return worker.verifiedHeld;
        }
        const DWORD previous = SuspendThread(worker.thread);
        if (previous != static_cast<DWORD>(-1))
        {
            worker.held = true;
        }
        if (previous != 0)
        {
            return false;
        }
        CONTEXT stopped{};
        stopped.ContextFlags = CONTEXT_CONTROL;
        worker.verifiedHeld = GetThreadContext(worker.thread, &stopped) != FALSE;
        return worker.verifiedHeld;
    }

    bool Release(Worker& worker)
    {
        if (!worker.held)
        {
            return false;
        }
        const DWORD previous = ResumeThread(worker.thread);
        if (previous != static_cast<DWORD>(-1))
        {
            worker.held = false;
            worker.verifiedHeld = false;
        }
        return previous == 1;
    }

    // 失败出口也先恢复权限，再发出自己的事件并归还自己的挂起计数。
    struct Cleanup
    {
        ~Cleanup()
        {
            InterlockedExchange(&aborting, 1);
            if (changedProtection && !Protect(originalProtection))
            {
                ExitProcess(3);
            }
            for (auto& worker : workers)
            {
                if (worker.start) SetEvent(worker.start);
                if (worker.grant) SetEvent(worker.grant);
                if (worker.finish) SetEvent(worker.finish);
                if (worker.held && !Release(worker)) ExitProcess(3);
            }
            for (auto& worker : workers)
            {
                if (worker.thread && WaitForSingleObject(worker.thread, waitMs) != WAIT_OBJECT_0)
                {
                    ExitProcess(3);
                }
            }
            if (observer) RemoveVectoredExceptionHandler(observer);
            for (auto& worker : workers)
            {
                const HANDLE handles[] = {worker.thread, worker.ready, worker.start,
                    worker.fault, worker.grant, worker.rearmed, worker.finish};
                for (HANDLE handle : handles)
                {
                    if (handle) CloseHandle(handle);
                }
            }
        }
    };

    bool Wait(HANDLE event)
    {
        return WaitForSingleObject(event, waitMs) == WAIT_OBJECT_0;
    }

    int Check(const char* name, bool success)
    {
        std::printf("STW_%s %s\n", success ? "PASS" : "FAIL", name);
        return success ? 0 : 1;
    }
}

// 返回失败项数；只调用一次，不向产品注册会话或改变系统配置。
int RunStopWorldExecutionProbe()
{
    Cleanup cleanup;
    SYSTEM_INFO info{};
    MEMORY_BASIC_INFORMATION memory{};
    GetSystemInfo(&info);
    pageBytes = info.dwPageSize;
    page = reinterpret_cast<std::uintptr_t>(&RunImageInstruction)
        & ~(static_cast<std::uintptr_t>(pageBytes) - 1);
    if (VirtualQuery(reinterpret_cast<void*>(page), &memory, sizeof(memory)) != sizeof(memory)
        || memory.Type != MEM_IMAGE || memory.Protect != PAGE_EXECUTE_READ
        || InPage(reinterpret_cast<std::uintptr_t>(&Observe))
        || InPage(reinterpret_cast<std::uintptr_t>(&WorkerMain)))
    {
        return 1;
    }
    originalProtection = memory.Protect;
    for (auto& worker : workers)
    {
        worker.ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        worker.start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        worker.fault = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        worker.grant = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        worker.rearmed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        worker.finish = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!worker.ready || !worker.start || !worker.fault || !worker.grant
            || !worker.rearmed || !worker.finish)
        {
            return 1;
        }
        worker.thread = CreateThread(nullptr, 0, WorkerMain, &worker, 0, &worker.tid);
        if (!worker.thread || !Wait(worker.ready)) return 1;
    }
    observer = AddVectoredExceptionHandler(1, Observe);
    if (!observer || !Protect(PAGE_READONLY)) return 1;
    changedProtection = true;
    int failures = 0;
    SetEvent(workers[0].start);
    if (!Wait(workers[0].fault) || !Hold(workers[0]) || !Hold(workers[1])) return 1;
    SetEvent(workers[1].start); // 第二线程已具备执行条件，但仍有真实挂起计数。
    failures += Check("all_owned_workers_held_before_rx", effects == 0 && workers[0].verifiedHeld
        && workers[1].verifiedHeld && workers[0].faults == 1 && workers[1].faults == 0);
    if (!Protect(PAGE_EXECUTE_READ)) return failures + 1;
    SetEvent(workers[0].grant);
    if (!Release(workers[0]) || !Wait(workers[0].rearmed)) return failures + 1;
    failures += Check("selected_worker_steps_and_rearms_before_other_release",
        effects == 1 && workers[0].steps > 0 && workers[1].verifiedHeld && workers[1].faults == 0);
    if (!Hold(workers[0])) return failures + 1;
    if (!Release(workers[1]) || !Wait(workers[1].fault)) return failures + 1;
    failures += Check("second_worker_still_faults_after_first_was_allowed",
        effects == 1 && workers[1].faults == 1 && workers[0].verifiedHeld);
    if (!Hold(workers[1]) || !Protect(PAGE_EXECUTE_READ)) return failures + 1;
    SetEvent(workers[1].grant);
    if (!Release(workers[1]) || !Wait(workers[1].rearmed) || !Hold(workers[1]))
    {
        return failures + 1;
    }
    failures += Check("two_independent_faults_two_completed_image_effects",
        effects == 2 && workers[0].faults == 1 && workers[1].faults == 1
        && workers[0].steps > 0 && workers[1].steps > 0 && failure == 0);
    SetEvent(workers[0].finish);
    SetEvent(workers[1].finish);
    if (!Release(workers[0]) || !Release(workers[1]) || !Wait(workers[0].thread)
        || !Wait(workers[1].thread)) return failures + 1;
    failures += Check("both_workers_exit_with_own_suspend_counts_released",
        workers[0].completed == 1 && workers[1].completed == 1 && failure == 0
        && !workers[0].held && !workers[1].held);
    std::printf("STW_EVIDENCE tids=%lu,%lu faults=%ld,%ld steps=%ld,%ld effects=%ld failure=%ld\n",
        workers[0].tid, workers[1].tid, workers[0].faults, workers[1].faults,
        workers[0].steps, workers[1].steps, effects, failure);
    std::printf("STW_RESULT=%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures;
}
