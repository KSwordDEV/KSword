// 用途：在自有进程内验证原有线程池线程的映像代码执行告警，不注入、不加载驱动。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <cstdio>

int RunStopWorldExecutionProbe();

namespace
{
    // 本次运行状态：真值由业务回调记录，异常计数由独立 VEH 记录。
    struct ProbeState
    {
        LONG phase = 0;                    // 当前任务阶段，零表示只预热工作线程。
        volatile LONG executions = 0;      // 被测函数确实执行的次数。
        DWORD warmThread = 0;              // 设防前已经存在的工作线程身份。
        DWORD currentThread = 0;           // 最近一次回调的实际工作线程身份。
    };

    std::uintptr_t watchedPage = 0;         // 本进程被测代码页的对齐地址。
    SIZE_T watchedBytes = 0;                // 系统页大小，也是本次设防范围。
    volatile LONG guardCount = 0;          // VEH 实际接收到的页面告警数。
    volatile LONG executeCount = 0;        // 告警标明执行访问的次数。
    volatile LONG readCount = 0;           // 告警标明读取访问的次数。
    volatile LONG faultThread = 0;         // 最近一次告警发生的真实线程 ID。
    volatile LONG nxFaultCount = 0;        // 自有 NX 实验实际收到的执行异常数。
    volatile LONG nxFailure = 0;           // NX 实验的保护恢复或等待失败标记。
    HANDLE nxEntered = nullptr;            // 首线程已在恢复执行权限后等待的通知。
    HANDLE nxRelease = nullptr;            // 控制器允许首线程离开异常处理器的事件。

    // 处理本测试页的告警；输入为 Windows 异常记录，输出为继续执行或交给其它处理器。
    // 不在异常路径打印、分配或重新设防，明确保留一次告警之后的无监视窗口。
    LONG CALLBACK ObserveGuard(EXCEPTION_POINTERS* exception)
    {
        if (!exception || !exception->ExceptionRecord)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        const auto* record = exception->ExceptionRecord; // 本次异常的访问类型与地址。
        if (record->NumberParameters < 2)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        const auto address = record->ExceptionInformation[1]; // 实际触碰的虚拟地址。
        if (address < watchedPage || address - watchedPage >= watchedBytes)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        // NX 对照只处理本测试页的执行异常，恢复权限后有界等待，模拟首命中保持。
        if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION
            && record->ExceptionInformation[0] == 8 && nxEntered && nxRelease)
        {
            DWORD previous = 0; // 本次恢复前的 NX 保护，仅供 API 输出使用。
            InterlockedIncrement(&nxFaultCount);
            if (!VirtualProtect(reinterpret_cast<void*>(watchedPage), watchedBytes,
                PAGE_EXECUTE_READ, &previous))
            {
                InterlockedExchange(&nxFailure, 1);
                return EXCEPTION_CONTINUE_SEARCH;
            }
            if (!SetEvent(nxEntered)
                || WaitForSingleObject(nxRelease, 5000) != WAIT_OBJECT_0)
            {
                InterlockedExchange(&nxFailure, 1);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (record->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        InterlockedIncrement(&guardCount);
        InterlockedExchange(&faultThread, static_cast<LONG>(GetCurrentThreadId()));
        if (record->ExceptionInformation[0] == 8)
        {
            InterlockedIncrement(&executeCount);
        }
        if (record->ExceptionInformation[0] == 0)
        {
            InterlockedIncrement(&readCount);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // 被测业务函数放在独立映像节，避免保护到测试控制器或异常处理器。
    // 输入为本次状态，输出为真值计数加一；本函数不包含 shellcode 或外部调用。
    __declspec(noinline) __declspec(code_seg(".ksprobe"))
    void ExecuteImageProbe(ProbeState* state)
    {
        InterlockedIncrement(&state->executions);
    }

    // 合法线程池回调：预热阶段仅登记 TID，后续阶段调用自带的映像代码。
    // context 指向调用者持有的 ProbeState；工作等待结束之前不会释放它。
    void CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE, void* context, PTP_WORK)
    {
        auto* state = static_cast<ProbeState*>(context); // 仅属于本次自有工作项。
        state->currentThread = GetCurrentThreadId();
        if (state->phase == 0)
        {
            state->warmThread = state->currentThread;
            return;
        }
        ExecuteImageProbe(state);
    }

    // 原生资源所有者：退出时先排空工作项，再恢复页保护并移除自己的 VEH。
    struct Resources
    {
        PTP_POOL pool = nullptr;             // 本测试的专用线程池。
        PTP_WORK work = nullptr;             // 合法创建的线程池工作项。
        void* handler = nullptr;             // 本测试登记的异常观察器。
        DWORD originalProtection = 0;        // 设防前的真实代码页保护。
        bool protectionChanged = false;      // 是否承担恢复本页保护的责任。

        ~Resources()
        {
            // 异常实验失败出口也必须释放首线程，随后才能排空线程池工作。
            if (nxRelease)
            {
                SetEvent(nxRelease);
            }
            if (work)
            {
                WaitForThreadpoolWorkCallbacks(work, TRUE);
                CloseThreadpoolWork(work);
            }
            if (protectionChanged)
            {
                DWORD discarded = 0; // 恢复时返回的旧保护，不再作为新状态使用。
                if (!VirtualProtect(reinterpret_cast<void*>(watchedPage), watchedBytes,
                    originalProtection, &discarded))
                {
                    std::fprintf(stderr, "CLEANUP_FAILURE win32=%lu\n", GetLastError());
                    ExitProcess(3);
                }
            }
            if (handler)
            {
                RemoveVectoredExceptionHandler(handler);
            }
            if (pool)
            {
                CloseThreadpool(pool);
            }
            if (nxEntered)
            {
                CloseHandle(nxEntered);
                nxEntered = nullptr;
            }
            if (nxRelease)
            {
                CloseHandle(nxRelease);
                nxRelease = nullptr;
            }
        }
    };

    // 提交一次任务并等待其完成；输入工作项和共享状态，返回是否仍为预热线程。
    bool RunWork(Resources& resources, ProbeState& state, LONG phase)
    {
        state.phase = phase;
        SubmitThreadpoolWork(resources.work);
        WaitForThreadpoolWorkCallbacks(resources.work, FALSE);
        return state.currentThread == state.warmThread;
    }

    // 给自有映像页加一次告警，保留首次保护以便退出恢复；失败返回 false。
    bool ArmGuard(Resources& resources)
    {
        DWORD previous = 0; // 此次调用之前的保护值，首次用于恢复。
        if (!VirtualProtect(reinterpret_cast<void*>(watchedPage), watchedBytes,
            PAGE_EXECUTE_READ | PAGE_GUARD, &previous))
        {
            return false;
        }
        if (!resources.protectionChanged)
        {
            resources.originalProtection = previous;
            resources.protectionChanged = true;
        }
        return true;
    }

    // 检查一项证据并打印稳定结果；输入断言名和实际条件，返回失败计数。
    int Check(const char* name, bool success)
    {
        std::printf("%s %s\n", success ? "PASS" : "FAIL", name);
        return success ? 0 : 1;
    }
}

// 控制台入口：仅操作自己的映像与合法工作项，返回零表示全部预期成立。
int main()
{
    Resources resources;                     // 覆盖所有成功及失败出口的资源清理。
    ProbeState state;                        // 业务执行真值及预热线程身份。
    SYSTEM_INFO systemInfo{};                // 本机真实页大小。
    MEMORY_BASIC_INFORMATION memoryInfo{};   // 被测函数的映像类型与保护信息。
    TP_CALLBACK_ENVIRON environment;         // 将工作项绑定专用线程池的参数。
    int failures = 0;                        // 与预期不符的证据项总数。
    GetSystemInfo(&systemInfo);
    watchedBytes = systemInfo.dwPageSize;
    watchedPage = reinterpret_cast<std::uintptr_t>(&ExecuteImageProbe)
        & ~(static_cast<std::uintptr_t>(watchedBytes) - 1);
    if (VirtualQuery(reinterpret_cast<void*>(watchedPage), &memoryInfo,
        sizeof(memoryInfo)) != sizeof(memoryInfo))
    {
        return 2;
    }
    failures += Check("source_is_existing_mem_image", memoryInfo.Type == MEM_IMAGE);
    failures += Check("source_is_read_execute", memoryInfo.Protect == PAGE_EXECUTE_READ);
    failures += Check("controller_outside_probe_page",
        reinterpret_cast<std::uintptr_t>(&ObserveGuard) / watchedBytes
        != watchedPage / watchedBytes
        && reinterpret_cast<std::uintptr_t>(&WorkCallback) / watchedBytes
        != watchedPage / watchedBytes);
    if (failures)
    {
        return 2;
    }

    // 固定一个真实线程池工作线程，先执行预热任务，随后才登记页面探针。
    resources.pool = CreateThreadpool(nullptr);
    if (!resources.pool)
    {
        return 2;
    }
    SetThreadpoolThreadMaximum(resources.pool, 1);
    if (!SetThreadpoolThreadMinimum(resources.pool, 1))
    {
        return 2;
    }
    InitializeThreadpoolEnvironment(&environment);
    SetThreadpoolCallbackPool(&environment, resources.pool);
    resources.work = CreateThreadpoolWork(WorkCallback, &state, &environment);
    DestroyThreadpoolEnvironment(&environment);
    if (!resources.work || !RunWork(resources, state, 0))
    {
        return 2;
    }
    resources.handler = AddVectoredExceptionHandler(1, ObserveGuard);
    if (!resources.handler || !ArmGuard(resources))
    {
        return 2;
    }

    // 首次进入必须来自已预热的 TID，并产生真实执行告警与独立业务计数。
    failures += Check("first_entry_reuses_existing_worker", RunWork(resources, state, 1));
    failures += Check("first_entry_identifies_tid",
        static_cast<DWORD>(faultThread) == state.warmThread);
    failures += Check("first_entry_execution_alarm",
        guardCount == 1 && executeCount == 1 && state.executions == 1);

    // 不重新设防就再次进入：预期业务继续执行而不再产生告警，记录真实盲区。
    failures += Check("second_entry_reuses_existing_worker", RunWork(resources, state, 2));
    failures += Check("unguarded_second_entry_is_missed",
        state.executions == 2 && guardCount == 1 && executeCount == 1);
    if (!ArmGuard(resources))
    {
        return 2;
    }
    failures += Check("rearmed_entry_reuses_existing_worker", RunWork(resources, state, 3));
    failures += Check("manual_rearm_restores_one_alarm",
        state.executions == 3 && guardCount == 2 && executeCount == 2);

    // 主线程先读取同一代码页，验证数据访问会消耗告警，不能冒充执行证据。
    if (!ArmGuard(resources))
    {
        return 2;
    }
    const auto firstByte = *reinterpret_cast<volatile const unsigned char*>(
        &ExecuteImageProbe); // 显式执行一次真实读取，避免优化删除该访问。
    failures += Check("read_consumes_guard_without_execution",
        guardCount == 3 && readCount == 1 && executeCount == 2
        && state.executions == 3);
    failures += Check("post_read_entry_reuses_existing_worker", RunWork(resources, state, 4));
    failures += Check("post_read_execution_is_missed",
        state.executions == 4 && guardCount == 3 && executeCount == 2);

    // NX 对照：首个工作线程保持在异常内，主线程进入已恢复执行权限的同一页。
    // 这只证明跨线程放行窗口，不宣称进行了真实多核同时取指压力验证。
    nxEntered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    nxRelease = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD priorNxProtection = 0; // 设置 NX 时返回的旧保护，统一恢复责任仍由 RAII 持有。
    if (!nxEntered || !nxRelease
        || !VirtualProtect(reinterpret_cast<void*>(watchedPage), watchedBytes,
            PAGE_READONLY, &priorNxProtection))
    {
        return 2;
    }
    state.phase = 5;
    SubmitThreadpoolWork(resources.work);
    const bool firstHeld = WaitForSingleObject(nxEntered, 5000) == WAIT_OBJECT_0;
    failures += Check("nx_first_worker_held_before_probe_body",
        firstHeld && nxFaultCount == 1 && state.executions == 4);
    if (firstHeld)
    {
        ExecuteImageProbe(&state);
        failures += Check("nx_other_thread_executes_during_first_stop",
            state.executions == 5 && nxFaultCount == 1);
    }
    SetEvent(nxRelease);
    WaitForThreadpoolWorkCallbacks(resources.work, FALSE);
    failures += Check("nx_original_worker_resumes_normally",
        firstHeld && state.executions == 6 && nxFaultCount == 1 && nxFailure == 0);
    std::printf("EVIDENCE warm_tid=%lu last_tid=%lu executions=%ld guards=%ld "
        "exec_faults=%ld read_faults=%ld first_byte=%u\n", state.warmThread,
        state.currentThread, state.executions, guardCount, executeCount, readCount,
        static_cast<unsigned>(firstByte));
    std::printf("NX_EVIDENCE faults=%ld failure=%ld executions=%ld\n",
        nxFaultCount, nxFailure, state.executions);
    failures += RunStopWorldExecutionProbe();
    std::printf("RESULT=%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
