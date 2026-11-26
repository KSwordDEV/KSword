/* 自有受控目标：真实心跳计数与脉冲应答，供进程集合 CLI 判定暂停与恢复。
 * 计数在共享内存中，冻结时不再前进；脉冲应答提供确定性的运行/冻结读回。
 * 目标不创建窗口、不接触任何外部进程，也不接受非继承句柄。 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

typedef struct SharedState {
    volatile LONG64 counter; /* 真实心跳计数：目标被冻结时不再前进。 */
    volatile LONG ready;     /* 两个心跳线程就绪标记。 */
    volatile LONG reserved;
} SharedState;

static HANDLE g_pulse = NULL;
static HANDLE g_reply = NULL;
static HANDLE g_stop = NULL;
static SharedState* g_state = NULL;

/* 只接受协调端继承的句柄；十进制表示且不允许尾随内容。 */
static HANDLE InheritedHandle(const wchar_t* text)
{
    wchar_t* end = NULL;
    const unsigned long long raw = wcstoull(text, &end, 10);
    if (!raw || text[0] < L'1' || text[0] > L'9' || *end || raw != (ULONG_PTR)raw) {
        return NULL;
    }
    return (HANDLE)(ULONG_PTR)raw;
}

static DWORD WINAPI CounterThread(void* unused)
{
    (void)unused;
    for (;;) {
        if (WaitForSingleObject(g_stop, 10) == WAIT_OBJECT_0) return 0;
        InterlockedIncrement64(&g_state->counter);
    }
}

static DWORD WINAPI PulseThread(void* unused)
{
    (void)unused;
    HANDLE inputs[2];
    inputs[0] = g_pulse;
    inputs[1] = g_stop;
    for (;;) {
        const DWORD signaled = WaitForMultipleObjects(2, inputs, FALSE, 10);
        if (signaled == WAIT_OBJECT_0) {
            InterlockedIncrement64(&g_state->counter);
            if (!SetEvent(g_reply)) return 1;
            continue;
        }
        if (signaled == WAIT_OBJECT_0 + 1) return 0;
        if (signaled == WAIT_TIMEOUT) {
            InterlockedIncrement64(&g_state->counter);
            continue;
        }
        return 2;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 7 || wcscmp(argv[1], L"--target") != 0) return 2;
    g_pulse = InheritedHandle(argv[4]);
    g_reply = InheritedHandle(argv[5]);
    g_stop = InheritedHandle(argv[6]);
    if (!g_pulse || !g_reply || !g_stop) return 3;

    const HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, argv[2]);
    if (!mapping) return 4;
    g_state = (SharedState*)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState));
    if (!g_state) {
        CloseHandle(mapping);
        return 5;
    }

    const HANDLE ready = InheritedHandle(argv[3]);
    if (!ready) return 6;
    const HANDLE counter = CreateThread(NULL, 0, CounterThread, NULL, 0, NULL);
    const HANDLE pulse = CreateThread(NULL, 0, PulseThread, NULL, 0, NULL);
    if (!counter || !pulse) return 7;
    InterlockedExchange(&g_state->ready, 1);
    if (!SetEvent(ready)) return 8;

    WaitForSingleObject(g_stop, INFINITE);
    const HANDLE threads[2] = {counter, pulse};
    const DWORD both = WaitForMultipleObjects(2, threads, TRUE, 5000);
    CloseHandle(counter);
    CloseHandle(pulse);
    CloseHandle(ready);
    UnmapViewOfFile(g_state);
    CloseHandle(mapping);
    return both == WAIT_OBJECT_0 ? 0 : 9;
}
