#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

static HANDLE OpenFixtureEvent(const wchar_t* prefix, const wchar_t* suffix, DWORD access)
{
    wchar_t name[128];
    if (swprintf_s(name, _countof(name), L"%ls-%ls", prefix, suffix) < 0) {
        return NULL;
    }
    return OpenEventW(access, FALSE, name);
}

__declspec(dllexport) __declspec(noinline) BOOL WINAPI ExportedTick(HANDLE done)
{
    return SetEvent(done);
}

// 对齐的自有数据导出，所有写入均由此程序自己执行。
__declspec(dllexport) __declspec(align(8)) volatile ULONGLONG WatchedData = 0x8877665511223344ULL;
// 由启动端在盘上读取的合作声明，目标仍由自己的入口运行。
__declspec(dllexport) const DWORD KSwordActionAnalyzeDataWatchV1 = 1;
static volatile LONG UnwatchedData = 0; // 普通数据写入用作范围负例。

typedef struct WriteThreadArgs {
    HANDLE done; // 写指令完成后发信号。
    unsigned offset; // 被监控区间的末字节，覆盖各个硬件宽度。
} WriteThreadArgs;

// 首次停点恢复后新建的线程。写高位字节后才发出业务完成信号。
static DWORD WINAPI WriteFromNewThread(void* value)
{
    const WriteThreadArgs* args = value;
    volatile unsigned char* bytes = (volatile unsigned char*)&WatchedData;
    bytes[args->offset] ^= 1;
    return SetEvent(args->done) ? 0 : 1;
}

// 顺序执行同值写、主线程变化、新线程变化和脱离后写入，各轮由 trigger 驱动。
static int RunWriteWatch(HANDLE trigger, HANDLE done, unsigned width)
{
    // 使用单字节写入，令掩码仅反映测试指定的真实字节变化。
    volatile unsigned char* bytes = (volatile unsigned char*)&WatchedData;
    WriteThreadArgs args = {done, width - 1};
    for (unsigned index = 0; index < 4; ++index) {
        if (WaitForSingleObject(trigger, 20000) != WAIT_OBJECT_0) return 3;
        if (index == 2) {
            const HANDLE writer = CreateThread(NULL, 0, WriteFromNewThread, &args, 0, NULL); // 新的实际写入者。
            if (!writer) return 4;
            DWORD code = 1; // 读取线程的真实返回值。
            const BOOL complete = WaitForSingleObject(writer, 20000) == WAIT_OBJECT_0 &&
                GetExitCodeThread(writer, &code) && code == 0;
            CloseHandle(writer);
            if (!complete) return 4;
            continue;
        }
        // 正常范围先写入，然后让同值写实际执行。最后一轮在脱离后继续运行。
        if (index == 0) {
            UnwatchedData = 1;
            bytes[0] = 0x44;
        } else {
            bytes[0] ^= 1;
        }
        if (!SetEvent(done)) return 5;
    }
    return 0;
}

// 只接受协调者传入的继承句柄；字符串使用十进制表示且不允许尾随内容。
static HANDLE InheritedHandle(const wchar_t* text)
{
    wchar_t* end = NULL;
    const unsigned long long raw = wcstoull(text, &end, 10);
    if (!raw || text[0] < L'1' || text[0] > L'9' || *end || raw != (ULONG_PTR)raw) {
        return NULL;
    }
    return (HANDLE)(ULONG_PTR)raw;
}

// 两个实例共享事件名前缀。PID 区分测试触发与回执；合作准入只走继承的 Ready/Gate。
static int RunCooperativePair(HANDLE ready, HANDLE gate)
{
    if (!ready || !gate || !SetEvent(ready)) {
        return 2;
    }
    CloseHandle(ready);
    char start = 0;
    DWORD bytes = 0;
    const BOOL received = ReadFile(gate, &start, sizeof(start), &bytes, NULL);
    const DWORD error = received ? ERROR_SUCCESS : GetLastError();
    CloseHandle(gate);
    if (!received) {
        return error == ERROR_BROKEN_PIPE ? 0 : 2;
    }
    if (bytes != sizeof(start) || start != '1') {
        return 2;
    }

    wchar_t run[64]; // 测试进程按本轮随机前缀创建事件。
    const DWORD size = GetEnvironmentVariableW(L"KSWORD_PRODUCT_BREAKPOINT_PAIR_EVENTS", run, _countof(run));
    wchar_t prefix[96]; // 每个自有实例只访问自己的 trigger/done。
    if (!size || size >= _countof(run) ||
        swprintf_s(prefix, _countof(prefix), L"%ls-%lu", run, GetCurrentProcessId()) < 0) {
        return 2;
    }
    // 父夹具在控制台 hello 返回实际 PID 后创建成员事件，再同时放行初始化。
    const HANDLE configured = OpenFixtureEvent(run, L"configured", SYNCHRONIZE);
    if (!configured) {
        return 2;
    }
    const DWORD configuration = WaitForSingleObject(configured, 20000);
    CloseHandle(configured);
    if (configuration != WAIT_OBJECT_0) {
        return 2;
    }
    const HANDLE trigger = OpenFixtureEvent(prefix, L"trigger", SYNCHRONIZE);
    const HANDLE done = OpenFixtureEvent(prefix, L"done", EVENT_MODIFY_STATE);
    int result = 2;
    if (trigger && done) {
        result = 0;
        // 第一轮由组继续，第二轮由关闭归还；第三轮确认脱离后的代码还能运行。
        for (unsigned round = 0; round < 3; ++round) {
            if (WaitForSingleObject(trigger, 20000) != WAIT_OBJECT_0 || !ExportedTick(done)) {
                result = 3;
                break;
            }
        }
    }
    if (done) CloseHandle(done);
    if (trigger) CloseHandle(trigger);
    return result;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 5 && wcscmp(argv[1], L"--ksword-breakpoint-ready") == 0 &&
        wcscmp(argv[3], L"--ksword-breakpoint-gate") == 0) {
        return RunCooperativePair(InheritedHandle(argv[2]), InheritedHandle(argv[4]));
    }
    if (argc != 1) {
        return 2;
    }
    wchar_t prefix[96];
    const DWORD size = GetEnvironmentVariableW(L"KSWORD_PRODUCT_BREAKPOINT_EVENTS", prefix, _countof(prefix));
    if (!size || size >= _countof(prefix)) {
        return 2;
    }
    HANDLE ready = OpenFixtureEvent(prefix, L"ready", EVENT_MODIFY_STATE);
    HANDLE trigger = OpenFixtureEvent(prefix, L"trigger", SYNCHRONIZE);
    HANDLE done = OpenFixtureEvent(prefix, L"done", EVENT_MODIFY_STATE);
    int result = 2;
    if (ready && trigger && done && SetEvent(ready)) {
        wchar_t mode[2] = {0}; // 现有执行断点夹具保留为默认模式。
        if (GetEnvironmentVariableW(L"KSWORD_PRODUCT_BREAKPOINT_WRITE_WATCH", mode, _countof(mode)) == 1 && mode[0] == L'1') {
            wchar_t width[2] = {0}; // 桌面既有夹具默认以 4 B 测试。
            const DWORD length = GetEnvironmentVariableW(L"KSWORD_PRODUCT_BREAKPOINT_WATCH_WIDTH", width, _countof(width));
            if (length == 0 || (length == 1 && wcschr(L"1248", width[0]))) {
                result = RunWriteWatch(trigger, done, length == 0 ? 4u : (unsigned)(width[0] - L'0'));
            }
        } else {
            result = 0;
            for (unsigned i = 0; i < 132; ++i) {
                if (WaitForSingleObject(trigger, 20000) != WAIT_OBJECT_0 || !ExportedTick(done)) {
                    result = 3;
                    break;
                }
            }
        }
    }
    if (done) CloseHandle(done);
    if (trigger) CloseHandle(trigger);
    if (ready) CloseHandle(ready);
    return result;
}
