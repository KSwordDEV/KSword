#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <intrin.h>

// 汇编实现的已知指令站点；此处只提供入口声明和事件握手。
extern void StepSite(void);
extern void StepSlowSite(void);

// 慢速被调方：测试持有 go 事件时阻塞在已知等待上，
// 使 over-call/跳出的硬件断点停点停留在在途状态。
static HANDLE g_block = NULL;
static HANDLE g_marker = NULL; // 可选的进度与异常标记文件。
static BOOL g_round_marks = FALSE; // 轮次标记会引入系统调用，默认关闭。

// 用户态自旋释放标志：协调者直接写入自有目标内存以结束自旋，
// 使在途步进不依赖被调方进入内核等待。
__declspec(dllexport) volatile LONG StepSpinRelease = 0;

// 只追加一行标记，供协调者确认自有目标实际执行到哪一步。
static void Mark(const char* text)
{
    if (!g_marker) {
        return;
    }
    DWORD written = 0;
    WriteFile(g_marker, text, (DWORD)strlen(text), &written, NULL);
    WriteFile(g_marker, "\n", 1, &written, NULL);
    FlushFileBuffers(g_marker);
}

// 记录未处理异常的代码与故障地址，随后继续默认处理，保留真实退出码。
static LONG CALLBACK MarkerException(EXCEPTION_POINTERS* info)
{
    char line[512];
    const unsigned long long* slots = (const unsigned long long*)((const char*)info->ContextRecord->Rsp - 0x40);
    const int length = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "EXCEPTION code=0x%08lx rip=0x%llx rsp=0x%llx slot-8=0x%llx slot-16=0x%llx slot0=0x%llx ntdll=0x%llx "
        "w-16=0x%llx w-24=0x%llx w-32=0x%llx w-40=0x%llx w+8=0x%llx",
        info->ExceptionRecord->ExceptionCode,
        (unsigned long long)info->ExceptionRecord->ExceptionAddress,
        (unsigned long long)info->ContextRecord->Rsp,
        slots[7], slots[6], slots[8],
        (unsigned long long)(ULONG_PTR)GetModuleHandleW(L"ntdll.dll"),
        slots[4], slots[3], slots[2], slots[1], slots[9]);
    if (length > 0) {
        Mark(line);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) void StepBlockingCallee(void)
{
    // 只做用户态自旋：不在被调方内做任何文件 I/O，便于区分自旋与外部写入的影响。
    if (g_block) {
        WaitForSingleObject(g_block, 20000);
        return;
    }
    const unsigned long long deadline = __rdtsc() + 6000000000ULL;
    while (InterlockedCompareExchange(&StepSpinRelease, 0, 0) == 0) {
        if (__rdtsc() > deadline) {
            break;
        }
        YieldProcessor();
    }
}

// 只接受协调者传入的事件名前缀；两个站点共享同一套握手事件。
static HANDLE OpenFixtureEvent(const wchar_t* prefix, const wchar_t* suffix, DWORD access)
{
    wchar_t name[128];
    if (swprintf_s(name, _countof(name), L"%ls-%ls", prefix, suffix) < 0) {
        return NULL;
    }
    return OpenEventW(access, FALSE, name);
}

int wmain(int argc, wchar_t** argv)
{
    (void)argv;
    if (argc != 1) {
        return 2;
    }
    wchar_t prefix[96];
    const DWORD size = GetEnvironmentVariableW(L"KSWORD_PRODUCT_STEP_EVENTS", prefix, _countof(prefix));
    if (!size || size >= _countof(prefix)) {
        return 2;
    }
    wchar_t mode[8];
    const DWORD modeSize = GetEnvironmentVariableW(L"KSWORD_PRODUCT_STEP_MODE", mode, _countof(mode));
    const BOOL slow = modeSize == 4 && wcscmp(mode, L"slow") == 0;
    // 默认走原有的良性系统调用等待（g_block 事件句柄）；纯用户态自旋只能显式选择，
    // 不得用纯自旋默认绕开被调方系统调用路径上的真实失败。
    const BOOL spin = GetEnvironmentVariableW(L"KSWORD_PRODUCT_STEP_SPIN", mode, _countof(mode)) == 1 &&
        mode[0] == L'1';
    wchar_t markerPath[MAX_PATH];
    const DWORD markerSize = GetEnvironmentVariableW(L"KSWORD_PRODUCT_STEP_MARKER", markerPath, _countof(markerPath));
    wchar_t roundMark[2];
    g_round_marks = GetEnvironmentVariableW(L"KSWORD_PRODUCT_STEP_MARK_ROUNDS", roundMark, _countof(roundMark)) == 1 &&
        roundMark[0] == L'1';
    if (markerSize && markerSize < _countof(markerPath)) {
        g_marker = CreateFileW(markerPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (g_marker == INVALID_HANDLE_VALUE) {
            g_marker = NULL;
        } else {
            AddVectoredExceptionHandler(1, MarkerException);
        }
    }

    HANDLE ready = OpenFixtureEvent(prefix, L"ready", EVENT_MODIFY_STATE);
    HANDLE trigger = OpenFixtureEvent(prefix, L"trigger", SYNCHRONIZE);
    HANDLE done = OpenFixtureEvent(prefix, L"done", EVENT_MODIFY_STATE);
    if (slow && !spin) {
        g_block = OpenFixtureEvent(prefix, L"go", SYNCHRONIZE);
        if (!g_block) {
            // 系统调用等待句柄打不开即夹具错误：不得隐式回退到纯用户态自旋。
            Mark("go-open-failed");
        }
    }
    int result = 2;
    const BOOL callee_ready = !slow || spin || g_block != NULL;
    if (ready && trigger && done && callee_ready && SetEvent(ready)) {
        result = 0;
        Mark("ready");
        {
            char line[64];
            const int length = _snprintf_s(line, sizeof(line), _TRUNCATE, "flag=0x%llx",
                (unsigned long long)(ULONG_PTR)&StepSpinRelease);
            if (length > 0) {
                Mark(line);
            }
        }
        // 每轮一个原生停点序列；步进结束后由协调者继续放行并收取 done。
        for (unsigned round = 0; round < 3 && result == 0; ++round) {
            if (WaitForSingleObject(trigger, 20000) != WAIT_OBJECT_0) {
                result = 3;
                break;
            }
            if (g_round_marks) {
                Mark("round-enter");
            }
            if (slow) {
                StepSlowSite();
            } else {
                StepSite();
            }
            if (g_round_marks) {
                Mark("round-return");
            }
            if (!SetEvent(done)) {
                result = 5;
            }
        }
    }
    Mark(result == 0 ? "exit-clean" : "exit-error");
    if (g_block) CloseHandle(g_block);
    if (done) CloseHandle(done);
    if (trigger) CloseHandle(trigger);
    if (ready) CloseHandle(ready);
    if (g_marker) CloseHandle(g_marker);
    return result;
}
