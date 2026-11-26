// ApiTransferValidationFixture.cpp
// API 转移参数源端验收夹具（父子双角色）。
// 父进程：加载正式 Release Agent，按命令执行四个转移 API（成功/失败/null/部分写），
//         目标一律为本夹具自有子进程；远程线程入口为本夹具 EXE 的自有导出函数。
// 子进程：分配可写目标缓冲与半未提交区域，报告身份，等待父进程退出。
// 不注入其他用户进程；不操作 GUI；不加载驱动。

#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <iterator>

extern "C" {

// 自有导出线程例程：在子进程映像内执行，递增共享计数器。
#if defined(_M_IX86)
// 32 位 stdcall 导出默认带装饰名；补充无装饰导出供 GetProcAddress 查找。
#pragma comment(linker, "/EXPORT:ApiTransferRemoteProc=_ApiTransferRemoteProc@4")
#endif
__declspec(dllexport) DWORD WINAPI ApiTransferRemoteProc(LPVOID)
{
    extern volatile LONG g_ApiTransferRunCounter;
    return static_cast<DWORD>(InterlockedIncrement(&g_ApiTransferRunCounter));
}

volatile LONG g_ApiTransferRunCounter = 0;

using NtWriteVirtualMemoryFn = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtCreateThreadExFn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static NtWriteVirtualMemoryFn ResolveNtWriteVirtualMemory()
{
    return reinterpret_cast<NtWriteVirtualMemoryFn>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory")));
}

static NtCreateThreadExFn ResolveNtCreateThreadEx()
{
    return reinterpret_cast<NtCreateThreadExFn>(reinterpret_cast<void*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx")));
}

static const char kPattern[] = "ApiTransferValidationPattern-0123456789";

struct ChildHandles
{
    HANDLE processOp = nullptr;      // OpenProcess 全权限写读操作句柄（输入句柄核对用）。
    HANDLE processLimited = nullptr; // 仅 PROCESS_VM_WRITE 的权限不足负例句柄。
    HANDLE processRaw = nullptr;     // CreateProcess 返回句柄，用于收尾终止。
    HANDLE threadA = nullptr;
    HANDLE threadB = nullptr;
    DWORD pid = 0;
    unsigned long long childBase = 0;
    unsigned long long procRva = 0;
    unsigned long long counterRva = 0;
    unsigned long long buffer = 0;
    unsigned long long region = 0; // 第二页保留未提交，用于部分写。
    unsigned long long lastInputHandle = 0;
};

static ChildHandles g_child;

static void FlushOut()
{
    fflush(stdout);
}

static LONG WINAPI CrashReport(EXCEPTION_POINTERS* info)
{
    HMODULE module = nullptr;
    char name[MAX_PATH] = {};
    const void* address = info->ExceptionRecord->ExceptionAddress;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(address), &module))
    {
        GetModuleFileNameA(module, name, MAX_PATH);
        fprintf(stderr, "CRASH code=%08lX addr=%p module=%s base=%p offset=0x%zX\n",
            info->ExceptionRecord->ExceptionCode, address, name, reinterpret_cast<void*>(module),
            static_cast<size_t>(static_cast<char*>(const_cast<void*>(address))
                - reinterpret_cast<char*>(module)));
    }
    else
    {
        fprintf(stderr, "CRASH code=%08lX addr=%p module=<unknown>\n",
            info->ExceptionRecord->ExceptionCode, address);
    }
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}

static bool SpawnChild(const wchar_t* selfPath)
{
    wchar_t command[512] = {};
    swprintf_s(command, L"\"%s\" child %lu", selfPath, GetCurrentProcessId());

    SECURITY_ATTRIBUTES inherit = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE readEnd = nullptr;
    HANDLE writeEnd = nullptr;
    if (!CreatePipe(&readEnd, &writeEnd, &inherit, 0)) return false;
    SetHandleInformation(writeEnd, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writeEnd;
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    startup.hStdInput = nullptr;
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(selfPath, command, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &process))
    {
        CloseHandle(readEnd);
        CloseHandle(writeEnd);
        return false;
    }
    CloseHandle(writeEnd);
    CloseHandle(process.hThread);

    char line[512] = {};
    DWORD readTotal = 0;
    while (readTotal + 1 < sizeof(line))
    {
        DWORD got = 0;
        char ch = 0;
        if (!ReadFile(readEnd, &ch, 1, &got, nullptr) || got == 0) break;
        if (ch == '\r') continue;
        line[readTotal++] = ch;
        if (ch == '\n') break;
    }
    line[readTotal] = 0;
    CloseHandle(readEnd);

    unsigned long long base = 0, procRva = 0, counterRva = 0, buffer = 0, region = 0;
    if (sscanf_s(line, "CHILDINFO %lu %llu %llu %llu %llu %llu",
        &g_child.pid, &base, &procRva, &counterRva, &buffer, &region) != 6)
    {
        CloseHandle(process.hProcess);
        return false;
    }
    g_child.childBase = base;
    g_child.procRva = procRva;
    g_child.counterRva = counterRva;
    g_child.buffer = buffer;
    g_child.region = region;
    g_child.processRaw = process.hProcess;
    return true;
}

static int ChildMain(DWORD parentPid)
{
    HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
    if (!parent) return 2;
    LPVOID buffer = VirtualAlloc(nullptr, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID region = VirtualAlloc(nullptr, 131072, MEM_RESERVE, PAGE_NOACCESS);
    LPVOID firstPage = nullptr;
    if (region) firstPage = VirtualAlloc(region, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer || !region || !firstPage) return 3;
    memcpy(buffer, kPattern, sizeof(kPattern));
    memcpy(firstPage, kPattern, sizeof(kPattern));

    HMODULE self = GetModuleHandleW(nullptr);
    void* proc = reinterpret_cast<void*>(GetProcAddress(self, "ApiTransferRemoteProc"));
    if (!proc) return 4;
    unsigned long long procRva = reinterpret_cast<unsigned long long>(proc)
        - reinterpret_cast<unsigned long long>(self);
    unsigned long long counterRva = reinterpret_cast<unsigned long long>(&g_ApiTransferRunCounter)
        - reinterpret_cast<unsigned long long>(self);
    printf("CHILDINFO %lu %llu %llu %llu %llu %llu\n",
        GetCurrentProcessId(),
        reinterpret_cast<unsigned long long>(self), procRva, counterRva,
        reinterpret_cast<unsigned long long>(buffer),
        reinterpret_cast<unsigned long long>(region));
    FlushOut();
    WaitForSingleObject(parent, INFINITE);
    return 0;
}

static void ReportHandle(HANDLE value)
{
    g_child.lastInputHandle = reinterpret_cast<unsigned long long>(value);
}

static void ExecuteCommands()
{
    static BYTE localPattern[8192];
    memcpy(localPattern, kPattern, sizeof(kPattern));
    SIZE_T written = 0;
    DWORD error = 0;
    LONG status = 0;
    HANDLE thread = nullptr;
    DWORD tid = 0;

    for (int c; (c = getchar()) != EOF;)
    {
        error = 0;
        written = 0;
        status = 0;
        thread = nullptr;
        tid = 0;
        switch (c)
        {
        case 'L': // 加载正式 Agent（由控制器提前写好本 PID 配置）。
        {
            wchar_t agentPath[MAX_PATH] = {};
            scanf_s("%511ls", agentPath, (unsigned)std::size(agentPath));
            HMODULE module = LoadLibraryW(agentPath);
            if (!module) { printf("ERR load %lu\n", GetLastError()); FlushOut(); continue; }
            printf("LOADED\n");
            FlushOut();
            break;
        }
        case 'S':
        {
            wchar_t selfPath[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
            if (!SpawnChild(selfPath)) { printf("ERR spawn\n"); FlushOut(); continue; }
            printf("CHILD %lu %llu %llu %llu %llu %llu\n", g_child.pid,
                g_child.childBase, g_child.procRva, g_child.counterRva,
                g_child.buffer, g_child.region);
            FlushOut();
            break;
        }
        case 'O': // 正常权限（含建线程权）与受限权限句柄。
        {
            g_child.processOp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, g_child.pid);
            g_child.processLimited = OpenProcess(PROCESS_VM_WRITE, FALSE, g_child.pid);
            printf("OPEN %llu %llu\n",
                reinterpret_cast<unsigned long long>(g_child.processOp),
                reinterpret_cast<unsigned long long>(g_child.processLimited));
            FlushOut();
            break;
        }
        case 'w': // WriteProcessMemory 成功。
        {
            BOOL ok = WriteProcessMemory(g_child.processOp,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x100),
                localPattern, 256, &written);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            printf("R w %llu %lu %llu\n", ok ? 1ull : 0ull, error,
                static_cast<unsigned long long>(written));
            FlushOut();
            break;
        }
        case 'W': // NtWriteVirtualMemory 成功。
        {
            auto fn = ResolveNtWriteVirtualMemory();
            status = fn(g_child.processOp,
                reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x300),
                localPattern, 128, &written);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            printf("R W %ld %lu %llu\n", status, error, static_cast<unsigned long long>(written));
            FlushOut();
            break;
        }
        case 'r': // CreateRemoteThread 成功，自有导出例程。
        {
            void* remote = reinterpret_cast<void*>(static_cast<std::uintptr_t>(
                g_child.childBase + g_child.procRva));
            thread = CreateRemoteThread(g_child.processOp, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(remote), nullptr, 0, &tid);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            if (thread && WaitForSingleObject(thread, 15000) != WAIT_OBJECT_0) error = 0xDEAD0001;
            g_child.threadA = thread;
            printf("R r %llu %lu %lu %llu\n", thread ? 1ull : 0ull, error, tid,
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(thread)));
            FlushOut();
            break;
        }
        case 'R': // NtCreateThreadEx 成功，同一自有导出例程。
        {
            auto fn = ResolveNtCreateThreadEx();
            void* remote = reinterpret_cast<void*>(static_cast<std::uintptr_t>(
                g_child.childBase + g_child.procRva));
            status = fn(&thread, THREAD_ALL_ACCESS, nullptr, g_child.processOp, remote, nullptr,
                0, 0, 0, 0, nullptr);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            if (status >= 0 && thread && WaitForSingleObject(thread, 15000) != WAIT_OBJECT_0) error = 0xDEAD0002;
            g_child.threadB = thread;
            printf("R R %ld %lu %lu\n", status, error, tid);
            FlushOut();
            break;
        }
        case 'n': // WriteProcessMemory 成功但 null 输出长度。
        {
            BOOL ok = WriteProcessMemory(g_child.processOp,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x400),
                localPattern, 64, nullptr);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            printf("R n %llu %lu\n", ok ? 1ull : 0ull, error);
            FlushOut();
            break;
        }
        case 'N': // NtWriteVirtualMemory 成功但 null 输出长度。
        {
            auto fn = ResolveNtWriteVirtualMemory();
            status = fn(g_child.processOp,
                reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x500),
                localPattern, 64, nullptr);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            printf("R N %ld %lu\n", status, error);
            FlushOut();
            break;
        }
        case 'm': // WriteProcessMemory 跨未提交页：失败 ERROR_PARTIAL_COPY。
        {
            BOOL ok = WriteProcessMemory(g_child.processOp,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(g_child.region) + 0x800),
                localPattern, 8192, &written);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            printf("R m %llu %lu %llu\n", ok ? 1ull : 0ull, error,
                static_cast<unsigned long long>(written));
            FlushOut();
            break;
        }
        case 'M': // NtWriteVirtualMemory 跨未提交页：STATUS_PARTIAL_COPY 部分写。
        {
            auto fn = ResolveNtWriteVirtualMemory();
            status = fn(g_child.processOp,
                reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(g_child.region) + 0x800),
                localPattern, 8192, &written);
            error = GetLastError();
            ReportHandle(g_child.processOp);
            printf("R M %ld %lu %llu\n", status, error, static_cast<unsigned long long>(written));
            FlushOut();
            break;
        }
        case 'c': // 调用后关闭句柄：WriteProcessMemory 失败。
        {
            HANDLE stale = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                FALSE, g_child.pid);
            CloseHandle(stale);
            BOOL ok = WriteProcessMemory(stale,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x600),
                localPattern, 32, &written);
            error = GetLastError();
            ReportHandle(stale);
            printf("R c %llu %lu\n", ok ? 1ull : 0ull, error);
            FlushOut();
            break;
        }
        case 'C': // 调用后关闭句柄：NtWriteVirtualMemory 失败。
        {
            HANDLE stale = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                FALSE, g_child.pid);
            CloseHandle(stale);
            auto fn = ResolveNtWriteVirtualMemory();
            status = fn(stale,
                reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x700),
                localPattern, 32, &written);
            error = GetLastError();
            ReportHandle(stale);
            printf("R C %ld %lu\n", status, error);
            FlushOut();
            break;
        }
        case 'p': // 权限不足：WriteProcessMemory 失败。
        {
            BOOL ok = WriteProcessMemory(g_child.processLimited,
                reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x800),
                localPattern, 16, &written);
            error = GetLastError();
            ReportHandle(g_child.processLimited);
            printf("R p %llu %lu\n", ok ? 1ull : 0ull, error);
            FlushOut();
            break;
        }
        case 'P': // 权限不足：NtWriteVirtualMemory 失败。
        {
            auto fn = ResolveNtWriteVirtualMemory();
            status = fn(g_child.processLimited,
                reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x900),
                localPattern, 16, &written);
            error = GetLastError();
            ReportHandle(g_child.processLimited);
            printf("R P %ld %lu\n", status, error);
            FlushOut();
            break;
        }
        case 't': // CreateRemoteThread 失败：非伪句柄的无效句柄。
        // 注意 -1 是当前进程伪句柄，KernelBase 会真的在自身进程建线程，不能用作用例。
        {
            HANDLE bogusProcess = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x1234));
            thread = CreateRemoteThread(bogusProcess, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(0x1000), nullptr, 0, &tid);
            error = GetLastError();
            ReportHandle(bogusProcess);
            printf("R t %llu %lu\n", thread ? 1ull : 0ull, error);
            FlushOut();
            break;
        }
        case 'T': // NtCreateThreadEx 失败：非伪句柄的无效句柄。
        // 注意 -1 是当前进程伪句柄，ntdll 层会真的在自身进程建线程，不能用作用例。
        {
            auto fn = ResolveNtCreateThreadEx();
            HANDLE bogusProcess = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x1234));
            status = fn(&thread, THREAD_ALL_ACCESS, nullptr, bogusProcess,
                reinterpret_cast<PVOID>(0x1000), nullptr, 0, 0, 0, 0, nullptr);
            error = GetLastError();
            ReportHandle(bogusProcess);
            printf("R T %ld %lu\n", status, error);
            FlushOut();
            break;
        }
        case 'v': // 核对子进程缓冲与自有线程实际执行计数。
        {
            unsigned long long counter = 0;
            SIZE_T got = 0;
            BOOL ok = ReadProcessMemory(g_child.processOp,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(
                    g_child.childBase + g_child.counterRva)),
                &counter, sizeof(counter), &got);
            BYTE remote[40] = {};
            BOOL patternOk = ReadProcessMemory(g_child.processOp,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(g_child.buffer) + 0x100),
                remote, sizeof(kPattern), &got);
            printf("V %llu %llu %llu\n", ok ? counter : 0ull,
                ok ? 1ull : 0ull, patternOk ? 1ull : 0ull);
            FlushOut();
            break;
        }
        case 'x': // 收尾：关闭全部自有句柄。
        {
            if (g_child.threadA) CloseHandle(g_child.threadA);
            if (g_child.threadB) CloseHandle(g_child.threadB);
            if (g_child.processOp) CloseHandle(g_child.processOp);
            if (g_child.processLimited) CloseHandle(g_child.processLimited);
            g_child.threadA = g_child.threadB = g_child.processOp = g_child.processLimited = nullptr;
            printf("CLOSED\n");
            FlushOut();
            break;
        }
        case 'Q':
        {
            if (g_child.processRaw)
            {
                TerminateProcess(g_child.processRaw, 0);
                WaitForSingleObject(g_child.processRaw, 10000);
                CloseHandle(g_child.processRaw);
            }
            return;
        }
        default:
            break;
        }
        (void)written;
    }
}

} // extern "C"

int wmain(int argc, wchar_t** argv)
{
    SetUnhandledExceptionFilter(CrashReport);
    if (argc >= 3 && wcscmp(argv[1], L"child") == 0)
    {
        return ChildMain(static_cast<DWORD>(_wtoi(argv[2])));
    }
    if (argc < 2)
    {
        return 1;
    }
    printf("PID %lu\n", GetCurrentProcessId());
    FlushOut();
    ExecuteCommands();
    return 0;
}
