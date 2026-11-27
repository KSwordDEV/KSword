/* Owned x64 two-role fixture for kind=6 ResumeThread handoff.
 * F publishes two genuinely suspended threads with RIPs set to exact private
 * executable stubs. A waits for the runner's formal-Agent-ready gate, then
 * resumes each thread once through a different API and preserves each result.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef NTSTATUS (NTAPI * NtResumeThreadFn)(HANDLE, PULONG);

typedef struct {
    volatile LONG ready, goWin32, goNt, stop;
    volatile LONG win32Result, win32LastError, win32Previous;
    volatile LONG ntStatus, ntLastError, ntPrevious;
    volatile LONG counter1, counter2;
    volatile LONG64 fPid, fCreation, aPid, aCreation;
    volatile LONG64 tid1, tid2, threadCreation1, threadCreation2;
    volatile LONG64 page1, page2, stub1, stub2;
} ResumeState;

static volatile LONG g_counter1 = 0;
static volatile LONG g_counter2 = 0;

static unsigned long long file_time_value(FILETIME value)
{
    return (static_cast<unsigned long long>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

static unsigned long long process_creation(HANDLE process)
{
    FILETIME created{}, exited{}, kernel{}, user{};
    return GetProcessTimes(process, &created, &exited, &kernel, &user) ? file_time_value(created) : 0;
}

static unsigned long long thread_creation(HANDLE thread)
{
    FILETIME created{}, exited{}, kernel{}, user{};
    return GetThreadTimes(thread, &created, &exited, &kernel, &user) ? file_time_value(created) : 0;
}

static HANDLE open_section(const wchar_t* name)
{
    HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!mapping) fwprintf(stderr, L"{\"error\":\"open-section\",\"win32Error\":%lu}\n", GetLastError());
    return mapping;
}

static ResumeState* map_state(HANDLE mapping)
{
    return static_cast<ResumeState*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ResumeState)));
}

static void write_counter_stub(unsigned char* code, volatile LONG* counter)
{
    // mov rax,counter; lock inc dword ptr [rax]; xor ecx,ecx; jmp ExitThread
    code[0] = 0x48; code[1] = 0xB8;
    const unsigned long long address = reinterpret_cast<unsigned long long>(counter);
    for (int i = 0; i < 8; ++i) code[2 + i] = static_cast<unsigned char>(address >> (i * 8));
    code[10] = 0xF0; code[11] = 0xFF; code[12] = 0x00;
    code[13] = 0x33; code[14] = 0xC9;
    code[15] = 0x48; code[16] = 0xB8;
    const unsigned long long exitAddress = reinterpret_cast<unsigned long long>(&ExitThread);
    for (int i = 0; i < 8; ++i) code[17 + i] = static_cast<unsigned char>(exitAddress >> (i * 8));
    code[25] = 0xFF; code[26] = 0xE0;
    FlushInstructionCache(GetCurrentProcess(), code, 27);
}

static DWORD WINAPI harmless_start(void*) { return 0; }

static HANDLE create_suspended_at(unsigned char* ip, unsigned long long* tid,
    unsigned long long* creation)
{
    DWORD threadId = 0;
    HANDLE thread = CreateThread(nullptr, 0, harmless_start, nullptr, CREATE_SUSPENDED, &threadId);
    if (!thread) return nullptr;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(thread, &context)) { CloseHandle(thread); return nullptr; }
    context.Rip = reinterpret_cast<DWORD64>(ip);
    if (!SetThreadContext(thread, &context)) { CloseHandle(thread); return nullptr; }
    *tid = threadId;
    *creation = thread_creation(thread);
    return thread;
}

static int run_f(const wchar_t* name)
{
    HANDLE mapping = open_section(name);
    if (!mapping) return 2;
    ResumeState* state = map_state(mapping);
    if (!state) { CloseHandle(mapping); return 3; }

    unsigned char* page1 = nullptr;
    unsigned char* page2 = nullptr;
    HANDLE thread1 = nullptr;
    HANDLE thread2 = nullptr;
    const auto cleanup = [&]() {
        if (thread1) CloseHandle(thread1);
        if (thread2) CloseHandle(thread2);
        if (page1) VirtualFree(page1, 0, MEM_RELEASE);
        if (page2) VirtualFree(page2, 0, MEM_RELEASE);
        UnmapViewOfFile(state);
        CloseHandle(mapping);
    };

    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);
    const SIZE_T pageBytes = systemInfo.dwPageSize ? systemInfo.dwPageSize : 0x1000;
    page1 = static_cast<unsigned char*>(VirtualAlloc(nullptr, pageBytes,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    page2 = static_cast<unsigned char*>(VirtualAlloc(nullptr, pageBytes,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!page1 || !page2) { cleanup(); return 4; }
    unsigned char* stub1 = page1 + 0x100;
    unsigned char* stub2 = page2 + 0x100;
    write_counter_stub(stub1, &g_counter1);
    write_counter_stub(stub2, &g_counter2);

    unsigned long long tid1 = 0, tid2 = 0, creation1 = 0, creation2 = 0;
    thread1 = create_suspended_at(stub1, &tid1, &creation1);
    thread2 = create_suspended_at(stub2, &tid2, &creation2);
    if (!thread1 || !thread2 || !creation1 || !creation2) { cleanup(); return 5; }

    state->fPid = GetCurrentProcessId();
    state->fCreation = process_creation(GetCurrentProcess());
    state->tid1 = tid1; state->tid2 = tid2;
    state->threadCreation1 = creation1; state->threadCreation2 = creation2;
    state->page1 = reinterpret_cast<LONG64>(page1); state->page2 = reinterpret_cast<LONG64>(page2);
    state->stub1 = reinterpret_cast<LONG64>(stub1); state->stub2 = reinterpret_cast<LONG64>(stub2);
    state->ready = 1;

    printf("{\"role\":\"f\",\"stage\":\"ready\",\"pid\":%lu,\"creation\":%llu,"
           "\"tid1\":%llu,\"tid2\":%llu,\"threadCreation1\":%llu,\"threadCreation2\":%llu,"
           "\"page1\":%llu,\"page2\":%llu,\"stub1\":%llu,\"stub2\":%llu,"
           "\"protection1\":%lu,\"protection2\":%lu,\"state1\":%lu,\"state2\":%lu}\n",
        GetCurrentProcessId(), state->fCreation,
        static_cast<unsigned long long>(tid1), static_cast<unsigned long long>(tid2), creation1, creation2,
        reinterpret_cast<unsigned long long>(page1), reinterpret_cast<unsigned long long>(page2),
        reinterpret_cast<unsigned long long>(stub1), reinterpret_cast<unsigned long long>(stub2),
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE, MEM_COMMIT, MEM_COMMIT);
    fflush(stdout);

    const ULONGLONG deadline = GetTickCount64() + 300000ULL;
    while (GetTickCount64() < deadline && !state->stop) {
        if (WaitForSingleObject(thread1, 0) == WAIT_OBJECT_0 &&
            WaitForSingleObject(thread2, 0) == WAIT_OBJECT_0) break;
        Sleep(10);
    }
    state->counter1 = g_counter1;
    state->counter2 = g_counter2;
    printf("{\"role\":\"f\",\"stage\":\"final\",\"pid\":%lu,\"creation\":%llu,"
           "\"counter1\":%ld,\"counter2\":%ld}\n",
        GetCurrentProcessId(), state->fCreation, state->counter1, state->counter2);
    fflush(stdout);
    while (!state->stop) Sleep(10);

    const bool executedOnce = state->counter1 == 1 && state->counter2 == 1;
    cleanup();
    return executedOnce ? 0 : 6;
}

static int run_a(const wchar_t* name)
{
    HANDLE mapping = open_section(name);
    if (!mapping) return 2;
    ResumeState* state = map_state(mapping);
    if (!state) { CloseHandle(mapping); return 3; }

    HANDLE thread1 = nullptr;
    HANDLE thread2 = nullptr;
    const auto cleanup = [&]() {
        if (thread1) CloseHandle(thread1);
        if (thread2) CloseHandle(thread2);
        UnmapViewOfFile(state);
        CloseHandle(mapping);
    };
    while (!state->ready && !state->stop) Sleep(5);
    if (!state->ready) { cleanup(); return 4; }

    const DWORD access = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
        THREAD_SUSPEND_RESUME | SYNCHRONIZE;
    thread1 = OpenThread(access, FALSE, static_cast<DWORD>(state->tid1));
    thread2 = OpenThread(access, FALSE, static_cast<DWORD>(state->tid2));
    if (!thread1 || !thread2) { cleanup(); return 5; }
    state->aPid = GetCurrentProcessId();
    state->aCreation = process_creation(GetCurrentProcess());
    printf("{\"role\":\"a\",\"stage\":\"waiting\",\"pid\":%lu,\"creation\":%llu,"
           "\"targetPid\":%llu,\"targetCreation\":%llu,\"tid1\":%llu,\"tid2\":%llu,"
           "\"threadCreation1\":%llu,\"threadCreation2\":%llu,\"access\":%lu}\n",
        GetCurrentProcessId(), state->aCreation, static_cast<unsigned long long>(state->fPid),
        static_cast<unsigned long long>(state->fCreation), static_cast<unsigned long long>(state->tid1),
        static_cast<unsigned long long>(state->tid2), static_cast<unsigned long long>(state->threadCreation1),
        static_cast<unsigned long long>(state->threadCreation2), access);
    fflush(stdout);

    const ULONGLONG deadline = GetTickCount64() + 300000ULL;
    while (!state->goWin32 && !state->stop && GetTickCount64() < deadline) Sleep(5);
    if (state->goWin32) {
        SetLastError(0);
        const DWORD previous = ResumeThread(thread1);
        const DWORD error = GetLastError();
        state->win32Result = static_cast<LONG>(previous);
        state->win32Previous = previous == static_cast<DWORD>(-1) ? -1 : static_cast<LONG>(previous);
        state->win32LastError = static_cast<LONG>(error);
        printf("{\"role\":\"a\",\"stage\":\"resume-win32\",\"api\":\"ResumeThread\","
               "\"previous\":%lu,\"lastError\":%lu}\n", previous, error);
        fflush(stdout);
    }

    while (!state->goNt && !state->stop && GetTickCount64() < deadline) Sleep(5);
    if (state->goNt) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        NtResumeThreadFn ntResume = ntdll ? reinterpret_cast<NtResumeThreadFn>(
            GetProcAddress(ntdll, "NtResumeThread")) : nullptr;
        if (!ntResume) { cleanup(); return 6; }
        ULONG previous = 0xFFFFFFFFu;
        SetLastError(0);
        const NTSTATUS status = ntResume(thread2, &previous);
        const DWORD error = GetLastError();
        state->ntStatus = status;
        state->ntPrevious = static_cast<LONG>(previous);
        state->ntLastError = static_cast<LONG>(error);
        printf("{\"role\":\"a\",\"stage\":\"resume-nt\",\"api\":\"NtResumeThread\","
               "\"module\":\"ntdll.dll\",\"status\":%ld,\"previous\":%lu,\"lastError\":%lu}\n",
            static_cast<long>(status), previous, error);
        fflush(stdout);
    }
    while (!state->stop && GetTickCount64() < deadline) Sleep(10);
    cleanup();
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3) return 1;
    if (wcscmp(argv[1], L"f") == 0) return run_f(argv[2]);
    if (wcscmp(argv[1], L"a") == 0) return run_a(argv[2]);
    return 1;
}
