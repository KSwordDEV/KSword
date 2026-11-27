/* Owned x64 fixture for the "456" continuous hand-off chain: A -> B -> C.
 *
 * One image, three roles:
 *   a <section>  owned x64 SOURCE.  Reports identity, waits for the driver's
 *                goHop1 flag (set only AFTER real Agent Ready), then issues ONE
 *                real NtQueueApcThreadEx into B's own private executable page.
 *                A never sees, arms or dispatches block2 or a launcher.
 *   b <section>  TAKEN-OVER B.  Allocates two committed private RX/RWX blocks:
 *                block1 and block2.  A short private trampoline in block1 calls
 *                the exported AA_OnBlock1 -> AA_HopToC, which issues a real
 *                cross-process NtQueueApcThreadEx to C's private stub.  Then, in
 *                that SAME exported routine, B itself calls CreateThread with
 *                block2 as the direct entry (no A pre-arm, no launcher stub).
 *                This exercises the product's same-process CreateThread private
 *                entry take-over and appended-range / new-thread admission.
 *   c <section>  NEXT TARGET C.  Publishes one committed private RX/RWX stub
 *                address.  Its entry is dispatched by B (not by Python) and the
 *                product auto-resolves C's private range; the CLI is never
 *                passed this address.
 *
 * The fixture never loads the product Agent itself, never joins a cooperative
 * session, and never touches a process it does not own.  Built into the fixed
 * IntDir tools/action_analyze_validation/api_handoff_chain/obj/Release and the
 * unified Ksword5.1/x64/Release output.  The driver does not build or run it
 * unless invoked with --execute.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NTAPI
#define NTAPI __cdecl
#endif

typedef NTSTATUS (NTAPI * NtQueueApcThreadExFn)(HANDLE thread, HANDLE reserve,
    PVOID routine, PVOID arg1, PVOID arg2, PVOID arg3);

/* Mirrored exactly by ChainState in run_api_handoff_chain.py. */
typedef struct {
    volatile LONG goHop1;          /* A may dispatch hop1 into B block1. */
    volatile LONG resultHop1;      /* NTSTATUS of A -> B block1. */
    volatile LONG resultHopC;      /* NTSTATUS of B -> C (issued by B itself). */
    volatile LONG counterB1;       /* side effect of B block1. */
    volatile LONG counterB2;       /* side effect of B block2 on the NEW thread. */
    volatile LONG counterC;        /* side effect of C stub. */
    volatile LONG stubRanB1;
    volatile LONG stubRanB2;
    volatile LONG stubRanC;
    volatile LONG newThreadB;      /* tid of the thread B created for block2. */
    volatile LONG stop;            /* 1: all roles exit normally through main(). */
    volatile LONG pad;
    volatile LONG64 block1B;       /* B publishes. */
    volatile LONG64 block2B;       /* B publishes. */
    volatile LONG64 threadB;       /* B main thread handle duplicated into A. */
    volatile LONG64 stubC;         /* C publishes. */
    volatile LONG64 threadC;       /* C main thread handle duplicated into B. */
} ChainState;

static volatile LONG g_counterB1 = 0;
static volatile LONG g_counterB2 = 0;
static volatile LONG g_counterC = 0;
static volatile LONG g_secondLaunched = 0;
static ChainState * g_state = NULL;

static unsigned long long creation_time(void)
{
    FILETIME created = {0}, exited = {0}, kernel = {0}, user = {0};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 0;
    return ((unsigned long long)created.dwHighDateTime << 32) | created.dwLowDateTime;
}

static HANDLE open_section(const wchar_t * name)
{
    HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (mapping == NULL)
        fprintf(stderr, "{\"error\":\"open-section\",\"win32Error\":%lu}\n", GetLastError());
    return mapping;
}

static NtQueueApcThreadExFn resolve_queue(void)
{
    static NtQueueApcThreadExFn cached = NULL;
    if (cached == NULL)
        cached = (NtQueueApcThreadExFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
            "NtQueueApcThreadEx");
    return cached;
}

/* Short private trampoline: sub rsp,0x28; mov rax,<fn>; call rax; add rsp,0x28; ret */
static void emit_call_stub(unsigned char * page, void * fn)
{
    unsigned long long addr = (unsigned long long)(ULONG_PTR)fn;
    unsigned char code[21] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    for (int index = 0; index < 8; ++index)
        code[6 + index] = (unsigned char)(addr >> (index * 8));
    memcpy(page, code, sizeof(code));
}

static unsigned char * alloc_stub(void)
{
    return (unsigned char *)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
}

/* ---- exported routines reached ONLY through a short private trampoline ---- */

extern "C" __declspec(dllexport) void AA_HopToC(void)
{
    if (g_state == NULL) return;
    NtQueueApcThreadExFn queue = resolve_queue();
    if (queue == NULL) {
        fprintf(stderr, "{\"error\":\"resolve-ntqueueapcthreadex\"}\n");
        return;
    }
    HANDLE thread = (HANDLE)(ULONG_PTR)g_state->threadC;
    PVOID stub = (PVOID)(ULONG_PTR)g_state->stubC;
    NTSTATUS status = queue(thread, NULL, stub, (PVOID)(ULONG_PTR)0x43524143ULL, NULL, NULL);
    g_state->resultHopC = (LONG)status;
    printf("{\"role\":\"b\",\"stage\":\"hop-b-to-c\",\"pid\":%lu,\"tid\":%lu,"
           "\"status\":%ld,\"stubC\":%llu}\n",
           (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(),
           (long)status, (unsigned long long)g_state->stubC);
    fflush(stdout);
}

extern "C" __declspec(dllexport) void AA_OnBlock1(void)
{
    InterlockedIncrement(&g_counterB1);
    if (g_state != NULL) {
        /* Publish the shared counter as well: the driver hand-shakes on the
         * shared memory counters, while the local counter stays an
         * independent local assertion of this routine. */
        InterlockedIncrement(&g_state->counterB1);
        g_state->stubRanB1 = 1;
    }
    printf("{\"role\":\"b\",\"stage\":\"hop1-entered\",\"pid\":%lu,\"tid\":%lu,\"counter\":%ld}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), g_counterB1);
    fflush(stdout);

    /* The real second hop is issued by B's own code, never by the driver. */
    AA_HopToC();

    /* The second private range is launched by B's OWN CreateThread, with block2
     * as the direct entry.  A never pre-arms block2 and no launcher is used. */
    if (g_state != NULL && InterlockedCompareExchange(&g_secondLaunched, 1, 0) == 0) {
        DWORD tid = 0;
        HANDLE thread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)(ULONG_PTR)g_state->block2B, NULL, 0, &tid);
        printf("{\"role\":\"b\",\"stage\":\"launch-second-thread\",\"pid\":%lu,\"tid\":%lu,"
               "\"created\":%s,\"newTid\":%lu,\"entry\":%llu}\n",
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(),
               thread ? "true" : "false", (unsigned long)tid,
               (unsigned long long)g_state->block2B);
        fflush(stdout);
        if (thread != NULL) CloseHandle(thread);
    }
}

extern "C" __declspec(dllexport) void AA_OnBlock2(void)
{
    InterlockedIncrement(&g_counterB2);
    if (g_state != NULL) {
        InterlockedIncrement(&g_state->counterB2);
        g_state->stubRanB2 = 1;
        g_state->newThreadB = (LONG)GetCurrentThreadId();
    }
    printf("{\"role\":\"b\",\"stage\":\"second-range-entered\",\"pid\":%lu,\"tid\":%lu,\"counter\":%ld}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), g_counterB2);
    fflush(stdout);
}

extern "C" __declspec(dllexport) void AA_OnCEntry(void)
{
    InterlockedIncrement(&g_counterC);
    if (g_state != NULL) {
        InterlockedIncrement(&g_state->counterC);
        g_state->stubRanC = 1;
    }
    printf("{\"role\":\"c\",\"stage\":\"hop2-entered\",\"pid\":%lu,\"tid\":%lu,\"counter\":%ld}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), g_counterC);
    fflush(stdout);
}

/* ---- roles ---- */

static int run_b(const wchar_t * name)
{
    HANDLE mapping = open_section(name);
    if (mapping == NULL) return 2;
    ChainState * state = (ChainState *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ChainState));
    if (state == NULL) { fprintf(stderr, "{\"error\":\"map-section\"}\n"); CloseHandle(mapping); return 3; }
    g_state = state;

    unsigned char * block1 = alloc_stub();
    unsigned char * block2 = alloc_stub();
    if (block1 == NULL || block2 == NULL) {
        fprintf(stderr, "{\"error\":\"allocate-blocks\"}\n"); return 4;
    }
    emit_call_stub(block1, (void *)&AA_OnBlock1);
    emit_call_stub(block2, (void *)&AA_OnBlock2);

    state->block1B = (LONGLONG)(ULONG_PTR)block1;
    state->block2B = (LONGLONG)(ULONG_PTR)block2;
    state->stubRanB1 = state->stubRanB2 = 0;

    printf("{\"role\":\"b\",\"stage\":\"waiting\",\"pid\":%lu,\"tid\":%lu,"
           "\"creation\":%llu,\"block1\":%llu,\"block2\":%llu}\n",
           (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), creation_time(),
           (unsigned long long)(ULONG_PTR)block1, (unsigned long long)(ULONG_PTR)block2);
    fflush(stdout);

    const ULONGLONG deadline = GetTickCount64() + 150000ULL;
    while (GetTickCount64() < deadline) {
        if (state->stop) break;
        SleepEx(20, TRUE);
    }
    printf("{\"role\":\"b\",\"stage\":\"final\",\"stubRan\":%s,\"counter1\":%ld,"
           "\"counter2\":%ld,\"newThreadB\":%ld,\"exit\":0,\"pid\":%lu,\"creation\":%llu}\n",
           (state->stubRanB1 && state->stubRanB2) ? "true" : "false",
           g_counterB1, g_counterB2, state->newThreadB,
           (unsigned long)GetCurrentProcessId(), creation_time());
    fflush(stdout);
    return 0;
}

static int run_c(const wchar_t * name)
{
    HANDLE mapping = open_section(name);
    if (mapping == NULL) return 2;
    ChainState * state = (ChainState *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ChainState));
    if (state == NULL) { fprintf(stderr, "{\"error\":\"map-section\"}\n"); CloseHandle(mapping); return 3; }
    g_state = state;

    unsigned char * stub = alloc_stub();
    if (stub == NULL) { fprintf(stderr, "{\"error\":\"allocate-stub\"}\n"); return 4; }
    emit_call_stub(stub, (void *)&AA_OnCEntry);
    state->stubC = (LONGLONG)(ULONG_PTR)stub;
    state->stubRanC = 0;

    printf("{\"role\":\"c\",\"stage\":\"waiting\",\"pid\":%lu,\"tid\":%lu,"
           "\"creation\":%llu,\"stub\":%llu}\n",
           (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(),
           creation_time(), (unsigned long long)(ULONG_PTR)stub);
    fflush(stdout);

    const ULONGLONG deadline = GetTickCount64() + 150000ULL;
    while (GetTickCount64() < deadline) {
        if (state->stop) break;
        SleepEx(20, TRUE);
    }
    printf("{\"role\":\"c\",\"stage\":\"final\",\"stubRan\":%s,\"counter\":%ld,"
           "\"exit\":0,\"pid\":%lu,\"creation\":%llu}\n",
           state->stubRanC ? "true" : "false", g_counterC,
           (unsigned long)GetCurrentProcessId(), creation_time());
    fflush(stdout);
    return 0;
}

static int run_a(const wchar_t * name)
{
    HANDLE mapping = open_section(name);
    if (mapping == NULL) return 2;
    ChainState * state = (ChainState *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ChainState));
    if (state == NULL) { fprintf(stderr, "{\"error\":\"map-section\"}\n"); CloseHandle(mapping); return 3; }
    g_state = state;

    NtQueueApcThreadExFn queue = resolve_queue();
    if (queue == NULL) { fprintf(stderr, "{\"error\":\"resolve-ntqueueapcthreadex\"}\n"); return 5; }

    printf("{\"role\":\"a\",\"stage\":\"waiting\",\"pid\":%lu,\"tid\":%lu,\"creation\":%llu}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), creation_time());
    fflush(stdout);

    /* A only ever dispatches block1.  It never arms block2 and has no launcher. */
    const ULONGLONG wait1 = GetTickCount64() + 120000ULL;
    while (GetTickCount64() < wait1 && state->goHop1 == 0 && state->stop == 0) Sleep(10);
    if (state->goHop1) {
        HANDLE threadB = (HANDLE)(ULONG_PTR)state->threadB;
        PVOID routine = (PVOID)(ULONG_PTR)state->block1B;
        NTSTATUS status = queue(threadB, NULL, routine, (PVOID)(ULONG_PTR)0x41424344ULL, NULL, NULL);
        state->resultHop1 = (LONG)status;
        printf("{\"role\":\"a\",\"stage\":\"hop1-dispatched\",\"pid\":%lu,\"tid\":%lu,"
               "\"status\":%ld,\"routine\":%llu}\n",
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(),
               (long)status, (unsigned long long)(ULONG_PTR)routine);
        fflush(stdout);
    }

    const ULONGLONG hold = GetTickCount64() + 60000ULL;
    while (GetTickCount64() < hold && state->stop == 0) Sleep(20);
    printf("{\"role\":\"a\",\"stage\":\"final\",\"resultHop1\":%ld,"
           "\"exit\":0,\"pid\":%lu,\"creation\":%llu}\n",
           state->resultHop1,
           (unsigned long)GetCurrentProcessId(), creation_time());
    fflush(stdout);
    return 0;
}

int wmain(int argc, wchar_t ** argv)
{
    if (argc < 3) { fprintf(stderr, "{\"error\":\"usage\"}\n"); return 1; }
    if (wcscmp(argv[1], L"a") == 0) return run_a(argv[2]);
    if (wcscmp(argv[1], L"b") == 0) return run_b(argv[2]);
    if (wcscmp(argv[1], L"c") == 0) return run_c(argv[2]);
    fprintf(stderr, "{\"error\":\"unknown-role\"}\n");
    return 1;
}
