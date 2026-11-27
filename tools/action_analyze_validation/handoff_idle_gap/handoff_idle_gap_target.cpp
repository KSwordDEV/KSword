/* Owned x64 fixture for the "hand-off idle gap" scenario: A -> B, B dies, gap, A -> C.
 *
 * One image, three roles, but B and C are INDEPENDENT process creations:
 *   a  owned x64 SOURCE that stays alive for the whole run.  It waits for goHop1,
 *      issues ONE real NtQueueApcThreadEx into B's private executable stub, then
 *      waits for goHop2 and issues a SECOND real NtQueueApcThreadEx into C's
 *      private stub.  Both addresses are resolved by the product; the CLI is
 *      never passed either address.
 *   b  taken-over target B.  Allocates ONE committed private RWX stub and
 *      publishes its address.  Its stub sets stubRanB, then B's main loop returns
 *      from the alertable wait and exits naturally with code 0.
 *   c  taken-over target C, created only AFTER the driver has confirmed B exited
 *      and an idle gap of at least 500 ms has elapsed.  Same shape as B.
 *
 * The fixture never loads the product Agent itself and never touches a process
 * it does not own.  Built into the fixed IntDir tools/action_analyze_validation/
 * handoff_idle_gap/obj/Release and the unified Ksword5.1/x64/Release output.
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

/* Mirrored exactly by GapState in run_handoff_idle_gap.py. */
typedef struct {
    volatile LONG goHop1;          /* A may dispatch hop1 into B's stub. */
    volatile LONG goHop2;          /* A may dispatch hop2 into C's stub. */
    volatile LONG resultHop1;      /* NTSTATUS of A -> B. */
    volatile LONG resultHop2;      /* NTSTATUS of A -> C. */
    volatile LONG stubRanB;        /* B's stub executed. */
    volatile LONG stubRanC;        /* C's stub executed. */
    volatile LONG counterB;        /* B stub side effect count. */
    volatile LONG counterC;        /* C stub side effect count. */
    volatile LONG stop;            /* 1: A exits normally through main(). */
    volatile LONG pad;
    volatile LONG64 stubB;         /* B publishes. */
    volatile LONG64 threadB;       /* B main thread handle duplicated into A. */
    volatile LONG64 stubC;         /* C publishes. */
    volatile LONG64 threadC;       /* C main thread handle duplicated into A. */
} GapState;

static volatile LONG g_counter = 0;
static GapState * g_state = NULL;

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

/* sub rsp,0x28; mov rax,<fn>; call rax; add rsp,0x28; ret */
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

/* Reached ONLY through the short private trampoline. */
extern "C" __declspec(dllexport) void AA_OnBEntry(void)
{
    InterlockedIncrement(&g_counter);
    if (g_state != NULL) {
        InterlockedIncrement(&g_state->counterB);
        g_state->stubRanB = 1;
    }
    printf("{\"role\":\"b\",\"stage\":\"stub-entered\",\"pid\":%lu,\"tid\":%lu,\"counter\":%ld}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), g_counter);
    fflush(stdout);
}

extern "C" __declspec(dllexport) void AA_OnCEntry(void)
{
    InterlockedIncrement(&g_counter);
    if (g_state != NULL) {
        InterlockedIncrement(&g_state->counterC);
        g_state->stubRanC = 1;
    }
    printf("{\"role\":\"c\",\"stage\":\"stub-entered\",\"pid\":%lu,\"tid\":%lu,\"counter\":%ld}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), g_counter);
    fflush(stdout);
}

static int run_target(const wchar_t * name, const char * role)
{
    HANDLE mapping = open_section(name);
    if (mapping == NULL) return 2;
    GapState * state = (GapState *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GapState));
    if (state == NULL) { fprintf(stderr, "{\"error\":\"map-section\"}\n"); CloseHandle(mapping); return 3; }
    g_state = state;

    unsigned char * stub = alloc_stub();
    if (stub == NULL) { fprintf(stderr, "{\"error\":\"allocate-stub\"}\n"); return 4; }
    if (strcmp(role, "b") == 0) {
        emit_call_stub(stub, (void *)&AA_OnBEntry);
        state->stubB = (LONGLONG)(ULONG_PTR)stub;
        state->stubRanB = 0;
    } else {
        emit_call_stub(stub, (void *)&AA_OnCEntry);
        state->stubC = (LONGLONG)(ULONG_PTR)stub;
        state->stubRanC = 0;
    }

    printf("{\"role\":\"%s\",\"stage\":\"waiting\",\"pid\":%lu,\"tid\":%lu,"
           "\"creation\":%llu,\"stub\":%llu}\n",
           role, (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(),
           creation_time(), (unsigned long long)(ULONG_PTR)stub);
    fflush(stdout);

    const ULONGLONG deadline = GetTickCount64() + 120000ULL;
    while (GetTickCount64() < deadline) {
        LONG ran = (strcmp(role, "b") == 0) ? state->stubRanB : state->stubRanC;
        if (ran || state->stop) break;
        SleepEx(10, TRUE);
    }
    LONG ran = (strcmp(role, "b") == 0) ? state->stubRanB : state->stubRanC;
    printf("{\"role\":\"%s\",\"stage\":\"final\",\"stubRan\":%s,\"counter\":%ld,"
           "\"exit\":0,\"pid\":%lu,\"creation\":%llu}\n",
           role, ran ? "true" : "false", g_counter,
           (unsigned long)GetCurrentProcessId(), creation_time());
    fflush(stdout);
    return 0;
}

static int run_a(const wchar_t * name)
{
    HANDLE mapping = open_section(name);
    if (mapping == NULL) return 2;
    GapState * state = (GapState *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GapState));
    if (state == NULL) { fprintf(stderr, "{\"error\":\"map-section\"}\n"); CloseHandle(mapping); return 3; }
    g_state = state;

    NtQueueApcThreadExFn queue = resolve_queue();
    if (queue == NULL) { fprintf(stderr, "{\"error\":\"resolve-ntqueueapcthreadex\"}\n"); return 5; }

    printf("{\"role\":\"a\",\"stage\":\"waiting\",\"pid\":%lu,\"tid\":%lu,\"creation\":%llu}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), creation_time());
    fflush(stdout);

    int did1 = 0, did2 = 0;
    const ULONGLONG deadline = GetTickCount64() + 120000ULL;
    while (GetTickCount64() < deadline && state->stop == 0) {
        if (!did1 && state->goHop1) {
            HANDLE threadB = (HANDLE)(ULONG_PTR)state->threadB;
            PVOID routine = (PVOID)(ULONG_PTR)state->stubB;
            NTSTATUS status = queue(threadB, NULL, routine, (PVOID)(ULONG_PTR)0x42424242ULL, NULL, NULL);
            state->resultHop1 = (LONG)status;
            did1 = 1;
            printf("{\"role\":\"a\",\"stage\":\"hop1-dispatched\",\"pid\":%lu,\"tid\":%lu,"
                   "\"status\":%ld,\"routine\":%llu}\n",
                   (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(),
                   (long)status, (unsigned long long)(ULONG_PTR)routine);
            fflush(stdout);
        }
        if (!did2 && state->goHop2) {
            HANDLE threadC = (HANDLE)(ULONG_PTR)state->threadC;
            PVOID routine = (PVOID)(ULONG_PTR)state->stubC;
            NTSTATUS status = queue(threadC, NULL, routine, (PVOID)(ULONG_PTR)0x43434343ULL, NULL, NULL);
            state->resultHop2 = (LONG)status;
            did2 = 1;
            printf("{\"role\":\"a\",\"stage\":\"hop2-dispatched\",\"pid\":%lu,\"tid\":%lu,"
                   "\"status\":%ld,\"routine\":%llu}\n",
                   (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(),
                   (long)status, (unsigned long long)(ULONG_PTR)routine);
            fflush(stdout);
        }
        Sleep(5);
    }
    printf("{\"role\":\"a\",\"stage\":\"final\",\"resultHop1\":%ld,\"resultHop2\":%ld,"
           "\"exit\":0,\"pid\":%lu,\"creation\":%llu}\n",
           state->resultHop1, state->resultHop2,
           (unsigned long)GetCurrentProcessId(), creation_time());
    fflush(stdout);
    return 0;
}

int wmain(int argc, wchar_t ** argv)
{
    if (argc < 3) { fprintf(stderr, "{\"error\":\"usage\"}\n"); return 1; }
    if (wcscmp(argv[1], L"a") == 0) return run_a(argv[2]);
    if (wcscmp(argv[1], L"b") == 0) return run_target(argv[2], "b");
    if (wcscmp(argv[1], L"c") == 0) return run_target(argv[2], "c");
    fprintf(stderr, "{\"error\":\"unknown-role\"}\n");
    return 1;
}
