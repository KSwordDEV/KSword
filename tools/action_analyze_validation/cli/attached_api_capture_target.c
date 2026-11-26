/* Owned x64 acceptance target for explicit R3 attachment.
 *
 * This target never loads the product Agent by itself, never opts into the
 * cooperative session directory and never sets
 * KSWORD_APIMON_COOPERATIVE_SESSION_V1. The Release CLI must attach to this
 * exact process instance and load APIMonitor_x64.dll on its behalf.
 *
 * It keeps issuing real local API calls so the attached Agent has something to
 * observe: KernelBase!WriteProcessMemory into its own buffer plus an occasional
 * ReadProcessMemory query.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define STOP_EVENT_ENV L"KSWORD_ATTACHED_VALIDATION_STOP"

int main(int argc, char* argv[])
{
    int hold_seconds = argc > 1 ? atoi(argv[1]) : 20;
    if (hold_seconds <= 0 || hold_seconds > 600) hold_seconds = 20;

    FILETIME created = {0};
    FILETIME exited = {0};
    FILETIME kernel = {0};
    FILETIME user = {0};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 2;
    const unsigned long long creation =
        ((unsigned long long)created.dwHighDateTime << 32) | created.dwLowDateTime;

    HANDLE stop_event = NULL;
    {
        wchar_t name[256];
        const DWORD size = GetEnvironmentVariableW(STOP_EVENT_ENV, name, 256);
        if (size > 0 && size < 256) stop_event = OpenEventW(SYNCHRONIZE, FALSE, name);
    }

    char buffer[4096] = {0};
    const char byte = 'Z';
    SIZE_T written = 0;
    printf("{\"pid\":%lu,\"tid\":%lu,\"creation\":%llu}\n",
        (unsigned long)GetCurrentProcessId(), (unsigned long)GetCurrentThreadId(), creation);
    fflush(stdout);

    const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)hold_seconds * 1000ULL;
    unsigned long calls = 0;
    while (GetTickCount64() < deadline) {
        if (!WriteProcessMemory(GetCurrentProcess(), buffer + (calls % (sizeof(buffer) - 1)),
                &byte, 1, &written) || written != 1) {
            break;
        }
        if ((calls % 8UL) == 0UL) {
            DWORD probe = 0;
            SIZE_T received = 0;
            (void)ReadProcessMemory(GetCurrentProcess(), buffer, &probe, sizeof(probe), &received);
        }
        ++calls;
        if (stop_event != NULL && WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) break;
        Sleep(20);
    }
    if (stop_event != NULL) CloseHandle(stop_event);
    printf("{\"calls\":%lu,\"agentLoaded\":%s}\n", calls,
        GetModuleHandleW(L"APIMonitor_x64.dll") != NULL ? "true" : "false");
    fflush(stdout);
    return 0;
}
