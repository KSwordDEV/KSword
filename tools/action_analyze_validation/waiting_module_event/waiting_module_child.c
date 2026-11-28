#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef LONG (WINAPI *WAITING_MODULE_ENTRY)(void);

static HANDLE OpenFixtureEvent(const wchar_t* prefix, const wchar_t* suffix, DWORD access)
{
    wchar_t name[160];
    if (swprintf_s(name, _countof(name), L"%ls-%ls", prefix, suffix) < 0) return NULL;
    return OpenEventW(access, FALSE, name);
}

int wmain(void)
{
    wchar_t prefix[96], modulePath[MAX_PATH], resultPath[MAX_PATH];
    const DWORD prefixLength = GetEnvironmentVariableW(L"KSWORD_WAITING_MODULE_EVENTS", prefix, _countof(prefix));
    const DWORD moduleLength = GetEnvironmentVariableW(L"KSWORD_WAITING_MODULE_PATH", modulePath, _countof(modulePath));
    const DWORD resultLength = GetEnvironmentVariableW(L"KSWORD_WAITING_MODULE_RESULT", resultPath, _countof(resultPath));
    if (!prefixLength || prefixLength >= _countof(prefix) || !moduleLength || moduleLength >= _countof(modulePath) ||
        !resultLength || resultLength >= _countof(resultPath)) return 2;

    HANDLE ready = OpenFixtureEvent(prefix, L"ready", EVENT_MODIFY_STATE);
    HANDLE load = OpenFixtureEvent(prefix, L"load", SYNCHRONIZE);
    HANDLE completed = OpenFixtureEvent(prefix, L"completed", EVENT_MODIFY_STATE);
    HANDLE release = OpenFixtureEvent(prefix, L"release", SYNCHRONIZE);
    if (!ready || !load || !completed || !release || !SetEvent(ready)) return 3;
    if (WaitForSingleObject(load, 20000) != WAIT_OBJECT_0) return 4;

    HMODULE module = LoadLibraryW(modulePath);
    if (!module) return 5;
    WAITING_MODULE_ENTRY entry = (WAITING_MODULE_ENTRY)GetProcAddress(module, "WaitingModuleEntry");
    if (!entry) return 6;
    const LONG count = entry();
    HANDLE result = CreateFileW(resultPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (result == INVALID_HANDLE_VALUE) return 7;
    char text[32];
    const int length = sprintf_s(text, sizeof(text), "%ld\n", count);
    DWORD written = 0;
    const BOOL saved = length > 0 && WriteFile(result, text, (DWORD)length, &written, NULL) && written == (DWORD)length;
    CloseHandle(result);
    if (!saved || !SetEvent(completed)) return 8;
    if (WaitForSingleObject(release, 20000) != WAIT_OBJECT_0) return 10;
    FreeLibrary(module);
    CloseHandle(release);
    CloseHandle(completed);
    CloseHandle(load);
    CloseHandle(ready);
    return count == 1 ? 0 : 9;
}
