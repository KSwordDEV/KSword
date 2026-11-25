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

int wmain(void)
{
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
        result = 0;
        for (unsigned i = 0; i < 132; ++i) {
            if (WaitForSingleObject(trigger, 20000) != WAIT_OBJECT_0 || !ExportedTick(done)) {
                result = 3;
                break;
            }
        }
    }
    if (done) CloseHandle(done);
    if (trigger) CloseHandle(trigger);
    if (ready) CloseHandle(ready);
    return result;
}
