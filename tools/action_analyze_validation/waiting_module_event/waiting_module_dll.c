#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG g_counter;

__declspec(dllexport) LONG WINAPI WaitingModuleEntry(void)
{
    return InterlockedIncrement(&g_counter);
}
