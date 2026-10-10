#include <Windows.h>
extern "C" __declspec(dllexport) DWORD WINAPI FixtureModuleWorker(void* context) {
    auto* counter = static_cast<LONG64*>(context);
    for (;;) {InterlockedIncrement64(counter);Sleep(50);}
}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID) {return TRUE;}
