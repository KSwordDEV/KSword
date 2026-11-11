#include "shared/WinApiMonitorProtocol.h"
#include <iostream>

int main()
{
    std::wstring sid;
    if (!ks::winapi_monitor::currentProcessUserSidString(&sid)) return 1;
    const auto name = L"Global\\KswordPauseFixture_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64());
    DWORD error = 0;
    HANDLE controller = ks::winapi_monitor::createPauseEvent(name, sid, false, &error);
    if (!controller) { std::cerr << "create error=" << error << '\n'; return 2; }
    HANDLE observer = OpenEventW(SYNCHRONIZE, FALSE, name.c_str());
    if (!observer || WaitForSingleObject(observer, 0) != WAIT_TIMEOUT) return 3;
    if (SetEvent(observer) || GetLastError() != ERROR_ACCESS_DENIED) return 4;
    if (!SetEvent(controller) || WaitForSingleObject(observer, 0) != WAIT_OBJECT_0) return 5;
    if (!ResetEvent(controller) || WaitForSingleObject(observer, 0) != WAIT_TIMEOUT) return 6;
    HANDLE collision = ks::winapi_monitor::createPauseEvent(name, sid, false, &error);
    if (collision || error != ERROR_ALREADY_EXISTS) return 7;
    CloseHandle(observer); CloseHandle(controller);
    std::cout << "PASS: pause control event, observer access and collision handling\n";
    return 0;
}
