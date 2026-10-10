#include <Windows.h>
#include <cwchar>
#include "ThreadFixture.h"
#include "ModuleFixtureHost.h"
#include "HotkeyFixture.h"
#include "WindowFixture.h"
#include "EtwFixture.h"

namespace {
SERVICE_STATUS_HANDLE statusHandle;
HANDLE stopEvent;
void publish(DWORD state) {
    SERVICE_STATUS status{};
    status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState=state;
    status.dwControlsAccepted=state==SERVICE_RUNNING || state==SERVICE_PAUSED ? SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_PAUSE_CONTINUE : 0;
    status.dwWaitHint=state==SERVICE_STOP_PENDING ? 5000 : 0;
    SetServiceStatus(statusHandle,&status);
}
void WINAPI control(DWORD action) {
    if(action==SERVICE_CONTROL_STOP) {publish(SERVICE_STOP_PENDING);SetEvent(stopEvent);}
    else if(action==SERVICE_CONTROL_PAUSE) publish(SERVICE_PAUSED);
    else if(action==SERVICE_CONTROL_CONTINUE) publish(SERVICE_RUNNING);
}
void WINAPI serviceMain(DWORD count,LPWSTR* args) {
    stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    statusHandle=RegisterServiceCtrlHandlerW(count ? args[0] : L"KswordCliFixture",control);
    if(!statusHandle || !stopEvent) {if(stopEvent)CloseHandle(stopEvent);return;}
    publish(SERVICE_RUNNING);
    WaitForSingleObject(stopEvent,INFINITE);
    publish(SERVICE_STOPPED);
    CloseHandle(stopEvent);
}
}
int wmain(int argc,wchar_t* argv[]) {
    if(argc==3 && std::wcscmp(argv[1],L"--etw")==0) return RunEtwFixture(argv[2]);
    if(argc==3 && std::wcscmp(argv[1],L"--windows-hierarchy")==0) return RunWindowFixture(argv[2],false,false,true);
    if(argc==3 && std::wcscmp(argv[1],L"--windows")==0) return RunWindowFixture(argv[2],false,false);
    if(argc==3 && std::wcscmp(argv[1],L"--windows-ignore-close")==0) return RunWindowFixture(argv[2],true,false);
    if(argc==3 && std::wcscmp(argv[1],L"--windows-hung")==0) return RunWindowFixture(argv[2],false,true);
    if(argc==3 && std::wcscmp(argv[1],L"--hotkeys")==0) return RunHotkeyFixture(argv[2],false);
    if(argc==3 && std::wcscmp(argv[1],L"--hotkeys-hung")==0) return RunHotkeyFixture(argv[2],true);
    if(argc==4 && std::wcscmp(argv[1],L"--modules")==0) return RunModuleFixture(argv[2],argv[3]);
    if(argc==3 && std::wcscmp(argv[1],L"--threads")==0) return RunThreadFixture(argv[2]);
    if(argc!=2 || std::wcscmp(argv[1],L"--service")!=0) return ERROR_INVALID_PARAMETER;
    SERVICE_TABLE_ENTRYW table[]={{const_cast<LPWSTR>(L"KswordCliFixture"),serviceMain},{nullptr,nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : static_cast<int>(GetLastError());
}
