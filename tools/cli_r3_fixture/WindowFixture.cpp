#include "WindowFixture.h"
#include <Windows.h>
#include <cstdint>
#include <sstream>
#include <string>
namespace {
HWND mainWindow=nullptr,hungWindow=nullptr;
DWORD hungTid=0,closeMessages=0;
std::wstring statePath;
bool ignoreClose=false;
std::uint64_t created(HANDLE handle,bool thread){FILETIME creation{},exit{},kernel{},user{};
    if(!(thread?GetThreadTimes(handle,&creation,&exit,&kernel,&user):GetProcessTimes(handle,&creation,&exit,&kernel,&user)))return 0;
    return static_cast<std::uint64_t>(creation.dwHighDateTime)<<32|creation.dwLowDateTime;}
void state(){
    if(!mainWindow||statePath.empty())return;
    const auto thread=hungTid?OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,hungTid):nullptr;
    const auto threadTime=thread?created(thread,true):0;if(thread)CloseHandle(thread);
    const auto primaryTid=GetWindowThreadProcessId(mainWindow,nullptr);const auto primary=OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,primaryTid);
    const auto primaryTime=primary?created(primary,true):0;if(primary)CloseHandle(primary);
    std::ostringstream out;out<<"{\"pid\":"<<GetCurrentProcessId()<<",\"tid\":"<<primaryTid<<",\"hwnd\":\"0x"<<std::hex<<reinterpret_cast<std::uintptr_t>(mainWindow)
        <<"\",\"hungWindow\":\"0x"<<reinterpret_cast<std::uintptr_t>(hungWindow)<<std::dec<<"\",\"hungTid\":"<<hungTid
        <<",\"processCreationTime\":\""<<created(GetCurrentProcess(),false)<<"\",\"threadCreationTime\":\""<<primaryTime
        <<"\",\"hungThreadCreationTime\":\""<<threadTime<<"\",\"closeMessages\":"<<closeMessages<<'}';
    const auto bytes=out.str();const auto temporary=statePath+L"."+std::to_wstring(GetCurrentThreadId())+L".tmp";
    const auto file=CreateFileW(temporary.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return;DWORD written=0;const bool ok=WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)&&written==bytes.size();CloseHandle(file);
    if(ok)MoveFileExW(temporary.c_str(),statePath.c_str(),MOVEFILE_REPLACE_EXISTING);
}
LRESULT CALLBACK procedure(HWND hwnd,UINT message,WPARAM w,LPARAM l){
    if(message==WM_CLOSE){++closeMessages;state();if(ignoreClose)return 0;}
    if(message==WM_SIZE)state();
    if(message==WM_DESTROY){if(hwnd==mainWindow)PostQuitMessage(0);return 0;}
    return DefWindowProcW(hwnd,message,w,l);
}
DWORD WINAPI stalled(void* event){hungTid=GetCurrentThreadId();hungWindow=CreateWindowExW(0,L"KswordCliWindowFixture",L"Unresponsive fixture",WS_OVERLAPPEDWINDOW,20,20,250,160,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    SetEvent(static_cast<HANDLE>(event));Sleep(120000);return 0;}
}
int RunWindowFixture(const wchar_t* path,bool ignore,bool hung){
    statePath=path;ignoreClose=ignore;WNDCLASSW cls{};cls.lpfnWndProc=procedure;cls.hInstance=GetModuleHandleW(nullptr);cls.lpszClassName=L"KswordCliWindowFixture";
    if(!RegisterClassW(&cls))return static_cast<int>(GetLastError());
    mainWindow=CreateWindowExW(0,cls.lpszClassName,L"KSword CLI window fixture",WS_OVERLAPPEDWINDOW,10,10,320,220,nullptr,nullptr,cls.hInstance,nullptr);
    if(!mainWindow)return static_cast<int>(GetLastError());ShowWindow(mainWindow,SW_SHOWNORMAL);
    HANDLE ready=nullptr,thread=nullptr;
    if(hung){ready=CreateEventW(nullptr,TRUE,FALSE,nullptr);thread=CreateThread(nullptr,0,stalled,ready,0,nullptr);
        if(!thread||WaitForSingleObject(ready,5000)!=WAIT_OBJECT_0)return ERROR_TIMEOUT;}
    state();MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    if(thread){TerminateThread(thread,0);WaitForSingleObject(thread,2000);CloseHandle(thread);}if(ready)CloseHandle(ready);return 0;
}
