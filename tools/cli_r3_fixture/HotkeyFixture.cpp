#include "HotkeyFixture.h"
#include <Windows.h>
#include <commctrl.h>
#include <sstream>
#include <string>
namespace {
HWND hungWindow = nullptr;
LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM w,LPARAM l) {
    if (message == WM_DESTROY) {PostQuitMessage(0);return 0;}
    return DefWindowProcW(window,message,w,l);
}
DWORD WINAPI stalled(void* ready) {
    hungWindow = CreateWindowExW(0,L"KswordCliHotkeyFixture",L"Stalled fixture",WS_OVERLAPPEDWINDOW,0,0,200,100,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    SetEvent(static_cast<HANDLE>(ready));Sleep(120000);return 0;
}
}
int RunHotkeyFixture(const wchar_t* path,bool hung) {
    WNDCLASSW cls{};cls.lpfnWndProc=procedure;cls.hInstance=GetModuleHandleW(nullptr);cls.lpszClassName=L"KswordCliHotkeyFixture";
    if (!RegisterClassW(&cls)) return static_cast<int>(GetLastError());
    const auto popup=CreatePopupMenu(),menu=CreateMenu();
    AppendMenuW(popup,MF_STRING,2002,L"&Probe");AppendMenuW(menu,MF_POPUP,reinterpret_cast<UINT_PTR>(popup),L"&Lab");
    const auto window=CreateWindowExW(0,cls.lpszClassName,L"KSword CLI hotkey fixture",WS_OVERLAPPEDWINDOW,0,0,300,200,nullptr,menu,cls.hInstance,nullptr);
    if (!window) {DestroyMenu(menu);return static_cast<int>(GetLastError());}
    const WORD hotkey=MAKEWORD(VK_F19,HOTKEYF_CONTROL|HOTKEYF_SHIFT);
    const auto setResult=SendMessageW(window,WM_SETHOTKEY,hotkey,0);
    if (setResult!=1 && setResult!=2) {DestroyWindow(window);return ERROR_INVALID_FUNCTION;}
    HANDLE ready=nullptr,thread=nullptr;
    if(hung){ready=CreateEventW(nullptr,TRUE,FALSE,nullptr);thread=CreateThread(nullptr,0,stalled,ready,0,nullptr);
        if(!thread || WaitForSingleObject(ready,5000)!=WAIT_OBJECT_0) return ERROR_TIMEOUT;}
    std::ostringstream state;state << "{\"pid\":" << GetCurrentProcessId() << ",\"tid\":" << GetCurrentThreadId()
        << ",\"window\":\"0x" << std::hex << reinterpret_cast<std::uintptr_t>(window) << "\",\"hungWindow\":\"0x"
        << reinterpret_cast<std::uintptr_t>(hungWindow) << std::dec << "\",\"hotkeyWord\":" << hotkey << '}';
    const auto bytes=state.str();const auto output=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output==INVALID_HANDLE_VALUE) return static_cast<int>(GetLastError());
    DWORD written=0;const BOOL ok=WriteFile(output,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr);CloseHandle(output);
    if(!ok || written!=bytes.size()) return ERROR_WRITE_FAULT;
    MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}
    if(thread){TerminateThread(thread,0);WaitForSingleObject(thread,2000);CloseHandle(thread);}if(ready)CloseHandle(ready);
    return 0;
}
