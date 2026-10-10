// Same-process test consumer of the production CLI adapter. No remote window
// injection or production window creation command is introduced.
#include "../../KswordCLI/CommandRegistry.h"
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <string>
namespace {
std::wstring created(HANDLE handle,bool thread){FILETIME c{},e{},k{},u{};
    if(!(thread?GetThreadTimes(handle,&c,&e,&k,&u):GetProcessTimes(handle,&c,&e,&k,&u)))return {};
    return std::to_wstring(static_cast<std::uint64_t>(c.dwHighDateTime)<<32|c.dwLowDateTime);}
}
int wmain(int argc,wchar_t* argv[]){
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    const auto hwnd=CreateWindowExW(WS_EX_LAYERED|WS_EX_TOOLWINDOW,L"STATIC",L"KSword capture fixture",WS_OVERLAPPEDWINDOW,-10000,-10000,32,32,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    if(!hwnd)return static_cast<int>(GetLastError());SetLayeredWindowAttributes(hwnd,0,255,LWA_ALPHA);ShowWindow(hwnd,SW_SHOWNOACTIVATE);
    const auto handle=std::to_wstring(reinterpret_cast<std::uintptr_t>(hwnd)),pid=std::to_wstring(GetCurrentProcessId()),tid=std::to_wstring(GetCurrentThreadId());
    const auto processTime=created(GetCurrentProcess(),false),threadTime=created(GetCurrentThread(),true);
    for(int i=1;i+1<argc;++i){const std::wstring key=argv[i];const auto* replacement=key==L"--hwnd"?&handle:key==L"--pid"?&pid:key==L"--tid"?&tid:key==L"--creation-time"?&processTime:key==L"--thread-creation-time"?&threadTime:nullptr;
        if(replacement&&std::wstring(argv[i+1])==L"self")argv[i+1]=const_cast<wchar_t*>(replacement->c_str());}
    ks::cli::registerWindowCapture();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);DestroyWindow(hwnd);return result;
}
