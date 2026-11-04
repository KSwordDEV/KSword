"""Capture a stack from an owned thread and check identity and resume behavior."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "STACK_SOURCE"
#include <iostream>
static DWORD WINAPI worker(void* event) { WaitForSingleObject(event, INFINITE); return 0; }
int wmain(int argc,wchar_t** argv) {
    if(argc==3 && std::wstring(argv[1])==L"child") {
        HANDLE wait=OpenEventW(SYNCHRONIZE,FALSE,argv[2]);if(!wait)return 20;
        WaitForSingleObject(wait,8000);CloseHandle(wait);return 0;
    }
    HANDLE event=CreateEventW(nullptr,TRUE,FALSE,nullptr); DWORD tid=0;
    HANDLE thread=CreateThread(nullptr,0,worker,event,0,&tid);
    if(!event||!thread)return 10;
    FILETIME c{},e{},k{},u{};if(!GetThreadTimes(thread,&c,&e,&k,&u))return 11;
    auto creation=(static_cast<unsigned long long>(c.dwHighDateTime)<<32)|c.dwLowDateTime;
    ks::cli::Args args;args.values[L"--pid"]=std::to_wstring(GetCurrentProcessId());args.values[L"--tid"]=std::to_wstring(tid);
    args.values[L"--thread-creation-time"]=std::to_wstring(creation);args.values[L"--limit"]=L"32";
    auto result=ks::cli::stack(args);
    if((result.code!=0&&result.code!=6)||result.data.text.find(L"\"frames\":[{")==std::wstring::npos||result.data.text.find(L"\"resumeWin32Error\":0")==std::wstring::npos)return 12;
    args.values[L"--thread-creation-time"]=std::to_wstring(creation+1);
    if(ks::cli::stack(args).code!=3)return 13;
    SetEvent(event);if(WaitForSingleObject(thread,5000)!=WAIT_OBJECT_0)return 14;
    CloseHandle(thread);CloseHandle(event);
    wchar_t image[MAX_PATH]{};if(!GetModuleFileNameW(nullptr,image,MAX_PATH))return 15;
    const auto name=L"Local\\KswordStackTest-"+std::to_wstring(GetCurrentProcessId());
    HANDLE childEvent=CreateEventW(nullptr,TRUE,FALSE,name.c_str());if(!childEvent)return 16;
    std::wstring command=L"\""+std::wstring(image)+L"\" child "+name;
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION child{};
    if(!CreateProcessW(image,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&child)){CloseHandle(childEvent);return 17;}
    Sleep(200);FILETIME pc{},tc{};
    bool ok=GetProcessTimes(child.hProcess,&pc,&e,&k,&u)&&GetThreadTimes(child.hThread,&tc,&e,&k,&u);
    if(ok) {
        const auto ptime=(static_cast<unsigned long long>(pc.dwHighDateTime)<<32)|pc.dwLowDateTime;
        const auto ttime=(static_cast<unsigned long long>(tc.dwHighDateTime)<<32)|tc.dwLowDateTime;
        args.values[L"--pid"]=std::to_wstring(child.dwProcessId);args.values[L"--tid"]=std::to_wstring(child.dwThreadId);
        args.values[L"--creation-time"]=std::to_wstring(ptime);args.values[L"--thread-creation-time"]=std::to_wstring(ttime);
        auto remote=ks::cli::stack(args);ok=(remote.code==0||remote.code==6)&&remote.data.text.find(L"\"frames\":[{")!=std::wstring::npos&&remote.data.text.find(L"\"resumeWin32Error\":0")!=std::wstring::npos;
    }
    SetEvent(childEvent);const bool exited=WaitForSingleObject(child.hProcess,5000)==WAIT_OBJECT_0;
    CloseHandle(child.hThread);CloseHandle(child.hProcess);CloseHandle(childEvent);
    if(!ok||!exited)return 18;
    std::cout<<"THREAD_STACK_PASS\n";return 0;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-stack-') as temp:
        folder=Path(temp); source=folder/'fixture.cpp'; exe=folder/'fixture.exe'
        source.write_text(SOURCE.replace('STACK_SOURCE',(ROOT/'KswordCLI/R3ThreadStack.cpp').as_posix()),encoding='utf-8')
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8',str(source),
            *[str(ROOT/p) for p in ('KswordCLI/CommandRegistry.cpp','KswordCLI/CliArgs.cpp','KswordCLI/CliText.cpp','shared/usermode/backend/Common.cpp')],
            '/Fe:'+str(exe),'/link','Dbghelp.lib'],cwd=folder,check=True)
        subprocess.run([str(exe)],check=True,timeout=30)

if __name__=='__main__':main()
