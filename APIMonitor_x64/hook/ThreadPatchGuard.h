#pragma once
#include "HookEngine.h"
#include "../core/MonitorDiagnostics.h"

namespace apimon::detail {
// Handles and context storage are allocated before suspending anyone. Contexts
// can be reused only while this exact frozen thread set remains suspended.
class ThreadPatchGuard {
public:
    ThreadPatchGuard() {
        APIMON_DIAG_SCOPE(SuspendTicks);
        using NextThread=LONG(NTAPI*)(HANDLE,HANDLE,ACCESS_MASK,ULONG,ULONG,PHANDLE);
        const auto next=reinterpret_cast<NextThread>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread"));
        if(!next){failure=L"thread enumeration unavailable";return;}
        HANDLE cursor=nullptr, own=nullptr;LONG status=0;bool complete=false;
        for(;;){
            HANDLE thread=nullptr;status=next(::GetCurrentProcess(),cursor,THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,0,0,&thread);
            if(status==static_cast<LONG>(0x8000001a)){complete=true;break;}
            if(status<0||!thread)break;
            cursor=thread;const auto id=::GetThreadId(thread);
            if(!id){status=static_cast<LONG>(::GetLastError());::CloseHandle(thread);break;}
            if(id==::GetCurrentThreadId())own=thread;else threads.push_back(thread);
        }
        if(own)::CloseHandle(own);
        if(!complete){
            APIMON_DIAG_MARK("thread-enumeration-failed",static_cast<unsigned long>(status),threads.size());
            wchar_t message[96]{};
            swprintf_s(message,L"NtGetNextThread incomplete; status=0x%08lX",static_cast<unsigned long>(status));
            failure=message;return;
        }
        ips.resize(threads.size());
        held.resize(threads.size(),0);
        for(std::size_t i=0;i<threads.size();++i){
            const auto thread=threads[i];
            // NtGetNextThread can still enumerate terminated thread objects
            // retained by other handles. Such threads cannot execute a patch.
            if(::WaitForSingleObject(thread,0)==WAIT_OBJECT_0)continue;
            if(::SuspendThread(thread)==static_cast<DWORD>(-1)){
                const auto error=::GetLastError();
                const auto wait=::WaitForSingleObject(thread,0);
                if(wait==WAIT_OBJECT_0)continue; // exited after the first check
                const auto id=::GetThreadId(thread);Resume();
                APIMON_DIAG_MARK("thread-suspend-failed",error,0);
                failure=L"SuspendThread failed; error="+std::to_wstring(error)+L" tid="+std::to_wstring(id)+L" wait="+std::to_wstring(wait);return;
            }
            held[i]=1;
        }
        ready=true;
    }
    ~ThreadPatchGuard(){Resume();for(const auto thread:threads)::CloseHandle(thread);}
    bool CaptureContexts(){
        APIMON_DIAG_SCOPE(ContextTicks);
        if(!ready)return false;if(captured)return true;
        for(std::size_t i=0;i<threads.size();++i){
            if(!held[i])continue;
            CONTEXT context{};context.ContextFlags=CONTEXT_CONTROL;
            if(!::GetThreadContext(threads[i],&context)){
                const auto error=::GetLastError();
                if(::WaitForSingleObject(threads[i],0)==WAIT_OBJECT_0){held[i]=0;continue;}
                Resume();
                APIMON_DIAG_MARK("thread-context-failed",error,0);
                failure=L"GetThreadContext failed; error="+std::to_wstring(error);return false;
            }
#ifdef _M_IX86
            ips[i]=context.Eip;
#else
            ips[i]=context.Rip;
#endif
        }
        captured=true;return true;
    }
    bool AllowsPatch(const void* address,std::size_t length)const{
        if(!ready||!captured)return false;
        const auto begin=reinterpret_cast<std::uintptr_t>(address);
        for(const auto ip:ips)if(ip>=begin&&ip-begin<length)return false;
        return true;
    }
    bool CanPatch(const void* address,std::size_t length){
        if(!CaptureContexts())return false;
        if(AllowsPatch(address,length))return true;
        Resume();failure=L"active patch-region thread; retry required";return false;
    }
    const std::wstring& FailureText()const{return failure;}
    void Resume(){
        APIMON_DIAG_SCOPE(ResumeTicks);
        for(std::size_t i=held.size();i>0;--i)if(held[i-1]){::ResumeThread(threads[i-1]);held[i-1]=0;}
        ready=false;
    }
private:
    ScopedInlineHookInternalBypass bypass;
    std::vector<HANDLE> threads;
    std::vector<std::uintptr_t> ips;
    std::vector<unsigned char> held;
    bool ready=false,captured=false;
    std::wstring failure;
};
}
