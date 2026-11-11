#include "R3ProcessShared.h"
#include "../Ksword5.1/Ksword5.1/ksword/dbghelp_serialization.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <winternl.h>
#include <array>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <vector>
#pragma comment(lib, "Dbghelp.lib")

namespace ks::cli {
namespace {
struct ThreadBasic { LONG status; void* teb; void* pid; void* tid; ULONG_PTR affinity; LONG priority; LONG basePriority; };
using QueryThread = LONG (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
struct Snapshot { std::uint64_t low=0, high=0, captured=0; std::vector<std::uint8_t> data; };
thread_local const Snapshot* currentSnapshot=nullptr;
BOOL CALLBACK readSnapshot(HANDLE process,DWORD64 address,PVOID output,DWORD bytes,LPDWORD read) {
    if(read) *read=0;
    if(currentSnapshot && address>=currentSnapshot->low && address<currentSnapshot->high) {
        if(address<currentSnapshot->captured || bytes>currentSnapshot->high-address) return FALSE;
        std::memcpy(output,currentSnapshot->data.data()+static_cast<std::size_t>(address-currentSnapshot->low),bytes);
        if(read) *read=bytes; return TRUE;
    }
    SIZE_T count=0; const BOOL ok=ReadProcessMemory(process,reinterpret_cast<LPCVOID>(address),output,bytes,&count);
    if(read) *read=static_cast<DWORD>(count); return ok;
}
struct ResumeGuard { HANDLE h; bool paused=false; ~ResumeGuard(){if(paused) ResumeThread(h);} };
std::uint64_t filetime(const FILETIME& t) {return (static_cast<std::uint64_t>(t.dwHighDateTime)<<32)|t.dwLowDateTime;}
Result stack(const Args& args) {
    const DWORD tid=args.u32(L"--tid"); (void)args.require(L"--tid");
    const auto expected=args.integer(L"--thread-creation-time"); (void)args.require(L"--thread-creation-time");
    const auto limit=args.u32(L"--limit",128);
    if(!tid||!expected||!limit||limit>128) throw std::invalid_argument("--tid and --thread-creation-time must be positive; --limit must be 1..128");
    if(tid==GetCurrentThreadId()) throw std::invalid_argument("cannot suspend the calling thread");
    process::Lease process(args,PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|SYNCHRONIZE);
    if(!process.matches||!process.alive()) return {3,Json::object({{L"target",process.json()}}),{L"Process identity is unavailable, mismatched or exited."}};
#if !defined(_M_X64)
    return {5,Json::object({{L"target",process.json()}}),{L"Stack capture requires an x64 CLI."}};
#else
    SYSTEM_INFO nativeSystem{}; GetNativeSystemInfo(&nativeSystem);
    if(nativeSystem.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_AMD64)
        return {5,Json::object({{L"target",process.json()}}),{L"Only native x64 Windows is supported for stack capture."}};
    BOOL wow64=FALSE;
    if(!IsWow64Process(process.handle.get(),&wow64)) return {3,Json::object({{L"win32Error",Json::number(GetLastError())}}),{L"Target architecture query failed."}};
    if(wow64) return {5,Json::object({{L"target",process.json()}}),{L"WOW64 stack capture is not supported by this command."}};
    ks::r3::common::UniqueHandle thread(OpenThread(THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION|SYNCHRONIZE,FALSE,tid));
    if(!thread.valid()) return {3,Json::object({{L"win32Error",Json::number(GetLastError())}}),{L"OpenThread failed."}};
    FILETIME created{},exited{},kernel{},user{};
    if(GetProcessIdOfThread(thread.get())!=process.pid||!GetThreadTimes(thread.get(),&created,&exited,&kernel,&user)||filetime(created)!=expected||WaitForSingleObject(thread.get(),0)!=WAIT_TIMEOUT)
        return {3,Json::object({{L"target",process.json()}}),{L"Thread identity mismatch, inaccessible or exited."}};
    auto query=reinterpret_cast<QueryThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationThread"));
    ThreadBasic basic{}; if(!query) return {5,Json::object({}),{L"NtQueryInformationThread unavailable."}};
    const LONG status=query(thread.get(),0,&basic,sizeof(basic),nullptr);
    if(status<0||!basic.teb) return {3,Json::object({{L"ntStatus",Json::hex(static_cast<DWORD>(status))}}),{L"Thread basic information unavailable."}};
    NT_TIB tib{}; SIZE_T read=0;
    if(!ReadProcessMemory(process.handle.get(),basic.teb,&tib,sizeof(tib),&read)||read<sizeof(tib))
        return {3,Json::object({{L"win32Error",Json::number(GetLastError())}}),{L"TEB stack bounds unavailable."}};
    Snapshot snapshot; snapshot.low=reinterpret_cast<std::uintptr_t>(tib.StackLimit); snapshot.high=reinterpret_cast<std::uintptr_t>(tib.StackBase);
    if(!snapshot.low||snapshot.high<=snapshot.low||snapshot.high-snapshot.low>16U*1024U*1024U)
        return {5,Json::object({}),{L"Stack bounds invalid or exceed 16 MiB."}};
    snapshot.data.resize(static_cast<std::size_t>(snapshot.high-snapshot.low));
    CONTEXT context{}; context.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER;
    ResumeGuard guard{thread.get()}; const DWORD previous=SuspendThread(thread.get());
    if(previous==DWORD(-1)) return {3,Json::object({{L"win32Error",Json::number(GetLastError())}}),{L"SuspendThread failed."}};
    guard.paused=true;
    const BOOL gotContext=GetThreadContext(thread.get(),&context); DWORD captureError=gotContext?0:GetLastError();
    snapshot.captured=context.Rsp; bool copied=gotContext&&snapshot.captured>=snapshot.low&&snapshot.captured<snapshot.high;
    if(copied) { const auto offset=static_cast<std::size_t>(snapshot.captured-snapshot.low); const auto length=static_cast<std::size_t>(snapshot.high-snapshot.captured);
        SIZE_T copiedBytes=0; const BOOL readOk=ReadProcessMemory(process.handle.get(),reinterpret_cast<LPCVOID>(snapshot.captured),snapshot.data.data()+offset,length,&copiedBytes);
        copied=readOk&&copiedBytes==length;
        if(!copied) captureError=readOk?ERROR_PARTIAL_COPY:GetLastError(); }
    else if(gotContext) captureError=ERROR_INVALID_ADDRESS;
    const DWORD resumeCount=ResumeThread(thread.get()); const DWORD resumeError=resumeCount==DWORD(-1)?GetLastError():0;
    guard.paused=resumeCount==DWORD(-1);
    if(guard.paused) return {6,Json::object({{L"resumeWin32Error",Json::number(resumeError)},{L"previousSuspendCount",Json::number(previous)}}),{L"Stack capture paused the thread, but resume failed; target state requires attention."}};
    if(!copied) return {3,Json::object({{L"captureWin32Error",Json::number(captureError)},{L"resumeWin32Error",Json::number(resumeError)}}),{L"Thread resumed; context or stack snapshot failed."}};
    std::lock_guard<std::mutex> lock(ks::dbghelp::SerializationMutex());
    SymSetOptions(SYMOPT_DEFERRED_LOADS|SYMOPT_UNDNAME);
    const bool symbols=SymInitializeW(process.handle.get(),L"",TRUE)!=FALSE; const DWORD symbolError=symbols?0:GetLastError();
    struct Cleanup {HANDLE h; bool active; ~Cleanup(){if(active) SymCleanup(h); currentSnapshot=nullptr;}} cleanup{process.handle.get(),symbols};
    currentSnapshot=&snapshot;
    STACKFRAME64 frame{};frame.AddrPC.Offset=context.Rip;frame.AddrPC.Mode=AddrModeFlat;frame.AddrFrame.Offset=context.Rbp;frame.AddrFrame.Mode=AddrModeFlat;frame.AddrStack.Offset=context.Rsp;frame.AddrStack.Mode=AddrModeFlat;
    std::vector<Json> frames; bool limited=false; DWORD walkError=0;
    for(std::uint32_t i=0;i<limit;++i) {
        SetLastError(ERROR_SUCCESS);
        if(!StackWalk64(IMAGE_FILE_MACHINE_AMD64,process.handle.get(),thread.get(),&frame,&context,readSnapshot,SymFunctionTableAccess64,SymGetModuleBase64,nullptr)||!frame.AddrPC.Offset) {walkError=GetLastError();break;}
        alignas(SYMBOL_INFOW) std::array<unsigned char,sizeof(SYMBOL_INFOW)+MAX_SYM_NAME*sizeof(wchar_t)> buffer{};
        auto* symbol=reinterpret_cast<SYMBOL_INFOW*>(buffer.data());symbol->SizeOfStruct=sizeof(*symbol);symbol->MaxNameLen=MAX_SYM_NAME;
        DWORD64 displacement=0; const bool named=symbols&&SymFromAddrW(process.handle.get(),frame.AddrPC.Offset,&displacement,symbol)!=FALSE;
        frames.push_back(Json::object({{L"address",Json::hex(frame.AddrPC.Offset)},{L"stackAddress",Json::hex(frame.AddrStack.Offset)},
            {L"symbol",named?Json::string(std::wstring(symbol->Name,symbol->NameLen)):Json{}},{L"displacement",named?Json::hex(displacement):Json{}}}));
    }
    limited=frames.size()==limit;
    const bool alive=process.alive()&&WaitForSingleObject(thread.get(),0)==WAIT_TIMEOUT;
    return {frames.empty()?3:(!alive||!symbols||limited||walkError)?6:0,Json::object({{L"target",process.json()},{L"tid",Json::number(tid)},
        {L"threadCreationTime",Json::count(expected)},{L"previousSuspendCount",Json::number(previous)},{L"resumeWin32Error",Json::number(resumeError)},
        {L"stackLimit",Json::hex(snapshot.low)},{L"stackBase",Json::hex(snapshot.high)},{L"capturedFrom",Json::hex(snapshot.captured)},
        {L"symbolsAvailable",Json::boolean(symbols)},{L"symbolWin32Error",Json::number(symbolError)},{L"walkWin32Error",Json::number(walkError)},
        {L"targetAlive",Json::boolean(alive)},{L"limited",Json::boolean(limited)},{L"frames",Json::array(frames)}}),
        {L"User-mode x64 snapshot: the thread is temporarily suspended; unwind metadata outside the captured stack remains live. Symbol resolution is best effort."}};
#endif
}
}
void registerThreadStack() {
    addCommand({L"process thread stack query",L"KswordCLI.exe process thread stack query --pid PID --tid TID --thread-creation-time FILETIME [--creation-time FILETIME] [--limit N] [--backend r3] [--json]",
        L"Capture and symbolize an x64 user-mode thread stack.",L"Required: --pid, --tid, --thread-creation-time. Optional: --creation-time, --limit 1..128 (128), --backend r3, --json.",
        L"Temporarily suspends the verified thread, copies its user stack, resumes it, then walks the snapshot. R3 x64 only; WOW64 unsupported. A resume failure reports partial and needs immediate attention. Symbols are best effort; live unwind metadata may change.",stack});
}
}
