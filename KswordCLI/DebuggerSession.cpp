#include "R3ProcessShared.h"
#include "../DebuggerBackend/KswordDebuggerBackend.h"
#include <TlHelp32.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>

namespace ks::cli {
#ifdef _WIN64
namespace {
using Handle = ks::r3::common::UniqueHandle;

std::uint64_t number(const std::wstring& s) {
    Args a; a.values[L"value"] = s; return a.integer(L"value");
}
DWORD dword(const std::wstring& s) {
    const auto n = number(s); if (n > MAXDWORD) throw std::invalid_argument("number exceeds uint32");
    return static_cast<DWORD>(n);
}
void send(const std::wstring& op, bool ok, Json data = Json::object({}), DWORD error = 0) {
    std::wcout << Json::object({{L"record",Json::string(L"debugger")},{L"operation",Json::string(op)},
        {L"ok",Json::boolean(ok)},{L"win32Error",Json::number(error)},{L"data",data}}).text << std::endl;
}
std::uint64_t& address(CONTEXT& c, DWORD slot) {
    switch (slot) { case 0: return c.Dr0; case 1: return c.Dr1; case 2: return c.Dr2; default: return c.Dr3; }
}
struct Breakpoint {
    DWORD tid, slot;
    std::uint64_t value, original, originalBits;
    Handle thread;
};
struct Session {
    DWORD pid;
    bool r0, attached = false, pending = false, exited = false, initialBreakpoint = true;
    DEBUG_EVENT event{};
    ksword::debugger::Backend backend;
    std::vector<Breakpoint> breaks;
    explicit Session(DWORD p, bool kernel) : pid(p), r0(kernel) {}
    HANDLE openThread(DWORD tid) {
        constexpr DWORD access = THREAD_QUERY_LIMITED_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | SYNCHRONIZE;
        HANDLE h = r0 ? backend.openThread(access, FALSE, tid) : OpenThread(access, FALSE, tid);
        if (h && GetProcessIdOfThread(h) != pid) { CloseHandle(h); SetLastError(ERROR_INVALID_PARAMETER); return nullptr; }
        return h;
    }
    BOOL get(HANDLE h, CONTEXT* c) { return r0 ? backend.getContext(h,c) : GetThreadContext(h,c); }
    BOOL set(HANDLE h, CONTEXT* c) { return r0 ? backend.setContext(h,c) : SetThreadContext(h,c); }
    BOOL resumeEvent(DWORD status) {
        const BOOL ok = r0 ? backend.continueEvent(event.dwProcessId,event.dwThreadId,status)
                           : ContinueDebugEvent(event.dwProcessId,event.dwThreadId,status);
        if (ok) { pending = false; if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) { exited = true; attached = false; } }
        return ok;
    }
    bool restore(Breakpoint& b) {
        if (WaitForSingleObject(b.thread.get(),0) == WAIT_OBJECT_0) return true;
        if (SuspendThread(b.thread.get()) == static_cast<DWORD>(-1)) return false;
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        bool ok = get(b.thread.get(),&c) != FALSE;
        const std::uint64_t mask = (3ULL << (2*b.slot)) | (15ULL << (16+4*b.slot));
        if (ok && (address(c,b.slot) != b.value || (c.Dr7 & mask) != (1ULL << (2*b.slot)))) {
            SetLastError(ERROR_INVALID_STATE); ok = false;
        }
        if (ok) { address(c,b.slot) = b.original; c.Dr7 = (c.Dr7 & ~mask) | b.originalBits; ok = set(b.thread.get(),&c) != FALSE; }
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (ResumeThread(b.thread.get()) == static_cast<DWORD>(-1) && ok) { ok = false; error = GetLastError(); }
        if (!ok) SetLastError(error);
        return ok;
    }
    bool removeAll() {
        bool ok = true; DWORD error = 0;
        for (auto it = breaks.begin(); it != breaks.end();) {
            if (restore(*it)) it = breaks.erase(it);
            else { ok = false; error = GetLastError(); ++it; }
        }
        if (!ok) SetLastError(error); return ok;
    }
    bool detach() {
        if (!removeAll()) return false;
        if (pending) {
            const DWORD status = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                !(initialBreakpoint && event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
                ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
            if (!resumeEvent(status)) return false;
        }
        if (attached && !DebugActiveProcessStop(pid)) return false;
        attached = false; return true;
    }
    ~Session() { if (attached || pending || !breaks.empty()) (void)detach(); if (r0) (void)backend.shutdown(); }
};
Json eventJson(const DEBUG_EVENT& e) {
    Json exception;
    if (e.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) exception = Json::object({
        {L"code",Json::hex(e.u.Exception.ExceptionRecord.ExceptionCode)},
        {L"address",Json::hex(reinterpret_cast<std::uint64_t>(e.u.Exception.ExceptionRecord.ExceptionAddress))},
        {L"firstChance",Json::boolean(e.u.Exception.dwFirstChance != 0)}});
    return Json::object({{L"eventCode",Json::number(e.dwDebugEventCode)},{L"pid",Json::number(e.dwProcessId)},
        {L"tid",Json::number(e.dwThreadId)},{L"exception",exception},
        {L"exitCode",e.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT ? Json::number(e.u.ExitProcess.dwExitCode) :
            e.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT ? Json::number(e.u.ExitThread.dwExitCode) : Json{}}});
}
void closeEventHandles(const DEBUG_EVENT& e) {
    if (e.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && e.u.CreateProcessInfo.hFile) CloseHandle(e.u.CreateProcessInfo.hFile);
    if (e.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && e.u.LoadDll.hFile) CloseHandle(e.u.LoadDll.hFile);
}
Json threads(DWORD pid, DWORD& error) {
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0));
    if (!snap.valid()) { error = GetLastError(); return {}; }
    THREADENTRY32 entry{}; entry.dwSize = sizeof(entry); std::vector<Json> result;
    if (!Thread32First(snap.get(),&entry)) { error = GetLastError(); return {}; }
    do { if (entry.th32OwnerProcessID == pid) result.push_back(Json::object({{L"tid",Json::number(entry.th32ThreadID)}})); }
    while (Thread32Next(snap.get(),&entry));
    error = GetLastError(); if (error == ERROR_NO_MORE_FILES) error = 0;
    return Json::array(result);
}
Result runSession(const Args& args) {
    (void)args.require(L"--pid"); (void)args.require(L"--creation-time"); (void)args.require(L"--confirm");
    process::Lease lease(args);
    if (!lease.matches || !lease.alive()) return {3,lease.json(),{L"Target identity, access, or liveness check failed."}};
    BOOL wow = FALSE;
    if (!IsWow64Process(lease.handle.get(),&wow) || wow) return {5,lease.json(),{L"Only native x64 targets are supported by this session."}};
    const bool r0 = args.get(L"--backend",L"r3") == L"r0";
    Session s(lease.pid,r0);
    if (r0 && !s.backend.initialize()) return {3,lease.json(),{L"R0 debugger backend initialization failed."}};
    BOOL attached = r0 ? s.backend.attach(s.pid) : DebugActiveProcess(s.pid);
    if (!attached) return {3,Json::object({{L"target",lease.json()},{L"win32Error",Json::number(GetLastError())}}),{L"Debug attach failed."}};
    s.attached = true;
    if ((!r0 && !DebugSetProcessKillOnExit(FALSE)) || !lease.alive()) {
        const DWORD error=GetLastError(); (void)s.detach();
        return {3,Json::object({{L"target",lease.json()},{L"win32Error",Json::number(error)}}),{L"Could not establish a stable, non-killing debug session."}};
    }
    send(L"attached",true,Json::object({{L"target",lease.json()},{L"backend",Json::string(r0?L"r0":L"r3")}}));
    bool failed=false; std::wstring line;
    while (s.attached && std::getline(std::wcin,line)) {
        std::wistringstream in(line); std::wstring op; in >> op; if (op.empty()) continue;
        try {
            if (op == L"wait") {
                std::wstring arg, extra; in >> arg >> extra; if (!extra.empty()) throw std::invalid_argument("wait [milliseconds]");
                if (s.pending) { send(op,false,{},ERROR_BUSY); continue; }
                const DWORD timeout = arg.empty()?1000:dword(arg);
                DEBUG_EVENT e{}; const BOOL ok = r0 ? s.backend.waitEvent(&e,timeout) : WaitForDebugEvent(&e,timeout);
                if (!ok) { send(op,false,{},GetLastError()); continue; }
                s.event=e; s.pending=true; closeEventHandles(e); send(op,true,eventJson(e));
            } else if (op == L"continue") {
                std::wstring status, extra; in >> status >> extra;
                if (!extra.empty() || (status != L"handled" && status != L"not-handled")) throw std::invalid_argument("continue handled|not-handled");
                if (!s.pending) { send(op,false,{},ERROR_INVALID_STATE); continue; }
                if (s.event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && s.event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                    auto it=std::find_if(s.breaks.begin(),s.breaks.end(),[&](const Breakpoint& b){return b.tid==s.event.dwThreadId;});
                    if (it != s.breaks.end()) {
                        CONTEXT c{}; c.ContextFlags=CONTEXT_CONTROL|CONTEXT_DEBUG_REGISTERS;
                        if (!s.get(it->thread.get(),&c)) { send(op,false,{},GetLastError()); continue; }
                        bool hit=false; for (const auto& b:s.breaks) if(b.tid==s.event.dwThreadId && (c.Dr6 & (1ULL<<b.slot)) && c.Rip==b.value) hit=true;
                        if(hit) { c.EFlags|=0x10000; c.ContextFlags=CONTEXT_CONTROL; if(!s.set(it->thread.get(),&c)){send(op,false,{},GetLastError());continue;} }
                    }
                }
                const bool wasInitial=s.initialBreakpoint && s.event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT && s.event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT;
                const BOOL ok=s.resumeEvent(status==L"handled"?DBG_CONTINUE:DBG_EXCEPTION_NOT_HANDLED); const DWORD error=ok?0:GetLastError();
                if(ok && wasInitial) s.initialBreakpoint=false; send(op,ok!=FALSE,{},error);
            } else if (op == L"threads") {
                std::wstring extra; in >> extra; if(!extra.empty()) throw std::invalid_argument("threads"); DWORD error=0; auto data=threads(s.pid,error); send(op,error==0,data,error);
            } else if (op == L"context") {
                std::wstring tidText,extra; in>>tidText>>extra; if(tidText.empty()||!extra.empty())throw std::invalid_argument("context TID");
                if(!s.pending){send(op,false,{},ERROR_INVALID_STATE);continue;} Handle h(s.openThread(dword(tidText))); if(!h.valid()){send(op,false,{},GetLastError());continue;}
                CONTEXT c{}; c.ContextFlags=CONTEXT_CONTROL|CONTEXT_DEBUG_REGISTERS; const BOOL ok=s.get(h.get(),&c); const DWORD error=ok?0:GetLastError();
                send(op,ok!=FALSE,ok?Json::object({{L"rip",Json::hex(c.Rip)},{L"rsp",Json::hex(c.Rsp)},{L"rbp",Json::hex(c.Rbp)},
                    {L"eflags",Json::hex(c.EFlags)},{L"dr0",Json::hex(c.Dr0)},{L"dr1",Json::hex(c.Dr1)},{L"dr2",Json::hex(c.Dr2)},
                    {L"dr3",Json::hex(c.Dr3)},{L"dr6",Json::hex(c.Dr6)},{L"dr7",Json::hex(c.Dr7)}}):Json{},error);
            } else if (op == L"read" || op == L"write") {
                std::wstring addrText, value, confirm,extra; in>>addrText>>value>>confirm>>extra;
                if(addrText.empty()||value.empty()||!extra.empty()||(op==L"read"&&!confirm.empty())||(op==L"write"&&confirm!=L"confirm"))throw std::invalid_argument("read ADDRESS BYTES | write ADDRESS HEX confirm");
                if(!s.pending){send(op,false,{},ERROR_INVALID_STATE);continue;}
                std::vector<std::uint8_t> bytes;
                if(op==L"read") {const auto n=number(value);if(!n||n>65536)throw std::invalid_argument("read size must be 1..65536");bytes.resize(static_cast<size_t>(n));}
                else {bytes=parseHexPayload(value);if(bytes.empty()||bytes.size()>65536)throw std::invalid_argument("write size must be 1..65536");}
                const DWORD access=PROCESS_QUERY_LIMITED_INFORMATION | (op==L"read"?PROCESS_VM_READ:PROCESS_VM_WRITE|PROCESS_VM_OPERATION);
                Handle proxy(r0?s.backend.openProcess(access,FALSE,s.pid):OpenProcess(access,FALSE,s.pid)); HANDLE h=proxy.get();
                if(!h){send(op,false,{},GetLastError());continue;}
                SIZE_T transferred=0; const auto ptr=reinterpret_cast<void*>(number(addrText)); BOOL ok;
                if(op==L"read")ok=r0?s.backend.readMemory(h,ptr,bytes.data(),bytes.size(),&transferred):ReadProcessMemory(h,ptr,bytes.data(),bytes.size(),&transferred);
                else ok=r0?s.backend.writeMemory(h,ptr,bytes.data(),bytes.size(),&transferred,ksword::debugger::Backend::MemoryWriteKind::data):WriteProcessMemory(h,ptr,bytes.data(),bytes.size(),&transferred);
                const DWORD error=ok?0:GetLastError(); bytes.resize(static_cast<size_t>(transferred));
                send(op,ok!=FALSE,Json::object({{L"transferred",Json::count(transferred)},{L"bytes",op==L"read"?Json::bytes(bytes,bytes.size()):Json{}}}),error);
            } else if (op == L"break") {
                std::wstring action,tidText,slotText,addrText,extra; in>>action>>tidText>>slotText>>addrText>>extra;
                if(tidText.empty()||slotText.empty()||!extra.empty()||(action==L"add"&&addrText.empty())||(action==L"remove"&&!addrText.empty())||(action!=L"add"&&action!=L"remove"))throw std::invalid_argument("break add TID SLOT ADDRESS | break remove TID SLOT");
                if(!s.pending){send(op,false,{},ERROR_INVALID_STATE);continue;} DWORD tid=dword(tidText),slot=dword(slotText);if(slot>3)throw std::invalid_argument("slot must be 0..3");
                auto it=std::find_if(s.breaks.begin(),s.breaks.end(),[&](const Breakpoint& b){return b.tid==tid&&b.slot==slot;});
                if(action==L"remove") {if(it==s.breaks.end()){send(op,false,{},ERROR_NOT_FOUND);continue;} const bool ok=s.restore(*it);const DWORD error=ok?0:GetLastError();if(ok)s.breaks.erase(it);send(op,ok,{},error);continue;}
                if(it!=s.breaks.end()){send(op,false,{},ERROR_ALREADY_EXISTS);continue;} Handle h(s.openThread(tid));if(!h.valid()){send(op,false,{},GetLastError());continue;}
                CONTEXT c{};c.ContextFlags=CONTEXT_DEBUG_REGISTERS;if(!s.get(h.get(),&c)){send(op,false,{},GetLastError());continue;}
                const std::uint64_t mask=(3ULL<<(2*slot))|(15ULL<<(16+4*slot)); if(c.Dr7&(3ULL<<(2*slot))){send(op,false,{},ERROR_BUSY);continue;}
                const auto old=address(c,slot), bits=c.Dr7&mask, value=number(addrText);if(!value)throw std::invalid_argument("zero breakpoint address");
                address(c,slot)=value;c.Dr7=(c.Dr7&~mask)|(1ULL<<(2*slot));if(!s.set(h.get(),&c)){send(op,false,{},GetLastError());continue;}
                s.breaks.push_back({tid,slot,value,old,bits,std::move(h)});send(op,true);
            } else if(op==L"detach") {
                std::wstring extra;in>>extra;if(!extra.empty())throw std::invalid_argument("detach");const bool ok=s.detach();const DWORD error=ok?0:GetLastError();send(op,ok,{},error);if(!ok)failed=true;
            } else throw std::invalid_argument("unknown session operation");
        } catch(const std::exception&) {send(op,false,Json::object({{L"diagnostic",Json::string(L"Invalid session operation or arguments.")}}),ERROR_INVALID_PARAMETER);}
    }
    if(s.attached || s.pending || !s.breaks.empty()) {const bool ok=s.detach();const DWORD error=ok?0:GetLastError();send(L"cleanup",ok,{},error);if(!ok)failed=true;}
    return {failed?3:0,Json::object({{L"target",lease.json()},{L"exited",Json::boolean(s.exited)},{L"detached",Json::boolean(!s.attached)}}),
        failed?std::vector<std::wstring>{L"Cleanup failed; inspect session records."}:std::vector<std::wstring>{}};
}
}
void registerDebuggerSession() {
    Command command{L"debugger session",L"KswordCLI.exe debugger session --pid PID --creation-time FILETIME --confirm [--backend r3|r0] --json",
        L"Attach a persistent, line-oriented native debugger session.",L"Required: --pid, --creation-time, --confirm. Optional: --backend, --json.",
        L"stdin commands: wait [ms]; continue handled|not-handled; threads; context TID; read ADDRESS BYTES; write ADDRESS HEX confirm; break add TID SLOT ADDRESS; break remove TID SLOT; detach. Each operation emits a JSON line, followed by the normal final result. x64 targets only; breakpoints are per-thread hardware execution slots, no HVM or software breakpoints. Memory and context require a pending debug event. EOF attempts cleanup.",runSession};
    command.supportsR0=true; addCommand(std::move(command));
}
#else
void registerDebuggerSession() {
    Command command{L"debugger session",L"KswordCLI.exe debugger session --pid PID --creation-time FILETIME --confirm [--backend r3|r0] --json",
        L"Attach a persistent debugger session.",L"Requires an x64 CLI build.",L"Unavailable in Win32 builds.",
        [](const Args&) -> Result { return {5,Json::object({}),{L"Debugger sessions require the x64 CLI build."}}; }};
    command.supportsR0=true; addCommand(std::move(command));
}
#endif
}
