#pragma once
#include "R3ProcessShared.h"
#include <limits>
namespace ks::cli::window {
inline HWND hwnd(const Args& a) {
    (void)a.require(L"--hwnd");const auto value=a.integer(L"--hwnd");
    if(!value||value>static_cast<std::uint64_t>((std::numeric_limits<std::uintptr_t>::max)()))throw std::invalid_argument("--hwnd must be a nonzero pointer-sized value");
    return reinterpret_cast<HWND>(static_cast<std::uintptr_t>(value));
}
struct Lease {
    HWND handle;
    process::Lease process;
    ks::r3::common::UniqueHandle thread;
    DWORD tid=0,error=ERROR_SUCCESS;
    std::uint64_t threadCreationTime=0;
    bool matches=false;
    explicit Lease(const Args& a):handle(hwnd(a)),process(a) {
        (void)a.require(L"--creation-time");(void)a.require(L"--tid");(void)a.require(L"--thread-creation-time");
        tid=a.u32(L"--tid");const auto expected=a.integer(L"--thread-creation-time");
        if(!tid||!expected)throw std::invalid_argument("--tid and --thread-creation-time must be positive");
        if(!process.matches||!process.alive())return;
        DWORD owner=0;const auto currentTid=::GetWindowThreadProcessId(handle,&owner);
        if(currentTid!=tid||owner!=process.pid||!::IsWindow(handle)){error=ERROR_INVALID_WINDOW_HANDLE;return;}
        thread.reset(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,tid));if(!thread.valid()){error=::GetLastError();return;}
        if(::GetProcessIdOfThread(thread.get())!=process.pid){error=ERROR_INVALID_PARAMETER;return;}
        FILETIME created{},exited{},kernel{},user{};
        if(!::GetThreadTimes(thread.get(),&created,&exited,&kernel,&user)){error=::GetLastError();return;}
        threadCreationTime=static_cast<std::uint64_t>(created.dwHighDateTime)<<32|created.dwLowDateTime;
        matches=threadCreationTime==expected&&ownerMatches();
    }
    bool ownersAlive()const{return process.alive()&&thread.valid()&&::WaitForSingleObject(thread.get(),0)==WAIT_TIMEOUT;}
    bool ownerMatches()const{DWORD pid=0;return ownersAlive()&&::IsWindow(handle)&&::GetWindowThreadProcessId(handle,&pid)==tid&&pid==process.pid;}
    Json json()const{return Json::object({{L"hwnd",Json::hex(reinterpret_cast<std::uintptr_t>(handle))},{L"process",process.json()},
        {L"tid",Json::number(tid)},{L"threadCreationTime",threadCreationTime?Json::count(threadCreationTime):Json{}},
        {L"identityMatched",Json::boolean(matches)},{L"win32Error",error?Json::number(error):Json{}}});}
};
}
