#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>
#include <string>

namespace apimon_probe {
inline FILE* g_trace = nullptr;
inline unsigned g_round = 0;
inline std::wstring g_root;
// Enabled only by the fixture after verifying the explicitly authorized VM.
inline bool g_allowGlobalStateChanges = false;
inline std::uint64_t Now() { FILETIME t{}; GetSystemTimeAsFileTime(&t); return (std::uint64_t(t.dwHighDateTime)<<32)|t.dwLowDateTime; }
template<class T> std::uint64_t Bits(const T& value) {
    static_assert(std::is_trivially_copyable_v<T> && sizeof(T)<=8);
    std::uint64_t result=0; std::memcpy(&result,&value,sizeof(value)); return result;
}
inline void Skip(unsigned id,const char* reason) {
    if(g_trace){std::fprintf(g_trace,"SKIP\t%u\t%u\t%s\n",g_round,id,reason);std::fflush(g_trace);}
}
// Resolve exact module!export, so the test invokes the same entry named by the
// production definition. The function pointer itself comes from SDK decltype.
template<class Fn,class... Args>
auto Call(unsigned id,const wchar_t* module,const char* api,Args&&... args) -> std::invoke_result_t<Fn,Args...> {
    using Ret=std::invoke_result_t<Fn,Args...>;
    HMODULE handle=GetModuleHandleW(module);if(!handle)handle=LoadLibraryW(module);
    auto function=handle?reinterpret_cast<Fn>(GetProcAddress(handle,api)):nullptr;
    if(!function){Skip(id,"export_missing");if constexpr(!std::is_void_v<Ret>)return Ret{};else return;}
    const auto begin=Now();
    if(g_trace){std::fprintf(g_trace,"BEGIN\t%u\t%u\t%llu\n",g_round,id,static_cast<unsigned long long>(begin));std::fflush(g_trace);}
    SetLastError(0x5a5a);
    if constexpr(std::is_void_v<Ret>) {
        function(std::forward<Args>(args)...);const DWORD error=GetLastError();const auto end=Now();
        if(g_trace){std::fprintf(g_trace,"CALL\t%u\t%u\t%llu\t%llu\t%lu\t0\t0\t%lu\n",g_round,id,static_cast<unsigned long long>(begin),static_cast<unsigned long long>(end),GetCurrentThreadId(),error);std::fflush(g_trace);}SetLastError(error);
    }else{
        Ret value=function(std::forward<Args>(args)...);const DWORD error=GetLastError();const auto end=Now();
        if(g_trace){std::fprintf(g_trace,"CALL\t%u\t%u\t%llu\t%llu\t%lu\t1\t%llx\t%lu\n",g_round,id,static_cast<unsigned long long>(begin),static_cast<unsigned long long>(end),GetCurrentThreadId(),static_cast<unsigned long long>(Bits(value)),error);std::fflush(g_trace);}SetLastError(error);return value;
    }
}
void RunWindowCases();
void RunMemoryThreadCases();
void RunServiceSecurityCases();
}
