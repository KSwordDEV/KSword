"""Exercise production patch removal with an in-flight detour and restore failure."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[2]
code = r"""
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <atomic>
#include <thread>
#include <cstdio>
static void* testTarget;
static bool failProtection=false;
HMODULE WINAPI TestGetModuleHandleW(LPCWSTR name) { return name && wcscmp(name,L"ntdll.dll")==0 ? GetModuleHandleW(name) : GetModuleHandleW(nullptr); }
FARPROC WINAPI TestGetProcAddress(HMODULE h,LPCSTR name) { if(strcmp(name,"VirtualAlloc2")==0)return nullptr;return strcmp(name,"NtGetNextThread")==0 ? GetProcAddress(h,name) : reinterpret_cast<FARPROC>(testTarget); }
BOOL WINAPI TestGetModuleHandleExW(DWORD,LPCWSTR,HMODULE* h) { *h=GetModuleHandleW(nullptr); return TRUE; }
BOOL WINAPI TestVirtualProtect(LPVOID p,SIZE_T n,DWORD access,PDWORD old) {
 if(failProtection) return FALSE;
 return VirtualProtect(p,n,access,old);
}
#define GetModuleHandleW TestGetModuleHandleW
#define GetProcAddress TestGetProcAddress
#define GetModuleHandleExW TestGetModuleHandleExW
#define VirtualProtect TestVirtualProtect
#include "HOOK_ENGINE_PATH"
#undef GetModuleHandleW
#undef GetProcAddress
#undef GetModuleHandleExW
#undef VirtualProtect
using Function=int(*)();
static void* original;
static std::atomic_bool entered{false}, releaseCall{false};
int Detour() {
 entered.store(true);
 while(!releaseCall.load()) std::this_thread::yield();
 return reinterpret_cast<Function>(original)()+1;
}
int main() {
 auto* code=static_cast<unsigned char*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE));
 memset(code,0x90,14); code[14]=0xB8;code[15]=42;memset(code+16,0,3);code[19]=0xC3;
 testTarget=code;
 apimon::InlineHookRecord hook; std::wstring error;
 auto result=apimon::InstallInlineHook(L"fixture","fixture",reinterpret_cast<void*>(&Detour),&hook,&original,&error);
 if(result!=apimon::InlineHookInstallResult::Installed) return 1;
 if(reinterpret_cast<Function>(original)()!=42) return 2;
 failProtection=true;
 if(apimon::UninstallInlineHook(&hook)||!hook.installed||hook.trampolineAddress!=original) return 3;
 failProtection=false;
 int observed=0;
 std::thread caller([&]{observed=reinterpret_cast<Function>(code)();});
 while(!entered.load()) std::this_thread::yield();
 if(!apimon::UninstallInlineHook(&hook)) { releaseCall.store(true);caller.join();return 4; }
 releaseCall.store(true);caller.join();
 if(observed!=43||reinterpret_cast<Function>(original)()!=42||reinterpret_cast<Function>(code)()!=42) return 5;
 printf("PASS: restore failure preserves hook; in-flight detour and retired trampoline remain callable\n");
}
"""
code=code.replace("HOOK_ENGINE_PATH",(root/"APIMonitor_x64/hook/HookEngine.cpp").as_posix())
with tempfile.TemporaryDirectory(prefix="ksword_hook_lifetime_") as temp:
 folder=Path(temp);cpp=folder/"test.cpp";cpp.write_text(code,encoding="utf-8")
 subprocess.run(["cl","/nologo","/EHsc","/std:c++17","/utf-8","/I"+str(root/"APIMonitor_x64"),str(cpp),"/Fe:"+str(folder/"test.exe"),"/Fo:"+str(folder/"test.obj")],check=True)
 subprocess.run([str(folder/"test.exe")],check=True,timeout=30)
