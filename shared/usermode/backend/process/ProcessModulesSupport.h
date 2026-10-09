#pragma once
#include "ProcessDetailTypes.h"
#include "ProcessThreadsSupport.h"
#include "../Common.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <limits>
namespace ks::r3::process_detail::detail {
using EnumProcessModulesExFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
using GetModuleInformationFn = BOOL(WINAPI*)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
using GetModuleFileNameExWFn = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);
struct ModuleApi {
    HMODULE library = nullptr;
    EnumProcessModulesExFn enumProcessModulesEx = nullptr;
    GetModuleInformationFn getModuleInformation = nullptr;
    GetModuleFileNameExWFn getModuleFileNameExW = nullptr;

    // available reports whether every module enumeration export was resolved.
    // There is no input; processing checks stored function pointers; output is
    // true only when CollectModules can call the API set safely.
    bool available() const {
        return enumProcessModulesEx && getModuleInformation && getModuleFileNameExW;
    }
};
std::wstring FormatHexPointer(std::uintptr_t value);
ModuleApi LoadModuleApi();
std::wstring BaseNameFromPath(const std::wstring& path);
std::vector<ProcessModuleInfo> CollectModules(DWORD processId, bool& succeededOut, std::wstring& statusOut);
void AttachRepresentativeThreads(
    std::vector<ProcessModuleInfo>& modules,
    const std::vector<ProcessThreadInfo>& threads);
}
