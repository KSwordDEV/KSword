#include "ProcessModulesSupport.h"
#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <sstream>
#include <utility>
#pragma comment(lib, "Psapi.lib")
namespace ks::r3::process_detail::detail {
std::wstring FormatHexPointer(std::uintptr_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase;
    if constexpr (sizeof(void*) == 8) {
        stream.width(16);
    } else {
        stream.width(8);
    }
    stream.fill(L'0');
    stream << value;
    return stream.str();
}
ModuleApi LoadModuleApi() {
    ModuleApi api{};

    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    api.library = kernel32;
    api.enumProcessModulesEx = ResolveProc<EnumProcessModulesExFn>(kernel32, "K32EnumProcessModulesEx");
    api.getModuleInformation = ResolveProc<GetModuleInformationFn>(kernel32, "K32GetModuleInformation");
    api.getModuleFileNameExW = ResolveProc<GetModuleFileNameExWFn>(kernel32, "K32GetModuleFileNameExW");
    if (api.available()) {
        return api;
    }

    HMODULE psapi = ::GetModuleHandleW(L"psapi.dll");
    if (!psapi) {
        psapi = ::LoadLibraryW(L"psapi.dll");
    }
    api.library = psapi;
    api.enumProcessModulesEx = ResolveProc<EnumProcessModulesExFn>(psapi, "EnumProcessModulesEx");
    api.getModuleInformation = ResolveProc<GetModuleInformationFn>(psapi, "GetModuleInformation");
    api.getModuleFileNameExW = ResolveProc<GetModuleFileNameExWFn>(psapi, "GetModuleFileNameExW");
    return api;
}
std::wstring BaseNameFromPath(const std::wstring& path) {
    const std::size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos + 1 >= path.size()) {
        return path;
    }
    return path.substr(pos + 1);
}
std::vector<ProcessModuleInfo> CollectModules(DWORD processId, bool& succeededOut, std::wstring& statusOut, ModuleEnumerationEvidence* evidence) {
    ModuleEnumerationEvidence local;
    if (!evidence) evidence = &local;
    *evidence = {};
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessModuleInfo> rows;

    const ModuleApi moduleApi = LoadModuleApi();
    if (!moduleApi.available()) {
        evidence->unsupported = true; evidence->win32Error = ERROR_PROC_NOT_FOUND;
        statusOut = L"Module enumeration API unavailable.";
        return rows;
    }

    ks::r3::common::UniqueHandle process(::OpenProcess(kProcessReadAccess | PROCESS_QUERY_INFORMATION, FALSE, processId));
    if (!process.valid()) {
        evidence->win32Error = ::GetLastError();
        statusOut = Win32ErrorText(L"OpenProcess", evidence->win32Error);
        return rows;
    }

    DWORD neededBytes = 0;
    std::vector<HMODULE> modules(256);
    for (unsigned attempt = 0;attempt < 4;++attempt) {
        if (!moduleApi.enumProcessModulesEx(process.get(), modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &neededBytes, LIST_MODULES_ALL)) {
            evidence->win32Error = ::GetLastError();
            statusOut = Win32ErrorText(attempt ? L"EnumProcessModulesEx retry" : L"EnumProcessModulesEx", evidence->win32Error);
            return rows;
        }
        if (neededBytes % sizeof(HMODULE) != 0) {evidence->malformed = true;break;}
        if (neededBytes <= modules.size() * sizeof(HMODULE)) {evidence->complete = true;break;}
        if (attempt < 3) modules.resize(neededBytes / sizeof(HMODULE));
    }
    if (evidence->malformed) {evidence->win32Error = ERROR_INVALID_DATA;statusOut = L"Module enumeration API unavailable.";return rows;}
    if (!evidence->complete) evidence->win32Error = ERROR_MORE_DATA;
    modules.resize((std::min)(modules.size(),static_cast<std::size_t>(neededBytes / sizeof(HMODULE))));

    for (HMODULE module : modules) {
        ProcessModuleInfo row{};
        row.moduleHandle = reinterpret_cast<std::uintptr_t>(module);
        MODULEINFO moduleInfo{};
        if (moduleApi.getModuleInformation(process.get(), module, &moduleInfo, sizeof(moduleInfo))) {
            row.infoKnown = moduleInfo.lpBaseOfDll != nullptr && moduleInfo.SizeOfImage != 0;
            row.infoEvidence.available = row.infoKnown;
            row.baseAddress = reinterpret_cast<std::uintptr_t>(moduleInfo.lpBaseOfDll);
            row.imageSize = moduleInfo.SizeOfImage;
        } else {row.infoEvidence = {false,true,false,::GetLastError()};}

        std::wstring path(MAX_PATH, L'\0');
        DWORD copied = moduleApi.getModuleFileNameExW(process.get(), module, path.data(), static_cast<DWORD>(path.size()));
        if (copied >= path.size() - 1) {
            path.resize(kMaxPathBufferChars, L'\0');
            copied = moduleApi.getModuleFileNameExW(process.get(), module, path.data(), static_cast<DWORD>(path.size()));
        }
        if (copied > 0) {
            row.pathKnown = copied < path.size() - 1;
            row.pathEvidence = {row.pathKnown,true,false,static_cast<DWORD>(row.pathKnown ? ERROR_SUCCESS : ERROR_MORE_DATA)};
            path.resize((std::min)(static_cast<std::size_t>(copied),path.size()));
            row.modulePath = path;
            row.moduleName = BaseNameFromPath(path);
            row.statusText = L"OK";
        } else {
            row.pathEvidence = {false,true,false,::GetLastError()};
            row.moduleName = FormatHexPointer(reinterpret_cast<std::uintptr_t>(module));
            row.modulePath = L"<module path unavailable>";
            row.statusText = Win32ErrorText(L"GetModuleFileNameExW", row.pathEvidence.win32Error);
        }
        rows.push_back(std::move(row));
    }

    succeededOut = true;
    statusOut = L"OK";
    std::sort(rows.begin(), rows.end(), [](const ProcessModuleInfo& left, const ProcessModuleInfo& right) {
        return left.baseAddress < right.baseAddress;
    });
    return rows;
}
}
namespace ks::r3::process_detail::detail {
void AttachRepresentativeThreads(
    std::vector<ProcessModuleInfo>& modules,
    const std::vector<ProcessThreadInfo>& threads) {
    if (modules.empty() || threads.empty()) {
        return;
    }

    for (ProcessModuleInfo& module : modules) {
        const std::uintptr_t moduleStart = module.baseAddress;
        const std::uintptr_t moduleEnd = moduleStart + static_cast<std::uintptr_t>(module.imageSize);
        if (moduleStart == 0 || moduleEnd <= moduleStart) {
            continue;
        }

        for (const ProcessThreadInfo& thread : threads) {
            if (thread.creationTime100ns != 0U &&
                thread.startAddress >= moduleStart && thread.startAddress < moduleEnd) {
                module.representativeThreadId = thread.threadId;
                module.representativeThreadCreationTime100ns = thread.creationTime100ns;
                break;
            }
        }
    }
}
}
