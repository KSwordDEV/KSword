#include "ModuleFixtureHost.h"
#include <Windows.h>
#include <sstream>
#include <string>
int RunModuleFixture(const wchar_t* path,const wchar_t* library) {
    const auto module = LoadLibraryW(library);
    if (!module || LoadLibraryW(library) != module) return static_cast<int>(GetLastError());
    const auto start = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(module,"FixtureModuleWorker"));
    if (!start) return ERROR_PROC_NOT_FOUND;
    LONG64 counter = 0;DWORD tid = 0;
    const auto thread = CreateThread(nullptr,0,start,&counter,0,&tid);
    if (!thread) return static_cast<int>(GetLastError());
    FILETIME c{},x{},k{},u{};
    if (!GetThreadTimes(thread,&c,&x,&k,&u)) return static_cast<int>(GetLastError());
    const auto creation = (static_cast<ULONGLONG>(c.dwHighDateTime)<<32) | c.dwLowDateTime;
    const auto temporary = std::wstring(path)+L".tmp";
    for (int tick = 0;tick < 600;++tick) {
        DWORD exitCode = STILL_ACTIVE;GetExitCodeThread(thread,&exitCode);
        std::ostringstream stream;
        stream << "{\"pid\":" << GetCurrentProcessId() << ",\"tid\":" << tid << ",\"creationTime\":\"" << creation
            << "\",\"base\":\"0x" << std::hex << reinterpret_cast<std::uintptr_t>(module) << std::dec
            << "\",\"counter\":\"" << InterlockedCompareExchange64(&counter,0,0) << "\",\"exitCode\":" << exitCode
            << ",\"modulePresent\":" << (GetModuleHandleW(library) ? "true" : "false") << '}';
        const auto bytes = stream.str();
        const auto output = CreateFileW(temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
        if (output == INVALID_HANDLE_VALUE) return static_cast<int>(GetLastError());
        DWORD written = 0;const BOOL ok = WriteFile(output,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr);CloseHandle(output);
        if (!ok || written != bytes.size()) return ERROR_WRITE_FAULT;
        bool moved = false;
        for (int attempt = 0;attempt < 20;++attempt) {
            if (MoveFileExW(temporary.c_str(),path,MOVEFILE_REPLACE_EXISTING)) {moved = true;break;}
            const DWORD error = GetLastError();
            if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED) return static_cast<int>(error);
            Sleep(10);
        }
        if (!moved) return ERROR_SHARING_VIOLATION;
        Sleep(200);
    }
    if (WaitForSingleObject(thread,0) == WAIT_TIMEOUT) TerminateThread(thread,0);
    WaitForSingleObject(thread,2000);CloseHandle(thread);return 0;
}
