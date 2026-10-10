#include "ThreadFixture.h"
#include <Windows.h>
#include <array>
#include <sstream>
#include <string>
namespace {
std::array<LONG64,3> counters{};
DWORD WINAPI worker(void* context) {
    auto* count = static_cast<LONG64*>(context);
    for (;;) {InterlockedIncrement64(count);Sleep(50);}
}
}
int RunThreadFixture(const wchar_t* path) {
    std::array<HANDLE,3> handles{};std::array<DWORD,3> ids{};
    for (std::size_t i = 0;i < handles.size();++i) {
        handles[i] = CreateThread(nullptr,0,worker,&counters[i],0,&ids[i]);
        if (!handles[i]) return static_cast<int>(GetLastError());
    }
    const std::wstring temporary = std::wstring(path)+L".tmp";
    for (int tick = 0;tick < 600;++tick) {
        std::ostringstream stream;
        stream << "{\"pid\":" << GetCurrentProcessId() << ",\"workers\":[";
        for (std::size_t i = 0;i < handles.size();++i) {
            FILETIME c{},x{},k{},u{};GetThreadTimes(handles[i],&c,&x,&k,&u);
            const auto creation = (static_cast<ULONGLONG>(c.dwHighDateTime)<<32) | c.dwLowDateTime;
            DWORD exitCode = STILL_ACTIVE;GetExitCodeThread(handles[i],&exitCode);
            if (i) stream << ',';
            stream << "{\"tid\":" << ids[i] << ",\"creationTime\":\"" << creation << "\",\"counter\":\""
                << InterlockedCompareExchange64(&counters[i],0,0) << "\",\"exitCode\":" << exitCode << '}';
        }
        stream << "]}";
        const auto bytes = stream.str();
        const HANDLE output = CreateFileW(temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
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
    for (const auto h : handles) {TerminateThread(h,1);WaitForSingleObject(h,2000);CloseHandle(h);}
    return 0;
}
