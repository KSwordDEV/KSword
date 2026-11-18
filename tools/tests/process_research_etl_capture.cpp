#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <array>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <string>
#include <string_view>

#pragma comment(lib, "advapi32.lib")

namespace
{
    constexpr wchar_t loggerName[] = L"KSword.ProcessResearch.EtlValidation";
    constexpr GUID loggerGuid{0xb189b595,0x151f,0x4da1,{0xa2,0x64,0xc6,0x73,0xd0,0x8e,0x09,0xcf}};
    constexpr GUID threadProvider{0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
    struct TraceProperties {
        EVENT_TRACE_PROPERTIES properties{};
        wchar_t name[128]{};
        wchar_t file[1024]{};
    };
    struct Oracle {
        DWORD markerTid = 0, switches = 0, ready = 0, markerSwitches = 0, markerReady = 0;
        unsigned char switchVersion = 0;
    };
    void WINAPI inspect(EVENT_RECORD* event)
    {
        if (!IsEqualGUID(event->EventHeader.ProviderId, threadProvider) || !event->UserData ||
            event->UserDataLength < sizeof(DWORD)) return;
        auto& counts = *static_cast<Oracle*>(event->UserContext);
        DWORD target = 0;
        std::memcpy(&target, event->UserData, sizeof(target));
        if (event->EventHeader.EventDescriptor.Opcode == 36) {
            ++counts.switches;
            counts.switchVersion = event->EventHeader.EventDescriptor.Version;
            counts.markerSwitches += target == counts.markerTid;
        } else if (event->EventHeader.EventDescriptor.Opcode == 50) {
            ++counts.ready;
            counts.markerReady += target == counts.markerTid;
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring_view(argv[1]) == L"--marker")
    {
        for (int i = 0; i < 45; ++i) { Sleep(3); SwitchToThread(); }
        return 0;
    }
    const bool scheduleOnly = argc == 3 && std::wstring_view(argv[2]) == L"--schedule-only";
    if ((argc != 2 && !scheduleOnly) || wcslen(argv[1]) >= 1024) return ERROR_INVALID_PARAMETER;
    std::array<wchar_t,1024> executable{};
    const auto n = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!n || n >= executable.size()) return ERROR_BAD_PATHNAME;
    std::wstring command = L"\"" + std::wstring(executable.data()) + L"\" --marker";
    auto file = CreateFileW(argv[1], GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return static_cast<int>(GetLastError());
    CloseHandle(file);

    TraceProperties buffer;
    auto& p = buffer.properties;
    p.Wnode.BufferSize = sizeof(buffer);
    p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p.Wnode.Guid = loggerGuid;
    p.Wnode.ClientContext = 1;
    p.LogFileMode = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_FILE_MODE_SEQUENTIAL;
    const ULONG enabled = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISPATCHER |
        (scheduleOnly ? 0 : EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD);
    p.EnableFlags = enabled;
    p.BufferSize = 64;
    p.MinimumBuffers = 32;
    p.MaximumBuffers = 128;
    p.MaximumFileSize = 64;
    p.FlushTimer = 1;
    p.LoggerNameOffset = offsetof(TraceProperties, name);
    p.LogFileNameOffset = offsetof(TraceProperties, file);
    wcscpy_s(buffer.name, loggerName);
    wcscpy_s(buffer.file, argv[1]);
    TRACEHANDLE session{};
    const auto started = StartTraceW(&session, loggerName, &p);
    if (started != ERROR_SUCCESS)
    {
        std::printf("START_ERROR=%lu\n", started);
        DeleteFileW(argv[1]); // reserved with CREATE_NEW before starting this session
        return static_cast<int>(started);
    }

    const auto begin = GetTickCount64();
    PROCESS_INFORMATION child{};
    STARTUPINFOW startup{sizeof(startup)};
    DWORD markerError = ERROR_SUCCESS;
    if (!CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child))
        markerError = GetLastError();
    else
    {
        std::printf("ETL_MARKER_PID=%lu\nETL_MARKER_TID=%lu\n", child.dwProcessId, child.dwThreadId);
        const DWORD wait = WaitForSingleObject(child.hProcess, 5000);
        DWORD childExit = 0;
        if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(child.hProcess, &childExit) || childExit)
            markerError = ERROR_PROCESS_ABORTED;
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
    }
    const auto elapsed = GetTickCount64() - begin;
    if (elapsed < 3000) Sleep(static_cast<DWORD>(3000 - elapsed));
    const auto stopped = ControlTraceW(session, nullptr, &p, EVENT_TRACE_CONTROL_STOP);
    std::printf("SESSION=%ls DURATION_MS=%llu START_FLAGS=0x%lx EVENTS_LOST=%lu BUFFERS_LOST=%lu STOP_RESULT=%lu\n",
        loggerName, GetTickCount64() - begin, enabled, p.EventsLost, p.LogBuffersLost, stopped);
    if (stopped == ERROR_SUCCESS && markerError == ERROR_SUCCESS) {
        Oracle oracle; oracle.markerTid = child.dwThreadId;
        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LogFileName = argv[1]; logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = inspect; logfile.Context = &oracle;
        auto reader = OpenTraceW(&logfile);
        if (reader == INVALID_PROCESSTRACE_HANDLE) return static_cast<int>(GetLastError());
        const auto error = ProcessTrace(&reader, 1, nullptr, nullptr);
        CloseTrace(reader);
        std::printf("NATIVE_ORACLE CSwitch=%lu version=%u ReadyThread=%lu marker_switch=%lu marker_ready=%lu\n",
            oracle.switches, unsigned(oracle.switchVersion), oracle.ready, oracle.markerSwitches, oracle.markerReady);
        if (error || !oracle.markerSwitches || !oracle.markerReady) return ERROR_INVALID_DATA;
    }
    return static_cast<int>(stopped != ERROR_SUCCESS ? stopped : markerError);
}
