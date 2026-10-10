"""Check ETW health, loss and real console cancellation using SDK fixtures."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
ULONG WINAPI FixtureStart(PTRACEHANDLE,LPCWSTR,PEVENT_TRACE_PROPERTIES);
ULONG WINAPI FixtureEnable(TRACEHANDLE,LPCGUID,ULONG,UCHAR,ULONGLONG,ULONGLONG,ULONG,PENABLE_TRACE_PARAMETERS);
PROCESSTRACE_HANDLE WINAPI FixtureOpen(PEVENT_TRACE_LOGFILEW);
ULONG WINAPI FixtureControl(TRACEHANDLE,LPCWSTR,PEVENT_TRACE_PROPERTIES,ULONG);
ULONG WINAPI FixtureProcess(PROCESSTRACE_HANDLE*,ULONG,LPFILETIME,LPFILETIME);
ULONG WINAPI FixtureClose(PROCESSTRACE_HANDLE);
#define StartTraceW FixtureStart
#define EnableTraceEx2 FixtureEnable
#define OpenTraceW FixtureOpen
#define ControlTraceW FixtureControl
#define ProcessTrace FixtureProcess
#define CloseTrace FixtureClose
'''
SOURCE = r'''
#include "mock.h"
#include "REGISTRY"
#include <atomic>
#include <thread>
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
static std::atomic_bool stopped{false},started{false};
static std::atomic_uint stops{0},closes{0};
static EVENT_TRACE_LOGFILEW consumer{};
ULONG WINAPI FixtureStart(PTRACEHANDLE h,LPCWSTR,PEVENT_TRACE_PROPERTIES) {
 if(mode==L"denied")return ERROR_ACCESS_DENIED;*h=91;stopped=false;started=true;return ERROR_SUCCESS;
}
ULONG WINAPI FixtureEnable(TRACEHANDLE,LPCGUID,ULONG,UCHAR,ULONGLONG,ULONGLONG,ULONG,PENABLE_TRACE_PARAMETERS) {return ERROR_SUCCESS;}
PROCESSTRACE_HANDLE WINAPI FixtureOpen(PEVENT_TRACE_LOGFILEW log) {consumer=*log;return static_cast<PROCESSTRACE_HANDLE>(77);}
ULONG WINAPI FixtureControl(TRACEHANDLE,LPCWSTR,PEVENT_TRACE_PROPERTIES p,ULONG action) {
 if(action==EVENT_TRACE_CONTROL_STOP){++stops;p->EventsLost=mode==L"loss"?7:0;stopped=true;}return ERROR_SUCCESS;
}
ULONG WINAPI FixtureProcess(PROCESSTRACE_HANDLE*,ULONG,LPFILETIME,LPFILETIME) {
 if(mode==L"loss"){consumer.EventsLost=7;consumer.BufferCallback(&consumer);}
 while(!stopped)Sleep(5);return ERROR_CANCELLED;
}
ULONG WINAPI FixtureClose(PROCESSTRACE_HANDLE) {++closes;return ERROR_SUCCESS;}
int wmain(int argc,wchar_t* argv[]) {
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 const std::wstring self=std::to_wstring(GetCurrentProcessId());
 for(int i=1;i+1<argc;++i)if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(self.c_str());
 std::thread cancel;
 if(mode==L"cancel")cancel=std::thread([]{while(!started)Sleep(5);Sleep(150);GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,0);});
 ks::cli::registerProcessTelemetry();const int rc=ks::cli::dispatchR3(argc,argv).value_or(1);
 if(cancel.joinable())cancel.join();
 if(mode==L"denied" ? stops!=0 || closes!=0 : stops!=1 || closes!=1)return 9;
 return rc;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-telemetry-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3ProcessTelemetry.cpp', 'KswordCLI/R3Cancellation.cpp',
                   'shared/usermode/backend/process/ProcessEnumerator.cpp', 'shared/usermode/backend/process/ProcessTelemetry.cpp',
                   'shared/usermode/backend/process/ProcessCounters.cpp', 'shared/usermode/backend/Common.cpp',
                   'shared/usermode/backend/NtApi.cpp', 'Ksword5.1/Ksword5.1/ksword/network/network_process_etw_monitor.cpp',
                   'Ksword5.1/Ksword5.1/ksword/string/string.cpp']
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/MT', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary), '/link', 'Advapi32.lib'], cwd=directory, check=True)
        def run(mode, code):
            startup = subprocess.STARTUPINFO()
            startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = subprocess.SW_HIDE
            result = subprocess.run([str(binary), mode, 'process', 'telemetry', 'sample', '--pid', 'self',
                                     '--interval-ms', '1000', '--network', 'on', '--json'], capture_output=True, timeout=15,
                                    creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        healthy = run('healthy', 0)
        assert healthy['networkRateKnown'] and healthy['networkBytesPerSecond'] == 0
        assert healthy['networkHealth']['running'] and not healthy['networkFinalHealth']['running']
        denied = run('denied', 6)
        assert denied['networkHealth']['win32Error'] == 5 and denied['networkBytesPerSecond'] is None
        lost = run('loss', 6)
        assert lost['networkFinalHealth']['eventsLost'] == '7' and lost['networkBytesPerSecond'] is None
        cancelled = run('cancel', 6)
        assert cancelled['cancelled']
        print('R3_TELEMETRY_FIXTURE_PASS ETW availability, loss, console cancellation and exact session/consumer release')


if __name__ == '__main__':
    main()
