"""ETW session lifecycle, provider/consumer failures, cancellation, loss and filtering."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
ULONG WINAPI FixtureStart(PTRACEHANDLE,LPCWSTR,PEVENT_TRACE_PROPERTIES);
ULONG WINAPI FixtureControl(TRACEHANDLE,LPCWSTR,PEVENT_TRACE_PROPERTIES,ULONG);
ULONG WINAPI FixtureEnable(TRACEHANDLE,LPCGUID,ULONG,UCHAR,ULONGLONG,ULONGLONG,ULONG,PENABLE_TRACE_PARAMETERS);
TRACEHANDLE WINAPI FixtureOpen(PEVENT_TRACE_LOGFILEW);
ULONG WINAPI FixtureProcess(PTRACEHANDLE,ULONG,LPFILETIME,LPFILETIME);
ULONG WINAPI FixtureClose(TRACEHANDLE);
BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE,BOOL);
#define StartTraceW FixtureStart
#define ControlTraceW FixtureControl
#define EnableTraceEx2 FixtureEnable
#define OpenTraceW FixtureOpen
#define ProcessTrace FixtureProcess
#define CloseTrace FixtureClose
#define SetConsoleCtrlHandler FixtureConsole
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <string>
static std::wstring mode;static PEVENT_RECORD_CALLBACK callback=nullptr;static void* context=nullptr;static HANDLE stopped=nullptr;
static PHANDLER_ROUTINE control=nullptr;static GUID provider{};static int starts=0,stops=0,closes=0,enables=0;static DWORD opener=0;
BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE handler,BOOL add){control=add?handler:nullptr;return TRUE;}
ULONG WINAPI FixtureStart(PTRACEHANDLE h,LPCWSTR name,PEVENT_TRACE_PROPERTIES properties){++starts;assert(properties->Wnode.ClientContext==2&&properties->FlushTimer==1&&name&&name[0]);
 if(mode==L"start-denied")return 5;if(mode==L"start-unsupported")return 50;if(mode==L"start-positive")return 258;if(mode==L"collision")return 183;*h=123;return 0;}
ULONG WINAPI FixtureEnable(TRACEHANDLE h,LPCGUID guid,ULONG code,UCHAR,ULONGLONG,ULONGLONG,ULONG,PENABLE_TRACE_PARAMETERS){assert(h==123&&code==EVENT_CONTROL_CODE_ENABLE_PROVIDER);++enables;provider=*guid;if(mode==L"enable-unsupported")return 50;if(mode==L"enable-denied"||mode==L"enable-partial"&&enables==1)return 5;return 0;}
TRACEHANDLE WINAPI FixtureOpen(PEVENT_TRACE_LOGFILEW file){opener=GetCurrentThreadId();if(mode==L"open-denied"){SetLastError(5);return INVALID_PROCESSTRACE_HANDLE;}callback=file->EventRecordCallback;context=file->Context;return 456;}
ULONG WINAPI FixtureControl(TRACEHANDLE h,LPCWSTR,PEVENT_TRACE_PROPERTIES properties,ULONG code){assert(h==123&&code==EVENT_TRACE_CONTROL_STOP);++stops;SetEvent(stopped);
 if(mode==L"stop-fail"||mode==L"stop-retry"&&stops==1)return 5;
 properties->EventsLost=mode==L"loss"?7:0;properties->LogBuffersLost=mode==L"loss"?3:0;properties->RealTimeBuffersLost=mode==L"loss"?2:0;return 0;}
ULONG WINAPI FixtureClose(TRACEHANDLE h){assert(h==456);++closes;SetEvent(stopped);return mode==L"close-fail"?5:mode==L"close-pending"?ERROR_CTX_CLOSE_PENDING:0;}
ULONG WINAPI FixtureProcess(PTRACEHANDLE h,ULONG count,LPFILETIME,LPFILETIME){assert(*h==456&&count==1&&opener==GetCurrentThreadId());
 if(mode!=L"empty"&&mode!=L"process-fail-empty")for(int i=0;i<3;++i){EVENT_RECORD record{};record.UserContext=context;record.EventHeader.ProviderId=provider;record.EventHeader.ProcessId=GetCurrentProcessId()+(i==1?1:0);record.EventHeader.ThreadId=opener;
 record.EventHeader.EventDescriptor.Id=static_cast<USHORT>(31000+i);record.EventHeader.EventDescriptor.Level=static_cast<BYTE>(2+i);record.EventHeader.EventDescriptor.Keyword=0x8000000000000001ULL;record.EventHeader.TimeStamp.QuadPart=133000000000000000+i;callback(&record);}
 if(mode==L"early-end")return 0;if(mode==L"cancel"){assert(control);control(CTRL_BREAK_EVENT);}assert(WaitForSingleObject(stopped,5000)==WAIT_OBJECT_0);return mode==L"process-fail"||mode==L"process-fail-empty"?5:0;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];stopped=CreateEventW(nullptr,TRUE,FALSE,nullptr);assert(stopped);
 for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;const auto pid=std::to_wstring(GetCurrentProcessId());for(int i=1;i+1<argc;++i)if(std::wstring(argv[i])==L"--pid"&&std::wstring(argv[i+1])==L"self")argv[i+1]=const_cast<wchar_t*>(pid.c_str());
 ks::cli::registerMonitorEtw();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);assert(starts==1&&closes<=1);if(mode==L"collision")assert(stops==0&&enables==0&&closes==0);if(mode==L"stop-retry")assert(stops==2);
 CloseHandle(stopped);return result;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-etw-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');(directory/'fixture.cpp').write_text(SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3MonitorEtw.cpp','shared/usermode/backend/monitor/EtwSessionController.cpp','shared/usermode/backend/monitor/EtwFilterModel.cpp','shared/usermode/backend/monitor/EtwEventModel.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Ole32.lib','Tdh.lib'],cwd=directory,check=True)
        def run(mode,code,extra=(),default=False):
            args=[] if default else ['--provider','{3BA8F5D1-14C1-4D13-B819-4CF3918867C2}']
            result=subprocess.run([str(binary),mode,'monitor','etw','capture','--duration-ms','100','--json',*args,*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        data=run('valid',0);assert data['receivedCount']=='3' and data['returnedCount']=='3' and data['sessionStopped'] and data['consumerJoined'] and data['statisticsKnown']
        assert data['events'][0]['timestampFileTime']=='133000000000000000' and data['events'][0]['keyword']=='0x8000000000000001'
        assert run('valid',0,('--pid','self','--level','3'))['filteredCount']=='2'
        assert run('empty',0)['returnedCount']=='0'
        assert run('valid',6,('--limit','1'))['droppedFromBufferCount']=='2'
        for mode,code,status in [('start-denied',3,5),('start-unsupported',5,50),('start-positive',3,258),('collision',3,183)]:
            failed=run(mode,code);assert failed['startWin32Error']==status and not failed['startSucceeded'] and failed['stopWin32Errors']==[] and not failed['openAttempted']
        denied=run('enable-denied',3);assert denied['enabledProviderCount']=='0' and denied['sessionStopped'] and denied['providers'][0]['win32Error']==5
        assert run('enable-unsupported',5)['providers'][0]['win32Error']==50
        partial=run('enable-partial',6,default=True);assert int(partial['enabledProviderCount'])>0 and partial['providers'][0]['win32Error']==5
        opened=run('open-denied',3);assert opened['openWin32Error']==5 and opened['sessionStopped'] and not opened['processAttempted']
        assert run('process-fail',6)['processTraceWin32Error']==5
        assert run('process-fail-empty',3)['processTraceWin32Error']==5
        assert run('close-fail',6)['closeTraceWin32Error']==5
        assert run('close-pending',0)['closeTraceWin32Error']==7007
        retried=run('stop-retry',6);assert retried['stopWin32Errors']==[5,0] and retried['sessionStopped']
        stopped=run('stop-fail',6);assert not stopped['sessionStopped'] and not stopped['statisticsKnown'] and stopped['eventsLost'] is None
        loss=run('loss',6);assert loss['eventsLost']=='7' and loss['logBuffersLost']=='3' and loss['realTimeBuffersLost']=='2'
        assert run('cancel',6)['cancelled']
        assert not run('early-end',6)['completedRequestedInterval']
        print('R3_ETW_FIXTURE_PASS startup/provider/consumer/shutdown evidence, no foreign collision stop, bounded buffering, filters, loss, cancellation and owned cleanup retry')
if __name__=='__main__':main()
