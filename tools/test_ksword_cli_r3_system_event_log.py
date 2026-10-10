"""Native wevtapi fields/layouts/messages/lifecycle, using the production CLI adapter."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
#include <winevt.h>
EVT_HANDLE WINAPI FixtureQuery(EVT_HANDLE,LPCWSTR,LPCWSTR,DWORD);
EVT_HANDLE WINAPI FixtureContext(DWORD,LPCWSTR*,DWORD);
BOOL WINAPI FixtureNext(EVT_HANDLE,DWORD,PEVT_HANDLE,DWORD,DWORD,PDWORD);
BOOL WINAPI FixtureRender(EVT_HANDLE,EVT_HANDLE,DWORD,DWORD,PVOID,PDWORD,PDWORD);
EVT_HANDLE WINAPI FixtureMetadata(EVT_HANDLE,LPCWSTR,LPCWSTR,LCID,DWORD);
BOOL WINAPI FixtureMessage(EVT_HANDLE,EVT_HANDLE,DWORD,DWORD,PEVT_VARIANT,DWORD,DWORD,LPWSTR,PDWORD);
BOOL WINAPI FixtureClose(EVT_HANDLE);BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE,BOOL);
#define EvtQuery FixtureQuery
#define EvtCreateRenderContext FixtureContext
#define EvtNext FixtureNext
#define EvtRender FixtureRender
#define EvtOpenPublisherMetadata FixtureMetadata
#define EvtFormatMessage FixtureMessage
#define EvtClose FixtureClose
#define SetConsoleCtrlHandler FixtureConsole
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <set>
#include <string>
static std::wstring mode;static std::set<EVT_HANDLE> live;static DWORD owner=0;static int issued=0,metadataCalls=0,messageCalls=0;
static PHANDLER_ROUTINE control=nullptr;
static EVT_HANDLE handle(std::uintptr_t value){return reinterpret_cast<EVT_HANDLE>(value);}
static EVT_HANDLE acquire(std::uintptr_t value){const auto h=handle(value);assert(live.insert(h).second);return h;}
static void same(){assert(owner==GetCurrentThreadId());}
BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE handler,BOOL add){control=add?handler:nullptr;return TRUE;}
EVT_HANDLE WINAPI FixtureQuery(EVT_HANDLE,LPCWSTR channel,LPCWSTR query,DWORD flags){owner=GetCurrentThreadId();assert(wcscmp(channel,L"System")==0&&query&&flags==(EvtQueryChannelPath|EvtQueryReverseDirection));if(mode==L"query-denied"||mode==L"query-unsupported"){SetLastError(mode==L"query-denied"?5:50);return nullptr;}return acquire(1);}
EVT_HANDLE WINAPI FixtureContext(DWORD count,LPCWSTR*,DWORD flags){same();assert(count==0&&flags==EvtRenderContextSystem);if(mode==L"context-denied"){SetLastError(5);return nullptr;}return acquire(2);}
BOOL WINAPI FixtureNext(EVT_HANDLE h,DWORD count,PEVT_HANDLE events,DWORD timeout,DWORD,PDWORD returned){same();assert(h==handle(1)&&timeout==5000&&count<=32);
 if(mode==L"next-denied"||mode==L"next-partial"&&issued){SetLastError(5);return FALSE;}
 if(mode==L"empty"||issued>=3){SetLastError(ERROR_NO_MORE_ITEMS);return FALSE;}
 const auto n=(std::min)(count,static_cast<DWORD>(3-issued));for(DWORD i=0;i<n;++i)events[i]=acquire(100+issued++);*returned=n;
 if(mode==L"bad-count")*returned=count+1;if(mode==L"zero-count")*returned=0;
 if(mode==L"duplicate-event"&&n>1){live.erase(events[1]);events[1]=events[0];}return TRUE;
}
BOOL WINAPI FixtureRender(EVT_HANDLE ctx,EVT_HANDLE event,DWORD flags,DWORD size,PVOID buffer,PDWORD used,PDWORD count){same();assert(ctx==handle(2)&&flags==EvtRenderEventValues&&live.count(event));
 if(mode==L"render-denied"||mode==L"render-partial"&&event==handle(100)){SetLastError(5);return FALSE;}
 if(mode==L"render-growth"){*used=32u*1024u*1024u;SetLastError(122);return FALSE;}
 const DWORD total=EvtSystemPropertyIdEND;const auto bytes=total*sizeof(EVT_VARIANT)+100;
 if(size<bytes){*used=static_cast<DWORD>(bytes);SetLastError(122);return FALSE;}*used=static_cast<DWORD>(bytes);*count=total;memset(buffer,0,bytes);
 auto* values=static_cast<PEVT_VARIANT>(buffer);auto* text=reinterpret_cast<wchar_t*>(static_cast<BYTE*>(buffer)+total*sizeof(EVT_VARIANT));wcscpy_s(text,50,L"FixtureProvider");wcscpy_s(text+20,30,L"FixtureComputer");
 values[EvtSystemProviderName].Type=EvtVarTypeString;values[EvtSystemProviderName].StringVal=text;
 values[EvtSystemComputer].Type=EvtVarTypeString;values[EvtSystemComputer].StringVal=text+20;
 values[EvtSystemEventID].Type=EvtVarTypeUInt16;values[EvtSystemEventID].UInt16Val=321;
 values[EvtSystemLevel].Type=EvtVarTypeByte;values[EvtSystemLevel].ByteVal=0;
 values[EvtSystemTimeCreated].Type=EvtVarTypeFileTime;values[EvtSystemTimeCreated].FileTimeVal=133000000000000000ULL;
 values[EvtSystemEventRecordId].Type=EvtVarTypeUInt64;values[EvtSystemEventRecordId].UInt64Val=9007199254741000ULL+103-reinterpret_cast<std::uintptr_t>(event);
 values[EvtSystemProcessID].Type=mode==L"null-pid"?EvtVarTypeNull:EvtVarTypeUInt32;values[EvtSystemProcessID].UInt32Val=0;
 if(mode==L"bad-variant")values[EvtSystemEventID].Type=EvtVarTypeString;
 if(mode==L"bad-pointer")values[EvtSystemProviderName].StringVal=reinterpret_cast<LPCWSTR>(1);
 if(mode==L"bad-property-count")*count=10000;if(mode==L"zero-properties")*count=0;
 if(mode==L"cancel"){assert(control);control(CTRL_BREAK_EVENT);}if(mode==L"deadline")Sleep(110);return TRUE;
}
EVT_HANDLE WINAPI FixtureMetadata(EVT_HANDLE,LPCWSTR,LPCWSTR,LCID,DWORD){same();++metadataCalls;if(mode==L"metadata-denied"){SetLastError(2);return nullptr;}return acquire(3);}
BOOL WINAPI FixtureMessage(EVT_HANDLE metadata,EVT_HANDLE,DWORD,DWORD,PEVT_VARIANT,DWORD flags,DWORD length,LPWSTR buffer,PDWORD used){same();assert(metadata==handle(3)&&flags==EvtFormatMessageEvent);++messageCalls;
 if(mode==L"message-empty"){*used=0;return TRUE;}
 if(mode==L"message-denied"){SetLastError(15027);return FALSE;}
 if(mode==L"message-growth"){*used=65537;SetLastError(122);return FALSE;}
 const wchar_t* text=L"Quoted \"message\"\r\nsecond line";*used=static_cast<DWORD>(wcslen(text)+1);if(!length){SetLastError(122);return FALSE;}
 assert(length>=*used);wcscpy_s(buffer,length,text);if(mode==L"message-no-terminator")buffer[*used-1]=L'x';
 if(mode==L"message-partial"){SetLastError(ERROR_EVT_UNRESOLVED_VALUE_INSERT);return FALSE;}return TRUE;
}
BOOL WINAPI FixtureClose(EVT_HANDLE h){same();assert(live.erase(h)==1);if(mode==L"close-denied"){SetLastError(5);return FALSE;}return TRUE;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::cli::registerSystemEventLog();const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);assert(live.empty());bool messages=false;for(int i=1;i<argc;++i)if(std::wstring(argv[i])==L"on")messages=true;if(!messages)assert(metadataCalls==0&&messageCalls==0);return code;
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-event-log-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');(directory/'fixture.cpp').write_text(SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SystemEventLog.cpp','shared/usermode/backend/system/EventLogReader.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Wevtapi.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'system','event-log','query','--limit','10','--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['returnedCount']=='3' and valid['pageComplete'] and valid['channelExhausted'] and valid['closeAttemptedCount']=='5'
        row=valid['events'][0];assert row['recordId']=='9007199254741003' and row['timestampFileTime']=='133000000000000000' and row['level']==0 and row['headerPid']==0 and row['message'] is None
        assert run('empty',0)['returnedCount']=='0'
        for mode,code,error in [('query-denied',3,5),('query-unsupported',5,50)]:assert run(mode,code)['queryWin32Error']==error
        assert run('context-denied',3)['contextWin32Error']==5
        assert run('next-denied',3)['nextWin32Error']==5
        assert run('next-partial',6)['returnedCount']=='3'
        assert run('render-denied',3)['renderFailedCount']=='3'
        assert run('render-partial',6)['renderFailedCount']=='1'
        for mode in ('bad-count','zero-count','duplicate-event','bad-variant','bad-pointer','bad-property-count'):assert run(mode,4)['malformed']
        assert run('render-growth',6)['limited']
        assert run('null-pid',0)['events'][0]['headerPid'] is None
        assert run('zero-properties',6)['events'][0]['eventId'] is None
        message=run('valid',0,('--messages','on'))['events'][0];assert '\r\n' in message['message'] and message['messageAvailable'] and not message['messagePartial']
        assert run('message-empty',0,('--messages','on'))['events'][0]['message']==''
        assert run('metadata-denied',6,('--messages','on'))['events'][0]['metadataWin32Error']==2
        assert run('message-denied',6,('--messages','on'))['events'][0]['messageWin32Error']==15027
        partial=run('message-partial',6,('--messages','on'))['events'][0];assert partial['messageAvailable'] and partial['messagePartial']
        assert run('message-growth',6,('--messages','on'))['events'][0]['messageLimited']
        assert run('message-no-terminator',4,('--messages','on'))['events'][0]['messageMalformed']
        assert run('close-denied',6)['closeFailedCount']=='5'
        assert run('cancel',6)['cancelled']
        assert run('deadline',6,('--duration-ms','100'))['limited']
        print('R3_EVENT_LOG_FIXTURE_PASS query/context/next/render/close failures, bounded variants/pointers/messages, null vs zero, raw u64/FILETIME, metadata off, partial descriptions, cancellation and thread-owned cleanup')
if __name__=='__main__':main()
