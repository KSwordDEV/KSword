"""Clock/zone/bias and W32Time native reply semantics, without changing the clock or registry."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
VOID WINAPI FixtureLocal(LPSYSTEMTIME);VOID WINAPI FixtureUtc(LPSYSTEMTIME);VOID WINAPI FixtureFileTime(LPFILETIME);
DWORD WINAPI FixtureZone(LPTIME_ZONE_INFORMATION);DWORD WINAPI FixtureDynamic(PDYNAMIC_TIME_ZONE_INFORMATION);ULONGLONG WINAPI FixtureTick();
LSTATUS WINAPI FixtureOpen(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);LSTATUS WINAPI FixtureEnum(HKEY,DWORD,LPWSTR,LPDWORD,LPDWORD,LPDWORD,LPBYTE,LPDWORD);LSTATUS WINAPI FixtureClose(HKEY);
#define GetLocalTime FixtureLocal
#define GetSystemTime FixtureUtc
#define GetSystemTimeAsFileTime FixtureFileTime
#define GetTimeZoneInformation FixtureZone
#define GetDynamicTimeZoneInformation FixtureDynamic
#define GetTickCount64 FixtureTick
#define RegOpenKeyExW FixtureOpen
#define RegEnumValueW FixtureEnum
#define RegCloseKey FixtureClose
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <string>
static std::wstring mode;static int closes=0;static DWORD owner=0;
VOID WINAPI FixtureUtc(LPSYSTEMTIME time){*time={2026,10,6,10,9,20,30,111};if(mode==L"bad-calendar")time->wMonth=99;}
VOID WINAPI FixtureLocal(LPSYSTEMTIME time){FixtureUtc(time);time->wHour=17;}
VOID WINAPI FixtureFileTime(LPFILETIME time){const ULONGLONG value=mode==L"underflow"?1:134361000000000000ULL;time->dwLowDateTime=static_cast<DWORD>(value);time->dwHighDateTime=static_cast<DWORD>(value>>32);}
DWORD WINAPI FixtureZone(LPTIME_ZONE_INFORMATION zone){*zone={};zone->Bias=mode==L"bias-min"?LONG_MIN:mode==L"bias-overflow"?LONG_MAX:-480;zone->StandardBias=mode==L"bias-overflow"?1:0;zone->DaylightBias=-60;
 wcscpy_s(zone->StandardName,L"Fixture standard");wcscpy_s(zone->DaylightName,L"Fixture daylight");if(mode==L"bad-zone-name")for(auto& c:zone->StandardName)c=L'x';
 if(mode==L"zone-failed"){SetLastError(5);return TIME_ZONE_ID_INVALID;}return mode==L"bad-zone-state"?17:mode==L"daylight"?TIME_ZONE_ID_DAYLIGHT:TIME_ZONE_ID_STANDARD;}
DWORD WINAPI FixtureDynamic(PDYNAMIC_TIME_ZONE_INFORMATION zone){*zone={};wcscpy_s(zone->TimeZoneKeyName,L"Fixture zone");zone->DynamicDaylightTimeDisabled=TRUE;
 if(mode==L"dynamic-failed"){SetLastError(50);return TIME_ZONE_ID_INVALID;}if(mode==L"bad-dynamic-name")for(auto& c:zone->TimeZoneKeyName)c=L'x';return TIME_ZONE_ID_STANDARD;}
ULONGLONG WINAPI FixtureTick(){return mode==L"tick-overflow"?~0ULL:1000;}
LSTATUS WINAPI FixtureOpen(HKEY hive,LPCWSTR path,DWORD,REGSAM,PHKEY key){assert(hive==HKEY_LOCAL_MACHINE&&wcscmp(path,L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters")==0);owner=GetCurrentThreadId();if(mode==L"missing-key")return 2;if(mode==L"denied-key")return 5;*key=reinterpret_cast<HKEY>(1);return 0;}
LSTATUS WINAPI FixtureEnum(HKEY key,DWORD index,LPWSTR name,LPDWORD nameLength,LPDWORD,LPDWORD type,LPBYTE data,LPDWORD size){assert(owner==GetCurrentThreadId()&&key==reinterpret_cast<HKEY>(1));
 if(mode==L"enum-failed")return 5;if(mode==L"empty-key"||index>0)return ERROR_NO_MORE_ITEMS;
 if(mode==L"registry-growth"){*size=32u*1024u*1024u;return ERROR_MORE_DATA;}
 std::vector<BYTE> value;
 if(mode==L"qword"){*type=REG_QWORD;const ULONGLONG n=9007199254740993ULL;value.resize(8);memcpy(value.data(),&n,8);}
 else if(mode==L"short-dword"){*type=REG_DWORD;value={1,2};}
 else if(mode==L"empty-multi"){*type=REG_MULTI_SZ;value={0,0};}
 else if(mode==L"unterminated-multi"){*type=REG_MULTI_SZ;value={65,0,0,0};}
 else if(mode==L"unterminated-string"){*type=REG_SZ;value={65,0,66,0};}
 else if(mode==L"odd-string"){*type=REG_SZ;value={65,0,0};}
 else if(mode==L"binary-growth"){*type=REG_BINARY;value.resize(8192,0x7f);}
 else {*type=REG_SZ;const wchar_t* text=L"NTP";value.resize((wcslen(text)+1)*sizeof(wchar_t));memcpy(value.data(),text,value.size());}
 if(*size<value.size()){*size=static_cast<DWORD>(value.size());return ERROR_MORE_DATA;}memcpy(data,value.data(),value.size());*size=static_cast<DWORD>(value.size());
 wcscpy_s(name,*nameLength,L"Type");*nameLength=4;if(mode==L"bad-name-length")*nameLength=16384;if(mode==L"bad-data-size")*size=65536;return 0;
}
LSTATUS WINAPI FixtureClose(HKEY key){assert(owner==GetCurrentThreadId()&&key==reinterpret_cast<HKEY>(1));++closes;return mode==L"close-failed"?5:0;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::cli::registerSystemTime();const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);assert(closes==(mode==L"missing-key"||mode==L"denied-key"?0:1));return code;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-system-time-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');(directory/'fixture.cpp').write_text(SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()),encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3SystemTime.cpp','shared/usermode/backend/system/SystemTimeInfo.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'system','time','query','--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['clock']['utcFileTime']=='134361000000000000' and valid['zone']['effectiveBiasMinutes']==-480 and valid['clock']['local']['hour']==17
        assert valid['uptime']['estimatedBootFileTime']=='134360999990000000' and valid['w32time']['values'][0]['dataHex']=='4e00540050000000'
        assert run('daylight',0)['zone']['effectiveBiasMinutes']==-540
        assert run('bias-min',0)['zone']['effectiveBiasMinutes']==-2147483648
        failed=run('zone-failed',6)['zone'];assert not failed['available'] and failed['effectiveBiasMinutes'] is None and failed['win32Error']==5
        assert run('dynamic-failed',6)['dynamicZone']['dynamicDaylightTimeDisabled'] is None
        for mode in ('bad-calendar','bad-zone-state','bad-zone-name','bad-dynamic-name','bias-overflow'):run(mode,4)
        assert run('bad-calendar',4)['clock']['utcRaw']['month']==99
        for mode in ('underflow','tick-overflow'):assert run(mode,6)['uptime']['estimatedBootFileTime'] is None
        assert run('qword',0)['w32time']['values'][0]['numericValue']=='9007199254740993'
        assert run('empty-key',0)['w32time']['valueCount']=='0'
        assert run('empty-multi',0)['w32time']['values'][0]['dataHex']=='0000'
        for mode in ('short-dword','odd-string','unterminated-string','unterminated-multi','bad-name-length','bad-data-size'):run(mode,4)
        assert run('missing-key',6)['w32time']['absent']
        assert run('denied-key',6)['w32time']['openWin32Error']==5
        assert run('enum-failed',6)['w32time']['enumWin32Error']==5
        assert run('close-failed',6)['w32time']['closeWin32Error']==5
        assert run('registry-growth',6)['w32time']['limited']
        assert run('binary-growth',0,('--max-data-bytes','8192'))['w32time']['values'][0]['byteCount']=='8192'
        assert run('valid',6,('--max-data-bytes','1'))['w32time']['values'][0]['dataTruncated']
        print('R3_SYSTEM_TIME_FIXTURE_PASS clock/bias/time-zone availability, bounded names and registry values, raw u64, boot overflow/underflow, empty MULTI_SZ, registry failures and close ownership')
if __name__=='__main__':main()
