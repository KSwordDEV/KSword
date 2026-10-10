"""Real owned helper lifecycle/JSON protocol plus native registry/SCM fault evidence."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
LSTATUS WINAPI FixtureRegOpen(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);LSTATUS WINAPI FixtureRegQuery(HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);LSTATUS WINAPI FixtureRegClose(HKEY);
SC_HANDLE WINAPI FixtureScm(LPCWSTR,LPCWSTR,DWORD);SC_HANDLE WINAPI FixtureService(SC_HANDLE,LPCWSTR,DWORD);BOOL WINAPI FixtureStatus(SC_HANDLE,SC_STATUS_TYPE,LPBYTE,DWORD,LPDWORD);BOOL WINAPI FixtureServiceClose(SC_HANDLE);
BOOL WINAPI FixturePipe(PHANDLE,PHANDLE,LPSECURITY_ATTRIBUTES,DWORD);BOOL WINAPI FixtureHandleInfo(HANDLE,DWORD,DWORD);BOOL WINAPI FixtureClose(HANDLE);
BOOL WINAPI FixtureProcess(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
DWORD WINAPI FixtureWait(HANDLE,DWORD);BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE,BOOL);
#define RegOpenKeyExW FixtureRegOpen
#define RegQueryValueExW FixtureRegQuery
#define RegCloseKey FixtureRegClose
#define OpenSCManagerW FixtureScm
#define OpenServiceW FixtureService
#define QueryServiceStatusEx FixtureStatus
#define CloseServiceHandle FixtureServiceClose
#define CreatePipe FixturePipe
#define SetHandleInformation FixtureHandleInfo
#define CloseHandle FixtureClose
#define CreateProcessW FixtureProcess
#define WaitForSingleObject FixtureWait
#define SetConsoleCtrlHandler FixtureConsole
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include "SECURITY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <set>
#undef CreatePipe
#undef SetHandleInformation
#undef CloseHandle
#undef CreateProcessW
#undef WaitForSingleObject
#undef SetConsoleCtrlHandler
static std::wstring mode;static std::set<HKEY> keys;static std::set<SC_HANDLE> services;static unsigned captureCloses=0;static PHANDLER_ROUTINE handler=nullptr;
static HANDLE h(std::uintptr_t v){return reinterpret_cast<HANDLE>(v);}
LSTATUS WINAPI FixtureRegOpen(HKEY root,LPCWSTR,DWORD,REGSAM access,PHKEY key){assert(root==HKEY_LOCAL_MACHINE&&access==(KEY_QUERY_VALUE|KEY_WOW64_64KEY));*key=nullptr;if(mode==L"reg-absent")return 2;if(mode==L"reg-denied")return 5;if(mode==L"reg-null")return 0;*key=reinterpret_cast<HKEY>(1);assert(keys.insert(*key).second);return 0;}
LSTATUS WINAPI FixtureRegQuery(HKEY key,LPCWSTR,LPDWORD,LPDWORD type,LPBYTE data,LPDWORD bytes){assert(keys.count(key));*type=mode==L"reg-qword"?REG_QWORD:REG_DWORD;const DWORD needed=mode==L"reg-qword"?8:mode==L"reg-malformed"?5:4;if(mode==L"reg-query-denied")return 5;if(mode==L"reg-value-absent")return 2;if(!data){*bytes=mode==L"reg-limit"?65537:needed;return 0;}assert(*bytes>=needed);if(mode==L"reg-growth-limit"){*bytes=65537;return ERROR_MORE_DATA;}*bytes=needed;const std::uint64_t value=mode==L"reg-qword"?9007199254740993ULL:1234;memcpy(data,&value,needed);return 0;}
LSTATUS WINAPI FixtureRegClose(HKEY key){assert(keys.erase(key)==1);return mode==L"reg-close"?5:0;}
SC_HANDLE WINAPI FixtureScm(LPCWSTR,LPCWSTR,DWORD access){assert(access==SC_MANAGER_CONNECT);if(mode==L"scm-denied"){SetLastError(5);return nullptr;}auto value=reinterpret_cast<SC_HANDLE>(2);assert(services.insert(value).second);return value;}
SC_HANDLE WINAPI FixtureService(SC_HANDLE scm,LPCWSTR,DWORD access){assert(services.count(scm)&&access==SERVICE_QUERY_STATUS);if(mode==L"service-absent"){SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);return nullptr;}if(mode==L"service-denied"){SetLastError(5);return nullptr;}auto value=reinterpret_cast<SC_HANDLE>(3);assert(services.insert(value).second);return value;}
BOOL WINAPI FixtureStatus(SC_HANDLE service,SC_STATUS_TYPE cls,LPBYTE data,DWORD bytes,LPDWORD needed){assert(services.count(service)&&cls==SC_STATUS_PROCESS_INFO&&bytes==sizeof(SERVICE_STATUS_PROCESS));if(mode==L"service-query-denied"){SetLastError(5);return FALSE;}auto* status=reinterpret_cast<SERVICE_STATUS_PROCESS*>(data);*status={};status->dwCurrentState=SERVICE_RUNNING;status->dwServiceType=SERVICE_KERNEL_DRIVER;*needed=bytes;return TRUE;}
BOOL WINAPI FixtureServiceClose(SC_HANDLE service){assert(services.erase(service)==1);if(mode==L"service-close"){SetLastError(5);return FALSE;}return TRUE;}
BOOL WINAPI FixturePipe(PHANDLE read,PHANDLE write,LPSECURITY_ATTRIBUTES sa,DWORD bytes){if(mode==L"pipe-denied"){SetLastError(5);return FALSE;}return ::CreatePipe(read,write,sa,bytes);}
BOOL WINAPI FixtureHandleInfo(HANDLE handle,DWORD mask,DWORD flags){if(mode==L"inherit-denied"){SetLastError(5);return FALSE;}return ::SetHandleInformation(handle,mask,flags);}
BOOL WINAPI FixtureClose(HANDLE handle){++captureCloses;const auto closed=::CloseHandle(handle);if(mode==L"capture-close"){SetLastError(5);return FALSE;}return closed;}
BOOL WINAPI FixtureProcess(LPCWSTR app,LPWSTR args,LPSECURITY_ATTRIBUTES process,LPSECURITY_ATTRIBUTES thread,BOOL inherit,DWORD flags,LPVOID env,LPCWSTR cwd,LPSTARTUPINFOW startup,LPPROCESS_INFORMATION result){assert(flags==CREATE_NO_WINDOW&&startup->wShowWindow==SW_HIDE);if(mode==L"create-denied"){SetLastError(5);return FALSE;}return ::CreateProcessW(app,args,process,thread,inherit,flags,env,cwd,startup,result);}
BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE value,BOOL add){handler=add?value:nullptr;return ::SetConsoleCtrlHandler(value,add);}
DWORD WINAPI FixtureWait(HANDLE process,DWORD duration){if(mode==L"wait-denied"){SetLastError(5);return WAIT_FAILED;}const auto wait=::WaitForSingleObject(process,duration);if(mode==L"helper-cancel"&&handler&&duration==25)handler(CTRL_BREAK_EVENT);return wait;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::cli::registerSecurityCi();ks::cli::security::add(L"fixture helper query",L"Fixture only",[](const ks::cli::Args& args){
  std::wstring body=L"[ordered]@{available=$true;count=[uint64]9007199254740993;text=([char]0x6d4b).ToString()}|ConvertTo-Json -Compress";
  if(mode==L"helper-unavailable")body=L"[ordered]@{available=$false;reason='fixture'}|ConvertTo-Json -Compress;exit 5";
  if(mode==L"helper-partial")body+=L";exit 6";if(mode==L"helper-empty")body=L"exit 0";if(mode==L"helper-bad")body=L"Write-Output 'not JSON'";if(mode==L"helper-float")body=L"[ordered]@{available=$true;value=1.5}|ConvertTo-Json -Compress";
  if(mode==L"helper-size")body=L"[Console]::Write(('x'*140000))";if(mode==L"helper-utf8")body=L"[Console]::OpenStandardOutput().WriteByte(255)";if(mode==L"helper-timeout"||mode==L"helper-cancel")body=L"Start-Sleep -Milliseconds 2000";
  std::vector<ks::r3::security::SecurityProbe> probes{{L"fixture",L"self-owned read-only helper",ks::r3::security::SecurityProbeKind::Command,body,{},{}}};return ks::cli::security::query(args,probes);
 });const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);assert(keys.empty()&&services.empty());if(mode==L"valid-helper"||mode==L"helper-unavailable"||mode==L"helper-partial"||mode==L"helper-empty"||mode==L"helper-bad"||mode==L"helper-size"||mode==L"helper-utf8"||mode==L"helper-float"||mode==L"helper-timeout"||mode==L"helper-cancel"||mode==L"capture-close"||mode==L"wait-denied")assert(captureCloses==4);return code;
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-security-ci-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');source=SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('"SECURITY"','"'+(ROOT/'KswordCLI/R3SecurityShared.h').as_posix()+'"');(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SecurityCi.cpp','shared/usermode/backend/security/CodeIntegrity.cpp','shared/usermode/backend/Common.cpp','shared/evidence/EvidenceJson.cpp','shared/evidence/LosslessValue.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Crypt32.lib'],cwd=directory,check=True)
        def run(mode,code,branch='registry',extra=()):
            args=['fixture','helper','query'] if branch=='helper' else ['security','ci',branch,'query']
            result=subprocess.run([str(binary),mode,*args,'--json',*extra],capture_output=True,timeout=12)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        assert run('valid',0)['evidence'][0]['data']['value']==1234
        assert run('reg-qword',0)['evidence'][0]['data']['value']=='9007199254740993'
        for mode in ('reg-absent','reg-value-absent'):assert run(mode,0)['evidence'][0]['data']['absent']
        for mode in ('reg-denied','reg-query-denied'):run(mode,3)
        for mode in ('reg-null','reg-malformed'):run(mode,4)
        for mode in ('reg-limit','reg-growth-limit','reg-close'):run(mode,6)
        assert run('valid',0,'service')['evidence'][0]['data']['state']==4
        assert run('service-absent',0,'service')['evidence'][0]['data']['state'] is None
        for mode in ('scm-denied','service-denied','service-query-denied'):run(mode,3,'service')
        run('service-close',6,'service')
        helper=run('valid-helper',0,'helper');assert helper['evidence'][0]['data']['count']=='9007199254740993' and helper['evidence'][0]['data']['text']=='\u6d4b'
        run('helper-unavailable',5,'helper');run('helper-partial',6,'helper')
        for mode in ('helper-empty','helper-bad','helper-float','helper-utf8'):run(mode,4,'helper')
        assert run('helper-size',6,'helper')['evidence'][0]['capture']['outputTruncated']
        timeout=run('helper-timeout',3,'helper',('--timeout-ms','500'));assert timeout['evidence'][0]['capture']['timedOut'] and timeout['evidence'][0]['capture']['terminated']
        assert run('helper-cancel',6,'helper')['evidence'][0]['capture']['cancelled']
        for mode in ('pipe-denied','inherit-denied','create-denied','wait-denied'):run(mode,3,'helper')
        run('capture-close',6,'helper')
        print('R3_SECURITY_CI_FIXTURE_PASS native registry/SCM absence/errors/limits/closure, real encoded UTF-8 JSON helper, large integer preservation, invalid/empty/float data, output draining, timeout/cancel/termination and owned handle lifecycle')
if __name__=='__main__':main()
