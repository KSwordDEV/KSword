"""Production file-holder scanner with real helper threads and owned file duplicates."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
HANDLE WINAPI FixtureCreateFile(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
BOOL WINAPI FixtureDuplicate(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD);
BOOL WINAPI FixtureClose(HANDLE);DWORD WINAPI FixtureType(HANDLE);
DWORD WINAPI FixtureDosDevice(LPCWSTR,LPWSTR,DWORD);
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR);
BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE,BOOL);
DWORD WINAPI FixtureWait(HANDLE,DWORD);
#define CreateFileW FixtureCreateFile
#define DuplicateHandle FixtureDuplicate
#define CloseHandle FixtureClose
#define GetFileType FixtureType
#define QueryDosDeviceW FixtureDosDevice
#define GetProcAddress FixtureProcedure
#define SetConsoleCtrlHandler FixtureConsole
#define WaitForSingleObject FixtureWait
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include "NTAPI"
#include <winternl.h>
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <mutex>
#include <set>
#include <string>
#undef CreateFileW
#undef DuplicateHandle
#undef CloseHandle
#undef GetFileType
#undef QueryDosDeviceW
#undef GetProcAddress
#undef SetConsoleCtrlHandler
#undef WaitForSingleObject
static std::wstring mode,targetName;static HANDLE probe=nullptr;static std::vector<HANDLE> sources;static std::mutex gate;static std::set<HANDLE> copies;static std::atomic_int queries{0};
static PHANDLER_ROUTINE control=nullptr;
BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE handler,BOOL add){control=add?handler:nullptr;return TRUE;}
DWORD WINAPI FixtureWait(HANDLE handle,DWORD duration){if(mode==L"wait-failed"&&duration==250){SetLastError(6);return WAIT_FAILED;}return WaitForSingleObject(handle,duration);}
HANDLE WINAPI FixtureCreateFile(LPCWSTR path,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD flags,HANDLE templ){const auto handle=CreateFileW(path,access,share,security,disposition,flags,templ);if(handle!=INVALID_HANDLE_VALUE)probe=handle;return handle;}
BOOL WINAPI FixtureDuplicate(HANDLE process,HANDLE source,HANDLE current,LPHANDLE output,DWORD access,BOOL inherit,DWORD options){if(mode==L"duplicate-denied"){SetLastError(5);return FALSE;}const bool success=DuplicateHandle(process,source,current,output,access,inherit,options)!=FALSE;if(success){std::lock_guard<std::mutex> lock(gate);assert(copies.insert(*output).second);}return success;}
BOOL WINAPI FixtureClose(HANDLE handle){{std::lock_guard<std::mutex> lock(gate);copies.erase(handle);}return CloseHandle(handle);}
DWORD WINAPI FixtureType(HANDLE handle){if(mode==L"pipe")return FILE_TYPE_PIPE;if(mode==L"type-denied"){SetLastError(5);return FILE_TYPE_UNKNOWN;}return GetFileType(handle);}
DWORD WINAPI FixtureDosDevice(LPCWSTR drive,LPWSTR value,DWORD length){if(wcscmp(drive,L"C:")!=0){SetLastError(2);return 0;}const wchar_t* text=L"\\Device\\Mock";wcscpy_s(value,length,text);return static_cast<DWORD>(wcslen(text)+1);}
LONG NTAPI FixtureObject(HANDLE,ULONG information,PVOID data,ULONG length,PULONG needed){assert(information==1);++queries;if(mode==L"timeout")Sleep(350);if(mode==L"cancel"){assert(control);control(CTRL_C_EVENT);}if(mode==L"name-positive")return 258;
 if(mode==L"name-growth"){*needed=32u*1024u*1024u;return static_cast<LONG>(0xc0000023UL);}
 const auto bytes=static_cast<ULONG>(sizeof(UNICODE_STRING)+targetName.size()*sizeof(wchar_t));assert(length>=bytes);*needed=bytes;auto* name=static_cast<UNICODE_STRING*>(data);name->Length=static_cast<USHORT>(targetName.size()*sizeof(wchar_t));name->MaximumLength=name->Length;
 name->Buffer=mode==L"bad-pointer"?reinterpret_cast<LPWSTR>(1):reinterpret_cast<LPWSTR>(static_cast<BYTE*>(data)+sizeof(UNICODE_STRING));if(mode!=L"bad-pointer")memcpy(name->Buffer,targetName.data(),name->Length);if(mode==L"odd-name")++name->Length;return 0;}
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR name){return mode==L"api-missing"?nullptr:strcmp(name,"NtQueryObject")==0?reinterpret_cast<FARPROC>(FixtureObject):nullptr;}
struct Entry {void* object;ULONG_PTR pid,handle;ULONG access;USHORT trace,type;ULONG attributes,reserved;};
struct Table {ULONG_PTR count,reserved;Entry entries[1];};
namespace ks::r3::common {
NtApi::NtApi():querySystemInformation_(nullptr){}bool NtApi::available()const{return mode!=L"snapshot-api-missing";}
LONG NtApi::querySystemInformation(SystemInformationClass cls,void* buffer,ULONG size,ULONG* needed)const{
 assert(static_cast<ULONG>(cls)==64);if(mode==L"snapshot-denied")return static_cast<LONG>(0xc0000022UL);if(mode==L"snapshot-positive")return 258;
 if(mode==L"snapshot-budget"){*needed=MAXDWORD;return static_cast<LONG>(0xc0000004UL);}
 const auto count=mode==L"empty"?0:sources.size()+1+(mode==L"protected"||mode==L"open-denied"?1:0);*needed=static_cast<ULONG>(offsetof(Table,entries)+count*sizeof(Entry));assert(*needed<=size);auto* info=static_cast<Table*>(buffer);info->count=mode==L"bad-count"?count+1:count;info->reserved=0;
 if(mode==L"short-header"){*needed=1;return 0;}if(!count)return 0;info->entries[0]={nullptr,GetCurrentProcessId(),reinterpret_cast<ULONG_PTR>(probe),FILE_READ_ATTRIBUTES,0,37,0,0};
 for(std::size_t i=0;i<sources.size();++i)info->entries[i+1]={nullptr,GetCurrentProcessId(),reinterpret_cast<ULONG_PTR>(sources[i]),0x120089,0,37,0,0};
 if(count>sources.size()+1)info->entries[count-1]={nullptr,mode==L"protected"?4u:MAXDWORD,123,0,0,37,0,0};return 0;
}
}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 std::wstring path;for(int i=1;i+1<argc;++i)if(std::wstring(argv[i])==L"--path")path=argv[i+1];assert(path.size()>2&&path[1]==L':');wchar_t expanded[32768]{};const auto n=GetLongPathNameW(path.c_str(),expanded,32768);if(n&&n<32768)path.assign(expanded,n);targetName=L"\\Device\\Mock"+path.substr(2);
 for(int i=0;i<(mode==L"timeout"?5:2);++i){const auto handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);assert(handle!=INVALID_HANDLE_VALUE);sources.push_back(handle);}
 ks::cli::registerSystemFileHolders();const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);if(mode==L"timeout"||mode==L"wait-failed")Sleep(700);{std::lock_guard<std::mutex> lock(gate);assert(copies.empty());}for(const auto handle:sources)CloseHandle(handle);if(mode==L"pipe"||mode==L"type-denied")assert(queries==0);return code;
}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-file-holders-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');source=SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('NTAPI',(ROOT/'shared/usermode/backend/NtApi.h').as_posix(),1)
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe';target=directory/'held.bin';target.write_bytes(b'fixture')
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SystemFileHolders.cpp','shared/usermode/backend/system/FileHolderScanner.cpp','shared/usermode/backend/system/ModulePath.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'system','file-holders','query','--path',str(target),'--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['matchedCount']=='2' and valid['complete'] and valid['timeoutCount']=='0'
        assert all(row['processCreationTime'] and row['processAlive'] and row['grantedAccess']=='0x120089' for row in valid['holders'])
        assert run('empty',0)['matchedCount']=='0'
        assert run('pipe',0)['nonDiskCount']=='2'
        for mode in ('api-missing','snapshot-api-missing'):assert run(mode,5)['snapshotNtStatus'] is None
        assert run('snapshot-denied',3)['snapshotNtStatus']=='0xc0000022'
        assert run('snapshot-positive',3)['snapshotNtStatus']=='0x102'
        assert run('snapshot-budget',3)['limited']
        for mode in ('bad-count','short-header'):assert run(mode,4)['malformed']
        assert run('protected',6)['protectedSkippedCount']=='1'
        assert run('open-denied',6)['openFailedCount']=='1'
        assert run('duplicate-denied',6)['duplicateFailedCount']=='2'
        for mode in ('bad-pointer','odd-name','name-growth','name-positive','type-denied'):assert run(mode,6)['nameFailedCount']=='2'
        timed=run('timeout',6);assert timed['timeoutCount']=='4' and timed['limited']
        waited=run('wait-failed',6);assert waited['timeoutCount']=='0' and waited['waitFailedCount']=='2' and waited['waitWin32Error']==6
        assert run('cancel',6)['cancelled']
        assert run('valid',6,('--max-handles','1'))['limited']
        assert run('valid',6,('--limit','1'))['truncated']
        print('R3_FILE_HOLDER_FIXTURE_PASS native snapshot status/layout/growth, non-disk/permission/duplicate/name failures, helper ownership/release, timeout cap, cancellation and scan/output budgets')
if __name__=='__main__':main()
