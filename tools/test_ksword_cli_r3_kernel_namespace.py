"""Directory/link NT reply bounds, strict statuses, limits and handle/DLL ownership."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''
#pragma once
#include <Windows.h>
HMODULE WINAPI FixtureModule(LPCWSTR);HMODULE WINAPI FixtureLoad(LPCWSTR);BOOL WINAPI FixtureFree(HMODULE);
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR);BOOL WINAPI FixtureClose(HANDLE);BOOL WINAPI FixtureSession(DWORD,DWORD*);BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE,BOOL);
#define GetModuleHandleW FixtureModule
#define LoadLibraryW FixtureLoad
#define FreeLibrary FixtureFree
#define GetProcAddress FixtureProcedure
#define CloseHandle FixtureClose
#define ProcessIdToSessionId FixtureSession
#define SetConsoleCtrlHandler FixtureConsole
'''
SOURCE=r'''
#include "mock.h"
#include "REGISTRY"
#include "BACKEND"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <set>
#include <string>
static std::wstring mode;static std::set<HANDLE> live;static int libraries=0,closes=0;static PHANDLER_ROUTINE control=nullptr;
static HANDLE h(std::uintptr_t v){return reinterpret_cast<HANDLE>(v);}static std::wstring objectName(POBJECT_ATTRIBUTES a){return std::wstring(a->ObjectName->Buffer,a->ObjectName->Length/2);}
BOOL WINAPI FixtureConsole(PHANDLER_ROUTINE handler,BOOL add){control=add?handler:nullptr;return TRUE;}
HMODULE WINAPI FixtureModule(LPCWSTR){return mode==L"owned-library"?nullptr:reinterpret_cast<HMODULE>(1);}
HMODULE WINAPI FixtureLoad(LPCWSTR){++libraries;return reinterpret_cast<HMODULE>(1);}BOOL WINAPI FixtureFree(HMODULE){--libraries;return TRUE;}
struct Lifetime{~Lifetime(){assert(libraries==0);}};static Lifetime lifetime;
BOOL WINAPI FixtureClose(HANDLE handle){assert(live.erase(handle)==1);++closes;if(mode==L"close-denied"){SetLastError(5);return FALSE;}return TRUE;}
BOOL WINAPI FixtureSession(DWORD,DWORD* session){if(mode==L"session-denied"){SetLastError(5);return FALSE;}*session=1;return TRUE;}
LONG NTAPI FixtureOpenDirectory(PHANDLE handle,ACCESS_MASK access,POBJECT_ATTRIBUTES a){assert(access==1);const auto path=objectName(a);*handle=nullptr;
 if(mode==L"open-denied"||mode==L"child-denied"&&path.find(L"ChildDir")!=std::wstring::npos||mode==L"some-root-denied"&&path==L"\\Security")return static_cast<LONG>(0xc0000022UL);
 if(mode==L"open-positive")return 258;if(mode==L"open-unsupported")return static_cast<LONG>(0xc00000bbUL);if(mode==L"open-null")return 0;
 *handle=path.find(L"ChildDir")!=std::wstring::npos?h(2):h(1);assert(live.insert(*handle).second);return 0;}
LONG NTAPI FixtureOpenLink(PHANDLE handle,ACCESS_MASK access,POBJECT_ATTRIBUTES){assert(access==1);*handle=nullptr;if(mode==L"link-open-denied")return static_cast<LONG>(0xc0000022UL);*handle=h(3);assert(live.insert(*handle).second);return 0;}
LONG NTAPI FixtureDirectory(HANDLE handle,PVOID data,ULONG bytes,BOOLEAN single,BOOLEAN,ULONG* context,ULONG* returned){assert(handle==h(1)&&live.count(handle)&&single);
 if(mode==L"query-denied"||mode==L"query-partial"&&*context>=1)return static_cast<LONG>(0xc0000022UL);if(mode==L"query-positive")return 258;
 if(mode==L"query-budget"){*returned=8u*1024u*1024u;return static_cast<LONG>(0xc0000023UL);}
 if(mode==L"query-growth"&&bytes<128u*1024u){*returned=128u*1024u;return static_cast<LONG>(0xc0000023UL);}
 if(mode==L"empty"||*context>=3){*returned=0;return static_cast<LONG>(0x8000001aUL);}
 if(mode==L"null-sentinel"){memset(data,0,sizeof(ks::r3::kernel::KOBJECT_DIRECTORY_INFORMATION));*returned=sizeof(ks::r3::kernel::KOBJECT_DIRECTORY_INFORMATION);return 0;}
 const auto index=mode==L"cycle"?0:*context;const std::wstring name=index==0?L"ChildDir":index==1?L"FixtureLink":L"LeafEvent";
 const std::wstring type=index==0?L"Directory":index==1?L"SymbolicLink":L"Event";
 auto* entry=static_cast<ks::r3::kernel::KOBJECT_DIRECTORY_INFORMATION*>(data);const auto header=sizeof(*entry);assert(bytes>header+(name.size()+type.size())*2);
 auto* chars=reinterpret_cast<LPWSTR>(static_cast<BYTE*>(data)+header);memcpy(chars,name.data(),name.size()*2);memcpy(chars+name.size(),type.data(),type.size()*2);
 entry->Name={static_cast<USHORT>(name.size()*2),static_cast<USHORT>(name.size()*2),chars};entry->TypeName={static_cast<USHORT>(type.size()*2),static_cast<USHORT>(type.size()*2),chars+name.size()};
 *returned=static_cast<ULONG>(header+(name.size()+type.size())*2);if(mode!=L"cycle")++*context;
 if(mode==L"short-reply")*returned=1;if(mode==L"huge-reply")*returned=bytes+1;if(mode==L"bad-pointer")entry->Name.Buffer=reinterpret_cast<PWSTR>(1);
 if(mode==L"odd-name")++entry->Name.Length;if(mode==L"bad-max")entry->Name.MaximumLength=1;
 if(mode==L"cancel"){assert(control);control(CTRL_BREAK_EVENT);}return 0;}
LONG NTAPI FixtureObject(HANDLE handle,ULONG cls,PVOID data,ULONG bytes,ULONG* returned){assert(live.count(handle)&&cls==0&&bytes==sizeof(ks::r3::kernel::KOBJECT_BASIC_INFORMATION));
 if(mode==L"basic-positive")return 258;if(mode==L"basic-denied")return static_cast<LONG>(0xc0000022UL);
 auto* basic=static_cast<ks::r3::kernel::KOBJECT_BASIC_INFORMATION*>(data);*basic={};basic->HandleCount=MAXDWORD;basic->PointerCount=55;basic->GrantedAccess=1;basic->PagedPoolUsage=128;
 *returned=mode==L"short-basic"?1:bytes;return 0;}
LONG NTAPI FixtureTarget(HANDLE handle,PUNICODE_STRING target,PULONG required){assert(handle==h(3)&&live.count(handle));if(mode==L"target-positive")return 258;
 if(mode==L"target-budget"){*required=65536;return static_cast<LONG>(0xc0000023UL);}
 const std::wstring text=mode==L"target-growth"?std::wstring(5000,L'x'):L"\\KnownDlls";*required=static_cast<ULONG>(text.size()*2);
 if(target->MaximumLength<*required)return static_cast<LONG>(0xc0000023UL);memcpy(target->Buffer,text.data(),*required);target->Length=static_cast<USHORT>(*required);
 if(mode==L"target-empty")target->Length=0;if(mode==L"target-pointer")target->Buffer=reinterpret_cast<PWSTR>(1);return 0;}
FARPROC WINAPI FixtureProcedure(HMODULE,LPCSTR name){if(mode==L"api-missing")return nullptr;
 if(strcmp(name,"NtOpenDirectoryObject")==0)return reinterpret_cast<FARPROC>(FixtureOpenDirectory);
 if(strcmp(name,"NtQueryDirectoryObject")==0)return reinterpret_cast<FARPROC>(FixtureDirectory);
 if(strcmp(name,"NtOpenSymbolicLinkObject")==0)return reinterpret_cast<FARPROC>(FixtureOpenLink);
 if(strcmp(name,"NtQuerySymbolicLinkObject")==0)return mode==L"target-api-missing"?nullptr:reinterpret_cast<FARPROC>(FixtureTarget);
 if(strcmp(name,"NtQueryObject")==0)return mode==L"basic-api-missing"?nullptr:reinterpret_cast<FARPROC>(FixtureObject);return nullptr;}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 ks::cli::registerKernelNamespace();const auto code=ks::cli::dispatchR3(argc,argv).value_or(1);assert(live.empty());return code;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-namespace-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');source=SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/ObjectNamespace.h').as_posix());(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelNamespace.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=(),common=False):
            args=[] if common else ['--root',r'\Fixture'];result=subprocess.run([str(binary),mode,'kernel','namespace','enum','--json',*args,*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['enumeratedCount']=='3' and valid['sources'][0]['complete'] and valid['sources'][0]['closed']
        assert valid['entries'][0]['basic']['handleCount']=='4294967295' and valid['entries'][1]['symlinkTarget']['value']==r'\KnownDlls' and valid['entries'][2]['opened'] is None
        for mode in ('empty','null-sentinel'):assert run(mode,0)['enumeratedCount']=='0'
        assert run('api-missing',5)['sources'][0]['openNtStatus'] is None
        for mode in ('open-denied','open-positive','query-denied','query-positive'):run(mode,3)
        assert run('open-unsupported',5)['sources'][0]['openNtStatus']=='0xc00000bb'
        for mode in ('open-null','short-reply','huge-reply','bad-pointer','odd-name','bad-max','short-basic','target-pointer'):assert run(mode,4)['malformed']
        assert run('query-partial',6)['enumeratedCount']=='1'
        assert run('query-growth',0)['enumeratedCount']=='3'
        assert run('query-budget',6)['limited']
        assert run('cycle',6)['sources'][0]['cycle']
        for mode in ('child-denied','link-open-denied','basic-positive','basic-denied','basic-api-missing','target-positive','target-api-missing'):run(mode,6)
        assert run('target-empty',0)['entries'][1]['symlinkTarget']['value']==''
        assert len(run('target-growth',0)['entries'][1]['symlinkTarget']['value'])==5000
        assert run('target-budget',6)['entries'][1]['symlinkTarget']['limited']
        assert not run('close-denied',6)['sources'][0]['closed']
        assert run('cancel',6)['cancelled']
        assert run('valid',6,('--max-entries','1'))['limited']
        assert run('valid',6,('--limit','1'))['truncated']
        assert run('owned-library',0)['enumeratedCount']=='3'
        assert not run('session-denied',6,common=True)['currentSessionKnown']
        assert run('some-root-denied',6,common=True)['openedRootCount']!='0'
        print('R3_NAMESPACE_FIXTURE_PASS strict NTSTATUS and empty results, counted-string/basic layouts and growth, unknown vs zero metadata, source/child closure, owned DLL release, cancellation/limits/cycles and session discovery')
if __name__=='__main__':main()
