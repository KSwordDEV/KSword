"""Fixed native probes and copied loaded-image export bounds, including exact-size retry."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
MOCK=r'''
#include <psapi.h>
BOOL WINAPI FixtureModuleInfo(HANDLE,HMODULE,LPMODULEINFO,DWORD);BOOL WINAPI FixtureRead(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);BOOL WINAPI FixtureToken(HANDLE,DWORD,PHANDLE);
#define GetModuleInformation FixtureModuleInfo
#define K32GetModuleInformation FixtureModuleInfo
#define ReadProcessMemory FixtureRead
#define OpenProcessToken FixtureToken
'''
QUERY=r'''
static std::vector<BYTE> image;
BOOL WINAPI FixtureToken(HANDLE,DWORD access,PHANDLE handle){assert(access==TOKEN_QUERY);*handle=nullptr;if(mode==L"token-denied"){SetLastError(5);return FALSE;}if(mode==L"token-null")return TRUE;*handle=h(5);assert(live.insert(*handle).second);return TRUE;}
LONG NTAPI FixtureProbe(PVOID,ULONG size,PULONG returned){*returned=(std::min<ULONG>)(size,64);if(mode==L"positive")return 258;if(mode==L"denied")return static_cast<LONG>(0xc0000022UL);if(mode==L"unsupported")return static_cast<LONG>(0xc0000003UL);
 if(mode==L"budget"){*returned=32u*1024u*1024u;return static_cast<LONG>(0xc0000004UL);}if(mode==L"exact"&&size!=48){*returned=48;return static_cast<LONG>(0xc0000004UL);}if(mode==L"exact")*returned=48;
 if(mode==L"growth"&&size<512u*1024u){*returned=512u*1024u;return static_cast<LONG>(0xc0000004UL);}if(mode==L"huge")*returned=size+1;return 0;}
LONG NTAPI FixtureSystem(ULONG,PVOID data,ULONG size,PULONG returned){return FixtureProbe(data,size,returned);}
LONG NTAPI FixtureHandle(HANDLE,ULONG,PVOID data,ULONG size,PULONG returned){return FixtureProbe(data,size,returned);}
BOOL WINAPI FixtureModuleInfo(HANDLE,HMODULE,LPMODULEINFO info,DWORD bytes){assert(bytes==sizeof(*info));if(mode==L"module-info-denied"){SetLastError(5);return FALSE;}
 image.assign(32768,0);auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());dos->e_magic=IMAGE_DOS_SIGNATURE;dos->e_lfanew=128;auto* nt=reinterpret_cast<IMAGE_NT_HEADERS*>(image.data()+128);nt->Signature=IMAGE_NT_SIGNATURE;nt->FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER);nt->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR_MAGIC;nt->OptionalHeader.NumberOfRvaAndSizes=16;nt->OptionalHeader.DataDirectory[0]={4096,2048};
 auto* exports=reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(image.data()+4096);exports->Base=5;exports->NumberOfNames=3;exports->NumberOfFunctions=3;exports->AddressOfNames=5000;exports->AddressOfNameOrdinals=5100;exports->AddressOfFunctions=5200;
 auto* names=reinterpret_cast<DWORD*>(image.data()+5000);auto* ordinals=reinterpret_cast<WORD*>(image.data()+5100);auto* functions=reinterpret_cast<DWORD*>(image.data()+5200);
 const char* texts[]={"NtQueryAlpha","NtQueryBeta","OtherExport"};for(int i=0;i<3;++i){names[i]=6000+100*i;ordinals[i]=static_cast<WORD>(i);functions[i]=8192+64*i;memcpy(image.data()+names[i],texts[i],strlen(texts[i])+1);}
 if(mode==L"dos")dos->e_magic=0;if(mode==L"nt-offset")dos->e_lfanew=MAXLONG;if(mode==L"optional")nt->FileHeader.SizeOfOptionalHeader=0;if(mode==L"arrays")exports->NumberOfNames=MAXDWORD;if(mode==L"ordinal")ordinals[0]=3;if(mode==L"function")functions[0]=40000;if(mode==L"name-end"){names[0]=32767;image.back()='X';}if(mode==L"no-exports")nt->OptionalHeader.DataDirectory[0]={0,0};if(mode==L"forwarded")functions[0]=4120;
 *info={image.data(),static_cast<DWORD>(image.size()),nullptr};return TRUE;
}
BOOL WINAPI FixtureRead(HANDLE,LPCVOID,LPVOID target,SIZE_T size,SIZE_T* copied){assert(size==image.size());if(mode==L"read-denied"){SetLastError(5);return FALSE;}memcpy(target,image.data(),size);*copied=mode==L"short-copy"?size-1:size;return TRUE;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-nt-query-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER+MOCK,encoding='utf-8')
        source=SOURCE.replace('registerKernelNamespace()','registerKernelNtQuery()').replace('FARPROC WINAPI FixtureProcedure(',QUERY+'\nFARPROC WINAPI FixtureProcedure(')
        source=source.replace('if(mode==L"api-missing")return nullptr;','if(mode==L"api-missing")return nullptr;\n if(strcmp(name,"NtQuerySystemInformation")==0)return reinterpret_cast<FARPROC>(FixtureSystem);\n if(strcmp(name,"NtQueryInformationProcess")==0||strcmp(name,"NtQueryInformationThread")==0||strcmp(name,"NtQueryInformationToken")==0||strcmp(name,"NtQueryObject")==0)return reinterpret_cast<FARPROC>(FixtureHandle);')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/NtQuery.h').as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelNtQuery.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/NtQuery.cpp','shared/usermode/backend/kernel/ObjectTypes.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Psapi.lib'],cwd=directory,check=True)
        def run(mode,code,args=('process','basic','query'),extra=()):
            result=subprocess.run([str(binary),mode,'kernel','nt-query',*args,'--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['queries'][0]['returnedBytes']=='48' and valid['queries'][0]['allocatedBytes']=='48'
        exact=run('exact',0,('process','image-name','query'))['queries'][0];assert exact['returnedBytes']=='48' and exact['allocatedBytes']=='48' and exact['attemptCount']=='2'
        assert run('growth',0)['queries'][0]['attemptCount']=='2'
        for mode in ('positive','denied'):run(mode,3)
        for mode in ('api-missing','unsupported'):run(mode,5)
        assert run('huge',4)['malformed']
        assert run('budget',6)['limited']
        full=run('valid',0,('query',));assert full['queryCount']=='18' and full['token']['closed']
        run('token-denied',6,('query',));run('token-denied',3,('token','user','query'));run('token-null',4,('query',));run('close-denied',6,('query',))
        ex=('exports','enum');exports=run('valid',0,ex);assert exports['ntQueryExportCount']=='2' and exports['exports'][0]['rva']=='0x2000' and exports['exports'][0]['ordinal']==5
        assert run('forwarded',0,ex)['exports'][0]['forwarded']
        assert run('no-exports',0,ex)['complete']
        for mode in ('dos','nt-offset','optional','arrays','ordinal','function','name-end'):assert run(mode,4,ex)['malformed']
        for mode in ('read-denied','short-copy','module-info-denied'):run(mode,3,ex)
        run('owned-library',5,ex)
        assert run('valid',6,ex,('--limit','1'))['truncated']
        assert run('valid',0,ex,('--filter','missing'))['returnedCount']=='0'
        print('R3_NT_QUERY_FIXTURE_PASS strict native/Win32 failures, returned vs allocated lengths/exact shrink/growth limits, fixed scope/token lifetime and copied PE arrays/strings/ordinals/RVAs')
if __name__=='__main__':main()
