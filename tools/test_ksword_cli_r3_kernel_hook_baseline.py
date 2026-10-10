"""Disk read evidence and PE RVA/raw range faults, including uint32 wrap and virtual tails."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
MOCK=r'''
HANDLE WINAPI FixtureFile(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);BOOL WINAPI FixtureSize(HANDLE,PLARGE_INTEGER);BOOL WINAPI FixtureInfo(HANDLE,LPBY_HANDLE_FILE_INFORMATION);BOOL WINAPI FixtureReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
#define CreateFileW FixtureFile
#define GetFileSizeEx FixtureSize
#define GetFileInformationByHandle FixtureInfo
#define ReadFile FixtureReadFile
'''
QUERY=r'''
static std::vector<BYTE> image;static int informationCalls=0;
HANDLE WINAPI FixtureFile(LPCWSTR,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES,DWORD creation,DWORD flags,HANDLE){assert(access==GENERIC_READ&&share==7&&creation==OPEN_EXISTING&&flags==FILE_ATTRIBUTE_NORMAL);
 if(mode==L"file-missing"||mode==L"file-denied"){SetLastError(mode==L"file-missing"?2:5);return INVALID_HANDLE_VALUE;}
 image.assign(1024,0);auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());dos->e_magic=IMAGE_DOS_SIGNATURE;dos->e_lfanew=128;auto* nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data()+128);nt->Signature=IMAGE_NT_SIGNATURE;nt->FileHeader.NumberOfSections=1;nt->FileHeader.SizeOfOptionalHeader=mode==L"pe32"?sizeof(IMAGE_OPTIONAL_HEADER32):sizeof(IMAGE_OPTIONAL_HEADER64);nt->OptionalHeader.Magic=mode==L"pe32"?IMAGE_NT_OPTIONAL_HDR32_MAGIC:IMAGE_NT_OPTIONAL_HDR64_MAGIC;nt->OptionalHeader.SizeOfHeaders=512;
 auto* section=reinterpret_cast<IMAGE_SECTION_HEADER*>(image.data()+152+nt->FileHeader.SizeOfOptionalHeader);section->VirtualAddress=0x1000;section->Misc.VirtualSize=0x600;section->SizeOfRawData=512;section->PointerToRawData=512;for(int i=0;i<512;++i)image[512+i]=static_cast<BYTE>(i);
 if(mode==L"magic")nt->OptionalHeader.Magic=0;if(mode==L"nt-offset")dos->e_lfanew=MAXLONG;if(mode==L"raw-range")section->PointerToRawData=0xfffffff0;if(mode==L"virtual-range")section->VirtualAddress=0xfffffff0;if(mode==L"overlap"){nt->FileHeader.NumberOfSections=2;section[1]=section[0];}if(mode==L"short-pe")image.resize(3);if(mode==L"empty")image.clear();
 informationCalls=0;assert(live.insert(h(6)).second);return h(6);
}
BOOL WINAPI FixtureSize(HANDLE handle,PLARGE_INTEGER size){assert(handle==h(6)&&live.count(handle));if(mode==L"size-denied"){SetLastError(5);return FALSE;}size->QuadPart=mode==L"size-limit"?128LL*1024LL*1024LL+1:static_cast<LONGLONG>(image.size());return TRUE;}
BOOL WINAPI FixtureInfo(HANDLE handle,LPBY_HANDLE_FILE_INFORMATION info){assert(handle==h(6)&&live.count(handle));if(mode==L"identity-denied"){SetLastError(5);return FALSE;}*info={};info->nFileIndexHigh=MAXDWORD;info->nFileIndexLow=MAXDWORD;info->nFileSizeLow=static_cast<DWORD>(image.size());info->dwVolumeSerialNumber=3;info->ftLastWriteTime.dwLowDateTime=mode==L"changed"?++informationCalls:10;return TRUE;}
BOOL WINAPI FixtureReadFile(HANDLE handle,LPVOID data,DWORD bytes,LPDWORD read,LPOVERLAPPED){assert(handle==h(6)&&live.count(handle)&&bytes==image.size());if(mode==L"read-denied"){SetLastError(5);*read=0;return FALSE;}*read=mode==L"short-read"?bytes-1:bytes;memcpy(data,image.data(),*read);return TRUE;}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-hook-baseline-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER+MOCK,encoding='utf-8')
        source=SOURCE.replace('registerKernelNamespace()','registerKernelHookBaseline()').replace('int wmain(',QUERY+'\nint wmain(')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/ObjectNamespace.h').as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Input.cpp','KswordCLI/R3KernelHookBaseline.cpp','shared/usermode/backend/kernel/HookDiskBaseline.cpp','shared/usermode/backend/file/PathNavigator.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Psapi.lib','Shell32.lib'],cwd=directory,check=True)
        def run(mode,code,rva='0x1010',compare=None):
            args=['query','--count','16'] if compare is None else ['compare','--bytes',compare]
            result=subprocess.run([str(binary),mode,'kernel','hook-baseline',*args,'--path',r'C:\fixture.dll','--rva',rva,'--json'],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['available'] and valid['fileOffset']=='0x210' and valid['bytesHex']=='101112131415161718191a1b1c1d1e1f' and valid['file']['fileId']=='0xffffffffffffffff' and valid['file']['closed']
        assert run('pe32',0)['mapping']['optionalMagic']=='0x10b'
        assert run('valid',0,compare=valid['bytesHex'])['differs'] is False
        assert run('valid',0,compare='00')['differs'] is True
        for rva in ('0x1300','0x11fa','0xfffffff8'):assert run('valid',5,rva)['available'] is False
        for mode in ('magic','nt-offset','raw-range','virtual-range','overlap','short-pe','empty'):run(mode,4)
        for mode in ('file-missing','file-denied','size-denied','read-denied','short-read'):run(mode,3)
        assert run('size-limit',5)['file']['limited']
        for mode in ('identity-denied','changed','close-denied'):run(mode,6)
        print('R3_HOOK_BASELINE_FIXTURE_PASS disk open/read/identity/close evidence, PE32/PE64 and 64-bit RVA/raw bounds, tails/overlap, cap and unverified supplied-byte comparison')
if __name__=='__main__':main()
