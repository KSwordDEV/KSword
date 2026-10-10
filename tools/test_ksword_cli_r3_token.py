"""Native token size/pointer/status faults and linked-handle ownership."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "TOKENHEADER"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <cstring>
static std::wstring mode;
static BOOL WINAPI tokenInfo(HANDLE token,TOKEN_INFORMATION_CLASS c,LPVOID out,DWORD capacity,PDWORD required) {
 if(mode==L"linked" && c==TokenLinkedToken){*required=sizeof(TOKEN_LINKED_TOKEN);if(!out){SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}
  TOKEN_LINKED_TOKEN data{CreateEventW(nullptr,TRUE,FALSE,nullptr)};std::memcpy(out,&data,sizeof(data));return TRUE;}
 if(mode==L"denied"){*required=0;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 if(mode==L"oversize"){*required=16*1024*1024+1;SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}
 if(mode==L"bad-sid" && c==TokenUser){*required=sizeof(TOKEN_USER);if(!out){SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}
  TOKEN_USER data{};data.User.Sid=reinterpret_cast<PSID>(1);std::memcpy(out,&data,sizeof(data));return TRUE;}
 if((mode==L"short" || mode==L"growing") && c==TokenElevation){*required=out ? mode==L"short"?1:8 : 4;
  if(!out){SetLastError(ERROR_INSUFFICIENT_BUFFER);return FALSE;}std::memset(out,0,capacity);return TRUE;}
 return GetTokenInformation(token,c,out,capacity,required);
}
static BOOL WINAPI adjust(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD){SetLastError(ERROR_NOT_ALL_ASSIGNED);return TRUE;}
static NTSTATUS NTAPI rawSet(HANDLE,TOKEN_INFORMATION_CLASS,PVOID,ULONG){return mode==L"positive" ? 258 : mode==L"nt-denied" ? static_cast<LONG>(0xc0000022) : 0;}
static FARPROC WINAPI resolve(HMODULE module,LPCSTR name){if(std::string(name)=="NtSetInformationToken")return reinterpret_cast<FARPROC>(rawSet);return GetProcAddress(module,name);}
#define GetTokenInformation tokenInfo
#define AdjustTokenPrivileges adjust
#define GetProcAddress resolve
#include "TOKENCPP"
#undef GetProcAddress
#undef AdjustTokenPrivileges
#undef GetTokenInformation
static BOOL WINAPI convertSid(PSID sid,LPWSTR* text){if(mode==L"sid-denied"){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return FALSE;}return ConvertSidToStringSidW(sid,text);}
#define ConvertSidToStringSidW convertSid
#include "CLICPP"
#undef ConvertSidToStringSidW
int wmain(int argc,wchar_t* argv[]) {
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 const auto pid=std::to_wstring(GetCurrentProcessId());
 DWORD policy=0,n=0;HANDLE token=nullptr;assert(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));
 assert(GetTokenInformation(token,TokenMandatoryPolicy,&policy,sizeof(policy),&n));
 std::wstring desired;
 const DWORD target=policy^2;
 for(unsigned i=0;i<4;++i){wchar_t hex[3]{};swprintf_s(hex,L"%02X",static_cast<unsigned>((target>>(i*8))&0xff));desired+=hex;}
 if(mode==L"linked"){
  DWORD before=0,after=0;assert(GetProcessHandleCount(GetCurrentProcess(),&before));
  for(int i=0;i<200;++i){std::vector<std::byte> bytes;DWORD error=0;assert(ks::r3::process_detail::token::QueryTokenBytes(token,TokenLinkedToken,bytes,error));
   HANDLE owned=nullptr;std::memcpy(&owned,bytes.data(),sizeof(owned));DWORD flags=0;assert(!GetHandleInformation(owned,&flags));}
  assert(GetProcessHandleCount(GetCurrentProcess(),&after) && after==before);
 }
 CloseHandle(token);
 for(int i=1;i+1<argc;++i){if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(pid.c_str());
  if(std::wstring(argv[i])==L"--hex")argv[i+1]=const_cast<wchar_t*>(desired.c_str());}
 ks::cli::registerProcessToken();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-token-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'TOKENHEADER':'shared/usermode/backend/process/ProcessToken.h','REGISTRY':'KswordCLI/CommandRegistry.h',
                         'TOKENCPP':'shared/usermode/backend/process/ProcessToken.cpp','CLICPP':'KswordCLI/R3ProcessToken.cpp'}.items():
            source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        sources=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Input.cpp','shared/usermode/backend/process/ThreadActions.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in sources],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,path,code,extra=()):
            result=subprocess.run([str(binary),mode,'process','token',*path,'--pid','self',*extra,'--json'],capture_output=True,timeout=20)
            assert result.returncode==code,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        for mode,name,code,error in [('bad-sid','TokenUser',4,0),('short','TokenElevation',4,0),('growing','TokenElevation',4,13),
                                     ('denied','TokenElevation',3,5),('oversize','TokenElevation',3,223),('sid-denied','TokenUser',3,8)]:
            data=run(mode,['query'],code,['--classes',name])
            assert data['availableCount']==0 and data['classes'][0]['value'] is None
            assert data['classes'][0]['win32Error']==error
        linked=run('linked',['raw','query'],0,['--class','TokenLinkedToken'])
        assert linked['classes'][0]['available'] and linked['classes'][0]['byteSize']=='8'
        unassigned=run('unassigned',['privilege','enable'],3,['--name','SeChangeNotifyPrivilege','--confirm'])
        assert unassigned['win32Error']==1300 and not unassigned['requestSucceeded'] and not unassigned['verified']
        for mode,code,status in [('positive',3,'0x102'),('nt-denied',3,'0xc0000022'),('unconfirmed',6,'0x0')]:
            data=run(mode,['raw','set'],code,['--class','TokenMandatoryPolicy','--hex','desired','--confirm'])
            assert data['ntStatus']==status and not data['verified']
            assert data['requestSucceeded']==(mode=='unconfirmed')
            if mode=='unconfirmed':assert data['requestedHex']!=data['readbackHex'] and data['readbackSize']=='4'
        print('R3_TOKEN_FIXTURE_PASS SID/scalar bounds, oversized/growing results, linked handle cleanup, NOT_ALL_ASSIGNED, positive NT status and unconfirmed write')


if __name__=='__main__':
    main()
