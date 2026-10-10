"""Switch boolean ABIs, unavailable fields and selected-write readback."""
from pathlib import Path
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
#include "SWITCHHEADER"
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
#include <cassert>
#include <cstring>
static std::wstring mode;
static DWORD policy=3,captured=0;static int writes=0;
static BOOL WINAPI info(HANDLE token,TOKEN_INFORMATION_CLASS c,LPVOID output,DWORD capacity,PDWORD length) {
 if(mode==L"byte" && c==TokenHasRestrictions){*length=1;*static_cast<BYTE*>(output)=1;return TRUE;}
 if(mode==L"short" && c==TokenUIAccess){*length=2;std::memset(output,0,capacity);return TRUE;}
 if(mode==L"unavailable" && static_cast<int>(c)==48){*length=0;SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
 if(mode.starts_with(L"policy") && c==TokenMandatoryPolicy){*length=4;std::memcpy(output,&policy,4);return TRUE;}
 return GetTokenInformation(token,c,output,capacity,length);
}
static NTSTATUS NTAPI set(HANDLE,TOKEN_INFORMATION_CLASS c,PVOID payload,ULONG bytes){
 ++writes;
 if(mode==L"positive")return 258;
 if(mode.starts_with(L"policy")){assert(c==TokenMandatoryPolicy && bytes==4);std::memcpy(&captured,payload,4);policy=mode==L"policy-mismatch"?captured&~2U:captured;}
 return 0;
}
static FARPROC WINAPI resolve(HMODULE module,LPCSTR name){if(std::string(name)=="NtSetInformationToken")return reinterpret_cast<FARPROC>(set);return GetProcAddress(module,name);}
#define GetTokenInformation info
#define GetProcAddress resolve
#include "SWITCHCPP"
#undef GetProcAddress
#undef GetTokenInformation
int wmain(int argc,wchar_t* argv[]) {
 _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
 mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
 const auto pid=std::to_wstring(GetCurrentProcessId());
 for(int i=1;i+1<argc;++i)if(std::wstring(argv[i])==L"--pid")argv[i+1]=const_cast<wchar_t*>(pid.c_str());
 ks::cli::registerTokenSwitches();const auto result=ks::cli::dispatchR3(argc,argv).value_or(1);
 if(mode==L"short")assert(writes==0);
 if(mode.starts_with(L"policy"))assert(captured==2);
 return result;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-switches-') as temp:
        directory=Path(temp);source=SOURCE
        for key,path in {'SWITCHHEADER':'shared/usermode/backend/process/ProcessTokenSwitches.h',
                         'REGISTRY':'KswordCLI/CommandRegistry.h','SWITCHCPP':'shared/usermode/backend/process/ProcessTokenSwitches.cpp'}.items():
            source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        sources=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3TokenSwitches.cpp','shared/usermode/backend/process/ProcessToken.cpp',
                 'shared/usermode/backend/process/ThreadActions.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(directory/'fixture.cpp'),*[str(ROOT/path) for path in sources],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,name,verb,code):
            args=[str(binary),mode,'process','token','switches',name,verb,'--pid','self','--json']
            if verb!='query':args+=['--confirm']
            result=subprocess.run(args,capture_output=True,timeout=15)
            assert result.returncode==code,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        byte=run('byte','has-restrictions','query',0)['switches'][0]
        assert byte['available'] and byte['value'] is True and byte['returnLength']==1 and not byte['writable']
        unavailable=run('unavailable','app-silo','query',5)['switches'][0]
        assert unavailable['informationClass']==48 and unavailable['value'] is None and unavailable['win32Error']==87
        short=run('short','ui-access','enable',4)
        assert not short['before']['available'] and short['before']['win32Error']==13
        positive=run('positive','ui-access','enable',3)
        assert positive['ntStatus']=='0x102' and not positive['requestSucceeded'] and not positive['verified']
        unchanged=run('unchanged','ui-access','enable',6)
        assert unchanged['requestSucceeded'] and not unchanged['verified'] and unchanged['after']['value'] is False
        preserved=run('policy','mandatory-no-write-up','disable',0)
        assert preserved['verified'] and preserved['otherPolicyBitPreserved'] and preserved['after']['policy']=='0x2'
        mismatch=run('policy-mismatch','mandatory-no-write-up','disable',6)
        assert mismatch['requestSucceeded'] and not mismatch['verified'] and not mismatch['otherPolicyBitPreserved']
        print('R3_SWITCHES_FIXTURE_PASS byte booleans, SDK class identity, unavailable/malformed no-op, positive status, unchanged effect and policy-bit preservation')


if __name__=='__main__':
    main()
