"""Atom holes vs unavailable evidence, separate namespaces and Win32 bounds/budgets."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
MOCK=r'''
UINT WINAPI FixtureGlobal(ATOM,LPWSTR,int);int WINAPI FixtureFormat(UINT,LPWSTR,int);ULONGLONG WINAPI FixtureTick();
#define GlobalGetAtomNameW FixtureGlobal
#define GetClipboardFormatNameW FixtureFormat
#define GetTickCount64 FixtureTick
'''
QUERY=r'''
ULONGLONG WINAPI FixtureTick(){static ULONGLONG tick=1;return mode==L"deadline"?(tick+=20000):tick;}
static int FixtureName(UINT id,LPWSTR text,int capacity,bool global){assert(capacity==512);if(mode==L"length")return 512;if(mode==L"negative"&&!global)return -1;
 if(mode==L"unknown-zero"){SetLastError(0);return 0;}if(mode==L"denied"||mode==L"mixed"&&id==0xc002){SetLastError(5);return 0;}
 const std::wstring name=mode==L"empty"?L"":id==0xc003?(global?L"GlobalSide":L"ClipSide"):global&&id==0xc001?L"\u5168\u5c40\u2602":!global&&id==0xc002?L"ClipName":L"";
 if(mode==L"cancel"){assert(control);control(CTRL_BREAK_EVENT);}if(name.empty()){SetLastError(ERROR_INVALID_HANDLE);return 0;}memcpy(text,name.data(),name.size()*2);return static_cast<int>(name.size());
}
UINT WINAPI FixtureGlobal(ATOM id,LPWSTR text,int capacity){return static_cast<UINT>(FixtureName(id,text,capacity,true));}
int WINAPI FixtureFormat(UINT id,LPWSTR text,int capacity){return FixtureName(id,text,capacity,false);}
'''
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-atoms-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER+MOCK,encoding='utf-8')
        source=SOURCE.replace('registerKernelNamespace()','registerKernelAtoms()').replace('int wmain(',QUERY+'\nint wmain(')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/AtomTable.h').as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelAtoms.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/AtomTable.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','User32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'kernel','atoms','enum','--start-id','0xc000','--end-id','0xc003','--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['completeRange'] and valid['scannedIdCount']=='4' and valid['returnedCount']=='3' and valid['globalNameCount']=='2' and valid['clipboardNameCount']=='2'
        assert valid['atoms'][0]['global']['name']=='\u5168\u5c40\u2602' and valid['atoms'][0]['clipboard']['absent'] and valid['atoms'][2]['sameName'] is False
        scoped=run('valid',0,('--scope','global'));assert scoped['clipboardNameCount']=='0' and scoped['atoms'][0]['clipboard']['available'] is None
        assert run('empty',0)['returnedCount']=='0'
        for mode in ('denied','unknown-zero'):assert run(mode,5)['failedQueryCount']=='8'
        assert run('mixed',6)['failedQueryCount']=='2'
        for mode in ('length','negative'):assert run(mode,4)['malformed']
        assert run('deadline',6)['limited']
        assert run('cancel',6)['cancelled']
        assert run('valid',6,('--limit','1'))['truncated']
        assert run('valid',0,('--filter','Clip'))['matchedCount']=='2'
        print('R3_ATOM_FIXTURE_PASS separate global/clipboard names, Unicode, holes vs unknown errors, null scope fields, raw API bounds and cancellation/deadline/output budgets')
if __name__=='__main__':main()
