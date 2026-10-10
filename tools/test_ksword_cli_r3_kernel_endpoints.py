"""Typed BFS/depth/budget collection with production flat namespace NT fault fixture."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-directory-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerKernelNamespace()','registerKernelEndpoints()').replace('#include <set>','#include <set>\n#include <map>')
        source=source.replace('static std::wstring mode;', 'static std::map<HANDLE,std::wstring> directories;static std::uintptr_t serial=10;\nstatic std::wstring mode;')
        source=source.replace('assert(live.erase(handle)==1);++closes;', 'assert(live.erase(handle)==1);directories.erase(handle);++closes;')
        source=source.replace('*handle=path.find(L"ChildDir")!=std::wstring::npos?h(2):h(1);', '*handle=h(++serial);directories[*handle]=path;')
        source=source.replace('assert(handle==h(1)&&live.count(handle)&&single);', 'assert(directories.count(handle)&&live.count(handle)&&single);const bool child=mode!=L"deep"&&directories[handle]==L"\\\\Fixture\\\\ChildDir";')
        source=source.replace('*context>=3', '*context>=(child?1u:3u)')
        source=source.replace('const std::wstring name=index==0?', 'const std::wstring name=child?L"GrandEvent":index==0?')
        source=source.replace('const std::wstring type=index==0?', 'const std::wstring type=child?L"Event":index==0?')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/ObjectNamespace.h').as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelEndpoints.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/ObjectDirectory.cpp','shared/usermode/backend/kernel/CommunicationEndpoints.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'kernel','endpoints','enum','--root',r'\Fixture','--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['completeWithinDepth'] and valid['scannedDirectoryCount']=='2' and valid['scannedEntryCount']=='4' and valid['storedCount']=='2'
        assert all(e['type']=='Event' for e in valid['entries'])
        assert any(e['name']=='GrandEvent' and e['depth']==1 for e in valid['entries'])
        assert [s['depth'] for s in valid['sources']]==[0,1]
        shallow=run('valid',0,('--max-depth','0'));assert shallow['scannedDirectoryCount']=='1' and shallow['depthBoundaryDirectoryCount']=='1' and shallow['storedCount']=='1'
        deep=run('deep',0,('--max-depth','3'));assert deep['scannedDirectoryCount']=='4' and deep['storedCount']=='4' and deep['depthBoundaryDirectoryCount']=='1'
        filtered=run('valid',0,('--filter','GrandEvent'));assert filtered['scannedEntryCount']=='4' and filtered['returnedCount']=='1'
        assert run('valid',6,('--max-scanned-entries','1'))['scannedEntryCount']=='1'
        assert run('valid',6,('--max-rows','1'))['storedCount']=='1'
        shown=run('valid',6,('--limit','1'));assert shown['truncated'] and shown['completeWithinDepth'] and shown['storedCount']=='2'
        assert run('empty',0)['scannedEntryCount']=='0'
        assert run('api-missing',5)['scannedDirectoryCount']=='1'
        assert run('open-denied',3)['storedCount']=='0'
        assert run('query-positive',3)['storedCount']=='0'
        assert run('bad-pointer',4)['malformed']
        assert run('short-basic',4,('--filter','LeafEvent'))['malformed']
        assert not run('basic-denied',6,('--filter','LeafEvent'))['metadataComplete']
        assert run('cancel',6)['cancelled']
        assert run('query-budget',6)['limited']
        assert run('close-denied',6)['sources'][0]['closed'] is False
        print('R3_ENDPOINTS_FIXTURE_PASS BFS depth and requested boundary, no symlink traversal, filter not pruning, collection/display budgets, typed native failures including filtered metadata and owned closures')
if __name__=='__main__':main()
