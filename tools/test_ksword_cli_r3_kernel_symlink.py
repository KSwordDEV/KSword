"""Symbolic-link adapter target/error/close semantics using the production NT fixture."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-symlink-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerKernelNamespace()','registerKernelSymlink()')
        source=source.replace('if(mode==L"link-open-denied")return', 'if(mode==L"link-open-positive")return 258;if(mode==L"link-open-null")return 0;if(mode==L"link-open-unsupported")return static_cast<LONG>(0xc00000bbUL);if(mode==L"link-open-denied")return')
        source=source.replace('if(strcmp(name,"NtOpenSymbolicLinkObject")==0)return reinterpret_cast<FARPROC>(FixtureOpenLink);', 'if(strcmp(name,"NtOpenSymbolicLinkObject")==0)return mode==L"link-api-missing"?nullptr:reinterpret_cast<FARPROC>(FixtureOpenLink);')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/ObjectNamespace.h').as_posix());(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelSymlink.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/SymbolicLinks.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,operation='query',extra=()):
            args=['--path',r'\Fixture\FixtureLink'] if operation=='query' else ['--root',r'\Fixture']
            result=subprocess.run([str(binary),mode,'kernel','symlink',operation,'--json',*args,*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['link']['symlinkTarget']['value']==r'\KnownDlls' and valid['link']['closed'] and valid['nameDerivedFromRequest']
        assert run('target-empty',0)['link']['symlinkTarget']['value']==''
        assert len(run('target-growth',0)['link']['symlinkTarget']['value'])==5000
        for mode in ('link-open-denied','link-open-positive','target-positive'):run(mode,3)
        for mode in ('link-api-missing','target-api-missing','link-open-unsupported'):run(mode,5)
        for mode in ('link-open-null','target-pointer','short-basic'):run(mode,4)
        assert run('target-budget',6)['link']['symlinkTarget']['limited']
        assert not run('basic-api-missing',6)['link']['basic']['attempted']
        assert not run('basic-denied',6)['link']['basic']['available']
        assert not run('close-denied',6)['link']['closed']
        enumeration=run('valid',0,'enum');assert enumeration['symbolicLinkCount']=='1' and enumeration['links'][0]['type']=='SymbolicLink'
        assert run('valid',0,'enum',('--target-filter','KNOWnDLLs'))['matchedCount']=='1'
        assert run('valid',0,'enum',('--target-filter','NoSuchTarget'))['matchedCount']=='0'
        unknown=run('target-api-missing',6,'enum',('--target-filter','NoSuchTarget'));assert unknown['unknownTargetFilterCount']=='1' and unknown['matchedCount']=='0'
        assert run('basic-denied',6,'enum')['links'][0]['basic']['handleCount'] is None
        assert run('child-denied',0,'enum')['symbolicLinkCount']=='1' # Directory metadata is not requested in this view.
        assert run('empty',0,'enum')['symbolicLinkCount']=='0'
        assert run('api-missing',5,'enum')['sources'][0]['openNtStatus'] is None
        assert run('query-positive',3,'enum')['matchedCount']=='0'
        assert run('valid',6,'enum',('--max-entries','1'))['limited']
        print('R3_SYMLINK_FIXTURE_PASS exact/empty/growing targets, native unavailable/error/malformed/close states, link-only metadata and unknown target-filter evidence')
if __name__=='__main__':main()
