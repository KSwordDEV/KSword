"""Object root/type selection with native fault/ownership fixture; no Device/Driver opener."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_kernel_namespace import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-objects-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8');source=SOURCE.replace('registerKernelNamespace()','registerKernelObjects()')
        source=source.replace('L"Directory":index==1?L"SymbolicLink":L"Event"','L"Device":index==1?L"Driver":L"Event"')
        source=source.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('BACKEND',(ROOT/'shared/usermode/backend/kernel/ObjectNamespace.h').as_posix());(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3KernelObjects.cpp','shared/usermode/backend/kernel/ObjectNamespace.cpp','shared/usermode/backend/kernel/DeviceDriverObjects.cpp','shared/usermode/backend/kernel/KernelTypes.cpp','shared/usermode/backend/Common.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'kernel','objects','enum','--json',*extra],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2000],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert valid['roots']==[r'\Device',r'\Driver',r'\FileSystem',r'\FileSystem\Filters'] and valid['enumeratedCount']=='12'
        assert all(row['opened'] is None and not row['openAttempted'] and row['basic']['handleCount'] is None for row in valid['objects'])
        assert run('valid',0,('--kind','driver'))['matchedCount']=='4'
        assert run('valid',0,('--scope','driver'))['roots']==[r'\Driver']
        assert run('empty',0)['matchedCount']=='0'
        assert run('api-missing',5)['matchedCount']=='0'
        for mode in ('open-denied','query-positive'):run(mode,3)
        assert run('query-partial',6)['matchedCount']=='4'
        assert run('bad-pointer',4)['malformed']
        assert run('close-denied',6)['sources'][0]['closed'] is False
        assert run('valid',6,('--max-entries','1'))['limited']
        assert run('valid',6,('--limit','1'))['truncated']
        assert run('cancel',6)['cancelled']
        print('R3_OBJECTS_FIXTURE_PASS fixed four roots, scope/type filters, null unsupported Device/Driver metadata, typed native failures/limits and owned root closure')
if __name__=='__main__':main()
