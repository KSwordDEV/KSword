"""BAM/ahcache source selection and existing service status/absence/lifetime boundaries."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_security_ci import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-security-bam-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerSecurityCi()','registerSecurityBamAhcache()').replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('"SECURITY"','"'+(ROOT/'KswordCLI/R3SecurityShared.h').as_posix()+'"');(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SecurityBamAhcache.cpp','shared/usermode/backend/security/BamAhcache.cpp','shared/usermode/backend/security/CodeIntegrity.cpp','shared/usermode/backend/Common.cpp','shared/evidence/EvidenceJson.cpp','shared/evidence/LosslessValue.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Crypt32.lib'],cwd=directory,check=True)
        for family in ('bam','ahcache'):
            def run(mode,code):
                result=subprocess.run([str(binary),mode,'security',family,'service','query','--json'],capture_output=True,timeout=10)
                assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
            assert run('valid',0)['evidence'][0]['data']['name']==family
            absent=run('service-absent',0)['evidence'][0]['data'];assert absent['absent'] and absent['state'] is None
            for mode in ('scm-denied','service-denied','service-query-denied'):run(mode,3)
            run('service-close',6)
        print('R3_SECURITY_BAM_AHCACHE_FIXTURE_PASS exact driver identities and known absence/permissions/native status/owned closure; summary-only metadata independently exercised by live suites')
if __name__=='__main__':main()
