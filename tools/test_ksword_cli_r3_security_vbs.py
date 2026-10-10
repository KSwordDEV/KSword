"""VBS probe selection with the shared native registry fault and lifetime fixture."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_security_ci import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-security-vbs-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerSecurityCi()','registerSecurityVbs()').replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('"SECURITY"','"'+(ROOT/'KswordCLI/R3SecurityShared.h').as_posix()+'"')
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SecurityVbs.cpp','shared/usermode/backend/security/Vbs.cpp','shared/usermode/backend/security/CodeIntegrity.cpp','shared/usermode/backend/Common.cpp','shared/evidence/EvidenceJson.cpp','shared/evidence/LosslessValue.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Crypt32.lib'],cwd=directory,check=True)
        def run(mode,code,leaf='hvci'):
            result=subprocess.run([str(binary),mode,'security','vbs',leaf,'query','--json'],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert [e['data']['name'] for e in valid['evidence']]==['Enabled','WasEnabledBy','Locked'] and all(e['data']['view']=='64-bit' for e in valid['evidence'])
        assert [e['data']['name'] for e in run('valid',0,'registry')['evidence']]==['EnableVirtualizationBasedSecurity','RequirePlatformSecurityFeatures','LsaCfgFlags']
        assert run('reg-absent',0)['evidence'][0]['data']['value'] is None
        run('reg-denied',3);run('reg-query-denied',3);run('reg-malformed',4);run('reg-close',6);run('reg-limit',6)
        assert run('reg-qword',0)['evidence'][0]['data']['value']=='9007199254740993'
        print('R3_SECURITY_VBS_FIXTURE_PASS HVCI/VBS/LSA group identity, source view/absence vs disabled, width and native failure/budget/closure evidence')
if __name__=='__main__':main()
