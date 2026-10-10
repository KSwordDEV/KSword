"""Hyper-V source identities and native service/configuration limitations."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_security_ci import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-security-hyperv-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerSecurityCi()','registerSecurityHyperV()').replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('"SECURITY"','"'+(ROOT/'KswordCLI/R3SecurityShared.h').as_posix()+'"');(directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SecurityHyperV.cpp','shared/usermode/backend/security/HyperV.cpp','shared/usermode/backend/security/CodeIntegrity.cpp','shared/usermode/backend/Common.cpp','shared/evidence/EvidenceJson.cpp','shared/evidence/LosslessValue.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Crypt32.lib'],cwd=directory,check=True)
        def run(mode,code,leaf='services'):
            result=subprocess.run([str(binary),mode,'security','hyperv',leaf,'query','--json'],capture_output=True,timeout=10)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert [row['data']['name'] for row in valid['evidence']]==['vmbus','VMSMP','HvHost','vpci']
        assert run('service-absent',0)['evidence'][0]['data']['state'] is None
        for mode in ('scm-denied','service-denied','service-query-denied'):run(mode,3)
        run('service-close',6)
        reg=run('valid',0,'registry')['evidence'][0]['data'];assert reg['name']=='HypervisorEnforcedCodeIntegrity' and reg['path']==r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        run('reg-absent',0,'registry');run('reg-denied',3,'registry');run('reg-malformed',4,'registry');run('reg-close',6,'registry')
        print('R3_SECURITY_HYPERV_FIXTURE_PASS exact service identities, current SCM data vs absence/permissions/close failure and DeviceGuard configuration provenance (not BCD)')
if __name__=='__main__':main()
