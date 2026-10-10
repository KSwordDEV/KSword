"""Real helper evaluates the migrated environment-only body with a disposable CIM fixture."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_security_ci import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-security-bugcheck-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerSecurityCi()','registerSecurityBugcheck()').replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('"SECURITY"','"'+(ROOT/'KswordCLI/R3SecurityShared.h').as_posix()+'"')
        source=source.replace('#include <fcntl.h>','#include "'+(ROOT/'shared/usermode/backend/security/BugcheckEvidence.h').as_posix()+'"\n#include <fcntl.h>')
        source=source.replace('std::vector<ks::r3::security::SecurityProbe> probes{{',r'''body=L"function Get-CimInstance{[CmdletBinding()]param([string]$ClassName);"+(mode==L"environment-empty"?std::wstring(L"return $null"):mode==L"environment-denied"?std::wstring(L"throw [UnauthorizedAccessException]::new('fixture permission denied')"):std::wstring(L"[pscustomobject]@{Manufacturer=('Fixture '+[char]0x6d4b);Model='Fixture Model'}"))+L"};"+ks::r3::security::BugcheckEnvironmentProbes()[0].body;
  std::vector<ks::r3::security::SecurityProbe> probes{{''')
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SecurityBugcheck.cpp','shared/usermode/backend/security/BugcheckEvidence.cpp','shared/usermode/backend/security/CodeIntegrity.cpp','shared/usermode/backend/Common.cpp','shared/evidence/EvidenceJson.cpp','shared/evidence/LosslessValue.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Crypt32.lib'],cwd=directory,check=True)
        def run(mode,code):
            result=subprocess.run([str(binary),mode,'fixture','helper','query','--json'],capture_output=True,timeout=12)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('environment-valid',0)['evidence'][0]['data'];assert valid['manufacturer']=='Fixture \u6d4b' and valid['model']=='Fixture Model' and valid['environmentOnly'] and 'crashDetected' not in valid
        assert run('environment-empty',5)['evidence'][0]['data']['available'] is False
        assert run('environment-denied',5)['evidence'][0]['data']['exceptionType']=='System.UnauthorizedAccessException'
        print('R3_SECURITY_BUGCHECK_FIXTURE_PASS production environment body, Unicode/manufacturer/model provenance, null instance/permission availability and no invented crash data')
if __name__=='__main__':main()
