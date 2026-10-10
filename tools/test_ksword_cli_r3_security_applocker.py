"""AppLocker source selection and real helper execution of the production XML count body."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_security_ci import HEADER,SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-security-applocker-') as temp:
        directory=Path(temp);(directory/'mock.h').write_text(HEADER,encoding='utf-8')
        source=SOURCE.replace('registerSecurityCi()','registerSecurityAppLocker()').replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix()).replace('"SECURITY"','"'+(ROOT/'KswordCLI/R3SecurityShared.h').as_posix()+'"')
        include=(ROOT/'shared/usermode/backend/security/AppLocker.h').as_posix();source=source.replace('#include <fcntl.h>','#include "'+include+'"\n#include <fcntl.h>')
        source=source.replace('std::vector<ks::r3::security::SecurityProbe> probes{{',r'''if(mode.rfind(L"policy-",0)==0){const auto xml=mode==L"policy-bad"?L"<broken":mode==L"policy-root"?L"<WrongRoot/>":L"<AppLockerPolicy><RuleCollection Type='Exe' EnforcementMode='AuditOnly'><FilePathRule/><RuleCollectionExtensions/><!-- comment --><FilePublisherRule/><FileHashRule/></RuleCollection><RuleCollection Type='Dll' EnforcementMode='NotConfigured'/></AppLockerPolicy>";
   body=L"function Get-AppLockerPolicy{[CmdletBinding()]param([switch]$Effective);$o=[pscustomobject]@{};$o|Add-Member ScriptMethod ToXml {return \""+std::wstring(xml)+L"\"};return $o};"+ks::r3::security::AppLockerProbes()[0].body;
  }std::vector<ks::r3::security::SecurityProbe> probes{{''')
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        files=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3SecurityAppLocker.cpp','shared/usermode/backend/security/AppLocker.cpp','shared/usermode/backend/security/CodeIntegrity.cpp','shared/usermode/backend/Common.cpp','shared/evidence/EvidenceJson.cpp','shared/evidence/LosslessValue.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE','/FI'+str(directory/'mock.h'),str(directory/'fixture.cpp'),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Crypt32.lib'],cwd=directory,check=True)
        def run(mode,code,leaf='drivers'):
            args=['fixture','helper','query'] if leaf=='helper' else ['security','applocker',leaf,'query']
            result=subprocess.run([str(binary),mode,*args,'--json'],capture_output=True,timeout=12)
            assert result.returncode==code,(mode,result.returncode,result.stdout[:2500],result.stderr);return json.loads(result.stdout)['data']
        valid=run('valid',0);assert [row['data']['name'] for row in valid['evidence']]==['AppID','applockerfltr','mssecflt']
        run('service-absent',0);run('service-denied',3);run('service-close',6)
        assert run('valid',0,'registry')['evidence'][0]['data']['name']=='DefaultLevel'
        run('reg-absent',0,'registry');run('reg-denied',3,'registry');run('reg-malformed',4,'registry');run('reg-close',6,'registry')
        policy=run('policy-valid',0,'helper')['evidence'][0]['data'];assert policy['collectionCount']=='2' and policy['ruleCount']=='3' and policy['collections'][0]['enforcementMode']=='AuditOnly' and policy['collections'][1]['ruleCount']=='0'
        for mode in ('policy-bad','policy-root'):assert run(mode,4,'helper')['evidence'][0]['data']['malformed']
        print('R3_SECURITY_APPLOCKER_FIXTURE_PASS exact service/SRP identities and native failure/absence/closure, production XML rule-only counts (no extension/comment count) and malformed XML/protocol exit semantics')
if __name__=='__main__':main()
