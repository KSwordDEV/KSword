"""Run production ApplicationControl commands against in-process PowerShell mocks.

No AppLocker or Defender policy is read or written. Requires HostX64 MSVC and
Windows PowerShell 5.1; export uses a unique temporary directory.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured"><FilePathRule Id="{11111111-1111-1111-1111-111111111111}" Name="old" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="C:\\old.exe"/></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'

SOURCE = r'''
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "REGISTRY"
#include "APPLICATION"
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
namespace ks::r3::security { CommandResult FakeRunner(const std::wstring&, DWORD, const std::function<bool()>& = {}); }
#define RunPowerShellJson FakeRunner
#include "BACKEND_SOURCE"
#undef RunPowerShellJson
namespace ks::r3::security {
CommandResult FakeRunner(const std::wstring& body,DWORD timeout,const std::function<bool()>&) {
    const std::wstring mock = LR"PS(
$global:policy='POLICY'
$global:pref=[pscustomobject]@{EnableControlledFolderAccess=0;PUAProtection=0;EnableNetworkProtection=0;DisableRealtimeMonitoring=$false;AttackSurfaceReductionRules_Ids=@('22222222-2222-2222-2222-222222222222');AttackSurfaceReductionRules_Actions=@(1)}
function Get-Module {param([switch]$ListAvailable,[string]$Name) [pscustomobject]@{Path='mock'} }
function Import-Module {param([string]$Name) }
function Get-AppLockerPolicy {param([switch]$Local,[switch]$Effective,[switch]$Xml) $global:policy }
function Set-AppLockerPolicy {param([string]$XmlPolicy) if($env:KSWORD_APP_CONTROL_TEST -eq 'fail-write'){throw 'simulated denied'};$global:policy=$XmlPolicy }
function Get-MpPreference { $global:pref }
function Set-MpPreference {
 [CmdletBinding()] param([object]$EnableControlledFolderAccess,[object]$PUAProtection,[object]$EnableNetworkProtection,[object]$DisableRealtimeMonitoring,[string[]]$AttackSurfaceReductionRules_Ids,[int[]]$AttackSurfaceReductionRules_Actions)
 if($env:KSWORD_APP_CONTROL_TEST -eq 'fail-write'){throw 'simulated denied'}
 foreach($key in $PSBoundParameters.Keys){if($null -ne $global:pref.PSObject.Properties[$key]){$global:pref.$key=$PSBoundParameters[$key]}}
}
)PS";
    return RunPowerShellJson(mock+body,timeout,{});
}
}
namespace ks::cli { void registerApplicationControl(); }
int wmain(int argc,wchar_t** argv) {
    _setmode(_fileno(stdout),_O_U8TEXT);ks::cli::registerApplicationControl();
    if(argc==2 && std::wstring(argv[1])==L"--fixture-help") return ks::cli::printHelp(L"security defender settings query") ? 0 : 1;
    return ks::cli::dispatchR3(argc,argv).value_or(99);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-app-control-') as temp:
        directory = Path(temp)
        source = SOURCE.replace('REGISTRY',(ROOT/'KswordCLI/CommandRegistry.h').as_posix())
        source = source.replace('APPLICATION',(ROOT/'shared/usermode/backend/security/ApplicationControl.h').as_posix())
        source = source.replace('BACKEND_SOURCE',(ROOT/'shared/usermode/backend/security/ApplicationControl.cpp').as_posix())
        source = source.replace('POLICY',POLICY.replace("'","''"))
        src = directory/'fixture.cpp'; src.write_text(source,encoding='utf-8')
        binary = directory/'fixture.exe'
        files = ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3ApplicationControl.cpp',
                 'shared/usermode/backend/security/CodeIntegrity.cpp','shared/usermode/backend/Common.cpp',
                 'shared/evidence/EvidenceJson.cpp','shared/evidence/LosslessValue.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',
                        str(src),*[str(ROOT/f) for f in files],'/Fe:'+str(binary),'/link','Advapi32.lib','Crypt32.lib','Ole32.lib'],cwd=directory,check=True)
        help_text = subprocess.run([str(binary),'--fixture-help'],capture_output=True,check=True).stdout.decode('utf-8')
        assert 'KswordCLI.exe security defender settings query [--timeout-ms' in help_text
        assert 'KswordCLI.exe security defender settings query  ' not in help_text
        def call(args, expected=0, env=None):
            run = subprocess.run([str(binary),'security',*args,'--json'],capture_output=True,env=env,timeout=30)
            assert run.returncode==expected,(args,run.returncode,run.stdout[:4000],run.stderr)
            return json.loads(run.stdout)['data']['result']
        current=call(['applocker','rules','enum'])
        assert current['totalCount']==1 and current['rules'][0]['id'].strip('{}')=='11111111-1111-1111-1111-111111111111'
        policy_hash=hashlib.sha256(POLICY.encode()).hexdigest()
        assert current['policyHash']==policy_hash,(current['policyHash'],policy_hash)
        destination=directory/'policy.xml'
        exported=call(['applocker','policy','export','--output',str(destination),'--confirm'])
        assert exported['verified'] and destination.read_text(encoding='utf-8')==POLICY
        call(['applocker','policy','export','--output',str(destination),'--confirm'],3)
        imported=call(['applocker','policy','import','--input',str(destination),'--expected-hash',policy_hash,'--confirm'])
        assert imported['verified']
        fields=['--name',"literal';throw 'INJECTED",'--sid','S-1-1-0','--action','allow','--path','C:\\quoted\'file.exe','--expected-hash',policy_hash,'--confirm']
        assert call(['applocker','rule','add','--collection','exe',*fields])['verified']
        assert call(['applocker','rule','update','--id','11111111-1111-1111-1111-111111111111',*fields])['verified']
        assert call(['applocker','rule','delete','--id','11111111-1111-1111-1111-111111111111','--expected-hash',policy_hash,'--confirm'])['verified']
        stale=call(['applocker','rule','delete','--id','11111111-1111-1111-1111-111111111111','--expected-hash','0'*64,'--confirm'],6)
        assert not stale['changed'] and stale['reason']=='policy changed'
        snap=call(['defender','settings','query']); expected=snap['snapshotHash']
        assert len(expected)==64 and snap['settings']['rules'][0]['action']==1
        assert call(['defender','setting','set','--setting','pua','--value','2','--expected-hash',expected,'--confirm'])['verified']
        assert call(['defender','asr','set','--id','22222222-2222-2222-2222-222222222222','--value','2','--expected-hash',expected,'--confirm'])['verified']
        assert call(['defender','asr','add','--id','33333333-3333-3333-3333-333333333333','--value','6','--expected-hash',expected,'--confirm'])['verified']
        assert call(['defender','asr','delete','--id','22222222-2222-2222-2222-222222222222','--expected-hash',expected,'--confirm'])['verified']
        env=dict(os.environ,KSWORD_APP_CONTROL_TEST='fail-write')
        denied=call(['defender','setting','set','--setting','pua','--value','2','--expected-hash',expected,'--confirm'],6,env)
        assert denied['attempted'] and not denied['verified'] and 'simulated denied' in denied['message']
        missing=subprocess.run([str(binary),'security','defender','setting','set','--setting','pua','--value','2','--expected-hash',expected,'--json'],capture_output=True)
        assert missing.returncode==1 and b'--confirm' in missing.stderr
    print('R3_APPLICATION_CONTROL_FIXTURE_PASS')


if __name__=='__main__': main()
