"""Exercise firewall rule identity gates and CLI arguments without changing firewall rules."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BACKEND = r'''
#include "BACKEND"
#include <cassert>
using namespace ks::r3::network;
static int scenario=0;
FirewallRuleEntry entry(){FirewallRuleEntry r;r.name=L"Fixture";r.fieldFlags=0xffff;r.protocol=6;r.profiles=7;r.enabled=true;return r;}
namespace ks::r3::network {
FirewallEnumerationResult EnumerateFirewallRules(){FirewallEnumerationResult r;r.success=true;r.complete=scenario!=3;
  if(scenario!=0)r.entries.push_back(entry());if(scenario==2)r.entries.push_back(entry());
  if(scenario==4){auto other=entry();other.enabled=false;r.entries.push_back(other);}return r;}
bool ReadFirewallRule(INetFwRule*,FirewallRuleEntry&){return false;}
}
int main(){
 auto a=entry();const auto hash=FirewallRuleFingerprint(a);assert(hash.size()==64);assert(hash==FirewallRuleFingerprint(a));
 auto changed=a;changed.enabled=false;assert(hash!=FirewallRuleFingerprint(changed));changed=a;changed.fieldFlags^=1u<<15;assert(hash!=FirewallRuleFingerprint(changed));
 scenario=0;auto absent=QueryFirewallRule(L"Fixture");assert(absent.success&&absent.complete&&absent.matchingCount==0);
 scenario=1;auto found=QueryFirewallRule(L"fixture");assert(found.success&&found.complete&&found.matchingCount==1&&found.fingerprint==hash);
 scenario=2;auto duplicate=QueryFirewallRule(L"Fixture");assert(duplicate.matchingCount==2&&duplicate.fingerprint.empty());
 FirewallRuleMutation m;m.name=L"Fixture";m.expectedFingerprint=hash;auto denied=RemoveFirewallRule(m);assert(!denied.requestAttempted);
 scenario=4;auto selected=QueryFirewallRule(L"Fixture",hash);assert(selected.nameMatchingCount==2&&selected.matchingCount==1&&selected.fingerprint==hash);
 denied=RemoveFirewallRule(m);assert(!denied.requestAttempted);
 scenario=3;auto incomplete=UpdateFirewallRule(m);assert(!incomplete.preflightComplete&&!incomplete.requestAttempted);
 scenario=1;m.expectedFingerprint=L"stale";auto stale=UpdateFirewallRule(m);assert(!stale.requestAttempted);
}
'''
CLI = r'''
#include "REGISTRY"
#include "BACKEND"
#include <fcntl.h>
#include <io.h>
namespace ks::cli {void registerFirewallActions();}
namespace ks::r3::network {
static FirewallRuleLookup lookup(){FirewallRuleLookup r;r.success=true;r.complete=true;r.matchingCount=1;r.nameMatchingCount=1;r.fingerprint=std::wstring(64,L'a');r.entry.name=L"fixture";r.entry.fieldFlags=1;return r;}
FirewallRuleLookup QueryFirewallRule(const std::wstring&,const std::wstring&){return lookup();}
FirewallMutationResult CreateFirewallRule(const FirewallRuleMutation& m){FirewallMutationResult r;r.preflightComplete=true;r.requestAttempted=true;r.requestSucceeded=m.fields.protocol==6&&m.fields.direction==1&&m.fields.enabled;r.verified=r.requestSucceeded;r.postcheckComplete=true;r.after=lookup();return r;}
FirewallMutationResult UpdateFirewallRule(const FirewallRuleMutation& m){FirewallMutationResult r;r.preflightComplete=true;r.requestAttempted=true;r.requestSucceeded=m.expectedFingerprint==std::wstring(64,L'a')&&((m.fields.fieldFlags&(1u<<14))||(m.rename&&m.newName==L"new"));r.verified=r.requestSucceeded;r.postcheckComplete=true;r.before=lookup();r.after=lookup();return r;}
FirewallMutationResult RemoveFirewallRule(const FirewallRuleMutation& m){FirewallMutationResult r;r.preflightComplete=true;r.requestAttempted=true;r.requestSucceeded=m.expectedFingerprint==std::wstring(64,L'a');r.verified=r.requestSucceeded;r.postcheckComplete=true;r.before=lookup();return r;}
}
int wmain(int argc,wchar_t* argv[]){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);ks::cli::registerFirewallActions();return ks::cli::dispatchR3(argc,argv).value_or(1);}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-firewall-actions-") as temp:
        path = Path(temp)
        header = (ROOT / "shared/usermode/backend/network/FirewallOperations.h").as_posix()
        registry = (ROOT / "KswordCLI/CommandRegistry.h").as_posix()
        (path / "backend.cpp").write_text(BACKEND.replace("BACKEND", header), encoding="utf-8")
        (path / "cli.cpp").write_text(CLI.replace("REGISTRY", registry).replace("BACKEND", header), encoding="utf-8")
        common = ["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", "/DNOMINMAX", "/DUNICODE", "/D_UNICODE"]
        subprocess.run(common + [str(path / "backend.cpp"), str(ROOT / "shared/usermode/backend/network/FirewallOperations.cpp"), "/Fe:" + str(path / "backend.exe"), "/link", "Advapi32.lib", "Ole32.lib", "OleAut32.lib"], cwd=path, check=True)
        subprocess.run([str(path / "backend.exe")], check=True, timeout=15)
        subprocess.run(common + [str(path / "cli.cpp"), str(ROOT / "KswordCLI/CommandRegistry.cpp"), str(ROOT / "KswordCLI/R3FirewallActions.cpp"), "/Fe:" + str(path / "cli.exe")], cwd=path, check=True)
        def run(*args):
            p = subprocess.run([str(path / "cli.exe"), "network", "firewall", "rule", *args, "--json"], capture_output=True, timeout=15)
            return p.returncode, json.loads(p.stdout)
        code, doc = run("query", "--name", "fixture")
        assert code == 0 and doc["data"]["fingerprint"] == "a" * 64
        code, doc = run("create", "--name", "fixture", "--protocol", "tcp", "--direction", "in", "--action", "block", "--profiles", "7", "--enabled", "on", "--confirm")
        assert code == 0 and doc["data"]["verified"]
        assert run("create", "--name", "fixture", "--confirm")[0] == 1
        assert run("delete", "--name", "fixture", "--fingerprint", "a" * 64)[0] == 1
        assert run("delete", "--name", "fixture", "--fingerprint", "bad", "--confirm")[0] == 1
        assert run("enable", "--name", "fixture", "--fingerprint", "a" * 64, "--confirm")[0] == 0
        assert run("update", "--name", "fixture", "--fingerprint", "a" * 64, "--confirm")[0] == 1
        assert run("update", "--name", "fixture", "--fingerprint", "a" * 64, "--new-name", "new", "--confirm")[0] == 0
        assert run("delete", "--name", "fixture", "--fingerprint", "a" * 64, "--confirm")[0] == 0
        print("R3_FIREWALL_ACTIONS_PASS identity, duplicate/incomplete snapshots, fingerprint, confirmation, arguments")


if __name__ == "__main__":
    main()
