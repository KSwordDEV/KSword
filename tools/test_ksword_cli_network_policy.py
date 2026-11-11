"""Exercise policy command routing and postchecks without changing system rules."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = r'''
#include "REGISTRY"
#include "POLICY"
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <cstring>
static std::wstring scenario;
static unsigned actions = 0;
static ks::r3::network::NetworkBlockRequest requested;
static std::wstring changedId;
static ks::r3::network::QosPolicy qosRequested;
static bool desiredEnabled = true, removed = false;
namespace ksword::ark { void InstallDriverNetworkPolicies() {} }
namespace ks::r3::network {
bool ParseNetworkAddressPrefix(const std::wstring& text, NetworkAddressPrefix& out) {
    if (text.empty() || text == L"bad") return false;
    out = {}; out.family=4; out.prefixLength=32; out.address[0]=127; return true;
}
NetworkPolicyResult CreateNetworkBlock(const NetworkBlockRequest& r) {
    ++actions; requested=r; changedId=r.backend==PolicyBackend::Driver?L"KSword.Driver.{ID}":L"KSword.Network.{ID}";
    return {true,0,changedId,L"created"};
}
NetworkPolicyResult SetNetworkBlockEnabled(const std::wstring& id, bool enabled) {
    ++actions; changedId=id; desiredEnabled=enabled;return {true,0,id,L"changed"};
}
NetworkPolicyResult RemoveNetworkBlock(const std::wstring& id) {
    ++actions; changedId=id; removed=true;return {true,0,id,L"removed"};
}
NetworkBlockList ListNetworkBlocks() {
    NetworkBlockList list; list.success=true; list.firewallAvailable=true;list.driverAvailable=scenario!=L"driver-down";
    list.driverProcessInstanceAvailable=list.driverAvailable;
    if (!changedId.empty() && !removed) {
        ManagedNetworkBlock row;row.policyId=changedId;row.backend=changedId.starts_with(L"KSword.Driver.")?PolicyBackend::Driver:PolicyBackend::Firewall;
        row.scope=requested.scope;row.applicationPath=requested.target.applicationPath;row.processId=requested.target.processId;row.creationTime100ns=requested.target.creationTime100ns;
        row.inbound=requested.inbound;row.outbound=requested.outbound;row.remotePrefixes=requested.remotePrefixes;
        row.enabled=scenario==L"wrong-state"?!desiredEnabled:desiredEnabled;row.complete=true;list.entries.push_back(row);
    }
    return list;
}
QosPolicyList ListQosPolicies() {
    QosPolicyList list;list.success=scenario!=L"qos-down";
    if(!qosRequested.policyId.empty()&&!removed)list.entries.push_back(qosRequested);
    return list;
}
NetworkPolicyResult SaveQosPolicy(const QosPolicy& p) {
    ++actions;qosRequested=p;if(qosRequested.policyId.empty())qosRequested.policyId=L"KSword.QoS.{ID}";
    return {true,0,qosRequested.policyId,L"saved"};
}
NetworkPolicyResult SetQosPolicyEnabled(const std::wstring& id,bool enabled) {
    ++actions;qosRequested.policyId=id;qosRequested.enabled=enabled;return {true,0,id,L"changed"};
}
NetworkPolicyResult RemoveQosPolicy(const std::wstring& id) {
    ++actions;removed=true;return {true,0,id,L"removed"};
}
}
namespace ks::cli { void registerNetworkPolicy(); }
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    scenario=argv[1]; ++argv;--argc;ks::cli::registerNetworkPolicy();
    const int code=ks::cli::dispatchR3(argc,argv).value_or(99);
    if (scenario==L"reject" && actions) return 98;
    return code;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-network-policy-") as temp:
        tmp = Path(temp)
        source = FIXTURE.replace("REGISTRY", (ROOT / "KswordCLI/CommandRegistry.h").as_posix()).replace(
            "POLICY", (ROOT / "shared/usermode/backend/network/NetworkPolicy.h").as_posix())
        (tmp / "fixture.cpp").write_text(source, encoding="utf-8")
        exe = tmp / "fixture.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/W4", "/WX", "/DNOMINMAX", "/DUNICODE", "/D_UNICODE",
                        str(tmp / "fixture.cpp"), str(ROOT / "KswordCLI/CommandRegistry.cpp"),
                        str(ROOT / "KswordCLI/NetworkPolicyCommand.cpp"), "/Fe:" + str(exe), "/link", "Ole32.lib"], cwd=tmp, check=True)

        def run(scenario, command, code):
            result = subprocess.run([str(exe), scenario, *command, "--json"], capture_output=True, timeout=10)
            assert result.returncode == code, (command, result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)

        r0 = run("ok", ["network", "policy", "create", "--backend", "r0", "--scope", "process", "--pid", "123", "--creation-time", "99", "--confirm"], 0)
        assert r0["backend"] == "r0" and r0["data"]["verified"] and r0["data"]["postcheck"]["pid"] == 123
        r3 = run("ok", ["network", "policy", "create", "--scope", "image", "--path", r"C:\a.exe", "--confirm"], 0)
        assert r3["backend"] == "r3" and r3["data"]["postcheck"]["scope"] == "image"
        partial = run("wrong-state", ["network", "policy", "create", "--scope", "all", "--remote", "127.0.0.1", "--confirm"], 6)
        assert not partial["data"]["verified"] and partial["data"]["requestSucceeded"]
        unknown = run("driver-down", ["network", "policy", "create", "--backend", "r0", "--scope", "all", "--remote", "127.0.0.1", "--confirm"], 6)
        assert unknown["data"]["postcheckPresent"] is None
        run("reject", ["network", "policy", "create", "--backend", "r0", "--scope", "image", "--path", r"C:\a.exe", "--confirm"], 1)
        run("reject", ["network", "policy", "create", "--scope", "all", "--remote", "bad", "--confirm"], 1)
        run("reject", ["network", "policy", "remove", "--backend", "r0", "--id", "KSword.Network.{ID}", "--confirm"], 1)
        run("reject", ["network", "policy", "create", "--scope", "all", "--remote", "127.0.0.1"], 1)
        qos = run("ok", ["network", "qos", "save", "--scope", "all", "--rate", "1000", "--protocol", "tcp", "--confirm"], 0)
        assert qos["data"]["verified"] and qos["data"]["postcheck"]["outboundBytesPerSecond"] == "1000"
        run("reject", ["network", "qos", "save", "--scope", "all", "--rate", "1000", "--dscp", "64", "--confirm"], 1)
        run("reject", ["network", "qos", "save", "--scope", "all", "--rate", "1000", "--source-port-start", "65536", "--confirm"], 1)
        run("reject", ["network", "qos", "enum", "--backend", "r0"], 1)
        print("CLI_NETWORK_POLICY_PASS: backends, identity, confirmation, validation and postcheck")


if __name__ == "__main__":
    main()
