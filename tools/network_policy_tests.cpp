// Execute validation and wire parsing from the production backend. Provider
// mutation APIs are reached only with requests rejected before COM/PowerShell.
#include "../shared/usermode/backend/network/NetworkPolicy.cpp"
#include <cassert>
#include <iostream>
using namespace ks::r3::network;
int main(){
    const std::wstring id=L"KSword.QoS.{12345678-1234-1234-1234-123456789abc}";
    assert(ownedId(id,qosPrefix));
    for(const auto* wrong:{L"Other.{12345678-1234-1234-1234-123456789abc}",L"KSword.QoS.*",L"KSword.QoS.{12345678-1234-1234-1234-123456789abz}"})assert(!ownedId(wrong,qosPrefix));
    for(const auto* valid:{L"127.0.0.1",L"192.0.2.0/24",L"2001:db8::1",L"2001:db8::/48",L"::/0"})assert(validPrefix(valid));
    for(const auto* invalid:{L"example.com",L"127.0.0.1/33",L"2001:db8::/129",L"127.0.0.1,8.8.8.8",L"*",L"1.2.3.4/",L"1.2.3.4;bad"})assert(!validPrefix(invalid));
    assert(validPath(L"C:\\Program Files\\app.exe"));assert(!validPath(L"app.exe"));assert(!validPath(L"C:\\*.exe"));
    const auto escaped=jsonString(L"C:\\app\"';$(exit)\n\u4e2d.exe");
    assert(escaped.find("$(exit)")==std::string::npos&&escaped.find("\\u0027")!=std::string::npos&&escaped.find("\\u4e2d")!=std::string::npos);
    const auto encode=[](const std::wstring& text){const auto value=base64(reinterpret_cast<const BYTE*>(text.data()),static_cast<DWORD>(text.size()*sizeof(wchar_t)));std::string narrow;for(const auto ch:value)narrow+=static_cast<char>(ch);return narrow;};
    const std::wstring image=L"C:\\Program Files\\example.exe";
    const std::string row="KQ1\tROW\t"+encode(id)+"\t"+encode(image)+"\t8192\r\n";
    auto parsed=parseQosResponse({0,row+"KQ1\tOK\r\n"});
    assert(parsed.success&&parsed.entries.size()==1&&parsed.entries[0].policyId==id&&parsed.entries[0].applicationPath==image&&parsed.entries[0].outboundBytesPerSecond==1024&&parsed.entries[0].enabled);
    assert(!parseQosResponse({0,row}).success);
    assert(!parseQosResponse({0,row+row+"KQ1\tOK\n"}).success);
    assert(!parseQosResponse({1,row+"KQ1\tOK\n"}).success);
    parsed=parseQosResponse({1,"KQ1\tERROR\t2147942405\t"+encode(L"Access denied")+"\n"});
    assert(!parsed.success&&parsed.nativeError==2147942405UL&&parsed.diagnostic==L"Access denied");
    assert(!parseQosResponse({ERROR_TIMEOUT,{}}).success);
    QosPolicy rich;rich.policyId=id;rich.applicationPath=image;rich.outboundBytesPerSecond=1024;
    rich.dscp=46;rich.priority8021=5;rich.protocol=QosProtocol::Tcp;rich.sourcePrefix=L"2001:db8::/48";
    rich.destinationPrefix=L"192.0.2.0/24";rich.sourcePortStart=1000;rich.sourcePortEnd=2000;
    rich.destinationPortStart=rich.destinationPortEnd=443;rich.precedence=200;
    rich.providerOwner=L"PowerShell / WMI";rich.providerDetails=L"Owner and full provider conditions";
    parsed=parseQosResponse({0,qosWireRow(rich)+"KQ1\tOK\n"});
    assert(parsed.success&&parsed.entries.size()==1&&parsed.entries[0].dscp==46&&parsed.entries[0].priority8021==5
        &&parsed.entries[0].sourcePrefix==rich.sourcePrefix&&parsed.entries[0].sourcePortEnd==2000
        &&parsed.entries[0].destinationPortStart==443&&parsed.entries[0].precedence==200&&parsed.entries[0].managed);
    rich.policyId=L"Administrator GPO policy";parsed=parseQosResponse({0,qosWireRow(rich)+"KQ1\tOK\n"});
    assert(parsed.success&&parsed.entries.size()==1&&!parsed.entries[0].managed&&parsed.entries[0].providerOwner==rich.providerOwner);
    rich.policyId=id;rich.sourcePortStart=rich.destinationPortStart=0;rich.sourcePortEnd=rich.destinationPortEnd=65535;
    parsed=parseQosResponse({0,qosWireRow(rich)+"KQ1\tOK\n"});
    assert(parsed.success&&parsed.entries[0].sourcePortStart==0&&parsed.entries[0].sourcePortEnd==0&&parsed.entries[0].destinationPortEnd==0);
    const auto restored=parseQosResponse({0,qosWireRow(parsed.entries[0])+"KQ1\tOK\n"});
    assert(restored.success&&restored.entries[0].sourcePortEnd==0&&restored.entries[0].destinationPortEnd==0);
    assert(samePrefix(L"192.0.2.123/24",L"192.0.2.0/24")&&samePrefix(L"2001:db8::1234/48",L"2001:db8::/48"));
    assert(!samePrefix(L"192.0.2.0/24",L"192.0.3.0/24")&&!samePrefix(L"::/0",L"0.0.0.0/0"));
    QosCommandReply creation;creation.created=true;QosPolicy created;created.policyId=id;
    unsigned rollbacks=0;
    const auto rollback=[&](const QosPolicy& value){assert(value.policyId==id);++rollbacks;QosPolicyList state;state.success=true;return state;};
    auto failed=qosFailure(creation,created,ERROR_INVALID_DATA,L"Readback mismatch",rollback);
    assert(!failed.success&&rollbacks==1&&failed.policyId==id&&failed.diagnostic.find(L"removed")!=std::wstring::npos&&failed.diagnostic.find(id)!=std::wstring::npos);
    creation.rolledBack=true;failed=qosFailure(creation,created,ERROR_INVALID_DATA,L"Provider failed",rollback);assert(rollbacks==1);
    QosCommandReply update;update.updated=true;failed=qosFailure(update,created,ERROR_ACCESS_DENIED,L"Provider failed",rollback);
    assert(rollbacks==1&&failed.diagnostic.find(L"may have changed")!=std::wstring::npos&&failed.diagnostic.find(id)!=std::wstring::npos);
    creation.rolledBack=false;
    failed=qosFailure(creation,created,ERROR_TIMEOUT,L"Provider timed out",[](const QosPolicy&){return QosPolicyList{};});
    assert(failed.diagnostic.find(L"may remain active")!=std::wstring::npos&&failed.diagnostic.find(L"Reuse this policy ID")!=std::wstring::npos);
    const auto timed=parseQosResponse({ERROR_TIMEOUT,"KQ1\tCREATE_ATTEMPT\n"});assert(!timed.success&&timed.created);
    std::uint64_t number=0;assert(parseUnsigned("18446744073709551615",number)&&number==UINT64_MAX);
    assert(!parseUnsigned("18446744073709551616",number)&&!parseUnsigned("-1",number));
    NetworkBlockRequest block;block.scope=PolicyScope::AllApplications;
    assert(!CreateNetworkBlock(block).success);
    block.remotePrefixes={L"bad;address"};assert(!CreateNetworkBlock(block).success);
    block.scope=PolicyScope::ProcessInstance;assert(CreateNetworkBlock(block).nativeError==ERROR_NOT_SUPPORTED);
    assert(!SetNetworkBlockEnabled(L"Unrelated firewall rule",false).success);
    assert(!RemoveNetworkBlock(L"Unrelated firewall rule").success);
    QosPolicy qos;qos.applicationPath=image;qos.outboundBytesPerSecond=0;
    assert(!SaveQosPolicy(qos).success);
    qos.outboundBytesPerSecond=UINT64_MAX;assert(!SaveQosPolicy(qos).success);
    qos.outboundBytesPerSecond=1024;qos.dscp=64;assert(!SaveQosPolicy(qos).success);
    qos.dscp=46;qos.priority8021=8;assert(!SaveQosPolicy(qos).success);
    qos.priority8021=-1;qos.sourcePortStart=2000;qos.sourcePortEnd=1000;assert(!SaveQosPolicy(qos).success);
    QosPolicy conditioned;conditioned.applicationPath=image;conditioned.outboundBytesPerSecond=1024;conditioned.sourcePrefix=L"192.0.2.0/24";
    const auto rejected=SaveQosPolicy(conditioned);assert(!rejected.success&&rejected.policyId.empty()&&rejected.diagnostic.find(L"Choose TCP")!=std::wstring::npos);
    conditioned.sourcePrefix.clear();conditioned.destinationPortStart=conditioned.destinationPortEnd=443;
    assert(!SaveQosPolicy(conditioned).success);
    assert(!SetQosPolicyEnabled(L"An unrelated QoS policy",false).success);
    assert(!RemoveQosPolicy(L"An unrelated QoS policy").success);
    const auto resolved=ResolveNetworkHost(L"2001:db8::/48");assert(resolved.success&&resolved.remotePrefixes.size()==1);
    std::cout<<"NETWORK_POLICY_TESTS=PASS provider_mutations=0 validation_protocol_identity_namespace_rate\n";
}
