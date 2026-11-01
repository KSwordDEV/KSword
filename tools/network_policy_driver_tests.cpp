#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverNetworkPolicy.cpp"
#include <cassert>
#include <iostream>
namespace {
enum class Reply { Valid, Short, Version, Duplicate, BadPrefix, Transport, WrongAction };
Reply reply=Reply::Valid;
unsigned calls=0;
KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST lastControl{};
}
namespace ksword::ark {
DriverHandle::DriverHandle(HANDLE value)noexcept:m_handle(value){}
DriverHandle::~DriverHandle()=default;
bool DriverHandle::isValid()const noexcept{return m_handle!=INVALID_HANDLE_VALUE;}
DriverHandle DriverClient::openSilently(unsigned long)const{return DriverHandle(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(1)));}
IoResult DriverClient::deviceIoControl(unsigned long code,void* input,unsigned long,void* output,unsigned long bytes,DriverHandle*)const{
    ++calls;IoResult io;io.ok=reply!=Reply::Transport;io.win32Error=io.ok?0:ERROR_ACCESS_DENIED;io.bytesReturned=bytes;if(!io.ok)return io;
    if(code==IOCTL_KSWORD_ARK_NETWORK_QUERY_MANAGED_POLICIES){
        auto& response=*static_cast<KSWORD_ARK_NETWORK_MANAGED_QUERY_RESPONSE*>(output);response={};
        response.version=KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION;response.size=sizeof(response);response.status=KSWORD_ARK_NETWORK_STATUS_APPLIED;
        response.capabilities=15;response.policyCount=2;
        auto& global=response.policies[0];global.policyId[0]=1;global.directionMask=3;global.flags=KSWORD_ARK_NETWORK_MANAGED_ENABLED;global.prefixCount=1;
        global.prefixes[0].family=4;global.prefixes[0].prefixLength=24;global.prefixes[0].address[0]=192;global.prefixes[0].address[1]=0;global.prefixes[0].address[2]=2;
        auto& process=response.policies[1];process.policyId[0]=2;process.directionMask=3;process.processId=42;process.creationTime100ns=99;
        process.flags=KSWORD_ARK_NETWORK_MANAGED_ENABLED|KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED;
        if(reply==Reply::Short)--io.bytesReturned;
        if(reply==Reply::Version)++response.version;
        if(reply==Reply::Duplicate)std::memcpy(process.policyId,global.policyId,16);
        if(reply==Reply::BadPrefix)global.prefixes[0].address[15]=1;
    }else{
        assert(code==IOCTL_KSWORD_ARK_NETWORK_CONTROL_MANAGED_POLICY);lastControl=*static_cast<KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST*>(input);
        auto& response=*static_cast<KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE*>(output);response={};
        response.version=KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION;response.size=sizeof(response);response.capabilities=15;
        response.status=lastControl.action==KSWORD_ARK_NETWORK_MANAGED_REMOVE?KSWORD_ARK_NETWORK_STATUS_CLEARED
            :lastControl.action==KSWORD_ARK_NETWORK_MANAGED_DISABLE?KSWORD_ARK_NETWORK_STATUS_DISABLED:KSWORD_ARK_NETWORK_STATUS_APPLIED;
        if(reply==Reply::WrongAction)response.status=KSWORD_ARK_NETWORK_STATUS_CLEARED;
    }
    return io;
}
}
int main(){
    using namespace ksword::ark;using namespace ks::r3::network;
    auto policies=query();assert(policies.success&&policies.driverAvailable&&policies.driverProcessInstanceAvailable&&policies.entries.size()==2);
    assert(policies.entries[0].remotePrefixes[0]==L"192.0.2.0/24"&&policies.entries[0].scope==PolicyScope::AllApplications);
    assert(policies.entries[1].processId==42&&policies.entries[1].creationTime100ns==99&&!policies.entries[1].enabled);
    for(const auto invalid:{Reply::Short,Reply::Version,Reply::Duplicate,Reply::BadPrefix,Reply::Transport}){
        reply=invalid;policies=query();assert(!policies.success&&policies.entries.empty());
    }
    reply=Reply::Valid;NetworkBlockRequest block;block.backend=PolicyBackend::Driver;block.scope=PolicyScope::ProcessInstance;
    block.target.processId=42;block.target.creationTime100ns=99;block.remotePrefixes={L"192.0.2.123/24",L"2001:db8::1234/48"};
    const auto applied=create(block);assert(applied.success&&lastControl.policy.processId==42&&lastControl.policy.creationTime100ns==99);
    assert(lastControl.policy.prefixCount==2&&lastControl.policy.prefixes[0].address[3]==0&&lastControl.policy.prefixes[1].family==6);
    unsigned char id[16]{};assert(parseId(applied.policyId,id)&&std::memcmp(id,lastControl.policy.policyId,16)==0);
    assert(change(applied.policyId,KSWORD_ARK_NETWORK_MANAGED_DISABLE).success);
    assert(change(applied.policyId,KSWORD_ARK_NETWORK_MANAGED_ENABLE).success);
    reply=Reply::WrongAction;assert(!change(applied.policyId,KSWORD_ARK_NETWORK_MANAGED_ENABLE).success);reply=Reply::Valid;
    const auto before=calls;block.scope=PolicyScope::ApplicationImage;assert(!create(block).success);
    block.scope=PolicyScope::ProcessInstance;block.target.creationTime100ns=0;assert(!create(block).success);
    assert(!change(L"An unrelated policy",KSWORD_ARK_NETWORK_MANAGED_REMOVE).success&&calls==before);
    std::cout<<"NETWORK_POLICY_DRIVER_TESTS=PASS actual_device_calls=0 typed_response_identity_scope_direction\n";
}
