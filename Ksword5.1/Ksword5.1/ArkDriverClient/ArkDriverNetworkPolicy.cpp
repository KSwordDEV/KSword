#include "ArkDriverNetworkPolicy.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include "ArkDriverClient.h"
#include "../../../shared/usermode/backend/network/NetworkPolicy.h"
#include "../../../shared/driver/KswordArkManagedNetworkIoctl.h"
#include <objbase.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>

namespace ksword::ark {
namespace {
using namespace ks::r3::network;
constexpr wchar_t prefix[]=L"KSword.Driver.";
constexpr unsigned long capabilities=KSWORD_ARK_NETWORK_MANAGED_CAP_IPV4|KSWORD_ARK_NETWORK_MANAGED_CAP_IPV6
    |KSWORD_ARK_NETWORK_MANAGED_CAP_CIDR|KSWORD_ARK_NETWORK_MANAGED_CAP_PROCESS_INSTANCE;
std::wstring policyId(const unsigned char* bytes){
    GUID guid{};std::memcpy(&guid,bytes,sizeof(guid));wchar_t text[40]{};
    if(!StringFromGUID2(guid,text,40))return {};return std::wstring(prefix)+text;
}
bool parseId(const std::wstring& id,unsigned char* bytes){
    if(id.size()!=std::size(prefix)-1+38||id.compare(0,std::size(prefix)-1,prefix)!=0)return false;
    GUID guid{};if(FAILED(CLSIDFromString(id.substr(std::size(prefix)-1).c_str(),&guid)))return false;
    const GUID empty{};if(std::memcmp(&guid,&empty,sizeof(guid))==0)return false;std::memcpy(bytes,&guid,sizeof(guid));return true;
}
std::wstring diagnostic(const IoResult& io,const long status){
    std::wostringstream text;text<<L"Driver network policy: Win32="<<io.win32Error<<L", NTSTATUS=0x"<<std::hex<<static_cast<unsigned long>(status);return text.str();
}
bool validStatus(const unsigned long status){
    return status==KSWORD_ARK_NETWORK_STATUS_APPLIED||status==KSWORD_ARK_NETWORK_STATUS_CLEARED
        ||status==KSWORD_ARK_NETWORK_STATUS_DISABLED||status==KSWORD_ARK_NETWORK_STATUS_INVALID_RULE
        ||status==KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE||status==KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
}
bool validRow(const KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY& row){
    const bool nonzero=std::any_of(std::begin(row.policyId),std::end(row.policyId),[](unsigned char value){return value!=0;});
    if(!nonzero||row.reserved0||row.reserved1||row.prefixCount>KSWORD_ARK_NETWORK_MANAGED_MAX_PREFIXES
        ||(row.directionMask&~KSWORD_ARK_NETWORK_DIRECTION_BOTH)||!row.directionMask
        ||(row.flags&~(KSWORD_ARK_NETWORK_MANAGED_ENABLED|KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED))
        ||(!row.processId&&row.creationTime100ns)||(row.processId&&!row.creationTime100ns)||(!row.processId&&!row.prefixCount))return false;
    for(unsigned long index=0;index<row.prefixCount;++index){
        const auto& host=row.prefixes[index];
        if((host.family!=4&&host.family!=6)||host.prefixLength>(host.family==4?32UL:128UL))return false;
        if(host.family==4&&std::any_of(host.address+4,host.address+16,[](unsigned char value){return value!=0;}))return false;
    }
    return true;
}
NetworkBlockList query(){
    DriverClient client;auto handle=client.openSilently(GENERIC_READ);NetworkBlockList result;
    if(!handle.isValid()){result.nativeError=GetLastError();result.diagnostic=L"The driver device is unavailable or access was denied.";return result;}
    auto response=std::make_unique<KSWORD_ARK_NETWORK_MANAGED_QUERY_RESPONSE>();
    const auto io=client.deviceIoControl(IOCTL_KSWORD_ARK_NETWORK_QUERY_MANAGED_POLICIES,nullptr,0,response.get(),sizeof(*response),&handle);
    result.nativeError=io.win32Error;result.diagnostic=diagnostic(io,response->lastStatus);
    if(!io.ok)return result;
    if(io.bytesReturned!=sizeof(*response)||response->version!=KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION
        ||response->size!=sizeof(*response)||response->reserved||response->policyCount>KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES
        ||(response->capabilities&~capabilities)||!validStatus(response->status)){
        result.nativeError=ERROR_INVALID_DATA;result.diagnostic=L"Invalid driver managed-network response.";return result;
    }
    if(response->lastStatus<0||response->status!=KSWORD_ARK_NETWORK_STATUS_APPLIED){result.nativeError=static_cast<unsigned long>(response->lastStatus);return result;}
    std::map<std::wstring,bool> identities;
    for(unsigned long index=0;index<response->policyCount;++index){
        const auto& row=response->policies[index];if(!validRow(row)){result.entries.clear();result.nativeError=ERROR_INVALID_DATA;return result;}
        ManagedNetworkBlock item;item.policyId=policyId(row.policyId);item.backend=PolicyBackend::Driver;
        if(item.policyId.empty()||!identities.emplace(item.policyId,true).second){result.entries.clear();result.nativeError=ERROR_INVALID_DATA;return result;}
        item.scope=row.processId?PolicyScope::ProcessInstance:PolicyScope::AllApplications;
        item.processId=row.processId;item.creationTime100ns=row.creationTime100ns;
        item.enabled=(row.flags&KSWORD_ARK_NETWORK_MANAGED_ENABLED)!=0&&(row.flags&KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED)==0;item.complete=true;
        item.inbound=(row.directionMask&KSWORD_ARK_NETWORK_DIRECTION_INBOUND)!=0;item.outbound=(row.directionMask&KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND)!=0;
        for(unsigned long host=0;host<row.prefixCount;++host){
            wchar_t text[INET6_ADDRSTRLEN]{};const auto& address=row.prefixes[host];
            if(!InetNtopW(address.family==4?AF_INET:AF_INET6,const_cast<unsigned char*>(address.address),text,INET6_ADDRSTRLEN)){result.entries.clear();result.nativeError=ERROR_INVALID_DATA;return result;}
            item.remotePrefixes.push_back(std::wstring(text)+L"/"+std::to_wstring(address.prefixLength));
        }
        result.entries.push_back(std::move(item));
    }
    result.success=true;result.driverAvailable=(response->capabilities&(KSWORD_ARK_NETWORK_MANAGED_CAP_IPV4|KSWORD_ARK_NETWORK_MANAGED_CAP_IPV6|KSWORD_ARK_NETWORK_MANAGED_CAP_CIDR))
        ==(KSWORD_ARK_NETWORK_MANAGED_CAP_IPV4|KSWORD_ARK_NETWORK_MANAGED_CAP_IPV6|KSWORD_ARK_NETWORK_MANAGED_CAP_CIDR);
    result.driverProcessInstanceAvailable=(response->capabilities&KSWORD_ARK_NETWORK_MANAGED_CAP_PROCESS_INSTANCE)!=0;
    return result;
}
NetworkPolicyResult control(const KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST& request,const std::wstring& id){
    DriverClient client;auto handle=client.openSilently(GENERIC_READ|GENERIC_WRITE);
    if(!handle.isValid())return {false,GetLastError(),id,L"The driver device is unavailable or access was denied."};
    auto input=request;KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE response{};
    const auto io=client.deviceIoControl(IOCTL_KSWORD_ARK_NETWORK_CONTROL_MANAGED_POLICY,&input,sizeof(input),&response,sizeof(response),&handle);
    if(!io.ok)return {false,io.win32Error,id,diagnostic(io,response.lastStatus)};
    if(io.bytesReturned!=sizeof(response)||response.version!=KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION||response.size!=sizeof(response)
        ||response.reserved||response.policyCount>KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES||(response.capabilities&~capabilities)||!validStatus(response.status))
        return {false,ERROR_INVALID_DATA,id,L"Invalid driver managed-network control response."};
    const auto expected=request.action==KSWORD_ARK_NETWORK_MANAGED_REMOVE?KSWORD_ARK_NETWORK_STATUS_CLEARED
        :request.action==KSWORD_ARK_NETWORK_MANAGED_DISABLE?KSWORD_ARK_NETWORK_STATUS_DISABLED:KSWORD_ARK_NETWORK_STATUS_APPLIED;
    const bool applied=response.lastStatus>=0&&response.status==expected;
    const auto error=applied?0UL:response.lastStatus<0?static_cast<unsigned long>(response.lastStatus):ERROR_INVALID_DATA;
    return {applied,error,id,diagnostic(io,response.lastStatus)};
}
KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST makeRequest(const unsigned long action){
    KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST request{};request.version=KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION;request.size=sizeof(request);request.action=action;return request;
}
NetworkPolicyResult create(const NetworkBlockRequest& block){
    if(block.scope!=PolicyScope::ProcessInstance&&block.scope!=PolicyScope::AllApplications)return {false,ERROR_NOT_SUPPORTED,{},L"Driver rules require a process instance or global host scope, not an application-image scope."};
    if(block.remotePrefixes.size()>KSWORD_ARK_NETWORK_MANAGED_MAX_PREFIXES||(!block.inbound&&!block.outbound)
        ||(block.scope==PolicyScope::AllApplications&&block.remotePrefixes.empty())
        ||(block.scope==PolicyScope::ProcessInstance&&(!block.target.processId||!block.target.creationTime100ns)))
        return {false,ERROR_INVALID_PARAMETER,{},L"Invalid driver policy identity, address scope or direction."};
    auto request=makeRequest(KSWORD_ARK_NETWORK_MANAGED_UPSERT);GUID guid{};
    const auto status=CoCreateGuid(&guid);if(FAILED(status))return {false,static_cast<unsigned long>(status),{},L"Cannot allocate a driver policy identity."};
    std::memcpy(request.policy.policyId,&guid,sizeof(guid));const auto id=policyId(request.policy.policyId);
    request.policy.processId=block.scope==PolicyScope::ProcessInstance?block.target.processId:0;
    request.policy.creationTime100ns=block.scope==PolicyScope::ProcessInstance?block.target.creationTime100ns:0;
    request.policy.directionMask=(block.inbound?KSWORD_ARK_NETWORK_DIRECTION_INBOUND:0UL)|(block.outbound?KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND:0UL);
    request.policy.flags=KSWORD_ARK_NETWORK_MANAGED_ENABLED;
    for(const auto& address:block.remotePrefixes){
        NetworkAddressPrefix parsed;if(!ParseNetworkAddressPrefix(address,parsed))return {false,ERROR_INVALID_PARAMETER,id,L"Driver host rules require numeric IPv4/IPv6 addresses or CIDR prefixes."};
        auto& hostPrefix=request.policy.prefixes[request.policy.prefixCount++];hostPrefix.family=parsed.family;hostPrefix.prefixLength=parsed.prefixLength;
        std::copy(parsed.address.begin(),parsed.address.end(),std::begin(hostPrefix.address));
    }
    return control(request,id);
}
NetworkPolicyResult change(const std::wstring& id,const unsigned long action){
    auto request=makeRequest(action);if(!parseId(id,request.policy.policyId))return {false,ERROR_INVALID_PARAMETER,id,L"Invalid owned driver policy identity."};
    return control(request,id);
}
}
void InstallDriverNetworkPolicies(){
    static std::once_flag once;std::call_once(once,[]{
        auto operations=std::make_shared<ks::r3::network::NetworkPolicyDriverOperations>();
        operations->create=create;operations->list=query;
        operations->enable=[](const std::wstring& id,bool enabled){return change(id,enabled?KSWORD_ARK_NETWORK_MANAGED_ENABLE:KSWORD_ARK_NETWORK_MANAGED_DISABLE);};
        operations->remove=[](const std::wstring& id){return change(id,KSWORD_ARK_NETWORK_MANAGED_REMOVE);};
        SetNetworkPolicyDriverOperations(std::move(operations));
    });
}
}
