#include "NetworkPolicy.h"
#include "Firewall.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <utility>
#include <atomic>
#include <thread>
#include <cstring>
#include <wincrypt.h>
#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"OleAut32.lib")
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Crypt32.lib")

namespace ks::r3::network {
namespace {
constexpr wchar_t blockPrefix[]=L"KSword.Network.";
constexpr wchar_t blockGroup[]=L"KSword Network Controls";
constexpr wchar_t qosPrefix[]=L"KSword.QoS.";
constexpr wchar_t driverPrefix[]=L"KSword.Driver.";
std::mutex policyLock;
std::mutex driverOperationsLock;
std::shared_ptr<const NetworkPolicyDriverOperations> driverOperations;
std::shared_ptr<const NetworkPolicyDriverOperations> currentDriverOperations(){const std::lock_guard<std::mutex> lock(driverOperationsLock);return driverOperations;}
template<class T> struct Com {
    T* value=nullptr;
    ~Com(){if(value)value->Release();}
    T** put(){return &value;}
    void** out(){return reinterpret_cast<void**>(&value);}
    T* operator->()const{return value;}
};
struct Apartment {
    HRESULT status=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE);
    ~Apartment(){if(SUCCEEDED(status))CoUninitialize();}
    bool good()const{return SUCCEEDED(status)||status==RPC_E_CHANGED_MODE;}
};
struct Bstr {
    BSTR value;
    explicit Bstr(const std::wstring& text):value(SysAllocStringLen(text.data(),static_cast<UINT>(text.size()))){}
    ~Bstr(){SysFreeString(value);}
    operator BSTR()const{return value;}
};
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    ~Handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
NetworkPolicyResult result(const bool success,const DWORD code,std::wstring id,std::wstring detail){
    return {success,code,std::move(id),std::move(detail)};
}
bool ownedId(const std::wstring& value,const wchar_t* prefix){
    const std::wstring start(prefix);
    if(value.size()!=start.size()+38||value.compare(0,start.size(),start)!=0)return false;
    const auto guid=value.substr(start.size());
    if(guid.front()!=L'{'||guid.back()!=L'}')return false;
    for(std::size_t index=1;index<37;++index){
        const auto ch=guid[index];
        if(index==9||index==14||index==19||index==24){if(ch!=L'-')return false;}
        else if(!((ch>=L'0'&&ch<=L'9')||(ch>=L'a'&&ch<=L'f')||(ch>=L'A'&&ch<=L'F')))return false;
    }
    return true;
}
std::wstring newId(const wchar_t* prefix){
    GUID value{};if(FAILED(CoCreateGuid(&value)))return {};
    wchar_t text[40]{};if(StringFromGUID2(value,text,40)==0)return {};
    return std::wstring(prefix)+text;
}
bool validPath(const std::wstring& path){
    return path.size()>3&&path.size()<32760&&path.find(L'\0')==std::wstring::npos
        &&((((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z'))&&path[1]==L':'&&(path[2]==L'\\'||path[2]==L'/'))||path.rfind(L"\\\\",0)==0)
        &&path.find_first_of(L"*?\r\n\"")==std::wstring::npos;
}
bool validateIdentity(const PolicyProcessIdentity& identity,Handle& process,DWORD& error){
    if(!validPath(identity.applicationPath)){error=ERROR_INVALID_PARAMETER;return false;}
    if(identity.processId==0){if(identity.creationTime100ns!=0){error=ERROR_INVALID_PARAMETER;return false;}return true;}
    if(identity.creationTime100ns==0){error=ERROR_INVALID_PARAMETER;return false;}
    process.value=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,identity.processId);
    if(process.value==nullptr){error=GetLastError();return false;}
    FILETIME creation{},exit{},kernel{},user{};wchar_t path[32768]{};DWORD length=32768;
    if(!GetProcessTimes(process.value,&creation,&exit,&kernel,&user)||!QueryFullProcessImageNameW(process.value,0,path,&length)){
        error=GetLastError();return false;
    }
    const auto stamp=(static_cast<std::uint64_t>(creation.dwHighDateTime)<<32)|creation.dwLowDateTime;
    if(stamp!=identity.creationTime100ns||WaitForSingleObject(process.value,0)!=WAIT_TIMEOUT
        ||CompareStringOrdinal(path,static_cast<int>(length),identity.applicationPath.data(),static_cast<int>(identity.applicationPath.size()),TRUE)!=CSTR_EQUAL){
        error=ERROR_INVALID_PARAMETER;return false;
    }
    return true;
}
bool validPrefix(const std::wstring& value){
    if(value.empty()||value.size()>100||value.find(L'\0')!=std::wstring::npos)return false;
    const auto slash=value.find(L'/');const auto address=value.substr(0,slash);
    IN_ADDR v4{};IN6_ADDR v6{};int maximum=0;
    if(InetPtonW(AF_INET,address.c_str(),&v4)==1)maximum=32;
    else if(InetPtonW(AF_INET6,address.c_str(),&v6)==1)maximum=128;
    else return false;
    if(slash==std::wstring::npos)return true;
    const auto suffix=value.substr(slash+1);if(suffix.empty()||suffix.size()>3)return false;
    int bits=0;for(const auto ch:suffix){if(ch<L'0'||ch>L'9')return false;bits=bits*10+ch-L'0';}
    return bits<=maximum;
}
bool samePrefix(const std::wstring& left,const std::wstring& right){
    if(left.empty()||right.empty())return left==right;
    const auto parse=[](const std::wstring& value,std::array<BYTE,16>& bytes,int& family,int& bits){
        if(!validPrefix(value))return false;const auto slash=value.find(L'/');const auto address=value.substr(0,slash);
        IN_ADDR v4{};IN6_ADDR v6{};
        if(InetPtonW(AF_INET,address.c_str(),&v4)==1){family=4;bits=32;std::memcpy(bytes.data(),&v4,4);}
        else if(InetPtonW(AF_INET6,address.c_str(),&v6)==1){family=6;bits=128;std::memcpy(bytes.data(),&v6,16);}else return false;
        if(slash!=std::wstring::npos)bits=std::stoi(value.substr(slash+1));
        for(int index=0;index<16;++index){const int keep=std::clamp(bits-index*8,0,8);bytes[static_cast<std::size_t>(index)]&=static_cast<BYTE>(keep?0xffU<<(8-keep):0);}
        return true;
    };
    std::array<BYTE,16> a{},b{};int af=0,bf=0,ab=0,bb=0;
    return parse(left,a,af,ab)&&parse(right,b,bf,bb)&&af==bf&&ab==bb&&a==b;
}
bool openRules(Com<INetFwPolicy2>& policy,Com<INetFwRules>& rules,HRESULT& status){
    status=CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),policy.out());
    if(SUCCEEDED(status))status=policy->get_Rules(rules.put());
    return SUCCEEDED(status)&&rules.value;
}
bool isOwnedRule(INetFwRule& rule){
    BSTR raw=nullptr;if(FAILED(rule.get_Grouping(&raw)))return false;
    const bool matches=raw&&std::wstring(raw,SysStringLen(raw))==blockGroup;SysFreeString(raw);return matches;
}
NetworkPolicyResult createFirewall(const NetworkBlockRequest& request){
    if(request.scope==PolicyScope::ProcessInstance)return result(false,ERROR_NOT_SUPPORTED,{},L"Windows Firewall application rules apply to every instance of an image, not one PID.");
    if(request.scope!=PolicyScope::ApplicationImage&&request.scope!=PolicyScope::AllApplications)return result(false,ERROR_INVALID_PARAMETER,{},L"Unknown policy scope.");
    if(request.remotePrefixes.size()>128)return result(false,ERROR_INVALID_PARAMETER,{},L"Too many remote address prefixes.");
    if(!request.inbound&&!request.outbound)return result(false,ERROR_INVALID_PARAMETER,{},L"Choose at least one direction.");
    if(request.scope==PolicyScope::AllApplications&&request.remotePrefixes.empty())return result(false,ERROR_INVALID_PARAMETER,{},L"Global host blocks require an explicit remote address.");
    for(const auto& prefix:request.remotePrefixes)if(!validPrefix(prefix))return result(false,ERROR_INVALID_PARAMETER,{},L"Remote hosts must be numeric IPv4/IPv6 addresses or CIDR prefixes.");
    Handle process;DWORD code=0;
    if(request.scope==PolicyScope::ApplicationImage&&!validateIdentity(request.target,process,code))return result(false,code,{},L"The selected process identity or image path no longer matches.");
    Apartment apartment;if(!apartment.good())return result(false,static_cast<DWORD>(apartment.status),{},L"COM initialization failed.");
    Com<INetFwPolicy2> policy;Com<INetFwRules> rules;HRESULT status=S_OK;
    if(!openRules(policy,rules,status))return result(false,static_cast<DWORD>(status),{},L"Cannot open Windows Firewall rules.");
    const auto id=newId(blockPrefix);if(id.empty())return result(false,ERROR_NOT_ENOUGH_MEMORY,{},L"Cannot allocate a policy identity.");
    std::wstring addresses;
    for(const auto& prefix:request.remotePrefixes){if(!addresses.empty())addresses+=L',';addresses+=prefix;}
    if(addresses.empty())addresses=L"*";
    std::vector<std::wstring> added;
    for(const auto direction:{NET_FW_RULE_DIR_IN,NET_FW_RULE_DIR_OUT}){
        if((direction==NET_FW_RULE_DIR_IN&&!request.inbound)||(direction==NET_FW_RULE_DIR_OUT&&!request.outbound))continue;
        const auto name=id+(direction==NET_FW_RULE_DIR_IN?L".in":L".out");
        Com<INetFwRule> rule;
        status=CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwRule),rule.out());
        if(SUCCEEDED(status))status=rule->put_Name(Bstr(name));
        if(SUCCEEDED(status))status=rule->put_Grouping(Bstr(blockGroup));
        if(SUCCEEDED(status))status=rule->put_Description(Bstr(L"KSword managed network block"));
        if(SUCCEEDED(status))status=rule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
        if(SUCCEEDED(status)&&request.scope==PolicyScope::ApplicationImage)status=rule->put_ApplicationName(Bstr(request.target.applicationPath));
        if(SUCCEEDED(status))status=rule->put_RemoteAddresses(Bstr(addresses));
        if(SUCCEEDED(status))status=rule->put_Direction(direction);
        if(SUCCEEDED(status))status=rule->put_Profiles(NET_FW_PROFILE2_ALL);
        if(SUCCEEDED(status))status=rule->put_Action(NET_FW_ACTION_BLOCK);
        if(SUCCEEDED(status))status=rule->put_Enabled(VARIANT_TRUE);
        if(SUCCEEDED(status))status=rules->Add(rule.value);
        if(FAILED(status)){
            bool restored=true;for(const auto& old:added)if(FAILED(rules->Remove(Bstr(old))))restored=false;
            return result(false,static_cast<DWORD>(status),id,restored?L"Windows Firewall rejected the policy; added directions were rolled back.":L"Windows Firewall rejected the policy and rollback failed; remove the returned policy ID.");
        }
        added.push_back(name);
    }
    return result(true,ERROR_SUCCESS,id,L"Windows Firewall application-image/address rule created.");
}
NetworkHostResolution resolveHost(const std::wstring& host){
    NetworkHostResolution output;
    if(validPrefix(host)){output.success=true;output.remotePrefixes.push_back(host);return output;}
    if(host.empty()||host.size()>253||host.find_first_of(L"/\\\r\n\t :*?\"'")!=std::wstring::npos||host.find(L'\0')!=std::wstring::npos){
        output.nativeError=ERROR_INVALID_PARAMETER;output.diagnostic=L"Enter a host name, numeric address, or CIDR prefix.";return output;
    }
    WSADATA data{};const int startup=WSAStartup(MAKEWORD(2,2),&data);
    if(startup){output.nativeError=static_cast<DWORD>(startup);output.diagnostic=L"Winsock initialization failed.";return output;}
    ADDRINFOW hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
    ADDRINFOW* addresses=nullptr;const int status=GetAddrInfoW(host.c_str(),nullptr,&hints,&addresses);
    if(status==0){
        for(auto* entry=addresses;entry&&output.remotePrefixes.size()<=64;entry=entry->ai_next){
            wchar_t text[INET6_ADDRSTRLEN]{};const void* address=nullptr;
            if(!entry->ai_addr)continue;
            if(entry->ai_family==AF_INET)address=&reinterpret_cast<const sockaddr_in*>(entry->ai_addr)->sin_addr;
            else if(entry->ai_family==AF_INET6)address=&reinterpret_cast<const sockaddr_in6*>(entry->ai_addr)->sin6_addr;
            if(address&&InetNtopW(entry->ai_family,const_cast<void*>(address),text,INET6_ADDRSTRLEN)){
                const std::wstring value(text);if(std::find(output.remotePrefixes.begin(),output.remotePrefixes.end(),value)==output.remotePrefixes.end())output.remotePrefixes.push_back(value);
            }
        }
    }
    if(addresses)FreeAddrInfoW(addresses);WSACleanup();
    if(output.remotePrefixes.size()>64){output.remotePrefixes.clear();output.nativeError=ERROR_MORE_DATA;output.diagnostic=L"The host resolved to too many addresses; choose explicit addresses or prefixes.";return output;}
    output.success=!output.remotePrefixes.empty();output.nativeError=output.success?0:static_cast<DWORD>(status?status:WSAHOST_NOT_FOUND);
    output.diagnostic=output.success?L"Resolved host addresses are a snapshot; later DNS changes require a new policy.":L"The host did not resolve to an IPv4 or IPv6 address.";
    return output;
}
NetworkPolicyResult changeFirewall(const std::wstring& id,const bool remove,const bool enabled){
    if(!ownedId(id,blockPrefix))return result(false,ERROR_INVALID_PARAMETER,id,L"This policy ID is not owned by KSword.");
    Apartment apartment;if(!apartment.good())return result(false,static_cast<DWORD>(apartment.status),id,L"COM initialization failed.");
    Com<INetFwPolicy2> policy;Com<INetFwRules> rules;HRESULT status=S_OK;
    if(!openRules(policy,rules,status))return result(false,static_cast<DWORD>(status),id,L"Cannot open Windows Firewall rules.");
    unsigned changed=0;HRESULT failure=S_OK;
    for(const auto suffix:{L".in",L".out"}){
        const auto name=id+suffix;Com<INetFwRule> rule;status=rules->Item(Bstr(name),rule.put());
        if(FAILED(status)){if(status!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))failure=status;continue;}
        if(!isOwnedRule(*rule.value)){failure=E_ACCESSDENIED;continue;}
        status=remove?rules->Remove(Bstr(name)):rule->put_Enabled(enabled?VARIANT_TRUE:VARIANT_FALSE);
        if(SUCCEEDED(status))++changed;else failure=status;
    }
    if(FAILED(failure))return result(false,static_cast<DWORD>(failure),id,L"One or more owned directions could not be changed; query the actual policy state.");
    if(!changed)return result(false,ERROR_NOT_FOUND,id,L"The owned policy was not found.");
    return result(true,ERROR_SUCCESS,id,remove?L"Owned firewall directions removed.":L"Owned firewall directions updated.");
}
std::wstring base64(const BYTE* bytes,const DWORD count){
    DWORD length=0;if(!CryptBinaryToStringW(bytes,count,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,nullptr,&length))return {};
    std::wstring encoded(length,L'\0');if(!CryptBinaryToStringW(bytes,count,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,encoded.data(),&length))return {};
    encoded.resize(length);if(!encoded.empty()&&encoded.back()==L'\0')encoded.pop_back();return encoded;
}
bool unbase64(const std::string& encoded,std::wstring& output){
    if(encoded.empty()){output.clear();return true;}
    DWORD length=0;
    if(!CryptStringToBinaryA(encoded.data(),static_cast<DWORD>(encoded.size()),CRYPT_STRING_BASE64,nullptr,&length,nullptr,nullptr)||length%sizeof(wchar_t))return false;
    output.resize(length/sizeof(wchar_t));
    return CryptStringToBinaryA(encoded.data(),static_cast<DWORD>(encoded.size()),CRYPT_STRING_BASE64,reinterpret_cast<BYTE*>(output.data()),&length,nullptr,nullptr)!=FALSE;
}
std::string jsonString(const std::wstring& text){
    constexpr char hex[]="0123456789abcdef";std::string output="\"";output.reserve(text.size()*6+2);
    for(const auto character:text){const auto value=static_cast<unsigned short>(character);output+="\\u";for(int shift=12;shift>=0;shift-=4)output+=hex[(value>>shift)&15];}
    output+='"';return output;
}
// Parameters arrive only as JSON through stdin. The command is a fixed program,
// never a path, address or policy name interpolated into PowerShell source.
constexpr wchar_t qosProgram[]=LR"PS(
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
function B64([string]$value){[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($value))}
function Number($policy,[string]$name,[long]$fallback){$value=$policy.PSBase.CimInstanceProperties[$name].Value;if($null -eq $value){$fallback}else{[long]$value}}
function BuildPolicyParameters($request,[bool]$updating){
 $parameters=@{Name=$request.id;PolicyStore='ActiveStore';NetworkProfile='All';AppPathNameMatchCondition=$request.applicationPath;ThrottleRateActionBitsPerSecond=[uint64]$request.bitsPerSecond;DSCPAction=[sbyte]$request.dscp;PriorityValue8021Action=[sbyte]$request.priority8021;IPProtocolMatchCondition=[uint32]$request.protocol;Precedence=[uint32]$request.precedence;IPSrcPrefixMatchCondition=$request.sourcePrefix;IPDstPrefixMatchCondition=$request.destinationPrefix;IPSrcPortStartMatchCondition=[uint16]$request.sourcePortStart;IPSrcPortEndMatchCondition=[uint16]$request.sourcePortEnd;IPDstPortStartMatchCondition=[uint16]$request.destinationPortStart;IPDstPortEndMatchCondition=[uint16]$request.destinationPortEnd;Confirm=$false;ErrorAction='Stop'}
 foreach($key in @('AppPathNameMatchCondition','IPSrcPrefixMatchCondition','IPDstPrefixMatchCondition')){
  if([string]::IsNullOrEmpty([string]$parameters[$key])){if($updating){$parameters[$key]=$null}else{$parameters.Remove($key)}}
 }
 if(-not $updating){
  foreach($key in @('IPSrcPortStartMatchCondition','IPSrcPortEndMatchCondition','IPDstPortStartMatchCondition','IPDstPortEndMatchCondition')){if([uint16]$parameters[$key] -eq 0){$parameters.Remove($key)}}
  if([uint64]$request.bitsPerSecond -eq 0){$parameters.Remove('ThrottleRateActionBitsPerSecond')}
  if([int]$request.dscp -lt 0){$parameters.Remove('DSCPAction')}
  if([int]$request.priority8021 -lt 0){$parameters.Remove('PriorityValue8021Action')}
 }
 return $parameters
}
function RollbackCreatedPolicy([string]$id){
 if(@(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {$_.Name -ceq $id}).Count){Remove-NetQosPolicy -Name $id -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop}
 if(@(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {$_.Name -ceq $id}).Count){throw 'The newly-created policy is still present.'}
}
function EmitPolicy($policy){
 $details=$policy|Format-List Name,Owner,NetworkProfile,Precedence,AppPathNameMatchCondition,IPProtocolMatchCondition,IPSrcPrefixMatchCondition,IPDstPrefixMatchCondition,IPSrcPortStartMatchCondition,IPSrcPortEndMatchCondition,IPDstPortStartMatchCondition,IPDstPortEndMatchCondition,DSCPAction,PriorityValue8021Action,ThrottleRateAction,MinBandwidthWeightAction,UserMatchCondition,URIMatchCondition,TemplateMatchCondition|Out-String -Width 2048
 $fields=@('KQ1','ROW',(B64 ([string]$policy.Name)),(B64 ([string]$policy.AppPathNameMatchCondition)),([uint64]$policy.ThrottleRateAction).ToString([Globalization.CultureInfo]::InvariantCulture),
  (Number $policy 'DSCPAction' -1),(Number $policy 'PriorityValue8021Action' -1),(Number $policy 'IPProtocolMatchCondition' 0),
  (B64 ([string]$policy.IPSrcPrefixMatchCondition)),(B64 ([string]$policy.IPDstPrefixMatchCondition)),
  (Number $policy 'IPSrcPortStartMatchCondition' 0),(Number $policy 'IPSrcPortEndMatchCondition' 0),(Number $policy 'IPDstPortStartMatchCondition' 0),(Number $policy 'IPDstPortEndMatchCondition' 0),
  (B64 ([string]$policy.Owner)),(Number $policy 'Precedence' 127),(B64 $details))
 [Console]::Out.WriteLine(($fields -join "`t"))
}
$createAttempted=$false
try {
 $request=[Console]::In.ReadToEnd()|ConvertFrom-Json
 Import-Module NetQos -ErrorAction Stop
 $all=@(Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop)
 if($request.operation -eq 'list'){
  foreach($policy in $all){EmitPolicy $policy}
 } else {
  if(([string]$request.id) -notmatch '^KSword\.QoS\.\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$'){throw 'Invalid policy identity.'}
  $existing=@($all|Where-Object {$_.Name -ceq $request.id})
  if($existing.Count -gt 1){throw 'Ambiguous policy identity.'}
  if($request.operation -eq 'remove'){
   if($existing.Count){Remove-NetQosPolicy -Name $request.id -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop}
   if(@(Get-NetQosPolicy -PolicyStore ActiveStore|Where-Object {$_.Name -ceq $request.id}).Count){throw 'Policy removal was not reflected by the provider.'}
  } elseif($request.operation -eq 'upsert'){
   $rate=[uint64]$request.bitsPerSecond
   $parameters=BuildPolicyParameters $request ($existing.Count -gt 0)
   if($existing.Count){
    [Console]::Out.WriteLine('KQ1'+"`tUPDATE_ATTEMPT")
    Set-NetQosPolicy @parameters|Out-Null
   } else {
    $createAttempted=$true
    [Console]::Out.WriteLine('KQ1'+"`tCREATE_ATTEMPT")
    New-NetQosPolicy @parameters|Out-Null
    [Console]::Out.WriteLine('KQ1'+"`tCREATED")
   }
   $actual=@(Get-NetQosPolicy -PolicyStore ActiveStore|Where-Object {$_.Name -ceq $request.id})
   if($actual.Count -ne 1 -or [uint64]$actual[0].ThrottleRateAction -ne $rate -or -not ([string]$actual[0].AppPathNameMatchCondition).Equals([string]$request.applicationPath,[StringComparison]::OrdinalIgnoreCase) -or (Number $actual[0] 'DSCPAction' -1) -ne [int]$request.dscp -or (Number $actual[0] 'PriorityValue8021Action' -1) -ne [int]$request.priority8021 -or (Number $actual[0] 'IPProtocolMatchCondition' 0) -ne [int]$request.protocol){throw 'The effective QoS policy does not match the request.'}
   EmitPolicy $actual[0]
  } else {throw 'Unsupported policy operation.'}
 }
 [Console]::Out.WriteLine('KQ1'+"`tOK")
 exit 0
} catch {
 $code=([int64]$_.Exception.HResult -band 4294967295L).ToString([Globalization.CultureInfo]::InvariantCulture)
 $detail=$_.Exception.Message
 if($createAttempted){
  try{RollbackCreatedPolicy ([string]$request.id);[Console]::Out.WriteLine('KQ1'+"`tROLLED_BACK")}
  catch{$detail+=' Policy ID '+[string]$request.id+' may remain active; refresh the provider state before retrying. '+$_.Exception.Message}
 }
 [Console]::Out.WriteLine('KQ1'+"`tERROR`t"+$code+"`t"+(B64 $detail))
 exit 1
}
)PS";
struct ProgramResult {DWORD error=ERROR_SUCCESS;std::string output;};
ProgramResult runQos(const std::string& input){
    ProgramResult result;
    wchar_t directory[MAX_PATH]{};if(!GetSystemDirectoryW(directory,MAX_PATH)){result.error=GetLastError();return result;}
    const std::wstring program=std::wstring(directory)+L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    const auto encoded=base64(reinterpret_cast<const BYTE*>(qosProgram),static_cast<DWORD>((std::size(qosProgram)-1)*sizeof(wchar_t)));
    std::wstring command=L"\""+program+L"\" -NoLogo -NoProfile -NonInteractive -EncodedCommand "+encoded;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),nullptr,TRUE};Handle inputRead,inputWrite,outputRead,outputWrite,errorSink;
    errorSink.value=CreateFileW(L"NUL",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&attributes,OPEN_EXISTING,0,nullptr);
    if(!CreatePipe(&inputRead.value,&inputWrite.value,&attributes,65536)||!CreatePipe(&outputRead.value,&outputWrite.value,&attributes,65536)
        ||errorSink.value==INVALID_HANDLE_VALUE||!SetHandleInformation(inputWrite.value,HANDLE_FLAG_INHERIT,0)||!SetHandleInformation(outputRead.value,HANDLE_FLAG_INHERIT,0)){
        result.error=GetLastError();return result;
    }
    SIZE_T attributeBytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&attributeBytes);std::vector<BYTE> attributeStorage(attributeBytes);
    auto* list=reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributeStorage.data());
    if(!InitializeProcThreadAttributeList(list,1,0,&attributeBytes)){result.error=GetLastError();return result;}
    const HANDLE inherited[]{inputRead.value,outputWrite.value,errorSink.value};
    if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,const_cast<HANDLE*>(inherited),sizeof(inherited),nullptr,nullptr)){
        result.error=GetLastError();DeleteProcThreadAttributeList(list);return result;
    }
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=list;
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;startup.StartupInfo.hStdInput=inputRead.value;
    // PowerShell serializes its host streams as CLIXML under EncodedCommand.
    // Structured failures are emitted by our catch to stdout; keep host streams
    // separate so progress/warning XML cannot corrupt provider records.
    startup.StartupInfo.hStdOutput=outputWrite.value;startup.StartupInfo.hStdError=errorSink.value;
    PROCESS_INFORMATION child{};Handle job;job.value=CreateJobObjectW(nullptr,nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!job.value||!SetInformationJobObject(job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits))){
        result.error=GetLastError();DeleteProcThreadAttributeList(list);return result;
    }
    const BOOL started=CreateProcessW(program.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&startup.StartupInfo,&child);
    result.error=started?0:GetLastError();DeleteProcThreadAttributeList(list);if(!started)return result;
    Handle process,thread;process.value=child.hProcess;thread.value=child.hThread;
    if(!AssignProcessToJobObject(job.value,process.value)){result.error=GetLastError();TerminateProcess(process.value,result.error);WaitForSingleObject(process.value,5000);return result;}
    CloseHandle(inputRead.value);inputRead.value=INVALID_HANDLE_VALUE;CloseHandle(outputWrite.value);outputWrite.value=INVALID_HANDLE_VALUE;
    std::atomic<DWORD> writeError{0};const HANDLE writerHandle=inputWrite.value;inputWrite.value=INVALID_HANDLE_VALUE;
    std::thread writer;
    try{writer=std::thread([&input,writerHandle,&writeError]{
        std::size_t offset=0;while(offset<input.size()){
            DWORD written=0;const DWORD count=static_cast<DWORD>(std::min<std::size_t>(16384,input.size()-offset));
            if(!WriteFile(writerHandle,input.data()+offset,count,&written,nullptr)||written==0){writeError.store(GetLastError());break;}offset+=written;
        }
        CloseHandle(writerHandle);
    });}catch(...){CloseHandle(writerHandle);TerminateJobObject(job.value,ERROR_NOT_ENOUGH_MEMORY);WaitForSingleObject(process.value,5000);result.error=ERROR_NOT_ENOUGH_MEMORY;return result;}
    ResumeThread(thread.value);const auto deadline=GetTickCount64()+30000;
    bool finished=false;
    for(;;){
        DWORD available=0;if(PeekNamedPipe(outputRead.value,nullptr,0,nullptr,&available,nullptr)&&available){
            char bytes[4096];DWORD read=0;
            if(ReadFile(outputRead.value,bytes,std::min<DWORD>(available,sizeof(bytes)),&read,nullptr))result.output.append(bytes,read);
            if(result.output.size()>1024*1024){result.error=ERROR_MORE_DATA;break;}
            continue;
        }
        if(finished)break;
        finished=WaitForSingleObject(process.value,20)==WAIT_OBJECT_0;
        if(GetTickCount64()>=deadline){result.error=ERROR_TIMEOUT;break;}
    }
    if(!finished){TerminateJobObject(job.value,result.error);WaitForSingleObject(process.value,5000);}
    if(writer.joinable())writer.join();
    if(!result.error&&writeError.load())result.error=writeError.load();
    if(!result.error){DWORD exit=0;if(!GetExitCodeProcess(process.value,&exit))result.error=GetLastError();else if(exit)result.error=exit;}
    return result;
}
bool parseUnsigned(const std::string& text,std::uint64_t& value){
    if(text.empty())return false;value=0;
    for(const auto character:text){if(character<'0'||character>'9'||value>((std::numeric_limits<std::uint64_t>::max)()-static_cast<unsigned>(character-'0'))/10)return false;value=value*10+static_cast<unsigned>(character-'0');}
    return true;
}
bool parseOption(const std::string& text,int& value,const int maximum){
    if(text=="-1"){value=-1;return true;}std::uint64_t number=0;
    if(!parseUnsigned(text,number)||number>static_cast<std::uint64_t>(maximum))return false;value=static_cast<int>(number);return true;
}
std::string asciiBase64(const std::wstring& text){
    const auto wide=base64(reinterpret_cast<const BYTE*>(text.data()),static_cast<DWORD>(text.size()*sizeof(wchar_t)));
    std::string output;output.reserve(wide.size());for(const auto ch:wide)output.push_back(static_cast<char>(ch));return output;
}
std::string qosWireRow(const QosPolicy& policy){
    return "KQ1\tROW\t"+asciiBase64(policy.policyId)+"\t"+asciiBase64(policy.applicationPath)+"\t"+std::to_string(policy.outboundBytesPerSecond*8)
        +"\t"+std::to_string(policy.dscp)+"\t"+std::to_string(policy.priority8021)+"\t"+std::to_string(static_cast<int>(policy.protocol))
        +"\t"+asciiBase64(policy.sourcePrefix)+"\t"+asciiBase64(policy.destinationPrefix)
        +"\t"+std::to_string(policy.sourcePortStart)+"\t"+std::to_string(policy.sourcePortEnd)+"\t"+std::to_string(policy.destinationPortStart)+"\t"+std::to_string(policy.destinationPortEnd)
        +"\t"+asciiBase64(policy.providerOwner)+"\t"+std::to_string(policy.precedence)+"\t"+asciiBase64(policy.providerDetails)+"\n";
}
struct QosCommandReply : QosPolicyList { bool created=false, updated=false, rolledBack=false; };
QosCommandReply parseQosResponse(const ProgramResult& invoked){
    QosCommandReply output;output.nativeError=invoked.error;
    if(invoked.error==ERROR_TIMEOUT)output.diagnostic=L"QoS provider timed out. Query this policy ID before retrying because the request may have completed.";
    bool completed=false;std::istringstream lines(invoked.output);std::string line;
    while(std::getline(lines,line)){
        if(!line.empty()&&line.back()=='\r')line.pop_back();
        std::vector<std::string> fields;std::istringstream columns(line);std::string field;while(std::getline(columns,field,'\t'))fields.push_back(field);
        if(!line.empty()&&line.back()=='\t')fields.emplace_back();
        if(fields.size()==2&&fields[0]=="KQ1"&&fields[1]=="OK"){completed=true;continue;}
        if(fields.size()==2&&fields[0]=="KQ1"&&fields[1]=="CREATED"){output.created=true;continue;}
        if(fields.size()==2&&fields[0]=="KQ1"&&fields[1]=="CREATE_ATTEMPT"){output.created=true;continue;}
        if(fields.size()==2&&fields[0]=="KQ1"&&fields[1]=="UPDATE_ATTEMPT"){output.updated=true;continue;}
        if(fields.size()==2&&fields[0]=="KQ1"&&fields[1]=="ROLLED_BACK"){output.rolledBack=true;continue;}
        if((fields.size()==5||fields.size()==17)&&fields[0]=="KQ1"&&fields[1]=="ROW"){
            QosPolicy row;std::uint64_t bits=0;
            if(!unbase64(fields[2],row.policyId)){output.nativeError=ERROR_INVALID_DATA;return output;}
            row.managed=ownedId(row.policyId,qosPrefix);
            if(!unbase64(fields[3],row.applicationPath)||!parseUnsigned(fields[4],bits)){
                output.nativeError=ERROR_INVALID_DATA;output.diagnostic=L"The QoS provider returned an invalid policy record.";return output;
            }
            if(row.managed&&std::any_of(output.entries.begin(),output.entries.end(),[&](const auto& other){return other.managed&&other.policyId==row.policyId;})){
                output.nativeError=ERROR_DUP_NAME;output.diagnostic=L"The QoS provider returned ambiguous policy identities.";return output;
            }
            if(fields.size()==17){
                int protocol=0;std::array<int,4> ports{};int precedence=0;
                if(!parseOption(fields[5],row.dscp,63)||!parseOption(fields[6],row.priority8021,7)||!parseOption(fields[7],protocol,3)||protocol<0
                    ||!unbase64(fields[8],row.sourcePrefix)||!unbase64(fields[9],row.destinationPrefix)
                    ||!parseOption(fields[10],ports[0],65535)||!parseOption(fields[11],ports[1],65535)
                    ||!parseOption(fields[12],ports[2],65535)||!parseOption(fields[13],ports[3],65535)
                    ||*std::min_element(ports.begin(),ports.end())<0||!unbase64(fields[14],row.providerOwner)
                    ||!parseOption(fields[15],precedence,255)||precedence<0||!unbase64(fields[16],row.providerDetails)){
                    output.nativeError=ERROR_INVALID_DATA;output.diagnostic=L"The QoS provider returned invalid filter or action fields.";return output;
                }
                row.protocol=static_cast<QosProtocol>(protocol);row.precedence=static_cast<std::uint32_t>(precedence);
                row.sourcePortStart=static_cast<std::uint16_t>(ports[0]);row.sourcePortEnd=static_cast<std::uint16_t>(ports[1]);
                row.destinationPortStart=static_cast<std::uint16_t>(ports[2]);row.destinationPortEnd=static_cast<std::uint16_t>(ports[3]);
                if(row.sourcePortStart==0&&row.sourcePortEnd==65535)row.sourcePortEnd=0;
                if(row.destinationPortStart==0&&row.destinationPortEnd==65535)row.destinationPortEnd=0;
            }
            row.scope=row.applicationPath.empty()?PolicyScope::AllApplications:PolicyScope::ApplicationImage;
            row.outboundBytesPerSecond=bits/8;row.enabled=true;output.entries.push_back(std::move(row));continue;
        }
        if(fields.size()==4&&fields[0]=="KQ1"&&fields[1]=="ERROR"){
            std::uint64_t code=0;if(parseUnsigned(fields[2],code)&&code<=MAXDWORD)output.nativeError=static_cast<DWORD>(code);
            if(!output.nativeError)output.nativeError=ERROR_GEN_FAILURE;
            unbase64(fields[3],output.diagnostic);return output;
        }
    }
    output.success=invoked.error==0&&completed;
    if(!output.success&&!output.nativeError)output.nativeError=ERROR_INVALID_DATA;
    if(!output.success&&output.diagnostic.empty())output.diagnostic=L"Windows Policy QoS did not return a complete provider response.";
    return output;
}
QosCommandReply qosCommand(const char* operation,const QosPolicy& policy={}){
    std::string input="{\"operation\":"+jsonString(std::wstring(operation,operation+std::char_traits<char>::length(operation)))+",\"id\":"+jsonString(policy.policyId)
        +",\"applicationPath\":"+jsonString(policy.applicationPath)+",\"bitsPerSecond\":\""+std::to_string(policy.outboundBytesPerSecond*8)+"\""
        +",\"dscp\":"+std::to_string(policy.dscp)+",\"priority8021\":"+std::to_string(policy.priority8021)+",\"protocol\":"+std::to_string(static_cast<int>(policy.protocol))
        +",\"sourcePrefix\":"+jsonString(policy.sourcePrefix)+",\"destinationPrefix\":"+jsonString(policy.destinationPrefix)
        +",\"sourcePortStart\":"+std::to_string(policy.sourcePortStart)+",\"sourcePortEnd\":"+std::to_string(policy.sourcePortEnd)
        +",\"destinationPortStart\":"+std::to_string(policy.destinationPortStart)+",\"destinationPortEnd\":"+std::to_string(policy.destinationPortEnd)
        +",\"precedence\":"+std::to_string(policy.precedence)+"}";
    return parseQosResponse(runQos(input));
}
constexpr wchar_t qosRegistry[]=L"Software\\KSword\\NetworkPolicies\\QoS";
DWORD saveQosTemplate(const QosPolicy& policy){
    HKEY key=nullptr;const auto path=std::wstring(qosRegistry)+L"\\"+policy.policyId;
    DWORD disposition=0;
    auto error=RegCreateKeyExW(HKEY_CURRENT_USER,path.c_str(),0,nullptr,0,KEY_SET_VALUE,nullptr,&key,&disposition);
    if(error)return static_cast<DWORD>(error);
    const auto record=qosWireRow(policy);
    error=RegSetValueExW(key,L"PolicyRecord",0,REG_BINARY,reinterpret_cast<const BYTE*>(record.data()),static_cast<DWORD>(record.size()));
    RegCloseKey(key);
    if(error&&disposition==REG_CREATED_NEW_KEY)RegDeleteTreeW(HKEY_CURRENT_USER,path.c_str());
    return static_cast<DWORD>(error);
}
QosPolicyList qosTemplates(){
    QosPolicyList output;HKEY root=nullptr;auto error=RegOpenKeyExW(HKEY_CURRENT_USER,qosRegistry,0,KEY_READ,&root);
    if(error==ERROR_FILE_NOT_FOUND){output.success=true;return output;}
    if(error){output.nativeError=static_cast<DWORD>(error);output.diagnostic=L"Cannot read saved QoS definitions.";return output;}
    for(DWORD index=0;index<10000;++index){
        wchar_t name[128]{};DWORD length=128;error=RegEnumKeyExW(root,index,name,&length,nullptr,nullptr,nullptr,nullptr);
        if(error==ERROR_NO_MORE_ITEMS){output.success=true;break;}
        if(error){output.nativeError=static_cast<DWORD>(error);break;}
        QosPolicy policy;policy.policyId.assign(name,length);policy.enabled=false;if(!ownedId(policy.policyId,qosPrefix))continue;
        HKEY key=nullptr;if(RegOpenKeyExW(root,name,0,KEY_QUERY_VALUE,&key)){output.nativeError=ERROR_INVALID_DATA;break;}
        DWORD size=0,type=0;error=RegQueryValueExW(key,L"PolicyRecord",nullptr,&type,nullptr,&size);
        std::string record;
        if(!error&&type==REG_BINARY&&size>0&&size<=256*1024){record.resize(size);error=RegQueryValueExW(key,L"PolicyRecord",nullptr,&type,reinterpret_cast<BYTE*>(record.data()),&size);}
        else error=ERROR_INVALID_DATA;
        RegCloseKey(key);const auto parsed=parseQosResponse({0,record+"KQ1\tOK\n"});
        if(error||!parsed.success||parsed.entries.size()!=1||parsed.entries[0].policyId!=policy.policyId){output.nativeError=ERROR_INVALID_DATA;break;}
        policy=parsed.entries[0];policy.enabled=false;output.entries.push_back(std::move(policy));
    }
    RegCloseKey(root);if(!output.success&&!output.nativeError)output.nativeError=ERROR_MORE_DATA;
    if(!output.success)output.diagnostic=L"Saved QoS definitions are incomplete or invalid.";return output;
}
DWORD deleteQosTemplate(const std::wstring& id){
    const auto path=std::wstring(qosRegistry)+L"\\"+id;const auto status=RegDeleteTreeW(HKEY_CURRENT_USER,path.c_str());
    return status==ERROR_FILE_NOT_FOUND?0:static_cast<DWORD>(status);
}
NetworkPolicyResult qosFailure(const QosCommandReply& applied,const QosPolicy& policy,const DWORD code,std::wstring detail,
    const std::function<QosPolicyList(const QosPolicy&)>& rollback){
    if(applied.rolledBack)detail+=L" The new policy was removed.";
    else if(applied.created){
        const auto reverted=rollback(policy);
        detail+=reverted.success?L" The new policy was removed.":L" The new policy may remain active; refresh the provider state before retrying.";
    }else if(applied.updated)detail+=L" Refresh the provider state before retrying; the existing policy may have changed.";
    if(code==ERROR_TIMEOUT)detail+=L" Reuse this policy ID after refreshing; a timed-out provider request may complete later.";
    detail+=L" Policy ID: "+policy.policyId;
    return result(false,code,policy.policyId,std::move(detail));
}
NetworkPolicyResult setQos(const QosPolicy& requested){
    QosPolicy policy=requested;
    const auto ports=[](std::uint16_t first,std::uint16_t last){return (first==0&&last==0)||(first>0&&last>=first);};
    const int protocol=static_cast<int>(policy.protocol);
    if((!policy.policyId.empty()&&!ownedId(policy.policyId,qosPrefix))||!policy.managed||(policy.scope!=PolicyScope::ApplicationImage&&policy.scope!=PolicyScope::AllApplications)
        ||(policy.scope==PolicyScope::ApplicationImage&&!validPath(policy.applicationPath))
        ||(policy.scope==PolicyScope::AllApplications&&!policy.applicationPath.empty())
        ||(!policy.outboundBytesPerSecond&&policy.dscp<0&&policy.priority8021<0)
        ||policy.outboundBytesPerSecond>(std::numeric_limits<std::uint64_t>::max)()/8
        ||policy.dscp < -1||policy.dscp>63||policy.priority8021 < -1||policy.priority8021>7||protocol<0||protocol>3||policy.precedence>255
        ||(!policy.sourcePrefix.empty()&&!validPrefix(policy.sourcePrefix))||(!policy.destinationPrefix.empty()&&!validPrefix(policy.destinationPrefix))
        ||!ports(policy.sourcePortStart,policy.sourcePortEnd)||!ports(policy.destinationPortStart,policy.destinationPortEnd))
        return result(false,ERROR_INVALID_PARAMETER,policy.policyId,L"Choose a valid image/global scope, action, IP prefix, protocol, precedence and port range. QoS supports outbound policy, not a PID instance.");
    if(policy.protocol==QosProtocol::Any&&(!policy.sourcePrefix.empty()||!policy.destinationPrefix.empty()||policy.sourcePortStart||policy.destinationPortStart))
        return result(false,ERROR_INVALID_PARAMETER,policy.policyId,L"Choose TCP, UDP or TCP + UDP before using IP prefixes or port conditions; the provider ignores these conditions for its default protocol.");
    if(policy.policyId.empty())policy.policyId=newId(qosPrefix);
    if(policy.policyId.empty())return result(false,ERROR_NOT_ENOUGH_MEMORY,{},L"Cannot allocate a QoS policy identity.");
    if(policy.enabled){
        const auto applied=qosCommand("upsert",policy);
        const auto failure=[&](DWORD code,std::wstring detail){return qosFailure(applied,policy,code,std::move(detail),[](const QosPolicy& value){return qosCommand("remove",value);});};
        if(!applied.success)return failure(applied.nativeError,applied.diagnostic);
        if(applied.entries.size()!=1)return failure(ERROR_INVALID_DATA,L"The QoS provider did not return the applied policy.");
        const auto& actual=applied.entries[0];
        const auto samePorts=[](std::uint16_t a,std::uint16_t b,std::uint16_t c,std::uint16_t d){
            const bool anyLeft=a==0&&(b==0||b==65535),anyRight=c==0&&(d==0||d==65535);return (anyLeft&&anyRight)||(a==c&&b==d);
        };
        if(!samePrefix(actual.sourcePrefix,policy.sourcePrefix)||!samePrefix(actual.destinationPrefix,policy.destinationPrefix)
            ||!samePorts(actual.sourcePortStart,actual.sourcePortEnd,policy.sourcePortStart,policy.sourcePortEnd)
            ||!samePorts(actual.destinationPortStart,actual.destinationPortEnd,policy.destinationPortStart,policy.destinationPortEnd)
            ||actual.precedence!=policy.precedence)return failure(ERROR_INVALID_DATA,L"The QoS provider did not retain the requested IP/port conditions or precedence.");
        const auto saved=saveQosTemplate(actual);if(saved)return failure(saved,L"The QoS restoration definition could not be saved.");
        return result(true,0,policy.policyId,L"Outbound application-image QoS is active for all instances; the ActiveStore policy expires after restart.");
    }
    const auto saved=saveQosTemplate(policy);if(saved)return result(false,saved,policy.policyId,L"Cannot save the disabled QoS definition.");
    const auto removed=qosCommand("remove",policy);return result(removed.success,removed.nativeError,policy.policyId,removed.success?L"QoS deactivated; its application and rate are retained for restoration.":removed.diagnostic);
}
}
void SetNetworkPolicyDriverOperations(std::shared_ptr<const NetworkPolicyDriverOperations> operations){const std::lock_guard<std::mutex> lock(driverOperationsLock);driverOperations=std::move(operations);}
bool ParseNetworkAddressPrefix(const std::wstring& text,NetworkAddressPrefix& output){
    output={};if(!validPrefix(text))return false;
    const auto slash=text.find(L'/');const auto address=text.substr(0,slash);IN_ADDR v4{};IN6_ADDR v6{};
    if(InetPtonW(AF_INET,address.c_str(),&v4)==1){output.family=4;output.prefixLength=32;std::memcpy(output.address.data(),&v4,4);}
    else if(InetPtonW(AF_INET6,address.c_str(),&v6)==1){output.family=6;output.prefixLength=128;std::memcpy(output.address.data(),&v6,16);}else return false;
    if(slash!=std::wstring::npos)output.prefixLength=static_cast<std::uint32_t>(std::stoi(text.substr(slash+1)));
    for(std::size_t index=0;index<output.address.size();++index){const int keep=std::clamp(static_cast<int>(output.prefixLength)-static_cast<int>(index)*8,0,8);output.address[index]&=static_cast<BYTE>(keep?0xffU<<(8-keep):0);}
    return true;
}
NetworkHostResolution ResolveNetworkHost(const std::wstring& host){return resolveHost(host);}
bool NetworkAddressMatchesPrefix(const NetworkAddressPrefix& address,const NetworkAddressPrefix& prefix){
    if(address.family!=prefix.family||(prefix.family!=4&&prefix.family!=6)||prefix.prefixLength>(prefix.family==4?32U:128U))return false;
    const auto count=prefix.family==4?4U:16U;
    for(unsigned index=0;index<count;++index){
        const int keep=std::clamp(static_cast<int>(prefix.prefixLength)-static_cast<int>(index)*8,0,8);
        const auto mask=static_cast<std::uint8_t>(keep?0xffU<<(8-keep):0);
        if((address.address[index]&mask)!=(prefix.address[index]&mask))return false;
    }
    return true;
}
NetworkPolicyResult CreateNetworkBlock(const NetworkBlockRequest& request){
    const std::lock_guard<std::mutex> lock(policyLock);
    if(request.backend==PolicyBackend::Driver){const auto driver=currentDriverOperations();return driver&&driver->create?driver->create(request):result(false,ERROR_DEVICE_NOT_CONNECTED,{},L"Driver policy transport is unavailable.");}
    if(request.backend!=PolicyBackend::Firewall)return result(false,ERROR_INVALID_PARAMETER,{},L"Unknown policy backend.");
    return createFirewall(request);
}
NetworkBlockList ListNetworkBlocks(){
    const std::lock_guard<std::mutex> lock(policyLock);NetworkBlockList output;
    const auto all=EnumerateFirewallRules();output.success=all.success&&all.complete;output.firewallAvailable=output.success;output.nativeError=all.hresult;
    output.diagnostic=all.profileSummary+L" "+all.diagnosticText;
    std::map<std::wstring,ManagedNetworkBlock> grouped;
    for(const auto& rule:all.entries){
        if(rule.grouping!=blockGroup||rule.name.size()<4)continue;
        const bool incoming=rule.name.compare(rule.name.size()-3,3,L".in")==0;
        const bool outgoing=rule.name.compare(rule.name.size()-4,4,L".out")==0;
        if(!incoming&&!outgoing)continue;
        const auto id=rule.name.substr(0,rule.name.size()-(incoming?3:4));if(!ownedId(id,blockPrefix))continue;
        auto& entry=grouped[id];const bool first=entry.policyId.empty();
        std::vector<std::wstring> prefixes;std::wistringstream stream(rule.remoteAddresses);std::wstring address;
        while(std::getline(stream,address,L','))if(address!=L"*")prefixes.push_back(address);
        constexpr std::uint32_t needed=(1U<<0)|(1U<<2)|(1U<<3)|(1U<<8)|(1U<<10)|(1U<<11)|(1U<<12)|(1U<<14);
        const bool consistent=(first||(entry.applicationPath==rule.applicationName&&entry.remotePrefixes==prefixes&&entry.enabled==rule.enabled));
        const bool directionMatches=(incoming&&rule.direction==NET_FW_RULE_DIR_IN)||(outgoing&&rule.direction==NET_FW_RULE_DIR_OUT);
        const bool complete=(rule.fieldFlags&needed)==needed&&rule.action==NET_FW_ACTION_BLOCK&&rule.protocol==NET_FW_IP_PROTOCOL_ANY&&directionMatches&&consistent;
        entry.complete=first?complete:entry.complete&&complete;
        entry.policyId=id;entry.applicationPath=rule.applicationName;
        entry.scope=rule.applicationName.empty()?PolicyScope::AllApplications:PolicyScope::ApplicationImage;
        entry.inbound|=rule.direction==NET_FW_RULE_DIR_IN;entry.outbound|=rule.direction==NET_FW_RULE_DIR_OUT;entry.enabled|=rule.enabled;
        entry.remotePrefixes=std::move(prefixes);
    }
    for(auto& value:grouped)output.entries.push_back(std::move(value.second));
    if(const auto driver=currentDriverOperations();driver&&driver->list){
        auto driverList=driver->list();output.driverAvailable=driverList.success&&driverList.driverAvailable;
        output.driverProcessInstanceAvailable=driverList.driverProcessInstanceAvailable;
        output.success|=driverList.success;output.diagnostic+=L" | "+driverList.diagnostic;
        if(driverList.success)for(auto& entry:driverList.entries)output.entries.push_back(std::move(entry));
    }else output.diagnostic+=L" | Driver policy transport is unavailable.";
    return output;
}
NetworkPolicyResult SetNetworkBlockEnabled(const std::wstring& id,const bool enabled){
    const std::lock_guard<std::mutex> lock(policyLock);
    if(ownedId(id,driverPrefix)){const auto driver=currentDriverOperations();return driver&&driver->enable?driver->enable(id,enabled):result(false,ERROR_DEVICE_NOT_CONNECTED,id,L"Driver policy transport is unavailable.");}
    return changeFirewall(id,false,enabled);
}
NetworkPolicyResult RemoveNetworkBlock(const std::wstring& id){
    const std::lock_guard<std::mutex> lock(policyLock);
    if(ownedId(id,driverPrefix)){const auto driver=currentDriverOperations();return driver&&driver->remove?driver->remove(id):result(false,ERROR_DEVICE_NOT_CONNECTED,id,L"Driver policy transport is unavailable.");}
    return changeFirewall(id,true,false);
}
QosPolicyList ListQosPolicies(){
    const std::lock_guard<std::mutex> lock(policyLock);auto live=qosCommand("list");if(!live.success)return live;
    auto saved=qosTemplates();if(!saved.success){live.success=false;live.nativeError=saved.nativeError;live.diagnostic=saved.diagnostic;return live;}
    for(auto& policy:saved.entries){const auto existing=std::find_if(live.entries.begin(),live.entries.end(),[&](const auto& active){return active.policyId==policy.policyId;});if(existing==live.entries.end())live.entries.push_back(std::move(policy));}
    live.diagnostic=L"ActiveStore policies affect outbound traffic for every instance of the application image. Disabled definitions are stored by KSword.";return live;
}
NetworkPolicyResult SaveQosPolicy(const QosPolicy& policy){const std::lock_guard<std::mutex> lock(policyLock);return setQos(policy);}
NetworkPolicyResult SetQosPolicyEnabled(const std::wstring& id,const bool enabled){
    const std::lock_guard<std::mutex> lock(policyLock);if(!ownedId(id,qosPrefix))return result(false,ERROR_INVALID_PARAMETER,id,L"Invalid owned QoS identity.");
    auto live=qosCommand("list");if(!live.success)return result(false,live.nativeError,id,live.diagnostic);
    const auto found=std::find_if(live.entries.begin(),live.entries.end(),[&](const auto& value){return value.policyId==id;});
    if(found!=live.entries.end()){auto policy=*found;policy.enabled=enabled;return setQos(policy);}
    auto templates=qosTemplates();if(!templates.success)return result(false,templates.nativeError,id,templates.diagnostic);
    const auto saved=std::find_if(templates.entries.begin(),templates.entries.end(),[&](const auto& value){return value.policyId==id;});
    if(saved==templates.entries.end())return result(false,ERROR_NOT_FOUND,id,L"The owned QoS definition was not found.");
    auto policy=*saved;policy.enabled=enabled;return setQos(policy);
}
NetworkPolicyResult RemoveQosPolicy(const std::wstring& id){
    const std::lock_guard<std::mutex> lock(policyLock);if(!ownedId(id,qosPrefix))return result(false,ERROR_INVALID_PARAMETER,id,L"Invalid owned QoS identity.");
    QosPolicy policy;policy.policyId=id;const auto removed=qosCommand("remove",policy);
    if(!removed.success)return result(false,removed.nativeError,id,removed.diagnostic);
    const auto code=deleteQosTemplate(id);return result(code==0,code,id,code?L"QoS is inactive, but its saved definition could not be removed.":L"Owned QoS policy and restoration definition removed.");
}
}
