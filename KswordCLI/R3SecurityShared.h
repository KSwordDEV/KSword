#pragma once
#include "CommandRegistry.h"
#include "../shared/usermode/backend/security/CodeIntegrity.h"
#include "../shared/evidence/EvidenceJson.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
namespace ks::cli::security {
namespace b=ks::r3::security;
namespace e=Ksword::Evidence;
inline std::wstring wide(const std::string& value){if(value.empty())return {};const auto size=::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);if(!size)throw std::invalid_argument("invalid UTF-8 in helper JSON");std::wstring result(size,L'\0');::MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),result.data(),size);return result;}
inline Json convert(const e::JsonValue& value){switch(value.type()){
    case e::JsonType::Null:return {};case e::JsonType::Bool:{bool v=false;value.tryGetBool(v);return Json::boolean(v);}
    case e::JsonType::UInt:{std::uint64_t v=0;value.tryGetU64(v);return v<=MAXDWORD?Json::number(static_cast<std::uint32_t>(v)):Json::count(v);}
    case e::JsonType::Int:{std::int64_t v=0;value.tryGetI64(v);return v>=INT32_MIN&&v<=INT32_MAX?Json::signedNumber(static_cast<std::int32_t>(v)):Json::string(std::to_wstring(v));}
    case e::JsonType::String:{std::string v;value.tryGetString(v);return Json::string(wide(v));}
    case e::JsonType::Array:{std::vector<Json> values;for(const auto& child:*value.asArray())values.push_back(convert(child));return Json::array(values);}
    case e::JsonType::Object:{std::vector<std::pair<std::wstring,Json>> values;for(const auto& [key,child]:*value.asObject())values.push_back({wide(key),convert(child)});return Json::object(values);}
    }return {};
}
inline Json payload(const b::CommandResult& command,int& code){if(command.output.empty()){if(code==0)code=4;return {};}
    const auto size=::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,command.output.data(),static_cast<int>(command.output.size()),nullptr,0,nullptr,nullptr);if(!size){code=4;return {};}
    std::string text(size,'\0');::WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,command.output.data(),static_cast<int>(command.output.size()),text.data(),size,nullptr,nullptr);
    e::JsonLimits limits;limits.maxDepth=16;limits.maxTotalBytes=128*1024;limits.maxStringBytes=65536;limits.maxContainerItems=4096;limits.maxTotalNodes=8192;limits.maxEstimatedNodeBytes=8*1024*1024;
    const auto parsed=e::ParseJson(text,limits);bool available=false;const auto flag=parsed.value.find("available");if(!parsed.ok()||!parsed.value.asObject()||!flag||!flag->tryGetBool(available)){if(!command.outputTruncated&&code!=3&&code!=5&&code!=6)code=4;return {};}
    if(code==0&&!available)code=5;try{return convert(parsed.value);}catch(const std::invalid_argument&){code=4;return {};}
}
inline Json result(const b::SecurityProbeResult& r,DWORD maxBytes,int& code){const auto kind=r.probe.kind;code=r.code;Json data,capture;
    if(kind==b::SecurityProbeKind::Command){const auto& c=r.command;data=payload(c,code);capture=Json::object({{L"started",Json::boolean(c.started)},{L"exitCodeKnown",Json::boolean(c.exitCodeKnown)},{L"exitCode",c.exitCodeKnown?Json::number(c.exitCode):Json{}},
        {L"win32Error",Json::number(c.win32Error)},{L"waitCompleted",Json::boolean(c.waitCompleted)},{L"timedOut",Json::boolean(c.timedOut)},{L"cancelled",Json::boolean(c.cancelled)},
        {L"terminated",Json::boolean(c.terminated)},{L"terminationWin32Error",Json::number(c.terminationError)},{L"terminationWait",c.terminated?Json::hex(c.terminationWait):Json{}},
        {L"outputTruncated",Json::boolean(c.outputTruncated)},{L"outputWin32Error",Json::number(c.outputError)},{L"decodeMalformed",Json::boolean(c.decodeMalformed)},{L"closeWin32Error",Json::number(c.closeError)},{L"diagnostic",Json::string(c.errorText)}});
    }else if(kind==b::SecurityProbeKind::Registry){const auto& v=r.registry;Json scalar;if(v.available&&v.type==REG_DWORD){DWORD x=0;memcpy(&x,v.bytes.data(),4);scalar=Json::number(x);}else if(v.available&&v.type==REG_QWORD){std::uint64_t x=0;memcpy(&x,v.bytes.data(),8);scalar=Json::count(x);}
        const bool truncated=v.available&&v.bytes.size()>maxBytes;if(code==0&&truncated)code=6;
        data=Json::object({{L"path",Json::string(L"HKLM\\"+r.probe.path)},{L"view",Json::string(L"64-bit")},{L"name",Json::string(r.probe.name)},
            {L"openAttempted",Json::boolean(v.openAttempted)},{L"opened",Json::boolean(v.opened)},{L"openWin32Error",Json::number(v.openError)},
            {L"queryAttempted",Json::boolean(v.queryAttempted)},{L"queryWin32Error",v.queryAttempted?Json::number(v.queryError):Json{}},{L"available",Json::boolean(v.available)},{L"absent",Json::boolean(v.absent)},
            {L"type",v.available?Json::number(v.type):Json{}},{L"reportedBytes",v.queryAttempted?Json::count(v.reportedBytes):Json{}},{L"value",scalar},{L"dataHex",v.available?Json::bytes(v.bytes,maxBytes):Json{}},
            {L"dataTruncated",Json::boolean(truncated)},{L"limited",Json::boolean(v.limited)},{L"malformed",Json::boolean(v.malformed)},
            {L"closeAttempted",Json::boolean(v.closeAttempted)},{L"closed",v.closeAttempted?Json::boolean(v.closed):Json{}},{L"closeWin32Error",v.closeAttempted?Json::number(v.closeError):Json{}}});
    }else{const auto& v=r.service;data=Json::object({{L"name",Json::string(r.probe.name)},{L"scmOpened",Json::boolean(v.scmOpened)},{L"opened",Json::boolean(v.opened)},
        {L"available",Json::boolean(v.available)},{L"absent",Json::boolean(v.absent)},{L"win32Error",Json::number(v.error)},
        {L"state",v.available?Json::number(v.status.dwCurrentState):Json{}},{L"serviceType",v.available?Json::hex(v.status.dwServiceType):Json{}},{L"pid",v.available?Json::number(v.status.dwProcessId):Json{}},
        {L"serviceCloseAttempted",Json::boolean(v.serviceCloseAttempted)},{L"serviceClosed",v.serviceCloseAttempted?Json::boolean(v.serviceClosed):Json{}},
        {L"scmCloseAttempted",Json::boolean(v.scmCloseAttempted)},{L"scmClosed",v.scmCloseAttempted?Json::boolean(v.scmClosed):Json{}},{L"closeWin32Error",Json::number(v.closeError)}});}
    return Json::object({{L"id",Json::string(r.probe.id)},{L"source",Json::string(r.probe.source)},{L"kind",Json::string(kind==b::SecurityProbeKind::Command?L"helper-json":kind==b::SecurityProbeKind::Registry?L"registry":L"service")},
        {L"status",Json::string(code==0?L"success":code==6?L"partial":code==5?L"unsupported":L"failed")},{L"exitCode",Json::number(static_cast<std::uint32_t>(code))},{L"data",data},{L"capture",capture}});
}
inline Result query(const Args& a,const std::vector<b::SecurityProbe>& definitions,const std::vector<std::wstring>& ids={}){
    b::SecurityProbeOptions options;options.durationMs=a.u32(L"--duration-ms",30000);options.timeoutMs=a.u32(L"--timeout-ms",12000);const auto maxBytes=a.u32(L"--max-data-bytes",256);
    if(options.durationMs<500||options.durationMs>60000)throw std::invalid_argument("--duration-ms must be 500..60000");if(options.timeoutMs<500||options.timeoutMs>30000)throw std::invalid_argument("--timeout-ms must be 500..30000");if(!maxBytes||maxBytes>65536)throw std::invalid_argument("--max-data-bytes must be 1..65536");
    Cancellation cancel;options.cancelled=[token=cancel.token]{return token->load(std::memory_order_relaxed);};std::vector<b::SecurityProbe> selected;for(const auto& d:definitions)if(ids.empty()||std::find(ids.begin(),ids.end(),d.id)!=ids.end())selected.push_back(d);
    const auto snapshot=b::CollectSecurityProbes(selected,options);std::vector<Json> rows;std::size_t success=0,partial=0,missing=0,failed=0;bool malformed=false;
    for(const auto& r:snapshot.results){int code=0;rows.push_back(result(r,maxBytes,code));success+=code==0;partial+=code==6;missing+=code==5;failed+=code!=0&&code!=6&&code!=5;malformed=malformed||code==4;}
    const int code=malformed?4:snapshot.limited||snapshot.cancelled||partial?6:success==rows.size()&&!rows.empty()?0:success?6:failed?3:5;
    return {code,Json::object({{L"source",Json::string(L"shared security read-only probes; structured helper JSON/native registry/SCM evidence")},
        {L"requestedCount",Json::count(snapshot.requestedCount)},{L"returnedCount",Json::count(rows.size())},{L"successCount",Json::count(success)},{L"partialCount",Json::count(partial)},
        {L"unavailableCount",Json::count(missing)},{L"failedCount",Json::count(failed)},{L"limited",Json::boolean(snapshot.limited)},{L"cancelled",Json::boolean(snapshot.cancelled)},{L"evidence",Json::array(rows)}}),
        {L"Availability/configuration/cached state observations from their stated source; no policy enforcement, active module or security guarantee inferred. Missing registry values/services are known absence with null values, not a disabled-policy conclusion. Helper native exit/wait/timeout/decoding/cleanup and validated JSON payload are separate evidence; no UI success/failure text parsing. Query helpers run hidden, own handles close before output; no driver or R0 fallback."}};
}
inline void add(const std::wstring& path,const std::wstring& summary,const std::function<Result(const Args&)>& run){addCommand({path,L"KswordCLI.exe "+path+L" [--duration-ms N] [--timeout-ms N] [--max-data-bytes N] [--backend r3] [--json]",summary,
    L"Optional: --duration-ms 500..60000 entire collection (30000); --timeout-ms 500..30000 per helper (12000, capped by remaining duration); --max-data-bytes 1..65536 registry byte preview (256); --backend r3; --json.",
    L"Output: requested/returned/success/partial/unavailable/failed counts, limits/cancel and evidence with source/kind/status/exit code, structured helper payload plus actual start/exit/wait/timeout/termination/read/decode/close diagnostics, or native registry/SCM identity/data/query/close evidence. Registry numbers/counts preserve widths; absent/unknown fields are null. No UI text status parsing, registry/service/policy mutation, driver or R0 fallback. Complete sources/known absence 0; partial/cleanup/time/output limits 6; all failed 3; unavailable sources 5; malformed payload/registry 4. Metadata/disk presence is not active policy/enforcement proof. Help performs no queries or helper launch.",run});}
}
