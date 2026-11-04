#include "CommandRegistry.h"
#include "../shared/usermode/backend/monitor/EtwSessionController.h"
#include <algorithm>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <objbase.h>
#include <cwctype>
#include <tdh.h>
#include <deque>
#include <cstring>
#include <limits>
namespace ks::cli {
namespace {
namespace b=ks::r3::monitor;
std::vector<b::EtwProviderPreset> presets(){return b::EtwFilterModel{}.state().providers;}
Json preset(const b::EtwProviderPreset& p){return Json::object({{L"name",Json::string(p.name)},{L"guid",Json::string(b::GuidToString(p.providerGuid))},
    {L"defaultEnabled",Json::boolean(p.enabled)},{L"defaultLevel",Json::number(p.level)},{L"defaultMatchAnyKeyword",Json::hex(p.matchAnyKeyword)}});}
Result providers(const Args&){std::vector<Json> rows;for(const auto& p:presets())rows.push_back(preset(p));return {0,Json::object({{L"source",Json::string(L"shared backend ETW provider presets; not installed-provider enumeration")},{L"count",Json::count(rows.size())},{L"providers",Json::array(rows)}}),{}};}

struct PayloadEvidence { Json json; bool targetKnown=false; std::uint32_t target=0; bool complete=false; };
std::wstring tdhString(const std::vector<unsigned char>& data, ULONG offset) {
    if (!offset || offset % alignof(wchar_t) || offset >= data.size()) return {};
    const auto* value=reinterpret_cast<const wchar_t*>(data.data()+offset);
    const std::size_t capacity=(data.size()-offset)/sizeof(wchar_t);
    std::size_t length=0;while(length<capacity&&value[length])++length;
    return length<capacity?std::wstring(value,length):std::wstring{};
}
PayloadEvidence payload(const EVENT_RECORD& original) {
    // TDH resolves layout; no byte offset or array element is guessed.
    auto* record=const_cast<EVENT_RECORD*>(&original); ULONG size=0;
    ULONG status=TdhGetEventInformation(record,0,nullptr,nullptr,&size);
    std::vector<unsigned char> raw;
    if (record->UserData && record->UserDataLength) {
        const auto* begin=static_cast<const std::uint8_t*>(record->UserData);
        raw.assign(begin,begin+(std::min<std::size_t>)(record->UserDataLength,256));
    }
    const auto result=[&](ULONG error,const std::wstring& eventName,const std::vector<Json>& fields,bool complete,
                           bool targetKnown,std::uint32_t target,const std::wstring& targetField,std::uint32_t skipped) {
        return PayloadEvidence{Json::object({{L"eventName",eventName.empty()?Json{}:Json::string(eventName)},
            {L"tdhStatus",Json::number(error)},{L"complete",Json::boolean(complete)},
            {L"skippedPropertyCount",Json::number(skipped)},{L"properties",Json::array(fields)},
            {L"targetPid",targetKnown?Json::number(target):Json{}},{L"targetPidField",targetKnown?Json::string(targetField):Json{}},
            {L"rawSize",Json::number(record->UserDataLength)},{L"rawPrefixHex",Json::bytes(raw,raw.size())},
            {L"rawTruncated",Json::boolean(raw.size()<record->UserDataLength)}}),targetKnown,target,complete};
    };
    if(status!=ERROR_INSUFFICIENT_BUFFER||size<offsetof(TRACE_EVENT_INFO,EventPropertyInfoArray)||size>65536)
        return result(status,L"",{},false,false,0,L"",0);
    std::vector<unsigned char> buffer(size); auto* info=reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    status=TdhGetEventInformation(record,0,nullptr,info,&size);
    if(status!=ERROR_SUCCESS||size>buffer.size()||size<offsetof(TRACE_EVENT_INFO,EventPropertyInfoArray))
        return result(status,L"",{},false,false,0,L"",0);
    buffer.resize(size);
    const auto maxProperties=(buffer.size()-offsetof(TRACE_EVENT_INFO,EventPropertyInfoArray))/sizeof(EVENT_PROPERTY_INFO);
    if(info->PropertyCount>maxProperties||info->TopLevelPropertyCount>info->PropertyCount)
        return result(ERROR_INVALID_DATA,L"",{},false,false,0,L"",0);
    const auto eventName=(info->DecodingSource==DecodingSourceXMLFile||info->DecodingSource==DecodingSourceTlg)
        ?tdhString(buffer,info->EventNameOffset):std::wstring{};
    std::vector<Json> fields;std::uint32_t skipped=0,target=0;bool targetKnown=false;std::wstring targetField;
    const auto count=(std::min<ULONG>)(info->TopLevelPropertyCount,32);
    skipped=info->TopLevelPropertyCount-count;
    for(ULONG i=0;i<count;++i) {
        const auto& property=info->EventPropertyInfoArray[i];const auto name=tdhString(buffer,property.NameOffset);
        if(name.empty()||(property.Flags&(PropertyStruct|PropertyParamCount|PropertyParamFixedCount|PropertyHasCustomSchema))||property.count>1){++skipped;continue;}
        PROPERTY_DATA_DESCRIPTOR descriptor{};descriptor.PropertyName=reinterpret_cast<ULONGLONG>(name.c_str());descriptor.ArrayIndex=ULONG_MAX;
        ULONG bytes=0;auto error=TdhGetPropertySize(record,0,nullptr,1,&descriptor,&bytes);
        if(error!=ERROR_SUCCESS||bytes>2048){++skipped;continue;}
        std::vector<unsigned char> value(bytes);
        error=TdhGetProperty(record,0,nullptr,1,&descriptor,bytes,value.data());
        if(error!=ERROR_SUCCESS){++skipped;continue;}
        const USHORT type=property.nonStructType.InType;Json rendered;
        std::uint64_t integer=0;bool numeric=false;
        if((type==TDH_INTYPE_UINT32||type==TDH_INTYPE_HEXINT32)&&bytes==4){std::uint32_t n;std::memcpy(&n,value.data(),4);integer=n;numeric=true;rendered=Json::number(n);}
        else if((type==TDH_INTYPE_UINT64||type==TDH_INTYPE_HEXINT64)&&bytes==8){std::memcpy(&integer,value.data(),8);numeric=true;rendered=Json::count(integer);}
        else if(type==TDH_INTYPE_UNICODESTRING&&bytes%sizeof(wchar_t)==0){const auto* text=reinterpret_cast<const wchar_t*>(value.data());std::size_t length=bytes/sizeof(wchar_t);while(length&&text[length-1]==0)--length;rendered=Json::string(std::wstring(text,length));}
        else rendered=Json::bytes(value,value.size());
        if(numeric&&integer<=(std::numeric_limits<std::uint32_t>::max)()&&(name==L"TargetProcessId"||name==L"NewProcessId")&&(!targetKnown||name==L"TargetProcessId")){
            targetKnown=true;target=static_cast<std::uint32_t>(integer);targetField=name;
        }
        fields.push_back(Json::object({{L"name",Json::string(name)},{L"tdhInType",Json::number(type)},{L"value",rendered}}));
    }
    return result(ERROR_SUCCESS,eventName,fields,skipped==0,targetKnown,target,targetField,skipped);
}

Json eventRow(const b::EtwEvent& e, const Json& decoded=Json{}) { return Json::object({{L"timestampFileTime",Json::count(e.timestamp)},{L"localTimeDisplay",Json::string(e.timeText)},
    {L"providerGuid",Json::string(e.providerText)},{L"headerPid",Json::number(e.processId)},{L"headerTid",Json::number(e.threadId)},
    {L"eventId",Json::number(e.eventId)},{L"version",Json::number(e.version)},{L"level",Json::number(e.level)},{L"opcode",Json::number(e.opcode)},
    {L"task",Json::number(e.task)},{L"keyword",Json::hex(e.keyword)},{L"summaryDisplay",Json::string(e.summary)},{L"payload",decoded}}); }
Result capture(const Args& a){
    const auto duration=a.u32(L"--duration-ms",1000),limit=a.u32(L"--limit",5000),level=a.u32(L"--level",5);
    if(duration<100||duration>120000)throw std::invalid_argument("--duration-ms must be 100..120000");
    if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");if(level>5)throw std::invalid_argument("--level must be 0..5");
    const auto decodeValue=a.u32(L"--decode",0),targetPid=a.u32(L"--target-pid",0);
    if(decodeValue>1)throw std::invalid_argument("--decode must be 0 or 1");
    if(a.has(L"--target-pid")&&!targetPid)throw std::invalid_argument("--target-pid must be positive");
    const bool decode=decodeValue!=0||a.has(L"--target-pid");
    b::EtwFilterState filter;filter.providers=presets();filter.processId=a.u32(L"--pid",0);if(a.has(L"--pid")&&!filter.processId)throw std::invalid_argument("--pid must be positive");filter.minimumLevel=static_cast<BYTE>(level);
    const auto selected=a.get(L"--provider",L"default");if(selected.empty())throw std::invalid_argument("empty --provider");
    bool matched=selected==L"default";
    if(!matched){for(auto& p:filter.providers){p.enabled=_wcsicmp(selected.c_str(),p.name.c_str())==0||_wcsicmp(selected.c_str(),b::GuidToString(p.providerGuid).c_str())==0;matched=matched||p.enabled;}
        if(!matched){bool canonical=selected.size()==38&&selected.front()==L'{'&&selected.back()==L'}';
            for(std::size_t i=1;canonical&&i<37;++i){const bool hyphen=i==9||i==14||i==19||i==24;canonical=hyphen?selected[i]==L'-':std::iswxdigit(selected[i])!=0;}
            GUID guid{};if(!canonical||::CLSIDFromString(selected.c_str(),&guid)!=S_OK)throw std::invalid_argument("--provider must be default, a shared preset name or canonical {GUID}");
            filter.providers={b::EtwProviderPreset{selected,guid,true,static_cast<BYTE>(level),0}};
        }}
    const auto keywords=a.integer(L"--keywords",0);for(auto& p:filter.providers){p.level=static_cast<BYTE>(level);p.matchAnyKeyword=keywords;}
    b::EtwEventModel events(limit);std::deque<Json> decodedRows;std::size_t decodedBytes=0;
    std::uint64_t targetFiltered=0,targetUnknown=0,decodedMatched=0,decodePartial=0,decodeDropped=0;
    Cancellation cancel;b::EtwSessionController controller;
    if(!decode) controller.setEventCallback([&](const b::EtwEvent& event){events.append(event);});
    else controller.setRawEventCallback([&](const b::EtwEvent& event,const EVENT_RECORD& record){
        const auto p=payload(record);
        if(a.has(L"--target-pid")) {if(!p.targetKnown){++targetUnknown;return;}if(p.target!=targetPid){++targetFiltered;return;}}
        ++decodedMatched;if(!p.complete)++decodePartial;
        auto row=eventRow(event,p.json);const std::size_t rowBytes=row.text.size()*sizeof(wchar_t);
        constexpr std::size_t maxBytes=16U*1024U*1024U;
        while(!decodedRows.empty()&&(decodedRows.size()>=limit||decodedBytes+rowBytes>maxBytes)){
            decodedBytes-=decodedRows.front().text.size()*sizeof(wchar_t);decodedRows.pop_front();++decodeDropped;
        }
        if(rowBytes>maxBytes){++decodeDropped;return;}decodedBytes+=rowBytes;decodedRows.push_back(std::move(row));
    });
    const auto begin=std::chrono::steady_clock::now();const bool started=controller.start(filter);
    bool cancelled=false,completedInterval=false;
    if(started){const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(duration);
        while(controller.running()&&std::chrono::steady_clock::now()<deadline){if(cancel.token->load(std::memory_order_relaxed)){cancelled=true;break;}std::this_thread::sleep_for(std::chrono::milliseconds(10));}
        completedInterval=std::chrono::steady_clock::now()>=deadline;}
    controller.stop();const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count();
    const auto evidence=controller.evidence();std::vector<Json> providerRows,stopStatuses,rows;std::size_t enabled=0;bool partial=cancelled||(started&&!completedInterval)||evidence.callbackFailed||evidence.threadStartFailed;
    for(const auto& p:evidence.providers){if(p.status==ERROR_SUCCESS)++enabled;else partial=true;providerRows.push_back(Json::object({{L"name",Json::string(p.name)},{L"guid",Json::string(p.guid)},{L"enabled",Json::boolean(p.status==ERROR_SUCCESS)},{L"win32Error",Json::number(p.status)}}));}
    for(const auto status:evidence.stopStatuses){stopStatuses.push_back(Json::number(status));if(status!=ERROR_SUCCESS&&status!=ERROR_WMI_INSTANCE_NOT_FOUND)partial=true;}
    const auto data=events.snapshot();const auto accepted=decode?decodedMatched:evidence.receivedEvents-evidence.filteredEvents;
    const auto dropped=decode?decodeDropped:(accepted>data.size()?accepted-data.size():0);
    if(decode){for(auto& row:decodedRows)rows.push_back(std::move(row));}else for(const auto& e:data)rows.push_back(eventRow(e));
    partial=partial||dropped||!evidence.statisticsKnown||evidence.eventsLost||evidence.logBuffersLost||evidence.realTimeBuffersLost||
        !evidence.sessionStopped||!evidence.closeAttempted||(evidence.closeStatus!=ERROR_SUCCESS&&evidence.closeStatus!=ERROR_CTX_CLOSE_PENDING)||
        !evidence.processCompleted||(evidence.processStatus!=ERROR_SUCCESS&&evidence.processStatus!=ERROR_CANCELLED)||targetUnknown||decodePartial;
    const bool processFailed=evidence.processCompleted&&evidence.processStatus!=ERROR_SUCCESS&&evidence.processStatus!=ERROR_CANCELLED;
    const bool failed=!evidence.startSucceeded||!enabled||evidence.threadStartFailed||(evidence.openAttempted&&evidence.openStatus!=ERROR_SUCCESS)||(processFailed&&rows.empty());
    const ULONG failure=!evidence.startSucceeded?evidence.startStatus:!enabled&&!evidence.providers.empty()?evidence.providers.front().status:
        evidence.openAttempted&&evidence.openStatus!=ERROR_SUCCESS?evidence.openStatus:processFailed?evidence.processStatus:ERROR_SUCCESS;
    const int code=failed?(failure==ERROR_NOT_SUPPORTED||failure==ERROR_CALL_NOT_IMPLEMENTED||failure==ERROR_INVALID_FUNCTION?5:3):partial?6:0;
    return {code,Json::object({{L"source",Json::string(L"shared real-time ETW controller, retained Kernel provider presets")},
        {L"requestedDurationMs",Json::number(duration)},{L"elapsedMs",Json::count(static_cast<std::uint64_t>(elapsed))},{L"cancelled",Json::boolean(cancelled)},{L"completedRequestedInterval",Json::boolean(completedInterval)},
        {L"sessionName",Json::string(evidence.sessionName)},{L"startAttempted",Json::boolean(evidence.startAttempted)},{L"startSucceeded",Json::boolean(evidence.startSucceeded)},
        {L"startWin32Error",Json::number(evidence.startStatus)},{L"threadStartFailed",Json::boolean(evidence.threadStartFailed)},
        {L"openAttempted",Json::boolean(evidence.openAttempted)},{L"openWin32Error",evidence.openAttempted?Json::number(evidence.openStatus):Json{}},
        {L"processAttempted",Json::boolean(evidence.processAttempted)},{L"processCompleted",Json::boolean(evidence.processCompleted)},
        {L"processTraceWin32Error",evidence.processCompleted?Json::number(evidence.processStatus):Json{}},
        {L"closeAttempted",Json::boolean(evidence.closeAttempted)},{L"closeTraceWin32Error",evidence.closeAttempted?Json::number(evidence.closeStatus):Json{}},
        {L"sessionStopped",Json::boolean(evidence.sessionStopped)},{L"stopWin32Errors",Json::array(stopStatuses)},{L"consumerJoined",Json::boolean(true)},
        {L"statisticsKnown",Json::boolean(evidence.statisticsKnown)},{L"eventsLost",evidence.statisticsKnown?Json::count(evidence.eventsLost):Json{}},
        {L"logBuffersLost",evidence.statisticsKnown?Json::count(evidence.logBuffersLost):Json{}},{L"realTimeBuffersLost",evidence.statisticsKnown?Json::count(evidence.realTimeBuffersLost):Json{}},
        {L"receivedCount",Json::count(evidence.receivedEvents)},{L"filteredCount",Json::count(evidence.filteredEvents)},
        {L"matchedCount",Json::count(accepted)},{L"returnedCount",Json::count(rows.size())},{L"droppedFromBufferCount",Json::count(dropped)},
        {L"targetFilteredCount",Json::count(targetFiltered)},{L"targetUnknownCount",Json::count(targetUnknown)},{L"decodePartialCount",Json::count(decodePartial)},
        {L"callbackFailed",Json::boolean(evidence.callbackFailed)},{L"enabledProviderCount",Json::count(enabled)},{L"providers",Json::array(providerRows)},
        {L"filter",Json::object({{L"headerPid",filter.processId?Json::number(filter.processId):Json{}},{L"targetPid",targetPid?Json::number(targetPid):Json{}},{L"decode",Json::boolean(decode)},{L"maxLevel",Json::number(level)},{L"matchAnyKeyword",Json::hex(keywords)}})},
        {L"events",Json::array(rows)}}),{L"Header PID/TID are recording context. Target filtering only uses explicit TargetProcessId/NewProcessId top-level scalar payload fields; unknown targets are excluded and counted. Decoding is bounded and TDH-dependent; raw payload is a capped prefix. Loss, partial decode, unknown targets or incomplete shutdown returns partial."}};
}
}
void registerMonitorEtw(){
    addFamily(L"monitor",L"Time-bounded R3 event capture.");
    addCommand({L"monitor etw providers enum",L"KswordCLI.exe monitor etw providers enum [--backend r3] [--json]",L"List the shared ETW provider presets without starting a session.",L"Optional: --backend r3, --json.",L"Output: preset names/GUIDs, defaultEnabled/defaultLevel/defaultMatchAnyKeyword; no installed-provider query, privilege adjustment or session creation.",providers});
    addCommand({L"monitor etw capture",L"KswordCLI.exe monitor etw capture [--provider PRESET] [--duration-ms N] [--pid PID] [--target-pid PID] [--decode 0|1] [--level N] [--keywords MASK] [--limit N] [--backend r3] [--json]",L"Capture ETW records for a finite interval, then stop and join the session.",
        L"Optional: --provider default (enabled presets), one preset name or canonical {GUID}; --duration-ms 100..120000 (1000); --pid positive (header PID); --target-pid positive (explicit decoded target); --decode 0|1 (0; implied by --target-pid); --level 0..5 (5); --keywords decimal/hex u64 (0); --limit 1..100000 (5000 retained latest rows); --backend r3; --json.",
        L"Header PID/TID are recording context. Target filtering matches only top-level scalar TargetProcessId/NewProcessId; missing target is unknown, excluded and counted, never inferred from the header. Optional TDH payload evidence includes event name, bounded top-level properties and a 256-byte raw prefix; unsupported/array/struct fields are skipped. Decode/target unknown are partial. Decoded retention is also capped at 16 MiB; dropped rows and ETW loss counts remain separate. Native session/start/stop/provider evidence remains available. Requires ETW session/provider permissions; no automatic elevation or R0. Unique owned session, collision does not stop other sessions. Cancellation, loss or incomplete capture/cleanup return 6; failed start/open/no provider returns 3 (explicit unsupported 5). Help does not start a session.",capture});
}
}
