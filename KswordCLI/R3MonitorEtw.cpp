#include "CommandRegistry.h"
#include "../shared/usermode/backend/monitor/EtwSessionController.h"
#include <algorithm>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <objbase.h>
#include <cwctype>
namespace ks::cli {
namespace {
namespace b=ks::r3::monitor;
std::vector<b::EtwProviderPreset> presets(){return b::EtwFilterModel{}.state().providers;}
Json preset(const b::EtwProviderPreset& p){return Json::object({{L"name",Json::string(p.name)},{L"guid",Json::string(b::GuidToString(p.providerGuid))},
    {L"defaultEnabled",Json::boolean(p.enabled)},{L"defaultLevel",Json::number(p.level)},{L"defaultMatchAnyKeyword",Json::hex(p.matchAnyKeyword)}});}
Result providers(const Args&){std::vector<Json> rows;for(const auto& p:presets())rows.push_back(preset(p));return {0,Json::object({{L"source",Json::string(L"shared backend ETW provider presets; not installed-provider enumeration")},{L"count",Json::count(rows.size())},{L"providers",Json::array(rows)}}),{}};}
Result capture(const Args& a){
    const auto duration=a.u32(L"--duration-ms",1000),limit=a.u32(L"--limit",5000),level=a.u32(L"--level",5);
    if(duration<100||duration>120000)throw std::invalid_argument("--duration-ms must be 100..120000");
    if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");if(level>5)throw std::invalid_argument("--level must be 0..5");
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
    b::EtwEventModel events(limit);Cancellation cancel;b::EtwSessionController controller;
    controller.setEventCallback([&](const b::EtwEvent& event){events.append(event);});const auto begin=std::chrono::steady_clock::now();const bool started=controller.start(filter);
    bool cancelled=false,completedInterval=false;
    if(started){const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(duration);
        while(controller.running()&&std::chrono::steady_clock::now()<deadline){if(cancel.token->load(std::memory_order_relaxed)){cancelled=true;break;}std::this_thread::sleep_for(std::chrono::milliseconds(10));}
        completedInterval=std::chrono::steady_clock::now()>=deadline;}
    controller.stop();const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count();
    const auto evidence=controller.evidence();std::vector<Json> providerRows,stopStatuses,rows;std::size_t enabled=0;bool partial=cancelled||(started&&!completedInterval)||evidence.callbackFailed||evidence.threadStartFailed;
    for(const auto& p:evidence.providers){if(p.status==ERROR_SUCCESS)++enabled;else partial=true;providerRows.push_back(Json::object({{L"name",Json::string(p.name)},{L"guid",Json::string(p.guid)},{L"enabled",Json::boolean(p.status==ERROR_SUCCESS)},{L"win32Error",Json::number(p.status)}}));}
    for(const auto status:evidence.stopStatuses){stopStatuses.push_back(Json::number(status));if(status!=ERROR_SUCCESS&&status!=ERROR_WMI_INSTANCE_NOT_FOUND)partial=true;}
    const auto data=events.snapshot();const auto accepted=evidence.receivedEvents-evidence.filteredEvents;const auto dropped=accepted>data.size()?accepted-data.size():0;
    partial=partial||dropped||!evidence.statisticsKnown||evidence.eventsLost||evidence.logBuffersLost||evidence.realTimeBuffersLost||
        !evidence.sessionStopped||!evidence.closeAttempted||(evidence.closeStatus!=ERROR_SUCCESS&&evidence.closeStatus!=ERROR_CTX_CLOSE_PENDING)||
        !evidence.processCompleted||(evidence.processStatus!=ERROR_SUCCESS&&evidence.processStatus!=ERROR_CANCELLED);
    for(const auto& e:data)rows.push_back(Json::object({{L"timestampFileTime",Json::count(e.timestamp)},{L"localTimeDisplay",Json::string(e.timeText)},
        {L"providerGuid",Json::string(e.providerText)},{L"headerPid",Json::number(e.processId)},{L"headerTid",Json::number(e.threadId)},
        {L"eventId",Json::number(e.eventId)},{L"version",Json::number(e.version)},{L"level",Json::number(e.level)},{L"opcode",Json::number(e.opcode)},
        {L"task",Json::number(e.task)},{L"keyword",Json::hex(e.keyword)},{L"summaryDisplay",Json::string(e.summary)}}));
    const bool processFailed=evidence.processCompleted&&evidence.processStatus!=ERROR_SUCCESS&&evidence.processStatus!=ERROR_CANCELLED;
    const bool failed=!evidence.startSucceeded||!enabled||evidence.threadStartFailed||(evidence.openAttempted&&evidence.openStatus!=ERROR_SUCCESS)||(processFailed&&data.empty());
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
        {L"callbackFailed",Json::boolean(evidence.callbackFailed)},{L"enabledProviderCount",Json::count(enabled)},{L"providers",Json::array(providerRows)},
        {L"filter",Json::object({{L"headerPid",filter.processId?Json::number(filter.processId):Json{}},{L"maxLevel",Json::number(level)},{L"matchAnyKeyword",Json::hex(keywords)}})},
        {L"events",Json::array(rows)}}),{L"Header PID/TID identify the event recording context, not necessarily a target process/thread. Shared backend records header metadata only, no payload decoding or R0 fallback. Empty successful capture is valid; provider enable success does not prove event emission. Loss/buffer truncation or incomplete shutdown returns partial."}};
}
}
void registerMonitorEtw(){
    addFamily(L"monitor",L"Time-bounded R3 event capture.");
    addCommand({L"monitor etw providers enum",L"KswordCLI.exe monitor etw providers enum [--backend r3] [--json]",L"List the shared ETW provider presets without starting a session.",L"Optional: --backend r3, --json.",L"Output: preset names/GUIDs, defaultEnabled/defaultLevel/defaultMatchAnyKeyword; no installed-provider query, privilege adjustment or session creation.",providers});
    addCommand({L"monitor etw capture",L"KswordCLI.exe monitor etw capture [--provider PRESET] [--duration-ms N] [--pid PID] [--level N] [--keywords MASK] [--limit N] [--backend r3] [--json]",L"Capture ETW header metadata for a finite interval, then stop and join the session.",
        L"Optional: --provider default (enabled presets), one preset name or canonical {GUID}; --duration-ms 100..120000 (1000); --pid positive (header PID); --level 0..5 (5; ETW maximum verbosity, 0 provider-defined); --keywords decimal/hex u64 (0); --limit 1..100000 (5000 retained latest rows); --backend r3; --json.",
        L"Output: session name, native StartTrace/EnableTrace/OpenTrace/ProcessTrace/CloseTrace/ControlTrace evidence, consumerJoined/sessionStopped, loss counts (null if unavailable), received/filtered/matched/returned/dropped counts, configured filters and events. Event fields: providerGuid, timestampFileTime decimal string (system clock), localTimeDisplay, headerPid/headerTid, eventId/version/level/opcode/task, keyword hex, summaryDisplay. Header identity is recording context, not decoded target; no payload decode. Requires ETW provider/session permissions; no automatic elevation, privilege enabling or R0. Some enabled presets may produce no events. Default presets may partially enable: failed providers retain raw error and partial status. Unique owned session; name collision fails without stopping an existing session. Cancellation stops/joins and returns 6. Duration controls collection wait; native API/consumer shutdown can extend elapsed time. Loss, dropped rows, callback failure or incomplete cleanup 6; failed start/open/no provider 3 (explicit unsupported 5); complete empty result 0. Help does not start a session.",capture});
}
}
