#include "CommandRegistry.h"
#include "../shared/usermode/backend/system/EventLogReader.h"
#include <thread>
#include <exception>
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::system_tools;
Result query(const Args& a){
    b::EventLogQueryRequest request;const auto channel=a.get(L"--channel",L"system");if(channel!=L"system"&&channel!=L"application")throw std::invalid_argument("--channel must be system or application");
    request.channel=channel==L"system"?b::EventLogChannel::System:b::EventLogChannel::Application;
    const auto level=a.get(L"--level",L"all");if(level==L"all")request.level=b::EventLogLevelFilter::All;else if(level==L"critical")request.level=b::EventLogLevelFilter::Critical;
    else if(level==L"error")request.level=b::EventLogLevelFilter::Error;else if(level==L"warning")request.level=b::EventLogLevelFilter::Warning;
    else if(level==L"information")request.level=b::EventLogLevelFilter::Information;else throw std::invalid_argument("--level must be all, critical, error, warning or information");
    const auto messages=a.get(L"--messages",L"off");if(messages!=L"off"&&messages!=L"on")throw std::invalid_argument("--messages must be off or on");request.messages=messages==L"on";
    request.maxCount=a.u32(L"--limit",100);if(!request.maxCount||request.maxCount>5000)throw std::invalid_argument("--limit must be 1..5000");
    request.maxDurationMs=a.u32(L"--duration-ms",10000);if(request.maxDurationMs<100||request.maxDurationMs>30000)throw std::invalid_argument("--duration-ms must be 100..30000");
    Cancellation cancel;request.cancelled=[token=cancel.token]{return token->load(std::memory_order_relaxed);};b::EventLogQueryResult snapshot;std::exception_ptr failure;
    std::thread worker([&]{try{snapshot=b::QueryEventLog(request);}catch(...){failure=std::current_exception();}});worker.join();if(failure)std::rethrow_exception(failure);
    std::vector<Json> rows,closeErrors;bool malformed=snapshot.malformed,partial=!snapshot.pageComplete||snapshot.closeFailed;
    for(const auto error:snapshot.closeErrors)closeErrors.push_back(Json::number(error));
    for(const auto& e:snapshot.entries){std::vector<std::pair<std::wstring,Json>> fields;
        for(const auto& [name,f]:e.fields){malformed=malformed||f.malformed;partial=partial||(!f.available&&!f.absent);
            if((name==L"providerName"||name==L"eventId"||name==L"recordId"||name==L"timestampFileTime")&&!f.available)partial=true;
            fields.push_back({name,Json::object({{L"available",Json::boolean(f.available)},{L"absent",Json::boolean(f.absent)},{L"malformed",Json::boolean(f.malformed)},{L"variantType",Json::number(f.type)}})});}
        const auto known=[&](const wchar_t* name){const auto f=e.fields.find(name);return f!=e.fields.end()&&f->second.available;};
        malformed=malformed||e.messageMalformed;partial=partial||(e.messageRequested&&(!e.messageAvailable||e.messagePartial));
        rows.push_back(Json::object({{L"providerName",known(L"providerName")?Json::string(e.providerName):Json{}},{L"eventId",known(L"eventId")?Json::number(e.eventId):Json{}},
            {L"recordId",known(L"recordId")?Json::count(e.recordId):Json{}},{L"timestampFileTime",known(L"timestampFileTime")?Json::count(e.timestampFileTime):Json{}},
            {L"localTimeDisplay",known(L"timestampFileTime")?Json::string(e.timeText):Json{}},{L"level",known(L"level")?Json::number(e.level):Json{}},
            {L"levelDisplay",known(L"level")?Json::string(e.levelText):Json{}},{L"headerPid",known(L"headerPid")?Json::number(e.processId):Json{}},
            {L"computer",known(L"computer")?Json::string(e.computer):Json{}},{L"fields",Json::object(fields)},
            {L"messageRequested",Json::boolean(e.messageRequested)},{L"messageAvailable",Json::boolean(e.messageAvailable)},{L"messagePartial",Json::boolean(e.messagePartial)},
            {L"messageMalformed",Json::boolean(e.messageMalformed)},{L"metadataWin32Error",e.messageRequested?Json::number(e.metadataError):Json{}},
            {L"messageLimited",Json::boolean(e.messageLimited)},
            {L"messageWin32Error",e.messageRequested?Json::number(e.messageError):Json{}},{L"message",e.messageAvailable?Json::string(e.messageRaw):Json{}}}));
    }
    const auto error=snapshot.queryError?snapshot.queryError:snapshot.contextError?snapshot.contextError:snapshot.nextError?snapshot.nextError:snapshot.renderError;
    const int code=malformed?4:!snapshot.success||((snapshot.nextError||snapshot.renderFailed)&&rows.empty()&&!snapshot.limited&&!snapshot.cancelled)?(error==ERROR_NOT_SUPPORTED||error==ERROR_CALL_NOT_IMPLEMENTED?5:3):partial?6:0;
    return {code,Json::object({{L"source",Json::string(L"Windows Event Log EvtQuery reverse direction + typed EvtRender system values")},
        {L"channel",Json::string(snapshot.channelPath)},{L"levelFilter",Json::string(level)},{L"messages",Json::boolean(request.messages)},
        {L"requestedCount",Json::count(request.maxCount)},{L"returnedCount",Json::count(rows.size())},{L"examinedCount",Json::count(snapshot.examined)},
        {L"pageComplete",Json::boolean(snapshot.pageComplete)},{L"channelExhausted",Json::boolean(snapshot.exhausted)},{L"limited",Json::boolean(snapshot.limited)},
        {L"cancelled",Json::boolean(snapshot.cancelled)},{L"malformed",Json::boolean(malformed)},{L"elapsedMs",Json::count(snapshot.elapsedMs)},
        {L"queryAttempted",Json::boolean(snapshot.queryAttempted)},{L"queryWin32Error",snapshot.queryAttempted?Json::number(snapshot.queryError):Json{}},
        {L"contextAttempted",Json::boolean(snapshot.contextAttempted)},{L"contextWin32Error",snapshot.contextAttempted?Json::number(snapshot.contextError):Json{}},
        {L"nextWin32Error",snapshot.nextError?Json::number(snapshot.nextError):Json{}},{L"renderFailedCount",Json::count(snapshot.renderFailed)},
        {L"lastRenderWin32Error",snapshot.renderFailed?Json::number(snapshot.renderError):Json{}},{L"unresolvedMessageCount",Json::count(snapshot.unresolvedMessages)},
        {L"closeAttemptedCount",Json::count(snapshot.closeAttempted)},{L"closeFailedCount",Json::count(snapshot.closeFailed)},{L"closeWin32ErrorsFirst32",Json::array(closeErrors)},
        {L"events",Json::array(rows)}}),{L"Newest requested page only, not a complete channel export. Header PID is event recording context, not decoded target identity. Optional message formatting depends on local publisher resources and may be partial/unavailable. Security/custom channels, XML payload parsing, clearing/deletion and R0 fallback are not provided."}};
}
}
void registerSystemEventLog(){
    addCommand({L"system event-log query",L"KswordCLI.exe system event-log query [--channel system|application] [--level LEVEL] [--messages off|on] [--limit N] [--duration-ms N] [--backend r3] [--json]",L"Read the newest R3 System/Application event-log page.",
        L"Optional: --channel system|application (system); --level all|critical|error|warning|information (all; information includes raw level 0/4); --messages off|on (off); --limit 1..5000 (100); --duration-ms 100..30000 (10000); --backend r3; --json.",
        L"Output: pageComplete/channelExhausted, returned/requested/examined counts, native query/context/next/render/close evidence, cancellation/limits, unresolved messages and events. Events have typed property availability/absence/malformed flags, provider, event/record ID, raw FILETIME/local display, level, headerPid, computer, optional uncollapsed message and metadata/format error/partial/limited state. u64 record/time/count decimal strings; unavailable null, not zero. Query newest-first; limit requests a page, not truncation of a promised full channel. No-more-items permits valid empty success. Missing local messages/partial inserts return 6; invalid reply layouts/types/pointers 4, failure without rows 3 (explicit unsupported 5), interrupted/limited/cancelled/close failure with evidence 6. Retained channels only; no arbitrary XPath, Security/custom channel, payload decode, clear/delete or R0. Query/publisher/context/event handles remain on the same dedicated worker and close before output. 16 MiB render/65536 message-character/5000 examined-record bounds. Duration checked between APIs; EvtNext waits up to 5 seconds and other native calls are not forcibly interrupted. Help performs no event-log calls.",query});
}
}
