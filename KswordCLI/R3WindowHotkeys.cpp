#include "CommandRegistry.h"
#include "../shared/usermode/backend/window/GlobalHotkeyProbe.h"
#include <thread>
#include <exception>
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::window_tools;
UINT modifiers(const std::wstring& text){
    if(text==L"none")return 0;UINT value=0;std::size_t begin=0;
    while(begin<text.size()){const auto end=text.find(L'+',begin);const auto part=text.substr(begin,end==std::wstring::npos?end:end-begin);
        const UINT bit=part==L"ctrl"?MOD_CONTROL:part==L"alt"?MOD_ALT:part==L"shift"?MOD_SHIFT:part==L"win"?MOD_WIN:0;
        if(!bit||(value&bit))throw std::invalid_argument("--modifiers must be none or unique ctrl/alt/shift/win joined with +");value|=bit;
        if(end==std::wstring::npos)break;begin=end+1;if(begin==text.size())throw std::invalid_argument("trailing + in --modifiers");
    }
    if(text.empty())throw std::invalid_argument("empty --modifiers");return value;
}
b::ProbeKey key(const Args& a){const auto requested=a.require(L"--key");for(const auto& k:b::BuildProbeKeys())if(_wcsicmp(requested.c_str(),k.name.c_str())==0)return k;
    const auto number=a.u32(L"--key");if(!number||number>254)throw std::invalid_argument("--key must be a supported name or VK code 1..254");return {number,L"VK "+requested};}
Result probe(const Args& a,bool scan){
    b::HotkeyProbeOptions options;options.skipReservedF12=true;
    if(scan){options.maxEntries=a.u32(L"--limit",1320);if(!options.maxEntries||options.maxEntries>1320)throw std::invalid_argument("--limit must be 1..1320");}
    else {options.keys={key(a)};options.modifiers={modifiers(a.require(L"--modifiers"))};}
    Cancellation cancel;options.cancelled=[token=cancel.token]{return token->load(std::memory_order_relaxed);};
    b::HotkeyProbeResult snapshot;std::exception_ptr failure;
    std::thread worker([&]{try{snapshot=b::ProbeHotkeys(options);}catch(...){failure=std::current_exception();}});worker.join();if(failure)std::rethrow_exception(failure);
    std::vector<Json> rows;std::size_t available=0,unavailable=0,reserved=0,unknown=0;
    for(const auto& e:snapshot.entries){
        const std::wstring state=e.reservedF12&&!e.attempted?L"reserved":e.registered?L"available":e.error==ERROR_HOTKEY_ALREADY_REGISTERED?L"occupied-or-reserved":L"unknown";
        if(state==L"reserved")++reserved;else if(state==L"available")++available;else if(state==L"occupied-or-reserved")++unavailable;else ++unknown;
        rows.push_back(Json::object({{L"combination",Json::string(e.modifiers?e.combination:L"None+"+e.keyText)},
            {L"modifiers",Json::hex(e.modifiers)},{L"virtualKey",Json::hex(e.virtualKey)},{L"classification",Json::string(state)},
            {L"attempted",Json::boolean(e.attempted)},{L"registered",Json::boolean(e.registered)},
            {L"registrationPossible",e.attempted&&(e.registered||e.error==ERROR_HOTKEY_ALREADY_REGISTERED)?Json::boolean(e.registered):Json{}},
            {L"registerWin32Error",e.attempted&&!e.registered?Json::number(e.error):Json{}},
            {L"unregisterAttempted",Json::boolean(e.unregisterAttempted)},{L"unregistered",Json::boolean(e.unregistered)},
            {L"unregisterWin32Error",e.unregisterAttempted&&!e.unregistered?Json::number(e.unregisterError):Json{}},
            {L"ownerPid",Json{}},{L"ownerWindow",Json{}},{L"systemReservedCandidate",Json::boolean(e.reservedF12||(e.modifiers&MOD_WIN)!=0)},
            {L"reservedReason",e.reservedF12?Json::string(L"F12 is reserved for the debugger and was not registered."):Json{}}}));
    }
    const int code=snapshot.cleanupFailed||!snapshot.complete||(unknown&&rows.size()>unknown)?6:unknown||(!scan&&reserved)?5:0;
    return {code,Json::object({{L"source",Json::string(L"same-thread transient RegisterHotKey/UnregisterHotKey, current desktop")},
        {L"transientRegistration",Json::boolean(true)},{L"workerThreadId",Json::number(snapshot.threadId)},{L"workerExited",Json::boolean(true)},
        {L"complete",Json::boolean(snapshot.complete)},{L"limited",Json::boolean(snapshot.limited)},{L"cancelled",Json::boolean(snapshot.cancelled)},
        {L"cleanupFailed",Json::boolean(snapshot.cleanupFailed)},{L"requestedCount",Json::count(snapshot.requested)},{L"returnedCount",Json::count(rows.size())},
        {L"availableCount",Json::count(available)},{L"occupiedOrReservedCount",Json::count(unavailable)},{L"reservedCount",Json::count(reserved)},{L"unknownCount",Json::count(unknown)},
        {L"entries",Json::array(rows)}}),{L"This probe temporarily registers then releases combinations; it can briefly intercept a hotkey. Failure 1409 cannot identify the owning process or distinguish registration from system reservation. Results are point-in-time; no permanent registration, key injection, owner enumeration or R0 fallback."}};
}
}
void registerWindowHotkeys(){
    const std::wstring notes=L"Output: transientRegistration, workerThreadId/workerExited, complete/limited/cancelled/cleanupFailed, requested/returned/available/occupiedOrReserved/reserved/unknown counts and entries. Each entry has combination, modifier/VK hex, classification, attempted/registered, registrationPossible (null if unknown), raw register/unregister errors, unregistered, null ownerPid/ownerWindow and systemReservedCandidate. Actual successful registration is immediately released on the same dedicated thread. 1409 means occupied-or-reserved, not an identified owner; other errors unknown. F12 debugger reservation is reported without registration. Win modifiers may be OS reserved; successful registration may override some defaults briefly. Snapshot evidence, no permanent hotkey, input injection or R0. Dedicated worker is joined before output; stop on release failure. Matrix limited to 1320 combinations/8 seconds between APIs; cancellation returns partial. Complete evidence (including unavailable combinations) 0, unknown-only/F12 single probe 5, mixed/limited/cancelled/cleanup failure 6. Help does not register a hotkey.";
    addCommand({L"window hotkeys probe",L"KswordCLI.exe window hotkeys probe --key KEY --modifiers MODIFIERS [--backend r3] [--json]",L"Temporarily probe one global hotkey combination.",
        L"Required: --key (A-Z, 0-9, F1-F24, named keys or VK 1..254), --modifiers (none or unique lower-case ctrl+alt+shift+win components). Optional: --backend r3, --json.",notes,[](const Args& a){return probe(a,false);}});
    addCommand({L"window hotkeys scan",L"KswordCLI.exe window hotkeys scan [--limit N] [--backend r3] [--json]",L"Temporarily probe the shared backend's global hotkey matrix.",
        L"Optional: --limit 1..1320 (1320), --backend r3, --json. A-Z, 0-9, F1-F24 and 28 named keys; all 15 nonempty ctrl/alt/shift/win combinations in backend order.",notes,[](const Args& a){return probe(a,true);}});
}
}
