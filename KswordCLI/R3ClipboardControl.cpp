#include "CommandRegistry.h"
#include "../shared/usermode/backend/window/ClipboardControl.h"
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::window_tools;
Result identity(bool opener){const auto e=b::QueryClipboardWindowIdentity(opener);const auto sequence=::GetClipboardSequenceNumber();
    return {e.identityKnown?0:6,Json::object({{L"source",Json::string(opener?L"GetOpenClipboardWindow/GetWindowThreadProcessId double sample":L"GetClipboardOwner/GetWindowThreadProcessId double sample")},
        {L"window",Json::hex(reinterpret_cast<std::uintptr_t>(e.window))},{L"windowAfter",Json::hex(reinterpret_cast<std::uintptr_t>(e.windowAfter))},
        {L"windowPresent",Json::boolean(e.window!=nullptr)},{L"stable",Json::boolean(e.stable)},{L"identityKnown",Json::boolean(e.identityKnown)},
        {L"pid",e.identityKnown&&e.window?Json::number(e.processId):Json{}},{L"tid",e.identityKnown&&e.window?Json::number(e.threadId):Json{}},{L"win32Error",e.error?Json::number(e.error):Json{}},
        {L"clipboardSequence",sequence?Json::number(sequence):Json{}}}),
        {L"Sampled window/PID/TID only, not a retained process lease or authorization target; window reuse can occur between samples. NULL opener HWND does not prove the clipboard is unlocked: OpenClipboard(NULL) can hold it. No clipboard open/content access, owner inference, mutation, driver or R0 fallback."}};
}
Result clear(const Args& a){if(!a.has(L"--confirm"))throw std::invalid_argument("--confirm is required to clear the caller window-station clipboard");const auto expected=a.u32(L"--expect-sequence",0);if(a.has(L"--expect-sequence")&&!expected)throw std::invalid_argument("--expect-sequence must be a positive uint32; zero sequence is unavailable");
    const auto e=b::ClearClipboard(nullptr,expected);const bool verified=e.emptied&&e.afterCountKnown&&e.countAfter==0&&e.closed;
    const auto code=e.malformed?4:!e.opened||!e.sequenceMatched?3:!e.emptied?(e.error==ERROR_NOT_SUPPORTED||e.error==ERROR_CALL_NOT_IMPLEMENTED?5:3):!verified||!e.beforeCountKnown||!e.sequenceBefore||!e.sequenceAfter?6:0;
    return {code,Json::object({{L"target",Json::string(L"current caller window-station clipboard")},{L"action",Json::string(L"empty")},{L"opened",Json::boolean(e.opened)},
        {L"attempted",Json::boolean(e.attempted)},{L"requestSucceeded",Json::boolean(e.emptied)},{L"verified",Json::boolean(verified)},{L"malformed",Json::boolean(e.malformed)},{L"win32Error",e.error?Json::number(e.error):Json{}},
        {L"expectedSequence",a.has(L"--expect-sequence")?Json::number(expected):Json{}},{L"sequenceMatched",Json::boolean(e.sequenceMatched)},
        {L"sequenceBefore",e.sequenceBefore?Json::number(e.sequenceBefore):Json{}},{L"sequenceAfter",e.sequenceAfter?Json::number(e.sequenceAfter):Json{}},
        {L"beforeCountKnown",Json::boolean(e.beforeCountKnown)},{L"beforeFormatCount",e.beforeCountKnown?Json::count(static_cast<std::uint64_t>(e.countBefore)):Json{}},{L"beforeCountWin32Error",e.countBeforeError?Json::number(e.countBeforeError):Json{}},
        {L"afterCountKnown",Json::boolean(e.afterCountKnown)},{L"afterFormatCount",e.afterCountKnown?Json::count(static_cast<std::uint64_t>(e.countAfter)):Json{}},{L"afterCountWin32Error",e.countAfterError?Json::number(e.countAfterError):Json{}},
        {L"closeAttempted",Json::boolean(e.closeAttempted)},{L"closed",e.closeAttempted?Json::boolean(e.closed):Json{}},{L"closeWin32Error",e.closeAttempted?Json::number(e.closeError):Json{}}}),
        {L"Clears every format in the caller window station; content is not read or restored. Optional expected sequence is compared while the clipboard is held, before EmptyClipboard. Sequence zero is unavailable, not a known empty clipboard. Actual empty/format-count/close evidence is required for verification; SDK calls may invoke owner notifications. Open/empty/close run on the same thread, with bounded open retries and owned close. No remote clipboard, policy changes, driver or R0 fallback."}};
}
}
void registerClipboardControl(){for(const auto* base:{L"window clipboard",L"clipboard"}){
    const auto path=std::wstring(base);const std::wstring notes=L"Output: source, raw HWND before/after (hex), windowPresent/stable/identityKnown, nullable PID/TID, native error and sequence. Zero sequence is not availability proof. PID/TID are sampled identifiers, not a retained process identity lease; no process/thread creation-time claim. NULL opener HWND does not prove unlocked. Query does not open/read/materialize clipboard data; races/identity lookup failure 6, stable valid no window 0. Caller window station only, no R0 or help-side query.";
    addCommand({path+L" owner query",L"KswordCLI.exe "+path+L" owner query [--backend r3] [--json]",L"Query current clipboard owner window/PID/TID without opening contents.",L"Optional: --backend r3; --json.",notes,[](const Args&){return identity(false);}});
    addCommand({path+L" opener query",L"KswordCLI.exe "+path+L" opener query [--backend r3] [--json]",L"Query the reported open-clipboard window/PID/TID; NULL is not unlocked proof.",L"Optional: --backend r3; --json.",notes,[](const Args&){return identity(true);}});
    addCommand({path+L" clear",L"KswordCLI.exe "+path+L" clear --confirm [--expect-sequence N] [--backend r3] [--json]",L"Empty all caller window-station clipboard formats and verify count/close.",
        L"Required: --confirm. Optional: --expect-sequence positive uint32 (guard checked while clipboard held); --backend r3; --json.",
        L"Output: target/action, open/attempt/requestSucceeded/verified/native error, expected and before/after sequence (zero unavailable=null), match, before/after format counts/errors and actual close. Clears contents without reading/restoring them; same-thread open/empty/count/close, open retry 4x12ms. No remote target or policy modification. Sequence mismatch/open/empty failure 3 (explicit unsupported 5), malformed count 4, successful empty plus zero-format/close proof 0, missing readback/sequence/before-count/close evidence 6. SDK owner notifications may block; no injection/driver/R0. Help never opens or clears clipboard.",clear});
}}
}
