#include "CommandRegistry.h"
#include "../shared/usermode/backend/window/Clipboard.h"
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::window_tools;
Json handle(HWND h){return h?Json::hex(reinterpret_cast<std::uintptr_t>(h)):Json{};}
Json metadata(const b::ClipboardSnapshot& s) {
    return Json::object({{L"source",Json::string(L"Win32 clipboard on caller window station")},{L"opened",Json::boolean(s.opened)},
        {L"openWin32Error",s.openError?Json::number(s.openError):Json{}},{L"closed",Json::boolean(s.closed)},
        {L"closeAttempted",Json::boolean(s.closeAttempted)},{L"closeWin32Error",s.closeError?Json::number(s.closeError):Json{}},
        {L"sequenceStart",s.opened||s.sequenceNumber?Json::number(s.sequenceNumber):Json{}},
        {L"sequenceEnd",s.opened?Json::number(s.sequenceAfter):Json{}},{L"changedDuringCapture",Json::boolean(s.changed)},
        {L"ownerWindow",handle(s.owner)},{L"ownerPid",s.ownerProcessId?Json::number(s.ownerProcessId):Json{}},
        {L"ownerTid",s.ownerThreadId?Json::number(s.ownerThreadId):Json{}},{L"ownerWin32Error",s.ownerError?Json::number(s.ownerError):Json{}},
        {L"openerWindowBeforeOpen",handle(s.openerWindow)},{L"viewerChainHead",handle(s.viewerWindow)},
        {L"advertisedFormatCount",s.countKnown?Json::number(static_cast<DWORD>(s.formatCount)):Json{}},
        {L"countWin32Error",s.countError?Json::number(s.countError):Json{}},{L"enumComplete",Json::boolean(s.enumComplete)},
        {L"enumWin32Error",s.enumError?Json::number(s.enumError):Json{}},{L"limited",Json::boolean(s.limited)}});
}
bool incomplete(const b::ClipboardSnapshot& s){return !s.enumComplete||s.limited||!s.countKnown||s.changed||!s.closed||(s.owner&&(!s.ownerProcessId||!s.ownerThreadId));}
Result formats(const Args& a) {
    const auto materialize=a.get(L"--materialize",L"off");if(materialize!=L"off"&&materialize!=L"on")throw std::invalid_argument("--materialize must be off or on");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>65536)throw std::invalid_argument("--limit must be 1..65536");
    b::ClipboardCaptureOptions options;options.materialize=materialize==L"on";options.previews=false;options.ownerDescriptions=false;
    const auto snapshot=b::CaptureClipboardSnapshot(nullptr,options);bool partial=incomplete(snapshot);std::vector<Json> rows;
    for(const auto& r:snapshot.formats) {
        const bool gdi=b::IsHandleBackedFormat(r.format);
        partial=partial||(r.nameError!=ERROR_SUCCESS)||(r.format>=0xC000&&!r.nameKnown)||(r.dataRequested&&(!r.dataAvailable||!r.sizeKnown));
        if(rows.size()>=limit)continue;
        const auto category=r.format>=CF_PRIVATEFIRST&&r.format<=CF_PRIVATELAST?L"private":r.format>=CF_GDIOBJFIRST&&r.format<=CF_GDIOBJLAST?L"gdi":r.format>=0xC000?L"registered":L"predefined-or-reserved";
        rows.push_back(Json::object({{L"id",Json::number(r.format)},{L"name",r.nameKnown?Json::string(r.name):Json{}},
            {L"nameWin32Error",r.nameError?Json::number(r.nameError):Json{}},{L"category",Json::string(category)},
            {L"handleBacked",Json::boolean(gdi)},{L"globalMemorySizeSupported",Json::boolean(!gdi)},
            {L"dataRequested",Json::boolean(r.dataRequested)},{L"dataAvailable",r.dataRequested?Json::boolean(r.dataAvailable):Json{}},
            {L"dataWin32Error",r.dataError?Json::number(r.dataError):Json{}},{L"byteSize",r.sizeKnown?Json::count(r.byteSize):Json{}},
            {L"sizeWin32Error",r.sizeError?Json::number(r.sizeError):Json{}}}));
    }
    const bool truncated=snapshot.formats.size()>rows.size();const int code=!snapshot.opened?3:snapshot.enumError==ERROR_INVALID_DATA?4:partial||truncated?6:0;
    return {code,Json::object({{L"clipboard",metadata(snapshot)},{L"materialize",Json::boolean(options.materialize)},
        {L"enumeratedCount",Json::count(snapshot.formats.size())},{L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},
        {L"truncated",Json::boolean(truncated)},{L"formats",Json::array(rows)}}),
        code?std::vector<std::wstring>{L"Clipboard acquisition, format enumeration, requested memory sizes, identity or cleanup was incomplete. GetClipboardData may synchronously invoke a delayed renderer; its calls are not forcibly interrupted."}:std::vector<std::wstring>{}};
}
Result text(const Args& a) {
    const auto format=a.get(L"--format",L"auto");if(format!=L"auto"&&format!=L"unicode"&&format!=L"ansi")throw std::invalid_argument("--format must be auto, unicode or ansi");
    const auto units=a.u32(L"--max-units",65536);if(!units||units>65536)throw std::invalid_argument("--max-units must be 1..65536");
    b::ClipboardCaptureOptions options;options.materialize=false;options.previews=true;options.ownerDescriptions=false;options.autoText=format==L"auto";
    options.textFormat=format==L"unicode"?CF_UNICODETEXT:format==L"ansi"?CF_TEXT:0;options.previewUnits=units;
    const auto s=b::CaptureClipboardSnapshot(nullptr,options);const auto& e=s.textEvidence;
    const int code=!s.opened?3:e.malformed||s.enumError==ERROR_INVALID_DATA?4:!s.textFormatAvailable?5:!e.available?3:incomplete(s)||e.truncated||!e.unlocked?6:0;
    return {code,Json::object({{L"clipboard",metadata(s)},{L"requestedFormat",Json::string(format)},
        {L"selectedFormat",s.textFormat?Json::number(s.textFormat):Json{}},{L"formatAvailable",Json::boolean(s.textFormatAvailable)},
        {L"textAvailable",Json::boolean(e.available)},{L"attempted",Json::boolean(e.attempted)},
        {L"text",e.available?Json::string(s.text):Json{}},{L"empty",Json::boolean(e.available&&s.text.empty()&&!e.truncated)},
        {L"returnedUtf16Units",e.available?Json::number(static_cast<DWORD>(s.text.size())):Json{}},
        {L"previewUnits",Json::number(units)},{L"previewUnit",Json::string(s.textFormat==CF_TEXT?L"ansi-bytes":L"utf16-code-units")},
        {L"allocatedByteSize",e.sizeKnown?Json::count(e.byteSize):Json{}},{L"malformed",Json::boolean(e.malformed)},
        {L"truncated",Json::boolean(e.truncated)},{L"terminated",e.terminationKnown?Json::boolean(e.terminated):Json{}},
        {L"ansiCodePage",e.codePage?Json::number(e.codePage):Json{}},{L"readWin32Error",e.error?Json::number(e.error):Json{}},
        {L"unlockAttempted",Json::boolean(e.unlockAttempted)},{L"unlocked",Json::boolean(e.unlocked)},
        {L"unlockWin32Error",e.unlockError?Json::number(e.unlockError):Json{}}}),
        code?std::vector<std::wstring>{L"Text was unsupported, inaccessible, malformed, truncated, changed during capture or not fully released. CF_TEXT uses the caller system ACP, not CF_LOCALE; delayed rendering may block the native call."}:std::vector<std::wstring>{}};
}
}
void registerClipboardRead() {
    addFamily(L"clipboard",L"Alias for window clipboard; inspect R3 formats and text.");
    const auto common=L"Output includes clipboard owner HWND/PID/TID, pre-open holder HWND, legacy viewer-chain head, sequence start/end, advertised count, enumeration and actual close state. NULL holder HWND does not prove the clipboard is unlocked (OpenClipboard may have used NULL). Clipboard/HGLOBAL handles are system-owned; copied values only, no GlobalFree. Open retries 4 times with 12ms waits; enumeration cap 65536 formats/8 seconds between calls. Native delayed rendering/provider calls are not forcibly interrupted. Access is scoped to the caller window station, no driver or R0 fallback. Help never opens clipboard.";
    for(const auto* base:{L"window clipboard",L"clipboard"}) {
    addCommand({std::wstring(base)+L" formats enum",std::wstring(L"KswordCLI.exe ")+base+L" formats enum [--materialize off|on] [--limit N] [--backend r3] [--json]",
        L"Enumerate R3 clipboard format metadata without reading content by default.",
        L"Optional: --materialize off|on (off), --limit (1..65536, default 1000), --backend r3, --json.",
        std::wstring(common)+L" Formats: id/name/category, eligible HGLOBAL byteSize (decimal string), actual request/size errors. off does not call GetClipboardData; on queries memory sizes and may trigger rendering/format conversion. GDI/display handles are not GlobalSize objects and remain null. Private/reserved names may be absent normally. Valid empty enumeration succeeds; incomplete/requested sizes/sequence changes/cleanup/truncation return 6, invalid format enumeration 4, open failure 3. Canonical paths use window clipboard; clipboard is an equivalent alias.",formats});
    addCommand({std::wstring(base)+L" text query",std::wstring(L"KswordCLI.exe ")+base+L" text query [--format auto|unicode|ansi] [--max-units N] [--backend r3] [--json]",
        L"Read bounded R3 clipboard Unicode or system-ACP text.",
        L"Optional: --format auto|unicode|ansi (auto prefers CF_UNICODETEXT), --max-units (1..65536, default 65536), --backend r3, --json.",
        std::wstring(common)+L" Text: selected format, availability, allocated bytes, preview units/type, text, empty/truncated/terminated, code page and read/unlock evidence. Unicode limit counts UTF16 units, ANSI limit counts input bytes before CP_ACP conversion; no CF_LOCALE inference or OEM/HTML/binary decoding. Valid empty terminated text succeeds, unsupported text format 5, read/lock failure 3, invalid UTF16/length/terminator 4, truncated/change/cleanup 6. Surrogate pairs are not split at the preview boundary. Canonical paths use window clipboard; clipboard is an equivalent alias.",text});
    }
}
}
