#include "CommandRegistry.h"
#include "../shared/usermode/backend/driver/DriverQueries.h"
#include <algorithm>
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::driver;
std::wstring trust(const b::DriverSignatureEvidence& e) {
    if (!e.evaluated) return {};
    switch(e.trustStatus) {
    case ERROR_SUCCESS:return L"trusted";
    case TRUST_E_NOSIGNATURE:return L"no-embedded-signature";
    case TRUST_E_BAD_DIGEST:return L"bad-digest";
    case CERT_E_EXPIRED:return L"expired";
    case CERT_E_REVOKED:return L"revoked";
    case CERT_E_UNTRUSTEDROOT:case TRUST_E_SUBJECT_NOT_TRUSTED:case CERT_E_CHAINING:return L"untrusted";
    default:return {};
    }
}
Json state(const std::wstring& name,const b::DriverEnumerationEvidence& e) {
    return Json::object({{L"source",Json::string(name)},{L"complete",Json::boolean(e.complete)},
        {L"malformed",Json::boolean(e.malformed)},{L"redacted",Json::boolean(e.redacted)},{L"unsupported",Json::boolean(e.unsupported)},
        {L"ntStatus",e.ntStatusKnown?Json::hex(static_cast<DWORD>(e.ntStatus)):Json{}},
        {L"win32Error",e.win32ErrorKnown?Json::number(e.win32Error):Json{}},{L"reportedCount",Json::number(e.reportedCount)}});
}
Json module(const b::DriverOverviewRow& r,const std::wstring& source,bool signature) {
    const auto status=trust(r.signature);
    return Json::object({{L"name",r.nameKnown?Json::string(r.driverName):Json{}},{L"baseAddress",r.baseKnown?Json::hex(r.baseAddress):Json{}},
        {L"imageSize",r.sizeKnown?Json::count(r.imageSize):Json{}},
        {L"endAddressExclusive",r.baseKnown&&r.sizeKnown&&r.rangeValid?Json::hex(r.baseAddress+r.imageSize):Json{}},
        {L"path",r.pathKnown?Json::string(r.pathText):Json{}},{L"source",Json::string(source)},
        {L"flags",source==L"nt"?Json::hex(r.flags):Json{}},{L"loadOrder",source==L"nt"?Json::number(r.loadOrder):Json{}},
        {L"initOrder",source==L"nt"?Json::number(r.initOrder):Json{}},{L"loadCount",source==L"nt"?Json::number(r.loadCount):Json{}},
        {L"nameWin32Error",r.nameError?Json::number(r.nameError):Json{}},{L"pathWin32Error",r.pathError?Json::number(r.pathError):Json{}},
        {L"signature",Json::object({{L"requested",Json::boolean(signature)},{L"available",Json::boolean(!status.empty())},
            {L"status",status.empty()?Json{}:Json::string(status)},{L"trustStatus",r.signature.evaluated?Json::hex(static_cast<DWORD>(r.signature.trustStatus)):Json{}},
            {L"localPath",r.signature.pathResolved?Json::string(r.signature.localPath):Json{}},
            {L"fileWin32Error",r.signature.fileError?Json::number(r.signature.fileError):Json{}},
            {L"catalogVerification",Json::boolean(false)}})}});
}
Result query(const Args& a,bool detail) {
    const auto requested=a.get(L"--source",L"auto");
    if(requested!=L"auto"&&requested!=L"nt"&&requested!=L"psapi") throw std::invalid_argument("--source must be auto, nt or psapi");
    const auto signatureOption=a.get(L"--signature",detail?L"on":L"off");
    if(signatureOption!=L"on"&&signatureOption!=L"off") throw std::invalid_argument("--signature must be on or off");
    const bool signature=signatureOption==L"on";
    if(detail&&a.has(L"--name")==a.has(L"--base")) throw std::invalid_argument("provide exactly one of --name or --base");
    const auto name=a.get(L"--name");if(a.has(L"--name")&&name.empty()) throw std::invalid_argument("--name must not be empty");
    const auto base=a.integer(L"--base");if(a.has(L"--base")&&!base) throw std::invalid_argument("--base must be nonzero");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000) throw std::invalid_argument("--limit must be 1..100000");
    std::vector<b::DriverOverviewRow> rows;std::vector<Json> sources;std::vector<std::wstring> diagnostics;
    b::DriverEnumerationEvidence evidence;std::wstring text,selected;bool ok=false;
    if(requested!=L"psapi") {
        selected=L"nt";ok=b::QueryModuleInformation(rows,text,&evidence,false);sources.push_back(state(selected,evidence));
        if(!text.empty()) diagnostics.push_back(text);
    }
    // A malformed successful response is evidence failure, not permission to hide it behind a fallback.
    if(requested==L"psapi"||(requested==L"auto"&&!ok&&!evidence.malformed)) {
        rows.clear();selected=L"psapi";ok=b::QueryPsapiModules(rows,text,&evidence,false);sources.push_back(state(selected,evidence));
        if(!text.empty()) diagnostics.push_back(text);
    }
    bool partial=!evidence.complete,useful=rows.empty()&&ok;std::vector<Json> values;std::size_t matched=0;
    for(auto& r:rows) {
        if(detail&&((a.has(L"--name")&&(!r.nameKnown||_wcsicmp(r.driverName.c_str(),name.c_str())))||(a.has(L"--base")&&(!r.baseKnown||r.baseAddress!=base)))) continue;
        ++matched;useful=useful||r.baseKnown||r.nameKnown||r.pathKnown;
        partial=partial||!r.baseKnown||!r.sizeKnown||!r.nameKnown||!r.pathKnown;
        if(values.size()>=limit) continue;
        if(signature&&r.pathKnown) b::VerifyDriverImageSignature(r.pathText,&r.signature);
        if(signature&&trust(r.signature).empty()) partial=true;
        values.push_back(module(r,selected,signature));
    }
    const bool truncated=matched>values.size();
    int code=evidence.malformed?4:!ok?(evidence.unsupported?5:3):!useful?5:partial||truncated?6:0;
    if(detail&&!matched) {
        // Hidden names/addresses cannot establish that a requested module is absent.
        const bool identifiable=std::all_of(rows.begin(),rows.end(),[&](const auto& r){return a.has(L"--name")?r.nameKnown:r.baseKnown;});
        code=evidence.malformed?4:!ok?code:identifiable&&evidence.complete?3:5;
        diagnostics.push_back(identifiable?L"Requested loaded module was not found in this snapshot.":L"Requested module cannot be resolved from redacted or unavailable identities.");
    }
    if(code==5||code==6) diagnostics.push_back(L"Addresses may be hidden by OS privilege policy; Psapi does not supply image sizes. Signature checks concern the accessible disk file and omit catalog verification. No kernel integrity or R0 evidence is inferred.");
    return {code,Json::object({{L"requestedSource",Json::string(requested)},{L"selectedSource",Json::string(selected)},
        {L"sources",Json::array(sources)},{L"enumeratedCount",Json::count(rows.size())},{L"matchedCount",Json::count(matched)},
        {L"returnedCount",Json::number(static_cast<DWORD>(values.size()))},{L"truncated",Json::boolean(truncated)},
        {L"modules",Json::array(values)}}),diagnostics};
}
}
void registerDriverModules() {
    const auto options=L"Optional: --source auto|nt|psapi (auto), --signature on|off, --limit (1..100000, default 1000), --backend r3, --json.";
    const auto notes=L"Output: selected source, separate NT/Psapi status and completeness, counts, loaded module name/base/imageSize/exclusive end/path, NT flags/loadOrder/initOrder/loadCount, optional disk-file trust evidence. Addresses are hex strings, sizes decimal strings, unknowns null. auto falls back only between R3 sources; explicit source does not fall back. Psapi sizes are unavailable (6); all identities hidden returns 5. Windows 11 24H2 Psapi needs enabled SeDebugPrivilege for addresses; use privilege run in the same CLI process when authorized. Invalid native layout returns 4; missing query match 3 only when identities are visible. Signature is cache-only WinVerifyTrust of accessible disk image, excludes catalog verification and in-memory integrity; no-embedded-signature does not mean the driver is unsigned. No R0 fallback. Snapshot is not a retained driver lifetime lease.";
    addCommand({L"driver modules enum",L"KswordCLI.exe driver modules enum [--source auto|nt|psapi] [--signature on|off] [--limit N] [--backend r3] [--json]",
        L"Enumerate loaded kernel images through R3 NT/Psapi sources.",options, std::wstring(notes)+L" Signature defaults off.",[](const Args& a){return query(a,false);}});
    addCommand({L"driver modules query",L"KswordCLI.exe driver modules query (--name NAME | --base ADDRESS) [--source auto|nt|psapi] [--signature on|off] [--limit N] [--backend r3] [--json]",
        L"Query loaded module metadata and optional disk signature.",std::wstring(L"Required: exactly one --name (case-insensitive exact leaf name) or --base (nonzero). ")+options,
        std::wstring(notes)+L" Signature defaults on. Existing R0 driver detail queries DriverObject and remains unchanged.",[](const Args& a){return query(a,true);}});
}
}
