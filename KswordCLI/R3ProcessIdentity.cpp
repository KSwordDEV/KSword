#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessNavigationIdentity.h"
#include "../shared/usermode/backend/process/ProcessDetailIdentity.h"
#include "../shared/usermode/backend/process/ProcessEvidenceName.h"
#include "../shared/usermode/backend/process/EventProcessImagePath.h"
namespace ks::cli {
namespace {
namespace b=ks::r3::process;
Json image(const b::ProcessImageEvidence& e){return Json::object({{L"opened",Json::boolean(e.opened)},{L"openWin32Error",Json::number(e.openError)},
    {L"timeAttempted",Json::boolean(e.timeAttempted)},{L"timeKnown",Json::boolean(e.timeKnown)},{L"creationTime",e.timeKnown?Json::count(e.creationTime):Json{}},
    {L"timeWin32Error",e.timeAttempted?Json::number(e.timeError):Json{}},{L"identityMatched",Json::boolean(e.matched)},{L"queryAttempted",Json::boolean(e.queryAttempted)},
    {L"available",Json::boolean(e.available)},{L"path",e.available?Json::string(e.path):Json{}},{L"queryWin32Error",e.queryAttempted?Json::number(e.queryError):Json{}},
    {L"capacityUtf16Units",Json::count(e.capacity)},{L"returnedUtf16Units",e.available?Json::count(e.returnedChars):Json{}},{L"limited",Json::boolean(e.limited)},{L"malformed",Json::boolean(e.malformed)},
    {L"closeAttempted",Json::boolean(e.closeAttempted)},{L"closed",e.closeAttempted?Json::boolean(e.closed):Json{}},{L"closeWin32Error",e.closeAttempted?Json::number(e.closeError):Json{}}});}
Result query(const Args& a){(void)a.require(L"--pid");if(!a.u32(L"--pid"))throw std::invalid_argument("--pid must be positive");process::Lease lease(a);const bool aliveBefore=lease.alive();
    if(!lease.matches||!lease.creationTime||!aliveBefore)return {3,Json::object({{L"target",lease.json()},{L"aliveBefore",Json::boolean(aliveBefore)},{L"identityVerified",Json::boolean(false)}}),{L"R3 process identity could not be opened, creation time differs, or the target exited."}};
    ks::r3::common::UniqueHandle detailLease;ks::r3::process_detail::detail::DetailIdentityEvidence detail;std::wstring display;
    const bool detailMatches=ks::r3::process_detail::detail::AcquireDetailIdentityLease(lease.pid,lease.creationTime,detailLease,display,&detail);
    b::ProcessIdentityEvidence navigation;b::ProcessImageEvidence nameEvidence,pathEvidence;ULONGLONG sampled=0;std::wstring name,path;
    if(detailMatches&&lease.alive()){sampled=b::QueryProcessCreationTimeR3(lease.pid,lease.creationTime,&navigation);
        if(sampled&&lease.alive()){name=b::ProcessDisplayName(lease.pid,&nameEvidence,lease.creationTime);path=b::QueryEventProcessImagePath(lease.pid,&pathEvidence,lease.creationTime);}}
    const bool aliveAfter=lease.alive();const bool verified=detailMatches&&sampled==lease.creationTime&&navigation.matched&&nameEvidence.matched&&pathEvidence.matched&&aliveAfter;
    const bool partial=!navigation.closed||!nameEvidence.available||!pathEvidence.available||!nameEvidence.closed||!pathEvidence.closed;
    const bool consistent=!nameEvidence.available||!pathEvidence.available||_wcsicmp(nameEvidence.path.c_str(),pathEvidence.path.c_str())==0;
    const auto code=nameEvidence.malformed||pathEvidence.malformed?4:!verified?3:partial||!consistent?6:0;
    return {code,Json::object({{L"source",Json::string(L"shared ProcessNavigationIdentity/ProcessDetailIdentity/ProcessEvidenceName/EventProcessImagePath")},
        {L"target",lease.json()},{L"aliveBefore",Json::boolean(aliveBefore)},{L"aliveAfter",Json::boolean(aliveAfter)},{L"identityVerified",Json::boolean(verified)},
        {L"detailLeaseRetainedDuringQueries",Json::boolean(detailLease.valid())},
        {L"detailIdentity",Json::object({{L"opened",Json::boolean(detail.opened)},{L"openWin32Error",Json::number(detail.openError)},{L"timeKnown",Json::boolean(detail.timeKnown)},
            {L"creationTime",detail.timeKnown?Json::count(detail.creationTime):Json{}},{L"timeWin32Error",Json::number(detail.timeError)},{L"identityMatched",Json::boolean(detail.matched)}})},
        {L"navigationIdentity",Json::object({{L"opened",Json::boolean(navigation.opened)},{L"openWin32Error",Json::number(navigation.openError)},
            {L"timeKnown",Json::boolean(navigation.timeKnown)},{L"creationTime",navigation.timeKnown?Json::count(navigation.creationTime):Json{}},{L"timeWin32Error",Json::number(navigation.timeError)},
            {L"identityMatched",Json::boolean(navigation.matched)},{L"closeAttempted",Json::boolean(navigation.closeAttempted)},{L"closed",navigation.closeAttempted?Json::boolean(navigation.closed):Json{}},{L"closeWin32Error",navigation.closeAttempted?Json::number(navigation.closeError):Json{}}})},
        {L"name",nameEvidence.available?Json::string(name):Json{}},{L"nameDisplayFallback",!name.empty()&&!nameEvidence.available?Json::string(name):Json{}},
        {L"imagePath",pathEvidence.available?Json::string(path):Json{}},{L"pathSamplesConsistent",Json::boolean(consistent)},{L"nameEvidence",image(nameEvidence)},{L"eventPathEvidence",image(pathEvidence)}}),
        {L"The CLI retains a creation-time-verified process handle with SYNCHRONIZE throughout the four shared R3 samplers and rejects exited/mismatched targets. Name/path samplers verify that same expected creation time on their own borrowed query context; temporary handles close before output. Name PID/Idle fallback labels are UI hints, not a queried executable identity; name is null if not acquired. Path samples can differ due concurrent changes and produce partial evidence. No cached navigation authority, inferred kernel object address, command line/memory read, process control or R0 fallback."}};
}
}
void registerProcessIdentity(){addCommand({L"process identity query",L"KswordCLI.exe process identity query --pid PID [--creation-time FILETIME] [--backend r3] [--json]",
    L"Verify live R3 PID/creation-time identity with shared navigation/detail/name/event samplers.",
    L"Required: --pid positive uint32. Optional: --creation-time positive raw Windows FILETIME decimal/hex uint64; --backend r3; --json.",
    L"Output: source, pinned target PID/creationTime/match/error, aliveBefore/aliveAfter/identityVerified, retained detail lease flag, typed detail/navigation open/time/match/close evidence, name/null and UI-only fallback, imagePath, path consistency and two path-sampler API/capacity/length/close results. Name limit 1040 UTF16 units, event path 32768; no truncated success or PID-label identity inference. Zero creation time is unavailable. Guard mismatch/open/time failure or target exit 3, malformed image reply 4, name/path/close/capacity inconsistency 6, verified complete identity 0. All handles released before output; Windows PID/HWND values are not lifetime authority without this lease/guard. No remote PEB write, memory/command-line access, navigation UI, kernel address, driver or R0 fallback. Help does not open a process.",query});}
}
