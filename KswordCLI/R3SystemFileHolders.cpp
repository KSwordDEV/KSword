#include "R3ProcessShared.h"
#include "../shared/usermode/backend/system/FileHolderScanner.h"
#include <thread>
#include <exception>
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::system_tools;
Result query(const Args& a){
    const auto input=a.require(L"--path");if(input.empty()||input.front()==L'"'||input.back()==L'"'||input.back()==L' ')throw std::invalid_argument("--path must be nonempty without literal wrapping quotes/trailing spaces");
    auto path=input;if(input.rfind(L"\\Device\\",0)!=0&&input.rfind(L"\\??\\",0)!=0){std::vector<wchar_t> buffer(32768);const auto n=::GetFullPathNameW(input.c_str(),static_cast<DWORD>(buffer.size()),buffer.data(),nullptr);
        if(!n||n>=buffer.size())throw std::invalid_argument("--path cannot be resolved to a bounded absolute path");path.assign(buffer.data(),n);
        const auto expanded=::GetLongPathNameW(path.c_str(),buffer.data(),static_cast<DWORD>(buffer.size()));if(expanded&&expanded<buffer.size())path.assign(buffer.data(),expanded);}
    const auto recursive=a.get(L"--recursive",L"off");if(recursive!=L"off"&&recursive!=L"on")throw std::invalid_argument("--recursive must be off or on");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");
    b::FileHolderScanOptions options;options.maxDurationMs=a.u32(L"--duration-ms",10000);options.maxHandles=a.u32(L"--max-handles",1000000);
    if(options.maxDurationMs<250||options.maxDurationMs>30000)throw std::invalid_argument("--duration-ms must be 250..30000");
    if(!options.maxHandles||options.maxHandles>1000000)throw std::invalid_argument("--max-handles must be 1..1000000");
    options.processId=a.u32(L"--pid",0);if(a.has(L"--pid")&&!options.processId)throw std::invalid_argument("--pid must be positive");
    if(a.has(L"--creation-time")&&(!options.processId||!a.integer(L"--creation-time")))throw std::invalid_argument("positive --creation-time requires --pid");
    options.processCreationTime=a.integer(L"--creation-time",0);
    std::unique_ptr<process::Lease> target;
    if(options.processId){target=std::make_unique<process::Lease>(a);if(!target->matches||!target->alive())return {3,Json::object({{L"targetIdentity",target->json()}}),{L"Requested process identity is unavailable, mismatched or exited."}};options.processCreationTime=target->creationTime;}
    Cancellation cancel;options.cancelled=[token=cancel.token]{return token->load(std::memory_order_relaxed);};b::FileHolderScanResult snapshot;std::exception_ptr failure;
    std::thread worker([&]{try{snapshot=b::ScanFileHolders(path,recursive==L"on",options);}catch(...){failure=std::current_exception();}});worker.join();if(failure)std::rethrow_exception(failure);
    std::vector<Json> rows;bool partial=!snapshot.complete;
    for(const auto& e:snapshot.entries){partial=partial||!e.creationTimeKnown||!e.processAliveKnown||!e.processAlive||!e.pathKnown;
        if(rows.size()>=limit)continue;rows.push_back(Json::object({{L"pid",Json::number(e.processId)},{L"processCreationTime",e.creationTimeKnown?Json::count(e.processCreationTime):Json{}},
            {L"processAlive",e.processAliveKnown?Json::boolean(e.processAlive):Json{}},{L"identityWin32Error",!e.creationTimeKnown?Json::number(e.identityError):Json{}},
            {L"processName",e.nameKnown?Json::string(e.processName):Json{}},{L"processPath",e.pathKnown?Json::string(e.processPath):Json{}},
            {L"pathWin32Error",!e.pathKnown?Json::number(e.pathError):Json{}},{L"handle",Json::hex(e.handleValue)},{L"grantedAccess",Json::hex(e.grantedAccess)},
            {L"accessDisplay",Json::string(e.accessText)},{L"objectName",Json::string(e.objectName)},{L"win32Name",Json::string(e.win32Name)}}));}
    const bool identityStable=!target||target->alive();const bool truncated=rows.size()<snapshot.entries.size();const int code=snapshot.malformed?4:snapshot.apiUnavailable?5:!snapshot.success||!identityStable?3:partial||truncated?6:0;
    return {code,Json::object({{L"source",Json::string(L"SystemExtendedHandleInformation + same-process DuplicateHandle and bounded NtQueryObject disk-name probes")},
        {L"requestedPath",Json::string(input)},{L"absolutePath",Json::string(path)},{L"targetNtPath",Json::string(snapshot.targetNtPath)},
        {L"recursive",Json::boolean(recursive==L"on")},{L"pidFilter",options.processId?Json::number(options.processId):Json{}},
        {L"targetIdentity",target?target->json():Json{}},{L"targetIdentityStable",target?Json::boolean(identityStable):Json{}},
        {L"creationTimeFilter",options.processCreationTime?Json::count(options.processCreationTime):Json{}},{L"complete",Json::boolean(snapshot.complete)},
        {L"limited",Json::boolean(snapshot.limited)},{L"cancelled",Json::boolean(snapshot.cancelled)},{L"malformed",Json::boolean(snapshot.malformed)},
        {L"snapshotAttempted",Json::boolean(snapshot.snapshotAttempted)},{L"snapshotNtStatus",snapshot.ntStatusKnown?Json::hex(static_cast<ULONG>(snapshot.snapshotNtStatus)):Json{}},
        {L"snapshotBytes",Json::count(snapshot.snapshotBytes)},{L"totalHandleCount",Json::count(snapshot.totalHandles)},{L"examinedHandleCount",Json::count(snapshot.examinedHandles)},
        {L"fileHandleCount",Json::count(snapshot.fileHandles)},{L"inspectedCount",Json::count(snapshot.inspectedHandles)},{L"skippedCount",Json::count(snapshot.skippedHandles)},
        {L"protectedSkippedCount",Json::count(snapshot.protectedSkipped)},{L"openFailedCount",Json::count(snapshot.openFailed)},{L"duplicateFailedCount",Json::count(snapshot.duplicateFailed)},
        {L"nonDiskCount",Json::count(snapshot.notDisk)},{L"nameFailedCount",Json::count(snapshot.nameFailed)},{L"timeoutCount",Json::count(snapshot.timedOutHandles)},
        {L"waitFailedCount",Json::count(snapshot.waitFailed)},{L"waitWin32Error",snapshot.waitFailed?Json::number(snapshot.waitWin32Error):Json{}},
        {L"identityMismatchCount",Json::count(snapshot.identityMismatch)},{L"elapsedMs",Json::count(snapshot.elapsedMs)},
        {L"matchedCount",Json::count(snapshot.entries.size())},{L"returnedCount",Json::count(rows.size())},{L"truncated",Json::boolean(truncated)},{L"holders",Json::array(rows)}}),
        {L"Names are compared as paths, not file IDs: hardlink/reparse/redirector aliases and module-only mappings may be missed. Remote handle/PID can change after the system snapshot; creation times describe the opened process, not an original snapshot generation. Returned handles are numbers in the remote process and are not live CLI handles. No close, unlock, termination or R0 fallback. Name query timeout leaves at most four helpers owning duplicated handles until the kernel returns or CLI exits; they are never killed. Partial/limited/denied results cannot prove no holders."}};
}
}
void registerSystemFileHolders(){
    addCommand({L"system file-holders query",L"KswordCLI.exe system file-holders query --path PATH [--recursive on|off] [--pid PID] [--creation-time FILETIME] [--duration-ms N] [--max-handles N] [--limit N] [--backend r3] [--json]",L"Query R3 disk-file handle holders with explicit sweep completeness.",
        L"Required: --path nonempty, no literal wrapping quotes/trailing spaces. Optional: --recursive off|on (off); --pid positive; --creation-time positive (requires pid); --duration-ms 250..30000 (10000); --max-handles 1..1000000 (1000000); --limit 1..100000 (1000 displayed matches); --backend r3; --json.",
        L"Output: path mapping, typed snapshot NTSTATUS, snapshot/scan/file/inspection/skip/timeout/failure counters, complete/limited/cancelled/malformed, matched/returned/truncated and holders (PID, queried process FILETIME/alive/name/path evidence, remote handle/access hex, NT/DOS names). Count/FILETIME decimal strings; unknown null. Protected/denied/duplicate/name/timeout/identity skips imply partial. Non-disk handles are deliberately excluded. Exact case-insensitive path or recursive directory boundary; not file-ID, all-hardlink or module mapping enumeration. Snapshot and remote handle reuse may change attribution; no modification/close/R0. Name API 250 ms, stop after four timeouts/wait failures; hung helpers retain owned handles safely and are not terminated. Wait failures retain waitFailedCount/waitWin32Error separately from actual timeouts. Normal helper joined on shutdown. Budget checked between native calls, no hard cancellation of kernel APIs. Complete valid empty 0, partial/truncation/cancel/limits 6, malformed 4, unavailable API 5, snapshot/type failure 3. Help performs no snapshot or opens.",query});
}
}
