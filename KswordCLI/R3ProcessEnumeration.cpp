#include "CommandRegistry.h"
#include "../shared/usermode/backend/process/ProcessEnumerator.h"
namespace ks::cli {
namespace {
Result enumerate(const Args& args) {
    const auto pid = args.u32(L"--pid"), limit = args.u32(L"--limit"); const auto name = args.get(L"--name");
    const auto snapshot = ks::r3::process::EnumerateProcessesByNtQuerySystemInformation();
    std::vector<Json> rows; std::uint32_t matched = 0, missingPaths = 0;
    for (const auto& row : snapshot.rows) {
        if (args.has(L"--pid") && row.processId != pid) continue;
        if (!name.empty() && _wcsicmp(name.c_str(), row.imageName.c_str()) != 0) continue;
        ++matched; if (row.imagePath.empty()) ++missingPaths;
        if (limit && rows.size() >= limit) continue;
        rows.push_back(Json::object({{L"pid", Json::number(row.processId)}, {L"parentPid", Json::number(row.parentProcessId)},
            {L"creationTime", row.creationTime100ns ? Json::count(row.creationTime100ns) : Json{}}, {L"name", Json::string(row.imageName)},
            {L"nameSource", Json::string(row.imageNameAvailable ? L"native-snapshot" : L"synthetic-display-name")},
            {L"path", row.imagePath.empty() ? Json{} : Json::string(row.imagePath)}, {L"pathWin32Error", Json::number(row.imagePathError)},
            {L"sessionId", Json::number(row.sessionId)}, {L"threadCount", Json::number(row.threadCount)}, {L"handleCount", Json::number(row.handleCount)},
            {L"basePriority", Json::signedNumber(row.basePriority)}, {L"kernelTime100ns", Json::count(row.kernelTime100ns)},
            {L"userTime100ns", Json::count(row.userTime100ns)}, {L"cycleTime", Json::count(row.cycleTime)},
            {L"workingSetBytes", Json::count(row.workingSetBytes)}, {L"peakWorkingSetBytes", Json::count(row.peakWorkingSetBytes)},
            {L"privatePageBytes", Json::count(row.privatePageBytes)}, {L"privateWorkingSetBytes", Json::count(row.privateWorkingSetBytes)},
            {L"virtualSizeBytes", Json::count(row.virtualSizeBytes)}, {L"commitBytes", Json::count(row.commitBytes)},
            {L"pagedPoolBytes", Json::count(row.pagedPoolBytes)}, {L"nonPagedPoolBytes", Json::count(row.nonPagedPoolBytes)},
            {L"pageFaultCount", Json::number(row.pageFaultCount)}, {L"ioReadOperations", Json::count(row.ioReadOperations)},
            {L"ioWriteOperations", Json::count(row.ioWriteOperations)}, {L"ioOtherOperations", Json::count(row.ioOtherOperations)},
            {L"ioReadBytes", Json::count(row.ioReadBytes)}, {L"ioWriteBytes", Json::count(row.ioWriteBytes)}, {L"ioOtherBytes", Json::count(row.ioOtherBytes)}}));
    }
    const auto status = static_cast<DWORD>(snapshot.ntStatus);
    Result result{!snapshot.success ? status == 0xc000007a || status == 0xc0000002 || status == 0xc00000bb ? 5 : 3 : snapshot.malformed ? 4 : missingPaths ? 6 : 0};
    result.data = Json::object({{L"source", Json::string(L"NtQuerySystemInformation/SystemProcessInformation")}, {L"complete", Json::boolean(snapshot.complete)},
        {L"malformed", Json::boolean(snapshot.malformed)}, {L"ntStatus", Json::hex(status)}, {L"totalCount", Json::number(static_cast<std::uint32_t>(snapshot.rows.size()))},
        {L"matchedCount", Json::number(matched)}, {L"returnedCount", Json::number(static_cast<std::uint32_t>(rows.size()))},
        {L"missingPathCount", Json::number(missingPaths)}, {L"processes", Json::array(rows)}});
    if (!snapshot.success || snapshot.malformed) result.diagnostics.push_back(snapshot.diagnosticText);
    if (missingPaths) result.diagnostics.push_back(L"Some matched processes have no accessible image path; native snapshot identity and counters remain available.");
    return result;
}
}
void registerProcessEnumeration() {
    addCommand({L"process enum", L"KswordCLI.exe process enum --backend r3 [--pid PID] [--name NAME] [--limit N] [--json]",
        L"Read native R3 process identities and counters without the driver.", L"Required: --backend r3. Optional: --pid exact PID (including 0), --name exact image name, --limit (0 = all), --json.",
        L"Fields: PID/creationTime, parentPid, image path/error, session, threads, handles, priority, memory, CPU/I/O totals. No sampled rates. Path enrichment checks creation time on the retained handle. Missing paths return 6; missing filters may succeed empty. Default/R0 syntax is preserved.", enumerate});
}
}
