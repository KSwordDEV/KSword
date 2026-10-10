#include "R3FileShared.h"
#include "../shared/usermode/backend/file/Ownership.h"
#include <Aclapi.h>
#include <sddl.h>

namespace ks::cli {
namespace {
namespace backend = ks::r3::file;
struct Owner {
    DWORD error = ERROR_SUCCESS;
    std::wstring sid;
    Json json() const { return Json::object({{L"sid", sid.empty() ? Json{} : Json::string(sid)}, {L"win32Error", Json::number(error)}}); }
};
Owner owner(const std::wstring& path) {
    Owner result; PSID sid = nullptr; PSECURITY_DESCRIPTOR security = nullptr;
    result.error = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &sid, nullptr, nullptr, nullptr, &security);
    if (result.error == ERROR_SUCCESS) {
        LPWSTR text = nullptr;
        if (sid && ConvertSidToStringSidW(sid, &text)) { result.sid = text; LocalFree(text); }
        else result.error = sid ? GetLastError() : ERROR_INVALID_SID;
    }
    if (security) LocalFree(security);
    return result;
}
Result take(const Args& args) {
    (void)args.require(L"--confirm"); const auto path = file::path(args, L"--path");
    const auto before = owner(path); const auto outcome = backend::TakeOwnership(path); const auto after = owner(path);
    const bool verified = outcome.success && !outcome.callerSid.empty() && after.sid == outcome.callerSid;
    Result result{!outcome.success ? 3 : verified ? 0 : 6};
    result.data = Json::object({{L"path", Json::string(path)}, {L"action", Json::string(L"take-ownership")},
        {L"callerSid", outcome.callerSid.empty() ? Json{} : Json::string(outcome.callerSid)}, {L"privilegeEnabled", Json::boolean(outcome.privilegeEnabled)},
        {L"requestSucceeded", Json::boolean(outcome.success)}, {L"win32Error", Json::number(outcome.errorCode)},
        {L"before", before.json()}, {L"after", after.json()}, {L"verified", Json::boolean(verified)}});
    if (!outcome.success) result.diagnostics.push_back(outcome.message);
    if (outcome.success && !verified) result.diagnostics.push_back(L"Owner SID readback did not confirm the requested result.");
    return result;
}
Result locks(const Args& args) {
    const auto path = file::path(args, L"--path"); const auto pid = args.u32(L"--pid"), limit = args.u32(L"--limit");
    const auto outcome = backend::ReadFileLockers(path); std::vector<Json> rows; std::uint32_t matched = 0;
    for (const auto& p : outcome.processes) {
        if (pid && p.pid != pid) continue;
        ++matched; if (limit && rows.size() >= limit) continue;
        rows.push_back(Json::object({{L"pid", Json::number(p.pid)}, {L"creationTime", Json::count(p.creationTime)},
            {L"application", Json::string(p.application)}, {L"service", Json::string(p.service)}, {L"applicationType", Json::number(p.applicationType)},
            {L"status", Json::hex(p.status)}, {L"sessionId", Json::number(p.sessionId)}, {L"restartable", Json::boolean(p.restartable)}}));
    }
    return {outcome.success ? 0 : 3, Json::object({{L"path", Json::string(path)}, {L"source", Json::string(L"Restart Manager")},
        {L"target", file::evidence(path).json()}, {L"win32Error", Json::number(outcome.errorCode)}, {L"rebootReason", Json::hex(outcome.rebootReason)},
        {L"totalCount", Json::number(static_cast<std::uint32_t>(outcome.processes.size()))}, {L"matchedCount", Json::number(matched)},
        {L"returnedCount", Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"processes", Json::array(rows)}}),
        outcome.success ? std::vector<std::wstring>{} : std::vector<std::wstring>{outcome.report}};
}
}
void registerFileOwnership() {
    addCommand({L"file ownership take", L"KswordCLI.exe file ownership take --path PATH --confirm [--backend r3] [--json]",
        L"Set the file or directory owner to the current token user and read it back.", L"Required: --path, --confirm. Optional: --backend r3, --json.",
        L"Fields: callerSid, privilegeEnabled, requestSucceeded, win32Error, before/after owner SIDs, verified. Attempts SeTakeOwnershipPrivilege in this process. Does not alter the DACL or recursively change children.", take});
    addCommand({L"file locks query", L"KswordCLI.exe file locks query --path PATH [--pid PID] [--limit N] [--backend r3] [--json]",
        L"Read Restart Manager visible file users without closing handles.", L"Required: --path. Optional: --pid filter (0 = all), --limit display (0 = all), --backend r3, --json.",
        L"Fields: target, rebootReason, processes with PID/creationTime, application, service, type, status, sessionId, restartable. Empty results do not prove the file is unlocked; RM does not validate path existence or expose all kernel handles.", locks});
}
}
