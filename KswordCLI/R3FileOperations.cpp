#include "R3FileShared.h"
#include "../shared/usermode/backend/file/FileOperations.h"

namespace ks::cli {
namespace {
namespace backend = ks::r3::file;
Result action(const Args& args, const std::wstring& operation) {
    (void)args.require(L"--confirm");
    std::wstring source, target; backend::FileOperationResult outcome;
    file::Evidence before;
    if (operation == L"create" || operation == L"create-directory") {
        source = file::path(args, L"--directory");
        outcome = operation == L"create" ? backend::CreateEmptyFileResult(source) : backend::CreateNewDirectoryResult(source);
        target = outcome.target; outcome.errorCategory = "win32";
    } else {
        source = file::path(args, L"--path"); before = file::evidence(source);
        if (operation == L"copy" || operation == L"move") {
            target = file::path(args, L"--to-directory");
            outcome = backend::TransferPathToFolder(source, target, operation == L"move"); target = outcome.target;
        } else {
            BOOL ok = FALSE;
            if (operation == L"rename") { target = file::path(args, L"--target"); ok = backend::RenamePath(source, target); }
            else if (operation == L"delete") ok = backend::DeleteFilePath(source);
            else ok = backend::DeleteEmptyDirectory(source);
            outcome.errorCode = ok ? ERROR_SUCCESS : GetLastError(); outcome.success = ok != FALSE; outcome.errorCategory = "win32";
        }
    }
    const auto sourceAfter = file::evidence(source); const auto targetAfter = target.empty() ? file::Evidence{} : file::evidence(target);
    bool verified = false;
    if (outcome.success) {
        if (operation == L"delete" || operation == L"delete-directory") verified = sourceAfter.known && !sourceAfter.present;
        else if (operation == L"create") verified = targetAfter.present && !targetAfter.directory() && targetAfter.size() == 0;
        else if (operation == L"create-directory") verified = targetAfter.directory();
        else {
            verified = targetAfter.present && before.present && targetAfter.directory() == before.directory() &&
                (before.directory() || targetAfter.size() == before.size());
            if (operation != L"copy" && _wcsicmp(source.c_str(), target.c_str()) != 0) verified &= sourceAfter.known && !sourceAfter.present;
        }
    }
    Result result{!outcome.success ? outcome.partial ? 6 : 3 : verified ? 0 : 6};
    result.data = Json::object({{L"source", Json::string(source)}, {L"target", Json::string(target)}, {L"action", Json::string(operation)},
        {L"requestSucceeded", Json::boolean(outcome.success)}, {L"partial", Json::boolean(outcome.partial)}, {L"verified", Json::boolean(verified)},
        {L"errorCode", Json::number(outcome.errorCode)}, {L"errorCategory", Json::string(std::wstring(outcome.errorCategory.begin(), outcome.errorCategory.end()))},
        {L"copyCompleted", Json::boolean(outcome.copied)}, {L"sourceRemoved", sourceAfter.known ? Json::boolean(!sourceAfter.present) : Json{}},
        {L"before", before.json()}, {L"sourceAfter", sourceAfter.json()}, {L"targetAfter", targetAfter.json()}});
    if (!outcome.success && !outcome.message.empty()) result.diagnostics.push_back(outcome.message);
    if (outcome.partial) result.diagnostics.push_back(L"The destination exists after failure; copying or source removal may be incomplete.");
    if (outcome.success && !verified) result.diagnostics.push_back(L"Request completed but final path/size evidence did not confirm the requested result.");
    return result;
}
Result pathQuery(const Args& args, bool shortcut) {
    const auto path = file::path(args, L"--path");
    if (shortcut && (path.size() < 4 || _wcsicmp(path.c_str() + path.size() - 4, L".lnk") != 0)) throw std::invalid_argument("--path must name a .lnk file");
    HRESULT status = S_OK;
    const auto target = shortcut ? backend::ResolveLinkTarget(path, &status) : backend::ShortPathForFile(path);
    const auto error = !shortcut && target.empty() ? GetLastError() : ERROR_SUCCESS;
    const int code = target.empty() ? shortcut && SUCCEEDED(status) ? 5 : 3 : 0;
    return {code, Json::object({{L"path", Json::string(path)}, {L"result", target.empty() ? Json{} : Json::string(target)},
        {L"win32Error", Json::number(error)}, {L"hresult", shortcut ? Json::hex(static_cast<DWORD>(status)) : Json{}}}),
        target.empty() && shortcut && SUCCEEDED(status) ? std::vector<std::wstring>{L"The shortcut has no filesystem target."} : std::vector<std::wstring>{}};
}
}
void registerFileOperations() {
    for (const auto& operation : {L"create", L"create-directory", L"copy", L"move", L"rename", L"delete", L"delete-directory"}) {
        const std::wstring op = operation;
        const std::wstring path = op == L"create-directory" ? L"file directory create" : op == L"delete-directory" ? L"file directory delete" : L"file " + op;
        const auto params = op.starts_with(L"create") ? L"--directory PATH" : op == L"copy" || op == L"move" ? L"--path PATH --to-directory PATH" : op == L"rename" ? L"--path PATH --target PATH" : L"--path PATH";
        addCommand({path, L"KswordCLI.exe " + path + L" " + params + L" --confirm [--backend r3] [--json]",
            L"Perform " + op + L" using the shared R3 filesystem backend.", L"Required: " + std::wstring(params) + L", --confirm. Optional: --backend r3, --json.",
            L"Fields: source, target, action, requestSucceeded, errorCode/errorCategory, verified, before/after. Create uses backend-generated collision-free names. Copy may overwrite; directory copy is recursive. Directory deletion requires empty directory. No rollback is implied.",
            [op](const Args& args) { return action(args, op); }});
    }
    addCommand({L"file delete-path", L"KswordCLI.exe file delete-path --path PATH --confirm --backend r3 [--json]",
        L"Delete one file using R3 when explicitly selected.", L"Required: --path, --confirm, --backend r3. Optional: --json.",
        L"R3 uses DeleteFileW; use file directory delete for an empty directory. Default/R0 invocation stays compatible.", [](const Args& args) { return action(args, L"delete"); }});
    addCommand({L"file path short query", L"KswordCLI.exe file path short query --path PATH [--backend r3] [--json]",
        L"Query the filesystem short path.", L"Required: --path. Optional: --backend r3, --json.", L"Fields: path, result, win32Error. A returned path need not differ if 8.3 generation is disabled.", [](const Args& args) { return pathQuery(args, false); }});
    addCommand({L"file shortcut query", L"KswordCLI.exe file shortcut query --path PATH [--backend r3] [--json]",
        L"Read a .lnk filesystem target without resolving or launching it.", L"Required: --path. Optional: --backend r3, --json.", L"Fields: path, result, hresult. Non-filesystem/empty targets are unsupported. COM uses the calling thread and is released on completion.", [](const Args& args) { return pathQuery(args, true); }});
}
}
