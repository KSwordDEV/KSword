#include "R3FileShared.h"
#include "../shared/usermode/backend/file/FileOperations.h"
#include <limits>

namespace ks::cli {
namespace {
namespace backend = ks::r3::file;
Result action(const Args& args, const std::wstring& operation) {
    (void)args.require(L"--confirm");
    std::wstring source, target; backend::FileOperationResult outcome;
    file::Evidence before;
    std::vector<std::uint8_t> contents;
    bool namedCreate = false;
    if (operation == L"create" || operation == L"create-directory") {
        if (args.has(L"--path") == args.has(L"--directory")) throw std::invalid_argument("specify exactly one of --path or --directory");
        const int payloads = static_cast<int>(args.has(L"--text")) + static_cast<int>(args.has(L"--hex")) + static_cast<int>(args.has(L"--data-file"));
        if (payloads > 1 || (payloads && (operation != L"create" || !args.has(L"--path"))))
            throw std::invalid_argument("file content requires --path and exactly one payload");
        if (args.has(L"--hex")) contents = parseHexPayload(args.get(L"--hex"));
        else if (args.has(L"--data-file")) {
            auto input = readPayloadFile(args.get(L"--data-file"));
            if (input.win32Error) return {3, Json::object({{L"dataFileWin32Error", Json::number(input.win32Error)}}), {L"Input payload could not be read; no file was created."}};
            contents = std::move(input.bytes);
        } else if (args.has(L"--text")) {
            const auto text = args.get(L"--text");
            if (text.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) throw std::invalid_argument("text too long");
            if (!text.empty()) {
                const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
                if (!size) throw std::invalid_argument("invalid UTF-16 text");
                contents.resize(size);
                if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), reinterpret_cast<char*>(contents.data()), size, nullptr, nullptr)) throw std::invalid_argument("cannot encode text as UTF-8");
            }
        }
        if (contents.size() > 64U * 1024U * 1024U) throw std::invalid_argument("file content exceeds 64 MiB");
        namedCreate = args.has(L"--path");
        source = file::path(args, namedCreate ? L"--path" : L"--directory");
        outcome = namedCreate ? backend::CreateNamedPathResult(source, operation == L"create-directory", contents) :
            operation == L"create" ? backend::CreateEmptyFileResult(source) : backend::CreateNewDirectoryResult(source);
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
        else if (operation == L"create") {
            verified = targetAfter.present && !targetAfter.directory() && targetAfter.size() == contents.size();
            if (verified && namedCreate) { const auto readback = readPayloadFile(target); verified = !readback.win32Error && readback.bytes == contents; }
        }
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
        const auto params = op == L"create" ? L"(--path PATH [--text TEXT | --hex HEX | --data-file PATH] | --directory PATH)" : op == L"create-directory" ? L"(--path PATH | --directory PATH)" : op == L"copy" || op == L"move" ? L"--path PATH --to-directory PATH" : op == L"rename" ? L"--path PATH --target PATH" : L"--path PATH";
        addCommand({path, L"KswordCLI.exe " + path + L" " + params + L" --confirm [--backend r3] [--json]",
            L"Perform " + op + L" using the shared R3 filesystem backend.", L"Required: " + std::wstring(params) + L", --confirm. Optional: --backend r3, --json.",
            L"Fields: source, target, action, requestSucceeded, errorCode/errorCategory, verified, before/after. Create --directory uses an automatic name; --path creates exactly that name and fails if it exists. File content is UTF-8 text or raw hex/file bytes (file payload limit 64 MiB); named files are read back for verification. Copy may overwrite; directory copy is recursive. Directory deletion requires empty directory. No rollback is implied.",
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
