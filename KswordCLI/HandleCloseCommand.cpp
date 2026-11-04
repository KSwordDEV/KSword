#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.h"

#include <Windows.h>
#include <stdexcept>
#include <utility>

namespace ks::cli {
namespace {
std::wstring wide(const std::string& text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return std::wstring(text.begin(), text.end());
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

Result close(const Args& args) {
    (void)args.require(L"--pid");
    (void)args.require(L"--handle");
    (void)args.require(L"--creation-time");
    (void)args.require(L"--object");
    (void)args.require(L"--confirm");
    const auto pid = args.u32(L"--pid");
    const auto handle = args.integer(L"--handle");
    const auto creationTime = args.integer(L"--creation-time");
    const auto object = args.integer(L"--object");
    if (pid <= 4 || pid == GetCurrentProcessId() || !handle || handle >= 0x80000000ULL || !creationTime || !object)
        throw std::invalid_argument("protected or unverifiable handle identity");
    const auto backend = args.get(L"--backend", L"r3");
    if (backend == L"r0") {
        const auto result = ksword::ark::DriverClient().closeHandleDetailed(pid, handle, creationTime, object);
        const auto& io = result.io;
        const auto status = static_cast<std::uint32_t>(result.closeStatus);
        const bool recoveryFailed = result.responseValid && result.resumeStatus < 0;
        const bool closed = result.responseValid && result.closeStatus >= 0;
        const int code = io.ok ? 0 : recoveryFailed ? 6 : io.deviceOpenFailed ? 2 :
            io.win32Error == ERROR_INVALID_DATA ? 4 :
            io.win32Error == ERROR_NOT_SUPPORTED || io.win32Error == ERROR_INVALID_FUNCTION ||
            (result.responseValid && (status == 0xc00000bbU || status == 0xc0000002U)) ? 5 : 3;
        return {code, Json::object({{L"pid", Json::number(pid)}, {L"handle", Json::hex(handle)},
            {L"creationTime", Json::count(creationTime)}, {L"object", Json::hex(object)},
            {L"responseValid", Json::boolean(result.responseValid)}, {L"requestSucceeded", Json::boolean(io.ok)},
            {L"closeSucceeded", result.responseValid ? Json::boolean(closed) : Json{}},
            {L"closeStatus", result.responseValid ? Json::hex(status) : Json{}},
            {L"resumeStatus", result.responseValid ? Json::hex(static_cast<std::uint32_t>(result.resumeStatus)) : Json{}},
            {L"win32Error", Json::number(io.win32Error)}, {L"deviceOpenFailed", Json::boolean(io.deviceOpenFailed)}}),
            {wide(io.message)}};
    }
    if (backend != L"r3") throw std::invalid_argument("--backend must be r3 or r0");
    const auto result = ks::file::CloseRemoteHandleByObjectIdentityDetailed(pid, handle, creationTime, object);
    const int code = result.success ? 0 : result.closeAttempted || (result.resumeAttempted && result.resumeStatus < 0) ? 6 : 3;
    return {code, Json::object({{L"pid", Json::number(pid)}, {L"handle", Json::hex(handle)},
        {L"creationTime", Json::count(creationTime)}, {L"object", Json::hex(object)},
        {L"requestSucceeded", Json::boolean(result.success)}, {L"suspendAttempted", Json::boolean(result.suspendAttempted)},
        {L"suspendStatus", result.suspendAttempted ? Json::hex(static_cast<std::uint32_t>(result.suspendStatus)) : Json{}},
        {L"closeAttempted", Json::boolean(result.closeAttempted)},
        {L"closeSucceeded", result.closeAttempted ? Json::boolean(result.closeSucceeded) : Json{}},
        {L"resumeAttempted", Json::boolean(result.resumeAttempted)},
        {L"resumeStatus", result.resumeAttempted ? Json::hex(static_cast<std::uint32_t>(result.resumeStatus)) : Json{}}}),
        {wide(result.detail), L"DuplicateHandle CLOSE_SOURCE can close the source even on failure; an attempted but unconfirmed close is partial. Snapshot identity narrows, but does not eliminate, concurrent handle reuse."}};
}
}

void registerHandleClose() {
    Command command{L"handle close",
        L"KswordCLI.exe handle close --pid PID --handle HANDLE --creation-time FILETIME --object ADDRESS --confirm [--backend r3|r0] [--json]",
        L"Close one previously enumerated handle after revalidating its process and object identity.",
        L"Required: --pid, --handle, --creation-time, --object, --confirm. Optional: --backend r3|r0 (r3), --json.",
        L"Use one handle enum or file-holders row, including its PID creation time, handle and object address. System and the calling process are rejected. The selected backend suspends the target while checking the object and closing the handle, then resumes it. Close and resume statuses are separate; partial effects return 6. No backend fallback or automatic retry; module mappings are not closable handles.", close};
    command.supportsR0 = true;
    addCommand(std::move(command));
}
}
