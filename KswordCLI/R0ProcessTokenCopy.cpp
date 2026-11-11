#include "R3ProcessShared.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/driver/KswordArkProcessIoctl.h"
#include <utility>

namespace ks::cli {
namespace {
constexpr ULONG identityFlags = KSWORD_ARK_PROCESS_TOKEN_COPY_SOURCE_IDENTITY |
    KSWORD_ARK_PROCESS_TOKEN_COPY_TARGET_IDENTITY;
constexpr ULONG verifiedFlags = identityFlags | KSWORD_ARK_PROCESS_TOKEN_COPY_SOURCE_TOKEN |
    KSWORD_ARK_PROCESS_TOKEN_COPY_BEFORE_TOKEN | KSWORD_ARK_PROCESS_TOKEN_COPY_ASSIGNED_TOKEN |
    KSWORD_ARK_PROCESS_TOKEN_COPY_ASSIGN_ATTEMPTED | KSWORD_ARK_PROCESS_TOKEN_COPY_APPLIED |
    KSWORD_ARK_PROCESS_TOKEN_COPY_AFTER_TOKEN | KSWORD_ARK_PROCESS_TOKEN_COPY_VERIFIED;

bool unsupported(std::uint32_t status) {
    return status == 0xc00000bbU || status == 0xc0000002U || status == 0xc0000010U || status == 0xc000007aU;
}

// Capture a query handle when available; explicit R0 identities also support inaccessible sources.
Args sourceArgs(const Args& args) {
    Args source;
    source.values[L"--pid"] = args.require(L"--source-pid");
    if (args.has(L"--source-creation-time"))
        source.values[L"--creation-time"] = args.require(L"--source-creation-time");
    return source;
}

std::uint64_t creationIdentity(const Args& args, const wchar_t* option, const process::Lease& lease) {
    if (args.has(option)) {
        const auto expected = args.integer(option);
        if (!expected) throw std::invalid_argument("process creation times must be positive");
        return expected;
    }
    return lease.creationTime;
}

Result copyToken(const Args& args) {
    (void)args.require(L"--confirm");
    const auto sourcePid = args.u32(L"--source-pid");
    const auto targetPid = args.u32(L"--pid");
    (void)args.require(L"--source-pid");
    (void)args.require(L"--pid");
    if (!sourcePid || targetPid <= 4 || sourcePid == targetPid)
        throw std::invalid_argument("--source-pid must be positive; --pid must be greater than 4 and different from source");

    process::Lease source(sourceArgs(args)), target(args);
    const auto sourceTime = creationIdentity(args, L"--source-creation-time", source);
    const auto targetTime = creationIdentity(args, L"--creation-time", target);
    const auto targets = Json::object({{L"source", source.json()}, {L"target", target.json()},
        {L"expectedSourceCreationTime", Json::count(sourceTime)}, {L"expectedTargetCreationTime", Json::count(targetTime)}});
    if (!sourceTime || !targetTime)
        return {3, Json::object({{L"targets", targets}, {L"requestAttempted", Json::boolean(false)}}),
            {L"Cannot capture process creation identity. Supply the real R0 enumeration values with --source-creation-time and --creation-time for inaccessible processes."}};
    if ((source.creationTime && !source.matches) || (target.creationTime && !target.matches) ||
        (source.handle.valid() && !source.alive()) || (target.handle.valid() && !target.alive()))
        return {3, Json::object({{L"targets", targets}, {L"requestAttempted", Json::boolean(false)}}),
            {L"A selected process has exited or its creation identity differs from the requested value."}};

    KSWORD_ARK_COPY_PROCESS_TOKEN_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_PROCESS_TOKEN_COPY_VERSION;
    request.sourceProcessId = sourcePid;
    request.targetProcessId = targetPid;
    request.flags = KSWORD_ARK_PROCESS_TOKEN_COPY_CONFIRMED;
    request.expectedSourceCreateTime100ns = sourceTime;
    request.expectedTargetCreateTime100ns = targetTime;
    KSWORD_ARK_COPY_PROCESS_TOKEN_RESPONSE response{};
    const auto io = ksword::ark::DriverClient().deviceIoControl(IOCTL_KSWORD_ARK_COPY_PROCESS_TOKEN,
        &request, sizeof(request), &response, sizeof(response));
    const bool valid = io.ok && io.bytesReturned == sizeof(response) && response.size == sizeof(response) &&
        response.version == request.version && response.sourceProcessId == sourcePid && response.targetProcessId == targetPid &&
        (response.fieldFlags & ~verifiedFlags) == 0 &&
        (!(response.fieldFlags & KSWORD_ARK_PROCESS_TOKEN_COPY_SOURCE_IDENTITY) || response.sourceCreateTime100ns == sourceTime) &&
        (!(response.fieldFlags & KSWORD_ARK_PROCESS_TOKEN_COPY_TARGET_IDENTITY) || response.targetCreateTime100ns == targetTime);
    const auto flags = valid ? response.fieldFlags : 0UL;
    const auto status = static_cast<std::uint32_t>(response.lastStatus);
    const bool applied = (flags & KSWORD_ARK_PROCESS_TOKEN_COPY_APPLIED) != 0;
    const bool attempted = (flags & KSWORD_ARK_PROCESS_TOKEN_COPY_ASSIGN_ATTEMPTED) != 0;
    const bool verified = valid && status == 0 && response.assignStatus == 0 && response.verifyStatus == 0 &&
        (flags & verifiedFlags) == verifiedFlags && response.assignedTokenId == response.sourceTokenId &&
        response.sourceTokenId == response.targetTokenIdAfter;
    int code = 0;
    if (!io.ok) code = io.deviceOpenFailed ? 2 :
        io.win32Error == ERROR_INVALID_DATA ? 4 : io.win32Error == ERROR_NOT_SUPPORTED ||
        io.win32Error == ERROR_INVALID_FUNCTION || io.win32Error == ERROR_CALL_NOT_IMPLEMENTED ||
        io.win32Error == ERROR_PROC_NOT_FOUND ? 5 : 3;
    else if (!valid) code = 4;
    else if (applied && !verified) code = 6;
    else if (unsupported(status)) code = 5;
    else if (status != 0) code = 3;
    else if (!verified) code = 4;

    const auto id = [flags](ULONG bit, std::uint64_t value) {
        return flags & bit ? Json::hex(value) : Json{};
    };
    std::vector<std::wstring> diagnostics;
    if (!io.message.empty()) diagnostics.emplace_back(io.message.begin(), io.message.end());
    if (valid && unsupported(status))
        diagnostics.emplace_back(L"Private token replacement requires trusted EPROCESS.Token and PDB-sourced EPROCESS.ProcessLock offsets for the current kernel.");
    if (applied && !verified)
        diagnostics.emplace_back(L"Assignment succeeded, but the new primary token was not verified. The target may already be changed; the command does not retry or roll back automatically.");
    return {code, Json::object({{L"targets", targets}, {L"responseValid", Json::boolean(valid)},
        {L"deviceOpenFailed", Json::boolean(io.deviceOpenFailed)}, {L"win32Error", Json::number(io.win32Error)},
        {L"fieldFlags", valid ? Json::hex(flags) : Json{}}, {L"assignmentAttempted", Json::boolean(attempted)},
        {L"applied", valid ? Json::boolean(applied) : Json{}}, {L"verified", Json::boolean(verified)},
        {L"lastStatus", valid ? Json::hex(status) : Json{}},
        {L"assignStatus", attempted ? Json::hex(static_cast<std::uint32_t>(response.assignStatus)) : Json{}},
        {L"verifyStatus", attempted ? Json::hex(static_cast<std::uint32_t>(response.verifyStatus)) : Json{}},
        {L"sourceTokenId", id(KSWORD_ARK_PROCESS_TOKEN_COPY_SOURCE_TOKEN, response.sourceTokenId)},
        {L"assignedTokenId", id(KSWORD_ARK_PROCESS_TOKEN_COPY_ASSIGNED_TOKEN, response.assignedTokenId)},
        {L"targetTokenIdBefore", id(KSWORD_ARK_PROCESS_TOKEN_COPY_BEFORE_TOKEN, response.targetTokenIdBefore)},
        {L"targetTokenIdAfter", id(KSWORD_ARK_PROCESS_TOKEN_COPY_AFTER_TOKEN, response.targetTokenIdAfter)}}), std::move(diagnostics)};
}
}

void registerProcessTokenCopy() {
    Command command{L"process token copy",
        L"KswordCLI.exe process token copy --source-pid PID --pid PID [--source-creation-time FILETIME] [--creation-time FILETIME] --confirm [--backend r0] [--json]",
        L"Replace a target process EPROCESS.Token reference with the selected source process token.",
        L"Required: --source-pid, --pid (target), --confirm. Optional: --source-creation-time, --creation-time, --backend r0, --json.",
        L"R0 only. Validates both process creation identities and replaces the target EPROCESS.Token fast reference using trusted current-kernel offsets. Source and target share the same token object; token edits affect both. Existing handles and thread impersonation tokens retain their previous semantics. Returns 0 after verified readback, 6 after an applied but unverified change, 5 for unavailable offsets, 3 for operation failure, 4 for malformed receipt, 2 for device-open failure, 1 for invalid arguments. No automatic retry or rollback.", copyToken};
    command.supportsR0 = true;
    command.supportsR3 = false;
    command.defaultBackend = L"r0";
    addCommand(std::move(command));
}
}
