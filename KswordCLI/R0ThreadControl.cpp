#include "R3ProcessShared.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <limits>

namespace ks::cli {
namespace {
using ksword::ark::DriverClient;
using ksword::ark::IoResult;

std::wstring detailText(const std::string& value) {
    return std::wstring(value.begin(), value.end());
}

int ioFailure(const IoResult& result) {
    if (result.deviceOpenFailed) return 2;
    if (result.win32Error == ERROR_NOT_SUPPORTED || result.win32Error == ERROR_INVALID_FUNCTION ||
        result.win32Error == ERROR_CALL_NOT_IMPLEMENTED || result.win32Error == ERROR_PROC_NOT_FOUND) return 5;
    return 3;
}

struct VerifiedReply {
    IoResult io;
    KSWORD_ARK_CONTROL_THREAD_VERIFIED_RESPONSE response{};
    int error = 0;
};
VerifiedReply sendVerified(KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST& request) {
    VerifiedReply result;
    result.io = DriverClient().deviceIoControl(IOCTL_KSWORD_ARK_CONTROL_THREAD_VERIFIED,
        &request, sizeof(request), &result.response, sizeof(result.response));
    if (!result.io.ok) { result.error = ioFailure(result.io); return result; }
    const auto& r = result.response;
    if (result.io.bytesReturned < sizeof(r) || r.size != sizeof(r) ||
        r.version != KSWORD_ARK_THREAD_VERIFIED_VERSION || r.processId != request.processId ||
        r.threadId != request.threadId || r.action != request.action) { result.error = 4; return result; }
    const auto status = static_cast<std::uint32_t>(r.status);
    if (status == 0xc00000bbU || status == 0xc000007aU || status == 0xc0000002U || status == 0xc0000010U)
        result.error = 5;
    else if (status != 0U) result.error = 3;
    else if ((r.fieldFlags & KSWORD_ARK_THREAD_VERIFIED_FIELD_IDENTITY) == 0 ||
        !r.processCreationTime100ns || !r.threadCreationTime100ns ||
        (request.action != KSWORD_ARK_THREAD_VERIFIED_QUERY &&
         (r.processCreationTime100ns != request.expectedProcessCreationTime100ns ||
          r.threadCreationTime100ns != request.expectedThreadCreationTime100ns))) result.error = 4;
    return result;
}

KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST verifiedRequest(const Args& args, ULONG action) {
    KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST request{};
    request.size = sizeof(request); request.version = KSWORD_ARK_THREAD_VERIFIED_VERSION;
    request.processId = args.u32(L"--pid"); (void)args.require(L"--pid");
    request.threadId = args.u32(L"--tid"); (void)args.require(L"--tid");
    request.action = action;
    if (!request.processId || !request.threadId) throw std::invalid_argument("--pid and --tid must be positive");
    return request;
}

Result identity(const Args& args) {
    auto request = verifiedRequest(args, KSWORD_ARK_THREAD_VERIFIED_QUERY);
    const auto result = sendVerified(request);
    const auto& r = result.response;
    const bool valid = result.error == 0;
    return {result.error, Json::object({{L"pid", Json::number(request.processId)}, {L"tid", Json::number(request.threadId)},
        {L"processCreationTime", valid ? Json::count(r.processCreationTime100ns) : Json{}},
        {L"threadCreationTime", valid ? Json::count(r.threadCreationTime100ns) : Json{}},
        {L"identityMatched", Json::boolean(valid)}, {L"status", result.io.ok ? Json::hex(static_cast<DWORD>(r.status)) : Json{}},
        {L"win32Error", Json::number(result.io.win32Error)}, {L"deviceOpenFailed", Json::boolean(result.io.deviceOpenFailed)}}),
        {detailText(result.io.message)}};
}

struct ThreadLease {
    process::Lease process;
    ks::r3::common::UniqueHandle thread;
    DWORD tid = 0;
    DWORD error = ERROR_SUCCESS;
    std::uint64_t expected = 0, actual = 0;
    bool matched = false;

    explicit ThreadLease(const Args& args) : process(args) {
        tid = args.u32(L"--tid"); (void)args.require(L"--tid");
        expected = args.integer(L"--thread-creation-time"); (void)args.require(L"--thread-creation-time");
        if (!tid || !expected) throw std::invalid_argument("--tid and --thread-creation-time must be positive");
        if (!process.matches || !process.alive()) return;
        thread.reset(OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid));
        if (!thread.valid()) { error = GetLastError(); return; }
        const auto owner = GetProcessIdOfThread(thread.get());
        if (!owner) { error = GetLastError(); return; }
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (!GetThreadTimes(thread.get(), &creation, &exit, &kernel, &user)) { error = GetLastError(); return; }
        actual = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        matched = owner == process.pid && actual == expected && alive();
    }
    bool alive() const {
        return process.alive() && thread.valid() && WaitForSingleObject(thread.get(), 0) == WAIT_TIMEOUT;
    }
    Json json() const {
        return Json::object({{L"process", process.json()}, {L"tid", Json::number(tid)},
            {L"expectedThreadCreationTime", Json::count(expected)},
            {L"threadCreationTime", actual ? Json::count(actual) : Json{}},
            {L"identityMatched", Json::boolean(matched)}, {L"win32Error", Json::number(error)}});
    }
};

struct SuspendCount { bool known = false; ULONG count = 0; LONG status = 0; bool statusKnown = false; };
SuspendCount readSuspendCount(HANDLE thread) {
    using NtQueryThread = LONG (NTAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);
    SuspendCount result;
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto query = module ? reinterpret_cast<NtQueryThread>(GetProcAddress(module, "NtQueryInformationThread")) : nullptr;
    if (query) {
        result.statusKnown = true;
        result.status = query(thread, 35, &result.count, sizeof(result.count), nullptr);
        result.known = result.status == 0;
    }
    return result;
}
Json countJson(const SuspendCount& count) {
    return Json::object({{L"count", count.known ? Json::number(count.count) : Json{}},
        {L"ntStatus", count.statusKnown ? Json::hex(static_cast<DWORD>(count.status)) : Json{}}});
}

Result userThreadAction(const Args& args, const std::wstring& verb) {
    (void)args.require(L"--confirm");
    (void)args.require(L"--creation-time");
    (void)args.require(L"--pid");
    if (!args.integer(L"--creation-time")) throw std::invalid_argument("--creation-time must be positive");
    if (args.u32(L"--pid") <= 4) throw std::invalid_argument("use thread driver commands for System threads");
    const auto exitStatus = args.u32(L"--exit-status", 1);
    auto request = verifiedRequest(args, verb == L"suspend" ? KSWORD_ARK_THREAD_VERIFIED_SUSPEND :
        verb == L"resume" ? KSWORD_ARK_THREAD_VERIFIED_RESUME : KSWORD_ARK_THREAD_VERIFIED_TERMINATE);
    request.flags = KSWORD_ARK_THREAD_VERIFIED_CONFIRMED;
    request.expectedProcessCreationTime100ns = args.integer(L"--creation-time");
    request.expectedThreadCreationTime100ns = args.integer(L"--thread-creation-time");
    (void)args.require(L"--thread-creation-time");
    if (!request.expectedThreadCreationTime100ns) throw std::invalid_argument("--thread-creation-time must be positive");
    request.exitStatus = static_cast<LONG>(exitStatus);
    ThreadLease lease(args);
    if (lease.process.handle.valid() && lease.process.creationTime && !lease.process.matches)
        return {3, Json::object({{L"target", lease.json()}, {L"requestAttempted", Json::boolean(false)}}),
            {L"The accessible process creation time differs from the requested identity."}};
    if (lease.thread.valid() && lease.actual && !lease.matched)
        return {3, Json::object({{L"target", lease.json()}, {L"requestAttempted", Json::boolean(false)}}),
            {L"The accessible thread identity differs from the requested identity or has exited."}};
    const auto before = verb != L"terminate" && lease.matched && lease.alive() ? readSuspendCount(lease.thread.get()) : SuspendCount{};
    const auto result = sendVerified(request);
    const auto& io = result.io;
    const bool succeeded = result.error == 0;

    bool confirmed = false;
    Json observed;
    if (verb == L"terminate" && lease.matched && lease.thread.valid()) {
        const DWORD wait = WaitForSingleObject(lease.thread.get(), succeeded ? 2000 : 0);
        DWORD resultCode = STILL_ACTIVE;
        const bool known = GetExitCodeThread(lease.thread.get(), &resultCode) != FALSE;
        confirmed = wait == WAIT_OBJECT_0 && known && resultCode == exitStatus;
        observed = Json::object({{L"exited", Json::boolean(wait == WAIT_OBJECT_0)},
            {L"exitCode", known ? Json::hex(resultCode) : Json{}}});
    } else if (verb != L"terminate" && lease.matched && lease.thread.valid()) {
        const auto after = readSuspendCount(lease.thread.get());
        const auto expected = verb == L"suspend" ? static_cast<std::uint64_t>(before.count) + 1 :
            before.count ? static_cast<std::uint64_t>(before.count) - 1 : 0;
        confirmed = lease.alive() && before.known && after.known && after.count == expected;
        observed = Json::object({{L"before", countJson(before)}, {L"after", countJson(after)}});
    }
    return {result.error ? result.error : confirmed ? 0 : 6,
        Json::object({{L"target", lease.json()}, {L"action", Json::string(verb)},
            {L"requestAttempted", Json::boolean(!io.deviceOpenFailed)}, {L"requestSucceeded", Json::boolean(succeeded)},
            {L"kernelIdentityValidated", Json::boolean(succeeded)},
            {L"verified", Json::boolean(succeeded && confirmed)}, {L"win32Error", Json::number(io.win32Error)},
            {L"ntStatus", io.ok ? Json::hex(static_cast<DWORD>(result.response.status)) : Json{}},
            {L"previousSuspendCount", (result.response.fieldFlags & KSWORD_ARK_THREAD_VERIFIED_FIELD_PREVIOUS_COUNT) ? Json::number(result.response.previousSuspendCount) : Json{}},
            {L"deviceOpenFailed", Json::boolean(io.deviceOpenFailed)}, {L"observed", observed}}),
        {detailText(io.message), L"The new R0 protocol validates creation times on the referenced thread and owner; no PID/TID-only fallback is attempted. R3 readback may be unavailable for a protected target."}};
}

Result driverThreadAction(const Args& args, const std::wstring& verb) {
    (void)args.require(L"--confirm");
    const auto tid = args.u32(L"--tid"); (void)args.require(L"--tid");
    const auto start = args.integer(L"--start-address"); (void)args.require(L"--start-address");
    const auto creation = args.integer(L"--thread-creation-time"); (void)args.require(L"--thread-creation-time");
    if (!tid || !start || !creation) throw std::invalid_argument("thread identity values must be positive");
    unsigned long method = KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE;
    if (verb == L"terminate") {
        const auto name = args.require(L"--method");
        if (name == L"psp") method = KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER;
        else if (name == L"zw") method = KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT;
        else if (name == L"normal-apc") method = KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC;
        else if (name == L"special-apc") method = KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC;
        else throw std::invalid_argument("--method must be psp, zw, normal-apc or special-apc");
    }
    const auto action = verb == L"suspend" ? KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND :
        verb == L"resume" ? KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME : KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE;
    const auto io = DriverClient().controlDriverThread(tid, start, creation, action, method, verb != L"resume");
    return {io.ok ? 6 : ioFailure(io), Json::object({{L"pid", Json::number(4)}, {L"tid", Json::number(tid)},
        {L"startAddress", Json::hex(start)}, {L"threadCreationTime", Json::count(creation)},
        {L"action", Json::string(verb)}, {L"method", Json::number(method)},
        {L"requestSucceeded", Json::boolean(io.ok)}, {L"effectConfirmed", Json::boolean(false)},
        {L"win32Error", Json::number(io.win32Error)}, {L"deviceOpenFailed", Json::boolean(io.deviceOpenFailed)}}),
        {detailText(io.message), L"The driver verifies the System-thread identity, but this protocol provides no effect receipt. An accepted request returns 6; APC delivery is asynchronous."}};
}

void addR0Command(Command command) {
    command.supportsR0 = true;
    command.supportsR3 = false;
    command.defaultBackend = L"r0";
    addCommand(std::move(command));
}
}

void registerR0ThreadControl() {
    addR0Command({L"thread r0 identity", L"KswordCLI.exe thread r0 identity --pid PID --tid TID [--backend r0] [--json]",
        L"Read the actual R0 thread and process creation identities.", L"Required: --pid, --tid.",
        L"Returns creation times from the referenced thread and owner. Requires the verified-thread IOCTL; old drivers return unsupported without falling back.", identity});
    for (const auto* name : {L"suspend", L"resume", L"terminate"}) {
        const std::wstring verb(name);
        addR0Command({L"thread r0 " + verb,
            L"KswordCLI.exe thread r0 " + verb + L" --pid PID --creation-time FILETIME --tid TID --thread-creation-time FILETIME" +
                (verb == L"terminate" ? L" [--exit-status N]" : L"") + L" --confirm [--backend r0] [--json]",
            L"Control one ordinary process thread through the R0 driver.",
            L"Required: --pid, --creation-time, --tid, --thread-creation-time, --confirm. Terminate accepts --exit-status (default 1).",
            L"R0 checks both creation times while holding the referenced thread and owner. R3 query handles are used only for optional readback. Requires the new verified-thread IOCTL; old drivers fail without PID/TID-only fallback. A successful request without matching readback returns 6.",
            [verb](const Args& args) { return userThreadAction(args, verb); }});
        addR0Command({L"thread driver " + verb,
            L"KswordCLI.exe thread driver " + verb + L" --tid TID --start-address VA --thread-creation-time FILETIME" +
                (verb == L"terminate" ? L" --method psp|zw|normal-apc|special-apc" : L"") + L" --confirm [--backend r0] [--json]",
            L"Control one System driver thread using the R0 identity-checked protocol.",
            L"Required: --tid, --start-address, --thread-creation-time, --confirm. Terminate also requires --method.",
            L"The driver verifies TID, start address and creation time and applies its existing protection rules. The protocol has no effect receipt; accepted requests return 6. APC methods queue asynchronously.",
            [verb](const Args& args) { return driverThreadAction(args, verb); }});
    }
}
}
