#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "ReadyOwnerFailureTrigger.h"

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

using ready_owner_failure::AllocationIdentity;
using ready_owner_failure::ControlMode;
using ready_owner_failure::HeldConfirmation;
using ready_owner_failure::RecoveryObservation;
using ready_owner_failure::ReleaseObservation;

constexpr std::uint64_t kAllocationBytes = 0x1000;
constexpr DWORD kDeadlineMs = 30000;

struct SharedState {
    volatile LONG ready = 0;
    volatile LONG go = 0;
    volatile LONG done = 0;
    volatile LONG stop = 0;
    volatile LONG64 allocationBase = 0;
    volatile LONG64 allocationAddress = 0;
    volatile LONG64 allocationBytes = 0;
    volatile LONG64 counter = 0;
};

class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    HANDLE release() { HANDLE value = value_; value_ = nullptr; return value; }

private:
    HANDLE value_ = nullptr;
};

std::wstring MappingName(DWORD pid) {
    return L"Local\\KswordReadyOwnerFailure-" + std::to_wstring(pid);
}

std::uint64_t CreationTime(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

bool ParseUnsigned(const std::map<std::string, std::string>& fields, const char* name,
    std::uint64_t& value) {
    const auto it = fields.find(name);
    if (it == fields.end() || it->second.empty()) return false;
    const char* first = it->second.data();
    const char* last = first + it->second.size();
    const auto result = std::from_chars(first, last, value, 10);
    return result.ec == std::errc{} && result.ptr == last;
}

bool ParseBool(const std::map<std::string, std::string>& fields, const char* name, bool& value) {
    const auto it = fields.find(name);
    if (it == fields.end()) return false;
    if (it->second == "true") { value = true; return true; }
    if (it->second == "false") { value = false; return true; }
    return false;
}

bool RequiredText(const std::map<std::string, std::string>& fields, const char* name,
    std::string& value) {
    const auto it = fields.find(name);
    if (it == fields.end() || it->second.empty()) return false;
    value = it->second;
    return true;
}

bool ParseMode(const std::map<std::string, std::string>& fields, ControlMode& mode) {
    const auto it = fields.find("mode");
    if (it == fields.end()) return false;
    if (it->second == "continue") { mode = ControlMode::Continue; return true; }
    if (it->second == "step") { mode = ControlMode::Step; return true; }
    return false;
}

const char* ModeName(ControlMode mode) {
    return mode == ControlMode::Step ? "step" : "continue";
}

bool ParseFields(const std::string& line, std::string& command,
    std::map<std::string, std::string>& fields) {
    fields.clear();
    const auto split = line.find(' ');
    command = line.substr(0, split);
    if (command.empty()) return false;
    std::size_t offset = split == std::string::npos ? line.size() : split + 1;
    while (offset < line.size()) {
        const auto end = line.find(' ', offset);
        const std::string token = line.substr(offset,
            end == std::string::npos ? line.size() - offset : end - offset);
        if (!token.empty()) {
            const auto equal = token.find('=');
            if (equal == std::string::npos || equal == 0 || equal + 1 == token.size()) return false;
            if (!fields.emplace(token.substr(0, equal), token.substr(equal + 1)).second) return false;
        }
        if (end == std::string::npos) break;
        offset = end + 1;
    }
    return true;
}

bool QueryRegion(HANDLE process, std::uint64_t address, MEMORY_BASIC_INFORMATION& info) {
    std::memset(&info, 0, sizeof(info));
    return VirtualQueryEx(process, reinterpret_cast<const void*>(address), &info, sizeof(info)) != 0;
}

bool ParseAllocation(const std::map<std::string, std::string>& fields, AllocationIdentity& identity) {
    std::uint64_t pid = 0;
    if (!ParseUnsigned(fields, "pid", pid) || !ParseUnsigned(fields, "creation", identity.processCreationTime) ||
        !ParseUnsigned(fields, "allocationBase", identity.allocationBase) ||
        !ParseUnsigned(fields, "address", identity.address) || !ParseUnsigned(fields, "bytes", identity.bytes) ||
        pid == 0 || pid > UINT32_MAX) return false;
    identity.pid = static_cast<std::uint32_t>(pid);
    return true;
}

bool ParseHeld(const std::map<std::string, std::string>& fields, HeldConfirmation& held) {
    if (!ParseAllocation(fields, held.target) || !ParseBool(fields, "agentLoaded", held.agentLoaded) ||
        !ParseBool(fields, "nativeRecoveryBranch", held.nativeRecoveryBranch) ||
        !ParseBool(fields, "statusHeld", held.statusHeld) ||
        !ParseBool(fields, "breakpointHit", held.breakpointHit) ||
        !ParseBool(fields, "heldComplete", held.heldComplete) ||
        !ParseUnsigned(fields, "eventPid", held.eventPid) || !ParseUnsigned(fields, "eventTid", held.eventTid) ||
        !ParseUnsigned(fields, "eventSerial", held.eventSerial) ||
        !ParseUnsigned(fields, "stateRevision", held.stateRevision) ||
        !RequiredText(fields, "ownerSampleId", held.ownerSampleId) ||
        !RequiredText(fields, "ownerSessionId", held.ownerSessionId) ||
        !RequiredText(fields, "ownerEpoch", held.ownerEpoch) ||
        !RequiredText(fields, "ownerBackendId", held.ownerBackendId) ||
        !RequiredText(fields, "groupId", held.groupId) || !RequiredText(fields, "stopId", held.stopId) ||
        !RequiredText(fields, "eventBackendId", held.eventBackendId)) return false;
    return true;
}

bool ParseRecovery(const std::map<std::string, std::string>& fields, RecoveryObservation& recovery) {
    std::uint64_t failureError = 0;
    if (!ParseMode(fields, recovery.mode) || !RequiredText(fields, "status", recovery.status) ||
        !ParseBool(fields, "firstRecoveryFailurePresent", recovery.firstRecoveryFailurePresent) ||
        !RequiredText(fields, "firstRecoveryFailureStage", recovery.firstRecoveryFailureStage) ||
        !ParseUnsigned(fields, "firstRecoveryFailureError", failureError) || failureError > UINT32_MAX ||
        !RequiredText(fields, "ownerSampleId", recovery.ownerSampleId) ||
        !RequiredText(fields, "ownerSessionId", recovery.ownerSessionId) ||
        !RequiredText(fields, "ownerEpoch", recovery.ownerEpoch) ||
        !RequiredText(fields, "ownerBackendId", recovery.ownerBackendId) ||
        !RequiredText(fields, "pendingEventBackendId", recovery.pendingEventBackendId) ||
        !ParseUnsigned(fields, "pendingEventSerial", recovery.pendingEventSerial) ||
        !RequiredText(fields, "releaseRequestId", recovery.releaseRequestId)) return false;
    recovery.firstRecoveryFailureError = static_cast<std::uint32_t>(failureError);
    return true;
}

int ChildMain(const wchar_t* mappingName) {
    Handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mappingName));
    if (!mapping.get()) return 2;
    auto* shared = static_cast<SharedState*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
    if (!shared) return 3;

    auto* page = static_cast<unsigned char*>(VirtualAlloc(nullptr, kAllocationBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!page) { UnmapViewOfFile(shared); return 4; }
    unsigned char code[13] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0x00, 0xC3};
    const std::uint64_t counter = reinterpret_cast<std::uint64_t>(&shared->counter);
    for (int index = 0; index < 8; ++index) code[2 + index] = static_cast<unsigned char>(counter >> (index * 8));
    std::memcpy(page, code, sizeof(code));
    shared->allocationBase = reinterpret_cast<LONGLONG>(page);
    shared->allocationAddress = reinterpret_cast<LONGLONG>(page);
    shared->allocationBytes = static_cast<LONGLONG>(kAllocationBytes);
    InterlockedExchange(&shared->ready, 1);
    while (!shared->go && !shared->stop) Sleep(1);
    if (!shared->stop) {
        reinterpret_cast<void(*)()>(page)();
        InterlockedExchange(&shared->done, 1);
    }
    while (!shared->stop) Sleep(5);
    VirtualFree(page, 0, MEM_RELEASE);
    UnmapViewOfFile(shared);
    return 0;
}

bool WaitReady(SharedState* shared) {
    const ULONGLONG deadline = GetTickCount64() + kDeadlineMs;
    while (GetTickCount64() < deadline) {
        if (shared->ready && shared->allocationBase && shared->allocationBytes) return true;
        Sleep(1);
    }
    return false;
}

bool SameAllocation(const AllocationIdentity& left, const AllocationIdentity& right) {
    return left.pid == right.pid && left.processCreationTime == right.processCreationTime &&
        left.allocationBase == right.allocationBase && left.address == right.address && left.bytes == right.bytes;
}

bool VerifyHeld(const HeldConfirmation& held, const AllocationIdentity& published) {
    return SameAllocation(held.target, published) && !held.agentLoaded && held.nativeRecoveryBranch && held.statusHeld &&
        held.breakpointHit && held.heldComplete && held.eventPid == published.pid && held.eventTid != 0 &&
        held.eventSerial != 0 && held.stateRevision != 0;
}

bool ReleasePublishedAllocation(HANDLE process, const AllocationIdentity& published,
    ReleaseObservation& observation) {
    MEMORY_BASIC_INFORMATION before{};
    if (!QueryRegion(process, published.address, before)) return false;
    observation.preState = before.State;
    observation.preAllocationBase = reinterpret_cast<std::uint64_t>(before.AllocationBase);
    observation.preRegionBytes = before.RegionSize;
    const bool exact = before.State == MEM_COMMIT && observation.preAllocationBase == published.allocationBase &&
        before.BaseAddress == reinterpret_cast<const void*>(published.address) &&
        before.RegionSize == published.bytes;
    if (!exact) return false;

    SetLastError(ERROR_SUCCESS);
    const BOOL freed = VirtualFreeEx(process, reinterpret_cast<void*>(published.allocationBase), 0, MEM_RELEASE);
    observation.freeSucceeded = freed != FALSE;
    observation.freeError = freed ? ERROR_SUCCESS : GetLastError();
    MEMORY_BASIC_INFORMATION after{};
    const bool queried = QueryRegion(process, published.address, after);
    observation.postState = queried ? after.State : 0;
    observation.postRegionBytes = queried ? after.RegionSize : 0;
    observation.regionVerifiedFree = observation.freeSucceeded && queried && after.State == MEM_FREE;
    return true;
}

void EmitRelease(const ReleaseObservation& observation, const AllocationIdentity& identity) {
    std::printf("RELEASE mode=%s freeSucceeded=%s freeError=%u preState=%u preAllocationBase=%llu "
        "preRegionBytes=%llu postState=%u postRegionBytes=%llu regionVerifiedFree=%s "
        "allocationBase=%llu address=%llu bytes=%llu\n", ModeName(observation.mode),
        observation.freeSucceeded ? "true" : "false", observation.freeError, observation.preState,
        static_cast<unsigned long long>(observation.preAllocationBase),
        static_cast<unsigned long long>(observation.preRegionBytes), observation.postState,
        static_cast<unsigned long long>(observation.postRegionBytes),
        observation.regionVerifiedFree ? "true" : "false",
        static_cast<unsigned long long>(identity.allocationBase), static_cast<unsigned long long>(identity.address),
        static_cast<unsigned long long>(identity.bytes));
    std::fflush(stdout);
}

void EmitRecovery(const RecoveryObservation& recovery) {
    std::printf("RECOVERY mode=%s status=%s firstRecoveryFailurePresent=%s "
        "firstRecoveryFailureStage=%s firstRecoveryFailureError=%u ownerSampleId=%s "
        "ownerSessionId=%s ownerEpoch=%s ownerBackendId=%s pendingEventBackendId=%s "
        "pendingEventSerial=%llu releaseRequestId=%s\n", ModeName(recovery.mode), recovery.status.c_str(),
        recovery.firstRecoveryFailurePresent ? "true" : "false", recovery.firstRecoveryFailureStage.c_str(),
        recovery.firstRecoveryFailureError, recovery.ownerSampleId.c_str(), recovery.ownerSessionId.c_str(),
        recovery.ownerEpoch.c_str(), recovery.ownerBackendId.c_str(), recovery.pendingEventBackendId.c_str(),
        static_cast<unsigned long long>(recovery.pendingEventSerial), recovery.releaseRequestId.c_str());
    std::fflush(stdout);
}

int RunServer() {
    const std::wstring mappingName = MappingName(GetCurrentProcessId());
    Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        sizeof(SharedState), mappingName.c_str()));
    if (!mapping.get()) { std::printf("ERROR stage=mapping win32=%lu\n", GetLastError()); return 1; }
    auto* shared = static_cast<SharedState*>(MapViewOfFile(mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
    if (!shared) { std::printf("ERROR stage=mappingView win32=%lu\n", GetLastError()); return 1; }
    std::memset(shared, 0, sizeof(SharedState));

    wchar_t executable[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, executable, MAX_PATH)) return 1;
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --target \"" + mappingName + L"\"";
    std::vector<wchar_t> commandLine(command.begin(), command.end());
    commandLine.push_back(L'\0');
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION processInfo{};
    if (!CreateProcessW(executable, commandLine.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &processInfo)) {
        std::printf("ERROR stage=targetCreate win32=%lu\n", GetLastError());
        return 1;
    }
    Handle process(processInfo.hProcess), thread(processInfo.hThread);
    ResumeThread(thread.get());
    if (!WaitReady(shared)) {
        InterlockedExchange(&shared->stop, 1);
        std::printf("ERROR stage=targetReady win32=%lu\n", GetLastError());
        return 1;
    }
    const AllocationIdentity ready{
        processInfo.dwProcessId, CreationTime(process.get()),
        static_cast<std::uint64_t>(shared->allocationBase), static_cast<std::uint64_t>(shared->allocationAddress),
        static_cast<std::uint64_t>(shared->allocationBytes)};
    std::printf("READY protocol=1 pid=%u creation=%llu allocationBase=%llu address=%llu bytes=%llu\n",
        ready.pid, static_cast<unsigned long long>(ready.processCreationTime),
        static_cast<unsigned long long>(ready.allocationBase), static_cast<unsigned long long>(ready.address),
        static_cast<unsigned long long>(ready.bytes));
    std::fflush(stdout);

    bool released = false;
    bool goIssued = false;
    bool recoveryReported = false;
    ControlMode mode = ControlMode::Continue;
    std::string line;
    while (std::getline(std::cin, line)) {
        std::string commandName;
        std::map<std::string, std::string> fields;
        if (!ParseFields(line, commandName, fields)) {
            std::printf("ERROR stage=protocol win32=%u\n", ERROR_INVALID_DATA); std::fflush(stdout); continue;
        }
        if (commandName == "GO" && !goIssued && !released) {
            InterlockedExchange(&shared->go, 1);
            goIssued = true;
            std::printf("GO_ACCEPTED pid=%u address=%llu\n", ready.pid,
                static_cast<unsigned long long>(ready.address));
            std::fflush(stdout);
            continue;
        }
        if (commandName == "HELD" && !released) {
            HeldConfirmation held;
            if (!goIssued || !ParseHeld(fields, held) || !VerifyHeld(held, ready) || !ParseMode(fields, mode)) {
                std::printf("ERROR stage=heldConfirmation win32=%u\n", ERROR_INVALID_DATA); std::fflush(stdout); continue;
            }
            ReleaseObservation observation;
            observation.mode = mode;
            if (!ReleasePublishedAllocation(process.get(), ready, observation)) {
                std::printf("ERROR stage=releasePrecondition win32=%lu\n", GetLastError()); std::fflush(stdout); continue;
            }
            observation.mode = mode;
            released = observation.regionVerifiedFree;
            EmitRelease(observation, ready);
            continue;
        }
        if (commandName == "RECOVERY" && released && !recoveryReported) {
            RecoveryObservation recovery;
            if (!ParseRecovery(fields, recovery) || recovery.mode != mode) {
                std::printf("ERROR stage=recoveryObservation win32=%u\n", ERROR_INVALID_DATA); std::fflush(stdout); continue;
            }
            recoveryReported = true;
            EmitRecovery(recovery);
            continue;
        }
        if (commandName == "STOP" && recoveryReported) {
            InterlockedExchange(&shared->stop, 1);
            const DWORD wait = WaitForSingleObject(process.get(), kDeadlineMs);
            std::printf("DONE childExitObserved=%s childExitCode=%lu executionCount=%lld\n",
                wait == WAIT_OBJECT_0 ? "true" : "false", wait == WAIT_OBJECT_0 ? [&]() { DWORD code = 0; GetExitCodeProcess(process.get(), &code); return code; }() : 0,
                static_cast<long long>(shared->counter));
            std::fflush(stdout);
            return wait == WAIT_OBJECT_0 ? 0 : 1;
        }
        if (commandName == "ABORT") {
            InterlockedExchange(&shared->stop, 1);
            return 2;
        }
        std::printf("ERROR stage=protocolState win32=%u\n", ERROR_INVALID_STATE);
        std::fflush(stdout);
    }
    InterlockedExchange(&shared->stop, 1);
    return 2;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wcscmp(argv[1], L"--target") == 0) return ChildMain(argv[2]);
    if (argc == 1 || (argc == 2 && std::wcscmp(argv[1], L"--serve") == 0)) return RunServer();
    std::fprintf(stderr, "用法：ReadyOwnerFailureTrigger.exe [--serve]\n");
    return 2;
}
