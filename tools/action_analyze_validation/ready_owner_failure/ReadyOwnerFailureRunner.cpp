#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "ReadyOwnerFailureRunner.h"

#include "../../../KswordCLI/ActionAnalyze/Control/NativeDebugOwner.h"

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <cwchar>

namespace native = ks::cli::action_analyze::control;
namespace fs = std::filesystem;

namespace ready_owner_failure {
namespace {

constexpr DWORD kDeadlineMs = 30000;
constexpr char kSampleId[] = "70000000-0000-4000-8000-000000000001";
constexpr char kSessionId[] = "70000000-0000-4000-8000-000000000002";
constexpr char kEpochId[] = "70000000-0000-4000-8000-000000000003";
constexpr char kBackendId[] = "70000000-0000-4000-8000-000000000004";

class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = nullptr; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }
    HANDLE get() const { return value_; }
    HANDLE release() { HANDLE value = value_; value_ = nullptr; return value; }
    void reset(HANDLE value = nullptr) {
        if (value_) CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

struct TriggerProcess {
    Handle process;
    Handle input;
    Handle output;

    TriggerProcess() = default;
    TriggerProcess(const TriggerProcess&) = delete;
    TriggerProcess& operator=(const TriggerProcess&) = delete;
    TriggerProcess(TriggerProcess&&) noexcept = default;
    TriggerProcess& operator=(TriggerProcess&&) noexcept = default;

    void Abort() const {
        if (!input.get()) return;
        const char command[] = "ABORT\n";
        DWORD written = 0;
        (void)WriteFile(input.get(), command, static_cast<DWORD>(sizeof(command) - 1), &written, nullptr);
    }
};

struct Receipt final {
    std::vector<std::string> lines;
    void Add(std::string line) {
        std::printf("%s\n", line.c_str());
        std::fflush(stdout);
        lines.push_back(std::move(line));
    }
    void AddCheck(const char* name, bool passed) {
        Add(std::string("CHECK ") + (passed ? "PASS " : "FAIL ") + name);
        if (!passed) throw std::runtime_error(name);
    }
};

std::string Number(std::uint64_t value) { return std::to_string(value); }

std::string Bool(bool value) { return value ? "true" : "false"; }

bool ParseUnsigned(const std::map<std::string, std::string>& fields, const char* name,
    std::uint64_t& value) {
    const auto it = fields.find(name);
    if (it == fields.end() || it->second.empty()) return false;
    const auto* first = it->second.data();
    const auto* last = first + it->second.size();
    const auto parsed = std::from_chars(first, last, value, 10);
    return parsed.ec == std::errc{} && parsed.ptr == last;
}

bool ParseBool(const std::map<std::string, std::string>& fields, const char* name, bool& value) {
    const auto it = fields.find(name);
    if (it == fields.end()) return false;
    if (it->second == "true") { value = true; return true; }
    if (it->second == "false") { value = false; return true; }
    return false;
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
        const auto token = line.substr(offset, end == std::string::npos ? line.size() - offset : end - offset);
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

bool ReadLine(HANDLE pipe, std::string& line) {
    line.clear();
    const ULONGLONG deadline = GetTickCount64() + kDeadlineMs;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) return false;
        if (!available) {
            if (GetTickCount64() >= deadline) return false;
            Sleep(1);
            continue;
        }
        char byte = 0;
        DWORD read = 0;
        if (!ReadFile(pipe, &byte, 1, &read, nullptr) || read != 1) return false;
        if (byte == '\n') return true;
        if (byte != '\r') line.push_back(byte);
    }
}

void Send(HANDLE pipe, std::string_view command) {
    std::string line(command);
    line.push_back('\n');
    DWORD written = 0;
    if (!WriteFile(pipe, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) ||
        written != line.size()) throw std::runtime_error("trigger-write");
}

fs::path CurrentModule() {
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!length || length >= MAX_PATH) throw std::runtime_error("runner-module-path");
    return fs::path(path);
}

TriggerProcess StartTrigger(const fs::path& executable) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    HANDLE childRead = nullptr;
    HANDLE parentWrite = nullptr;
    HANDLE parentRead = nullptr;
    HANDLE childWrite = nullptr;
    if (!CreatePipe(&childRead, &parentWrite, &attributes, 0) ||
        !CreatePipe(&parentRead, &childWrite, &attributes, 0)) {
        if (childRead) CloseHandle(childRead);
        if (parentWrite) CloseHandle(parentWrite);
        if (parentRead) CloseHandle(parentRead);
        if (childWrite) CloseHandle(childWrite);
        throw std::runtime_error("trigger-pipe");
    }
    if (!SetHandleInformation(parentWrite, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(parentRead, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(childRead); CloseHandle(parentWrite); CloseHandle(parentRead); CloseHandle(childWrite);
        throw std::runtime_error("trigger-pipe-inherit");
    }

    std::wstring command = L"\"" + executable.wstring() + L"\" --serve";
    std::vector<wchar_t> commandLine(command.begin(), command.end());
    commandLine.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = childRead;
    startup.hStdOutput = childWrite;
    startup.hStdError = childWrite;
    PROCESS_INFORMATION processInfo{};
    const BOOL created = CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &processInfo);
    CloseHandle(childRead);
    CloseHandle(childWrite);
    if (!created) {
        CloseHandle(parentWrite); CloseHandle(parentRead);
        throw std::runtime_error("trigger-create");
    }
    TriggerProcess result;
    result.process.reset(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
    result.input.reset(parentWrite);
    result.output.reset(parentRead);
    return result;
}

AllocationIdentity ParseReady(const std::string& line) {
    std::string command;
    std::map<std::string, std::string> fields;
    if (!ParseFields(line, command, fields) || command != "READY") throw std::runtime_error("ready-line");
    std::uint64_t pid = 0;
    AllocationIdentity identity;
    if (!ParseUnsigned(fields, "pid", pid) || !ParseUnsigned(fields, "creation", identity.processCreationTime) ||
        !ParseUnsigned(fields, "allocationBase", identity.allocationBase) ||
        !ParseUnsigned(fields, "address", identity.address) || !ParseUnsigned(fields, "bytes", identity.bytes) ||
        !pid || pid > UINT32_MAX || !identity.processCreationTime || !identity.allocationBase ||
        !identity.address || !identity.bytes) throw std::runtime_error("ready-fields");
    identity.pid = static_cast<std::uint32_t>(pid);
    return identity;
}

bool SameAllocation(const AllocationIdentity& left, const AllocationIdentity& right) {
    return left.pid == right.pid && left.processCreationTime == right.processCreationTime &&
        left.allocationBase == right.allocationBase && left.address == right.address && left.bytes == right.bytes;
}

native::ReleaseRequest MakeRelease(const native::OwnerIdentity& owner,
    const native::NativeControlResult& stop, std::string requestId) {
    native::ReleaseRequest request;
    request.owner = owner;
    request.groupId = stop.group ? stop.group->groupId : std::string();
    request.stopId = stop.responsibility ? stop.responsibility->stopId : std::string();
    request.event = stop.pending ? stop.pending->event : native::NativeEventKey{};
    request.requestId = std::move(requestId);
    request.expectedStateRevision = stop.group ? stop.group->stateRevision : 0;
    return request;
}

native::NativeStepRequest MakeStep(const native::OwnerIdentity& owner,
    const native::NativeControlResult& stop, std::string requestId) {
    native::NativeStepRequest request;
    request.release = MakeRelease(owner, stop, std::move(requestId));
    if (!stop.pending || !stop.responsibility) throw std::runtime_error("step-origin");
    for (const auto& frozen : stop.frozenThreads) {
        if (frozen.tid == stop.pending->tid && frozen.identity == stop.responsibility->actualEventThread) {
            request.thread = frozen.identity;
            request.tid = frozen.tid;
            request.threadCreationTime = frozen.creationTime;
            break;
        }
    }
    request.mode = native::NativeStepMode::Into;
    if (request.tid == 0 || request.threadCreationTime == 0) throw std::runtime_error("step-thread");
    return request;
}

native::NativeControlResult WaitBinding(native::NativeDebugOwner& owner,
    native::NativeBreakpointState expected) {
    native::NativeControlResult result;
    const ULONGLONG deadline = GetTickCount64() + kDeadlineMs;
    while (GetTickCount64() < deadline) {
        result = owner.Query();
        if (result.breakpoint && (result.breakpoint->state == expected ||
            result.breakpoint->state == native::NativeBreakpointState::Rejected ||
            result.breakpoint->state == native::NativeBreakpointState::RecoveryRequired)) return result;
        Sleep(1);
    }
    return result;
}

native::NativeControlResult WaitStep(native::NativeDebugOwner& owner, std::string_view requestId) {
    native::NativeControlResult result;
    const ULONGLONG deadline = GetTickCount64() + kDeadlineMs;
    while (GetTickCount64() < deadline) {
        result = owner.QueryStep(requestId);
        if (result.step && result.step->state != native::NativeStepState::Running) return result;
        Sleep(1);
    }
    return result;
}

native::NativeControlResult WaitRecovery(native::NativeDebugOwner& owner) {
    native::NativeControlResult result;
    const ULONGLONG deadline = GetTickCount64() + kDeadlineMs;
    while (GetTickCount64() < deadline) {
        result = owner.Query();
        if (result.firstRecoveryFailure.has_value()) return result;
        Sleep(1);
    }
    return result;
}

native::NativeControlResult WaitClean(native::NativeDebugOwner& owner) {
    native::NativeControlResult result;
    const ULONGLONG deadline = GetTickCount64() + kDeadlineMs;
    while (GetTickCount64() < deadline) {
        result = owner.Query();
        if (result.clean && !result.attached) return result;
        Sleep(1);
    }
    return result;
}

HeldConfirmation BuildHeld(const AllocationIdentity& ready, const native::OwnerIdentity& owner,
    const native::NativeControlResult& held) {
    HeldConfirmation confirmation;
    confirmation.target = ready;
    confirmation.agentLoaded = false;
    confirmation.nativeRecoveryBranch = true;
    confirmation.statusHeld = held.status == native::NativeControlStatus::Held;
    confirmation.breakpointHit = held.breakpointHit && held.breakpointHit->address == ready.address;
    confirmation.heldComplete = held.group && !held.group->historical &&
        held.group->state == native::GroupState::HeldComplete;
    if (held.pending) {
        confirmation.eventPid = held.pending->pid;
        confirmation.eventTid = held.pending->tid;
        confirmation.eventSerial = held.pending->event.serial;
        confirmation.eventBackendId = held.pending->event.backendInstanceId;
    }
    if (held.group) {
        confirmation.stateRevision = held.group->stateRevision;
        confirmation.groupId = held.group->groupId;
    }
    if (held.responsibility) confirmation.stopId = held.responsibility->stopId;
    confirmation.ownerSampleId = owner.sampleId;
    confirmation.ownerSessionId = owner.sessionId;
    confirmation.ownerEpoch = owner.epoch;
    confirmation.ownerBackendId = owner.backendInstanceId;
    return confirmation;
}

std::string HeldCommand(const HeldConfirmation& held, ControlMode mode) {
    return "HELD mode=" + std::string(mode == ControlMode::Step ? "step" : "continue") +
        " agentLoaded=" + Bool(held.agentLoaded) +
        " nativeRecoveryBranch=" + Bool(held.nativeRecoveryBranch) +
        " statusHeld=" + Bool(held.statusHeld) + " breakpointHit=" + Bool(held.breakpointHit) +
        " heldComplete=" + Bool(held.heldComplete) + " pid=" + Number(held.target.pid) +
        " creation=" + Number(held.target.processCreationTime) +
        " allocationBase=" + Number(held.target.allocationBase) + " address=" + Number(held.target.address) +
        " bytes=" + Number(held.target.bytes) + " eventPid=" + Number(held.eventPid) +
        " eventTid=" + Number(held.eventTid) + " eventSerial=" + Number(held.eventSerial) +
        " stateRevision=" + Number(held.stateRevision) + " ownerSampleId=" + held.ownerSampleId +
        " ownerSessionId=" + held.ownerSessionId + " ownerEpoch=" + held.ownerEpoch +
        " ownerBackendId=" + held.ownerBackendId + " groupId=" + held.groupId + " stopId=" + held.stopId +
        " eventBackendId=" + held.eventBackendId;
}

void Persist(const fs::path& path, const Receipt& receipt) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("receipt-open");
    for (const auto& line : receipt.lines) output << line << '\n';
    if (!output) throw std::runtime_error("receipt-write");
}

} // namespace

int RunNativeOwnerFailure(ControlMode mode, const fs::path& receiptPath) {
    Receipt receipt;
    std::unique_ptr<TriggerProcess> trigger;
    std::unique_ptr<native::NativeDebugOwner> owner;
    try {
        const auto triggerPath = CurrentModule().parent_path() / L"ActionAnalyzeReadyOwnerFailureTrigger.exe";
        trigger = std::make_unique<TriggerProcess>(StartTrigger(triggerPath));
        std::string line;
        receipt.AddCheck("trigger-started", ReadLine(trigger->output.get(), line));
        const auto ready = ParseReady(line);
        receipt.Add("READY pid=" + Number(ready.pid) + " creation=" + Number(ready.processCreationTime) +
            " allocationBase=" + Number(ready.allocationBase) + " address=" + Number(ready.address) +
            " bytes=" + Number(ready.bytes));

        native::OwnerIdentity ownerId{kSampleId, kSessionId, kEpochId, kBackendId};
        owner = std::make_unique<native::NativeDebugOwner>(ownerId);
        native::NativeBreakpointRequest request;
        request.target.requestId = "ready-owner-failure-target";
        request.target.pid = ready.pid;
        request.target.processCreationTime = ready.processCreationTime;
        request.target.explicitlyAuthorized = true;
        request.target.disposition = native::NativeTargetDisposition::ResumeAndDetach;
        request.privateAddress = ready.address;
        request.privateRangeBytes = ready.bytes;
        const auto accepted = owner->ArmBreakpoint(request);
        receipt.AddCheck("arm-accepted", accepted.status == native::NativeControlStatus::Accepted && accepted.breakpoint);
        const auto armed = WaitBinding(*owner, native::NativeBreakpointState::Armed);
        receipt.AddCheck("armed-from-native-owner", armed.breakpoint &&
            armed.breakpoint->state == native::NativeBreakpointState::Armed &&
            armed.breakpoint->address == ready.address && armed.breakpoint->rangeBytes == ready.bytes);

        Send(trigger->input.get(), "GO");
        receipt.AddCheck("go-accepted", ReadLine(trigger->output.get(), line) && line.starts_with("GO_ACCEPTED"));
        const auto held = WaitBinding(*owner, native::NativeBreakpointState::Held);
        const auto confirmation = BuildHeld(ready, ownerId, held);
        receipt.AddCheck("native-held-status", confirmation.statusHeld);
        receipt.AddCheck("native-held-identity", SameAllocation(confirmation.target, ready));
        receipt.AddCheck("native-held-page-hit", confirmation.breakpointHit);
        receipt.AddCheck("native-held-group", confirmation.heldComplete);
        receipt.AddCheck("native-held-event", confirmation.eventPid == ready.pid && confirmation.eventTid != 0 &&
            confirmation.eventSerial != 0 && !confirmation.eventBackendId.empty());
        receipt.AddCheck("native-owner-identity", confirmation.ownerSampleId == ownerId.sampleId &&
            confirmation.ownerSessionId == ownerId.sessionId && confirmation.ownerEpoch == ownerId.epoch &&
            confirmation.ownerBackendId == ownerId.backendInstanceId);
        receipt.AddCheck("native-recovery-branch", !confirmation.agentLoaded && confirmation.nativeRecoveryBranch);
        receipt.Add("OWNER_HELD processInstanceId=" + held.processInstanceId +
            " pid=" + Number(held.pid) + " creation=" + Number(held.processCreationTime) +
            " groupId=" + (held.group ? held.group->groupId : "") +
            " stateRevision=" + Number(held.group ? held.group->stateRevision : 0) +
            " responsibilityGroupId=" + (held.responsibility ? held.responsibility->groupId : "") +
            " stopId=" + (held.responsibility ? held.responsibility->stopId : "") +
            " pendingEventBackendId=" + (held.pending ? held.pending->event.backendInstanceId : "") +
            " pendingEventSerial=" + Number(held.pending ? held.pending->event.serial : 0) +
            " breakpointState=" + std::to_string(held.breakpoint ? static_cast<int>(held.breakpoint->state) : -1) +
            " breakpointAddress=" + Number(held.breakpoint ? held.breakpoint->address : 0) +
            " breakpointRangeBytes=" + Number(held.breakpoint ? held.breakpoint->rangeBytes : 0) +
            " breakpointHitAddress=" + Number(held.breakpointHit ? held.breakpointHit->address : 0) +
            " releaseRequestId=" + (held.releaseRequestId ? *held.releaseRequestId : "none"));

        Send(trigger->input.get(), HeldCommand(confirmation, mode));
        const bool releaseRead = ReadLine(trigger->output.get(), line);
        receipt.AddCheck("release-receipt", releaseRead);
        if (releaseRead) receipt.Add(line);
        std::string releaseCommand;
        std::map<std::string, std::string> releaseFields;
        receipt.AddCheck("release-fields", ParseFields(line, releaseCommand, releaseFields) && releaseCommand == "RELEASE");
        bool freeSucceeded = false, regionVerifiedFree = false;
        std::uint64_t freeError = 0, postState = 0;
        receipt.AddCheck("release-exact-free", ParseBool(releaseFields, "freeSucceeded", freeSucceeded) && freeSucceeded &&
            ParseBool(releaseFields, "regionVerifiedFree", regionVerifiedFree) && regionVerifiedFree &&
            ParseUnsigned(releaseFields, "freeError", freeError) && freeError == 0 &&
            ParseUnsigned(releaseFields, "postState", postState) && postState == MEM_FREE);

        native::NativeControlResult action;
        std::string releaseRequestId;
        if (mode == ControlMode::Continue) {
            releaseRequestId = "continue/1";
            action = owner->Continue(MakeRelease(ownerId, held, releaseRequestId));
        } else {
            releaseRequestId = "step/1";
            action = owner->Step(MakeStep(ownerId, held, releaseRequestId));
            receipt.AddCheck("step-submitted", action.status != native::NativeControlStatus::Rejected);
            const auto step = WaitStep(*owner, releaseRequestId);
            receipt.AddCheck("step-finished", step.step && step.step->state != native::NativeStepState::Running);
        }
        const auto actionState = owner->Query();
        receipt.Add("OWNER_ACTION status=" + std::to_string(static_cast<int>(actionState.status)) +
            " processInstanceId=" + actionState.processInstanceId +
            " groupId=" + (actionState.group ? actionState.group->groupId : "") +
            " responsibilityGroupId=" + (actionState.responsibility ? actionState.responsibility->groupId : "") +
            " pendingEventBackendId=" + (actionState.pending ? actionState.pending->event.backendInstanceId : "") +
            " pendingEventSerial=" + Number(actionState.pending ? actionState.pending->event.serial : 0) +
            " releaseRequestId=" + (actionState.releaseRequestId ? *actionState.releaseRequestId : releaseRequestId));
        const auto recovery = WaitRecovery(*owner);
        receipt.AddCheck("production-recovery-failure", recovery.firstRecoveryFailure.has_value());
        const auto& failure = *recovery.firstRecoveryFailure;
        receipt.Add("OWNER_RECOVERY status=" + std::to_string(static_cast<int>(recovery.status)) +
            " stage=" + failure.stage + " error=" + Number(failure.win32Error) +
            " pendingEventBackendId=" + (failure.pendingEvent ? failure.pendingEvent->backendInstanceId : "") +
            " pendingEventSerial=" + Number(failure.pendingEvent ? failure.pendingEvent->serial : 0) +
            " releaseRequestId=" + (failure.releaseRequestId ? *failure.releaseRequestId : releaseRequestId));

        const std::string recoveryCommand = "RECOVERY mode=" + std::string(mode == ControlMode::Step ? "step" : "continue") +
            " status=" + std::to_string(static_cast<int>(recovery.status)) +
            " firstRecoveryFailurePresent=true firstRecoveryFailureStage=" + failure.stage +
            " firstRecoveryFailureError=" + Number(failure.win32Error) + " ownerSampleId=" + failure.owner.sampleId +
            " ownerSessionId=" + failure.owner.sessionId + " ownerEpoch=" + failure.owner.epoch +
            " ownerBackendId=" + failure.owner.backendInstanceId +
            " pendingEventBackendId=" + (failure.pendingEvent ? failure.pendingEvent->backendInstanceId : "none") +
            " pendingEventSerial=" + Number(failure.pendingEvent ? failure.pendingEvent->serial : 0) +
            " releaseRequestId=" + (failure.releaseRequestId ? *failure.releaseRequestId : releaseRequestId);
        Send(trigger->input.get(), recoveryCommand);
        const bool recoveryRead = ReadLine(trigger->output.get(), line);
        if (recoveryRead) receipt.Add(line);
        receipt.AddCheck("recovery-serialized", recoveryRead && line.starts_with("RECOVERY"));

        const auto closed = owner->Close();
        receipt.AddCheck("owner-close-requested", closed.status == native::NativeControlStatus::Closed ||
            closed.status == native::NativeControlStatus::ClosePending || closed.status == native::NativeControlStatus::RecoveryRequired);
        const auto afterClose = WaitClean(*owner);
        receipt.Add("OWNER_CLEAN status=" + std::to_string(static_cast<int>(afterClose.status)) +
            " clean=" + Bool(afterClose.clean) + " attached=" + Bool(afterClose.attached) +
            " firstRecoveryFailurePresent=" + Bool(afterClose.firstRecoveryFailure.has_value()));
        receipt.AddCheck("owner-cleanup-evidence", afterClose.clean && afterClose.firstRecoveryFailure.has_value());
        Send(trigger->input.get(), "STOP");
        receipt.AddCheck("trigger-cleanup", ReadLine(trigger->output.get(), line) && line.starts_with("DONE"));
        receipt.Add("RESULT mode=" + std::string(mode == ControlMode::Step ? "step" : "continue") + " status=PASS");
        Persist(receiptPath, receipt);
        return 0;
    } catch (const std::exception& error) {
        receipt.Add(std::string("RESULT status=FAIL reason=") + error.what());
        if (trigger) trigger->Abort();
        if (owner) {
            (void)owner->Close();
        }
        try { Persist(receiptPath, receipt); } catch (...) {}
        return 1;
    }
}

} // namespace ready_owner_failure

int wmain(int argc, wchar_t** argv) {
    ready_owner_failure::ControlMode mode = ready_owner_failure::ControlMode::Continue;
    std::filesystem::path receiptPath = std::filesystem::current_path() / L"ready-owner-failure-receipt.txt";
    for (int index = 1; index < argc; ++index) {
        if (std::wcscmp(argv[index], L"--step") == 0) mode = ready_owner_failure::ControlMode::Step;
        else if (std::wcscmp(argv[index], L"--continue") == 0) mode = ready_owner_failure::ControlMode::Continue;
        else if (std::wcscmp(argv[index], L"--receipt") == 0 && index + 1 < argc) receiptPath = argv[++index];
        else {
            std::fwprintf(stderr, L"usage: ReadyOwnerFailureRunner.exe [--continue|--step] [--receipt path]\n");
            return 2;
        }
    }
    return ready_owner_failure::RunNativeOwnerFailure(mode, receiptPath);
}
