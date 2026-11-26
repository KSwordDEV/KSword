// Versioned native execution evidence acceptance for the production owner + project reader.
//
// This fixture is a self-created benign cooperative child of this process. It runs a
// fixed MASM sequence (NativeExecutionFixture.asm) with known instruction boundaries so
// each accepted document is checked against a real DR0 event, a real SINGLE_STEP
// completion, the actual event thread, the observed QPC and the on-disk SHA-256.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <TlHelp32.h>

#include "../../../KswordCLI/ActionAnalyze/Control/NativeDebugOwner.h"
#include "../../../KswordCLI/ActionAnalyze/Control/NativeExecutionEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectNativeExecution.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentBodies.h"
#include "../../../shared/evidence/EvidenceJson.h"
#include "NativeExecutionFixture.h"

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace native = ks::cli::action_analyze::control;
namespace archive = ks::cli::action_analyze::archive;
namespace evidence = Ksword::Evidence;
namespace aa = Ksword::ActionAnalyze;
namespace fs = std::filesystem;

// 数据写入停点验证使用的自有导出。仅本验证 EXE 使用，子进程在协调者放行后自增。
extern "C" __declspec(dllexport) volatile LONG g_nativeExecutionWriteWatch = 1;

namespace {

constexpr DWORD kDeadlineMs = 30000;
constexpr DWORD kFixtureExitCode = 0;
constexpr unsigned kFlagLoop = 1u << 0;
constexpr unsigned kFlagWrite = 1u << 1;

enum EventIndex { kGo = 0, kReady = 1, kDone = 2, kExit = 3, kPulse = 4, kAck = 5, kEventCount = 6 };

const char* const kSessionId = "20000000-0000-4000-8000-000000000001";
const char* const kEpochId = "20000000-0000-4000-8000-000000000002";
const char* const kBackendId = "20000000-0000-4000-8000-000000000003";
const char* const kWrongId = "20000000-0000-4000-8000-0000000000ff";

unsigned checks = 0;
unsigned failures = 0;

std::FILE* g_childLog = nullptr;
std::wstring g_diagDir;

void Require(bool condition, const char* what) {
    ++checks;
    if (!condition) {
        ++failures;
        std::fprintf(stderr, "FAIL %s win32=%lu\n", what, GetLastError());
        throw std::runtime_error(what);
    }
}

class Handle {
public:
    explicit Handle(HANDLE handle = nullptr) : handle_(handle) {}
    ~Handle() { if (handle_) { CloseHandle(handle_); } }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE Get() const { return handle_; }
    void Reset(HANDLE value = nullptr) {
        if (handle_) { CloseHandle(handle_); }
        handle_ = value;
    }
private:
    HANDLE handle_;
};

std::wstring Wide(const std::string& text) { return {text.begin(), text.end()}; }

std::string ReadFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) { throw std::runtime_error("fixture-read-file"); }
    return {std::istreambuf_iterator<char>(input), {}};
}

void WriteFile(const fs::path& path, std::string_view bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!output) { throw std::runtime_error("fixture-write-file"); }
}

std::string Sha256Hex(std::string_view bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    DWORD objectBytes = 0;
    DWORD returned = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectBytes),
            static_cast<ULONG>(sizeof(objectBytes)), &returned, 0) < 0) {
        if (algorithm) { BCryptCloseAlgorithmProvider(algorithm, 0); }
        throw std::runtime_error("fixture-sha-open");
    }
    std::vector<unsigned char> object(objectBytes);
    BCRYPT_HASH_HANDLE hash = nullptr;
    unsigned char digest[32]{};
    const auto input = const_cast<PUCHAR>(reinterpret_cast<const unsigned char*>(bytes.data()));
    const bool ok = BCryptCreateHash(algorithm, &hash, object.data(), objectBytes, nullptr, 0, 0) >= 0 &&
        BCryptHashData(hash, input, static_cast<ULONG>(bytes.size()), 0) >= 0 &&
        BCryptFinishHash(hash, digest, static_cast<ULONG>(sizeof(digest)), 0) >= 0;
    if (hash) { BCryptDestroyHash(hash); }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok) { throw std::runtime_error("fixture-sha"); }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string text;
    text.reserve(64);
    for (const unsigned char byte : digest) {
        text.push_back(kHex[byte >> 4]);
        text.push_back(kHex[byte & 0xf]);
    }
    return text;
}

fs::path SampleDir(const fs::path& root, const std::string& sample) {
    return root / L"samples" / Wide(sample);
}

fs::path SegmentPath(const fs::path& root, const std::string& sample, std::uint64_t ordinal,
    const wchar_t* streamDirectory) {
    std::wostringstream name;
    name << std::setw(20) << std::setfill(L'0') << ordinal << L".ksaseg";
    return SampleDir(root, sample) / streamDirectory / name.str();
}

std::map<std::string, std::string> TreeHashes(const fs::path& root) {
    std::map<std::string, std::string> result;
    if (!fs::exists(root)) { return result; }
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) { continue; }
        const auto relative = entry.path().lexically_relative(root).generic_string();
        result.emplace(relative, Sha256Hex(ReadFile(entry.path())));
    }
    return result;
}

void ChildLog(const char* format, ...) {
    if (!g_childLog) { return; }
    va_list arguments;
    va_start(arguments, format);
    std::vfprintf(g_childLog, format, arguments);
    va_end(arguments);
    std::fputc('\n', g_childLog);
    std::fflush(g_childLog);
}

DWORD WINAPI PeerThread(void* context) {
    auto* const events = static_cast<HANDLE*>(context);
    const HANDLE waits[]{events[kPulse], events[kExit]};
    for (;;) {
        const auto result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (result != WAIT_OBJECT_0) { break; }
        SetEvent(events[kAck]);
    }
    return 0;
}

int ChildMain(unsigned flags, wchar_t** args) {
    HANDLE events[kEventCount]{};
    for (int i = 0; i < kEventCount; ++i) {
        events[i] = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(args[i], nullptr, 10)));
    }
    std::FILE* log = nullptr;
    if (_wfopen_s(&log, args[kEventCount], L"a") != 0 || !log) { return 6; }
    g_childLog = log;
    ChildLog("CHILD_START flags=0x%x main=%u", flags, static_cast<unsigned int>(GetCurrentThreadId()));
    const auto peer = CreateThread(nullptr, 0, PeerThread, events, 0, nullptr);
    if (!peer) { return 2; }
    ChildLog("CHILD_PEER tid=%u", static_cast<unsigned int>(GetThreadId(peer)));
    SetEvent(events[kReady]);
    if (WaitForSingleObject(events[kGo], INFINITE) != WAIT_OBJECT_0) { return 2; }
    if (flags & kFlagWrite) {
        InterlockedIncrement(&g_nativeExecutionWriteWatch);
        ChildLog("CHILD_WROTE_WATCH value=%ld", static_cast<long>(g_nativeExecutionWriteWatch));
    } else {
        const unsigned rounds = (flags & kFlagLoop) ? 2u : 1u;
        for (unsigned round = 0; round < rounds; ++round) {
            ChildLog("CHILD_FIXTURE round=%u", round);
            FixtureEnter();
        }
    }
    SetEvent(events[kDone]);
    ChildLog("CHILD_DONE");
    if (WaitForSingleObject(events[kExit], INFINITE) != WAIT_OBJECT_0) { return 2; }
    WaitForSingleObject(peer, 5000);
    CloseHandle(peer);
    if (log) { std::fclose(log); }
    return 0;
}

class ChildFixture {
public:
    ChildFixture(const std::wstring& executable, unsigned flags) : job_(CreateJobObjectW(nullptr, nullptr)) {
        Require(job_.Get() != nullptr, "fixture-job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Require(SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "fixture-job-limits");
        std::wstring command = L"\"" + executable + L"\" --child " + std::to_wstring(flags);
        HANDLE inherited[kEventCount]{};
        for (int i = 0; i < kEventCount; ++i) {
            inherited[i] = events_[i].Get();
            command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(inherited[i]));
        }
        command += L" \"" + LogPath() + L"\"";
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
        Require(bytes != 0, "fixture-attribute-size");
        std::vector<std::uintptr_t> storage((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Require(InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes) != FALSE,
            "fixture-attribute-list");
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr) != FALSE, "fixture-inherited-handles");
        auto job = job_.Get();
        Require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job, sizeof(job), nullptr, nullptr) != FALSE, "fixture-create-time-job");
        PROCESS_INFORMATION process{};
        const auto created = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
            &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        Require(created != FALSE, "fixture-create");
        const Handle initialThread(process.hThread);
        process_.Reset(process.hProcess);
        pid = process.dwProcessId;
        BOOL inJob = FALSE;
        Require(IsProcessInJob(process_.Get(), job_.Get(), &inJob) && inJob, "fixture-in-job");
        Require(ResumeThread(initialThread.Get()) == 1, "fixture-resume");
        Require(WaitForSingleObject(events_[kReady].Get(), kDeadlineMs) == WAIT_OBJECT_0, "fixture-ready");
        FILETIME creation{}, exited{}, kernel{}, user{};
        Require(GetProcessTimes(process_.Get(), &creation, &exited, &kernel, &user) != FALSE, "fixture-times");
        creationTime = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    }

    ~ChildFixture() {
        if (process_.Get() && WaitForSingleObject(process_.Get(), 0) == WAIT_TIMEOUT) {
            TerminateProcess(process_.Get(), 99);
            WaitForSingleObject(process_.Get(), 5000);
        }
    }

    void Signal(int index) const { Require(SetEvent(events_[index].Get()) != FALSE, "fixture-signal"); }
    bool Wait(int index, DWORD limit) const {
        return WaitForSingleObject(events_[index].Get(), limit) == WAIT_OBJECT_0;
    }
    bool WaitExit(DWORD limit) const { return WaitForSingleObject(process_.Get(), limit) == WAIT_OBJECT_0; }
    DWORD ExitCode() const {
        DWORD code = 0;
        GetExitCodeProcess(process_.Get(), &code);
        return code;
    }
    void Terminate() {
        if (process_.Get() && WaitForSingleObject(process_.Get(), 0) == WAIT_TIMEOUT) {
            TerminateProcess(process_.Get(), 99);
            WaitForSingleObject(process_.Get(), 5000);
        }
    }

    DWORD pid = 0;
    std::uint64_t creationTime = 0;

private:
    static HANDLE InheritedEvent(bool manualReset = true) {
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
        const auto event = CreateEventW(&attributes, manualReset, FALSE, nullptr);
        Require(event != nullptr, "fixture-event");
        return event;
    }

    std::wstring LogPath() const {
        const auto directory = g_diagDir.empty() ? std::wstring(L".") : g_diagDir;
        std::wostringstream path;
        path << directory << L"\\native-exec-child-" << GetCurrentProcessId() << L"-" << nextLog_++ << L".log";
        return path.str();
    }

    static inline unsigned nextLog_ = 0;
    Handle job_;
    Handle process_;
    Handle events_[kEventCount]{Handle(InheritedEvent()), Handle(InheritedEvent()), Handle(InheritedEvent()),
        Handle(InheritedEvent()), Handle(InheritedEvent(false)), Handle(InheritedEvent())};
};

const native::NativeFrozenThread& OriginOf(const native::NativeControlResult& stop) {
    Require(stop.pending && stop.responsibility, "stop-has-origin");
    for (const auto& thread : stop.frozenThreads) {
        if (thread.tid == stop.pending->tid && thread.identity == stop.responsibility->actualEventThread) {
            return thread;
        }
    }
    throw std::runtime_error("origin-thread-missing");
}

class LiveSession {
public:
    LiveSession(const std::wstring& executable, unsigned flags, const std::string& sampleId)
        : fixture_(executable, flags),
          owner_({sampleId, kSessionId, kEpochId, kBackendId}) {
        modulePath_ = CurrentModulePath();
        pause_ = {"native-execution-acceptance", fixture_.pid, fixture_.creationTime, true,
            native::NativeTargetDisposition::ResumeAndDetach};
        request_.target = pause_;
        request_.modulePath = modulePath_;
    }

    ~LiveSession() {
        if (!closed_) {
            (void)owner_.Close();
            if (!WaitClean(2000)) { fixture_.Terminate(); }
        }
    }

    native::NativeControlResult ArmRva(std::uint32_t rva) {
        request_.rva = rva;
        request_.exportName.clear();
        request_.writeWatchBytes = 0;
        request_.writeWatchPointerExport = false;
        dataWatch_ = false;
        const auto accepted = owner_.ArmBreakpoint(request_);
        if (accepted.status != native::NativeControlStatus::Accepted || !accepted.breakpoint) {
            std::fprintf(stderr, "ARM_REJECTED stage=%s error=%u status=%d\n", accepted.stage,
                accepted.win32Error, static_cast<int>(accepted.status));
        }
        Require(accepted.status == native::NativeControlStatus::Accepted && accepted.breakpoint, "arm-accepted");
        armed_ = WaitBreakpoint(native::NativeBreakpointState::Armed);
        Require(armed_.breakpoint->address == armed_.breakpoint->moduleBase + rva, "armed-rva-address");
        Require(armed_.breakpoint->state == native::NativeBreakpointState::Armed, "armed-state");
        return armed_;
    }

    native::NativeControlResult ArmData(std::string_view exportName, std::uint32_t width) {
        request_.rva.reset();
        request_.exportName.assign(exportName);
        request_.writeWatchBytes = width;
        request_.writeWatchPointerExport = false;
        dataWatch_ = true;
        const auto accepted = owner_.ArmBreakpoint(request_);
        Require(accepted.status == native::NativeControlStatus::Accepted && accepted.breakpoint, "arm-data-accepted");
        armed_ = WaitBreakpoint(native::NativeBreakpointState::Armed);
        Require(armed_.breakpoint->address != 0 && armed_.breakpoint->writeWatchBytes == width, "armed-data-address");
        return armed_;
    }

    native::NativeControlResult WaitHeld() {
        fixture_.Signal(kGo);
        const auto held = WaitBreakpoint(native::NativeBreakpointState::Held);
        Require(held.breakpointHit && held.breakpointHit->address == armed_.breakpoint->address,
            "held-real-breakpoint-hit");
        Require(held.pending && held.pending->exceptionCode == EXCEPTION_SINGLE_STEP && held.responsibility,
            "held-exact-single-step");
        Require(held.pending->eventCode == EXCEPTION_DEBUG_EVENT && held.pending->exceptionFirstChance == true,
            "held-first-chance-debug-event");
        Require(held.group && !held.group->historical && held.group->state == native::GroupState::HeldComplete,
            "held-frozen-group");
        Require(held.breakpoint && held.breakpoint->state == native::NativeBreakpointState::Held,
            "held-binding-state");
        if (dataWatch_) {
            Require(held.group->origin && held.group->origin->phase == native::StopPhase::DataWriteObserved,
                "held-data-phase");
            Require(held.breakpointHit->dataChange && held.breakpointHit->dataChange->changedByteMask != 0,
                "held-data-change");
        } else {
            Require(held.group->origin && held.group->origin->phase == native::StopPhase::ExecutionEnterAttempt,
                "held-execution-phase");
        }
        return held;
    }

    native::NativeStepRequest MakeStep(const native::NativeControlResult& stop, std::string id,
        native::NativeStepMode mode) const {
        const auto& origin = OriginOf(stop);
        return {ToRelease(owner_, stop, std::move(id)), origin.identity, origin.tid, origin.creationTime, mode};
    }

    native::NativeControlResult WaitNextHeld() { return WaitBreakpoint(native::NativeBreakpointState::Held); }

    native::NativeControlResult Step(const native::NativeStepRequest& request) {
        const auto result = owner_.Step(request);
        if (result.status == native::NativeControlStatus::Rejected) {
            std::fprintf(stderr, "STEP_REJECTED stage=%s error=%u ledger=%d\n", result.stage, result.win32Error,
                static_cast<int>(result.ledgerResult));
        }
        Require(result.status != native::NativeControlStatus::Rejected, "step-accepted");
        Require(result.release && result.release->receipt &&
            result.release->receipt->result == native::ReleaseResult::Continued, "step-released");
        return result;
    }

    native::NativeControlResult WaitStep(std::string_view requestId) {
        const auto deadline = GetTickCount64() + kDeadlineMs;
        native::NativeControlResult result;
        do {
            result = owner_.QueryStep(requestId);
            if (result.step && result.step->state != native::NativeStepState::Running) { break; }
            Sleep(1);
        } while (GetTickCount64() < deadline);
        if (!result.step || result.step->state == native::NativeStepState::Running) {
            std::fprintf(stderr, "STEP_TIMEOUT id=%s stage=%s error=%u\n", std::string(requestId).c_str(),
                result.stage, result.win32Error);
        }
        Require(result.step && result.step->state != native::NativeStepState::Running, "step-left-running");
        return result;
    }

    void Continue(const native::NativeControlResult& stop, std::string id) {
        const auto released = owner_.Continue(ToRelease(owner_, stop, std::move(id)));
        Require(released.release && released.release->receipt &&
            released.release->receipt->result == native::ReleaseResult::Continued, "stop-released");
    }

    void CloseAndFinish() {
        if (closed_) { return; }
        const auto closed = owner_.Close();
        Require(closed.status == native::NativeControlStatus::Closed ||
            closed.status == native::NativeControlStatus::ClosePending, "owner-close-accepted");
        Require(WaitClean(kDeadlineMs), "owner-clean");
        closed_ = true;
        fixture_.Signal(kExit);
        Require(fixture_.WaitExit(kDeadlineMs), "fixture-exited");
        Require(fixture_.ExitCode() == kFixtureExitCode, "fixture-exit-code");
    }

    ChildFixture& fixture() { return fixture_; }
    native::NativeDebugOwner& owner() { return owner_; }
    const native::OwnerIdentity& ownerId() const { return owner_; }
    const native::NativeControlResult& armed() const { return armed_; }

private:
    static std::wstring CurrentModulePath() {
        wchar_t module[MAX_PATH]{};
        const auto length = GetModuleFileNameW(nullptr, module, MAX_PATH);
        Require(length != 0 && length < MAX_PATH, "fixture-module-path");
        return module;
    }

    native::NativeControlResult WaitBreakpoint(native::NativeBreakpointState expected) {
        const auto deadline = GetTickCount64() + kDeadlineMs;
        native::NativeControlResult result;
        do {
            result = owner_.Query();
            if (result.breakpoint && (result.breakpoint->state == expected ||
                result.breakpoint->state == native::NativeBreakpointState::Rejected ||
                result.breakpoint->state == native::NativeBreakpointState::RecoveryRequired)) {
                break;
            }
            Sleep(1);
        } while (GetTickCount64() < deadline);
        if (!result.breakpoint || result.breakpoint->state != expected) {
            std::fprintf(stderr, "BREAKPOINT_STAGE stage=%s binding=%s error=%u status=%d\n", result.stage,
                result.breakpoint ? result.breakpoint->stage : "none", result.win32Error,
                static_cast<int>(result.status));
        }
        Require(result.breakpoint && result.breakpoint->state == expected, "observed-exact-breakpoint-state");
        return result;
    }

    bool WaitClean(DWORD limit) {
        const auto deadline = GetTickCount64() + limit;
        native::NativeControlResult state;
        do {
            state = owner_.Query();
            if (state.clean && !state.attached) { return true; }
            Sleep(2);
        } while (GetTickCount64() < deadline);
        return false;
    }

    static native::ReleaseRequest ToRelease(const native::OwnerIdentity& owner,
        const native::NativeControlResult& stop, std::string id) {
        Require(stop.group && stop.responsibility, "stop-has-group");
        return {owner, stop.group->groupId, stop.responsibility->stopId, stop.responsibility->event,
            std::move(id), stop.group->stateRevision};
    }

    ChildFixture fixture_;
    native::NativeDebugOwner owner_;
    native::NativePauseRequest pause_;
    native::NativeBreakpointRequest request_;
    std::wstring modulePath_;
    native::NativeControlResult armed_;
    bool dataWatch_ = false;
    bool closed_ = false;
};

// ---- typing helpers -------------------------------------------------------

std::uint64_t JsonU64(const evidence::JsonValue& object, const char* key) {
    const auto* field = object.find(key);
    std::uint64_t value = 0;
    if (!field || !field->tryGetU64(value)) {
        std::fprintf(stderr, "JSON_U64 field=%s\n", key);
        throw std::runtime_error(key);
    }
    ++checks;
    return value;
}

std::string JsonStr(const evidence::JsonValue& object, const char* key) {
    const auto* field = object.find(key);
    std::string value;
    if (!field || !field->tryGetString(value)) {
        std::fprintf(stderr, "JSON_STR field=%s\n", key);
        throw std::runtime_error(key);
    }
    ++checks;
    return value;
}

bool JsonBool(const evidence::JsonValue& object, const char* key) {
    const auto* field = object.find(key);
    bool value = false;
    if (!field || field->type() != evidence::JsonType::Bool || !field->tryGetBool(value)) {
        std::fprintf(stderr, "JSON_BOOL field=%s\n", key);
        throw std::runtime_error(key);
    }
    ++checks;
    return value;
}

const evidence::JsonValue& JsonObject(const evidence::JsonValue& object, const char* key) {
    const auto* field = object.find(key);
    if (!field || !field->asObject()) {
        std::fprintf(stderr, "JSON_OBJECT field=%s\n", key);
        throw std::runtime_error(key);
    }
    ++checks;
    return *field;
}

void ExpectEqual(std::uint64_t actual, std::uint64_t expected, const char* what) {
    if (actual != expected) {
        std::fprintf(stderr, "MISMATCH %s actual=%llu expected=%llu\n", what,
            static_cast<unsigned long long>(actual), static_cast<unsigned long long>(expected));
    }
    Require(actual == expected, what);
}

void ExpectText(std::string_view actual, std::string_view expected, const char* what) {
    if (actual != expected) {
        std::fprintf(stderr, "MISMATCH %s actual=%.*s expected=%.*s\n", what,
            static_cast<int>(actual.size()), actual.data(), static_cast<int>(expected.size()), expected.data());
    }
    Require(actual == expected, what);
}

void VerifyDoc(const aa::ArchivedNativeExecution& archived, std::string_view projectId,
    const std::string& sampleId, const native::OwnerIdentity& owner,
    const native::NativeControlResult& state, native::NativeExecutionKind kind,
    const native::NativeFrozenThread& thread, std::uint64_t instruction,
    std::optional<std::uint64_t> next) {
    const auto& document = archived.document;
    Require(document.type() == evidence::JsonType::Object && document.asObject()->size() == 18,
        "document-exact-fields");
    ExpectText(JsonStr(document, "kind"), "native-execution-v1", "doc-kind");
    ExpectText(JsonStr(document, "projectId"), projectId, "doc-project");
    ExpectText(JsonStr(document, "sampleId"), sampleId, "doc-sample");
    ExpectText(JsonStr(document, "sessionId"), owner.sessionId, "doc-session");
    ExpectText(JsonStr(document, "epoch"), owner.epoch, "doc-epoch");
    ExpectText(JsonStr(document, "source"), "native-debug-owner", "doc-source");
    Require(JsonBool(document, "historical"), "doc-historical");
    ExpectText(JsonStr(document, "observation"),
        kind == native::NativeExecutionKind::InstructionCompleted ? "instruction-completed" : "execution-enter-attempt",
        "doc-observation");

    const auto& target = JsonObject(document, "target");
    const auto& threadObject = JsonObject(document, "thread");
    const auto& event = JsonObject(document, "event");
    Require(target.asObject()->size() == 3 && threadObject.asObject()->size() == 3 &&
        event.asObject()->size() == 2, "document-nested-fields");
    ExpectText(JsonStr(target, "processInstanceId"), thread.identity.processInstanceId, "doc-process-instance");
    ExpectText(JsonStr(threadObject, "threadId"), thread.identity.threadId, "doc-thread-identity");
    ExpectText(JsonStr(event, "backendInstanceId"), owner.backendInstanceId, "doc-backend");
    const auto* pid = target.find("pid");
    const auto* tid = threadObject.find("tid");
    Require(pid && pid->type() == evidence::JsonType::UInt && tid && tid->type() == evidence::JsonType::UInt,
        "doc-raw-ids-are-uint");
    std::uint64_t pidValue = 0;
    std::uint64_t tidValue = 0;
    Require(pid->tryGetU64(pidValue) && tid->tryGetU64(tidValue), "doc-raw-ids");
    ExpectEqual(pidValue, state.pid, "doc-pid");
    ExpectEqual(tidValue, thread.tid, "doc-tid");
    ExpectEqual(JsonU64(target, "creationFileTime"), state.processCreationTime, "doc-process-time");
    ExpectEqual(JsonU64(threadObject, "creationFileTime"), thread.creationTime, "doc-thread-time");
    ExpectEqual(JsonU64(event, "serial"), state.pending->event.serial, "doc-event-serial");
    ExpectText(JsonStr(document, "groupId"), state.group->groupId, "doc-group");
    ExpectText(JsonStr(document, "stopId"), state.responsibility->stopId, "doc-stop");
    ExpectEqual(JsonU64(document, "stateRevision"), state.group->stateRevision, "doc-revision");
    ExpectEqual(JsonU64(document, "instructionAddress"), instruction, "doc-instruction");
    if (next) {
        ExpectEqual(JsonU64(document, "nextInstructionAddress"), *next, "doc-next-instruction");
    } else {
        const auto* field = document.find("nextInstructionAddress");
        Require(field && field->isNull(), "doc-next-instruction-null");
    }
    Require(state.timing.eventObservedQpc.has_value() && state.timing.qpcFrequency != 0, "state-has-qpc");
    ExpectEqual(JsonU64(document, "observedQpc"), *state.timing.eventObservedQpc, "doc-qpc");
    ExpectEqual(JsonU64(document, "qpcFrequency"), state.timing.qpcFrequency, "doc-qpc-frequency");
}

void VerifyReceipt(const aa::ProjectNativeExecutionReceipt& receipt, std::uint64_t ordinal,
    std::uint64_t recordSequence, const fs::path& path) {
    ExpectEqual(receipt.ordinal, ordinal, "receipt-ordinal");
    Require(receipt.verified, "receipt-verified");
    Require(aa::ProjectStorage::IsHash(receipt.sha256), "receipt-sha-format");
    Require(receipt.raw.result.status == archive::SegmentWriteStatus::Ok, "receipt-status");
    Require(receipt.raw.written && receipt.raw.flushed, "receipt-boundaries");
    ExpectEqual(receipt.raw.flushed->blockOrdinal, 1, "receipt-block-ordinal");
    ExpectEqual(receipt.raw.flushed->lastSequence, recordSequence, "receipt-record-sequence");
    ExpectEqual(receipt.raw.written->byteOffset, receipt.raw.flushed->byteOffset, "receipt-written-endpoint");
    const auto bytes = ReadFile(path);
    ExpectEqual(static_cast<std::uint64_t>(bytes.size()), receipt.raw.flushed->byteOffset, "receipt-file-endpoint");
    ExpectText(Sha256Hex(bytes), receipt.sha256, "receipt-file-sha");
}

void ExpectNoRead(const aa::ProjectResult& result, const aa::ArchivedNativeExecution& out, const char* what) {
    if (result.error != aa::ProjectError::Corrupt || std::string_view(result.detail) != "nativeExecutionReadback") {
        std::fprintf(stderr, "READ_UNEXPECTED %s error=%s detail=%s\n", what,
            aa::ProjectErrorName(result.error), result.detail);
    }
    Require(result.error == aa::ProjectError::Corrupt && std::string_view(result.detail) == "nativeExecutionReadback",
        what);
    Require(out.document.isNull() && out.sha256.empty() && out.end.byteOffset == 0 && out.end.blockOrdinal == 0 &&
        out.end.lastSequence == 0, "rejected-read-has-no-output-document");
}

aa::ArchivedNativeExecution ReadOk(const aa::ProjectDocument& project, const std::string& sample,
    std::uint64_t ordinal, std::optional<std::uint64_t> previous, const char* what) {
    aa::ArchivedNativeExecution out;
    const auto result = aa::ReadNativeExecution(project, sample, ordinal, previous, out);
    if (result.error != aa::ProjectError::None) {
        std::fprintf(stderr, "READ_FAILED %s error=%s detail=%s\n", what,
            aa::ProjectErrorName(result.error), result.detail);
    }
    Require(result.error == aa::ProjectError::None, what);
    Require(!out.document.isNull() && out.sha256.size() == 64, "read-document-and-sha");
    return out;
}

void RawRecord(aa::ProjectDocument& project, std::string_view projectId, const std::string& sample,
    std::uint64_t ordinal, const std::string& metadata, std::string_view inlineRawData,
    aa::ProjectEvidenceLane lane = aa::ProjectEvidenceLane::NativeExecution) {
    archive::RawEvidenceReceipt receipt;
    const aa::ProjectRawEvidenceWrite request{projectId, sample, ordinal, std::nullopt,
        [&](archive::RawEvidenceArchive& writer) -> aa::ProjectResult {
            const archive::RawEvidenceInput row{metadata, inlineRawData};
            const auto appended = writer.Append(std::span(&row, 1));
            if (appended.result.status == archive::SegmentWriteStatus::Ok) { return {}; }
            return {aa::ProjectError::IoError, appended.result.error.win32Error, "nativeExecutionFixtureRaw"};
        }, lane};
    const auto result = project.WriteRawEvidenceSegment(request, receipt);
    Require(result.error == aa::ProjectError::None, "fixture-raw-write");
    Require(receipt.result.status == archive::SegmentWriteStatus::Ok && receipt.flushed, "fixture-raw-flushed");
}

void RawRecordPair(aa::ProjectDocument& project, std::string_view projectId, const std::string& sample,
    std::uint64_t ordinal, const std::string& metadata) {
    archive::RawEvidenceReceipt receipt;
    const aa::ProjectRawEvidenceWrite request{projectId, sample, ordinal, std::nullopt,
        [&](archive::RawEvidenceArchive& writer) -> aa::ProjectResult {
            const archive::RawEvidenceInput rows[2]{{metadata, {}}, {metadata, {}}};
            const auto appended = writer.Append(std::span(rows, 2));
            if (appended.result.status == archive::SegmentWriteStatus::Ok) { return {}; }
            return {aa::ProjectError::IoError, appended.result.error.win32Error, "nativeExecutionFixtureRawPair"};
        }, aa::ProjectEvidenceLane::NativeExecution};
    const auto result = project.WriteRawEvidenceSegment(request, receipt);
    Require(result.error == aa::ProjectError::None, "fixture-raw-pair-write");
    Require(receipt.result.status == archive::SegmentWriteStatus::Ok && receipt.flushed, "fixture-raw-pair-flushed");
}

std::string StoredMetadata(const aa::ProjectDocument& project, std::string_view projectId,
    const std::string& sample, std::uint64_t ordinal, bool& single, bool& noInline) {
    std::string metadata;
    std::size_t count = 0;
    bool inlineEmpty = true;
    const aa::ProjectRawEvidenceRead request{projectId, sample, ordinal, std::nullopt, std::nullopt,
        [&](const archive::SegmentIdentity&, const archive::BlockInfo&, const std::vector<archive::DecodedRecord>& records) {
            for (const auto& record : records) {
                ++count;
                const auto* body = std::get_if<archive::RawRecordV1>(&record.body);
                if (!body) { inlineEmpty = false; return false; }
                metadata.assign(body->metadataJson);
                if (!body->inlineRawData.empty()) { inlineEmpty = false; }
            }
            return true;
        }, 64 * 1024, aa::ProjectEvidenceLane::NativeExecution};
    archive::RawEvidenceScanResult scanned;
    const auto result = project.ReadRawEvidenceSegment(request, scanned);
    Require(result.error == aa::ProjectError::None, "fixture-raw-read");
    Require(scanned.checked && scanned.VerifiedBoundary(*scanned.checked), "fixture-raw-scan");
    single = count == 1;
    noInline = inlineEmpty;
    return metadata;
}

std::string ReplaceOnce(std::string text, std::string_view before, std::string_view after) {
    const auto position = text.find(before);
    if (position == std::string::npos) {
        std::fprintf(stderr, "REPLACE_MISSING before=%.*s\n", static_cast<int>(before.size()), before.data());
        throw std::runtime_error("fixture-replace");
    }
    text.replace(position, before.size(), after);
    return text;
}

void ForSampleInPlace(std::string& text, std::string_view from, std::string_view to) {
    text = ReplaceOnce(std::move(text), from, to);
}

std::uint32_t RvaOf(const void* label) {
    const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto address = reinterpret_cast<std::uintptr_t>(label);
    if (!base || address < base || address - base > 0xffffffffull) {
        throw std::runtime_error("fixture-rva");
    }
    return static_cast<std::uint32_t>(address - base);
}

void VerifyFileDoc(const fs::path& path, const aa::ArchivedNativeExecution& archived) {
    const auto bytes = ReadFile(path);
    ExpectEqual(static_cast<std::uint64_t>(bytes.size()), archived.end.byteOffset, "archived-file-endpoint");
    ExpectText(Sha256Hex(bytes), archived.sha256, "archived-file-sha");
}

struct Fixture {
    fs::path root;
    std::wstring exe;
    aa::ProjectDocument writer;
    aa::ProjectDocument reader;
    std::string projectId;
    std::map<std::string, std::string> samples;
    std::string docText;

    const std::string& Id(const char* name) const {
        const auto found = samples.find(name);
        if (found == samples.end()) { throw std::runtime_error("fixture-sample"); }
        return found->second;
    }
};

template <class Body>
void RunScenario(const char* name, Body&& body) {
    try {
        body();
        std::printf("SCENARIO_OK %s\n", name);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "SCENARIO_ERROR scenario=%s detail=%s\n", name, error.what());
    }
}

void ScenarioEntryAndInto(Fixture& f) {
    const auto& sample = f.Id("A");
    LiveSession session(f.exe, kFlagLoop, sample);
    const auto armed = session.ArmRva(RvaOf(&FixtureNop));
    auto held = session.WaitHeld();
    const auto& origin = OriginOf(held);
    const auto path1 = SegmentPath(f.root, sample, 1, L"raw-native");
    const auto path2 = SegmentPath(f.root, sample, 2, L"raw-native");
    const auto path3 = SegmentPath(f.root, sample, 3, L"raw-native");

    // 错误 owner / sample 不能落盘，也不能产生已验证回执。
    const native::OwnerIdentity variants[]{
        {kWrongId, session.ownerId().sessionId, session.ownerId().epoch, session.ownerId().backendInstanceId},
        {sample, kWrongId, session.ownerId().epoch, session.ownerId().backendInstanceId},
        {sample, session.ownerId().sessionId, kWrongId, session.ownerId().backendInstanceId},
        {sample, session.ownerId().sessionId, session.ownerId().epoch, kWrongId}};
    for (const auto& variant : variants) {
        aa::ProjectNativeExecutionReceipt receipt;
        const auto result = aa::WriteNativeExecution(f.writer, variant, 1, std::nullopt, held, receipt);
        Require(result.error == aa::ProjectError::InvalidArgument &&
            std::string_view(result.detail) == "nativeExecutionActiveOwner", "wrong-owner-rejected");
        Require(!receipt.verified && receipt.sha256.empty(), "wrong-owner-no-receipt");
        Require(!fs::exists(path1), "wrong-owner-no-file");
    }

    // 只读项目不能写本 lane。
    {
        aa::ProjectNativeExecutionReceipt receipt;
        const auto result = aa::WriteNativeExecution(f.reader, session.ownerId(), 1, std::nullopt, held, receipt);
        Require(result.error == aa::ProjectError::ReadOnly && std::string_view(result.detail) == "project",
            "read-only-write-rejected");
        Require(!receipt.verified && receipt.sha256.empty(), "read-only-no-receipt");
    }

    // 同采样先有 API raw/1 和 raw-memory/1，native 写入不能覆盖。
    RawRecord(f.writer, f.projectId, sample, 1, "{\"kind\":\"fixture-primary\"}", {},
        aa::ProjectEvidenceLane::Primary);
    RawRecord(f.writer, f.projectId, sample, 1, "{\"kind\":\"fixture-memory\"}", {},
        aa::ProjectEvidenceLane::MemorySnapshots);
    const auto primaryPath = SegmentPath(f.root, sample, 1, L"raw");
    const auto memoryPath = SegmentPath(f.root, sample, 1, L"raw-memory");
    Require(fs::exists(primaryPath) && fs::exists(memoryPath), "primary-and-memory-present");
    const auto treeBefore = TreeHashes(SampleDir(f.root, sample));

    aa::ProjectNativeExecutionReceipt r1;
    const auto write1 = aa::WriteNativeExecution(f.writer, session.ownerId(), 1, std::nullopt, held, r1);
    Require(write1.error == aa::ProjectError::None, "write-entry");
    VerifyReceipt(r1, 1, 1, path1);

    auto read1 = ReadOk(f.reader, sample, 1, std::nullopt, "read-entry");
    VerifyDoc(read1, f.projectId, sample, session.ownerId(), held, native::NativeExecutionKind::EnterAttempt,
        origin, held.breakpointHit->address, std::nullopt);
    VerifyFileDoc(path1, read1);
    bool single = false;
    bool noInline = false;
    const auto metadata1 = StoredMetadata(f.reader, f.projectId, sample, 1, single, noInline);
    Require(single && noInline, "entry-one-record-no-inline");
    ExpectText(evidence::WriteJson(read1.document), metadata1, "entry-stored-metadata");
    f.docText = evidence::WriteJson(read1.document);

    // CREATE_NEW 拒绝覆盖同段；底层首错回执保留，原文件字节不变。
    {
        const auto before = Sha256Hex(ReadFile(path1));
        aa::ProjectNativeExecutionReceipt receipt;
        const auto result = aa::WriteNativeExecution(f.writer, session.ownerId(), 1, std::nullopt, held, receipt);
        Require(result.error == aa::ProjectError::IoError &&
            std::string_view(result.detail) == "nativeExecutionWrite", "create-new-rejected");
        Require(receipt.raw.result.status == archive::SegmentWriteStatus::IoError, "failed-write-receipt");
        Require(receipt.raw.result.error.win32Error == ERROR_FILE_EXISTS, "failed-write-error");
        Require(!receipt.raw.written && !receipt.raw.flushed, "failed-write-no-boundary");
        Require(!receipt.verified && receipt.sha256.empty(), "failed-write-no-verification");
        ExpectText(Sha256Hex(ReadFile(path1)), before, "create-new-preserves-bytes");
    }

    // 错前序不能创建第二段。
    {
        aa::ProjectNativeExecutionReceipt receipt;
        const auto result = aa::WriteNativeExecution(f.writer, session.ownerId(), 2, 999, held, receipt);
        Require(result.error == aa::ProjectError::RecoveryRequired &&
            std::string_view(result.detail) == "archivePreviousSegment", "wrong-previous-rejected");
        Require(!fs::exists(path2), "wrong-previous-no-file");
    }

    // 真实 Into：DR0 命中后单指令 TF 完成，新事件与资源恢复归同一 stop。
    const auto step = session.MakeStep(held, "continue/1", native::NativeStepMode::Into);
    session.Step(step);
    const auto done = session.WaitStep("continue/1");
    Require(done.step->state == native::NativeStepState::Completed, "into-completed");
    Require(done.step->resourcesRestored, "into-resources-restored");
    const auto base = armed.breakpoint->moduleBase;
    ExpectEqual(done.step->startIp, armed.breakpoint->address, "into-start-address");
    ExpectEqual(*done.step->observedIp, base + RvaOf(&FixtureNop) + 1, "into-next-instruction");
    Require(done.step->observedSp && *done.step->observedSp == done.step->startSp, "into-stack-unchanged");
    Require(done.step->stopGroupId && *done.step->stopGroupId != held.group->groupId, "into-new-group");
    auto stepStop = session.owner().Query(*done.step->stopGroupId);
    Require(stepStop.status == native::NativeControlStatus::Held && stepStop.group && !stepStop.group->historical,
        "step-stop-held");
    Require(!stepStop.breakpointHit, "step-stop-has-no-entry-hit");
    Require(stepStop.pending && stepStop.step && stepStop.step->observedEvent &&
        *stepStop.step->observedEvent == stepStop.pending->event, "step-event-is-current-stop");
    Require(stepStop.step->stopGroupId && *stepStop.step->stopGroupId == stepStop.group->groupId,
        "step-stop-group-receipt");
    const auto& stepOrigin = OriginOf(stepStop);

    // 旧停点组已经历史化，不能再次作为活证据写入。
    {
        const auto oldGroup = session.owner().Query(held.group->groupId);
        Require(oldGroup.group && oldGroup.group->historical, "old-group-historical");
        aa::ProjectNativeExecutionReceipt receipt;
        const auto result = aa::WriteNativeExecution(f.writer, session.ownerId(), 3, 2, oldGroup, receipt);
        Require(result.error == aa::ProjectError::InvalidArgument &&
            std::string_view(result.detail) == "nativeExecutionActiveOwner", "historical-stop-rejected");
        Require(!fs::exists(path3), "historical-stop-no-file");
    }

    aa::ProjectNativeExecutionReceipt r2;
    const auto write2 = aa::WriteNativeExecution(f.writer, session.ownerId(), 2, 1, stepStop, r2);
    Require(write2.error == aa::ProjectError::None, "write-completed");
    VerifyReceipt(r2, 2, 2, path2);
    auto read2 = ReadOk(f.reader, sample, 2, 1, "read-completed");
    VerifyDoc(read2, f.projectId, sample, session.ownerId(), stepStop,
        native::NativeExecutionKind::InstructionCompleted, stepOrigin, done.step->startIp, done.step->observedIp);
    VerifyFileDoc(path2, read2);
    const auto metadata2 = StoredMetadata(f.reader, f.projectId, sample, 2, single, noInline);
    Require(single && noInline, "completed-one-record-no-inline");
    ExpectText(evidence::WriteJson(read2.document), metadata2, "completed-stored-metadata");

    // 同采样 API raw/1 与 raw-memory/1 未被覆盖；读回不修改文件。
    const auto treeAfter = TreeHashes(SampleDir(f.root, sample));
    for (const auto& [relative, hash] : treeBefore) {
        const auto found = treeAfter.find(relative);
        Require(found != treeAfter.end() && found->second == hash, "existing-lane-preserved");
    }
    Require(fs::exists(primaryPath) && fs::exists(memoryPath), "primary-and-memory-preserved");

    // 关闭全部写入后重新只读打开，同一字节和 SHA 仍可回读。
    {
        aa::ProjectDocument reopened;
        Require(reopened.Open(f.root.wstring(), aa::ProjectAccess::ReadOnly).error == aa::ProjectError::None,
            "reopen-read-only");
        const auto reopen1 = ReadOk(reopened, sample, 1, std::nullopt, "reopen-entry");
        const auto reopen2 = ReadOk(reopened, sample, 2, 1, "reopen-completed");
        ExpectText(evidence::WriteJson(reopen1.document), metadata1, "reopen-entry-bytes");
        ExpectText(evidence::WriteJson(reopen2.document), metadata2, "reopen-completed-bytes");
        ExpectText(reopen1.sha256, r1.sha256, "reopen-entry-sha");
        ExpectText(reopen2.sha256, r2.sha256, "reopen-completed-sha");
        reopened.Close();
    }

    // 释放 step stop 后，该组不能再作为活证据。
    session.Continue(stepStop, "continue/2");
    {
        const auto released = session.owner().Query(*done.step->stopGroupId);
        aa::ProjectNativeExecutionReceipt receipt;
        const auto result = aa::WriteNativeExecution(f.writer, session.ownerId(), 3, 2, released, receipt);
        Require(result.error == aa::ProjectError::InvalidArgument &&
            std::string_view(result.detail) == "nativeExecutionActiveOwner", "released-stop-rejected");
        Require(!fs::exists(path3), "released-stop-no-file");
    }

    // 循环第二轮的真正 DR0 入口不得被旧 step 回执误判成 instruction-completed。
    const auto held2 = session.WaitNextHeld();
    Require(held2.group && held2.group->groupId != held.group->groupId, "second-entry-new-group");
    Require(held2.pending && held2.breakpointHit && held2.breakpointHit->address == armed.breakpoint->address,
        "second-entry-real-hit");
    Require(!held2.step || !held2.step->observedEvent || *held2.step->observedEvent != held2.pending->event,
        "old-step-not-bound-to-new-stop");
    const auto observed2 = native::NativeExecutionFromOwnedStop(held2);
    Require(observed2 && observed2->kind == native::NativeExecutionKind::EnterAttempt,
        "old-step-does-not-masquerade");
    ExpectEqual(observed2->instructionAddress, armed.breakpoint->address, "second-entry-address");
    session.Continue(held2, "continue/3");

    Require(session.fixture().Wait(kDone, kDeadlineMs), "fixture-done");
    session.fixture().Signal(kPulse);
    Require(session.fixture().Wait(kAck, kDeadlineMs), "peer-resumed-after-steps");
    session.CloseAndFinish();
}

void ScenarioWriteWatch(Fixture& f) {
    const auto& sample = f.Id("B");
    LiveSession session(f.exe, kFlagWrite, sample);
    const auto armed = session.ArmData("g_nativeExecutionWriteWatch", 4);
    const auto held = session.WaitHeld();
    Require(armed.breakpoint->writeWatchBytes == 4, "write-watch-width");
    Require(held.breakpointHit->dataChange.has_value(), "write-watch-change");
    Require(!native::NativeExecutionFromOwnedStop(held).has_value(), "write-stop-is-not-execution");
    aa::ProjectNativeExecutionReceipt receipt;
    const auto result = aa::WriteNativeExecution(f.writer, session.ownerId(), 1, std::nullopt, held, receipt);
    Require(result.error == aa::ProjectError::InvalidArgument &&
        std::string_view(result.detail) == "nativeExecutionActiveOwner", "write-stop-rejected");
    Require(!receipt.verified && receipt.sha256.empty(), "write-stop-no-receipt");
    Require(!fs::exists(SegmentPath(f.root, sample, 1, L"raw-native")), "write-stop-no-file");
    session.Continue(held, "continue/1");
    Require(session.fixture().Wait(kDone, kDeadlineMs), "write-fixture-done");
    session.CloseAndFinish();
}

void ScenarioOverCall(Fixture& f) {
    const auto& sample = f.Id("C");
    LiveSession session(f.exe, 0, sample);
    const auto armed = session.ArmRva(RvaOf(&FixtureCall));
    auto held = session.WaitHeld();
    session.Step(session.MakeStep(held, "continue/1", native::NativeStepMode::OverCall));
    const auto done = session.WaitStep("continue/1");
    Require(done.step->state == native::NativeStepState::Completed, "over-call-completed");
    ExpectEqual(*done.step->observedIp, armed.breakpoint->moduleBase + RvaOf(&FixtureAfterCall),
        "over-call-return-site");
    auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.status == native::NativeControlStatus::Held && !stop.breakpointHit, "over-call-stop-held");
    Require(!native::NativeExecutionFromOwnedStop(stop).has_value(), "over-call-is-not-completion");
    aa::ProjectNativeExecutionReceipt receipt;
    const auto result = aa::WriteNativeExecution(f.writer, session.ownerId(), 1, std::nullopt, stop, receipt);
    Require(result.error == aa::ProjectError::InvalidArgument &&
        std::string_view(result.detail) == "nativeExecutionActiveOwner", "over-call-rejected");
    Require(!fs::exists(SegmentPath(f.root, sample, 1, L"raw-native")), "over-call-no-file");
    session.Continue(stop, "continue/2");
    Require(session.fixture().Wait(kDone, kDeadlineMs), "over-call-fixture-done");
    session.CloseAndFinish();
}

void ScenarioOut(Fixture& f) {
    const auto& sample = f.Id("D");
    LiveSession session(f.exe, 0, sample);
    const auto armed = session.ArmRva(RvaOf(&FixtureCall));
    auto held = session.WaitHeld();
    session.Step(session.MakeStep(held, "continue/1", native::NativeStepMode::Into));
    const auto entered = session.WaitStep("continue/1");
    Require(entered.step->state == native::NativeStepState::Completed, "out-prepare-into-completed");
    ExpectEqual(*entered.step->observedIp, armed.breakpoint->moduleBase + RvaOf(&FixtureCalleeEntry),
        "out-prepare-callee-entry");
    auto entryStop = session.owner().Query(*entered.step->stopGroupId);
    session.Step(session.MakeStep(entryStop, "continue/2", native::NativeStepMode::Out));
    const auto done = session.WaitStep("continue/2");
    Require(done.step->state == native::NativeStepState::Completed, "out-completed");
    ExpectEqual(*done.step->observedIp, armed.breakpoint->moduleBase + RvaOf(&FixtureAfterCall), "out-return-site");
    auto stop = session.owner().Query(*done.step->stopGroupId);
    Require(stop.status == native::NativeControlStatus::Held && !stop.breakpointHit, "out-stop-held");
    Require(!native::NativeExecutionFromOwnedStop(stop).has_value(), "out-is-not-completion");
    aa::ProjectNativeExecutionReceipt receipt;
    const auto result = aa::WriteNativeExecution(f.writer, session.ownerId(), 1, std::nullopt, stop, receipt);
    Require(result.error == aa::ProjectError::InvalidArgument &&
        std::string_view(result.detail) == "nativeExecutionActiveOwner", "out-rejected");
    Require(!fs::exists(SegmentPath(f.root, sample, 1, L"raw-native")), "out-no-file");
    session.Continue(stop, "continue/3");
    Require(session.fixture().Wait(kDone, kDeadlineMs), "out-fixture-done");
    session.CloseAndFinish();
}

void ScenarioReadRejections(Fixture& f) {
    const auto& a = f.Id("A");
    const auto realText = f.docText;
    const auto aPath = SegmentPath(f.root, a, 1, L"raw-native");

    // 已存在完整段时，错前序读回也要拒绝。
    {
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, a, 2, 999, out);
        ExpectNoRead(result, out, "read-wrong-previous");
    }

    // 段头身份来自另一采样时拒绝。
    {
        const auto& sample = f.Id("R1");
        const auto path = SegmentPath(f.root, sample, 1, L"raw-native");
        fs::create_directories(path.parent_path());
        fs::copy_file(aPath, path, fs::copy_options::overwrite_existing);
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-wrong-segment-identity");
    }

    // 截尾。
    {
        const auto& sample = f.Id("R2");
        auto text = realText;
        ForSampleInPlace(text, a, sample);
        RawRecord(f.writer, f.projectId, sample, 1, text, {});
        const auto path = SegmentPath(f.root, sample, 1, L"raw-native");
        const auto bytes = ReadFile(path);
        Require(bytes.size() > 8u, "truncate-source-size");
        fs::resize_file(path, bytes.size() - 3);
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-truncated");
        WriteFile(path, bytes);
    }

    // 坏 CRC。
    {
        const auto& sample = f.Id("R3");
        auto text = realText;
        ForSampleInPlace(text, a, sample);
        RawRecord(f.writer, f.projectId, sample, 1, text, {});
        const auto path = SegmentPath(f.root, sample, 1, L"raw-native");
        auto bytes = ReadFile(path);
        Require(bytes.size() > 8u, "crc-source-size");
        bytes[bytes.size() - 4] ^= 0x01;
        WriteFile(path, bytes);
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-bad-crc");
    }

    // 元数据字段类型错误。
    {
        const auto& sample = f.Id("R4");
        auto text = realText;
        ForSampleInPlace(text, a, sample);
        text = ReplaceOnce(std::move(text), "\"historical\":true", "\"historical\":\"true\"");
        RawRecord(f.writer, f.projectId, sample, 1, text, {});
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-wrong-metadata-type");
    }

    // 未知字段。
    {
        const auto& sample = f.Id("R5");
        auto text = realText;
        ForSampleInPlace(text, a, sample);
        Require(!text.empty() && text.front() == '{', "unknown-field-source");
        text.insert(1, "\"extra\":\"x\",");
        RawRecord(f.writer, f.projectId, sample, 1, text, {});
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-unknown-field");
    }

    // API 入口文档不能进入 native lane。
    {
        const auto& sample = f.Id("R6");
        auto text = realText;
        ForSampleInPlace(text, a, sample);
        text = ReplaceOnce(std::move(text), "\"kind\":\"native-execution-v1\"", "\"kind\":\"api-event-v1\"");
        RawRecord(f.writer, f.projectId, sample, 1, text, {});
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-api-kind");
    }

    // 每段必须恰好一条且无 inline 原始字节。
    {
        const auto& sample = f.Id("R7");
        auto text = realText;
        ForSampleInPlace(text, a, sample);
        RawRecord(f.writer, f.projectId, sample, 1, text, "x");
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-inline-bytes");
    }
    {
        const auto& sample = f.Id("R8");
        auto text = realText;
        ForSampleInPlace(text, a, sample);
        RawRecordPair(f.writer, f.projectId, sample, 1, text);
        aa::ArchivedNativeExecution out;
        const auto result = aa::ReadNativeExecution(f.reader, sample, 1, std::nullopt, out);
        ExpectNoRead(result, out, "read-two-records");
    }
}

int RunAll(const std::wstring& root, const std::wstring& exe) {
    Require(!fs::exists(fs::path(root)), "fixture-root-must-not-exist");
    Fixture f;
    f.root = root;
    f.exe = exe;
    Require(f.writer.Create(root, {"native execution acceptance", ""}).error == aa::ProjectError::None,
        "project-create");
    f.projectId = f.writer.Info()->projectId;
    const char* const names[] = {"A", "B", "C", "D", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"};
    for (const auto* name : names) {
        aa::SampleInfo info;
        Require(f.writer.CreateSample(name, info).error == aa::ProjectError::None, "sample-create");
        f.samples[name] = info.sampleId;
    }
    Require(f.reader.Open(root, aa::ProjectAccess::ReadOnly).error == aa::ProjectError::None, "reader-open");

    RunScenario("entry-and-into", [&] { ScenarioEntryAndInto(f); });
    RunScenario("write-watch", [&] { ScenarioWriteWatch(f); });
    RunScenario("over-call", [&] { ScenarioOverCall(f); });
    RunScenario("out", [&] { ScenarioOut(f); });
    if (!f.docText.empty()) {
        RunScenario("read-rejections", [&] { ScenarioReadRejections(f); });
    } else {
        std::fprintf(stderr, "SKIP read-rejections: no live document from entry-and-into\n");
    }

    std::printf("RESULT=%s checks=%u failures=%u\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == kEventCount + 4 && std::wcscmp(argv[1], L"--child") == 0) {
        return ChildMain(static_cast<unsigned>(std::wcstoul(argv[2], nullptr, 10)), argv + 3);
    }
    std::wstring root;
    std::wstring exe;
    std::wstring diag;
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view argument = argv[index];
        if (argument == L"--root" && index + 1 < argc) {
            root = argv[++index];
        } else if (argument == L"--exe" && index + 1 < argc) {
            exe = argv[++index];
        } else if (argument == L"--diag-dir" && index + 1 < argc) {
            diag = argv[++index];
        } else {
            return 2;
        }
    }
    if (root.empty() || exe.empty() || diag.empty()) { return 2; }
    g_diagDir = diag;
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    try {
        return RunAll(root, exe);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FATAL %s\n", error.what());
        return 1;
    }
}

