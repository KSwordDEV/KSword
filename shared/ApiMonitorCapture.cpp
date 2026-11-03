#include "ApiMonitorCapture.h"
#include "ApiMonitorInjection.h"
#include "ApiMonitorInjectionBroker.h"
#ifdef _WIN64
#include "ApiMonitorR0Injection.h"
#endif
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <set>
#include <thread>

namespace ks::winapi_monitor {
#ifdef _WIN64
namespace {
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE v = nullptr) : value(v) {}
    ~Handle() { reset(); }
    void reset(HANDLE v = nullptr) { if (value && value != INVALID_HANDLE_VALUE) ::CloseHandle(value); value = v; }
};
template<std::size_t N> std::wstring text(const wchar_t (&s)[N]) {
    return {s, std::find(s, s + N, L'\0')};
}
std::wstring uniqueSession() {
    LARGE_INTEGER counter{}; ::QueryPerformanceCounter(&counter);
    return L"cli_" + std::to_wstring(::GetCurrentProcessId()) + L"_" + std::to_wstring(counter.QuadPart);
}
// Publish a complete UTF-16 INI in one rename. Never expose a partially written
// config to a resident Agent, and never leave a failed temp file in the namespace.
bool publish(const std::wstring& path, const std::wstring& body, DWORD pid, std::wstring& error) {
    const auto temporary = path + L"." + uniqueSession() + L".tmp";
    Handle file(::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) return platformFailure(&error, L"create session config", ::GetLastError());
    const std::wstring data = L"\xfeff" + body;
    const auto bytes = static_cast<DWORD>(data.size() * sizeof(wchar_t)); DWORD written = 0;
    bool ok = ::WriteFile(file.value, data.data(), bytes, &written, nullptr) && written == bytes && ::FlushFileBuffers(file.value);
    const DWORD failure = ok ? ERROR_SUCCESS : ::GetLastError(); file.reset();
    if (ok) ok = grantSessionFileRead(temporary, pid, &error);
    if (ok) {
        // GetPrivateProfileString may briefly open a resident Agent's old INI
        // without delete sharing. Retry the atomic rename, never truncate it.
        const auto deadline = ::GetTickCount64() + 2000;
        while (!::MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            const auto code = ::GetLastError();
            if ((code != ERROR_ACCESS_DENIED && code != ERROR_SHARING_VIOLATION) || ::GetTickCount64() >= deadline) {
                ok = platformFailure(&error, L"publish session config", code); break;
            }
            ::Sleep(10);
        }
    }
    if (!ok) { ::DeleteFileW(temporary.c_str()); if (error.empty()) platformFailure(&error, L"write session config", failure ? failure : ERROR_WRITE_FAULT); }
    return ok;
}
struct Reader {
    CaptureProcess evidence;
    Handle process, pipe;
    SessionLease lease;
    std::unique_ptr<CoverageSnapshotReceiver> receiver;
    ApiMonitorEventPacket packet{};
    DWORD offset = 0;
    bool disconnected = false;
};
void finishPipeRead(Reader& reader, CaptureResult& result, DWORD failure) {
    auto& state = reader.evidence;
    const bool eof = failure == ERROR_BROKEN_PIPE || failure == ERROR_PIPE_NOT_CONNECTED || failure == ERROR_HANDLE_EOF;
    if (reader.offset) { ++result.invalidPackets; state.coverageStale = true; }
    if (!state.exited && (!state.removed || !eof || reader.offset)) {
        state.pipeError = failure ? failure : ERROR_HANDLE_EOF;
        state.coverageStale = true;
    }
    if (reader.receiver->stale() || (state.finalRevision && state.revision < state.finalRevision))
        state.coverageStale = true;
    reader.pipe.reset(); reader.disconnected = true;
}
class Capture {
public:
    Capture(const CaptureRequest& r, const std::atomic_bool& c) : request(r), cancel(c) {}
    ~Capture() { if (broker) broker->stop(); }
    CaptureResult run();
private:
    const CaptureRequest& request;
    const std::atomic_bool& cancel;
    CaptureResult result;
    SessionLease rootLease;
    Handle cancelEvent;
    std::unique_ptr<InjectionBroker> broker;
    std::vector<std::unique_ptr<Reader>> readers;
    std::vector<DWORD> pendingChildren;
    bool stopping = false, startupSucceeded = false, stopFailure = false;
    std::uint64_t startedAt = ::GetTickCount64();
    bool start();
    bool addReader(DWORD pid, std::uint64_t expected = 0);
    void poll();
    void pollReader(Reader& reader);
    void consume(Reader& reader, const ApiMonitorEventPacket& packet);
    void discoverChildren();
    bool writeStop(DWORD pid, std::uint64_t creation, bool root, bool* written = nullptr);
    void cleanup();
    void error(const std::wstring& value) { result.errors.push_back(value); }
};
bool Capture::addReader(DWORD pid, std::uint64_t expected) {
    for (const auto& reader : readers) if (reader->evidence.pid == pid) return true;
    if (readers.size() >= 8192) { error(L"child reader capacity exceeded"); return false; }
    auto reader = std::make_unique<Reader>(); reader->evidence.pid = pid;
    reader->process.reset(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!reader->process.value) { error(L"open capture target " + std::to_wstring(pid) + L"; error=" + std::to_wstring(::GetLastError())); return false; }
    reader->evidence.creation = processCreationIdentity(reader->process.value);
    if (!reader->evidence.creation || (expected && reader->evidence.creation != expected)) {
        error(L"capture target identity changed: " + std::to_wstring(pid)); return false;
    }
    std::wstring session = result.sessionId;
    if (pid != request.pid) {
        DWORD failure = 0;
        if (!reader->lease.acquire(pid, &failure)) { error(L"child session lease unavailable: " + std::to_wstring(pid)); return false; }
        wchar_t value[1024]{};
        ::GetPrivateProfileStringW(L"monitor", L"session_id", L"", value, 1024, buildConfigPathForPid(pid).c_str());
        session = value;
        if (session.rfind(result.sessionId + L"_", 0) != 0) { error(L"foreign child session rejected"); return false; }
    }
    reader->evidence.session = sessionIdentity(session);
    reader->receiver = std::make_unique<CoverageSnapshotReceiver>(pid, reader->evidence.session);
    readers.push_back(std::move(reader)); return true;
}
bool Capture::start() {
    result.sessionId = uniqueSession();
    DWORD failure = 0;
    if (!rootLease.acquire(request.pid, &failure)) { error(L"session lease unavailable; error=" + std::to_wstring(failure)); return false; }
    if (!addReader(request.pid)) return false;
    std::wstring detail;
    if (!resolveAgentPath(request.pid, request.agentPath, &result.agentPath, &detail)) { error(detail); return false; }
    if (!addSessionDirectoryReader(request.pid, &detail)) { error(detail); return false; }
    result.configPath = buildConfigPathForPid(request.pid); result.stopPath = buildStopFlagPathForPid(request.pid);
    cancelEvent.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!cancelEvent.value) { error(L"create cancellation event failed"); return false; }
    InjectionEndpoint endpoint;
    if (request.autoChildren) {
        broker = std::make_unique<InjectionBroker>();
        InjectionBroker::Injector childInjector;
        if (request.useR0Injection) childInjector = [](DWORD pid, const std::wstring& path, std::wstring* error,
                std::uint64_t creation, HANDLE stop) { return injectAgentR0(pid, path, error, stop, creation); };
        if (!broker->start(request.pid, result.agentPath, result.sessionId, result.stopPath, &detail, std::move(childInjector))) { error(detail); return false; }
        endpoint = broker->endpoint();
    }
    std::wstring sid;
    if (!currentProcessUserSidString(&sid)) { error(L"read controller SID failed"); return false; }
    std::wstring body = L"[monitor]\r\n";
    auto append = [&](const std::wstring& key, const std::wstring& value) { body += key + L"=" + value + L"\r\n"; };
    for (const auto& option : request.options) append(option.first, option.second);
    append(L"pipe_name", buildPipeNameForPid(request.pid)); append(L"session_id", result.sessionId);
    append(L"stop_flag_path", result.stopPath); append(L"root_stop_flag_path", result.stopPath);
    append(L"controller_sid", sid); append(L"agent_dll_path", result.agentPath);
    append(L"auto_inject_child", request.autoChildren ? L"1" : L"0");
    append(L"injection_broker_pipe", endpoint.pipeName); append(L"injection_broker_token", endpoint.token);
    append(L"injection_broker_pid", std::to_wstring(endpoint.hostPid)); append(L"injection_broker_creation", std::to_wstring(endpoint.hostCreation));
    if (cancel.load() || ::WaitForSingleObject(readers.front()->process.value, 0) != WAIT_TIMEOUT) return false;
    if (!publish(result.configPath, body, request.pid, detail)) { error(detail); return false; }
    result.configPublished = true;
    if (!::DeleteFileW(result.stopPath.c_str()) && ::GetLastError() != ERROR_FILE_NOT_FOUND) { error(L"remove old stop marker failed"); return false; }
    result.reusedResident = remoteImageLoaded(request.pid, result.agentPath);
    if (!result.reusedResident) {
        // The injector has a bounded native wait; a watcher translates Ctrl+C to
        // its cancellation handle without ever closing handles from another thread.
        std::atomic_bool done{false};
        std::thread watcher([&] { while (!done.load()) { if (cancel.load()) { ::SetEvent(cancelEvent.value); break; } ::Sleep(10); } });
        bool injected = false;
        try {
            injected = request.useR0Injection
                ? injectAgentR0(request.pid, result.agentPath, &detail, cancelEvent.value, readers.front()->evidence.creation)
                : injectAgent(request.pid, result.agentPath, &detail, cancelEvent.value, readers.front()->evidence.creation);
        }
        catch (...) { done.store(true); watcher.join(); throw; }
        done.store(true); watcher.join();
        if (!injected) { error(detail); return false; }
    }
    const auto deadline = ::GetTickCount64() + request.startupTimeoutMs;
    while (::GetTickCount64() < deadline && !cancel.load()) {
        poll();
        const auto& root = readers.front()->evidence;
        if (root.installed) return true;
        if (root.exited || root.installFailed || root.pipeError || root.removed) return false;
        ::Sleep(5);
    }
    error(cancel.load() ? L"startup cancelled" : L"timed out waiting for HooksInstalled"); return false;
}
void Capture::consume(Reader& reader, const ApiMonitorEventPacket& packet) {
    auto& state = reader.evidence;
    if (packet.size != sizeof(packet) || packet.version != kProtocolVersion || packet.pid != state.pid || packet.sessionIdentity != state.session) {
        ++result.invalidPackets; return;
    }
    if (isCoverageEvent(packet.eventKind)) {
        if (reader.receiver->consume(packet)) {
            state.coverage = reader.receiver->items(); state.revision = reader.receiver->revision(); state.coverageComplete = true;
        }
        state.coverageStale = reader.receiver->stale(); return;
    }
    ++result.received;
    if (packet.category == static_cast<std::uint32_t>(EventCategory::Internal) && text(packet.moduleName) == L"Agent") {
        const auto name = text(packet.apiName);
        if (name == L"HooksInstalled") state.installed = true;
        if (name == L"HooksRemoved") { state.removed = true; state.finalRevision = packet.snapshotRevision; }
        if (name == L"InstallHooksFailed") state.installFailed = true;
        if (name == L"AgentFailure") error(L"Agent failure: " + text(packet.detailText));
        if (name == L"HooksPartial") state.partialHooks = true;
        if (name == L"AutoInjectChild" && request.autoChildren && !stopping) {
            const auto detail = text(packet.detailText); const auto marker = detail.find(L"childPid=");
            if (marker != std::wstring::npos) {
                const auto begin = detail.c_str() + marker + 9; wchar_t* end = nullptr;
                const auto pid = std::wcstoul(begin, &end, 10);
                if (end != begin && pid > 4) pendingChildren.push_back(static_cast<DWORD>(pid));
            }
        }
        if (name == L"EventsDropped") {
            const auto value = text(packet.detailText); wchar_t* end = nullptr;
            const auto count = ::_wcstoui64(value.c_str(), &end, 10);
            if (!value.empty() && end && !*end) state.agentDropped = std::max(state.agentDropped, count);
        }
    }
    // Control was consumed above and cannot be excluded. Pre-filtering happens
    // before the bounded event buffer and does not masquerade as packet loss.
    if (request.preFilter.excludes(packet) || request.importedPreFilter.excludes(packet)) { ++result.preFiltered; return; }
    if (request.collectTimeline) result.timeline.append(packet);
    if (result.events.size() == request.eventLimit) { result.events.pop_front(); ++result.bufferDropped; }
    result.events.push_back(packet);
}
void Capture::pollReader(Reader& reader) {
    auto& state = reader.evidence;
    state.exited = ::WaitForSingleObject(reader.process.value, 0) == WAIT_OBJECT_0;
    if (!reader.pipe.value) {
        if (state.exited || reader.disconnected || state.pipeError) return;
        HANDLE pipe = ::CreateFileW(buildPipeNameForPid(state.pid).c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            const auto failure = ::GetLastError();
            if (failure != ERROR_FILE_NOT_FOUND && failure != ERROR_PIPE_BUSY) state.pipeError = failure;
            return;
        }
        reader.pipe.reset(pipe); ULONG serverPid = 0;
        if (!::GetNamedPipeServerProcessId(pipe, &serverPid) || serverPid != state.pid || processCreationIdentity(reader.process.value) != state.creation) {
            state.pipeError = ERROR_ACCESS_DENIED; reader.pipe.reset(); return;
        }
        state.connected = true;
    }
    // Limit each turn so one hot producer cannot starve cancellation/children.
    for (unsigned budget = 0; budget < 512; ++budget) {
        DWORD available = 0;
        if (!::PeekNamedPipe(reader.pipe.value, nullptr, 0, nullptr, &available, nullptr)) {
            finishPipeRead(reader, result, ::GetLastError()); return;
        }
        if (!available) return;
        const auto remaining = static_cast<DWORD>(sizeof(reader.packet)) - reader.offset;
        DWORD count = 0;
        if (!::ReadFile(reader.pipe.value, reinterpret_cast<unsigned char*>(&reader.packet) + reader.offset, std::min(remaining, available), &count, nullptr) || !count) {
            finishPipeRead(reader, result, ::GetLastError()); return;
        }
        reader.offset += count;
        if (reader.offset == sizeof(reader.packet)) { consume(reader, reader.packet); reader.offset = 0; }
    }
}
void Capture::discoverChildren() {
    // Only the authenticated broker can register an injected descendant. Events
    // are notifications; verify the child INI session and retained process ID.
    std::vector<DWORD> candidates; candidates.swap(pendingChildren);
    for (const auto pid : candidates) addReader(pid);
}
void Capture::poll() {
    for (auto& reader : readers) pollReader(*reader);
    if (request.autoChildren && !stopping) discoverChildren();
}
bool Capture::writeStop(DWORD pid, std::uint64_t creation, bool root, bool* markerWritten) {
    if (markerWritten) *markerWritten = false;
    Handle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!process.value) return ::GetLastError() == ERROR_INVALID_PARAMETER;
    if (processCreationIdentity(process.value) != creation || ::WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) return true;
    const auto config = buildConfigPathForPid(pid);
    wchar_t session[1024]{}; ::GetPrivateProfileStringW(L"monitor", L"session_id", L"", session, 1024, config.c_str());
    if (root ? result.sessionId != session : std::wstring(session).rfind(result.sessionId + L"_", 0) != 0) return false;
    const auto path = buildStopFlagPathForPid(pid);
    Handle file(::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    DWORD written = 0;
    if (file.value == INVALID_HANDLE_VALUE || !::WriteFile(file.value, "stop", 4, &written, nullptr) || written != 4 || !::FlushFileBuffers(file.value)) return false;
    if (markerWritten) *markerWritten = true;
    file.reset(); std::wstring detail;
    return grantSessionFileRead(path, pid, &detail) && (root || grantSessionFileRead(result.stopPath, pid, &detail));
}
void Capture::cleanup() {
    stopping = true;
    if (!result.configPublished) { result.cleanupComplete = true; return; }
    stopFailure = !writeStop(request.pid, readers.front()->evidence.creation, true, &result.stopWritten);
    if (broker) {
        const auto participants = broker->stopAndTakeParticipants(); broker.reset();
        for (const auto& child : participants) {
            const bool notified = writeStop(child.pid, child.creation, false);
            if (!notified) { stopFailure = true; error(L"cannot stop child " + std::to_wstring(child.pid)); }
            bool known = false; for (const auto& reader : readers) if (reader->evidence.pid == child.pid) known = true;
            if (!known && !addReader(child.pid, child.creation)) {
                Handle process(::OpenProcess(SYNCHRONIZE, FALSE, child.pid));
                if (process.value && ::WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT) stopFailure = true;
            }
        }
    }
    const auto deadline = ::GetTickCount64() + request.stopTimeoutMs;
    do {
        poll();
        bool complete = !stopFailure;
        for (const auto& reader : readers) complete = complete && ((reader->evidence.removed && reader->disconnected) || reader->evidence.exited);
        if (complete) { result.cleanupComplete = true; break; }
        ::Sleep(5);
    } while (::GetTickCount64() < deadline);
    if (!result.cleanupComplete) error(L"stop not confirmed for every target; stop markers retained for Agent retry");
    // The persistent marker must remain: a late loader or resident worker must
    // never restart this session after the controller has released its lease.
}
CaptureResult Capture::run() {
    try {
        startupSucceeded = start();
        if (startupSucceeded) {
            const auto deadline = ::GetTickCount64() + request.durationMs;
            while (!cancel.load() && ::GetTickCount64() < deadline) {
                poll();
                if (readers.front()->evidence.exited || readers.front()->evidence.pipeError) break;
                if(readers.front()->evidence.removed){error(L"Agent stopped before requested interval");break;}
                ::Sleep(5);
            }
            result.completedInterval = ::GetTickCount64() >= deadline;
        }
    } catch (const std::exception&) { error(L"capture controller exception"); }
    result.cancelled = cancel.load();
    try { cleanup(); } catch (...) { error(L"capture cleanup exception; stop confirmation unavailable"); }
    bool partial = !result.completedInterval || result.cancelled || !result.cleanupComplete || result.bufferDropped || result.invalidPackets || !result.errors.empty();
    for (auto& reader : readers) {
        const auto& state = reader->evidence;
        partial = partial || state.pipeError || state.agentDropped || state.partialHooks || state.installFailed || !state.installed || !state.coverageComplete || state.coverageStale;
        result.processes.push_back(std::move(reader->evidence));
    }
    result.code = startupSucceeded ? (partial ? 6 : 0) : result.cancelled ? 6 : 3;
    result.elapsedMs = ::GetTickCount64() - startedAt;
    return std::move(result);
}
}
CaptureResult captureApiMonitor(const CaptureRequest& request, const std::atomic_bool& cancel) {
    const std::set<std::wstring> allowed{L"enable_file",L"enable_registry",L"enable_network",L"enable_process",L"enable_loader",L"enable_clipboard",
        L"capture_call_stack",L"enable_raw_fallback",L"raw_use_default_denylist",L"raw_modules",L"raw_denylist",L"fake_success_enabled",L"fake_success_raw_fallback",
        L"fake_success_rules",L"detail_limit",L"clipboard_read_action",L"clipboard_write_action",L"clipboard_enum_action"};
    bool valid = request.pid > 4 && request.pid != ::GetCurrentProcessId() && !request.agentPath.empty()
        && request.durationMs >= 100 && request.durationMs <= 120000 && request.eventLimit && request.eventLimit <= 100000
        && request.startupTimeoutMs >= 1000 && request.startupTimeoutMs <= 120000 && request.stopTimeoutMs >= 1000 && request.stopTimeoutMs <= 120000;
    for (const auto& [key, value] : request.options)
        valid = valid && allowed.count(key) && value.size() <= 16000 && value.find_first_of(L"\r\n\0", 0, 3) == std::wstring::npos;
    if (!valid) { CaptureResult result; result.code = 1; result.errors.push_back(L"invalid capture request"); return result; }
    return Capture(request, cancel).run();
}
#else
CaptureResult captureApiMonitor(const CaptureRequest&, const std::atomic_bool&) {
    CaptureResult result; result.code = 5;
    result.errors.push_back(L"API Monitor capture requires the x64 CLI host"); return result;
}
#endif
}
