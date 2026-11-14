#include "Proxy.h"
#include "ControlProtocol.h"
#include "../DebuggerBackend/KswordDebuggerFileProtocol.h"
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

extern "C" unsigned long __stdcall KSwordBackendCall(KSWORD_DEBUGGER_CALL* call);

namespace ksword::titan
{
    namespace
    {
        std::mutex controlMutex;
        std::wstring environment(const wchar_t* name)
        {
            wchar_t buffer[32768]{};
            const DWORD count = GetEnvironmentVariableW(name, buffer, _countof(buffer));
            return count == 0 || count >= _countof(buffer) ? std::wstring{} : std::wstring(buffer, count);
        }
        KSWORD_DEBUGGER_POLICY_STATUS adapterPolicyStatus()
        {
            std::lock_guard<std::recursive_mutex> policy(policyMutex);
            auto actual = debugger::backend().policyStatus();
            const auto installedPath = adapterBreakpointPath();
            if (installedPath == KSWORD_DEBUGGER_PATH_SHADOW ||
                (installedPath == KSWORD_DEBUGGER_PATH_EPT && actual.activePath == KSWORD_DEBUGGER_PATH_NATIVE))
                actual.activePath = installedPath;
            actual.activeBreakpoints = (std::max)(actual.activeBreakpoints, static_cast<std::uint32_t>(adapterBreakpointCount()));
            if (actual.activeBreakpoints != 0 || hasPendingBindingChanges() || hasPendingDebug() || (nativeProcessId() != 0 && !nativeEventHeld())) actual.canChangeOptions = 0;
            return actual;
        }
        DWORD selectConfiguration(DWORD enabled, const KSWORD_DEBUGGER_OPTIONS* requested,
            KSWORD_DEBUGGER_BACKEND_STATUS& state)
        {
            std::lock_guard<std::mutex> lock(controlMutex);
            std::lock_guard<std::recursive_mutex> policy(policyMutex);
            auto& backend = debugger::backend();
            const auto original = backend.options();
            const auto options = requested == nullptr ? original : *requested;
            state = backend.status();
            if (options.version != KSWORD_DEBUGGER_OPTIONS_VERSION || options.size != sizeof(options)) return ERROR_REVISION_MISMATCH;
            if (enabled > 1 || !control::valid(options)) return ERROR_INVALID_PARAMETER;
            const auto status = adapterPolicyStatus();
            if (!control::changeAllowed(enabled != 0, options, state.useHvm != 0, original,
                nativeProcessId() != 0 && !nativeEventHeld(), status.canChangeOptions == 0))
            {
                log("Policy change refused: source=Tab/C-ABI error=170 -> actual=" +
                    std::to_string(status.activePath) + "; pause the debugger and remove active breakpoint/Shadow write bindings");
                return ERROR_BUSY;
            }
            if (replayProvider() && ((enabled != 0) != (state.useHvm != 0) || !control::same(options, original)))
            {
                log("HVM policy change refused: replay provider owns synthetic memory/handles; stop replay before changing the next live-session policy");
                return ERROR_NOT_SUPPORTED;
            }
            const bool selectionChanged = (enabled != 0) != (state.useHvm != 0);
            if (!selectionChanged && control::same(options, original)) return ERROR_SUCCESS;
            DWORD error = backend.setOptions(options);
            if (error != ERROR_SUCCESS) { state = backend.status(); return error; }
            if (selectionChanged)
            {
                if (enabled != 0 && !backend.initialize()) error = GetLastError();
                else error = backend.setUseHvm(enabled != 0);
                hvmSelected = backend.status().useHvm != 0;
                if (error == ERROR_SUCCESS && hvmSelected.load() && nativeEventHeld())
                {
                    error = adoptCurrentNativeSession();
                    if (error != ERROR_SUCCESS) { (void)backend.setUseHvm(false); (void)releaseSession(); }
                }
                if (error != ERROR_SUCCESS) (void)backend.setOptions(original);
            }
            state = backend.status(); hvmSelected = state.useHvm != 0;
            const auto actual = adapterPolicyStatus();
            log("Policy request: source=Tab/C-ABI error=" + std::to_string(error) + " -> actual=" +
                std::to_string(actual.activePath) + " mode=" + std::to_string(actual.options.mode) +
                " useHvm=" + std::to_string(state.useHvm) + " allowFallback=" + std::to_string(actual.options.allowFallback));
            if (actual.options.mode == KSWORD_DEBUGGER_MODE_STEALTH)
                log("Stealth execution policy selected; Windows debug-event transport remains active; debug-port hiding is not provided");
            return error;
        }
        void writeAck(const std::filesystem::path& path, const std::string& session,
            std::uint64_t revision, DWORD error)
        {
            const auto temporary = std::filesystem::path(path.wstring() + L".tmp");
            std::string packet;
            {
                std::lock_guard<std::recursive_mutex> policy(policyMutex);
                packet = control::ack(session, revision, error, debugger::backend().status(), adapterPolicyStatus());
            }
            {
                std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
                if (!stream) return;
                stream << packet; stream.flush(); if (!stream) return;
            }
            (void)MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        }
    }
    void startControlWorker()
    {
        const auto controlPath = environment(L"KSWORD_DEBUGGER_CONTROL_FILE");
        const auto state = environment(L"KSWORD_DEBUGGER_STATE_FILE");
        const auto wideSession = environment(L"KSWORD_DEBUGGER_SESSION_ID");
        if (controlPath.empty() || state.empty() || wideSession.empty()) return;
        std::string session;
        for (const wchar_t c : wideSession) { if (c < 0x21 || c > 0x7E) return; session.push_back(static_cast<char>(c)); }
        if (!control::sessionValid(session)) return;
        // Both proxy and native module were pinned before this worker starts.
        std::thread([controlPath, state, session] {
            std::uint64_t previous = 0; DWORD lastError = ERROR_SUCCESS; unsigned int ticks = 0;
            writeAck(state, session, previous, lastError);
            for (;;)
            {
                std::string packet; control::Request request;
                (void)debugger::readControlPacket(controlPath, packet);
                if (control::parseRequest(packet, request) && request.session == session && request.revision > previous)
                {
                    KSWORD_DEBUGGER_BACKEND_STATUS actual{};
                    lastError = selectConfiguration(request.selected, request.extended ? &request.options : nullptr, actual);
                    previous = request.revision; writeAck(state, session, previous, lastError);
                }
                else
                {
                    // An identified malformed request receives a failure ACK,
                    // without adopting any partial options or a stale session.
                    std::istringstream stream(packet); std::string candidate; std::uint64_t revision = 0;
                    if (stream >> candidate && candidate == session && control::number(stream, revision) && revision > previous)
                    { previous = revision; lastError = ERROR_INVALID_PARAMETER; writeAck(state, session, previous, lastError); log("Invalid policy packet: source=control file error=87 -> actual policy retained"); }
                }
                // Publish changing pause/binding/actual-path state while idle.
                if (++ticks >= 5) { ticks = 0; writeAck(state, session, previous, lastError); }
                Sleep(100);
            }
        }).detach();
    }
}

// SEH copying stays outside C++ lock scopes, including failed actual-state ACKs.
static bool safeCopy(void* destination, const void* source, SIZE_T bytes) noexcept
{
    __try { if (destination == nullptr || source == nullptr) return false; memcpy(destination, source, bytes); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

extern "C" DWORD __stdcall KSwordTitanControl(DWORD enabled, KSWORD_DEBUGGER_BACKEND_STATUS* status)
{
    using namespace ksword::titan;
    DWORD error = ensureNative(); if (error != ERROR_SUCCESS) return error;
    KSWORD_DEBUGGER_BACKEND_STATUS actual{};
    error = selectConfiguration(enabled, nullptr, actual);
    if (status != nullptr && !safeCopy(status, &actual, sizeof(actual))) return ERROR_NOACCESS;
    return error;
}

extern "C" unsigned long __stdcall KSwordDebuggerCall(KSWORD_DEBUGGER_CALL* call)
{
    using namespace ksword::titan;
    KSWORD_DEBUGGER_CALL snapshot{};
    if (!safeCopy(&snapshot, call, sizeof(snapshot))) return ERROR_NOACCESS;
    // This independent channel must not initialize Titan, install its Windows
    // event seam, or start its native-session monitor merely to use an IOCTL.
    if (snapshot.command == KSWORD_DEBUGGER_NOATTACH || snapshot.command == KSWORD_DEBUGGER_KERNEL_NOATTACH) return KSwordBackendCall(call);
    if (snapshot.command == KSWORD_DEBUGGER_OPERATION_LAYOUT && snapshot.inputBytes == sizeof(DWORD))
    {
        DWORD requested = 0;
        if (!safeCopy(&requested, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(snapshot.input)), sizeof(requested)))
            return ERROR_NOACCESS;
        if (requested == KSWORD_DEBUGGER_NOATTACH || requested == KSWORD_DEBUGGER_KERNEL_NOATTACH) return KSwordBackendCall(call);
    }
    const DWORD error = ensureNative(); if (error != ERROR_SUCCESS) return error;
    if (snapshot.command == KSWORD_DEBUGGER_QUERY_ENGINE || snapshot.command == KSWORD_DEBUGGER_QUERY_BREAKPOINT)
    {
        snapshot.bytesReturned = 0;
        const SIZE_T outputBytes = snapshot.command == KSWORD_DEBUGGER_QUERY_ENGINE ? sizeof(KSWORD_DEBUGGER_ENGINE_INFO) : sizeof(KSWORD_DEBUGGER_BREAKPOINT_INFO);
        const SIZE_T inputBytes = snapshot.command == KSWORD_DEBUGGER_QUERY_ENGINE ? 0 : sizeof(KSWORD_DEBUGGER_BREAKPOINT_QUERY);
        if (snapshot.version != KSWORD_DEBUGGER_API_VERSION || snapshot.size != sizeof(snapshot) || snapshot.reserved != 0) snapshot.error = ERROR_REVISION_MISMATCH;
        else if (snapshot.inputBytes != inputBytes) snapshot.error = ERROR_INVALID_PARAMETER;
        else if (snapshot.outputBytes < outputBytes) snapshot.error = ERROR_INSUFFICIENT_BUFFER;
        else
        {
            KSWORD_DEBUGGER_ENGINE_INFO engine{}; KSWORD_DEBUGGER_BREAKPOINT_INFO breakpoint{};
            KSWORD_DEBUGGER_BREAKPOINT_QUERY query{};
            if (snapshot.command == KSWORD_DEBUGGER_QUERY_ENGINE) snapshot.error = queryEngineInfo(engine);
            else if (!safeCopy(&query, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(snapshot.input)), sizeof(query))) snapshot.error = ERROR_NOACCESS;
            else snapshot.error = queryBreakpoint(query, breakpoint);
            const void* data = snapshot.command == KSWORD_DEBUGGER_QUERY_ENGINE ? static_cast<const void*>(&engine) : static_cast<const void*>(&breakpoint);
            if (snapshot.error == ERROR_SUCCESS || snapshot.error == ERROR_NOT_FOUND)
            {
                if (!safeCopy(reinterpret_cast<void*>(static_cast<std::uintptr_t>(snapshot.output)), data, outputBytes)) snapshot.error = ERROR_NOACCESS;
                else snapshot.bytesReturned = static_cast<DWORD>(outputBytes);
            }
        }
        return safeCopy(call, &snapshot, sizeof(snapshot)) ? snapshot.error : ERROR_NOACCESS;
    }
    if (snapshot.command == KSWORD_DEBUGGER_USE_HVM || snapshot.command == KSWORD_DEBUGGER_SET_OPTIONS || snapshot.command == KSWORD_DEBUGGER_QUERY_POLICY)
    {
        snapshot.bytesReturned = 0;
        const SIZE_T outputBytes = snapshot.command == KSWORD_DEBUGGER_USE_HVM ? sizeof(KSWORD_DEBUGGER_BACKEND_STATUS) :
            snapshot.command == KSWORD_DEBUGGER_SET_OPTIONS ? sizeof(KSWORD_DEBUGGER_OPTIONS) : sizeof(KSWORD_DEBUGGER_POLICY_STATUS);
        const SIZE_T inputBytes = snapshot.command == KSWORD_DEBUGGER_USE_HVM ? sizeof(DWORD) :
            snapshot.command == KSWORD_DEBUGGER_SET_OPTIONS ? sizeof(KSWORD_DEBUGGER_OPTIONS) : 0;
        if (snapshot.version != KSWORD_DEBUGGER_API_VERSION || snapshot.size != sizeof(snapshot) || snapshot.reserved != 0) snapshot.error = ERROR_REVISION_MISMATCH;
        else if (snapshot.inputBytes != inputBytes) snapshot.error = ERROR_INVALID_PARAMETER;
        else if (snapshot.outputBytes < outputBytes) snapshot.error = ERROR_INSUFFICIENT_BUFFER;
        else if (snapshot.output == 0) snapshot.error = ERROR_NOACCESS;
        else
        {
            DWORD enabled = 0; KSWORD_DEBUGGER_OPTIONS options{}; KSWORD_DEBUGGER_BACKEND_STATUS state{};
            const auto input = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(snapshot.input));
            if (snapshot.command == KSWORD_DEBUGGER_USE_HVM)
            {
                if (!safeCopy(&enabled, input, sizeof(enabled))) snapshot.error = ERROR_NOACCESS;
                else snapshot.error = selectConfiguration(enabled, nullptr, state);
            }
            else if (snapshot.command == KSWORD_DEBUGGER_SET_OPTIONS)
            {
                if (!safeCopy(&options, input, sizeof(options))) snapshot.error = ERROR_NOACCESS;
                else snapshot.error = selectConfiguration(ksword::debugger::backend().status().useHvm, &options, state);
            }
            else snapshot.error = ERROR_SUCCESS;
            const auto actual = adapterPolicyStatus();
            const auto destination = reinterpret_cast<void*>(static_cast<std::uintptr_t>(snapshot.output));
            if (snapshot.command == KSWORD_DEBUGGER_USE_HVM) state = ksword::debugger::backend().status();
            const void* actualOutput = snapshot.command == KSWORD_DEBUGGER_USE_HVM ? static_cast<const void*>(&state) :
                snapshot.command == KSWORD_DEBUGGER_SET_OPTIONS ? static_cast<const void*>(&actual.options) : static_cast<const void*>(&actual);
            if (!safeCopy(destination, actualOutput, outputBytes)) snapshot.error = ERROR_NOACCESS;
            else snapshot.bytesReturned = static_cast<DWORD>(outputBytes);
        }
        return safeCopy(call, &snapshot, sizeof(snapshot)) ? snapshot.error : ERROR_NOACCESS;
    }
    // Options and layout/status queries are valid with no loaded driver.
    if (snapshot.command >= KSWORD_DEBUGGER_HVM_STATUS && !ksword::debugger::backend().initialize()) return GetLastError();
    const DWORD result = KSwordBackendCall(call);
    hvmSelected = ksword::debugger::backend().status().useHvm != 0;
    return result;
}
