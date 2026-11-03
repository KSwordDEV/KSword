#include "ApiMonitorInjectionBroker.h"
#include "ApiMonitorInjection.h"
#include "WinApiMonitorProtocol.h"
#include <sddl.h>
#include <thread>
#include <unordered_map>

namespace ks::winapi_monitor
{
    namespace {
        std::wstring brokerIni(const std::wstring& path, const wchar_t* key)
        {
            wchar_t buffer[4096]{};
            const auto count = ::GetPrivateProfileStringW(L"monitor", key, L"", buffer, static_cast<DWORD>(std::size(buffer)), path.c_str());
            return count < std::size(buffer) - 1 ? std::wstring(buffer, count) : std::wstring();
        }
        DWORD processParent(HANDLE process)
        {
            struct Basic { LONG exitStatus; void* peb; ULONG_PTR affinity; LONG priority; ULONG_PTR pid, parent; } info{};
            using Query = LONG(NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
            const auto query = reinterpret_cast<Query>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
            return query && query(process, 0, &info, sizeof(info), nullptr) >= 0 && info.parent <= MAXDWORD
                ? static_cast<DWORD>(info.parent) : 0;
        }
        bool privatePipeSecurity(PSECURITY_DESCRIPTOR* descriptor)
        {
            HANDLE token = nullptr; DWORD size = 0;
            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
            ::GetTokenInformation(token, TokenUser, nullptr, 0, &size);
            std::vector<unsigned char> buffer(size);
            const bool read = size && ::GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
            ::CloseHandle(token); if (!read) return false;
            wchar_t* sid = nullptr;
            if (!::ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) return false;
            const std::wstring acl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + std::wstring(sid) + L")";
            ::LocalFree(sid);
            return ::ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, descriptor, nullptr);
        }
    }
    struct InjectionBroker::State {
        struct Participant { std::uint64_t creation; std::wstring agentPath, session; };
        InjectionEndpoint endpoint;
        std::wstring rootStopPath;
        InjectionBroker::Injector injector;
        std::unordered_map<DWORD, Participant> participants;
        std::unordered_map<DWORD, std::uint64_t> attemptedParticipants;
        HANDLE stopEvent = nullptr, pipe = INVALID_HANDLE_VALUE;
        std::thread worker;
        ~State() {
            if (stopEvent) ::SetEvent(stopEvent);
            if (worker.joinable()) worker.join();
            if (pipe != INVALID_HANDLE_VALUE) ::CloseHandle(pipe);
            if (stopEvent) ::CloseHandle(stopEvent);
        }
        bool stopping() const {
            return ::WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0
                || (!rootStopPath.empty() && ::GetFileAttributesW(rootStopPath.c_str()) != INVALID_FILE_ATTRIBUTES);
        }
        bool authorizeAndInject(ULONG clientPid, const InjectionRequest& request, std::wstring* error)
        {
            if (stopping()) return platformFailure(error, L"injection session stopped", ERROR_OPERATION_ABORTED);
            if (request.size != sizeof(request) || request.version != kInjectionProtocolVersion || request.reserved
                || !std::wmemchr(request.token, 0, std::size(request.token)) || endpoint.token != request.token)
                return platformFailure(error, L"injection session identity mismatch", ERROR_ACCESS_DENIED);
            const auto found = participants.find(clientPid);
            if (found == participants.end() || found->second.creation != request.clientCreation)
                return platformFailure(error, L"unregistered injection requester", ERROR_ACCESS_DENIED);
            const Participant parent = found->second;
            HANDLE client = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, clientPid);
            const bool current = client && processCreationIdentity(client) == parent.creation
                && ::WaitForSingleObject(client, 0) == WAIT_TIMEOUT;
            if (client) ::CloseHandle(client);
            if (!current) return platformFailure(error, L"injection requester exited or changed", ERROR_INVALID_HANDLE);
            HANDLE child = ::OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, request.childPid);
            const bool identity = child && request.childCreation && processCreationIdentity(child) == request.childCreation
                && ::WaitForSingleObject(child, 0) == WAIT_TIMEOUT && processParent(child) == clientPid;
            if (child) ::CloseHandle(child);
            if (!identity) return platformFailure(error, L"child process identity or parent mismatch", ERROR_ACCESS_DENIED);
            std::wstring selected;
            if (!resolveAgentPath(request.childPid, parent.agentPath, &selected, error)) return false;
            const auto config = buildConfigPathForPid(request.childPid);
            const auto session = brokerIni(config, L"session_id");
            if (session.rfind(parent.session + L"_", 0) != 0
                || _wcsicmp(brokerIni(config, L"agent_dll_path").c_str(), selected.c_str()) != 0
                || brokerIni(config, L"root_stop_flag_path") != rootStopPath
                || brokerIni(config, L"injection_broker_pipe") != endpoint.pipeName
                || brokerIni(config, L"injection_broker_token") != endpoint.token)
                return platformFailure(error, L"child configuration does not belong to this session", ERROR_ACCESS_DENIED);
            const auto existing = participants.find(request.childPid);
            if (existing != participants.end() && existing->second.creation == request.childCreation) {
                if (existing->second.session == session && remoteImageLoaded(request.childPid, selected)) return true;
                return platformFailure(error, L"child injection session conflict", ERROR_ALREADY_EXISTS);
            }
            if (participants.size() >= 8192)
                return platformFailure(error, L"injection session participant capacity reached", ERROR_NOT_ENOUGH_QUOTA);
            if (!attemptedParticipants.contains(request.childPid) && attemptedParticipants.size() >= 8192)
                return platformFailure(error, L"injection session participant capacity reached", ERROR_NOT_ENOUGH_QUOTA);
            attemptedParticipants[request.childPid] = request.childCreation;
            if (injector) {
                if (!injector(request.childPid, selected, error, request.childCreation, stopEvent)) return false;
            } else if (!injectAgentNative(request.childPid, selected, error, request.childCreation, stopEvent)) return false;
            if (stopping()) return platformFailure(error, L"injection session stopped during load", ERROR_OPERATION_ABORTED);
            participants[request.childPid] = {request.childCreation, selected, session};
            return true;
        }
        void run() noexcept {
            while (::WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0) {
                OVERLAPPED connection{}; connection.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (!connection.hEvent) break;
                BOOL connected = ::ConnectNamedPipe(pipe, &connection);
                const DWORD code = connected ? ERROR_SUCCESS : ::GetLastError();
                if (code == ERROR_PIPE_CONNECTED) connected = TRUE;
                else if (code == ERROR_IO_PENDING) {
                    HANDLE waits[] = {connection.hEvent, stopEvent};
                    if (::WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
                        DWORD ignored = 0; connected = ::GetOverlappedResult(pipe, &connection, &ignored, FALSE);
                    } else {
                        ::CancelIoEx(pipe, &connection); DWORD ignored = 0;
                        ::GetOverlappedResult(pipe, &connection, &ignored, TRUE);
                    }
                }
                ::CloseHandle(connection.hEvent);
                if (!connected || ::WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) break;
                ULONG clientPid = 0; InjectionRequest request{}; InjectionResponse response{};
                if (::GetNamedPipeClientProcessId(pipe, &clientPid)
                    && injectionPipeTransfer(pipe, &request, sizeof(request), false, stopEvent, 2000)) {
                    std::wstring detail;
                    try {
                        const bool injected = authorizeAndInject(clientPid, request, &detail);
                        response.error = injected ? ERROR_SUCCESS : ::GetLastError();
                    } catch (...) { response.error = ERROR_NOT_ENOUGH_MEMORY; detail = L"injection broker allocation failed"; }
                    wcsncpy_s(response.detail, detail.c_str(), _TRUNCATE);
                    injectionPipeTransfer(pipe, &response, sizeof(response), true, stopEvent, 2000);
                }
                ::DisconnectNamedPipe(pipe);
            }
        }
    };
    InjectionBroker::InjectionBroker() = default;
    InjectionBroker::~InjectionBroker() = default;
    void InjectionBroker::stop() { m_state.reset(); }
    std::vector<InjectionParticipant> InjectionBroker::stopAndTakeParticipants()
    {
        if (!m_state) return {};
        if (m_state->stopEvent) ::SetEvent(m_state->stopEvent);
        if (m_state->worker.joinable()) m_state->worker.join();
        std::vector<InjectionParticipant> result;
        result.reserve(m_state->attemptedParticipants.size());
        for (const auto& [pid, creation] : m_state->attemptedParticipants) result.push_back({pid, creation});
        m_state.reset();
        return result;
    }
    InjectionEndpoint InjectionBroker::endpoint() const { return m_state ? m_state->endpoint : InjectionEndpoint{}; }
    bool InjectionBroker::start(DWORD rootPid, const std::wstring& agentPath, const std::wstring& session,
        const std::wstring& rootStopPath, std::wstring* error, Injector injector)
    {
        static_assert(sizeof(void*) == 8, "InjectionBroker must be hosted by the x64 main program");
        stop();
        if (!rootPid || session.empty() || session.size() >= 128 || session.find_first_not_of(L"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_") != std::wstring::npos
            || rootStopPath.empty()) return platformFailure(error, L"invalid injection broker session", ERROR_INVALID_PARAMETER);
        HANDLE root = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, rootPid);
        const auto creation = root ? processCreationIdentity(root) : 0;
        if (root) ::CloseHandle(root);
        if (!creation) return platformFailure(error, L"injection broker root unavailable", ERROR_INVALID_HANDLE);
        auto state = std::make_unique<State>();
        state->endpoint.hostPid = ::GetCurrentProcessId(); state->endpoint.hostCreation = processCreationIdentity(::GetCurrentProcess());
        state->endpoint.token = session;
        state->endpoint.pipeName = L"\\\\.\\pipe\\KswordApiInject_" + std::to_wstring(state->endpoint.hostPid)
            + L"_" + std::to_wstring(rootPid) + L"_" + session;
        state->rootStopPath = rootStopPath; state->injector = std::move(injector);
        state->participants[rootPid] = {creation, agentPath, session};
        state->stopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!state->stopEvent) return platformFailure(error, L"create injection stop event", ::GetLastError());
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!privatePipeSecurity(&descriptor)) return platformFailure(error, L"create private injection pipe security", ::GetLastError());
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        state->pipe = ::CreateNamedPipeW(state->endpoint.pipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
            sizeof(InjectionResponse), sizeof(InjectionRequest), 0, &security);
        const DWORD code = ::GetLastError(); ::LocalFree(descriptor);
        if (state->pipe == INVALID_HANDLE_VALUE) return platformFailure(error, L"create injection broker pipe", code);
        try { state->worker = std::thread([raw = state.get()] { raw->run(); }); }
        catch (...) { return platformFailure(error, L"start injection broker thread", ERROR_NOT_ENOUGH_MEMORY); }
        m_state = std::move(state); return true;
    }
}
