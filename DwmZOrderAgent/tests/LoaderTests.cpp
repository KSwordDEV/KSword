#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include "../../shared/window/DwmRemoteLoader.h"
#include "../../shared/window/DwmProcessIdentity.h"
#include "../../Ksword5.1/Ksword5.1/OtherDock/DwmAgentDeployment.h"

ks::dwm_order::transport::PreparedAgent RunDeploymentTests(void (*check)(bool, const char*), const wchar_t* agentPath);

void RunLoaderTests(void (*check)(bool, const char*), const wchar_t* agentPath)
{
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const std::wstring executablePath(executable);
    const auto directory = executablePath.substr(0, executablePath.find_last_of(L'\\') + 1);
    const auto fixturePath = directory + L"DwmLoaderFixture.dll";
    HANDLE token = nullptr, identification = nullptr;
    const bool tokenReady = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)
        && DuplicateTokenEx(token, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr, SecurityIdentification,
            TokenImpersonation, &identification);
    check(tokenReady, "create identification-only token to reproduce the former loader failure");
    if (tokenReady)
    {
        const bool assigned = SetThreadToken(nullptr, identification) != FALSE;
        check(assigned, "assign identification-only token to the test thread");
        if (assigned)
        {
            HMODULE local = LoadLibraryExW(fixturePath.c_str(), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            const DWORD localError = GetLastError();
            const BOOL restored = RevertToSelf();
            std::cout << "LOADER_CASE=identification WIN32=" << localError << '\n';
            check(!local && localError == ERROR_BAD_IMPERSONATION_LEVEL,
                "identification-level impersonation reproduces genuine loader error 1346");
            check(restored != FALSE, "restore test thread identity after the 1346 reproduction");
            if (local) FreeLibrary(local);
        }
    }
    if (identification) CloseHandle(identification);
    if (token) CloseHandle(token);
    auto prepared = RunDeploymentTests(check, agentPath);
    if (prepared.path.empty()) return;

    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    HANDLE finished = CreateEventW(&attributes, TRUE, FALSE, nullptr);
    HANDLE ready = CreateEventW(&attributes, TRUE, FALSE, nullptr);
    check(finished && ready, "create child readiness and lifetime events");
    if (!finished || !ready)
    {
        if (finished) CloseHandle(finished);
        if (ready) CloseHandle(ready);
        return;
    }
    std::wstring command = L"\"" + executablePath + L"\" --loader-child "
        + std::to_wstring(reinterpret_cast<std::uintptr_t>(finished)) + L" "
        + std::to_wstring(reinterpret_cast<std::uintptr_t>(ready));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const BOOL created = CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, directory.c_str(), &startup, &child);
    check(created != FALSE, "create disposable loader test process");
    if (!created) { CloseHandle(finished); CloseHandle(ready); return; }
    CloseHandle(child.hThread);
    const bool started = WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0;
    check(started, "child has initialized before remote loader tests");
    CloseHandle(ready);
    if (!started)
    {
        SetEvent(finished);
        WaitForSingleObject(child.hProcess, 5000);
        CloseHandle(child.hProcess);
        CloseHandle(finished);
        return;
    }
    using ks::dwm_order::transport::LoadAgent;
    const auto report = [](const char* name, const ks::dwm_order::transport::LoadResult& value)
    {
        std::cout << "LOADER_CASE=" << name << " WIN32=" << value.error
            << " THREAD=" << value.threadExitCode << " COMPLETED=" << value.loaderCompleted
            << " MODULE=" << value.module << '\n';
    };
    const auto missing = LoadAgent(child.hProcess, child.dwProcessId, directory + L"missing-DWM-loader-test.dll");
    report("missing", missing);
    check(missing.loaderCompleted && missing.error == ERROR_MOD_NOT_FOUND && !missing.module,
        "missing DLL returns loader error 126 instead of a fabricated 1114");
    const auto rejected = LoadAgent(child.hProcess, child.dwProcessId, directory + L"DwmLoaderReject.dll");
    report("rejected", rejected);
    check(rejected.loaderCompleted && rejected.error == ERROR_DLL_INIT_FAILED && !rejected.module,
        "a genuine DllMain rejection retains loader error 1114");
    const auto loaded = LoadAgent(child.hProcess, child.dwProcessId, fixturePath);
    report("process-identity", loaded);
    check(loaded.loaderCompleted && !loaded.error && !loaded.threadExitCode && loaded.module,
        "remote loader runs as the target process without any impersonation token");
    const auto agent = LoadAgent(child.hProcess, child.dwProcessId, prepared.path, prepared.lease);
    report("agent", agent);
    check(agent.loaderCompleted && !agent.error && !agent.threadExitCode && agent.module,
        "production agent loads through the production cross-process transport");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, child.dwProcessId);
    bool matched = false;
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry)) do
        {
            if (lstrcmpiW(entry.szModule, L"KswordDwmZOrder.dll") == 0)
                matched = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr) == agent.module;
        } while (Module32NextW(snapshot, &entry));
        CloseHandle(snapshot);
    }
    check(matched, "receipt preserves the complete remote HMODULE and matches the module list");
    using ks::dwm_order::MatchesProcessIdentity;
    ks::dwm_order::WindowIdentity identity;
    identity.processId = child.dwProcessId;
    FILETIME time{}, exit{}, kernel{}, user{};
    const bool timesRead = GetProcessTimes(child.hProcess, &time, &exit, &kernel, &user) != FALSE;
    identity.processCreated = (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    HANDLE query = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, child.dwProcessId);
    check(timesRead && query && MatchesProcessIdentity(query, identity),
        "query-only process handle validates the original process identity");
    check(!MatchesProcessIdentity(GetCurrentProcess(), identity), "different process handle is rejected");
    ++identity.processCreated;
    check(!MatchesProcessIdentity(query, identity), "mismatched process creation time is rejected");
    --identity.processCreated;
    HANDLE unexpectedToken = nullptr;
    const BOOL impersonating = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &unexpectedToken);
    check(!impersonating && GetLastError() == ERROR_NO_TOKEN, "caller thread identity is unchanged after loading");
    if (unexpectedToken) CloseHandle(unexpectedToken);
    SetEvent(finished);
    check(WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0, "test child exits normally without termination");
    check(!MatchesProcessIdentity(query, identity), "terminated process handle is rejected even with the original PID");
    if (query) CloseHandle(query);
    CloseHandle(child.hProcess);
    CloseHandle(finished);
}
