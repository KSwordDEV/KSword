#include "ExplorerProbe.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <new>
#include <string>
#include <vector>

using namespace ExplorerProbe;

namespace
{
    struct Handle
    {
        HANDLE value = nullptr;
        explicit Handle(HANDLE handle = nullptr) : value(handle) {}
        ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        operator HANDLE() const { return value; }
    };

    int failures = 0;
    bool Check(const char* name, bool value)
    {
        std::printf("%s %s error=%lu\n", value ? "PASS" : "FAIL", name, value ? 0 : GetLastError());
        if (!value) ++failures;
        return value;
    }

    ULONGLONG ProcessCreated(HANDLE process)
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        return GetProcessTimes(process, &created, &exited, &kernel, &user) ? FileTicks(created) : 0;
    }

    bool TargetIdentity(HANDLE process, DWORD pid, ULONGLONG created)
    {
        wchar_t path[32768]{};
        DWORD count = static_cast<DWORD>(std::size(path));
        wchar_t windows[MAX_PATH]{};
        if (!QueryFullProcessImageNameW(process, 0, path, &count)
            || !GetWindowsDirectoryW(windows, MAX_PATH)) return false;
        const std::wstring expected = std::wstring(windows) + L"\\explorer.exe";
        DWORD targetSession = 0, ourSession = 0;
        BOOL wow = TRUE, debugged = TRUE;
        return GetProcessId(process) == pid && ProcessCreated(process) == created
            && _wcsicmp(path, expected.c_str()) == 0
            && ProcessIdToSessionId(pid, &targetSession)
            && ProcessIdToSessionId(GetCurrentProcessId(), &ourSession) && targetSession == ourSession
            && IsWow64Process(process, &wow) && !wow
            && CheckRemoteDebuggerPresent(process, &debugged) && !debugged;
    }

    HWND FindExplorerWindow(DWORD pid)
    {
        struct Search { DWORD pid; HWND hwnd; } search{pid, nullptr};
        EnumWindows([](HWND hwnd, LPARAM parameter) -> BOOL
        {
            auto& item = *reinterpret_cast<Search*>(parameter);
            DWORD owner = 0;
            GetWindowThreadProcessId(hwnd, &owner);
            if (owner != item.pid) return TRUE;
            wchar_t name[128]{};
            GetClassNameW(hwnd, name, static_cast<int>(std::size(name)));
            if (std::wcscmp(name, L"Shell_TrayWnd") == 0)
            {
                item.hwnd = hwnd;
                return FALSE;
            }
            if (!item.hwnd && std::wcscmp(name, L"CabinetWClass") == 0) item.hwnd = hwnd;
            return TRUE;
        }, reinterpret_cast<LPARAM>(&search));
        return search.hwnd;
    }

    bool Responsive(HWND window, DWORD pid)
    {
        DWORD owner = 0;
        GetWindowThreadProcessId(window, &owner);
        DWORD_PTR result = 0;
        return owner == pid && SendMessageTimeoutW(window, WM_NULL, 0, 0,
            SMTO_ABORTIFHUNG | SMTO_BLOCK, 2000, &result) != 0;
    }

    std::vector<unsigned char> Read(HANDLE target, std::uintptr_t address, SIZE_T bytes)
    {
        std::vector<unsigned char> result(bytes);
        SIZE_T copied = 0;
        if (!ReadProcessMemory(target, reinterpret_cast<void*>(address), result.data(), bytes, &copied)
            || copied != bytes) result.clear();
        return result;
    }

    std::uint64_t Fingerprint(const std::vector<unsigned char>& bytes)
    {
        std::uint64_t hash = 14695981039346656037ull;
        for (auto byte : bytes) { hash ^= byte; hash *= 1099511628211ull; }
        return hash;
    }

    std::uintptr_t RemoteDispatch(HANDLE target, DWORD pid)
    {
        HMODULE user = GetModuleHandleW(L"user32.dll");
        FARPROC local = GetProcAddress(user, "DispatchMessageW");
        HMODULE containing = nullptr;
        if (!local || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(local), &containing)) return 0;
        wchar_t path[MAX_PATH]{};
        if (!GetModuleFileNameW(containing, path, MAX_PATH)) return 0;
        const wchar_t* name = std::wcsrchr(path, L'\\');
        name = name ? name + 1 : path;
        const auto offset = reinterpret_cast<std::uintptr_t>(local)
            - reinterpret_cast<std::uintptr_t>(containing);
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
        MODULEENTRY32W module{};
        module.dwSize = sizeof(module);
        if (snapshot.value == INVALID_HANDLE_VALUE || !Module32FirstW(snapshot, &module)) return 0;
        do
        {
            if (_wcsicmp(module.szModule, name) != 0) continue;
            const auto remote = reinterpret_cast<std::uintptr_t>(module.modBaseAddr) + offset;
            const auto bytes = Read(target, remote, 32);
            if (bytes.size() == 32 && std::memcmp(bytes.data(), reinterpret_cast<void*>(local), 32) == 0)
            {
                std::printf("EXPORT module=%ls rva=0x%llx remote=0x%llx bytes_equal=1\n", name,
                    static_cast<unsigned long long>(offset), static_cast<unsigned long long>(remote));
                return remote;
            }
        } while (Module32NextW(snapshot, &module));
        return 0;
    }

    bool RestorePage(Shared& state)
    {
        if (!state.protectionOwned) return true;
        DWORD previous = 0;
        if (!VirtualProtectEx(state.target, reinterpret_cast<void*>(state.watch), state.watchBytes,
            state.originalProtection, &previous)) return false;
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQueryEx(state.target, reinterpret_cast<void*>(state.watch), &memory, sizeof(memory))
            != sizeof(memory) || memory.Protect != state.originalProtection) return false;
        InterlockedExchange(&state.protectionOwned, 0);
        state.protectRestored = 1;
        return true;
    }

    // Emergency path only. Freeze the live thread set while the native debugger still exists,
    // restore pages, end our controller, retire its TF/counts, then release guardian-owned counts.
    bool EmergencyRecover(Shared& state, HANDLE child)
    {
        struct RecoveryThread { HANDLE handle; DWORD tid; ULONGLONG created; };
        std::vector<RecoveryThread> held;
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        THREADENTRY32 item{};
        item.dwSize = sizeof(item);
        bool good = snapshot.value != INVALID_HANDLE_VALUE && Thread32First(snapshot, &item);
        if (good)
        {
            do
            {
                if (item.th32OwnerProcessID != state.pid) continue;
                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
                    | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, item.th32ThreadID);
                if (!thread) { good = false; continue; }
                FILETIME created{}, exited{}, kernel{}, user{};
                if (!GetThreadTimes(thread, &created, &exited, &kernel, &user)
                    || SuspendThread(thread) == static_cast<DWORD>(-1))
                {
                    CloseHandle(thread);
                    good = false;
                    continue;
                }
                held.push_back({thread, item.th32ThreadID, FileTicks(created)});
            } while (Thread32Next(snapshot, &item));
        }
        if (!RestorePage(state)) good = false;
        if (!TerminateProcess(child, 91) || WaitForSingleObject(child, 3000) != WAIT_OBJECT_0) good = false;
        for (auto& thread : held)
        {
            for (LONG i = 0; i < state.ledgerCount && i < static_cast<LONG>(maxThreads); ++i)
            {
                auto& ledger = state.ledger[static_cast<size_t>(i)];
                if (ledger.tid != thread.tid || ledger.created != thread.created) continue;
                if (ledger.ownTf)
                {
                    CONTEXT context{};
                    context.ContextFlags = CONTEXT_CONTROL;
                    if (!GetThreadContext(thread.handle, &context)) good = false;
                    else
                    {
                        context.EFlags &= ~trapFlag;
                        if (!SetThreadContext(thread.handle, &context)) good = false;
                        else InterlockedExchange(&ledger.ownTf, 0);
                    }
                }
                if (ledger.held)
                {
                    if (ResumeThread(thread.handle) == static_cast<DWORD>(-1)) good = false;
                    else InterlockedExchange(&ledger.held, 0);
                }
            }
            if (ResumeThread(thread.handle) == static_cast<DWORD>(-1)) good = false;
            CloseHandle(thread.handle);
        }
        return good;
    }

    bool RunCase(HANDLE target, HANDLE guardian, DWORD pid, ULONGLONG created, HWND window,
        const char* name, Mode mode, std::uintptr_t watch, SIZE_T watchBytes,
        std::uintptr_t execution, SIZE_T executionBytes, std::uintptr_t entry,
        DWORD expected, DWORD calls)
    {
        std::printf("CASE_BEGIN %s\n", name);
        if (!Check("case_target_identity_and_no_existing_debugger", TargetIdentity(target, pid, created))) return false;
        if (!Check("shell_responsive_before_case", Responsive(window, pid))) return false;
        const auto before = Read(target, watch, watchBytes);
        if (!Check("page_readable_before_case", before.size() == watchBytes)) return false;
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
            static_cast<DWORD>(sizeof(Shared)), nullptr));
        Handle ready(CreateEventW(&security, TRUE, FALSE, nullptr));
        HANDLE outputCopy = nullptr;
        DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE), GetCurrentProcess(),
            &outputCopy, 0, TRUE, DUPLICATE_SAME_ACCESS);
        Handle output(outputCopy);
        Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security, OPEN_EXISTING, 0, nullptr));
        if (!mapping.value || !ready.value) return Check("supervisor_resources", false);
        auto* state = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
        if (!state) return Check("map_shared_ledger", false);
        new (state) Shared{};
        state->pid = pid;
        state->created = created;
        state->mode = mode;
        state->target = target;
        state->guardian = guardian;
        state->faultReady = ready;
        state->watch = watch;
        state->watchBytes = watchBytes;
        state->execution = execution;
        state->executionBytes = executionBytes;
        state->entry = entry;
        state->expectedExit = expected;
        state->requestedCalls = calls;
        state->goal = 8;

        SIZE_T attributeBytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
        std::vector<unsigned char> storage(attributeBytes);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeBytes))
        {
            UnmapViewOfFile(state);
            return Check("attribute_list", false);
        }
        HANDLE inherited[] = {mapping.value, ready.value, target, guardian, output.value, input.value};
        const BOOL updated = UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr);
        wchar_t executable[32768]{};
        GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable)));
        wchar_t command[34000]{};
        swprintf_s(command, L"\"%ls\" --child %llu", executable,
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(mapping.value)));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input;
        startup.StartupInfo.hStdOutput = output;
        startup.StartupInfo.hStdError = output;
        startup.lpAttributeList = attributes;
        PROCESS_INFORMATION process{};
        const BOOL launched = updated && CreateProcessW(executable, command, nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr, &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(attributes);
        if (!launched)
        {
            UnmapViewOfFile(state);
            return Check("start_external_controller", false);
        }
        Handle child(process.hProcess), childThread(process.hThread);
        const ULONGLONG deadline = GetTickCount64() + 15000;
        bool guardianRecovery = false, emergency = false;
        DWORD posted = 0;
        HANDLE waited[] = {child.value, ready.value};
        for (;;)
        {
            const DWORD wait = WaitForMultipleObjects(2, waited, FALSE, 20);
            if (wait == WAIT_OBJECT_0) break;
            if (wait == WAIT_OBJECT_0 + 1 && mode == Mode::Guardian)
            {
                // Known first-NX boundary: native event freezes target and no private TF/count exists.
                bool noResponsibilities = true;
                for (LONG i = 0; i < state->ledgerCount; ++i)
                    if (state->ledger[static_cast<size_t>(i)].held || state->ledger[static_cast<size_t>(i)].ownTf)
                        noResponsibilities = false;
                guardianRecovery = noResponsibilities && RestorePage(*state)
                    && TerminateProcess(child, 77) && WaitForSingleObject(child, 3000) == WAIT_OBJECT_0;
                break;
            }
            if (wait == WAIT_FAILED || GetTickCount64() > deadline)
            {
                emergency = true;
                Check("emergency_controller_recovery", EmergencyRecover(*state, child));
                break;
            }
            if (mode == Mode::Image && PostMessageW(window, WM_NULL, 0, 0)) ++posted;
        }
        DWORD exit = STILL_ACTIVE;
        GetExitCodeProcess(child, &exit);
        bool callsGood = true;
        for (DWORD i = 0; i < calls; ++i)
        {
            auto& call = state->calls[i];
            Handle handle(call.guardianHandle);
            DWORD actual = STILL_ACTIVE;
            const bool complete = handle.value && WaitForSingleObject(handle, 4000) == WAIT_OBJECT_0
                && GetExitCodeThread(handle, &actual) && actual == expected;
            std::printf("CALL index=%lu tid=%lu create=%ld faults=%ld exit_event=%ld actual=0x%lx expected=0x%lx\n",
                i, call.tid, call.createSeen, call.faults, call.exitSeen, actual, expected);
            if (!complete || !call.createSeen || !call.faults) callsGood = false;
        }
        const auto after = Read(target, watch, watchBytes);
        bool noResponsibilities = true;
        for (LONG i = 0; i < state->ledgerCount; ++i)
            if (state->ledger[static_cast<size_t>(i)].held || state->ledger[static_cast<size_t>(i)].ownTf)
                noResponsibilities = false;
        MEMORY_BASIC_INFORMATION memory{};
        const bool restored = VirtualQueryEx(target, reinterpret_cast<void*>(watch), &memory, sizeof(memory))
            == sizeof(memory) && memory.Protect == PAGE_EXECUTE_READ && !state->protectionOwned;
        const int previousFailures = failures;
        Check("controller_expected_exit", !emergency && (mode == Mode::Guardian ? guardianRecovery && exit == 77
            : exit == 0 && state->done && !state->failed));
        Check("real_explorer_has_many_threads", state->attachedThreads >= 8);
        Check("watched_bytes_unchanged_by_probe", !after.empty() && before == after);
        Check("original_rx_protection_restored", restored && state->protectRestored);
        Check("no_owned_tf_or_suspend_counts", noResponsibilities);
        Check("native_debugger_detached", TargetIdentity(target, pid, created));
        Check("same_explorer_still_alive", WaitForSingleObject(target, 0) == WAIT_TIMEOUT);
        Check("shell_responsive_after_case", Responsive(window, pid));
        if (mode == Mode::Image)
        {
            Check("existing_explorer_thread_executes_watched_image", state->existingThreadFaults >= 8);
            Check("repeated_rearm_before_release", state->rearms >= 8);
            Check("stimulus_was_posted", posted > 0);
        }
        else Check("independent_remote_call_return_values", callsGood);
        if (mode == Mode::Private || mode == Mode::CrossPage)
        {
            Check("all_four_new_threads_have_individual_nx_hits", state->distinctFaultThreads >= calls
                && state->callsCompleted == calls && state->rearms >= calls);
        }
        if (mode == Mode::CrossPage) Check("cross_page_rip_and_fault_va_are_distinct_pages", state->crossPageFaults >= calls);
        if (mode == Mode::AbortStep) Check("abort_inside_page_restores_tf_protection_and_allows_return", state->abortedInPage == 1);
        if (mode == Mode::Guardian) Check("guardian_restores_before_terminating_controller_at_nx", guardianRecovery);
        std::printf("EVIDENCE case=%s pid=%lu threads=%lu peak=%lu creates=%lu creates_during_step=%lu faults=%lu distinct=%lu existing=%lu steps=%lu rearms=%lu cross_page=%lu unowned_exceptions=%lu max_cycle_us=%llu posted=%lu controller_exit=%lu child_error=%lu page_fnv1a=%016llx\n",
            name, pid, state->attachedThreads, state->peakThreads, state->createdThreads,
            state->createdWhileStepping, state->faults, state->distinctFaultThreads, state->existingThreadFaults,
            state->steps, state->rearms, state->crossPageFaults, state->unknownFirstChance,
            static_cast<unsigned long long>(state->maxCycleUs), posted, exit, state->lastError,
            static_cast<unsigned long long>(Fingerprint(after)));
        std::printf("THREAD_RECONCILIATION pending_create=%lu exited_snapshot=%lu queued_nx=%lu\n",
            state->snapshotPendingThreads, state->snapshotExitedThreads, state->queuedFaults);
        const bool good = previousFailures == failures;
        std::printf("CASE_RESULT name=%s result=%s\n", name, good ? "PASS" : "FAIL");
        UnmapViewOfFile(state);
        return good;
    }

    std::array<unsigned char, 29> ComputationCode(DWORD value, DWORD add)
    {
        // Aligned thread entry; the 10-byte MOV RCX at page+4093 crosses into the second page.
        // Only volatile registers are used. RET returns to Windows' original thread-start wrapper.
        std::array<unsigned char, 29> code{
            0xb8, 0, 0, 0, 0,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x48, 0xb9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            0x05, 0, 0, 0, 0, 0xc3};
        std::memcpy(code.data() + 1, &value, sizeof(value));
        std::memcpy(code.data() + 24, &add, sizeof(add));
        return code;
    }

    bool WriteVersion(HANDLE target, std::uintptr_t base, DWORD value, DWORD add)
    {
        const auto code = ComputationCode(value, add);
        DWORD previous = 0;
        if (!VirtualProtectEx(target, reinterpret_cast<void*>(base), 8192, PAGE_READWRITE, &previous)) return false;
        SIZE_T written = 0;
        const BOOL wrote = WriteProcessMemory(target, reinterpret_cast<void*>(base + 4080), code.data(), code.size(), &written);
        DWORD ignored = 0;
        const BOOL protectedAgain = VirtualProtectEx(target, reinterpret_cast<void*>(base), 8192, PAGE_EXECUTE_READ, &ignored);
        const BOOL flushed = FlushInstructionCache(target, reinterpret_cast<void*>(base), 8192);
        const auto readback = Read(target, base + 4080, code.size());
        return wrote && written == code.size() && protectedAgain && flushed
            && readback.size() == code.size() && std::equal(code.begin(), code.end(), readback.begin());
    }
}

int wmain(int argc, wchar_t** argv)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc == 3 && std::wcscmp(argv[1], L"--child") == 0)
    {
        HANDLE mapping = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(_wcstoui64(argv[2], nullptr, 10)));
        auto* state = static_cast<Shared*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
        if (!state || !TargetIdentity(state->target, state->pid, state->created)) return 2;
        const int result = RunDebugSession(*state);
        UnmapViewOfFile(state);
        CloseHandle(mapping);
        return result;
    }
    if (argc == 5 && std::wcscmp(argv[1], L"--release-retained") == 0)
    {
        const DWORD cleanupPid = std::wcstoul(argv[2], nullptr, 10);
        const auto base = static_cast<std::uintptr_t>(_wcstoui64(argv[3], nullptr, 0));
        const auto created = _wcstoui64(argv[4], nullptr, 10);
        Handle target(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION
            | SYNCHRONIZE, FALSE, cleanupPid));
        if (!Check("cleanup_exact_explorer_identity", target.value && TargetIdentity(target, cleanupPid, created))) return 1;
        const auto actual = Read(target, base, 8192);
        std::vector<unsigned char> expected(8192);
        const auto code = ComputationCode(0x24680000, 2);
        std::copy(code.begin(), code.end(), expected.begin() + 4080);
        MEMORY_BASIC_INFORMATION memory{};
        if (!Check("cleanup_exact_owned_bytes_and_mapping", actual == expected
            && VirtualQueryEx(target, reinterpret_cast<void*>(base), &memory, sizeof(memory)) == sizeof(memory)
            && memory.AllocationBase == reinterpret_cast<void*>(base) && memory.RegionSize == 8192
            && memory.Type == MEM_PRIVATE && memory.Protect == PAGE_EXECUTE_READ)) return 1;
        return Check("retained_owned_allocation_freed", VirtualFreeEx(target, reinterpret_cast<void*>(base), 0, MEM_RELEASE) != FALSE) ? 0 : 1;
    }
    const bool includeControllerDeath = argc == 4
        && std::wcscmp(argv[3], L"--include-controller-death-probe") == 0;
    if ((argc != 3 && !includeControllerDeath) || std::wcscmp(argv[1], L"--explorer-pid") != 0)
    {
        std::fprintf(stderr, "Usage: ExplorerProbeValidation --explorer-pid <PID> [--include-controller-death-probe]\n");
        return 2;
    }
    const DWORD pid = std::wcstoul(argv[2], nullptr, 10);
    Handle target(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | SYNCHRONIZE, TRUE, pid));
    Handle guardian(OpenProcess(PROCESS_DUP_HANDLE | SYNCHRONIZE, TRUE, GetCurrentProcessId()));
    const ULONGLONG created = target.value ? ProcessCreated(target) : 0;
    if (!Check("explicit_same_session_x64_windows_explorer_only", target.value && created
        && TargetIdentity(target, pid, created)) || !Check("guardian_handle", guardian.value != nullptr)) return 1;
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    if (!Check("require_4k_pages", system.dwPageSize == 4096)) return 1;
    const HWND window = FindExplorerWindow(pid);
    if (!Check("explorer_window_and_baseline_response", window && Responsive(window, pid))) return 1;
    std::printf("TARGET pid=%lu created=%llu window=0x%llx session_local=1\n", pid,
        static_cast<unsigned long long>(created),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(window)));
    const auto dispatch = RemoteDispatch(target, pid);
    if (!Check("matching_dispatch_export_without_code_patching", dispatch != 0)) return 1;
    const auto imagePage = dispatch & ~static_cast<std::uintptr_t>(4095);
    if (!RunCase(target, guardian, pid, created, window, "image-natural", Mode::Image,
        imagePage, 4096, imagePage, 4096, 0, 0, 0)) return 1;

    const auto allocation = reinterpret_cast<std::uintptr_t>(VirtualAllocEx(target, nullptr, 8192,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!Check("allocate_owned_two_page_computation_region", allocation != 0)) return 1;
    bool safeToFree = true;
    const DWORD first = 0x13570000, second = 0x24680000;
    bool good = Check("version1_real_write_readback_rx_and_flush", WriteVersion(target, allocation, first, 1));
    const auto version1 = Read(target, allocation, 8192);
    if (good) good = RunCase(target, guardian, pid, created, window, "private-version1", Mode::Private,
        allocation, 8192, allocation, 8192, allocation + 4080, first + 1, 4);
    if (good) good = Check("version2_real_write_readback_rx_and_flush", WriteVersion(target, allocation, second, 2));
    const auto version2 = Read(target, allocation, 8192);
    if (good) good = Check("same_mapping_has_distinct_content_versions", !version1.empty() && !version2.empty()
        && version1 != version2);
    std::printf("VERSIONS base=0x%llx bytes=8192 v1_fnv1a=%016llx v2_fnv1a=%016llx\n",
        static_cast<unsigned long long>(allocation), static_cast<unsigned long long>(Fingerprint(version1)),
        static_cast<unsigned long long>(Fingerprint(version2)));
    if (good) good = RunCase(target, guardian, pid, created, window, "private-version2", Mode::Private,
        allocation, 8192, allocation, 8192, allocation + 4080, second + 2, 4);
    if (good) good = RunCase(target, guardian, pid, created, window, "cross-page-fetch", Mode::CrossPage,
        allocation + 4096, 4096, allocation, 8192, allocation + 4080, second + 2, 4);
    if (good) good = RunCase(target, guardian, pid, created, window, "abort-inside-page", Mode::AbortStep,
        allocation, 8192, allocation, 8192, allocation + 4080, second + 2, 1);
    if (good && includeControllerDeath) good = RunCase(target, guardian, pid, created, window, "guardian-at-nx", Mode::Guardian,
        allocation, 8192, allocation, 8192, allocation + 4080, second + 2, 1);
    if (!includeControllerDeath) std::printf("NOT_RUN guardian-at-nx: known pending-exception controller-death failure; explicit option required\n");
    // Never free execution storage after an unverified failure: an outstanding thread could still use it.
    if (!good) safeToFree = false;
    if (safeToFree) Check("owned_remote_allocation_freed", VirtualFreeEx(target, reinterpret_cast<void*>(allocation), 0, MEM_RELEASE) != FALSE);
    else std::printf("RECOVERY_REQUIRED retained_allocation=0x%llx bytes=8192\n", static_cast<unsigned long long>(allocation));
    Check("final_same_explorer_identity_and_no_debugger", TargetIdentity(target, pid, created));
    Check("final_shell_responsive", Responsive(window, pid));
    std::printf("RESULT=%s failures=%d\n", good && failures == 0 ? "PASS" : "FAIL", failures);
    return good && failures == 0 ? 0 : 1;
}
