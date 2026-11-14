#include <Windows.h>
#include "../../DebuggerBackend/KswordDebuggerApi.h"
#include "../../shared/driver/KswordArkHvmNoAttachIoctl.h"
#include "../../shared/driver/KswordArkKernelNoAttachIoctl.h"
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <string>

// Run only in the explicitly selected test VM. The target creates its own
// known instruction sequence; no code is injected into another application.
namespace
{
    struct Shared
    {
        volatile LONG ready, command, completed, quit;
        volatile LONG64 heartbeat;
        unsigned long pid, tid;
        unsigned long long code, value;
    };
    struct Handle
    {
        HANDLE value = nullptr;
        explicit Handle(HANDLE h = nullptr) : value(h) {}
        ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
    };
    using BackendCall = unsigned long (__stdcall*)(KSWORD_DEBUGGER_CALL*);
    using QueryProcess = LONG (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
    BackendCall backendCall = nullptr;
    KSWORD_ARK_HVM_NOATTACH_RESPONSE current{};
    unsigned int checks = 0;
    bool kernelTransport = false;
    bool closeAtStop = false;
    constexpr unsigned char knownCode[]{0x48,0xB8,0x00,0x01,0,0,0,0,0,0, 0x48,0xFF,0xC0, 0x48,0x89,0x01, 0xC3};
    void check(bool condition, const char* description)
    {
        if (!condition) { std::fprintf(stderr, "FAIL %s (Win32=%lu)\n", description, GetLastError()); throw std::runtime_error(description); }
        ++checks; std::printf("PASS %s\n", description); std::fflush(stdout);
    }
    bool control(unsigned long operation, unsigned long long address = 0, unsigned long id = 0,
                 unsigned long pid = 0, unsigned long tid = 0, unsigned long long rax = 0,
                 unsigned long long staleStop = 0)
    {
        KSWORD_ARK_HVM_NOATTACH_REQUEST request{};
        request.version = kernelTransport ? KSWORD_ARK_KERNEL_NOATTACH_VERSION : KSWORD_ARK_HVM_NOATTACH_VERSION;
        request.size = sizeof(request); request.operation = operation;
        request.sessionId = current.sessionId; request.stopId = staleStop ? staleStop : current.stopId;
        request.flags = KSWORD_ARK_HVM_NOATTACH_CONFIRMED | (kernelTransport ? KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK : KSWORD_ARK_HVM_NOATTACH_ALLOW_NESTED);
        request.processId = pid; request.threadId = tid; request.address = address; request.breakpointId = id;
        if (operation == KSWORD_ARK_HVM_NOATTACH_SET_GPR) { request.registerMask = 1; request.registers.rax = rax; }
        KSWORD_ARK_HVM_NOATTACH_RESPONSE response{};
        KSWORD_DEBUGGER_CALL call{KSWORD_DEBUGGER_API_VERSION, sizeof(call), kernelTransport ? KSWORD_DEBUGGER_KERNEL_NOATTACH : KSWORD_DEBUGGER_NOATTACH, 0,
            reinterpret_cast<std::uintptr_t>(&request), reinterpret_cast<std::uintptr_t>(&response), sizeof(request), sizeof(response), 0, 0};
        const auto transport = backendCall(&call);
        if (operation != KSWORD_ARK_HVM_NOATTACH_QUERY || transport || response.status < 0 ||
            response.state != current.state || response.sessionId != current.sessionId || response.stopId != current.stopId)
        {
            std::printf("CONTROL op=%lu transport=%lu NTSTATUS=%08lX state=%lu session=%llu stop=%llu capabilities=%lX\n", operation,
                transport, static_cast<unsigned long>(response.status), response.state, response.sessionId, response.stopId, response.capabilities);
            std::fflush(stdout);
        }
        if (transport || call.error || call.bytesReturned != sizeof(response) || response.version != request.version || response.size != sizeof(response)) return false;
        if (response.sessionId || response.status >= 0) current = response;
        return response.status >= 0;
    }
    template<class Predicate> bool wait(Predicate predicate, DWORD milliseconds = 10000)
    {
        const auto deadline = GetTickCount64() + milliseconds;
        do { if (predicate()) return true; Sleep(10); } while (GetTickCount64() < deadline);
        return false;
    }
    void stopped(unsigned long reason)
    {
        check(wait([reason]() { return control(KSWORD_ARK_HVM_NOATTACH_QUERY) && current.state == KSWORD_ARK_HVM_NOATTACH_STOPPED && current.stopReason == reason; }),
            "new real stop arrives within timeout");
        check(current.sessionId != 0 && current.stopId != 0, "stop has consumable session/stop identity");
    }
    void noDebugObject(HANDLE process)
    {
        const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        QueryProcess query = nullptr; std::memcpy(&query, &address, sizeof(query));
        check(query != nullptr, "process debug relationship query is available");
        ULONG_PTR port = ~ULONG_PTR{0}; HANDLE object = reinterpret_cast<HANDLE>(~ULONG_PTR{0});
        check(query(process, 7, &port, sizeof(port), nullptr) >= 0 && port == 0, "target DebugPort remains zero");
        const auto status = query(process, 30, &object, sizeof(object), nullptr);
        check((status >= 0 || status == static_cast<LONG>(0xC0000353UL)) && object == nullptr, "target has no Windows Debug Object");
    }
    DWORD WINAPI heartbeat(void* data)
    {
        auto* shared = static_cast<Shared*>(data);
        while (!InterlockedCompareExchange(&shared->quit, 0, 0)) { InterlockedIncrement64(&shared->heartbeat); Sleep(1); }
        return 0;
    }
    int target(const wchar_t* name)
    {
        Handle mapping(OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name));
        if (!mapping.value) return 2;
        auto* shared = static_cast<Shared*>(MapViewOfFile(mapping.value, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
        if (!shared) return 3;
        void* executable = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!executable) return 4;
        std::memcpy(executable, knownCode, sizeof(knownCode));
        DWORD old = 0;
        if (!VirtualProtect(executable, 4096, PAGE_EXECUTE_READ, &old) || !FlushInstructionCache(GetCurrentProcess(), executable, sizeof(knownCode))) return 5;
        using Function = void (*)(unsigned long long*);
        Function function = nullptr; std::memcpy(&function, &executable, sizeof(function));
        Handle other(CreateThread(nullptr, 0, heartbeat, shared, 0, nullptr));
        shared->pid = GetCurrentProcessId(); shared->tid = GetCurrentThreadId();
        shared->code = reinterpret_cast<std::uintptr_t>(executable);
        InterlockedExchange(&shared->ready, 1);
        while (!InterlockedCompareExchange(&shared->quit, 0, 0))
        {
            if (InterlockedCompareExchange(&shared->command, 0, 0) == 1)
            {
                function(&shared->value);
                InterlockedExchange(&shared->command, 0);
                InterlockedIncrement(&shared->completed);
            }
            SwitchToThread();
        }
        WaitForSingleObject(other.value, 3000);
        VirtualFree(executable, 0, MEM_RELEASE); UnmapViewOfFile(shared);
        return 0;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wcscmp(argv[1], L"--target") == 0) return target(argv[2]);
    if (argc != 3 || (std::wcscmp(argv[1], L"--vm-confirmed") != 0 && std::wcscmp(argv[1], L"--kernel-vm-confirmed") != 0 &&
                     std::wcscmp(argv[1], L"--query-only") != 0 && std::wcscmp(argv[1], L"--kernel-query-only") != 0 &&
                     std::wcscmp(argv[1], L"--kernel-close-stopped-vm-confirmed") != 0))
    { std::fprintf(stderr, "Use in the selected test VM: --vm-confirmed | --kernel-vm-confirmed | --query-only | --kernel-query-only <absolute backend DLL>\n"); return 2; }
    kernelTransport = std::wcsstr(argv[1], L"kernel") != nullptr;
    closeAtStop = std::wcsstr(argv[1], L"close-stopped") != nullptr;
    HMODULE module = LoadLibraryExW(argv[2], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!module) { std::fprintf(stderr, "Backend load error %lu\n", GetLastError()); return 3; }
    const auto exported = GetProcAddress(module, "KSwordDebuggerCall"); std::memcpy(&backendCall, &exported, sizeof(backendCall));
    if (!backendCall) return 4;
    if (std::wcsstr(argv[1], L"query-only") != nullptr)
    { const bool queried = control(KSWORD_ARK_HVM_NOATTACH_QUERY); FreeLibrary(module); return queried ? 0 : 1; }
    wchar_t path[32768]{}; GetModuleFileNameW(nullptr, path, _countof(path));
    const auto name = L"Local\\KSwordNoAttachProbe-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(Shared), name.c_str()));
    if (!mapping.value) return 5;
    auto* shared = static_cast<Shared*>(MapViewOfFile(mapping.value, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Shared)));
    if (!shared) return 6;
    std::wstring command = L"\"" + std::wstring(path) + L"\" --target \"" + name + L"\"";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
    if (!CreateProcessW(path, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return 7;
    Handle child(process.hProcess), childThread(process.hThread);
    bool passed = false, opened = false;
    try
    {
        check(wait([shared]() { return InterlockedCompareExchange(&shared->ready, 0, 0) != 0; }), "self-owned x64 target publishes identity/code");
        noDebugObject(child.value);
        opened = true; // An uncertain OPEN ACK still requires QUERY/CLOSE recovery.
        check(control(KSWORD_ARK_HVM_NOATTACH_OPEN, 0, 0, shared->pid, shared->tid), "selected independent backend opens in selected VM");
        check(control(KSWORD_ARK_HVM_NOATTACH_PAUSE), "pause is requested explicitly"); stopped(KSWORD_ARK_HVM_NOATTACH_STOP_FETCH);
        check(current.processId == shared->pid && current.threadId == shared->tid, "stop is the requested process/thread");
        const auto ticks = shared->heartbeat; Sleep(100);
        check(shared->heartbeat > ticks, "other thread and local controller remain runnable while target is stopped");
        noDebugObject(child.value);
        const auto address = shared->code + 10;
        check(control(KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT, address), "execution breakpoint installs at known INC instruction");
        if (kernelTransport) stopped(KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT);
        InterlockedExchange(&shared->command, 1);
        check(control(KSWORD_ARK_HVM_NOATTACH_CONTINUE), "continue consumes original stop"); stopped(KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT);
        check(current.rip == address && current.rax == 0x100 && current.breakpointId != 0, "exact execution hit occurs before INC with original RAX");
        const auto breakpointId = current.breakpointId;
        const auto initialStop = current.stopId;
        check((current.rflags & 0x100) == 0, "owned TF is clear in the published stop");
        if (closeAtStop)
        {
            check(control(KSWORD_ARK_HVM_NOATTACH_CLOSE) && current.state == 0 && current.sessionId == 0,
                "close at a live DR stop confirms restoration and observer drain");
            check(wait([shared]() { return shared->completed == 1; }) && shared->value == 0x101,
                "formerly stopped instruction completes with original registers after close");
        }
        else
        {
        check(!control(KSWORD_ARK_HVM_NOATTACH_STEP, 0, 0, 0, 0, 0, initialStop + 1) && current.stopId == initialStop,
            "stale stop identity is rejected without consuming the real stop");
        check(control(KSWORD_ARK_HVM_NOATTACH_STEP), kernelTransport ? "TF step is accepted" : "MTF step is accepted"); stopped(KSWORD_ARK_HVM_NOATTACH_STOP_STEP);
        check(current.stopId > initialStop && current.rip == shared->code + 13 && current.rax == 0x101, "one known INC retires into a new hardware step stop");
        check((current.rflags & 0x100) == 0, "owned TF is clear after the actual hardware step");
        check(control(KSWORD_ARK_HVM_NOATTACH_SET_GPR, 0, 0, 0, 0, 0x777), "integer register edit is accepted");
        stopped(KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT);
        check(current.rax == 0x777 && current.rip == shared->code + 13, "new stop confirms register commit without executing STORE");
        check(control(KSWORD_ARK_HVM_NOATTACH_CONTINUE), "continue after register commit");
        check(wait([shared]() { return shared->completed == 1; }) && shared->value == 0x777, "actual target STORE uses edited register");
        InterlockedExchange(&shared->command, 1); stopped(KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT);
        check(current.rip == address && current.rax == 0x100, "persistent execution breakpoint rearms for second invocation");
        check(control(KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT, 0, breakpointId), "remove exact owned breakpoint");
        if (kernelTransport) stopped(KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT);
        check(control(KSWORD_ARK_HVM_NOATTACH_RUN_TO, shared->code + 13), "run-to installs one-shot before resuming");
        stopped(KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT);
        check(current.rip == shared->code + 13 && current.rax == 0x101, "run-to stops after known INC");
        check(current.breakpointCount == 1 && (current.breakpoints[0].flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED), "one-shot is reported consumed");
        check(control(KSWORD_ARK_HVM_NOATTACH_CONTINUE), "continue past consumed run-to");
        check(wait([shared]() { return shared->completed == 2; }) && shared->value == 0x101, "second invocation completes normally");
        InterlockedExchange(&shared->command, 1);
        check(wait([shared]() { return shared->completed == 3; }), "consumed breakpoint does not stop next invocation");
        }
        unsigned char actualCode[sizeof(knownCode)]{}; SIZE_T codeBytes = 0;
        check(ReadProcessMemory(child.value, reinterpret_cast<void*>(shared->code), actualCode, sizeof(actualCode), &codeBytes) &&
            codeBytes == sizeof(actualCode) && std::memcmp(actualCode, knownCode, sizeof(actualCode)) == 0,
            "target executable bytes remain unchanged");
        noDebugObject(child.value);
        passed = true;
    }
    catch (const std::exception&) {}
    bool closed = true;
    if (opened)
    {
        // Recover a lost OPEN response through the same facade/control file.
        if (!current.sessionId) (void)control(KSWORD_ARK_HVM_NOATTACH_QUERY);
        closed = control(KSWORD_ARK_HVM_NOATTACH_CLOSE) && !current.sessionId &&
            (current.state == KSWORD_ARK_HVM_NOATTACH_CLOSED || current.state == KSWORD_ARK_HVM_NOATTACH_UNSUPPORTED);
    }
    if (closed)
    {
        InterlockedExchange(&shared->quit, 1);
        if (WaitForSingleObject(child.value, 5000) != WAIT_OBJECT_0)
        { passed = false; std::fprintf(stderr, "FAIL owned target did not exit after confirmed close\n"); }
        else
        {
            DWORD targetExit = 0;
            const bool cleanExit = GetExitCodeProcess(child.value, &targetExit) && targetExit == 0;
            std::printf("TARGET_EXIT=%08lX\n", targetExit);
            if (cleanExit) { ++checks; std::printf("PASS owned target exits normally after confirmed close\n"); }
            else { passed = false; std::fprintf(stderr, "FAIL owned target exit status is not success\n"); }
        }
    }
    else std::fprintf(stderr, "RECOVERY_REQUIRED: target remains alive; do not unload a resident driver\n");
    UnmapViewOfFile(shared); FreeLibrary(module);
    std::printf("NOATTACH_LIVE_%s checks=%u close_confirmed=%u\n", passed && closed ? "PASS" : "FAIL", checks, closed ? 1U : 0U);
    return passed && closed ? 0 : 1;
}
