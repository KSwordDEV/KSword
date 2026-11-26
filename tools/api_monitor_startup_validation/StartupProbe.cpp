#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include "ProbeStages.h"

#ifndef _WIN64
static int CooperativeWin32Target()
{
    USHORT processMachine = 0, nativeMachine = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &processMachine, &nativeMachine)
        || processMachine != IMAGE_FILE_MACHINE_I386 || nativeMachine != IMAGE_FILE_MACHINE_AMD64) return 20;
    wchar_t directory[32768]{};
    const DWORD cooperativeLength = GetEnvironmentVariableW(L"KSWORD_APIMON_COOPERATIVE_SESSION_V1", directory, ARRAYSIZE(directory));
    if (!cooperativeLength || cooperativeLength >= ARRAYSIZE(directory)) return 21;
    const DWORD length = GetModuleFileNameW(nullptr, directory, ARRAYSIZE(directory));
    if (!length || length >= ARRAYSIZE(directory)) return 21;
    std::wstring agentPath(directory, length);
    agentPath.resize(agentPath.find_last_of(L'\\') + 1);
    agentPath += L"APIMonitor_x86.dll";
    const ULONGLONG start = GetTickCount64();
    const HMODULE agent = LoadLibraryExW(agentPath.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!agent) return 22;
    const auto loadMs = GetTickCount64() - start;
    using Enable = DWORD(WINAPI*)();
    using WaitForStartup = DWORD(WINAPI*)(DWORD);
    using WriteMemory = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    const HMODULE kernelBase = GetModuleHandleW(L"KernelBase.dll");
#pragma warning(suppress: 4191) // These exports use the declared Win32 signatures.
    const auto enable = reinterpret_cast<Enable>(GetProcAddress(agent, "KSwordApiMonitorEnableCooperativeCapture"));
#pragma warning(suppress: 4191)
    const auto waitForStartup = reinterpret_cast<WaitForStartup>(GetProcAddress(agent, "KSwordApiMonitorWaitForCooperativeStartup"));
#pragma warning(suppress: 4191)
    const auto writeMemory = kernelBase ? reinterpret_cast<WriteMemory>(GetProcAddress(kernelBase, "WriteProcessMemory")) : nullptr;
    if (!enable || !waitForStartup || !writeMemory || waitForStartup(0) != ERROR_NOT_READY) return 23;
    DWORD status = enable();
    const ULONGLONG enableDeadline = GetTickCount64() + 5000;
    while (status == ERROR_NOT_READY && GetTickCount64() < enableDeadline) {
        Sleep(25);
        status = enable();
    }
    if (status) return 24;
    const auto enabledMs = GetTickCount64() - start;
    const DWORD beforeController = waitForStartup(25);
    if (beforeController != ERROR_TIMEOUT) return 25;

    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 26;
    const auto creation = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    char destination[4096]{};
    std::printf("{\"pid\":%lu,\"tid\":%lu,\"creation\":%llu,\"base\":%llu,\"processMachine\":%u,"
        "\"nativeMachine\":%u,\"agentLoadNs\":%llu,\"agentEnabledNs\":%llu,\"localStartupBeforeController\":%lu}\n",
        GetCurrentProcessId(), GetCurrentThreadId(), creation,
        static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(destination)),
        static_cast<unsigned>(processMachine), static_cast<unsigned>(nativeMachine),
        loadMs * 1000000ULL, enabledMs * 1000000ULL, beforeController);
    std::fflush(stdout);
    status = waitForStartup(15000);
    if (status) {
        std::fprintf(stderr, "LOCAL_STARTUP_WIN32_ERROR=%lu\n", status);
        return 27;
    }
    const auto localReady = GetTickCount64();
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    const char source = 'Z';
    const ULONGLONG workloadDeadline = localReady + 65000;
    ULONGLONG firstAction = 0;
    unsigned count = 0;
    while (count < sizeof(destination) && GetTickCount64() < workloadDeadline) {
        if (!PeekNamedPipe(input, nullptr, 0, nullptr, nullptr, nullptr)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) return 28;
            const DWORD afterStop = waitForStartup(0);
            std::printf("{\"calls\":%u,\"agentLoaded\":true,\"localReadyNs\":%llu,\"firstActionNs\":%llu,"
                "\"localStartupAfterStop\":%lu}\n", count, localReady * 1000000ULL, firstAction * 1000000ULL, afterStop);
            return 0;
        }
        if (!count) firstAction = GetTickCount64();
        SIZE_T written = 0;
        if (!writeMemory(GetCurrentProcess(), destination + count, &source, 1, &written)
            || written != 1 || destination[count] != source) return 29;
        ++count;
        Sleep(25);
    }
    return 30;
}
#endif

// Only owned test children receive these environment variables. No sample or
// existing desktop process is opened by this fixture.
static void MarkStage(unsigned stage)
{
    wchar_t name[256]{}, directory[32768]{};
    if (!GetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_MAP", name, 256)) return;
    HANDLE mapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, name);
    if (!mapping) return;
    auto* state = static_cast<ProbeStages*>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(ProbeStages)));
    if (state) {
        volatile LONG* counters[] = { &state->tls, &state->constructor, &state->main };
        volatile LONG* writes[] = { &state->tlsWrite, &state->constructorWrite, &state->mainWrite };
        InterlockedIncrement(counters[stage]);
        const DWORD length = GetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_DIRECTORY", directory, 32768);
        if (length && length < 32700) {
            const wchar_t* suffix[] = { L"\\tls.marker", L"\\constructor.marker", L"\\main.marker" };
            // The EXE process-attach TLS callback precedes CRT initialization.
            // Keep this marker CRT-free; in particular do not allocate std::wstring.
            lstrcatW(directory, suffix[stage]);
            HANDLE file = CreateFileW(directory, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                const char value = static_cast<char>('T' + stage); DWORD written = 0;
                if (WriteFile(file, &value, 1, &written, nullptr) && written == 1) InterlockedIncrement(writes[stage]);
                CloseHandle(file);
            }
        }
        UnmapViewOfFile(state);
    }
    CloseHandle(mapping);
}

static void NTAPI ProbeTls(PVOID, DWORD reason, PVOID)
{
    if (reason == DLL_PROCESS_ATTACH) MarkStage(0);
}
#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK startupProbeTls = ProbeTls;
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:startupProbeTls")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_startupProbeTls")
#endif
struct ConstructorMarker { ConstructorMarker() { MarkStage(1); } };
static ConstructorMarker constructorMarker;

static int ChildMain()
{
    MarkStage(2);
    wchar_t name[256]{};
    if (!GetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_MAP", name, 256)) return 10;
    const std::wstring quitName = std::wstring(name) + L"-quit";
    HANDLE quit = OpenEventW(SYNCHRONIZE, FALSE, quitName.c_str());
    if (!quit) return 11;
    const DWORD wait = WaitForSingleObject(quit, 60000);
    CloseHandle(quit);
    return wait == WAIT_OBJECT_0 ? 0 : 12;
}

#ifdef _WIN64
#include "../../shared/ApiMonitorInjection.h"
#include "../../shared/WinApiMonitorProtocol.h"
#include <filesystem>
#include <stdexcept>
#include <vector>

namespace wm = ks::winapi_monitor;
namespace fs = std::filesystem;
static unsigned checks = 0;
static void Check(bool value, const char* message)
{
    std::printf("%s %s\n", value ? "PASS" : "FAIL", message); std::fflush(stdout);
    if (!value) throw std::runtime_error(message);
    ++checks;
}
static void Require(BOOL value, const char* message)
{
    if (!value) { std::printf("WIN32_ERROR=%lu operation=%s\n", GetLastError(), message); throw std::runtime_error(message); }
}

struct OwnedRun {
    PROCESS_INFORMATION pi{};
    HANDLE mapping = nullptr, quit = nullptr, pipe = INVALID_HANDLE_VALUE;
    ProbeStages* stages = nullptr;
    bool debugAttached = false;
    bool ownsConfig = false, ownsStop = false;
    std::wstring config, stop;
    fs::path directory;
    ~OwnedRun() {
        if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
        if (pi.hProcess) {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT) {
                // Only a process created and retained by this exact run is terminated.
                TerminateProcess(pi.hProcess, 90);
                if (debugAttached) {
                    DEBUG_EVENT event{};
                    for (unsigned n = 0; n < 200; ++n) {
                        if (!WaitForDebugEvent(&event, 10)) continue;
                        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
                        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
                    }
                }
                WaitForSingleObject(pi.hProcess, 5000);
            }
            if (debugAttached) DebugActiveProcessStop(pi.dwProcessId);
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
        if (stages) UnmapViewOfFile(stages);
        if (mapping) CloseHandle(mapping);
        if (quit) CloseHandle(quit);
        if (ownsConfig) DeleteFileW(config.c_str());
        if (ownsStop) DeleteFileW(stop.c_str());
        if (!directory.empty()) {
            for (const auto* file : { L"tls.marker", L"constructor.marker", L"main.marker" })
                DeleteFileW((directory / file).c_str());
            RemoveDirectoryW(directory.c_str());
        }
    }
};

static void WriteConfig(OwnedRun& run)
{
    run.config = wm::buildConfigPathForPid(run.pi.dwProcessId);
    run.stop = wm::buildStopFlagPathForPid(run.pi.dwProcessId);
    Check(GetFileAttributesW(run.config.c_str()) == INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesW(run.stop.c_str()) == INVALID_FILE_ATTRIBUTES, "no preexisting PID configuration or stop file");
    fs::create_directories(fs::path(run.config).parent_path());
    const std::wstring text = L"\xfeff[monitor]\r\npid=" + std::to_wstring(run.pi.dwProcessId)
        + L"\r\npipe_name=" + wm::buildPipeNameForPid(run.pi.dwProcessId)
        + L"\r\nsession_id=startup-probe-" + std::to_wstring(run.pi.dwProcessId)
        + L"\r\nstop_flag_path=" + run.stop
        + L"\r\nenable_file=1\r\nenable_process=0\r\nenable_thread=0\r\nenable_memory=0"
          L"\r\nenable_registry=0\r\nenable_network=0\r\nenable_loader=0\r\nenable_clipboard=0"
          L"\r\nenable_window=0\r\nenable_gui=0\r\nenable_service=0\r\nenable_security=0"
          L"\r\nenable_raw_fallback=0\r\nauto_inject_child=0\r\ndetail_limit=319\r\n";
    HANDLE file = CreateFileW(run.config.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr);
    Require(file != INVALID_HANDLE_VALUE, "create owned configuration");
    run.ownsConfig = true;
    DWORD written = 0;
    const BOOL ok = WriteFile(file, text.data(), static_cast<DWORD>(text.size() * sizeof(wchar_t)), &written, nullptr);
    CloseHandle(file);
    Require(ok && written == text.size() * sizeof(wchar_t), "write configuration");
}

static void HoldAtEntry(OwnedRun& run, bool target32)
{
    Check(ResumeThread(run.pi.hThread) == 1, "release only original CREATE_SUSPENDED count for loader advance");
    std::uintptr_t entry = 0;
    unsigned char original = 0;
    const ULONGLONG deadline = GetTickCount64() + 30000;
    while (GetTickCount64() < deadline) {
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, 100)) continue;
        DWORD continuation = DBG_CONTINUE;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            const auto base = reinterpret_cast<std::uintptr_t>(event.u.CreateProcessInfo.lpBaseOfImage);
            IMAGE_DOS_HEADER dos{}; SIZE_T read = 0;
            Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(base), &dos, sizeof(dos), &read), "read target PE");
            DWORD rva = 0;
            // AddressOfEntryPoint has the same offset in PE32 and PE32+ optional headers.
            Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(base + dos.e_lfanew + 24 + 16), &rva, sizeof(rva), &read), "read entry RVA");
            entry = base + rva;
            std::printf("DEBUG_IMAGE base=0x%llx entry=0x%llx target32=%u\n", static_cast<unsigned long long>(base),
                static_cast<unsigned long long>(entry), target32 ? 1U : 0U);
            Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(entry), &original, 1, &read), "read original entry byte");
            DWORD protection = 0, ignored = 0; const unsigned char breakpoint = 0xcc;
            Require(VirtualProtectEx(run.pi.hProcess, reinterpret_cast<void*>(entry), 1, PAGE_EXECUTE_READWRITE, &protection), "entry protection");
            Require(WriteProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(entry), &breakpoint, 1, &read), "install owned entry breakpoint");
            Require(VirtualProtectEx(run.pi.hProcess, reinterpret_cast<void*>(entry), 1, protection, &ignored), "restore entry protection");
            Require(FlushInstructionCache(run.pi.hProcess, reinterpret_cast<void*>(entry), 1), "flush entry breakpoint");
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto& exception = event.u.Exception.ExceptionRecord;
            std::printf("DEBUG_EXCEPTION code=0x%08lx address=0x%llx firstChance=%lu\n", exception.ExceptionCode,
                reinterpret_cast<unsigned long long>(exception.ExceptionAddress), event.u.Exception.dwFirstChance);
            if ((exception.ExceptionCode == EXCEPTION_BREAKPOINT || exception.ExceptionCode == 0x4000001fUL) &&
                reinterpret_cast<std::uintptr_t>(exception.ExceptionAddress) == entry) {
                Check(event.dwThreadId == run.pi.dwThreadId, "EXE entry hit belongs to primary thread");
                DWORD protection = 0, ignored = 0; SIZE_T written = 0;
                Require(VirtualProtectEx(run.pi.hProcess, reinterpret_cast<void*>(entry), 1, PAGE_EXECUTE_READWRITE, &protection), "entry restore protection");
                Require(WriteProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(entry), &original, 1, &written), "restore entry byte");
                Require(VirtualProtectEx(run.pi.hProcess, reinterpret_cast<void*>(entry), 1, protection, &ignored), "restore original protection");
                Require(FlushInstructionCache(run.pi.hProcess, reinterpret_cast<void*>(entry), 1), "flush restored entry");
                if (target32) {
                    WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_CONTROL;
                    Require(Wow64GetThreadContext(run.pi.hThread, &context), "get WOW64 entry context");
                    context.Eip = static_cast<DWORD>(entry);
                    Require(Wow64SetThreadContext(run.pi.hThread, &context), "restore WOW64 entry IP");
                } else {
                    CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
                    Require(GetThreadContext(run.pi.hThread, &context), "get entry context");
                    context.Rip = entry;
                    Require(SetThreadContext(run.pi.hThread, &context), "restore entry IP");
                }
                Check(SuspendThread(run.pi.hThread) == 0, "hold primary thread with one explicitly owned suspend");
                Require(ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE), "continue entry event");
                Require(DebugActiveProcessStop(run.pi.dwProcessId), "detach while preserving primary suspend");
                run.debugAttached = false;
                return;
            }
            if (exception.ExceptionCode != EXCEPTION_BREAKPOINT && exception.ExceptionCode != 0x4000001fUL)
                continuation = DBG_EXCEPTION_NOT_HANDLED;
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            std::printf("DEBUG_EARLY_EXIT=0x%08lx tls=%ld ctor=%ld main=%ld\n", event.u.ExitProcess.dwExitCode,
                run.stages->tls, run.stages->constructor, run.stages->main);
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            throw std::runtime_error("target exited before entry");
        }
        Require(ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation), "continue loader event");
    }
    throw std::runtime_error("entry breakpoint timeout");
}

struct Receiver {
    OwnedRun& run;
    std::vector<unsigned char> bytes;
    bool sessionReady = false, installed = false, removed = false;
    bool tlsEvent = false, constructorEvent = false, mainEvent = false;
    unsigned writes = 0, coverageItems = 0;
    explicit Receiver(OwnedRun& value) : run(value) {}
    void Pump() {
        if (run.pipe == INVALID_HANDLE_VALUE) {
            run.pipe = CreateFileW(wm::buildPipeNameForPid(run.pi.dwProcessId).c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (run.pipe == INVALID_HANDLE_VALUE) return;
        }
        DWORD available = 0;
        if (!PeekNamedPipe(run.pipe, nullptr, 0, nullptr, &available, nullptr) || !available) return;
        const auto old = bytes.size(); bytes.resize(old + available); DWORD read = 0;
        Require(ReadFile(run.pipe, bytes.data() + old, available, &read, nullptr), "read Agent packets");
        bytes.resize(old + read);
        std::size_t consumed = 0;
        while (bytes.size() - consumed >= sizeof(wm::ApiMonitorEventPacket)) {
            wm::ApiMonitorEventPacket packet{};
            std::memcpy(&packet, bytes.data() + consumed, sizeof(packet)); consumed += sizeof(packet);
            Require(packet.size == sizeof(packet) && packet.version == wm::kProtocolVersion && packet.pid == run.pi.dwProcessId
                && packet.sessionIdentity == wm::sessionIdentity(L"startup-probe-" + std::to_wstring(run.pi.dwProcessId)),
                "validate Agent packet size, version, PID and session");
            const std::wstring api(packet.apiName), detail(packet.detailText);
            if (api == L"SessionReady") { sessionReady = true; std::wprintf(L"AGENT_SESSION_READY %ls\n", detail.c_str()); }
            if (api == L"HooksInstalled") { Require(sessionReady, "SessionReady precedes HooksInstalled"); installed = true; }
            if (api == L"HooksRemoved") removed = true;
            if (api == L"InstallHooksFailed" || api == L"AgentFailure") {
                std::wprintf(L"AGENT_FAILURE %ls %ls\n", api.c_str(), detail.c_str());
                throw std::runtime_error("Agent installation failed");
            }
            if (packet.eventKind == static_cast<std::uint32_t>(wm::EventKind::CoverageItem)) ++coverageItems;
            if (api == L"CreateFileW") {
                if (detail.find(L"tls.marker") != std::wstring::npos) tlsEvent = true;
                if (detail.find(L"constructor.marker") != std::wstring::npos) constructorEvent = true;
                if (detail.find(L"main.marker") != std::wstring::npos) mainEvent = true;
            }
            if (api == L"WriteFile") ++writes;
        }
        bytes.erase(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(consumed));
    }
    template<class Predicate> void Until(Predicate predicate, DWORD timeout = 30000) {
        const auto deadline = GetTickCount64() + timeout;
        do { Pump(); if (predicate()) return; Sleep(10); } while (GetTickCount64() < deadline);
        throw std::runtime_error("Agent packet/state timeout");
    }
};

static void ArrangeEarlyImport(OwnedRun& run, bool target32, const fs::path& bootstrap)
{
    using QueryProcess = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<QueryProcess>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    Require(query != nullptr, "resolve process information query");
    std::uintptr_t base = 0;
    SIZE_T read = 0;
    if (target32) {
        ULONG_PTR peb = 0;
        Require(query(run.pi.hProcess, 26, &peb, sizeof(peb), nullptr) >= 0 && peb != 0, "query owned WOW64 PEB");
        DWORD base32 = 0;
        Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(peb + 8), &base32, sizeof(base32), &read), "read owned WOW64 image base");
        base = base32;
    } else {
        struct Basic { PVOID unused; PVOID peb; PVOID reserved[2]; ULONG_PTR pid; PVOID parent; } basic{};
        Require(query(run.pi.hProcess, 0, &basic, sizeof(basic), nullptr) >= 0, "query owned PEB");
        Require(ReadProcessMemory(run.pi.hProcess, static_cast<unsigned char*>(basic.peb) + 16, &base, sizeof(base), &read), "read owned image base");
    }
    IMAGE_DOS_HEADER dos{};
    Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(base), &dos, sizeof(dos), &read), "read fresh DOS header");
    Require(dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0, "verify owned DOS header");
    const auto ntAddress = base + static_cast<unsigned>(dos.e_lfanew);
    IMAGE_DATA_DIRECTORY import{};
    DWORD imageSize = 0;
    std::uintptr_t dataDirectory = 0;
    if (target32) {
        IMAGE_NT_HEADERS32 nt{};
        Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(ntAddress), &nt, sizeof(nt), &read), "read fresh PE32");
        Require(nt.Signature == IMAGE_NT_SIGNATURE && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_I386, "verify PE32 machine");
        import = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        imageSize = nt.OptionalHeader.SizeOfImage;
        dataDirectory = ntAddress + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory);
    } else {
        IMAGE_NT_HEADERS64 nt{};
        Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(ntAddress), &nt, sizeof(nt), &read), "read fresh PE64");
        Require(nt.Signature == IMAGE_NT_SIGNATURE && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64, "verify PE64 machine");
        import = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        imageSize = nt.OptionalHeader.SizeOfImage;
        dataDirectory = ntAddress + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory);
    }
    std::vector<IMAGE_IMPORT_DESCRIPTOR> old;
    for (unsigned n = 0; n < 256; ++n) {
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        Require(ReadProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(base + import.VirtualAddress + n * sizeof(descriptor)),
            &descriptor, sizeof(descriptor), &read), "read fresh import descriptor");
        if (!descriptor.Name) break;
        old.push_back(descriptor);
    }
    Require(!old.empty() && old.size() < 256, "bounded owned import table");
    const auto widePath = bootstrap.wstring();
    for (wchar_t ch : widePath) Require(ch > 0 && ch < 128, "test bootstrap path is ASCII");
    std::string path;
    path.reserve(widePath.size());
    for (wchar_t ch : widePath) path.push_back(static_cast<char>(ch));
    const std::size_t descriptorBytes = (old.size() + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    const std::size_t thunkOffset = (descriptorBytes + 15) & ~std::size_t(15);
    const std::size_t thunkBytes = target32 ? 8 : 16;
    const std::size_t nameOffset = thunkOffset + thunkBytes * 2;
    const auto allocationSize = nameOffset + path.size() + 1;
    std::uintptr_t candidate = (base + imageSize + 65535) & ~std::uintptr_t(65535);
    void* allocation = nullptr;
    const auto upper = target32 ? std::uintptr_t(0xff000000) : base + 0xefff0000;
    for (unsigned n = 0; n < 4096 && candidate < upper; ++n) {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQueryEx(run.pi.hProcess, reinterpret_cast<void*>(candidate), &region, sizeof(region))) break;
        if (region.State == MEM_FREE && region.RegionSize >= allocationSize) {
            allocation = VirtualAllocEx(run.pi.hProcess, reinterpret_cast<void*>(candidate), allocationSize,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (allocation) break;
        }
        const auto next = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
        if (next <= candidate || next > upper) break;
        candidate = (next + 65535) & ~std::uintptr_t(65535);
    }
    Require(allocation != nullptr, "allocate bounded owned startup import storage");
    const auto rva64 = reinterpret_cast<std::uintptr_t>(allocation) - base;
    Require(rva64 + allocationSize < MAXDWORD, "startup imports fit unsigned RVA");
    const auto rva = static_cast<DWORD>(rva64);
    std::vector<unsigned char> bytes(allocationSize, 0);
    auto* descriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(bytes.data());
    descriptors[0].Name = rva + static_cast<DWORD>(nameOffset);
    descriptors[0].OriginalFirstThunk = rva + static_cast<DWORD>(thunkOffset);
    descriptors[0].FirstThunk = rva + static_cast<DWORD>(thunkOffset + thunkBytes);
    std::memcpy(descriptors + 1, old.data(), old.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    const std::uint64_t ordinal = target32 ? (std::uint64_t(IMAGE_ORDINAL_FLAG32) | 1) : (IMAGE_ORDINAL_FLAG64 | 1);
    const auto width = target32 ? sizeof(DWORD) : sizeof(std::uint64_t);
    std::memcpy(bytes.data() + thunkOffset, &ordinal, width);
    std::memcpy(bytes.data() + thunkOffset + thunkBytes, &ordinal, width);
    std::memcpy(bytes.data() + nameOffset, path.c_str(), path.size() + 1);
    Require(WriteProcessMemory(run.pi.hProcess, allocation, bytes.data(), bytes.size(), &read) && read == bytes.size(), "write owned startup import storage");
    const IMAGE_DATA_DIRECTORY replacement{ rva, static_cast<DWORD>(descriptorBytes) }, unbound{};
    DWORD protection = 0, ignored = 0;
    Require(VirtualProtectEx(run.pi.hProcess, reinterpret_cast<void*>(dataDirectory),
        sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES, PAGE_READWRITE, &protection), "make owned PE directory writable");
    Require(WriteProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(dataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(import)),
        &replacement, sizeof(replacement), &read), "set startup import directory");
    Require(WriteProcessMemory(run.pi.hProcess, reinterpret_cast<void*>(dataDirectory + IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT * sizeof(import)),
        &unbound, sizeof(unbound), &read), "invalidate only owned bound imports");
    Require(VirtualProtectEx(run.pi.hProcess, reinterpret_cast<void*>(dataDirectory),
        sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES, protection, &ignored), "restore owned PE directory protection");
    Check(run.stages->tls == 0 && run.stages->constructor == 0 && run.stages->main == 0 && run.stages->bootstrapLoaded == 0,
        "early bootstrap import arranged before any target startup code or bootstrap DllMain runs");
    std::printf("EARLY_IMPORT imageBase=0x%llx importRva=0x%08lx descriptors=%zu\n",
        static_cast<unsigned long long>(base), rva, old.size() + 1);
}

static void RunCase(const fs::path& target, const fs::path& agent, const fs::path& artifacts, bool target32, unsigned mode)
{
    const bool entryMode = mode == 1;
    OwnedRun run;
    const wchar_t* modes[] = { L"fresh", L"entry", L"early-import" };
    const auto label = std::wstring(target32 ? L"x86-" : L"x64-") + modes[mode];
    std::wprintf(L"CASE=%ls\n", label.c_str());
    const auto name = L"Local\\KSwordStartupProbe-" + std::to_wstring(GetCurrentProcessId()) + L"-" + label;
    run.mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(ProbeStages), name.c_str());
    Require(run.mapping != nullptr, "create stage mapping");
    run.stages = static_cast<ProbeStages*>(MapViewOfFile(run.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ProbeStages)));
    Require(run.stages != nullptr, "map stage counters");
    run.quit = CreateEventW(nullptr, TRUE, FALSE, (name + L"-quit").c_str()); Require(run.quit != nullptr, "create quit event");
    run.directory = artifacts / label; fs::create_directories(run.directory);
    Require(SetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_MAP", name.c_str()), "set child mapping");
    Require(SetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_DIRECTORY", run.directory.c_str()), "set child artifact directory");
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    auto command = wm::quoteWindowsArgument(target.wstring()) + L" --child";
    const BOOL created = CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | (entryMode ? DEBUG_ONLY_THIS_PROCESS : 0), nullptr, target.parent_path().c_str(), &startup, &run.pi);
    const auto creationError = GetLastError();
    SetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_MAP", nullptr);
    SetEnvironmentVariableW(L"KSWORD_STARTUP_PROBE_DIRECTORY", nullptr);
    SetLastError(creationError); Require(created, "create owned suspended target");
    run.debugAttached = entryMode;
    std::printf("TARGET_PID=%lu CREATION=%llu\n", run.pi.dwProcessId, wm::processCreationIdentity(run.pi.hProcess));
    WriteConfig(run);
    Check(run.stages->tls == 0 && run.stages->constructor == 0 && run.stages->main == 0, "fresh suspended process has run no owned startup marker");
    if (mode == 2) {
        const auto bootstrap = agent.parent_path() / (target32 ? L"StartupProbeBootstrap_x86.dll" : L"StartupProbeBootstrap_x64.dll");
        ArrangeEarlyImport(run, target32, bootstrap);
        Check(ResumeThread(run.pi.hThread) == 1, "first primary resume occurs only after early bootstrap import is arranged");
        const auto deadline = GetTickCount64() + 10000;
        while (!run.stages->mainWrite && WaitForSingleObject(run.pi.hProcess, 0) == WAIT_TIMEOUT && GetTickCount64() < deadline) Sleep(10);
        std::printf("EARLY_RESULT loaded=%ld installed=%ld beforeTls=%ld tls=%ld ctor=%ld main=%ld capturedTls=%ld capturedCtor=%ld capturedMain=%ld\n",
            run.stages->bootstrapLoaded, run.stages->bootstrapInstalled, run.stages->bootstrapBeforeTls,
            run.stages->tls, run.stages->constructor, run.stages->main,
            run.stages->tlsCaptured, run.stages->constructorCaptured, run.stages->mainCaptured);
        DWORD exit = 0; GetExitCodeProcess(run.pi.hProcess, &exit); std::printf("EARLY_PROCESS_EXIT_OR_ACTIVE=0x%08lx\n", exit);
        Check(run.stages->bootstrapLoaded == 1 && run.stages->bootstrapInstalled == 1 && run.stages->bootstrapBeforeTls == 1,
            "test bootstrap loads and installs owned IAT hook before process-attach TLS callback");
        Check(run.stages->tlsCaptured == 1 && run.stages->constructorCaptured == 1 && run.stages->mainCaptured == 1,
            "early test hook captures first TLS, constructor and main file-open calls");
        Check(run.stages->tlsWrite == 1 && run.stages->constructorWrite == 1 && run.stages->mainWrite == 1,
            "early instrumentation preserves original startup file writes");
        Check(wm::remoteImageLoaded(run.pi.dwProcessId, bootstrap.wstring()), "bootstrap identity confirmed in owned target module list");
        SetEvent(run.quit);
        Check(WaitForSingleObject(run.pi.hProcess, 10000) == WAIT_OBJECT_0, "early-instrumented owned target exits normally");
        Require(GetExitCodeProcess(run.pi.hProcess, &exit), "read early-instrumented exit");
        Check(exit == 0, "early-instrumented target exit code zero");
        return;
    }
    if (entryMode) {
        HoldAtEntry(run, target32);
        std::printf("AT_ENTRY tls=%ld ctor=%ld main=%ld\n", run.stages->tls, run.stages->constructor, run.stages->main);
        Check(run.stages->tls == 1 && run.stages->tlsWrite == 1, "EXE TLS callback already ran before EXE entry breakpoint");
        Check(run.stages->constructor == 0 && run.stages->main == 0, "CRT constructor and main remain unexecuted at entry");
    }
    std::wstring error;
    const bool loaded = wm::injectAgentNative(run.pi.dwProcessId, agent.wstring(), &error, wm::processCreationIdentity(run.pi.hProcess));
    const auto injectionError = GetLastError();
    std::wprintf(L"INJECT loaded=%u error=%lu detail=%ls\n", loaded ? 1U : 0U, injectionError, error.c_str());
    if (!entryMode) {
        // This is an observation of the existing injector, not a universal
        // assertion that pre-loader instrumentation is impossible.
        std::printf("FRESH_CURRENT_INJECTOR_RESULT=%s\n", loaded ? "LOADED" : "NOT_LOADED");
        Check(!loaded, "current module-resolving injector rejects fresh uninitialized target (negative control)");
        Check(run.stages->tls == 0 && run.stages->constructor == 0 && run.stages->main == 0, "failed fresh injection did not run target startup markers");
        SetEvent(run.quit);
        Check(ResumeThread(run.pi.hThread) == 1, "release fresh target original suspend exactly once");
        Check(WaitForSingleObject(run.pi.hProcess, 10000) == WAIT_OBJECT_0, "negative-control target exits normally");
        DWORD exit = 0; Require(GetExitCodeProcess(run.pi.hProcess, &exit), "read negative-control exit");
        std::printf("CONTROL_EXIT=%lu tls=%ld ctor=%ld main=%ld tlsWrite=%ld ctorWrite=%ld mainWrite=%ld\n", exit,
            run.stages->tls, run.stages->constructor, run.stages->main,
            run.stages->tlsWrite, run.stages->constructorWrite, run.stages->mainWrite);
        Check(exit == 0 && run.stages->tls == 1 && run.stages->constructor == 1 && run.stages->main == 1,
            "unmonitored control executes TLS, constructor and main normally");
        return;
    }
    Check(loaded, "production R3 injector loads real Release Agent while primary thread remains suspended at entry");
    Receiver receiver(run);
    receiver.Until([&] { return receiver.installed; });
    Check(receiver.sessionReady && receiver.installed, "real Agent reports SessionReady then HooksInstalled");
    Check(run.stages->constructor == 0 && run.stages->main == 0, "Hook installation completes before constructor and main execute");
    CONTEXT native{}; WOW64_CONTEXT wow{};
    if (target32) { wow.ContextFlags = WOW64_CONTEXT_CONTROL; Require(Wow64GetThreadContext(run.pi.hThread, &wow), "read held WOW64 primary"); }
    else { native.ContextFlags = CONTEXT_CONTROL; Require(GetThreadContext(run.pi.hThread, &native), "read held primary"); }
    Check(ResumeThread(run.pi.hThread) == 1, "release only explicit entry suspend after HooksInstalled");
    receiver.Until([&] { return receiver.mainEvent && receiver.constructorEvent && receiver.writes >= 2 && run.stages->mainWrite == 1; });
    Check(receiver.constructorEvent && receiver.mainEvent, "Agent captures first constructor and main CreateFileW calls");
    Check(!receiver.tlsEvent, "pre-Agent process-attach TLS call is explicitly outside capture coverage");
    Check(run.stages->constructorWrite == 1 && run.stages->mainWrite == 1, "constructor and main retain successful original file writes");
    HANDLE stop = CreateFileW(run.stop.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, 0, nullptr);
    Require(stop != INVALID_HANDLE_VALUE, "create owned stop flag"); run.ownsStop = true; CloseHandle(stop);
    receiver.Until([&] { return receiver.removed; });
    Check(receiver.removed, "real Agent restores hooks and reports HooksRemoved");
    std::printf("OBSERVED coverageItems=%u writeEvents=%u tlsCaptured=%u ctorCaptured=%u mainCaptured=%u\n",
        receiver.coverageItems, receiver.writes, receiver.tlsEvent ? 1U : 0U, receiver.constructorEvent ? 1U : 0U, receiver.mainEvent ? 1U : 0U);
    SetEvent(run.quit);
    Check(WaitForSingleObject(run.pi.hProcess, 10000) == WAIT_OBJECT_0, "instrumented owned target exits normally");
    DWORD exit = 0; Require(GetExitCodeProcess(run.pi.hProcess, &exit), "read instrumented target exit");
    Check(exit == 0, "instrumented target exit code zero");
}
#endif

int wmain(int argc, wchar_t** argv)
{
#ifndef _WIN64
    if (argc == 2 && std::wstring(argv[1]) == L"--cooperative-target") return CooperativeWin32Target();
#endif
    if (argc == 2 && std::wstring(argv[1]) == L"--child") return ChildMain();
#ifdef _WIN64
    if (argc != 3) { std::fprintf(stderr, "usage: ApiMonitorStartupValidation releaseDirectory fixedArtifactDirectory\n"); return 2; }
    try {
        const fs::path release = fs::absolute(argv[1]), artifacts = fs::absolute(argv[2]);
        wchar_t ownPath[32768]{}; Require(GetModuleFileNameW(nullptr, ownPath, 32768), "read controller path");
        fs::create_directories(artifacts);
        for (bool target32 : { false, true }) {
            const auto target = target32 ? release / L"ApiMonitorStartupTarget_x86.exe" : fs::path(ownPath);
            const auto agent = release / (target32 ? L"APIMonitor_x86.dll" : L"APIMonitor_x64.dll");
            for (unsigned mode : { 0U, 1U, 2U }) RunCase(target, agent, artifacts, target32, mode);
        }
        RemoveDirectoryW(artifacts.c_str());
        std::printf("SUMMARY checks=%u failures=0 scope=owned-x64-and-x86-Release-Agent-plus-distinct-early-IAT-prototype\n", checks);
        return 0;
    } catch (const std::exception& exception) {
        std::printf("SUMMARY checks=%u failure=%s\n", checks, exception.what()); return 1;
    }
#else
    return 2;
#endif
}
