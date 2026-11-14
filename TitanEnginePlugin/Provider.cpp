#include "Proxy.h"
#include <filesystem>
#include <map>

extern "C" unsigned long __stdcall KSwordDebuggerCall(KSWORD_DEBUGGER_CALL* call);

namespace ksword::titan
{
    namespace
    {
        NativeApi replayApi{};
        std::atomic<NativeApi*> provider{&nativeApi};
        std::map<TitanEngineVariable, bool> engineVariables;
        TitanBreakpointType breakpointOptions = UE_BREAKPOINT_INT3;

        DWORD loadReplay()
        {
            // Initialization is outside DllMain and uses the host checked loader.
            // A failed load may be retried after the missing dependency is fixed.
            if (replayApi.GetSessionInfo != nullptr) return ERROR_SUCCESS;
            HMODULE proxy = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&KSwordTitanInitialize), &proxy)) return GetLastError();
            wchar_t path[32768]{};
            const auto count = GetModuleFileNameW(proxy, path, _countof(path));
            if (count == 0 || count >= _countof(path)) return ERROR_BAD_PATHNAME;
            const auto replayPath = std::filesystem::path(path).parent_path().parent_path() / L"DbgEng" / L"TitanEngine.dll";
            using CheckedLoader = HMODULE (*)(const wchar_t*, bool);
            HMODULE bridge = GetModuleHandleW(L"x64bridge.dll");
            if (bridge == nullptr) bridge = GetModuleHandleW(L"x64_bridge.dll");
            const auto checked = bridge == nullptr ? nullptr : reinterpret_cast<CheckedLoader>(GetProcAddress(bridge, "BridgeLoadLibraryCheckedW"));
            const HMODULE module = checked != nullptr ? checked(replayPath.c_str(), true) :
                LoadLibraryExW(replayPath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
            if (module == nullptr) return GetLastError();
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(module) + dos->e_lfanew);
            if (module == proxy || GetProcAddress(module, "KSwordTitanInitialize") != nullptr ||
                dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            { FreeLibrary(module); return ERROR_BAD_EXE_FORMAT; }
            NativeApi candidate{};
#define KSW_RESOLVE(name) candidate.name = reinterpret_cast<decltype(candidate.name)>(GetProcAddress(module, #name)); \
            if (candidate.name == nullptr) { FreeLibrary(module); return ERROR_PROC_NOT_FOUND; }
#include "ResolveExports.inc"
#undef KSW_RESOLVE
            HMODULE pinned = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(candidate.GetSessionInfo), &pinned))
            { const DWORD error = GetLastError(); FreeLibrary(module); return error; }
            // Upstream performs COM/DbgEng worker initialization here, not in
            // InitReplayW. A provider loaded after bridge startup must receive
            // the same startup handshake before any replay entry point.
            if (!candidate.EngineCheckStructAlignment(UE_STRUCT_TITAN_ENGINE_CONTEXT, sizeof(TITAN_ENGINE_CONTEXT_t)))
            { const DWORD error = GetLastError(); return error == ERROR_SUCCESS ? ERROR_DLL_INIT_FAILED : error; }
            replayApi = candidate;
            log("DbgEng replay provider validated: 64 AMD64 exports; synthetic handles remain inside this provider");
            return ERROR_SUCCESS;
        }
    }

    NativeApi& activeApi()
    { return debugger::backend().independentFrontend().selected() ? independentApi() : *provider.load(std::memory_order_acquire); }
    bool replayProvider() { return provider.load(std::memory_order_acquire) != &nativeApi; }
    bool useHvm() { return hvmSelected.load() && !replayProvider() && !debugger::backend().independentFrontend().selected(); }

    DWORD selectLiveProvider()
    {
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        if (activeApi().IsFileBeingDebugged()) return ERROR_BUSY;
        if (debugger::backend().independentFrontend().selected()) return ERROR_SUCCESS;
        const DWORD error = releaseSession();
        if (error != ERROR_SUCCESS) return error;
        provider.store(&nativeApi, std::memory_order_release);
        return ERROR_SUCCESS;
    }

    void rememberBreakpointOptions(TitanBreakpointType type)
    {
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        breakpointOptions = type;
    }

    PROCESS_INFORMATION* startReplay(const wchar_t* artifact, TitanSessionKind kind)
    {
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        if (artifact == nullptr || (kind != UE_SESSION_MINIDUMP && kind != UE_SESSION_TTD))
        { SetLastError(ERROR_INVALID_PARAMETER); return nullptr; }
        if (debugger::backend().independentFrontend().selected()) { SetLastError(ERROR_BUSY); return nullptr; }
        if (activeApi().IsFileBeingDebugged()) { SetLastError(ERROR_BUSY); return nullptr; }
        DWORD error = releaseSession();
        if (error == ERROR_SUCCESS) error = loadReplay();
        if (error != ERROR_SUCCESS)
        { log("Replay provider initialization failed: " + std::to_string(error)); SetLastError(error); return nullptr; }
        for (const auto& option : engineVariables) replayApi.SetEngineVariable(option.first, option.second);
        replayApi.SetBPXOptions(breakpointOptions);
        auto* result = replayApi.InitReplayW(artifact, kind);
        const DWORD initError = GetLastError();
        if (result != nullptr)
        {
            provider.store(&replayApi, std::memory_order_release);
            log("Session provider=DbgEng kind=" + std::to_string(kind) + "; HVM preference retained for the next live session; replay memory and handles stay synthetic");
        }
        SetLastError(initError); return result;
    }

    DWORD queryEngineInfo(KSWORD_DEBUGGER_ENGINE_INFO& info)
    {
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        TITAN_SESSION_INFO session{};
        if (!activeApi().GetSessionInfo(&session)) return GetLastError();
        if (session.structSize != sizeof(session)) return ERROR_REVISION_MISMATCH;
        info = {};
        info.version = KSWORD_DEBUGGER_ENGINE_INFO_VERSION; info.size = sizeof(info);
        info.provider = replayProvider() ? KSWORD_DEBUGGER_PROVIDER_DBGENG : KSWORD_DEBUGGER_PROVIDER_NATIVE;
        info.sessionKind = session.kind; info.capabilities = session.capabilities; info.processId = session.processId;
        info.configuredHvm = hvmSelected.load() ? 1U : 0U;
        info.activeHvm = useHvm() && session.kind == UE_SESSION_LIVE ? 1U : 0U;
        info.windowsDebugTransport = session.kind == UE_SESSION_LIVE && !debugger::backend().independentFrontend().selected() ? 1U : 0U;
        info.hardwareSlots = 4; info.eptDataGranularity = 4096;
        info.backend = debugger::backend().status();
        KSWORD_DEBUGGER_CALL call{KSWORD_DEBUGGER_API_VERSION, sizeof(call), KSWORD_DEBUGGER_QUERY_POLICY, 0, 0,
            reinterpret_cast<std::uintptr_t>(&info.policy), 0, sizeof(info.policy), 0, 0};
        return KSwordDebuggerCall(&call);
    }
}

extern "C"
{
    PROCESS_INFORMATION* InitReplayW(const wchar_t* artifact, TitanSessionKind kind)
    {
        if (ksword::titan::ensureNative() != ERROR_SUCCESS) return nullptr;
        return ksword::titan::startReplay(artifact, kind);
    }

    bool GetSessionInfo(TITAN_SESSION_INFO* info)
    {
        using namespace ksword::titan;
        if (ensureNative() != ERROR_SUCCESS) return false;
        if (info == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
        const bool result = activeApi().GetSessionInfo(info);
        if (result && info->structSize != sizeof(*info)) { SetLastError(ERROR_REVISION_MISMATCH); return false; }
        return result;
    }

    void SetEngineVariable(TitanEngineVariable variable, bool value)
    {
        using namespace ksword::titan;
        if (ensureNative() != ERROR_SUCCESS) return;
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        engineVariables[variable] = value;
        // Apply to the live provider too so switching back retains the policy.
        nativeApi.SetEngineVariable(variable, value);
        if (replayProvider()) activeApi().SetEngineVariable(variable, value);
    }

    SIZE_T MemoryQuerySafe(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION info, SIZE_T bytes)
    {
        using namespace ksword::titan;
        if (ensureNative() != ERROR_SUCCESS) return 0;
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        return useHvm() && GetProcessId(process) != GetCurrentProcessId()
            ? ksword::debugger::backend().queryMemory(process, address, info, bytes)
            : activeApi().MemoryQuerySafe(process, address, info, bytes);
    }

    LPVOID MemoryAllocSafe(HANDLE process, LPVOID address, SIZE_T bytes, DWORD type, DWORD protection)
    {
        using namespace ksword::titan;
        if (ensureNative() != ERROR_SUCCESS) return nullptr;
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        return useHvm() && GetProcessId(process) != GetCurrentProcessId()
            ? ksword::debugger::backend().allocateMemory(process, address, bytes, type, protection)
            : activeApi().MemoryAllocSafe(process, address, bytes, type, protection);
    }

    bool MemoryProtectSafe(HANDLE process, LPVOID address, SIZE_T bytes, DWORD protection, PDWORD previous)
    {
        using namespace ksword::titan;
        if (ensureNative() != ERROR_SUCCESS) return false;
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        return useHvm() && GetProcessId(process) != GetCurrentProcessId()
            ? ksword::debugger::backend().protectMemory(process, address, bytes, protection, previous) != FALSE
            : activeApi().MemoryProtectSafe(process, address, bytes, protection, previous);
    }

    DWORD TitanSuspendThread(HANDLE thread)
    {
        using namespace ksword::titan;
        if (ensureNative() != ERROR_SUCCESS) return MAXDWORD;
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        return useHvm() ? ksword::debugger::backend().suspendThread(thread) : activeApi().TitanSuspendThread(thread);
    }

    DWORD TitanResumeThread(HANDLE thread)
    {
        using namespace ksword::titan;
        if (ensureNative() != ERROR_SUCCESS) return MAXDWORD;
        std::lock_guard<std::recursive_mutex> lock(policyMutex);
        return useHvm() ? ksword::debugger::backend().resumeThread(thread) : activeApi().TitanResumeThread(thread);
    }
}
