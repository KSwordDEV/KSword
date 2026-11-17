#include "KswordCeBridge.h"
#include "../DebuggerBackend/KswordDebuggerBackend.h"
#include "../shared/driver/KswordArkKernelNoAttachIoctl.h"

#include <mutex>
#include <limits>
#include <string>
#include <vector>

namespace ksword::ce
{
    namespace
    {
        // The adapter only translates CE's SDK calls; all backend policy is reusable.
        struct Hook { void* slot; void* replacement; void* original; };
        std::mutex g_mutex;
        std::vector<Hook> g_hooks;
        ExportedFunctions* g_functions = nullptr;
        int g_pluginId = -1;
        int g_registrationId = -1;

        struct DataProtection
        {
            // 保护与下一次写入保留同一目标作用域，不在保护成功后补抓公开槽位。
            std::shared_ptr<debugger::Backend::TargetLease> identity;
            DWORD pid = 0;
            std::uintptr_t address = 0;
            SIZE_T bytes = 0;
            MEMORY_BASIC_INFORMATION original{};
        };
        // CE SetValue / freeze temporarily asks for RWX even for ordinary data.
        // Retain one same-thread, one-write transaction, never a global PID hint.
        thread_local DataProtection g_dataProtection;

        bool contains(std::uintptr_t base, SIZE_T length, std::uintptr_t address, SIZE_T bytes)
        {
            return bytes != 0 && length <= (std::numeric_limits<std::uintptr_t>::max)() - base &&
                address >= base && address <= base + length && bytes <= base + length - address;
        }

        bool executable(DWORD protection)
        {
            return (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        template<typename T, typename Action> T boundary(Action action, T failure) noexcept
        {
            try { return action(); }
            catch (...) { SetLastError(ERROR_GEN_FAILURE); return failure; }
        }

        // Environment-driven no-attach selector. Set BEFORE launching CE:
        //   KSWORD_DEBUGGER_NOATTACH_MODE=hvm  (EPT + MTF/VMX-TF transport)
        //   KSWORD_DEBUGGER_NOATTACH_MODE=kernel (ordinary-driver DR + TF transport)
        //   KSWORD_DEBUGGER_NOATTACH_TID=<decimal thread id to hold>
        // Any other value or missing TID keeps CE on its default attach path.
        DWORD readDecimal(const wchar_t* name)
        {
            wchar_t buffer[32]{};
            const DWORD read = GetEnvironmentVariableW(name, buffer, _countof(buffer));
            if (read == 0 || read >= _countof(buffer)) return 0;
            DWORD value = 0;
            for (DWORD i = 0; i < read; ++i)
            {
                if (buffer[i] < L'0' || buffer[i] > L'9') return 0;
                if (value > (std::numeric_limits<DWORD>::max)() / 10) return 0;
                value = value * 10 + static_cast<DWORD>(buffer[i] - L'0');
            }
            return value;
        }
        DWORD readMode()
        {
            wchar_t buffer[16]{};
            const DWORD read = GetEnvironmentVariableW(L"KSWORD_DEBUGGER_NOATTACH_MODE", buffer, _countof(buffer));
            if (read == 0 || read >= _countof(buffer)) return 0;
            if (read == 3 && _wcsnicmp(buffer, L"hvm", 3) == 0) return KSWORD_DEBUGGER_NOATTACH;
            if (read == 6 && _wcsnicmp(buffer, L"kernel", 6) == 0) return KSWORD_DEBUGGER_KERNEL_NOATTACH;
            return 0;
        }
        DWORD armIndependentFrontend(DWORD pid)
        {
            const DWORD mode = readMode();
            if (mode == 0) return ERROR_SUCCESS;
            const DWORD tid = readDecimal(L"KSWORD_DEBUGGER_NOATTACH_TID");
            if (tid == 0 || pid <= 4) return ERROR_SUCCESS;
            auto& frontend = debugger::backend().independentFrontend();
            if (frontend.selected()) return ERROR_SUCCESS;
            KSWORD_DEBUGGER_FRONTEND_REQUEST request{};
            request.version = KSWORD_DEBUGGER_FRONTEND_VERSION;
            request.size = sizeof(request);
            request.operation = KSWORD_DEBUGGER_FRONTEND_SELECT;
            request.command = mode;
            request.flags = KSWORD_ARK_HVM_NOATTACH_CONFIRMED |
                (mode == KSWORD_DEBUGGER_KERNEL_NOATTACH ? KSWORD_ARK_KERNEL_NOATTACH_HOOK_ACK : 0);
            request.processId = pid; request.threadId = tid;
            KSWORD_DEBUGGER_FRONTEND_STATUS status{};
            const DWORD error = frontend.control(request, status);
            debugger::backend().log(error == ERROR_SUCCESS ?
                "CE no-attach SELECT accepted: mode=" + std::to_string(mode) + " PID=" + std::to_string(pid) + " TID=" + std::to_string(tid) :
                "CE no-attach SELECT refused: error=" + std::to_string(error) + " mode=" + std::to_string(mode) + " PID=" + std::to_string(pid) + " TID=" + std::to_string(tid));
            return error;
        }
        void disarmIndependentFrontend()
        {
            auto& frontend = debugger::backend().independentFrontend();
            if (!frontend.selected() || frontend.active()) return;
            KSWORD_DEBUGGER_FRONTEND_REQUEST request{};
            request.version = KSWORD_DEBUGGER_FRONTEND_VERSION;
            request.size = sizeof(request);
            request.operation = KSWORD_DEBUGGER_FRONTEND_CLOSE;
            KSWORD_DEBUGGER_FRONTEND_STATUS status{};
            (void)frontend.control(request, status);
        }

        HANDLE WINAPI openProcess(DWORD access, BOOL inherit, DWORD pid)
        { return boundary([&] { return debugger::backend().openProcess(access, inherit, pid); }, static_cast<HANDLE>(nullptr)); }
        BOOL WINAPI readMemory(HANDLE process, LPCVOID address, LPVOID data, SIZE_T bytes, SIZE_T* transferred)
        { return boundary([&] {
            if (transferred != nullptr) *transferred = 0;
            debugger::Backend::TargetLease target;
            if (!debugger::backend().retainTarget(process, false, target)) return FALSE;
            process = target.native();
            // CE's Local Lua functions build our ABI packets in its own memory.
            // Driver process protections must not intercept these local buffers.
            if (target.processId() == GetCurrentProcessId())
                return ::ReadProcessMemory(process, address, data, bytes, transferred);
            return debugger::backend().readMemory(process, address, data, bytes, transferred);
        }, FALSE); }
        BOOL WINAPI writeMemory(HANDLE process, LPVOID address, LPCVOID data, SIZE_T bytes, SIZE_T* transferred)
        { return boundary([&] {
            if (transferred != nullptr) *transferred = 0;
            auto transaction = std::move(g_dataProtection);
            g_dataProtection = {};
            debugger::Backend::TargetLease target;
            if (!debugger::backend().retainTarget(process, false, target)) return FALSE;
            process = target.native();
            if (target.processId() == GetCurrentProcessId())
                return ::WriteProcessMemory(process, address, data, bytes, transferred);
            auto kind = debugger::Backend::MemoryWriteKind::byProtection;
            if (transaction.pid != 0 && target.processId() == transaction.pid &&
                contains(transaction.address, transaction.bytes, reinterpret_cast<std::uintptr_t>(address), bytes))
            {
                MEMORY_BASIC_INFORMATION current{};
                if (!transaction.identity || transaction.identity->processId() != transaction.pid ||
                    debugger::backend().queryMemory(process, address, &current, sizeof(current)) == 0 ||
                    current.State != MEM_COMMIT || current.Protect != PAGE_EXECUTE_READWRITE ||
                    current.AllocationBase != transaction.original.AllocationBase || current.Type != transaction.original.Type ||
                    !contains(reinterpret_cast<std::uintptr_t>(current.BaseAddress), current.RegionSize,
                        reinterpret_cast<std::uintptr_t>(address), bytes))
                {
                    if (transferred != nullptr) *transferred = 0;
                    debugger::backend().log("CE data write refused: temporary-protection transaction could not be verified");
                    SetLastError(ERROR_INVALID_STATE); return FALSE;
                }
                kind = debugger::Backend::MemoryWriteKind::data;
            }
            return debugger::backend().writeMemory(process, address, data, bytes, transferred, kind);
        }, FALSE); }
        SIZE_T WINAPI queryMemory(HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION info, SIZE_T bytes)
        { return boundary([&] { return debugger::backend().queryMemory(process, address, info, bytes); }, static_cast<SIZE_T>(0)); }
        BOOL WINAPI getContext(HANDLE thread, LPCONTEXT context)
        { return boundary([&] { return debugger::backend().getContext(thread, context); }, FALSE); }
        BOOL WINAPI setContext(HANDLE thread, const CONTEXT* context)
        { return boundary([&] { return debugger::backend().setContext(thread, context); }, FALSE); }
        DWORD WINAPI suspendThread(HANDLE thread)
        { return boundary([&] { return debugger::backend().suspendThread(thread); }, MAXDWORD); }
        DWORD WINAPI resumeThread(HANDLE thread)
        { return boundary([&] { return debugger::backend().resumeThread(thread); }, MAXDWORD); }
        BOOL WINAPI waitEvent(LPDEBUG_EVENT event, DWORD milliseconds)
        { return boundary([&] { return debugger::backend().waitEvent(event, milliseconds); }, FALSE); }
        BOOL WINAPI continueEvent(DWORD pid, DWORD tid, DWORD status)
        { return boundary([&] { return debugger::backend().continueEvent(pid, tid, status); }, FALSE); }
        BOOL WINAPI attach(DWORD pid)
        { return boundary([&] {
            const DWORD armError = armIndependentFrontend(pid);
            if (armError != ERROR_SUCCESS) { SetLastError(armError); return FALSE; }
            const BOOL ok = debugger::backend().attach(pid);
            if (!ok) { const DWORD saved = GetLastError(); disarmIndependentFrontend(); SetLastError(saved); }
            return ok;
        }, FALSE); }
        BOOL WINAPI protectMemory(HANDLE process, LPVOID address, SIZE_T bytes, DWORD protection, PDWORD previous)
        { return boundary([&] {
            g_dataProtection = {};
            auto target = std::make_shared<debugger::Backend::TargetLease>();
            if (!debugger::backend().retainTarget(process, false, *target)) return FALSE;
            process = target->native();
            MEMORY_BASIC_INFORMATION original{};
            const auto requested = reinterpret_cast<std::uintptr_t>(address);
            const bool data = protection == PAGE_EXECUTE_READWRITE &&
                debugger::backend().queryMemory(process, address, &original, sizeof(original)) != 0 &&
                original.State == MEM_COMMIT && !executable(original.Protect) &&
                (original.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
                contains(reinterpret_cast<std::uintptr_t>(original.BaseAddress), original.RegionSize, requested, bytes);
            const BOOL ok = debugger::backend().protectMemory(process, address, bytes, protection, previous);
            const DWORD error = GetLastError();
            if (ok && data && previous != nullptr && *previous == original.Protect)
            {
                g_dataProtection.pid = target->processId();
                g_dataProtection.address = requested; g_dataProtection.bytes = bytes;
                g_dataProtection.original = original;
                // TLS 析构只能释放引用，不在 loader lock 下等待后端 mutex。
                target->releaseAlias();
                g_dataProtection.identity = std::move(target);
            }
            SetLastError(error); return ok;
        }, FALSE); }
        LPVOID WINAPI allocateMemory(HANDLE process, LPVOID address, SIZE_T bytes, DWORD type, DWORD protection)
        { return boundary([&] { return debugger::backend().allocateMemory(process, address, bytes, type, protection); }, static_cast<LPVOID>(nullptr)); }
        HANDLE WINAPI createThread(HANDLE process, LPSECURITY_ATTRIBUTES attributes, SIZE_T stackBytes,
            LPTHREAD_START_ROUTINE start, LPVOID parameter, DWORD flags, LPDWORD tid)
        { return boundary([&] { return debugger::backend().createThread(process, attributes, stackBytes, start, parameter, flags, tid); }, static_cast<HANDLE>(nullptr)); }
        HANDLE WINAPI openThread(DWORD access, BOOL inherit, DWORD tid)
        { return boundary([&] { return debugger::backend().openThread(access, inherit, tid); }, static_cast<HANDLE>(nullptr)); }

        template<typename Function> void addHook(void* slot, Function function)
        {
            g_hooks.push_back({slot, reinterpret_cast<void*>(function), nullptr});
        }

        bool installHooks()
        {
            if (g_functions == nullptr) return false;
            if (g_hooks.empty())
            {
                addHook(g_functions->readProcessMemory, &readMemory);
                addHook(g_functions->writeProcessMemory, &writeMemory);
                addHook(g_functions->openProcess, &openProcess);
                addHook(g_functions->virtualQueryEx, &queryMemory);
                addHook(g_functions->getThreadContext, &getContext);
                addHook(g_functions->setThreadContext, &setContext);
                addHook(g_functions->suspendThread, &suspendThread);
                addHook(g_functions->resumeThread, &resumeThread);
                addHook(g_functions->waitForDebugEvent, &waitEvent);
                addHook(g_functions->continueDebugEvent, &continueEvent);
                addHook(g_functions->debugActiveProcess, &attach);
                addHook(g_functions->virtualProtectEx, &protectMemory);
                addHook(g_functions->virtualAllocEx, &allocateMemory);
                addHook(g_functions->createRemoteThread, &createThread);
                addHook(g_functions->openThread, &openThread);
                for (const auto& hook : g_hooks) if (hook.slot == nullptr) { g_hooks.clear(); return false; }
            }
            for (auto& hook : g_hooks)
            {
                auto* slot = static_cast<void* volatile*>(hook.slot);
                if (*slot != hook.replacement)
                    hook.original = InterlockedExchangePointer(slot, hook.replacement);
            }
            return true;
        }
    }

    BOOL initializeBridge(ExportedFunctions* functions, int pluginId)
    {
        if (functions == nullptr || functions->sizeofExportedFunctions < static_cast<int>(kRequiredExportedFunctionsSize))
            return FALSE;
        // CE can disable a plugin while its debug-event thread is inside a hook.
        // Keep code mapped until CE exits; disabling still restores every slot and
        // releases the driver session, so an outstanding call cannot return into
        // an unloaded DLL. No loader work occurs from DllMain.
        HMODULE pinned = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&initializeBridge), &pinned)) return FALSE;
        const bool driverReady = debugger::backend().initialize();
        const DWORD driverError = driverReady ? ERROR_SUCCESS : GetLastError();
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_functions != nullptr) return g_functions == functions ? TRUE : FALSE;
            g_functions = functions; g_pluginId = pluginId;
            if (driverReady && !installHooks()) { g_functions = nullptr; g_pluginId = -1; return FALSE; }
        }
        if (functions->registerFunction != nullptr)
        {
            FunctionPointerChangeInitialization initialization{&notifyFunctionPointersChanged};
            const int id = functions->registerFunction(pluginId, PluginType::functionPointerChange, &initialization);
            std::lock_guard<std::mutex> lock(g_mutex);
            g_registrationId = id;
        }
        debugger::backend().log(driverReady ? "CE adapter installed 15 memory/thread/debugger function hooks; edits and freeze share write policy" :
            "CE bridge connected; explicit native route: R0 unavailable (error " + std::to_string(driverError) +
            "), CE retains its native function table; Shadow/HVM memory policy is not active");
        return TRUE;
    }

    BOOL disableBridge()
    {
        // Refuse unloading code if backend cleanup left a live EPT transaction.
        if (!debugger::backend().shutdown()) return FALSE;
        UnregisterFunction unregister = nullptr;
        int pluginId = -1, registrationId = -1;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_functions == nullptr) return TRUE;
            for (const auto& hook : g_hooks)
                (void)InterlockedCompareExchangePointer(static_cast<void* volatile*>(hook.slot), hook.original, hook.replacement);
            unregister = g_functions->unregisterFunction;
            pluginId = g_pluginId; registrationId = g_registrationId;
            g_functions = nullptr; g_pluginId = -1; g_registrationId = -1; g_hooks.clear();
        }
        if (unregister != nullptr && registrationId >= 0) (void)unregister(pluginId, registrationId);
        return TRUE;
    }

    void __stdcall notifyFunctionPointersChanged(int reserved)
    {
        UNREFERENCED_PARAMETER(reserved);
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_functions != nullptr && debugger::backend().initialize()) (void)installHooks();
    }
}
