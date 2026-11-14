#include "Proxy.h"
#include "NativeApi.h"
#include "../DebuggerBackend/KswordDebuggerBackend.h"
#pragma warning(push)
#pragma warning(disable: 4324)
#include "../third_party/x64dbg_abi/TitanEngine.h"
#pragma warning(pop)

#include <Windows.h>
#include <limits>
#include <array>
#include <map>
#include <mutex>
#include <vector>

// Independent transport shim for TitanEngine. Entries that IndependentFrontend
// cannot cover yet must stay here to keep the native table complete, so
// Provider.cpp can route activeApi() without dereferencing a null slot. Each
// stub reports ERROR_CALL_NOT_IMPLEMENTED; the known callable surface grows as
// IndependentFrontend gains features (XSTATE, watchpoints, DebugLoop fan-out).

namespace ksword::titan
{
    namespace
    {
        bool rejectBool() { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return false; }
        template<typename T> T rejectValue(T value)
        { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return value; }

        // Address<->id bookkeeping for the Independent transport. TitanEngine's
        // API addresses breakpoints by VA while the driver returns opaque ids;
        // the shim keeps the translation and clears it whenever the owning
        // session is retired by the frontend (StopDebug/DetachDebuggerEx).
        std::mutex softwareBreakpointMutex;
        std::map<ULONG_PTR, std::uint32_t> softwareBreakpointIds;
        std::array<std::uint32_t, 4> hardwareBreakpointIds{};
        std::array<ULONG_PTR, 4> hardwareBreakpointAddresses{};
        void clearBreakpointBindings()
        {
            std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
            softwareBreakpointIds.clear();
            hardwareBreakpointIds = {};
            hardwareBreakpointAddresses = {};
        }

        BOOL readMemoryShim(HANDLE process, LPCVOID address, LPVOID data, SIZE_T bytes, SIZE_T* done)
        {
            if (done != nullptr) *done = 0;
            debugger::Backend::TargetLease target;
            if (!debugger::backend().retainTarget(process, false, target)) return FALSE;
            return debugger::backend().readMemory(target.native(), address, data, bytes, done);
        }

        BOOL writeMemoryShim(HANDLE process, LPVOID address, LPCVOID data, SIZE_T bytes, SIZE_T* done)
        {
            if (done != nullptr) *done = 0;
            debugger::Backend::TargetLease target;
            if (!debugger::backend().retainTarget(process, false, target)) return FALSE;
            return debugger::backend().writeMemory(target.native(), address, data, bytes, done);
        }
    }

    NativeApi& independentApi()
    {
        static NativeApi api = [] {
            NativeApi table{};
            table.MemoryReadSafe = [](HANDLE process, LPVOID address, LPVOID data, SIZE_T bytes, SIZE_T* done) -> bool
            { return readMemoryShim(process, address, data, bytes, done) != FALSE; };
            table.MemoryReadUnsafe = [](HANDLE process, LPCVOID address, LPVOID data, SIZE_T bytes, SIZE_T* done) -> bool
            { return readMemoryShim(process, address, data, bytes, done) != FALSE; };
            table.MemoryWriteSafe = [](HANDLE process, LPVOID address, LPCVOID data, SIZE_T bytes, SIZE_T* done) -> bool
            { return writeMemoryShim(process, address, data, bytes, done) != FALSE; };
            table.MemoryQuerySafe = [](HANDLE process, LPCVOID address, PMEMORY_BASIC_INFORMATION info, SIZE_T bytes) -> SIZE_T
            {
                debugger::Backend::TargetLease target;
                if (!debugger::backend().retainTarget(process, false, target)) return 0;
                return debugger::backend().queryMemory(target.native(), address, info, bytes);
            };
            table.MemoryAllocSafe = [](HANDLE process, LPVOID address, SIZE_T bytes, DWORD type, DWORD protection) -> LPVOID
            {
                debugger::Backend::TargetLease target;
                if (!debugger::backend().retainTarget(process, false, target)) return nullptr;
                return debugger::backend().allocateMemory(target.native(), address, bytes, type, protection);
            };
            table.MemoryFreeSafe = [](HANDLE process, LPVOID address, SIZE_T bytes, DWORD type) -> bool
            {
                debugger::Backend::TargetLease target;
                if (!debugger::backend().retainTarget(process, false, target)) return false;
                return debugger::backend().freeMemory(target.native(), address, bytes, type) != FALSE;
            };
            table.MemoryProtectSafe = [](HANDLE process, LPVOID address, SIZE_T bytes, DWORD protection, PDWORD previous) -> bool
            {
                debugger::Backend::TargetLease target;
                if (!debugger::backend().retainTarget(process, false, target)) return false;
                return debugger::backend().protectMemory(target.native(), address, bytes, protection, previous) != FALSE;
            };
            table.GetPEBLocation = [](HANDLE) -> ULONG_PTR { return rejectValue<ULONG_PTR>(0); };
            table.GetTEBLocation = [](HANDLE) -> ULONG_PTR { return rejectValue<ULONG_PTR>(0); };
            table.InitDebugW = [](const wchar_t*, const wchar_t*, const wchar_t*) -> PROCESS_INFORMATION*
            { return rejectValue<PROCESS_INFORMATION*>(nullptr); };
            table.InitReplayW = [](const wchar_t*, TitanSessionKind) -> PROCESS_INFORMATION*
            { return rejectValue<PROCESS_INFORMATION*>(nullptr); };
            table.GetSessionInfo = [](TITAN_SESSION_INFO*) -> bool { return rejectBool(); };
            table.ReplayGetPosition = [](TITAN_REPLAY_POSITION*) -> bool { return rejectBool(); };
            table.ReplayGetExtent = [](TITAN_REPLAY_POSITION*, TITAN_REPLAY_POSITION*) -> bool { return rejectBool(); };
            table.ReplaySetPosition = [](const TITAN_REPLAY_POSITION*) -> bool { return rejectBool(); };
            table.ReplayRunBack = []() -> bool { return rejectBool(); };
            table.ReplayStepBack = [](TITANCBSTEP) -> bool { return rejectBool(); };
            table.StopDebug = []() -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected() && !frontend.active()) return true;
                KSWORD_DEBUGGER_FRONTEND_REQUEST request{};
                request.version = KSWORD_DEBUGGER_FRONTEND_VERSION;
                request.size = sizeof(request);
                request.operation = KSWORD_DEBUGGER_FRONTEND_CLOSE;
                KSWORD_DEBUGGER_FRONTEND_STATUS status{};
                const DWORD error = frontend.control(request, status);
                if (error == ERROR_SUCCESS) clearBreakpointBindings();
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.SetBPXOptions = [](TitanBreakpointType) {};
            table.IsBPXEnabled = [](ULONG_PTR address) -> bool
            {
                std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                return softwareBreakpointIds.find(address) != softwareBreakpointIds.end();
            };
            table.SetBPX = [](ULONG_PTR address, DWORD, TITANCBSOFTBP) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.active()) { SetLastError(ERROR_INVALID_STATE); return false; }
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    if (softwareBreakpointIds.find(address) != softwareBreakpointIds.end())
                    { SetLastError(ERROR_ALREADY_EXISTS); return false; }
                }
                std::uint32_t id = 0;
                const DWORD error = frontend.addBreakpoint(address, false, id);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    softwareBreakpointIds[address] = id;
                }
                SetLastError(ERROR_SUCCESS); return true;
            };
            table.DeleteBPX = [](ULONG_PTR address) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                std::uint32_t id = 0;
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    auto it = softwareBreakpointIds.find(address);
                    if (it == softwareBreakpointIds.end()) { SetLastError(ERROR_NOT_FOUND); return false; }
                    id = it->second; softwareBreakpointIds.erase(it);
                }
                const DWORD error = frontend.removeBreakpoint(id);
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.SetMemoryBPXEx = [](ULONG_PTR, SIZE_T, TitanMemoryBreakpointType, bool, TITANCBMEMBP) -> bool { return rejectBool(); };
            table.RemoveMemoryBPX = [](ULONG_PTR, SIZE_T) -> bool { return rejectBool(); };
            table.GetFullContextDataEx = [](HANDLE, TITAN_ENGINE_CONTEXT_t*) -> bool { return rejectBool(); };
            table.SetFullContextDataEx = [](HANDLE, TITAN_ENGINE_CONTEXT_t*) -> bool { return rejectBool(); };
            table.GetContextDataEx = [](HANDLE, TitanRegister) -> ULONG_PTR { return rejectValue<ULONG_PTR>(0); };
            table.SetContextDataEx = [](HANDLE, TitanRegister, ULONG_PTR) -> bool { return rejectBool(); };
            table.GetAVXContext = [](HANDLE, TITAN_ENGINE_CONTEXT_t*) -> bool { return rejectBool(); };
            table.SetAVXContext = [](HANDLE, TITAN_ENGINE_CONTEXT_t*) -> bool { return rejectBool(); };
            table.GetAVX512Context = [](HANDLE, TITAN_ENGINE_CONTEXT_AVX512_t*) -> bool { return rejectBool(); };
            table.SetAVX512Context = [](HANDLE, TITAN_ENGINE_CONTEXT_AVX512_t*) -> bool { return rejectBool(); };
            table.GetDebugData = []() -> const DEBUG_EVENT* { return nullptr; };
            table.SetCustomHandler = [](TitanCustomHandler, TITANCALLBACKARG) {};
            // Step shims resume once; the step boundary stop arrives on the
            // next driver event. A Titan-shaped callback fan-out still needs
            // DebugLoop, so these intentionally skip the callback for now.
            table.StepInto = [](TITANCBSTEP) {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected()) { SetLastError(ERROR_INVALID_STATE); return; }
                const DWORD error = frontend.resume(true);
                SetLastError(error);
            };
            table.StepOver = [](TITANCBSTEP) {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected()) { SetLastError(ERROR_INVALID_STATE); return; }
                const DWORD error = frontend.resume(true);
                SetLastError(error);
            };
            table.GetUnusedHardwareBreakPointRegister = [](LPDWORD slot) -> bool
            {
                if (slot == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                for (DWORD i = 0; i < hardwareBreakpointIds.size(); ++i)
                    if (hardwareBreakpointIds[i] == 0) { *slot = i; return true; }
                SetLastError(ERROR_NO_MORE_ITEMS); return false;
            };
            table.SetHardwareBreakPoint = [](ULONG_PTR address, DWORD slot, TitanHardwareBreakpointType, TitanHardwareBreakpointSize, TITANCBHWBP) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.active()) { SetLastError(ERROR_INVALID_STATE); return false; }
                if (slot >= hardwareBreakpointIds.size()) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    if (hardwareBreakpointIds[slot] != 0) { SetLastError(ERROR_ALREADY_EXISTS); return false; }
                }
                std::uint32_t id = 0;
                const DWORD error = frontend.addBreakpoint(address, false, id);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    hardwareBreakpointIds[slot] = id; hardwareBreakpointAddresses[slot] = address;
                }
                SetLastError(ERROR_SUCCESS); return true;
            };
            table.DeleteHardwareBreakPoint = [](DWORD slot) -> bool
            {
                if (slot >= hardwareBreakpointIds.size()) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                auto& frontend = debugger::backend().independentFrontend();
                std::uint32_t id = 0;
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    id = hardwareBreakpointIds[slot];
                    if (id == 0) { SetLastError(ERROR_NOT_FOUND); return false; }
                    hardwareBreakpointIds[slot] = 0; hardwareBreakpointAddresses[slot] = 0;
                }
                const DWORD error = frontend.removeBreakpoint(id);
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.RemoveAllBreakPoints = [](TitanBreakpointRemoveOption) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                std::vector<std::uint32_t> ids;
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    for (const auto& entry : softwareBreakpointIds) ids.push_back(entry.second);
                    for (auto id : hardwareBreakpointIds) if (id != 0) ids.push_back(id);
                    softwareBreakpointIds.clear();
                    hardwareBreakpointIds = {};
                    hardwareBreakpointAddresses = {};
                }
                DWORD firstError = ERROR_SUCCESS;
                for (auto id : ids)
                { const DWORD error = frontend.removeBreakpoint(id);
                  if (error != ERROR_SUCCESS && firstError == ERROR_SUCCESS) firstError = error; }
                SetLastError(firstError); return firstError == ERROR_SUCCESS;
            };
            table.DebugLoop = []() { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); };
            table.SetNextDbgContinueStatus = [](DWORD) {};
            table.AttachDebugger = [](DWORD pid, bool, LPVOID, TITANCALLBACK) -> bool
            {
                auto& backend = debugger::backend();
                if (!backend.independentFrontend().selected()) { SetLastError(ERROR_INVALID_STATE); return false; }
                return backend.attach(pid) != FALSE;
            };
            table.DetachDebuggerEx = [](DWORD) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected()) return true;
                KSWORD_DEBUGGER_FRONTEND_REQUEST request{};
                request.version = KSWORD_DEBUGGER_FRONTEND_VERSION;
                request.size = sizeof(request);
                request.operation = KSWORD_DEBUGGER_FRONTEND_CLOSE;
                KSWORD_DEBUGGER_FRONTEND_STATUS status{};
                const DWORD error = frontend.control(request, status);
                if (error == ERROR_SUCCESS) clearBreakpointBindings();
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.IsFileBeingDebugged = []() -> bool
            { return debugger::backend().independentFrontend().active(); };
            table.TitanOpenProcess = [](DWORD access, bool inherit, DWORD pid) -> HANDLE
            { return ::OpenProcess(access, inherit ? TRUE : FALSE, pid); };
            table.TitanOpenThread = [](DWORD access, bool inherit, DWORD tid) -> HANDLE
            { return ::OpenThread(access, inherit ? TRUE : FALSE, tid); };
            table.TitanGetProcessImagePathW = [](HANDLE process, LPWSTR path, SIZE_T chars) -> bool
            {
                if (chars == 0 || chars > (std::numeric_limits<DWORD>::max)()) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                DWORD size = static_cast<DWORD>(chars);
                return QueryFullProcessImageNameW(process, 0, path, &size) != FALSE;
            };
            table.TitanGetModulePathW = [](HANDLE, ULONG_PTR, LPWSTR, SIZE_T) -> bool { return rejectBool(); };
            table.TitanCloseHandle = [](HANDLE handle) -> bool { return ::CloseHandle(handle) != FALSE; };
            table.ProcessIsWow64 = [](HANDLE process, PBOOL isWow64) -> bool
            { return IsWow64Process(process, isWow64) != FALSE; };
            table.TitanTerminateProcess = [](HANDLE, DWORD) -> bool { return rejectBool(); };
            table.RequestPause = [](TitanPausePolicy, TITANCBPAUSE) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected()) { SetLastError(ERROR_INVALID_STATE); return false; }
                KSWORD_DEBUGGER_FRONTEND_REQUEST request{};
                request.version = KSWORD_DEBUGGER_FRONTEND_VERSION;
                request.size = sizeof(request);
                request.operation = KSWORD_DEBUGGER_FRONTEND_PAUSE;
                KSWORD_DEBUGGER_FRONTEND_STATUS status{};
                const DWORD error = frontend.control(request, status);
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.TitanCreateRemoteThread = [](HANDLE, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) -> HANDLE
            { return rejectValue<HANDLE>(nullptr); };
            table.TitanSuspendThread = [](HANDLE thread) -> DWORD { return ::SuspendThread(thread); };
            table.TitanResumeThread = [](HANDLE thread) -> DWORD { return ::ResumeThread(thread); };
            table.TitanTerminateThread = [](HANDLE, DWORD) -> bool { return rejectBool(); };
            table.TitanGetThreadId = [](HANDLE thread) -> DWORD { return ::GetThreadId(thread); };
            table.TitanGetThreadPriority = [](HANDLE thread) -> int { return ::GetThreadPriority(thread); };
            table.TitanSetThreadPriority = [](HANDLE thread, int priority) -> bool
            { return ::SetThreadPriority(thread, priority) != FALSE; };
            table.TitanGetThreadTimes = [](HANDLE thread, LPFILETIME creation, LPFILETIME exited, LPFILETIME kernel, LPFILETIME user) -> bool
            { return ::GetThreadTimes(thread, creation, exited, kernel, user) != FALSE; };
            table.TitanQueryThreadCycleTime = [](HANDLE thread, PULONG64 cycleTime) -> bool
            { return ::QueryThreadCycleTime(thread, cycleTime) != FALSE; };
            table.SetEngineVariable = [](TitanEngineVariable, bool) {};
            table.EngineCheckStructAlignment = [](TitanStructureType, ULONG_PTR) -> bool { return rejectBool(); };
            return table;
        }();
        return api;
    }
}
