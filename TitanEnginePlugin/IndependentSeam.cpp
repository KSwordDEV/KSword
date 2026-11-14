#include "Proxy.h"
#include "NativeApi.h"
#include "../DebuggerBackend/KswordDebuggerBackend.h"
#pragma warning(push)
#pragma warning(disable: 4324)
#include "../third_party/x64dbg_abi/TitanEngine.h"
#pragma warning(pop)

#include <Windows.h>
#include <limits>

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
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.SetBPXOptions = [](TitanBreakpointType) {};
            table.IsBPXEnabled = [](ULONG_PTR) -> bool { return rejectBool(); };
            table.SetBPX = [](ULONG_PTR, DWORD, TITANCBSOFTBP) -> bool { return rejectBool(); };
            table.DeleteBPX = [](ULONG_PTR) -> bool { return rejectBool(); };
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
            table.StepInto = [](TITANCBSTEP) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); };
            table.StepOver = [](TITANCBSTEP) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); };
            table.GetUnusedHardwareBreakPointRegister = [](LPDWORD) -> bool { return rejectBool(); };
            table.SetHardwareBreakPoint = [](ULONG_PTR, DWORD, TitanHardwareBreakpointType, TitanHardwareBreakpointSize, TITANCBHWBP) -> bool { return rejectBool(); };
            table.DeleteHardwareBreakPoint = [](DWORD) -> bool { return rejectBool(); };
            table.RemoveAllBreakPoints = [](TitanBreakpointRemoveOption) -> bool { return rejectBool(); };
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
