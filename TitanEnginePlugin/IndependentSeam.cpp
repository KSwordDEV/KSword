#include "Proxy.h"
#include "NativeApi.h"
#include "../DebuggerBackend/KswordDebuggerBackend.h"
#pragma warning(push)
#pragma warning(disable: 4324)
#include "../third_party/x64dbg_abi/TitanEngine.h"
#pragma warning(pop)

#include <Windows.h>
#include <TlHelp32.h>
#include <limits>
#include <array>
#include <cstring>
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
        struct SoftwareBreakpointRecord { TITANCBSOFTBP callback = nullptr; bool oneshot = false; };
        std::map<ULONG_PTR, SoftwareBreakpointRecord> softwareBreakpointCallbacks;
        std::array<std::uint32_t, 4> hardwareBreakpointIds{};
        std::array<ULONG_PTR, 4> hardwareBreakpointAddresses{};
        std::array<TITANCBHWBP, 4> hardwareBreakpointCallbacks{};
        // Step and pause callbacks are consumed on the next matching stop; a
        // second StepInto before the first fires overwrites the pending one
        // because x64dbg waits on the inner callback before issuing another.
        std::atomic<TITANCBSTEP> pendingStepCallback{nullptr};
        std::atomic<TITANCBPAUSE> pendingPauseCallback{nullptr};
        void clearBreakpointBindings()
        {
            std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
            softwareBreakpointIds.clear();
            softwareBreakpointCallbacks.clear();
            hardwareBreakpointIds = {};
            hardwareBreakpointAddresses = {};
            hardwareBreakpointCallbacks = {};
            pendingStepCallback.store(nullptr);
            pendingPauseCallback.store(nullptr);
        }

        // Project a Windows CONTEXT snapshot into the Titan tuple. YMM high
        // halves are reported as zero because IndependentFrontend does not
        // read the XSTATE buffer yet; CE/x64dbg show them as zeroed.
        void projectToTitan(const CONTEXT& source, TITAN_ENGINE_CONTEXT_t& destination) noexcept
        {
            destination = {};
            destination.cax = source.Rax; destination.ccx = source.Rcx;
            destination.cdx = source.Rdx; destination.cbx = source.Rbx;
            destination.csp = source.Rsp; destination.cbp = source.Rbp;
            destination.csi = source.Rsi; destination.cdi = source.Rdi;
            destination.r8 = source.R8; destination.r9 = source.R9;
            destination.r10 = source.R10; destination.r11 = source.R11;
            destination.r12 = source.R12; destination.r13 = source.R13;
            destination.r14 = source.R14; destination.r15 = source.R15;
            destination.cip = source.Rip; destination.eflags = source.EFlags;
            destination.gs = source.SegGs; destination.fs = source.SegFs;
            destination.es = source.SegEs; destination.ds = source.SegDs;
            destination.cs = source.SegCs; destination.ss = source.SegSs;
            destination.dr0 = static_cast<ULONG_PTR>(source.Dr0);
            destination.dr1 = static_cast<ULONG_PTR>(source.Dr1);
            destination.dr2 = static_cast<ULONG_PTR>(source.Dr2);
            destination.dr3 = static_cast<ULONG_PTR>(source.Dr3);
            destination.dr6 = static_cast<ULONG_PTR>(source.Dr6);
            destination.dr7 = static_cast<ULONG_PTR>(source.Dr7);
            destination.x87fpu.ControlWord = source.FltSave.ControlWord;
            destination.x87fpu.StatusWord = source.FltSave.StatusWord;
            destination.x87fpu.TagWord = source.FltSave.TagWord;
            destination.x87fpu.ErrorOffset = source.FltSave.ErrorOffset;
            destination.x87fpu.ErrorSelector = source.FltSave.ErrorSelector;
            destination.x87fpu.DataOffset = source.FltSave.DataOffset;
            destination.x87fpu.DataSelector = source.FltSave.DataSelector;
            destination.MxCsr = source.FltSave.MxCsr;
            for (int i = 0; i < 8; ++i)
                std::memcpy(&destination.RegisterArea[i * 10], &source.FltSave.FloatRegisters[i], 10);
            for (int i = 0; i < 16; ++i)
            {
                destination.XmmRegisters[i].Low = source.FltSave.XmmRegisters[i].Low;
                destination.XmmRegisters[i].High = static_cast<LONGLONG>(source.FltSave.XmmRegisters[i].High);
            }
        }

        // Apply Titan's GPR/DR/segment/EFlags/FP/XMM edits onto a captured
        // CONTEXT. IndependentFrontend::writeContext now accepts FP/MxCsr/
        // XMM changes (via SuspendThread + SetThreadContext on the target),
        // so Titan-driven CPU-panel edits propagate to the real thread.
        void applyFromTitan(const TITAN_ENGINE_CONTEXT_t& source, CONTEXT& destination) noexcept
        {
            destination.FltSave.ControlWord = static_cast<WORD>(source.x87fpu.ControlWord);
            destination.FltSave.StatusWord = static_cast<WORD>(source.x87fpu.StatusWord);
            destination.FltSave.TagWord = static_cast<BYTE>(source.x87fpu.TagWord);
            destination.FltSave.ErrorOffset = source.x87fpu.ErrorOffset;
            destination.FltSave.ErrorSelector = static_cast<WORD>(source.x87fpu.ErrorSelector);
            destination.FltSave.DataOffset = source.x87fpu.DataOffset;
            destination.FltSave.DataSelector = static_cast<WORD>(source.x87fpu.DataSelector);
            destination.FltSave.MxCsr = source.MxCsr;
            destination.MxCsr = source.MxCsr;
            for (int i = 0; i < 8; ++i)
                std::memcpy(&destination.FltSave.FloatRegisters[i], &source.RegisterArea[i * 10], 10);
            for (int i = 0; i < 16; ++i)
            {
                destination.FltSave.XmmRegisters[i].Low = source.XmmRegisters[i].Low;
                destination.FltSave.XmmRegisters[i].High = static_cast<ULONGLONG>(source.XmmRegisters[i].High);
            }
            destination.Rax = source.cax; destination.Rcx = source.ccx;
            destination.Rdx = source.cdx; destination.Rbx = source.cbx;
            destination.Rsp = source.csp; destination.Rbp = source.cbp;
            destination.Rsi = source.csi; destination.Rdi = source.cdi;
            destination.R8 = source.r8; destination.R9 = source.r9;
            destination.R10 = source.r10; destination.R11 = source.r11;
            destination.R12 = source.r12; destination.R13 = source.r13;
            destination.R14 = source.r14; destination.R15 = source.r15;
            destination.Rip = source.cip; destination.EFlags = static_cast<DWORD>(source.eflags);
            destination.SegGs = source.gs; destination.SegFs = source.fs;
            destination.SegEs = source.es; destination.SegDs = source.ds;
            destination.SegCs = source.cs; destination.SegSs = source.ss;
            destination.Dr0 = source.dr0; destination.Dr1 = source.dr1;
            destination.Dr2 = source.dr2; destination.Dr3 = source.dr3;
            destination.Dr6 = source.dr6; destination.Dr7 = source.dr7;
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

        // PEB / TEB queries only read live kernel bookkeeping and never
        // establish a Windows debugger relationship. Resolve ntdll entry
        // points once so repeated calls stay cheap.
        ULONG_PTR pebFromProcess(HANDLE process)
        {
            using NtQIP = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            static const auto query = reinterpret_cast<NtQIP>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
            if (!query) return 0;
            struct { LONG ExitStatus; ULONG_PTR PebBaseAddress; ULONG_PTR AffinityMask;
                LONG BasePriority; ULONG_PTR UniqueProcessId;
                ULONG_PTR InheritedFromUniqueProcessId; } information{};
            ULONG returned = 0;
            return query(process, 0, &information, sizeof(information), &returned) >= 0
                ? information.PebBaseAddress : 0;
        }

        ULONG_PTR tebFromThread(HANDLE thread)
        {
            using NtQIT = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            static const auto query = reinterpret_cast<NtQIT>(
                GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
            if (!query) return 0;
            struct { LONG ExitStatus; ULONG_PTR TebBaseAddress;
                struct { HANDLE UniqueProcess; HANDLE UniqueThread; } Cid;
                ULONG_PTR AffinityMask; LONG Priority; LONG BasePriority; } information{};
            ULONG returned = 0;
            return query(thread, 0, &information, sizeof(information), &returned) >= 0
                ? information.TebBaseAddress : 0;
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
            // Pure Windows bookkeeping queries, no debugger relationship.
            // Callers (x64dbg CPU panel, Titan info widgets) open their own
            // PROCESS_QUERY_INFORMATION / THREAD_QUERY_LIMITED_INFORMATION
            // handle, so these shims do not consult the Independent frontend.
            table.GetPEBLocation = [](HANDLE process) -> ULONG_PTR
            {
                if (process == nullptr) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
                const auto peb = pebFromProcess(process);
                SetLastError(peb != 0 ? ERROR_SUCCESS : ERROR_INVALID_HANDLE);
                return peb;
            };
            table.GetTEBLocation = [](HANDLE thread) -> ULONG_PTR
            {
                if (thread == nullptr) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
                const auto teb = tebFromThread(thread);
                SetLastError(teb != 0 ? ERROR_SUCCESS : ERROR_INVALID_HANDLE);
                return teb;
            };
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
            table.SetBPX = [](ULONG_PTR address, DWORD bpxType, TITANCBSOFTBP callback) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.active()) { SetLastError(ERROR_INVALID_STATE); return false; }
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    if (softwareBreakpointIds.find(address) != softwareBreakpointIds.end())
                    { SetLastError(ERROR_ALREADY_EXISTS); return false; }
                }
                // UE_SINGLESHOOT is the low bit on the TitanBreakpointType mix;
                // x64dbg's Run to Cursor and Step Out take this path, so the
                // driver must retire the binding after the first hit.
                const bool oneshot = (bpxType & UE_SINGLESHOOT) != 0;
                std::uint32_t id = 0;
                const DWORD error = frontend.addBreakpoint(address, oneshot, id);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                {
                    std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                    softwareBreakpointIds[address] = id;
                    softwareBreakpointCallbacks[address] = {callback, oneshot};
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
                    softwareBreakpointCallbacks.erase(address);
                }
                const DWORD error = frontend.removeBreakpoint(id);
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.SetMemoryBPXEx = [](ULONG_PTR, SIZE_T, TitanMemoryBreakpointType, bool, TITANCBMEMBP) -> bool { return rejectBool(); };
            table.RemoveMemoryBPX = [](ULONG_PTR, SIZE_T) -> bool { return rejectBool(); };
            table.GetFullContextDataEx = [](HANDLE thread, TITAN_ENGINE_CONTEXT_t* ctx) -> bool
            {
                if (ctx == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                CONTEXT snapshot{};
                snapshot.ContextFlags = CONTEXT_ALL;
                auto& frontend = debugger::backend().independentFrontend();
                const DWORD error = frontend.readContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                projectToTitan(snapshot, *ctx);
                return true;
            };
            table.SetFullContextDataEx = [](HANDLE thread, TITAN_ENGINE_CONTEXT_t* ctx) -> bool
            {
                if (ctx == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                CONTEXT snapshot{};
                snapshot.ContextFlags = CONTEXT_ALL;
                auto& frontend = debugger::backend().independentFrontend();
                DWORD error = frontend.readContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                applyFromTitan(*ctx, snapshot);
                snapshot.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                    CONTEXT_DEBUG_REGISTERS | CONTEXT_FLOATING_POINT;
                error = frontend.writeContext(thread, snapshot);
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.GetContextDataEx = [](HANDLE thread, TitanRegister index) -> ULONG_PTR
            {
                TITAN_ENGINE_CONTEXT_t snapshot{};
                CONTEXT raw{};
                raw.ContextFlags = CONTEXT_ALL;
                auto& frontend = debugger::backend().independentFrontend();
                const DWORD error = frontend.readContext(thread, raw);
                if (error != ERROR_SUCCESS) { SetLastError(error); return 0; }
                projectToTitan(raw, snapshot);
                switch (index)
                {
                    case UE_RAX: return snapshot.cax; case UE_RCX: return snapshot.ccx;
                    case UE_RDX: return snapshot.cdx; case UE_RBX: return snapshot.cbx;
                    case UE_RSP: return snapshot.csp; case UE_RBP: return snapshot.cbp;
                    case UE_RSI: return snapshot.csi; case UE_RDI: return snapshot.cdi;
                    case UE_R8: return snapshot.r8; case UE_R9: return snapshot.r9;
                    case UE_R10: return snapshot.r10; case UE_R11: return snapshot.r11;
                    case UE_R12: return snapshot.r12; case UE_R13: return snapshot.r13;
                    case UE_R14: return snapshot.r14; case UE_R15: return snapshot.r15;
                    case UE_RIP: case UE_CIP: return snapshot.cip;
                    case UE_EFLAGS: case UE_RFLAGS: return snapshot.eflags;
                    case UE_CSP: return snapshot.csp;
                    case UE_DR0: return snapshot.dr0; case UE_DR1: return snapshot.dr1;
                    case UE_DR2: return snapshot.dr2; case UE_DR3: return snapshot.dr3;
                    case UE_DR6: return snapshot.dr6; case UE_DR7: return snapshot.dr7;
                    case UE_SEG_CS: return snapshot.cs; case UE_SEG_DS: return snapshot.ds;
                    case UE_SEG_ES: return snapshot.es; case UE_SEG_FS: return snapshot.fs;
                    case UE_SEG_GS: return snapshot.gs; case UE_SEG_SS: return snapshot.ss;
                    default: SetLastError(ERROR_NOT_SUPPORTED); return 0;
                }
            };
            table.SetContextDataEx = [](HANDLE thread, TitanRegister index, ULONG_PTR value) -> bool
            {
                CONTEXT snapshot{};
                snapshot.ContextFlags = CONTEXT_ALL;
                auto& frontend = debugger::backend().independentFrontend();
                DWORD error = frontend.readContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                switch (index)
                {
                    case UE_RAX: snapshot.Rax = value; break; case UE_RCX: snapshot.Rcx = value; break;
                    case UE_RDX: snapshot.Rdx = value; break; case UE_RBX: snapshot.Rbx = value; break;
                    case UE_RSP: snapshot.Rsp = value; break; case UE_RBP: snapshot.Rbp = value; break;
                    case UE_RSI: snapshot.Rsi = value; break; case UE_RDI: snapshot.Rdi = value; break;
                    case UE_R8: snapshot.R8 = value; break; case UE_R9: snapshot.R9 = value; break;
                    case UE_R10: snapshot.R10 = value; break; case UE_R11: snapshot.R11 = value; break;
                    case UE_R12: snapshot.R12 = value; break; case UE_R13: snapshot.R13 = value; break;
                    case UE_R14: snapshot.R14 = value; break; case UE_R15: snapshot.R15 = value; break;
                    case UE_RIP: case UE_CIP: snapshot.Rip = value; break;
                    case UE_CSP: snapshot.Rsp = value; break;
                    case UE_EFLAGS: case UE_RFLAGS:
                        snapshot.EFlags = static_cast<DWORD>(value); break;
                    default: SetLastError(ERROR_NOT_SUPPORTED); return false;
                }
                snapshot.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                error = frontend.writeContext(thread, snapshot);
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            // XMM low 128 travels in FltSave while YMM high 128 and ZMM
            // extensions live in the XSAVE area. Fetch the extension via the
            // frontend's XSTATE primitive and compose the full view; if the
            // CPU/OS does not expose XSTATE the XMM-only result is still a
            // correct AVX snapshot (YMM high reads as zero on such parts).
            table.GetAVXContext = [](HANDLE thread, TITAN_ENGINE_CONTEXT_t* ctx) -> bool
            {
                if (ctx == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                CONTEXT snapshot{};
                snapshot.ContextFlags = CONTEXT_ALL;
                auto& frontend = debugger::backend().independentFrontend();
                const DWORD error = frontend.readContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                projectToTitan(snapshot, *ctx);
                const DWORD64 enabled = GetEnabledXStateFeatures();
                const DWORD64 avxMask = XSTATE_MASK_AVX & enabled;
                if (avxMask == 0) { SetLastError(ERROR_SUCCESS); return true; }
                const DWORD flags = CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;
                DWORD required = 0;
                InitializeContext(nullptr, flags, nullptr, &required);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                { SetLastError(ERROR_SUCCESS); return true; }
                std::vector<BYTE> buffer(required);
                PCONTEXT xctx = nullptr;
                if (!InitializeContext(buffer.data(), flags, &xctx, &required) ||
                    !SetXStateFeaturesMask(xctx, avxMask))
                { SetLastError(ERROR_SUCCESS); return true; }
                if (frontend.readXStateContext(thread, xctx) != ERROR_SUCCESS)
                { SetLastError(ERROR_SUCCESS); return true; }
                DWORD length = 0;
                const auto* avx = static_cast<const M128A*>(LocateXStateFeature(xctx, XSTATE_AVX, &length));
                if (avx != nullptr && length >= 16 * sizeof(M128A))
                {
                    for (int i = 0; i < 16; ++i)
                    {
                        ctx->YmmRegisters[i].Low = ctx->XmmRegisters[i];
                        ctx->YmmRegisters[i].High.Low = avx[i].Low;
                        ctx->YmmRegisters[i].High.High = avx[i].High;
                    }
                }
                SetLastError(ERROR_SUCCESS); return true;
            };
            table.SetAVXContext = [](HANDLE thread, TITAN_ENGINE_CONTEXT_t* ctx) -> bool
            {
                if (ctx == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                CONTEXT snapshot{};
                snapshot.ContextFlags = CONTEXT_ALL;
                auto& frontend = debugger::backend().independentFrontend();
                DWORD error = frontend.readContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                applyFromTitan(*ctx, snapshot);
                snapshot.ContextFlags = CONTEXT_FLOATING_POINT;
                error = frontend.writeContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                const DWORD64 enabled = GetEnabledXStateFeatures();
                const DWORD64 avxMask = XSTATE_MASK_AVX & enabled;
                if (avxMask == 0) { SetLastError(ERROR_SUCCESS); return true; }
                const DWORD flags = CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;
                DWORD required = 0;
                InitializeContext(nullptr, flags, nullptr, &required);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                { SetLastError(ERROR_SUCCESS); return true; }
                std::vector<BYTE> buffer(required);
                PCONTEXT xctx = nullptr;
                if (!InitializeContext(buffer.data(), flags, &xctx, &required) ||
                    !SetXStateFeaturesMask(xctx, avxMask))
                { SetLastError(ERROR_SUCCESS); return true; }
                // Round-trip to preserve features we do not touch (MXCSR, etc).
                if (frontend.readXStateContext(thread, xctx) != ERROR_SUCCESS)
                { SetLastError(ERROR_SUCCESS); return true; }
                DWORD length = 0;
                auto* avx = static_cast<M128A*>(LocateXStateFeature(xctx, XSTATE_AVX, &length));
                if (avx != nullptr && length >= 16 * sizeof(M128A))
                {
                    for (int i = 0; i < 16; ++i)
                    {
                        avx[i].Low = ctx->YmmRegisters[i].High.Low;
                        avx[i].High = ctx->YmmRegisters[i].High.High;
                    }
                    error = frontend.writeXStateContext(thread, xctx);
                    if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                }
                SetLastError(ERROR_SUCCESS); return true;
            };
            // AVX-512 widens ZMM0-15 into XSAVE's high-256 region, exposes
            // ZMM16-31 as a full 512-bit extension, and surfaces the eight
            // opmask (k0-k7) registers. When the CPU or OS does not advertise
            // AVX-512 the shim still returns whatever XMM/AVX state the host
            // thread has, with the AVX-512 half zeroed.
            table.GetAVX512Context = [](HANDLE thread, TITAN_ENGINE_CONTEXT_AVX512_t* titcontext) -> bool
            {
                if (titcontext == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                std::memset(titcontext, 0, sizeof(*titcontext));
                auto& frontend = debugger::backend().independentFrontend();
                CONTEXT snapshot{};
                snapshot.ContextFlags = CONTEXT_ALL;
                const DWORD fpError = frontend.readContext(thread, snapshot);
                if (fpError != ERROR_SUCCESS) { SetLastError(fpError); return false; }
                for (int i = 0; i < 16; ++i)
                {
                    titcontext->ZmmRegisters[i].Low.Low.Low = snapshot.FltSave.XmmRegisters[i].Low;
                    titcontext->ZmmRegisters[i].Low.Low.High =
                        static_cast<LONGLONG>(snapshot.FltSave.XmmRegisters[i].High);
                }
                const DWORD64 enabled = GetEnabledXStateFeatures();
                const DWORD64 desired = (XSTATE_MASK_AVX | XSTATE_MASK_AVX512) & enabled;
                if (desired == 0) { SetLastError(ERROR_SUCCESS); return true; }
                const DWORD flags = CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;
                DWORD required = 0;
                InitializeContext(nullptr, flags, nullptr, &required);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                { SetLastError(ERROR_SUCCESS); return true; }
                std::vector<BYTE> buffer(required);
                PCONTEXT xctx = nullptr;
                if (!InitializeContext(buffer.data(), flags, &xctx, &required) ||
                    !SetXStateFeaturesMask(xctx, desired))
                { SetLastError(ERROR_SUCCESS); return true; }
                if (frontend.readXStateContext(thread, xctx) != ERROR_SUCCESS)
                { SetLastError(ERROR_SUCCESS); return true; }
                DWORD length = 0;
                const auto* avx = static_cast<const M128A*>(LocateXStateFeature(xctx, XSTATE_AVX, &length));
                if (avx != nullptr && length >= 16 * sizeof(M128A))
                    for (int i = 0; i < 16; ++i)
                    {
                        titcontext->ZmmRegisters[i].Low.High.Low = avx[i].Low;
                        titcontext->ZmmRegisters[i].Low.High.High = avx[i].High;
                    }
                length = 0;
                const auto* zmmHi = static_cast<const BYTE*>(LocateXStateFeature(xctx, XSTATE_AVX512_ZMM_H, &length));
                if (zmmHi != nullptr && length >= 16U * 32U)
                    for (int i = 0; i < 16; ++i)
                        std::memcpy(&titcontext->ZmmRegisters[i].High, zmmHi + i * 32, 32);
                length = 0;
                const auto* zmm16 = static_cast<const BYTE*>(LocateXStateFeature(xctx, XSTATE_AVX512_ZMM, &length));
                if (zmm16 != nullptr && length >= 16U * 64U)
                    for (int i = 0; i < 16; ++i)
                        std::memcpy(&titcontext->ZmmRegisters[16 + i], zmm16 + i * 64, 64);
                length = 0;
                const auto* kmask = static_cast<const DWORD64*>(LocateXStateFeature(xctx, XSTATE_AVX512_KMASK, &length));
                if (kmask != nullptr && length >= 8 * sizeof(DWORD64))
                    for (int i = 0; i < 8; ++i)
                        titcontext->Opmask[i] = kmask[i];
                SetLastError(ERROR_SUCCESS); return true;
            };
            table.SetAVX512Context = [](HANDLE thread, TITAN_ENGINE_CONTEXT_AVX512_t* titcontext) -> bool
            {
                if (titcontext == nullptr) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                auto& frontend = debugger::backend().independentFrontend();
                CONTEXT snapshot{};
                snapshot.ContextFlags = CONTEXT_ALL;
                DWORD error = frontend.readContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                for (int i = 0; i < 16; ++i)
                {
                    snapshot.FltSave.XmmRegisters[i].Low = titcontext->ZmmRegisters[i].Low.Low.Low;
                    snapshot.FltSave.XmmRegisters[i].High =
                        static_cast<ULONGLONG>(titcontext->ZmmRegisters[i].Low.Low.High);
                }
                snapshot.ContextFlags = CONTEXT_FLOATING_POINT;
                error = frontend.writeContext(thread, snapshot);
                if (error != ERROR_SUCCESS) { SetLastError(error); return false; }
                const DWORD64 enabled = GetEnabledXStateFeatures();
                const DWORD64 desired = (XSTATE_MASK_AVX | XSTATE_MASK_AVX512) & enabled;
                if (desired == 0) { SetLastError(ERROR_SUCCESS); return true; }
                const DWORD flags = CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;
                DWORD required = 0;
                InitializeContext(nullptr, flags, nullptr, &required);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                { SetLastError(ERROR_SUCCESS); return true; }
                std::vector<BYTE> buffer(required);
                PCONTEXT xctx = nullptr;
                if (!InitializeContext(buffer.data(), flags, &xctx, &required) ||
                    !SetXStateFeaturesMask(xctx, desired))
                { SetLastError(ERROR_SUCCESS); return true; }
                if (frontend.readXStateContext(thread, xctx) != ERROR_SUCCESS)
                { SetLastError(ERROR_SUCCESS); return true; }
                DWORD length = 0;
                auto* avx = static_cast<M128A*>(LocateXStateFeature(xctx, XSTATE_AVX, &length));
                if (avx != nullptr && length >= 16 * sizeof(M128A))
                    for (int i = 0; i < 16; ++i)
                    {
                        avx[i].Low = titcontext->ZmmRegisters[i].Low.High.Low;
                        avx[i].High = titcontext->ZmmRegisters[i].Low.High.High;
                    }
                length = 0;
                auto* zmmHi = static_cast<BYTE*>(LocateXStateFeature(xctx, XSTATE_AVX512_ZMM_H, &length));
                if (zmmHi != nullptr && length >= 16U * 32U)
                    for (int i = 0; i < 16; ++i)
                        std::memcpy(zmmHi + i * 32, &titcontext->ZmmRegisters[i].High, 32);
                length = 0;
                auto* zmm16 = static_cast<BYTE*>(LocateXStateFeature(xctx, XSTATE_AVX512_ZMM, &length));
                if (zmm16 != nullptr && length >= 16U * 64U)
                    for (int i = 0; i < 16; ++i)
                        std::memcpy(zmm16 + i * 64, &titcontext->ZmmRegisters[16 + i], 64);
                length = 0;
                auto* kmask = static_cast<DWORD64*>(LocateXStateFeature(xctx, XSTATE_AVX512_KMASK, &length));
                if (kmask != nullptr && length >= 8 * sizeof(DWORD64))
                    for (int i = 0; i < 8; ++i)
                        kmask[i] = titcontext->Opmask[i];
                error = frontend.writeXStateContext(thread, xctx);
                SetLastError(error); return error == ERROR_SUCCESS;
            };
            table.GetDebugData = []() -> const DEBUG_EVENT* { return nullptr; };
            table.SetCustomHandler = [](TitanCustomHandler, TITANCALLBACKARG) {};
            // Step shims resume once and record the callback for DebugLoop
            // to fire when the step-boundary stop arrives from the driver.
            table.StepInto = [](TITANCBSTEP callback) {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected()) { SetLastError(ERROR_INVALID_STATE); return; }
                pendingStepCallback.store(callback);
                const DWORD error = frontend.resume(true);
                if (error != ERROR_SUCCESS) pendingStepCallback.store(nullptr);
                SetLastError(error);
            };
            table.StepOver = [](TITANCBSTEP callback) {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected()) { SetLastError(ERROR_INVALID_STATE); return; }
                pendingStepCallback.store(callback);
                const DWORD error = frontend.resume(true);
                if (error != ERROR_SUCCESS) pendingStepCallback.store(nullptr);
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
            table.SetHardwareBreakPoint = [](ULONG_PTR address, DWORD slot, TitanHardwareBreakpointType, TitanHardwareBreakpointSize, TITANCBHWBP callback) -> bool
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
                    hardwareBreakpointCallbacks[slot] = callback;
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
                    hardwareBreakpointCallbacks[slot] = nullptr;
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
            table.DebugLoop = []() {
                auto& frontend = debugger::backend().independentFrontend();
                std::uint64_t lastStopId = 0;
                {
                    KSWORD_ARK_HVM_NOATTACH_RESPONSE current{};
                    if (frontend.snapshot(current) == ERROR_SUCCESS) lastStopId = current.stopId;
                }
                while (frontend.active())
                {
                    KSWORD_ARK_HVM_NOATTACH_RESPONSE snap{};
                    const DWORD error = frontend.waitForStop(100, lastStopId, snap);
                    if (error == ERROR_SEM_TIMEOUT) continue;
                    if (error == ERROR_OPERATION_ABORTED || error == ERROR_PROCESS_ABORTED ||
                        error == ERROR_INVALID_STATE) break;
                    if (error != ERROR_SUCCESS) { SetLastError(error); break; }
                    lastStopId = snap.stopId;
                    if (auto pauseCb = pendingPauseCallback.exchange(nullptr); pauseCb != nullptr)
                        pauseCb();
                    if (snap.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_STEP)
                    { if (auto cb = pendingStepCallback.exchange(nullptr); cb != nullptr) cb(); }
                    else if (snap.stopReason == KSWORD_ARK_HVM_NOATTACH_STOP_BREAKPOINT)
                    {
                        TITANCBSOFTBP softwareCb = nullptr;
                        TITANCBHWBP hardwareCb = nullptr;
                        ULONG_PTR consumedOneshot = 0;
                        {
                            std::lock_guard<std::mutex> lock(softwareBreakpointMutex);
                            for (const auto& entry : softwareBreakpointIds)
                                if (entry.second == snap.breakpointId)
                                {
                                    auto it = softwareBreakpointCallbacks.find(entry.first);
                                    if (it != softwareBreakpointCallbacks.end())
                                    {
                                        softwareCb = it->second.callback;
                                        if (it->second.oneshot) consumedOneshot = entry.first;
                                    }
                                    break;
                                }
                            if (softwareCb == nullptr)
                                for (SIZE_T i = 0; i < hardwareBreakpointIds.size(); ++i)
                                    if (hardwareBreakpointIds[i] == snap.breakpointId)
                                    { hardwareCb = hardwareBreakpointCallbacks[i]; break; }
                            if (consumedOneshot != 0)
                            {
                                softwareBreakpointIds.erase(consumedOneshot);
                                softwareBreakpointCallbacks.erase(consumedOneshot);
                            }
                        }
                        if (softwareCb != nullptr) softwareCb();
                        else if (hardwareCb != nullptr) hardwareCb(nullptr);
                    }
                }
            };
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
            // Module enumeration uses the live loader snapshot; it is not
            // tied to a stop and therefore not routed through the frontend.
            table.TitanGetModulePathW = [](HANDLE process, ULONG_PTR base, LPWSTR path, SIZE_T chars) -> bool
            {
                if (process == nullptr || path == nullptr || chars == 0 ||
                    chars > (std::numeric_limits<DWORD>::max)())
                { SetLastError(ERROR_INVALID_PARAMETER); return false; }
                const DWORD pid = GetProcessId(process);
                if (pid == 0) { SetLastError(ERROR_INVALID_HANDLE); return false; }
                HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                if (snapshot == INVALID_HANDLE_VALUE) return false;
                MODULEENTRY32W entry{};
                entry.dwSize = sizeof(entry);
                DWORD completion = ERROR_MOD_NOT_FOUND;
                bool copied = false;
                if (Module32FirstW(snapshot, &entry))
                {
                    do
                    {
                        if (reinterpret_cast<ULONG_PTR>(entry.modBaseAddr) != base) continue;
                        const SIZE_T length = std::wcslen(entry.szExePath);
                        if (length >= chars) { completion = ERROR_INSUFFICIENT_BUFFER; break; }
                        std::memcpy(path, entry.szExePath, (length + 1) * sizeof(wchar_t));
                        completion = ERROR_SUCCESS; copied = true; break;
                    } while (Module32NextW(snapshot, &entry));
                }
                CloseHandle(snapshot);
                SetLastError(completion);
                return copied;
            };
            table.TitanCloseHandle = [](HANDLE handle) -> bool { return ::CloseHandle(handle) != FALSE; };
            table.ProcessIsWow64 = [](HANDLE process, PBOOL isWow64) -> bool
            { return IsWow64Process(process, isWow64) != FALSE; };
            table.TitanTerminateProcess = [](HANDLE, DWORD) -> bool { return rejectBool(); };
            table.RequestPause = [](TitanPausePolicy, TITANCBPAUSE callback) -> bool
            {
                auto& frontend = debugger::backend().independentFrontend();
                if (!frontend.selected()) { SetLastError(ERROR_INVALID_STATE); return false; }
                pendingPauseCallback.store(callback);
                KSWORD_DEBUGGER_FRONTEND_REQUEST request{};
                request.version = KSWORD_DEBUGGER_FRONTEND_VERSION;
                request.size = sizeof(request);
                request.operation = KSWORD_DEBUGGER_FRONTEND_PAUSE;
                KSWORD_DEBUGGER_FRONTEND_STATUS status{};
                const DWORD error = frontend.control(request, status);
                if (error != ERROR_SUCCESS) pendingPauseCallback.store(nullptr);
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
