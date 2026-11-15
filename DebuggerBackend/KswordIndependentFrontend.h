#pragma once

#include "KswordDebuggerApi.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/driver/KswordArkHvmNoAttachIoctl.h"

#include <Windows.h>
#include <array>
#include <cstdint>

namespace ksword::debugger
{
    class Backend;

    // This object belongs to a single frontend process. All driver requests
    // share the facade's exact control file and its recursive control lock.
    class IndependentFrontend
    {
    public:
        explicit IndependentFrontend(Backend& backend) noexcept : backend_(backend) {}
        DWORD control(const KSWORD_DEBUGGER_FRONTEND_REQUEST&, KSWORD_DEBUGGER_FRONTEND_STATUS&);
        bool selected() const;
        bool active() const;
        bool ownsProcess(DWORD pid) const;
        bool ownsThread(HANDLE thread) const;
        DWORD start(DWORD pid);
        DWORD close();
        DWORD pause();
        DWORD resume(bool step, std::uint64_t runTo = 0, std::uint64_t minimumRsp = 0);
        // Waits without holding the backend lock across the polling interval.
        DWORD waitForStop(DWORD milliseconds, std::uint64_t after, KSWORD_ARK_HVM_NOATTACH_RESPONSE&);
        DWORD snapshot(KSWORD_ARK_HVM_NOATTACH_RESPONSE&);
        // Execute-only wrapper over the protocol-flag overload; kept for the
        // CE bridge, Titan software BPX, and IndependentFrontend's own hw
        // regen path, which all install plain execute breakpoints.
        DWORD addBreakpoint(std::uint64_t address, bool once, std::uint32_t& id);
        // Protocol-flag overload accepts WATCH_WRITE/WATCH_READWRITE and
        // SIZE_* bits for DR-backed data watchpoints on the kernel backend;
        // HVM rejects them because EPT execution views cannot witness data
        // accesses. Callers OR the appropriate KSWORD_ARK_HVM_NOATTACH_BP_*
        // flags together.
        DWORD addBreakpoint(std::uint64_t address, DWORD protocolFlags, std::uint32_t& id);
        DWORD removeBreakpoint(std::uint32_t id);
        // Page-level memory watchpoints: VirtualProtectEx tightens the
        // requested range, the kernel no-attach driver's exception
        // dispatcher consumes the resulting first-chance AV, and a stop
        // publishes with reason KSWORD_ARK_HVM_NOATTACH_STOP_MEMORY_WATCH.
        // On hit the frontend atomically removes the watch and restores
        // the original protection so the target retries its fault
        // instruction once the user resumes. HVM backend refuses.
        enum class MemoryWatchType : std::uint32_t { any = 0, read = 1, write = 2, execute = 4 };
        // Caller-side callback registries (Titan softwareBreakpointCallbacks
        // style) live in the shim; this layer tracks only the range and the
        // original protection so it can restore them on retire.
        DWORD addMemoryWatch(std::uint64_t address, SIZE_T length, MemoryWatchType type, std::uint32_t& id);
        DWORD removeMemoryWatch(std::uint32_t id);
        DWORD readContext(HANDLE thread, CONTEXT&);
        DWORD writeContext(HANDLE thread, const CONTEXT&);
        // XSTATE-aware variants accept a caller-allocated CONTEXT_EX (sized
        // via InitializeContext with CONTEXT_XSTATE). Required features must
        // already be set on the context with SetXStateFeaturesMask. The
        // driver still owns the stop point; these routines only drain live
        // AVX/AVX-512 register files via SuspendThread + Get/SetThreadContext.
        DWORD readXStateContext(HANDLE thread, PCONTEXT context);
        DWORD writeXStateContext(HANDLE thread, const CONTEXT* context);
        bool takeStepIntent();
        std::uint64_t takeStepOverTarget();
        DWORD processInfo(PROCESS_INFORMATION&);
        DWORD moduleInfo(std::uintptr_t& base, std::wstring& path);
        DWORD threadId() const;
        // CE's SDK expects native-shaped notifications. These are private
        // frontend projections of live stops, not Windows debug events.
        BOOL waitCeEvent(LPDEBUG_EVENT, DWORD milliseconds);
        BOOL continueCeEvent(DWORD pid, DWORD tid, DWORD continueStatus);
        DWORD logicalCodeWrite(HANDLE process, std::uint64_t address, const void* bytes, SIZE_T length);
        bool canWriteData(HANDLE process, std::uint64_t address, SIZE_T length);

    private:
        struct Binding { std::uint64_t address = 0; std::uint32_t id = 0; BYTE original = 0; };
        struct MemoryWatchBinding
        {
            std::uint32_t id = 0;
            std::uint64_t address = 0;
            SIZE_T length = 0;
            DWORD originalProtection = 0;
            MemoryWatchType type = MemoryWatchType::any;
        };
        // Return the slot index carrying `id` or memoryWatches_.size() when absent.
        std::size_t findMemoryWatch(std::uint32_t id) const;
        // Compute the tightened page protection for the requested watch type
        // starting from the caller's original protection flags.
        static DWORD tightenedProtection(DWORD original, MemoryWatchType type);
        // Restore the caller's original protection and clear the slot.
        // Caller holds backend_.mutex_ and `index` is the slot to reset.
        void retireMemoryWatchLocked(std::size_t index);
        DWORD request(ULONG operation, const KSWORD_ARK_HVM_NOATTACH_REQUEST* edits = nullptr);
        DWORD finishContextRequest();
        DWORD captureContext(CONTEXT&);
        bool targetThread(HANDLE) const;
        void resetSession();
        void fillStatus(KSWORD_DEBUGGER_FRONTEND_STATUS&) const;
        Backend& backend_;
        ark::DriverHandle process_, thread_;
        DWORD command_ = 0, flags_ = 0, pid_ = 0, tid_ = 0, configuredPid_ = 0, configuredTid_ = 0;
        DWORD lastError_ = ERROR_SUCCESS;
        bool reserved_ = false, recovery_ = false, stepIntent_ = false;
        KSWORD_ARK_HVM_NOATTACH_RESPONSE stop_{};
        CONTEXT captured_{};
        std::uint64_t capturedStop_ = 0;
        std::array<Binding, 4> hardware_{};
        std::array<Binding, 8> software_{};
        std::array<MemoryWatchBinding, 4> memoryWatches_{};
        std::uint64_t logicalDr6_ = 0;
        enum class CeEvent { none, process, initial, stop, exit };
        CeEvent ceEvent_ = CeEvent::none;
        bool ceBootstrap_ = true, ceSoftwareRip_ = false;
        std::uint64_t ceDeliveredStop_ = 0;
        std::uint64_t phaseGeneration_ = 0;
        std::uint64_t stepOverTarget_ = 0;
    };
}
