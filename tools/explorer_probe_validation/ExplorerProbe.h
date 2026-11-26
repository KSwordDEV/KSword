#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <array>
#include <cstdint>

// Test-only protocol. Handles are passed only to our child through an explicit inherit list.
namespace ExplorerProbe
{
    constexpr DWORD trapFlag = 0x100;
    constexpr size_t maxThreads = 1024;
    constexpr size_t maxCalls = 4;
    enum class Mode : DWORD { Image, Private, CrossPage, AbortStep, Guardian };

    struct ThreadLedger
    {
        DWORD tid = 0;
        ULONGLONG created = 0;
        volatile LONG held = 0;
        DWORD previousSuspendCount = 0;
        volatile LONG ownTf = 0;
    };

    struct CallResult
    {
        DWORD tid = 0;
        DWORD exitCode = STILL_ACTIVE;
        HANDLE guardianHandle = nullptr;
        LONG createSeen = 0;
        LONG faults = 0;
        LONG exitSeen = 0;
    };

    struct Shared
    {
        DWORD pid = 0;
        ULONGLONG created = 0;
        Mode mode = Mode::Image;
        HANDLE target = nullptr;
        HANDLE guardian = nullptr;
        HANDLE faultReady = nullptr;
        std::uintptr_t watch = 0;
        SIZE_T watchBytes = 0;
        std::uintptr_t execution = 0;
        SIZE_T executionBytes = 0;
        std::uintptr_t entry = 0;
        void* argument = nullptr;
        DWORD originalProtection = 0;
        DWORD expectedExit = 0;
        DWORD requestedCalls = 0;
        DWORD goal = 0;
        volatile LONG protectionOwned = 0;
        volatile LONG ledgerCount = 0;
        volatile LONG done = 0;
        volatile LONG failed = 0;
        DWORD attachedThreads = 0;
        DWORD peakThreads = 0;
        DWORD createdThreads = 0;
        DWORD createdWhileStepping = 0;
        DWORD faults = 0;
        DWORD existingThreadFaults = 0;
        DWORD distinctFaultThreads = 0;
        DWORD steps = 0;
        DWORD rearms = 0;
        DWORD crossPageFaults = 0;
        DWORD queuedFaults = 0;
        DWORD snapshotPendingThreads = 0;
        DWORD snapshotExitedThreads = 0;
        DWORD unknownFirstChance = 0;
        DWORD abortedInPage = 0;
        DWORD protectRestored = 0;
        DWORD detached = 0;
        DWORD callsCompleted = 0;
        DWORD lastError = 0;
        ULONGLONG maxCycleUs = 0;
        std::array<ThreadLedger, maxThreads> ledger{};
        std::array<CallResult, maxCalls> calls{};
    };

    inline ULONGLONG FileTicks(const FILETIME& time)
    {
        return (static_cast<ULONGLONG>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    }
    inline bool Inside(std::uintptr_t address, std::uintptr_t start, SIZE_T bytes)
    {
        return address >= start && address - start < bytes;
    }
    int RunDebugSession(Shared& state);
}
