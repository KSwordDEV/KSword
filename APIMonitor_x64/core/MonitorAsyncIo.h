#pragma once
#include "pch.h"
#include "../../shared/WinApiMonitorProtocol.h"

namespace apimon
{
    // Published callback contexts retain these tokens until process exit.
    struct IoOperation
    {
        std::uint64_t id = 0, session = 0, resourceIdentity = 0;
        std::uintptr_t resource = 0;
        LPOVERLAPPED overlapped = nullptr;
        HANDLE port = nullptr;
        ULONG_PTR completionKey = 0;
        const wchar_t* module = nullptr;
        const wchar_t* api = nullptr;
        ks::winapi_monitor::EventCategory category{};
        std::uint32_t apiId = 0;
        DWORD issuingThread = 0;
        std::uint64_t requested = 0;
        // Set before the original call; read only while observing completion.
        const void* captureAddress = nullptr;
        const int* captureAddressLength = nullptr;
        void (*completionDetail)(const std::shared_ptr<IoOperation>&, wchar_t*, std::size_t) = nullptr;
        // Fields below are protected by the tracker mutex.
        bool submitted = false, completed = false, callbackExpected = false;
        bool completionBytesKnown = true;
        bool portExpected = false, portConsumed = false, earlyCompletion = false;
        bool lookupAmbiguous = false;
        DWORD completionError = 0, completionBytes = 0;
        void (*completionObserver)(const std::shared_ptr<IoOperation>&, DWORD) = nullptr;
        void* observerContext = nullptr;
    };
    using IoToken = std::shared_ptr<IoOperation>;
    IoToken BeginIo(std::uintptr_t resource, LPOVERLAPPED overlapped,
        const wchar_t* module, const wchar_t* api, ks::winapi_monitor::EventCategory category,
        std::uint64_t requested, bool callbackExpected = false) noexcept;
    void FinishIo(const IoToken& operation, bool accepted, bool pending, DWORD error, DWORD bytes, bool bytesKnown = true) noexcept;
    void AbortIo(const IoToken& operation) noexcept;
    void CompleteIo(const IoToken& operation, DWORD error, DWORD bytes) noexcept;
    void ObserveIoResult(std::uintptr_t resource, LPOVERLAPPED overlapped, bool completed,
        DWORD error, DWORD bytes, bool bytesKnown = true) noexcept;
    void ObservePortCompletion(HANDLE port, LPOVERLAPPED overlapped, DWORD error, DWORD bytes,
        ULONG_PTR completionKey = 0) noexcept;
    void ObserveIoCancellation(std::uintptr_t resource, LPOVERLAPPED overlapped, DWORD error,
        bool issuingThreadOnly = false) noexcept;
    void BindIoPort(std::uintptr_t resource, HANDLE port, ULONG_PTR completionKey = 0) noexcept;
    void SetIoNotificationMode(std::uintptr_t resource, UCHAR flags) noexcept;
    void RetireIoResource(std::uintptr_t resource) noexcept;
    std::uint64_t UntrackedIoCount() noexcept;
}
