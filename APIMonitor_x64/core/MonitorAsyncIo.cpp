#include "pch.h"
#include "MonitorAsyncIo.h"
#include "MonitorCoverage.h"
#include "MonitorPipe.h"
#include "../MonitorAgent.h"
#include "../hook/HookEngine.h"
#include <array>

namespace apimon
{
    namespace
    {
        constexpr std::size_t kCapacity = 8192;
        struct Resource { std::uint64_t session = 0, identity = 0; HANDLE port = nullptr; ULONG_PTR completionKey = 0; UCHAR mode = 0; };
        auto& g_mutex = *new std::mutex;
        auto& g_operations = *new std::array<IoToken, kCapacity>;
        auto& g_resources = *new std::unordered_map<std::uintptr_t, Resource>;
        std::uint64_t g_nextOperation = 0, g_nextResource = 0, g_resourceSession = 0;
        std::atomic_uint64_t g_untracked{0};
        Resource& ResourceFor(std::uintptr_t handle, std::uint64_t session)
        {
            if (g_resourceSession != session) { g_resources.clear(); g_resourceSession = session; }
            auto& resource = g_resources[handle];
            if (resource.session != session) { resource = {}; resource.session = session; resource.identity = ++g_nextResource; }
            return resource;
        }
        bool EventCurrent(const IoToken& op)
        { return op && op->session == CurrentMonitorSessionIdentity() && !StopRequested(); }
        void SendIo(const IoToken& op, ks::winapi_monitor::EventKind kind, DWORD error, DWORD bytes,
            const wchar_t* observation = L"", bool bytesKnown = true)
        {
            if (!EventCurrent(op)) return;
            wchar_t detail[ks::winapi_monitor::kMaxDetailChars]{};
            wchar_t output[ks::winapi_monitor::kMaxDetailChars]{};
            if (kind == ks::winapi_monitor::EventKind::IoComplete && op->completionDetail) {
                if (error == ERROR_SUCCESS) op->completionDetail(op, output, std::size(output));
                else wcscpy_s(output, L"completion_detail=unknown");
            }
            wchar_t bytesText[32]{};
            if (bytesKnown) _snwprintf_s(bytesText, _TRUNCATE, L"%lu", bytes);
            else wcscpy_s(bytesText, L"unknown");
            _snwprintf_s(detail, _TRUNCATE,
                L"resource=0x%llX resourceIdentity=%llu overlapped=0x%llX completionKey=0x%llX requested=%llu bytes=%s %s %s",
                static_cast<unsigned long long>(op->resource), op->resourceIdentity,
                reinterpret_cast<unsigned long long>(op->overlapped), static_cast<unsigned long long>(op->completionKey),
                op->requested, bytesText, observation, output);
            // A zero-error wait observation means the operation is still
            // pending, not that its eventual completion succeeded. Nonzero
            // wait errors describe the actual observation and stay visible.
            const auto resultKind = kind == ks::winapi_monitor::EventKind::IoWait && error == ERROR_SUCCESS
                ? ks::winapi_monitor::EventResultKind::StatusUnknown
                : ks::winapi_monitor::EventResultKind::StatusCode;
            SendMonitorEventRaw(op->category, op->module, op->api, static_cast<std::int32_t>(error), detail,
                resultKind, kind, op->id, op->apiId);
        }
        void NotTracked()
        {
            const auto count = ++g_untracked;
            wchar_t detail[96]{};
            _snwprintf_s(detail, _TRUNCATE, L"untracked=%llu capacity=8192; original call/callback retained", count);
            SendMonitorEventRaw(ks::winapi_monitor::EventCategory::Internal, L"Agent", L"IoUntracked", 0, detail);
        }
        bool CompleteLocked(const IoToken& op, DWORD error, DWORD bytes, bool bytesKnown = true)
        {
            if (!op || op->completed) return false;
            if (!op->submitted) {
                // Preserve the first actual completion observation; later calls
                // can race and may refer to the same reused OVERLAPPED.
                if (!op->earlyCompletion) { op->earlyCompletion = true; op->completionError = error;
                    op->completionBytes = bytes; op->completionBytesKnown = bytesKnown; }
                return false;
            }
            op->completed = true;
            op->completionError = error; op->completionBytes = bytes; op->completionBytesKnown = bytesKnown;
            SendIo(op, ks::winapi_monitor::EventKind::IoComplete, error, bytes, L"", bytesKnown);
            return true;
        }
        void NotifyCompletion(const IoToken& op)
        { if (EventCurrent(op) && op->completionObserver) op->completionObserver(op, op->completionError); }
        IoToken FindLocked(std::uintptr_t resource, LPOVERLAPPED ov)
        {
            const auto identity = g_resources.find(resource);
            if (identity == g_resources.end() || identity->second.session != CurrentMonitorSessionIdentity()) return {};
            IoToken latest;
            for (const auto& op : g_operations)
                if (op && op->resource == resource && op->resourceIdentity == identity->second.identity
                    && op->overlapped == ov && !op->lookupAmbiguous
                    && op->session == identity->second.session && (!latest || latest->id < op->id)) latest = op;
            return latest;
        }
        bool EventSuppressed(LPOVERLAPPED ov)
        {
            __try { return (reinterpret_cast<std::uintptr_t>(ov->hEvent) & 1) != 0; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return true; }
        }
    }
    IoToken BeginIo(std::uintptr_t resource, LPOVERLAPPED ov, const wchar_t* module, const wchar_t* api,
        ks::winapi_monitor::EventCategory category, std::uint64_t requested, bool callbackExpected) noexcept
    {
        try
        {
            ScopedInlineHookInternalBypass bypass;
            const auto session = CurrentMonitorSessionIdentity();
            if (!ov || !session || StopRequested()) return {};
            std::lock_guard lock(g_mutex);
            auto& identity = ResourceFor(resource, session);
            // Outstanding reuse is ambiguous. Never attach a new request to an older operation.
            for (const auto& op : g_operations)
                if (op && op->overlapped == ov && op->resourceIdentity == identity.identity && !op->completed)
                { op->lookupAmbiguous = true; NotTracked(); return {}; }
            for (auto& slot : g_operations)
                if (!slot || (slot->completed && (!slot->portExpected || slot->portConsumed))
                    || (slot->session != session && !slot->callbackExpected && (!slot->portExpected || slot->portConsumed)))
                {
                    auto op = std::make_shared<IoOperation>();
                    op->id = ++g_nextOperation; op->session = session; op->resource = resource;
                    op->resourceIdentity = identity.identity; op->overlapped = ov; op->port = identity.port;
                    op->completionKey = identity.completionKey;
                    op->module = module; op->api = api; op->category = category; op->requested = requested;
                    op->apiId = RuntimeApiId(module, api); op->callbackExpected = callbackExpected;
                    op->issuingThread = ::GetCurrentThreadId();
                    op->portExpected = identity.port && !callbackExpected && !EventSuppressed(ov);
                    slot = op; return op;
                }
            NotTracked();
        }
        catch (...) { ++g_untracked; }
        return {};
    }
    void FinishIo(const IoToken& op, bool accepted, bool pending, DWORD error, DWORD bytes, bool bytesKnown) noexcept
    {
        try
        {
            if (!op) return;
            ScopedInlineHookInternalBypass bypass;
            bool notify = false;
            {
                std::lock_guard lock(g_mutex);
                op->submitted = true;
                SendIo(op, ks::winapi_monitor::EventKind::IoSubmit, error, bytes,
                    accepted ? (pending ? L"asynchronous=pending" : L"synchronous=completed") : L"submission=rejected", bytesKnown);
                if (!accepted) { op->completed = true; op->portExpected = false; op->callbackExpected = false; return; }
                const auto resource = g_resources.find(op->resource);
                if (!pending && resource != g_resources.end() && (resource->second.mode & FILE_SKIP_COMPLETION_PORT_ON_SUCCESS))
                    op->portExpected = false;
                if (op->earlyCompletion) notify = CompleteLocked(op, op->completionError, op->completionBytes, op->completionBytesKnown);
                else if (!pending && !op->callbackExpected) notify = CompleteLocked(op, 0, bytes, bytesKnown);
                else SendIo(op, ks::winapi_monitor::EventKind::IoWait, 0, bytes, L"completion=pending", false);
            }
            if (notify) NotifyCompletion(op);
        }
        catch (...) {}
    }
    void AbortIo(const IoToken& op) noexcept
    {
        try { std::lock_guard lock(g_mutex); if (op) { op->completed = true; op->callbackExpected = false; op->portExpected = false; NotTracked(); } }
        catch (...) {}
    }
    void CompleteIo(const IoToken& op, DWORD error, DWORD bytes) noexcept
    { try { ScopedInlineHookInternalBypass bypass; bool notify = false;
        { std::lock_guard lock(g_mutex); notify = CompleteLocked(op, error, bytes); }
        if (notify) NotifyCompletion(op);
    } catch (...) {} }
    void ObserveIoResult(std::uintptr_t resource, LPOVERLAPPED ov, bool completed, DWORD error, DWORD bytes, bool bytesKnown) noexcept
    {
        try { ScopedInlineHookInternalBypass bypass; bool notify = false; IoToken op;
            { std::lock_guard lock(g_mutex); op = FindLocked(resource, ov);
            // A completed OVERLAPPED may already be reused by an untracked call.
            // Its later observed bytes cannot safely be attributed to this token.
            if (completed) notify = CompleteLocked(op, error, bytes, bytesKnown);
            else SendIo(op, ks::winapi_monitor::EventKind::IoWait, error, bytes, L"", bytesKnown); }
            if (notify) NotifyCompletion(op);
        }
        catch (...) {}
    }
    void ObservePortCompletion(HANDLE port, LPOVERLAPPED ov, DWORD error, DWORD bytes, ULONG_PTR completionKey) noexcept
    {
        try { ScopedInlineHookInternalBypass bypass; IoToken oldest; bool notify = false;
            { std::lock_guard lock(g_mutex);
            for (const auto& op : g_operations)
                if (op && op->overlapped == ov && !op->lookupAmbiguous && op->port == port && op->completionKey == completionKey
                    && op->portExpected && !op->portConsumed
                    && (!oldest || op->id < oldest->id)) oldest = op;
            if (oldest) { oldest->portConsumed = true; notify = CompleteLocked(oldest, error, bytes); } }
            if (notify) NotifyCompletion(oldest);
        }
        catch (...) {}
    }
    void ObserveIoCancellation(std::uintptr_t resource, LPOVERLAPPED ov, DWORD error, bool issuingThreadOnly) noexcept
    {
        try { ScopedInlineHookInternalBypass bypass; std::lock_guard lock(g_mutex);
            const auto identity = g_resources.find(resource);
            if (identity == g_resources.end()) return;
            for (const auto& op : g_operations)
                if (op && op->resource == resource && op->resourceIdentity == identity->second.identity
                    && (!issuingThreadOnly || op->issuingThread == ::GetCurrentThreadId())
                    && (!ov || op->overlapped == ov) && !op->completed)
                    SendIo(op, ks::winapi_monitor::EventKind::IoCancel, error, 0, L"cancellation=request; completion recorded separately"); }
        catch (...) {}
    }
    void BindIoPort(std::uintptr_t resource, HANDLE port, ULONG_PTR completionKey) noexcept
    { try { ScopedInlineHookInternalBypass bypass; std::lock_guard lock(g_mutex);
        auto& identity = ResourceFor(resource, CurrentMonitorSessionIdentity());
        identity.port = port; identity.completionKey = completionKey;
    } catch (...) {} }
    void SetIoNotificationMode(std::uintptr_t resource, UCHAR flags) noexcept
    { try { ScopedInlineHookInternalBypass bypass; std::lock_guard lock(g_mutex); ResourceFor(resource, CurrentMonitorSessionIdentity()).mode = flags; } catch (...) {} }
    void RetireIoResource(std::uintptr_t resource) noexcept
    { try { ScopedInlineHookInternalBypass bypass; std::lock_guard lock(g_mutex);
        for (const auto& op : g_operations) if (op) {
            if (reinterpret_cast<std::uintptr_t>(op->port) == resource) {
                op->portConsumed = true;
                if (!op->callbackExpected) op->completed = true;
            }
            if (op->resource == resource && !op->portExpected && !op->callbackExpected) op->completed = true;
        }
        g_resources.erase(resource);
    } catch (...) {} }
    std::uint64_t UntrackedIoCount() noexcept { return g_untracked.load(); }
}
