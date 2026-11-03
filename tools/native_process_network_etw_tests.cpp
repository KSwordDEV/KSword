#include "native_process_network_etw_fake_api.h"
#include "../KswordARKLight/Ui/BackgroundWork.h"

#include <cassert>
#include <array>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <stdexcept>

namespace {
struct FakeBackend final {
    std::mutex mutex;
    std::condition_variable changed;
    bool session = false;
    bool consumer = false;
    bool endConsumer = false;
    unsigned starts = 0;
    unsigned stops = 0;
    unsigned closes = 0;
    unsigned failStops = 0;
    unsigned failCloses = 0;
    ULONG enableError = ERROR_SUCCESS;
    ULONG processError = ERROR_CANCELLED;
    std::wstring identity;
    PEVENT_RECORD_CALLBACK callback = nullptr;
    void* callbackContext = nullptr;
} backend;

template<class Predicate> void Eventually(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!predicate()) {
        if (std::chrono::steady_clock::now() > deadline) throw std::runtime_error("fake-backend timeout");
        std::this_thread::yield();
    }
}
void Reset() {
    std::lock_guard lock(backend.mutex);
    assert(!backend.session && !backend.consumer);
    backend.endConsumer = false;
    backend.failStops = backend.failCloses = 0;
    backend.enableError = ERROR_SUCCESS;
    backend.processError = ERROR_CANCELLED;
}
} // namespace

ULONG WINAPI NativeFakeStartTraceW(PTRACEHANDLE handle, LPCWSTR name, PEVENT_TRACE_PROPERTIES) {
    std::lock_guard lock(backend.mutex);
    assert(!backend.session);
    ++backend.starts;
    backend.identity = name;
    backend.session = true;
    backend.endConsumer = false;
    *handle = 17;
    return ERROR_SUCCESS;
}
ULONG WINAPI NativeFakeControlTraceW(TRACEHANDLE handle, LPCWSTR name, PEVENT_TRACE_PROPERTIES properties, ULONG action) {
    std::lock_guard lock(backend.mutex);
    assert(handle == 17 && backend.identity == name && action == EVENT_TRACE_CONTROL_STOP);
    ++backend.stops;
    if (backend.failStops) { --backend.failStops; return ERROR_ACCESS_DENIED; }
    const bool existed = backend.session;
    backend.session = false;
    properties->EventsLost = 3;
    backend.changed.notify_all();
    return existed ? ERROR_SUCCESS : ERROR_WMI_INSTANCE_NOT_FOUND;
}
ULONG WINAPI NativeFakeEnableTraceEx2(TRACEHANDLE, LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG, PENABLE_TRACE_PARAMETERS) {
    std::lock_guard lock(backend.mutex);
    return backend.enableError;
}
PROCESSTRACE_HANDLE WINAPI NativeFakeOpenTraceW(PEVENT_TRACE_LOGFILEW logFile) {
    std::lock_guard lock(backend.mutex);
    backend.callback = logFile->EventRecordCallback;
    backend.callbackContext = logFile->Context;
    backend.consumer = true;
    return 23;
}
ULONG WINAPI NativeFakeCloseTrace(PROCESSTRACE_HANDLE handle) {
    std::lock_guard lock(backend.mutex);
    assert(handle == 23);
    ++backend.closes;
    if (backend.failCloses) { --backend.failCloses; return ERROR_GEN_FAILURE; }
    backend.consumer = false;
    backend.changed.notify_all();
    return ERROR_SUCCESS;
}
ULONG WINAPI NativeFakeProcessTrace(PROCESSTRACE_HANDLE* handle, ULONG count, LPFILETIME, LPFILETIME) {
    std::unique_lock lock(backend.mutex);
    assert(count == 1 && *handle == 23);
    backend.changed.wait(lock, [] { return !backend.consumer || !backend.session || backend.endConsumer; });
    return backend.processError;
}

int main() {
    using ks::network::ProcessNetworkEtwMonitor;
    {
        ProcessNetworkEtwMonitor monitor;
        assert(monitor.Start());
        assert(monitor.SnapshotHealth().acceptedEvents == 0);
        EVENT_RECORD record{};
        record.EventHeader.ProviderId = GUID{0x7dd42a49,0x5329,0x4832,{0x8d,0xfd,0x43,0xd9,0x79,0x15,0x3a,0x88}};
        std::uint32_t payload[2]{1234,2048};
        record.UserData = payload;record.UserDataLength = static_cast<USHORT>(sizeof(payload));
        record.UserContext = backend.callbackContext;
        record.EventHeader.ProcessId = 9999;
        for (const USHORT id : std::array<USHORT,4>{10,26,42,58}) {record.EventHeader.EventDescriptor.Id=id;backend.callback(&record);}
        for (const USHORT id : std::array<USHORT,4>{11,27,43,59}) {record.EventHeader.EventDescriptor.Id=id;backend.callback(&record);}
        const auto counters = monitor.SnapshotCounters();
        assert(counters.at(1234).rxBytes == 8192 && counters.at(1234).txBytes == 8192 && counters.count(9999) == 0);
        assert(monitor.SnapshotHealth().acceptedEvents == 8);
        record.EventHeader.EventDescriptor.Id=12;backend.callback(&record);
        record.EventHeader.EventDescriptor.Id=10;record.UserDataLength=7;backend.callback(&record);
        record.UserDataLength=static_cast<USHORT>(sizeof(payload));payload[0]=0;backend.callback(&record);
        payload[0]=1234;payload[1]=0;backend.callback(&record);
        assert(monitor.SnapshotHealth().acceptedEvents == 8);
        assert(monitor.StopChecked());
    }
    Reset();
    {
        ProcessNetworkEtwMonitor monitor;
        assert(monitor.Start());
        unsigned before = 0;
        std::wstring identity;
        { std::lock_guard lock(backend.mutex); backend.failStops = 2; before = backend.starts; identity = backend.identity; }
        assert(!monitor.StopChecked());
        auto health = monitor.SnapshotHealth();
        assert(!health.isRunning && health.cleanupPending && health.stopErrorKnown && health.stopError == ERROR_ACCESS_DENIED);
        assert(!monitor.Start());
        { std::lock_guard lock(backend.mutex); assert(backend.starts == before && backend.identity == identity && backend.session); }
        assert(monitor.StopChecked());
        assert(!monitor.SnapshotHealth().cleanupPending);
        assert(monitor.Start());
        assert(monitor.StopChecked());
    }
    Reset();
    {
        ProcessNetworkEtwMonitor monitor;
        assert(monitor.Start());
        { std::lock_guard lock(backend.mutex); backend.failStops = 2; backend.processError = ERROR_INVALID_DATA; backend.endConsumer = true; backend.changed.notify_all(); }
        Eventually([&] { return !monitor.IsRunning(); });
        assert(monitor.SnapshotHealth().cleanupPending);
        assert(!monitor.StopChecked());
        assert(monitor.StopChecked());
    }
    Reset();
    {
        // Both STOP and CloseTrace fail with a live fake consumer. Cancel only
        // reopens admission; the value-owned cleanup retains its exact target.
        auto monitor = std::make_shared<ProcessNetworkEtwMonitor>();
        const std::weak_ptr<ProcessNetworkEtwMonitor> weak = monitor;
        assert(monitor->Start());
        unsigned before = 0;
        { std::lock_guard lock(backend.mutex); backend.failStops = 1; backend.failCloses = 1; before = backend.starts; }
        Ksword::Ui::BackgroundWorkRegistry registry;
        registry.beginClosing();
        auto cleanup = registry.retire([monitor] { return monitor->StopChecked(); });
        monitor.reset();
        Eventually([&] { return cleanup->failure() == Ksword::Ui::BackgroundWorkRegistry::Failure::Operation; });
        assert(!weak.expired() && registry.pending() == 1);
        registry.cancelClosing();
        { std::lock_guard lock(backend.mutex); assert(backend.starts == before && backend.session && backend.consumer); }
        registry.retry(true);
        Eventually([&] { return cleanup->complete(); });
        assert(weak.expired() && registry.pending() == 0);
    }
    Reset();
    {
        // Provider enable fails after StartTrace. A failed compensating STOP
        // must retain the newly accepted session, even without a consumer.
        ProcessNetworkEtwMonitor monitor;
        { std::lock_guard lock(backend.mutex); backend.enableError = ERROR_NOT_SUPPORTED; backend.failStops = 1; }
        assert(!monitor.Start() && monitor.SnapshotHealth().cleanupPending);
        assert(monitor.StopChecked());
    }
    Reset();
    {
        ProcessNetworkEtwMonitor monitor;
        assert(monitor.Start());
        { std::lock_guard lock(backend.mutex); backend.failCloses = 2; }
        assert(!monitor.StopChecked());
        assert(monitor.SnapshotHealth().cleanupPending);
        Eventually([&] { return monitor.StopChecked(); });
    }
    Reset();
    std::cout << "PASS: production STOP failure/identity retry, natural consumer exit, CloseTrace failure, close+Cancel retention, provider-start compensation\n";
}
