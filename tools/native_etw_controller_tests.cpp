#include "native_etw_controller_fake_api.h"
#include "../KswordARKLight/Ui/BackgroundWork.h"
#include "../shared/usermode/backend/monitor/PassiveEtwSource.h"

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <stdexcept>

#ifdef NDEBUG
#error Native ETW regression assertions must be enabled.
#endif

namespace {
constexpr TRACEHANDLE kSessionHandle = 17;
constexpr TRACEHANDLE kConsumerHandle = 23;
constexpr GUID kProvider{0xda71e251, 0xd49e, 0x4a7d, {0xaa, 0xbe, 0x95, 0x5d, 0xf1, 0x79, 0x02, 0x13}};
struct Backend {
    std::mutex mutex;
    std::condition_variable changed;
    std::wstring identity;
    bool session = false, consumer = false, entered = false, endConsumer = false;
    unsigned failStop = 0, failClose = 0, starts = 0;
    bool holdOpen = false, openEntered = false, observeProcess = true;
    PEVENT_RECORD_CALLBACK eventCallback = nullptr;
    void* eventContext = nullptr;
    unsigned stopCalls = 0, closeCalls = 0;
    ULONG openError = ERROR_SUCCESS, closeResult = ERROR_SUCCESS;
    ULONG enableError = ERROR_SUCCESS, processError = ERROR_CANCELLED;
} backend;
template<class Predicate> void Eventually(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!predicate()) {
        if (std::chrono::steady_clock::now() > deadline) throw std::runtime_error("fake controller timeout");
        std::this_thread::yield();
    }
}
void Reset() {
    std::lock_guard lock(backend.mutex);
    assert(!backend.session && !backend.consumer);
    backend.entered = backend.endConsumer = false;
    backend.failStop = backend.failClose = 0;
    backend.holdOpen = backend.openEntered = false;
    backend.observeProcess = true;
    backend.eventCallback = nullptr;
    backend.eventContext = nullptr;
    backend.stopCalls = backend.closeCalls = 0;
    backend.openError = backend.closeResult = ERROR_SUCCESS;
    backend.enableError = ERROR_SUCCESS;
    backend.processError = ERROR_CANCELLED;
}
ks::r3::monitor::EtwFilterState Filter() {
    ks::r3::monitor::EtwFilterState filter;
    filter.providers.push_back({L"fake provider", {}});
    return filter;
}
void WaitConsumer() { Eventually([] { std::lock_guard lock(backend.mutex); return backend.entered; }); }
} // namespace

ULONG WINAPI NativeControllerStartTraceW(PTRACEHANDLE handle, LPCWSTR name, PEVENT_TRACE_PROPERTIES) {
    std::lock_guard lock(backend.mutex);
    assert(!backend.session);
    backend.session = true;
    backend.entered = backend.endConsumer = false;
    backend.identity = name;
    ++backend.starts;
    *handle = kSessionHandle;
    return ERROR_SUCCESS;
}
ULONG WINAPI NativeControllerControlTraceW(TRACEHANDLE handle, LPCWSTR name, PEVENT_TRACE_PROPERTIES, ULONG action) {
    std::lock_guard lock(backend.mutex);
    assert(handle == kSessionHandle && name == backend.identity && action == EVENT_TRACE_CONTROL_STOP);
    ++backend.stopCalls;
    if (backend.failStop) { --backend.failStop; return ERROR_ACCESS_DENIED; }
    const bool existed = backend.session;
    backend.session = false;
    backend.changed.notify_all();
    return existed ? ERROR_SUCCESS : ERROR_WMI_INSTANCE_NOT_FOUND;
}
ULONG WINAPI NativeControllerEnableTraceEx2(TRACEHANDLE, LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG, PENABLE_TRACE_PARAMETERS) {
    std::lock_guard lock(backend.mutex);
    return backend.enableError;
}
TRACEHANDLE WINAPI NativeControllerOpenTraceW(PEVENT_TRACE_LOGFILEW logfile) {
    std::unique_lock lock(backend.mutex);
    assert(backend.session && logfile->LoggerName == backend.identity);
    backend.openEntered = true;
    backend.changed.notify_all();
    backend.changed.wait(lock, [] { return !backend.holdOpen; });
    assert(backend.session);
    if (backend.openError != ERROR_SUCCESS) {
        ::SetLastError(backend.openError);
        return INVALID_PROCESSTRACE_HANDLE;
    }
    backend.consumer = true;
    backend.eventCallback = logfile->EventRecordCallback;
    backend.eventContext = logfile->Context;
    return kConsumerHandle;
}
ULONG WINAPI NativeControllerCloseTrace(TRACEHANDLE handle) {
    std::lock_guard lock(backend.mutex);
    assert(handle == kConsumerHandle && backend.consumer);
    ++backend.closeCalls;
    if (backend.failClose) { --backend.failClose; return ERROR_GEN_FAILURE; }
    backend.consumer = false;
    backend.changed.notify_all();
    return backend.closeResult;
}
ULONG WINAPI NativeControllerProcessTrace(TRACEHANDLE* handle, ULONG count, LPFILETIME, LPFILETIME) {
    std::unique_lock lock(backend.mutex);
    assert(count == 1 && *handle == kConsumerHandle);
    if (backend.observeProcess) {
        assert(backend.eventCallback && backend.eventContext);
        EVENT_RECORD event{};
        event.UserContext = backend.eventContext;
        backend.eventCallback(&event);
    }
    backend.entered = true;
    backend.changed.notify_all();
    backend.changed.wait(lock, [] { return !backend.session || !backend.consumer || backend.endConsumer; });
    return backend.processError;
}

int main() {
    using namespace ks::r3::monitor;
    {
        // Begin with both native resources live, then fail each retirement API once.
        EtwSessionController controller;
        assert(controller.start(Filter()));
        WaitConsumer();
        const auto name = controller.evidence().sessionName;
        { std::lock_guard lock(backend.mutex); backend.failStop = 1; backend.failClose = 1; }
        assert(!controller.stopChecked());
        const auto pending = controller.evidence();
        assert(controller.cleanupPending() && !pending.sessionStopped && !pending.processCompleted);
        assert(pending.sessionName == name && pending.stopStatuses == std::vector<ULONG>{ERROR_ACCESS_DENIED});
        assert(pending.closeAttempted && pending.closeStatus == ERROR_GEN_FAILURE);
        {
            std::lock_guard lock(backend.mutex);
            assert(backend.session && backend.consumer && backend.identity == name);
            assert(backend.stopCalls == 1 && backend.closeCalls == 1);
        }
        assert(controller.stopChecked());
        const auto retired = controller.evidence();
        assert(!controller.cleanupPending() && retired.sessionStopped && retired.processCompleted);
        assert(retired.sessionName == name && retired.closeStatus == ERROR_SUCCESS);
        assert((retired.stopStatuses == std::vector<ULONG>{ERROR_ACCESS_DENIED, ERROR_SUCCESS}));
        {
            std::lock_guard lock(backend.mutex);
            assert(!backend.session && !backend.consumer && backend.identity == name);
            assert(backend.stopCalls == 2 && backend.closeCalls == 2);
        }
    }
    Reset();
    for (const ULONG openError : {ERROR_SUCCESS, ERROR_INVALID_PARAMETER}) {
        // Hold the native open call before publishing its result. Request stop
        // and release it only after the controller has published stop intent.
        EtwSessionController controller;
        {
            std::lock_guard lock(backend.mutex);
            backend.holdOpen = true;
            backend.openError = openError;
        }
        assert(controller.start(Filter()));
        Eventually([] { std::lock_guard lock(backend.mutex); return backend.openEntered; });
        bool stopped = false;
        std::thread stopper([&] { stopped = controller.stopChecked(); });
        Eventually([&] { return !controller.running(); });
        {
            std::lock_guard lock(backend.mutex);
            assert(backend.stopCalls == 0);
            backend.holdOpen = false;
            backend.changed.notify_all();
        }
        stopper.join();
        const auto receipt = controller.evidence();
        assert(stopped && receipt.sessionStopped && receipt.openAttempted && receipt.openStatus == openError);
        assert(!receipt.processAttempted && !receipt.processCompleted);
        assert(receipt.startupAbort == (openError == ERROR_SUCCESS ?
            EtwStartupAbort::BeforeProcessTrace : EtwStartupAbort::None));
        { std::lock_guard lock(backend.mutex); assert(!backend.entered); }
        Reset();
    }
    for (const ULONG result : {ERROR_INVALID_PARAMETER, ERROR_CANCELLED}) {
        PassiveEtwSource source;
        PassiveEtwOptions options;
        options.provider = kProvider;
        assert(source.start(options));
        WaitConsumer();
        { std::lock_guard lock(backend.mutex); backend.processError = result; }
        assert(source.stop());
        const auto terminal = source.status();
        assert(terminal.state == PassiveEtwState::Failed && terminal.native.sessionStopped);
        assert(terminal.native.processCompleted && terminal.native.processStatus == result);
        assert(terminal.native.startupAbort == EtwStartupAbort::None);
        Reset();
    }
    for (const bool observed : {true, false}) {
        PassiveEtwSource source;
        PassiveEtwOptions options;
        options.provider = kProvider;
        {
            std::lock_guard lock(backend.mutex);
            backend.processError = ERROR_SUCCESS;
            backend.observeProcess = observed;
        }
        assert(source.start(options));
        WaitConsumer();
        assert(source.stop());
        const auto terminal = source.status();
        assert(terminal.state == (observed ? PassiveEtwState::Stopped : PassiveEtwState::Failed));
        assert(terminal.native.sessionStopped && terminal.native.receivedEvents == (observed ? 1U : 0U));
        assert(terminal.native.processCompleted && terminal.native.processStatus == ERROR_SUCCESS);
        assert(terminal.native.statisticsKnown && terminal.native.tailDeliveryUnconfirmed == !observed);
        Reset();
    }
    {
        // Close can be accepted before the logger is stopped. A clean retry
        // and ProcessTrace=0 still cannot establish complete tail delivery.
        PassiveEtwSource source;
        PassiveEtwOptions options;
        options.provider = kProvider;
        assert(source.start(options));
        WaitConsumer();
        {
            std::lock_guard lock(backend.mutex);
            backend.failStop = 1;
            backend.processError = ERROR_SUCCESS;
            backend.closeResult = ERROR_CTX_CLOSE_PENDING;
        }
        assert(source.stop());
        const auto terminal = source.status();
        assert(terminal.state == PassiveEtwState::Failed && terminal.native.sessionStopped);
        assert(terminal.native.processCompleted && terminal.native.processStatus == ERROR_SUCCESS);
        assert(terminal.native.closeStatus == ERROR_CTX_CLOSE_PENDING && terminal.native.statisticsKnown);
        assert(terminal.native.tailDeliveryUnconfirmed);
    }
    Reset();
    {
        EtwSessionController controller;
        assert(controller.start(Filter()));
        WaitConsumer();
        unsigned before = 0;
        { std::lock_guard lock(backend.mutex); backend.failStop = 8; before = backend.starts; }
        assert(!controller.stopChecked());
        assert(!controller.evidence().sessionStopped && controller.cleanupPending());
        assert(!controller.start(Filter()));
        { std::lock_guard lock(backend.mutex); assert(backend.starts == before && backend.session); backend.failStop = 0; }
        assert(controller.stopChecked());
        assert(controller.evidence().sessionStopped && !controller.cleanupPending());
    }
    Reset();
    {
        // STOP succeeds but both final consumer-close attempts fail. The old
        // sessionStopped-only completion predicate must not report readiness.
        EtwSessionController controller;
        assert(controller.start(Filter()));
        WaitConsumer();
        { std::lock_guard lock(backend.mutex); backend.failClose = 2; }
        assert(!controller.stopChecked());
        assert(controller.evidence().sessionStopped && controller.evidence().closeStatus == ERROR_GEN_FAILURE && controller.cleanupPending());
        assert(controller.stopChecked());
    }
    Reset();
    {
        auto controller = std::make_shared<EtwSessionController>();
        const std::weak_ptr<EtwSessionController> weak = controller;
        assert(controller->start(Filter()));
        WaitConsumer();
        { std::lock_guard lock(backend.mutex); backend.failStop = 1; backend.failClose = 1; }
        Ksword::Ui::BackgroundWorkRegistry registry;
        registry.beginClosing();
        auto cleanup = registry.retire([controller] { return controller->stopChecked(); });
        controller.reset();
        Eventually([&] { return cleanup->failure() == Ksword::Ui::BackgroundWorkRegistry::Failure::Operation; });
        registry.cancelClosing();
        assert(!weak.expired() && registry.pending() == 1);
        { std::lock_guard lock(backend.mutex); assert(backend.session && backend.consumer); }
        registry.retry(true);
        Eventually([&] { return cleanup->complete(); });
        assert(weak.expired() && registry.pending() == 0);
    }
    Reset();
    {
        EtwSessionController controller;
        assert(controller.start(Filter()));
        WaitConsumer();
        { std::lock_guard lock(backend.mutex); backend.failStop = 8; backend.endConsumer = true; backend.processError = ERROR_INVALID_PARAMETER; backend.changed.notify_all(); }
        Eventually([&] { return !controller.running(); });
        const auto failed = controller.evidence();
        assert(failed.processCompleted && failed.processStatus == ERROR_INVALID_PARAMETER);
        assert(failed.startupAbort == EtwStartupAbort::None && failed.tailDeliveryUnconfirmed);
        assert(!controller.stopChecked());
        { std::lock_guard lock(backend.mutex); backend.failStop = 0; }
        assert(controller.stopChecked());
    }
    Reset();
    {
        EtwSessionController controller;
        { std::lock_guard lock(backend.mutex); backend.enableError = ERROR_NOT_SUPPORTED; backend.failStop = 2; }
        assert(!controller.start(Filter()));
        assert(controller.evidence().startSucceeded && !controller.evidence().sessionStopped);
        assert(controller.stopChecked());
    }
    Reset();
    std::cout << "PASS: fast stop, native status, tail coverage, STOP+Close ownership and retry, natural exit, provider compensation\n";
}
