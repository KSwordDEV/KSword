#pragma once

#include "../Win32.h"
#include "EtwEventModel.h"
#include "EtwFilterModel.h"

#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace ks::r3::monitor {
struct EtwProviderEvidence {
    std::wstring name,guid;
    ULONG status = ERROR_SUCCESS;
};
enum class EtwStartupAbort { None, BeforeOpenTrace, BeforeProcessTrace };

struct EtwSessionEvidence {
    std::wstring sessionName;
    bool startAttempted = false,startSucceeded = false,threadStartFailed = false;
    // A startup abort identifies an API call the worker skipped after stop intent.
    EtwStartupAbort startupAbort = EtwStartupAbort::None;
    bool openAttempted = false;
    bool processAttempted = false; // Dispatch committed on the worker, before the native call.
    bool processCompleted = false;
    bool consumerJoined = false; // The owner joined a worker for this session.
    bool tailDeliveryUnconfirmed = false; // No observed entry at STOP, or consumer retired before logger.
    bool closeAttempted = false,statisticsKnown = false,sessionStopped = false,callbackFailed = false;
    ULONG startStatus = ERROR_SUCCESS,openStatus = ERROR_SUCCESS,processStatus = ERROR_SUCCESS,closeStatus = ERROR_SUCCESS;
    ULONG eventsLost = 0,logBuffersLost = 0,realTimeBuffersLost = 0;
    std::uint64_t receivedEvents = 0,filteredEvents = 0;
    std::vector<EtwProviderEvidence> providers;
    std::vector<ULONG> stopStatuses;
};

// EtwSessionController owns a real-time ETW session. The owner serializes
// start and stop calls. The worker opens the consumer and processes records.
class EtwSessionController final {
public:
    using EventCallback = std::function<void(const EtwEvent&)>;
    // Raw record is valid only during the callback; consumers must copy any data.
    using RawEventCallback = std::function<void(const EtwEvent&, const EVENT_RECORD&)>;
    // 只借用原生记录，适用于不需要旧界面格式化行的来源。
    using NativeRecordCallback = std::function<void(const EVENT_RECORD&)>;
    using StatusCallback = std::function<void(const std::wstring&)>;

    EtwSessionController();
    ~EtwSessionController();

    EtwSessionController(const EtwSessionController&) = delete;
    EtwSessionController& operator=(const EtwSessionController&) = delete;

    // setEventCallback stores the UI/model event sink. Input is callable; no return.
    void setEventCallback(EventCallback callback);
    void setRawEventCallback(RawEventCallback callback);
    // 设置原生订阅回调，保留既有行回调和过滤的行为。
    void setNativeRecordCallback(NativeRecordCallback callback);

    // setStatusCallback stores the UI status sink. Input is callable; no return.
    void setStatusCallback(StatusCallback callback);

    // start creates a real-time ETW trace session and starts ProcessTrace on a
    // worker thread. Input is filter state; output is true when the session starts.
    bool start(const EtwFilterState& filterState);

    // stop requests ProcessTrace shutdown and releases ETW handles. No input.
    void stop();
    // Exact retirement receipt: failed STOP/CloseTrace retains its original
    // resource identity and returns false, so the value owner can retry safely.
    bool stopChecked();
    bool cleanupPending() const noexcept { return cleanupPending_.load(std::memory_order_acquire); }

    // running reports whether the controller currently owns an active session.
    bool running() const;

    // lastError returns the latest human-readable error/status text.
    std::wstring lastError() const;
    EtwSessionEvidence evidence() const;

private:
    static VOID WINAPI EventRecordCallback(EVENT_RECORD* record);
    void handleEventRecord(EVENT_RECORD* record);
    void workerLoop();
    bool enableProviders();
    void publishStatus(const std::wstring& text);
    void publishLastError(const std::wstring& text);
    void stopOwnedSession();
    bool closeConsumer();

    mutable std::mutex mutex_;
    EventCallback eventCallback_;
    RawEventCallback rawEventCallback_;
    NativeRecordCallback nativeRecordCallback_; // 新来源直接复制 EVENT_RECORD 的入口。
    StatusCallback statusCallback_;
    EtwFilterState filterState_;
    std::wstring sessionName_;
    std::wstring lastError_;
    std::atomic<TRACEHANDLE> sessionHandle_{ 0 };
    std::atomic<TRACEHANDLE> consumerHandle_{ INVALID_PROCESSTRACE_HANDLE };
    std::mutex resourceMutex_;
    EtwSessionEvidence evidence_;
    std::thread workerThread_;
    std::atomic<bool> running_{ false };
    std::atomic_bool consumerFinished_{true};
    std::atomic_bool cleanupPending_{false};
    std::atomic<bool> stopRequested_{ false };
};

} // namespace ks::r3::monitor
