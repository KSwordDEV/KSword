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
struct EtwSessionEvidence {
    std::wstring sessionName;
    bool startAttempted = false,startSucceeded = false,threadStartFailed = false;
    bool openAttempted = false,processAttempted = false,processCompleted = false;
    bool closeAttempted = false,statisticsKnown = false,sessionStopped = false,callbackFailed = false;
    ULONG startStatus = ERROR_SUCCESS,openStatus = ERROR_SUCCESS,processStatus = ERROR_SUCCESS,closeStatus = ERROR_SUCCESS;
    ULONG eventsLost = 0,logBuffersLost = 0,realTimeBuffersLost = 0;
    std::uint64_t receivedEvents = 0,filteredEvents = 0;
    std::vector<EtwProviderEvidence> providers;
    std::vector<ULONG> stopStatuses;
};

// EtwSessionController owns a real-time ETW session. Inputs are filter state
// and callbacks; processing starts/stops Windows ETW APIs on a worker thread;
// callbacks receive compact EtwEvent rows and status text.
class EtwSessionController final {
public:
    using EventCallback = std::function<void(const EtwEvent&)>;
    using StatusCallback = std::function<void(const std::wstring&)>;

    EtwSessionController();
    ~EtwSessionController();

    EtwSessionController(const EtwSessionController&) = delete;
    EtwSessionController& operator=(const EtwSessionController&) = delete;

    // setEventCallback stores the UI/model event sink. Input is callable; no return.
    void setEventCallback(EventCallback callback);

    // setStatusCallback stores the UI status sink. Input is callable; no return.
    void setStatusCallback(StatusCallback callback);

    // start creates a real-time ETW trace session and starts ProcessTrace on a
    // worker thread. Input is filter state; output is true when the session starts.
    bool start(const EtwFilterState& filterState);

    // stop requests ProcessTrace shutdown and releases ETW handles. No input.
    void stop();

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
    void closeConsumer();

    mutable std::mutex mutex_;
    EventCallback eventCallback_;
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
    std::atomic<bool> stopRequested_{ false };
};

} // namespace ks::r3::monitor
