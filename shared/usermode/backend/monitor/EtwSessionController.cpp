#include "EtwSessionController.h"

#include <evntrace.h>
#include <tdh.h>

#include <chrono>
#include <cwchar>
#include <iterator>
#include <memory>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Tdh.lib")

namespace ks::r3::monitor {
namespace {

constexpr std::size_t kTracePropertiesBufferBytes =
    sizeof(EVENT_TRACE_PROPERTIES) + 1024U * sizeof(wchar_t);

std::wstring Win32ErrorText(const wchar_t* action, const ULONG errorCode) {
    wchar_t buffer[256] = {};
    std::swprintf(buffer, std::size(buffer), L"%s failed, error=%lu", action, errorCode);
    return buffer;
}

std::wstring BuildSessionName() {
    static std::atomic<unsigned long long> serial{0};
    wchar_t buffer[128] = {};
    std::swprintf(
        buffer,
        std::size(buffer),
        L"KswordARKLight-ETW-%lu-%llu-%llu",
        ::GetCurrentProcessId(),
        static_cast<unsigned long long>(::GetTickCount64()),++serial);
    return buffer;
}

std::vector<unsigned char> MakeTracePropertiesBuffer(const std::wstring& sessionName) {
    std::vector<unsigned char> buffer(kTracePropertiesBufferBytes, 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(buffer.size());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2; // EventHeader timestamp is system FILETIME, not guessed QPC.
    properties->FlushTimer = 1;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 512U * sizeof(wchar_t);

    wchar_t* nameBuffer = reinterpret_cast<wchar_t*>(buffer.data() + properties->LoggerNameOffset);
    ::wcsncpy_s(nameBuffer, 512U, sessionName.c_str(), _TRUNCATE);
    return buffer;
}

std::wstring BuildEventSummary(const EVENT_RECORD& record) {
    wchar_t buffer[256] = {};
    std::swprintf(
        buffer,
        std::size(buffer),
        L"ID=%u Version=%u Level=%u Opcode=%u Task=%u Keyword=0x%llX",
        static_cast<unsigned int>(record.EventHeader.EventDescriptor.Id),
        static_cast<unsigned int>(record.EventHeader.EventDescriptor.Version),
        static_cast<unsigned int>(record.EventHeader.EventDescriptor.Level),
        static_cast<unsigned int>(record.EventHeader.EventDescriptor.Opcode),
        static_cast<unsigned int>(record.EventHeader.EventDescriptor.Task),
        static_cast<unsigned long long>(record.EventHeader.EventDescriptor.Keyword));
    return buffer;
}

} // namespace

EtwSessionController::EtwSessionController() = default;

EtwSessionController::~EtwSessionController() {
    stop();
}

void EtwSessionController::setEventCallback(EventCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    eventCallback_ = std::move(callback);
}

void EtwSessionController::setStatusCallback(StatusCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    statusCallback_ = std::move(callback);
}

bool EtwSessionController::start(const EtwFilterState& filterState) {
    if (running() || sessionHandle_.load() != 0) {
        publishLastError(L"ETW session is already running.");
        return false;
    }

    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    filterState_ = filterState;
    sessionName_ = BuildSessionName();
    {std::lock_guard<std::mutex> lock(mutex_);evidence_ = {};evidence_.sessionName = sessionName_;evidence_.startAttempted = true;}
    std::vector<unsigned char> propertiesBuffer = MakeTracePropertiesBuffer(sessionName_);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesBuffer.data());

    TRACEHANDLE newSessionHandle = 0;
    ULONG status = ::StartTraceW(&newSessionHandle, sessionName_.c_str(), properties);
    {std::lock_guard<std::mutex> lock(mutex_);evidence_.startStatus = status;evidence_.startSucceeded = status == ERROR_SUCCESS;}
    if (status != ERROR_SUCCESS) {
        publishLastError(Win32ErrorText(L"StartTraceW", status));
        return false;
    }

    sessionHandle_.store(newSessionHandle);
    stopRequested_.store(false);
    running_.store(true);

    if (!enableProviders()) {
        stop();
        return false;
    }

    try {
        workerThread_ = std::thread([this]() {
            workerLoop();
        });
    }
    catch (...) {
        running_.store(false);
        {std::lock_guard<std::mutex> lock(mutex_);evidence_.threadStartFailed = true;}
        stopOwnedSession();
        publishLastError(L"failed to create ETW consumer thread");
        return false;
    }

    publishStatus(L"ETW session started.");
    return true;
}

void EtwSessionController::stop() {
    const bool wasRunning = running_.exchange(false);
    if (!wasRunning && !workerThread_.joinable() && sessionHandle_.load() == 0) {
        return;
    }
    stopRequested_.store(true);

    stopOwnedSession();if (sessionHandle_.load() != 0) closeConsumer();

    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    stopOwnedSession();if (sessionHandle_.load() == 0) sessionName_.clear();
    publishStatus(L"ETW session stopped.");
}

bool EtwSessionController::running() const {
    return running_.load();
}
EtwSessionEvidence EtwSessionController::evidence() const {
    std::lock_guard<std::mutex> lock(mutex_);return evidence_;
}
void EtwSessionController::stopOwnedSession() {
    std::lock_guard<std::mutex> operation(resourceMutex_);const auto handle = sessionHandle_.load();if (!handle || sessionName_.empty()) return;
    auto buffer = MakeTracePropertiesBuffer(sessionName_);auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    const auto status = ::ControlTraceW(handle,sessionName_.c_str(),properties,EVENT_TRACE_CONTROL_STOP);
    {std::lock_guard<std::mutex> lock(mutex_);evidence_.stopStatuses.push_back(status);
        if (status == ERROR_SUCCESS) {evidence_.statisticsKnown = true;evidence_.eventsLost = properties->EventsLost;evidence_.logBuffersLost = properties->LogBuffersLost;evidence_.realTimeBuffersLost = properties->RealTimeBuffersLost;}
        if (status == ERROR_SUCCESS || status == ERROR_WMI_INSTANCE_NOT_FOUND) evidence_.sessionStopped = true;
    }
    if (status == ERROR_SUCCESS || status == ERROR_WMI_INSTANCE_NOT_FOUND) sessionHandle_.store(0);
}
void EtwSessionController::closeConsumer() {
    const auto handle = consumerHandle_.exchange(INVALID_PROCESSTRACE_HANDLE);if (handle == INVALID_PROCESSTRACE_HANDLE) return;
    const auto status = ::CloseTrace(handle);std::lock_guard<std::mutex> lock(mutex_);evidence_.closeAttempted = true;evidence_.closeStatus = status;
}

std::wstring EtwSessionController::lastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastError_;
}

VOID WINAPI EtwSessionController::EventRecordCallback(EVENT_RECORD* record) {
    if (record == nullptr || record->UserContext == nullptr) {
        return;
    }
    auto* controller = static_cast<EtwSessionController*>(record->UserContext);
    try {controller->handleEventRecord(record);}catch (...) {std::lock_guard<std::mutex> lock(controller->mutex_);controller->evidence_.callbackFailed = true;}
}

void EtwSessionController::handleEventRecord(EVENT_RECORD* record) {
    if (record == nullptr) {
        return;
    }

    const EVENT_HEADER& header = record->EventHeader;
    {std::lock_guard<std::mutex> lock(mutex_);++evidence_.receivedEvents;}
    if (!EventMatchesFilter(header.ProcessId, header.EventDescriptor.Level, filterState_)) {
        std::lock_guard<std::mutex> lock(mutex_);++evidence_.filteredEvents;
        return;
    }

    EtwEvent eventRow{};
    eventRow.timestamp = static_cast<std::uint64_t>(header.TimeStamp.QuadPart);
    eventRow.timeText = FileTimeToLocalText(header.TimeStamp);
    eventRow.providerText = GuidToString(header.ProviderId);
    eventRow.eventId = header.EventDescriptor.Id;
    eventRow.version = header.EventDescriptor.Version;
    eventRow.level = header.EventDescriptor.Level;
    eventRow.opcode = header.EventDescriptor.Opcode;
    eventRow.task = header.EventDescriptor.Task;
    eventRow.processId = header.ProcessId;
    eventRow.threadId = header.ThreadId;
    eventRow.keyword = header.EventDescriptor.Keyword;
    eventRow.summary = BuildEventSummary(*record);

    EventCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = eventCallback_;
    }
    if (callback) {
        try {callback(eventRow);}catch (...) {std::lock_guard<std::mutex> lock(mutex_);evidence_.callbackFailed = true;}
    }
}

void EtwSessionController::workerLoop() {
    const std::wstring sessionName = sessionName_;

    if (stopRequested_.load()) {
        running_.store(false);
        return;
    }

    EVENT_TRACE_LOGFILEW logFile{};
    logFile.LoggerName = const_cast<LPWSTR>(sessionName.c_str());
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    logFile.EventRecordCallback = &EtwSessionController::EventRecordCallback;
    logFile.Context = this;

    const TRACEHANDLE traceHandle = ::OpenTraceW(&logFile);
    const ULONG openStatus = traceHandle == INVALID_PROCESSTRACE_HANDLE ? ::GetLastError() : ERROR_SUCCESS;
    {std::lock_guard<std::mutex> lock(mutex_);evidence_.openAttempted = true;evidence_.openStatus = openStatus;}
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        const ULONG errorCode = openStatus;
        stopOwnedSession();
        const bool stopped = stopRequested_.load();
        running_.store(false);
        if (!stopped) {
            publishLastError(Win32ErrorText(L"OpenTraceW", errorCode));
        }
        return;
    }
    consumerHandle_.store(traceHandle);

    if (stopRequested_.load()) {
        closeConsumer();
        stopOwnedSession();
        running_.store(false);
        return;
    }

    TRACEHANDLE handles[] = { traceHandle };
    {std::lock_guard<std::mutex> lock(mutex_);evidence_.processAttempted = true;}
    const ULONG status = ::ProcessTrace(handles, 1, nullptr, nullptr);
    {std::lock_guard<std::mutex> lock(mutex_);evidence_.processCompleted = true;evidence_.processStatus = status;}
    closeConsumer();
    stopOwnedSession();

    const bool stopped = stopRequested_.load();
    running_.store(false);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED && !stopped) {
        publishLastError(Win32ErrorText(L"ProcessTrace", status));
    }
    else if (!stopped) {
        publishStatus(L"ETW session stopped.");
    }
}

bool EtwSessionController::enableProviders() {
    bool enabledAny = false;
    for (const EtwProviderPreset& provider : filterState_.providers) {
        if (!provider.enabled) {
            continue;
        }
        ENABLE_TRACE_PARAMETERS parameters{};
        parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        const ULONG status = ::EnableTraceEx2(
            sessionHandle_.load(),
            &provider.providerGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            provider.level,
            provider.matchAnyKeyword,
            0,
            0,
            &parameters);
        {std::lock_guard<std::mutex> lock(mutex_);evidence_.providers.push_back({provider.name,GuidToString(provider.providerGuid),status});}
        if (status != ERROR_SUCCESS) {
            publishLastError(Win32ErrorText(L"EnableTraceEx2", status));
            continue;
        }
        enabledAny = true;
    }

    if (!enabledAny) {
        publishLastError(L"No ETW providers are enabled.");
    }
    return enabledAny;
}

void EtwSessionController::publishStatus(const std::wstring& text) {
    StatusCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        lastError_ = text;
        callback = statusCallback_;
    }
    if (callback) {
        callback(text);
    }
}

void EtwSessionController::publishLastError(const std::wstring& text) {
    publishStatus(text);
}

} // namespace ks::r3::monitor
