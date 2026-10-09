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
    wchar_t buffer[128] = {};
    std::swprintf(
        buffer,
        std::size(buffer),
        L"KswordARKLight-ETW-%lu-%llu",
        ::GetCurrentProcessId(),
        static_cast<unsigned long long>(::GetTickCount64()));
    return buffer;
}

std::vector<unsigned char> MakeTracePropertiesBuffer(const std::wstring& sessionName) {
    std::vector<unsigned char> buffer(kTracePropertiesBufferBytes, 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(buffer.size());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
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
    if (running()) {
        publishLastError(L"ETW session is already running.");
        return false;
    }

    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    filterState_ = filterState;
    sessionName_ = BuildSessionName();
    std::vector<unsigned char> propertiesBuffer = MakeTracePropertiesBuffer(sessionName_);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesBuffer.data());

    TRACEHANDLE newSessionHandle = 0;
    ULONG status = ::StartTraceW(&newSessionHandle, sessionName_.c_str(), properties);
    if (status == ERROR_ALREADY_EXISTS) {
        (void)::ControlTraceW(0, sessionName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        status = ::StartTraceW(&newSessionHandle, sessionName_.c_str(), properties);
    }
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
        (void)::ControlTraceW(newSessionHandle, sessionName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        sessionHandle_.store(0);
        sessionName_.clear();
        publishLastError(L"failed to create ETW consumer thread");
        return false;
    }

    publishStatus(L"ETW session started.");
    return true;
}

void EtwSessionController::stop() {
    const bool wasRunning = running_.exchange(false);
    if (!wasRunning && !workerThread_.joinable()) {
        return;
    }
    stopRequested_.store(true);

    const TRACEHANDLE ownedSessionHandle = sessionHandle_.exchange(0);
    if (ownedSessionHandle != 0 && !sessionName_.empty()) {
        std::vector<unsigned char> propertiesBuffer = MakeTracePropertiesBuffer(sessionName_);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesBuffer.data());
        (void)::ControlTraceW(
            ownedSessionHandle,
            sessionName_.c_str(),
            properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    if (workerThread_.joinable()) {
        workerThread_.join();
    }

    sessionName_.clear();
    publishStatus(L"ETW session stopped.");
}

bool EtwSessionController::running() const {
    return running_.load();
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
    controller->handleEventRecord(record);
}

void EtwSessionController::handleEventRecord(EVENT_RECORD* record) {
    if (record == nullptr || stopRequested_.load()) {
        return;
    }

    const EVENT_HEADER& header = record->EventHeader;
    if (!EventMatchesFilter(header.ProcessId, header.EventDescriptor.Level, filterState_)) {
        return;
    }

    EtwEvent eventRow{};
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
        callback(eventRow);
    }
}

void EtwSessionController::workerLoop() {
    const std::wstring sessionName = sessionName_;
    const auto stopOwnedSession = [this, &sessionName]() {
        const TRACEHANDLE ownedSessionHandle = sessionHandle_.exchange(0);
        if (ownedSessionHandle == 0 || sessionName.empty()) {
            return;
        }
        std::vector<unsigned char> propertiesBuffer = MakeTracePropertiesBuffer(sessionName);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesBuffer.data());
        (void)::ControlTraceW(
            ownedSessionHandle,
            sessionName.c_str(),
            properties,
            EVENT_TRACE_CONTROL_STOP);
    };

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
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        const ULONG errorCode = ::GetLastError();
        stopOwnedSession();
        const bool stopped = stopRequested_.load();
        running_.store(false);
        if (!stopped) {
            publishLastError(Win32ErrorText(L"OpenTraceW", errorCode));
        }
        return;
    }

    if (stopRequested_.load()) {
        (void)::CloseTrace(traceHandle);
        stopOwnedSession();
        running_.store(false);
        return;
    }

    TRACEHANDLE handles[] = { traceHandle };
    const ULONG status = ::ProcessTrace(handles, 1, nullptr, nullptr);
    (void)::CloseTrace(traceHandle);
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
