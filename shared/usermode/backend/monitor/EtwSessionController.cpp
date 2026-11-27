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
    // Legacy callers still cannot destroy a live callback context. Checked
    // retirement keeps this object owned on failure, outside the GUI lifetime.
    if (workerThread_.joinable()) workerThread_.join();
}

void EtwSessionController::setEventCallback(EventCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    eventCallback_ = std::move(callback);
}

void EtwSessionController::setRawEventCallback(RawEventCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    rawEventCallback_ = std::move(callback);
}

void EtwSessionController::setNativeRecordCallback(NativeRecordCallback callback) {
    const std::lock_guard<std::mutex> lock(mutex_); // 回调槽位与消费线程共享。
    nativeRecordCallback_ = std::move(callback);
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

    if ((workerThread_.joinable() || sessionHandle_.load() != 0 || consumerHandle_.load() != INVALID_PROCESSTRACE_HANDLE) && !stopChecked()) {
        return false;
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
    cleanupPending_.store(true, std::memory_order_release);
    stopRequested_.store(false);
    running_.store(true);

    if (!enableProviders()) {
        stop();
        return false;
    }

    consumerFinished_.store(false, std::memory_order_release);
    try {
        workerThread_ = std::thread([this]() {
            workerLoop();
        });
    }
    catch (...) {
        consumerFinished_.store(true, std::memory_order_release);
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
    (void)stopChecked();
}

bool EtwSessionController::stopChecked() {
    {
        const std::lock_guard lock(mutex_);
        stopRequested_.store(true);
        running_.store(false);
        // STOP flushes pending buffers; zero callbacks before STOP does not
        // establish loss. Premature consumer retirement is recorded separately.
    }
    stopOwnedSession();
    // logger 已清退时让 ProcessTrace 自行排空。仍持有 logger 时才用 CloseTrace 唤醒消费者。
    if (sessionHandle_.load() != 0 && !closeConsumer() && !consumerFinished_.load(std::memory_order_acquire)) {
        return false;
    }
    if (workerThread_.joinable()) {
        workerThread_.join();
        const std::lock_guard lock(mutex_);
        evidence_.consumerJoined = true;
    }
    stopOwnedSession();
    const bool consumerClosed = closeConsumer();
    const bool complete = sessionHandle_.load() == 0 && consumerClosed &&
        consumerHandle_.load() == INVALID_PROCESSTRACE_HANDLE;
    if (complete) {
        cleanupPending_.store(false, std::memory_order_release);
        sessionName_.clear();
        publishStatus(L"ETW session stopped.");
    } else {
        const auto state = evidence();
        const ULONG error = !consumerClosed ? state.closeStatus :
            (state.stopStatuses.empty() ? ERROR_GEN_FAILURE : state.stopStatuses.back());
        publishLastError(Win32ErrorText(!consumerClosed ? L"CloseTrace" : L"ControlTraceW(STOP)", error));
    }
    return complete;
}

bool EtwSessionController::running() const {
    return running_.load();
}
EtwSessionEvidence EtwSessionController::evidence() const {
    std::lock_guard<std::mutex> lock(mutex_);return evidence_;
}
// 对当前自有 logger 请求 STOP，将资源是否清退和原生统计是否回读分别写入证据。
void EtwSessionController::stopOwnedSession() {
    const std::lock_guard operation(resourceMutex_); // 串行化 STOP、消费打开和关闭。
    const auto handle = sessionHandle_.load(); // 本次启动获得的 logger 句柄。
    if (!handle || sessionName_.empty()) {
        return;
    }

    auto buffer = MakeTracePropertiesBuffer(sessionName_); // 接收本次 STOP 的属性和统计。
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data()); // Windows 回写位置。
    const auto status = ::ControlTraceW(handle, sessionName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP); // 原始结果码。
    // ControlTraceW 约定 MORE_DATA 在 STOP 生效后返回。NOT_FOUND 则只证明 logger 已不存在。
    const bool retired = status == ERROR_SUCCESS || status == ERROR_MORE_DATA ||
        status == ERROR_WMI_INSTANCE_NOT_FOUND;
    {
        const std::lock_guard lock(mutex_); // 同一次调用的结果一并写入状态快照。
        evidence_.stopStatuses.push_back(status);
        if (status == ERROR_SUCCESS) {
            evidence_.statisticsKnown = true;
            evidence_.eventsLost = properties->EventsLost;
            evidence_.logBuffersLost = properties->LogBuffersLost;
            evidence_.realTimeBuffersLost = properties->RealTimeBuffersLost;
        }
        if (retired) {
            evidence_.sessionStopped = true;
        }
    }
    if (retired) {
        sessionHandle_.store(0);
    }
}
bool EtwSessionController::closeConsumer() {
    const std::lock_guard operation(resourceMutex_);
    const auto handle = consumerHandle_.load();
    if (handle == INVALID_PROCESSTRACE_HANDLE) return true;
    const bool beforeStop = sessionHandle_.load() != 0;
    const auto status = ::CloseTrace(handle);
    const bool closed = status == ERROR_SUCCESS || status == ERROR_CTX_CLOSE_PENDING || status == ERROR_INVALID_HANDLE;
    {
        const std::lock_guard lock(mutex_);
        evidence_.closeAttempted = true;
        evidence_.closeStatus = status;
        if (closed && beforeStop && evidence_.processAttempted) evidence_.tailDeliveryUnconfirmed = true;
    }
    if (closed) consumerHandle_.store(INVALID_PROCESSTRACE_HANDLE);
    return closed;
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

    // 原生订阅无需构造本地化时间、字符串和摘要。旧回调照常取得格式化行。
    EventCallback callback; // 旧行的消费入口。
    RawEventCallback rawCallback; // 同时消费原生记录及旧行的入口。
    NativeRecordCallback nativeCallback; // 只接收原生记录的入口。
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        callback = eventCallback_;
        rawCallback = rawEventCallback_;
        nativeCallback = nativeRecordCallback_;
    }
    if (nativeCallback) {
        try {
            nativeCallback(*record);
        } catch (...) {
            const std::lock_guard<std::mutex> lock(mutex_);
            evidence_.callbackFailed = true;
        }
    }
    if (!callback && !rawCallback) {
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

    if (callback) {
        try {callback(eventRow);}catch (...) {std::lock_guard<std::mutex> lock(mutex_);evidence_.callbackFailed = true;}
    }
    if (rawCallback) {
        try {rawCallback(eventRow, *record);}catch (...) {std::lock_guard<std::mutex> lock(mutex_);evidence_.callbackFailed = true;}
    }
}

void EtwSessionController::workerLoop() {
    struct Finished final {
        std::atomic_bool& value;
        ~Finished() { value.store(true, std::memory_order_release); }
    } finished{consumerFinished_};
    const std::wstring sessionName = sessionName_;

    EVENT_TRACE_LOGFILEW logFile{};
    logFile.LoggerName = const_cast<LPWSTR>(sessionName.c_str());
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    logFile.EventRecordCallback = &EtwSessionController::EventRecordCallback;
    logFile.Context = this;

    TRACEHANDLE traceHandle = INVALID_PROCESSTRACE_HANDLE;
    ULONG openStatus = ERROR_SUCCESS;
    bool dispatchProcessTrace = false;
    {
        // Keep the logger alive through the submitted OpenTrace call and handle publication.
        const std::lock_guard operation(resourceMutex_);
        {
            const std::lock_guard lock(mutex_);
            if (stopRequested_.load()) {
                evidence_.startupAbort = EtwStartupAbort::BeforeOpenTrace;
                return;
            }
        }
        traceHandle = ::OpenTraceW(&logFile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE) openStatus = ::GetLastError();

        const std::lock_guard lock(mutex_);
        evidence_.openAttempted = true;
        evidence_.openStatus = openStatus;
        if (traceHandle != INVALID_PROCESSTRACE_HANDLE) {
            consumerHandle_.store(traceHandle);
            dispatchProcessTrace = !stopRequested_.load();
            if (dispatchProcessTrace) evidence_.processAttempted = true;
            else evidence_.startupAbort = EtwStartupAbort::BeforeProcessTrace;
        }
    }
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        stopOwnedSession();
        const bool stopped = stopRequested_.load();
        running_.store(false);
        if (!stopped) {
            publishLastError(Win32ErrorText(L"OpenTraceW", openStatus));
        }
        return;
    }

    if (!dispatchProcessTrace) {
        closeConsumer();
        stopOwnedSession();
        running_.store(false);
        return;
    }

    TRACEHANDLE handles[] = { traceHandle };
    // A stop can still race the native call after dispatch was committed.
    // Keep its actual return code without inferring the cause from stop intent.
    const ULONG status = ::ProcessTrace(handles, 1, nullptr, nullptr);
    {
        const std::lock_guard operation(resourceMutex_);
        const std::lock_guard lock(mutex_);
        evidence_.processCompleted = true;
        evidence_.processStatus = status;
        if (sessionHandle_.load() != 0) evidence_.tailDeliveryUnconfirmed = true;
    }
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
