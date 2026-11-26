#include "NetworkCaptureCommand.h"
#include "NetworkTrafficCommand.h"

#include "../Project/ProjectNetworkEvidence.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"
#include "../../../shared/usermode/backend/monitor/KernelNetworkEvidenceProjection.h"

#include <evntrace.h>
#include <evntcons.h>
#include <objbase.h>
#include <tdh.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

#pragma comment(lib, "Tdh.lib")

namespace ks::cli::action_analyze {
namespace {

namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
namespace net = ks::r3::monitor;

constexpr GUID kProvider{0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
constexpr auto kSource = net::kKernelNetworkProviderId;
constexpr std::uint32_t kMinDuration = 100;
constexpr std::uint32_t kMaxDuration = 60'000;

std::uint64_t FileTime100ns(const FILETIME& value) noexcept
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

std::optional<std::uint64_t> QpcNow() noexcept
{
    LARGE_INTEGER tick{};
    if (!QueryPerformanceCounter(&tick) || tick.QuadPart < 0) return std::nullopt;
    return static_cast<std::uint64_t>(tick.QuadPart);
}

// 从 Windows 读取本次启动实例。标签用于本次本机来源绑定。
std::string BootId()
{
    using QuerySystem = LONG (NTAPI*)(ULONG, void*, ULONG, ULONG*);
    constexpr ULONG kSystemBootEnvironmentInformation = 90;
    struct BootEnvironment { GUID bootIdentifier; ULONG firmwareType; ULONGLONG bootFlags; } value{};
    const auto module = GetModuleHandleW(L"ntdll.dll");
    if (!module) return {};
    const auto query = reinterpret_cast<QuerySystem>(GetProcAddress(module, "NtQuerySystemInformation"));
    if (!query || query(kSystemBootEnvironmentInformation, &value, static_cast<ULONG>(sizeof(value)), nullptr) < 0) {
        return {};
    }
    wchar_t guid[39]{};
    constexpr auto guidChars = static_cast<int>(ARRAYSIZE(guid));
    if (StringFromGUID2(value.bootIdentifier, guid, guidChars) != guidChars) return {};
    std::string id;
    for (std::size_t index = 1; index <= 36; ++index) {
        auto ch = guid[index];
        if (ch >= L'A' && ch <= L'F') ch += L'a' - L'A';
        id.push_back(static_cast<char>(ch));
    }
    return storage::IsUuid(id) && id != "00000000-0000-0000-0000-000000000000" ? id : std::string{};
}

bool IsLoopback(const net::NetworkEndpoint& endpoint) noexcept
{
    const auto& address = endpoint.address;
    if (endpoint.family == net::NetworkAddressFamily::Ipv4) return address[0] == 127;
    if (endpoint.family != net::NetworkAddressFamily::Ipv6) return false;
    constexpr std::array<std::uint8_t, 16> ipv6Loopback{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const bool mappedLoopback = std::all_of(address.begin(), address.begin() + 10, [](auto byte) { return byte == 0; }) &&
        address[10] == 0xff && address[11] == 0xff && address[12] == 127;
    return address == ipv6Loopback || mappedLoopback;
}

struct TraceProperties {
    EVENT_TRACE_PROPERTIES props{};
    wchar_t loggerName[128]{};
    wchar_t logFileName[128]{};

    explicit TraceProperties(const GUID& sessionGuid)
    {
        props.Wnode.BufferSize = static_cast<ULONG>(sizeof(*this));
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.Wnode.Guid = sessionGuid;
        props.Wnode.ClientContext = 1; // QPC，同一频率用于进程有效区间和原始事件时间戳。
        props.FlushTimer = 1;
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.LoggerNameOffset = static_cast<ULONG>(offsetof(TraceProperties, loggerName));
        props.LogFileNameOffset = static_cast<ULONG>(offsetof(TraceProperties, logFileName));
    }
};

// 带 PID 谓词的每项描述符都必须能由本机清单生成。调用者不启用宽范围备选来源。
class NetworkPidFilter final {
public:
    ~NetworkPidFilter()
    {
        if (descriptor.Ptr) TdhCleanupPayloadEventFilterDescriptor(&descriptor);
        for (auto& filter : filters_) {
            if (filter) TdhDeletePayloadFilter(&filter);
        }
    }

    ULONG Build(std::uint32_t pid, const std::array<std::uint16_t, 8>& allowIds)
    {
        GUID provider = kProvider;
        ULONG bytes = 0;
        auto status = TdhEnumerateManifestProviderEvents(&provider, nullptr, &bytes);
        if (status != ERROR_INSUFFICIENT_BUFFER) return status ? status : ERROR_NOT_SUPPORTED;
        if (bytes < sizeof(PROVIDER_EVENT_INFO) || bytes > 1024u * 1024u) return ERROR_NOT_SUPPORTED;
        std::vector<std::byte> buffer(bytes);
        const auto manifest = reinterpret_cast<PROVIDER_EVENT_INFO*>(buffer.data());
        status = TdhEnumerateManifestProviderEvents(&provider, manifest, &bytes);
        if (status != ERROR_SUCCESS) return status;
        // SDK 的变长描述符数组起点用于核对 TDH 返回的实际缓冲区。
        constexpr auto eventOffset = offsetof(PROVIDER_EVENT_INFO, EventDescriptorsArray);
        if (bytes > buffer.size() || bytes < eventOffset || manifest->NumberOfEvents >
            (bytes - eventOffset) / sizeof(EVENT_DESCRIPTOR)) return ERROR_INVALID_DATA;
        std::vector<EVENT_DESCRIPTOR> events(manifest->NumberOfEvents);
        if (events.empty()) return ERROR_NOT_SUPPORTED;
        std::memcpy(events.data(), buffer.data() + eventOffset, events.size() * sizeof(EVENT_DESCRIPTOR));

        auto pidText = std::to_wstring(pid);
        wchar_t field[] = L"PID";
        PAYLOAD_FILTER_PREDICATE predicate{field, PAYLOADFIELD_EQ, pidText.data()};
        for (std::size_t index = 0; index < allowIds.size(); ++index) {
            const auto match = std::find_if(events.begin(), events.end(), [&](const EVENT_DESCRIPTOR& event) {
                return event.Id == allowIds[index] && event.Version == 0;
            });
            if (match == events.end()) return ERROR_NOT_SUPPORTED;
            status = TdhCreatePayloadFilter(&provider, &*match, FALSE, 1, &predicate, &filters_[index]);
            if (status != ERROR_SUCCESS || !filters_[index]) return status ? status : ERROR_NOT_SUPPORTED;
        }
        return TdhAggregatePayloadFilters(static_cast<ULONG>(filters_.size()), filters_.data(), nullptr, &descriptor);
    }

    EVENT_FILTER_DESCRIPTOR descriptor{};

private:
    std::array<void*, 8> filters_{};
};

// 首段是有限采样。ProcessTrace 线程只保留投影后的回环元数据，项目写线程串行归档。
class LoopbackCapture final {
public:
    LoopbackCapture(DWORD pid, std::uint64_t creation, HANDLE target,
        const std::string& epoch, const std::string& bootId, std::uint64_t frequency)
        : pid_(pid), creation_(creation), target_(target),
          name_(L"KSword-ActionAnalyze-Network-" + storage::WideAscii(epoch)),
          scope_{.machineId = "local-windows", .sourceId = kSource, .sourceEpoch = epoch,
              .clock = {net::NetworkSourceClock::Qpc, epoch, bootId, frequency}, .allowedPids = {&pid_, 1}}
    {
        rows.reserve(archive::kNetworkQueueCapacity);
    }

    ~LoopbackCapture() { Stop(); }

    ULONG Arm(const wchar_t*& stage)
    {
        stage = L"TDH scoped PID filter";
        const auto eventIds = net::KernelNetworkEvidenceEventIds();
        NetworkPidFilter pidFilter;
        const auto filterStatus = pidFilter.Build(pid_, eventIds);
        if (filterStatus != ERROR_SUCCESS || !pidFilter.descriptor.Ptr) {
            return filterStatus != ERROR_SUCCESS ? filterStatus : ERROR_NOT_SUPPORTED;
        }
        stage = L"session-identity";
        if (FAILED(CoCreateGuid(&sessionGuid_))) return ERROR_GEN_FAILURE;
        TraceProperties properties(sessionGuid_);
        stage = L"StartTraceW";
        if (const auto status = StartTraceW(&logger_, name_.c_str(), &properties.props); status != ERROR_SUCCESS) {
            logger_ = 0;
            return status;
        }

        // 同一次 EnableTraceEx2 受理载荷 PID 和事件 ID 筛选。内核事件报头 PID 可能属于记录线程。
        struct EventFilter { BOOLEAN in; UCHAR reserved; USHORT count; std::array<std::uint16_t, 8> ids; };
        static_assert(offsetof(EventFilter, ids) == offsetof(EVENT_FILTER_EVENT_ID, Events));
        const EventFilter events{TRUE, 0, static_cast<USHORT>(eventIds.size()), eventIds};
        EVENT_FILTER_DESCRIPTOR filters[]{pidFilter.descriptor, {static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(&events)),
            static_cast<ULONG>(sizeof(events)), EVENT_FILTER_TYPE_EVENT_ID}};
        ENABLE_TRACE_PARAMETERS parameters{};
        parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        parameters.EnableFilterDesc = filters;
        parameters.FilterDescCount = static_cast<ULONG>(ARRAYSIZE(filters));
        stage = L"EnableTraceEx2(scoped)";
        const auto enabled = EnableTraceEx2(logger_, &kProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE, net::kKernelNetworkIpKeywords, 0, 3000, &parameters);
        if (enabled != ERROR_SUCCESS) return enabled;

        stage = L"OpenTraceW";
        EVENT_TRACE_LOGFILEW log{};
        log.LoggerName = name_.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME |
            PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.EventRecordCallback = OnRecord;
        log.Context = this;
        consumer_ = OpenTraceW(&log);
        return consumer_ == INVALID_PROCESSTRACE_HANDLE ? GetLastError() : ERROR_SUCCESS;
    }

    bool Start(std::string_view projectId, std::string_view sampleId, std::uint32_t durationMs)
    {
        const auto start = QpcNow();
        const auto frequency = *scope_.clock.frequencyHz;
        if (!start || WaitForSingleObject(target_, 0) != WAIT_TIMEOUT || frequency > UINT64_MAX / durationMs) {
            return false;
        }
        const auto duration = frequency * durationMs / 1000;
        if (!duration || *start > UINT64_MAX - duration) return false;
        scope_.projectId = projectId;
        scope_.sampleId = sampleId;
        scope_.firstSourceTick = *start;
        scope_.endSourceTick = *start + duration;
        if (!net::IsValidNetworkSampleScope(scope_)) return false;
        verifiedTick_.store(*start);

        try {
            worker_ = std::thread([this, handle = consumer_]() mutable {
                processStatus = ProcessTrace(&handle, 1, nullptr, nullptr);
                finished_.store(true, std::memory_order_release);
            });
        } catch (const std::system_error&) {
            return false;
        }
        return true;
    }

    const wchar_t* Wait(const std::atomic_bool& cancelled)
    {
        for (;;) {
            const auto tick = QpcNow();
            if (!tick) return L"clock-unavailable";
            const auto state = WaitForSingleObject(target_, 0);
            if (state == WAIT_OBJECT_0) return L"target-exited";
            if (state != WAIT_TIMEOUT) return L"target-wait-failed";
            ExtendVerified(*tick);
            if (scopeViolation.load()) return L"native-pid-filter-mismatch";
            if (finished_.load(std::memory_order_acquire) || callbackFailed.load()) return L"source-ended";
            if (cancelled.load()) {
                cutoff_ = *tick;
                return L"cancelled";
            }
            if (*tick >= *scope_.endSourceTick) return L"duration-elapsed";
            const auto remaining = *scope_.endSourceTick - *tick;
            const auto frequency = *scope_.clock.frequencyHz;
            const auto delay = (std::min)(std::uint64_t{25}, remaining * 1000 / frequency + 1);
            (void)WaitForSingleObject(target_, static_cast<DWORD>(delay));
        }
    }

    void Stop()
    {
        if (logger_) {
            TraceProperties properties(sessionGuid_);
            stopStatus = ControlTraceW(logger_, name_.c_str(), &properties.props, EVENT_TRACE_CONTROL_STOP);
            if (stopStatus == ERROR_SUCCESS || stopStatus == ERROR_MORE_DATA ||
                stopStatus == ERROR_WMI_INSTANCE_NOT_FOUND) logger_ = 0;
            if (stopStatus == ERROR_SUCCESS) {
                eventsLost = properties.props.EventsLost;
                buffersLost = properties.props.RealTimeBuffersLost;
            }
        }
        if (logger_) CloseConsumer(); // STOP 失败时让消费者退出，仍记录本次 logger 清退失败。
        if (worker_.joinable()) worker_.join();
        CloseConsumer();
        if (cutoff_) std::erase_if(rows, [&](const auto& row) { return row.flow.sourceTimestamp >= *cutoff_; });
    }

    bool Clean() const noexcept { return !logger_ && consumer_ == INVALID_PROCESSTRACE_HANDLE; }

    std::vector<project::ProjectNetworkObservation> rows; // 内核 ETW 只提供元数据，正文保持未捕获。
    std::uint64_t bufferDrops = 0;
    std::uint64_t unsupportedLayouts = 0;
    ULONG processStatus = ERROR_SUCCESS;
    ULONG stopStatus = ERROR_SUCCESS;
    ULONG closeStatus = ERROR_SUCCESS;
    std::optional<ULONG> eventsLost, buffersLost;
    std::atomic_bool callbackFailed{false};
    std::atomic_bool scopeViolation{false};

private:
    void CloseConsumer() noexcept
    {
        if (consumer_ == INVALID_PROCESSTRACE_HANDLE) return;
        closeStatus = CloseTrace(consumer_);
        if (closeStatus == ERROR_SUCCESS || closeStatus == ERROR_CTX_CLOSE_PENDING || closeStatus == ERROR_INVALID_HANDLE) {
            consumer_ = INVALID_PROCESSTRACE_HANDLE;
        }
    }

    void ExtendVerified(std::uint64_t tick) noexcept
    {
        auto previous = verifiedTick_.load();
        while (tick > previous && !verifiedTick_.compare_exchange_weak(previous, tick)) {}
    }

    static void WINAPI OnRecord(EVENT_RECORD* record) noexcept
    {
        if (!record || !record->UserContext) return;
        auto& owner = *static_cast<LoopbackCapture*>(record->UserContext);
        try {
            owner.Observe(*record);
        } catch (...) {
            owner.callbackFailed.store(true);
        }
    }

    void Observe(const EVENT_RECORD& record)
    {
        const auto& header = record.EventHeader;
        if (!IsEqualGUID(header.ProviderId, kProvider) || header.TimeStamp.QuadPart < 0 ||
            !record.UserData || callbackFailed.load() || scopeViolation.load()) return;
        const auto stamp = static_cast<std::uint64_t>(header.TimeStamp.QuadPart);
        // 检查持有的同一对象。进程退出后仅承认已经验证的时刻，不以数值 PID 追踪复用目标。
        if (stamp > verifiedTick_.load()) {
            const auto now = QpcNow();
            if (now && WaitForSingleObject(target_, 0) == WAIT_TIMEOUT) ExtendVerified(*now);
            if (stamp > verifiedTick_.load()) return;
        }
        const auto& descriptor = header.EventDescriptor;
        const auto projection = net::ProjectKernelNetworkObservation(scope_, {kSource, kSource, scope_.sourceEpoch,
            descriptor.Id, descriptor.Version, descriptor.Opcode, stamp, std::nullopt,
            {static_cast<const std::uint8_t*>(record.UserData), record.UserDataLength}});
        if (!projection.flow) {
            if (projection.status == net::NetworkProjectionStatus::OutOfScopePid) scopeViolation.store(true);
            if (projection.status == net::NetworkProjectionStatus::UnsupportedLayout ||
                projection.status == net::NetworkProjectionStatus::TruncatedMetadata) ++unsupportedLayouts;
            return;
        }
        const auto& value = *projection.flow;
        if (!IsLoopback(value.sourceField) || !IsLoopback(value.destinationField)) return;
        if (rows.size() == archive::kNetworkQueueCapacity) {
            ++bufferDrops;
            return;
        }
        archive::NetworkFlowMetadata flow;
        flow.family = static_cast<archive::NetworkFamily>(value.sourceField.family);
        flow.transport = static_cast<archive::NetworkTransport>(value.protocol);
        flow.direction = static_cast<archive::NetworkDirection>(value.direction);
        flow.sourceField = {value.sourceField.address, value.sourceField.port};
        flow.destinationField = {value.destinationField.address, value.destinationField.port};
        flow.processId = value.payloadPid;
        flow.processCreatedUtc100ns = creation_;
        flow.sourceTimestamp = value.sourceTick;
        flow.observedBytes = value.observedEtwBytes;
        flow.etw = archive::NetworkFlowMetadata::EtwDescriptor{value.eventId, value.version, value.opcode};
        rows.push_back({std::move(flow)});
    }

    const std::uint32_t pid_;
    const std::uint64_t creation_;
    const HANDLE target_;
    std::wstring name_;
    net::NetworkSampleScopeView scope_;
    GUID sessionGuid_{};
    TRACEHANDLE logger_ = 0;
    TRACEHANDLE consumer_ = INVALID_PROCESSTRACE_HANDLE;
    std::optional<std::uint64_t> cutoff_;
    std::atomic<std::uint64_t> verifiedTick_{0};
    std::atomic_bool finished_{false};
    std::thread worker_;
};

Result NativeFailure(const wchar_t* stage, ULONG error, int code = 3)
{
    return {code, Json::object({{L"stage", Json::string(stage)}, {L"win32Error", Json::number(error)}}), {}};
}

Json ProjectIssue(const project::ProjectResult& issue)
{
    if (issue) return {};
    return Json::object({{L"error", Json::string(storage::WideAscii(project::ProjectErrorName(issue.error)))},
        {L"detail", Json::string(storage::WideAscii(issue.detail))}, {L"win32Error", Json::number(issue.nativeError)}});
}

Result Run(const Args& args)
{
    if (args.require(L"--authorize-loopback") != L"yes") {
        throw std::invalid_argument("Use --authorize-loopback yes for a process you are authorized to observe");
    }
    const auto path = args.require(L"--project");
    const auto pid = args.u32(L"--pid");
    const auto creation = args.integer(L"--create-time");
    const auto duration = args.u32(L"--duration-ms");
    if (path.empty() || !pid || pid == UINT32_MAX || !creation || duration < kMinDuration || duration > kMaxDuration) {
        throw std::invalid_argument("Expected a project, one PID and creation FILETIME, and a duration of 100..60000 ms");
    }

    const HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!handle) return NativeFailure(L"OpenProcess", GetLastError());
    const storage::Handle target(handle);
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(handle, &created, &exited, &kernel, &user)) return NativeFailure(L"GetProcessTimes", GetLastError());
    if (FileTime100ns(created) != creation || WaitForSingleObject(handle, 0) != WAIT_TIMEOUT) {
        return NativeFailure(L"target-identity-or-lifetime", ERROR_INVALID_PARAMETER, 1);
    }

    project::ProjectDocument document;
    if (const auto opened = document.Open(path, project::ProjectAccess::ReadWrite); !opened) {
        return {3, Json::object({{L"projectError", ProjectIssue(opened)}}), {}};
    }
    const auto projectId = document.Info()->projectId;
    const auto revision = document.Info()->revisionId;
    std::string epoch;
    if (const auto id = storage::NewId(epoch); !id) return {3, ProjectIssue(id), {}};
    const auto bootId = BootId();
    LARGE_INTEGER frequency{};
    if (bootId.empty() || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
        return NativeFailure(L"boot-or-qpc-identity", ERROR_NOT_SUPPORTED, 5);
    }

    const Cancellation cancellation;
    project::SampleInfo sample; // Scope 借用其 ID，必须比采集所有者更晚释放。
    LoopbackCapture capture(pid, creation, handle, epoch, bootId, static_cast<std::uint64_t>(frequency.QuadPart));
    const wchar_t* stage = L"ETW";
    if (const auto status = capture.Arm(stage); status != ERROR_SUCCESS) {
        // 启动中途失败也可能已有 ETW 会话。先清退，再公布此次尝试的原生回执。
        capture.Stop();
        const bool clean = capture.Clean(); // ETW 资源是否均已回收，独立于启用结果。
        Result result{!clean || status == ERROR_ACCESS_DENIED ? 3 : 5, Json::object({
            {L"stage", Json::string(stage)}, {L"win32Error", Json::number(status)},
            {L"stopStatus", Json::number(capture.stopStatus)}, {L"closeStatus", Json::number(capture.closeStatus)},
            {L"cleanupConfirmed", Json::boolean(clean)}}), {}}; // 此时项目尚未创建采样。
        if (status == ERROR_ACCESS_DENIED) {
            result.diagnostics.push_back(L"Windows denied the scoped ETW operation for this process token.");
        }
        if (!clean) {
            result.diagnostics.push_back(L"The private ETW session did not confirm shutdown.");
        }
        return result;
    }

    const auto title = "Loopback network metadata (PID " + std::to_string(pid) + ")";
    if (const auto createdSample = document.CreateSample(title, sample, revision); !createdSample) {
        capture.Stop();
        return {3, Json::object({{L"projectError", ProjectIssue(createdSample)},
            {L"cleanupConfirmed", Json::boolean(capture.Clean())}}), {}};
    }
    const bool started = capture.Start(projectId, sample.sampleId, duration);
    const std::wstring reason = started ? capture.Wait(*cancellation.token) : L"source-not-started";
    capture.Stop();

    archive::NetworkEvidenceBinding source{storage::UuidBytes(projectId), storage::UuidBytes(sample.sampleId),
        std::string(kSource), storage::UuidBytes(epoch), epoch, bootId, archive::NetworkTimeDomain::Qpc,
        static_cast<std::uint64_t>(frequency.QuadPart)};
    archive::NetworkLoss loss;
    loss.sourceLost = capture.eventsLost.value_or(0);
    loss.sourceLossUnquantified = capture.buffersLost.value_or(0) != 0 || capture.bufferDrops ||
        capture.unsupportedLayouts || capture.callbackFailed.load() || capture.scopeViolation.load();
    const bool sourceFailed = !capture.Clean() || capture.processStatus != ERROR_SUCCESS || capture.callbackFailed.load() ||
        capture.scopeViolation.load() || reason == L"source-ended" || reason == L"target-wait-failed" ||
        reason == L"clock-unavailable";
    const auto end = sourceFailed ? archive::NetworkArchiveEnd::SourceFailed : !started ?
        archive::NetworkArchiveEnd::SourceUnavailable : archive::NetworkArchiveEnd::Stopped;
    project::ProjectNetworkEvidenceReceipt receipt;
    const auto archived = project::WriteInitialNetworkEvidence(document, sample.sampleId, source, capture.rows, loss,
        end, receipt);

    std::vector<Json> locators;
    locators.reserve(receipt.locations.size());
    for (const auto& location : receipt.locations) {
        locators.push_back(Json::object({{L"recordSequence", Json::count(location.sequence)},
            {L"recordOffset", Json::count(location.offset)}}));
    }
    const bool complete = started && archived && !sourceFailed && !loss.sourceLost &&
        !loss.sourceLossUnquantified && capture.eventsLost.has_value() && reason == L"duration-elapsed";
    return {complete ? 0 : archived && started ? 6 : 3, Json::object({
        {L"projectId", Json::string(storage::WideAscii(projectId))}, {L"sampleId", Json::string(storage::WideAscii(sample.sampleId))},
        {L"stream", Json::string(L"raw")}, {L"ordinal", Json::count(1)}, {L"segmentVerified", Json::boolean(static_cast<bool>(archived))},
        {L"pid", Json::number(pid)}, {L"creationFileTime", Json::count(creation)}, {L"durationMs", Json::number(duration)},
        {L"reason", Json::string(reason)}, {L"captureCoverage", Json::string(L"unknown")},
        {L"captureLayer", Json::string(L"flow-metadata")}, {L"capturedLength", Json::count(0)},
        {L"flowCount", Json::count(receipt.locations.size())},
        {L"eventsLost", capture.eventsLost ? Json::number(*capture.eventsLost) : Json{}},
        {L"realTimeBuffersLost", capture.buffersLost ? Json::number(*capture.buffersLost) : Json{}},
        {L"bufferDrops", Json::count(capture.bufferDrops)}, {L"unsupportedLayouts", Json::count(capture.unsupportedLayouts)},
        {L"nativePidFilterMismatch", Json::boolean(capture.scopeViolation.load())},
        {L"processTraceStatus", Json::number(capture.processStatus)}, {L"stopStatus", Json::number(capture.stopStatus)},
        {L"closeStatus", Json::number(capture.closeStatus)}, {L"cleanupConfirmed", Json::boolean(capture.Clean())},
        {L"archiveError", ProjectIssue(archived)}, {L"records", Json::array(locators)}}), {}};
}

} // namespace

void RegisterNetworkCaptureCommand()
{
    RegisterNetworkTrafficCommands(BootId); // 新正文采集与只读回放复用正式登记路径及启动身份读取器。
    Command command;
    command.path = L"analyze network-capture";
    command.syntax = L"KswordCLI.exe analyze network-capture --project PATH --pid PID --create-time FILETIME --duration-ms MS --authorize-loopback yes [--json]";
    command.summary = L"Archive authorized loopback network metadata for one process instance into a new project sample.";
    command.options = L"Use an existing project, the target PID and creation FILETIME, a duration of 100..60000 ms and --authorize-loopback yes.";
    command.notes = L"The private real-time ETW source requires scoped enablement. Returns record coordinates for archive.inspect network. Coverage is unknown and communication bytes are unavailable.";
    command.run = Run;
    addCommand(std::move(command));
}

} // namespace ks::cli::action_analyze
