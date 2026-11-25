#include "PassiveEtwSource.h"

#include <objbase.h>

#include <algorithm>
#include <cstring>
#include <type_traits>
#include <utility>

#pragma comment(lib, "Ole32.lib")

namespace ks::r3::monitor {
namespace {

constexpr std::uint16_t kRead = 15;                  // Kernel-File Read。
constexpr std::uint16_t kWrite = 16;                 // Kernel-File Write。
constexpr std::uint16_t kOperationEnd = 24;          // Kernel-File OperationEnd。
constexpr std::size_t kExtendedItemsToScan = 32;     // 仅检查前 32 个扩展项的关联活动。

// 把原生 GUID 转为规范的小写形式，失败返回空字符串。
std::string CanonicalGuid(const GUID& guid)
{
    const auto guidText = GuidToString(guid); // 共享格式化入口返回大写带括号的 GUID。
    if (guidText.size() != 38) {
        return {};
    }
    std::string value; // 归档使用的小写无括号表示。
    value.reserve(36);
    for (std::size_t i = 1; i + 1 < guidText.size(); ++i) {
        const auto ch = guidText[i]; // GUID 字符在 ASCII 范围内无损转换。
        value.push_back(static_cast<char>(ch >= L'A' && ch <= L'F' ? ch + (L'a' - L'A') : ch));
    }
    return value;
}

// 创建本端实际拥有的新来源代次。失败返回空串。
std::string NewEpoch()
{
    GUID guid{}; // 新生成的代次身份。
    return SUCCEEDED(CoCreateGuid(&guid)) ? CanonicalGuid(guid) : std::string{};
}

// 只按原生 Enable 状态判定不可用。启用成功而零事件时仍保留未知生产者状态。
PassiveEtwState EnableFailure(ULONG status)
{
    if (status == ERROR_ACCESS_DENIED) {
        return PassiveEtwState::AccessDenied;
    }
    if (status == ERROR_WMI_GUID_NOT_FOUND || status == ERROR_NOT_FOUND ||
        status == ERROR_FILE_NOT_FOUND || status == ERROR_NOT_SUPPORTED) {
        return PassiveEtwState::ProviderUnavailable;
    }
    return PassiveEtwState::Failed;
}

// 从本次源的控制阶段与原生回执计算状态。
PassiveEtwState SessionState(const EtwSessionEvidence& native, bool running, bool stopped)
{
    if (native.startStatus == ERROR_ACCESS_DENIED || native.openStatus == ERROR_ACCESS_DENIED ||
        native.processStatus == ERROR_ACCESS_DENIED) {
        return PassiveEtwState::AccessDenied;
    }
    if (native.startAttempted && !native.startSucceeded) {
        return PassiveEtwState::Failed;
    }
    if (!native.providers.empty() && native.providers.front().status != ERROR_SUCCESS) {
        return EnableFailure(native.providers.front().status);
    }
    if (native.threadStartFailed || native.callbackFailed ||
        (native.openAttempted && native.openStatus != ERROR_SUCCESS)) {
        return PassiveEtwState::Failed;
    }
    if (native.tailDeliveryUnconfirmed ||
        (native.processCompleted && native.processStatus != ERROR_SUCCESS)) {
        return PassiveEtwState::Failed;
    }
    if (stopped) {
        return PassiveEtwState::Stopped;
    }
    if (native.processCompleted || !running) {
        return PassiveEtwState::Failed;
    }
    // Running admits a producer once dispatch is committed. Native callbacks and
    // the terminal result provide the separate evidence for delivery coverage.
    return native.processAttempted ? PassiveEtwState::Running : PassiveEtwState::Starting;
}

// 已确认总长度后按小端读取无符号整数。ETW 负载不保证自然对齐。
template <typename T>
T ReadLittleEndian(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    static_assert(std::is_unsigned_v<T> && sizeof(T) <= sizeof(std::uint64_t));
    std::uint64_t value = 0; // 移位累加先在 u64 中进行。
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
    }
    return static_cast<T>(value);
}

// 只接受自描述头给出的明确 32/64 位。冲突或缺失时保持未知。
std::size_t PointerBytes(std::uint16_t flags)
{
    const bool bits32 = (flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0; // 生产者头部标记。
    const bool bits64 = (flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0; // 生产者头部标记。
    if (bits32 == bits64) {
        return 0;
    }
    return bits32 ? 4 : 8;
}

// 在已验证范围内读取一个指针字段，只返回数值线索，不解引用。
std::uint64_t ReadPointer(const PassiveEtwRecord& record, std::size_t offset, std::size_t pointerBytes)
{
    if (pointerBytes == 4) {
        return ReadLittleEndian<std::uint32_t>(record.payloadPrefix, offset);
    }
    return ReadLittleEndian<std::uint64_t>(record.payloadPrefix, offset);
}

// 只复制类型与长度明确的关联活动。扩展负载有单独预算，不读取未知项。
std::optional<GUID> CopyRelatedActivity(const EVENT_RECORD& record)
{
    if (!record.ExtendedData || record.ExtendedDataCount > kExtendedItemsToScan) {
        return std::nullopt;
    }
    std::optional<GUID> related; // 该条观察唯一的有效关联活动。
    for (std::size_t i = 0; i < record.ExtendedDataCount; ++i) {
        const auto& item = record.ExtendedData[i]; // 仅在回调期间借用扩展项。
        if (item.ExtType != EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID) {
            continue;
        }
        if (related || item.DataSize != sizeof(GUID) || !item.DataPtr) {
            return std::nullopt;
        }
        GUID value{}; // 关联 ID 独立于头部 ActivityId。
        std::memcpy(&value, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(item.DataPtr)), sizeof(value));
        related = value;
    }
    return related;
}

} // namespace

PassiveEtwRecord CopyPassiveEtwRecord(const EVENT_RECORD& record, std::size_t maxPayloadBytes,
    std::optional<std::uint64_t> receivedQpc, std::uint64_t qpcFrequencyHz)
{
    const auto& header = record.EventHeader; // 回调借用的头部。
    const auto& descriptor = header.EventDescriptor; // 原生描述符的原值。
    PassiveEtwRecord result; // 所有字段在返回前完成复制。
    result.provider = header.ProviderId;
    result.descriptor = {descriptor.Id, descriptor.Version, descriptor.Channel, descriptor.Level,
        descriptor.Opcode, descriptor.Task, descriptor.Keyword};
    result.headerFlags = header.Flags;
    result.headerPid = header.ProcessId;
    result.headerTid = header.ThreadId;
    result.sourceFileTime100ns = static_cast<std::uint64_t>(header.TimeStamp.QuadPart);

    // 时钟、活动与扩展项均与报头 PID/TID 各自独立。
    if (receivedQpc && qpcFrequencyHz) {
        result.receivedQpc = receivedQpc;
        result.qpcFrequencyHz = qpcFrequencyHz;
    }
    result.activityId = header.ActivityId;
    result.relatedActivityId = CopyRelatedActivity(record);
    result.extendedDataCount = record.ExtendedDataCount;
    result.originalPayloadBytes = record.UserDataLength;
    result.malformedPayload = record.UserDataLength != 0 && !record.UserData;

    // 只复制回调借用字节中满足上限的前缀，空指针不参与地址运算。
    const auto count = (std::min)({maxPayloadBytes, kPassiveEtwMaxPayloadBytes,
        static_cast<std::size_t>(record.UserDataLength)}); // 实际可采字节数。
    if (count && record.UserData) {
        const auto* bytes = static_cast<const std::uint8_t*>(record.UserData); // 当前借用的负载首字节。
        result.payloadPrefix.assign(bytes, bytes + count);
    }
    return result;
}

PassiveKernelFileDecode DecodePassiveKernelFileRecord(const PassiveEtwRecord& record)
{
    PassiveKernelFileDecode decoded; // 默认只交付原始记录。
    if (!IsEqualGUID(record.provider, kKernelFileProviderGuid)) {
        return decoded;
    }
    const auto& d = record.descriptor; // 布局身份来自原生描述符，不用显示名猜测。
    if (d.id != kRead && d.id != kWrite && d.id != kOperationEnd) {
        return decoded;
    }
    const bool completion = d.id == kOperationEnd; // 完成布局与请求独立。
    const auto pointerBytes = PointerBytes(record.headerFlags); // 布局声明给出的指针宽度。
    constexpr auto incompatibleFlags = EVENT_HEADER_FLAG_CLASSIC_HEADER |
        EVENT_HEADER_FLAG_TRACE_MESSAGE | EVENT_HEADER_FLAG_STRING_ONLY; // 排除其它 ETW 编码。
    if (!pointerBytes || (record.headerFlags & incompatibleFlags) || d.task != d.id ||
        d.channel != 16 || d.level != TRACE_LEVEL_INFORMATION || d.opcode != 0 ||
        (completion ? d.version != 0 : d.version > 1)) {
        decoded.status = PassiveEtwDecodeStatus::UnsupportedLayout;
        return decoded;
    }

    // Windows manifest 的 Read/Write v0/v1 与 OperationEnd v0 定长模板。
    const auto expected = completion ? 2 * pointerBytes + 4 :
        (d.version == 0 ? 16 + 4 * pointerBytes : 24 + 3 * pointerBytes); // 模板总负载字节数。
    if (record.malformedPayload || record.originalPayloadBytes != expected || record.payloadPrefix.size() > expected) {
        decoded.status = PassiveEtwDecodeStatus::Malformed;
        return decoded;
    }
    if (record.payloadPrefix.size() < expected) {
        decoded.status = PassiveEtwDecodeStatus::Truncated;
        return decoded;
    }

    // v0 的 ThreadId 指针字段没有线程实例证明，保留在原始负载中。
    decoded.status = PassiveEtwDecodeStatus::Decoded;
    if (completion) {
        decoded.kind = KernelFileObservationKind::OperationEnd;
        decoded.irp = ReadPointer(record, 0, pointerBytes);
        decoded.ntStatus = ReadLittleEndian<std::uint32_t>(record.payloadPrefix, 2 * pointerBytes);
        return decoded;
    }
    decoded.kind = d.id == kRead ? KernelFileObservationKind::ReadRequest : KernelFileObservationKind::WriteRequest;
    decoded.byteOffset = ReadLittleEndian<std::uint64_t>(record.payloadPrefix, 0);
    decoded.irp = ReadPointer(record, 8, pointerBytes);
    const auto fileObjectOffset = 8 + (d.version == 0 ? 2 : 1) * pointerBytes; // v0 跳过 ThreadId。
    decoded.fileObject = ReadPointer(record, fileObjectOffset, pointerBytes);
    decoded.fileKey = ReadPointer(record, fileObjectOffset + pointerBytes, pointerBytes);
    const auto afterPointers = fileObjectOffset + 2 * pointerBytes; // 后续字段均为 u32。
    if (d.version == 1) {
        decoded.issuingThreadId = ReadLittleEndian<std::uint32_t>(record.payloadPrefix, afterPointers);
    }
    decoded.requestedBytes = ReadLittleEndian<std::uint32_t>(record.payloadPrefix,
        afterPointers + (d.version == 1 ? 4 : 0));
    return decoded;
}

KernelFileProjection ProjectPassiveKernelFileRecord(const PassiveEtwRecord& record,
    const KernelFileSourceView& source, std::string_view receiveClockId)
{
    using Status = KernelFileProjectionStatus;
    if (!IsEqualGUID(record.provider, kKernelFileProviderGuid)) {
        return {Status::UnsupportedProvider, std::nullopt};
    }
    if (!record.sourceEpoch.empty() && record.sourceEpoch != source.sourceEpoch) {
        return {Status::InvalidSource, std::nullopt};
    }
    const auto decoded = DecodePassiveKernelFileRecord(record); // 可信模板或显式原始回退状态。
    switch (decoded.status) {
    case PassiveEtwDecodeStatus::Decoded: break;
    case PassiveEtwDecodeStatus::Truncated: return {Status::TruncatedPayload, std::nullopt};
    case PassiveEtwDecodeStatus::Malformed: return {Status::MalformedPayload, std::nullopt};
    default: return {Status::UnsupportedEvent, std::nullopt};
    }

    // 投影接口只借用本次记录，返回的原始及规范字段各自拥有内存。
    const auto activity = CanonicalGuid(record.activityId); // 头部活动，保留零 GUID。
    const auto related = record.relatedActivityId ? CanonicalGuid(*record.relatedActivityId) : std::string{};
    KernelFileObservationView view; // 已验证的单条记录字段视图。
    view.providerId = kKernelFileProviderId;
    view.source = source;
    view.descriptor = record.descriptor;
    view.sourceFileTime100ns = record.sourceFileTime100ns;
    view.headerPid = record.headerPid;
    view.headerTid = record.headerTid;
    view.originalPayloadBytes = record.originalPayloadBytes;
    view.payloadPrefix = record.payloadPrefix;
    view.irp = decoded.irp;
    view.fileObject = decoded.fileObject;
    view.fileKey = decoded.fileKey;
    view.byteOffset = decoded.byteOffset;
    view.requestedBytes = decoded.requestedBytes;
    view.ntStatus = decoded.ntStatus;
    view.issuingThreadId = decoded.issuingThreadId;
    view.headerFlags = record.headerFlags;
    view.extendedDataCount = record.extendedDataCount;
    view.activityId = activity;
    if (!related.empty()) {
        view.relatedActivityId = related;
    }
    if (record.receivedQpc) {
        view.receiveQpc = KernelFileReceiveQpcView{receiveClockId, *record.receivedQpc, record.qpcFrequencyHz};
    }
    return ProjectKernelFileObservation(view);
}

PassiveEtwSource::PassiveEtwSource()
{
    controller_.setNativeRecordCallback([this](const EVENT_RECORD& record) {
        accept(record);
    });
}

PassiveEtwSource::~PassiveEtwSource() = default;

bool PassiveEtwSource::start(const PassiveEtwOptions& options)
{
    const std::lock_guard lifecycle(lifecycleMutex_); // 本次启动独占原生会话控制。
    {
        const std::lock_guard lock(dataMutex_); // 有未提交的旧接纳记录时保留原代次。
        if (!queue_.empty() || controller_.cleanupPending() || controller_.running()) {
            return false;
        }
        counts_ = {};
        nativeAttempted_ = false;
        stopRequested_ = false;
        stopInFlight_ = false;
        cleanupFailed_ = false;

        // 输入预算为各端在调用点冻结，不允许隐式扩大采样范围。
        if (IsEqualGUID(options.provider, GUID{}) || options.maxPayloadBytes > kPassiveEtwMaxPayloadBytes ||
            options.maxQueuedRecords == 0 || options.maxQueuedRecords > kPassiveEtwMaxQueuedRecords ||
            options.maxQueuedRecords * options.maxPayloadBytes > kPassiveEtwMaxQueuedPayloadBytes) {
            counts_.inputError = ERROR_INVALID_PARAMETER;
            return false;
        }
        counts_.sourceEpoch = NewEpoch();
        if (counts_.sourceEpoch.empty()) {
            counts_.inputError = ERROR_GEN_FAILURE;
            return false;
        }
        LARGE_INTEGER frequency{}; // 接收时钟校准，失败时记录仍可使用 FILETIME。
        frequencyHz_ = QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0 ?
            static_cast<std::uint64_t>(frequency.QuadPart) : 0;
        options_ = options;
        counts_.state = PassiveEtwState::Starting;
    }

    // 既有控制器管理原生 ETW 会话，逐条原生报头范围由本源记录抑制计数。
    EtwFilterState filter; // 只订阅本次选定的 provider。
    filter.minimumLevel = 0;
    filter.providers.push_back({GuidToString(options.provider), options.provider, true,
        options.level, options.matchAnyKeyword});
    const bool started = controller_.start(filter); // 打开消费上下文在原生线程中进行。
    const std::lock_guard lock(dataMutex_); // 将本次原生回执交给状态查询。
    nativeAttempted_ = true;
    cleanupFailed_ = !started && controller_.cleanupPending();
    return started;
}

bool PassiveEtwSource::stop()
{
    const std::lock_guard lifecycle(lifecycleMutex_); // 与启动及重复恢复串行。
    {
        const std::lock_guard lock(dataMutex_); // 立即发布清退状态，同时允许回调排空。
        if (!nativeAttempted_) {
            return true;
        }
        stopRequested_ = true;
        stopInFlight_ = true;
    }
    const bool stopped = controller_.stopChecked(); // 原生 STOP、消费尾部及资源清理回执。
    const std::lock_guard lock(dataMutex_); // 完成后才发布终态。
    stopInFlight_ = false;
    cleanupFailed_ = !stopped;
    return stopped;
}

std::vector<PassiveEtwRecord> PassiveEtwSource::drain(std::size_t maxRecords)
{
    const std::lock_guard lock(dataMutex_); // 与消费线程的入队互斥。
    std::vector<PassiveEtwRecord> batch; // 返回拥有内存的队首片段。
    const auto count = (std::min)(maxRecords, queue_.size()); // 实际可移出的条数。
    batch.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        batch.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    return batch;
}

PassiveEtwStatus PassiveEtwSource::status() const
{
    const std::lock_guard lock(dataMutex_); // 同步本端计数和当前队列深度。
    auto result = counts_; // 返回给宿主的只读状态副本。
    result.queued = queue_.size();
    if (result.inputError != ERROR_SUCCESS) {
        result.state = PassiveEtwState::Failed;
    } else if (nativeAttempted_) {
        result.native = controller_.evidence();
        if (stopInFlight_) {
            result.state = PassiveEtwState::Stopping;
        } else if (cleanupFailed_) {
            result.state = PassiveEtwState::CleanupPending;
        } else {
            result.state = SessionState(result.native, controller_.running(), stopRequested_);
        }
    }
    return result;
}

void PassiveEtwSource::accept(const EVENT_RECORD& record)
{
    LARGE_INTEGER qpc{}; // 在等待队列锁之前读取本端接收时钟。
    const bool hasQpc = QueryPerformanceCounter(&qpc) && qpc.QuadPart >= 0; // 零刻度有效。
    const std::lock_guard lock(dataMutex_); // 同步队列边界与计数。
    if (!IsEqualGUID(record.EventHeader.ProviderId, options_.provider)) {
        return;
    }
    ++counts_.providerEvents;
    if (options_.headerPid && record.EventHeader.ProcessId != *options_.headerPid) {
        ++counts_.headerFiltered;
        return;
    }
    if (queue_.size() >= options_.maxQueuedRecords) {
        ++counts_.queueDropped;
        return;
    }

    // 回调结束后 Windows 可以重用原负载缓冲区，队列只持有独立值。
    const auto ticks = hasQpc ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(qpc.QuadPart)) :
        std::nullopt; // 实测单调刻度，失败保持缺失。
    auto copy = CopyPassiveEtwRecord(record, options_.maxPayloadBytes, ticks, frequencyHz_); // 拥有负载的队列值。
    copy.sourceEpoch = counts_.sourceEpoch;
    queue_.push_back(std::move(copy));
    const auto& queued = queue_.back(); // 刚迁入队列的完整证据值。
    ++counts_.enqueued;
    if (queued.malformedPayload) {
        ++counts_.malformedPayload;
    } else if (queued.payloadPrefix.size() < queued.originalPayloadBytes) {
        ++counts_.payloadTruncated;
    }
}

} // namespace ks::r3::monitor
