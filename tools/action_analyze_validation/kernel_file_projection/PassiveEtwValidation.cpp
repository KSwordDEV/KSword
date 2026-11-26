#include "../../../shared/usermode/backend/monitor/PassiveEtwSource.h"

#include <evntprov.h>

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {

namespace M = ks::r3::monitor;
using State = M::PassiveEtwState;
using Decode = M::PassiveEtwDecodeStatus;
using namespace std::chrono_literals;

constexpr GUID kFixtureProvider{0x5f169cb9, 0xfef5, 0x4242, {0x83, 0x31, 0x9c, 0xaa, 0x49, 0xff, 0x69, 0x9b}};
constexpr GUID kUnregisteredProvider{0xd2cfdaee, 0x45f3, 0x48a0, {0xb2, 0x32, 0x4b, 0xbf, 0xbf, 0xa2, 0x31, 0x84}};
unsigned checks = 0; // 已通过的断言数。

// 首个失败时返回准确的用例标签，成功时累加断言数。
void Check(bool passed, const char* label)
{
    if (!passed) {
        throw std::runtime_error(label);
    }
    ++checks;
}

// 产生经过钉死的大小端向量，可在两种事件头部位宽下运行。
void Append(std::vector<std::uint8_t>& bytes, std::size_t width, std::uint64_t value)
{
    for (std::size_t i = 0; i < width; ++i) {
        bytes.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
    }
}

// 按本机 Windows manifest 形状构造受控的 ETW 负载，返回拥有自己的值。
M::PassiveEtwRecord FileVector(std::uint16_t id, std::uint8_t version, std::size_t pointerBytes)
{
    std::vector<std::uint8_t> payload; // 按原生字段声明顺序序列化。
    if (id == 24) {
        Append(payload, pointerBytes, 0x26);
        Append(payload, pointerBytes, 0x40);
        Append(payload, 4, 0xc0000022);
    } else {
        Append(payload, 8, 0x0123456789abcdef);
        Append(payload, pointerBytes, 0x26);
        if (version == 0) {
            Append(payload, pointerBytes, 0xcafe);
        }
        Append(payload, pointerBytes, 0x11);
        Append(payload, pointerBytes, 0xffffffff12348765);
        if (version == 1) {
            Append(payload, 4, 0xffff0000);
        }
        Append(payload, 4, 0);
        Append(payload, 4, 0);
        if (version == 1) {
            Append(payload, 4, 0);
        }
    }

    EVENT_HEADER_EXTENDED_DATA_ITEM related{}; // 扩展关联活动来自另一份输入字节。
    GUID relatedId = kUnregisteredProvider; // 用于验证复制并与头部活动相区分。
    related.ExtType = EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID;
    related.DataSize = sizeof(relatedId);
    related.DataPtr = reinterpret_cast<ULONG_PTR>(&relatedId);
    EVENT_RECORD native{}; // 短期借用的 ETW 回调表示。
    native.EventHeader.ProviderId = M::kKernelFileProviderGuid;
    native.EventHeader.Flags = pointerBytes == 8 ? EVENT_HEADER_FLAG_64_BIT_HEADER : EVENT_HEADER_FLAG_32_BIT_HEADER;
    native.EventHeader.EventDescriptor = {id, version, 16, TRACE_LEVEL_INFORMATION, 0, id, 0x8000000000000000};
    native.EventHeader.ProcessId = 19;
    native.EventHeader.ThreadId = 77;
    native.EventHeader.TimeStamp.QuadPart = 134084736000000017;
    native.EventHeader.ActivityId = kFixtureProvider;
    native.ExtendedData = &related;
    native.ExtendedDataCount = 1;
    native.UserData = payload.data();
    native.UserDataLength = static_cast<USHORT>(payload.size());
    return M::CopyPassiveEtwRecord(native, 512, 0, 10'000'000);
}

// 覆盖每个已登记描述符和位宽，验证全部字段来源与未知布局回退。
void ValidateVectors()
{
    for (const std::size_t pointerBytes : {4U, 8U}) {
        for (const std::uint16_t id : std::array<std::uint16_t, 3>{15, 16, 24}) {
            for (std::uint8_t version = 0; version <= (id == 24 ? 0 : 1); ++version) {
                const auto copy = FileVector(id, version, pointerBytes); // 原借用的栈与向量已经销毁。
                const auto parsed = M::DecodePassiveKernelFileRecord(copy); // 精确模板解码。
                Check(parsed.status == Decode::Decoded && parsed.kind.has_value(), "Known ETW layout");
                Check(copy.relatedActivityId && IsEqualGUID(*copy.relatedActivityId, kUnregisteredProvider) &&
                    IsEqualGUID(copy.activityId, kFixtureProvider), "Independent copied activity IDs");
                Check(copy.headerPid == 19 && copy.headerTid == 77 && copy.receivedQpc == 0ULL &&
                    copy.qpcFrequencyHz == 10'000'000, "Header context and receive clock");
                Check(parsed.irp == 0x26ULL && copy.originalPayloadBytes == copy.payloadPrefix.size(), "IRP and complete raw payload");
                if (id == 24) {
                    Check(parsed.kind == M::KernelFileObservationKind::OperationEnd && parsed.ntStatus == 0xc0000022 &&
                        !parsed.requestedBytes && !parsed.issuingThreadId, "Completion only fields");
                } else {
                    Check(parsed.kind == (id == 15 ? M::KernelFileObservationKind::ReadRequest : M::KernelFileObservationKind::WriteRequest),
                        "Read/write exact event kind");
                    Check(parsed.fileObject == 0x11ULL && parsed.fileKey == (pointerBytes == 8 ? 0xffffffff12348765ULL : 0x12348765ULL),
                        "Pointer width and offsets");
                    Check(parsed.requestedBytes == 0U && parsed.byteOffset == 0x0123456789abcdefULL && !parsed.ntStatus,
                        "Request only fields and known zero");
                    Check(version == 1 ? parsed.issuingThreadId == 0xffff0000 : !parsed.issuingThreadId,
                        "Payload issuing thread separate from report context");
                }

                const auto projected = M::ProjectPassiveKernelFileRecord(copy,
                    {"fixture", "d55b5f45-8f35-4cea-83c4-c74c188daae2", "known-test-boot", "filetime"}, "qpc");
                Check(projected.status == M::KernelFileProjectionStatus::Ok && projected.evidence &&
                    projected.evidence->raw.inlineBytes == copy.payloadPrefix, "Native projection retains independently owned bytes");
                const auto& metadata = projected.evidence->raw.metadata; // 离线解码的原生上下文。
                Check(metadata.find("headerFlags") && metadata.find("activityId") && metadata.find("relatedActivityId") &&
                    metadata.find("extendedDataCount"), "Projection retains native width and activity metadata");
                const auto& fields = projected.evidence->canonical.fields; // 仅基础目录中的事实。
                Check(fields.asObject()->size() == 4 && fields.find("source.headerTid"), "No invented actor, target or sequence");
            }
        }
    }

    // 错误来源和未来布局保持原始记录。真实数据不完整时禁止部分猜字段。
    auto base = FileVector(15, 1, 8); // 可覆盖精确位置的已知向量。
    base.provider = kFixtureProvider;
    Check(M::DecodePassiveKernelFileRecord(base).status == Decode::RawOnly, "Foreign provider raw only");
    base = FileVector(15, 1, 8);
    base.descriptor.version = 2;
    Check(M::DecodePassiveKernelFileRecord(base).status == Decode::UnsupportedLayout, "Future version");
    base = FileVector(15, 1, 8);
    base.descriptor.opcode = 1;
    Check(M::DecodePassiveKernelFileRecord(base).status == Decode::UnsupportedLayout, "Conflicting opcode");
    base = FileVector(15, 1, 8);
    base.headerFlags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
    Check(M::DecodePassiveKernelFileRecord(base).status == Decode::UnsupportedLayout, "Conflicting width");
    base = FileVector(15, 1, 8);
    base.payloadPrefix.pop_back();
    Check(M::DecodePassiveKernelFileRecord(base).status == Decode::Truncated, "Budget truncation");
    --base.originalPayloadBytes;
    Check(M::DecodePassiveKernelFileRecord(base).status == Decode::Malformed, "Native length mismatch");
    base = FileVector(15, 1, 8);
    base.sourceEpoch = "ee001603-bec3-4999-990f-44114dddcf7f";
    Check(M::ProjectPassiveKernelFileRecord(base,
        {"fixture", "d55b5f45-8f35-4cea-83c4-c74c188daae2", "known-test-boot", "filetime"}, "qpc").status ==
        M::KernelFileProjectionStatus::InvalidSource, "Source epoch cannot be rebound after draining");

    EVENT_RECORD empty{}; // 指针缺失负控，无效长度保留供诊断。
    empty.UserDataLength = 2;
    const auto malformed = M::CopyPassiveEtwRecord(empty, 100); // 不读取不存在的指针。
    Check(malformed.malformedPayload && malformed.payloadPrefix.empty() && malformed.originalPayloadBytes == 2,
        "Malformed native payload view");
    M::PassiveEtwSource source; // 明确区分输入失败与 Windows 权限。
    Check(source.status().state == State::Idle && !source.start({}) &&
        source.status().inputError == ERROR_INVALID_PARAMETER && source.stop(), "Invalid source options");
}

// 最多等待五秒让实时消费完成回调交付，提前终止时保留原生回执。
template<typename Predicate>
auto WaitFor(M::PassiveEtwSource& source, Predicate done)
{
    const auto deadline = std::chrono::steady_clock::now() + 5s; // 本测试的等待上限。
    auto state = source.status(); // 最新权威原生状态。
    while (!done(state) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
        state = source.status();
    }
    return state;
}

// 输出单个原生会话的可复查错误和接纳计数，不输出其它进程的负载。
void PrintNative(const char* label, const M::PassiveEtwStatus& status)
{
    const auto& n = status.native; // Windows 的实际阶段结果。
    std::cout << label << " start=" << n.startStatus << " enable=";
    if (n.providers.empty()) {
        std::cout << "unattempted";
    } else {
        std::cout << n.providers.front().status;
    }
    std::cout << " openAttempted=" << n.openAttempted << " open=" << n.openStatus
        << " processAttempted=" << n.processAttempted << " observed=" << status.providerEvents
        << " enqueued=" << status.enqueued << " queueDropped=" << status.queueDropped
        << " statisticsKnown=" << n.statisticsKnown << " systemEventsLost=" << n.eventsLost
        << " realTimeBuffersLost=" << n.realTimeBuffersLost << '\n';
}

// 仅注册本夹具自己的 provider 并发送受控的八字节负载。
void ValidateOwnProvider()
{
    struct Registration {
        REGHANDLE value = 0; // 本测试注册的唯一 provider。
        ~Registration() { if (value) EventUnregister(value); }
    } provider;
    Check(EventRegister(&kFixtureProvider, nullptr, nullptr, &provider.value) == ERROR_SUCCESS, "Register own ETW provider");

    M::PassiveEtwSource source; // 使用与产品相同的 Windows ETW 控制器。
    M::PassiveEtwOptions options; // 故意选择一条队列和三字节上限。
    options.provider = kFixtureProvider;
    options.headerPid = GetCurrentProcessId();
    options.maxPayloadBytes = 3;
    options.maxQueuedRecords = 1;
    const bool started = source.start(options); // 同一进程既生产又消费受控数据。
    auto status = WaitFor(source, [](const auto& value) { return value.state != State::Starting; });
    if (status.state == State::AccessDenied) {
        Check(status.native.startStatus == 5 || status.native.openStatus == 5 || status.native.processStatus == 5 ||
            (!status.native.providers.empty() && status.native.providers.front().status == 5), "Exact access denied status");
        Check(source.stop(), "Retire after access denied");
        PrintNative("own-provider ACCESS_DENIED", status);
        return;
    }
    Check(started && status.state == State::Running && status.native.processAttempted && status.providerEvents == 0,
        "Consumer ready before first observation");
    const auto epoch = status.sourceEpoch; // 保存以验证下一次启动改代次。
    const EVENT_DESCRIPTOR descriptor{41, 3, 0, TRACE_LEVEL_INFORMATION, 0, 0, 0}; // 自有描述符。
    const std::array<std::uint8_t, 8> bytes{0x11, 0xa2, 0x00, 4, 5, 6, 7, 8}; // 固定无敏感数据。
    EVENT_DATA_DESCRIPTOR data{}; // EventWrite 的同步数据视图。
    EventDataDescCreate(&data, bytes.data(), static_cast<ULONG>(bytes.size()));
    for (int i = 0; i < 3; ++i) {
        Check(EventWrite(provider.value, &descriptor, 1, &data) == ERROR_SUCCESS, "Emit own provider event");
    }
    status = WaitFor(source, [](const auto& value) { return value.providerEvents >= 3; });
    Check(status.enqueued == 1 && status.queueDropped == 2 && status.payloadTruncated == 1 && status.queued == 1,
        "Live queue drop and prefix limit are independent");
    Check(source.stop() && source.status().state == State::Stopped, "Retire and drain same session");
    Check(!source.start(options), "Pending records preserve source generation");
    const auto batch = source.drain(10); // 已停止后仍可消费旧代次的数据。
    Check(batch.size() == 1 && batch.front().sourceEpoch == epoch &&
        batch.front().descriptor.id == 41 && batch.front().descriptor.version == 3 &&
        batch.front().headerPid == GetCurrentProcessId() && batch.front().receivedQpc &&
        batch.front().payloadPrefix == std::vector<std::uint8_t>{0x11, 0xa2, 0x00} &&
        batch.front().originalPayloadBytes == bytes.size(), "Real callback owned exact payload prefix");
    PrintNative("own-provider", source.status());
    options.headerPid = 0; // 明确的零 PID，不能被解释成取消过滤。
    Check(source.start(options) && source.status().sourceEpoch != epoch, "New epoch after draining");
    status = WaitFor(source, [](const auto& value) { return value.state != State::Starting; });
    Check(status.state == State::Running, "Second consumer ready");
    Check(EventWrite(provider.value, &descriptor, 1, &data) == ERROR_SUCCESS, "Emit outside header filter");
    status = WaitFor(source, [](const auto& value) { return value.providerEvents > 0; });
    Check(status.headerFiltered == 1 && status.enqueued == 0 && status.queueDropped == 0, "Header filter suppression is not loss");
    Check(source.stop(), "Retire second generation");
}

// 尝试实际 provider，不因未知 GUID 被 ETW 接受就宣称它在生产事件。
void ValidateProviderStatus(const GUID& guid, const char* label)
{
    M::PassiveEtwSource source; // 每个用例独占生命周期和统计。
    M::PassiveEtwOptions options; // 报头过滤仅准入自有进程。
    options.provider = guid;
    options.headerPid = GetCurrentProcessId();
    const bool started = source.start(options); // 记录实际权限和消费阶段回执。
    const auto status = WaitFor(source, [](const auto& value) { return value.state != State::Starting; });
    Check((started && status.state == State::Running) || status.state == State::AccessDenied ||
        status.state == State::ProviderUnavailable, "Provider receipt has explicit state");
    if (IsEqualGUID(guid, kUnregisteredProvider)) {
        Check(status.providerEvents == 0 && status.enqueued == 0, "Unknown producer does not imply event coverage");
    }
    if (status.state == State::AccessDenied && status.native.startSucceeded && !status.native.providers.empty() &&
        status.native.providers.front().status == ERROR_ACCESS_DENIED) {
        Check(!status.native.openAttempted, "Enable access denied occurs before OpenTrace");
    }
    Check(source.stop(), "Provider session cleaned up");
    PrintNative(label, source.status());
}

} // namespace

// 运行独立的 ETW 来源回归，受控实时会话由调用方显式开启。
void ValidatePassiveEtw(bool live)
{
    ValidateVectors();
    if (live) {
        ValidateOwnProvider();
        ValidateProviderStatus(kUnregisteredProvider, "unregistered-provider");
        ValidateProviderStatus(M::kKernelFileProviderGuid, "kernel-file");
    }
    std::cout << "Passive ETW checks passed: " << checks << '\n';
}
