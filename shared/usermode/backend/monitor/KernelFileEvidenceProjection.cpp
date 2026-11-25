#include "KernelFileEvidenceProjection.h"

#include <utility>

namespace ks::r3::monitor {
namespace {

using Ksword::Evidence::JsonObject;
using Ksword::Evidence::JsonValue;
using Ksword::Evidence::U64Format;
using Kind = KernelFileObservationKind;
using Status = KernelFileProjectionStatus;

// 这三个常量是 Kernel-File manifest 的 ETW ID，作用域限于该 provider。
constexpr std::uint16_t kRead = 15;
constexpr std::uint16_t kWrite = 16;
constexpr std::uint16_t kOperationEnd = 24;
constexpr std::size_t kMaxTextBytes = 64U * 1024U; // Stored v1 单字符串界限。

// 根据原生事件 ID 分类。冲突的已知任务不得作为请求/完成证据。
std::optional<Kind> Classify(const KernelFileDescriptor& descriptor)
{
    const auto task = descriptor.task; // 与 ID 独立保留的原生任务值。
    if ((task == kRead || task == kWrite || task == kOperationEnd) && task != descriptor.id) {
        return std::nullopt;
    }
    switch (descriptor.id) {
    case kRead: return Kind::ReadRequest;
    case kWrite: return Kind::WriteRequest;
    case kOperationEnd: return Kind::OperationEnd;
    default: return std::nullopt;
    }
}

// 校验归档文本的 UTF-8 标量和字节界限。嵌入 NUL 不是有效的路径或时钟标识。
bool IsArchiveText(std::string_view text)
{
    if (text.size() > kMaxTextBytes) {
        return false;
    }
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i++]); // 当前标量的首字节。
        if (first == 0) return false;
        if (first < 0x80) continue;
        if (first < 0xc2 || first > 0xf4) return false;

        const auto extra = first < 0xe0 ? 1U : (first < 0xf0 ? 2U : 3U); // 后续字节数。
        if (extra > text.size() - i) return false;
        const auto second = static_cast<unsigned char>(text[i]); // 用于限制标量取值域。
        if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0) ||
            (first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90)) {
            return false;
        }
        for (unsigned j = 0; j < extra; ++j) {
            if ((static_cast<unsigned char>(text[i++]) & 0xc0) != 0x80) return false;
        }
    }
    return true;
}

// 按 A0 UUID 字符规则验证观察代次。
bool IsCanonicalUuid(std::string_view value)
{
    if (value.size() != 36) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i]; // 对应位置的 UUID 字符。
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (ch != '-') return false;
        } else if (!(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f')) {
            return false;
        }
    }
    return true;
}

// 非空的归档来源标识保留调用方给出的文本。
bool IsSourceIdentifier(std::string_view value)
{
    return !value.empty() && IsArchiveText(value);
}

// 为 JSON 输出持有一份 UTF-8 字符串。
JsonValue Text(std::string_view value)
{
    return JsonValue::makeString(std::string(value));
}

// 用十进制字符串保存 u64 的全部精度。
JsonValue U64(std::uint64_t value)
{
    return JsonValue::makeU64Text(value, U64Format::Decimal);
}

// 给已知标量生成基础契约的 FieldValue，保留数值零。
JsonValue Known(std::string_view type, JsonValue value)
{
    return JsonValue::makeObject({
        {"state", Text("known")}, {"type", Text(type)}, {"value", std::move(value)},
    });
}

// 按 identity.schema.json 的 rawClock 形状表示来源或接收时钟。
JsonValue Clock(std::string_view domain, std::uint64_t value, std::string_view clockId,
                std::string_view bootId, std::optional<std::uint64_t> frequency = std::nullopt)
{
    JsonObject fields{
        {"domain", Text(domain)}, {"value", U64(value)},
        {"clockId", Text(clockId)}, {"bootId", Text(bootId)},
    };
    if (frequency) {
        fields.emplace_back("frequencyHz", U64(*frequency));
    }
    return JsonValue::makeObject(std::move(fields));
}

// 保存原生描述符的每个值，供离线解码和来源复核。
JsonValue Descriptor(const KernelFileDescriptor& descriptor)
{
    return JsonValue::makeObject({
        {"id", JsonValue::makeUInt(descriptor.id)}, {"version", JsonValue::makeUInt(descriptor.version)},
        {"channel", JsonValue::makeUInt(descriptor.channel)}, {"level", JsonValue::makeUInt(descriptor.level)},
        {"opcode", JsonValue::makeUInt(descriptor.opcode)}, {"task", JsonValue::makeUInt(descriptor.task)},
        {"keyword", U64(descriptor.keyword)},
    });
}

// 文件字段尚无基础 canonical catalog 项。只在来源专用 RawRecord 元数据中保存。
JsonValue FileFields(const KernelFileObservationView& observation)
{
    JsonObject fields; // 仅保存该条记录上真实存在的值。
    if (observation.pathUtf8) fields.emplace_back("path", Text(*observation.pathUtf8));
    if (observation.fileObject) fields.emplace_back("fileObject", U64(*observation.fileObject));
    if (observation.fileKey) fields.emplace_back("fileKey", U64(*observation.fileKey));
    if (observation.irp) fields.emplace_back("irp", U64(*observation.irp));
    if (observation.requestedBytes) fields.emplace_back("requestedBytes", U64(*observation.requestedBytes));
    if (observation.byteOffset) fields.emplace_back("byteOffset", U64(*observation.byteOffset));
    if (observation.ntStatus) fields.emplace_back("ntStatus", JsonValue::makeUInt(*observation.ntStatus));
    if (observation.issuingThreadId) {
        fields.emplace_back("issuingThreadId", JsonValue::makeUInt(*observation.issuingThreadId));
    }
    return JsonValue::makeObject(std::move(fields));
}

} // namespace

KernelFileProjection ProjectKernelFileObservation(const KernelFileObservationView& observation)
{
    // 验证 provider 和原生事件种类，再读取来源专用字段。
    if (observation.providerId != kKernelFileProviderId) return {Status::UnsupportedProvider, std::nullopt};
    const auto kind = Classify(observation.descriptor); // 本条记录的投影种类。
    if (!kind) return {Status::UnsupportedEvent, std::nullopt};
    const auto& source = observation.source; // 来源与原生 FILETIME 时钟的先验身份。
    if (!IsSourceIdentifier(source.sourceId) || !IsCanonicalUuid(source.sourceEpoch) ||
        !IsSourceIdentifier(source.bootId) || !IsSourceIdentifier(source.fileTimeClockId)) {
        return {Status::InvalidSource, std::nullopt};
    }
    if ((observation.activityId && !IsCanonicalUuid(*observation.activityId)) ||
        (observation.relatedActivityId && !IsCanonicalUuid(*observation.relatedActivityId))) {
        return {Status::InvalidSource, std::nullopt};
    }
    const auto& receive = observation.receiveQpc; // 可选的独立接收时钟观察。
    if (receive && (!IsSourceIdentifier(receive->clockId) || receive->clockId == source.fileTimeClockId ||
                    receive->frequencyHz == 0)) {
        return {Status::InvalidReceiveClock, std::nullopt};
    }
    if (observation.payloadPrefix.size() > observation.originalPayloadBytes) {
        return {Status::InvalidPayloadLength, std::nullopt};
    }
    if (observation.pathUtf8 && !IsArchiveText(*observation.pathUtf8)) {
        return {Status::InvalidPath, std::nullopt};
    }
    const bool completion = *kind == Kind::OperationEnd; // 完成记录独立，保留未知请求。
    if ((completion && (observation.requestedBytes || observation.byteOffset || observation.issuingThreadId)) ||
        (!completion && observation.ntStatus)) {
        return {Status::InvalidFileFields, std::nullopt};
    }

    // 原始元数据保留事件原值、来源时钟及捕获长度，队列或归档接手后仍可核对。
    const auto fileTime = Clock("filetime100ns", observation.sourceFileTime100ns,
                                source.fileTimeClockId, source.bootId);
    JsonObject metadata{
        {"providerId", Text(observation.providerId)}, {"sourceId", Text(source.sourceId)},
        {"sourceEpoch", Text(source.sourceEpoch)}, {"descriptor", Descriptor(observation.descriptor)},
        {"headerPid", JsonValue::makeUInt(observation.headerPid)},
        {"headerTid", JsonValue::makeUInt(observation.headerTid)}, {"sourceClock", fileTime},
        {"originalPayloadBytes", U64(observation.originalPayloadBytes)},
        {"capturedPayloadBytes", U64(observation.payloadPrefix.size())},
        {"payloadTruncated", JsonValue::makeBool(observation.payloadPrefix.size() < observation.originalPayloadBytes)},
        {"file", FileFields(observation)},
    };
    if (observation.headerFlags) {
        metadata.emplace_back("headerFlags", JsonValue::makeUInt(*observation.headerFlags));
    }
    if (observation.extendedDataCount) {
        metadata.emplace_back("extendedDataCount", JsonValue::makeUInt(*observation.extendedDataCount));
    }
    if (observation.activityId) {
        metadata.emplace_back("activityId", Text(*observation.activityId));
    }
    if (observation.relatedActivityId) {
        metadata.emplace_back("relatedActivityId", Text(*observation.relatedActivityId));
    }

    // 规范字段沿用基础目录。记录上下文单列，actor/target/线程对象均保持缺失。
    JsonObject fields{
        {"source.headerPid", Known("u32", JsonValue::makeUInt(observation.headerPid))},
        {"source.headerTid", Known("u32", JsonValue::makeUInt(observation.headerTid))},
        {"time.rawClock", fileTime},
    };
    std::optional<std::uint64_t> receiveTicks; // 缺失与已知零在核心及字段中均可区分。
    if (receive) {
        receiveTicks = receive->ticks;
        fields.emplace_back("time.receivedQpc", Known("u64", U64(receive->ticks)));
        metadata.emplace_back("receiveClock", Clock("qpc", receive->ticks, receive->clockId,
                                                    source.bootId, receive->frequencyHz));
    }

    // 复制字节，输出不引用采集者的 EVENT_RECORD 或输入文本。
    std::vector<std::uint8_t> inlineBytes;
    if (!observation.payloadPrefix.empty()) {
        inlineBytes.assign(observation.payloadPrefix.begin(), observation.payloadPrefix.end());
    }
    return {Status::Ok, KernelFileEvidence{
        {JsonValue::makeObject(std::move(metadata)), std::move(inlineBytes)},
        {*kind, observation.sourceFileTime100ns, receiveTicks, JsonValue::makeObject(std::move(fields))},
    }};
}

} // namespace ks::r3::monitor
