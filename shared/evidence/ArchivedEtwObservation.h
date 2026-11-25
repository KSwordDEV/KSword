#pragma once

#include "EvidenceJson.h"

#include <charconv>
#include <optional>

namespace Ksword::Evidence {

// 从已校验的 RawRecord v1 读取 ETW 记录上下文。归档字段不是已解析对象身份。
struct ArchivedEtwObservation {
    std::string providerId; // 提供程序 GUID。
    std::string sourceEpoch; // 记录声明的采集代次。
    std::uint64_t fileTime = 0; // ETW 头中的 FILETIME。
    std::optional<std::uint64_t> receiveQpc; // 本地接收时钟；缺失保持为空。
    std::optional<std::uint64_t> qpcFrequencyHz; // 接收时钟的频率。
    std::uint32_t headerPid = 0; // ETW 记录头 PID。
    std::uint32_t headerTid = 0; // ETW 记录头 TID。
    std::uint16_t eventId = 0; // ETW 描述符编号。
    std::uint8_t version = 0; // 描述符版本。
    std::uint8_t opcode = 0; // 描述符操作码。
    std::uint16_t originalPayloadBytes = 0; // 原生 UserDataLength。
    bool malformedPayload = false; // 采集端报告原生载荷异常。
};

// 输入为已通过 Stored 正文校验的 JSON 和实际内联长度。未知或不一致的记录仍可作原始记录查看。
inline std::optional<ArchivedEtwObservation> ReadArchivedEtwObservation(
    const JsonValue& metadata, std::size_t inlineBytes)
{
    // 先识别来源版本。计划、终态及其它 RawRecord 共用相同的外层封装。
    std::string kind; // 记录的语义判别值。
    const auto* kindField = metadata.find("kind");
    if (!kindField || !kindField->tryGetString(kind) || kind != "etw-observation-v1")
    {
        return {};
    }

    // 标识采用规范 GUID 文本，限制字段可用作安全、可复制的列表标签。
    const auto guid = [&](std::string_view key, std::string& value) {
        const auto* field = metadata.find(key); // 来源或代次 GUID。
        if (!field || !field->tryGetString(value) || value.size() != 36)
        {
            return false;
        }
        for (std::size_t i = 0; i < value.size(); ++i)
        {
            const char ch = value[i]; // 连字符位置采用 RFC 文本布局。
            const bool separator = i == 8 || i == 13 || i == 18 || i == 23;
            if (separator ? ch != '-' : !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            {
                return false;
            }
        }
        return true;
    };

    // 窄字段保留原 JSON 整数类型，时钟和长度字符串按十进制无损读取。
    const auto narrow = [](const JsonValue& parent, std::string_view key, std::uint64_t max) -> std::optional<std::uint64_t> {
        const auto* field = parent.find(key); // 描述符或报头里的整数。
        std::uint64_t value = 0;
        if (!field || field->type() != JsonType::UInt || !field->tryGetU64(value) || value > max)
        {
            return {};
        }
        return value;
    };
    const auto decimal = [](const JsonValue* field) -> std::optional<std::uint64_t> {
        std::string digits; // 原样获取十进制字符串，拒绝符号及其它进制。
        if (!field || !field->tryGetString(digits) || digits.empty() || (digits.size() > 1 && digits.front() == '0'))
        {
            return {};
        }
        std::uint64_t value = 0;
        const char* end = digits.data() + digits.size(); // 数字必须消费完整字段。
        const auto [next, error] = std::from_chars(digits.data(), end, value);
        return error == std::errc{} && next == end ? std::optional{value} : std::nullopt;
    };

    ArchivedEtwObservation result; // 仅在长度、头字段和时钟一致时提交。
    const auto* descriptor = metadata.find("descriptor");
    if (!descriptor || !guid("providerId", result.providerId) || !guid("sourceEpoch", result.sourceEpoch))
    {
        return {};
    }
    const auto id = narrow(*descriptor, "id", UINT16_MAX); // ETW EVENT_DESCRIPTOR.Id。
    const auto version = narrow(*descriptor, "version", UINT8_MAX);
    const auto opcode = narrow(*descriptor, "opcode", UINT8_MAX);
    const auto pid = narrow(metadata, "headerPid", UINT32_MAX);
    const auto tid = narrow(metadata, "headerTid", UINT32_MAX);
    const auto fileTime = decimal(metadata.find("sourceFileTime100ns"));
    const auto original = narrow(metadata, "originalPayloadBytes", UINT16_MAX);
    const auto stored = decimal(metadata.find("storedPayloadBytes"));
    const auto* malformed = metadata.find("malformedPayload");
    if (!id || !version || !opcode || !pid || !tid || !fileTime || !original || !stored ||
        !malformed || !malformed->tryGetBool(result.malformedPayload) || *stored != inlineBytes || *stored > *original)
    {
        return {};
    }

    const auto* qpc = metadata.find("receiveQpc"); // 采集端同时记录 tick 与频率，或同时留空。
    const auto* frequency = metadata.find("qpcFrequencyHz");
    if (!qpc || !frequency || qpc->isNull() != frequency->isNull())
    {
        return {};
    }
    if (!qpc->isNull())
    {
        result.receiveQpc = decimal(qpc);
        result.qpcFrequencyHz = decimal(frequency);
        if (!result.receiveQpc || !result.qpcFrequencyHz || *result.qpcFrequencyHz == 0)
        {
            return {};
        }
    }

    // 上方已验证每个窄字段范围，直接保留合法的零值。
    result.fileTime = *fileTime;
    result.headerPid = static_cast<std::uint32_t>(*pid);
    result.headerTid = static_cast<std::uint32_t>(*tid);
    result.eventId = static_cast<std::uint16_t>(*id);
    result.version = static_cast<std::uint8_t>(*version);
    result.opcode = static_cast<std::uint8_t>(*opcode);
    result.originalPayloadBytes = static_cast<std::uint16_t>(*original);
    return result;
}

} // namespace Ksword::Evidence
