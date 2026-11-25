#pragma once

#include "SegmentReader.h"

#include <string>
#include <string_view>
#include <variant>

namespace ks::cli::action_analyze::archive {

inline constexpr std::size_t kRawRecordV1PrefixBytes = 4;
inline constexpr std::uint16_t kCoverageRecordType = 14;
inline constexpr std::size_t kMaxEtwCoverageV1Bytes = 1024;

struct RawRecordV1 {
    std::string_view metadataJson;
    std::uint32_t inlineRawOffsetInPayload = 0;
    std::uint32_t inlineRawBytes = 0;
    // 借用当前已校验块中的原始字节，读者须在回调返回前使用或复制。
    std::string_view inlineRawData;
};

// 所有引用均限于本采样，需由上层解析。四个枚举字段保留线上编号。
struct CanonicalEventV1 {
    std::uint64_t eventOrdinal = 0;
    std::optional<std::uint64_t> primaryRawRecordSequence;
    std::uint64_t sourceInstanceDictionaryId = 0;
    std::uint64_t sourceEpochDictionaryId = 0;
    std::optional<std::uint64_t> producerSequence;
    std::optional<std::uint64_t> sourceTimestamp;
    std::optional<std::uint64_t> receiveQpc;
    std::optional<std::uint64_t> actorProcessObjectId;
    std::optional<std::uint64_t> targetProcessObjectId;
    std::optional<std::uint64_t> observedThreadObjectId;
    std::optional<std::uint64_t> operationDictionaryId;
    std::optional<std::uint64_t> captureRevisionDictionaryId;
    std::optional<std::uint64_t> effectiveRevisionDictionaryId;
    std::optional<std::uint64_t> coverageDictionaryId;
    std::uint32_t eventKind = 0;
    std::uint16_t category = 0;
    std::uint8_t phase = 0;
    std::uint8_t clockDomain = 0;
    std::uint32_t validityBits = 0;
    std::string_view fieldJson;
};

// 被动 ETW 终态的采集覆盖。序号引用同一项目、同一采样中的一个 raw 段。
struct EtwCoverageV1 {
    std::string providerId;
    std::string sourceEpoch;
    std::uint64_t rawSegmentOrdinal = 0;
    std::uint64_t planRawSequence = 0;
    std::uint64_t endRawSequence = 0;
    std::uint64_t observationCount = 0;
    // STOP 统计不可用时三项均为空。0 表示系统已报告无对应丢失。
    std::optional<std::uint32_t> eventsLost;
    std::optional<std::uint32_t> logBuffersLost;
    std::optional<std::uint32_t> realTimeBuffersLost;
    std::uint64_t queueDropped = 0;
    std::uint64_t payloadTruncated = 0;
    std::uint64_t malformedPayload = 0;
};

enum class BodyIssue {
    None,
    Length,
    Json,
    JsonBudget,
    RequiredRef,
    ValidityBits,
    ValidityValue,
    UnsupportedKind,
    CoverageFields,
    CoverageFlags,
};

struct BodyFailure {
    BodyIssue issue = BodyIssue::None;
    std::uint16_t recordType = 0;
    std::uint64_t recordOffset = 0;
};

// 仅编码已冻结的 RawRecord v1 封装。调用方定义元数据字段的语义，失败时不改动输出。
BodyIssue EncodeRawRecordV1(std::string_view metadataJson, std::string_view inlineRawData,
                          std::vector<std::uint8_t>& out);

// 正文为 etw-coverage-v1 JSON。记录头用 type 14、schemaVersion 1、kRequiredRecord，写入 records 流。
// 失败时不改动输出。直接解码遇到其它 kind 返回 UnsupportedKind。
// 解码检查正文与范围算术，raw 引用须由上层核对。
BodyIssue EncodeEtwCoverageV1(const EtwCoverageV1& coverage, std::vector<std::uint8_t>& out);
BodyIssue DecodeEtwCoverageV1(std::string_view json, EtwCoverageV1& out);

// monostate 表示没有适用的正文解码器。RawRecord 和 CanonicalEvent 的 JSON 视图借用块缓冲区。
using RecordBody = std::variant<std::monostate, RawRecordV1, CanonicalEventV1, EtwCoverageV1>;

struct DecodedRecord {
    std::uint64_t recordSequence = 0;
    std::uint64_t recordOffset = 0;
    std::uint16_t recordType = 0;
    std::uint16_t recordSchemaVersion = 0;
    std::uint32_t flags = 0;
    RecordBody body;
};

struct SegmentBodyScanResult {
    SegmentScanResult framing;
    BodyFailure bodyFailure;
    // 仅表示这一范围内支持的正文通过了结构检查。缺解码器的记录单独计数。
    std::uint64_t bodyCheckedBytes = 0;
    std::uint64_t bodyCheckedBlocks = 0;
    std::uint64_t opaqueOptionalRecords = 0;
    std::uint64_t opaqueRequiredRecords = 0;
};

// 回调中的项目/采样/流身份来自匹配的段头。记录、正文和字符串有效至回调返回。
// 回调拿到完整验证的支持范围。正文结构通过不涉及字典解析、时钟校准或采集质量。
using SegmentBodyVisitor = std::function<bool(const SegmentIdentity&, const BlockInfo&,
                                              const std::vector<DecodedRecord>&)>;

// 借用已验证的同步文件句柄。首个正文失败停止推进正文端点，封装扫描仍可继续。
SegmentBodyScanResult ScanOpenSegmentBodies(void* fileHandle, const SegmentIdentity& expectedIdentity,
                                            std::optional<std::uint64_t> endOffset = std::nullopt,
                                            const SegmentBodyVisitor& visitor = {});

} // namespace ks::cli::action_analyze::archive
