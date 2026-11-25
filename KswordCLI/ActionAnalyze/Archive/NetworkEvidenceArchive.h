#pragma once

#include "SegmentReader.h"
#include "SegmentWriter.h"

#include <span>
#include <string>
#include <string_view>

namespace ks::cli::action_analyze::archive {

// RawRecord v1, flags=0, kind="ksword.actionAnalyze.network.v1". The segment
// header supplies projectId/sampleId. Common metadata keys are kind, record,
// sourceId, sourceEpoch, clockId, bootId, clockDomain and frequencyHz.
// Flow keys additionally include family, protocol, direction, sourceAddress,
// sourcePort, destinationAddress, destinationPort, payloadPid, createTime100ns,
// processObjectId, sourceTick, producerSequence, receiveQpc, observedBytes,
// eventId, version, opcode, captureLayer, payloadState, encoding,
// originalLength, producerCapturedLength, capturedLength and sourceTruncated.
// Values are lowercase network-byte-order hex addresses, decimal strings for
// unsigned integers, booleans and null. Metadata stores no source-record bytes.
// Inline RawRecord bytes are actual communication bytes, limited to 65536 bytes.
// Large contents may be deferred to the owner for normal sample-local BlobStore.
// Loss and EOF are metadata-only with independent typed fields.
// All UUIDs use RFC byte order. Source/clock/boot labels are at most 64 ASCII bytes.
enum class NetworkTimeDomain : std::uint8_t { Qpc = 1, FileTime = 2 };

struct NetworkEvidenceBinding {
    ArchiveUuid project{};
    ArchiveUuid sample{};
    std::string sourceId;
    ArchiveUuid sourceEpoch{};
    std::string clockId;
    std::string bootId;
    NetworkTimeDomain clockDomain = NetworkTimeDomain::Qpc;
    std::optional<std::uint64_t> frequencyHz;
};

enum class NetworkFamily : std::uint8_t { IPv4 = 4, IPv6 = 6 };
enum class NetworkTransport : std::uint8_t { Tcp = 6, Udp = 17 };
enum class NetworkDirection : std::uint8_t { Inbound = 1, Outbound = 2 };

struct NetworkEndpointMetadata {
    // Network byte order. IPv4 occupies the first four bytes, with a zero suffix.
    std::array<std::uint8_t, 16> address{};
    std::optional<std::uint16_t> port; // Host order. Absence differs from observed zero.
};

struct NetworkFlowMetadata {
    NetworkFamily family = NetworkFamily::IPv4;
    NetworkTransport transport = NetworkTransport::Tcp;
    NetworkDirection direction = NetworkDirection::Outbound;
    NetworkEndpointMetadata sourceField;
    NetworkEndpointMetadata destinationField;
    // Only a verified process instance is eligible. Object ID, when present, is sample-local.
    std::uint32_t processId = 0;
    std::uint64_t processCreatedUtc100ns = 0;
    std::optional<std::uint64_t> processObjectId;
    std::uint64_t sourceTimestamp = 0;
    std::optional<std::uint64_t> producerSequence;
    std::optional<std::uint64_t> receiveQpc;
    std::optional<std::uint64_t> observedBytes;
    struct EtwDescriptor { std::uint16_t eventId; std::uint8_t version; std::uint8_t opcode; };
    std::optional<EtwDescriptor> etw;

    // The independent destination view requires an attributable, non-wildcard endpoint.
    const NetworkEndpointMetadata* OutboundDestination() const noexcept;
};

struct NetworkLoss {
    std::uint64_t queueDropped = 0;
    std::uint64_t sourceLost = 0; // Known delta. A provider may also report unquantified loss.
    bool sourceLossUnquantified = false;
    bool queueCounterSaturated = false;
    bool sourceCounterSaturated = false;
};

enum class NetworkCaptureLayer { FlowMetadata, TransportPayload, IpPacket, LinkFrame };
enum class NetworkPayloadState { MetadataOnly, NoPayload, Complete, Truncated, Captured };
enum class NetworkInlinePolicy { RequireInline, RetainPrefix };

// 供离线展示区分实际材料与采集状态。Captured/Truncated 的线上状态允许保留零字节。
enum class NetworkCommunicationEvidence {
    MetadataOnly,      // 本条仅有端点、计数等流元数据。
    ConfirmedEmpty,    // 在本记录的捕获层已确认原始长度为零。
    RetainedBytes,     // 归档中有实际字节，是否完整使用 NetworkPayloadState 判断。
    MissingBytes,      // 已声明截断或已知存在原始字节，归档保留为零。
    UnknownPresence,   // 既无归档字节也无原始长度或截断证据。
};

struct NetworkCapturedBytes {
    NetworkCaptureLayer layer = NetworkCaptureLayer::FlowMetadata;
    std::optional<std::uint64_t> originalLength;
    std::span<const std::uint8_t> bytes;
    bool sourceTruncated = false;
};

struct NetworkCaptureSummary {
    NetworkCaptureLayer layer = NetworkCaptureLayer::FlowMetadata;
    NetworkPayloadState state = NetworkPayloadState::MetadataOnly;
    std::optional<std::uint64_t> originalLength;
    std::uint64_t producerCapturedLength = 0;
    std::uint32_t capturedLength = 0;
    bool sourceTruncated = false;

    // 仅对已校验的捕获摘要使用。结果不使用 ETW observedBytes 等跨层计数。
    NetworkCommunicationEvidence CommunicationEvidence() const noexcept;
};

enum class NetworkArchiveEnd : std::uint8_t { Stopped = 1, SourceUnavailable = 2, SourceFailed = 3 };
enum class NetworkSubmitStatus { Queued, QueueFull, WrongBinding, InvalidObservation, NeedsBlob, Closed };

inline constexpr std::size_t kNetworkQueueCapacity = 256;
inline constexpr std::size_t kNetworkQueuedPayloadBudget = 4u * 1024u * 1024u;
inline constexpr std::size_t kNetworkBatchRecords = 64;
inline constexpr std::size_t kNetworkMaxMetadataBytes = 1536;
inline constexpr std::size_t kNetworkMaxInlineBytes = 65536;

struct NetworkArchiveReceipt {
    SegmentIdentity segment;
    SegmentWriteResult result;
    std::uint64_t writtenBytes = 0;
    std::uint64_t flushedBytes = 0; // Successful file flush. Project checkpoint state is unavailable here.
    std::optional<std::uint64_t> lastWrittenSequence;
    std::optional<std::uint64_t> lastFlushedSequence;
    std::size_t queuedObservations = 0;
    std::size_t queuedPayloadBytes = 0;
    NetworkLoss pendingLoss;
    bool eofWritten = false;
    bool eofFlushed = false;
};

// A serialized adapter for a segment reserved exclusively by the sample's single Raw
// stream writer. The caller retains the writer lease, pins the validated sample/raw
// directory, and provides its next segment ordinal and previous stream sequence.
// This adapter owns a CREATE_NEW SegmentWriter and never reopens an old segment for append.
class NetworkEvidenceArchive final {
public:
    NetworkEvidenceArchive(const std::filesystem::path& resolvedRawDirectory,
                           NetworkEvidenceBinding binding, std::uint64_t segmentOrdinal,
                           std::uint64_t createdUtc100ns,
                           std::optional<std::uint64_t> previousSequence = std::nullopt);

    NetworkEvidenceArchive(const NetworkEvidenceArchive&) = delete;
    NetworkEvidenceArchive& operator=(const NetworkEvidenceArchive&) = delete;

    // All operations are on the writer's serialized lane. Submit/ReportSourceLoss
    // only touch bounded memory. Each accepted submission copies its retained bytes.
    NetworkSubmitStatus Submit(const NetworkEvidenceBinding& binding, const NetworkFlowMetadata& observation,
        const NetworkCapturedBytes& capture = {}, NetworkInlinePolicy policy = NetworkInlinePolicy::RequireInline) noexcept;
    bool ReportSourceLoss(const NetworkEvidenceBinding& binding, std::optional<std::uint64_t> delta) noexcept;
    NetworkArchiveReceipt Drain(); // Append at most one block, with any pending loss summary.
    NetworkArchiveReceipt Flush() noexcept;
    NetworkArchiveReceipt Finish(NetworkArchiveEnd end); // Drain, append EOF, flush, close.
    NetworkArchiveReceipt Receipt() const noexcept;

private:
    struct QueuedFlow {
        NetworkFlowMetadata flow;
        NetworkCaptureSummary capture;
    };

    NetworkArchiveReceipt Append(const std::vector<StoredRecord>& records, std::optional<QpcRange> qpc);

    NetworkEvidenceBinding binding_;
    SegmentIdentity identity_;
    SegmentWriter writer_;
    std::uint64_t previousSequence_ = 0;
    std::array<QueuedFlow, kNetworkQueueCapacity> queue_{};
    std::vector<std::uint8_t> payloadRing_;
    std::size_t head_ = 0;
    std::size_t queued_ = 0;
    std::size_t payloadHead_ = 0;
    std::size_t queuedPayloadBytes_ = 0;
    NetworkLoss pendingLoss_;
    NetworkArchiveReceipt state_;
    bool closed_ = false;
};

struct NetworkArchivedFlow {
    std::uint64_t recordSequence = 0;
    std::uint64_t recordOffset = 0;
    NetworkFlowMetadata observation;
    NetworkCaptureSummary capture;
};

struct DecodedRecord;

enum class NetworkSourceTrust { RecordedDeclaration, MatchedVerifiedBinding };

struct NetworkFlowRecordProjection {
    NetworkArchivedFlow flow; // 经类型和范围校验的记录身份、端点及捕获信息。
    NetworkEvidenceBinding source; // 段身份及记录声明的来源、代次、时钟。
    NetworkSourceTrust sourceTrust = NetworkSourceTrust::RecordedDeclaration;
    std::uint32_t inlineOffsetInPayload = 0; // 以 RawRecord payload 起点为基准。
    std::string_view inlineBytes; // 借用共享正文回调中的已校验字节。
};

// 在 ScanOpenSegmentBodies 的回调内传入已核验的段身份和当前记录，返回网络流投影。
// 只有项目所有者独立提供并核对 verifiedBinding 后，来源绑定才具备相应的可信度。
// 可选 ETW 描述符是记录中的声明。缺失时来源类型未知，不能推断为 API。
// 非网络流或格式不符返回 nullopt。保存投影前须复制仍需保留的 inlineBytes。
std::optional<NetworkFlowRecordProjection> ProjectNetworkFlowRecord(const SegmentIdentity& segment,
    const DecodedRecord& record, const NetworkEvidenceBinding* verifiedBinding = nullptr);

// Stored 读者也可以直接传入已经验证封装和 CRC 的原始记录，正文验证与上面入口相同。
// 返回结果借用 record.payload，保存时使用下方拥有字节的投影或自行复制。
std::optional<NetworkFlowRecordProjection> ProjectNetworkFlowRecord(const SegmentIdentity& segment,
    const RecordView& record, const NetworkEvidenceBinding* verifiedBinding = nullptr);

inline constexpr std::size_t kNetworkStoredPreviewBytes = 256; // 每行最多复制的通信正文前缀。

struct NetworkStoredFlowPreview {
    std::uint64_t segmentOrdinal = 0; // 原记录及数据偏移所属段。
    NetworkArchivedFlow flow; // 保留记录序号、原捕获状态与完整的归档长度。
    NetworkEvidenceBinding source; // 归档中的来源声明和同段项目/采样身份。
    NetworkSourceTrust sourceTrust = NetworkSourceTrust::RecordedDeclaration;
    std::optional<std::uint64_t> inlineFileOffset; // 有保留字节时，Stored v1 文件内的字节起点。
    std::vector<std::uint8_t> bytes; // 拥有内容的有界预览，允许跨块回调保存。
};

// 从已通过封装验证的 codec=Stored 原始记录生成可存入 Light 结果行的投影。
// 可选来源绑定须来自项目的独立核验。未识别或无效记录返回 nullopt。
std::optional<NetworkStoredFlowPreview> PreviewStoredNetworkFlow(const SegmentIdentity& segment,
    const RecordView& record, const NetworkEvidenceBinding* verifiedBinding = nullptr);

struct NetworkArchiveRecovery {
    SegmentScanResult framing;
    // The last whole block whose network metadata and EOF ordering were verified.
    std::uint64_t checkedBytes = 0;
    std::optional<std::uint64_t> invalidMetadataOffset;
    std::optional<NetworkArchiveEnd> eof;
    NetworkLoss loss;
};

// Called after a complete block has been checked. Row storage is borrowed until return.
using NetworkFlowBlockVisitor = std::function<void(const BlockInfo&, const std::vector<NetworkArchivedFlow>&)>;

// The project caller supplies a verified, pinned file handle and binding. A scan can
// recover earlier whole blocks after a truncated suffix. EOF means the adapter did
// write a terminal record. Neither EOF nor an observed prefix publishes a checkpoint.
NetworkArchiveRecovery ScanOpenNetworkEvidence(void* file, const NetworkEvidenceBinding& binding,
    std::uint64_t segmentOrdinal, std::optional<std::uint64_t> endOffset = std::nullopt,
    const NetworkFlowBlockVisitor& visitor = {});

} // namespace ks::cli::action_analyze::archive
