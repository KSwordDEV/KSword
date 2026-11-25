#pragma once

#include "KernelNetworkEvidenceProjection.h"

#include <vector>

namespace ks::r3::monitor {

enum class PacketEvidenceLayer { Ipv4, Ipv6 };
enum class PacketCollectorKind : std::uint8_t { RawSocketIp = 1 }; // 采集所有者的原生来源类型。

struct PacketCollectorRecordView {
    PacketCollectorKind kind; // 既有采集所有者提供的明确类型。
    std::string_view sourceId; // 已授权来源实例标识。
    std::string_view sourceEpoch; // 同一代次内的来源序号保持唯一。
    std::uint64_t observationOrdinal; // 来源所有者分配的序号，与 UI 行号无关。
};

// 归档交接：类型 Ipv4/Ipv6 均映射到 captureLayer=ip-packet，表示原始字节以 IP 头起始。
// 原始字节放在 JSON 外。非空附件的 encoding=bytes。
// capturedLength 使用 span.size()。originalLength 是可空的完整 IP 报文长度。
// wireLength 是可空链路长度。sourceIpLength 是旧来源夹紧至实收字节的计数。
// 旧 R3 PacketRecord 的保留字节上限为 4096 B，
// 超出归档自身内联预算的来源可由归档所有者使用同样本 SHA-256 blob slice 保存。
// 截断状态来自来源，未知则保持未知。空字节只提供 metadataOnly 状态，统一交给归档记录。
// 捕获来源的 sourceId/sourceEpoch/observationOrdinal 标识报文本身。
// 链接 ETW 记录时需要独立归属证据和同采样的持久原始记录引用。
inline constexpr std::size_t kLegacyRawIpInlineBytes = 4096;
inline constexpr std::size_t kMaxCapturedIpEvidenceBytes = 65535 + 40;

struct CapturedPacketView {
    PacketCollectorRecordView collector{};
    std::uint64_t captureTimestampUnixMs = 0; // 原始来源时钟，毫秒精度。
    std::uint32_t observedPid = 0; // 若来源提供 PID 则用于复核。
    std::optional<NetworkDirection> directionHint; // 采集记录中已判定的方向提示。
    bool directionNeedsProof = false; // 本地双端点或采集者无法确认方向时置位。
    std::optional<NetworkProtocol> protocol; // 来源已解析的协议。
    std::optional<PacketEvidenceLayer> layer; // 由真实采集入口说明。
    std::optional<std::uint32_t> originalLength; // 完整的 IP 层报文长度，有来源证据时填写。
    std::optional<std::uint32_t> wireLength; // 链路原始长度，来源未测时缺失。
    std::optional<std::uint32_t> sourceIpLength; // 原来源可报告的 IP 层长度。
    std::optional<bool> truncated; // 来源明确知道截断状态时填入。
    std::span<const std::uint8_t> originalBytes; // 只借用来源已经保存的原始字节。
};

// 采集所有者在明确授权并核实该条报文归属后提供。端口表或时间接近不足以建立此证明。
struct PacketProcessEvidenceView {
    PacketCollectorRecordView collector{};
    std::uint64_t captureTimestampUnixMs = 0;
    NetworkProcessBindingView process;
    std::optional<NetworkDirection> verifiedDirection; // 独立方向证据，可用于解开本机双端点歧义。
};

struct SamplePacketEvidence {
    std::string projectId;
    std::string sampleId;
    std::string sourceId;
    std::string sourceEpoch;
    std::string clockId; // 转换后的 FILETIME 时钟，与原始 Unix ms 一起保存。
    std::string bootId;
    PacketCollectorKind collectorKind = PacketCollectorKind::RawSocketIp;
    std::uint64_t observationOrdinal = 0;
    std::uint64_t captureTimestampUnixMs = 0;
    std::uint64_t sourceFileTime100ns = 0;
    std::uint32_t pid = 0;
    std::uint64_t processObjectId = 0;
    std::uint64_t createTime100ns = 0;
    NetworkDirection direction = NetworkDirection::Outbound;
    std::optional<NetworkProtocol> protocol;
    PacketEvidenceLayer layer = PacketEvidenceLayer::Ipv4;
    std::optional<std::uint32_t> originalLength;
    std::optional<std::uint32_t> wireLength;
    std::optional<std::uint32_t> sourceIpLength;
    std::uint32_t capturedLength = 0;
    std::optional<bool> truncated;
    std::vector<std::uint8_t> originalBytes; // 单份拥有内存的值，可搬移给归档。
};

enum class PacketEvidenceStatus { Ok, MetadataOnly, UnsupportedLayer, InvalidScope,
                                  OutOfSample, UnverifiedProcess, AmbiguousDirection, InvalidLengths, ByteLimit };

struct PacketEvidenceProjection {
    PacketEvidenceStatus status;
    std::optional<SamplePacketEvidence> packet; // 仅在通过全部授权范围/归属检查后持有字节。
};

// 采样范围使用对应来源的 FILETIME 时钟，供确定原始 Unix ms 的完整归属区间。
// 无身份凭证时返回 UnverifiedProcess，调用者只记录状态计数。
PacketEvidenceProjection ProjectSamplePacketEvidence(const NetworkSampleScopeView& scope,
                                                    const CapturedPacketView& captured,
                                                    const std::optional<PacketProcessEvidenceView>& proof);

} // namespace ks::r3::monitor
