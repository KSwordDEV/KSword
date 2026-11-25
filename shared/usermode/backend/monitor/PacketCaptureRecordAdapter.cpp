#include "PacketCaptureRecordAdapter.h"

// 先加载 Winsock2，网络工具头的进程依赖可能先引入 Windows.h。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include "../../../../Ksword5.1/Ksword5.1/ksword/network/network.h"

namespace ks::r3::monitor {
namespace {

// 旧抓包层可能先按 recv 实收长度裁剪。读取 IP 头声明的整包长度，保留原证据。
// IPv6 零负载字段也可能是巨型包标记。此时不推断长度。
std::optional<std::uint32_t> DeclaredIpLength(std::span<const std::uint8_t> bytes)
{
    const auto version = bytes.front() >> 4;
    if (version == 4 && bytes.size() >= 20) {
        const auto declared = (std::uint32_t{bytes[2]} << 8) | bytes[3];
        if (declared >= 20) {
            return declared;
        }
    }
    if (version == 6 && bytes.size() >= 40) {
        const auto declaredPayload = (std::uint32_t{bytes[4]} << 8) | bytes[5];
        if (declaredPayload != 0) {
            return 40 + declaredPayload;
        }
    }
    return std::nullopt;
}

} // namespace

PacketEvidenceProjection ProjectExistingRawSocketPacket(
    const NetworkSampleScopeView& scope, const PacketCollectorRecordView& collector,
    const ks::network::PacketRecord& record,
    const std::optional<PacketProcessEvidenceView>& proof)
{
    // 只支持现有 R3 Raw Socket 路径的原始 IP 头。ALE 事件不含报文字节。
    if (record.wfpAleEventNoPayload || record.packetBytes.empty()) {
        return {PacketEvidenceStatus::MetadataOnly, std::nullopt};
    }
    if (collector.kind != PacketCollectorKind::RawSocketIp) {
        return {PacketEvidenceStatus::UnsupportedLayer, std::nullopt};
    }
    static_assert(kLegacyRawIpInlineBytes == ks::network::detail::kMaxRetainedPacketBytes);
    if (record.packetBytes.size() > kLegacyRawIpInlineBytes) {
        return {PacketEvidenceStatus::ByteLimit, std::nullopt};
    }

    CapturedPacketView captured{}; // 在校验转发之前，适配器只借用原始缓冲区。
    captured.collector = collector;
    captured.captureTimestampUnixMs = record.captureTimestampMs;
    captured.observedPid = record.processId;
    captured.originalBytes = record.packetBytes;
    captured.directionNeedsProof = record.localToLocalAmbiguous;
    if (record.direction == ks::network::PacketDirection::Outbound) {
        captured.directionHint = NetworkDirection::Outbound;
    } else if (record.direction == ks::network::PacketDirection::Inbound) {
        captured.directionHint = NetworkDirection::Inbound;
    }
    if (record.protocol == ks::network::PacketTransportProtocol::Tcp) {
        captured.protocol = NetworkProtocol::Tcp;
    } else if (record.protocol == ks::network::PacketTransportProtocol::Udp) {
        captured.protocol = NetworkProtocol::Udp;
    }

    // 原有网络解析器保留 IP 头，并将 IP 长度限制在 recv 实收范围。没有链路长度证据。
    const auto ipVersion = record.packetBytes.front() >> 4;
    if (ipVersion == 4) {
        captured.layer = PacketEvidenceLayer::Ipv4;
    } else if (ipVersion == 6) {
        captured.layer = PacketEvidenceLayer::Ipv6;
    }
    if (record.totalPacketSize != 0) {
        captured.sourceIpLength = record.totalPacketSize;
    }
    captured.originalLength = DeclaredIpLength(captured.originalBytes);
    if (record.packetBytesTruncated) {
        captured.truncated = true;
    } else if (captured.originalLength) {
        captured.truncated = *captured.originalLength > captured.originalBytes.size();
    }
    return ProjectSamplePacketEvidence(scope, captured, proof);
}

} // namespace ks::r3::monitor
