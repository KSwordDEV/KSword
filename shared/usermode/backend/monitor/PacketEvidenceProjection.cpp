#include "PacketEvidenceProjection.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace ks::r3::monitor {
namespace {

// 将来源毫秒映射为整个 FILETIME 时间桶，避免在同一毫秒的 PID 切换处误归属。
constexpr std::uint64_t kFileTimeUnixEpoch100ns = 116444736000000000ULL;
constexpr std::uint64_t kFileTimeTicksPerMs = 10000;

} // namespace

PacketEvidenceProjection ProjectSamplePacketEvidence(const NetworkSampleScopeView& scope,
                                                    const CapturedPacketView& captured,
                                                    const std::optional<PacketProcessEvidenceView>& proof)
{
    // ETW 和 ALE 等仅含元数据的输入不会生成报文归档正文。
    if (captured.originalBytes.empty()) {
        return {PacketEvidenceStatus::MetadataOnly, std::nullopt};
    }
    if (!IsValidNetworkSampleScope(scope) || scope.clock.domain != NetworkSourceClock::FileTime100ns) {
        return {PacketEvidenceStatus::InvalidScope, std::nullopt};
    }

    // 必须能证明整个来源毫秒落在本次采样及同一来源代次。
    constexpr auto kMaxUnixMs = (std::numeric_limits<std::uint64_t>::max() - kFileTimeUnixEpoch100ns -
                                 (kFileTimeTicksPerMs - 1)) / kFileTimeTicksPerMs;
    const auto& collector = captured.collector; // 实际采集者提供的来源描述符。
    if (collector.kind != PacketCollectorKind::RawSocketIp || collector.sourceId != scope.sourceId ||
        collector.sourceEpoch != scope.sourceEpoch ||
        captured.captureTimestampUnixMs > kMaxUnixMs) {
        return {PacketEvidenceStatus::OutOfSample, std::nullopt};
    }
    const auto firstTick = kFileTimeUnixEpoch100ns + captured.captureTimestampUnixMs * kFileTimeTicksPerMs;
    const auto lastTick = firstTick + kFileTimeTicksPerMs - 1;
    if (firstTick < scope.firstSourceTick || (scope.endSourceTick && lastTick >= *scope.endSourceTick)) {
        return {PacketEvidenceStatus::OutOfSample, std::nullopt};
    }

    // 只有已核对到该条报文的强身份及本样本声明的进程范围允许复制字节。
    if (!proof || proof->collector.kind != collector.kind || proof->collector.sourceId != collector.sourceId ||
        proof->collector.sourceEpoch != collector.sourceEpoch ||
        proof->collector.observationOrdinal != collector.observationOrdinal ||
        proof->captureTimestampUnixMs != captured.captureTimestampUnixMs) {
        return {PacketEvidenceStatus::UnverifiedProcess, std::nullopt};
    }

    // 双本地端点的展示方向仅是线索，要求归属证明同时提供独立方向。
    auto direction = captured.directionHint;
    if (captured.directionNeedsProof || !direction) {
        direction = proof->verifiedDirection;
    } else if (proof->verifiedDirection && direction != proof->verifiedDirection) {
        return {PacketEvidenceStatus::AmbiguousDirection, std::nullopt};
    }
    if (direction != NetworkDirection::Outbound && direction != NetworkDirection::Inbound) {
        return {PacketEvidenceStatus::AmbiguousDirection, std::nullopt};
    }
    const auto pid = proof->process.pid; // 采用经所有者验证的进程 PID。
    if (pid == 0 || pid == UINT32_MAX || (captured.observedPid != 0 && pid != captured.observedPid) ||
        std::find(scope.allowedPids.begin(), scope.allowedPids.end(), pid) == scope.allowedPids.end() ||
        !NetworkProcessBindingCovers(scope, proof->process, pid, firstTick, lastTick)) {
        return {PacketEvidenceStatus::UnverifiedProcess, std::nullopt};
    }

    // 仅支持原始 IP 层。核对版本位和最小头长度，避免把其他层误标为 IP。
    const auto version = captured.originalBytes.front() >> 4;
    if (!captured.layer ||
        (*captured.layer == PacketEvidenceLayer::Ipv4 && (version != 4 || captured.originalBytes.size() < 20)) ||
        (*captured.layer == PacketEvidenceLayer::Ipv6 && (version != 6 || captured.originalBytes.size() < 40)) ||
        (*captured.layer != PacketEvidenceLayer::Ipv4 && *captured.layer != PacketEvidenceLayer::Ipv6)) {
        return {PacketEvidenceStatus::UnsupportedLayer, std::nullopt};
    }

    // 链路长度和来源 IP 长度各自可缺。归档捕获长度只使用实际复制的字节数。
    const auto capturedBytes = captured.originalBytes.size();
    if (capturedBytes > kMaxCapturedIpEvidenceBytes) {
        return {PacketEvidenceStatus::ByteLimit, std::nullopt};
    }
    if ((captured.originalLength && *captured.originalLength < capturedBytes) ||
        (captured.wireLength && *captured.wireLength < capturedBytes) ||
        (captured.originalLength && captured.wireLength && *captured.wireLength < *captured.originalLength) ||
        (captured.sourceIpLength && *captured.sourceIpLength < capturedBytes)) {
        return {PacketEvidenceStatus::InvalidLengths, std::nullopt};
    }
    if (captured.originalLength && captured.truncated &&
        *captured.truncated != (*captured.originalLength > capturedBytes)) {
        return {PacketEvidenceStatus::InvalidLengths, std::nullopt};
    }

    SamplePacketEvidence packet; // 通过全部核验后构造可移交归档的样本证据。
    packet.projectId = scope.projectId;
    packet.sampleId = scope.sampleId;
    packet.sourceId = scope.sourceId;
    packet.sourceEpoch = scope.sourceEpoch;
    packet.clockId = scope.clock.clockId;
    packet.bootId = scope.clock.bootId;
    packet.collectorKind = collector.kind;
    packet.observationOrdinal = collector.observationOrdinal;
    packet.captureTimestampUnixMs = captured.captureTimestampUnixMs;
    packet.sourceFileTime100ns = firstTick;

    // 保留来源描述符和实际字节形态。未报告的长度保持缺失。
    packet.pid = pid;
    packet.processObjectId = proof->process.processObjectId;
    packet.createTime100ns = proof->process.createTime100ns;
    packet.direction = *direction;
    packet.protocol = captured.protocol;
    packet.layer = *captured.layer;
    packet.originalLength = captured.originalLength;
    packet.wireLength = captured.wireLength;
    packet.sourceIpLength = captured.sourceIpLength;
    packet.capturedLength = static_cast<std::uint32_t>(capturedBytes);
    packet.truncated = captured.truncated;
    packet.originalBytes.assign(captured.originalBytes.begin(), captured.originalBytes.end());
    return {PacketEvidenceStatus::Ok, std::move(packet)};
}

} // namespace ks::r3::monitor
