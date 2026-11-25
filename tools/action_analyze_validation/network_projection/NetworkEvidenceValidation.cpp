#include "../../../shared/usermode/backend/monitor/KernelNetworkEvidenceProjection.h"
#include "../../../shared/usermode/backend/monitor/PacketCaptureRecordAdapter.h"

// 网络工具头的进程依赖要求 Winsock2 先于 Windows.h。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include "../../../Ksword5.1/Ksword5.1/ksword/network/network.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>

using namespace ks::r3::monitor;

namespace {
constexpr std::string_view kProject = "be57c458-b15a-4e52-9eed-5ed15998f97b";
constexpr std::string_view kSample = "9da3f254-4e49-49fd-9020-d03134f51b2d";
constexpr std::string_view kEpoch = "653a3b38-631e-42c3-8e67-fe3dea117001";
constexpr std::array<std::uint32_t, 1> kPids{17}; // 声明的唯一测试目标。
unsigned checks = 0; // 已执行断言。

// 记录每个断言并在失败时返回明确的用例名称。
void Check(bool passed, const char* description)
{
    ++checks;
    if (!passed) {
        std::cerr << "FAIL: " << description << '\n';
        std::exit(1);
    }
}

// 生成八种清单 v0 收发记录，核对每种协议/地址族、字节序和出站条件。
void CheckManifest()
{
    const NetworkClockView clock{NetworkSourceClock::Qpc, "source-qpc", "boot", 10'000'000};
    NetworkSampleScopeView scope{kProject, kSample, "machine", "network-etw", kEpoch, clock, 0, 200, kPids};
    NetworkProcessBindingView process{kSample, "machine", clock, 17, 101, 12345, 0, 100};
    constexpr std::array<std::uint16_t, 8> ids{10, 11, 26, 27, 42, 43, 58, 59};
    constexpr std::array<std::uint8_t, 8> opcodes{10, 11, 10, 11, 42, 43, 42, 43};
    std::array<std::uint8_t, 60> buffer{}; // 模拟本机清单的固定前缀和无关尾部。
    for (std::size_t index = 0; index < ids.size(); ++index) {
        const bool ipv6 = (index % 4) >= 2;
        const bool outbound = (index % 2) == 0;
        const std::size_t addressBytes = ipv6 ? 16 : 4;
        const std::size_t firstPort = 8 + 2 * addressBytes;
        buffer.fill(0);
        buffer[0] = 17;
        buffer[4] = 0x20;
        buffer[5] = 0x01;
        buffer[8] = ipv6 ? 0x20 : 127;
        buffer[8 + addressBytes - 1] = 14;
        buffer[8 + addressBytes] = ipv6 ? 0x20 : 127;
        buffer[8 + 2 * addressBytes - 1] = 3;
        buffer[firstPort] = 0x01;
        buffer[firstPort + 1] = 0xbb;
        buffer[firstPort + 2] = 0xdb;
        buffer[firstPort + 3] = 0x08;

        const KernelNetworkObservationView event{kKernelNetworkProviderId, "network-etw", kEpoch,
                                                 ids[index], 0, opcodes[index], 0, 0, buffer};
        const auto result = ProjectKernelNetworkObservation(scope, event, process);
        Check(result.status == NetworkProjectionStatus::Ok && result.flow, "manifest layout");
        const auto& flow = *result.flow;
        Check(flow.protocol == (index < 4 ? NetworkProtocol::Tcp : NetworkProtocol::Udp), "protocol");
        Check(flow.direction == (outbound ? NetworkDirection::Outbound : NetworkDirection::Inbound), "direction");
        Check(flow.destinationField.family == (ipv6 ? NetworkAddressFamily::Ipv6 : NetworkAddressFamily::Ipv4), "family");
        Check(flow.destinationField.port == 443 && flow.sourceField.port == 56072, "network port order");
        Check(flow.destinationField.address[addressBytes - 1] == 14 && flow.sourceField.address[addressBytes - 1] == 3,
              "native endpoints");
        Check(flow.processObjectId == 101 && flow.createTime100ns == 12345 && flow.payloadPid == 17, "strong identity");
        Check(flow.observedEtwBytes == 288 && flow.sourceTick == 0 && flow.producerSequence == 0 &&
              flow.frequencyHz == 10'000'000, "ETW bytes and clock preserve known zero");
        Check(ConfirmedOutboundDestination(flow) == (outbound ? &flow.destinationField : nullptr), "outbound evidence");
    }

    // 同 PID 不同生命周期、错误来源、过期时间及解析失败分别拥有独立状态。
    auto event = KernelNetworkObservationView{kKernelNetworkProviderId, "network-etw", kEpoch, 10, 0, 10, 100, 0, buffer};
    const auto unresolved = ProjectKernelNetworkObservation(scope, event, process);
    Check(unresolved.flow && !unresolved.flow->processObjectId && !ConfirmedOutboundDestination(*unresolved.flow), "PID reused");
    event.sourceTick = 200;
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::OutOfSample, "sample end");
    event.sourceTick = 0;
    event.version = 1;
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::UnsupportedLayout, "manifest version");
    event.version = 0;
    event.eventId = 12;
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::UnsupportedEvent, "connect is not send");
    event.eventId = 10;
    event.sourceEpoch = kProject;
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::OutOfSample, "source epoch");
    event.sourceEpoch = kEpoch;
    event.userData = std::span(buffer).first(19);
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::TruncatedMetadata, "truncated ports");
    event.userData = buffer;
    buffer[0] = 0;
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::UnknownPayloadPid, "unknown PID");
    buffer[0] = 18;
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::OutOfScopePid, "out of scope PID");
    buffer[0] = 17;
    buffer[4] = 0;
    buffer[5] = 0;
    const auto zero = ProjectKernelNetworkObservation(scope, event, process);
    Check(zero.flow && zero.flow->observedEtwBytes == 0 && !ConfirmedOutboundDestination(*zero.flow), "zero bytes and port");
    scope.clock.frequencyHz = 0;
    Check(ProjectKernelNetworkObservation(scope, event).status == NetworkProjectionStatus::InvalidScope, "QPC zero frequency");
}

// 原始 IP/UDP 本机保留前缀由固定合成字节组成。夹具不启动捕获、ETW 或 socket。
void CheckPacket()
{
    constexpr std::uint64_t captureMs = 42;
    constexpr std::uint64_t filetime = 116444736000420000ULL;
    const NetworkClockView clock{NetworkSourceClock::FileTime100ns, "capture-filetime", "boot", std::nullopt};
    NetworkSampleScopeView scope{kProject, kSample, "machine", "raw-ip-capture", kEpoch, clock,
                                 filetime, filetime + 10000, kPids};
    const PacketCollectorRecordView collector{PacketCollectorKind::RawSocketIp, "raw-ip-capture", kEpoch, 12};
    PacketProcessEvidenceView proof{collector, captureMs,
                                    {kSample, "machine", clock, 17, 101, 12345, filetime, filetime + 10000}, std::nullopt};
    constexpr std::array<std::uint8_t, 31> bytes{
        0x45, 0, 0, 31, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        0xdb, 0x08, 0x01, 0xbb, 0, 11, 0, 0, 0, 0xff, 0x6b,
    };
    ks::network::PacketRecord record;
    record.sequenceId = 900; // 界面序号与采集所有者分配的序号不同。
    record.sourceText = "UI label";
    record.captureTimestampMs = captureMs;
    record.processId = 17;
    record.direction = ks::network::PacketDirection::Outbound;
    record.protocol = ks::network::PacketTransportProtocol::Udp;
    record.totalPacketSize = static_cast<std::uint32_t>(bytes.size());
    record.packetBytes.assign(bytes.begin(), bytes.end());
    auto convert = [&](const auto& candidate) {
        return ProjectExistingRawSocketPacket(scope, collector, record, candidate);
    };

    const auto result = convert(proof);
    Check(result.status == PacketEvidenceStatus::Ok && result.packet, "legacy packet accepted with proof");
    const auto& packet = *result.packet;
    Check(std::equal(bytes.begin(), bytes.end(), packet.originalBytes.begin(), packet.originalBytes.end()), "byte exact");
    Check(packet.originalBytes.data() != record.packetBytes.data(), "archive-safe ownership");
    Check(packet.capturedLength == bytes.size() && packet.originalLength == bytes.size() &&
          !packet.wireLength && packet.sourceIpLength == bytes.size(), "lengths");
    Check(packet.truncated == false && packet.layer == PacketEvidenceLayer::Ipv4 && packet.protocol == NetworkProtocol::Udp,
          "raw IPv4 UDP and complete bytes");
    Check(packet.captureTimestampUnixMs == captureMs && packet.sourceFileTime100ns == filetime, "source time preserved");
    Check(packet.collectorKind == PacketCollectorKind::RawSocketIp && packet.observationOrdinal == 12,
          "collector identity independent of UI sequence and label");
    Check(convert(std::nullopt).status == PacketEvidenceStatus::UnverifiedProcess, "bare PID rejected");

    // 避免把另一条报文、另一采样或同一毫秒中的进程退出误归属。
    auto bad = proof;
    bad.collector.observationOrdinal++;
    Check(convert(bad).status == PacketEvidenceStatus::UnverifiedProcess, "wrong packet sequence");
    bad = proof;
    bad.process.sampleId = kProject;
    Check(convert(bad).status == PacketEvidenceStatus::UnverifiedProcess, "wrong sample");
    bad = proof;
    bad.process.endVerifiedSourceTick--;
    Check(convert(bad).status == PacketEvidenceStatus::UnverifiedProcess, "partial timestamp millisecond");
    scope.endSourceTick = filetime + 9999;
    Check(convert(proof).status == PacketEvidenceStatus::OutOfSample, "partial sample millisecond");
    scope.endSourceTick = filetime + 10000;
    record.wfpAleEventNoPayload = true;
    Check(convert(proof).status == PacketEvidenceStatus::MetadataOnly, "ALE metadata only");
    record.wfpAleEventNoPayload = false;
    const PacketCollectorRecordView unsupported{static_cast<PacketCollectorKind>(0), "raw-ip-capture", kEpoch, 12};
    Check(ProjectExistingRawSocketPacket(scope, unsupported, record, proof).status == PacketEvidenceStatus::UnsupportedLayer,
          "unknown capture collector");
    record.localToLocalAmbiguous = true;
    Check(convert(proof).status == PacketEvidenceStatus::AmbiguousDirection, "local-to-local direction rejected");
    bad = proof;
    bad.verifiedDirection = NetworkDirection::Inbound;
    const auto resolved = convert(bad);
    Check(resolved.packet && resolved.packet->direction == NetworkDirection::Inbound, "independent direction evidence");
    record.localToLocalAmbiguous = false;
    Check(convert(bad).status == PacketEvidenceStatus::AmbiguousDirection, "contradictory direction rejected");
    record.direction = ks::network::PacketDirection::Unknown;
    Check(convert(proof).status == PacketEvidenceStatus::AmbiguousDirection, "unknown direction rejected");
    record.direction = ks::network::PacketDirection::Outbound;
    record.packetBytes.pop_back();
    const auto truncated = convert(proof);
    Check(truncated.packet && truncated.packet->truncated == true && truncated.packet->capturedLength == 30 &&
          truncated.packet->originalLength == 31u, "IP length truncation");
    Check(truncated.packet && std::equal(bytes.begin(), bytes.end() - 1,
                                        truncated.packet->originalBytes.begin(), truncated.packet->originalBytes.end()),
          "UDP retained prefix exact");

    // IPv6/TCP 固定回环报文含数据字节。用原始字节和移动后的所有权核对传输链路。
    const std::array<std::uint8_t, 63> tcpBytes{
        0x60, 0, 0, 0, 0, 23, 6, 64,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x01, 0xbb, 0xdb, 0x08, 0, 0, 0, 5, 0, 0, 0, 7, 0x50, 0x18, 0x20, 0, 0, 0, 0, 0, 'K', 0, 'S',
    };
    record.packetBytes.assign(tcpBytes.begin(), tcpBytes.end());
    record.totalPacketSize = static_cast<std::uint32_t>(tcpBytes.size());
    record.protocol = ks::network::PacketTransportProtocol::Tcp;
    const auto ipv6 = convert(proof);
    Check(ipv6.packet && ipv6.packet->layer == PacketEvidenceLayer::Ipv6 && ipv6.packet->truncated == false &&
          ipv6.packet->protocol == NetworkProtocol::Tcp,
          "IPv6 complete bytes");
    record.packetBytes.back() = 'X';
    Check(ipv6.packet && std::equal(tcpBytes.begin(), tcpBytes.end(), ipv6.packet->originalBytes.begin(),
                                   ipv6.packet->originalBytes.end()), "TCP byte-exact output survives source change");

    // 时间溢出或另一来源代次均不能提交报文字节。
    record.captureTimestampMs = UINT64_MAX;
    Check(convert(proof).status == PacketEvidenceStatus::OutOfSample, "Unix millisecond overflow");
    record.captureTimestampMs = captureMs;
    const PacketCollectorRecordView wrongEpoch{PacketCollectorKind::RawSocketIp, "raw-ip-capture", kProject, 12};
    Check(ProjectExistingRawSocketPacket(scope, wrongEpoch, record, proof).status == PacketEvidenceStatus::OutOfSample,
          "wrong capture epoch");

    // 支持采集者直接提供链路长度和捕获层，非法长度不复制原始缓冲区。
    CapturedPacketView direct{collector, captureMs, 17, NetworkDirection::Outbound, false, NetworkProtocol::Udp,
                              PacketEvidenceLayer::Ipv4, 31, 50, 31, false, bytes};
    const auto captured = ProjectSamplePacketEvidence(scope, direct, proof);
    Check(captured.packet && captured.packet->wireLength == 50u, "explicit wire length");
    direct.wireLength = 12;
    Check(ProjectSamplePacketEvidence(scope, direct, proof).status == PacketEvidenceStatus::InvalidLengths, "invalid wire length");
    direct.wireLength = 50;
    direct.truncated = true;
    Check(ProjectSamplePacketEvidence(scope, direct, proof).status == PacketEvidenceStatus::InvalidLengths, "contradictory truncation");
}
} // namespace

int main()
{
    CheckManifest();
    CheckPacket();
    Check(SummarizeNetworkLoss({}) == NetworkLossState::Unknown, "unknown loss");
    Check(SummarizeNetworkLoss({0, 0, 0, 0}) == NetworkLossState::ZeroReported, "known zero loss");
    Check(SummarizeNetworkLoss({std::nullopt, 0, 1, 0}) == NetworkLossState::LossReported, "queue loss independent of ETW");
    std::cout << "PASS " << checks << " checks\n";
}
