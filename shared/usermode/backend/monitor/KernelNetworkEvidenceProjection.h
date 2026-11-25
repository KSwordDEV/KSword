#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace ks::r3::monitor {

// 清单提供者的规范 GUID 与 EnableTraceEx2 的 IPv4/IPv6 关键字。
inline constexpr std::string_view kKernelNetworkProviderId = "7dd42a49-5329-4832-8dfd-43d979153a88";
inline constexpr std::uint64_t kKernelNetworkIpKeywords = 0x10 | 0x20;

enum class NetworkProtocol : std::uint8_t { Tcp = 6, Udp = 17 };
enum class NetworkAddressFamily : std::uint8_t { Ipv4 = 4, Ipv6 = 6 };
enum class NetworkDirection : std::uint8_t { Inbound = 1, Outbound = 2 };
enum class NetworkSourceClock : std::uint8_t { Qpc = 1, FileTime100ns = 2 };

struct NetworkEndpoint {
    NetworkAddressFamily family = NetworkAddressFamily::Ipv4;
    std::array<std::uint8_t, 16> address{}; // 网络字节序，IPv4 仅使用前四字节。
    std::uint16_t port = 0; // 主机字节序的原生端口值。

    bool operator==(const NetworkEndpoint&) const = default;
};

// 两种时钟都要以来源实际观测为准。频率只用于 QPC。
struct NetworkClockView {
    NetworkSourceClock domain = NetworkSourceClock::FileTime100ns;
    std::string_view clockId; // 本次采集的来源时钟标识。
    std::string_view bootId; // 采集所有者核验的启动实例。
    std::optional<std::uint64_t> frequencyHz; // QPC 必填且大于零。
};

// 采集所有者创建并冻结此范围。字符串和 PID 视图借用至函数返回。
struct NetworkSampleScopeView {
    std::string_view projectId;
    std::string_view sampleId;
    std::string_view machineId;
    std::string_view sourceId;
    std::string_view sourceEpoch;
    NetworkClockView clock;
    std::uint64_t firstSourceTick = 0; // 采样在此来源时钟上的起点，含该点。
    std::optional<std::uint64_t> endSourceTick; // 采样停止水位，不含该点。
    std::span<const std::uint32_t> allowedPids; // 采集者已声明的 PID 范围，空范围拒收全部。
};

struct KernelNetworkObservationView {
    std::string_view providerId; // 规范小写清单 GUID。
    std::string_view sourceId; // 实际提供事件的来源实例。
    std::string_view sourceEpoch; // 实际回调所属的会话代次。
    std::uint16_t eventId = 0; // 清单 EVENT_DESCRIPTOR.Id。
    std::uint8_t version = 0;
    std::uint8_t opcode = 0;
    std::uint64_t sourceTick = 0; // EVENT_HEADER.TimeStamp，采用此来源的已配置时钟。
    std::optional<std::uint64_t> producerSequence; // 可选来源序号，零是有效值。
    std::span<const std::uint8_t> userData; // 原生 ETW 元数据，仅借用至函数返回。
};

// 所有者仅在唯一、强进程身份且有效区间得到独立证据时提供。
// 此区间映射到来源时钟，来源观测首尾和当前 PID 查询不能充当生命周期证据。
struct NetworkProcessBindingView {
    std::string_view sampleId;
    std::string_view machineId;
    NetworkClockView clock;
    std::uint32_t pid = 0;
    std::uint64_t processObjectId = 0; // 本采样身份表中已验证的进程对象 ID。
    std::uint64_t createTime100ns = 0; // 强进程实例的原生创建时间。
    std::uint64_t firstVerifiedSourceTick = 0; // 已证实实例区间，含该点。
    std::uint64_t endVerifiedSourceTick = 0; // 已证实实例区间，不含该点。
};

struct NetworkFlowObservation {
    std::string projectId; // 两个 ID 按 A0 样本引用规则持久化。
    std::string sampleId;
    std::string sourceId; // 与 sourceEpoch 共同定位采集来源。
    std::string sourceEpoch;
    std::string clockId;
    std::string bootId;
    NetworkSourceClock clockDomain = NetworkSourceClock::FileTime100ns;
    std::optional<std::uint64_t> frequencyHz;
    std::uint64_t sourceTick = 0;
    std::optional<std::uint64_t> producerSequence;
    std::uint16_t eventId = 0; // 与 version/opcode 保留原始描述符身份。
    std::uint8_t version = 0;
    std::uint8_t opcode = 0;
    std::uint32_t payloadPid = 0; // 合法载荷中的 PID，可有 PID 但无实例。
    std::optional<std::uint64_t> processObjectId;
    std::optional<std::uint64_t> createTime100ns;
    NetworkProtocol protocol = NetworkProtocol::Tcp;
    NetworkDirection direction = NetworkDirection::Outbound;
    NetworkEndpoint sourceField; // 原生 saddr/sport，接收事件也按字段保存。
    NetworkEndpoint destinationField; // 原生 daddr/dport，接收事件也按字段保存。
    std::uint32_t observedEtwBytes = 0; // ETW size 字段的已知值，包括已知零。
};

// 归档交接：sourceId/clockId/bootId 为 1–64 字节的 ASCII [A-Za-z0-9._:/-] 标签。
// sourceEpoch 是实际订阅代次 UUID。CanonicalEvent 所需来源字典引用由所有者另行分配。
// sourceTick/clockDomain/clockId/bootId/frequencyHz 保留实际来源时钟。
// sourceField/destinationField 保留原始方向字段。只有发送事件按 sourceField→local、
// destinationField→remote 映射出站链路。接收事件的本地/远端映射须由采集验收另行确认。
// observedEtwBytes 映射到 observedBytes。ETW UserData 是源记录元数据，此投影只消费字段，
// 归档中的捕获层 flow-metadata、字节状态 metadata-only、capturedLength=0。

enum class NetworkProjectionStatus {
    Ok, OtherProvider, UnsupportedEvent, UnsupportedLayout, InvalidScope,
    OutOfSample, TruncatedMetadata, UnknownPayloadPid, OutOfScopePid,
};

struct NetworkProjection {
    NetworkProjectionStatus status;
    std::optional<NetworkFlowObservation> flow; // 仅 Ok 携带拥有内存的值。
};

// 两种投影共用采样范围及进程绑定验证。firstTick/lastTick 是证据时钟上的闭区间。
bool IsValidNetworkSampleScope(const NetworkSampleScopeView& scope) noexcept;
bool NetworkProcessBindingCovers(const NetworkSampleScopeView& scope, const NetworkProcessBindingView& binding,
                                 std::uint32_t pid, std::uint64_t firstTick, std::uint64_t lastTick) noexcept;

// 接收一条由现有 ETW 所有者提供的记录。归档只使用 Ok 的元数据，筛选拒绝只记状态计数。
NetworkProjection ProjectKernelNetworkObservation(const NetworkSampleScopeView& scope,
                                                  const KernelNetworkObservationView& observation,
                                                  const std::optional<NetworkProcessBindingView>& binding = std::nullopt);

// 由已解码且强实例已归属的采样发送记录提供目的端点。返回值借用自 flow。
// 持久化回跳使用同一样本 CanonicalEvent 的 eventOrdinal，由归档层在提交时绑定。
const NetworkEndpoint* ConfirmedOutboundDestination(const NetworkFlowObservation& flow) noexcept;

// 未报计数为 nullopt。已知零由该采样同一 ETW 代次有边界的观测明确提供。
// 共享 ETW 会话的丢失统计是会话级证据，不能归给具体进程或端点。
struct NetworkSampleLoss {
    std::optional<std::uint64_t> sourceEventsLost;
    std::optional<std::uint64_t> sourceRealTimeBuffersLost;
    std::optional<std::uint64_t> queueDrops;
    std::optional<std::uint64_t> archiveFailures;
};

enum class NetworkLossState { Unknown, ZeroReported, LossReported };

// 按可用计数汇总证据状态。任一非零即可确认存在损失，所有项已知才可报告零。
NetworkLossState SummarizeNetworkLoss(const NetworkSampleLoss& loss) noexcept;

} // namespace ks::r3::monitor
