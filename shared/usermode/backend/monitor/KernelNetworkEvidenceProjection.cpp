#include "KernelNetworkEvidenceProjection.h"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace ks::r3::monitor {
namespace {

struct ManifestEvent {
    std::uint16_t id; // 清单 ID，与经典内核网络的事件类型编号分开。
    std::uint8_t opcode; // 清单记录对应的操作码。
    NetworkProtocol protocol;
    NetworkAddressFamily family;
    NetworkDirection direction;
};

// 现有 ProcessNetworkEtwMonitor 的八项 ID。Windows Kernel-Network 清单还确认了操作码和 v0 布局。
constexpr std::array<ManifestEvent, 8> kManifestEvents{{
    {10, 10, NetworkProtocol::Tcp, NetworkAddressFamily::Ipv4, NetworkDirection::Outbound},
    {11, 11, NetworkProtocol::Tcp, NetworkAddressFamily::Ipv4, NetworkDirection::Inbound},
    {26, 10, NetworkProtocol::Tcp, NetworkAddressFamily::Ipv6, NetworkDirection::Outbound},
    {27, 11, NetworkProtocol::Tcp, NetworkAddressFamily::Ipv6, NetworkDirection::Inbound},
    {42, 42, NetworkProtocol::Udp, NetworkAddressFamily::Ipv4, NetworkDirection::Outbound},
    {43, 43, NetworkProtocol::Udp, NetworkAddressFamily::Ipv4, NetworkDirection::Inbound},
    {58, 42, NetworkProtocol::Udp, NetworkAddressFamily::Ipv6, NetworkDirection::Outbound},
    {59, 43, NetworkProtocol::Udp, NetworkAddressFamily::Ipv6, NetworkDirection::Inbound},
}};

// A0 ID 使用规范小写 8-4-4-4-12 格式。核对写法后交给归档所有者处理其引用。
bool IsCanonicalUuid(std::string_view text) noexcept
{
    if (text.size() != 36 || text == "00000000-0000-0000-0000-000000000000") {
        return false;
    }
    for (std::size_t index = 0; index < text.size(); ++index) {
        const char ch = text[index]; // 当前位置的 UUID 字符。
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (ch != '-') {
                return false;
            }
        } else if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
            return false;
        }
    }
    return true;
}

// 与网络 RawRecord 一致，限制归档来源/时钟/启动标签的大小和字符集合。
bool ValidLabel(std::string_view label) noexcept
{
    return !label.empty() && label.size() <= 64 && std::all_of(label.begin(), label.end(), [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
               ch == '-' || ch == '_' || ch == '.' || ch == ':' || ch == '/';
    });
}

// 校验来源时钟及必要元数据。FILETIME 保留原始 100ns 值，QPC 必须具备可用频率。
bool ValidClock(const NetworkClockView& clock) noexcept
{
    if (!ValidLabel(clock.clockId) || !ValidLabel(clock.bootId)) {
        return false;
    }
    switch (clock.domain) {
    case NetworkSourceClock::FileTime100ns:
        return !clock.frequencyHz;
    case NetworkSourceClock::Qpc:
        return clock.frequencyHz.value_or(0) > 0;
    }
    return false;
}

// 清单 PID/size 为 Windows 小端 UINT32。调用者已验证固定前缀范围。
std::uint32_t ReadLe32(std::span<const std::uint8_t> data, std::size_t offset) noexcept
{
    return std::uint32_t{data[offset]} | (std::uint32_t{data[offset + 1]} << 8) |
           (std::uint32_t{data[offset + 2]} << 16) | (std::uint32_t{data[offset + 3]} << 24);
}

// 复制已校验地址字节，并把清单 win:Port 的网络序转换为主机序整数。
NetworkEndpoint ReadEndpoint(NetworkAddressFamily family, std::span<const std::uint8_t> address,
                             std::span<const std::uint8_t> port) noexcept
{
    NetworkEndpoint result;
    result.family = family;
    std::copy(address.begin(), address.end(), result.address.begin());
    result.port = static_cast<std::uint16_t>((std::uint16_t{port[0]} << 8) | port[1]);
    return result;
}

} // namespace

std::array<std::uint16_t, 8> KernelNetworkEvidenceEventIds() noexcept
{
    std::array<std::uint16_t, kManifestEvents.size()> ids{};
    std::transform(kManifestEvents.begin(), kManifestEvents.end(), ids.begin(),
        [](const ManifestEvent& row) { return row.id; });
    return ids;
}

bool IsValidNetworkSampleScope(const NetworkSampleScopeView& scope) noexcept
{
    return IsCanonicalUuid(scope.projectId) && IsCanonicalUuid(scope.sampleId) &&
           IsCanonicalUuid(scope.sourceEpoch) && ValidLabel(scope.sourceId) && !scope.machineId.empty() &&
           ValidClock(scope.clock) && (!scope.endSourceTick || *scope.endSourceTick >= scope.firstSourceTick);
}

bool NetworkProcessBindingCovers(const NetworkSampleScopeView& scope, const NetworkProcessBindingView& binding,
                                 std::uint32_t pid, std::uint64_t firstTick, std::uint64_t lastTick) noexcept
{
    // 核对所有者提供的唯一绑定属于同一采样、设备、启动、时钟、PID 及整个时间区间。
    return binding.sampleId == scope.sampleId && binding.machineId == scope.machineId &&
           binding.clock.bootId == scope.clock.bootId && binding.clock.clockId == scope.clock.clockId &&
           binding.clock.domain == scope.clock.domain && binding.clock.frequencyHz == scope.clock.frequencyHz &&
           binding.pid == pid && binding.processObjectId != 0 && binding.createTime100ns != 0 && firstTick <= lastTick &&
           binding.firstVerifiedSourceTick <= firstTick && lastTick < binding.endVerifiedSourceTick;
}

NetworkProjection ProjectKernelNetworkObservation(const NetworkSampleScopeView& scope,
                                                  const KernelNetworkObservationView& observation,
                                                  const std::optional<NetworkProcessBindingView>& binding)
{
    // 只有清单提供者和已核实的版本、ID、操作码组合进入解码路径。
    if (observation.providerId != kKernelNetworkProviderId) {
        return {NetworkProjectionStatus::OtherProvider, std::nullopt};
    }
    const auto manifest = std::find_if(kManifestEvents.begin(), kManifestEvents.end(),
                                       [&](const ManifestEvent& row) { return row.id == observation.eventId; });
    if (manifest == kManifestEvents.end()) {
        return {NetworkProjectionStatus::UnsupportedEvent, std::nullopt};
    }
    if (observation.version != 0 || observation.opcode != manifest->opcode) {
        return {NetworkProjectionStatus::UnsupportedLayout, std::nullopt};
    }

    // 先验证采样边界及来源代次，再读载荷。结束水位用于排除迟到或下一次采样事件。
    if (!IsValidNetworkSampleScope(scope)) {
        return {NetworkProjectionStatus::InvalidScope, std::nullopt};
    }
    if (observation.sourceId != scope.sourceId || observation.sourceEpoch != scope.sourceEpoch ||
        observation.sourceTick < scope.firstSourceTick ||
        (scope.endSourceTick && observation.sourceTick >= *scope.endSourceTick)) {
        return {NetworkProjectionStatus::OutOfSample, std::nullopt};
    }

    // 清单 v0 的首段为 PID、size、daddr、saddr、dport、sport。其余字段不使用。
    constexpr std::size_t addressOffset = 8;
    constexpr std::size_t portBytes = 2;
    const std::size_t addressBytes = manifest->family == NetworkAddressFamily::Ipv4 ? 4 : 16;
    const std::size_t portOffset = addressOffset + 2 * addressBytes;
    const auto data = observation.userData; // 原生回调提供的借用数据。
    if (data.size() < portOffset + 2 * portBytes) {
        return {NetworkProjectionStatus::TruncatedMetadata, std::nullopt};
    }

    // PID 只看原生载荷。未知或越出声明范围只返回计数原因，不复制地址。
    const std::uint32_t payloadPid = ReadLe32(data, 0);
    if (payloadPid == 0 || payloadPid == UINT32_MAX) {
        return {NetworkProjectionStatus::UnknownPayloadPid, std::nullopt};
    }
    if (std::find(scope.allowedPids.begin(), scope.allowedPids.end(), payloadPid) == scope.allowedPids.end()) {
        return {NetworkProjectionStatus::OutOfScopePid, std::nullopt};
    }

    // 输出拥有其元数据，允许采集者在回调结束后排队归档。
    NetworkFlowObservation flow;
    flow.projectId = scope.projectId;
    flow.sampleId = scope.sampleId;
    flow.sourceId = scope.sourceId;
    flow.sourceEpoch = scope.sourceEpoch;
    flow.clockId = scope.clock.clockId;
    flow.bootId = scope.clock.bootId;
    flow.clockDomain = scope.clock.domain;
    flow.frequencyHz = scope.clock.frequencyHz;
    flow.sourceTick = observation.sourceTick;
    flow.producerSequence = observation.producerSequence;

    // 各项保留采样可比较的类型，不以当前发送/接收字节速率重建原生记录。
    flow.eventId = observation.eventId;
    flow.version = observation.version;
    flow.opcode = observation.opcode;
    flow.payloadPid = payloadPid;
    flow.protocol = manifest->protocol;
    flow.direction = manifest->direction;
    flow.observedEtwBytes = ReadLe32(data, 4);
    flow.destinationField = ReadEndpoint(manifest->family, data.subspan(addressOffset, addressBytes),
                                         data.subspan(portOffset, portBytes));
    flow.sourceField = ReadEndpoint(manifest->family, data.subspan(addressOffset + addressBytes, addressBytes),
                                    data.subspan(portOffset + portBytes, portBytes));

    // 证据缺失时保留可读的载荷 PID 和未解析实例状态。
    if (binding && NetworkProcessBindingCovers(scope, *binding, payloadPid,
                                               observation.sourceTick, observation.sourceTick)) {
        flow.processObjectId = binding->processObjectId;
        flow.createTime100ns = binding->createTime100ns;
    }
    return {NetworkProjectionStatus::Ok, std::move(flow)};
}

const NetworkEndpoint* ConfirmedOutboundDestination(const NetworkFlowObservation& flow) noexcept
{
    // 仅已归属的实际发送记录能进入独立出站地址视图，通配地址和零端口保留在原事件中。
    if (flow.direction != NetworkDirection::Outbound || !flow.processObjectId || !flow.createTime100ns ||
        flow.destinationField.port == 0 || std::all_of(flow.destinationField.address.begin(),
                                                       flow.destinationField.address.end(),
                                                       [](std::uint8_t octet) { return octet == 0; })) {
        return nullptr;
    }
    return &flow.destinationField;
}

NetworkLossState SummarizeNetworkLoss(const NetworkSampleLoss& loss) noexcept
{
    // 各计量单位不同，检查证据是否存在但不相加。有损证据优先于其他缺失值。
    const std::array counts{loss.sourceEventsLost, loss.sourceRealTimeBuffersLost, loss.queueDrops,
                            loss.archiveFailures};
    if (std::any_of(counts.begin(), counts.end(), [](const auto& count) { return count.value_or(0) != 0; })) {
        return NetworkLossState::LossReported;
    }
    return std::all_of(counts.begin(), counts.end(), [](const auto& count) { return count.has_value(); })
               ? NetworkLossState::ZeroReported : NetworkLossState::Unknown;
}

} // namespace ks::r3::monitor
