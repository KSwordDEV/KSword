#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <array>

namespace ks::r3::network {
enum class PolicyBackend { Firewall, Driver };
enum class PolicyScope { ApplicationImage, AllApplications, ProcessInstance };
struct PolicyProcessIdentity {
    std::uint32_t processId = 0;
    std::uint64_t creationTime100ns = 0;
    std::wstring applicationPath;
};
struct NetworkPolicyResult {
    bool success = false;
    std::uint32_t nativeError = 0;
    std::wstring policyId;
    std::wstring diagnostic;
};
struct NetworkBlockRequest {
    PolicyBackend backend = PolicyBackend::Firewall;
    PolicyScope scope = PolicyScope::ApplicationImage;
    PolicyProcessIdentity target;
    // Numeric IPv4/IPv6 addresses or CIDR prefixes. Empty means all destinations
    // only for an explicit ApplicationImage or ProcessInstance scope.
    std::vector<std::wstring> remotePrefixes;
    bool inbound = true;
    bool outbound = true;
};
struct ManagedNetworkBlock {
    std::wstring policyId;
    PolicyBackend backend = PolicyBackend::Firewall;
    PolicyScope scope = PolicyScope::ApplicationImage;
    std::wstring applicationPath;
    std::uint32_t processId = 0;
    std::uint64_t creationTime100ns = 0;
    std::vector<std::wstring> remotePrefixes;
    bool inbound = false, outbound = false, enabled = false, complete = false;
};
struct NetworkBlockList {
    bool success = false;
    std::uint32_t nativeError = 0;
    std::wstring diagnostic;
    std::vector<ManagedNetworkBlock> entries;
    bool firewallAvailable = false, driverAvailable = false, driverProcessInstanceAvailable = false;
};
// The application installs its ArkDriverClient transport. The shared backend
// does not open the device or issue DeviceIoControl itself.
struct NetworkPolicyDriverOperations {
    std::function<NetworkPolicyResult(const NetworkBlockRequest&)> create;
    std::function<NetworkBlockList()> list;
    std::function<NetworkPolicyResult(const std::wstring&,bool)> enable;
    std::function<NetworkPolicyResult(const std::wstring&)> remove;
};
void SetNetworkPolicyDriverOperations(std::shared_ptr<const NetworkPolicyDriverOperations> operations);
struct NetworkHostResolution {
    bool success = false;
    std::uint32_t nativeError = 0;
    std::wstring diagnostic;
    std::vector<std::wstring> remotePrefixes;
};
struct NetworkAddressPrefix {
    std::uint32_t family = 0, prefixLength = 0;
    std::array<std::uint8_t,16> address{};
};
bool ParseNetworkAddressPrefix(const std::wstring& text, NetworkAddressPrefix& output);
bool NetworkAddressMatchesPrefix(const NetworkAddressPrefix& address, const NetworkAddressPrefix& prefix);
NetworkHostResolution ResolveNetworkHost(const std::wstring& host);
// Blocking worker-thread APIs. They never alter rules outside KSword ownership.
NetworkPolicyResult CreateNetworkBlock(const NetworkBlockRequest& request);
NetworkBlockList ListNetworkBlocks();
NetworkPolicyResult SetNetworkBlockEnabled(const std::wstring& policyId, bool enabled);
NetworkPolicyResult RemoveNetworkBlock(const std::wstring& policyId);

enum class QosProtocol { Any = 0, Tcp = 1, Udp = 2, TcpAndUdp = 3 };
struct QosPolicy {
    std::wstring policyId;
    std::wstring applicationPath;
    std::uint64_t outboundBytesPerSecond = 0;
    PolicyScope scope = PolicyScope::ApplicationImage;
    QosProtocol protocol = QosProtocol::Any;
    std::wstring sourcePrefix, destinationPrefix;
    std::uint16_t sourcePortStart = 0, sourcePortEnd = 0;
    std::uint16_t destinationPortStart = 0, destinationPortEnd = 0;
    int dscp = -1, priority8021 = -1;
    std::uint32_t precedence = 127;
    bool enabled = true;
    bool managed = true;
    std::wstring providerOwner, providerDetails;
};
struct QosPolicyList {
    bool success = false;
    std::uint32_t nativeError = 0;
    std::wstring diagnostic;
    std::vector<QosPolicy> entries;
};
// Windows Policy QoS matches the application image (all instances) and shapes
// outbound traffic. It does not suspend processes or promise inbound shaping.
QosPolicyList ListQosPolicies();
NetworkPolicyResult SaveQosPolicy(const QosPolicy& policy);
NetworkPolicyResult SetQosPolicyEnabled(const std::wstring& policyId, bool enabled);
NetworkPolicyResult RemoveQosPolicy(const std::wstring& policyId);
}
