#include "NetToolsModel.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <objbase.h>
// netfw.h is included by the model only for the NET_FW_* enumerations. The rule
// text belongs next to every other display formatter, and duplicating the
// numeric values here would silently drift from the SDK.
#include <netfw.h>

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <mutex>
#include <utility>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace Ksword::Features::NetTools {
namespace {

// kAnyProtocol is what the firewall store reports for a rule that does not pin a
// transport. It is 256 rather than 0 because 0 is a real IANA protocol number.
constexpr std::int32_t kAnyProtocol = 256;

bool IsUdp(const ConnectionProtocol protocol) {
    return protocol == ConnectionProtocol::Udp4 || protocol == ConnectionProtocol::Udp6;
}

// ProtocolOrder groups the table by transport before anything else. An operator
// scanning this page reads all TCP rows together, then all UDP rows; interleaving
// the four tables by address would make that impossible.
int ProtocolOrder(const ConnectionProtocol protocol) {
    switch (protocol) {
    case ConnectionProtocol::Tcp4: return 0;
    case ConnectionProtocol::Tcp6: return 1;
    case ConnectionProtocol::Udp4: return 2;
    case ConnectionProtocol::Udp6: return 3;
    }
    return 4;
}

bool MatchesProtocolFilter(const ConnectionEntry& entry, const ConnectionProtocolFilter filter) {
    switch (filter) {
    case ConnectionProtocolFilter::Tcp:
        return !IsUdp(entry.protocol);
    case ConnectionProtocolFilter::Udp:
        return IsUdp(entry.protocol);
    case ConnectionProtocolFilter::All:
        break;
    }
    return true;
}

bool MatchesDirectionFilter(const FirewallRuleEntry& entry, const FirewallDirectionFilter filter) {
    switch (filter) {
    case FirewallDirectionFilter::Inbound:
        return entry.direction == NET_FW_RULE_DIR_IN;
    case FirewallDirectionFilter::Outbound:
        return entry.direction == NET_FW_RULE_DIR_OUT;
    case FirewallDirectionFilter::All:
        break;
    }
    return true;
}

int CompareCaseInsensitive(const std::wstring& left, const std::wstring& right) {
    return ::CompareStringOrdinal(
        left.c_str(), static_cast<int>(left.size()), right.c_str(), static_cast<int>(right.size()), TRUE);
}

std::wstring PortText(const std::uint16_t port) {
    // Port 0 in a connection table means "unbound", which is a real state for a
    // half-open or listening endpoint, so it is shown rather than blanked.
    return std::to_wstring(static_cast<unsigned int>(port));
}

std::wstring EndpointText(const std::wstring& address, const std::uint16_t port, const bool ipv6) {
    if (address.empty()) {
        return PortText(port);
    }
    // Bracket notation is not decoration here: an unbracketed IPv6 literal
    // followed by ":443" is ambiguous with the address's own colons.
    return ipv6 ? L"[" + address + L"]:" + PortText(port) : address + L":" + PortText(port);
}

} // namespace

void ConnectionModel::setEntries(std::vector<ConnectionEntry> entries) {
    allEntries_ = std::move(entries);
    rebuildView();
}

void ConnectionModel::setProtocolFilter(const ConnectionProtocolFilter filter) {
    protocolFilter_ = filter;
    rebuildView();
}

ConnectionProtocolFilter ConnectionModel::protocolFilter() const noexcept {
    return protocolFilter_;
}

const std::vector<ConnectionEntry>& ConnectionModel::entries() const noexcept {
    return entries_;
}

const std::vector<ConnectionEntry>& ConnectionModel::allEntries() const noexcept {
    return allEntries_;
}

const ConnectionEntry* ConnectionModel::entryAt(const int index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= entries_.size()) {
        return nullptr;
    }
    return &entries_[static_cast<std::size_t>(index)];
}

std::wstring ConnectionModel::textForColumn(const ConnectionEntry& entry, const int column) const {
    switch (column) {
    case 0: return ConnectionProtocolText(entry.protocol);
    case 1: return entry.localAddress;
    case 2: return PortText(entry.localPort);
    case 3: return entry.remoteAddress;
    case 4: return entry.hasState || entry.remotePort != 0 ? PortText(entry.remotePort) : std::wstring{};
    case 5: return entry.hasState ? TcpStateText(entry.state) : std::wstring(L"—");
    case 6: return std::to_wstring(entry.processId);
    case 7: return entry.processName;
    default: break;
    }
    return {};
}

std::vector<NetToolsProperty> ConnectionModel::propertiesForEntry(const ConnectionEntry& entry) const {
    const bool ipv6 = entry.protocol == ConnectionProtocol::Tcp6 || entry.protocol == ConnectionProtocol::Udp6;
    std::vector<NetToolsProperty> properties;
    properties.push_back({ L"协议", ConnectionProtocolText(entry.protocol) });
    properties.push_back({ L"本地端点", EndpointText(entry.localAddress, entry.localPort, ipv6) });
    properties.push_back({ L"远端端点",
        entry.remoteAddress.empty() ? std::wstring(L"—") : EndpointText(entry.remoteAddress, entry.remotePort, ipv6) });
    properties.push_back({ L"连接状态", entry.hasState ? TcpStateText(entry.state) : std::wstring(L"UDP 无连接状态") });
    properties.push_back({ L"进程 ID", std::to_wstring(entry.processId) });
    properties.push_back({ L"进程名", entry.processName.empty() ? std::wstring(L"（无法读取）") : entry.processName });
    properties.push_back({ L"可结束",
        ConnectionCanClose(entry) ? std::wstring(L"是（SetTcpEntry 删除 TCB）")
                                  : std::wstring(L"否（仅 IPv4 TCP 的已连接状态支持）") });
    return properties;
}

void ConnectionModel::rebuildView() {
    entries_.clear();
    entries_.reserve(allEntries_.size());
    for (const ConnectionEntry& entry : allEntries_) {
        if (MatchesProtocolFilter(entry, protocolFilter_)) {
            entries_.push_back(entry);
        }
    }
    std::stable_sort(entries_.begin(), entries_.end(), [](const ConnectionEntry& left, const ConnectionEntry& right) {
        const int leftOrder = ProtocolOrder(left.protocol);
        const int rightOrder = ProtocolOrder(right.protocol);
        if (leftOrder != rightOrder) {
            return leftOrder < rightOrder;
        }
        if (left.processId != right.processId) {
            return left.processId < right.processId;
        }
        return left.localPort < right.localPort;
    });
}

void FirewallModel::setEntries(std::vector<FirewallRuleEntry> entries) {
    allEntries_ = std::move(entries);
    rebuildView();
}

void FirewallModel::setDirectionFilter(const FirewallDirectionFilter filter) {
    directionFilter_ = filter;
    rebuildView();
}

FirewallDirectionFilter FirewallModel::directionFilter() const noexcept {
    return directionFilter_;
}

const std::vector<FirewallRuleEntry>& FirewallModel::entries() const noexcept {
    return entries_;
}

const std::vector<FirewallRuleEntry>& FirewallModel::allEntries() const noexcept {
    return allEntries_;
}

const FirewallRuleEntry* FirewallModel::entryAt(const int index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= entries_.size()) {
        return nullptr;
    }
    return &entries_[static_cast<std::size_t>(index)];
}

std::wstring FirewallModel::textForColumn(const FirewallRuleEntry& entry, const int column) const {
    switch (column) {
    case 0: return entry.name;
    case 1: return FirewallDirectionText(entry.direction);
    case 2: return FirewallActionText(entry.action);
    case 3: return entry.enabled ? std::wstring(L"启用") : std::wstring(L"停用");
    case 4: return FirewallProtocolText(entry.protocol);
    case 5: return entry.localPorts.empty() ? std::wstring(L"任意") : entry.localPorts;
    case 6: return entry.remotePorts.empty() ? std::wstring(L"任意") : entry.remotePorts;
    case 7: return FirewallProfilesText(entry.profiles);
    case 8: return entry.applicationName.empty() ? std::wstring(L"任意程序") : entry.applicationName;
    default: break;
    }
    return {};
}

std::vector<NetToolsProperty> FirewallModel::propertiesForEntry(const FirewallRuleEntry& entry) const {
    std::vector<NetToolsProperty> properties;
    properties.push_back({ L"规则名称", entry.name });
    properties.push_back({ L"启用状态", entry.enabled ? L"启用" : L"停用" });
    properties.push_back({ L"方向", FirewallDirectionText(entry.direction) });
    properties.push_back({ L"动作", FirewallActionText(entry.action) });
    properties.push_back({ L"协议", FirewallProtocolText(entry.protocol) });
    properties.push_back({ L"配置文件", FirewallProfilesText(entry.profiles) });
    properties.push_back({ L"本地端口", entry.localPorts.empty() ? L"任意" : entry.localPorts });
    properties.push_back({ L"远端端口", entry.remotePorts.empty() ? L"任意" : entry.remotePorts });
    properties.push_back({ L"本地地址", entry.localAddresses.empty() ? L"任意" : entry.localAddresses });
    properties.push_back({ L"远端地址", entry.remoteAddresses.empty() ? L"任意" : entry.remoteAddresses });
    properties.push_back({ L"程序路径", entry.applicationName.empty() ? L"任意程序" : entry.applicationName });
    properties.push_back({ L"服务名", entry.serviceName.empty() ? L"（未限定）" : entry.serviceName });
    properties.push_back({ L"分组", entry.grouping.empty() ? L"（无分组）" : entry.grouping });
    properties.push_back({ L"接口类型", entry.interfaceTypes.empty() ? L"全部" : entry.interfaceTypes });
    properties.push_back({ L"边缘穿越", entry.edgeTraversal ? L"允许" : L"不允许" });
    properties.push_back({ L"描述", entry.description.empty() ? L"（无描述）" : entry.description });
    return properties;
}

void FirewallModel::rebuildView() {
    entries_.clear();
    entries_.reserve(allEntries_.size());
    for (const FirewallRuleEntry& entry : allEntries_) {
        if (MatchesDirectionFilter(entry, directionFilter_)) {
            entries_.push_back(entry);
        }
    }
    std::stable_sort(entries_.begin(), entries_.end(), [](const FirewallRuleEntry& left, const FirewallRuleEntry& right) {
        return CompareCaseInsensitive(left.name, right.name) == CSTR_LESS_THAN;
    });
}

std::wstring ConnectionProtocolText(const ConnectionProtocol protocol) {
    switch (protocol) {
    case ConnectionProtocol::Tcp4: return L"TCP";
    case ConnectionProtocol::Tcp6: return L"TCPv6";
    case ConnectionProtocol::Udp4: return L"UDP";
    case ConnectionProtocol::Udp6: return L"UDPv6";
    }
    return L"未知";
}

std::wstring TcpStateText(const std::uint32_t state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED: return L"CLOSED";
    case MIB_TCP_STATE_LISTEN: return L"LISTENING";
    case MIB_TCP_STATE_SYN_SENT: return L"SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return L"SYN_RECEIVED";
    case MIB_TCP_STATE_ESTAB: return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return L"FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return L"FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return L"LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return L"TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
    default: break;
    }
    return L"未知(" + std::to_wstring(state) + L")";
}







std::wstring FirewallDirectionText(const std::int32_t direction) {
    switch (direction) {
    case NET_FW_RULE_DIR_IN: return L"入站";
    case NET_FW_RULE_DIR_OUT: return L"出站";
    default: break;
    }
    return L"未知(" + std::to_wstring(direction) + L")";
}

std::wstring FirewallActionText(const std::int32_t action) {
    switch (action) {
    case NET_FW_ACTION_BLOCK: return L"阻止";
    case NET_FW_ACTION_ALLOW: return L"允许";
    default: break;
    }
    return L"未知(" + std::to_wstring(action) + L")";
}

std::wstring FirewallProtocolText(const std::int32_t protocol) {
    switch (protocol) {
    case 1: return L"ICMPv4";
    case 6: return L"TCP";
    case 17: return L"UDP";
    case 47: return L"GRE";
    case 50: return L"ESP";
    case 51: return L"AH";
    case 58: return L"ICMPv6";
    case kAnyProtocol: return L"任意";
    default: break;
    }
    return L"协议 " + std::to_wstring(protocol);
}

std::wstring FirewallProfilesText(const std::int32_t profiles) {
    if ((profiles & NET_FW_PROFILE2_ALL) == NET_FW_PROFILE2_ALL) {
        return L"全部";
    }
    std::wstring text;
    const auto append = [&text](const wchar_t* label) {
        if (!text.empty()) {
            text += L", ";
        }
        text += label;
    };
    if ((profiles & NET_FW_PROFILE2_DOMAIN) != 0) {
        append(L"域");
    }
    if ((profiles & NET_FW_PROFILE2_PRIVATE) != 0) {
        append(L"专用");
    }
    if ((profiles & NET_FW_PROFILE2_PUBLIC) != 0) {
        append(L"公用");
    }
    return text.empty() ? L"（未指定）" : text;
}

bool FirewallRuleIsInbound(const FirewallRuleEntry& entry) {
    return entry.direction == NET_FW_RULE_DIR_IN;
}

bool FirewallRuleIsOutbound(const FirewallRuleEntry& entry) {
    return entry.direction == NET_FW_RULE_DIR_OUT;
}

bool FirewallRuleIsBlocking(const FirewallRuleEntry& entry) {
    return entry.action == NET_FW_ACTION_BLOCK;
}









} // namespace Ksword::Features::NetTools
