#pragma once

#include "../../../shared/usermode/backend/network/Connections.h"

#include "../../Core/Win32Lean.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::NetTools {
using ks::r3::network::ConnectionProtocol;
using ks::r3::network::ConnectionEntry;
using ks::r3::network::ConnectionEnumerationResult;


// NetToolsProperty is one detail-pane name/value pair. Values are already
// formatted for display and are never parsed back by the view.
struct NetToolsProperty {
    std::wstring name;
    std::wstring value;
};

// ConnectionProtocol names the four extended tables this page reads. It is kept
// as one enum rather than a protocol flag plus a family flag because every
// decision the page makes -- which column text to show, whether a row can be
// closed at all -- depends on both at once.


// ConnectionEntry is the model row for one TCP or UDP endpoint. The raw tuple
// fields keep the exact byte order the IP Helper table reported, because
// SetTcpEntry expects the same representation back and re-parsing the display
// text would be a lossy round trip.


// ConnectionEnumerationResult carries one full enumeration pass. Partial results
// are still returned with their diagnostic attached: an IPv6 table that cannot
// be read is not a reason to hide the IPv4 rows that were read fine.


// ConnectionProtocolFilter narrows the table to one transport. It lives in the
// model rather than in the text filter because "udp" typed into a search box
// would also match a process called udpclient.exe.
enum class ConnectionProtocolFilter {
    All,
    Tcp,
    Udp
};

// ConnectionModel stores the latest snapshot and prepares display text. Inputs
// are entry vectors; processing applies the protocol filter and a stable sort;
// outputs stay valid until the next setEntries call.
class ConnectionModel final {
public:
    ConnectionModel() = default;

    // setEntries replaces the snapshot and re-applies the active filter.
    void setEntries(std::vector<ConnectionEntry> entries);

    // setProtocolFilter changes the transport filter and rebuilds the view.
    void setProtocolFilter(ConnectionProtocolFilter filter);

    ConnectionProtocolFilter protocolFilter() const noexcept;

    // entries returns the filtered, sorted rows the table shows.
    const std::vector<ConnectionEntry>& entries() const noexcept;

    // allEntries returns the unfiltered snapshot, used for the summary counts.
    const std::vector<ConnectionEntry>& allEntries() const noexcept;

    // entryAt validates a row index; output is nullptr when out of range.
    const ConnectionEntry* entryAt(int index) const;

    // textForColumn returns list text for one entry. Columns are protocol, local
    // address, local port, remote address, remote port, state, PID and process.
    std::wstring textForColumn(const ConnectionEntry& entry, int column) const;

    // propertiesForEntry expands one entry into the detail pane rows.
    std::vector<NetToolsProperty> propertiesForEntry(const ConnectionEntry& entry) const;

private:
    void rebuildView();

private:
    std::vector<ConnectionEntry> allEntries_;
    std::vector<ConnectionEntry> entries_;
    ConnectionProtocolFilter protocolFilter_ = ConnectionProtocolFilter::All;
};

// FirewallRuleEntry is one rule read back from INetFwPolicy2. Every field is
// stored as the API reported it; the numeric ones are turned into text only at
// display time so the filter can still match on the raw port lists.
struct FirewallRuleEntry {
    std::wstring name;
    std::wstring description;
    std::wstring grouping;
    std::wstring applicationName;
    std::wstring serviceName;
    std::wstring localPorts;
    std::wstring remotePorts;
    std::wstring localAddresses;
    std::wstring remoteAddresses;
    std::wstring interfaceTypes;
    std::int32_t direction = 0;   // NET_FW_RULE_DIR_*
    std::int32_t action = 0;      // NET_FW_ACTION_*
    std::int32_t protocol = 0;    // IANA protocol number, 256 for "any".
    std::int32_t profiles = 0;    // NET_FW_PROFILE_TYPE2 bitmask.
    bool enabled = false;
    bool edgeTraversal = false;
};

// FirewallEnumerationResult carries one rule-store read plus the per-profile
// on/off summary. The summary matters as much as the rules: a blocking rule in a
// profile whose firewall is switched off is not actually blocking anything.
struct FirewallEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::wstring profileSummary;
    std::vector<FirewallRuleEntry> entries;
};

// FirewallDirectionFilter narrows the rule table. Inbound and outbound rules are
// usually audited separately, and the store returns them interleaved.
enum class FirewallDirectionFilter {
    All,
    Inbound,
    Outbound
};

// FirewallModel stores the latest rule snapshot and prepares display text.
// Inputs are rule vectors; processing applies the direction filter and sorts by
// name; outputs stay valid until the next setEntries call.
class FirewallModel final {
public:
    FirewallModel() = default;

    void setEntries(std::vector<FirewallRuleEntry> entries);
    void setDirectionFilter(FirewallDirectionFilter filter);
    FirewallDirectionFilter directionFilter() const noexcept;

    const std::vector<FirewallRuleEntry>& entries() const noexcept;
    const std::vector<FirewallRuleEntry>& allEntries() const noexcept;
    const FirewallRuleEntry* entryAt(int index) const;

    // textForColumn returns list text for one rule. Columns are name, direction,
    // action, enabled, protocol, local ports, remote ports, profiles and program.
    std::wstring textForColumn(const FirewallRuleEntry& entry, int column) const;

    // propertiesForEntry expands one rule into the detail pane rows.
    std::vector<NetToolsProperty> propertiesForEntry(const FirewallRuleEntry& entry) const;

private:
    void rebuildView();

private:
    std::vector<FirewallRuleEntry> allEntries_;
    std::vector<FirewallRuleEntry> entries_;
    FirewallDirectionFilter directionFilter_ = FirewallDirectionFilter::All;
};

// ConnectionProtocolText formats the transport plus address family for display.
std::wstring ConnectionProtocolText(ConnectionProtocol protocol);

// TcpStateText formats a MIB_TCP_STATE value. UDP rows have no state and are
// rendered as a dash rather than as a fake "CLOSED".
std::wstring TcpStateText(std::uint32_t state);

// ConnectionCanClose reports whether SetTcpEntry could plausibly act on a row.
// Only IPv4 TCP has a delete-TCB path at all, and only a row that is actually in
// a connection state has a TCB to delete: offering the button on a UDP endpoint
// or a listener would just produce an error dialog after the fact.
using ks::r3::network::ConnectionCanClose;

// ConnectionIsEstablished / ConnectionIsListening classify a row for the summary
// counts. They live here rather than in the view so the MIB_TCP_STATE_* values
// stay behind one header and the views never pull in the IP Helper SDK.
using ks::r3::network::ConnectionIsEstablished;
using ks::r3::network::ConnectionIsListening;

// FirewallDirectionText / FirewallActionText / FirewallProtocolText /
// FirewallProfilesText format the numeric rule fields for display.
std::wstring FirewallDirectionText(std::int32_t direction);
std::wstring FirewallActionText(std::int32_t action);
std::wstring FirewallProtocolText(std::int32_t protocol);
std::wstring FirewallProfilesText(std::int32_t profiles);

// FirewallRuleIsInbound / FirewallRuleIsOutbound / FirewallRuleIsBlocking
// classify a rule for the summary counts. They keep the NET_FW_* values behind
// this header so the views never have to include the firewall COM headers.
bool FirewallRuleIsInbound(const FirewallRuleEntry& entry);
bool FirewallRuleIsOutbound(const FirewallRuleEntry& entry);
bool FirewallRuleIsBlocking(const FirewallRuleEntry& entry);

// EnsureWinsockInitialized brings Winsock 2.2 up once for this process. Address
// formatting and name resolution both need it, and the module is reached from
// worker threads, so the one-time init is guarded rather than left to the caller.
// There is deliberately no matching cleanup: the sockets stay usable for the
// lifetime of the process and an unbalanced WSACleanup elsewhere would break
// every other consumer.
using ks::r3::network::EnsureWinsockInitialized;

// FormatIpv4Address renders a network-byte-order IPv4 address as dotted quad.
using ks::r3::network::FormatIpv4Address;

// FormatIpv6Address renders 16 address bytes plus a scope id in RFC 5952 form.
using ks::r3::network::FormatIpv6Address;

// FormatWin32Error turns a Win32 or Winsock status into readable Chinese text.
// Input is the status code; output always contains the numeric code too, because
// the system message for network errors is often too vague to act on alone.
using ks::r3::network::FormatWin32Error;

} // namespace Ksword::Features::NetTools
