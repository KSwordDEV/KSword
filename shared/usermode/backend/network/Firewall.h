#pragma once
#include "NetworkSupport.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::network {
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

struct FirewallEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::wstring profileSummary;
    std::vector<FirewallRuleEntry> entries;
};
FirewallEnumerationResult EnumerateFirewallRules();
}
