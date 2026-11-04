#pragma once
#include "Firewall.h"
#include <cstdint>
#include <string>

namespace ks::r3::network {
// Identity is the SHA-256 of the exact enumerated field availability and values.
// It is a snapshot check, not an atomic compare-and-write primitive.
std::wstring FirewallRuleFingerprint(const FirewallRuleEntry& entry);

struct FirewallRuleCandidate {
    FirewallRuleEntry entry;
    std::wstring fingerprint;
};
struct FirewallRuleLookup {
    bool success = false;
    bool complete = false;
    std::uint32_t matchingCount = 0;
    std::uint32_t nameMatchingCount = 0;
    std::uint32_t hresult = 0;
    FirewallRuleEntry entry;
    std::wstring fingerprint;
    std::wstring diagnostic;
    std::vector<FirewallRuleCandidate> candidates;
};
FirewallRuleLookup QueryFirewallRule(const std::wstring& name, const std::wstring& fingerprint = {});

// The entry fieldFlags bit assignments are the same as FirewallRuleEntry.
// Only fields with a set bit are written; name is supplied separately.
struct FirewallRuleMutation {
    std::wstring name;
    std::wstring expectedFingerprint;
    bool rename = false;
    std::wstring newName;
    FirewallRuleEntry fields;
};
struct FirewallMutationResult {
    bool preflightComplete = false;
    bool requestAttempted = false;
    bool requestSucceeded = false;
    bool partialEffectPossible = false;
    bool postcheckComplete = false;
    bool verified = false;
    std::uint32_t hresult = 0;
    std::wstring stage;
    std::wstring diagnostic;
    FirewallRuleLookup before;
    FirewallRuleLookup after;
};
FirewallMutationResult CreateFirewallRule(const FirewallRuleMutation& mutation);
FirewallMutationResult UpdateFirewallRule(const FirewallRuleMutation& mutation);
FirewallMutationResult RemoveFirewallRule(const FirewallRuleMutation& mutation);
}
