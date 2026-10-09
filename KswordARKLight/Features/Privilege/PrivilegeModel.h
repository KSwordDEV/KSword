#pragma once

#include "../../../shared/usermode/backend/privilege/PrivilegeTypes.h"

#include "../../Core/Win32Lean.h"

#include <string>
#include <vector>

namespace Ksword::Features::Privilege {
using ks::r3::privilege::PrivilegeProperty;
using ks::r3::privilege::PrivilegeEntry;
using ks::r3::privilege::TokenSummary;
using ks::r3::privilege::PrivilegeSnapshot;


// PrivilegeProperty is one detail-pane name/value pair.


// PrivilegeEntry is one row of the process token's privilege array. The LUID is
// carried along so an enable/disable can address the privilege without a second
// name lookup, which would otherwise re-resolve it on the local machine.


// TokenSummary describes the process token itself, which is the context every
// privilege row has to be read in: the same privilege list means something very
// different in an elevated token than in a filtered one.


// PrivilegeSnapshot is one full read of the current process token.


// PrivilegeModel stores the latest snapshot and prepares display text.
class PrivilegeModel final {
public:
    PrivilegeModel() = default;

    void setSnapshot(PrivilegeSnapshot snapshot);

    const std::vector<PrivilegeEntry>& privileges() const noexcept;
    const TokenSummary& token() const noexcept;

    const PrivilegeEntry* entryAt(int index) const;

    // textForColumn returns list text. Columns are name, display name, state and
    // risk.
    std::wstring textForColumn(const PrivilegeEntry& entry, int column) const;

    std::vector<PrivilegeProperty> propertiesForEntry(const PrivilegeEntry& entry) const;

    // tokenProperties expands the token summary for the detail pane when no
    // privilege row is selected.
    std::vector<PrivilegeProperty> tokenProperties() const;

private:
    PrivilegeSnapshot snapshot_;
};

// PrivilegeStateText formats the enabled/default/removed combination into one
// readable state instead of three separate columns of booleans.
using ks::r3::privilege::PrivilegeStateText;

// DescribePrivilege returns the plain-language meaning of a well-known privilege
// constant. Input is the constant name; output is empty for privileges this
// table has no text for, which is preferable to inventing one.
using ks::r3::privilege::DescribePrivilege;

// PrivilegeRiskText marks the privileges that let a holder step around normal
// access checks -- the ones worth noticing on an audit. Output is empty for the
// ordinary ones.
using ks::r3::privilege::PrivilegeRiskText;

} // namespace Ksword::Features::Privilege
