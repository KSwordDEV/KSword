#pragma once

#include "PrivilegeTypes.h"

namespace ks::r3::privilege {

// EnumerateProcessPrivileges reads the current process token: its identity,
// integrity level, groups and full privilege array. There is no input;
// processing runs on the calling thread and is safe from a worker; output is one
// snapshot with a diagnostic string when part of the read failed.
//
// A partial read still returns success: the privilege array is the point of the
// page, and losing it because a group name failed to resolve would be a poor
// trade.
PrivilegeSnapshot EnumerateProcessPrivileges();

} // namespace ks::r3::privilege
