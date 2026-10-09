#pragma once

#include "PrivilegeTypes.h"

namespace ks::r3::privilege {

// PrivilegeActionResult is the value-only outcome of one AdjustTokenPrivileges
// call. The message is already user-facing text.
struct PrivilegeActionResult {
    bool success = false;
    std::wstring message;
};

// SetPrivilegeEnabled enables or disables one privilege on the current process
// token. Inputs are the privilege constant name and the target state; processing
// issues a single AdjustTokenPrivileges; output reports what the API actually
// did.
//
// AdjustTokenPrivileges is notorious for returning TRUE while changing nothing:
// it reports success as long as the call was well-formed, and signals "this
// token was never granted that privilege" only through
// ERROR_NOT_ALL_ASSIGNED from GetLastError. That case is treated as a failure
// here, because a UI that says "已启用" for a privilege the token does not hold
// is worse than no UI at all.
PrivilegeActionResult SetPrivilegeEnabled(const std::wstring& privilegeName, bool enable);

} // namespace ks::r3::privilege
