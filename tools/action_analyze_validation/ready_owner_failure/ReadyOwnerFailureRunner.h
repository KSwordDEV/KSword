#pragma once

#include "ReadyOwnerFailureTrigger.h"

#include <filesystem>

namespace ready_owner_failure {

// Runs one native-owner recovery scenario. The trigger is only a synchronization
// child; all final Held and recovery evidence comes from NativeDebugOwner.
int RunNativeOwnerFailure(ControlMode mode, const std::filesystem::path& receiptPath);

} // namespace ready_owner_failure
