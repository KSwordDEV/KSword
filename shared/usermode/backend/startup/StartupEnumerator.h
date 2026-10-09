#pragma once

#include "StartupTypes.h"

namespace ks::r3::startup {

// EnumerateStartupEntries returns every startup surface owned by this module.
// There is no input; processing queries registry Run/RunOnce, Startup folders,
// services, and the scheduled-task facade; output is a complete snapshot.
StartupEnumerationResult EnumerateStartupEntries();

} // namespace ks::r3::startup
