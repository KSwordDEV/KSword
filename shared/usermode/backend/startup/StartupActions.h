#pragma once

#include "StartupTypes.h"

#include <string>

namespace ks::r3::startup {

// StartupActionResult reports the outcome of a startup-entry operation. Inputs
// are produced by StartupActions functions; consumers display the message and do
// not throw exceptions across Win32 callbacks.
struct StartupActionResult {
    bool success = false;
    std::wstring message;
};

// EnableStartupEntry restores a disabled startup entry where this module has a
// reversible storage path. Input is a StartupEntry selected in the view;
// processing routes by kind; output reports success or a concrete limitation.
StartupActionResult EnableStartupEntry(const StartupEntry& entry);

// DisableStartupEntry disables a startup entry without deleting its command when
// reversible storage is available. Input is a StartupEntry selected in the view;
// processing routes all mutations through this action layer; output reports the
// result for the status pane.
StartupActionResult DisableStartupEntry(const StartupEntry& entry);

// DeleteStartupEntry removes one startup entry. Input is a StartupEntry selected
// in the view; processing deletes registry values or files and routes service
// deletion through SCM; scheduled-task facade rows return a backend limitation.
StartupActionResult DeleteStartupEntry(const StartupEntry& entry);

// OpenStartupEntryLocation opens the registry editor or file explorer at the
// selected startup location when possible. Input is a StartupEntry; processing is
// best-effort ShellExecute/Regedit launch; output reports whether a request was
// issued.
StartupActionResult OpenStartupEntryLocation(const StartupEntry& entry);

} // namespace ks::r3::startup
