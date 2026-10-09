#pragma once

#include "ServiceTypes.h"

namespace ks::r3::service {

// ServiceActionResult is the value-only outcome of one SCM mutation. Inputs come
// from the action functions below; the message is already user-facing text and
// the view never needs to interpret the result any further.
struct ServiceActionResult {
    bool success = false;
    std::wstring message;
    std::uint32_t win32Error = 0, finalState = 0;
    bool partial = false;
};

// ServiceStartTypeChoice is what the start-type combo offers. It is a closed set
// rather than a raw SERVICE_* value because boot/system start types are only
// meaningful for drivers and are not something this page should let a user set
// on an ordinary service by accident.
enum class ServiceStartTypeChoice {
    Automatic,
    AutomaticDelayed,
    Manual,
    Disabled
};

// StartService / StopService / PauseService / ContinueService drive one SCM
// transition and wait for it to settle. Input is the short service name;
// processing blocks for up to a bounded timeout and is therefore only ever
// called from a worker thread; output reports the final state in its message.
//
// Stopping is the destructive one here: a running service is doing work for
// something, and the SCM does not stop its dependents for us. The view asks for
// confirmation before calling this.
ServiceActionResult StartServiceEntry(const std::wstring& serviceName);
ServiceActionResult StopServiceEntry(const std::wstring& serviceName);
ServiceActionResult PauseServiceEntry(const std::wstring& serviceName);
ServiceActionResult ContinueServiceEntry(const std::wstring& serviceName);

// ApplyServiceStartType writes the start type and the delayed-auto flag. Inputs
// are the short name and the chosen option; processing issues one
// ChangeServiceConfigW plus, for automatic starts, one delayed-auto write;
// output reports which parts were applied.
//
// The delayed flag is written for every automatic choice, including the plain
// one: switching from delayed to plain automatic has to clear the flag, and
// leaving it set would silently keep the old behavior while the UI claims
// otherwise.
ServiceActionResult ApplyServiceStartType(const std::wstring& serviceName, ServiceStartTypeChoice choice);

} // namespace ks::r3::service
