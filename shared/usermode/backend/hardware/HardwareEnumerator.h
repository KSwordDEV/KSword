#pragma once

#include "HardwareTypes.h"

namespace ks::r3::hardware {

// EnumerateDeviceManagerTree builds the read-only hardware audit baseline. There
// is no input; processing uses SetupAPI for device records and Configuration
// Manager for parent/status data; output contains a tree-ready snapshot.
HardwareEnumerationResult EnumerateDeviceManagerTree();

// QueryDeviceManagerDetails returns live details for one instance ID. Input is a
// PnP device instance ID; processing reopens that devnode through SetupAPI and
// CM APIs; output contains found=false when the device disappeared or cannot be
// opened.
HardwareDeviceDetail QueryDeviceManagerDetails(const std::wstring& instanceId);

} // namespace ks::r3::hardware
