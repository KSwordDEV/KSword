#pragma once
#include "../Common.h"
#include "HardwareTypes.h"
namespace ks::r3::hardware {
std::wstring ToLower(std::wstring value);
bool ContainsAny(const std::wstring& haystack, const std::initializer_list<const wchar_t*> markers);
std::wstring NodeSearchText(const HardwareDeviceNode& node);
bool HasFilterEvidence(const HardwareDeviceNode& node);
bool IsInputDevice(const HardwareDeviceNode& node);
bool IsHidDevice(const HardwareDeviceNode& node);
bool IsUsbDevice(const HardwareDeviceNode& node);
bool IsPciDevice(const HardwareDeviceNode& node);
bool IsAcpiDevice(const HardwareDeviceNode& node);
std::wstring DeviceStateText(HardwareDeviceState state, ULONG problemCode);
std::wstring CompactDeviceName(const HardwareDeviceNode& node);
std::wstring HardwareReadOnlyAuditDescription(const HardwareDeviceNode& node);
}
