#pragma once
#include "../Win32.h"
#include <cfgmgr32.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
namespace ks::r3::hardware {
struct HardwareFieldEvidence {
    bool available = false,absent = false,malformed = false;
    DWORD type = REG_NONE,error = ERROR_SUCCESS;
    CONFIGRET cmStatus = CR_SUCCESS;
    std::vector<std::wstring> values;
    std::uint64_t number = 0;
    bool numeric = false;
};
enum class HardwareDeviceState {
    Unknown,
    Started,
    Stopped,
    Disabled,
    Problem,
    Phantom
};
struct HardwareProperty {
    std::wstring name;
    std::wstring value;
};
struct HardwareDeviceNode {
    int index = -1;
    int parentIndex = -1;
    int depth = 0;
    DEVINST devInst = 0;
    ULONG statusFlags = 0;
    ULONG problemCode = 0;
    HardwareDeviceState state = HardwareDeviceState::Unknown;
    std::wstring instanceId;
    std::wstring parentInstanceId;
    std::wstring displayName;
    std::wstring className;
    std::wstring classGuid;
    std::wstring manufacturer;
    std::wstring serviceName;
    std::wstring driverKey;
    std::wstring location;
    std::wstring locationPaths;
    std::wstring hardwareIds;
    std::wstring compatibleIds;
    std::wstring upperFilters;
    std::wstring lowerFilters;
    std::wstring classUpperFilters;
    std::wstring classLowerFilters;
    std::vector<int> childIndices;
    std::map<std::wstring,HardwareFieldEvidence> evidence;
};
struct HardwareAuditSummary {
    std::size_t totalDevices = 0;
    std::size_t inputDevices = 0;
    std::size_t hidDevices = 0;
    std::size_t usbDevices = 0;
    std::size_t pciDevices = 0;
    std::size_t acpiDevices = 0;
    std::size_t filterEvidenceDevices = 0;
    std::size_t problemDevices = 0;
};
struct HardwareDeviceDetail {
    bool found = false;
    std::wstring title;
    std::wstring instanceId;
    std::vector<HardwareProperty> properties;
    HardwareDeviceNode node;
    DWORD win32Error = ERROR_SUCCESS;
};
struct HardwareEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<HardwareDeviceNode> devices;
    DWORD win32Error = ERROR_SUCCESS;
    bool complete = false,limited = false;
};
std::wstring DeviceStateText(HardwareDeviceState state, ULONG problemCode);
std::wstring CompactDeviceName(const HardwareDeviceNode& node);
std::wstring HardwareReadOnlyAuditDescription(const HardwareDeviceNode& node);
}
