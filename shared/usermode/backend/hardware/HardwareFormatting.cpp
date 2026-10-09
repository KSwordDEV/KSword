#include "HardwareFormatting.h"
#include <algorithm>
#include <cwctype>
#include <sstream>
namespace ks::r3::hardware {
std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}
bool ContainsAny(const std::wstring& haystack, const std::initializer_list<const wchar_t*> markers) {
    for (const wchar_t* marker : markers) {
        if (haystack.find(marker) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}
std::wstring NodeSearchText(const HardwareDeviceNode& node) {
    return ToLower(node.instanceId + L" " +
        node.parentInstanceId + L" " +
        node.displayName + L" " +
        node.className + L" " +
        node.classGuid + L" " +
        node.serviceName + L" " +
        node.location + L" " +
        node.locationPaths + L" " +
        node.hardwareIds + L" " +
        node.compatibleIds);
}
bool HasFilterEvidence(const HardwareDeviceNode& node) {
    return !node.upperFilters.empty() ||
        !node.lowerFilters.empty() ||
        !node.classUpperFilters.empty() ||
        !node.classLowerFilters.empty();
}
bool IsInputDevice(const HardwareDeviceNode& node) {
    const std::wstring text = NodeSearchText(node);
    return ContainsAny(text, { L"keyboard", L"kbd", L"mouse", L"mou", L"hidclass", L"hidusb", L"hid\\", L"hid_device" });
}
bool IsHidDevice(const HardwareDeviceNode& node) {
    const std::wstring text = NodeSearchText(node);
    return ContainsAny(text, { L"hidclass", L"hidusb", L"hid\\", L"hid_device", L"hid-compliant" });
}
bool IsUsbDevice(const HardwareDeviceNode& node) {
    const std::wstring text = NodeSearchText(node);
    return ContainsAny(text, { L"usb\\", L"usbstor", L"usbccgp", L"usbhub", L"usbxhci", L"ucx", L"vid_", L"pid_", L"mi_" });
}
bool IsPciDevice(const HardwareDeviceNode& node) {
    const std::wstring text = NodeSearchText(node);
    return ContainsAny(text, { L"pci\\", L"pciroot", L"ven_", L"dev_", L"subsys_" });
}
bool IsAcpiDevice(const HardwareDeviceNode& node) {
    const std::wstring text = NodeSearchText(node);
    return ContainsAny(text, { L"acpi\\", L"acpi(", L"processor", L"intelpep", L"processr", L"pdc" });
}
std::wstring DeviceStateText(HardwareDeviceState state, ULONG problemCode) {
    switch (state) {
    case HardwareDeviceState::Started:
        return L"Started";
    case HardwareDeviceState::Stopped:
        return L"Stopped";
    case HardwareDeviceState::Disabled:
        return L"Disabled";
    case HardwareDeviceState::Problem:
        return L"Problem " + std::to_wstring(problemCode);
    case HardwareDeviceState::Phantom:
        return L"Not present";
    default:
        break;
    }
    return L"Unknown";
}
std::wstring CompactDeviceName(const HardwareDeviceNode& node) {
    if (!node.displayName.empty()) {
        return node.displayName;
    }
    if (!node.className.empty()) {
        return node.className;
    }
    if (!node.instanceId.empty()) {
        return node.instanceId;
    }
    return L"Unnamed device";
}
std::wstring HardwareReadOnlyAuditDescription(const HardwareDeviceNode& node) {
    std::vector<std::wstring> labels;
    if (IsInputDevice(node)) {
        labels.push_back(L"Input chain");
    }
    if (IsHidDevice(node)) {
        labels.push_back(L"HID");
    }
    if (IsUsbDevice(node)) {
        labels.push_back(L"USB topology");
    }
    if (IsPciDevice(node)) {
        labels.push_back(L"PCI/PnP");
    }
    if (IsAcpiDevice(node)) {
        labels.push_back(L"ACPI/PnP");
    }
    if (HasFilterEvidence(node)) {
        labels.push_back(L"Filter registry evidence");
    }
    if (labels.empty()) {
        return L"Device stack/PnP row from SetupAPI and Configuration Manager";
    }

    std::wstring out;
    for (const std::wstring& label : labels) {
        if (!out.empty()) {
            out += L"; ";
        }
        out += label;
    }
    return out;
}
}
