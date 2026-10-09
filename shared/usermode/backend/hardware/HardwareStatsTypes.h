#pragma once

#include "../Win32.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ks::r3::hardware_stats {

// PerformanceMetricRow is one already-formatted counter line. The numeric value
// is kept next to the display text because the view sorts and colors on the
// number while the table shows the unit-bearing string; re-parsing the display
// text back into a number would tie ordering to the formatting rules.
struct PerformanceMetricRow {
    std::wstring group;         // Section the row belongs to (CPU / 内存 / ...).
    std::wstring name;          // Metric label shown to the user.
    std::wstring value;         // Formatted value including its unit.
    std::wstring source;        // Counter path actually queried, for auditing.
    double numericValue = 0.0;  // Raw sample; meaningless when valid is false.
    bool valid = false;         // False when PDH had no usable sample this pass.
};

// DiskActivityRow is one PhysicalDisk instance for the disk tab. Rates are kept
// raw so the view can format and sort them without a second parse.
struct DiskActivityRow {
    std::wstring instance;                 // PDH instance, e.g. "0 C:".
    double readBytesPerSecond = 0.0;
    double writeBytesPerSecond = 0.0;
    double readsPerSecond = 0.0;
    double writesPerSecond = 0.0;
    double currentQueueLength = 0.0;
    double averageQueueLength = 0.0;
    double busyPercent = 0.0;
    double readLatencySeconds = 0.0;
    double writeLatencySeconds = 0.0;
};

// PerformanceSnapshot carries one sampling pass. A failed pass still returns
// whatever rows were readable: a single counter that a hardened or virtualized
// machine refuses should not blank the whole table.
struct PerformanceSnapshot {
    bool success = false;
    std::wstring diagnosticText;
    std::wstring counterResolutionText;  // How counter paths were resolved.
    std::vector<PerformanceMetricRow> metrics;
    std::vector<DiskActivityRow> disks;
};

// UsbNodeKind separates the three roles a USB devnode can play. The tree reads
// very differently depending on whether a node can have children, so the kind is
// resolved once during enumeration instead of being guessed per view.
enum class UsbNodeKind {
    HostController,
    Hub,
    Device
};

// UsbNode is one devnode in the USB tree. parentIndex/depth are resolved against
// the same snapshot, so an index is only ever valid inside its own snapshot.
struct UsbNode {
    int index = 0;
    int parentIndex = -1;
    int depth = 0;
    UsbNodeKind kind = UsbNodeKind::Device;
    std::wstring instanceId;
    std::wstring parentInstanceId;
    std::wstring description;
    std::wstring manufacturer;
    std::wstring vendorId;        // "046D" style, empty when absent.
    std::wstring productId;       // "C52B" style, empty when absent.
    std::wstring revision;
    std::wstring serialNumber;    // Last instance-id segment when unique.
    std::wstring deviceClass;     // Setup class name (HIDClass / USB / ...).
    std::wstring service;         // Function driver service name.
    std::wstring driverKey;
    std::wstring portText;        // Hub port number or location text.
    std::wstring locationInfo;
    std::wstring hardwareIds;
    std::wstring statusText;
    std::wstring problemText;
};

// UsbTopologySnapshot is one full USB enumeration pass.
struct UsbTopologySnapshot {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<UsbNode> nodes;
};

// BusDeviceRow is one PCI/ACPI style devnode with its bus placement and the
// hardware resources the PnP manager currently has arbitrated to it.
struct BusDeviceRow {
    std::wstring instanceId;
    std::wstring description;
    std::wstring manufacturer;
    std::wstring enumeratorName;   // PCI / ACPI / ROOT / ...
    std::wstring busTypeText;      // Friendly name for the bus type GUID.
    std::wstring busTypeGuid;
    std::wstring legacyBusType;    // INTERFACE_TYPE rendered as text.
    std::wstring busNumber;
    std::wstring address;          // PCI device/function or bus-specific address.
    std::wstring uiNumber;         // Slot number as shown on the chassis.
    std::wstring locationInfo;
    std::wstring locationPaths;
    std::wstring deviceClass;
    std::wstring service;
    std::wstring driverKey;
    std::wstring resourceText;     // IRQ / IO / MEM / DMA summary.
    std::wstring statusText;
    std::wstring problemText;
};

// BusDeviceSnapshot is one full bus enumeration pass.
struct BusDeviceSnapshot {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<BusDeviceRow> rows;
};

// FormatByteSize renders a byte count with a binary unit. Input is a byte count
// as a double because PDH hands back doubles; output always carries a unit so a
// bare number can never be mistaken for a different scale.
std::wstring FormatByteSize(double bytes);

// FormatByteRate renders a throughput value, appending "/s" to the byte size.
std::wstring FormatByteRate(double bytesPerSecond);

// FormatPercent renders a percentage with one decimal place.
std::wstring FormatPercent(double value);

// FormatRate renders an operations-per-second value.
std::wstring FormatRate(double perSecond);

// FormatCount renders a plain count with thousands separators.
std::wstring FormatCount(double value);

// FormatDecimal renders a small unitless number with two decimals. Queue lengths
// are averages and routinely land between 0 and 1, where an integer render would
// collapse every idle and lightly loaded disk onto the same "0".
std::wstring FormatDecimal(double value);

// FormatLatency renders a PDH "Avg. Disk sec/..." value in milliseconds, which
// is the unit every storage tool and vendor datasheet uses.
std::wstring FormatLatency(double seconds);

// FormatUpTime renders a second count as days/hours/minutes.
std::wstring FormatUpTime(double seconds);

// UsbNodeKindText returns the display label for a node kind.
std::wstring UsbNodeKindText(UsbNodeKind kind);

// IndentedName prefixes a name with tree indentation. Input is the display name
// and its depth; output is the same name shifted right so a flat report ListView
// still shows the parent/child shape of the USB tree.
std::wstring IndentedName(const std::wstring& name, int depth);

} // namespace ks::r3::hardware_stats
