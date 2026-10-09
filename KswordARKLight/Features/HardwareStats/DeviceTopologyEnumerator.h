#pragma once
#include "../../../shared/usermode/backend/hardware/BusTopology.h"
#include "../../../shared/usermode/backend/hardware/UsbTopology.h"

#include "HardwareStatsModel.h"

namespace Ksword::Features::HardwareStats {

// EnumerateUsbTopology walks the USB device tree through SetupAPI and the
// Configuration Manager. There is no input; processing runs entirely on the
// calling thread and is safe to call from a worker; output is one snapshot whose
// nodes are already ordered parent-before-child with depth resolved.
//
// Enumeration deliberately covers the whole USB enumerator rather than only the
// GUID_DEVINTERFACE_USB_DEVICE interface: a device whose function driver failed
// to start exposes no device interface at all, and those are exactly the nodes
// worth seeing on this page.
using ks::r3::hardware_stats::EnumerateUsbTopology;

// EnumerateBusDevices reads PCI/ACPI style devnodes with their bus placement and
// arbitrated hardware resources. Input selects the scope; processing runs on the
// calling thread and is safe from a worker; output is one snapshot.
//
// includeAllEnumerators widens the pass from the PCI/ACPI/root buses to every
// present devnode. It is off by default because resource arbitration has to be
// queried per devnode, and doing that for the couple of thousand nodes on a
// typical desktop costs seconds for rows nobody asked for.
using ks::r3::hardware_stats::EnumerateBusDevices;

} // namespace Ksword::Features::HardwareStats
