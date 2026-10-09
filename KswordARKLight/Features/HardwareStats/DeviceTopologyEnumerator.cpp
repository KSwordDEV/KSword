#include "../../../shared/usermode/backend/hardware/BusTopology.h"
#include "../../../shared/usermode/backend/hardware/UsbTopology.h"
#include "DeviceTopologyEnumerator.h"

#include "../../Core/Common.h"

#include <cfgmgr32.h>
#include <setupapi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>
#include <set>
#include <utility>
#include <vector>

#ifndef DN_PHANTOM
#define DN_PHANTOM 0x00004000
#endif

namespace Ksword::Features::HardwareStats {
namespace {
using namespace ks::r3::hardware_stats;
using namespace ks::r3::hardware_stats;

// The DEVPROPKEY values this module reads are spelled out instead of including
// devpkey.h. That header only declares its keys; the definitions appear only
// when INITGUID is defined first, which then also forces every DEFINE_GUID in
// the headers included afterwards to be emitted into this object file. Writing
// out the handful of keys used here keeps the translation unit free of that
// side effect while still going through the modern typed property API.


















// The USB device interface classes are declared locally for the same reason: the
// GUIDs in usbiodef.h only become storage when INITGUID is in effect.




// DevInfoSet owns a SetupAPI HDEVINFO handle. Inputs are handles from
// SetupDiGetClassDevsW; processing releases the handle at scope exit; get()
// returns the raw handle without transferring ownership.




// QueryRawProperty reads one device property into a byte buffer. Output is false
// when the devnode does not carry the property, which is normal rather than an
// error: bus placement properties only exist on devices that sit on a bus.


















// DescribeDeviceStatus turns the Configuration Manager status bits into text.
// The problem text is returned separately because a device can be started and
// still carry a warning, and folding both into one column would hide one of them.


// CollectInterfaceOwners returns the instance IDs of every devnode exposing one
// device interface class. It is the reliable way to tell a hub from a plain
// device: the hub driver is what publishes the hub interface, so the answer does
// not depend on guessing from a service name or a class code.


// ExtractHexField pulls a fixed-width hex field such as VID_ or PID_ out of a
// hardware ID. Output is empty when the marker is absent, which is normal for
// hubs synthesized by the root enumerator.


// SerialNumberFromInstanceId recovers a USB serial number when the device has
// one. Windows synthesizes an instance segment containing '&' for devices that
// report no serial number, so a segment without '&' is the device's own string.


// FormatDeviceResources renders the resources the PnP arbiters actually handed
// to one devnode. The allocated configuration is preferred over the boot
// configuration because it is what the device is using right now; the boot list
// is only a fallback for devices the arbiters never revisited.


// BusTypeGuidName names the bus type GUIDs that ship with Windows. Unknown GUIDs
// deliberately fall through to their raw text instead of an invented label: a
// wrong bus name on this page would be worse than no name at all.


// LegacyBusTypeText renders the INTERFACE_TYPE enum the PnP manager reports.
// The numeric values are part of the driver ABI and are written out rather than
// pulled from wdm.h, which is a kernel-mode header this user-mode module must
// not include.


// UsbNodeFromDevInfo converts one devnode into a USB tree node without linking
// it to its parent yet. The hub and controller instance sets decide the node
// kind because only the driver that owns the port knows what it really is.


// AppendEnumeratorNodes adds every present devnode under one PnP enumerator.


// AppendInterfaceNodes adds the devnodes exposing one interface class. USB host
// controllers live under the PCI enumerator, so the USB enumerator pass alone
// would leave every hub parentless and flatten the tree.


// OrderUsbNodesDepthFirst rewrites the node vector so every parent precedes its
// children. A flat report ListView cannot express nesting on its own, so the
// snapshot order plus the depth field is what makes the tree readable.






} // namespace





} // namespace Ksword::Features::HardwareStats
