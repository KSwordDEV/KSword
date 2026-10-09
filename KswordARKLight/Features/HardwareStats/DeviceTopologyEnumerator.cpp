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

// The DEVPROPKEY values this module reads are spelled out instead of including
// devpkey.h. That header only declares its keys; the definitions appear only
// when INITGUID is defined first, which then also forces every DEFINE_GUID in
// the headers included afterwards to be emitted into this object file. Writing
// out the handful of keys used here keeps the translation unit free of that
// side effect while still going through the modern typed property API.










constexpr DEVPROPKEY kPropUiNumber = { kDevPropGuidDevice, 18 };
constexpr DEVPROPKEY kPropBusTypeGuid = { kDevPropGuidDevice, 21 };
constexpr DEVPROPKEY kPropLegacyBusType = { kDevPropGuidDevice, 22 };
constexpr DEVPROPKEY kPropBusNumber = { kDevPropGuidDevice, 23 };
constexpr DEVPROPKEY kPropEnumeratorName = { kDevPropGuidDevice, 24 };

constexpr DEVPROPKEY kPropLocationPaths = { kDevPropGuidDevice, 37 };

// The USB device interface classes are declared locally for the same reason: the
// GUIDs in usbiodef.h only become storage when INITGUID is in effect.




// DevInfoSet owns a SetupAPI HDEVINFO handle. Inputs are handles from
// SetupDiGetClassDevsW; processing releases the handle at scope exit; get()
// returns the raw handle without transferring ownership.


std::wstring GuidToString(const GUID& guid) {
    wchar_t buffer[64] = {};
    const int written = swprintf_s(buffer,
        L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        static_cast<unsigned long>(guid.Data1),
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]);
    return written > 0 ? std::wstring(buffer) : std::wstring();
}

// QueryRawProperty reads one device property into a byte buffer. Output is false
// when the devnode does not carry the property, which is normal rather than an
// error: bus placement properties only exist on devices that sit on a bus.










bool QueryGuidProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key, GUID& value) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data) || data.size() < sizeof(GUID) ||
        type != DEVPROP_TYPE_GUID) {
        return false;
    }
    std::memcpy(&value, data.data(), sizeof(value));
    return true;
}







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
std::wstring FormatDeviceResources(DEVINST devInst) {
    LOG_CONF logConf = 0;
    CONFIGRET result = ::CM_Get_First_Log_Conf(&logConf, devInst, ALLOC_LOG_CONF);
    if (result != CR_SUCCESS) {
        result = ::CM_Get_First_Log_Conf(&logConf, devInst, BOOT_LOG_CONF);
    }
    if (result != CR_SUCCESS) {
        return {};
    }

    std::wstring text;
    const auto append = [&text](const std::wstring& part) {
        if (part.empty()) {
            return;
        }
        if (!text.empty()) {
            text += L"; ";
        }
        text += part;
    };

    // Message-signalled interrupts are collected separately. A single PCIe
    // function routinely allocates a dozen or more of them, and listing each one
    // inline would push the memory and I/O ranges -- the parts an operator
    // actually reads -- off the end of the cell.
    std::vector<long> messageIrqs;

    RES_DES current = static_cast<RES_DES>(logConf);
    bool ownsCurrent = false;
    for (;;) {
        RES_DES next = 0;
        RESOURCEID resourceType = 0;
        const CONFIGRET step = ::CM_Get_Next_Res_Des(&next, current, ResType_All, &resourceType, 0);
        if (ownsCurrent) {
            ::CM_Free_Res_Des_Handle(current);
            ownsCurrent = false;
        }
        if (step != CR_SUCCESS) {
            break;
        }
        current = next;
        ownsCurrent = true;

        ULONG size = 0;
        if (::CM_Get_Res_Des_Data_Size(&size, current, 0) != CR_SUCCESS || size == 0) {
            continue;
        }
        std::vector<BYTE> data(size, 0);
        if (::CM_Get_Res_Des_Data(current, data.data(), size, 0) != CR_SUCCESS) {
            continue;
        }

        wchar_t buffer[128] = {};
        switch (resourceType) {
        case ResType_Mem:
            if (data.size() >= sizeof(MEM_DES)) {
                const auto* description = reinterpret_cast<const MEM_DES*>(data.data());
                swprintf_s(buffer, L"MEM 0x%016llX-0x%016llX",
                    static_cast<unsigned long long>(description->MD_Alloc_Base),
                    static_cast<unsigned long long>(description->MD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_MemLarge:
            if (data.size() >= sizeof(MEM_LARGE_DES)) {
                const auto* description = reinterpret_cast<const MEM_LARGE_DES*>(data.data());
                swprintf_s(buffer, L"MEM64 0x%016llX-0x%016llX",
                    static_cast<unsigned long long>(description->MLD_Alloc_Base),
                    static_cast<unsigned long long>(description->MLD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_IO:
            if (data.size() >= sizeof(IO_DES)) {
                const auto* description = reinterpret_cast<const IO_DES*>(data.data());
                swprintf_s(buffer, L"IO 0x%04llX-0x%04llX",
                    static_cast<unsigned long long>(description->IOD_Alloc_Base),
                    static_cast<unsigned long long>(description->IOD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_DMA:
            if (data.size() >= sizeof(DMA_DES)) {
                const auto* description = reinterpret_cast<const DMA_DES*>(data.data());
                swprintf_s(buffer, L"DMA %lu", static_cast<unsigned long>(description->DD_Alloc_Chan));
                append(buffer);
            }
            break;
        case ResType_IRQ:
            if (data.size() >= sizeof(IRQ_DES)) {
                const auto* description = reinterpret_cast<const IRQ_DES*>(data.data());
                const ULONG allocated = description->IRQD_Alloc_Num;
                // A message-signalled interrupt has no wire, so the PnP manager
                // reports a vector that is negative when read as a signed value.
                // Printing the raw unsigned number instead would show 4294967253
                // where Device Manager shows -43.
                if (allocated >= 0x80000000UL) {
                    messageIrqs.push_back(static_cast<long>(static_cast<LONG>(allocated)));
                } else {
                    swprintf_s(buffer, L"IRQ %lu", static_cast<unsigned long>(allocated));
                    append(buffer);
                }
            }
            break;
        case ResType_BusNumber:
            append(L"BUS");
            break;
        default:
            break;
        }
    }

    if (ownsCurrent) {
        ::CM_Free_Res_Des_Handle(current);
    }
    ::CM_Free_Log_Conf_Handle(logConf);

    if (!messageIrqs.empty()) {
        std::sort(messageIrqs.begin(), messageIrqs.end());
        wchar_t buffer[128] = {};
        if (messageIrqs.size() <= 4) {
            for (const long vector : messageIrqs) {
                swprintf_s(buffer, L"IRQ %ld (MSI)", vector);
                append(buffer);
            }
        } else {
            swprintf_s(buffer, L"IRQ %ld…%ld (MSI ×%zu)",
                messageIrqs.front(), messageIrqs.back(), messageIrqs.size());
            append(buffer);
        }
    }
    return text;
}

// BusTypeGuidName names the bus type GUIDs that ship with Windows. Unknown GUIDs
// deliberately fall through to their raw text instead of an invented label: a
// wrong bus name on this page would be worse than no name at all.
std::wstring BusTypeGuidName(const std::wstring& guidText) {
    static const std::map<std::wstring, const wchar_t*> names = {
        { L"{C8EBDFB0-B510-11D0-80E5-00A0C92542E3}", L"PCI" },
        { L"{9D7DEBBC-C85D-11D1-9EB4-006008C3A19A}", L"USB" },
        { L"{1530EA73-086B-11D1-A09F-00C04FC340B1}", L"Internal" },
        { L"{E676F854-D87D-11D0-92B2-00A0C9055FC5}", L"ISAPNP" },
        { L"{09343630-AF9F-11D0-92E9-0000F81E1B30}", L"PCMCIA" },
        { L"{DDC35509-F3FC-11D0-A537-0000F8753ED1}", L"EISA" },
        { L"{1C75997A-DC33-11D0-92B2-00A0C9055FC5}", L"MCA" },
        { L"{77114A87-8944-11D1-BD90-00A0C906BE2D}", L"Serenum" },
        { L"{F74E73EB-9AC5-45EB-BE4D-772CC71DDFB3}", L"IEEE 1394" },
        { L"{EEAF37D0-1963-47C4-AA48-72476DB7CF49}", L"HID" },
        { L"{C06FF265-AE09-48F0-812C-16753D7CBA83}", L"AVC" },
        { L"{7AE17DC1-C944-44D6-881F-4C2E61053BC1}", L"IrDA" },
        { L"{E700CC04-4036-4E89-9579-89EBF45F00CD}", L"SD" },
        { L"{C4CA1000-2DDC-11D5-A17A-00C04F60524D}", L"LPTENUM" },
        { L"{441EE000-4342-11D5-A184-00C04F60524D}", L"USBPRINT" },
        { L"{441EE001-4342-11D5-A184-00C04F60524D}", L"DOT4PRT" },
    };
    const auto found = names.find(guidText);
    return found != names.end() ? std::wstring(found->second) : std::wstring();
}

// LegacyBusTypeText renders the INTERFACE_TYPE enum the PnP manager reports.
// The numeric values are part of the driver ABI and are written out rather than
// pulled from wdm.h, which is a kernel-mode header this user-mode module must
// not include.
std::wstring LegacyBusTypeText(const DWORD value) {
    switch (value) {
    case 0: return L"Internal";
    case 1: return L"ISA";
    case 2: return L"EISA";
    case 3: return L"MicroChannel";
    case 4: return L"TurboChannel";
    case 5: return L"PCI";
    case 6: return L"VME";
    case 7: return L"NuBus";
    case 8: return L"PCMCIA";
    case 9: return L"CBus";
    case 10: return L"MPI";
    case 11: return L"MPSA";
    case 12: return L"ProcessorInternal";
    case 13: return L"InternalPower";
    case 14: return L"PNPISA";
    case 15: return L"PNP";
    case 16: return L"VMCS";
    case 17: return L"ACPI";
    default: return L"未知 (" + std::to_wstring(value) + L")";
    }
}

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


BusDeviceRow BusRowFromDevInfo(HDEVINFO set, SP_DEVINFO_DATA& info) {
    BusDeviceRow row;
    row.instanceId = DevInstToInstanceId(info.DevInst);
    row.description = QueryStringProperty(set, info, kPropFriendlyName);
    if (row.description.empty()) {
        row.description = QueryStringProperty(set, info, kPropDeviceDesc);
    }
    if (row.description.empty()) {
        row.description = row.instanceId;
    }
    row.manufacturer = QueryStringProperty(set, info, kPropManufacturer);
    row.enumeratorName = QueryStringProperty(set, info, kPropEnumeratorName);
    row.deviceClass = QueryStringProperty(set, info, kPropClass);
    row.service = QueryStringProperty(set, info, kPropService);
    row.driverKey = QueryStringProperty(set, info, kPropDriver);
    row.locationInfo = QueryStringProperty(set, info, kPropLocationInfo);
    row.locationPaths = QueryStringListProperty(set, info, kPropLocationPaths);

    GUID busType{};
    if (QueryGuidProperty(set, info, kPropBusTypeGuid, busType)) {
        row.busTypeGuid = GuidToString(busType);
        row.busTypeText = BusTypeGuidName(row.busTypeGuid);
    }
    DWORD numeric = 0;
    if (QueryUint32Property(set, info, kPropLegacyBusType, numeric)) {
        row.legacyBusType = LegacyBusTypeText(numeric);
        if (row.busTypeText.empty()) {
            row.busTypeText = row.legacyBusType;
        }
    }
    if (row.busTypeText.empty()) {
        row.busTypeText = row.enumeratorName;
    }
    if (QueryUint32Property(set, info, kPropBusNumber, numeric)) {
        row.busNumber = std::to_wstring(numeric);
    }
    if (QueryUint32Property(set, info, kPropAddress, numeric)) {
        // A PCI address packs the device number in the high word and the
        // function number in the low word, so the decoded pair is shown next to
        // the raw value that other tools print.
        wchar_t buffer[64] = {};
        if (row.enumeratorName == L"PCI") {
            swprintf_s(buffer, L"0x%08lX (dev %lu, func %lu)",
                static_cast<unsigned long>(numeric),
                static_cast<unsigned long>(numeric >> 16),
                static_cast<unsigned long>(numeric & 0xFFFFu));
        } else {
            swprintf_s(buffer, L"0x%08lX", static_cast<unsigned long>(numeric));
        }
        row.address = buffer;
    }
    if (QueryUint32Property(set, info, kPropUiNumber, numeric)) {
        row.uiNumber = std::to_wstring(numeric);
    }

    row.resourceText = FormatDeviceResources(info.DevInst);
    row.statusText = DescribeDeviceStatus(info.DevInst, row.problemText);
    return row;
}

void AppendBusRows(const wchar_t* enumeratorName, std::vector<BusDeviceRow>& rows, std::set<std::wstring>& seen) {
    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, enumeratorName, nullptr,
        DIGCF_PRESENT | DIGCF_ALLCLASSES));
    if (!set.valid()) {
        return;
    }
    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            break;
        }
        BusDeviceRow row = BusRowFromDevInfo(set.get(), info);
        if (row.instanceId.empty() || !seen.insert(row.instanceId).second) {
            continue;
        }
        rows.push_back(std::move(row));
    }
}

} // namespace



BusDeviceSnapshot EnumerateBusDevices(const bool includeAllEnumerators) {
    BusDeviceSnapshot snapshot;
    std::set<std::wstring> seen;

    if (includeAllEnumerators) {
        DevInfoSet set(::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES));
        if (!set.valid()) {
            snapshot.success = false;
            snapshot.diagnosticText = L"SetupDiGetClassDevsW 失败：" + Ksword::Core::LastErrorMessage();
            return snapshot;
        }
        for (DWORD ordinal = 0;; ++ordinal) {
            SP_DEVINFO_DATA info{};
            info.cbSize = sizeof(info);
            if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
                break;
            }
            BusDeviceRow row = BusRowFromDevInfo(set.get(), info);
            if (row.instanceId.empty() || !seen.insert(row.instanceId).second) {
                continue;
            }
            snapshot.rows.push_back(std::move(row));
        }
    } else {
        for (const wchar_t* enumeratorName : { L"PCI", L"ACPI", L"ACPI_HAL", L"PCIIDE", L"ROOT" }) {
            AppendBusRows(enumeratorName, snapshot.rows, seen);
        }
    }

    if (snapshot.rows.empty()) {
        snapshot.success = false;
        snapshot.diagnosticText = L"未枚举到任何总线设备：" + Ksword::Core::LastErrorMessage();
        return snapshot;
    }

    std::sort(snapshot.rows.begin(), snapshot.rows.end(),
        [](const BusDeviceRow& left, const BusDeviceRow& right) {
            if (left.enumeratorName != right.enumeratorName) {
                return left.enumeratorName < right.enumeratorName;
            }
            return left.instanceId < right.instanceId;
        });

    snapshot.success = true;
    snapshot.diagnosticText = L"共 " + std::to_wstring(snapshot.rows.size()) + L" 个总线设备。";
    return snapshot;
}

} // namespace Ksword::Features::HardwareStats
