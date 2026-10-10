#include "BusTopology.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <utility>
#pragma comment(lib,"Setupapi.lib")
#pragma comment(lib,"Cfgmgr32.lib")
namespace ks::r3::hardware_stats {
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
bool QueryGuidProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key, GUID& value,ks::r3::hardware::HardwareFieldEvidence* output) {
    ks::r3::hardware::HardwareFieldEvidence local;auto& e = output ? *output : local;
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data,&e)) return false;
    if (data.size() != sizeof(GUID) || type != DEVPROP_TYPE_GUID) {e.available = false;e.malformed = true;return false;}
    std::memcpy(&value, data.data(), sizeof(value));e.values = {GuidToString(value)};
    return true;
}
std::wstring FormatDeviceResources(DEVINST devInst,BusResourceEvidence* output) {
    BusResourceEvidence local;auto& e = output ? *output : local;e = {};
    LOG_CONF logConf = 0;
    CONFIGRET result = ::CM_Get_First_Log_Conf(&logConf, devInst, ALLOC_LOG_CONF);
    e.allocatedStatus = result;
    if (result != CR_SUCCESS) {
        result = ::CM_Get_First_Log_Conf(&logConf, devInst, BOOT_LOG_CONF);e.bootStatusKnown = true;e.bootStatus = result;e.usedBoot = result == CR_SUCCESS;
    }
    if (result != CR_SUCCESS) {
        e.noConfiguration = e.allocatedStatus == CR_NO_MORE_LOG_CONF && result == CR_NO_MORE_LOG_CONF;
        e.available = e.noConfiguration;e.complete = e.noConfiguration;return {};
    }
    e.available = true;
    struct Owners {
        LOG_CONF log;BusResourceEvidence& evidence;RES_DES current;bool owned = false,logOwned = true;
        void closeResource() {
            if (!owned) return;const auto code = ::CM_Free_Res_Des_Handle(current);owned = false;evidence.resourceFreeKnown = true;
            if (code != CR_SUCCESS) {evidence.resourceFreeStatus = code;evidence.cleanupComplete = false;}
        }
        void closeLog() {if (!logOwned) return;const auto code = ::CM_Free_Log_Conf_Handle(log);logOwned = false;evidence.logFreeKnown = true;evidence.logFreeStatus = code;evidence.cleanupComplete = evidence.cleanupComplete && code == CR_SUCCESS;}
        ~Owners() {closeResource();closeLog();}
    } owner{logConf,e,static_cast<RES_DES>(logConf)};

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

    for (DWORD ordinal = 0;ordinal<4096;++ordinal) {
        RES_DES next = 0;
        RESOURCEID resourceType = 0;
        const CONFIGRET step = ::CM_Get_Next_Res_Des(&next, owner.current, ResType_All, &resourceType, 0);
        owner.closeResource();
        if (step != CR_SUCCESS) {e.terminalKnown = true;e.terminalStatus = step;break;}
        owner.current = next;owner.owned = true;
        BusResourceRow row;row.ordinal = ordinal;row.type = resourceType;++e.descriptorCount;

        ULONG size = 0;
        row.sizeStatus = ::CM_Get_Res_Des_Data_Size(&size,owner.current,0);row.sizeKnown = row.sizeStatus == CR_SUCCESS;row.dataSize = size;
        // ResType_None is an arbitration placeholder with a legitimately empty
        // payload, not a short MEM/IRQ descriptor.
        if (row.sizeKnown && resourceType == ResType_None && !size) {
            row.kind = L"none";row.dataKnown = true;row.interpreted = true;e.rows.push_back(std::move(row));continue;
        }
        if (!row.sizeKnown || !size || size>16u*1024*1024) {
            row.malformed = row.sizeKnown && !size;e.malformed = e.malformed || row.malformed;e.limited = e.limited || size>16u*1024*1024;
            ++e.skippedCount;e.rows.push_back(std::move(row));continue;
        }
        std::vector<BYTE> data(size,BYTE{0});row.dataStatus = ::CM_Get_Res_Des_Data(owner.current,data.data(),size,0);row.dataKnown = row.dataStatus == CR_SUCCESS;
        if (!row.dataKnown) {++e.skippedCount;e.rows.push_back(std::move(row));continue;}
        row.rawPreview.assign(data.begin(),data.begin()+(std::min)(data.size(),std::size_t{256}));

        wchar_t buffer[128] = {};
        switch (resourceType) {
        case ResType_Mem:
            if (data.size() >= sizeof(MEM_DES)) {
                const auto* description = reinterpret_cast<const MEM_DES*>(data.data());
                row.kind = L"memory";row.base = description->MD_Alloc_Base;row.endInclusive = description->MD_Alloc_End;row.rangeKnown = row.endInclusive >= row.base;row.interpreted = true;row.malformed = !row.rangeKnown;
                swprintf_s(buffer, L"MEM 0x%016llX-0x%016llX",
                    static_cast<unsigned long long>(description->MD_Alloc_Base),
                    static_cast<unsigned long long>(description->MD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_MemLarge:
            if (data.size() >= sizeof(MEM_LARGE_DES)) {
                const auto* description = reinterpret_cast<const MEM_LARGE_DES*>(data.data());
                row.kind = L"memory-large";row.base = description->MLD_Alloc_Base;row.endInclusive = description->MLD_Alloc_End;row.rangeKnown = row.endInclusive >= row.base;row.interpreted = true;row.malformed = !row.rangeKnown;
                swprintf_s(buffer, L"MEM64 0x%016llX-0x%016llX",
                    static_cast<unsigned long long>(description->MLD_Alloc_Base),
                    static_cast<unsigned long long>(description->MLD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_IO:
            if (data.size() >= sizeof(IO_DES)) {
                const auto* description = reinterpret_cast<const IO_DES*>(data.data());
                row.kind = L"io";row.base = description->IOD_Alloc_Base;row.endInclusive = description->IOD_Alloc_End;row.rangeKnown = row.endInclusive >= row.base;row.interpreted = true;row.malformed = !row.rangeKnown;
                swprintf_s(buffer, L"IO 0x%04llX-0x%04llX",
                    static_cast<unsigned long long>(description->IOD_Alloc_Base),
                    static_cast<unsigned long long>(description->IOD_Alloc_End));
                append(buffer);
            }
            break;
        case ResType_DMA:
            if (data.size() >= sizeof(DMA_DES)) {
                const auto* description = reinterpret_cast<const DMA_DES*>(data.data());
                row.kind = L"dma";row.number = description->DD_Alloc_Chan;row.numberKnown = true;row.interpreted = true;
                swprintf_s(buffer, L"DMA %lu", static_cast<unsigned long>(description->DD_Alloc_Chan));
                append(buffer);
            }
            break;
        case ResType_IRQ:
            if (data.size() >= sizeof(IRQ_DES)) {
                const auto* description = reinterpret_cast<const IRQ_DES*>(data.data());
                const ULONG allocated = description->IRQD_Alloc_Num;
                row.kind = L"irq";row.number = allocated;row.numberKnown = true;row.interpreted = true;
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
            if (data.size() >= sizeof(BUSNUMBER_DES)) {const auto* description = reinterpret_cast<const BUSNUMBER_DES*>(data.data());row.kind = L"bus-number";row.base = description->BUSD_Alloc_Base;row.endInclusive = description->BUSD_Alloc_End;row.rangeKnown = row.endInclusive >= row.base;row.interpreted = true;row.malformed = !row.rangeKnown;}
            append(L"BUS");
            break;
        default:
            break;
        }
        if (!row.interpreted) {
            const bool known = resourceType == ResType_Mem || resourceType == ResType_MemLarge || resourceType == ResType_IO || resourceType == ResType_IRQ || resourceType == ResType_DMA || resourceType == ResType_BusNumber;
            row.malformed = known;if (!known) row.kind = L"other";++e.skippedCount;
        }
        e.malformed = e.malformed || row.malformed;e.rows.push_back(std::move(row));
    }
    if (!e.terminalKnown) e.limited = true;
    owner.closeResource();owner.closeLog();
    e.complete = e.terminalKnown && e.terminalStatus == CR_NO_MORE_RES_DES && !e.skippedCount && !e.limited && !e.malformed && e.cleanupComplete && (e.allocatedStatus == CR_SUCCESS || e.allocatedStatus == CR_NO_MORE_LOG_CONF);

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
BusDeviceRow BusRowFromDevInfo(HDEVINFO set, SP_DEVINFO_DATA& info) {
    BusDeviceRow row;
    row.instanceId = DevInstToInstanceId(info.DevInst,&row.evidence[L"instanceId"]);
    row.description = QueryStringProperty(set, info, kPropFriendlyName,&row.evidence[L"friendlyName"]);
    row.evidence[L"description"] = row.evidence[L"friendlyName"];
    if (row.description.empty()) {
        row.description = QueryStringProperty(set, info, kPropDeviceDesc,&row.evidence[L"deviceDescription"]);
        row.evidence[L"description"] = row.evidence[L"deviceDescription"];
    }
    if (row.description.empty()) {
        row.description = row.instanceId;
    }
    row.manufacturer = QueryStringProperty(set, info, kPropManufacturer,&row.evidence[L"manufacturer"]);
    row.enumeratorName = QueryStringProperty(set, info, kPropEnumeratorName,&row.evidence[L"enumeratorName"]);
    row.deviceClass = QueryStringProperty(set, info, kPropClass,&row.evidence[L"deviceClass"]);
    row.service = QueryStringProperty(set, info, kPropService,&row.evidence[L"service"]);
    row.driverKey = QueryStringProperty(set, info, kPropDriver,&row.evidence[L"driverKey"]);
    row.locationInfo = QueryStringProperty(set, info, kPropLocationInfo,&row.evidence[L"locationInfo"]);
    row.locationPaths = QueryStringListProperty(set, info, kPropLocationPaths,&row.evidence[L"locationPaths"]);

    GUID busType{};
    if (QueryGuidProperty(set, info, kPropBusTypeGuid, busType,&row.evidence[L"busTypeGuid"])) {
        row.busTypeGuid = GuidToString(busType);
        row.busTypeText = BusTypeGuidName(row.busTypeGuid);
    }
    DWORD numeric = 0;
    if (QueryUint32Property(set, info, kPropLegacyBusType, numeric,&row.evidence[L"legacyBusType"])) {
        row.legacyBusType = LegacyBusTypeText(numeric);
        if (row.busTypeText.empty()) {
            row.busTypeText = row.legacyBusType;
        }
    }
    if (row.busTypeText.empty()) {
        row.busTypeText = row.enumeratorName;
    }
    if (QueryUint32Property(set, info, kPropBusNumber, numeric,&row.evidence[L"busNumber"])) {
        row.busNumber = std::to_wstring(numeric);
    }
    if (QueryUint32Property(set, info, kPropAddress, numeric,&row.evidence[L"address"])) {
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
    if (QueryUint32Property(set, info, kPropUiNumber, numeric,&row.evidence[L"uiNumber"])) {
        row.uiNumber = std::to_wstring(numeric);
    }

    row.resourceText = FormatDeviceResources(info.DevInst,&row.resources);
    row.statusText = DescribeDeviceStatus(info.DevInst, row.problemText,&row.statusFlags,&row.problemCode,&row.statusResult);row.statusKnown = row.statusResult == CR_SUCCESS;
    return row;
}
void AppendBusRows(const wchar_t* enumeratorName,std::vector<BusDeviceRow>& rows,std::set<std::wstring>& seen,UsbEnumerationSource* output) {
    UsbEnumerationSource local;auto& e = output ? *output : local;e = {};e.name = enumeratorName ? enumeratorName : L"all";
    DevInfoSet set(::SetupDiGetClassDevsW(nullptr,enumeratorName,nullptr,DIGCF_PRESENT | DIGCF_ALLCLASSES));
    if (!set.valid()) {e.win32Error = ::GetLastError();return;}e.opened = true;
    for (DWORD ordinal = 0;ordinal<100000;++ordinal) {
        SP_DEVINFO_DATA info{};info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(),ordinal,&info)) {const auto error = ::GetLastError();e.complete = error == ERROR_NO_MORE_ITEMS;if (!e.complete) e.win32Error = error;break;}
        ++e.examinedCount;BusDeviceRow row = BusRowFromDevInfo(set.get(),info);row.enumerationSource = e.name;
        if (row.instanceId.empty()) {++e.skippedCount;e.cmStatus = row.evidence[L"instanceId"].cmStatus;e.malformed = e.malformed || row.evidence[L"instanceId"].malformed;continue;}
        if (!seen.insert(row.instanceId).second) continue;rows.push_back(std::move(row));
    }
    if (!e.complete && !e.win32Error) {e.limited = true;e.win32Error = ERROR_MORE_DATA;}
}
BusDeviceSnapshot EnumerateBusDevices(const bool includeAllEnumerators) {
    BusDeviceSnapshot snapshot;
    std::set<std::wstring> seen;

    if (includeAllEnumerators) {
        snapshot.sources.resize(1);AppendBusRows(nullptr,snapshot.rows,seen,&snapshot.sources[0]);
        if (!snapshot.sources[0].opened) {
            snapshot.success = false;snapshot.diagnosticText = L"SetupDiGetClassDevsW 失败：" + ks::r3::common::LastErrorMessage();return snapshot;
        }
    } else {
        snapshot.sources.resize(5);std::size_t i = 0;
        for (const wchar_t* enumeratorName : {L"PCI",L"ACPI",L"ACPI_HAL",L"PCIIDE",L"ROOT"}) AppendBusRows(enumeratorName,snapshot.rows,seen,&snapshot.sources[i++]);
    }

    if (snapshot.rows.empty()) {
        snapshot.success = false;
        snapshot.diagnosticText = L"未枚举到任何总线设备：" + ks::r3::common::LastErrorMessage();
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
}
