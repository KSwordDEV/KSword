#pragma once
#include "../Common.h"
#include "UsbTopology.h"
namespace ks::r3::hardware_stats {
constexpr DEVPROPKEY kPropUiNumber = { kDevPropGuidDevice, 18 };
constexpr DEVPROPKEY kPropBusTypeGuid = { kDevPropGuidDevice, 21 };
constexpr DEVPROPKEY kPropLegacyBusType = { kDevPropGuidDevice, 22 };
constexpr DEVPROPKEY kPropBusNumber = { kDevPropGuidDevice, 23 };
constexpr DEVPROPKEY kPropEnumeratorName = { kDevPropGuidDevice, 24 };
constexpr DEVPROPKEY kPropLocationPaths = { kDevPropGuidDevice, 37 };
std::wstring GuidToString(const GUID& guid);
bool QueryGuidProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key, GUID& value);
std::wstring FormatDeviceResources(DEVINST devInst);
std::wstring BusTypeGuidName(const std::wstring& guidText);
std::wstring LegacyBusTypeText(const DWORD value);
BusDeviceRow BusRowFromDevInfo(HDEVINFO set, SP_DEVINFO_DATA& info);
void AppendBusRows(const wchar_t* enumeratorName, std::vector<BusDeviceRow>& rows, std::set<std::wstring>& seen);
BusDeviceSnapshot EnumerateBusDevices(const bool includeAllEnumerators);
}
