#pragma once
#include "../Common.h"
#include "HardwareStatsTypes.h"
#include <cfgmgr32.h>
#include <setupapi.h>
#include <set>
#include <map>
#ifndef DN_PHANTOM
#define DN_PHANTOM 0x00004000
#endif
namespace ks::r3::hardware_stats {
constexpr GUID kDevPropGuidDevice =
    { 0xa45c254e, 0xdf1c, 0x4efd, { 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0 } };
constexpr DEVPROPKEY kPropDeviceDesc = { kDevPropGuidDevice, 2 };
constexpr DEVPROPKEY kPropHardwareIds = { kDevPropGuidDevice, 3 };
constexpr DEVPROPKEY kPropService = { kDevPropGuidDevice, 6 };
constexpr DEVPROPKEY kPropClass = { kDevPropGuidDevice, 9 };
constexpr DEVPROPKEY kPropDriver = { kDevPropGuidDevice, 11 };
constexpr DEVPROPKEY kPropManufacturer = { kDevPropGuidDevice, 13 };
constexpr DEVPROPKEY kPropFriendlyName = { kDevPropGuidDevice, 14 };
constexpr DEVPROPKEY kPropLocationInfo = { kDevPropGuidDevice, 15 };
constexpr DEVPROPKEY kPropAddress = { kDevPropGuidDevice, 30 };
constexpr GUID kUsbDeviceInterface =
    { 0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } };
constexpr GUID kUsbHubInterface =
    { 0xF18A0E88, 0xC30C, 0x11D0, { 0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8 } };
constexpr GUID kUsbHostControllerInterface =
    { 0x3ABF6F2D, 0x71C4, 0x462A, { 0x8A, 0x92, 0x1E, 0x68, 0x61, 0xE6, 0xAF, 0x27 } };
class DevInfoSet final {
public:
    explicit DevInfoSet(HDEVINFO handle) : handle_(handle) {}
    ~DevInfoSet() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            ::SetupDiDestroyDeviceInfoList(handle_);
        }
    }

    DevInfoSet(const DevInfoSet&) = delete;
    DevInfoSet& operator=(const DevInfoSet&) = delete;

    HDEVINFO get() const { return handle_; }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HDEVINFO handle_;
};
bool QueryRawProperty(HDEVINFO set,
    SP_DEVINFO_DATA& info,
    const DEVPROPKEY& key,
    DEVPROPTYPE& type,
    std::vector<BYTE>& data);
std::wstring JoinStringList(const std::vector<BYTE>& data);
std::wstring QueryStringProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key);
std::wstring QueryStringListProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key);
bool QueryUint32Property(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key, DWORD& value);
std::wstring DevInstToInstanceId(DEVINST devInst);
std::wstring ParentInstanceId(DEVINST devInst);
std::wstring ProblemCodeText(const ULONG problem);
std::wstring DescribeDeviceStatus(DEVINST devInst, std::wstring& problemText);
std::set<std::wstring> CollectInterfaceOwners(const GUID& interfaceGuid);
std::wstring ExtractHexField(const std::wstring& text, const wchar_t* marker, const std::size_t width);
std::wstring SerialNumberFromInstanceId(const std::wstring& instanceId);
UsbNode UsbNodeFromDevInfo(HDEVINFO set,
    SP_DEVINFO_DATA& info,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers);
void AppendEnumeratorNodes(const wchar_t* enumeratorName,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers,
    std::vector<UsbNode>& nodes,
    std::set<std::wstring>& seen);
void AppendInterfaceNodes(const GUID& interfaceGuid,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers,
    std::vector<UsbNode>& nodes,
    std::set<std::wstring>& seen);
std::vector<UsbNode> OrderUsbNodesDepthFirst(std::vector<UsbNode> nodes);
UsbTopologySnapshot EnumerateUsbTopology();
}
