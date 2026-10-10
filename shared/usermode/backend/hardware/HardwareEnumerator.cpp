#include "HardwareEnumerator.h"

#include "../Common.h"

#include <algorithm>
#include <cfgmgr32.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <setupapi.h>
#include <vector>

#ifndef DN_PHANTOM
#define DN_PHANTOM 0x00004000
#endif

namespace ks::r3::hardware {
namespace {

// DevInfoSet owns a SetupAPI HDEVINFO handle. Inputs are handles from
// SetupDiGetClassDevsW or SetupDiCreateDeviceInfoList; processing releases the
// handle at scope exit; get() returns the raw handle without transferring it.
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

// JoinMultiSz converts a REG_MULTI_SZ buffer into a semicolon-separated string.
// Input is the raw UTF-16 buffer returned by SetupAPI; output is compact display
// text and is empty when the buffer has no strings.
std::wstring JoinMultiSz(const std::vector<wchar_t>& buffer) {
    std::wstring out;
    const wchar_t* cursor = buffer.data();
    const wchar_t* end = buffer.data() + buffer.size();
    while (cursor < end && *cursor) {
        const std::wstring part(cursor);
        if (!out.empty()) {
            out += L"; ";
        }
        out += part;
        cursor += part.size() + 1;
    }
    return out;
}

// RegistryTypeToString formats non-string registry data. Inputs are registry type
// and raw bytes; processing keeps display deterministic; output is readable text.
std::wstring RegistryTypeToString(DWORD type, const std::vector<BYTE>& data) {
    if ((type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) && data.size() >= sizeof(DWORD)) {
        DWORD value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        return L"0x" + std::to_wstring(value);
    }
    if (type == REG_QWORD && data.size() >= sizeof(ULONGLONG)) {
        ULONGLONG value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        return std::to_wstring(value);
    }
    return L"(" + std::to_wstring(data.size()) + L" bytes)";
}

// QueryDeviceRegistryProperty reads one SPDRP_* value as display text. Inputs are
// the device set, device info record and property identifier; processing handles
// REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ and numeric fallbacks; output is empty on
// missing or unsupported values.
bool MissingProperty(DWORD error) {
    return error == ERROR_INVALID_DATA || error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
std::wstring DecodeProperty(DWORD type,const std::vector<BYTE>& bytes,HardwareFieldEvidence& evidence) {
    evidence.type = type;
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        if (bytes.size()%sizeof(wchar_t) || bytes.size() < sizeof(wchar_t)) {evidence.malformed = true;return {};}
        std::vector<wchar_t> text(bytes.size()/sizeof(wchar_t));std::memcpy(text.data(),bytes.data(),bytes.size());
        if (text.back() != L'\0' || (type == REG_MULTI_SZ && (text.size()<2 || text[text.size()-2] != L'\0'))) {evidence.malformed = true;return {};}
        if (type != REG_MULTI_SZ) evidence.values.emplace_back(text.data());
        else {
            std::size_t position = 0;
            while (position<text.size() && text[position]) {
                const auto finish = std::find(text.begin()+position,text.end(),L'\0');
                if (finish == text.end()) {evidence.malformed = true;return {};}
                const auto length = static_cast<std::size_t>(finish-(text.begin()+position));
                evidence.values.emplace_back(text.data()+position,length);position += length+1;
            }
        }
        evidence.available = true;
        return type == REG_MULTI_SZ ? JoinMultiSz(text) : evidence.values.front();
    }
    if (type == REG_DWORD && bytes.size() == sizeof(DWORD)) {DWORD value;std::memcpy(&value,bytes.data(),sizeof(value));evidence.number = value;evidence.numeric = true;}
    else if (type == REG_QWORD && bytes.size() == sizeof(ULONGLONG)) {std::memcpy(&evidence.number,bytes.data(),sizeof(evidence.number));evidence.numeric = true;}
    else {evidence.malformed = true;return {};}
    evidence.available = true;return RegistryTypeToString(type,bytes);
}
std::wstring QueryDeviceRegistryProperty(HDEVINFO set,SP_DEVINFO_DATA& data,DWORD property,HardwareFieldEvidence* output = nullptr) {
    HardwareFieldEvidence local;auto& e = output ? *output : local;e = {};
    DWORD type = 0,needed = 0;
    if (!::SetupDiGetDeviceRegistryPropertyW(set,&data,property,&type,nullptr,0,&needed)) {
        e.error = ::GetLastError();
        if (e.error != ERROR_INSUFFICIENT_BUFFER) {e.absent = MissingProperty(e.error);return {};}
    }
    for (int attempt = 0;attempt<4;++attempt) {
        if (!needed || needed>16u*1024*1024) {e.error = ERROR_MORE_DATA;return {};}
        std::vector<BYTE> bytes(needed,BYTE{0});DWORD returned = 0;
        if (::SetupDiGetDeviceRegistryPropertyW(set,&data,property,&type,bytes.data(),needed,&returned)) {
            e.error = ERROR_SUCCESS;
            if (returned>bytes.size()) {e.malformed = true;return {};}
            bytes.resize(returned);return DecodeProperty(type,bytes,e);
        }
        e.error = ::GetLastError();if (e.error != ERROR_INSUFFICIENT_BUFFER) {e.absent = MissingProperty(e.error);return {};}
        if (returned <= needed) return {};needed = returned;
    }
    e.error = ERROR_MORE_DATA;return {};
}

// GuidToString converts a device setup class GUID to display text. Input is a
// GUID supplied by SetupAPI; processing formats locally to avoid adding a new
// link-time dependency; output is empty only if formatting fails.
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
    if (written <= 0) {
        return {};
    }
    return std::wstring(buffer);
}

// QueryDeviceRegistryMultiSz reads REG_MULTI_SZ values from a device registry
// key. Inputs are an HDEVINFO, device info, property scope and value name;
// processing opens the requested key read-only; output is semicolon-separated
// text or empty when the value/key is absent.
std::wstring QueryRegistryMultiSz(HKEY key,const wchar_t* valueName,HardwareFieldEvidence& e) {
    e = {};
    if (key == INVALID_HANDLE_VALUE) {e.error = ::GetLastError();e.absent = MissingProperty(e.error);return {};}
    DWORD type = 0,needed = 0;LONG status = ::RegQueryValueExW(key,valueName,nullptr,&type,nullptr,&needed);
    std::wstring result;
    for (int attempt = 0;status == ERROR_SUCCESS && attempt<4;++attempt) {
        if (!needed || needed>16u*1024*1024) {status = ERROR_MORE_DATA;break;}
        std::vector<BYTE> bytes(needed,BYTE{0});DWORD returned = needed;
        status = ::RegQueryValueExW(key,valueName,nullptr,&type,bytes.data(),&returned);
        if (status == ERROR_SUCCESS) {
            if (returned>bytes.size() || type != REG_MULTI_SZ) e.malformed = true;
            else {bytes.resize(returned);result = DecodeProperty(type,bytes,e);}
            break;
        }
        if (status != ERROR_MORE_DATA || returned<=needed) break;
        needed = returned;status = attempt<3 ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }
    ::RegCloseKey(key);e.error = static_cast<DWORD>(status);e.absent = MissingProperty(e.error);return result;
}
std::wstring QueryDeviceRegistryMultiSz(HDEVINFO set,SP_DEVINFO_DATA& data,DWORD scope,DWORD hardwareProfile,const wchar_t* valueName,HardwareFieldEvidence* output = nullptr) {
    HardwareFieldEvidence local;return QueryRegistryMultiSz(::SetupDiOpenDevRegKey(set,&data,scope,hardwareProfile,DIREG_DEV,KEY_QUERY_VALUE),valueName,output ? *output : local);
}
std::wstring QueryClassRegistryMultiSz(const GUID& classGuid,const wchar_t* valueName,HardwareFieldEvidence* output = nullptr) {
    HardwareFieldEvidence local;return QueryRegistryMultiSz(::SetupDiOpenClassRegKeyExW(&classGuid,KEY_QUERY_VALUE,DIOCR_INSTALLER,nullptr,nullptr),valueName,output ? *output : local);
}

// DevInstToInstanceId returns the stable PnP instance ID for one devnode. Input
// is a DEVINST from SetupAPI/CM; processing uses CM_Get_Device_IDW; output is
// empty when the devnode is invalid or was removed while enumerating.
std::wstring DevInstToInstanceId(DEVINST devInst,HardwareFieldEvidence* output = nullptr) {
    HardwareFieldEvidence local;auto& e = output ? *output : local;e = {};
    ULONG length = 0;
    e.cmStatus = ::CM_Get_Device_ID_Size(&length, devInst, 0);
    if (e.cmStatus != CR_SUCCESS) {
        return {};
    }
    if (!length || length>32767) {e.malformed = true;return {};}
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1, L'\0');
    e.cmStatus = ::CM_Get_Device_IDW(devInst, buffer.data(), static_cast<ULONG>(buffer.size()), 0);
    if (e.cmStatus != CR_SUCCESS) {
        return {};
    }
    if (std::find(buffer.begin(),buffer.end(),L'\0') == buffer.end()) {e.malformed = true;return {};}
    e.available = true;e.values.emplace_back(buffer.data());return e.values.front();
}

// QueryParentInstanceId reads the parent devnode ID through Configuration
// Manager. Input is a child DEVINST; output is empty for root devices or failed
// parent lookups.
std::wstring QueryParentInstanceId(DEVINST devInst,HardwareFieldEvidence* output = nullptr) {
    HardwareFieldEvidence local;auto& e = output ? *output : local;e = {};
    DEVINST parent = 0;
    e.cmStatus = ::CM_Get_Parent(&parent, devInst, 0);
    if (e.cmStatus != CR_SUCCESS) {
        return {};
    }
    return DevInstToInstanceId(parent,&e);
}

// StateFromStatus converts CM status/problem values to a small UI enum. Inputs
// are raw status flags and problem code; output is a HardwareDeviceState used by
// model and view formatting.
HardwareDeviceState StateFromStatus(ULONG status, ULONG problem) {
    if ((status & DN_HAS_PROBLEM) != 0) {
        if (problem == CM_PROB_DISABLED) {
            return HardwareDeviceState::Disabled;
        }
        return HardwareDeviceState::Problem;
    }
    if ((status & DN_STARTED) != 0) {
        return HardwareDeviceState::Started;
    }
    if ((status & DN_PHANTOM) != 0) {
        return HardwareDeviceState::Phantom;
    }
    if (status != 0) {
        return HardwareDeviceState::Stopped;
    }
    return HardwareDeviceState::Unknown;
}

// QueryStatus fills status flags and problem code for one device. Input is a
// DEVINST; processing uses CM_Get_DevNode_Status; output is the derived state.
HardwareDeviceState QueryStatus(DEVINST devInst, ULONG& status, ULONG& problem,HardwareFieldEvidence* output = nullptr) {
    HardwareFieldEvidence local;auto& e = output ? *output : local;e = {};
    status = 0;
    problem = 0;
    e.cmStatus = ::CM_Get_DevNode_Status(&status, &problem, devInst, 0);
    if (e.cmStatus != CR_SUCCESS) {
        return HardwareDeviceState::Unknown;
    }
    e.available = true;return StateFromStatus(status, problem);
}

// AppendProperty adds a live detail row when a value exists. Inputs are mutable
// detail, label and value; processing filters empty values; no return.
void AppendProperty(HardwareDeviceDetail& detail, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        detail.properties.push_back({ name, value });
    }
}

// PopulateNodeFromDevInfo converts one SP_DEVINFO_DATA into the module model.
// Inputs are a SetupAPI set, info data and index; processing queries SetupAPI and
// CM fields; output is one HardwareDeviceNode with no child links yet.
HardwareDeviceNode PopulateNodeFromDevInfo(HDEVINFO set, SP_DEVINFO_DATA& info, int index) {
    HardwareDeviceNode node;
    node.index = index;
    node.devInst = info.DevInst;
    node.instanceId = DevInstToInstanceId(info.DevInst,&node.evidence[L"instanceId"]);
    node.parentInstanceId = QueryParentInstanceId(info.DevInst,&node.evidence[L"parentInstanceId"]);
    node.classGuid = GuidToString(info.ClassGuid);node.evidence[L"classGuid"].available = !node.classGuid.empty();node.evidence[L"classGuid"].values = {node.classGuid};
    node.displayName = QueryDeviceRegistryProperty(set, info, SPDRP_FRIENDLYNAME,&node.evidence[L"friendlyName"]);
    node.evidence[L"displayName"] = node.evidence[L"friendlyName"];
    if (node.displayName.empty()) {
        node.displayName = QueryDeviceRegistryProperty(set, info, SPDRP_DEVICEDESC,&node.evidence[L"deviceDescription"]);
        node.evidence[L"displayName"] = node.evidence[L"deviceDescription"];
    }
    node.className = QueryDeviceRegistryProperty(set, info, SPDRP_CLASS,&node.evidence[L"className"]);
    node.manufacturer = QueryDeviceRegistryProperty(set, info, SPDRP_MFG,&node.evidence[L"manufacturer"]);
    node.serviceName = QueryDeviceRegistryProperty(set, info, SPDRP_SERVICE,&node.evidence[L"serviceName"]);
    node.driverKey = QueryDeviceRegistryProperty(set, info, SPDRP_DRIVER,&node.evidence[L"driverKey"]);
    node.location = QueryDeviceRegistryProperty(set, info, SPDRP_LOCATION_INFORMATION,&node.evidence[L"location"]);
    node.locationPaths = QueryDeviceRegistryProperty(set, info, SPDRP_LOCATION_PATHS,&node.evidence[L"locationPaths"]);
    node.hardwareIds = QueryDeviceRegistryProperty(set, info, SPDRP_HARDWAREID,&node.evidence[L"hardwareIds"]);
    node.compatibleIds = QueryDeviceRegistryProperty(set, info, SPDRP_COMPATIBLEIDS,&node.evidence[L"compatibleIds"]);
    node.upperFilters = QueryDeviceRegistryMultiSz(set, info, DICS_FLAG_GLOBAL, 0, L"UpperFilters",&node.evidence[L"upperFilters"]);
    node.lowerFilters = QueryDeviceRegistryMultiSz(set, info, DICS_FLAG_GLOBAL, 0, L"LowerFilters",&node.evidence[L"lowerFilters"]);
    node.classUpperFilters = QueryClassRegistryMultiSz(info.ClassGuid, L"UpperFilters",&node.evidence[L"classUpperFilters"]);
    node.classLowerFilters = QueryClassRegistryMultiSz(info.ClassGuid, L"LowerFilters",&node.evidence[L"classLowerFilters"]);
    node.state = QueryStatus(info.DevInst, node.statusFlags, node.problemCode,&node.evidence[L"status"]);
    return node;
}

// RebuildHierarchy links device nodes using parent instance IDs. Input is a flat
// device vector; processing fills parentIndex, depth, and childIndices fields; no
// value is returned.
void RebuildHierarchy(std::vector<HardwareDeviceNode>& devices) {
    std::map<std::wstring, int> byInstance;
    for (HardwareDeviceNode& node : devices) {
        node.parentIndex = -1;
        node.depth = 0;
        node.childIndices.clear();
        if (!node.instanceId.empty()) {
            byInstance[node.instanceId] = node.index;
        }
    }

    for (HardwareDeviceNode& node : devices) {
        if (node.parentInstanceId.empty()) {
            continue;
        }
        const auto found = byInstance.find(node.parentInstanceId);
        if (found != byInstance.end() && found->second != node.index) {
            node.parentIndex = found->second;
            devices[found->second].childIndices.push_back(node.index);
        }
    }

    for (HardwareDeviceNode& node : devices) {
        int depth = 0;
        int parent = node.parentIndex;
        while (parent >= 0 && parent < static_cast<int>(devices.size()) && depth < 64) {
            ++depth;
            parent = devices[parent].parentIndex;
        }
        node.depth = depth;
    }

    for (HardwareDeviceNode& node : devices) {
        std::sort(node.childIndices.begin(), node.childIndices.end(), [&devices](int left, int right) {
            return CompactDeviceName(devices[left]) < CompactDeviceName(devices[right]);
        });
    }
}

// FindDeviceByInstanceId opens a specific devnode into an existing read-only
// enumeration set. Inputs are an HDEVINFO and instance ID; processing calls
// SetupDiOpenDeviceInfoW only to address the devnode for property queries; output
// is true when infoData has been initialized for the matching device.
bool FindDeviceByInstanceId(HDEVINFO set, const std::wstring& instanceId, SP_DEVINFO_DATA& infoData) {
    infoData = {};
    infoData.cbSize = sizeof(infoData);
    return ::SetupDiOpenDeviceInfoW(set, instanceId.c_str(), nullptr, 0, &infoData) == TRUE;
}

} // namespace

HardwareEnumerationResult EnumerateDeviceManagerTree(bool presentOnly) {
    HardwareEnumerationResult result;
    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | (presentOnly ? DIGCF_PRESENT : 0)));
    if (!set.valid()) {
        result.success = false;result.win32Error = ::GetLastError();
        result.diagnosticText = L"SetupDiGetClassDevsW failed: " + ks::r3::common::LastErrorMessage();
        return result;
    }

    for (DWORD ordinal = 0;ordinal<100000;++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                result.complete = true;break;
            }
            result.success = false;result.win32Error = error;
            result.diagnosticText = L"SetupDiEnumDeviceInfo failed: " + ks::r3::common::LastErrorMessage(error);
            return result;
        }
        result.devices.push_back(PopulateNodeFromDevInfo(set.get(), info, static_cast<int>(result.devices.size())));
    }

    if (!result.complete) {result.limited = true;result.win32Error = ERROR_MORE_DATA;}
    RebuildHierarchy(result.devices);
    std::sort(result.devices.begin(), result.devices.end(), [](const HardwareDeviceNode& left, const HardwareDeviceNode& right) {
        if (left.parentIndex != right.parentIndex) {
            return left.parentIndex < right.parentIndex;
        }
        return CompactDeviceName(left) < CompactDeviceName(right);
    });
    for (int i = 0; i < static_cast<int>(result.devices.size()); ++i) {
        result.devices[i].index = i;
    }
    RebuildHierarchy(result.devices);

    result.success = true;
    result.diagnosticText = L"OK";
    return result;
}

HardwareDeviceDetail QueryDeviceManagerDetails(const std::wstring& instanceId) {
    HardwareDeviceDetail detail;
    detail.instanceId = instanceId;
    if (instanceId.empty()) {
        return detail;
    }

    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES));
    if (!set.valid()) {
        detail.win32Error = ::GetLastError();return detail;
    }

    SP_DEVINFO_DATA info{};
    if (!FindDeviceByInstanceId(set.get(), instanceId, info)) {
        detail.win32Error = ::GetLastError();return detail;
    }

    HardwareDeviceNode node = PopulateNodeFromDevInfo(set.get(), info, 0);
    detail.node = node;detail.found = true;
    detail.title = CompactDeviceName(node);
    detail.instanceId = node.instanceId;
    AppendProperty(detail, L"Display name", CompactDeviceName(node));
    AppendProperty(detail, L"Instance ID", node.instanceId);
    AppendProperty(detail, L"Parent instance ID", node.parentInstanceId);
    AppendProperty(detail, L"Class", node.className);
    AppendProperty(detail, L"Class GUID", node.classGuid);
    AppendProperty(detail, L"Manufacturer", node.manufacturer);
    AppendProperty(detail, L"Service", node.serviceName);
    AppendProperty(detail, L"Driver key", node.driverKey);
    AppendProperty(detail, L"Location", node.location);
    AppendProperty(detail, L"Location paths", node.locationPaths);
    AppendProperty(detail, L"Hardware IDs", node.hardwareIds);
    AppendProperty(detail, L"Compatible IDs", node.compatibleIds);
    AppendProperty(detail, L"Device UpperFilters", node.upperFilters);
    AppendProperty(detail, L"Device LowerFilters", node.lowerFilters);
    AppendProperty(detail, L"Class UpperFilters", node.classUpperFilters);
    AppendProperty(detail, L"Class LowerFilters", node.classLowerFilters);
    AppendProperty(detail, L"State", DeviceStateText(node.state, node.problemCode));
    AppendProperty(detail, L"Status flags", L"0x" + std::to_wstring(node.statusFlags));
    AppendProperty(detail, L"Problem code", std::to_wstring(node.problemCode));
    return detail;
}

} // namespace ks::r3::hardware
