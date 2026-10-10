#include "UsbTopology.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <utility>
#pragma comment(lib,"Setupapi.lib")
#pragma comment(lib,"Cfgmgr32.lib")
namespace ks::r3::hardware_stats {
using FieldEvidence = ks::r3::hardware::HardwareFieldEvidence;
bool QueryRawProperty(HDEVINFO set,SP_DEVINFO_DATA& info,const DEVPROPKEY& key,DEVPROPTYPE& type,std::vector<BYTE>& data,FieldEvidence* output) {
    FieldEvidence local;auto& e = output ? *output : local;e = {};type = 0;data.clear();DWORD needed = 0;
    if (!::SetupDiGetDevicePropertyW(set,&info,&key,&type,nullptr,0,&needed,0)) {
        e.error = ::GetLastError();
        if (e.error != ERROR_INSUFFICIENT_BUFFER) {e.absent = e.error == ERROR_NOT_FOUND || e.error == ERROR_FILE_NOT_FOUND;return false;}
    }
    for (int attempt = 0;attempt<4;++attempt) {
        if (!needed || needed>16u*1024*1024) {e.error = ERROR_MORE_DATA;return false;}
        data.assign(needed,BYTE{0});DWORD returned = 0;
        if (::SetupDiGetDevicePropertyW(set,&info,&key,&type,data.data(),needed,&returned,0)) {
            e.error = ERROR_SUCCESS;e.type = type;
            if (returned>data.size()) {e.malformed = true;data.clear();return false;}
            data.resize(returned);e.available = true;return true;
        }
        e.error = ::GetLastError();data.clear();
        if (e.error != ERROR_INSUFFICIENT_BUFFER) {e.absent = e.error == ERROR_NOT_FOUND || e.error == ERROR_FILE_NOT_FOUND;return false;}
        if (returned<=needed) return false;needed = returned;
    }
    e.error = ERROR_MORE_DATA;return false;
}
std::wstring JoinStringList(const std::vector<BYTE>& data) {
    if (data.size()%sizeof(wchar_t)) return {};
    std::vector<wchar_t> text(data.size()/sizeof(wchar_t));if (text.empty()) return {};std::memcpy(text.data(),data.data(),data.size());
    std::wstring result;std::size_t position = 0;
    while (position<text.size() && text[position]) {
        const auto finish = std::find(text.begin()+position,text.end(),L'\0');if (finish == text.end()) return {};
        if (!result.empty()) result += L"; ";const auto length = static_cast<std::size_t>(finish-(text.begin()+position));
        result.append(text.data()+position,length);position += length+1;
    }
    return result;
}
std::wstring QueryStringProperty(HDEVINFO set,SP_DEVINFO_DATA& info,const DEVPROPKEY& key,FieldEvidence* output) {
    FieldEvidence local;auto& e = output ? *output : local;DEVPROPTYPE type = 0;std::vector<BYTE> data;
    if (!QueryRawProperty(set,info,key,type,data,&e)) return {};
    e.available = false;
    if ((type != DEVPROP_TYPE_STRING && type != DEVPROP_TYPE_STRING_LIST) || data.empty() || data.size()%sizeof(wchar_t)) {e.malformed = true;return {};}
    std::vector<wchar_t> text(data.size()/sizeof(wchar_t));std::memcpy(text.data(),data.data(),data.size());
    if (text.back() != L'\0' || (type == DEVPROP_TYPE_STRING_LIST && (text.size()<2 || text[text.size()-2] != L'\0'))) {e.malformed = true;return {};}
    if (type == DEVPROP_TYPE_STRING) e.values.emplace_back(text.data());
    else {std::size_t position = 0;while (position<text.size() && text[position]) {
        const auto finish = std::find(text.begin()+position,text.end(),L'\0');const auto length = static_cast<std::size_t>(finish-(text.begin()+position));
        e.values.emplace_back(text.data()+position,length);position += length+1;
    }}
    e.available = true;return type == DEVPROP_TYPE_STRING_LIST ? JoinStringList(data) : e.values.front();
}
std::wstring QueryStringListProperty(HDEVINFO set,SP_DEVINFO_DATA& info,const DEVPROPKEY& key,FieldEvidence* output) {
    return QueryStringProperty(set,info,key,output);
}
bool QueryUint32Property(HDEVINFO set,SP_DEVINFO_DATA& info,const DEVPROPKEY& key,DWORD& value,FieldEvidence* output) {
    FieldEvidence local;auto& e = output ? *output : local;DEVPROPTYPE type = 0;std::vector<BYTE> data;
    if (!QueryRawProperty(set,info,key,type,data,&e)) return false;
    if ((type != DEVPROP_TYPE_UINT32 && type != DEVPROP_TYPE_INT32) || data.size() != sizeof(DWORD)) {e.available = false;e.malformed = true;return false;}
    std::memcpy(&value,data.data(),sizeof(value));e.numeric = true;e.number = value;return true;
}
std::wstring DevInstToInstanceId(DEVINST devInst,FieldEvidence* output) {
    FieldEvidence local;auto& e = output ? *output : local;e = {};ULONG length = 0;
    e.cmStatus = ::CM_Get_Device_ID_Size(&length,devInst,0);if (e.cmStatus != CR_SUCCESS) return {};
    if (!length || length>32767) {e.malformed = true;return {};}
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length)+1,L'\0');
    e.cmStatus = ::CM_Get_Device_IDW(devInst,buffer.data(),static_cast<ULONG>(buffer.size()),0);if (e.cmStatus != CR_SUCCESS) return {};
    if (buffer.back() != L'\0') {e.malformed = true;return {};}
    e.available = true;e.values.emplace_back(buffer.data());return e.values.front();
}
std::wstring ParentInstanceId(DEVINST devInst,FieldEvidence* output) {
    FieldEvidence local;auto& e = output ? *output : local;e = {};DEVINST parent = 0;
    e.cmStatus = ::CM_Get_Parent(&parent,devInst,0);if (e.cmStatus != CR_SUCCESS) return {};
    return DevInstToInstanceId(parent,&e);
}
std::wstring ProblemCodeText(const ULONG problem) {
    switch (problem) {
    case CM_PROB_NOT_CONFIGURED: return L"未配置驱动（CM_PROB_NOT_CONFIGURED）";
    case CM_PROB_OUT_OF_MEMORY: return L"资源不足（CM_PROB_OUT_OF_MEMORY）";
    case CM_PROB_FAILED_START: return L"启动失败（CM_PROB_FAILED_START）";
    case CM_PROB_NORMAL_CONFLICT: return L"资源冲突（CM_PROB_NORMAL_CONFLICT）";
    case CM_PROB_NEED_RESTART: return L"需要重启（CM_PROB_NEED_RESTART）";
    case CM_PROB_DISABLED: return L"已被禁用（CM_PROB_DISABLED）";
    case CM_PROB_DEVICE_NOT_THERE: return L"设备不存在（CM_PROB_DEVICE_NOT_THERE）";
    case CM_PROB_DRIVER_FAILED_LOAD: return L"驱动加载失败（CM_PROB_DRIVER_FAILED_LOAD）";
    case CM_PROB_HELD_FOR_EJECT: return L"等待弹出（CM_PROB_HELD_FOR_EJECT）";
    case 0: return {};
    default: return L"问题代码 " + std::to_wstring(problem);
    }
}
std::wstring DescribeDeviceStatus(DEVINST devInst, std::wstring& problemText,ULONG* flags,ULONG* problemCode,CONFIGRET* result) {
    ULONG status = 0;
    ULONG problem = 0;
    problemText.clear();
    const auto code = ::CM_Get_DevNode_Status(&status,&problem,devInst,0);
    if (flags) *flags = status;if (problemCode) *problemCode = problem;if (result) *result = code;
    if (code != CR_SUCCESS) {
        return L"未知";
    }
    problemText = ProblemCodeText(problem);
    if ((status & DN_HAS_PROBLEM) != 0) {
        return problem == CM_PROB_DISABLED ? L"已禁用" : L"有问题";
    }
    if ((status & DN_STARTED) != 0) {
        return L"已启动";
    }
    if ((status & DN_PHANTOM) != 0) {
        return L"幻影节点";
    }
    return status != 0 ? L"已停止" : L"未知";
}
std::set<std::wstring> CollectInterfaceOwners(const GUID& interfaceGuid,UsbEnumerationSource* output) {
    UsbEnumerationSource local;auto& e = output ? *output : local;e = {};
    std::set<std::wstring> owners;
    DevInfoSet set(::SetupDiGetClassDevsW(&interfaceGuid, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (!set.valid()) {
        e.win32Error = ::GetLastError();return owners;
    }
    e.opened = true;
    for (DWORD ordinal = 0;ordinal<100000;++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            const auto error = ::GetLastError();e.complete = error == ERROR_NO_MORE_ITEMS;if (!e.complete) e.win32Error = error;break;
        }
        ++e.examinedCount;FieldEvidence identity;std::wstring instanceId = DevInstToInstanceId(info.DevInst,&identity);
        if (!identity.available) {++e.skippedCount;e.cmStatus = identity.cmStatus;e.malformed = e.malformed || identity.malformed;}
        if (!instanceId.empty()) {
            owners.insert(std::move(instanceId));
        }
    }
    if (!e.complete && !e.win32Error) {e.limited = true;e.win32Error = ERROR_MORE_DATA;}
    return owners;
}
std::wstring ExtractHexField(const std::wstring& text, const wchar_t* marker, const std::size_t width) {
    const std::size_t position = text.find(marker);
    if (position == std::wstring::npos) {
        return {};
    }
    const std::size_t start = position + std::wcslen(marker);
    if (start + width > text.size()) {
        return {};
    }
    const std::wstring field = text.substr(start, width);
    for (const wchar_t character : field) {
        const bool isHex = (character >= L'0' && character <= L'9') ||
            (character >= L'A' && character <= L'F') ||
            (character >= L'a' && character <= L'f');
        if (!isHex) {
            return {};
        }
    }
    return field;
}
std::wstring SerialNumberFromInstanceId(const std::wstring& instanceId) {
    const std::size_t lastSeparator = instanceId.rfind(L'\\');
    if (lastSeparator == std::wstring::npos || lastSeparator + 1 >= instanceId.size()) {
        return {};
    }
    const std::wstring segment = instanceId.substr(lastSeparator + 1);
    if (segment.find(L'&') != std::wstring::npos) {
        return {};
    }
    return segment;
}
UsbNode UsbNodeFromDevInfo(HDEVINFO set,
    SP_DEVINFO_DATA& info,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers) {
    UsbNode node;
    node.instanceId = DevInstToInstanceId(info.DevInst,&node.evidence[L"instanceId"]);
    node.parentInstanceId = ParentInstanceId(info.DevInst,&node.evidence[L"parentInstanceId"]);
    node.description = QueryStringProperty(set, info, kPropFriendlyName,&node.evidence[L"friendlyName"]);
    node.evidence[L"description"] = node.evidence[L"friendlyName"];
    if (node.description.empty()) {
        node.description = QueryStringProperty(set, info, kPropDeviceDesc,&node.evidence[L"deviceDescription"]);
        node.evidence[L"description"] = node.evidence[L"deviceDescription"];
    }
    if (node.description.empty()) {
        node.description = node.instanceId;
    }
    node.manufacturer = QueryStringProperty(set, info, kPropManufacturer,&node.evidence[L"manufacturer"]);
    node.deviceClass = QueryStringProperty(set, info, kPropClass,&node.evidence[L"deviceClass"]);
    node.service = QueryStringProperty(set, info, kPropService,&node.evidence[L"service"]);
    node.driverKey = QueryStringProperty(set, info, kPropDriver,&node.evidence[L"driverKey"]);
    node.locationInfo = QueryStringProperty(set, info, kPropLocationInfo,&node.evidence[L"locationInfo"]);
    node.hardwareIds = QueryStringListProperty(set, info, kPropHardwareIds,&node.evidence[L"hardwareIds"]);

    const std::wstring identitySource = node.hardwareIds.empty() ? node.instanceId : node.hardwareIds;
    node.vendorId = ExtractHexField(identitySource, L"VID_", 4);
    node.productId = ExtractHexField(identitySource, L"PID_", 4);
    node.revision = ExtractHexField(identitySource, L"REV_", 4);
    node.serialNumber = SerialNumberFromInstanceId(node.instanceId);

    node.statusText = DescribeDeviceStatus(info.DevInst, node.problemText,&node.statusFlags,&node.problemCode,&node.statusResult);
    node.statusKnown = node.statusResult == CR_SUCCESS;
    if (controllers.count(node.instanceId) != 0) {
        node.kind = UsbNodeKind::HostController;
    } else if (hubs.count(node.instanceId) != 0) {
        node.kind = UsbNodeKind::Hub;
    } else {
        node.kind = UsbNodeKind::Device;
    }

    // DEVPKEY_Device_Address is the hub port number only for devnodes that hang
    // off a hub. A host controller is a PCI function, where the same property
    // holds the packed PCI device/function pair -- rendering that as a port would
    // put a number like 1310720 in the port column.
    DWORD port = 0;node.addressKnown = QueryUint32Property(set,info,kPropAddress,port,&node.evidence[L"address"]);node.address = port;
    if (node.kind != UsbNodeKind::HostController && node.addressKnown) {
        node.portText = std::to_wstring(port);
    } else if (!node.locationInfo.empty()) {
        // Some hubs report only the textual location, which still names the port.
        node.portText = node.locationInfo;
    }
    return node;
}
void AppendEnumeratorNodes(const wchar_t* enumeratorName,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers,
    std::vector<UsbNode>& nodes,
    std::set<std::wstring>& seen,UsbEnumerationSource* output) {
    UsbEnumerationSource local;auto& e = output ? *output : local;e = {};
    DevInfoSet set(::SetupDiGetClassDevsW(nullptr, enumeratorName, nullptr,
        DIGCF_PRESENT | DIGCF_ALLCLASSES));
    if (!set.valid()) {
        e.win32Error = ::GetLastError();return;
    }
    e.opened = true;
    for (DWORD ordinal = 0;ordinal<100000;++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            const auto error = ::GetLastError();e.complete = error == ERROR_NO_MORE_ITEMS;if (!e.complete) e.win32Error = error;break;
        }
        ++e.examinedCount;UsbNode node = UsbNodeFromDevInfo(set.get(), info, hubs, controllers);
        if (node.instanceId.empty()) {++e.skippedCount;e.cmStatus = node.evidence[L"instanceId"].cmStatus;e.malformed = e.malformed || node.evidence[L"instanceId"].malformed;continue;}
        if (!seen.insert(node.instanceId).second) {
            continue;
        }
        nodes.push_back(std::move(node));
    }
    if (!e.complete && !e.win32Error) {e.limited = true;e.win32Error = ERROR_MORE_DATA;}
}
void AppendInterfaceNodes(const GUID& interfaceGuid,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers,
    std::vector<UsbNode>& nodes,
    std::set<std::wstring>& seen,UsbEnumerationSource* output) {
    UsbEnumerationSource local;auto& e = output ? *output : local;e = {};
    DevInfoSet set(::SetupDiGetClassDevsW(&interfaceGuid, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (!set.valid()) {
        e.win32Error = ::GetLastError();return;
    }
    e.opened = true;
    for (DWORD ordinal = 0;ordinal<100000;++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            const auto error = ::GetLastError();e.complete = error == ERROR_NO_MORE_ITEMS;if (!e.complete) e.win32Error = error;break;
        }
        ++e.examinedCount;UsbNode node = UsbNodeFromDevInfo(set.get(), info, hubs, controllers);
        if (node.instanceId.empty()) {++e.skippedCount;e.cmStatus = node.evidence[L"instanceId"].cmStatus;e.malformed = e.malformed || node.evidence[L"instanceId"].malformed;continue;}
        if (!seen.insert(node.instanceId).second) {
            continue;
        }
        nodes.push_back(std::move(node));
    }
    if (!e.complete && !e.win32Error) {e.limited = true;e.win32Error = ERROR_MORE_DATA;}
}
std::vector<UsbNode> OrderUsbNodesDepthFirst(std::vector<UsbNode> nodes) {
    std::map<std::wstring, std::size_t> byInstance;
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        byInstance.emplace(nodes[index].instanceId, index);
    }

    std::vector<std::vector<std::size_t>> children(nodes.size());
    std::vector<std::size_t> roots;
    std::vector<int> parentOf(nodes.size(), -1);
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        const auto found = byInstance.find(nodes[index].parentInstanceId);
        if (found != byInstance.end() && found->second != index) {
            parentOf[index] = static_cast<int>(found->second);
            children[found->second].push_back(index);
        } else {
            roots.push_back(index);
        }
    }

    const auto orderKey = [&nodes](const std::size_t index) {
        // Sorting on the port keeps the children of one hub in physical order
        // rather than in whatever order SetupAPI happened to return them.
        const UsbNode& node = nodes[index];
        return node.portText + L"\x1F" + node.description;
    };
    const auto sortIndexes = [&orderKey](std::vector<std::size_t>& indexes) {
        std::sort(indexes.begin(), indexes.end(), [&orderKey](const std::size_t left, const std::size_t right) {
            return orderKey(left) < orderKey(right);
        });
    };
    sortIndexes(roots);
    for (auto& list : children) {
        sortIndexes(list);
    }

    std::vector<UsbNode> ordered;
    ordered.reserve(nodes.size());
    std::vector<char> visited(nodes.size(), 0);
    std::vector<std::pair<std::size_t, int>> stack;
    for (auto root = roots.rbegin(); root != roots.rend(); ++root) {
        stack.emplace_back(*root, 0);
    }
    while (!stack.empty()) {
        const auto [index, depth] = stack.back();
        stack.pop_back();
        if (visited[index]) {
            continue;
        }
        visited[index] = 1;
        UsbNode node = nodes[index];
        node.depth = depth;
        node.index = static_cast<int>(ordered.size());
        ordered.push_back(std::move(node));
        for (auto child = children[index].rbegin(); child != children[index].rend(); ++child) {
            stack.emplace_back(*child, depth + 1);
        }
    }

    // A cycle or a parent outside the snapshot would strand nodes; appending them
    // at depth zero keeps the table complete instead of silently dropping rows.
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        if (!visited[index]) {
            UsbNode node = nodes[index];
            node.depth = 0;
            node.index = static_cast<int>(ordered.size());
            ordered.push_back(std::move(node));
        }
    }

    std::map<std::wstring, int> orderedByInstance;
    for (const UsbNode& node : ordered) {
        orderedByInstance.emplace(node.instanceId, node.index);
    }
    for (UsbNode& node : ordered) {
        const auto found = orderedByInstance.find(node.parentInstanceId);
        node.parentIndex = found != orderedByInstance.end() && found->second != node.index
            ? found->second
            : -1;
    }
    return ordered;
}
UsbTopologySnapshot EnumerateUsbTopology() {
    UsbTopologySnapshot snapshot;

    snapshot.sources.resize(6);
    const std::set<std::wstring> hubs = CollectInterfaceOwners(kUsbHubInterface,&snapshot.sources[0]);
    const std::set<std::wstring> controllers = CollectInterfaceOwners(kUsbHostControllerInterface,&snapshot.sources[1]);

    std::vector<UsbNode> nodes;
    std::set<std::wstring> seen;
    AppendInterfaceNodes(kUsbHostControllerInterface, hubs, controllers, nodes, seen,&snapshot.sources[2]);
    AppendEnumeratorNodes(L"USB", hubs, controllers, nodes, seen,&snapshot.sources[3]);
    // USBSTOR children hang off a USB device and are what actually carries the
    // removable volume, so leaving them out would hide the interesting half of a
    // mass-storage device.
    AppendEnumeratorNodes(L"USBSTOR", hubs, controllers, nodes, seen,&snapshot.sources[4]);
    // The device interface pass is a safety net for devnodes whose enumerator is
    // not literally "USB" but which still publish the USB device interface.
    AppendInterfaceNodes(kUsbDeviceInterface, hubs, controllers, nodes, seen,&snapshot.sources[5]);

    const wchar_t* names[] = {L"hub-classification",L"controller-classification",L"host-controller-interfaces",L"USB-enumerator",L"USBSTOR-enumerator",L"USB-device-interfaces"};
    for (std::size_t i = 0;i<snapshot.sources.size();++i) snapshot.sources[i].name = names[i];
    if (nodes.empty()) {
        snapshot.success = false;
        snapshot.diagnosticText = L"未枚举到任何 USB 设备节点：" + ks::r3::common::LastErrorMessage();
        return snapshot;
    }

    snapshot.nodes = OrderUsbNodesDepthFirst(std::move(nodes));
    snapshot.success = true;
    snapshot.diagnosticText = L"共 " + std::to_wstring(snapshot.nodes.size()) + L" 个 USB 节点。";
    return snapshot;
}
}
