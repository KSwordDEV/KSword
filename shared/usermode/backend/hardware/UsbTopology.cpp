#include "UsbTopology.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <utility>
#pragma comment(lib,"Setupapi.lib")
#pragma comment(lib,"Cfgmgr32.lib")
namespace ks::r3::hardware_stats {
bool QueryRawProperty(HDEVINFO set,
    SP_DEVINFO_DATA& info,
    const DEVPROPKEY& key,
    DEVPROPTYPE& type,
    std::vector<BYTE>& data) {
    type = 0;
    data.clear();
    DWORD required = 0;
    ::SetupDiGetDevicePropertyW(set, &info, &key, &type, nullptr, 0, &required, 0);
    if (required == 0) {
        return false;
    }
    data.assign(static_cast<std::size_t>(required) + sizeof(wchar_t) * 2, 0);
    if (!::SetupDiGetDevicePropertyW(set, &info, &key, &type, data.data(), required, nullptr, 0)) {
        data.clear();
        return false;
    }
    return true;
}
std::wstring JoinStringList(const std::vector<BYTE>& data) {
    if (data.size() < sizeof(wchar_t)) {
        return {};
    }
    const auto* cursor = reinterpret_cast<const wchar_t*>(data.data());
    const auto* end = cursor + data.size() / sizeof(wchar_t);
    std::wstring joined;
    while (cursor < end && *cursor) {
        const std::wstring part(cursor);
        if (!joined.empty()) {
            joined += L"; ";
        }
        joined += part;
        cursor += part.size() + 1;
    }
    return joined;
}
std::wstring QueryStringProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data)) {
        return {};
    }
    if (type == DEVPROP_TYPE_STRING) {
        return std::wstring(reinterpret_cast<const wchar_t*>(data.data()));
    }
    if (type == DEVPROP_TYPE_STRING_LIST) {
        return JoinStringList(data);
    }
    return {};
}
std::wstring QueryStringListProperty(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data)) {
        return {};
    }
    if (type == DEVPROP_TYPE_STRING_LIST) {
        return JoinStringList(data);
    }
    if (type == DEVPROP_TYPE_STRING) {
        return std::wstring(reinterpret_cast<const wchar_t*>(data.data()));
    }
    return {};
}
bool QueryUint32Property(HDEVINFO set, SP_DEVINFO_DATA& info, const DEVPROPKEY& key, DWORD& value) {
    DEVPROPTYPE type = 0;
    std::vector<BYTE> data;
    if (!QueryRawProperty(set, info, key, type, data) || data.size() < sizeof(DWORD)) {
        return false;
    }
    if (type != DEVPROP_TYPE_UINT32 && type != DEVPROP_TYPE_INT32) {
        return false;
    }
    std::memcpy(&value, data.data(), sizeof(value));
    return true;
}
std::wstring DevInstToInstanceId(DEVINST devInst) {
    ULONG length = 0;
    if (::CM_Get_Device_ID_Size(&length, devInst, 0) != CR_SUCCESS) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 2, L'\0');
    if (::CM_Get_Device_IDW(devInst, buffer.data(), static_cast<ULONG>(buffer.size()), 0) != CR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}
std::wstring ParentInstanceId(DEVINST devInst) {
    DEVINST parent = 0;
    if (::CM_Get_Parent(&parent, devInst, 0) != CR_SUCCESS) {
        return {};
    }
    return DevInstToInstanceId(parent);
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
std::wstring DescribeDeviceStatus(DEVINST devInst, std::wstring& problemText) {
    ULONG status = 0;
    ULONG problem = 0;
    problemText.clear();
    if (::CM_Get_DevNode_Status(&status, &problem, devInst, 0) != CR_SUCCESS) {
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
std::set<std::wstring> CollectInterfaceOwners(const GUID& interfaceGuid) {
    std::set<std::wstring> owners;
    DevInfoSet set(::SetupDiGetClassDevsW(&interfaceGuid, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (!set.valid()) {
        return owners;
    }
    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            break;
        }
        std::wstring instanceId = DevInstToInstanceId(info.DevInst);
        if (!instanceId.empty()) {
            owners.insert(std::move(instanceId));
        }
    }
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
    node.instanceId = DevInstToInstanceId(info.DevInst);
    node.parentInstanceId = ParentInstanceId(info.DevInst);
    node.description = QueryStringProperty(set, info, kPropFriendlyName);
    if (node.description.empty()) {
        node.description = QueryStringProperty(set, info, kPropDeviceDesc);
    }
    if (node.description.empty()) {
        node.description = node.instanceId;
    }
    node.manufacturer = QueryStringProperty(set, info, kPropManufacturer);
    node.deviceClass = QueryStringProperty(set, info, kPropClass);
    node.service = QueryStringProperty(set, info, kPropService);
    node.driverKey = QueryStringProperty(set, info, kPropDriver);
    node.locationInfo = QueryStringProperty(set, info, kPropLocationInfo);
    node.hardwareIds = QueryStringListProperty(set, info, kPropHardwareIds);

    const std::wstring identitySource = node.hardwareIds.empty() ? node.instanceId : node.hardwareIds;
    node.vendorId = ExtractHexField(identitySource, L"VID_", 4);
    node.productId = ExtractHexField(identitySource, L"PID_", 4);
    node.revision = ExtractHexField(identitySource, L"REV_", 4);
    node.serialNumber = SerialNumberFromInstanceId(node.instanceId);

    node.statusText = DescribeDeviceStatus(info.DevInst, node.problemText);
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
    DWORD port = 0;
    if (node.kind != UsbNodeKind::HostController && QueryUint32Property(set, info, kPropAddress, port)) {
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
    std::set<std::wstring>& seen) {
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
        UsbNode node = UsbNodeFromDevInfo(set.get(), info, hubs, controllers);
        if (node.instanceId.empty() || !seen.insert(node.instanceId).second) {
            continue;
        }
        nodes.push_back(std::move(node));
    }
}
void AppendInterfaceNodes(const GUID& interfaceGuid,
    const std::set<std::wstring>& hubs,
    const std::set<std::wstring>& controllers,
    std::vector<UsbNode>& nodes,
    std::set<std::wstring>& seen) {
    DevInfoSet set(::SetupDiGetClassDevsW(&interfaceGuid, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (!set.valid()) {
        return;
    }
    for (DWORD ordinal = 0;; ++ordinal) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!::SetupDiEnumDeviceInfo(set.get(), ordinal, &info)) {
            break;
        }
        UsbNode node = UsbNodeFromDevInfo(set.get(), info, hubs, controllers);
        if (node.instanceId.empty() || !seen.insert(node.instanceId).second) {
            continue;
        }
        nodes.push_back(std::move(node));
    }
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

    const std::set<std::wstring> hubs = CollectInterfaceOwners(kUsbHubInterface);
    const std::set<std::wstring> controllers = CollectInterfaceOwners(kUsbHostControllerInterface);

    std::vector<UsbNode> nodes;
    std::set<std::wstring> seen;
    AppendInterfaceNodes(kUsbHostControllerInterface, hubs, controllers, nodes, seen);
    AppendEnumeratorNodes(L"USB", hubs, controllers, nodes, seen);
    // USBSTOR children hang off a USB device and are what actually carries the
    // removable volume, so leaving them out would hide the interesting half of a
    // mass-storage device.
    AppendEnumeratorNodes(L"USBSTOR", hubs, controllers, nodes, seen);
    // The device interface pass is a safety net for devnodes whose enumerator is
    // not literally "USB" but which still publish the USB device interface.
    AppendInterfaceNodes(kUsbDeviceInterface, hubs, controllers, nodes, seen);

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
