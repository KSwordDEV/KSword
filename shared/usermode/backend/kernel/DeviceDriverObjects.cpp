#include "DeviceDriverObjects.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
std::vector<std::wstring> DeviceDriverObjectRoots(){return {L"\\Device",L"\\Driver",L"\\FileSystem",L"\\FileSystem\\Filters"};}
KernelOperationResult QueryDeviceDriverObjects(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    const auto roots=DeviceDriverObjectRoots();
    for (const std::wstring& root : roots) {
        AppendDirectoryRoot(packet, runtime, root, root, request.filterText);
    }
    return MakeResult(request.featureId, !packet.rows.empty(), L"设备与驱动对象枚举", std::move(packet));
}
}
