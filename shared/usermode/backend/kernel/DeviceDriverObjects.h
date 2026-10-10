#pragma once
#include "../Common.h"
#include "KernelTypes.h"
#include <winternl.h>
#include <array>
#include <deque>
#include <functional>
#include <set>
#include <string_view>
#include <unordered_map>
#include "ObjectNamespace.h"
#include "ObjectDirectory.h"
#include "SymbolicLinks.h"
namespace ks::r3::kernel {
KernelOperationResult QueryDeviceDriverObjects(const KernelRequest& request);
std::vector<std::wstring> DeviceDriverObjectRoots();
}
