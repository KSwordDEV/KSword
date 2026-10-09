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
#include "DeviceDriverObjects.h"
#include "BaseNamedObjects.h"
namespace ks::r3::kernel {
bool IsCommunicationType(const std::wstring& typeName);
void AppendCommunicationEndpointsRecursive(
    QueryPacket& packet,
    const NtRuntime& runtime,
    const std::wstring& root,
    const std::wstring& source,
    const std::wstring& filter);
KernelOperationResult QueryCommunicationEndpoint(const KernelRequest& request);
}
