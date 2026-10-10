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
namespace ks::r3::kernel {
KernelOperationResult QueryBaseNamedObjects(const KernelRequest& request);
std::vector<std::wstring> BaseNamedObjectRoots(DirectoryQueryEvidence* discovery=nullptr,DWORD* currentSessionError=nullptr,const DirectoryQueryOptions& options={},bool* currentSessionKnown=nullptr);
}
