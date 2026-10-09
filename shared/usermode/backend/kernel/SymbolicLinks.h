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
namespace ks::r3::kernel {
std::wstring JoinStrings(const std::vector<std::wstring>& values, const wchar_t* separator);
KernelOperationResult QuerySymbolicLinks(const KernelRequest& request);
KernelOperationResult ExecuteNativeSymbolicLinkResolve(const KernelActionRequest& request);
}
