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
namespace ks::r3::kernel {
constexpr std::size_t kMaxDirectoryRows = 2500;
KernelOperationResult QueryObjectDirectoryRecursive(const KernelRequest& request);
}
