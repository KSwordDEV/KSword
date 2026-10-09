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
#include "CommunicationEndpoints.h"
#include "ObjectTypes.h"
#include "NamedPipes.h"
namespace ks::r3::kernel {
KernelOperationResult QueryAtomTable(const KernelRequest& request);
}
