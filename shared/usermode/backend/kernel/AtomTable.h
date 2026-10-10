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
struct AtomNameEvidence {bool attempted=false,available=false,absent=false,malformed=false;DWORD error=0;std::wstring name;};
struct AtomEntry {UINT id=0;AtomNameEvidence global,clipboard;};
struct AtomQueryOptions {UINT first=0xc000,last=0xffff;bool global=true,clipboard=true;ULONGLONG deadlineTick=0;std::function<bool()> cancelled;};
struct AtomSnapshot {bool complete=false,limited=false,cancelled=false,malformed=false;UINT scannedIds=0,globalFound=0,clipboardFound=0,failedQueries=0;std::vector<AtomEntry> entries;};
AtomSnapshot CollectAtoms(const AtomQueryOptions& options={});
KernelOperationResult QueryAtomTable(const KernelRequest& request);
}
