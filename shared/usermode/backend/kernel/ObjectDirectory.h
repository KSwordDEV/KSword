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
struct RecursiveDirectoryOptions {
    std::wstring root=L"\\",filter;
    DWORD maxDepth=4,maxRows=2500,maxScannedRows=10000;
    DirectoryQueryOptions directory;
    std::function<bool(const DirectoryEntry&)> selectEntry;
};
struct RecursiveDirectoryRow {DirectoryEntry entry;DWORD depth=0;};
struct RecursiveDirectorySnapshot {
    bool complete=false,limited=false,cancelled=false,malformed=false,metadataPartial=false;
    DWORD scannedRows=0,matchedObserved=0,depthBoundaryCount=0,deduplicatedPaths=0;
    std::vector<RecursiveDirectoryRow> rows;
    std::vector<DirectoryQueryEvidence> sources;
    std::vector<std::wstring> warnings;
};
RecursiveDirectorySnapshot CollectObjectDirectories(const RecursiveDirectoryOptions& options);
KernelOperationResult QueryObjectDirectoryRecursive(const KernelRequest& request);
}
