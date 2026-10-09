#include "ObjectDirectory.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
KernelOperationResult QueryObjectDirectoryRecursive(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    const bool filterLooksLikePath = !request.filterText.empty() && request.filterText.front() == L'\\';
    const std::wstring startPath = filterLooksLikePath ? request.filterText : L"\\";
    const std::wstring rowFilter = filterLooksLikePath ? std::wstring{} : request.filterText;
    std::size_t maxDepth = 4;
    if (!request.moduleFilterText.empty()) {
        wchar_t* end = nullptr;
        const unsigned long parsed = std::wcstoul(request.moduleFilterText.c_str(), &end, 10);
        if (end != request.moduleFilterText.c_str()) {
            maxDepth = std::min<std::size_t>(32, parsed);
        }
    }
    struct WorkItem {
        std::wstring path;
        std::size_t depth = 0;
    };

    std::deque<WorkItem> queue;
    std::set<std::wstring> visited;
    std::size_t scannedRows = 0;
    queue.push_back({ startPath, 0 });
    visited.insert(ToLowerCopy(startPath));

    while (!queue.empty() && packet.rows.size() < kMaxDirectoryRows && scannedRows < kMaxDirectoryRows * 4) {
        const WorkItem item = queue.front();
        queue.pop_front();
        const std::vector<DirectoryEntry> entries = EnumerateDirectoryFlat(runtime, item.path, packet.warnings);
        for (const DirectoryEntry& entry : entries) {
            ++scannedRows;
            if (MatchesDirectoryFilter(entry, rowFilter)) {
                AppendDirectoryEntryRow(packet, L"Recursive", item.depth, entry);
            }
            if (entry.typeName == L"Directory" && item.depth < maxDepth && packet.rows.size() < kMaxDirectoryRows && scannedRows < kMaxDirectoryRows * 4) {
                const std::wstring key = ToLowerCopy(entry.fullPath);
                if (visited.insert(key).second) {
                    queue.push_back({ entry.fullPath, item.depth + 1 });
                }
            }
        }
    }

    if (!queue.empty() || scannedRows >= kMaxDirectoryRows * 4) {
        packet.warnings.push_back(std::wstring(L"目录递归达到显示上限 ") + std::to_wstring(kMaxDirectoryRows) + L" 行，已截断。可在“过滤/起点”输入框指定更小的对象目录。");
    }
    return MakeResult(request.featureId, !packet.rows.empty(), L"对象目录递归", std::move(packet));
}
}
