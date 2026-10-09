#include "CommunicationEndpoints.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
bool IsCommunicationType(const std::wstring& typeName) {
    const std::wstring lower = ToLowerCopy(typeName);
    return lower == L"alpc port"
        || lower == L"port"
        || lower == L"waitcompletionpacket"
        || lower == L"tpworkerfactory"
        || lower == L"event"
        || lower == L"section"
        || lower == L"mutant"
        || lower == L"semaphore"
        || lower == L"iocompletion"
        || lower == L"timer"
        || lower == L"job"
        || lower == L"keyed event";
}
void AppendCommunicationEndpointsRecursive(
    QueryPacket& packet,
    const NtRuntime& runtime,
    const std::wstring& root,
    const std::wstring& source,
    const std::wstring& filter) {
    struct WorkItem {
        std::wstring path;
        std::size_t depth = 0;
    };

    std::deque<WorkItem> queue;
    std::set<std::wstring> visited;
    queue.push_back({ root, 0 });
    visited.insert(ToLowerCopy(root));
    while (!queue.empty() && packet.rows.size() < kMaxDirectoryRows) {
        const WorkItem item = queue.front();
        queue.pop_front();
        const std::vector<DirectoryEntry> entries = EnumerateDirectoryFlat(runtime, item.path, packet.warnings);
        for (const DirectoryEntry& entry : entries) {
            if (IsCommunicationType(entry.typeName) && MatchesDirectoryFilter(entry, filter)) {
                AppendDirectoryEntryRow(packet, source, item.depth, entry);
            }
            if (entry.typeName == L"Directory" && item.depth < 3 && packet.rows.size() < kMaxDirectoryRows) {
                const std::wstring key = ToLowerCopy(entry.fullPath);
                if (visited.insert(key).second) {
                    queue.push_back({ entry.fullPath, item.depth + 1 });
                }
            }
        }
    }
}
KernelOperationResult QueryCommunicationEndpoint(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    for (const std::wstring& root : CommonNamespaceRoots()) {
        AppendCommunicationEndpointsRecursive(packet, runtime, root, root, request.filterText);
    }
    return MakeResult(request.featureId, !packet.rows.empty(), L"通信端点枚举", std::move(packet));
}
}
