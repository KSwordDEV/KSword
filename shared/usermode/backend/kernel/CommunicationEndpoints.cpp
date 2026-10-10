#include "CommunicationEndpoints.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
RecursiveDirectorySnapshot CollectCommunicationEndpoints(RecursiveDirectoryOptions options){
    options.selectEntry=[](const DirectoryEntry& entry){return IsCommunicationType(entry.typeName);};return CollectObjectDirectories(options);
}
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
    (void)runtime; if(packet.rows.size()>=kMaxDirectoryRows)return;
    RecursiveDirectoryOptions options;options.root=root;options.filter=filter;options.maxDepth=3;options.maxRows=static_cast<DWORD>(kMaxDirectoryRows-packet.rows.size());
    const auto snapshot=CollectCommunicationEndpoints(options);packet.warnings.insert(packet.warnings.end(),snapshot.warnings.begin(),snapshot.warnings.end());
    for(const auto& row:snapshot.rows)AppendDirectoryEntryRow(packet,source,row.depth,row.entry);
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
