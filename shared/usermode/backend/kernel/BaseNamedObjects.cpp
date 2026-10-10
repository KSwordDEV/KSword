#include "BaseNamedObjects.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
std::vector<std::wstring> BaseNamedObjectRoots(DirectoryQueryEvidence* discovery,DWORD* currentSessionError,const DirectoryQueryOptions& options,bool* currentSessionKnown){
    std::vector<std::wstring> roots{L"\\BaseNamedObjects"};for(const auto id:DiscoverSessionIds(Runtime(),discovery,currentSessionError,options,currentSessionKnown))roots.push_back(L"\\Sessions\\"+std::to_wstring(id)+L"\\BaseNamedObjects");
    std::sort(roots.begin(),roots.end());roots.erase(std::unique(roots.begin(),roots.end()),roots.end());return roots;
}
KernelOperationResult QueryBaseNamedObjects(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    const auto roots=BaseNamedObjectRoots();
    for (const std::wstring& root : roots) {
        AppendDirectoryRoot(packet, runtime, root, root, request.filterText);
    }
    return MakeResult(request.featureId, !packet.rows.empty(), L"BaseNamedObjects 枚举", std::move(packet));
}
}
