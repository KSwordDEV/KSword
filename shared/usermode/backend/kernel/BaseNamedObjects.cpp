#include "BaseNamedObjects.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
KernelOperationResult QueryBaseNamedObjects(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    std::vector<std::wstring> roots{
        L"\\BaseNamedObjects",
    };
    for (const DWORD sessionId : DiscoverSessionIds(runtime)) {
        roots.push_back(std::wstring(L"\\Sessions\\") + std::to_wstring(sessionId) + L"\\BaseNamedObjects");
    }
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    for (const std::wstring& root : roots) {
        AppendDirectoryRoot(packet, runtime, root, root, request.filterText);
    }
    return MakeResult(request.featureId, !packet.rows.empty(), L"BaseNamedObjects 枚举", std::move(packet));
}
}
