#include "SymbolicLinks.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
std::wstring JoinStrings(const std::vector<std::wstring>& values, const wchar_t* separator) {
    std::wstring joined;
    for (const std::wstring& value : values) {
        if (value.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += separator;
        }
        joined += value;
    }
    return joined;
}
KernelOperationResult QuerySymbolicLinks(const KernelRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    for (const std::wstring& root : CommonNamespaceRoots()) {
        const std::vector<DirectoryEntry> entries = EnumerateDirectoryFlat(runtime, root, packet.warnings);
        for (const DirectoryEntry& entry : entries) {
            const bool targetMatched = request.moduleFilterText.empty() ||
                ContainsI(entry.targetPath, request.moduleFilterText) ||
                ContainsI(JoinStrings(DosPathCandidatesFromNtPath(entry.targetPath), L"; "), request.moduleFilterText);
            if (entry.typeName == L"SymbolicLink" && MatchesDirectoryFilter(entry, request.filterText) && targetMatched) {
                AppendDirectoryEntryRow(packet, root, 0, entry);
            }
        }
    }
    return MakeResult(request.featureId, !packet.rows.empty(), L"符号链接解析", std::move(packet));
}
KernelOperationResult ExecuteNativeSymbolicLinkResolve(const KernelActionRequest& request) {
    const NtRuntime& runtime = Runtime();
    QueryPacket packet;
    const std::wstring path = NativePathFromAction(request);
    if (path.empty()) {
        packet.warnings.push_back(L"当前行没有可解析的符号链接 Path。");
        return MakeNativeActionResult(request, false, L"符号链接解析", std::move(packet));
    }

    LONG openStatus = 0;
    HANDLE link = OpenSymbolicLink(runtime, path, &openStatus);
    std::wstring handleCount;
    std::wstring pointerCount;
    std::wstring target;
    if (link) {
        QueryBasicObjectCounts(runtime, link, handleCount, pointerCount);
        target = QuerySymbolicLinkTarget(runtime, link);
    }
    const std::vector<std::wstring> candidates = DosPathCandidatesFromNtPath(target);
    packet.rows.push_back(Row({
        { L"Action", L"NativeSymbolicLinkResolve" },
        { L"Path", path },
        { L"OpenStatus", StatusText(openStatus) },
        { L"OpenStatusText", StatusMeaningText(openStatus) },
        { L"Target", target },
        { L"DosCandidates", JoinStrings(candidates, L"; ") },
        { L"Handles", handleCount.empty() ? L"N/A" : handleCount },
        { L"Pointers", pointerCount.empty() ? L"N/A" : pointerCount },
        { L"Status", link ? (target.empty() ? L"已打开但目标为空" : L"已打开并查询") : L"打开失败" },
    }, target.empty() ? StatusMeaningText(openStatus) : target));
    if (link) {
        ::CloseHandle(link);
    }
    return MakeNativeActionResult(request, link != nullptr && !target.empty(), L"符号链接解析", std::move(packet));
}
}
