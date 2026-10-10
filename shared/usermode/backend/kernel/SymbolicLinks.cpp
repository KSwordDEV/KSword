#include "SymbolicLinks.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
DirectoryEntry QueryOneSymbolicLink(const std::wstring& path) {
    DirectoryEntry entry;entry.fullPath=path;entry.typeName=L"SymbolicLink";entry.metadataRequested=true;
    const auto separator=path.find_last_of(L'\\');entry.parentPath=separator==0?L"\\":path.substr(0,separator);entry.name=path.substr(separator+1);
    const auto& runtime=Runtime();entry.openAttempted=runtime.openSymbolicLinkObject!=nullptr;if(!entry.openAttempted)return entry;
    ks::r3::common::UniqueHandle handle(OpenSymbolicLink(runtime,path,&entry.openStatus));if(!handle.valid())return entry;entry.canOpen=true;
    QueryBasicObjectCounts(runtime,handle.get(),entry.handleCountText,entry.pointerCountText,&entry.basic);entry.targetPath=QuerySymbolicLinkTarget(runtime,handle.get(),&entry.target);
    entry.closeAttempted=true;::SetLastError(ERROR_SUCCESS);entry.closed=::CloseHandle(handle.release())!=FALSE;entry.closeError=entry.closed?ERROR_SUCCESS: ::GetLastError();
    entry.statusText=DirectoryStatusText(entry.typeName,entry.canOpen,!entry.targetPath.empty());return entry;
}
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
    QueryPacket packet;
    const std::wstring path = NativePathFromAction(request);
    if (path.empty()) {
        packet.warnings.push_back(L"当前行没有可解析的符号链接 Path。");
        return MakeNativeActionResult(request, false, L"符号链接解析", std::move(packet));
    }

    const auto snapshot=QueryOneSymbolicLink(path);const auto openStatus=snapshot.openStatus;
    const bool link=snapshot.canOpen;const auto& handleCount=snapshot.handleCountText;const auto& pointerCount=snapshot.pointerCountText;const auto& target=snapshot.targetPath;
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
    return MakeNativeActionResult(request, link && !target.empty(), L"符号链接解析", std::move(packet));
}
}
