#include "ObjectDirectory.h"
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>
namespace ks::r3::kernel {
RecursiveDirectorySnapshot CollectObjectDirectories(const RecursiveDirectoryOptions& options) {
    RecursiveDirectorySnapshot result;const auto& runtime=Runtime();
    struct WorkItem {std::wstring path;DWORD depth;};std::deque<WorkItem> queue{{options.root,0}};std::set<std::wstring> visited{ToLowerCopy(options.root)};
    while(!queue.empty()){
        if(options.directory.cancelled&&options.directory.cancelled()){result.cancelled=true;break;}
        if(result.rows.size()>=options.maxRows||result.scannedRows>=options.maxScannedRows||(options.directory.deadlineTick&&::GetTickCount64()>=options.directory.deadlineTick)){result.limited=true;break;}
        const auto item=queue.front();queue.pop_front();auto scan=options.directory;scan.maxEntries=(std::min)(scan.maxEntries,options.maxScannedRows-result.scannedRows);
        DirectoryQueryEvidence evidence;evidence.depth=item.depth;const auto entries=EnumerateDirectoryFlat(runtime,item.path,result.warnings,&evidence,scan);
        result.limited=result.limited||evidence.limited;result.cancelled=result.cancelled||evidence.cancelled;result.malformed=result.malformed||evidence.malformed;
        result.sources.push_back(std::move(evidence));
        for(const auto& entry:entries){result.malformed=result.malformed||entry.basic.malformed||entry.target.malformed;
            result.metadataPartial=result.metadataPartial||(entry.metadataRequested&&(!entry.canOpen||!entry.basic.available||(entry.typeName==L"SymbolicLink"&&!entry.target.available)))||(entry.closeAttempted&&!entry.closed);}
        for(const auto& entry:entries){
            if(result.rows.size()>=options.maxRows||result.scannedRows>=options.maxScannedRows){result.limited=true;break;}
            ++result.scannedRows;
            if(MatchesDirectoryFilter(entry,options.filter)){++result.matchedObserved;result.rows.push_back({entry,item.depth});}
            if(entry.typeName==L"Directory"){
                if(item.depth>=options.maxDepth){++result.depthBoundaryCount;continue;}
                const auto key=ToLowerCopy(entry.fullPath);if(visited.insert(key).second)queue.push_back({entry.fullPath,item.depth+1});else ++result.deduplicatedPaths;
            }
        }
        if(result.limited||result.cancelled||result.malformed)break;
    }
    result.complete=queue.empty()&&!result.limited&&!result.cancelled&&!result.malformed&&std::all_of(result.sources.begin(),result.sources.end(),[](const auto& source){return source.complete;});return result;
}
KernelOperationResult QueryObjectDirectoryRecursive(const KernelRequest& request) {
    QueryPacket packet;RecursiveDirectoryOptions options;
    const bool filterLooksLikePath=!request.filterText.empty()&&request.filterText.front()==L'\\';options.root=filterLooksLikePath?request.filterText:L"\\";options.filter=filterLooksLikePath?std::wstring{}:request.filterText;
    if(!request.moduleFilterText.empty()){wchar_t* end=nullptr;const auto parsed=std::wcstoul(request.moduleFilterText.c_str(),&end,10);if(end!=request.moduleFilterText.c_str())options.maxDepth=static_cast<DWORD>((std::min<std::size_t>)(32,parsed));}
    const auto snapshot=CollectObjectDirectories(options);packet.warnings=snapshot.warnings;
    for(const auto& row:snapshot.rows)AppendDirectoryEntryRow(packet,L"Recursive",row.depth,row.entry);
    if(snapshot.limited)packet.warnings.push_back(std::wstring(L"目录递归达到显示上限 ")+std::to_wstring(kMaxDirectoryRows)+L" 行，已截断。可在“过滤/起点”输入框指定更小的对象目录。");
    return MakeResult(request.featureId,!packet.rows.empty(),L"对象目录递归",std::move(packet));
}
}
